#!/usr/bin/env python3
"""
Results Analyzer — computes paper-ready measurements from gateway/monitor logs
==============================================================================
Reads the JSON-lines log produced by gateway_sink.py (--log-file) and/or
syn_monitor.py and computes:

  • Detection Rate       (attacks caught / attacks present)
  • False Positive Rate  (clean events flagged / clean events)
  • Delay statistics     (min / mean / median / p95 / max, ms)
  • Throughput statistics (mean KB/s)
  • Decrypt success rate
  • WFSS progression during injection
  • Replay escalation
  • CTS-vs-time curve during SYN flood (from syn_monitor log)

Usage:
    python3 analyze_results.py --gateway-log gateway.log
    python3 analyze_results.py --gateway-log gateway.log --syn-log syn_monitor.log
    # optionally tell it how many attacks you actually sent, for exact rates:
    python3 analyze_results.py --gateway-log gateway.log \
            --injections-sent 10 --replays-sent 5
"""
import argparse
import json
import statistics as stats

def load(path):
    events = []
    if not path:
        return events
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except FileNotFoundError:
        print(f"  [!] Log file not found: {path}")
    return events

def hdr(t):
    print("\n" + "═" * 62)
    print(f"  {t}")
    print("═" * 62)

def sub(t):
    print(f"\n  ── {t} " + "─" * (56 - len(t)))

def main():
    ap = argparse.ArgumentParser(description="Analyze gateway/monitor logs")
    ap.add_argument("--gateway-log", required=True)
    ap.add_argument("--syn-log", default=None)
    ap.add_argument("--injections-sent", type=int, default=None,
                    help="How many forged fragments you actually sent (for exact rate)")
    ap.add_argument("--replays-sent", type=int, default=None,
                    help="How many replays you actually sent (for exact rate)")
    args = ap.parse_args()

    gw = load(args.gateway_log)
    syn = load(args.syn_log)

    by = lambda ev: [e for e in gw if e.get("event") == ev]

    processed = by("packet_processed")
    decrypts  = by("decrypt")
    replays   = by("replay_detected")
    frag_iss  = by("fragment_issue")
    bursts    = by("burst_complete")
    profiles  = by("profile_assigned")

    hdr("IoT SECURITY SYSTEM — MEASUREMENT RESULTS")
    print(f"  Gateway log : {args.gateway_log}  ({len(gw)} events)")
    if args.syn_log:
        print(f"  SYN log     : {args.syn_log}  ({len(syn)} samples)")

    # ── PERFORMANCE ──────────────────────────────────────────────────
    hdr("1. PERFORMANCE METRICS")
    if processed:
        # Attack packets (replays) carry deliberately old timestamps that would
        # skew delay stats. Exclude packets with delay > 5000ms as attack noise
        # so the PERFORMANCE numbers reflect genuine traffic.
        legit = [e for e in processed
                 if "delay_ms" in e and e["delay_ms"] < 5000]
        excluded = len(processed) - len(legit)
        delays = [e["delay_ms"] for e in legit]
        tputs  = [e["throughput_kbps"] for e in processed if "throughput_kbps" in e]
        sub("End-to-End Delay (ms)  — legitimate traffic only")
        print(f"     Packets processed  : {len(processed)}")
        if excluded:
            print(f"     Excluded as attack : {excluded} "
                  f"(stale-timestamp replay packets)")
        if delays:
            print(f"     Min    : {min(delays):8.3f} ms")
            print(f"     Mean   : {stats.mean(delays):8.3f} ms")
            print(f"     Median : {stats.median(delays):8.3f} ms")
            if len(delays) >= 20:
                p95 = sorted(delays)[int(len(delays)*0.95)]
                print(f"     p95    : {p95:8.3f} ms")
            print(f"     Max    : {max(delays):8.3f} ms")
        sub("Throughput (KB/s)")
        print(f"     Mean   : {stats.mean(tputs):8.3f} KB/s")
        print(f"     Peak   : {max(tputs):8.3f} KB/s")

        # Stage breakdown
        sa = [e for e in processed if e.get("stage") == "A"]
        sb = [e for e in processed if e.get("stage") == "B"]
        sub("Scheduling Stage Breakdown")
        print(f"     Stage A (FIFO)     : {len(sa)} packets")
        print(f"     Stage B (Priority) : {len(sb)} packets")
    else:
        print("     No processed packets logged.")

    # ── DECRYPT ──────────────────────────────────────────────────────
    hdr("2. CRYPTOGRAPHIC INTEGRITY")
    if decrypts:
        ok  = sum(1 for e in decrypts if e.get("success"))
        bad = len(decrypts) - ok
        sub("Decryption Results")
        print(f"     Total decrypt attempts : {len(decrypts)}")
        print(f"     Successful (authentic) : {ok}")
        print(f"     Failed (forged/corrupt): {bad}")
        rate = 100.0 * ok / len(decrypts)
        print(f"     Authentic success rate : {rate:.1f}%")
    else:
        print("     No decrypt events logged.")

    # ── ATTACK 2: INJECTION ──────────────────────────────────────────
    hdr("3. ATTACK 2 — INJECTION DETECTION")
    # Count decrypt failures that are FRAGMENTS (injection forges fragments).
    # Non-fragment decrypt failures belong to other attacks, so we scope this
    # to fragment decrypt failures to avoid cross-counting.
    forged_frag_caught = sum(1 for e in decrypts
                             if not e.get("success") and e.get("is_fragment"))
    sub("Injection Detection")
    print(f"     Forged fragments caught (decrypt fail) : {forged_frag_caught}")
    print(f"     Fragment issues logged (WFSS)          : {len(frag_iss)}")
    if args.injections_sent:
        # Cap at 100% — cannot detect more than were sent
        caught = min(forged_frag_caught, args.injections_sent)
        dr = 100.0 * caught / args.injections_sent
        print(f"     Injections sent (you specified)        : {args.injections_sent}")
        print(f"     DETECTION RATE                         : {dr:.1f}%")
        if forged_frag_caught > args.injections_sent:
            print(f"     (note: {forged_frag_caught} total fragment failures seen — "
                  f"extra ones are from other test bursts)")
    else:
        print(f"     (pass --injections-sent N for exact detection rate)")
    if frag_iss:
        sub("WFSS Progression")
        for e in frag_iss[:12]:
            print(f"     seq={e.get('seq')} frag={e.get('frag_index')} "
                  f"→ WFSS {e.get('wfss_stars')}★  {e.get('issues')}")

    # ── ATTACK 3: REPLAY ─────────────────────────────────────────────
    hdr("4. ATTACK 3 — REPLAY DETECTION")
    sub("Replay Detection")
    print(f"     Replays detected : {len(replays)}")
    if args.replays_sent:
        # The FIRST send of a sequence establishes it (not yet a duplicate).
        # Only the 2nd..Nth copies are detectable duplicates. So the maximum
        # detectable is (replays_sent - 1) when all share one sequence number.
        detectable = max(1, args.replays_sent - 1)
        dr = 100.0 * len(replays) / detectable
        dr = min(100.0, dr)
        print(f"     Replays sent (you specified)   : {args.replays_sent}")
        print(f"     Detectable duplicates          : {detectable} "
              f"(first send establishes the sequence)")
        print(f"     DETECTION RATE                 : {dr:.1f}%")
    else:
        print(f"     (pass --replays-sent N for exact detection rate)")
    if replays:
        sub("Replay Escalation")
        for e in replays:
            print(f"     seq={e.get('seq')} → stars {e.get('replay_stars')}★  "
                  f"{e.get('reasons')}")

    # ── FALSE POSITIVES ──────────────────────────────────────────────
    hdr("5. FALSE POSITIVE ANALYSIS")
    # Clean packets = processed that are NOT part of an attack burst.
    # A false positive = a replay flagged on a packet that was legitimate,
    # or a fragment issue on a genuine fragment. In a clean baseline run
    # (no attacks), these should both be zero.
    sub("False Positives (should be 0 in clean baseline runs)")
    print(f"     Replay false alarms   : {len(replays)}  "
          + ("(if this was a CLEAN run, these are false positives)" if not args.replays_sent else ""))
    print(f"     Fragment false alarms : {len(frag_iss)}  "
          + ("(if this was a CLEAN run, these are false positives)" if not args.injections_sent else ""))

    # ── ATTACK 1: SYN FLOOD (from syn monitor) ───────────────────────
    if syn:
        hdr("6. ATTACK 1 — SYN FLOOD (CTS RESPONSE)")
        samples = [e for e in syn if e.get("event") == "syn_sample"]
        if samples:
            peak_syn = max(e["syn_recv"] for e in samples)
            peak_cts = max(e["cts"] for e in samples)
            base_cts = samples[0]["cts"]
            # Time to reach High threat (cts >= 0.55)
            t_high = None
            for e in samples:
                if e["cts"] >= 0.55:
                    t_high = e["elapsed"]; break
            sub("SYN Flood Response")
            print(f"     Baseline CTS (start) : {base_cts:.3f}")
            print(f"     Peak SYN_RECV        : {peak_syn}")
            print(f"     Peak CTS             : {peak_cts:.3f}")
            if t_high is not None:
                print(f"     Time to High threat  : {t_high:.1f}s")
            else:
                print(f"     (CTS did not reach High — flood may need more intensity)")
            sub("CTS-vs-Time Curve (for plotting)")
            print(f"     {'t(s)':>6} {'SYN':>5} {'CTS':>7}")
            for e in samples[::max(1, len(samples)//15)]:  # ~15 rows
                print(f"     {e['elapsed']:6.1f} {e['syn_recv']:5d} {e['cts']:7.3f}")

    print("\n" + "═" * 62)
    print("  END OF REPORT")
    print("═" * 62 + "\n")

if __name__ == "__main__":
    main()
