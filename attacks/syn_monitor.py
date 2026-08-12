#!/usr/bin/env python3
"""
SYN_RECV Monitor — samples the cluster head's own socket states during an attack
================================================================================
Run this ON THE CLUSTER HEAD PI while a SYN flood is happening against it.
It samples SYN_RECV / CLOSE_WAIT / TIME_WAIT every second and computes the
NAS and CTS values exactly as the node does, producing a smooth time-series
you can plot for the paper (CTS-vs-time curve during the attack).

Writes JSON-lines to a log file for the analyzer.

Usage (on the cluster head Pi):
    python3 syn_monitor.py --duration 60 --log-file syn_monitor.log
"""
import argparse
import json
import time

THREAT_NORM     = 20.0
THREAT_BASELINE = 0.05

def sample_sockets():
    s = c = t = 0
    try:
        import psutil
        for conn in psutil.net_connections(kind='inet'):
            if   conn.status == 'SYN_RECV':   s += 1
            elif conn.status == 'CLOSE_WAIT': c += 1
            elif conn.status == 'TIME_WAIT':  t += 1
    except Exception as e:
        print(f"[monitor] psutil error: {e}")
    return s, c, t

def compute_cts(s, c, t):
    nas = (s + 0.5*c + 0.25*t) / THREAT_NORM
    cts = THREAT_BASELINE + (1.0 - THREAT_BASELINE) * nas
    return min(1.0, cts), nas

def threat_level(cts):
    if cts < 0.30: return "Low", 1
    if cts < 0.55: return "Medium", 2
    if cts < 0.80: return "High", 3
    return "Extremely High", 4

def main():
    ap = argparse.ArgumentParser(description="SYN_RECV monitor for the cluster head")
    ap.add_argument("--duration", type=int, default=60, help="Seconds to monitor")
    ap.add_argument("--interval", type=float, default=1.0, help="Sample interval (s)")
    ap.add_argument("--log-file", default="syn_monitor.log")
    args = ap.parse_args()

    fh = open(args.log_file, "a", buffering=1)
    print("═" * 60)
    print("  SYN_RECV MONITOR — sampling this host's socket states")
    print(f"  Duration: {args.duration}s   Interval: {args.interval}s")
    print(f"  Logging to: {args.log_file}")
    print("═" * 60)
    print(f"  {'time':>6} {'SYN':>5} {'CW':>5} {'TW':>5} {'NAS':>7} {'CTS':>7}  Threat")
    print("─" * 60)

    start = time.time()
    peak_cts = 0.0
    peak_syn = 0
    try:
        while time.time() - start < args.duration:
            s, c, t = sample_sockets()
            cts, nas = compute_cts(s, c, t)
            level, stars = threat_level(cts)
            elapsed = time.time() - start
            peak_cts = max(peak_cts, cts)
            peak_syn = max(peak_syn, s)

            print(f"  {elapsed:6.1f} {s:5d} {c:5d} {t:5d} "
                  f"{nas:7.3f} {cts:7.3f}  {level} ({stars}★)")

            fh.write(json.dumps({
                "ts": time.time(), "event": "syn_sample",
                "elapsed": round(elapsed, 1),
                "syn_recv": s, "close_wait": c, "time_wait": t,
                "nas": round(nas, 4), "cts": round(cts, 4),
                "threat_level": level, "threat_stars": stars,
            }) + "\n")

            time.sleep(args.interval)
    except KeyboardInterrupt:
        print("\n  Interrupted.")

    fh.close()
    print("─" * 60)
    print(f"  Peak SYN_RECV: {peak_syn}   Peak CTS: {peak_cts:.3f}")
    print(f"  Data saved to {args.log_file}")

if __name__ == "__main__":
    main()
