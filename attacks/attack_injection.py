#!/usr/bin/env python3
"""
ATTACK 2 — Injection Attack (Threat Scenario III.B.2)
======================================================
Injects forged fragments into an ongoing fragmented (urgent burst)
transmission. The attacker sends packets with:
  (a) wrong fragment sizes, and/or
  (b) forged ciphertext without the correct pre-shared key.

The cluster head detects these via:
  - ASCON authentication failure (forged ciphertext) → WFSS decrypt_fail weight 1.5
  - Fragment size mismatch vs announcement            → WFSS size_mismatch weight 1.0
  - Reassembled size falling short of announced size  → integrity check fails

Usage:
    python3 attack_injection.py --target 10.25.96.150 --port 9999 \
            --node-id Pi2_Node --mode forged

Modes:
    forged     — send fragments with garbage ciphertext (fails ASCON auth)
    oversized  — send fragments with wrong size (size mismatch alert)
    announce   — send a fake announcement then wrong-count fragments
"""
import argparse
import json
import os
import socket
import time

def _c(code, t): return f"\033[{code}m{t}\033[0m"
def RED(t):    return _c("91", t)
def GREEN(t):  return _c("92", t)
def YELLOW(t): return _c("93", t)
def BOLD(t):   return _c("1", t)

def make_forged_fragment(node_id: str, seq: int, frag_idx: int,
                         frag_total: int, frag_size: int,
                         original_size: int, oversized: bool) -> bytes:
    """Build a forged fragment packet that will fail authentication."""
    # Garbage ciphertext — attacker does NOT have the pre-shared key
    payload_size = 80 if oversized else frag_size  # oversized triggers size mismatch
    fake_ct = os.urandom(payload_size + 16).hex()   # +16 for fake tag
    fake_nonce = os.urandom(16).hex()
    fake_ad = b"header".hex()

    pkt = {
        "type": "ascon_node_msg",
        "node_id": node_id,
        "seq": seq,
        "ts": time.time(),
        "fragment": {
            "is_fragment": True,
            "frag_index": frag_idx,
            "frag_total": frag_total,
            "frag_size": payload_size,
            "original_size": original_size,
        },
        "metrics": {
            "length_bytes": payload_size, "length_band": "Short", "length_stars": 4,
            "criticality": "Critical", "criticality_stars": 4,
            "threat": "Low", "threat_stars": 1,
            "cts_score": 0.05, "nas_score": 0.0,
            "n_syn_recv": 0, "n_close_wait": 0, "n_time_wait": 0,
            "cpu_percent": 5, "cpu_stars": 4, "ram_percent": 14, "ram_stars": 4,
            "sum_stars": 17, "percent_score": 85, "decimal_score": 0.85,
        },
        "priority_norm": 1.0,
        "priority_hint": 1.0,
        "security": {
            "profile_id": 4, "profile_name": "Critical PQ",
            "variant": "Ascon-80pq", "tag_len": 16,
        },
        "ad_hex": fake_ad,
        "nonce_hex": fake_nonce,
        "ct_hex": fake_ct,
        "energy": {"model": "forged", "power_w": 3.0, "enc_time_us": 0,
                   "energy_j": 0, "energy_uj": 0},
    }
    return json.dumps(pkt).encode()

def main():
    ap = argparse.ArgumentParser(description="Fragment Injection attack simulator")
    ap.add_argument("--target",   required=True, help="Cluster head IP")
    ap.add_argument("--port",     type=int, default=9999)
    ap.add_argument("--node-id",  default="Pi2_Node",
                    help="Node ID to impersonate")
    ap.add_argument("--mode",     default="forged",
                    choices=["forged", "oversized", "announce"],
                    help="Attack variant")
    ap.add_argument("--fragments", type=int, default=10, help="Number of forged fragments")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (args.target, args.port)

    print(RED("═" * 60))
    print(RED(BOLD("  INJECTION ATTACK — Threat Scenario 2")))
    print(RED("═" * 60))
    print(f"  Target    : {BOLD(args.target)}:{args.port}")
    print(f"  Impersona.: {BOLD(args.node_id)}")
    print(f"  Mode      : {BOLD(args.mode)}")
    print(RED("═" * 60))
    print()

    frag_total = args.fragments
    frag_size = 40
    original_size = frag_total * frag_size

    # ── Send a fake announcement first (so cluster head expects a burst) ──
    if args.mode == "announce":
        # Announce MORE fragments than we'll actually send → missing fragments
        announced_total = frag_total + 5
        announcement = {
            "type": "urgent_announcement",
            "node_id": args.node_id,
            "seq": 9000,
            "ts": time.time(),
            "frag_total": announced_total,
            "frag_size": frag_size,
            "original_size": announced_total * frag_size,
            "profile_id": 4,
            "variant": "Ascon-80pq",
            "tag_len": 16,
            "priority_norm": 1.0,
        }
        sock.sendto(json.dumps(announcement).encode(), addr)
        print(YELLOW(f"  Sent fake announcement: claims {announced_total} fragments"))
        print(YELLOW(f"  But will only send {frag_total} → missing fragment detection"))
        print()
        time.sleep(0.2)

    oversized = (args.mode == "oversized")

    for i in range(frag_total):
        pkt = make_forged_fragment(
            args.node_id, 9001 + i, i, frag_total, frag_size,
            original_size, oversized)
        sock.sendto(pkt, addr)
        size_note = "80B (oversized!)" if oversized else "40B"
        print(f"  {RED('▶')} Forged fragment {i+1}/{frag_total}  "
              f"seq={9001+i}  {size_note}  "
              + RED("garbage ciphertext (no valid key)"))
        time.sleep(0.05)

    sock.close()
    print()
    print(GREEN(f"  Injection complete. Sent {frag_total} forged fragments."))
    print(YELLOW("  On the cluster head you should have seen:"))
    if oversized:
        print(YELLOW("    • SIZE MISMATCH alerts (fragment size ≠ declared)"))
    print(YELLOW("    • Decrypt ✘ FAIL on each forged fragment (ASCON auth)"))
    print(YELLOW("    • WFSS stars rising for the impersonated node"))
    if args.mode == "announce":
        print(YELLOW("    • Reassembly size shortfall vs announced size"))

if __name__ == "__main__":
    main()
