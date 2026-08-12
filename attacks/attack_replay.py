#!/usr/bin/env python3
"""
ATTACK 3 — Packet Replay (Threat Scenario III.B.3)
===================================================
Captures a legitimate packet and replays it later unchanged. The cluster
head's Replay Count metric detects this. Per the paper, a CONFIRMED replay
requires at least TWO of these three conditions simultaneously:
  1. (node_id, seq) already seen  (duplicate)
  2. timestamp older than 30s     (stale)
  3. timestamp >10s in the future (future)

This script sends a packet, waits, then replays the SAME packet with its
OLD timestamp — triggering BOTH duplicate seq AND stale timestamp, which
is a confirmed replay (2 conditions).

Usage:
    python3 attack_replay.py --target 10.25.96.150 --port 9999 \
            --node-id Pi2_Node --replays 5
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

def make_packet(node_id: str, seq: int, ts: float) -> bytes:
    """Build a plausible-looking data packet with a specific timestamp."""
    pkt = {
        "type": "ascon_node_msg",
        "node_id": node_id,
        "seq": seq,
        "ts": ts,                       # ← attacker controls this
        "metrics": {
            "length_bytes": 40, "length_band": "Short", "length_stars": 4,
            "criticality": "Low", "criticality_stars": 1,
            "threat": "Low", "threat_stars": 1,
            "cts_score": 0.05, "nas_score": 0.0,
            "n_syn_recv": 0, "n_close_wait": 0, "n_time_wait": 0,
            "cpu_percent": 5, "cpu_stars": 4, "ram_percent": 14, "ram_stars": 4,
            "sum_stars": 11, "percent_score": 55, "decimal_score": 0.55,
        },
        "priority_norm": 0.625,
        "security": {
            "profile_id": 2, "profile_name": "Standard",
            "variant": "Ascon-128", "tag_len": 16,
        },
        "ad_hex": b"header".hex(),
        "nonce_hex": os.urandom(16).hex(),
        "ct_hex": os.urandom(56).hex(),
        "energy": {"model": "replay", "power_w": 3.0, "enc_time_us": 0,
                   "energy_j": 0, "energy_uj": 0},
    }
    return json.dumps(pkt).encode()

def main():
    ap = argparse.ArgumentParser(description="Packet Replay attack simulator")
    ap.add_argument("--target",   required=True, help="Cluster head IP")
    ap.add_argument("--port",     type=int, default=9999)
    ap.add_argument("--node-id",  default="Pi2_Node",
                    help="Node ID to impersonate")
    ap.add_argument("--replays",  type=int, default=5,
                    help="Number of confirmed replays to send")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    addr = (args.target, args.port)

    print(RED("═" * 60))
    print(RED(BOLD("  PACKET REPLAY ATTACK — Threat Scenario 3")))
    print(RED("═" * 60))
    print(f"  Target    : {BOLD(args.target)}:{args.port}")
    print(f"  Impersona.: {BOLD(args.node_id)}")
    print(f"  Replays   : {args.replays}")
    print(YELLOW("  Method    : duplicate seq + stale timestamp (2 conditions)"))
    print(RED("═" * 60))
    print()

    # Build ONE "captured" packet with an OLD timestamp (40s in the past → stale)
    captured_seq = 7777
    old_ts = time.time() - 40.0     # 40 seconds old → exceeds 30s stale window

    captured = make_packet(args.node_id, captured_seq, old_ts)

    print(YELLOW(f"  Captured packet: seq={captured_seq}, "
                 f"timestamp 40s in the past"))
    print(YELLOW(f"  Replaying it {args.replays} times (same seq + stale ts)..."))
    print()

    for i in range(args.replays):
        # Replay the EXACT same packet — same seq, same old timestamp.
        # This trips: duplicate seq (after 1st) + stale timestamp = confirmed replay
        sock.sendto(captured, addr)
        print(f"  {RED('▶')} Replay {i+1}/{args.replays}  "
              f"seq={captured_seq} (duplicate)  "
              f"ts=-40s (stale)  "
              + RED("→ 2 conditions = CONFIRMED replay"))
        time.sleep(0.4)

    sock.close()
    print()
    print(GREEN(f"  Replay attack complete. Sent {args.replays} replays."))
    print(YELLOW("  On the cluster head you should have seen:"))
    print(YELLOW("    • 🔁 REPLAY ATTACK DETECTED alerts"))
    print(YELLOW("    • Replay Count stars rising for the node"))
    print(YELLOW("    • Node forced to minimum Profile 3 for the rest of the epoch"))

if __name__ == "__main__":
    main()
