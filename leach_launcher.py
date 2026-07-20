#!/usr/bin/env python3
"""
LEACH-style Cluster Head Election Launcher
===========================================
Each node independently decides whether to become the cluster head each round
using the LEACH threshold formula, then coordinates over UDP to guarantee that
EXACTLY ONE node is the cluster head per round.

LEACH threshold:
    T(n) = P / (1 - P * (r mod (1/P)))   if node is eligible this round
    T(n) = 0                              if node already served in this cycle

Election protocol (per round):
    1. Each node rolls random number; if < T(n), it self-elects as candidate.
    2. All candidates broadcast their claim (with priority = lower IP wins).
    3. Every node listens for a fixed window and resolves the winner
       deterministically (lowest IP among candidates).
    4. If NO candidate appears, the lowest-IP node becomes gateway (fallback).
    5. Winner runs gateway_sink.py; everyone else runs node_ascon_sender.py.

Ports:
    9999 = encrypted data      (gateway_sink / node_ascon_sender)
    9998 = profile assignment  (gateway_sink / node_ascon_sender)
    9997 = LEACH election      (this launcher)
"""

from __future__ import annotations
import argparse
import json
import os
import random
import signal
import socket
import subprocess
import sys
import time

# ── Colours ──────────────────────────────────────────────────────────
def _c(code, t): return f"\033[{code}m{t}\033[0m"
def CYAN(t):   return _c("96", t)
def GREEN(t):  return _c("92", t)
def YELLOW(t): return _c("93", t)
def RED(t):    return _c("91", t)
def BOLD(t):   return _c("1",  t)
def DIM(t):    return _c("2",  t)
def MAGENTA(t):return _c("95", t)

def banner(text, colour=CYAN):
    line = "═" * 60
    print(colour(line))
    print(colour(BOLD(f"  {text}")))
    print(colour(line))


ELECTION_PORT = 9997


def ip_priority(ip: str) -> int:
    """Lower IP = higher priority (smaller number wins).
    Convert dotted IP to an integer for comparison."""
    parts = ip.strip().split(".")
    return sum(int(p) << (8 * (3 - i)) for i, p in enumerate(parts))


def leach_threshold(P: float, round_num: int, served_recently: bool) -> float:
    """
    LEACH threshold T(n).
    P              = desired cluster-head probability (e.g. 0.5 for 2 nodes)
    round_num      = current round index (0-based)
    served_recently= True if this node was CH within the current 1/P cycle
    """
    if served_recently:
        return 0.0
    cycle = int(round(1.0 / P))
    r_mod = round_num % cycle
    denom = 1.0 - P * r_mod
    if denom <= 0:
        return 1.0   # guarantee election near end of cycle
    return P / denom


def run_election(my_id: str, my_ip: str, peers: list[str],
                 P: float, round_num: int, served_recently: bool,
                 election_window: float = 3.0) -> str:
    """
    Returns the IP of the node that should be the gateway this round.
    All nodes running the same election converge on the same winner IP,
    so every node knows exactly who the cluster head is.
    """
    my_prio = ip_priority(my_ip)

    # ── Step 1: LEACH self-election roll ──────────────────────────────
    T = leach_threshold(P, round_num, served_recently)
    roll = random.random()
    self_elected = roll < T

    print(DIM(f"  [LEACH] Round {round_num} │ T(n)={T:.3f} │ roll={roll:.3f} │ "
              f"{'SELF-ELECTED candidate' if self_elected else 'not a candidate'}"
              f"{' (served recently, T=0)' if served_recently else ''}"))

    # ── Step 2: open election socket ──────────────────────────────────
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", ELECTION_PORT))
    except OSError:
        time.sleep(1.0)
        try:
            sock.bind(("0.0.0.0", ELECTION_PORT))
        except OSError:
            print(RED("  [LEACH] Election port busy — using fallback winner"))
            sock.close()
            return min([my_ip] + peers, key=ip_priority)
    sock.settimeout(0.2)

    # ── Step 3: broadcast our claim repeatedly ────────────────────────
    claim = json.dumps({
        "type": "leach_claim",
        "node_id": my_id,
        "ip": my_ip,
        "priority": my_prio,
        "round": round_num,
        "candidate": self_elected,
    }).encode()

    candidates: dict[str, int] = {}
    if self_elected:
        candidates[my_ip] = my_prio

    deadline = time.time() + election_window
    last_send = 0.0

    while time.time() < deadline:
        if time.time() - last_send > 0.4:
            for peer in peers:
                try:
                    sock.sendto(claim, (peer, ELECTION_PORT))
                except Exception:
                    pass
            last_send = time.time()

        try:
            data, addr = sock.recvfrom(2048)
            msg = json.loads(data.decode())
            if msg.get("type") == "leach_claim" and msg.get("round") == round_num:
                if msg.get("candidate"):
                    candidates[msg["ip"]] = int(msg["priority"])
        except socket.timeout:
            continue
        except Exception:
            continue

    sock.close()

    # ── Step 4: resolve winner (all nodes converge on same result) ────
    all_ips = [my_ip] + peers

    if candidates:
        winner_ip = min(candidates, key=lambda ip: candidates[ip])
        reason = "lowest-IP candidate"
    else:
        winner_ip = min(all_ips, key=ip_priority)
        reason = "fallback (no candidates, lowest IP)"

    print(DIM(f"  [LEACH] Candidates: {list(candidates.keys()) or 'none'} │ "
              f"Winner: {winner_ip} ({reason})"))

    return winner_ip


def main():
    ap = argparse.ArgumentParser(description="LEACH Cluster Head Election Launcher")
    ap.add_argument("--node-id",   required=True, help="This node's ID (e.g. Pi1_Node)")
    ap.add_argument("--my-ip",     required=True, help="This node's own IP address")
    ap.add_argument("--peers",     required=True,
                    help="Comma-separated peer IPs (e.g. 10.25.96.151,10.25.96.152)")
    ap.add_argument("--P",         type=float, default=0.5,
                    help="LEACH cluster-head probability (0.5 for 2 nodes, 0.2 for 5)")
    ap.add_argument("--round-time",type=int, default=60, help="Seconds per round")
    ap.add_argument("--data-port",   type=int, default=9999)
    ap.add_argument("--profile-port",type=int, default=9998)
    ap.add_argument("--gateway-script", default="gateway_sink.py")
    ap.add_argument("--node-script",    default="node_ascon_sender.py")
    args = ap.parse_args()

    peers = [p.strip() for p in args.peers.split(",") if p.strip()]
    all_ips = [args.my_ip] + peers

    banner("LEACH CLUSTER HEAD ELECTION LAUNCHER", MAGENTA)
    print(f"  Node ID    : {BOLD(args.node_id)}")
    print(f"  My IP      : {BOLD(args.my_ip)}")
    print(f"  Peers      : {', '.join(peers)}")
    print(f"  P (CH prob): {args.P}   →  ~1 gateway per {int(round(1/args.P))} nodes")
    print(f"  Round time : {args.round_time}s")
    print(MAGENTA("═" * 60))
    print()

    round_num = 0
    # Track which rounds this node served as CH (for the 1/P exclusion cycle)
    last_served_round = -999
    cycle = int(round(1.0 / args.P))

    def cleanup(signum=None, frame=None):
        print(YELLOW("\n  [LEACH] Shutting down — freeing ports..."))
        os.system(f"sudo fuser -k {args.data_port}/udp {args.profile_port}/udp "
                  f"{ELECTION_PORT}/udp 2>/dev/null")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    while True:
        # Free ports from previous round
        os.system(f"sudo fuser -k {args.data_port}/udp {args.profile_port}/udp 2>/dev/null")
        time.sleep(1)

        # Determine if we served within the current cycle (LEACH exclusion)
        served_recently = (round_num - last_served_round) < cycle

        banner(f"ROUND {round_num} — ELECTION PHASE", CYAN)
        winner_ip = run_election(
            args.node_id, args.my_ip, peers,
            args.P, round_num, served_recently,
        )
        i_am_gateway = (winner_ip == args.my_ip)

        if i_am_gateway:
            last_served_round = round_num
            banner(f"ROUND {round_num}: I AM THE GATEWAY (Cluster Head)", GREEN)
            cmd = [
                "python3", args.gateway_script,
                "--bind-host", "0.0.0.0",
                "--bind-port", str(args.data_port),
                "--profile-port", str(args.profile_port),
                "--decrypt",
            ]
        else:
            # Every node agreed on the same winner_ip during the election,
            # so we send our data straight to the elected cluster head.
            banner(f"ROUND {round_num}: I AM A NODE → sending to {winner_ip}", YELLOW)
            cmd = [
                "python3", args.node_script,
                "--node-id", args.node_id,
                "--gateway-host", winner_ip,
                "--gateway-port", str(args.data_port),
                "--profile-port", str(args.profile_port),
                "--length-mode", "auto",
            ]

        # Run the chosen role for round_time seconds
        try:
            proc = subprocess.Popen(cmd)
            time.sleep(args.round_time)
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
        except FileNotFoundError:
            print(RED(f"  [LEACH] Script not found: {cmd[1]}"))
            time.sleep(2)

        round_num += 1
        print()


if __name__ == "__main__":
    main()
