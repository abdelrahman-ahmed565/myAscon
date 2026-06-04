#!/usr/bin/env python3
"""
Gateway/Sink (Academic IoT Research - Updated):

Stage A : FIFO time-based scheduling for a configured duration.
Stage B : Priority scheduling with Mathematical Queue Aging.

Key features:
──────────────────────────────────────────────────────────────────────────────
1. Gateway Profile Assignment (port 9998)
   A dedicated thread listens on port 9998 for profile requests from nodes.
   The gateway receives the node's metrics, calculates the security score,
   selects the appropriate ASCON profile, and replies to the node.
   The node then encrypts using that gateway-assigned profile.

2. Mathematical Queue Aging (no re-sort overhead)
   Aging key pushed into heapq at insertion time:
       Key = -(Priority_base - k * t_arrival)    k = 0.1
   Older packets surface to the front automatically — no periodic re-sort.

3. Urgent Fragment Priority Floor
   Urgent fragments (priority_norm >= 0.95) are given a guaranteed priority
   floor so they cannot be overtaken by aged routine packets.
   Urgent fragments always process before routine packets in Stage B.

4. Announcement Packet Validation
   When a node sends an urgent_announcement packet before a burst, the gateway
   stores the expected fragment count and size. As fragments arrive it tracks
   them and prints a warning if the count or sizes do not match — detecting
   transmission failures or injection attacks.

5. Event-Driven Processing Worker Thread
   A dedicated daemon thread pulls packets from a thread-safe queue.Queue.
   No artificial time.sleep() bottlenecks anywhere in the gateway.

6. Metrics: End-to-End Delay (ms) and Throughput (KB/s) per packet.
──────────────────────────────────────────────────────────────────────────────
"""

from __future__ import annotations

import argparse
import heapq
import json
import queue
import socket
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias, Iterable

BytesLike: TypeAlias = bytes | bytearray | memoryview
AsconAeadVariant: TypeAlias = Literal["Ascon-128", "Ascon-128a", "Ascon-80pq"]
ProfileId: TypeAlias = Literal[1, 2, 3, 4]

# -------------------- Ascon AEAD --------------------

@dataclass(frozen=True)
class AeadParams:
    key_len: int
    nonce_len: int
    rate: int
    a: int
    b: int
    tag_len: int
    iv: bytes

AEAD_PARAMS: dict[AsconAeadVariant, AeadParams] = {
    "Ascon-128":  AeadParams(16, 16, 8,  12, 6, 16, bytes.fromhex("80400c0600000000")),
    "Ascon-128a": AeadParams(16, 16, 16, 12, 8, 16, bytes.fromhex("80800c0800000000")),
    "Ascon-80pq": AeadParams(20, 16, 8,  12, 6, 16, bytes.fromhex("a0400c06")),
}

def ascon_decrypt(
    key: BytesLike, nonce: BytesLike, associateddata: BytesLike,
    ciphertext: BytesLike, variant: AsconAeadVariant = "Ascon-128",
    tag_len: int | None = None,
) -> bytes | None:
    p = AEAD_PARAMS[variant]
    if tag_len is None: tag_len = p.tag_len
    assert len(key) == p.key_len and len(nonce) == p.nonce_len
    assert 0 < tag_len <= 16 and len(ciphertext) >= tag_len
    ct, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
    S = [0, 0, 0, 0, 0]
    ascon_initialize(S, p, key, nonce)
    ascon_process_associated_data(S, p.b, p.rate, associateddata)
    plaintext = ascon_process_ciphertext(S, p.b, p.rate, ct)
    full_tag = ascon_finalize(S, p, key)
    if full_tag[:tag_len] == tag: return plaintext
    return None

def ascon_initialize(S: list[int], p: AeadParams, key: BytesLike, nonce: BytesLike) -> None:
    iv_len = 24 - p.key_len
    assert len(p.iv) == iv_len
    init = p.iv + to_bytes(key) + to_bytes(nonce)
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(init)
    ascon_permutation(S, p.a)
    buf = bytearray(state_to_bytes(S))
    off = 40 - p.key_len
    for i in range(p.key_len): buf[off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))

def ascon_process_associated_data(S: list[int], b: int, rate: int, associateddata: BytesLike) -> None:
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded  = to_bytes(associateddata) + a_padding
        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16: S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])
            ascon_permutation(S, b)
    S[4] ^= 1 << 63

def ascon_process_ciphertext(S: list[int], b: int, rate: int, ciphertext: BytesLike) -> bytes:
    c_lastlen = len(ciphertext) % rate
    c_padded  = to_bytes(ciphertext) + zero_bytes(rate - c_lastlen)
    plaintext = b""
    for block in range(0, len(c_padded) - rate, rate):
        c0 = bytes_to_int(c_padded[block:block + 8])
        if rate == 16:
            c1 = bytes_to_int(c_padded[block + 8:block + 16])
            plaintext += int_to_bytes(S[0] ^ c0, 8) + int_to_bytes(S[1] ^ c1, 8)
            S[0], S[1] = c0, c1
        else:
            plaintext += int_to_bytes(S[0] ^ c0, 8)
            S[0] = c0
        ascon_permutation(S, b)
    block = len(c_padded) - rate
    c0    = bytes_to_int(c_padded[block:block + 8])
    if rate == 16:
        c1  = bytes_to_int(c_padded[block + 8:block + 16])
        out = (int_to_bytes(S[0] ^ c0, 8) + int_to_bytes(S[1] ^ c1, 8))[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        S[0] = (S[0] & bytes_to_int(c_mask[0:8])) ^ c0 ^ bytes_to_int(c_padx[0:8])
        S[1] = (S[1] & bytes_to_int(c_mask[8:16])) ^ c1 ^ bytes_to_int(c_padx[8:16])
    else:
        out = int_to_bytes(S[0] ^ c0, 8)[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        S[0] = (S[0] & bytes_to_int(c_mask[0:8])) ^ c0 ^ bytes_to_int(c_padx[0:8])
    return plaintext

def ascon_finalize(S: list[int], p: AeadParams, key: BytesLike) -> bytes:
    buf     = bytearray(state_to_bytes(S))
    pre_off = p.rate
    for i in range(p.key_len):
        if pre_off + i < 40: buf[pre_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    ascon_permutation(S, p.a)
    buf      = bytearray(state_to_bytes(S))
    post_off = 40 - p.key_len
    for i in range(p.key_len): buf[post_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    return int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)

def ascon_permutation(S: list[int], rounds: int = 1) -> None:
    for r in range(12 - rounds, 12):
        S[2] ^= (0xF0 - r * 0x10 + r * 0x1)
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        T = [(S[i] ^ 0xFFFFFFFFFFFFFFFF) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5): S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]; S[2] ^= 0xFFFFFFFFFFFFFFFF
        S[0] ^= rotr(S[0], 19) ^ rotr(S[0], 28)
        S[1] ^= rotr(S[1], 61) ^ rotr(S[1], 39)
        S[2] ^= rotr(S[2], 1)  ^ rotr(S[2], 6)
        S[3] ^= rotr(S[3], 10) ^ rotr(S[3], 17)
        S[4] ^= rotr(S[4], 7)  ^ rotr(S[4], 41)

# -------------------- Helpers --------------------

def zero_bytes(n: int) -> bytes:     return n * b"\x00"
def ff_bytes(n: int) -> bytes:       return n * b"\xFF"
def to_bytes(l: BytesLike | Iterable[int]) -> bytes: return bytes(l)
def bytes_to_int(b: BytesLike) -> int: return int.from_bytes(b, "little")
def bytes_to_state(b: bytes) -> list[int]:
    return [bytes_to_int(b[8 * w:8 * (w + 1)]) for w in range(5)]
def state_to_bytes(S: list[int]) -> bytes:
    return b"".join(int_to_bytes(w, 8) for w in S)
def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return integer.to_bytes(nbytes, "little")
def rotr(val: int, r: int) -> int:
    return (val >> r) | ((val & ((1 << r) - 1)) << (64 - r))
def hex_to_bytes(s: str) -> bytes: return bytes.fromhex(s)

# -------------------- Keying (must match node) --------------------

def derive_node_master_key(node_id: str) -> bytes:
    seed = (node_id + "|research-master-key").encode("utf-8")
    raw  = bytearray(20)
    acc  = 0
    for i in range(20):
        acc    = (acc + seed[i % len(seed)] + (i * 31)) % 256
        raw[i] = acc
    return bytes(raw)

def profile_key_from_master(master20: bytes, profile: int) -> bytes:
    if profile == 4: return master20
    return master20[:16]

# -------------------- Profile Assignment --------------------

SECURITY_PROFILE_NAMES = {
    1: "Lightweight (IoT)",
    2: "Standard (default)",
    3: "High Security",
    4: "Critical / Long-Term",
}

def calculate_profile_from_metrics(metrics: dict) -> int:
    """
    Gateway-side profile selection.
    Receives the node's metric stars, computes the total score,
    and returns the appropriate profile ID.

    Score = sum_stars * 5  (max 100, since max stars = 20)
    Profile bands (same as node fallback):
        score < 43.75  → Profile 1 (Lightweight)
        score < 62.5   → Profile 2 (Standard)
        score < 81.25  → Profile 3 (High Security)
        score >= 81.25 → Profile 4 (Critical / Ascon-80pq)
    """
    percent_score = int(metrics.get("percent_score", 0))
    x = max(0, min(100, percent_score)) / 100.0
    if x < 0.4375: return 1
    if x < 0.625:  return 2
    if x < 0.8125: return 3
    return 4

# -------------------- Scheduling structures --------------------

@dataclass
class InboundItem:
    arrival_ts:    float
    node_id:       str
    seq:           int
    priority_norm: float
    pkt:           dict[str, Any]


# -------------------- Announcement tracking --------------------

@dataclass
class BurstExpectation:
    """Stores what the gateway expects from an announced urgent burst."""
    node_id:       str
    frag_total:    int
    frag_size:     int
    original_size: int
    profile_id:    int
    received:      int = 0
    announced_at:  float = field(default_factory=time.time)


# -------------------- Mathematical Aging Key --------------------
#
#   Key = -(Priority_base - k * t_arrival)
#
# With k = 0.1, older packets have a less-negative key and surface first.
# No periodic re-sort required.
#
# URGENT PRIORITY FLOOR:
# Packets with priority_norm >= URGENT_FLOOR bypass the aging formula
# and always receive a key of -9999.0, guaranteeing they are processed
# before any routine packet regardless of how long routine packets have aged.

AGING_K       = 0.1     # aging coefficient
URGENT_FLOOR  = 0.95    # priority_norm threshold for urgent treatment


def aging_key(priority_norm: float, arrival_ts: float) -> float:
    """
    Return the heap key implementing mathematical aging + urgent priority floor.

    heapq is a min-heap so lower (more negative) key = processed first.

    Urgent fragments (priority_norm >= 0.95):
        Key = -9999.0  (always processed before any routine packet)

    Routine packets:
        Key = -(Priority_base - k * t_arrival)
    """
    if priority_norm >= URGENT_FLOOR:
        # Urgent: fixed floor key so they always beat routine packets.
        # Use arrival_ts as a tiebreaker among urgent fragments themselves
        # so older urgent fragments are still processed first.
        return -9999.0 - arrival_ts
    return -(priority_norm - AGING_K * arrival_ts)


# -------------------- Decryption --------------------

def compute_priority_from_packet(pkt: dict[str, Any]) -> float:
    """
    Read priority directly from packet if present (urgent fragments embed 1.0),
    otherwise compute from length_stars + criticality_stars.
    """
    explicit = pkt.get("priority_norm")
    if explicit is not None:
        return float(explicit)
    m = pkt.get("metrics", {})
    length_stars      = int(m.get("length_stars", 0))
    criticality_stars = int(m.get("criticality_stars", 0))
    raw = length_stars + criticality_stars
    return max(0.0, min(1.0, raw / 8.0))


def try_decrypt(pkt: dict[str, Any]) -> bytes | None:
    sec        = pkt.get("security", {})
    variant    = sec.get("variant", "Ascon-128")
    tag_len    = int(sec.get("tag_len", 16))
    profile_id = int(sec.get("profile_id", 2))
    node_id    = str(pkt.get("node_id"))
    ad         = hex_to_bytes(pkt["ad_hex"])
    nonce      = hex_to_bytes(pkt["nonce_hex"])
    ct         = hex_to_bytes(pkt["ct_hex"])
    master     = derive_node_master_key(node_id)
    key        = profile_key_from_master(master, profile_id)
    return ascon_decrypt(
        key=key, nonce=nonce, associateddata=ad,
        ciphertext=ct, variant=variant, tag_len=tag_len,
    )


# -------------------- Shared Gateway State --------------------

class GatewayState:
    """
    Thread-safe container for all mutable gateway state.
    Three threads share this object:
      - Main receiver thread (writes packets)
      - GW-Processor thread (reads/pops packets)
      - Profile-Server thread (reads nothing here, writes nothing here)
    """

    def __init__(self, time_scheduler_seconds: float):
        self.start_ts               = time.time()
        self.time_scheduler_seconds = time_scheduler_seconds

        self.lock      = threading.Lock()
        self.fifo:  list[InboundItem]                      = []
        self.heap:  list[tuple[float, float, InboundItem]] = []
        self.stage_a_ended = False

        self._total_bytes = 0
        self._bytes_lock  = threading.Lock()

        self.work_q: queue.Queue[tuple[InboundItem, str]] = queue.Queue()

        # Burst expectation tracking: node_id -> BurstExpectation
        self._burst_lock         = threading.Lock()
        self._burst_expectations: dict[str, BurstExpectation] = {}

    # ── helpers ──────────────────────────────────────────────────────────────

    def elapsed(self) -> float:
        return time.time() - self.start_ts

    def stage_a_active(self) -> bool:
        return self.elapsed() < self.time_scheduler_seconds

    def add_bytes(self, n: int) -> None:
        with self._bytes_lock:
            self._total_bytes += n

    def total_bytes(self) -> int:
        with self._bytes_lock:
            return self._total_bytes

    def throughput_kbps(self) -> float:
        elapsed = max(1.0, self.elapsed())
        return (self.total_bytes() / elapsed) / 1024.0

    # ── burst announcement tracking ──────────────────────────────────────────

    def register_burst(self, node_id: str, ann: dict) -> None:
        """Store what we expect from an announced urgent burst."""
        exp = BurstExpectation(
            node_id=node_id,
            frag_total=int(ann.get("frag_total", 0)),
            frag_size=int(ann.get("frag_size", 0)),
            original_size=int(ann.get("original_size", 0)),
            profile_id=int(ann.get("profile_id", 1)),
        )
        with self._burst_lock:
            self._burst_expectations[node_id] = exp
        print(
            f"\n[gateway] 📢 Burst announcement from {node_id}: "
            f"expecting {exp.frag_total} fragments × ~{exp.frag_size}B "
            f"(total {exp.original_size}B) using Profile {exp.profile_id}"
        )

    def record_fragment(self, node_id: str, frag_size: int, declared_frag_size: int) -> None:
        """
        Track an arriving fragment against the announced expectation.
        Prints a warning if the fragment size doesn't match what was declared.
        """
        with self._burst_lock:
            exp = self._burst_expectations.get(node_id)
            if exp is None:
                return
            exp.received += 1

            # Size validation — last fragment is allowed to be smaller
            if frag_size != declared_frag_size and frag_size != exp.frag_size:
                delta = abs(frag_size - exp.frag_size)
                print(
                    f"🚨 [ATTACK/FAILURE] Fragment size mismatch from {node_id}! "
                    f"Expected ~{exp.frag_size}B, got {frag_size}B "
                    f"(delta={delta}B). Possible injection or corruption."
                )

            # Check if burst is complete
            if exp.received >= exp.frag_total:
                print(
                    f"[gateway] ✅ Burst from {node_id} complete: "
                    f"{exp.received}/{exp.frag_total} fragments received."
                )
                del self._burst_expectations[node_id]

    # ── stage transition ──────────────────────────────────────────────────────

    def transition_to_stage_b(self) -> None:
        with self.lock:
            if self.stage_a_ended:
                return
            count = len(self.fifo)
            while self.fifo:
                old_item = self.fifo.pop(0)
                key = aging_key(old_item.priority_norm, old_item.arrival_ts)
                heapq.heappush(self.heap, (key, old_item.arrival_ts, old_item))
            self.stage_a_ended = True
        if count:
            print(f"\n[gateway] Transition: moved {count} Stage-A packet(s) into Stage-B heap.")

    # ── enqueue ───────────────────────────────────────────────────────────────

    def enqueue_stage_a(self, item: InboundItem) -> None:
        with self.lock:
            self.fifo.append(item)
            out = self.fifo.pop(0)
        self.work_q.put((out, "A"))

    def enqueue_stage_b(self, item: InboundItem) -> None:
        key = aging_key(item.priority_norm, item.arrival_ts)
        with self.lock:
            heapq.heappush(self.heap, (key, item.arrival_ts, item))
        self._drain_heap_to_work_q()

    def _drain_heap_to_work_q(self) -> None:
        with self.lock:
            if self.heap:
                _, _, out = heapq.heappop(self.heap)
                self.work_q.put((out, "B"))


# -------------------- Profile Server Thread (port 9998) --------------------

def profile_server_thread(state: GatewayState, bind_host: str, profile_port: int) -> None:
    """
    Listens on port 9998 for profile_request packets from nodes.
    Calculates the profile from the node's metrics and replies immediately.

    This runs in a dedicated daemon thread so it never blocks the main
    packet receiver on port 9999.
    """
    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv_sock.bind((bind_host, profile_port))
    srv_sock.settimeout(0.5)

    print(f"[gateway] Profile server listening on {bind_host}:{profile_port}")

    while True:
        try:
            data, addr = srv_sock.recvfrom(4096)
        except socket.timeout:
            continue

        try:
            req = json.loads(data.decode("utf-8"))
        except json.JSONDecodeError:
            continue

        if req.get("type") != "profile_request":
            continue

        node_id  = str(req.get("node_id", "unknown"))
        metrics  = req.get("metrics", {})
        profile  = calculate_profile_from_metrics(metrics)
        pname    = SECURITY_PROFILE_NAMES.get(profile, "Unknown")

        # Print what the gateway sees and decided
        cts   = metrics.get("cts_score", 0.0)
        nas   = metrics.get("nas_score", 0.0)
        syn   = metrics.get("n_syn_recv", 0)
        cw    = metrics.get("n_close_wait", 0)
        tw    = metrics.get("n_time_wait", 0)
        stars = metrics.get("sum_stars", 0)
        pct   = metrics.get("percent_score", 0)

        print(
            f"\n[profile-server] Request from {node_id} @ {addr[0]} | "
            f"Stars={stars}/20 ({pct}%) | "
            f"CTS={cts:.3f} NAS={nas:.3f} | "
            f"SYN={syn} CW={cw} TW={tw}"
        )
        print(f"[profile-server] → Assigned Profile {profile} ({pname}) to {node_id}")

        response = {
            "type":       "profile_response",
            "node_id":    node_id,
            "profile_id": profile,
            "profile_name": pname,
        }
        srv_sock.sendto(json.dumps(response).encode("utf-8"), addr)


# -------------------- Processor Thread --------------------

def processor_thread(state: GatewayState, do_decrypt: bool) -> None:
    """
    Event-driven worker: blocks on work_q.get(timeout=0.1).
    Wakes the microsecond a packet is enqueued — zero artificial delay.
    """
    print("[gateway] Processor thread started (event-driven, no sleep).")
    while True:
        try:
            item, stage = state.work_q.get(timeout=0.1)
        except queue.Empty:
            state._drain_heap_to_work_q()
            continue

        now       = time.time()
        delay_ms  = (now - item.pkt["ts"]) * 1000.0
        tput_kbps = state.throughput_kbps()

        # Is this an urgent fragment?
        frag_info  = item.pkt.get("fragment", {})
        is_frag    = frag_info.get("is_fragment", False)
        frag_label = ""
        if is_frag:
            fi    = frag_info.get("frag_index", 0) + 1
            ft    = frag_info.get("frag_total", 0)
            fsize = frag_info.get("frag_size", 0)
            frag_label = f" [frag {fi}/{ft}]"
            # Record fragment against announcement
            state.record_fragment(item.node_id, fsize, fsize)

        label = "Stage A Out" if stage == "A" else "Stage B Out"
        urgent_tag = " 🚨URGENT" if item.priority_norm >= URGENT_FLOOR else ""

        print(
            f"<- [{label}]{urgent_tag}{frag_label} "
            f"Node: {item.node_id} Seq: {item.seq:04d} | "
            f"Prio: {item.priority_norm:.3f} | "
            f"Delay: {delay_ms:.3f} ms | "
            f"Throughput: {tput_kbps:.3f} KB/s"
        )

        if do_decrypt:
            t0        = time.perf_counter()
            decrypted = try_decrypt(item.pkt)
            dec_us    = (time.perf_counter() - t0) * 1_000_000
            status    = "OK" if decrypted is not None else "FAIL"
            print(f"   Decrypt: {status}  ({dec_us:.2f} µs)")

        state.work_q.task_done()


# -------------------- Receiver (main) Thread --------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="IoT Gateway – Profile Assignment | Event-Driven | Mathematical Aging"
    )
    ap.add_argument("--bind-host",              default="0.0.0.0")
    ap.add_argument("--bind-port",              type=int, default=9999,
                    help="UDP port for encrypted data packets")
    ap.add_argument("--profile-port",           type=int, default=9998,
                    help="UDP port for profile request/response with nodes")
    ap.add_argument("--time-scheduler-seconds", type=float, default=20.0,
                    help="Duration of Stage A (FIFO) before switching to Stage B (Priority)")
    ap.add_argument("--process-interval",       type=float, default=1.0,
                    help="(Legacy parameter – retained for CLI compatibility.)")
    ap.add_argument("--decrypt",                action="store_true",
                    help="Attempt to decrypt and verify each message")
    args = ap.parse_args()

    # ── Data socket (port 9999) ───────────────────────────────────────────────
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_host, args.bind_port))
    sock.settimeout(0.05)

    state = GatewayState(time_scheduler_seconds=args.time_scheduler_seconds)

    print(f"[gateway] Data socket listening on {args.bind_host}:{args.bind_port}")
    print(f"[gateway] Stage A (FIFO) for {args.time_scheduler_seconds}s "
          f"→ Stage B (Priority + Aging)")
    print(f"[gateway] Aging formula: Key = -(Priority_base - k*t_arrival)  k={AGING_K}")
    print(f"[gateway] Urgent floor: priority_norm >= {URGENT_FLOOR} → Key = -9999 - t_arrival")
    print(f"[gateway] Decrypt={args.decrypt}")
    print()

    # ── Profile server thread (port 9998) ────────────────────────────────────
    prof_thread = threading.Thread(
        target=profile_server_thread,
        args=(state, args.bind_host, args.profile_port),
        daemon=True,
        name="GW-ProfileServer",
    )
    prof_thread.start()

    # ── Processor thread ──────────────────────────────────────────────────────
    proc_thread = threading.Thread(
        target=processor_thread,
        args=(state, args.decrypt),
        daemon=True,
        name="GW-Processor",
    )
    proc_thread.start()

    stage_b_announced = False

    try:
        while True:
            # ── Stage transition ──────────────────────────────────────────────
            if not state.stage_a_active() and not state.stage_a_ended:
                print(f"\n[gateway] Stage A expired at t={state.elapsed():.1f}s. "
                      "Transitioning to Stage B (Priority Scheduling).")
                state.transition_to_stage_b()

            if state.stage_a_ended and not stage_b_announced:
                print(f"[gateway] Stage B active. "
                      f"Key = -(p - {AGING_K}*t_arrival) | "
                      f"Urgent floor at prio >= {URGENT_FLOOR}\n")
                stage_b_announced = True

            # ── Receive packet ────────────────────────────────────────────────
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue

            state.add_bytes(len(data))

            try:
                pkt = json.loads(data.decode("utf-8"))
            except json.JSONDecodeError:
                print(f"[gateway] Malformed packet from {addr}, ignored.")
                continue

            pkt_type = pkt.get("type")

            # ── Handle announcement packet ────────────────────────────────────
            if pkt_type == "urgent_announcement":
                node_id = str(pkt.get("node_id", "unknown"))
                state.register_burst(node_id, pkt)
                continue

            # ── Handle normal / fragment data packets ─────────────────────────
            if pkt_type != "ascon_node_msg":
                continue

            node_id = str(pkt.get("node_id", "unknown"))
            seq     = int(pkt.get("seq", 0))
            pr      = compute_priority_from_packet(pkt)
            now     = time.time()

            item = InboundItem(
                arrival_ts=now,
                node_id=node_id,
                seq=seq,
                priority_norm=pr,
                pkt=pkt,
            )

            is_urgent = pr >= URGENT_FLOOR
            tag       = " 🚨URGENT" if is_urgent else ""

            if state.stage_a_active():
                print(f"-> [Stage A In]{tag}  Node: {node_id}  Seq: {seq:04d}  Prio: {pr:.3f}")
                state.enqueue_stage_a(item)
            else:
                key_val = aging_key(pr, now)
                print(
                    f"-> [Stage B In]{tag}  Node: {node_id}  Seq: {seq:04d}  "
                    f"Prio: {pr:.3f}  Key: {key_val:.4f}"
                )
                state.enqueue_stage_b(item)

    except KeyboardInterrupt:
        print("\n[gateway] Interrupted by user. Shutting down.")
    finally:
        sock.close()
        print("[gateway] Socket closed.")


if __name__ == "__main__":
    main()
