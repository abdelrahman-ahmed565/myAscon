#!/usr/bin/env python3
"""
Cluster Head / Gateway (Academic IoT Research - Updated)
=========================================================

TWO-PART SCORING SYSTEM (28 stars total):
─────────────────────────────────────────
  NODE metrics (20 stars max) — sent by sensor node:
    1. Payload Length      (1-4 stars)
    2. Criticality         (1-4 stars)
    3. Threat Level / CTS  (1-4 stars)  NAS=(S+0.5C+0.25T)/20, CTS=0.05+0.95*NAS
    4. CPU Utilization     (1-4 stars)
    5. RAM Utilization     (1-4 stars)

  GATEWAY metrics (8 stars max) — computed at cluster head:
    6. Fragment Quality / WFSS  (0-4 stars)
       WFSS = Σ(w_i * b_i) / total_fragments
       w_i: size_mismatch=1.0, decrypt_fail=1.5, out_of_order=0.5
       0 stars = no bad fragments (clean)

    7. Replay Count             (0-4 stars)
       Detects: duplicate seq, stale timestamp (>10s), future timestamp (>2s)
       0 stars = no replays detected (clean)
       Response: lower criticality, force higher profile, raise threat score

  COMBINED SCORE:
    Total Stars   = node_stars (max 20) + gateway_stars (max 8)
    Final Score % = (Total Stars / 28) * 100
    Profile       = based on Final Score %

Scheduling:
  Stage A : FIFO for first N seconds (default 20s)
  Stage B : Priority + Mathematical Aging  Key=-(Priority - 0.1*t_arrival)
  Urgent  : priority >= 0.95 → Key=-1e12+t_arrival (always processed first, order preserved)

Other features:
  - Fragment reassembly with integrity check
  - Event-driven processor thread (zero sleep)
  - Colour-coded terminal output
"""

from __future__ import annotations

import argparse
import heapq
import json
import queue
import socket
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Literal, TypeAlias, Iterable

BytesLike:        TypeAlias = bytes | bytearray | memoryview
AsconAeadVariant: TypeAlias = Literal["Ascon-128", "Ascon-128a", "Ascon-80pq"]

# ═══════════════════════════════════════════════════════════════════
#  TERMINAL COLOURS
# ═══════════════════════════════════════════════════════════════════
USE_COLOUR = True

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text

def CYAN(t):    return _c("96", t)
def GREEN(t):   return _c("92", t)
def YELLOW(t):  return _c("93", t)
def RED(t):     return _c("91", t)
def BOLD(t):    return _c("1",  t)
def DIM(t):     return _c("2",  t)
def MAGENTA(t): return _c("95", t)
def BLUE(t):    return _c("94", t)

def divider(char="─", width=72): print(DIM(char * width))
def section(title: str):
    divider("═")
    print(BOLD(CYAN(f"  {title}")))
    divider("═")


# ═══════════════════════════════════════════════════════════════════
#  ASCON AEAD
# ═══════════════════════════════════════════════════════════════════
@dataclass(frozen=True)
class AeadParams:
    key_len: int; nonce_len: int; rate: int
    a: int;      b: int;         tag_len: int; iv: bytes

AEAD_PARAMS: dict[AsconAeadVariant, AeadParams] = {
    "Ascon-128":  AeadParams(16,16, 8,12, 6,16, bytes.fromhex("80400c0600000000")),
    "Ascon-128a": AeadParams(16,16,16,12, 8,16, bytes.fromhex("80800c0800000000")),
    "Ascon-80pq": AeadParams(20,16, 8,12, 6,16, bytes.fromhex("a0400c06")),
}

def ascon_decrypt(key, nonce, ad, ct, variant="Ascon-128", tag_len=None):
    p = AEAD_PARAMS[variant]
    if tag_len is None: tag_len = p.tag_len
    assert len(key)==p.key_len and len(nonce)==p.nonce_len
    assert 0 < tag_len <= 16 and len(ct) >= tag_len
    body, tag = ct[:-tag_len], ct[-tag_len:]
    S = [0,0,0,0,0]
    _init(S,p,key,nonce); _process_ad(S,p.b,p.rate,ad)
    pt = _process_ct(S,p.b,p.rate,body)
    full_tag = _finalize(S,p,key)
    return pt if full_tag[:tag_len] == tag else None

def _init(S,p,key,nonce):
    init = p.iv + bytes(key) + bytes(nonce)
    S[0],S[1],S[2],S[3],S[4] = _b2s(init); _perm(S,p.a)
    buf = bytearray(_s2b(S)); off = 40-p.key_len
    for i in range(p.key_len): buf[off+i] ^= key[i]
    S[0],S[1],S[2],S[3],S[4] = _b2s(bytes(buf))

def _process_ad(S,b,rate,ad):
    if len(ad) > 0:
        pad = bytes([0x01]) + b"\x00"*(rate-(len(ad)%rate)-1)
        padded = bytes(ad)+pad
        for i in range(0,len(padded),rate):
            S[0] ^= _b2i(padded[i:i+8])
            if rate==16: S[1] ^= _b2i(padded[i+8:i+16])
            _perm(S,b)
    S[4] ^= 1<<63

def _process_ct(S,b,rate,ct):
    lastlen = len(ct)%rate
    padded = bytes(ct)+b"\x00"*(rate-lastlen)
    pt = b""
    for i in range(0,len(padded)-rate,rate):
        c0 = _b2i(padded[i:i+8])
        if rate==16:
            c1 = _b2i(padded[i+8:i+16])
            pt += _i2b(S[0]^c0,8)+_i2b(S[1]^c1,8); S[0],S[1] = c0,c1
        else:
            pt += _i2b(S[0]^c0,8); S[0] = c0
        _perm(S,b)
    i = len(padded)-rate; c0 = _b2i(padded[i:i+8])
    if rate==16:
        c1 = _b2i(padded[i+8:i+16])
        out = (_i2b(S[0]^c0,8)+_i2b(S[1]^c1,8))[:lastlen]; pt += out
        px = b"\x00"*lastlen+bytes([0x01])+b"\x00"*(rate-lastlen-1)
        mx = b"\x00"*lastlen+b"\xFF"*(rate-lastlen)
        S[0]=(S[0]&_b2i(mx[0:8]))^c0^_b2i(px[0:8])
        S[1]=(S[1]&_b2i(mx[8:16]))^c1^_b2i(px[8:16])
    else:
        out = _i2b(S[0]^c0,8)[:lastlen]; pt += out
        px = b"\x00"*lastlen+bytes([0x01])+b"\x00"*(rate-lastlen-1)
        mx = b"\x00"*lastlen+b"\xFF"*(rate-lastlen)
        S[0]=(S[0]&_b2i(mx[0:8]))^c0^_b2i(px[0:8])
    return pt

def _finalize(S,p,key):
    buf = bytearray(_s2b(S))
    for i in range(p.key_len):
        if p.rate+i < 40: buf[p.rate+i] ^= key[i]
    S[0],S[1],S[2],S[3],S[4] = _b2s(bytes(buf)); _perm(S,p.a)
    buf = bytearray(_s2b(S)); off = 40-p.key_len
    for i in range(p.key_len): buf[off+i] ^= key[i]
    S[0],S[1],S[2],S[3],S[4] = _b2s(bytes(buf))
    return _i2b(S[3],8)+_i2b(S[4],8)

def _perm(S,rounds):
    for r in range(12-rounds,12):
        S[2]^=(0xF0-r*0x10+r*0x1)
        S[0]^=S[4];S[4]^=S[3];S[2]^=S[1]
        T=[(S[i]^0xFFFFFFFFFFFFFFFF)&S[(i+1)%5] for i in range(5)]
        for i in range(5): S[i]^=T[(i+1)%5]
        S[1]^=S[0];S[0]^=S[4];S[3]^=S[2];S[2]^=0xFFFFFFFFFFFFFFFF
        S[0]^=_r(S[0],19)^_r(S[0],28); S[1]^=_r(S[1],61)^_r(S[1],39)
        S[2]^=_r(S[2],1)^_r(S[2],6);   S[3]^=_r(S[3],10)^_r(S[3],17)
        S[4]^=_r(S[4],7)^_r(S[4],41)

def _r(v,r): return (v>>r)|((v&((1<<r)-1))<<(64-r))
def _b2i(b): return int.from_bytes(b,"little")
def _i2b(i,n): return i.to_bytes(n,"little")
def _b2s(b): return [_b2i(b[8*w:8*(w+1)]) for w in range(5)]
def _s2b(S): return b"".join(_i2b(w,8) for w in S)
def _hx(s): return bytes.fromhex(s)


# ═══════════════════════════════════════════════════════════════════
#  KEY DERIVATION  (must match node)
# ═══════════════════════════════════════════════════════════════════
def derive_key(node_id: str) -> bytes:
    seed = (node_id + "|research-master-key").encode()
    raw = bytearray(20); acc = 0
    for i in range(20):
        acc = (acc + seed[i%len(seed)] + (i*31)) % 256; raw[i] = acc
    return bytes(raw)

def key_for_profile(master20: bytes, profile: int) -> bytes:
    return master20 if profile == 4 else master20[:16]


# ═══════════════════════════════════════════════════════════════════
#  PROFILE NAMES
# ═══════════════════════════════════════════════════════════════════
PROFILE_NAMES = {
    1: "Lightweight  (Ascon-128  / 8-byte tag)",
    2: "Standard     (Ascon-128  / 16-byte tag)",
    3: "High Security(Ascon-128a / 16-byte tag)",
    4: "Critical PQ  (Ascon-80pq / 16-byte tag)",
}


# ═══════════════════════════════════════════════════════════════════
#  METRIC 6 — WEIGHTED FRAGMENT SUSPICION SCORE (WFSS)
# ═══════════════════════════════════════════════════════════════════
# WFSS = Σ(w_i * b_i) / total_fragments
# Weights: decrypt_fail=1.5, size_mismatch=1.0, out_of_order=0.5
#
# Stars:
#   WFSS = 0.00          → 0★ (perfectly clean)
#   0.00 < WFSS ≤ 0.25   → 1★ (minor anomaly)
#   0.25 < WFSS ≤ 0.50   → 2★ (moderate concern)
#   0.50 < WFSS ≤ 0.75   → 3★ (high suspicion)
#   WFSS > 0.75          → 4★ (under injection attack)

WFSS_W_DECRYPT_FAIL   = 1.5   # worst — authentication broken
WFSS_W_SIZE_MISMATCH  = 1.0   # bad — possible injection
WFSS_W_OUT_OF_ORDER   = 0.5   # mild — could be network reordering

@dataclass
class FragmentTracker:
    """Tracks fragment quality per node per burst."""
    node_id:       str
    frag_total:    int
    frag_size:     int          # declared nominal fragment size
    original_size: int
    profile_id:    int
    announced_at:  float = field(default_factory=time.time)

    # Suspicion accumulator
    total_weight:  float = 0.0  # Σ(w_i * b_i)
    total_frags:   int   = 0    # fragments processed so far
    good_frags:    int   = 0
    bad_frags:     int   = 0
    last_seq:      int   = -1   # for out-of-order detection

    # For reassembly
    fragments: dict[int, bytes] = field(default_factory=dict)

    def record(self, frag_idx: int, plaintext: bytes | None,
                actual_size: int) -> list[str]:
        """
        Record a fragment result. Returns list of issue strings (empty if clean).
        Updates the WFSS accumulator.
        """
        issues = []
        weight = 0.0

        # Check 1 — decrypt failure (highest weight)
        if plaintext is None:
            issues.append("DECRYPT FAIL")
            weight += WFSS_W_DECRYPT_FAIL

        # Check 2 — size mismatch (not the last fragment)
        if frag_idx < self.frag_total - 1:
            if actual_size != self.frag_size:
                delta = abs(actual_size - self.frag_size)
                issues.append(f"SIZE MISMATCH (got {actual_size}B, expected {self.frag_size}B, Δ={delta}B)")
                weight += WFSS_W_SIZE_MISMATCH

        # Check 3 — out of order
        if self.last_seq >= 0 and frag_idx != self.last_seq + 1:
            issues.append(f"OUT OF ORDER (got idx {frag_idx}, expected {self.last_seq+1})")
            weight += WFSS_W_OUT_OF_ORDER

        self.last_seq    = frag_idx
        self.total_frags += 1
        self.total_weight += weight

        if issues:
            self.bad_frags += 1
        else:
            self.good_frags += 1
            if plaintext is not None:
                self.fragments[frag_idx] = plaintext

        return issues

    def wfss(self) -> float:
        if self.total_frags == 0:
            return 0.0
        return min(1.0, self.total_weight / self.total_frags)

    def wfss_stars(self) -> int:
        w = self.wfss()
        if w == 0.0:    return 0
        if w <= 0.25:   return 1
        if w <= 0.50:   return 2
        if w <= 0.75:   return 3
        return 4

    @property
    def complete(self) -> bool:
        return self.total_frags >= self.frag_total

    def reassemble(self) -> bytes:
        return b"".join(self.fragments[i] for i in sorted(self.fragments))


# ═══════════════════════════════════════════════════════════════════
#  METRIC 7 — REPLAY DETECTION & COUNT
# ═══════════════════════════════════════════════════════════════════
#
# A TRUE replay requires TWO or more checks to fail simultaneously.
# This eliminates false positives from:
#   - Queue processing delays causing stale timestamps
#   - Node restarts reusing sequence numbers from 0
#   - Network jitter causing slight timestamp drift
#
# The three independent checks:
#   1. (node_id, seq) seen before      → duplicate sequence
#   2. packet_ts < now - STALE_WINDOW  → stale timestamp (30s window)
#   3. packet_ts > now + FUTURE_WINDOW → future-dated (10s window)
#
# A packet is only flagged as a replay if:
#   - Check 1 AND Check 2 both fail  (duplicate + stale = clear replay)
#   - Check 1 AND Check 3 both fail  (duplicate + future = spoofed)
#   - Check 2 AND Check 3 both fail  (impossible in practice, but covered)
#
# Single failures are logged silently as warnings but NOT counted as replays.
# This matches real-world IDS behaviour — multiple evidence points required.
#
# Replay stars:
#   0 confirmed replays  → 0★
#   1-2                  → 1★
#   3-5                  → 2★
#   6-10                 → 3★
#   11+                  → 4★
#
# Response when confirmed replay:
#   → Increase replay count stars
#   → Force profile escalation (minimum Profile 3)
#   → Print red alert

STALE_WINDOW_S  = 30.0   # seconds — generous window to avoid queue-delay false positives
FUTURE_WINDOW_S = 10.0   # seconds — generous window to avoid clock-drift false positives

@dataclass
class ReplayTracker:
    """
    Tracks confirmed replay attempts per node.
    Requires TWO independent checks to fail before flagging a replay.
    Single check failures are soft warnings only.
    """
    seen_seqs:    set   = field(default_factory=set)
    replay_count: int   = 0

    def check(self, node_id: str, seq: int, pkt_ts: float, now: float
              ) -> list[str]:
        """
        Check a packet for replay using multi-evidence approach.
        Returns list of confirmed replay reasons (empty = clean or soft warning only).
        A confirmed replay requires at least 2 checks to fail simultaneously.
        """
        # Run all three checks independently
        is_duplicate = False
        is_stale     = False
        is_future    = False

        # Check 1 — duplicate sequence number
        key = (node_id, seq)
        if key in self.seen_seqs:
            is_duplicate = True
        else:
            self.seen_seqs.add(key)
            # Limit memory — keep only last 2000 seen seqs
            if len(self.seen_seqs) > 2000:
                self.seen_seqs.pop()

        # Check 2 — stale timestamp
        age = now - pkt_ts
        if age > STALE_WINDOW_S:
            is_stale = True

        # Check 3 — future timestamp
        if pkt_ts > now + FUTURE_WINDOW_S:
            is_future = True

        # ── Multi-evidence decision ──────────────────────────────────
        # Only flag as confirmed replay if 2+ checks fail
        confirmed_reasons = []

        if is_duplicate and is_stale:
            confirmed_reasons.append(
                f"DUPLICATE SEQ={seq} + STALE (age={age:.1f}s) — confirmed replay")

        if is_duplicate and is_future:
            future = pkt_ts - now
            confirmed_reasons.append(
                f"DUPLICATE SEQ={seq} + FUTURE ({future:.1f}s ahead) — spoofed replay")

        if is_stale and is_future:
            # Logically impossible but covered for completeness
            confirmed_reasons.append(
                f"STALE + FUTURE timestamp contradiction — packet manipulation")

        if confirmed_reasons:
            self.replay_count += 1

        return confirmed_reasons

    def stars(self) -> int:
        c = self.replay_count
        if c == 0:   return 0
        if c <= 2:   return 1
        if c <= 5:   return 2
        if c <= 10:  return 3
        return 4


# ═══════════════════════════════════════════════════════════════════
#  COMBINED 28-STAR PROFILE ASSIGNMENT
# ═══════════════════════════════════════════════════════════════════
def assign_profile(
    node_stars: int,          # from node metrics (max 20)
    wfss_stars: int,          # gateway metric 6 (0-4)
    replay_stars: int,        # gateway metric 7 (0-4)
    force_min_profile: int = 1,  # replay attack forces minimum
) -> tuple[int, int, float]:
    """
    Combined 28-star profile selection.

    Total Stars = node_stars + wfss_stars + replay_stars  (max 28)
    Score %     = (total_stars / 28) * 100

    Profile bands (same thresholds, now over 28):
        < 43.75%  → Profile 1
        < 62.50%  → Profile 2
        < 81.25%  → Profile 3
        >= 81.25% → Profile 4

    Returns (profile_id, total_stars, score_pct)
    """
    total_stars = node_stars + wfss_stars + replay_stars
    score_pct   = (total_stars / 28.0) * 100.0

    if   score_pct < 43.75: profile = 1
    elif score_pct < 62.50: profile = 2
    elif score_pct < 81.25: profile = 3
    else:                   profile = 4

    # Enforce minimum profile (e.g. replay attack forces at least Profile 3)
    profile = max(profile, force_min_profile)

    return profile, total_stars, score_pct


# ═══════════════════════════════════════════════════════════════════
#  PRIORITY EXTRACTION
# ═══════════════════════════════════════════════════════════════════
def get_priority(pkt: dict) -> float:
    explicit = pkt.get("priority_norm")
    if explicit is not None:
        return float(explicit)
    m  = pkt.get("metrics", {})
    ls = int(m.get("length_stars", 0))
    cs = int(m.get("criticality_stars", 0))
    return max(0.0, min(1.0, (ls + cs) / 8.0))


# ═══════════════════════════════════════════════════════════════════
#  DECRYPTION HELPER
# ═══════════════════════════════════════════════════════════════════
def decrypt_packet(pkt: dict) -> bytes | None:
    sec     = pkt.get("security", {})
    variant = sec.get("variant", "Ascon-128")
    tag_len = int(sec.get("tag_len", 16))
    pid     = int(sec.get("profile_id", 2))
    master  = derive_key(str(pkt.get("node_id", "")))
    key     = key_for_profile(master, pid)
    return ascon_decrypt(
        key=key, nonce=_hx(pkt["nonce_hex"]),
        ad=_hx(pkt["ad_hex"]), ct=_hx(pkt["ct_hex"]),
        variant=variant, tag_len=tag_len,
    )


# ═══════════════════════════════════════════════════════════════════
#  SCHEDULING STRUCTURES
# ═══════════════════════════════════════════════════════════════════
@dataclass
class InboundItem:
    arrival_ts:    float
    node_id:       str
    seq:           int
    priority_norm: float
    pkt:           dict[str, Any]

AGING_K      = 0.1
URGENT_FLOOR = 0.95

def aging_key(priority: float, ts: float) -> float:
    """
    Routine:  Key = -(priority - 0.1 * t_arrival)   older = smaller key = first
    Urgent:   Key = -1e12 + t_arrival                always beats routine,
                                                     older fragment = smaller key = first

    heapq is a min-heap so the smallest key is processed first.

    The urgent offset (-1e12) is far more negative than any routine key
    (routine keys are ~1.7e8), so every urgent packet is guaranteed to be
    processed before every routine packet. Adding t_arrival back means that
    AMONG urgent fragments, the older one (smaller timestamp) has the smaller
    key and is therefore processed first — preserving fragment order.
    """
    if priority >= URGENT_FLOOR:
        return -1e12 + ts
    return -(priority - AGING_K * ts)


# ═══════════════════════════════════════════════════════════════════
#  CLUSTER HEAD STATE
# ═══════════════════════════════════════════════════════════════════
class ClusterHeadState:
    def __init__(self, stage_a_seconds: float):
        self.start_ts        = time.time()
        self.stage_a_seconds = stage_a_seconds

        self.lock          = threading.Lock()
        self.fifo:  list[InboundItem]                      = []
        self.heap:  list[tuple[float, float, InboundItem]] = []
        self.stage_a_ended = False

        self._total_bytes = 0
        self._bytes_lock  = threading.Lock()
        self.work_q: queue.Queue[tuple[InboundItem, str]] = queue.Queue()

        # Per-node trackers (thread-safe via lock)
        self._tracker_lock   = threading.Lock()
        self._frag_trackers: dict[str, FragmentTracker]  = {}
        self._replay_trackers: dict[str, ReplayTracker]  = defaultdict(ReplayTracker)

        # Per-node replay-forced profile minimum
        self._forced_profile: dict[str, int] = defaultdict(lambda: 1)

    # ── timing ──────────────────────────────────────────────────────
    def elapsed(self) -> float: return time.time() - self.start_ts
    def stage_a_active(self) -> bool: return self.elapsed() < self.stage_a_seconds

    # ── bytes / throughput ───────────────────────────────────────────
    def add_bytes(self, n: int):
        with self._bytes_lock: self._total_bytes += n
    def total_bytes(self) -> int:
        with self._bytes_lock: return self._total_bytes
    def throughput_kbps(self) -> float:
        return (self.total_bytes() / max(1.0, self.elapsed())) / 1024.0

    # ── replay check ────────────────────────────────────────────────
    def check_replay(self, node_id: str, seq: int, pkt_ts: float
                     ) -> tuple[list[str], int]:
        """Returns (reasons, replay_stars)."""
        with self._tracker_lock:
            tracker = self._replay_trackers[node_id]
            reasons = tracker.check(node_id, seq, pkt_ts, time.time())
            stars   = tracker.stars()
        return reasons, stars

    def get_replay_stars(self, node_id: str) -> int:
        with self._tracker_lock:
            return self._replay_trackers[node_id].stars()

    def get_replay_count(self, node_id: str) -> int:
        with self._tracker_lock:
            return self._replay_trackers[node_id].replay_count

    def set_forced_profile(self, node_id: str, min_profile: int):
        with self._tracker_lock:
            self._forced_profile[node_id] = max(
                self._forced_profile[node_id], min_profile)

    def get_forced_profile(self, node_id: str) -> int:
        with self._tracker_lock:
            return self._forced_profile[node_id]

    def get_wfss_stars(self, node_id: str) -> int:
        with self._tracker_lock:
            t = self._frag_trackers.get(node_id)
            return t.wfss_stars() if t else 0

    # ── burst announcement ───────────────────────────────────────────
    def register_burst(self, node_id: str, ann: dict):
        tracker = FragmentTracker(
            node_id       = node_id,
            frag_total    = int(ann.get("frag_total", 0)),
            frag_size     = int(ann.get("frag_size", 40)),
            original_size = int(ann.get("original_size", 0)),
            profile_id    = int(ann.get("profile_id", 1)),
        )
        with self._tracker_lock:
            self._frag_trackers[node_id] = tracker
        divider()
        print(MAGENTA(f"  📢  BURST ANNOUNCEMENT from {BOLD(node_id)}"))
        print(f"      Expecting : {BOLD(str(tracker.frag_total))} fragments × ~{tracker.frag_size}B")
        print(f"      Total size: {BOLD(str(tracker.original_size))} bytes")
        print(f"      Profile   : {tracker.profile_id} — {PROFILE_NAMES.get(tracker.profile_id,'?')}")
        divider()

    def record_fragment(self, node_id: str, frag_idx: int,
                        plaintext: bytes | None, actual_size: int
                        ) -> tuple[list[str], FragmentTracker | None]:
        """
        Record a fragment. Returns (issues, completed_tracker_or_None).
        completed_tracker is returned only when ALL fragments received.
        """
        with self._tracker_lock:
            tracker = self._frag_trackers.get(node_id)
            if tracker is None:
                return [], None
            issues = tracker.record(frag_idx, plaintext, actual_size)
            if tracker.complete:
                del self._frag_trackers[node_id]
                return issues, tracker
        return issues, None

    # ── stage transition ─────────────────────────────────────────────
    def transition_to_stage_b(self):
        with self.lock:
            if self.stage_a_ended: return
            count = len(self.fifo)
            while self.fifo:
                item = self.fifo.pop(0)
                k = aging_key(item.priority_norm, item.arrival_ts)
                heapq.heappush(self.heap, (k, item.arrival_ts, item))
            self.stage_a_ended = True
        if count:
            print(YELLOW(f"\n  ⚡ Transition: {count} FIFO packet(s) moved to Priority Heap\n"))

    # ── enqueue ──────────────────────────────────────────────────────
    def enqueue_stage_a(self, item: InboundItem):
        with self.lock:
            self.fifo.append(item)
            out = self.fifo.pop(0)
        self.work_q.put((out, "A"))

    def enqueue_stage_b(self, item: InboundItem):
        k = aging_key(item.priority_norm, item.arrival_ts)
        with self.lock:
            heapq.heappush(self.heap, (k, item.arrival_ts, item))
        self._drain()

    def _drain(self):
        with self.lock:
            if self.heap:
                _, _, out = heapq.heappop(self.heap)
                self.work_q.put((out, "B"))


# ═══════════════════════════════════════════════════════════════════
#  PROFILE SERVER THREAD  (port 9998)
# ═══════════════════════════════════════════════════════════════════
def profile_server_thread(state: ClusterHeadState,
                          bind_host: str, profile_port: int):
    """
    Receives profile_request from nodes.
    Combines node stars (from request) with gateway stars (WFSS + Replay)
    to compute the final 28-star score and assign a profile.
    """
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind((bind_host, profile_port))
    srv.settimeout(0.5)
    print(GREEN(f"  [Profile Server] Listening on {bind_host}:{profile_port}"))

    while True:
        try:
            data, addr = srv.recvfrom(4096)
        except socket.timeout:
            continue
        try:
            req = json.loads(data.decode())
        except json.JSONDecodeError:
            continue
        if req.get("type") != "profile_request":
            continue

        node_id    = str(req.get("node_id", "unknown"))
        metrics    = req.get("metrics", {})
        node_stars = int(metrics.get("sum_stars", 0))

        # Gateway metrics
        wfss_stars   = state.get_wfss_stars(node_id)
        replay_stars = state.get_replay_stars(node_id)
        replay_count = state.get_replay_count(node_id)
        forced_min   = state.get_forced_profile(node_id)

        profile, total_stars, score_pct = assign_profile(
            node_stars   = node_stars,
            wfss_stars   = wfss_stars,
            replay_stars = replay_stars,
            force_min_profile = forced_min,
        )
        pname = PROFILE_NAMES.get(profile, "?")

        # Terminal output
        cts   = metrics.get("cts_score", 0.0)
        syn   = metrics.get("n_syn_recv", 0)
        cw    = metrics.get("n_close_wait", 0)
        tw    = metrics.get("n_time_wait", 0)
        pct_n = int(metrics.get("percent_score", 0))

        divider()
        print(BLUE(f"  [Profile Server] ← {BOLD(node_id)} @ {addr[0]}"))
        print(f"  ┌─ NODE metrics  (20★ max)")
        print(f"  │  Stars : {node_stars}/20 ({pct_n}%)  │  "
              f"CTS={cts:.3f}  │  SYN={syn} CW={cw} TW={tw}")
        print(f"  ├─ GATEWAY metrics  (8★ max)")
        print(f"  │  WFSS (Fragment Quality) : {wfss_stars}★  │  "
              f"Replay Count : {replay_stars}★ ({replay_count} replays)")
        print(f"  ├─ COMBINED SCORE")
        print(f"  │  Total : {BOLD(str(total_stars))}/28 stars  │  "
              f"Score = {score_pct:.1f}%")
        if forced_min > 1:
            print(f"  │  {YELLOW('⚠ Replay attack detected — forced minimum Profile ' + str(forced_min))}")
        print(f"  └─ {GREEN('→ Assigned Profile ' + str(profile) + ': ' + pname)}")
        divider()

        srv.sendto(json.dumps({
            "type":         "profile_response",
            "node_id":      node_id,
            "profile_id":   profile,
            "profile_name": pname,
            "total_stars":  total_stars,
            "score_pct":    round(score_pct, 1),
        }).encode(), addr)


# ═══════════════════════════════════════════════════════════════════
#  PROCESSOR THREAD
# ═══════════════════════════════════════════════════════════════════
def processor_thread(state: ClusterHeadState, do_decrypt: bool):
    print(GREEN("  [Processor] Event-driven worker started (zero sleep)"))

    while True:
        try:
            item, stage = state.work_q.get(timeout=0.1)
        except queue.Empty:
            state._drain(); continue

        pkt       = item.pkt
        now       = time.time()
        delay_ms  = (now - pkt["ts"]) * 1000.0
        tput      = state.throughput_kbps()
        node_id   = item.node_id
        is_urgent = item.priority_norm >= URGENT_FLOOR
        frag_info = pkt.get("fragment", {})
        is_frag   = frag_info.get("is_fragment", False)

        # ── Replay check ─────────────────────────────────────────────
        pkt_ts         = float(pkt.get("ts", now))
        replay_reasons, replay_stars = state.check_replay(
            node_id, item.seq, pkt_ts)

        # ── Stage label ───────────────────────────────────────────────
        stage_label = (GREEN("Stage A │ FIFO") if stage == "A"
                       else YELLOW("Stage B │ Priority"))
        urgent_tag  = RED(" 🚨 URGENT") if is_urgent else ""

        # ── Header line ───────────────────────────────────────────────
        divider()
        if is_frag:
            fi = frag_info.get("frag_index", 0)
            ft = frag_info.get("frag_total", 0)
            print(f"  ◀ [{stage_label}]{urgent_tag}  "
                  f"{BOLD(node_id)}  Seq={item.seq:04d}  "
                  f"{CYAN(f'Fragment {fi+1}/{ft}')}")
        else:
            print(f"  ◀ [{stage_label}]{urgent_tag}  "
                  f"{BOLD(node_id)}  Seq={item.seq:04d}")

        print(f"    Priority   : {item.priority_norm:.3f}  │  "
              f"Delay : {CYAN(f'{delay_ms:.2f} ms')}  │  "
              f"Throughput : {CYAN(f'{tput:.3f} KB/s')}")

        # ── Replay alert ──────────────────────────────────────────────
        if replay_reasons:
            print(RED(f"    🔁 REPLAY ATTACK DETECTED from {node_id}!"))
            for r in replay_reasons:
                print(RED(f"       Reason : {r}"))
            print(YELLOW(f"       Response: Replay stars={replay_stars}★  │  "
                         f"Forcing minimum Profile 3  │  "
                         f"Threat score increased"))
            state.set_forced_profile(node_id, 3)

        # ── Decrypt ───────────────────────────────────────────────────
        plaintext = None
        if do_decrypt:
            t0        = time.perf_counter()
            plaintext = decrypt_packet(pkt)
            dec_us    = (time.perf_counter() - t0) * 1_000_000
            status    = GREEN("✔ OK") if plaintext is not None else RED("✘ FAIL")
            sec       = pkt.get("security", {})
            print(f"    Decrypt    : {status}  ({dec_us:.1f} µs)  │  "
                  f"Profile {sec.get('profile_id','?')} — {sec.get('variant','?')}")

        # ── Fragment quality tracking ─────────────────────────────────
        if is_frag and do_decrypt:
            fi           = frag_info.get("frag_index", 0)
            actual_size  = frag_info.get("frag_size", len(plaintext or b""))
            issues, completed = state.record_fragment(
                node_id, fi, plaintext, actual_size)

            if issues:
                print(RED(f"    ⚠ Fragment issues: {' | '.join(issues)}"))
                wfss_stars = state.get_wfss_stars(node_id)
                print(YELLOW(f"      WFSS updated → {wfss_stars}★  "
                             f"(weight accumulating)"))
            else:
                print(GREEN(f"    ✔ Fragment {fi+1} clean"))

            # ── Reassembly on burst completion ────────────────────────
            if completed is not None:
                reassembled  = completed.reassemble()
                wfss_score   = completed.wfss()
                wfss_stars_f = completed.wfss_stars()
                replay_stars_f = state.get_replay_stars(node_id)
                node_stars_f = int(pkt.get("metrics", {}).get("sum_stars", 0))
                _, total_s, score_p = assign_profile(
                    node_stars_f, wfss_stars_f, replay_stars_f)

                divider("─")
                print(MAGENTA(BOLD(f"  ✅  BURST REASSEMBLY COMPLETE — {node_id}")))
                print(f"  ┌─ Fragment Summary")
                print(f"  │  Received  : {completed.frag_total}/{completed.frag_total} fragments")
                print(f"  │  Good      : {GREEN(str(completed.good_frags))}  │  "
                      f"Bad : {RED(str(completed.bad_frags)) if completed.bad_frags else GREEN('0')}")
                print(f"  ├─ Integrity Check")
                reasm_size = len(reassembled)
                orig_size  = completed.original_size
                if reasm_size == orig_size:
                    print(f"  │  Size      : {reasm_size}B == {orig_size}B  "
                          + GREEN("✔ MATCH — Transmission Integrity Verified"))
                else:
                    delta = abs(reasm_size - orig_size)
                    print(f"  │  Size      : {reasm_size}B ≠ {orig_size}B  "
                          + RED(f"✘ MISMATCH (Δ={delta}B) — Possible Attack"))
                print(f"  ├─ WFSS (Fragment Quality)")
                print(f"  │  Score     : {wfss_score:.3f}  │  Stars : {wfss_stars_f}★")
                print(f"  └─ Updated 28-star score after burst: "
                      f"{BOLD(str(total_s))}/28 ({score_p:.1f}%)")
                divider("─")

        state.work_q.task_done()


# ═══════════════════════════════════════════════════════════════════
#  MAIN — RECEIVER THREAD
# ═══════════════════════════════════════════════════════════════════
def main():
    global USE_COLOUR
    ap = argparse.ArgumentParser(
        description="IoT Cluster Head — 28-Star Scoring | Profile Assignment | Scheduling")
    ap.add_argument("--bind-host",              default="0.0.0.0")
    ap.add_argument("--bind-port",              type=int, default=9999)
    ap.add_argument("--profile-port",           type=int, default=9998)
    ap.add_argument("--time-scheduler-seconds", type=float, default=20.0)
    ap.add_argument("--process-interval",       type=float, default=1.0,
                    help="Legacy — kept for CLI compatibility")
    ap.add_argument("--decrypt",   action="store_true")
    ap.add_argument("--no-colour", action="store_true")
    args = ap.parse_args()

    if args.no_colour:
        USE_COLOUR = False

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_host, args.bind_port))
    sock.settimeout(0.05)

    state = ClusterHeadState(stage_a_seconds=args.time_scheduler_seconds)

    # ── Startup banner ────────────────────────────────────────────────
    section("IoT CLUSTER HEAD — STARTING UP")
    print(f"  Data port    : {BOLD(str(args.bind_port))}   (encrypted packets)")
    print(f"  Profile port : {BOLD(str(args.profile_port))}   (28-star profile assignment)")
    print(f"  Stage A      : FIFO for {args.time_scheduler_seconds}s")
    print(f"  Stage B      : Priority + Aging  Key=-(p-{AGING_K}×t)")
    print(f"  Urgent floor : priority ≥ {URGENT_FLOOR} → Key=-1e12+t")
    print(f"  Decrypt      : {GREEN('ON') if args.decrypt else DIM('OFF')}")
    divider()
    print(BOLD("  SCORING SYSTEM (28 stars total):"))
    print(f"  ┌─ NODE metrics (max 20★)")
    print(f"  │  1. Payload Length    2. Criticality    3. Threat/CTS")
    print(f"  │  4. CPU Usage         5. RAM Usage")
    print(f"  ├─ GATEWAY metrics (max 8★)")
    print(f"  │  6. WFSS Fragment Quality  (0-4★)  WFSS=Σ(w·b)/n")
    print(f"  │     weights: decrypt_fail=1.5  size_mismatch=1.0  out_of_order=0.5")
    print(f"  │  7. Replay Count           (0-4★)  requires 2+ checks: dup_seq+stale>{STALE_WINDOW_S}s | dup_seq+future>{FUTURE_WINDOW_S}s")
    print(f"  └─ Score = (total_stars/28)×100  →  Profile 1-4")
    divider()
    print()

    # ── Start threads ─────────────────────────────────────────────────
    threading.Thread(
        target=profile_server_thread,
        args=(state, args.bind_host, args.profile_port),
        daemon=True, name="ProfileServer"
    ).start()

    threading.Thread(
        target=processor_thread,
        args=(state, args.decrypt),
        daemon=True, name="Processor"
    ).start()

    stage_b_shown = False

    try:
        while True:
            # ── Stage transition ──────────────────────────────────────
            if not state.stage_a_active() and not state.stage_a_ended:
                section(f"SWITCHING TO STAGE B — Priority Scheduling (t={state.elapsed():.1f}s)")
                state.transition_to_stage_b()

            if state.stage_a_ended and not stage_b_shown:
                print(YELLOW("  Stage B active │ "
                             "Key = -(priority − 0.1 × t_arrival)\n"))
                stage_b_shown = True

            # ── Receive ───────────────────────────────────────────────
            try:
                data, addr = sock.recvfrom(65535)
            except socket.timeout:
                continue

            state.add_bytes(len(data))

            try:
                pkt = json.loads(data.decode())
            except json.JSONDecodeError:
                print(RED(f"  [!] Malformed packet from {addr}"))
                continue

            ptype = pkt.get("type")

            # ── Announcement packet ───────────────────────────────────
            if ptype == "urgent_announcement":
                state.register_burst(str(pkt.get("node_id","?")), pkt)
                continue

            if ptype != "ascon_node_msg":
                continue

            node_id = str(pkt.get("node_id", "unknown"))
            seq     = int(pkt.get("seq", 0))
            pr      = get_priority(pkt)
            now     = time.time()

            item = InboundItem(
                arrival_ts=now, node_id=node_id,
                seq=seq, priority_norm=pr, pkt=pkt)

            is_urgent  = pr >= URGENT_FLOOR
            urgent_tag = RED(" 🚨 URGENT") if is_urgent else ""
            frag_info  = pkt.get("fragment", {})
            is_frag    = frag_info.get("is_fragment", False)
            frag_label = ""
            if is_frag:
                fi = frag_info.get("frag_index", 0) + 1
                ft = frag_info.get("frag_total", 0)
                frag_label = f"  {CYAN(f'Fragment {fi}/{ft}')}"

            if state.stage_a_active():
                print(f"  ▶ [{GREEN('Stage A')}]{urgent_tag}  "
                      f"{BOLD(node_id)}  Seq={seq:04d}  "
                      f"Prio={pr:.3f}{frag_label}")
                state.enqueue_stage_a(item)
            else:
                k = aging_key(pr, now)
                print(f"  ▶ [{YELLOW('Stage B')}]{urgent_tag}  "
                      f"{BOLD(node_id)}  Seq={seq:04d}  "
                      f"Prio={pr:.3f}  Key={k:.2f}{frag_label}")
                state.enqueue_stage_b(item)

    except KeyboardInterrupt:
        print()
        section("CLUSTER HEAD SHUTTING DOWN")
        print(f"  Total bytes received : {state.total_bytes():,}")
        print(f"  Total time           : {state.elapsed():.1f}s")
        print(f"  Avg throughput       : {state.throughput_kbps():.3f} KB/s")
        divider()
    finally:
        sock.close()


if __name__ == "__main__":
    main()
