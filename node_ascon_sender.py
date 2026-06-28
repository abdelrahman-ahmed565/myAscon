#!/usr/bin/env python3
"""
Node code (Academic IoT Research - Updated):
- Generates traffic of varying lengths
- Measures 5 metrics: Length, Criticality, Threat Level, CPU, RAM
- Converts each metric to a 1..4 star score
- Sums stars (max 20), converts to percentage
- Requests security profile from Gateway (port 9998) — gateway decides profile
- Encrypts with Ascon using gateway-assigned profile
- Mathematical Energy Estimation: E = P × t
    P_current = 3.0 + (3.0 × CPU/100)   [idle=3W, max=6W]
- Sends to gateway over UDP (JSON packet, port 9999) with timestamp for Delay calculation

Threat Model (Continuous Threat Score):
    NAS = (S + 0.5*C + 0.25*T) / 20
    CTS = 0.05 + 0.95 * NAS
    Where S=SYN_RECV, C=CLOSE_WAIT, T=TIME_WAIT (from psutil)
    CTS in [0.05, 1.0] — never zero
    Levels: Low(1★) 0.05-0.30 | Medium(2★) 0.30-0.55 | High(3★) 0.55-0.80 | Extremely High(4★) 0.80-1.0

Traffic Modes (Duty Cycle):
- ROUTINE: sense → metrics → request profile from GW → small payload (~40B) → encrypt → send → sleep 2-3s
- URGENT:  metrics → request profile from GW ONCE → announcement packet → fragment 1800B into ~40B chunks
           → encrypt all with same profile → burst-send with no sleep
"""

from __future__ import annotations

import argparse
import json
import os
import random
import socket
import time
from dataclasses import dataclass
from typing import Literal, TypeAlias, Iterable

# -------------------- Terminal Colours --------------------
def _c(code, text): return f"\033[{code}m{text}\033[0m"
def CYAN(t):    return _c("96", t)
def GREEN(t):   return _c("92", t)
def YELLOW(t):  return _c("93", t)
def RED(t):     return _c("91", t)
def BOLD(t):    return _c("1",  t)
def DIM(t):     return _c("2",  t)
def MAGENTA(t): return _c("95", t)
def divider(c="─", w=70): print(DIM(c * w))

# -------------------- pyJoules (optional, not available on ARM) --------------------
try:
    from pyJoules.energy_meter import EnergyMeter
    PYJOULES_AVAILABLE = True
except ImportError:
    PYJOULES_AVAILABLE = False
    print("Warning: pyJoules not installed / not supported on this platform. "
          "Using mathematical energy model (E = P x t) instead.")

# -------------------- Types --------------------

BytesLike: TypeAlias = bytes | bytearray | memoryview
AsconAeadVariant: TypeAlias = Literal["Ascon-128", "Ascon-128a", "Ascon-80pq"]
ProfileId: TypeAlias = Literal[1, 2, 3, 4]

# -------------------- Debug --------------------

debug = False
debugpermutation = False

# -------------------- AEAD Parameters --------------------

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
    "Ascon-128":  AeadParams(16, 16, 8, 12, 6, 16, bytes.fromhex("80400c0600000000")),
    "Ascon-128a": AeadParams(16, 16, 16, 12, 8, 16, bytes.fromhex("80800c0800000000")),
    "Ascon-80pq": AeadParams(20, 16, 8, 12, 6, 16, bytes.fromhex("a0400c06")),
}

@dataclass(frozen=True)
class SecurityProfile:
    name: str
    variant: AsconAeadVariant
    tag_len: int

SECURITY_PROFILES: dict[ProfileId, SecurityProfile] = {
    1: SecurityProfile("Lightweight (IoT)", "Ascon-128", 8),
    2: SecurityProfile("Standard (default)", "Ascon-128", 16),
    3: SecurityProfile("High Security", "Ascon-128a", 16),
    4: SecurityProfile("Critical / Long-Term", "Ascon-80pq", 16),
}

# -------------------- Mathematical Energy Estimation --------------------

IDLE_POWER_W  = 3.0   # Watts at 0% CPU
MAX_POWER_W   = 6.0   # Watts at 100% CPU
POWER_RANGE_W = MAX_POWER_W - IDLE_POWER_W   # = 3.0 W

# -------------------- Traffic / Duty-Cycle Constants --------------------

ROUTINE_PAYLOAD_BYTES    = 40
ROUTINE_SLEEP_MIN_S      = 2.0
ROUTINE_SLEEP_MAX_S      = 3.0

URGENT_PAYLOAD_BYTES     = 1800
URGENT_FRAGMENT_SIZE     = 40
URGENT_PRIORITY_HINT     = 1.0
URGENT_INTER_FRAG_SLEEP  = 0.0
URGENT_EVENT_PROBABILITY = 0.15

# -------------------- Threat Model Constants --------------------
# NAS = (S + 0.5*C + 0.25*T) / THREAT_NORM
# CTS = THREAT_BASELINE + (1 - THREAT_BASELINE) * NAS

THREAT_NORM     = 20.0   # normalization denominator
THREAT_BASELINE = 0.05   # minimum CTS — network is never perfectly safe


# -------------------- Energy --------------------

def estimate_energy(cpu_percent: float, duration_s: float) -> tuple[float, float]:
    """
    Mathematical energy model: E = P x t
    P_current = 3.0 + (3.0 x CPU / 100)
    Returns (power_watts, energy_joules)
    """
    p_current = IDLE_POWER_W + (POWER_RANGE_W * (cpu_percent / 100.0))
    energy_j  = p_current * duration_s
    return p_current, energy_j


# -------------------- Metrics --------------------

LengthBand       = Literal["Short", "Normal", "Long", "Very Long"]
CriticalityLevel = Literal["Low", "Moderate", "High", "Critical"]
ThreatLevel      = Literal["Low", "Medium", "High", "Extremely High"]


@dataclass(frozen=True)
class MetricScores:
    length_band: LengthBand
    length_bytes: int
    length_stars: int

    criticality: CriticalityLevel
    criticality_stars: int

    threat: ThreatLevel
    threat_stars: int
    cts_score: float          # raw Continuous Threat Score 0.05-1.0
    nas_score: float          # raw Network Anomaly Score 0.0-1.0
    n_syn_recv: int
    n_close_wait: int
    n_time_wait: int

    cpu_percent: float
    cpu_stars: int

    ram_percent: float
    ram_stars: int

    sum_stars: int
    percent_score: int
    decimal_score: float


def _score_length(n: int) -> tuple[LengthBand, int]:
    if 0   <= n <= 64:   return ("Short",     4)
    if 65  <= n <= 254:  return ("Normal",    3)
    if 255 <= n <= 1024: return ("Long",      2)
    return ("Very Long", 1)


def _score_criticality(level: CriticalityLevel) -> int:
    return {"Low": 1, "Moderate": 2, "High": 3, "Critical": 4}[level]


def measure_threat_level() -> tuple[ThreatLevel, int, float, float, int, int, int]:
    """
    Collect raw psutil socket counts, compute NAS and CTS, map to threat level.

    Formulae:
        NAS = (S + 0.5*C + 0.25*T) / 20
        CTS = 0.05 + 0.95 * NAS
        clamped to [0.05, 1.0]

    Where:
        S = number of SYN_RECV connections  (SYN flood indicator)
        C = number of CLOSE_WAIT connections (hanging/broken connections)
        T = number of TIME_WAIT connections  (connection churn)

    Threat levels:
        Low           (1 star)  : 0.05 <= CTS < 0.30
        Medium        (2 stars) : 0.30 <= CTS < 0.55
        High          (3 stars) : 0.55 <= CTS < 0.80
        Extremely High(4 stars) : 0.80 <= CTS <= 1.00

    Returns:
        (threat_level, threat_stars, cts_score, nas_score,
         n_syn_recv, n_close_wait, n_time_wait)
    """
    n_syn_recv   = 0
    n_close_wait = 0
    n_time_wait  = 0

    try:
        import psutil
        conns = psutil.net_connections(kind='inet')

        # Print raw psutil output so it is visible in the terminal
        print(f"  {DIM(f'[psutil] {len(conns)} sockets total')}")
        for conn in conns:
            if conn.status == 'SYN_RECV':
                n_syn_recv += 1
            elif conn.status == 'CLOSE_WAIT':
                n_close_wait += 1
            elif conn.status == 'TIME_WAIT':
                n_time_wait += 1

    except Exception as e:
        # Permission error on some systems — use small non-zero defaults
        # to preserve the baseline threat guarantee
        print(f"  [psutil] net_connections unavailable ({e}), using baseline defaults.")
        n_time_wait  = random.randint(1, 3)
        n_close_wait = random.randint(0, 1)

    # ── NAS formula ──────────────────────────────────────────────────────────
    # NAS = (S + 0.5*C + 0.25*T) / 20
    nas = (n_syn_recv + 0.5 * n_close_wait + 0.25 * n_time_wait) / THREAT_NORM

    # ── CTS formula ──────────────────────────────────────────────────────────
    # CTS = 0.05 + 0.95 * NAS   (guaranteed >= 0.05)
    cts = THREAT_BASELINE + (1.0 - THREAT_BASELINE) * nas
    cts = min(1.0, cts)   # clamp — extreme attack may push NAS > 1

    # ── Map CTS to named threat level + stars ────────────────────────────────
    if cts < 0.30:
        level, stars = "Low",            1
    elif cts < 0.55:
        level, stars = "Medium",         2
    elif cts < 0.80:
        level, stars = "High",           3
    else:
        level, stars = "Extremely High", 4

    # ── Terminal print ───────────────────────────────────────────────────────
    threat_colour = {
        "Low": GREEN, "Medium": YELLOW,
        "High": RED,  "Extremely High": lambda t: RED(BOLD(t))
    }.get(level, str)
    print(f"  {DIM('[psutil]')} SYN={n_syn_recv} CW={n_close_wait} TW={n_time_wait}  "
          f"│  NAS={nas:.3f}  CTS={cts:.3f}  "
          f"│  Threat: {threat_colour(f'{level} ({stars}★)')}")

    return level, stars, cts, nas, n_syn_recv, n_close_wait, n_time_wait


def _score_utilization(percent: float) -> int:
    if 0  <= percent < 25: return 4
    if 25 <= percent < 50: return 3
    if 50 <= percent < 75: return 2
    return 1


def measure_cpu_ram() -> tuple[float, float]:
    try:
        import psutil
        cpu = float(psutil.cpu_percent(interval=0.2))
        ram = float(psutil.virtual_memory().percent)
        return max(0.0, min(100.0, cpu)), max(0.0, min(100.0, ram))
    except Exception:
        return random.uniform(0, 60), random.uniform(10, 70)


def compute_metrics(payload_len: int) -> MetricScores:
    length_band, length_stars = _score_length(payload_len)

    criticality: CriticalityLevel = random.choice(["Low", "Moderate", "High", "Critical"])
    criticality_stars = _score_criticality(criticality)

    (threat, threat_stars, cts_score, nas_score,
     n_syn_recv, n_close_wait, n_time_wait) = measure_threat_level()

    cpu_percent, ram_percent = measure_cpu_ram()
    cpu_stars = _score_utilization(cpu_percent)
    ram_stars = _score_utilization(ram_percent)

    sum_stars     = length_stars + criticality_stars + threat_stars + cpu_stars + ram_stars
    percent_score = max(0, min(100, int(sum_stars * 5)))
    decimal_score = percent_score / 100.0

    return MetricScores(
        length_band=length_band,
        length_bytes=payload_len,
        length_stars=length_stars,
        criticality=criticality,
        criticality_stars=criticality_stars,
        threat=threat,
        threat_stars=threat_stars,
        cts_score=cts_score,
        nas_score=nas_score,
        n_syn_recv=n_syn_recv,
        n_close_wait=n_close_wait,
        n_time_wait=n_time_wait,
        cpu_percent=cpu_percent,
        cpu_stars=cpu_stars,
        ram_percent=ram_percent,
        ram_stars=ram_stars,
        sum_stars=sum_stars,
        percent_score=percent_score,
        decimal_score=decimal_score,
    )


# -------------------- Ascon Core --------------------

def ascon_encrypt(
    key: BytesLike,
    nonce: BytesLike,
    associateddata: BytesLike,
    plaintext: BytesLike,
    variant: AsconAeadVariant = "Ascon-128",
    tag_len: int | None = None,
) -> bytes:
    p = AEAD_PARAMS[variant]
    if tag_len is None:
        tag_len = p.tag_len
    assert len(key) == p.key_len
    assert len(nonce) == p.nonce_len
    assert 0 < tag_len <= 16
    S = [0, 0, 0, 0, 0]
    ascon_initialize(S, p, key, nonce)
    ascon_process_associated_data(S, p.b, p.rate, associateddata)
    ciphertext = ascon_process_plaintext(S, p.b, p.rate, plaintext)
    full_tag = ascon_finalize(S, p, key)
    return ciphertext + full_tag[:tag_len]


def ascon_decrypt(
    key: BytesLike,
    nonce: BytesLike,
    associateddata: BytesLike,
    ciphertext: BytesLike,
    variant: AsconAeadVariant = "Ascon-128",
    tag_len: int | None = None,
) -> bytes | None:
    p = AEAD_PARAMS[variant]
    if tag_len is None:
        tag_len = p.tag_len
    assert len(key) == p.key_len
    assert len(nonce) == p.nonce_len
    assert 0 < tag_len <= 16
    assert len(ciphertext) >= tag_len
    ct, tag = ciphertext[:-tag_len], ciphertext[-tag_len:]
    S = [0, 0, 0, 0, 0]
    ascon_initialize(S, p, key, nonce)
    ascon_process_associated_data(S, p.b, p.rate, associateddata)
    plaintext = ascon_process_ciphertext(S, p.b, p.rate, ct)
    full_tag = ascon_finalize(S, p, key)
    if full_tag[:tag_len] == tag:
        return plaintext
    return None


def ascon_initialize(S: list[int], p: AeadParams, key: BytesLike, nonce: BytesLike) -> None:
    iv_len = 24 - p.key_len
    assert len(p.iv) == iv_len, f"IV length mismatch: expected {iv_len}, got {len(p.iv)}"
    init = p.iv + to_bytes(key) + to_bytes(nonce)
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(init)
    if debug: printstate(S, "initial value:")
    ascon_permutation(S, p.a)
    buf = bytearray(state_to_bytes(S))
    off = 40 - p.key_len
    for i in range(p.key_len):
        buf[off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    if debug: printstate(S, "initialization:")


def ascon_process_associated_data(S: list[int], b: int, rate: int, associateddata: BytesLike) -> None:
    if len(associateddata) > 0:
        a_padding = to_bytes([0x01]) + zero_bytes(rate - (len(associateddata) % rate) - 1)
        a_padded  = to_bytes(associateddata) + a_padding
        for block in range(0, len(a_padded), rate):
            S[0] ^= bytes_to_int(a_padded[block:block + 8])
            if rate == 16:
                S[1] ^= bytes_to_int(a_padded[block + 8:block + 16])
            ascon_permutation(S, b)
    S[4] ^= 1 << 63
    if debug: printstate(S, "process associated data:")


def ascon_process_plaintext(S: list[int], b: int, rate: int, plaintext: BytesLike) -> bytes:
    p_lastlen = len(plaintext) % rate
    p_padding = to_bytes([0x01]) + zero_bytes(rate - p_lastlen - 1)
    p_padded  = to_bytes(plaintext) + p_padding
    ciphertext = b""
    for block in range(0, len(p_padded) - rate, rate):
        S[0] ^= bytes_to_int(p_padded[block:block + 8])
        if rate == 16:
            S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
            ciphertext += int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8)
        else:
            ciphertext += int_to_bytes(S[0], 8)
        ascon_permutation(S, b)
    block = len(p_padded) - rate
    S[0] ^= bytes_to_int(p_padded[block:block + 8])
    if rate == 16:
        S[1] ^= bytes_to_int(p_padded[block + 8:block + 16])
        out = int_to_bytes(S[0], 8) + int_to_bytes(S[1], 8)
    else:
        out = int_to_bytes(S[0], 8)
    ciphertext += out[:p_lastlen]
    if debug: printstate(S, "process plaintext:")
    return ciphertext


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
    c0 = bytes_to_int(c_padded[block:block + 8])
    if rate == 16:
        c1  = bytes_to_int(c_padded[block + 8:block + 16])
        out = (int_to_bytes(S[0] ^ c0, 8) + int_to_bytes(S[1] ^ c1, 8))[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        cm0, cm1 = c_mask[0:8], c_mask[8:16]
        px0, px1 = c_padx[0:8], c_padx[8:16]
        S[0] = (S[0] & bytes_to_int(cm0)) ^ c0 ^ bytes_to_int(px0)
        S[1] = (S[1] & bytes_to_int(cm1)) ^ c1 ^ bytes_to_int(px1)
    else:
        out = int_to_bytes(S[0] ^ c0, 8)[:c_lastlen]
        plaintext += out
        c_padx = zero_bytes(c_lastlen) + to_bytes([0x01]) + zero_bytes(rate - c_lastlen - 1)
        c_mask = zero_bytes(c_lastlen) + ff_bytes(rate - c_lastlen)
        S[0] = (S[0] & bytes_to_int(c_mask[0:8])) ^ c0 ^ bytes_to_int(c_padx[0:8])
    if debug: printstate(S, "process ciphertext:")
    return plaintext


def ascon_finalize(S: list[int], p: AeadParams, key: BytesLike) -> bytes:
    assert len(key) == p.key_len
    buf     = bytearray(state_to_bytes(S))
    pre_off = p.rate
    for i in range(p.key_len):
        if pre_off + i < 40:
            buf[pre_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    ascon_permutation(S, p.a)
    buf      = bytearray(state_to_bytes(S))
    post_off = 40 - p.key_len
    for i in range(p.key_len):
        buf[post_off + i] ^= key[i]
    S[0], S[1], S[2], S[3], S[4] = bytes_to_state(bytes(buf))
    tag = int_to_bytes(S[3], 8) + int_to_bytes(S[4], 8)
    if debug: printstate(S, "finalization:")
    return tag


def ascon_permutation(S: list[int], rounds: int = 1) -> None:
    assert rounds <= 12
    if debugpermutation: printwords(S, "permutation input:")
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

def get_random_bytes(num: int) -> bytes:
    return os.urandom(num)

def zero_bytes(n: int) -> bytes:
    return n * b"\x00"

def ff_bytes(n: int) -> bytes:
    return n * b"\xFF"

def to_bytes(l: BytesLike | Iterable[int]) -> bytes:
    return bytes(l)

def bytes_to_int(b: BytesLike) -> int:
    return int.from_bytes(b, "little")

def bytes_to_state(b: bytes) -> list[int]:
    assert len(b) == 40, f"state must be 40 bytes, got {len(b)}"
    return [bytes_to_int(b[8 * w:8 * (w + 1)]) for w in range(5)]

def state_to_bytes(S: list[int]) -> bytes:
    return b"".join(int_to_bytes(w, 8) for w in S)

def int_to_bytes(integer: int, nbytes: int) -> bytes:
    return integer.to_bytes(nbytes, "little")

def rotr(val: int, r: int) -> int:
    return (val >> r) | ((val & ((1 << r) - 1)) << (64 - r))

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def hex_to_bytes(s: str) -> bytes:
    return bytes.fromhex(s)

def printstate(S: list[int], description: str = "") -> None:
    print(" " + description)
    print(" ".join(["{s:016x}".format(s=s) for s in S]))

def printwords(S: list[int], description: str = "") -> None:
    print(" " + description)
    print("\n".join(["  x{i}={s:016x}".format(**locals()) for i, s in enumerate(S)]))


# -------------------- Traffic generation --------------------

def generate_payload(length_mode: str) -> bytes:
    if length_mode.startswith("fixed:"):
        n = int(length_mode.split(":", 1)[1])
        return get_random_bytes(max(0, n))
    mode = length_mode.lower().strip()
    if mode == "short":                                   n = random.randint(0, 64)
    elif mode == "normal":                                n = random.randint(65, 254)
    elif mode == "long":                                  n = random.randint(255, 1024)
    elif mode in ("verylong", "very_long", "very-long"):  n = random.randint(1025, 2048)
    else:
        choice = random.choice(["short", "normal", "long", "verylong"])
        return generate_payload(choice)
    return get_random_bytes(n)


# -------------------- Keying model (pre-shared) --------------------

def derive_node_master_key(node_id: str) -> bytes:
    seed = (node_id + "|research-master-key").encode("utf-8")
    raw  = bytearray(20)
    acc  = 0
    for i in range(20):
        acc    = (acc + seed[i % len(seed)] + (i * 31)) % 256
        raw[i] = acc
    return bytes(raw)


def profile_key_from_master(master20: bytes, profile: ProfileId) -> bytes:
    if profile == 4:
        return master20
    return master20[:16]


# -------------------- Gateway Profile Request (port 9998) --------------------

def request_profile_from_gateway(
    gateway_host: str,
    profile_port: int,
    node_id: str,
    metrics: MetricScores,
    timeout: float = 3.0,
) -> ProfileId:
    """
    Send metrics to the gateway on port 9998 and wait for a profile ID response.
    The gateway calculates the score and decides which ASCON profile to use.

    If the gateway does not respond within `timeout` seconds, fall back to
    local profile selection so the node is never blocked.

    Returns a ProfileId (1, 2, 3, or 4).
    """
    request = {
        "type":    "profile_request",
        "node_id": node_id,
        "metrics": {
            "length_stars":      metrics.length_stars,
            "criticality_stars": metrics.criticality_stars,
            "threat_stars":      metrics.threat_stars,
            "cpu_stars":         metrics.cpu_stars,
            "ram_stars":         metrics.ram_stars,
            "sum_stars":         metrics.sum_stars,
            "percent_score":     metrics.percent_score,
            "cts_score":         round(metrics.cts_score, 4),
            "nas_score":         round(metrics.nas_score, 4),
            "n_syn_recv":        metrics.n_syn_recv,
            "n_close_wait":      metrics.n_close_wait,
            "n_time_wait":       metrics.n_time_wait,
            "cpu_percent":       round(metrics.cpu_percent, 2),
            "ram_percent":       round(metrics.ram_percent, 2),
        },
    }

    req_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    req_sock.settimeout(timeout)

    try:
        req_bytes = json.dumps(request).encode("utf-8")
        req_sock.sendto(req_bytes, (gateway_host, profile_port))

        resp_data, _ = req_sock.recvfrom(512)
        resp         = json.loads(resp_data.decode("utf-8"))

        if resp.get("type") == "profile_response" and resp.get("node_id") == node_id:
            profile_id = int(resp["profile_id"])
            profile_name = SECURITY_PROFILES[profile_id].name
            print(GREEN(f"  [Profile] ← Gateway assigned Profile {profile_id} ({profile_name})"))
            return profile_id

    except (socket.timeout, json.JSONDecodeError, KeyError, ValueError) as e:
        print(YELLOW(f"  [Profile] Gateway unreachable ({e}). Using local fallback."))
    finally:
        req_sock.close()

    # ---- Fallback: compute profile locally ----
    return _local_profile_fallback(metrics.percent_score)


def _local_profile_fallback(percent_score: int) -> ProfileId:
    """Local profile selection used only if gateway is unreachable."""
    x = max(0, min(100, percent_score)) / 100.0
    if x < 0.4375: return 1
    if x < 0.625:  return 2
    if x < 0.8125: return 3
    return 4


# -------------------- Packet build & send --------------------

def build_packet(
    node_id: str,
    seq: int,
    associated_data: bytes,
    payload: bytes,
    profile: ProfileId,
) -> dict:
    """
    Build and return the full packet dict (without sending).
    Profile is provided externally (assigned by gateway).
    Energy estimation is included in the returned dict under 'energy'.
    """
    metrics = compute_metrics(len(payload))
    sp      = SECURITY_PROFILES[profile]
    p       = AEAD_PARAMS[sp.variant]

    master = derive_node_master_key(node_id)
    key    = profile_key_from_master(master, profile)
    nonce  = get_random_bytes(p.nonce_len)

    enc_start = time.perf_counter()
    ciphertext_and_tag = ascon_encrypt(
        key=key,
        nonce=nonce,
        associateddata=associated_data,
        plaintext=payload,
        variant=sp.variant,
        tag_len=sp.tag_len,
    )
    enc_end     = time.perf_counter()
    enc_time_s  = enc_end - enc_start
    enc_time_us = enc_time_s * 1_000_000

    power_w, energy_j = estimate_energy(metrics.cpu_percent, enc_time_s)
    energy_uj = energy_j * 1_000_000

    pri_raw  = metrics.length_stars + metrics.criticality_stars
    pri_norm = pri_raw / 8.0

    pkt = {
        "type":    "ascon_node_msg",
        "node_id": node_id,
        "seq":     seq,
        "ts":      time.time(),
        "metrics": {
            "length_bytes":       metrics.length_bytes,
            "length_band":        metrics.length_band,
            "length_stars":       metrics.length_stars,
            "criticality":        metrics.criticality,
            "criticality_stars":  metrics.criticality_stars,
            "threat":             metrics.threat,
            "threat_stars":       metrics.threat_stars,
            "cts_score":          round(metrics.cts_score, 4),
            "nas_score":          round(metrics.nas_score, 4),
            "n_syn_recv":         metrics.n_syn_recv,
            "n_close_wait":       metrics.n_close_wait,
            "n_time_wait":        metrics.n_time_wait,
            "cpu_percent":        round(metrics.cpu_percent, 2),
            "cpu_stars":          metrics.cpu_stars,
            "ram_percent":        round(metrics.ram_percent, 2),
            "ram_stars":          metrics.ram_stars,
            "sum_stars":          metrics.sum_stars,
            "percent_score":      metrics.percent_score,
            "decimal_score":      metrics.decimal_score,
        },
        "priority_norm": pri_norm,
        "security": {
            "profile_id":   profile,
            "profile_name": sp.name,
            "variant":      sp.variant,
            "tag_len":      sp.tag_len,
        },
        "ad_hex":    associated_data.hex(),
        "nonce_hex": nonce.hex(),
        "ct_hex":    ciphertext_and_tag.hex(),
        "energy": {
            "model":        "E = P_current x t_encrypt",
            "idle_power_w": IDLE_POWER_W,
            "max_power_w":  MAX_POWER_W,
            "cpu_percent":  round(metrics.cpu_percent, 2),
            "power_w":      round(power_w, 6),
            "enc_time_s":   round(enc_time_s, 9),
            "enc_time_us":  round(enc_time_us, 4),
            "energy_j":     round(energy_j, 9),
            "energy_uj":    round(energy_uj, 6),
        },
    }
    return pkt


def build_and_send_packet(
    sock: socket.socket,
    gateway_addr: tuple[str, int],
    node_id: str,
    seq: int,
    associated_data: bytes,
    payload: bytes,
    profile: ProfileId,
) -> None:
    """Build packet and transmit it, then print metrics to terminal."""
    pkt = build_packet(node_id, seq, associated_data, payload, profile)
    raw = json.dumps(pkt).encode("utf-8")
    sock.sendto(raw, gateway_addr)

    e   = pkt["energy"]
    m   = pkt["metrics"]
    sec = pkt["security"]
    pr  = pkt["priority_norm"]

    lb   = m['length_bytes'];  lband = m['length_band']
    pid  = sec['profile_id'];   pname = sec['profile_name']
    var  = sec['variant']
    ls=m['length_stars']; cs=m['criticality_stars']; crit=m['criticality']
    ts=m['threat_stars'];  thr=m['threat'];           cts=m['cts_score']
    cpus=m['cpu_stars'];   cpup=m['cpu_percent']
    rams=m['ram_stars'];   ramp=m['ram_percent']
    ss=m['sum_stars'];     pct=m['percent_score']

    divider()
    print(f"  ▶ {BOLD(CYAN('[NODE ' + node_id + ']'))}  "
          f"Seq={BOLD(str(seq).zfill(4))}  │  "
          f"Payload={BOLD(str(lb) + 'B')} ({lband})")
    print(f"    Profile  : {GREEN('Profile ' + str(pid) + ' — ' + pname)}  "
          f"│  Variant={var}")
    print(f"    Metrics  : "
          f"Length {ls}★  "
          f"Crit {cs}★ ({crit})  "
          f"Threat {ts}★ ({thr})  "
          f"CTS={YELLOW(f'{cts:.3f}')}  "
          f"CPU {cpus}★ ({cpup:.0f}%)  "
          f"RAM {rams}★ ({ramp:.0f}%)")
    print(f"    Score    : {BOLD(str(ss) + '/20')} ({pct}%)  "
          f"│  Priority={BOLD(f'{pr:.3f}')}")
    print(f"    ⚡ Energy : P={e['power_w']:.3f}W  │  "
          f"Enc={e['enc_time_us']:.1f}µs  │  "
          f"E={e['energy_j']:.9f}J  ({e['energy_uj']:.3f}µJ)")
    print(f"    Wire size: {len(raw)} bytes")
    print()


# -------------------- Fragmentation --------------------

def fragment_payload(payload: bytes, fragment_size: int) -> list[bytes]:
    """
    Split a large payload into chunks of at most `fragment_size` bytes.
    Example: 1800 bytes / 40 bytes per fragment = 45 fragments.
    The last fragment carries whatever bytes remain (may be smaller).
    """
    chunks = []
    offset = 0
    while offset < len(payload):
        chunks.append(payload[offset: offset + fragment_size])
        offset += fragment_size
    return chunks


# -------------------- Duty-Cycle Send Helpers --------------------

def _routine_sleep(payload_len: int) -> None:
    """
    Sleep duration depends on payload size.
    Small payloads simulate real IoT sense→send→sleep duty cycle.
    Large payloads send immediately — no point sleeping for big data.

        0   –  64 bytes  (Short)    : sleep 2–3 seconds
        65  – 254 bytes  (Normal)   : sleep 1–2 seconds
        255 – 1024 bytes (Long)     : sleep 0.5 seconds
        1025+ bytes      (Very Long): no sleep
    """
    if payload_len <= 64:
        sleep_s = random.uniform(2.0, 3.0)
        print(DIM(f"  💤 Short payload — sleeping {sleep_s:.2f}s (duty cycle)\n"))
        time.sleep(sleep_s)
    elif payload_len <= 254:
        sleep_s = random.uniform(1.0, 2.0)
        print(DIM(f"  💤 Normal payload — sleeping {sleep_s:.2f}s (duty cycle)\n"))
        time.sleep(sleep_s)
    elif payload_len <= 1024:
        print(DIM(f"  💤 Long payload — sleeping 0.5s (duty cycle)\n"))
        time.sleep(0.5)
    else:
        print(DIM(f"  ⚡ Very long payload — sending immediately (no sleep)\n"))


def send_routine_packet(
    sock: socket.socket,
    gateway_addr: tuple[str, int],
    gateway_host: str,
    profile_port: int,
    node_id: str,
    seq: int,
    associated_data: bytes,
) -> int:
    """
    ROUTINE TRAFFIC MODE — sense → request profile → send → sleep (size-dependent).
    1. Generate a fully random payload (1-2048 bytes).
    2. Measure metrics — criticality is random and independent of size.
    3. Request profile from gateway on port 9998.
    4. Encrypt and send packet.
    5. Sleep based on payload size (large payloads = no sleep).
    Returns next sequence number.
    """
    # Fully random payload size 1-2048 bytes
    payload = get_random_bytes(random.randint(1, 2048))
    divider("═")
    print(BOLD(CYAN(f"  [ROUTINE] Node {node_id}  │  Seq={seq:04d}  │  Payload={len(payload)}B")))

    # Measure metrics — criticality is randomly assigned inside compute_metrics()
    # and is completely independent of payload size
    metrics = compute_metrics(len(payload))

    # Gateway decides the profile
    profile = request_profile_from_gateway(gateway_host, profile_port, node_id, metrics)

    build_and_send_packet(
        sock=sock,
        gateway_addr=gateway_addr,
        node_id=node_id,
        seq=seq,
        associated_data=associated_data,
        payload=payload,
        profile=profile,
    )
    seq += 1

    # Sleep depends on how big the payload was
    _routine_sleep(len(payload))
    return seq


def send_urgent_burst(
    sock: socket.socket,
    gateway_addr: tuple[str, int],
    gateway_host: str,
    profile_port: int,
    node_id: str,
    seq: int,
    associated_data: bytes,
) -> int:
    """
    URGENT TRAFFIC MODE — measure ONCE → request profile ONCE → announce → burst fragments.

    1. Measure metrics once for the whole burst.
    2. Request profile from gateway ONCE — all fragments use this same profile.
    3. Send an announcement packet declaring fragment count, total size, and profile.
    4. Send all fragments immediately (no sleep between them).
    Returns next sequence number after all fragments are sent.
    """
    # Fully random payload size 1-2048 bytes for urgent burst
    full_payload = get_random_bytes(random.randint(1, 2048))
    fragments    = fragment_payload(full_payload, URGENT_FRAGMENT_SIZE)
    total_frags  = len(fragments)

    print(f"\n")
    divider("═")
    print(RED(BOLD(f"  🚨 URGENT BURST — CRITICAL EVENT — Node {node_id}")))
    print(f"     Full payload : {BOLD(str(len(full_payload)))}B  →  "
          f"{BOLD(str(total_frags))} fragments × ~{URGENT_FRAGMENT_SIZE}B")
    divider("═")
    print()

    # ── Step 1: measure metrics ONCE for the whole burst ──────────────────────
    # Use full payload size for metric calculation
    metrics = compute_metrics(len(full_payload))

    # ── Step 2: request profile from gateway ONCE ─────────────────────────────
    profile  = request_profile_from_gateway(gateway_host, profile_port, node_id, metrics)
    sp       = SECURITY_PROFILES[profile]
    p_params = AEAD_PARAMS[sp.variant]
    master   = derive_node_master_key(node_id)
    key      = profile_key_from_master(master, profile)

    print(GREEN(f"  [URGENT] Gateway assigned Profile {profile} ({sp.name}) "
                f"for ALL {total_frags} fragments\n"))

    # ── Step 3: send announcement packet ──────────────────────────────────────
    # This tells the gateway exactly what to expect so it can validate
    # fragment count and detect missing/injected fragments.
    announcement = {
        "type":          "urgent_announcement",
        "node_id":       node_id,
        "seq":           seq,
        "ts":            time.time(),
        "frag_total":    total_frags,
        "frag_size":     URGENT_FRAGMENT_SIZE,
        "original_size": len(full_payload),
        "profile_id":    profile,
        "variant":       sp.variant,
        "tag_len":       sp.tag_len,
        "priority_norm": URGENT_PRIORITY_HINT,
    }
    ann_bytes = json.dumps(announcement).encode("utf-8")
    sock.sendto(ann_bytes, gateway_addr)
    print(MAGENTA(f"  📢 Announcement sent → {total_frags} fragments coming, "
                  f"original={len(full_payload)}B, profile={profile} ({sp.variant})"))
    seq += 1

    # ── Step 4: burst-send all fragments ──────────────────────────────────────
    cpu_percent, ram_percent = measure_cpu_ram()

    for frag_idx, frag_data in enumerate(fragments):
        nonce = get_random_bytes(p_params.nonce_len)

        enc_start = time.perf_counter()
        ct = ascon_encrypt(
            key=key,
            nonce=nonce,
            associateddata=associated_data,
            plaintext=frag_data,
            variant=sp.variant,
            tag_len=sp.tag_len,
        )
        enc_end    = time.perf_counter()
        enc_time_s = enc_end - enc_start
        power_w, energy_j = estimate_energy(cpu_percent, enc_time_s)

        frag_pkt = {
            "type":    "ascon_node_msg",
            "node_id": node_id,
            "seq":     seq,
            "ts":      time.time(),
            "fragment": {
                "is_fragment":   True,
                "frag_index":    frag_idx,
                "frag_total":    total_frags,
                "frag_size":     len(frag_data),
                "original_size": len(full_payload),
            },
            "metrics": {
                "length_bytes":       len(frag_data),
                "length_band":        _score_length(len(frag_data))[0],
                "length_stars":       _score_length(len(frag_data))[1],
                "criticality":        "Critical",   # urgent events always critical
                "criticality_stars":  4,
                "threat":             metrics.threat,
                "threat_stars":       metrics.threat_stars,
                "cts_score":          round(metrics.cts_score, 4),
                "nas_score":          round(metrics.nas_score, 4),
                "n_syn_recv":         metrics.n_syn_recv,
                "n_close_wait":       metrics.n_close_wait,
                "n_time_wait":        metrics.n_time_wait,
                "cpu_percent":        round(cpu_percent, 2),
                "cpu_stars":          _score_utilization(cpu_percent),
                "ram_percent":        round(ram_percent, 2),
                "ram_stars":          _score_utilization(ram_percent),
            },
            # All fragments carry maximum priority so gateway Stage B
            # processes them before any routine packets
            "priority_norm":  URGENT_PRIORITY_HINT,
            "priority_hint":  URGENT_PRIORITY_HINT,
            "security": {
                "profile_id":   profile,
                "profile_name": sp.name,
                "variant":      sp.variant,
                "tag_len":      sp.tag_len,
            },
            "ad_hex":    associated_data.hex(),
            "nonce_hex": nonce.hex(),
            "ct_hex":    ct.hex(),
            "energy": {
                "model":       "E = P_current x t_encrypt",
                "power_w":     round(power_w, 6),
                "enc_time_us": round(enc_time_s * 1_000_000, 4),
                "energy_j":    round(energy_j, 9),
                "energy_uj":   round(energy_j * 1_000_000, 6),
            },
        }

        raw = json.dumps(frag_pkt).encode("utf-8")
        sock.sendto(raw, gateway_addr)

        print(
            f"  ▶ {RED(f'Frag {frag_idx+1:03d}/{total_frags}')}  "
            f"Seq={seq:04d}  │  {len(frag_data)}B  │  "
            f"Prio={URGENT_PRIORITY_HINT:.1f}  │  "
            f"Profile={profile}  │  "
            f"⚡ {energy_j*1e6:.3f}µJ"
        )
        seq += 1

        if URGENT_INTER_FRAG_SLEEP > 0:
            time.sleep(URGENT_INTER_FRAG_SLEEP)

    divider()
    print(GREEN(f"  ✅ Burst complete — {total_frags} fragments sent  "
                f"│  Total={len(full_payload)}B\n"))
    return seq


# -------------------- Main --------------------

def main() -> None:
    ap = argparse.ArgumentParser(
        description="IoT Node – Ascon Sender | CTS Threat Model | Gateway Profile Assignment"
    )
    ap.add_argument("--node-id",        default="node1")
    ap.add_argument("--gateway-host",   default="127.0.0.1")
    ap.add_argument("--gateway-port",   type=int, default=9999,
                    help="UDP port for encrypted data packets")
    ap.add_argument("--profile-port",   type=int, default=9998,
                    help="UDP port for profile request/response with gateway")
    ap.add_argument("--count",          type=int, default=20,
                    help="Number of ROUTINE cycles to run (0 = infinite)")
    ap.add_argument("--interval",       type=float, default=None,
                    help="Override routine sleep interval in seconds. "
                         "Default: random 2-3s duty cycle.")
    ap.add_argument("--length-mode",    default="routine",
                    help="routine | urgent | auto | short | normal | long | verylong | random | fixed:<N>")
    ap.add_argument("--ad",             default="header",
                    help="Associated data string (authenticated but not encrypted)")
    ap.add_argument("--urgent-prob",    type=float, default=URGENT_EVENT_PROBABILITY,
                    help="Probability (0.0-1.0) that an urgent event fires after each routine cycle")
    args = ap.parse_args()

    sock            = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    gateway_addr    = (args.gateway_host, args.gateway_port)
    associated_data = args.ad.encode("utf-8")

    print(f"\033[96m{'═'*70}\033[0m")
    print(f"\033[1m\033[96m  IoT SENSOR NODE — STARTING UP\033[0m")
    print(f"\033[96m{'═'*70}\033[0m")
    print(f"  Node ID      : {BOLD(args.node_id)}")
    print(f"  Cluster Head : {BOLD(args.gateway_host)}:{args.gateway_port}")
    print(f"  Profile port : {BOLD(str(args.profile_port))}")
    print(f"  Mode         : {BOLD(mode)}")
    print(f"  Threat model : NAS=(S+0.5C+0.25T)/{THREAT_NORM}  CTS={THREAT_BASELINE}+{1-THREAT_BASELINE}*NAS")
    print(f"  Energy model : P={IDLE_POWER_W}+{POWER_RANGE_W}*(CPU/100)W  E=P*t")
    print(f"\033[96m{'─'*70}\033[0m\n")

    seq      = 0
    infinite = (args.count == 0)
    mode     = args.length_mode.lower().strip()

    try:
        # ── MODE: urgent ──────────────────────────────────────────────────────
        if mode == "urgent":
            seq = send_urgent_burst(
                sock, gateway_addr, args.gateway_host, args.profile_port,
                args.node_id, seq, associated_data
            )

        # ── MODE: routine / auto ──────────────────────────────────────────────
        elif mode in ("routine", "auto"):
            routine_count = 0
            while infinite or routine_count < args.count:
                seq = send_routine_packet(
                    sock, gateway_addr, args.gateway_host, args.profile_port,
                    args.node_id, seq, associated_data
                )
                routine_count += 1

                if mode == "auto" and args.urgent_prob > 0.0:
                    if random.random() < args.urgent_prob:
                        seq = send_urgent_burst(
                            sock, gateway_addr, args.gateway_host, args.profile_port,
                            args.node_id, seq, associated_data
                        )

        # ── LEGACY MODES ──────────────────────────────────────────────────────
        else:
            legacy_interval = args.interval if args.interval is not None else 1.0
            legacy_count    = 0
            while infinite or legacy_count < args.count:
                payload  = generate_payload(mode)
                metrics  = compute_metrics(len(payload))
                profile  = request_profile_from_gateway(
                    args.gateway_host, args.profile_port, args.node_id, metrics
                )
                build_and_send_packet(
                    sock=sock,
                    gateway_addr=gateway_addr,
                    node_id=args.node_id,
                    seq=seq,
                    associated_data=associated_data,
                    payload=payload,
                    profile=profile,
                )
                seq          += 1
                legacy_count += 1
                if infinite or legacy_count < args.count:
                    time.sleep(legacy_interval)

    except KeyboardInterrupt:
        print("\n[node] Interrupted by user.")
    finally:
        sock.close()
        print(f"[node] Done. Total packets/fragments sent: {seq}")


if __name__ == "__main__":
    main()
