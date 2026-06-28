#!/usr/bin/env python3
"""
Cluster Head / Gateway (Academic IoT Research)
===============================================
Stage A : FIFO scheduling for the first N seconds (default 20s)
Stage B : Priority scheduling with Mathematical Queue Aging
           Key = -(Priority_base - 0.1 * t_arrival)
           Urgent fragments (priority >= 0.95) get Key = -9999 - t_arrival

Features:
  - Profile Assignment Server  (port 9998): assigns ASCON profile to each node
  - Fragment Reassembly        : rebuilds original data from urgent burst fragments
  - Transmission Integrity     : validates reassembled size vs announced size
  - Event-Driven Processing    : zero sleep, wakes instantly on packet arrival
  - Clear colour-coded terminal output for easy demo presentation
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

BytesLike:       TypeAlias = bytes | bytearray | memoryview
AsconAeadVariant:TypeAlias = Literal["Ascon-128", "Ascon-128a", "Ascon-80pq"]

# ═══════════════════════════════════════════════════════════════════
#  TERMINAL COLOURS  (disable with --no-colour)
# ═══════════════════════════════════════════════════════════════════
USE_COLOUR = True

def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if USE_COLOUR else text

def CYAN(t):   return _c("96", t)
def GREEN(t):  return _c("92", t)
def YELLOW(t): return _c("93", t)
def RED(t):    return _c("91", t)
def BOLD(t):   return _c("1",  t)
def DIM(t):    return _c("2",  t)
def MAGENTA(t):return _c("95", t)

def divider(char="─", width=70):
    print(DIM(char * width))

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

def ascon_decrypt(key,nonce,ad,ct,variant="Ascon-128",tag_len=None):
    p=AEAD_PARAMS[variant]
    if tag_len is None: tag_len=p.tag_len
    assert len(key)==p.key_len and len(nonce)==p.nonce_len
    assert 0<tag_len<=16 and len(ct)>=tag_len
    body,tag=ct[:-tag_len],ct[-tag_len:]
    S=[0,0,0,0,0]
    _init(S,p,key,nonce); _process_ad(S,p.b,p.rate,ad)
    pt=_process_ct(S,p.b,p.rate,body); full_tag=_finalize(S,p,key)
    return pt if full_tag[:tag_len]==tag else None

def _init(S,p,key,nonce):
    iv_len=24-p.key_len
    init=p.iv+bytes(key)+bytes(nonce)
    S[0],S[1],S[2],S[3],S[4]=_b2s(init); _perm(S,p.a)
    buf=bytearray(_s2b(S)); off=40-p.key_len
    for i in range(p.key_len): buf[off+i]^=key[i]
    S[0],S[1],S[2],S[3],S[4]=_b2s(bytes(buf))

def _process_ad(S,b,rate,ad):
    if len(ad)>0:
        pad=bytes([0x01])+b"\x00"*(rate-(len(ad)%rate)-1)
        padded=bytes(ad)+pad
        for i in range(0,len(padded),rate):
            S[0]^=_b2i(padded[i:i+8])
            if rate==16: S[1]^=_b2i(padded[i+8:i+16])
            _perm(S,b)
    S[4]^=1<<63

def _process_ct(S,b,rate,ct):
    lastlen=len(ct)%rate
    padded=bytes(ct)+b"\x00"*(rate-lastlen)
    pt=b""
    for i in range(0,len(padded)-rate,rate):
        c0=_b2i(padded[i:i+8])
        if rate==16:
            c1=_b2i(padded[i+8:i+16])
            pt+=_i2b(S[0]^c0,8)+_i2b(S[1]^c1,8); S[0],S[1]=c0,c1
        else:
            pt+=_i2b(S[0]^c0,8); S[0]=c0
        _perm(S,b)
    i=len(padded)-rate; c0=_b2i(padded[i:i+8])
    if rate==16:
        c1=_b2i(padded[i+8:i+16])
        out=((_i2b(S[0]^c0,8)+_i2b(S[1]^c1,8)))[:lastlen]; pt+=out
        px=b"\x00"*lastlen+bytes([0x01])+b"\x00"*(rate-lastlen-1)
        mx=b"\x00"*lastlen+b"\xFF"*(rate-lastlen)
        S[0]=(S[0]&_b2i(mx[0:8]))^c0^_b2i(px[0:8])
        S[1]=(S[1]&_b2i(mx[8:16]))^c1^_b2i(px[8:16])
    else:
        out=_i2b(S[0]^c0,8)[:lastlen]; pt+=out
        px=b"\x00"*lastlen+bytes([0x01])+b"\x00"*(rate-lastlen-1)
        mx=b"\x00"*lastlen+b"\xFF"*(rate-lastlen)
        S[0]=(S[0]&_b2i(mx[0:8]))^c0^_b2i(px[0:8])
    return pt

def _finalize(S,p,key):
    buf=bytearray(_s2b(S))
    for i in range(p.key_len):
        if p.rate+i<40: buf[p.rate+i]^=key[i]
    S[0],S[1],S[2],S[3],S[4]=_b2s(bytes(buf)); _perm(S,p.a)
    buf=bytearray(_s2b(S)); off=40-p.key_len
    for i in range(p.key_len): buf[off+i]^=key[i]
    S[0],S[1],S[2],S[3],S[4]=_b2s(bytes(buf))
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
def _zb(n): return n*b"\x00"
def _fb(n): return n*b"\xFF"
def _hx(s): return bytes.fromhex(s)


# ═══════════════════════════════════════════════════════════════════
#  KEY DERIVATION  (must match node)
# ═══════════════════════════════════════════════════════════════════
def derive_key(node_id: str) -> bytes:
    seed=(node_id+"|research-master-key").encode()
    raw=bytearray(20); acc=0
    for i in range(20):
        acc=(acc+seed[i%len(seed)]+(i*31))%256; raw[i]=acc
    return bytes(raw)

def key_for_profile(master20: bytes, profile: int) -> bytes:
    return master20 if profile==4 else master20[:16]


# ═══════════════════════════════════════════════════════════════════
#  PROFILE ASSIGNMENT
# ═══════════════════════════════════════════════════════════════════
PROFILE_NAMES = {
    1: "Lightweight  (Ascon-128  / 8-byte tag)",
    2: "Standard     (Ascon-128  / 16-byte tag)",
    3: "High Security(Ascon-128a / 16-byte tag)",
    4: "Critical PQ  (Ascon-80pq / 16-byte tag)",
}

def assign_profile(metrics: dict) -> int:
    pct = max(0, min(100, int(metrics.get("percent_score", 0)))) / 100.0
    if pct < 0.4375: return 1
    if pct < 0.625:  return 2
    if pct < 0.8125: return 3
    return 4


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
    Routine:  Key = -(priority - 0.1 * t_arrival)   older = higher priority
    Urgent:   Key = -9999 - t_arrival                always beats routine
    """
    if priority >= URGENT_FLOOR:
        return -9999.0 - ts
    return -(priority - AGING_K * ts)


# ═══════════════════════════════════════════════════════════════════
#  FRAGMENT REASSEMBLY BUFFER
# ═══════════════════════════════════════════════════════════════════
@dataclass
class BurstBuffer:
    """Accumulates decrypted fragments until the burst is complete."""
    node_id:       str
    frag_total:    int
    frag_size:     int
    original_size: int
    profile_id:    int
    announced_at:  float = field(default_factory=time.time)
    # slot index → decrypted plaintext bytes
    fragments:     dict[int, bytes] = field(default_factory=dict)

    @property
    def received(self) -> int:
        return len(self.fragments)

    @property
    def complete(self) -> bool:
        return self.received >= self.frag_total

    def reassemble(self) -> bytes:
        """Concatenate fragments in order."""
        return b"".join(
            self.fragments[i]
            for i in sorted(self.fragments)
        )


# ═══════════════════════════════════════════════════════════════════
#  PRIORITY EXTRACTION
# ═══════════════════════════════════════════════════════════════════
def get_priority(pkt: dict) -> float:
    explicit = pkt.get("priority_norm")
    if explicit is not None:
        return float(explicit)
    m = pkt.get("metrics", {})
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
    node_id = str(pkt.get("node_id", ""))
    master  = derive_key(node_id)
    key     = key_for_profile(master, pid)
    return ascon_decrypt(
        key   = key,
        nonce = _hx(pkt["nonce_hex"]),
        ad    = _hx(pkt["ad_hex"]),
        ct    = _hx(pkt["ct_hex"]),
        variant = variant,
        tag_len = tag_len,
    )


# ═══════════════════════════════════════════════════════════════════
#  CLUSTER HEAD STATE  (shared across threads)
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

        # Fragment reassembly: (node_id) -> BurstBuffer
        self._burst_lock    = threading.Lock()
        self._bursts: dict[str, BurstBuffer] = {}

    # ── timing ──────────────────────────────────────────────────────
    def elapsed(self) -> float:
        return time.time() - self.start_ts

    def stage_a_active(self) -> bool:
        return self.elapsed() < self.stage_a_seconds

    # ── bytes / throughput ───────────────────────────────────────────
    def add_bytes(self, n: int):
        with self._bytes_lock: self._total_bytes += n

    def total_bytes(self) -> int:
        with self._bytes_lock: return self._total_bytes

    def throughput_kbps(self) -> float:
        return (self.total_bytes() / max(1.0, self.elapsed())) / 1024.0

    # ── burst announcement ───────────────────────────────────────────
    def register_burst(self, node_id: str, ann: dict):
        buf = BurstBuffer(
            node_id       = node_id,
            frag_total    = int(ann.get("frag_total", 0)),
            frag_size     = int(ann.get("frag_size", 40)),
            original_size = int(ann.get("original_size", 0)),
            profile_id    = int(ann.get("profile_id", 1)),
        )
        with self._burst_lock:
            self._bursts[node_id] = buf
        divider()
        print(MAGENTA(f"  📢  BURST ANNOUNCEMENT from {node_id}"))
        print(f"      Expecting : {BOLD(str(buf.frag_total))} fragments × ~{buf.frag_size}B")
        print(f"      Total size: {BOLD(str(buf.original_size))} bytes")
        print(f"      Profile   : {buf.profile_id} — {PROFILE_NAMES.get(buf.profile_id,'?')}")
        divider()

    def add_fragment(self, node_id: str, frag_idx: int,
                     plaintext: bytes, declared_frag_size: int) -> BurstBuffer | None:
        """
        Store a decrypted fragment.  Returns the BurstBuffer once complete,
        None if still waiting for more fragments.
        """
        with self._burst_lock:
            buf = self._bursts.get(node_id)
            if buf is None:
                return None
            # Size validation
            if frag_idx < buf.frag_total - 1:   # not the last fragment
                if len(plaintext) != buf.frag_size:
                    delta = abs(len(plaintext) - buf.frag_size)
                    print(RED(f"  🚨 SIZE MISMATCH frag {frag_idx} from {node_id}! "
                              f"Got {len(plaintext)}B expected {buf.frag_size}B "
                              f"(Δ={delta}B) — possible injection/corruption"))
            buf.fragments[frag_idx] = plaintext
            if buf.complete:
                del self._bursts[node_id]
                return buf
        return None

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

        node_id = str(req.get("node_id", "unknown"))
        metrics = req.get("metrics", {})
        profile = assign_profile(metrics)
        pname   = PROFILE_NAMES.get(profile, "?")
        cts     = metrics.get("cts_score", 0.0)
        stars   = metrics.get("sum_stars", 0)
        pct     = metrics.get("percent_score", 0)
        syn     = metrics.get("n_syn_recv", 0)
        cw      = metrics.get("n_close_wait", 0)
        tw      = metrics.get("n_time_wait", 0)

        print(CYAN(f"\n  [Profile Server] ← {node_id} @ {addr[0]}"))
        print(f"    Stars : {stars}/20 ({pct}%)  |  CTS={cts:.3f}  "
              f"|  SYN={syn} CW={cw} TW={tw}")
        print(GREEN(f"    → Assigned Profile {profile}: {pname}"))

        srv.sendto(json.dumps({
            "type":         "profile_response",
            "node_id":      node_id,
            "profile_id":   profile,
            "profile_name": pname,
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
            state._drain()
            continue

        pkt       = item.pkt
        now       = time.time()
        delay_ms  = (now - pkt["ts"]) * 1000.0
        tput      = state.throughput_kbps()
        is_urgent = item.priority_norm >= URGENT_FLOOR
        frag_info = pkt.get("fragment", {})
        is_frag   = frag_info.get("is_fragment", False)

        # ── stage label ──────────────────────────────────────────────
        stage_label = (GREEN("Stage A │ FIFO") if stage == "A"
                       else YELLOW("Stage B │ Priority"))
        urgent_tag  = RED(" 🚨 URGENT") if is_urgent else ""

        divider()
        if is_frag:
            fi = frag_info.get("frag_index", 0)
            ft = frag_info.get("frag_total", 0)
            print(f"  ◀ [{stage_label}]{urgent_tag}  "
                  f"{BOLD(item.node_id)}  Seq={item.seq:04d}  "
                  f"Fragment {fi+1}/{ft}")
        else:
            print(f"  ◀ [{stage_label}]{urgent_tag}  "
                  f"{BOLD(item.node_id)}  Seq={item.seq:04d}")

        print(f"    Priority : {item.priority_norm:.3f}  │  "
              f"Delay : {CYAN(f'{delay_ms:.2f} ms')}  │  "
              f"Throughput : {CYAN(f'{tput:.3f} KB/s')}")

        # ── decrypt ──────────────────────────────────────────────────
        plaintext = None
        if do_decrypt:
            t0        = time.perf_counter()
            plaintext = decrypt_packet(pkt)
            dec_us    = (time.perf_counter() - t0) * 1_000_000
            status    = GREEN("✔ OK") if plaintext is not None else RED("✘ FAIL")
            print(f"    Decrypt  : {status}  ({dec_us:.1f} µs)  │  "
                  f"Profile {pkt.get('security',{}).get('profile_id','?')} "
                  f"— {pkt.get('security',{}).get('variant','?')}")

        # ── fragment reassembly ──────────────────────────────────────
        if is_frag and do_decrypt and plaintext is not None:
            fi       = frag_info.get("frag_index", 0)
            dec_size = frag_info.get("frag_size", len(plaintext))
            buf = state.add_fragment(item.node_id, fi, plaintext, dec_size)

            if buf is not None:
                # All fragments collected — reassemble
                reassembled = buf.reassemble()
                divider("─")
                print(MAGENTA(f"  ✅  BURST REASSEMBLY COMPLETE — {item.node_id}"))
                print(f"      Fragments received : {buf.frag_total}/{buf.frag_total}")
                print(f"      Reassembled size   : {BOLD(str(len(reassembled)))} bytes")
                print(f"      Announced size     : {BOLD(str(buf.original_size))} bytes  ", end="")
                if len(reassembled) == buf.original_size:
                    print(GREEN("✔  MATCH — Transmission Integrity Verified"))
                else:
                    delta = abs(len(reassembled) - buf.original_size)
                    print(RED(f"✘  MISMATCH (Δ={delta}B) — Possible Attack / Data Loss"))
                divider("─")

        state.work_q.task_done()


# ═══════════════════════════════════════════════════════════════════
#  MAIN — RECEIVER THREAD
# ═══════════════════════════════════════════════════════════════════
def main():
    global USE_COLOUR
    ap = argparse.ArgumentParser(
        description="IoT Cluster Head — Profile Assignment | Scheduling | Reassembly")
    ap.add_argument("--bind-host",              default="0.0.0.0")
    ap.add_argument("--bind-port",              type=int, default=9999)
    ap.add_argument("--profile-port",           type=int, default=9998)
    ap.add_argument("--time-scheduler-seconds", type=float, default=20.0)
    ap.add_argument("--process-interval",       type=float, default=1.0,
                    help="Legacy — kept for CLI compatibility, not used")
    ap.add_argument("--decrypt",  action="store_true")
    ap.add_argument("--no-colour",action="store_true")
    args = ap.parse_args()

    if args.no_colour:
        USE_COLOUR = False

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind_host, args.bind_port))
    sock.settimeout(0.05)

    state = ClusterHeadState(stage_a_seconds=args.time_scheduler_seconds)

    # ── startup banner ───────────────────────────────────────────────
    section("IoT CLUSTER HEAD — STARTING UP")
    print(f"  Data port    : {BOLD(str(args.bind_port))}   (encrypted packets)")
    print(f"  Profile port : {BOLD(str(args.profile_port))}   (profile assignment)")
    print(f"  Stage A      : FIFO for {args.time_scheduler_seconds}s")
    print(f"  Stage B      : Priority + Aging  Key=-(p-{AGING_K}×t)")
    print(f"  Urgent floor : priority ≥ {URGENT_FLOOR} → Key=-9999-t")
    print(f"  Decrypt      : {GREEN('ON') if args.decrypt else DIM('OFF')}")
    print(f"  Reassembly   : {GREEN('ON') if args.decrypt else DIM('OFF (needs --decrypt)')}")
    divider()
    print()

    # ── start threads ────────────────────────────────────────────────
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
            # ── stage transition ──────────────────────────────────────
            if not state.stage_a_active() and not state.stage_a_ended:
                section(f"SWITCHING TO STAGE B — Priority Scheduling (t={state.elapsed():.1f}s)")
                state.transition_to_stage_b()

            if state.stage_a_ended and not stage_b_shown:
                print(YELLOW("  Stage B active │ Key = -(priority − 0.1 × t_arrival)\n"))
                stage_b_shown = True

            # ── receive ───────────────────────────────────────────────
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

            # ── announcement packet ───────────────────────────────────
            if ptype == "urgent_announcement":
                state.register_burst(str(pkt.get("node_id", "?")), pkt)
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
            is_frag    = pkt.get("fragment", {}).get("is_fragment", False)
            frag_label = ""
            if is_frag:
                fi = pkt["fragment"].get("frag_index", 0) + 1
                ft = pkt["fragment"].get("frag_total", 0)
                frag_label = f"  Fragment {fi}/{ft}"

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
