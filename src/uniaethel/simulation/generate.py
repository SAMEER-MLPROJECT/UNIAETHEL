
from __future__ import annotations

import json
import zlib
from pathlib import Path
import numpy as np

WORKSTATIONS = [f"10.0.{s}.{h}" for s in (1, 2, 3) for h in range(10, 16)]
DNS_SRV, WEB_SRV, FILE_SRV = "10.0.0.53", "10.0.0.80", "10.0.0.45"
ADMIN = "10.0.3.10"
CLOUD = "203.0.113.10"
UPDATE = "203.0.113.20"


def _ext_ip(name: str) -> str:
    h = zlib.crc32(name.encode())
    return f"{[23, 34, 52, 104, 142, 151, 203][h % 7]}.{(h >> 8) & 255}.{(h >> 16) & 255}.{max(1, (h >> 24) & 255)}"


def _mac(ip: str) -> str:
    h = zlib.crc32(ip.encode())
    return "02:%02x:%02x:%02x:%02x:%02x" % ((h >> 32) & 255 if h > 2**32 else 0, (h >> 24) & 255, (h >> 16) & 255, (h >> 8) & 255, h & 255)


class Cap:
    """Accumulates packet records (t, proto, src, dst, sport, dport, ip_len, tcp_flags)."""

    def __init__(self) -> None:
        self.recs: list[tuple] = []

    def tcp(self, t, src, dst, dport, nbytes, sport=None, flags="PA", rng=None):
        sport = int(sport if sport is not None else (rng.integers(1024, 65535) if rng is not None else 40000))
        self.recs.append((float(t), 6, src, dst, sport, int(dport), int(max(40, min(nbytes, 1500))), flags))

    def udp(self, t, src, dst, dport, nbytes, sport=None, rng=None):
        sport = int(sport if sport is not None else (rng.integers(1024, 65535) if rng is not None else 40000))
        self.recs.append((float(t), 17, src, dst, sport, int(dport), int(max(28, min(nbytes, 1500))), ""))

    def syn(self, t, src, dst, dport, rng=None):
        self.tcp(t, src, dst, dport, 60, flags="S", rng=rng)

    @property
    def pkts(self):
        return self.recs


_FLAG_BITS = {"F": 0x01, "S": 0x02, "R": 0x04, "P": 0x08, "A": 0x10}


def _flags(fl: str) -> int:
    return sum(_FLAG_BITS[c] for c in fl)


def write_pcap_scapy(recs, path):
    """Reference writer: every packet built by Scapy."""
    from scapy.all import IP, TCP, UDP, Ether, Raw, wrpcap
    out = []
    for t, proto, src, dst, sp, dp, ln, fl in recs:
        l4 = TCP(sport=sp, dport=dp, flags=fl) if proto == 6 else UDP(sport=sp, dport=dp)
        pay = ln - (40 if proto == 6 else 28)
        pk = Ether(src=_mac(src), dst=_mac(dst)) / IP(src=src, dst=dst) / l4
        if pay > 0:
            pk = pk / Raw(b"\x00" * pay)
        pk.time = t
        out.append(pk)
    wrpcap(path, out)


def write_pcap_fast(recs, path, snaplen: int = 96):
    """Fast writer: the same Ethernet/IPv4/TCP|UDP frames as the Scapy writer, captured with a snap
    length (like `tcpdump -s 96`). Each record keeps caplen <= snaplen and orig_len = true frame length;
    the IP total-length field carries the true packet size. Payload bytes are never analysed."""
    import socket
    import struct
    import dpkt
    with open(path, "wb") as f:
        f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, 1))
        for t, proto, src, dst, sp, dp, ln, fl in recs:
            if proto == 6:
                l4 = dpkt.tcp.TCP(sport=sp, dport=dp, flags=_flags(fl), off=5)
            else:
                l4 = dpkt.udp.UDP(sport=sp, dport=dp); l4.ulen = max(8, ln - 20)
            ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=64, data=l4)
            ip.len = ln
            frame = bytes(dpkt.ethernet.Ethernet(src=bytes.fromhex(_mac(src).replace(":", "")),
                                                 dst=bytes.fromhex(_mac(dst).replace(":", "")), type=0x0800, data=ip))
            frame = bytearray(frame)
            frame[16:18] = struct.pack(">H", ln)            # true IP total length
            frame[24:26] = b"\x00\x00"
            frame[24:26] = struct.pack(">H", dpkt.in_cksum(bytes(frame[14:34])))
            orig = 14 + ln
            cap = bytes(frame[:snaplen])
            sec = int(t); usec = int(round((t - sec) * 1e6))
            if usec >= 1000000:
                sec += 1; usec -= 1000000
            f.write(struct.pack("<IIII", sec, usec, len(cap), orig)); f.write(cap)


def _tls_flow(cap, rng, t, client, server, out_bytes, in_bytes, dur, dport=443, sport=None):
    """A TLS-like exchange as directional packets both ways (each direction observed independently)."""
    n_out = max(1, int(out_bytes / rng.uniform(400, 800)))
    n_in = max(1, int(in_bytes / rng.uniform(1000, 1400)))
    sp = int(sport) if sport is not None else int(rng.integers(1024, 65535))
    for i in range(n_out):
        cap.tcp(t + i * dur / max(n_out, 1), client, server, dport, out_bytes / n_out, sport=sp, rng=rng)
    for i in range(n_in):
        cap.tcp(t + 0.01 + i * dur / max(n_in, 1), server, client, sp, in_bytes / n_in, sport=dport, rng=rng)


def benign_background(cap, rng, duration):
    for h in WORKSTATIONS:
        t, active = 0.0, rng.random() < 0.5
        while t < duration:
            rate = 0.15 if active else 0.02
            t += rng.exponential(1 / rate)
            if t >= duration:
                break
            if rng.random() < 0.1:
                active = not active
            cap.udp(t, h, DNS_SRV, 53, rng.uniform(70, 120), rng=rng)
            site = _ext_ip(f"site{int(rng.integers(0, 400))}")
            _tls_flow(cap, rng, t + 0.02, h, site, rng.lognormal(6.8, 0.6), rng.lognormal(9.8, 1.1), rng.lognormal(-0.5, 0.8))
        for t in np.arange(rng.uniform(0, 30), duration, 30.0):      # NTP-like heartbeat (benign periodic)
            cap.udp(t + rng.normal(0, 0.5), h, _ext_ip("ntp"), 123, 90, rng=rng)
        for t in np.arange(rng.uniform(0, 64), duration, 64.0):      # telemetry (benign periodic)
            cap.tcp(t + rng.normal(0, 1.0), h, _ext_ip("telemetry"), 443, rng.uniform(400, 800), rng=rng)
        for t in np.arange(rng.uniform(0, 15), duration, 15.0):      # API polling (benign periodic, faster)
            _tls_flow(cap, rng, t + rng.normal(0, 0.3), h, _ext_ip("api"), 500, 1500, 0.1)
        t = rng.exponential(40)
        while t < duration:                                          # internal file share
            _tls_flow(cap, rng, t, h, FILE_SRV, rng.lognormal(8, 1), rng.lognormal(10, 1.2), 1.0, dport=445)
            t += rng.exponential(40)
    t = 0.0
    while t < duration:                                              # public web server clients
        t += rng.exponential(1 / 2.5)
        c = _ext_ip(f"client{int(rng.integers(0, 3000))}")
        _tls_flow(cap, rng, t, c, WEB_SRV, rng.lognormal(6.5, 0.5), rng.lognormal(9.5, 1.0), rng.lognormal(-1, 0.7))


# ------------------------------------------------------------------ events
def _t0(rng):
    return float(rng.uniform(80, 130))


def ev_c2(cap, rng, p, dur):
    host, dst = p["host"], p["dst"]
    t0 = _t0(rng); end = min(t0 + p["duration_s"], dur); t = t0
    while t < end:
        _tls_flow(cap, rng, t, host, dst, rng.uniform(300, 700), rng.uniform(120, 300), 0.15)
        t += p["period_s"] * (1 + rng.uniform(-p["jitter"], p["jitter"]))
    return {"cls": "C2", "host": host, "t_start": t0, "t_end": end, "dst": dst}


def ev_recon(cap, rng, p, dur):
    host = p["host"]; t0 = _t0(rng); end = min(t0 + p["duration_s"], dur)
    targets = [h for h in WORKSTATIONS if h != host] + [WEB_SRV, FILE_SRV, DNS_SRV]
    ports = [22, 80, 443, 445, 3389, 8080]
    t = t0; i = 0
    while t < end:
        frac = (t - t0) / (end - t0)
        rate = p["start_rate"] + (p["end_rate"] - p["start_rate"]) * frac
        cap.syn(t, host, targets[i % len(targets)], ports[i % len(ports)], rng=rng); i += 1
        t += 1.0 / max(rate, 0.05)
    return {"cls": "RECON", "host": host, "t_start": t0, "t_end": end,
            "related_hosts": [h for h in targets if h.startswith("10.")]}


def ev_ddos(cap, rng, p, dur):
    tgt = p["target"]; t0 = _t0(rng); end = min(t0 + p["duration_s"], dur); t = t0
    while t < end:
        frac = min(1.0, (t - t0) / p["ramp_s"])
        rate = max(1.0, p["peak_pps"] * frac)
        src = f"{rng.choice([45, 77, 91, 185, 203])}.{rng.integers(0,256)}.{rng.integers(0,256)}.{rng.integers(1,255)}"
        cap.tcp(t, src, tgt, 443, rng.uniform(60, 120), flags="S", rng=rng)
        t += 1.0 / rate
    return {"cls": "DDOS", "host": tgt, "t_start": t0, "t_end": end}


def ev_exfil(cap, rng, p, dur):
    host, dst = p["host"], p["dst"]; t0 = _t0(rng); end = min(t0 + p["duration_s"], dur)
    total = p["mbytes"] * 1e6
    if p.get("chunk_period_s"):
        n = max(1, int(p["duration_s"] / p["chunk_period_s"]))
        for k in range(n):
            _tls_flow(cap, rng, t0 + k * p["chunk_period_s"], host, dst, total / n, 3000, p["chunk_period_s"] * 0.8)
    else:
        step = (end - t0) / 60
        sp = int(rng.integers(1024, 65535))                  
        for k in range(60):
            _tls_flow(cap, rng, t0 + k * step, host, dst, total / 60, 2000, step * 0.9, sport=sp)
    return {"cls": "EXFIL", "host": host, "t_start": t0, "t_end": end, "dst": dst}


def ev_unknown_dns_tunnel(cap, rng, p, dur):
    host = p["host"]; t0 = _t0(rng); end = min(t0 + p["duration_s"], dur); t = t0
    while t < end:
        burst = int(rng.integers(1, 5))
        for _ in range(burst):
            cap.udp(t, host, DNS_SRV, 53, rng.uniform(200, 500), rng=rng)   
            t += rng.exponential(1 / (p["pps"] * 3))
        t += rng.exponential(1 / p["pps"])
    return {"cls": "UNKNOWN", "host": host, "t_start": t0, "t_end": end}



def hn_heartbeat(cap, rng, p, dur):
    host = WORKSTATIONS[int(rng.integers(0, len(WORKSTATIONS)))]; dst = _ext_ip("svc-health")
    for t in np.arange(_t0(rng), dur, 10.0):
        _tls_flow(cap, rng, t, host, dst, rng.uniform(300, 500), rng.uniform(200, 400), 0.1)
    return {"cls": "BENIGN", "host": host, "t_start": 0, "t_end": dur, "benign": True, "hard_negative_for": "C2"}


def hn_telemetry_new(cap, rng, p, dur):
    hosts = WORKSTATIONS[:3]; dst = _ext_ip("new-agent")
    for h in hosts:
        for t in np.arange(_t0(rng), dur, 5.0):
            cap.tcp(t + rng.normal(0, 0.2), h, dst, 443, rng.uniform(300, 500), rng=rng)
    return {"cls": "BENIGN", "host": hosts[0], "t_start": 0, "t_end": dur, "benign": True, "hard_negative_for": "C2"}


def hn_api_polling(cap, rng, p, dur):
    host = WORKSTATIONS[int(rng.integers(0, len(WORKSTATIONS)))]; dst = _ext_ip("api-fast")
    for t in np.arange(_t0(rng), dur, 2.0):
        _tls_flow(cap, rng, t, host, dst, 500, 1500, 0.05)
    return {"cls": "BENIGN", "host": host, "t_start": 0, "t_end": dur, "benign": True, "hard_negative_for": "C2"}


def hn_inventory(cap, rng, p, dur):
    t0 = _t0(rng); targets = [h for h in WORKSTATIONS if h != ADMIN] + [WEB_SRV, FILE_SRV]
    for i, h in enumerate(targets):
        cap.tcp(t0 + i * 0.8, ADMIN, h, 5985, 3000, rng=rng)
    return {"cls": "BENIGN", "host": ADMIN, "t_start": t0, "t_end": t0 + len(targets) * 0.8, "benign": True,
            "hard_negative_for": "RECON", "related_hosts": [h for h in targets if h.startswith("10.")]}


def hn_app_restart(cap, rng, p, dur):
    host = WORKSTATIONS[0]; peers = WORKSTATIONS[1:9]; t0 = _t0(rng)
    for i, pr in enumerate(peers):
        cap.tcp(t0 + i * 0.3, host, pr, 8080, 2000, rng=rng)
    return {"cls": "BENIGN", "host": host, "t_start": t0, "t_end": t0 + 3, "benign": True, "hard_negative_for": "RECON",
            "related_hosts": peers}


def hn_flash_crowd(cap, rng, p, dur):
    t0 = _t0(rng); end = t0 + 60; t = t0
    while t < end:
        c = _ext_ip(f"flash{int(rng.integers(0, 5000))}")
        _tls_flow(cap, rng, t, c, WEB_SRV, rng.lognormal(6.5, 0.5), rng.lognormal(9.5, 1.0), 0.3)
        t += rng.exponential(1 / 15.0)
    return {"cls": "BENIGN", "host": WEB_SRV, "t_start": t0, "t_end": end, "benign": True, "hard_negative_for": "DDOS"}


def hn_load_test(cap, rng, p, dur):
    gens = WORKSTATIONS[:4]; t0 = _t0(rng); end = t0 + 60
    for g in gens:
        t = t0
        while t < end:
            cap.tcp(t, g, WEB_SRV, 443, rng.uniform(200, 600), rng=rng); t += rng.exponential(1 / 30.0)
    return {"cls": "BENIGN", "host": WEB_SRV, "t_start": t0, "t_end": end, "benign": True, "hard_negative_for": "DDOS"}


def hn_backup(cap, rng, p, dur):
    host = WORKSTATIONS[2]; t0 = _t0(rng)
    _tls_flow(cap, rng, t0, host, FILE_SRV, 40e6, 40000, 120, dport=445)
    return {"cls": "BENIGN", "host": host, "t_start": t0, "t_end": min(t0 + 120, dur), "benign": True, "hard_negative_for": "EXFIL"}


def hn_cloud_sync(cap, rng, p, dur):
    host = WORKSTATIONS[3]; t0 = _t0(rng)
    _tls_flow(cap, rng, t0, host, CLOUD, 25e6, 60000, 120)
    return {"cls": "BENIGN", "host": host, "t_start": t0, "t_end": min(t0 + 120, dur), "benign": True, "hard_negative_for": "EXFIL"}


def hn_software_update(cap, rng, p, dur):
    t0 = _t0(rng)
    for h in WORKSTATIONS[:8]:
        _tls_flow(cap, rng, t0 + rng.uniform(0, 10), h, UPDATE, 4000, 6e6, 60)     # inbound-dominated
    return {"cls": "BENIGN", "host": WORKSTATIONS[0], "t_start": t0, "t_end": min(t0 + 60, dur), "benign": True, "hard_negative_for": "EXFIL"}


EVENTS = {"c2": ev_c2, "recon": ev_recon, "ddos": ev_ddos, "exfil": ev_exfil, "unknown_dns_tunnel": ev_unknown_dns_tunnel,
          "heartbeat": hn_heartbeat, "telemetry_new": hn_telemetry_new, "api_polling": hn_api_polling,
          "inventory": hn_inventory, "app_restart": hn_app_restart, "flash_crowd": hn_flash_crowd,
          "load_test": hn_load_test, "backup": hn_backup, "cloud_sync": hn_cloud_sync, "software_update": hn_software_update}


def generate(scenario_type: str, seed: int, cfg: dict, params: dict | None = None, out_pcap: str | None = None,
             backend: str = "fast"):
    dur = cfg["scenarios"]["duration_s"]
    rng = np.random.default_rng(seed)
    cap = Cap()
    benign_background(cap, rng, dur)
    truth = {"type": scenario_type, "seed": seed, "duration": dur, "events": []}
    if scenario_type != "normal":
        p = dict(cfg["scenarios"]["defaults"].get(scenario_type, {}))
        p.update(params or {})
        p.setdefault("duration_s", dur)
        ev = EVENTS[scenario_type](cap, rng, p, dur)
        ev["type"] = scenario_type; ev["params"] = p
        truth["events"].append(ev)
    cap.recs = sorted((r for r in cap.recs if 0.0 <= r[0] < dur), key=lambda x: x[0])   
    truth["packets"] = len(cap.recs)
    if out_pcap:
        Path(out_pcap).parent.mkdir(parents=True, exist_ok=True)
        (write_pcap_scapy if backend == "scapy" else write_pcap_fast)(cap.recs, out_pcap)
        json.dump(truth, open(out_pcap.replace(".pcap", ".truth.json"), "w"), indent=1, default=float)
    return cap, truth
