"""Synthetic capture builders for NetSleuth's test suite.

Every capture used in tests is generated from scratch with scapy — no
real-world traffic, so the fixtures are safe to commit and legal to
redistribute. Builders keep TCP sequence/ack accounting consistent so
stream reassembly sees realistic conversations.
"""

from __future__ import annotations

from scapy.all import DNS, DNSQR, DNSRR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

BASE_TS = 1755400000.0                     # 2025-08-17 ~05:33 UTC, fixed
CMAC = "08:00:27:11:11:11"
SMAC = "08:00:27:22:22:22"


def _eth(src: str, dst: str) -> Ether:
    return Ether(src=src, dst=dst)


def write_pcap(path, packets) -> str:
    for i, p in enumerate(packets):
        if not hasattr(p, "time") or p.time == 0:
            p.time = BASE_TS + i * 0.001
    wrpcap(str(path), packets)
    return str(path)


def tcp_conversation(
    cip: str,
    cport: int,
    sip: str,
    sport: int,
    c2s: list[bytes],
    s2c: list[bytes],
    *,
    handshake: bool = True,
    close: bool = True,
    base_ts: float = BASE_TS,
    segment_size: int = 1400,
    retransmit_index: int | None = None,   # index into the flat c2s segment list to duplicate
) -> list:
    """Build a TCP conversation with correct seq/ack bookkeeping.

    ``c2s``/``s2c`` payloads are split into ``segment_size`` chunks, each
    becoming its own packet. Returns the scapy packet list.
    """
    pkts = []
    t = base_ts
    cseq, sseq = 1000, 5000

    def emit(src_ip, src_port, dst_ip, dst_port, flags, seq, ack, payload=b""):
        nonlocal t
        mac_src = CMAC if src_ip == cip else SMAC
        mac_dst = SMAC if src_ip == cip else CMAC
        pkt = _eth(mac_src, mac_dst) / IP(src=src_ip, dst=dst_ip) / TCP(
            sport=src_port, dport=dst_port, flags=flags, seq=seq, ack=ack)
        if payload:
            pkt = pkt / Raw(payload)
        pkt.time = t
        t += 0.0007
        pkts.append(pkt)

    if handshake:
        emit(cip, cport, sip, sport, "S", cseq, 0)
        emit(sip, sport, cip, cport, "SA", sseq, cseq + 1)
        emit(cip, cport, sip, sport, "A", cseq + 1, sseq + 1)
        cseq += 1
        sseq += 1

    # (direction, seq, payload) triples with running sequence counters
    flat = []
    c_run, s_run = cseq, sseq
    for chunk in c2s:
        for i in range(0, len(chunk), segment_size):
            seg = chunk[i:i + segment_size]
            flat.append(("c", c_run, seg))
            c_run += len(seg)
    for chunk in s2c:
        for i in range(0, len(chunk), segment_size):
            seg = chunk[i:i + segment_size]
            flat.append(("s", s_run, seg))
            s_run += len(seg)

    for idx, (direction, seq, seg) in enumerate(flat):
        if direction == "c":
            emit(cip, cport, sip, sport, "PA", seq, sseq, seg)
        else:
            emit(sip, sport, cip, cport, "PA", seq, cseq, seg)
        if retransmit_index == idx:
            if direction == "c":
                emit(cip, cport, sip, sport, "PA", seq, sseq, seg)
            else:
                emit(sip, sport, cip, cport, "PA", seq, cseq, seg)

    cseq, sseq = c_run, s_run
    if close:
        emit(cip, cport, sip, sport, "FA", cseq, sseq)
        emit(sip, sport, cip, cport, "FA", sseq, cseq + 1)
        emit(cip, cport, sip, sport, "A", cseq + 1, sseq + 1)
    return pkts


def udp_pair(cip: str, cport: int, sip: str, sport: int, c2s: bytes = b"", s2c: bytes = b""):
    pkts = []
    if c2s:
        pkts.append(_eth(CMAC, SMAC) / IP(src=cip, dst=sip) / UDP(sport=cport, dport=sport) / Raw(c2s))
    if s2c:
        pkts.append(_eth(SMAC, CMAC) / IP(src=sip, dst=cip) / UDP(sport=sport, dport=cport) / Raw(s2c))
    return pkts


def dns_pair(cip: str, sip: str, name: str, *, answers=(), qtype="A", ts=None,
             response: bool = True, rcode: int = 0, answer_type: str = "A"):
    qname = name.encode() if isinstance(name, str) else name
    q = _eth(CMAC, SMAC) / IP(src=cip, dst=sip) / UDP(sport=5353, dport=53) / DNS(
        rd=1, qd=DNSQR(qname=qname, qtype=qtype))
    pkts = [q]
    if response:
        rrs = [DNSRR(type=answer_type, rdata=a, ttl=300) for a in answers]
        r = _eth(SMAC, CMAC) / IP(src=sip, dst=cip) / UDP(sport=53, dport=5353) / DNS(
            qr=1, rcode=rcode, qd=DNSQR(qname=qname, qtype=qtype), an=rrs)
        pkts.append(r)
    return pkts


def icmp_echo(cip: str, sip: str, payload: bytes, *, reply: bool = False, ts=None):
    if reply:
        return _eth(SMAC, CMAC) / IP(src=sip, dst=cip) / ICMP(type=0) / Raw(payload)
    return _eth(CMAC, SMAC) / IP(src=cip, dst=sip) / ICMP(type=8) / Raw(payload)


def syn_scan(cip: str, sip: str, ports, *, base_ts: float = BASE_TS):
    """SYN packets to many ports (one reply for the open ones)."""
    pkts = []
    for i, port in enumerate(ports):
        p = _eth(CMAC, SMAC) / IP(src=cip, dst=sip) / TCP(sport=40000 + i, dport=port, flags="S", seq=1000 + i)
        p.time = base_ts + i * 0.01
        pkts.append(p)
    return pkts


# ------------------------------------------------------------ covert channels

def http_version_covert(cip, sip, message: bytes, *, base_ts=BASE_TS,
                        sport=48000, ver_hi="1.1", ver_lo="1.0"):
    """One keep-alive TCP stream whose request HTTP-versions encode `message`.

    Each bit of the message (MSB-first) chooses the version of one
    request: bit=1 → ver_hi, bit=0 → ver_lo. Returns (packets, ground_truth).
    """
    requests = []
    i = 0
    for byte in message:
        for bit_i in range(7, -1, -1):
            ver = ver_hi if (byte >> bit_i) & 1 else ver_lo
            requests.append(
                f"GET /item/{i} HTTP/{ver}\r\nHost: shop.example\r\n"
                f"User-Agent: Mozilla/5.0 (shopper)\r\n\r\n".encode())
            i += 1
    responses = [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"] * len(requests)
    pkts = tcp_conversation(cip, sport, sip, 80, requests, responses,
                            base_ts=base_ts, segment_size=1 << 20)
    return pkts, message


def http_version_benign(cip, sip, versions, *, base_ts=BASE_TS, sport=48100):
    """Stream with arbitrary per-request versions (negative/red-herring case)."""
    requests = [
        f"GET /p/{i} HTTP/{v}\r\nHost: shop.example\r\n"
        f"User-Agent: Mozilla/5.0 (v{v})\r\n\r\n".encode()
        for i, v in enumerate(versions)]
    responses = [b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"] * len(requests)
    return tcp_conversation(cip, sport, sip, 80, requests, responses,
                            base_ts=base_ts, segment_size=1 << 20)


def dns_qtype_covert(cip, sip, message: bytes, *, base_ts=BASE_TS):
    """Encode `message` (uppercase A-Z + a small alphabet) via DNS query-type
    choice: bit=1 → AAAA, bit=0 → A. Returns (packets, ground_truth)."""
    import time
    rng2 = __import__("random").Random(99)
    pkts = []
    t = base_ts
    i = 0
    for byte in message:
        for bit_i in range(7, -1, -1):
            qtype = "AAAA" if (byte >> bit_i) & 1 else "A"
            name = f"img{i:03d}.cdn.example"
            q = (_eth(CMAC, SMAC) / IP(src=cip, dst=sip) /
                 UDP(sport=5353, dport=53) /
                 DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype)))
            q.time = t
            pkts.append(q)
            t += 0.01
            i += 1
    return pkts, message
