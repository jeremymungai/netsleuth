#!/usr/bin/env python3
"""Benchmark NetSleuth on synthetic captures of increasing size.

Measures wall time, packets/second and resident memory for the full
pipeline. Synthetic traffic only — no real captures needed.

Usage:  python scripts/benchmark.py [packets=50000]
"""

from __future__ import annotations

import os
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from scapy.all import Ether, IP, TCP, UDP, DNS, DNSQR, Raw, wrpcap  # noqa: E402

from netsleuth.pipeline import Options, Pipeline  # noqa: E402


def gen_capture(path: str, n: int) -> None:
    """n packets of mixed DNS + TCP-with-payload traffic."""
    pkts = []
    base = 1755472800.0
    for i in range(n):
        t = base + i * 0.001
        if i % 3 == 0:
            p = (Ether(src="08:00:27:11:11:11", dst="08:00:27:22:22:22") /
                 IP(src="192.168.1.50", dst="8.8.8.8") /
                 UDP(sport=5353, dport=53) /
                 DNS(rd=1, qd=DNSQR(qname=f"host{i % 50}.example.com")))
        else:
            payload = b"GET /page HTTP/1.1\r\nHost: bench.test\r\n\r\n"
            p = (Ether(src="08:00:27:11:11:11", dst="08:00:27:22:22:22") /
                 IP(src="192.168.1.50", dst="93.184.216.34") /
                 TCP(sport=40000 + (i % 500), dport=80, flags="PA",
                     seq=1000 + i * 40, ack=1) / Raw(payload))
        p.time = t
        pkts.append(p)
    wrpcap(path, pkts)


def rss_mb() -> float:
    """Peak resident memory in MB (platform-dependent)."""
    if os.name == "nt":
        import ctypes

        class PMC(ctypes.Structure):
            _fields_ = [("cb", ctypes.c_uint32), ("PageFaultCount", ctypes.c_uint32),
                        ("PeakWorkingSetSize", ctypes.c_size_t),
                        ("WorkingSetSize", ctypes.c_size_t)]
        pmc = PMC()
        pmc.cb = ctypes.sizeof(PMC)
        kernel32 = ctypes.WinDLL("kernel32")
        proc = kernel32.GetCurrentProcess()
        for dll_name in ("psapi", "kernel32"):
            try:
                dll = ctypes.WinDLL(dll_name)
                api = getattr(dll, "GetProcessMemoryInfo", None) or \
                    getattr(dll, "K32GetProcessMemoryInfo", None)
                if api is None:
                    continue
                api.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_uint32]
                api.restype = ctypes.c_int
                if api(proc, ctypes.byref(pmc), pmc.cb):
                    return pmc.PeakWorkingSetSize / (1024 * 1024)
            except OSError:
                continue
        return -1.0
    import resource
    return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024


def main() -> None:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 50_000
    with tempfile.TemporaryDirectory() as d:
        cap = os.path.join(d, "bench.pcap")
        t0 = time.perf_counter()
        gen_capture(cap, n)
        gen_s = time.perf_counter() - t0
        size = os.path.getsize(cap) / 1e6

        t0 = time.perf_counter()
        res = Pipeline(cap).run()
        wall = time.perf_counter() - t0

        print(f"packets        : {n:,}")
        print(f"capture size   : {size:.1f} MB")
        print(f"full pipeline  : {wall:.2f} s  "
              f"({int(n / wall):,} packets/s)")
        rss = rss_mb()
        print(f"peak RSS       : {f'{rss:.0f} MB' if rss >= 0 else 'not measurable in this environment'}")
        print(f"result         : {res.meta.packet_count:,} packets, "
              f"{len(res.streams)} streams, {len(res.http)} http, "
              f"{res.dns.total_queries if res.dns else 0} dns queries, "
              f"{len(res.findings)} findings")
        print(f"(fixture generation itself took {gen_s:.1f} s — excluded)")


if __name__ == "__main__":
    main()
