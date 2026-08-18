#!/usr/bin/env python3
"""Generate NetSleuth's covert-channel demo capture (all synthetic).

The story: a workstation exfiltrates a message through the *choice of
HTTP version* on ordinary-looking shopping requests — every packet is
individually legal, and only the version sequence carries data.

    ground truth message:  COVERT{v3rsion_s3l3ction}
    encoding:              bit=1 → HTTP/1.1, bit=0 → HTTP/1.0, MSB-first

Red herrings included: a second client with constant versions, a third
with random version noise, random DNS query-type chatter, and a small
port scan.

Usage:  python examples/generate_covert.py [out.pcap]
Then:   python -m netsleuth covert out.pcap
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "tests"))

from pcapfix import (  # noqa: E402
    BASE_TS, dns_pair, http_version_benign, http_version_covert, syn_scan,
    write_pcap,
)

C, S = "192.168.1.50", "203.0.113.9"
TRUTH = b"COVERT{v3rsion_s3l3ction}"


def build() -> list:
    rng = random.Random(2026)
    pkts, _ = http_version_covert(C, S, TRUTH)
    pkts += http_version_benign("192.168.1.61", S, ["1.1"] * 60,
                                base_ts=BASE_TS + 5)
    pkts += http_version_benign("192.168.1.62", S,
                                [rng.choice(("1.0", "1.1")) for _ in range(60)],
                                base_ts=BASE_TS + 6)
    for i in range(40):
        pkts += dns_pair("192.168.1.62", "8.8.8.8", f"h{i}.example",
                         answers=[], response=False,
                         qtype=rng.choice(("A", "AAAA")))
    pkts += syn_scan("192.168.1.70", S, range(300, 330), base_ts=BASE_TS + 9)
    return pkts


def main() -> None:
    out = sys.argv[1] if len(sys.argv) > 1 else \
        str(Path(__file__).parent / "covert.pcap")
    pkts = build()
    write_pcap(out, pkts)
    print(f"wrote {out}: {len(pkts)} packets")
    print(f"ground truth: {TRUTH.decode()} "
          f"(HTTP version selection, MSB-first, 1 bit/request)")
    print("recover it with:  python -m netsleuth covert " + out)


if __name__ == "__main__":
    main()
