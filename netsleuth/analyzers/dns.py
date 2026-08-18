"""DNS analyzer: query inventory plus the signals detectors need.

The analyzer only *collects* facts (query counts, name lengths, label
entropy, TXT values, NXDOMAIN rates, subdomain fan-out). Judging whether
those facts mean "tunneling" or "C2" is the job of detection/dnshunt,
which consumes this data and must justify its conclusions with evidence.
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field

from netsleuth.models import DNSRecord, Packet, iso


def shannon_entropy(s: str) -> float:
    """Shannon entropy H(x) in bits/char — uniform-random ≈ log2(len alphabet)."""
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


@dataclass
class DomainStats:
    domain: str
    queries: int = 0
    nxdomain: int = 0
    subdomains: set[str] = field(default_factory=set)
    resolved_ips: set[str] = field(default_factory=set)
    txt_values: list[str] = field(default_factory=list)
    longest_label: int = 0
    max_entropy: float = 0.0
    query_types: Counter = field(default_factory=Counter)

    def to_dict(self) -> dict:
        return {
            "domain": self.domain, "queries": self.queries, "nxdomain": self.nxdomain,
            "unique_subdomains": len(self.subdomains), "resolved_ips": sorted(self.resolved_ips),
            "txt_record_count": len(self.txt_values),
            "longest_label": self.longest_label, "max_label_entropy": round(self.max_entropy, 2),
            "query_types": dict(self.query_types),
        }


@dataclass
class DNSData:
    queries: list[DNSRecord] = field(default_factory=list)
    domain_stats: dict[str, DomainStats] = field(default_factory=dict)
    total_queries: int = 0
    total_responses: int = 0
    nxdomain_count: int = 0
    txt_count: int = 0

    def base_domain(self, name: str) -> str:
        """example.co.uk → example.co.uk; a.b.example.com → example.com.

        A tiny public-suffix heuristic (not a full PSL): keeps the last
        three labels for known two-part TLDs, else the last two.
        """
        two_part = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au",
                    "co.jp", "or.jp", "co.nz", "com.br", "com.cn", "co.in",
                    "co.kr", "com.mx", "co.za", "com.tr"}
        labels = name.rstrip(".").split(".")
        if len(labels) <= 2:
            return name.rstrip(".")
        if ".".join(labels[-2:]) in two_part:
            return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def to_dict(self) -> dict:
        return {
            "total_queries": self.total_queries,
            "total_responses": self.total_responses,
            "nxdomain_count": self.nxdomain_count,
            "txt_record_count": self.txt_count,
            "queries": [
                {"ts": iso(q.ts), "client": q.client, "name": q.name,
                 "type": q.qtype, "response": q.is_response, "rcode": q.response_code,
                 "answers": q.answers}
                for q in self.queries[:2000]],
            "domains": [d.to_dict() for d in
                        sorted(self.domain_stats.values(), key=lambda d: -d.queries)],
        }


class DNSAnalyzer:
    name = "dns"

    def __init__(self) -> None:
        self.data = DNSData()

    def feed(self, pkt: Packet) -> None:
        if pkt.dns is None:
            return
        rec = pkt.dns
        d = self.data
        d.queries.append(rec)
        if rec.is_response:
            d.total_responses += 1
        else:
            d.total_queries += 1
        if rec.response_code == "NXDOMAIN":
            d.nxdomain_count += 1

        base = d.base_domain(rec.name)
        st = d.domain_stats.get(base)
        if st is None:
            st = DomainStats(domain=base)
            d.domain_stats[base] = st
        st.queries += 0 if rec.is_response else 1
        st.query_types[rec.qtype] += 1
        if rec.response_code == "NXDOMAIN":
            st.nxdomain += 1

        labels = rec.name.rstrip(".").split(".") if rec.name else []
        for label in labels:
            if len(label) > st.longest_label:
                st.longest_label = len(label)
            ent = shannon_entropy(label) if len(label) >= 8 else 0.0
            if ent > st.max_entropy:
                st.max_entropy = round(ent, 3)
        if labels:
            st.subdomains.add(".".join(labels[:-1]) or "(root)")

        for ans in rec.answers:
            if rec.answer_type == "A" or _looks_like_ip(ans):
                if ":" not in ans and ans[0].isdigit():
                    st.resolved_ips.add(ans)
            if rec.answer_type == "TXT":
                st.txt_values.append(ans)
                d.txt_count += 1

    def finalize(self) -> None:
        pass


def _looks_like_ip(s: str) -> bool:
    parts = s.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)
