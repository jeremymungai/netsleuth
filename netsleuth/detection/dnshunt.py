"""DNS threat hunting: tunneling, NXDOMAIN anomalies, TXT abuse.

Every signal here is *combined* — a single "long label" or one odd TXT
record fires nothing. Confidence grows with the number of independent
signals observed for the same domain, and the finding lists exactly
which signals fired.
"""

from __future__ import annotations

from netsleuth.analyzers.dns import shannon_entropy
from netsleuth.enrichment.mitre import mitre
from netsleuth.extraction.encodings import looks_like_base32, looks_like_hex
from netsleuth.models import Confidence, Finding, Severity

LONG_LABEL = 32                  # tunnel chunk size territory
HIGH_ENTROPY = 3.6               # bits/char for a random-looking label
MANY_SUBDOMAINS = 25             # unique subdomains per base domain
TXT_BULK = 4                     # TXT answers for one domain in one capture
NXDOMAIN_BULK = 15
LONG_NAME = 100


def _example_queries(result, domain: str, n: int = 3) -> list[str]:
    seen = []
    for q in result.dns.queries:
        if result.dns.base_domain(q.name) == domain and q.name not in seen:
            seen.append(q.name)
        if len(seen) >= n:
            break
    return seen


def detect_dns_tunneling(result) -> list[Finding]:
    if result.dns is None:
        return []
    findings = []
    for st in result.dns.domain_stats.values():
        if st.queries == 0:
            continue
        signals: list[str] = []
        examples = _example_queries(result, st.domain)

        if st.longest_label >= LONG_LABEL:
            signals.append(f"unusually long labels (max {st.longest_label} chars; "
                           "normal hostnames rarely exceed ~25)")
        if st.max_entropy >= HIGH_ENTROPY:
            signals.append(f"high-entropy labels (max {st.max_entropy} bits/char "
                           "— consistent with encoded data, not words)")
        if len(st.subdomains) >= MANY_SUBDOMAINS:
            signals.append(f"{len(st.subdomains)} unique subdomains queried "
                           "(rapidly-changing left-hand parts)")
        if len(st.txt_values) >= TXT_BULK:
            signals.append(f"{len(st.txt_values)} TXT responses (TXT is the classic "
                           "channel for tunnel replies)")
        if not signals:
            continue

        encoded_look = any(looks_like_base32(l.split(".")[0])
                           or looks_like_hex(l.split(".")[0])
                           for l in examples if l)
        if encoded_look:
            signals.append("left-most labels look Base32/Hex-encoded")

        if len(signals) >= 3:
            severity, conf = Severity.HIGH, Confidence.HIGH
        elif len(signals) == 2:
            severity, conf = Severity.MEDIUM, Confidence.MEDIUM
        else:
            severity, conf = Severity.LOW, Confidence.LOW

        findings.append(Finding(
            id=f"dns.tunnel.{st.domain}",
            title=f"Possible DNS tunneling via {st.domain}",
            severity=severity,
            confidence=conf,
            description=(f"{st.queries} queries to *.{st.domain} show "
                         + "; ".join(signs.lower() for signs in signals) + "."),
            explanation=(
                "DNS tunneling encodes data (C2 commands or exfiltrated bytes) "
                "into hostname labels — e.g. "
                "NBSWY3DPFQQFO33SNRSC65LJMQ.tunnel.example.com. The encoding "
                "forces long, high-entropy, ever-changing subdomains, which is "
                "what these signals measure. Legitimate services (CDNs, "
                "load balancers) can also generate many subdomains — check "
                "whether the labels decode to something meaningful before "
                "calling it malicious."),
            verification=(f'In Wireshark: dns.qry.name contains "{st.domain}" '
                          "— inspect the queried names; try Base32/Base64-"
                          "decoding the left-most label of the longest ones."),
            evidence=[f"signals fired: {len(signals)}"] +
                     [f"example query: {e[:100]}" for e in examples],
            hosts=sorted({q.client for q in result.dns.queries
                          if result.dns.base_domain(q.name) == st.domain}),
            protocol="dns",
            first_ts=min((q.ts for q in result.dns.queries
                          if result.dns.base_domain(q.name) == st.domain), default=None),
            wireshark_filters=[f'dns.qry.name contains "{st.domain}"'],
            mitre=[mitre("T1071.004", "DNS used as a data channel"),
                   mitre("T1132.001", "hostname labels consistent with encoded data")],
        ))
    return findings[:8]


def detect_nxdomain_anomaly(result) -> list[Finding]:
    if result.dns is None:
        return []
    findings = []
    for st in result.dns.domain_stats.values():
        if st.nxdomain < NXDOMAIN_BULK or st.queries == 0:
            continue
        if st.nxdomain / st.queries < 0.5:
            continue
        findings.append(Finding(
            id=f"dns.nx.{st.domain}",
            title=f"High NXDOMAIN rate for {st.domain} "
                  f"({st.nxdomain}/{st.queries})",
            severity=Severity.LOW,
            confidence=Confidence.LOW,
            description=(f"{st.nxdomain} of {st.queries} queries under "
                         f"{st.domain} returned NXDOMAIN (domain does not exist)."),
            explanation=(
                "Bursts of NXDOMAIN usually mean one of: a DGA (malware "
                "generating random domains to find its C2), subdomain "
                "brute-forcing, or simply broken software retrying a "
                "hard-coded name. On its own this is weak — correlate with "
                "the querying host's other activity."),
            verification=f'In Wireshark: dns.qry.name contains "{st.domain}" '
                         "&& dns.flags.rcode == 3",
            evidence=[f"NXDOMAIN: {st.nxdomain}/{st.queries} queries"],
            hosts=sorted({q.client for q in result.dns.queries
                          if result.dns.base_domain(q.name) == st.domain}),
            protocol="dns",
            wireshark_filters=[f'dns.qry.name contains "{st.domain}" '
                               "&& dns.flags.rcode == 3"],
            mitre=[mitre("T1071.004", "high-volume failing DNS lookups "
                                      "(DGA-style behavior)")],
        ))
    return findings[:4]


def detect_suspicious_txt(result) -> list[Finding]:
    if result.dns is None:
        return []
    interesting: list[tuple[str, str]] = []
    for st in result.dns.domain_stats.values():
        for val in st.txt_values:
            if len(val) >= 60 and (looks_like_base32(val.upper()) or
                                   shannon_entropy(val) >= 4.2):
                interesting.append((st.domain, val))
    if not interesting:
        return []
    domain, val = interesting[0]
    return [Finding(
        id=f"dns.txt.{domain}",
        title=f"Dense data in DNS TXT record for {domain}",
        severity=Severity.MEDIUM,
        confidence=Confidence.MEDIUM,
        description=(f"TXT record carries {len(val)} characters of "
                     "high-entropy, encoded-looking data."),
        explanation=(
            "TXT records legitimately hold SPF/DKIM data, but those are "
            "readable strings like \"v=spf1 -all\". Long opaque blobs are "
            "how DNS-tunnel C2 replies and some malware configs travel. "
            "Try Base32/Base64-decoding the value."),
        verification=f'In Wireshark: dns.qry.name == "{domain}" && dns.txt',
        evidence=[f"TXT value ({len(val)} chars): {val[:80]}…",
                  f"entropy: {shannon_entropy(val):.1f} bits/char"],
        hosts=sorted({q.client for q in result.dns.queries
                      if result.dns.base_domain(q.name) == domain}),
        protocol="dns",
        wireshark_filters=[f'dns.qry.name == "{domain}" && dns.txt'],
        mitre=[mitre("T1071.004", "data-bearing TXT records")],
    )]
