"""Covert-channel detector: promotes engine candidates into findings.

The heavy lifting lives in ``netsleuth.covert``; this module only
translates candidates into the Finding contract (evidence, confidence,
Wireshark filter, MITRE where justified) so covert channels surface in
`detect`, `analyze` and the reports.
"""

from __future__ import annotations

from netsleuth.enrichment.mitre import mitre
from netsleuth.models import Confidence, Finding, Severity

_SEV = {"high": (Severity.HIGH, Confidence.HIGH),
        "medium": (Severity.MEDIUM, Confidence.MEDIUM),
        "low": (Severity.LOW, Confidence.LOW)}


def detect_covert_channels(result) -> list[Finding]:
    findings = []
    for c in result.covert:
        severity, confidence = _SEV.get(c.confidence, (Severity.LOW, Confidence.LOW))
        findings.append(Finding(
            id=f"covert.{c.protocol}.{c.field}.{c.source}",
            title=f"Possible covert-channel candidate: {c.protocol} "
                  f"{c.field} of {c.source}",
            severity=severity,
            confidence=confidence,
            description=(
                f"The {c.field} field across {c.sequence_len} "
                f"{c.protocol.upper()} messages from {c.source} varies over a "
                f"small alphabet ({', '.join(c.observed_values)}) in a "
                f"{c.pattern}. Mapping the values to bits and grouping 8 "
                f"per byte yields {c.byte_len} bytes that decode to "
                f"printable-looking output ({c.printable_ratio:.0%})."),
            explanation=(
                "Protocol metadata fields that the sender can freely choose "
                "(HTTP version, query type, TTL, port…) can carry hidden "
                "information by *value selection*: every packet is legal on "
                "its own, and only the sequence encodes data. This is an "
                "indicator, not proof — the same variation can occur "
                "naturally (client pools, load balancers). Judge by whether "
                "the decoded output is meaningful and whether the pattern "
                "persists. Full derivation: `netsleuth covert <pcap>`."),
            verification=(
                f"In Wireshark: {c.wireshark_filters[0] if c.wireshark_filters else '—'}"
                " — read the field of each packet in order, note the values "
                "(the engine observed: " +
                ", ".join(f"{v}×{n}" for v, n in list(c.value_counts.items())[:4]) +
                "), assign bits per the mapping and decode 8 bits per byte."),
            evidence=[f"pattern: {c.pattern}",
                      f"mapping: {c.mapping}",
                      f"bitstream: {c.bits_len} bits → {c.byte_len} bytes",
                      f"decoded (first 120 chars): {c.decoded[:120]!r}",
                      f"printable ratio: {c.printable_ratio:.2f}"]
                     + ([f"frames {c.frames[0]}–{c.frames[-1]}"] if c.frames else []),
            hosts=[c.source],
            protocol=c.protocol,
            first_ts=c.first_ts, last_ts=c.last_ts,
            packet_refs=[f"frame {f}" for f in c.frames[:4]],
            wireshark_filters=list(c.wireshark_filters),
            mitre=[mitre("T1132.001", "information encoded into protocol "
                                     "field choices rather than payload"),
                   mitre("T1071.001" if c.protocol == "http" else "T1095",
                         "application/protocol metadata used as a covert "
                         "data channel")],
        ))
    return findings[:6]
