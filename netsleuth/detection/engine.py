"""Detector registry and execution.

A detector is a function ``detect(result) -> list[Finding]`` that reads
the structured AnalysisResult (never raw packets) and returns findings.
That makes every detector unit-testable with synthetic results and
keeps detection logic auditable: if you disagree with a finding, read
the detector — the evidence list shows exactly what it saw.
"""

from __future__ import annotations

from netsleuth.models import Confidence, Finding, Severity


def run_detectors(result) -> list[Finding]:
    from netsleuth.detection import (behaviors, beaconing, covert as covert_det,
                                    dnshunt, httphunt, misc)

    findings: list[Finding] = []
    for detector in (
        behaviors.detect_syn_scan,
        behaviors.detect_host_scan,
        behaviors.detect_unusual_ports,
        beaconing.detect_tcp_beaconing,
        beaconing.detect_dns_beaconing,
        dnshunt.detect_dns_tunneling,
        dnshunt.detect_nxdomain_anomaly,
        dnshunt.detect_suspicious_txt,
        httphunt.detect_attack_patterns,
        httphunt.detect_cleartext_http_auth,
        httphunt.detect_unusual_methods,
        misc.detect_arp_conflict,
        misc.detect_icmp_payload,
        misc.detect_cleartext_protocols,
        misc.detect_secret_material,
        misc.detect_bulk_transfer,
        covert_det.detect_covert_channels,
    ):
        try:
            findings.extend(detector(result))
        except Exception as e:                      # a broken detector never
            findings.append(Finding(                # kills the whole report
                id=f"internal.detector-error.{detector.__name__}",
                title=f"detector {detector.__name__} failed",
                severity=Severity.INFO,
                confidence=Confidence.HIGH,
                description=f"{type(e).__name__}: {e}",
                explanation="Internal error — the remaining findings are still valid; "
                            "please report this as a bug with the capture file.",
            ))
    # Correlate multiple findings converging on the same host
    findings.extend(correlate_findings(findings))

    sev = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    conf = {"high": 0, "medium": 1, "low": 2}
    findings.sort(key=lambda f: (sev[f.severity.value], conf[f.confidence.value], f.id))
    # stable dedupe by id (keeps first = most severe)
    seen: set[str] = set()
    out: list[Finding] = []
    for f in findings:
        if f.id not in seen:
            seen.add(f.id)
            out.append(f)
    return out


def correlate_findings(findings: list[Finding]) -> list[Finding]:
    """Correlate findings sharing the same source or destination host.

    When a single host is implicated in multiple distinct threats (e.g.
    port scanning + C2 beaconing + cleartext credentials), generate a
    high-confidence composite correlation finding linking the activities.
    """
    from netsleuth.enrichment.mitre import mitre

    by_host: dict[str, list[Finding]] = {}
    for f in findings:
        if f.severity == Severity.INFO or f.id.startswith("internal."):
            continue
        for h in f.hosts:
            if h and h not in ("?", "127.0.0.1", "::1"):
                by_host.setdefault(h, []).append(f)

    correlated: list[Finding] = []
    for host, h_findings in sorted(by_host.items()):
        # distinct finding categories (first segment of id)
        distinct_cats = {f.id.split(".")[0] for f in h_findings}
        med_high = [f for f in h_findings if f.severity in (Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)]
        
        # Trigger correlation if 3+ findings or 2+ medium/high findings across distinct categories
        if len(h_findings) >= 3 or (len(med_high) >= 2 and len(distinct_cats) >= 2):
            titles = [f"[{f.severity.value}] {f.title}" for f in h_findings[:5]]
            proto_set = {f.protocol for f in h_findings if f.protocol}
            proto_filter = "ipv6" if ":" in host else "ip"
            host_flt = f"{proto_filter}.addr == {host}"
            flts = [host_flt]
            for f in h_findings:
                for flt in f.wireshark_filters:
                    if flt not in flts:
                        flts.append(flt)

            correlated.append(Finding(
                id=f"correlation.host.{host}",
                title=f"Multi-finding correlation on host {host} ({len(h_findings)} findings)",
                severity=Severity.HIGH,
                confidence=Confidence.HIGH,
                description=(f"Host {host} is involved in {len(h_findings)} separate threat "
                             f"indicators across categories: {', '.join(sorted(distinct_cats))}."),
                explanation=(
                    "When multiple distinct suspicious behaviors (e.g., scanning, beaconing, "
                    "attack patterns, or credential exposure) converge on the same host, the "
                    "likelihood of a true incident is elevated. This correlated finding unifies "
                    "them for high-priority triage."),
                verification=f"In Wireshark: {host_flt} — isolate and review all conversation streams.",
                evidence=[f"correlated findings ({len(h_findings)} total):"] + titles,
                hosts=[host],
                protocol="/".join(sorted(proto_set)) or "tcp",
                wireshark_filters=flts[:4],
                mitre=[mitre("T1071", "correlated multi-stage network activity")],
            ))
    return correlated
