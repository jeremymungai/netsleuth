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
