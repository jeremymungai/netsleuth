"""Risk scoring — a triage number, not a verdict.

Formula (documented so nobody has to guess):

    score = strongest finding's severity weight
          + 25% of every other finding's severity weight
          × confidence multiplier   (high = 1.0, medium = 0.7, low = 0.4)
    capped at 100

The intent: one CRITICAL finding alone means 90; adding noise findings
never outweighs real severity. The breakdown field shows exactly what
fed the number.
"""

from __future__ import annotations

from netsleuth.models import Finding, RiskScore, Severity

_CONF_MULT = {"high": 1.0, "medium": 0.7, "low": 0.4}


def score_findings(findings: list[Finding]) -> RiskScore:
    if not findings:
        return RiskScore(score=0, breakdown={})
    contributions = sorted(
        (f.severity.weight * _CONF_MULT[f.confidence.value] for f in findings),
        reverse=True)
    score = contributions[0] + sum(c * 0.25 for c in contributions[1:])
    breakdown = {}
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = sum(1 for f in findings if f.severity == Severity(sev))
        if n:
            breakdown[sev] = n
    return RiskScore(score=min(100, int(round(score))), breakdown=breakdown)
