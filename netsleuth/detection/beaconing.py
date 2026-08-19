"""Statistical beaconing detection.

Looks for repeated connections whose *intervals* are suspiciously
regular (low jitter) — the timing signature of C2 check-ins. This is an
indicator, never proof: NTP, monitoring agents and update checks also
beacon beautifully. Every finding says so.

Method: for each (source, destination, port) group of TCP connections,
compute the coefficient of variation (stddev/mean) of inter-connection
intervals. Low CV + enough samples = regular timing. Payload-size
uniformity adds supporting weight.
"""

from __future__ import annotations

import statistics

from netsleuth.detection.allowlists import is_telemetry_domain
from netsleuth.detection.dnshunt import well_known_query
from netsleuth.detection.dcs import is_dc_port
from netsleuth.enrichment.mitre import mitre
from netsleuth.models import Confidence, Finding, Severity

MIN_CONNECTIONS = 8            # below this, regularity is coincidence
CV_HIGH = 0.30                 # very regular
CV_MEDIUM = 0.55
CV_LOW = 0.90                  # borderline — only reported with size regularity


def _cv(values: list[float]) -> float:
    if len(values) < 2:
        return 99.0
    mean = statistics.mean(values)
    if mean == 0:
        return 99.0
    return statistics.pstdev(values) / mean


def detect_tcp_beaconing(result) -> list[Finding]:
    if result.overview is None:
        return []
    groups: dict[tuple, list] = {}
    for f in result.overview.flow_tracker.flows.values():
        if f.proto != "tcp" or f.first_ts is None:
            continue
        groups.setdefault((f.src, f.dst, f.dport), []).append(f)

    findings = []
    dcs = set(getattr(result, "domain_controllers", None) or ())
    for (src, dst, dport), flows in sorted(groups.items()):
        if dst in dcs and is_dc_port(dport):
            continue      # scheduled DC traffic: Group Policy, Kerberos, SYSVOL
        starts = sorted(f.first_ts for f in flows)
        if len(starts) < MIN_CONNECTIONS:
            continue
        intervals = [b - a for a, b in zip(starts, starts[1:]) if b > a]
        if len(intervals) < MIN_CONNECTIONS - 2:
            continue
        cv = _cv(intervals)
        sizes = [f.bytes for f in flows if f.bytes > 0]
        size_cv = _cv(sizes) if len(sizes) >= MIN_CONNECTIONS - 2 else 99.0
        span = starts[-1] - starts[0]

        conf, severity = None, None
        if cv < CV_HIGH:
            conf, severity = Confidence.HIGH, Severity.HIGH
        elif cv < CV_MEDIUM:
            conf, severity = Confidence.MEDIUM, Severity.MEDIUM
        elif cv < CV_LOW and size_cv < 0.5:
            conf, severity = Confidence.LOW, Severity.LOW
        if conf is None:
            continue

        mean_interval = statistics.mean(intervals)
        findings.append(Finding(
            id=f"beacon.tcp.{src}.{dst}.{dport}",
            title=f"Periodic connections: {src} → {dst}:{dport} "
                  f"({len(starts)} connections, ~{mean_interval:.1f}s interval)",
            severity=severity,
            confidence=conf,
            description=(f"{src} connected to {dst}:{dport} {len(starts)} times "
                         f"with a mean interval of {mean_interval:.1f}s and low "
                         f"timing variance (CV={cv:.2f})."),
            explanation=(
                "Malware check-ins are often timer-driven, so their connection "
                "intervals are far more regular than human-driven traffic. "
                "BUT: software updaters, NTP clients, monitoring agents and "
                "messaging apps also produce regular traffic. This is an "
                "indicator to investigate, not evidence of compromise on its "
                "own. Check the destination's reputation and the stream "
                "content."),
            verification=(f"In Wireshark: ip.addr == {dst} && tcp.port == {dport}"
                          " — look at the time column (Δtime) between "
                          "connections."),
            evidence=[f"connections: {len(starts)}",
                      f"mean interval: {mean_interval:.1f}s "
                      f"(jitter stddev {statistics.pstdev(intervals):.2f}s, CV {cv:.2f})",
                      f"observation window: {span:.0f}s "
                      f"(≈ {span / max(mean_interval, 0.001):.0f} intervals)",
                      f"payload size uniformity: CV {size_cv:.2f} across "
                      f"{len(sizes)} data-bearing connections"
                      + (" (sizes highly uniform)" if size_cv < 0.3 else "")],
            hosts=[src, dst],
            protocol="tcp",
            first_ts=starts[0], last_ts=starts[-1],
            wireshark_filters=[f"ip.addr == {dst} && tcp.port == {dport}"],
            mitre=[mitre("T1071.001" if dport in (80, 8080, 443, 8443) else "T1095",
                         "regularly-timed repeated connections consistent with "
                         "a C2 check-in schedule")],
        ))
    return findings[:6]


def detect_dns_beaconing(result) -> list[Finding]:
    """Same idea for repeated DNS queries to one domain."""
    if result.dns is None:
        return []
    groups: dict[tuple, list[float]] = {}
    for q in result.dns.queries:
        if q.is_response or not q.name:
            continue
        groups.setdefault((q.client, q.name), []).append(q.ts)
    findings = []
    for (client, name), times in sorted(groups.items()):
        if is_telemetry_domain(name) or well_known_query(name):
            continue      # OS telemetry and WPAD/AD service discovery are
                          # scheduled by the OS itself, not by malware
        times.sort()
        if len(times) < MIN_CONNECTIONS:
            continue
        intervals = [b - a for a, b in zip(times, times[1:]) if b > a]
        if len(intervals) < MIN_CONNECTIONS - 2:
            continue
        cv = _cv(intervals)
        if cv >= CV_MEDIUM:
            continue
        mean_interval = statistics.mean(intervals)
        findings.append(Finding(
            id=f"beacon.dns.{client}.{name}",
            title=f"Periodic DNS queries: {client} → {name} every ~{mean_interval:.0f}s",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM if cv < CV_HIGH else Confidence.LOW,
            description=(f"{client} queried {name} {len(times)} times at a mean "
                         f"interval of {mean_interval:.1f}s (CV={cv:.2f})."),
            explanation=(
                "Regular DNS lookups of the same name can be DNS-based C2 "
                "(queries carry no data here, but the schedule does) or plain "
                "background software behavior. Judge together with the "
                "resolved addresses and any tunneling indicators."),
            verification=f'In Wireshark: dns.qry.name == "{name}"',
            evidence=[f"queries: {len(times)}",
                      f"mean interval: {mean_interval:.1f}s (CV {cv:.2f})"],
            hosts=[client],
            protocol="dns",
            first_ts=times[0], last_ts=times[-1],
            wireshark_filters=[f'dns.qry.name == "{name}"'],
            mitre=[mitre("T1071.004", "regularly scheduled DNS queries to a "
                                      "single domain")],
        ))
    return findings[:4]
