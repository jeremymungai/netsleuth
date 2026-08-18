"""Investigation timeline: chronological, filterable event view."""

from __future__ import annotations

from netsleuth.models import TimelineEvent

MAX_EVENTS = 600


def build_timeline(result) -> list[TimelineEvent]:
    events: list[TimelineEvent] = []

    if result.dns is not None:
        for q in result.dns.queries[:300]:
            if q.is_response:
                continue
            events.append(TimelineEvent(
                ts=q.ts, kind="dns",
                summary=f"DNS query {q.name!r} ({q.qtype}) from {q.client}",
                hosts=[q.client],
                wireshark_filter=f'dns.qry.name == "{q.name}"'))

    for t in result.http[:300]:
        label = f"HTTP {t.method} {t.host}{t.path}"
        if t.status:
            label += f" → {t.status}"
        events.append(TimelineEvent(
            ts=t.ts or 0, kind="http", summary=label,
            hosts=[h for h in (t.client, t.host) if h], stream=t.stream,
            wireshark_filter=(f'http.host == "{t.host}"' if t.host else "")))

    for s in result.tls[:200]:
        events.append(TimelineEvent(
            ts=s.ts or 0, kind="tls",
            summary=f"TLS handshake to {s.sni or s.dst}:{s.dst_port}"
                    + (f" (JA3 {s.ja3[:8]}…)" if s.ja3 else ""),
            hosts=[s.src, s.dst],
            wireshark_filter=(f'tls.handshake.extensions_server_name == "{s.sni}"'
                              if s.sni else "")))

    for st in result.streams[:150]:
        if st.bytes_c2s + st.bytes_s2c > 0:
            events.append(TimelineEvent(
                ts=st.start_ts or 0, kind="tcp",
                summary=f"TCP stream {st.index}: {st.client}:{st.client_port} → "
                        f"{st.server}:{st.server_port} "
                        f"({st.total_bytes} B)",
                hosts=[st.client, st.server], stream=st.index,
                wireshark_filter=f"tcp.stream == {st.index}"))

    for a in result.artifacts[:100]:
        events.append(TimelineEvent(
            ts=a.ts or 0, kind="file",
            summary=f"File transferred: {a.filename} ({a.size} B, {a.detected_type})",
            hosts=[h for h in (a.src, a.dst) if h], stream=a.stream))

    for f in result.findings:
        if f.severity.value in ("CRITICAL", "HIGH", "MEDIUM") and f.first_ts:
            events.append(TimelineEvent(
                ts=f.first_ts, kind="detection",
                summary=f"[{f.severity.value}] {f.title}",
                severity=f.severity, hosts=f.hosts,
                wireshark_filter=f.wireshark_filters[0] if f.wireshark_filters else ""))

    events.sort(key=lambda e: e.ts)
    return events[:MAX_EVENTS]


def filter_events(events, host=None, kind=None, min_severity=None):
    min_sev = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    floor = min_sev.get(min_severity, 0) if min_severity else 0
    out = []
    for e in events:
        if host and host not in e.hosts:
            continue
        if kind and e.kind != kind:
            continue
        if min_sev.get(e.severity.value, 0) < floor:
            continue
        out.append(e)
    return out
