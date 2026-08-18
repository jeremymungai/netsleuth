"""Wireshark companion: display filters for manual verification.

The philosophy: "we found this — here is how you would find it yourself
in Wireshark." Every finding already carries its filters; this module
builds the broader per-host / per-domain / per-stream filter kit that
the guided analysis prints as its final step.
"""

from __future__ import annotations


def companion_filters(result, max_hosts: int = 10) -> list[tuple[str, list[str]]]:
    """Grouped display filters for the capture's key entities."""
    groups: list[tuple[str, list[str]]] = []

    if result.findings:
        ffilters: list[str] = []
        for f in result.findings:
            for flt in f.wireshark_filters[:1]:
                entry = f"{flt}"
                if entry not in ffilters:
                    ffilters.append(entry)
        if ffilters:
            groups.append(("Verify findings", ffilters[:12]))

    if result.overview is not None:
        hosts = result.overview.top_talkers(max_hosts)
        host_filters = [f"ip.addr == {h.ip}" for h in hosts[:6]]
        if host_filters:
            groups.append(("Focus on top talkers", host_filters))

    suspicious_domains = []
    if result.dns is not None:
        for st in sorted(result.dns.domain_stats.values(),
                         key=lambda s: -s.queries)[:5]:
            if st.queries >= 3:
                suspicious_domains.append(f'dns.qry.name contains "{st.domain}"')
    if suspicious_domains:
        groups.append(("Top queried domains", suspicious_domains))

    cred_streams = sorted({c.stream for c in result.credentials if c.stream >= 0})
    if cred_streams:
        groups.append(("Streams with cleartext credentials",
                       [f"tcp.stream == {i}" for i in cred_streams[:8]]))

    if result.http:
        posts = [f'http.request.method == "{t.method}"'
                 for t in result.http if t.method in ("POST", "PUT")]
        if posts:
            groups.append(("State-changing HTTP requests", posts[:1]))
        downloads = [t for t in result.http
                     if t.status == 200 and t.resp_body_len > 0][:6]
        dl = [f'http.request.full_uri contains "{t.path}"' for t in downloads
              if t.path not in ("/",)]
        if dl:
            groups.append(("File downloads over HTTP", dl))

    unusual = [st for st in result.streams
               if st.server_port not in (80, 443, 53, 22, 25) and st.total_bytes > 0]
    if unusual:
        groups.append(("Streams on unusual ports",
                       [f"tcp.stream == {st.index}" for st in unusual[:8]]))

    return groups
