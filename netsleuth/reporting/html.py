"""Self-contained HTML report.

Security: every value derived from the capture passes through
``html.escape`` (this is a tool that renders attacker-controlled data).
The report embeds CSS only — no scripts, no external resources, no
CDNs — so it is safe to open locally and to share.
"""

from __future__ import annotations

import html
from datetime import datetime, timezone

from netsleuth.models import iso

_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--border:#30363d;--fg:#c9d1d9;--dim:#8b949e;
--accent:#58a6ff;--crit:#f85149;--high:#f85149;--med:#d29922;--low:#58a6ff;
--ok:#3fb950;--mono:ui-monospace,'Cascadia Code',Consolas,monospace}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--fg);font:14px/1.6 -apple-system,'Segoe UI',Roboto,sans-serif;padding:2rem}
.wrap{max-width:1100px;margin:0 auto}
h1{font-size:1.6rem;margin-bottom:.3rem} h2{font-size:1.2rem;margin:2rem 0 .8rem;
border-bottom:1px solid var(--border);padding-bottom:.4rem;color:var(--accent)}
h3{font-size:1rem;margin:1rem 0 .4rem}
.meta{color:var(--dim);margin-bottom:1.5rem}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:13px}
th,td{border:1px solid var(--border);padding:6px 10px;text-align:left;vertical-align:top}
th{background:var(--panel);font-weight:600}
tr:nth-child(even) td{background:#11161d}
code,.mono{font-family:var(--mono);font-size:12px;color:var(--accent);word-break:break-all}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:11px;font-weight:700}
.CRITICAL{background:var(--crit);color:#fff}.HIGH{background:#3d1618;color:var(--high)}
.MEDIUM{background:#3a2d0a;color:var(--med)}.LOW{background:#0e2a44;color:var(--low)}
.INFO{background:#1c2128;color:var(--dim)}
.score-hero{display:flex;align-items:center;gap:1.5rem;background:var(--panel);
border:1px solid var(--border);border-radius:8px;padding:1.2rem 1.5rem;margin:1rem 0}
.score-num{font-size:2.6rem;font-weight:800;font-family:var(--mono)}
.finding{background:var(--panel);border:1px solid var(--border);border-left:4px solid var(--dim);
border-radius:6px;padding:1rem 1.2rem;margin:.8rem 0}
.finding.CRITICAL{border-left-color:var(--crit)}.finding.HIGH{border-left-color:var(--high)}
.finding.MEDIUM{border-left-color:var(--med)}.finding.LOW{border-left-color:var(--low)}
.finding .title{font-weight:700;margin-bottom:.3rem}
.ev{color:var(--dim);font-size:13px;margin:.3rem 0 .3rem 1rem;list-style:square}
.why{color:var(--dim);font-size:13px;margin:.4rem 0 0;font-style:italic}
details{margin:.4rem 0} summary{cursor:pointer;color:var(--accent);font-size:13px}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:.8rem}
.card{background:var(--panel);border:1px solid var(--border);border-radius:6px;padding:.8rem}
.card .k{color:var(--dim);font-size:11px;text-transform:uppercase;letter-spacing:.5px}
.card .v{font-size:1.25rem;font-weight:700;font-family:var(--mono)}
footer{color:var(--dim);font-size:12px;margin-top:3rem;border-top:1px solid var(--border);padding-top:1rem}
.filter{font-family:var(--mono);font-size:12px;background:#0a0e14;border:1px solid var(--border);
border-radius:4px;padding:2px 8px;display:inline-block;margin:2px 0;color:#7ee787}
"""


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def e(s) -> str:
    return html.escape(str(s if s is not None else ""), quote=True)


def generate_html(result) -> str:
    m = result.meta
    score = result.score
    parts: list[str] = [f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetSleuth Report — {e(m.path)}</title>
<style>{_CSS}</style></head><body><div class="wrap">
<h1>NetSleuth Analysis Report</h1>
<p class="meta">{e(m.path)} · generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}
· <b>{e(m.format)}</b>{' · <b>truncated</b>' if m.truncated else ''}</p>"""]

    # score hero + stat cards
    sev_color = {"critical": "var(--crit)", "high": "var(--high)",
                 "elevated": "var(--med)", "low": "var(--low)",
                 "none": "var(--ok)"}[score.label]
    cards = [
        ("Packets", f"{m.packet_count:,}"),
        ("Duration", f"{m.duration:.1f}s"),
        ("Hosts", str(len(result.overview.hosts)) if result.overview else "—"),
        ("Findings", str(len(result.findings))),
    ]
    parts.append(f"""<div class="score-hero">
<div class="score-num" style="color:{sev_color}">{score.score}<span style="font-size:1rem;color:var(--dim)">/100</span></div>
<div><b style="color:{sev_color};text-transform:uppercase">{e(score.label)}</b><br>
<span style="color:var(--dim)">composite risk — a triage signal, not a verdict</span></div>
<div class="grid" style="margin-left:auto">""")
    for k, v in cards:
        parts.append(f'<div class="card"><div class="k">{e(k)}</div><div class="v">{e(v)}</div></div>')
    parts.append("</div></div>")

    # overview table
    parts.append("<h2>Capture overview</h2><table>")
    for k, v in (("File", m.path), ("Format", m.format), ("Size", _fmt_bytes(m.size_bytes)),
                 ("Packets", f"{m.packet_count:,}"), ("First packet", iso(m.first_ts) or "—"),
                 ("Last packet", iso(m.last_ts) or "—"), ("Duration", f"{m.duration:.3f}s"),
                 ("Link type", m.linktype or "—")):
        parts.append(f"<tr><th>{e(k)}</th><td>{e(v)}</td></tr>")
    parts.append("</table>")
    for note in m.notes:
        parts.append(f'<p style="color:var(--med)">note: {e(note)}</p>')

    # hosts
    if result.overview is not None:
        from netsleuth.enrichment.nets import classify_network
        parts.append("<h2>Hosts</h2><table><tr><th>IP</th><th>Network</th>"
                     "<th>Hostnames</th><th>Sent</th><th>Received</th></tr>")
        for h in sorted(result.overview.hosts.values(), key=lambda h: h.ip)[:200]:
            parts.append(f"<tr><td class='mono'>{e(h.ip)}</td><td>{e(classify_network(h.ip))}"
                         f"</td><td>{e(', '.join(sorted(h.hostnames)) or '—')}"
                         f"</td><td>{e(_fmt_bytes(h.bytes_sent))}"
                         f"</td><td>{e(_fmt_bytes(h.bytes_received))}</td></tr>")
        parts.append("</table><h2>Top conversations</h2><table><tr><th>A</th><th>B</th>"
                     "<th>Port</th><th>Proto</th><th>Packets</th><th>Bytes</th></tr>")
        for c in result.overview.top_conversations(12):
            parts.append(f"<tr><td class='mono'>{e(c.a)}</td><td class='mono'>{e(c.b)}</td>"
                         f"<td>{e(c.b_port)}</td><td>{e(c.proto)}</td><td>{c.packets:,}"
                         f"</td><td>{e(_fmt_bytes(c.bytes))}</td></tr>")
        parts.append("</table>")

    # DNS
    if result.dns is not None:
        parts.append("<h2>DNS</h2><table><tr><th>Domain</th><th>Queries</th><th>NX</th>"
                     "<th>Subdomains</th><th>Resolved</th><th>Max label / entropy</th></tr>")
        for st in sorted(result.dns.domain_stats.values(), key=lambda s: -s.queries)[:25]:
            parts.append(f"<tr><td>{e(st.domain)}</td><td>{st.queries}</td><td>{st.nxdomain}</td>"
                         f"<td>{len(st.subdomains)}</td>"
                         f"<td class='mono'>{e(', '.join(sorted(st.resolved_ips)[:2]) or '—')}"
                         f"</td><td>{st.longest_label} ch / {st.max_entropy:.1f} bpc</td></tr>")
        parts.append("</table>")

    # HTTP
    if result.http:
        parts.append("<h2>HTTP</h2><table><tr><th>Time</th><th>Method</th><th>Host + path</th>"
                     "<th>Status</th><th>Type</th><th>Bytes</th></tr>")
        for t in result.http[:150]:
            parts.append(f"<tr><td>{e((iso(t.ts) or '')[11:19])}</td><td>{e(t.method)}</td>"
                         f"<td class='mono'>{e(t.host)}{e(t.path)}</td><td>{e(t.status or '…')}"
                         f"</td><td>{e((t.content_type_resp or '—').split(';')[0])}</td>"
                         f"<td>{e(t.resp_body_len or t.req_body_len)}</td></tr>")
        parts.append("</table>")

    # TLS
    if result.tls:
        parts.append("<h2>TLS metadata</h2><table><tr><th>Client</th><th>Destination</th>"
                     "<th>SNI</th><th>Version</th><th>JA3</th><th>Certificate</th></tr>")
        for s in result.tls[:60]:
            parts.append(f"<tr><td class='mono'>{e(s.src)}</td>"
                         f"<td class='mono'>{e(s.dst)}:{e(s.dst_port)}</td><td>{e(s.sni or '(none)')}"
                         f"</td><td>{e(s.tls_version)}</td><td class='mono'>{e(s.ja3[:16])}…</td>"
                         f"<td>{e(s.cert_subject or '—')}</td></tr>")
        parts.append("</table><p style='color:var(--dim)'>TLS payloads are encrypted — "
                     "handshake metadata only.</p>")

    # credentials
    if result.credentials:
        parts.append("<h2>Cleartext credentials</h2><table><tr><th>Time</th><th>Protocol</th>"
                     "<th>Client</th><th>Server</th><th>Username</th><th>Password</th></tr>")
        for c in result.credentials:
            parts.append(f"<tr><td>{e((iso(c.ts) or '')[11:19])}</td><td>{e(c.protocol)}</td>"
                         f"<td class='mono'>{e(c.client)}</td><td class='mono'>{e(c.server)}</td>"
                         f"<td>{e(c.username)}</td><td class='mono'>{e(c.masked_password())}</td></tr>")
        parts.append("</table><p style='color:var(--dim)'>Passwords masked in reports "
                     "(<code>netsleuth secrets &lt;pcap&gt; --reveal</code> shows values).</p>")

    # artifacts
    if result.artifacts:
        parts.append("<h2>Extracted artifacts</h2><table><tr><th>File</th><th>Protocol</th>"
                     "<th>Type</th><th>Size</th><th>SHA-256</th></tr>")
        for a in result.artifacts:
            parts.append(f"<tr><td>{e(a.filename)}</td><td>{e(a.protocol)}</td>"
                         f"<td>{e(a.detected_type)}</td><td>{e(_fmt_bytes(a.size))}</td>"
                         f"<td class='mono'>{e(a.sha256[:32])}…</td></tr>")
        parts.append("</table>")

    # covert candidates
    if result.covert:
        parts.append("<h2>Covert-channel candidates</h2>")
        for c in result.covert:
            parts.append(
                f"<div class='finding {'' if c.confidence != 'high' else 'HIGH'}'>"
                f"<div class='title'><span class='badge "
                f"{'HIGH' if c.confidence == 'high' else 'MEDIUM' if c.confidence == 'medium' else 'LOW'}'>"
                f"{e(c.confidence)}</span> {e(c.protocol.upper())} "
                f"{e(c.field)} — {e(c.source)}</div>"
                f"<div>Observed values: " + ", ".join(
                    f"<code>{e(v)}</code>×{c.value_counts.get(v, 0)}"
                    for v in c.observed_values[:6]) + "</div>"
                f"<div>Pattern: {e(c.pattern)} · mapping {e(c.mapping)} · "
                f"{c.bits_len} bits → {c.byte_len} bytes</div>"
                f"<div>Decoded: <code>{e(c.decoded[:200])}</code> "
                f"({c.printable_ratio:.0%} printable)</div>")
            if c.wireshark_filters:
                parts.append("<p><span class='filter'>"
                             f"{e(c.wireshark_filters[0])}</span></p>")
            parts.append("<details><summary>assumptions</summary><ul>")
            parts.extend(f"<li class='ev'>{e(a)}</li>" for a in c.assumptions)
            parts.append("</ul></details></div>")

    # findings
    parts.append("<h2>Suspicious activity</h2>")
    if not result.findings:
        parts.append("<p>No findings. Absence of findings is not proof of safety.</p>")
    for f in result.findings:
        parts.append(f"<div class='finding {e(f.severity.value)}'>"
                     f"<div class='title'><span class='badge {e(f.severity.value)}'>"
                     f"{e(f.severity.value)}</span> {e(f.title)} "
                     f"<span style='color:var(--dim);font-weight:400'>"
                     f"(confidence: {e(f.confidence.value)})</span></div>"
                     f"<div>{e(f.description)}</div>")
        if f.evidence:
            parts.append("<details><summary>evidence</summary><ul>")
            parts.extend(f"<li class='ev mono'>{e(ev)}</li>" for ev in f.evidence[:8])
            parts.append("</ul></details>")
        if f.explanation:
            parts.append(f"<p class='why'>{e(f.explanation)}</p>")
        if f.mitre:
            parts.append("<p><b>MITRE ATT&amp;CK:</b> " + ", ".join(
                f"<code>{e(m.technique)}</code> {e(m.name)}" for m in f.mitre) + "</p>")
        if f.wireshark_filters:
            parts.append("<p>" + " ".join(
                f"<span class='filter'>{e(flt)}</span>" for flt in f.wireshark_filters) + "</p>")
        parts.append("</div>")

    # secrets
    if result.secrets:
        parts.append("<h2>Secrets &amp; flags</h2><table><tr><th>Kind</th><th>Value</th>"
                     "<th>Confidence</th><th>Source</th></tr>")
        for s in result.secrets[:80]:
            parts.append(f"<tr><td>{e(s.kind)}</td><td class='mono'>{e(s.masked())}</td>"
                         f"<td>{e(s.confidence)}</td><td>{e(s.source)}</td></tr>")
        parts.append("</table>")

    # timeline
    if result.events:
        parts.append("<h2>Timeline</h2><table><tr><th>Time</th><th>Kind</th><th>Event</th></tr>")
        for ev in result.events[:200]:
            sev = f" <span class='badge {e(ev.severity.value)}'>{e(ev.severity.value)}</span>" \
                if ev.severity.value != "INFO" else ""
            parts.append(f"<tr><td>{e((iso(ev.ts) or '')[11:23])}</td><td>{e(ev.kind)}</td>"
                         f"<td>{e(ev.summary)}{sev}</td></tr>")
        parts.append("</table>")

    # wireshark companion
    from netsleuth.reporting import wireshark as ws
    groups = ws.companion_filters(result)
    if groups:
        parts.append("<h2>Verify in Wireshark</h2>")
        for title, filters in groups:
            parts.append(f"<h3>{e(title)}</h3>")
            parts.extend(f"<span class='filter'>{e(flt)}</span>" for flt in filters)

    parts.append(f"""<footer>Generated by <b>NetSleuth</b> · findings carry evidence and
confidence — they are indicators, not verdicts · report is self-contained
(no scripts, no external resources).</footer></div></body></html>""")
    return "".join(parts)
