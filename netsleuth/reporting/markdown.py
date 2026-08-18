"""Markdown report generator."""

from __future__ import annotations

from datetime import datetime, timezone

from netsleuth.models import iso


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def generate_markdown(result) -> str:
    m = result.meta
    out: list[str] = [f"# NetSleuth Analysis Report",
                      "",
                      f"**Capture:** `{m.path}`  ",
                      f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ",
                      f"**Risk score:** {result.score.score}/100 ({result.score.label})",
                      ""]

    # Executive summary
    out += ["## Executive summary", ""]
    n_find = len(result.findings)
    top = [f for f in result.findings if f.severity.value in ("CRITICAL", "HIGH")]
    out.append(f"- Capture contains **{m.packet_count:,} packets** over "
               f"{m.duration:.1f}s ({_fmt_bytes(m.size_bytes)}, {m.format}).")
    if result.overview is not None:
        out.append(f"- **{len(result.overview.hosts)} hosts** observed; "
                   f"{sum(1 for h in result.overview.hosts.values() if not h.is_internal)} "
                   f"external.")
    if n_find:
        out.append(f"- **{n_find} finding(s)**, including "
                   f"{len(top)} high/critical — see [Suspicious activity](#suspicious-activity).")
    else:
        out.append("- No suspicious behavior detected by the rule engine "
                   "(absence of findings is not proof of safety).")
    if result.secrets:
        out.append(f"- {len(result.secrets)} interesting strings/secrets matched "
                   "(see [Secrets](#secrets--flags)).")
    out.append("")

    out += ["## Capture overview", "",
            f"| Field | Value |", f"|---|---|",
            f"| File | `{m.path}` |",
            f"| Format | {m.format}{' (truncated)' if m.truncated else ''} |",
            f"| Size | {_fmt_bytes(m.size_bytes)} |",
            f"| Packets | {m.packet_count:,} |",
            f"| First packet | {iso(m.first_ts) or '—'} |",
            f"| Last packet | {iso(m.last_ts) or '—'} |",
            f"| Duration | {m.duration:.3f}s |",
            f"| Link type | {m.linktype or '—'} |", ""]
    for note in m.notes:
        out.append(f"> note: {note}")
    if m.notes:
        out.append("")

    if result.overview is not None:
        ov = result.overview
        out += ["## Hosts", "", "| IP | Network | Hostnames | Sent | Received |",
                "|---|---|---|---|---|"]
        from netsleuth.enrichment.nets import classify_network
        for h in sorted(ov.hosts.values(), key=lambda h: h.ip):
            out.append(f"| {h.ip} | {classify_network(h.ip)} | "
                       f"{', '.join(sorted(h.hostnames)) or '—'} | "
                       f"{_fmt_bytes(h.bytes_sent)} | {_fmt_bytes(h.bytes_received)} |")
        out += ["", "### Top conversations", "",
                "| A | B | Port | Proto | Packets | Bytes |",
                "|---|---|---|---|---|---|"]
        for c in ov.top_conversations(12):
            out.append(f"| {c.a} | {c.b} | {c.b_port} | {c.proto} | "
                       f"{c.packets:,} | {_fmt_bytes(c.bytes)} |")
        out.append("")

    if result.dns is not None:
        d = result.dns
        out += ["## DNS findings", "",
                f"{d.total_queries} queries, {d.total_responses} responses, "
                f"{d.nxdomain_count} NXDOMAIN, {d.txt_count} TXT records.", "",
                "| Domain | Queries | NX | Subdomains | Resolved | Max label/entropy |",
                "|---|---|---|---|---|---|"]
        for st in sorted(d.domain_stats.values(), key=lambda s: -s.queries)[:25]:
            out.append(f"| {st.domain} | {st.queries} | {st.nxdomain} | "
                       f"{len(st.subdomains)} | "
                       f"{', '.join(sorted(st.resolved_ips)[:2]) or '—'} | "
                       f"{st.longest_label} ch / {st.max_entropy:.1f} bpc |")
        out.append("")

    if result.http:
        out += ["## HTTP findings", "", "| Time | Method | Host + path | Status | Type | Bytes |",
                "|---|---|---|---|---|---|"]
        for t in result.http[:100]:
            out.append(f"| {iso(t.ts)[11:19] if t.ts else '—'} | {t.method} | "
                       f"{t.host}{t.path} | {t.status or '…'} | "
                       f"{(t.content_type_resp or '—').split(';')[0]} | "
                       f"{t.resp_body_len or t.req_body_len} |")
        out.append("")

    if result.tls:
        out += ["## TLS metadata", "",
                "| Client | Destination | SNI | Version | JA3 | Certificate |",
                "|---|---|---|---|---|---|"]
        for s in result.tls[:50]:
            out.append(f"| {s.src} | {s.dst}:{s.dst_port} | {s.sni or '(none)'} | "
                       f"{s.tls_version} | `{s.ja3[:12]}…` | {s.cert_subject or '—'} |")
        out += ["", "> TLS payloads are encrypted; only handshake metadata is reported.", ""]

    if result.credentials:
        out += ["## Cleartext credentials", "", "| Time | Protocol | Client | Server | Username | Password |",
                "|---|---|---|---|---|---|"]
        for c in result.credentials:
            out.append(f"| {iso(c.ts)[11:19] if c.ts else '—'} | {c.protocol} | "
                       f"{c.client} | {c.server} | {c.username} | "
                       f"`{c.masked_password()}` |")
        out += ["", "> Passwords are masked in reports. Use "
                "`netsleuth secrets <pcap> --reveal` for the values.", ""]

    if result.artifacts:
        out += ["## Extracted artifacts", "",
                "| File | Protocol | Type | Size | SHA-256 |",
                "|---|---|---|---|---|"]
        for a in result.artifacts:
            out.append(f"| `{a.filename}` | {a.protocol} | {a.detected_type} | "
                       f"{_fmt_bytes(a.size)} | `{a.sha256[:24]}…` |")
        out.append("")

    if result.covert:
        out += ["## Covert-channel candidates", ""]
        for c in result.covert:
            out += [f"### {c.protocol.upper()} {c.field} — {c.source} "
                    f"(confidence: {c.confidence})", "",
                    f"- **Observed values:** " + ", ".join(
                        f"`{v}` ×{c.value_counts.get(v, 0)}"
                        for v in c.observed_values[:6]),
                    f"- **Pattern:** {c.pattern}",
                    f"- **Mapping:** {c.mapping}",
                    f"- **Bitstream:** {c.bits_len} bits → {c.byte_len} bytes",
                    f"- **Decoded:** `{c.decoded[:120]}`",
                    f"- **Printable ratio:** {c.printable_ratio:.0%}",
                    f"- **Wireshark:** `{c.wireshark_filters[0]}`"
                    if c.wireshark_filters else "",
                    "", "Assumptions:"]
            out += [f"- {a}" for a in c.assumptions]
            out.append("")
        out.append("> Candidates are derivations, not verdicts — see "
                   "`docs/covert-channels.md`.", "")

    # Suspicious activity (findings)
    out += ["## Suspicious activity", ""]
    if not result.findings:
        out += ["_No findings._", ""]
    for f in result.findings:
        out.append(f"### [{f.severity.value}] {f.title}  ")
        out.append(f"_confidence: {f.confidence.value}_")
        out.extend(["", f.description, ""])
        if f.evidence:
            out.append("**Evidence:**")
            out.extend(f"- {e}" for e in f.evidence[:8])
            out.append("")
        if f.explanation:
            out.extend([f"**Why it matters:** {f.explanation}", ""])
        if f.mitre:
            out.append("**MITRE ATT&CK:** " + ", ".join(
                f"`{m.technique}` {m.name} — {m.why}" for m in f.mitre))
            out.append("")
        if f.wireshark_filters:
            out.append("**Wireshark:** `" + "`, `".join(f.wireshark_filters) + "`")
            out.append("")
        if f.verification:
            out.extend([f"**Verify manually:** {f.verification}", ""])

    if result.secrets:
        out += ["## Secrets & flags", "", "| Kind | Value | Confidence | Source |",
                "|---|---|---|---|"]
        for s in result.secrets[:60]:
            out.append(f"| {s.kind} | `{s.masked()}` | {s.confidence} | {s.source} |")
        out += ["", "> Values masked; use `--reveal` on the CLI for full values.", ""]

    if result.events:
        out += ["## Timeline", "", "| Time | Kind | Event |", "|---|---|---|"]
        for e in result.events[:150]:
            sev = f" **[{e.severity.value}]**" if e.severity.value != "INFO" else ""
            out.append(f"| {iso(e.ts)[11:23] if e.ts else '—'} | {e.kind} | "
                       f"{e.summary}{sev} |")
        out.append("")

    out += ["## Recommended manual investigation", ""]
    from netsleuth.reporting import wireshark as ws
    for title, filters in ws.companion_filters(result):
        out.append(f"**{title}**")
        out.extend(f"- `{flt}`" for flt in filters)
        out.append("")

    out += ["---", "_Generated by NetSleuth — findings are indicators with "
            "evidence and confidence, not verdicts._"]
    return "\n".join(out)
