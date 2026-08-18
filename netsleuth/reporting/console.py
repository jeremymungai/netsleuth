"""Rich console rendering for every section of the analysis."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from netsleuth.models import iso
from netsleuth.reporting import wireshark as ws

SEVERITY_STYLE = {
    "CRITICAL": ("bold white on red", "CRITICAL"),
    "HIGH": ("bold red", "HIGH"),
    "MEDIUM": ("bold yellow", "MEDIUM"),
    "LOW": ("cyan", "LOW"),
    "INFO": ("dim", "INFO"),
}

_SCORE_STYLE = {"critical": "bold white on red", "high": "bold red",
                "elevated": "bold yellow", "low": "cyan", "none": "green"}


def _fmt_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} PB"


def _fmt_ts(ts) -> str:
    if ts is None:
        return "—"
    return iso(ts)[11:23] if iso(ts) else "—"


def _sev_tag(sev) -> Text:
    style, label = SEVERITY_STYLE.get(sev.value, ("dim", sev.value))
    return Text(f" {label} ", style=style)


def _sev_text(sev) -> str:
    """Plain bracketed severity for compact one-line lists."""
    return f"[{sev.value}]"


# ------------------------------------------------------------------ sections

def render_summary(result, console: Console) -> None:
    m = result.meta
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold cyan", width=22)
    table.add_column()
    table.add_row("File", m.path)
    table.add_row("Format", f"{m.format}" + (" (truncated)" if m.truncated else ""))
    table.add_row("Size", _fmt_bytes(m.size_bytes))
    table.add_row("Packets", f"{m.packet_count:,}")
    table.add_row("First packet", iso(m.first_ts) or "—")
    table.add_row("Last packet", iso(m.last_ts) or "—")
    table.add_row("Duration", f"{m.duration:.3f} s")
    table.add_row("Link type", m.linktype or "—")
    if result.overview is not None:
        ov = result.overview
        table.add_row("Hosts", str(len(ov.hosts)))
        table.add_row("Payload bytes", _fmt_bytes(ov.total_payload_bytes))
        table.add_row("Protocols",
                      ", ".join(f"{k} ({v})" for k, v in
                                sorted(ov.protocol_counts.items(), key=lambda kv: -kv[1])[:8])
                      or "—")
    console.print(Panel(table, title="[bold]Capture Overview", expand=False))
    for note in m.notes:
        console.print(Text(f"  note: {note}", style="yellow"))


def render_hosts(result, console: Console, limit: int = 30) -> None:
    if result.overview is None:
        console.print("[dim]no overview module[/dim]")
        return
    ov = result.overview
    table = Table(title=f"Hosts ({len(ov.hosts)})", header_style="bold")
    table.add_column("IP", style="cyan", no_wrap=True)
    table.add_column("Where")
    table.add_column("Hostnames (DNS)")
    table.add_column("Sent", justify="right")
    table.add_column("Received", justify="right")
    table.add_column("MACs (vendor)")
    for h in sorted(ov.hosts.values(), key=lambda h: h.ip)[:limit]:
        from netsleuth.enrichment.nets import classify_network
        from netsleuth.enrichment.oui import vendor_lookup
        macs = ", ".join(f"{m} ({vendor_lookup(m)})" if vendor_lookup(m) else m
                         for m in sorted(h.macs)[:2])
        table.add_row(h.ip, classify_network(h.ip),
                      ", ".join(sorted(h.hostnames)[:2]) or "—",
                      _fmt_bytes(h.bytes_sent), _fmt_bytes(h.bytes_received),
                      macs or "—")
    console.print(table)

    convs = ov.top_conversations(8)
    if convs:
        ct = Table(title="Top conversations", header_style="bold")
        ct.add_column("A", style="cyan")
        ct.add_column("B", style="cyan")
        ct.add_column("Port")
        ct.add_column("Proto")
        ct.add_column("Packets", justify="right")
        ct.add_column("Bytes", justify="right")
        for c in convs:
            ct.add_row(c.a, c.b, str(c.b_port), c.proto,
                       f"{c.packets:,}", _fmt_bytes(c.bytes))
        console.print(ct)


def render_dns(result, console: Console, limit: int = 20) -> None:
    if result.dns is None:
        console.print("[dim]no dns module[/dim]")
        return
    d = result.dns
    console.print(Panel(
        f"queries: [bold]{d.total_queries}[/bold]   "
        f"responses: [bold]{d.total_responses}[/bold]   "
        f"NXDOMAIN: [bold]{d.nxdomain_count}[/bold]   "
        f"TXT records: [bold]{d.txt_count}[/bold]",
        title="[bold]DNS Activity", expand=False))
    if not d.domain_stats:
        return
    table = Table(title="Domains queried", header_style="bold")
    table.add_column("Domain", style="cyan", overflow="fold", min_width=28)
    table.add_column("Queries", justify="right")
    table.add_column("NX", justify="right")
    table.add_column("Subdomains", justify="right")
    table.add_column("Resolved to")
    table.add_column("Max label / entropy", justify="right")
    for st in sorted(d.domain_stats.values(), key=lambda s: -s.queries)[:limit]:
        table.add_row(st.domain, str(st.queries), str(st.nxdomain),
                      str(len(st.subdomains)),
                      ", ".join(sorted(st.resolved_ips)[:2]) or "—",
                      f"{st.longest_label} ch / {st.max_entropy:.1f} bpc")
    console.print(table)


def render_http(result, console: Console, limit: int = 30) -> None:
    if not result.http:
        console.print("[dim]No cleartext HTTP transactions found[/dim]"
                      " (HTTPS traffic is encrypted — see TLS metadata)")
        return
    table = Table(title=f"HTTP transactions ({len(result.http)})", header_style="bold")
    table.add_column("Time", no_wrap=True)
    table.add_column("Stream", justify="right")
    table.add_column("Method")
    table.add_column("Host + path", style="cyan", overflow="fold")
    table.add_column("Status", justify="right")
    table.add_column("Type")
    table.add_column("Bytes", justify="right")
    for t in result.http[:limit]:
        status_style = "green" if t.status and t.status < 400 else \
            ("yellow" if 400 <= t.status < 500 else "red")
        table.add_row(_fmt_ts(t.ts), str(t.stream), t.method,
                      f"{t.host}{t.path}",
                      Text(str(t.status or "…"), style=status_style),
                      (t.content_type_resp or "—").split(";")[0],
                      str(t.resp_body_len if t.resp_body_len else t.req_body_len))
    console.print(table)


def render_tls(result, console: Console, limit: int = 30) -> None:
    if not result.tls:
        console.print("[dim]No TLS handshakes recovered[/dim]")
        return
    table = Table(title=f"TLS sessions ({len(result.tls)})", header_style="bold")
    table.add_column("Time", no_wrap=True)
    table.add_column("Client", style="cyan")
    table.add_column("Destination", style="cyan")
    table.add_column("SNI")
    table.add_column("Version")
    table.add_column("JA3", no_wrap=True)
    table.add_column("Certificate subject", overflow="fold")
    for s in result.tls[:limit]:
        table.add_row(_fmt_ts(s.ts), s.src, f"{s.dst}:{s.dst_port}",
                      s.sni or "[yellow](none)[/yellow]", s.tls_version or "—",
                      s.ja3[:12] or "—", s.cert_subject or "(not captured)")
    console.print(table)
    console.print("[dim]TLS payloads are encrypted — metadata only, no content claims.[/dim]")


def render_streams(result, console: Console, limit: int = 40) -> None:
    if not result.streams:
        console.print("[dim]No TCP streams[/dim]")
        return
    table = Table(title=f"TCP streams ({len(result.streams)})", header_style="bold")
    table.add_column("#", justify="right", style="bold")
    table.add_column("Client", style="cyan")
    table.add_column("Server", style="cyan")
    table.add_column("Packets", justify="right")
    table.add_column("C→S", justify="right")
    table.add_column("S→C", justify="right")
    table.add_column("Flags")
    for st in result.streams[:limit]:
        flags = []
        flags.append("[green]HS[/green]" if st.handshake else "[dim]hs?[/dim]")
        if st.terminated_cleanly:
            flags.append("[green]FIN[/green]")
        if st.gaps:
            flags.append(f"[yellow]{st.gaps} gap(s)[/yellow]")
        table.add_row(str(st.index),
                      f"{st.client}:{st.client_port}", f"{st.server}:{st.server_port}",
                      str(st.packets), _fmt_bytes(st.bytes_c2s),
                      _fmt_bytes(st.bytes_s2c), " ".join(flags))
    console.print(table)


def render_stream_detail(index: int, data, console: Console, hex_view: bool = False,
                         max_bytes: int = 4096) -> None:
    info = data.info
    head = (f"stream [bold]{info.index}[/bold]   {info.client}:{info.client_port} → "
            f"{info.server}:{info.server_port}   "
            f"{_fmt_ts(info.start_ts)} → {_fmt_ts(info.end_ts)}\n"
            f"client→server: {_fmt_bytes(info.bytes_c2s)}   "
            f"server→client: {_fmt_bytes(info.bytes_s2c)}   "
            f"handshake: {'yes' if info.handshake else 'no'}   "
            f"gaps: {info.gaps}")
    console.print(Panel(head, title="[bold]TCP Stream", expand=False))

    for label, payload in (("client → server", data.c2s), ("server → client", data.s2c)):
        if not payload:
            continue
        console.print(f"\n[bold magenta]── {label} ({len(payload)} bytes) ──[/bold magenta]")
        window = payload[:max_bytes]
        if hex_view:
            for off in range(0, min(len(window), 2048), 16):
                chunk = window[off:off + 16]
                hexpart = " ".join(f"{b:02x}" for b in chunk)
                asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
                console.print(f"[dim]{off:08x}[/dim]  {hexpart:<47}  {asciipart}")
        else:
            text = window.decode("utf-8", "replace")
            console.print(Text(text))
        if len(payload) > max_bytes:
            console.print(f"[dim]… {len(payload) - max_bytes} more bytes "
                          f"(use --max-bytes / --hex)[/dim]")


def render_credentials(result, console: Console, reveal: bool = False) -> None:
    if not result.credentials:
        return
    table = Table(title=f"Cleartext credentials ({len(result.credentials)})",
                  header_style="bold red")
    table.add_column("Time", no_wrap=True)
    table.add_column("Protocol")
    table.add_column("Client")
    table.add_column("Server")
    table.add_column("Username", style="cyan")
    table.add_column("Password", style="bold yellow")
    for c in result.credentials:
        table.add_row(_fmt_ts(c.ts), c.protocol, c.client, c.server,
                      c.username, c.password if reveal else c.masked_password())
    console.print(table)
    if not reveal:
        console.print("[dim]passwords masked — use --reveal to show them[/dim]")


def render_artifacts(result, console: Console) -> None:
    if not result.artifacts:
        console.print("[dim]No files extracted[/dim]")
        return
    table = Table(title=f"Extracted artifacts ({len(result.artifacts)})", header_style="bold")
    table.add_column("File", style="cyan")
    table.add_column("Protocol")
    table.add_column("Type")
    table.add_column("Size", justify="right")
    table.add_column("SHA-256", no_wrap=True)
    for a in result.artifacts:
        table.add_row(a.filename, a.protocol, a.detected_type,
                      _fmt_bytes(a.size), a.sha256[:16] + "…")
    console.print(table)


def render_secrets(result, console: Console, reveal: bool = False,
                   limit: int = 25) -> None:
    if not result.secrets:
        console.print("[dim]No flags, credentials or interesting strings matched[/dim]")
        return
    table = Table(title=f"Interesting strings / secrets ({len(result.secrets)})",
                  header_style="bold")
    table.add_column("Kind", style="magenta")
    table.add_column("Value", style="bold cyan", overflow="fold")
    table.add_column("Conf.")
    table.add_column("Found in", overflow="fold")
    for s in result.secrets[:limit]:
        table.add_row(s.kind, s.value if reveal else s.masked(),
                      s.confidence, s.source)
    console.print(table)


def render_findings(result, console: Console, verbose: bool = False) -> None:
    score = result.score
    console.print(Panel(
        Text(f" RISK SCORE {score.score}/100 — {score.label.upper()} ",
             style=_SCORE_STYLE[score.label], justify="center"),
        title="[bold]Detection Summary", expand=False))
    if not result.findings:
        console.print("[green]No suspicious behavior detected.[/green] "
                      "Absence of findings ≠ absence of compromise — see limitations in docs.")
        return
    counts = score.breakdown
    console.print("  findings: " +
                  "  ".join(f"[bold]{k}: {v}[/bold]" for k, v in counts.items()))
    console.print()
    for f in result.findings:
        body = Text()
        body.append(_sev_tag(f.severity))
        body.append(Text(f" {f.title}", style="bold"))
        body.append(Text(f"  (confidence: {f.confidence.value})", style="dim"))
        lines = [body, Text(f"  {f.description}", style="")]
        if verbose:
            if f.explanation:
                lines.append(Text.assemble(("  why it matters: ", "dim bold"),
                                            (f.explanation, "dim italic")))
            if f.evidence:
                lines.append(Text("  evidence:", style="dim bold"))
                lines.extend(Text(f"    • {e}", style="dim") for e in f.evidence[:6])
            if f.mitre:
                lines.append(Text("  MITRE: " + ", ".join(
                    f"{m.technique} ({m.tactic})" for m in f.mitre), style="dim"))
        else:
            if f.evidence:
                lines.append(Text(f"  evidence: {f.evidence[0]}", style="dim"))
        if f.wireshark_filters:
            lines.append(Text.assemble(("  Wireshark: ", "dim bold"),
                                       (f.wireshark_filters[0], "cyan")))
        if verbose and f.verification:
            lines.append(Text.assemble(("  verify: ", "dim bold"),
                                       (f.verification, "dim italic")))
        lines.append(Text())
        console.print(lines[0])
        for ln in lines[1:]:
            console.print(ln)


def render_timeline(result, console: Console, events=None, limit: int = 80) -> None:
    evs = events if events is not None else result.events
    if not evs:
        console.print("[dim]No timeline events[/dim]")
        return
    table = Table(title=f"Investigation timeline ({len(evs)} events, showing "
                        f"{min(limit, len(evs))})", header_style="bold")
    table.add_column("Time", no_wrap=True)
    table.add_column("Kind", style="magenta")
    table.add_column("Event", overflow="fold")
    for e in evs[:limit]:
        summary = Text(e.summary)
        if e.severity.value in ("HIGH", "CRITICAL"):
            summary = Text(e.summary, style="bold red")
        elif e.severity.value == "MEDIUM":
            summary = Text(e.summary, style="yellow")
        table.add_row(_fmt_ts(e.ts), e.kind, summary)
    console.print(table)


def render_covert(result, console: Console, explain: bool = True) -> None:
    """Covert-channel candidates with full derivation receipts."""
    from netsleuth.covert.engine import EDUCATION
    if not result.covert:
        console.print("[green]No protocol-metadata covert-channel candidates.[/green] "
                      "(Fields varied benignly or decodings looked like noise — "
                      "see docs/covert-channels.md for what was tested.)")
        return
    for c in result.covert:
        sev_style = {"high": "bold red", "medium": "bold yellow",
                     "low": "cyan"}[c.confidence] if c.confidence in (
                     "high", "medium", "low") else "dim"
        head = Text()
        head.append(Text(f" {c.confidence.upper()} ", style=sev_style))
        head.append(Text(f" {c.protocol.upper()} {c.field} — {c.source}",
                         style="bold"))
        console.print(head)
        rows = [
            ("Observed values", ", ".join(
                f"{v} ×{c.value_counts.get(v, 0)}" for v in c.observed_values[:6])),
            ("Pattern", c.pattern),
            ("Mapping", c.mapping),
            ("Bits", f"{c.bits_len} bits → {c.byte_len} bytes "
                     f"(preview {c.bits[:32]}…)"),
            ("Decoded", repr(c.decoded[:120])),
            ("Printable ratio", f"{c.printable_ratio:.0%}"),
        ]
        if c.frames:
            rows.append(("Packets", f"frames {c.frames[0]}…{c.frames[-1]}"))
        for k, v in rows:
            console.print(f"  [dim bold]{k:<16}[/dim bold] {v}")
        if explain:
            console.print("  [dim bold]Assumptions[/dim bold]")
            for a in c.assumptions:
                console.print(f"    • {a}", style="dim")
        if c.wireshark_filters:
            console.print(f"  [dim bold]Wireshark[/dim bold] "
                          f"[cyan]{c.wireshark_filters[0]}[/cyan]")
        console.print()
    if explain:
        console.print(Panel(EDUCATION, title="[bold]How this works",
                            expand=False))


def render_wireshark_companion(result, console: Console) -> None:
    groups = ws.companion_filters(result)
    if not groups:
        return
    console.print(Panel("Copy these display filters into Wireshark to verify "
                        "every finding by hand.", title="[bold]Wireshark Companion",
                        expand=False))
    for title, filters in groups:
        console.print(f"[bold] {title}[/bold]")
        for flt in filters:
            console.print(f"   [cyan]{flt}[/cyan]")


# ------------------------------------------------------------- guided mode

def render_analyze(result, console: Console, verbose: bool = False,
                   reveal: bool = False) -> None:
    """The guided 11-step investigation workflow (steps always numbered 1-11)."""
    step = [0]

    def heading(title: str) -> None:
        step[0] += 1
        console.print(Panel(Text(f"STEP {step[0]} — {title}", style="bold"),
                            expand=False))

    console.print(Panel(
        f"[bold]NetSleuth analysis of[/bold] {result.meta.path}",
        subtitle=f"risk {result.score.score}/100 ({result.score.label})",
                expand=False))

    heading("Capture overview")
    render_summary(result, console)

    heading("Important hosts & conversations")
    render_hosts(result, console)

    heading("DNS activity")
    if result.dns is not None:
        render_dns(result, console)
    else:
        console.print("[dim]dns module not run[/dim]")

    heading("Suspicious connections")
    if result.findings:
        for f in result.findings:
            console.print(f"  {_sev_text(f.severity)}  {f.title}")
        console.print("[dim]full evidence follows in step 9 / `netsleuth detect -v`[/dim]")
    else:
        console.print("[green]No suspicious behavior detected.[/green] "
                      "Absence of findings ≠ absence of compromise — see docs.")

    heading("HTTP artifacts")
    render_http(result, console)

    heading("TLS metadata")
    render_tls(result, console)

    heading("Extracted files")
    if result.artifacts:
        render_artifacts(result, console)
    else:
        console.print("[dim]No files extracted in this run — use "
                      "`netsleuth extract <pcap> --output DIR` to carve them[/dim]")

    heading("Credentials & secrets")
    render_credentials(result, console, reveal=reveal)
    render_secrets(result, console, reveal=reveal)

    heading("Possible malicious behavior")
    render_findings(result, console, verbose=verbose)

    heading("CTF / flag candidates")
    flags = [s for s in result.secrets if s.kind == "flag"]
    if flags:
        for i, s in enumerate(flags[:10], 1):
            console_out_line = (f"  {i}. {s.value if reveal else s.masked()}"
                                f"  [dim]({s.confidence}, {s.source})[/dim]")
            console.print(console_out_line)
        console.print("[dim]discovery details: netsleuth ctf <pcap>[/dim]")
    else:
        console.print("[dim]no flag-shaped strings matched — try "
                      "`netsleuth ctf <pcap>` for deeper (encoded/XOR) hunting[/dim]")

    heading("Recommended manual investigation (Wireshark)")
    render_wireshark_companion(result, console)
    console.print("[dim]Guided mode explains each section; re-run any command "
                  "with --verbose for full evidence.[/dim]")
