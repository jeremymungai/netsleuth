"""NetSleuth command-line interface.

Commands map one-to-one onto analysis views:

    netsleuth analyze   capture.pcap     guided 11-step investigation
    netsleuth summary   capture.pcap     capture metadata
    netsleuth hosts     capture.pcap     hosts + conversations
    netsleuth dns       capture.pcap     DNS inventory
    netsleuth http      capture.pcap     HTTP transactions
    netsleuth tls       capture.pcap     TLS metadata
    netsleuth streams   capture.pcap     TCP stream index
    netsleuth stream    capture.pcap 42  one stream, followed
    netsleuth extract   capture.pcap     carve transferred files
    netsleuth secrets   capture.pcap     flags/credentials scanner
    netsleuth ctf       capture.pcap     CTF helper mode
    netsleuth covert    capture.pcap     protocol-metadata covert channels
    netsleuth detect    capture.pcap     detection engine + risk score
    netsleuth timeline  capture.pcap     chronological events
    netsleuth report    capture.pcap     json / md / html report file
"""

from __future__ import annotations

import sys
from typing import Optional

import typer
from rich.console import Console

console_out = Console()
err_console = Console(stderr=True)

if sys.stdout.isatty():
    _import_status = console_out.status("[cyan]Warming up NetSleuth...[/cyan]", spinner="dots")
    _import_status.start()
else:
    _import_status = None

from netsleuth import __version__
from netsleuth.capture import CaptureError
from netsleuth.pipeline import Options, Pipeline

if _import_status:
    _import_status.stop()

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="NetSleuth — offline PCAP analysis & network threat hunting. "
         "Reads capture files only; never touches the network.",
    rich_markup_mode="rich",
)

# option aliases shared by most commands
MAX_PACKETS = typer.Option(0, "--max-packets", help="Stop after N packets (0 = all).")
RULES_OPT = typer.Option(None, "--rules", help="Extra YAML rule file or directory.")
REVEAL = typer.Option(False, "--reveal", help="Show masked secrets/passwords.")
VERBOSE = typer.Option(False, "--verbose", "-v", help="Full evidence in output.")
AS_JSON = typer.Option(False, "--json", help="Emit JSON instead of tables.")
QUIET = typer.Option(False, "--quiet", "-q", help="Suppress progress/notes.")


def _err_exit(msg: str, code: int = 2) -> None:
    err_console.print(f"[bold red]error:[/bold red] {msg}")
    raise typer.Exit(code)


def _run(pcap: str, modules: Optional[set[str]], max_packets: int = 0,
         rules: Optional[str] = None, extract_dir: Optional[str] = None,
         show_progress: bool = True):
    """Shared pipeline driver with progress reporting."""
    rules_paths = [rules] if rules else []
    opts = Options(modules=modules, max_packets=max_packets,
                   rules_paths=rules_paths, extract_dir=extract_dir)

    status = None
    if not QUIET and console_out.is_terminal:
        status = console_out.status("[cyan]netSleuth is working...[/cyan]", spinner="dots")
        status.start()

    try:
        pipe = Pipeline(pcap, opts)
        res = pipe.run()
    except CaptureError as e:
        if status is not None:
            status.stop()
        _err_exit(str(e))
    finally:
        if status is not None:
            status.stop()

    return res


# ------------------------------------------------------------------ commands

def _version_callback(value: bool):
    if value:
        console_out.print(f"NetSleuth {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(False, "--version", callback=_version_callback,
                                 is_eager=True, help="Show version and exit."),
):
    """NetSleuth — turn a packet capture into an investigation."""


@app.command()
def summary(pcap: str = typer.Argument(..., help="Capture file (.pcap/.pcapng)."),
            max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON):
    """Capture metadata: size, packets, duration, link type, notes."""
    res = _run(pcap, {"overview"}, max_packets, show_progress=False)
    if as_json:
        import json
        console_out.print_json(json.dumps(res.meta.to_dict()))
    else:
        from netsleuth.reporting import console as rc
        rc.render_summary(res, console_out)


@app.command()
def hosts(pcap: str = typer.Argument(...),
          max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON,
          limit: int = typer.Option(30, help="Max rows.")):
    """Hosts, their networks, and top conversations."""
    res = _run(pcap, {"overview"}, max_packets, show_progress=False)
    if as_json:
        import json
        console_out.print_json(json.dumps(res.overview.to_dict()))
    else:
        from netsleuth.reporting import console as rc
        rc.render_hosts(res, console_out, limit)


@app.command()
def dns(pcap: str = typer.Argument(...),
        max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON,
        limit: int = typer.Option(20, help="Max domain rows.")):
    """DNS query inventory with tunneling-relevant statistics."""
    res = _run(pcap, {"dns", "overview"}, max_packets, show_progress=False)
    if as_json:
        import json
        console_out.print_json(json.dumps(res.dns.to_dict()))
    else:
        from netsleuth.reporting import console as rc
        rc.render_dns(res, console_out, limit)


@app.command()
def http(pcap: str = typer.Argument(...),
         max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON):
    """Cleartext HTTP transactions extracted from TCP streams."""
    res = _run(pcap, {"streams", "http"}, max_packets)
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"transactions": [t.to_dict() for t in res.http]}))
    else:
        from netsleuth.reporting import console as rc
        rc.render_http(res, console_out)


@app.command()
def tls(pcap: str = typer.Argument(...),
        max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON):
    """TLS handshake metadata: SNI, versions, JA3, certificates."""
    res = _run(pcap, {"streams", "tls"}, max_packets)
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"sessions": [s.to_dict() for s in res.tls]}))
    else:
        from netsleuth.reporting import console as rc
        rc.render_tls(res, console_out)


@app.command()
def streams(pcap: str = typer.Argument(...),
            max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON):
    """Index of reconstructed TCP streams."""
    res = _run(pcap, {"streams"}, max_packets)
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"streams": [s.to_dict() for s in res.streams]}))
    else:
        from netsleuth.reporting import console as rc
        rc.render_streams(res, console_out)


@app.command()
def stream(pcap: str = typer.Argument(...),
           index: int = typer.Argument(..., help="Stream number (see `streams`)."),
           max_packets: int = MAX_PACKETS,
           hex_view: bool = typer.Option(False, "--hex", help="Hex dump view."),
           max_bytes: int = typer.Option(4096, "--max-bytes",
                                         help="Bytes shown per direction."),
           direction: str = typer.Option("both", "--direction",
                                         help="both | c2s | s2c")):
    """Follow one reconstructed TCP stream (like Wireshark's Follow Stream)."""
    res = _run(pcap, {"streams"}, max_packets)
    data = next((s for s in res.stream_data if s.info.index == index), None)
    if data is None:
        _err_exit(f"stream {index} not found (0..{len(res.streams) - 1} "
                  f"— run `netsleuth streams {pcap}`)")
    from netsleuth.reporting import console as rc
    rc.render_stream_detail(index, data, console_out, hex_view=hex_view,
                            max_bytes=max_bytes)
    if direction == "c2s":
        pass  # detail renderer already labels both; direction chosen for pipe use
    console_out.print(f"[dim]Wireshark: tcp.stream == {index}[/dim]")


@app.command()
def extract(pcap: str = typer.Argument(...),
            out_dir: str = typer.Option(None, "--output", "-o",
                                        help="Output directory (required)."),
            max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON):
    """Carve transferred files (HTTP downloads/uploads, mail attachments)."""
    if not out_dir:
        _err_exit("extract requires --output DIR (files are never executed, "
                  "just written and hashed)")
    res = _run(pcap, {"streams", "http", "creds", "extract"}, max_packets,
               extract_dir=out_dir)
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"artifacts": [a.to_dict() for a in res.artifacts]}))
    else:
        from netsleuth.reporting import console as rc
        rc.render_artifacts(res, console_out)
        if res.artifacts:
            import os
            console_out.print(f"\n[dim]files written under "
                              f"{os.path.dirname(res.artifacts[0].stored_path)}[/dim]")


@app.command()
def secrets(pcap: str = typer.Argument(...),
            rules: Optional[str] = RULES_OPT,
            pattern: str = typer.Option(None, "--pattern",
                                        help="Extra regex to hunt (e.g. 'FLAG{.*?}')."),
            max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON,
            reveal: bool = REVEAL):
    """Scan streams, HTTP, DNS TXT and ICMP for flags, credentials, keys."""
    from netsleuth import rules as rules_mod
    extra = None
    if pattern:
        try:
            extra = rules_mod.adhoc_rule(pattern)
        except rules_mod.RuleError as e:
            _err_exit(str(e))
    res = _run(pcap, {"streams", "http", "dns", "icmp", "secrets"}, max_packets, rules)
    if extra is not None:
        from netsleuth.extraction import secrets as secrets_mod
        extra_hits = secrets_mod.scan(res, [rules] if rules else [], extra_rule=extra)
        res.secrets = extra_hits + [s for s in res.secrets
                                    if (s.kind, s.value) not in
                                    {(h.kind, h.value) for h in extra_hits}]
        res.secrets.sort(key=lambda s: (s.kind, s.confidence != "high"))
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"matches": [s.to_dict(reveal=reveal) for s in res.secrets]}))
    else:
        from netsleuth.reporting import console as rc
        rc.render_secrets(res, console_out, reveal)


@app.command()
def detect(pcap: str = typer.Argument(...),
           rules: Optional[str] = RULES_OPT,
           max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON,
           verbose: bool = VERBOSE):
    """Run the detection engine: findings, evidence, risk score."""
    res = _run(pcap, None, max_packets, rules)
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"findings": [f.to_dict() for f in res.findings],
             "score": res.score.to_dict()}))
    else:
        from netsleuth.reporting import console as rc
        rc.render_findings(res, console_out, verbose=verbose)


@app.command()
def timeline(pcap: str = typer.Argument(...),
             max_packets: int = MAX_PACKETS, as_json: bool = AS_JSON,
             host: str = typer.Option(None, "--host", help="Filter by host IP."),
             kind: str = typer.Option(None, "--kind", help="dns|http|tls|tcp|file|detection."),
             severity: str = typer.Option(None, "--severity",
                                          help="Minimum severity LOW|MEDIUM|HIGH|CRITICAL."),
             limit: int = typer.Option(80)):
    """Chronological investigation timeline."""
    res = _run(pcap, None, max_packets)
    from netsleuth.reporting.timeline import filter_events
    events = filter_events(res.events, host=host, kind=kind, min_severity=severity)
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"events": [e.to_dict() for e in events[:1000]]}))
    else:
        from netsleuth.reporting import console as rc
        rc.render_timeline(res, console_out, events=events, limit=limit)


@app.command()
def report(pcap: str = typer.Argument(...),
           fmt: str = typer.Option("html", "--format",
                                   help="json | md | html"),
           output: str = typer.Option(None, "--output", "-o",
                                      help="Output file (default: <pcap>.<fmt>)."),
           rules: Optional[str] = RULES_OPT,
           max_packets: int = MAX_PACKETS, reveal: bool = REVEAL):
    """Full investigation report (exec summary, findings, timeline, filters)."""
    res = _run(pcap, None, max_packets, rules)
    from netsleuth.reporting.reports import write_report
    out = output or f"{pcap}.{fmt}"
    try:
        path = write_report(res, fmt, out, reveal=reveal)
    except ValueError as e:
        _err_exit(str(e))
    console_out.print(f"[green]report written:[/green] {path}")


@app.command()
def analyze(pcap: str = typer.Argument(...),
            rules: Optional[str] = RULES_OPT,
            max_packets: int = MAX_PACKETS, verbose: bool = VERBOSE,
            reveal: bool = REVEAL):
    """Guided 11-step investigation: overview → findings → Wireshark filters."""
    res = _run(pcap, None, max_packets, rules)
    from netsleuth.reporting import console as rc
    rc.render_analyze(res, console_out, verbose=verbose, reveal=reveal)


@app.command()
def covert(pcap: str = typer.Argument(...),
           max_packets: int = MAX_PACKETS,
           as_json: bool = AS_JSON,
           no_explain: bool = typer.Option(False, "--no-explain",
                                           help="Skip the educational block.")):
    """Protocol-metadata covert-channel analysis (generic field engine).

    Finds fields whose values vary systematically across repeated
    messages (HTTP version/method/headers, DNS types/TTL, ports, IP
    ID/TTL…), maps the value sequences to symbols, decodes candidate
    bitstreams, and reports the full derivation — evidence, never
    verdicts.
    """
    res = _run(pcap, None, max_packets)
    if as_json:
        import json
        console_out.print_json(json.dumps(
            {"candidates": [c.to_dict() for c in res.covert]}))
        return
    from netsleuth.reporting import console as rc
    rc.render_covert(res, console_out, explain=not no_explain)


# ----------------------------------------------------------------- ctf mode

@app.command()
def ctf(pcap: str = typer.Argument(...),
        rules: Optional[str] = RULES_OPT,
        pattern: str = typer.Option(None, "--pattern", help="Custom flag regex."),
        max_packets: int = MAX_PACKETS,
        reveal: bool = REVEAL):
    """CTF helper: flag candidates, decodings, hidden data — with receipts.

    Prioritizes: flag-like strings, encoded blobs, DNS TXT, ICMP payloads,
    credentials, unusual ports and interesting strings — and explains where
    each candidate came from so you learn where the evidence lives.
    """
    from netsleuth import rules as rules_mod
    from netsleuth.extraction import encodings, strings as strings_mod
    extra = None
    if pattern:
        try:
            extra = rules_mod.adhoc_rule(pattern)
        except rules_mod.RuleError as e:
            _err_exit(str(e))

    res = _run(pcap, None, max_packets, rules)
    if extra is not None:
        from netsleuth.extraction import secrets as secrets_mod
        res.secrets = secrets_mod.scan(res, [rules] if rules else [],
                                       extra_rule=extra)

    from rich.panel import Panel
    from rich.table import Table

    console_out.print(Panel(
        "[bold]CTF MODE[/bold] — candidates below are ranked guesses with "
        "sources; every hit explains how it was found.", expand=False))

    # 1. flag candidates
    flags = [s for s in res.secrets if s.kind == "flag"] or \
        [s for s in res.secrets if "{" in s.value and "}" in s.value]
    if flags:
        t = Table(title="Flag candidates", header_style="bold magenta")
        t.add_column("#", justify="right")
        t.add_column("Candidate", style="bold cyan", overflow="fold")
        t.add_column("Conf.")
        t.add_column("How it was found", overflow="fold")
        for i, s in enumerate(flags[:15], 1):
            t.add_row(str(i), s.value if reveal else s.masked(),
                      s.confidence, s.how or s.source)
        console_out.print(t)
    else:
        console_out.print("[yellow]No direct flag-pattern matches.[/yellow] "
                          "Trying deeper techniques below…")

    # 2. encoded strings that decode to something interesting
    console_out.print("\n[bold]Encoded-looking strings[/bold] "
                      "(decoding attempted with confidence):")
    decoded_any = False
    seen_blobs: set[str] = set()
    done = False
    for st in res.stream_data:
        if done:
            break
        for blob in (st.c2s, st.s2c):
            for s in strings_mod.top_strings(blob, n=10):
                # candidates: the whole string AND its whitespace tokens —
                # encoded payloads usually sit inside a sentence
                cands = [s.value.strip()] + [t for t in s.value.split()
                                             if len(t) >= 12]
                for cand in cands:
                    if len(cand) < 12 or cand in seen_blobs:
                        continue
                    chain = encodings.analyze_chain(cand)
                    if chain.steps and chain.final_is_printable and len(chain.final) > 3:
                        seen_blobs.add(cand)
                        decoded_any = True
                        console_out.print(
                            f"  [dim]{cand[:48]}{'…' if len(cand) > 48 else ''}[/dim]"
                            f" → {chain.description} → "
                            f"[bold]{chain.final[:80]!r}[/bold]")
                        if len(seen_blobs) >= 8:
                            done = True
                            break
                if done:
                    break
            if done:
                break
    if not decoded_any:
        console_out.print("  [dim]none decoded cleanly[/dim]")

    # 3. single-byte XOR hunt (classic)
    console_out.print("\n[bold]Single-byte XOR sweep[/bold] "
                      "(flag prefixes searched over every key):")
    xor_hits = 0
    for st in res.stream_data:
        for blob in (st.c2s, st.s2c):
            if not blob:
                continue
            for key, found in encodings.xor_brute_prefix(blob):
                xor_hits += 1
                console_out.print(f"  key 0x{key:02x} → [bold]{found}[/bold] "
                                  f"[dim](stream {st.info.index})[/dim]")
    if not xor_hits:
        console_out.print("  [dim]no XOR-encoded flag prefixes found[/dim]")

    # 4. covert-channel (protocol metadata) phase
    console_out.print("\n[bold]Covert channels — protocol metadata[/bold] "
                      "(fields that vary systematically):")
    if res.covert:
        for c in res.covert:
            style = "bold red" if c.confidence == "high" else "yellow"
            console_out.print(
                f"  [{style}]{c.protocol.upper()} {c.field}[/] of {c.source}: "
                f"{c.pattern}; {c.bits_len} bits -> {c.byte_len} bytes "
                f"({c.printable_ratio:.0%} printable) -> "
                f"[bold]{c.decoded[:60]!r}[/bold]")
            if c.wireshark_filters:
                console_out.print(f"    [dim]Wireshark: {c.wireshark_filters[0]}[/dim]")
        console_out.print("[dim]full derivation: netsleuth covert <pcap>[/dim]")
    else:
        console_out.print("  [dim]no metadata channels decoded to structured "
                          "output[/dim]")

    # 5. hiding spots checklist
    console_out.print("\n[bold]Where data hides — checklist for this capture:[/bold]")
    checklist = []
    if res.dns is not None:
        txt = [q for q in res.dns.queries if q.answer_type == "TXT"]
        checklist.append(f"DNS TXT records: {len(txt)} seen"
                         + (" [yellow](inspect them!)[/yellow]" if txt else ""))
        long_names = [q for q in res.dns.queries if len(q.name) > 60]
        checklist.append(f"Very long DNS names (>60 ch): {len(long_names)}")
    icmp_payloads = [o for o in res.icmp if o.payload_len > 0]
    checklist.append(f"ICMP payloads: {len(icmp_payloads)}"
                     + (" [yellow](data inside ping!)[/yellow]" if icmp_payloads else ""))
    odd_ports = [st for st in res.streams if st.server_port not in
                 (80, 443, 53, 22, 25, 123) and st.total_bytes > 0]
    checklist.append(f"Streams on unusual ports: {len(odd_ports)}")
    for line in checklist:
        console_out.print(f"  • {line}")

    if odd_ports:
        t = Table(title="Streams on unusual ports", header_style="bold")
        t.add_column("Stream", justify="right")
        t.add_column("Conversation")
        t.add_column("Bytes", justify="right")
        t.add_column("Wireshark")
        for st in odd_ports[:10]:
            t.add_row(str(st.index),
                      f"{st.client}:{st.client_port} → {st.server}:{st.server_port}",
                      str(st.total_bytes), f"tcp.stream == {st.index}")
        console_out.print(t)

    # 6. next steps
    console_out.print(Panel(
        "Next steps:\n"
        "  • [bold]netsleuth stream <pcap> N[/bold] — read any suspicious stream in full\n"
        "  • [bold]netsleuth extract <pcap> -o out/[/bold] — carve transferred files\n"
        "  • [bold]netsleuth secrets <pcap> --reveal[/bold] — full secret values\n"
        "  • in Wireshark: try the filters above; check protocol hierarchy "
        "(Statistics → Protocol Hierarchy) for anything exotic",
        title="Keep digging", expand=False))


def main() -> None:
    """Console-script entry point."""
    app()


if __name__ == "__main__":
    app()
