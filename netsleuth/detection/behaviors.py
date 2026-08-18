"""Scan and network-behavior detectors."""

from __future__ import annotations

from netsleuth.enrichment.mitre import mitre
from netsleuth.enrichment.ports import service_name
from netsleuth.models import Confidence, Finding, Severity


def detect_syn_scan(result) -> list[Finding]:
    """Many SYN attempts, few completed handshakes → port scan."""
    if result.overview is None:
        return []
    findings = []
    for src, flows in result.overview.flow_tracker.syn_scans():
        ports = sorted({f.dport for f in flows})
        completed = sum(1 for f in result.overview.flow_tracker.flows.values()
                        if f.src == src and f.ack_of_syn)
        first = min(f.first_ts for f in flows if f.first_ts)
        last = max(f.last_ts for f in flows if f.last_ts)
        duration = (last - first) if first and last else 0.0
        findings.append(Finding(
            id=f"scan.syn.{src}",
            title=f"Possible port scan from {src} ({len(flows)} connection attempts)",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH if len(flows) >= 30 else Confidence.MEDIUM,
            description=(f"{src} sent SYN packets to {len(ports)} distinct ports on "
                         f"other hosts; only {completed} handshakes completed."),
            explanation=(
                "A SYN scan probes many ports quickly to find open services "
                "without completing connections. Legitimate software rarely "
                "touches dozens of ports on remote hosts in one burst — but "
                "load balancers and monitoring systems sometimes do, so check "
                "what {src} is before concluding.".replace("{src}", src)),
            verification=(
                "In Wireshark, filter for this source's SYN packets "
                '("ip.src == {src} && tcp.flags.syn == 1 && !tcp.flags.ack") '
                "and check which ports answered SYN+ACK.".replace("{src}", src)),
            evidence=[f"distinct destination ports probed: {len(ports)}",
                      f"example ports: {', '.join(map(str, ports[:12]))}"
                      + ("…" if len(ports) > 12 else ""),
                      f"handshake completion rate: {completed}/{len(flows)}",
                      f"scan window: {duration:.1f}s"],
            hosts=[src],
            protocol="tcp",
            first_ts=first, last_ts=last,
            wireshark_filters=[f'ip.src == {src} && tcp.flags.syn == 1 && !tcp.flags.ack'],
            mitre=[mitre("T1046", "mass TCP SYN probing of many ports"),
                   mitre("T1595", "active scanning behavior against network hosts")],
        ))
    return findings[:10]


def detect_host_scan(result) -> list[Finding]:
    """One source sweeping many destination hosts on the same port."""
    if result.overview is None:
        return []
    by_src_port: dict[tuple, set] = {}
    flow_times: dict[tuple, list] = {}
    for f in result.overview.flow_tracker.flows.values():
        if f.proto != "tcp" or f.syn_count == 0:
            continue
        key = (f.src, f.dport)
        by_src_port.setdefault(key, set()).add(f.dst)
        flow_times.setdefault(key, []).extend([f.first_ts, f.last_ts])
    findings = []
    for (src, dport), dsts in sorted(by_src_port.items(), key=lambda kv: -len(kv[1])):
        if len(dsts) < 20:
            continue
        times = [t for t in flow_times[(src, dport)] if t]
        findings.append(Finding(
            id=f"scan.host.{src}.{dport}",
            title=f"Host sweep: {src} contacted {len(dsts)} hosts on port {dport}",
            severity=Severity.MEDIUM,
            confidence=Confidence.MEDIUM,
            description=(f"{src} attempted connections to {len(dsts)} distinct "
                         f"destination hosts, all on port {dport}"
                         + (f" ({service_name(dport)})" if service_name(dport) else "") + "."),
            explanation=(
                "Contacting many hosts on a single port is the signature of a "
                "host sweep looking for one vulnerable service (or of network "
                "discovery tooling). Compare with the port-scan finding: a port "
                "scan hits many ports on one host, a sweep hits one port on "
                "many hosts."),
            verification=(f"In Wireshark: ip.src == {src} && tcp.dstport == {dport} "
                          "— count the distinct ip.dst values."),
            evidence=[f"distinct destination IPs: {len(dsts)}",
                      f"example destinations: {', '.join(sorted(dsts)[:8])}"
                      + ("…" if len(dsts) > 8 else "")],
            hosts=[src],
            protocol="tcp",
            first_ts=min(times) if times else None,
            last_ts=max(times) if times else None,
            wireshark_filters=[f"ip.src == {src} && tcp.dstport == {dport}"],
            mitre=[mitre("T1595.001", "scanning many IP addresses on one service port")],
        ))
        if len(findings) >= 5:
            break
    return findings


def detect_unusual_ports(result) -> list[Finding]:
    """Well-known service running on a nonstandard port."""
    if result.overview is None:
        return []
    suspicious: list[tuple[str, str, int, str]] = []
    for conv in result.overview.flow_tracker.conversations.values():
        if conv.proto != "tcp":
            continue
        port = conv.service_port
        known = {4444: "Metasploit default handler", 5555: "ADB / reverse shell",
                 31337: "Elite / backdoor", 50050: "Metasploit RPC",
                 4445: "Metasploit", 6666: "IRC-based C2", 6667: "IRC-based C2",
                 12345: "NetBus", 12346: "NetBus", 54321: "NetBus 2"}
        if port in known and conv.bytes > 0:
            suspicious.append((conv.a, conv.b, port, known[port]))
    findings = []
    for a, b, port, why in suspicious[:10]:
        findings.append(Finding(
            id=f"port.unusual.{a}.{b}.{port}",
            title=f"Traffic on commonly-abused port {port} ({why})",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description=f"{a} ↔ {b} exchanged data on port {port}, commonly "
                        f"associated with {why}.",
            explanation=(
                "Ports like these are defaults for offensive tooling, but they "
                "are also used by legitimate software occasionally. The port "
                "number alone is a weak indicator — inspect the stream content "
                "before deciding."),
            verification=f"In Wireshark: tcp.port == {port}, then right-click a "
                         "packet → Follow → TCP Stream.",
            evidence=[f"connection {a} ↔ {b} port {port}"],
            hosts=[a, b], protocol="tcp",
            wireshark_filters=[f"tcp.port == {port}"],
            mitre=[mitre("T1571", "service communicating on a non-standard, "
                                  "tooling-associated port")],
        ))
    return findings
