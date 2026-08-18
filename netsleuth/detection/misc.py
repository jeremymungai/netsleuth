"""Miscellaneous detectors: ARP, ICMP, cleartext protocols, secrets, volume."""

from __future__ import annotations

from netsleuth.enrichment.mitre import mitre
from netsleuth.enrichment.nets import is_internal_ip
from netsleuth.models import Confidence, Finding, Severity


def detect_arp_conflict(result) -> list[Finding]:
    if result.arp is None:
        return []
    conflicts = result.arp.conflicts()
    findings = []
    for ip, macs in list(conflicts.items())[:6]:
        events = [e for e in result.arp.events if e.sender_ip == ip]
        findings.append(Finding(
            id=f"arp.conflict.{ip}",
            title=f"Two MAC addresses claimed IP {ip}",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description=(f"{ip} was announced by {len(macs)} different MAC "
                        f"addresses: {', '.join(macs)}."),
            explanation=(
                "One IP should have one MAC. Two claimants usually means ARP "
                "spoofing — an attacker impersonating a host (gateway!) to "
                "intercept traffic — or a misconfigured/HA failover device "
                "that didn't clean up. Check whether the capture shows the "
                "legitimate MAC losing traffic to the new one, and whether "
                "hosts started sending everything to the attacker."),
            verification=(f"In Wireshark: arp.dst.proto_ipv4 == {ip} or "
                          f"arp.src.proto_ipv4 == {ip} — compare "
                          "arp.src.hw_mac across replies."),
            evidence=[f"claimed by: {mac}" for mac in macs],
            hosts=[ip], protocol="arp",
            first_ts=min((e.ts for e in events), default=None),
            last_ts=max((e.ts for e in events), default=None),
            wireshark_filters=[f"arp.src.proto_ipv4 == {ip}"],
            mitre=[mitre("T1557", "conflicting ARP claims consistent with "
                                  "traffic interception")],
        ))
    return findings


def detect_icmp_payload(result) -> list[Finding]:
    data = [o for o in result.icmp if o.icmp_type == "echo-request"
            and o.payload_len >= 16]
    if not data:
        return []
    total = sum(o.payload_len for o in data)
    o0 = data[0]
    return [Finding(
        id="icmp.payload-channel",
        title=f"ICMP echo requests carrying {total} bytes of data payload",
        severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        description=(f"{len(data)} echo request(s) carry payloads of "
                     f"{o0.payload_len}+ bytes (normal ping payloads are "
                     "usually small and uniform)."),
        explanation=(
            "The ping protocol has no business carrying rich text/binary "
            "data. Large or varied payloads inside ICMP echo are how simple "
            "backdoors exfiltrate or beacon while slipping past port-based "
            "rules. Some monitoring tools do embed data, so read the payload "
            "before judging."),
        verification=f"In Wireshark: icmp && data.len >= 16, then inspect the "
                     "echo data field.",
        evidence=[f"example payload ({o0.payload_len} bytes): "
                  f"{o0.payload[:64].decode('latin-1', 'replace')!r}"] +
                 [f"{o.src} → {o.dst}: {o.payload_len} bytes" for o in data[:5]],
        hosts=sorted({o.src for o in data} | {o.dst for o in data}),
        protocol="icmp",
        first_ts=data[0].ts,
        wireshark_filters=["icmp.type == 8 && data.len >= 16"],
        mitre=[mitre("T1095", "ICMP echo used as a data channel"),
               mitre("T1048.003", "data moved over an unencrypted "
                                  "non-application protocol")],
    )]


def detect_cleartext_protocols(result) -> list[Finding]:
    if not result.credentials:
        return []
    by_proto: dict[str, list] = {}
    for c in result.credentials:
        if c.kind in ("login", "auth"):
            by_proto.setdefault(c.protocol, []).append(c)
    findings = []
    for proto, creds in sorted(by_proto.items()):
        c0 = creds[0]
        findings.append(Finding(
            id=f"creds.cleartext.{proto}",
            title=f"Cleartext {proto.upper()} credentials observed "
                  f"({len(creds)} login(s))",
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(f"{c0.client} authenticated to {c0.server} over "
                         f"unencrypted {proto.upper()}; the capture contains "
                         "the username and password in plaintext."),
            explanation=(
                "FTP/SMTP/IMAP/POP3/telnet (and HTTP Basic) send credentials "
                "without encryption. This is an observed fact, not an "
                "inference: anyone with this capture can read them. If this "
                "is your own traffic, treat those passwords as compromised "
                "and move the protocol to its TLS variant (FTPS/SMTPS/IMAPS/"
                "HTTPS)."),
            verification=(f"In Wireshark: right-click any {proto.upper()} "
                          f"packet → Follow → TCP Stream "
                          + (f"(tcp.stream == {c0.stream})" if c0.stream >= 0 else "")
                          + " — the USER/PASS lines are visible in the "
                          "reassembled conversation."),
            evidence=[f"{c.protocol}: user={c.username!r} password="
                      f"{c.masked_password()}" for c in creds[:5]],
            hosts=[c0.client, c0.server],
            protocol=proto,
            first_ts=min((c.ts for c in creds if c.ts), default=None),
            wireshark_filters=[f"tcp.stream == {c0.stream}"] if c0.stream >= 0 else [],
            mitre=[mitre("T1552.001", "credentials readable in cleartext "
                                      "network traffic")],
        ))
    return findings


def detect_secret_material(result) -> list[Finding]:
    """Promote high-value secret scanner hits into detections."""
    out = []
    key_material = [s for s in result.secrets if s.kind == "key-material"]
    if key_material:
        s0 = key_material[0]
        out.append(Finding(
            id="secrets.private-key",
            title=f"Private key material in traffic ({len(key_material)} occurrence(s))",
            severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            description=("A PEM 'BEGIN PRIVATE KEY' block was transferred in "
                         "the clear and is captured in this file."),
            explanation=(
                "Private keys crossing the network unencrypted (paste sites, "
                "misconfigured backups, HTTP uploads) are immediately "
                "compromisable. If this capture is from your environment, "
                "rotate that key now and find the transfer's source."),
            verification="In Wireshark: frame contains \"PRIVATE KEY-----\"",
            evidence=[f"{s.source}: {s.value[:40]}…" for s in key_material[:4]],
            hosts=[h for s in key_material[:4] for h in s.hosts],
            first_ts=s0.ts,
            wireshark_filters=['frame contains "PRIVATE KEY-----"'],
            mitre=[mitre("T1552.004", "private key exposed in transit")],
        ))
    api_keys = [s for s in result.secrets if s.kind == "api-key"]
    if api_keys:
        s0 = api_keys[0]
        out.append(Finding(
            id="secrets.api-keys",
            title=f"API-key-shaped strings in traffic ({len(api_keys)})",
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            description=("Strings matching known API key formats (AWS/Google/"
                         "…) were found in captured traffic."),
            explanation=(
                "These may be live credentials leaked in URLs, pastes or "
                "logs — or test/dummy values that share the format. Verify "
                "against the provider before assuming compromise; never "
                "validate a key by calling the provider from this tool."),
            verification="In Wireshark: frame contains the key prefix "
                         "(e.g. 'AKIA' for AWS)",
            evidence=[f"{s.source}: {s.masked()}" for s in api_keys[:5]],
            hosts=[h for s in api_keys[:5] for h in s.hosts],
            first_ts=s0.ts,
            wireshark_filters=['frame contains "AKIA" || frame contains "AIza"'],
            mitre=[mitre("T1552.001", "credential-shaped secrets visible in "
                                      "captured traffic")],
        ))
    return out


def detect_bulk_transfer(result) -> list[Finding]:
    """Volume-based exfiltration heuristic: unusual outbound bulk."""
    if result.overview is None:
        return []
    BULK = 50 * 1024 * 1024            # 50 MB in one conversation
    flagged = []
    for conv in result.overview.flow_tracker.conversations.values():
        if conv.bytes >= BULK and is_internal_ip(conv.a) and not is_internal_ip(conv.b):
            flagged.append(conv)
    findings = []
    for conv in flagged[:5]:
        findings.append(Finding(
            id=f"exfil.bulk.{conv.a}.{conv.b}.{conv.service_port}",
            title=f"Bulk transfer to external host: {conv.a} → {conv.b} "
                  f"({conv.bytes / 1e6:.1f} MB)",
            severity=Severity.MEDIUM,
            confidence=Confidence.LOW,
            description=(f"A single {conv.proto.upper()} conversation moved "
                         f"{conv.bytes / 1e6:.1f} MB from internal {conv.a} "
                         f"to external {conv.b} on port {conv.service_port}."),
            explanation=(
                "This is purely a volume heuristic: backups, updates and "
                "media uploads look identical. It matters when the host or "
                "destination is unexpected, or when it correlates with other "
                "findings on the same host."),
            verification=(f"In Wireshark: ip.addr == {conv.b} && "
                          f"tcp.port == {conv.service_port}, check protocol "
                          "and content in the followed stream."),
            evidence=[f"{conv.packets} packets, {conv.bytes} bytes payload"],
            hosts=[conv.a, conv.b],
            protocol=conv.proto,
            first_ts=conv.first_ts, last_ts=conv.last_ts,
            wireshark_filters=[f"ip.addr == {conv.b} && tcp.port == {conv.service_port}"],
            mitre=[mitre("T1048.003", "large outbound volume over a "
                                      "cleartext protocol")],
        ))
    return findings
