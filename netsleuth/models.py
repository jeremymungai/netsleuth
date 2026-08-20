"""Core data models shared by every stage of the pipeline.

Design rule: once a packet has been dissected, analyzers, detectors and
reporters only ever see the dataclasses in this module — never scapy
objects. That keeps the analysis layers decoupled from the parsing
library and lets every component be unit-tested with synthetic data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


def utc(ts: float) -> datetime:
    """Convert a unix timestamp to an aware UTC datetime."""
    return datetime.fromtimestamp(ts, tz=timezone.utc)


def iso(ts: Optional[float]) -> Optional[str]:
    """Render a unix timestamp as an ISO-8601 UTC string (or None)."""
    return utc(ts).isoformat(sep=" ", timespec="milliseconds") if ts is not None else None


class Severity(str, Enum):
    """Finding severity levels, ordered from informational to critical."""

    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def weight(self) -> int:
        return {"INFO": 0, "LOW": 15, "MEDIUM": 35, "HIGH": 65, "CRITICAL": 90}[self.value]


class Confidence(str, Enum):
    """How sure a detector is that its finding reflects malicious activity.

    NetSleuth distinguishes *observed evidence* from *inference*: a
    confidence level is attached to every conclusion so the analyst knows
    how much weight to give it.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


# --------------------------------------------------------------------------
# Normalized packet (the unit the streaming pipeline hands to analyzers)
# --------------------------------------------------------------------------

@dataclass
class DNSRecord:
    """One DNS question/answer pair extracted from a packet."""

    ts: float
    client: str
    server: str
    name: str
    qtype: str                      # A, AAAA, TXT, ...
    is_response: bool
    response_code: str = ""         # NOERROR, NXDOMAIN, ...
    answers: list[str] = field(default_factory=list)   # resolved values (IPs, CNAMEs, TXT...)
    answer_type: str = ""           # A, CNAME, TXT, MX, ...
    ttl: int = 0
    frame: int = 0                  # capture packet number (evidence)


@dataclass
class Packet:
    """A link-, network- and transport-normalized view of one packet.

    Cheap scalar fields are extracted eagerly; payloads are carried as
    bytes so higher layers (stream reassembly, secret scanning) never need
    the original packet structure. ``payload`` excludes network/transport
    headers.
    """

    ts: float
    src: str = ""                   # IP address (L3), or "" when none
    dst: str = ""
    ip_version: int = 0             # 4, 6, or 0
    mac_src: str = ""
    mac_dst: str = ""
    proto: str = ""                 # tcp, udp, icmp, icmp6, arp, other L3...
    sport: int = 0
    dport: int = 0
    tcp_flags: str = ""             # e.g. "SA", "FA", "R"
    tcp_seq: int = 0                # raw sequence number (TCP only)
    payload_len: int = 0
    payload: bytes = b""
    dns: Optional[DNSRecord] = None
    frame_len: int = 0
    icmp_type: int = -1             # ICMP type when proto is icmp/icmp6
    frame: int = 0                  # 1-based packet index in the capture
    ip_id: int = -1                 # IPv4 identification field (covert-channel signal)
    ip_ttl: int = -1                # IPv4 TTL (covert-channel signal)


# --------------------------------------------------------------------------
# Capture metadata
# --------------------------------------------------------------------------

@dataclass
class CaptureMeta:
    """File-level facts about the capture being analyzed."""

    path: str = ""
    format: str = ""                # pcap | pcapng
    size_bytes: int = 0
    packet_count: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    linktype: str = ""
    interfaces: list[str] = field(default_factory=list)
    truncated: bool = False         # capture ended mid-packet
    notes: list[str] = field(default_factory=list)

    @property
    def duration(self) -> float:
        if self.first_ts is None or self.last_ts is None:
            return 0.0
        return self.last_ts - self.first_ts

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "format": self.format,
            "size_bytes": self.size_bytes,
            "packet_count": self.packet_count,
            "first_ts": iso(self.first_ts),
            "last_ts": iso(self.last_ts),
            "duration_seconds": round(self.duration, 3),
            "linktype": self.linktype,
            "interfaces": list(self.interfaces),
            "truncated": self.truncated,
            "notes": list(self.notes),
        }


# --------------------------------------------------------------------------
# Network visibility
# --------------------------------------------------------------------------

@dataclass
class Host:
    """An endpoint observed in the capture (L3 address keyed)."""

    ip: str
    ip_version: int = 4
    macs: set[str] = field(default_factory=set)
    is_internal: bool = True        # RFC1918 / link-local / ULA heuristic
    hostnames: set[str] = field(default_factory=set)   # learned from DNS answers
    packets_sent: int = 0
    packets_received: int = 0
    bytes_sent: int = 0
    bytes_received: int = 0
    ports_contacted: set[int] = field(default_factory=set)
    services: set[int] = field(default_factory=set)    # ports this host listened on

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "ip_version": self.ip_version,
            "macs": sorted(self.macs),
            "is_internal": self.is_internal,
            "hostnames": sorted(self.hostnames),
            "packets_sent": self.packets_sent,
            "packets_received": self.packets_received,
            "bytes_sent": self.bytes_sent,
            "bytes_received": self.bytes_received,
            "ports_contacted": sorted(self.ports_contacted),
            "services": sorted(self.services),
        }


@dataclass
class Flow:
    """One directional transport conversation (single 5-tuple direction)."""

    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    packets: int = 0
    bytes: int = 0                  # payload bytes (headers excluded)
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    syn_count: int = 0
    ack_of_syn: bool = False        # handshake completed (SA seen from peer)
    fin_count: int = 0
    rst_count: int = 0

    @property
    def key(self) -> tuple:
        return (self.proto, self.src, self.sport, self.dst, self.dport)


@dataclass
class Conversation:
    """Bidirectional aggregate of the two directions of a connection."""

    a: str                          # endpoint that initiated (first packet)
    b: str
    a_port: int = 0                 # ephemeral port of the initiator
    b_port: int = 0                 # service port
    proto: str = "tcp"
    packets: int = 0
    bytes: int = 0
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None

    @property
    def service_port(self) -> int:
        return self.b_port

    def to_dict(self) -> dict:
        return {
            "a": self.a, "b": self.b, "a_port": self.a_port, "b_port": self.b_port,
            "proto": self.proto, "packets": self.packets, "bytes": self.bytes,
            "first_ts": iso(self.first_ts), "last_ts": iso(self.last_ts),
        }


# --------------------------------------------------------------------------
# TCP streams
# --------------------------------------------------------------------------

@dataclass
class StreamInfo:
    """Summary of one reconstructed TCP stream (both directions)."""

    index: int                      # stream id, ordered by first packet time
    client: str                     # initiator address
    server: str
    client_port: int
    server_port: int
    start_ts: Optional[float] = None
    end_ts: Optional[float] = None
    packets: int = 0
    bytes_c2s: int = 0
    bytes_s2c: int = 0
    handshake: bool = False         # full SYN/ACK seen
    terminated_cleanly: bool = False
    gaps: int = 0                   # unrecovered sequence gaps

    @property
    def total_bytes(self) -> int:
        return self.bytes_c2s + self.bytes_s2c

    def to_dict(self) -> dict:
        return {
            "index": self.index, "client": self.client, "server": self.server,
            "client_port": self.client_port, "server_port": self.server_port,
            "start_ts": iso(self.start_ts), "end_ts": iso(self.end_ts),
            "packets": self.packets, "bytes_c2s": self.bytes_c2s,
            "bytes_s2c": self.bytes_s2c, "handshake": self.handshake,
            "terminated_cleanly": self.terminated_cleanly, "gaps": self.gaps,
        }


@dataclass
class StreamData:
    """Reassembled payload of a TCP stream, kept per direction."""

    info: StreamInfo
    c2s: bytes = b""                # client → server payload
    s2c: bytes = b""                # server → client payload

    def direction(self, payload: bytes) -> str:
        return "c2s" if payload is self.c2s else "s2c"


# --------------------------------------------------------------------------
# Application-layer observations
# --------------------------------------------------------------------------

@dataclass
class HTTPTransaction:
    """One HTTP request/response pair recovered from a TCP stream."""

    ts: Optional[float] = None
    stream: int = -1
    client: str = ""
    host: str = ""
    method: str = ""
    url: str = ""                   # full URL as requested (path [+ query])
    path: str = ""
    query: str = ""
    user_agent: str = ""
    content_type_req: str = ""
    status: int = 0
    content_type_resp: str = ""
    server_header: str = ""
    resp_content_length: int = -1
    req_body_len: int = 0
    resp_body_len: int = 0
    auth_header: str = ""           # Authorization header (value masked upstream)
    cookies: str = ""
    version: str = ""               # "HTTP/1.0" / "HTTP/1.1" (covert-channel field)
    header_count: int = 0           # request header count (covert-channel field)
    body_excerpt: bytes = b""       # first bytes of request body (detection)
    resp_body: Optional[bytes] = None    # full response body when retained (carving)
    req_body: Optional[bytes] = None     # request body (POST) when retained

    def to_dict(self, include_body: bool = False) -> dict:
        d = {
            "ts": iso(self.ts), "stream": self.stream, "client": self.client,
            "host": self.host, "method": self.method, "url": self.url,
            "path": self.path, "query": self.query, "user_agent": self.user_agent,
            "status": self.status, "content_type": self.content_type_resp,
            "req_body_len": self.req_body_len, "resp_body_len": self.resp_body_len,
            "auth": self.auth_header, "cookies": self.cookies,
        }
        if include_body and self.resp_body:
            d["resp_body_b64"] = self.resp_body.hex()
        return d


@dataclass
class TLSSession:
    """Metadata recovered from a TLS exchange (contents are never decrypted)."""

    ts: Optional[float] = None
    src: str = ""
    dst: str = ""
    dst_port: int = 0
    sni: str = ""
    tls_version: str = ""           # negotiated / offered
    alpn: list[str] = field(default_factory=list)
    ja3: str = ""
    ja3_clear: str = ""
    cert_subject: str = ""
    cert_issuer: str = ""
    cert_valid_from: str = ""
    cert_valid_to: str = ""
    cert_self_signed: Optional[bool] = None
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "ts": iso(self.ts), "src": self.src, "dst": self.dst, "dst_port": self.dst_port,
            "sni": self.sni, "version": self.tls_version, "alpn": list(self.alpn),
            "ja3": self.ja3, "subject": self.cert_subject, "issuer": self.cert_issuer,
            "valid_from": self.cert_valid_from, "valid_to": self.cert_valid_to,
            "self_signed": self.cert_self_signed, "errors": list(self.errors),
        }


@dataclass
class Credential:
    """A cleartext credential (or credential-shaped secret) observed on the wire."""

    ts: Optional[float] = None
    protocol: str = ""              # ftp, smtp, imap, pop3, http, telnet...
    client: str = ""
    server: str = ""
    username: str = ""
    password: str = ""
    kind: str = "login"             # login, auth-header, cookie, api-key...
    detail: str = ""
    stream: int = -1

    def masked_password(self) -> str:
        if not self.password:
            return ""
        if len(self.password) <= 2:
            return "*" * len(self.password)
        return self.password[0] + "…" + self.password[-1] + f" ({len(self.password)} chars)"

    def to_dict(self, reveal: bool = False) -> dict:
        return {
            "ts": iso(self.ts), "protocol": self.protocol, "client": self.client,
            "server": self.server, "username": self.username,
            "password": self.password if reveal else self.masked_password(),
            "kind": self.kind, "detail": self.detail, "stream": self.stream,
        }


@dataclass
class ICMPObservation:
    """ICMP packet carrying a payload worth reporting (e.g. echo with data)."""

    ts: float
    src: str
    dst: str
    icmp_type: str                  # echo-request, echo-reply, ...
    payload_len: int
    payload: bytes = b""

    def to_dict(self) -> dict:
        return {
            "ts": iso(self.ts), "src": self.src, "dst": self.dst,
            "type": self.icmp_type, "payload_len": self.payload_len,
            "payload_utf8_replace": self.payload.decode("utf-8", "replace")[:200],
        }


@dataclass
class DHCPObservation:
    ts: float
    client_mac: str = ""
    message_type: str = ""          # discover, offer, request, ack...
    requested_ip: str = ""
    assigned_ip: str = ""
    hostname: str = ""

    def to_dict(self) -> dict:
        return {
            "ts": iso(self.ts), "client_mac": self.client_mac,
            "message_type": self.message_type, "requested_ip": self.requested_ip,
            "assigned_ip": self.assigned_ip, "hostname": self.hostname,
        }


# --------------------------------------------------------------------------
# Detections & artifacts
# --------------------------------------------------------------------------

@dataclass
class MitreRef:
    technique: str                  # e.g. "T1071.004"
    tactic: str                     # e.g. "Command and Control"
    name: str = ""
    why: str = ""                   # why this mapping applies to the finding

    def to_dict(self) -> dict:
        return {"technique": self.technique, "tactic": self.tactic,
                "name": self.name, "why": self.why}


@dataclass
class Finding:
    """One explainable detection result.

    Every finding carries its own evidence, affected hosts, timestamps,
    a Wireshark display filter for manual verification, an explanation of
    what it means, and how confident NetSleuth is. Findings deliberately
    never claim certainty the evidence does not support.
    """

    id: str
    title: str
    severity: Severity
    confidence: Confidence
    description: str = ""           # what was observed
    explanation: str = ""           # what it usually means and why it matters
    verification: str = ""          # how to check by hand (prose)
    evidence: list[str] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    protocol: str = ""
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    packet_refs: list[str] = field(default_factory=list)   # e.g. ["frame 142"]
    wireshark_filters: list[str] = field(default_factory=list)
    mitre: list[MitreRef] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "id": self.id, "title": self.title, "severity": self.severity.value,
            "confidence": self.confidence.value, "description": self.description,
            "explanation": self.explanation, "verification": self.verification,
            "evidence": list(self.evidence), "hosts": list(self.hosts),
            "protocol": self.protocol,
            "first_ts": iso(self.first_ts), "last_ts": iso(self.last_ts),
            "packet_refs": list(self.packet_refs),
            "wireshark_filters": list(self.wireshark_filters),
            "mitre": [m.to_dict() for m in self.mitre],
        }


@dataclass
class Artifact:
    """A file recovered from the capture."""

    filename: str                   # sanitized name under the output directory
    protocol: str = ""              # http, smtp, ftp...
    src: str = ""
    dst: str = ""
    ts: Optional[float] = None
    size: int = 0
    sha256: str = ""
    sha1: str = ""
    md5: str = ""
    detected_type: str = ""         # magic-byte based
    claimed_type: str = ""          # from headers (content-type / filename)
    stream: int = -1
    url: str = ""
    stored_path: str = ""

    def to_dict(self) -> dict:
        return {
            "filename": self.filename, "protocol": self.protocol, "src": self.src,
            "dst": self.dst, "ts": iso(self.ts), "size": self.size,
            "sha256": self.sha256, "sha1": self.sha1, "md5": self.md5,
            "detected_type": self.detected_type, "claimed_type": self.claimed_type,
            "stream": self.stream, "url": self.url,
        }


@dataclass
class SecretMatch:
    """A string that looks like a flag, credential, key or token."""

    kind: str                       # flag, password, api-key, token, email...
    value: str
    source: str                     # human description of where it was found
    protocol: str = ""
    ts: Optional[float] = None
    stream: int = -1
    hosts: list[str] = field(default_factory=list)
    confidence: str = "medium"
    how: str = ""                   # how it was discovered (CTF teaching aid)

    def masked(self) -> str:
        if not self.value:
            return ""
        if len(self.value) <= 4:
            return "*" * len(self.value)
        if len(self.value) <= 8:
            return self.value[0] + "…" + self.value[-1]
        if len(self.value) <= 14:
            return self.value[:6] + "…" + self.value[-2:]
        return self.value[:7] + "…" + self.value[-3:]

    def to_dict(self, reveal: bool = False) -> dict:
        return {
            "kind": self.kind, "value": self.value if reveal else self.masked(),
            "source": self.source, "protocol": self.protocol, "ts": iso(self.ts),
            "stream": self.stream, "hosts": list(self.hosts),
            "confidence": self.confidence, "how": self.how,
        }


@dataclass
class CovertCandidate:
    """A protocol-metadata field that appears to encode information.

    Anti-hallucination contract: a candidate never claims hidden data —
    it reports exactly what was observed (field, values, sequence), what
    mapping and decoding were *attempted*, and how plausible the result
    is. All steps are reproducible from the evidence.
    """

    protocol: str                   # http | dns | tcp | ip
    field: str                      # e.g. "request version", "query type"
    source: str                     # host whose traffic carries the sequence
    observed_values: list[str] = field(default_factory=list)   # distinct values
    value_counts: dict[str, int] = field(default_factory=dict)
    sequence: list[str] = field(default_factory=list)          # chronological, capped
    sequence_len: int = 0
    pattern: str = ""               # e.g. "two-state repeated sequence"
    mapping: str = ""               # "HTTP/1.0→0, HTTP/1.1→1"
    bits: str = ""                  # extracted bitstream (capped for display)
    bits_len: int = 0
    byte_len: int = 0
    decoded: str = ""               # best candidate decoding
    printable_ratio: float = 0.0
    confidence: str = "low"
    first_ts: Optional[float] = None
    last_ts: Optional[float] = None
    frames: list[int] = field(default_factory=list)            # first/last packet numbers
    wireshark_filters: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    alternatives_considered: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "protocol": self.protocol, "field": self.field, "source": self.source,
            "observed_values": list(self.observed_values),
            "value_counts": dict(self.value_counts),
            "sequence": self.sequence[:64], "sequence_length": self.sequence_len,
            "pattern": self.pattern, "mapping": self.mapping,
            "bits_preview": self.bits[:64], "bits_length": self.bits_len,
            "grouped_bytes": self.byte_len, "decoded": self.decoded[:400],
            "printable_ratio": round(self.printable_ratio, 3),
            "confidence": self.confidence,
            "first_ts": iso(self.first_ts), "last_ts": iso(self.last_ts),
            "frames": list(self.frames),
            "wireshark_filters": list(self.wireshark_filters),
            "assumptions": list(self.assumptions),
            "alternatives_considered": list(self.alternatives_considered),
        }


@dataclass
class TimelineEvent:
    """A chronological investigation event rendered in the timeline."""

    ts: float
    kind: str                       # dns, http, tls, tcp, file, detection...
    summary: str
    severity: Severity = Severity.INFO
    hosts: list[str] = field(default_factory=list)
    stream: int = -1
    wireshark_filter: str = ""

    def to_dict(self) -> dict:
        return {
            "ts": iso(self.ts), "kind": self.kind, "summary": self.summary,
            "severity": self.severity.value, "hosts": list(self.hosts),
            "stream": self.stream, "wireshark_filter": self.wireshark_filter,
        }


@dataclass
class RiskScore:
    """Composite risk score (0-100) derived from findings — a triage signal,
    not a verdict. See detection/scoring for the formula."""

    score: int = 0
    breakdown: dict[str, int] = field(default_factory=dict)

    @property
    def label(self) -> str:
        if self.score >= 80:
            return "critical"
        if self.score >= 60:
            return "high"
        if self.score >= 35:
            return "elevated"
        if self.score > 0:
            return "low"
        return "none"

    def to_dict(self) -> dict:
        return {"score": self.score, "label": self.label, "breakdown": dict(self.breakdown)}
