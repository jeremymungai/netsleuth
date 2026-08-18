"""Network overview: hosts, protocols, services, conversations, talkers."""

from __future__ import annotations

from dataclasses import dataclass, field

from netsleuth.enrichment.nets import classify_network, is_internal_ip
from netsleuth.enrichment.oui import vendor_lookup
from netsleuth.flows import FlowTracker
from netsleuth.models import Packet


@dataclass
class Overview:
    hosts: dict[str, object] = field(default_factory=dict)
    protocol_counts: dict[str, int] = field(default_factory=dict)
    l7_counts: dict[str, int] = field(default_factory=dict)      # dns/http/tls/ssh...
    mac_vendors: dict[str, str] = field(default_factory=dict)
    total_bytes: int = 0
    total_payload_bytes: int = 0
    flow_tracker: FlowTracker = field(default_factory=FlowTracker)

    def top_talkers(self, n: int = 10):
        return sorted(self.hosts.values(),
                      key=lambda h: h.bytes_sent + h.bytes_received, reverse=True)[:n]

    def top_conversations(self, n: int = 10):
        return sorted(self.flow_tracker.conversations.values(),
                      key=lambda c: c.bytes, reverse=True)[:n]

    def to_dict(self) -> dict:
        return {
            "hosts": [h.to_dict() for h in
                      sorted(self.hosts.values(), key=lambda h: h.ip)],
            "protocol_counts": dict(sorted(self.protocol_counts.items(),
                                           key=lambda kv: -kv[1])),
            "l7_counts": dict(sorted(self.l7_counts.items(), key=lambda kv: -kv[1])),
            "mac_vendors": dict(self.mac_vendors),
            "total_bytes": self.total_bytes,
            "total_payload_bytes": self.total_payload_bytes,
        }


# L7 identification purely by port + payload presence (best-effort,
# clearly labeled as inferred in reports).
_L7: dict[tuple[str, int], str] = {
    ("udp", 53): "dns", ("tcp", 53): "dns", ("udp", 67): "dhcp", ("udp", 68): "dhcp",
    ("tcp", 80): "http", ("tcp", 8080): "http", ("tcp", 8000): "http",
    ("tcp", 443): "tls", ("tcp", 8443): "tls", ("tcp", 22): "ssh",
    ("tcp", 21): "ftp", ("tcp", 25): "smtp", ("tcp", 587): "smtp",
    ("tcp", 110): "pop3", ("tcp", 143): "imap", ("tcp", 23): "telnet",
    ("tcp", 445): "smb", ("tcp", 139): "smb", ("tcp", 88): "kerberos",
    ("tcp", 389): "ldap", ("tcp", 3389): "rdp", ("tcp", 3306): "mysql",
    ("tcp", 5432): "postgresql", ("tcp", 6379): "redis",
}


class OverviewAnalyzer:
    """Builds the host/protocol/traffic map during the packet pass."""

    name = "overview"

    def __init__(self) -> None:
        self.data = Overview()

    def feed(self, pkt: Packet) -> None:
        ov = self.data
        ov.flow_tracker.feed(pkt)
        ov.protocol_counts[pkt.proto or "other"] = ov.protocol_counts.get(pkt.proto or "other", 0) + 1
        ov.total_bytes += pkt.frame_len
        ov.total_payload_bytes += pkt.payload_len

        if pkt.mac_src and pkt.mac_src not in ov.mac_vendors:
            v = vendor_lookup(pkt.mac_src)
            if v:
                ov.mac_vendors[pkt.mac_src] = v

        for mac, ip in ((pkt.mac_src, pkt.src), (pkt.mac_dst, pkt.dst)):
            if not ip:
                continue
            h = ov.hosts.get(ip)
            if h is None:
                from netsleuth.models import Host
                h = Host(ip=ip, ip_version=pkt.ip_version or (6 if ":" in ip else 4),
                         is_internal=is_internal_ip(ip))
                ov.hosts[ip] = h
            if mac:
                h.macs.add(mac)

        if pkt.src and pkt.dst:
            src_h, dst_h = ov.hosts.get(pkt.src), ov.hosts.get(pkt.dst)
            if src_h is not None and dst_h is not None:
                src_h.packets_sent += 1
                src_h.bytes_sent += pkt.frame_len
                dst_h.packets_received += 1
                dst_h.bytes_received += pkt.frame_len
                if pkt.dport:
                    src_h.ports_contacted.add(pkt.dport)
                    if classify_network(pkt.src) == "private":
                        dst_h.services.add(pkt.dport)

        if pkt.proto in ("tcp", "udp") and pkt.payload_len > 0:
            for key in ((pkt.proto, pkt.dport), (pkt.proto, pkt.sport)):
                name = _L7.get(key)
                if name:
                    ov.l7_counts[name] = ov.l7_counts.get(name, 0) + 1
                    break

    def finalize(self) -> None:
        # learn hostnames from DNS is done by the DNS analyzer writing
        # into overview.hosts; nothing to compute here yet
        pass
