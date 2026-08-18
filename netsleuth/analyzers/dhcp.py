"""DHCP analyzer — parses BOOTP/DHCP straight from UDP payloads.

Standalone (no scapy dependency) so it is unit-testable with hand-built
byte payloads. Handles the common message types, hostname option and
requested/assigned addresses.
"""

from __future__ import annotations

import socket

from netsleuth.models import DHCPObservation, Packet

_MAGIC = b"\x63\x82\x53\x63"
_MSG_TYPES = {1: "discover", 2: "offer", 3: "request", 4: "decline",
              5: "ack", 6: "nak", 7: "release", 8: "inform"}


def parse_dhcp(payload: bytes) -> DHCPObservation | None:
    """Parse a BOOTP/DHCP message; returns None when not DHCP-shaped."""
    if len(payload) < 240 or payload[236:240] != _MAGIC:
        return None
    op = payload[0]
    hlen = payload[2]
    chaddr = payload[28:28 + hlen]
    mac = ":".join(f"{b:02x}" for b in chaddr[:6])
    yiaddr = socket.inet_ntoa(payload[16:20]) if any(payload[16:20]) else ""
    siaddr = socket.inet_ntoa(payload[20:24]) if any(payload[20:24]) else ""

    msg_type = ""
    hostname = ""
    requested_ip = ""
    server_id = ""
    i = 240
    while i + 2 <= len(payload):
        code, length = payload[i], payload[i + 1]
        if code == 0:               # padding
            i += 1
            continue
        if code == 255:             # end
            break
        if i + 2 + length > len(payload):
            break
        val = payload[i + 2:i + 2 + length]
        if code == 53 and val:
            msg_type = _MSG_TYPES.get(val[0], f"type-{val[0]}")
        elif code == 12:
            hostname = val.split(b"\x00")[0].decode("utf-8", "replace")
        elif code == 50 and length == 4:
            requested_ip = socket.inet_ntoa(val)
        elif code == 54 and length == 4:
            server_id = socket.inet_ntoa(val)
        i += 2 + length

    if not msg_type:
        return None                 # BOOTP without DHCP options — skip
    role = "server" if op == 2 else "client"
    return DHCPObservation(
        ts=0.0, client_mac=mac, message_type=msg_type,
        requested_ip=requested_ip or (yiaddr if role == "client" and msg_type != "discover" else ""),
        assigned_ip=yiaddr if msg_type in ("offer", "ack") else "",
        hostname=hostname,
    )


class DHCPAnalyzer:
    name = "dhcp"

    def __init__(self) -> None:
        self.messages: list[DHCPObservation] = []

    def feed(self, pkt: Packet) -> None:
        if pkt.proto != "udp" or 67 not in (pkt.sport, pkt.dport) or not pkt.payload:
            return
        obs = parse_dhcp(pkt.payload)
        if obs is not None:
            obs.ts = pkt.ts
            self.messages.append(obs)

    def finalize(self) -> None:
        pass
