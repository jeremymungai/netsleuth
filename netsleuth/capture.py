"""Capture ingestion: validation, metadata, and streaming packet dissection.

This is the **only** module that imports scapy. Everything downstream
consumes the normalized :class:`netsleuth.models.Packet` records produced
here, which keeps the rest of the codebase independent of the parsing
library and easy to test with synthetic data.

Supports classic pcap (both endiannesses, micro/nanosecond) and pcapng,
optionally gzip-compressed. Malformed or truncated captures never abort
an analysis: what could be read is analyzed and the truncation is
reported in the capture metadata.
"""

from __future__ import annotations

import gzip
import os
import struct
from typing import Iterator, Optional

from scapy.error import Scapy_Exception
from scapy.packet import Packet as ScapyPacket
# importing scapy.utils alone does NOT load the layer modules, leaving
# conf.l2types empty — PcapReader would then decode every link type as
# raw bytes — and protocol/port bindings (UDP 53 → DNS, ICMPv6 types…)
# would never register. These side-effect imports load the bindings the
# dissector depends on, without pulling in all of scapy.all.
import scapy.layers.inet    # noqa: F401  (linktype + IP/TCP/UDP bindings)
import scapy.layers.inet6   # noqa: F401  (ICMPv6)
import scapy.layers.dns     # noqa: F401  (UDP 53 ⇄ DNS)

from netsleuth import structure
from netsleuth.models import CaptureMeta, DNSRecord, Packet

# ---------------------------------------------------------------------------
# Magic bytes / format detection
# ---------------------------------------------------------------------------

_MAGIC = {
    b"\xd4\xc3\xb2\xa1": ("pcap", "little-endian, microsecond"),
    b"\xa1\xb2\xc3\xd4": ("pcap", "big-endian, microsecond"),
    b"\x4d\x3c\xb2\xa1": ("pcap", "little-endian, nanosecond"),
    b"\xa1\xb2\x3c\x4d": ("pcap", "big-endian, nanosecond"),
    b"\x0a\x0d\x0d\x0a": ("pcapng", ""),
}

_LINKTYPES = {
    0: "NULL/loopback", 1: "Ethernet", 6: "Token ring", 8: "SLIP", 9: "PPP",
    12: "Raw IP (BSD)", 101: "Raw IP", 105: "IEEE 802.11", 107: "FDDI",
    113: "Linux cooked (SLL)", 114: "Linux cooked v2 (SLL2)", 143: "DOCSIS",
    195: "IEEE 802.15.4",
}


class CaptureError(Exception):
    """Raised when a capture file cannot be opened or is not a capture."""


def detect_format(path: str) -> tuple[str, str]:
    """Identify a capture file by magic bytes.

    Returns ``(format, detail)``. Raises :class:`CaptureError` for files
    that are not captures at all — with a message that tries to help.
    """
    try:
        size = os.path.getsize(path)
    except OSError as e:
        raise CaptureError(f"cannot read '{path}': {e.strerror or e}") from e
    if size == 0:
        raise CaptureError(f"'{path}' is empty (0 bytes) — nothing to analyze")
    try:
        with open(path, "rb") as fh:
            head = fh.read(4)
    except OSError as e:
        raise CaptureError(f"cannot read '{path}': {e.strerror or e}") from e
    if head in _MAGIC:
        fmt, detail = _MAGIC[head]
        return fmt, detail
    if head[:2] == b"\x1f\x8b":
        try:
            with gzip.open(path, "rb") as fh:
                inner = fh.read(4)
        except (OSError, gzip.BadGzipFile):
            raise CaptureError(f"'{path}' looks gzip-compressed but is not a valid gzip stream")
        if inner in _MAGIC:
            fmt, detail = _MAGIC[inner]
            return fmt, f"gzip-compressed {fmt} ({detail})"
        raise CaptureError(f"'{path}' is gzip-compressed but does not contain a capture")
    raise CaptureError(
        f"'{path}' is not a pcap or pcapng file (bad magic bytes {head.hex()}). "
        "If this is a Wireshark 'pdml'/'csv' export, re-export the raw capture instead."
    )


# ---------------------------------------------------------------------------
# DNS dissection helpers
# ---------------------------------------------------------------------------

QTYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT",
    17: "RP", 24: "SIG", 25: "KEY", 28: "AAAA", 29: "LOC", 33: "SRV",
    35: "NAPTR", 39: "DNAME", 41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC",
    48: "DNSKEY", 49: "DHCID", 50: "NSEC3", 51: "NSEC3PARAM", 52: "TLSA",
    59: "CDS", 60: "CDNSKEY", 61: "OPENPGPKEY", 62: "CSYNC", 63: "ZONEMD",
    64: "SVCB", 65: "HTTPS", 99: "SPF", 249: "TKEY", 250: "TSIG",
    251: "IXFR", 252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA",
}
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
          4: "NOTIMP", 5: "REFUSED"}


def _safe_ascii(raw: bytes, limit: int = 8192) -> str:
    """Decode a possibly hostile DNS name, escaping non-printable bytes."""
    out = []
    for b in raw[:limit]:
        out.append(chr(b) if 32 <= b < 127 else f"\\x{b:02x}")
    s = "".join(out)
    if len(raw) > limit:
        s += f"…(+{len(raw) - limit} bytes)"
    return s


def _rdata_str(rr) -> str:
    """Extract a printable rdata string from a scapy DNSRR."""
    try:
        rd = rr.rdata
    except Exception:
        return ""
    if isinstance(rd, bytes):
        return _safe_ascii(rd, 1024)
    txt = str(rd)
    if rr.type in (12, 5, 2):    # PTR/CNAME/NS — scapy prepends a dot
        txt = txt.lstrip(".")
    if rr.type == 15 and "," in txt:   # MX "10 mail.example.com"
        pref, _, rest = txt.partition(",")
        txt = f"{pref.strip()} {rest.strip()}"
    return txt


# ---------------------------------------------------------------------------
# The capture reader
# ---------------------------------------------------------------------------

class CaptureReader:
    """Streaming reader that yields normalized :class:`Packet` records.

    Usage::

        reader = CaptureReader("file.pcap")          # validates eagerly
        for pkt in reader:                           # single pass
            ...
        meta = reader.meta                           # filled during iteration
    """

    #: payloads above this size are truncated for analysis (1 MiB)
    MAX_PAYLOAD_SLICE = 1_048_576

    def __init__(self, path: str, max_packets: int = 0):
        self.path = os.path.abspath(path)
        fmt, detail = detect_format(self.path)
        self._fmt = fmt
        self._detail = detail
        self._max_packets = max_packets
        self.meta = CaptureMeta(
            path=self.path,
            format=fmt,
            size_bytes=os.path.getsize(self.path),
            notes=[f"format detail: {detail}"] if detail else [],
        )
        # cheap structural pre-scan: exact packet count, truncation, interfaces
        st = structure.scan(self.path)
        if st.truncated:
            self.meta.truncated = True
            self.meta.notes.append(
                "capture file is structurally truncated (ends mid-record); "
                "packets after the cut point are unrecoverable")
        if st.interfaces:
            self.meta.interfaces = st.interfaces
        if st.linktypes and not self.meta.linktype:
            self.meta.linktype = ", ".join(dict.fromkeys(st.linktypes))
        self._expected_packets = st.packet_count
        self._linktype = 1                # refined by _open()
        self._opened = False

    # -- public API ---------------------------------------------------------

    def iter_packets(self) -> Iterator[Packet]:
        """Yield normalized packets; fills ``self.meta`` along the way."""
        reader = self._open()
        self._opened = True
        n = 0
        try:
            for raw, md in reader:
                n += 1
                ts = self._md_ts(md)
                try:
                    pkt = self._fast_dissect(raw, ts, frame=n) or                         self._scapy_dissect(raw, ts, frame=n)
                except Exception:
                    pkt = self._scapy_dissect(raw, ts, frame=n)
                self._update_meta(pkt)
                yield pkt
                if self._max_packets and n >= self._max_packets:
                    self.meta.notes.append(
                        f"analysis stopped early at --max-packets={self._max_packets}")
                    break
        except (Scapy_Exception, OSError, EOFError, ValueError, struct.error) as e:
            # Truncated / corrupt capture: analyze what we got, say so.
            self.meta.truncated = True
            self.meta.notes.append(f"stopped reading after packet {n}: {type(e).__name__}: {e}")
        finally:
            self._check_leftover_bytes(reader)
            self._record_linktype(reader)
            try:
                reader.close()
            except Exception:
                pass
        self.meta.packet_count = n
        if self._expected_packets and n < self._expected_packets:
            self.meta.truncated = True
            self.meta.notes.append(
                f"structure scan expected {self._expected_packets} packets but only "
                f"{n} were parsed")

    def _md_ts(self, md) -> float:
        sec = getattr(md, "sec", None)
        frac = getattr(md, "usec", getattr(md, "nsec", 0)) or 0
        if sec is None:
            ts = getattr(md, "ts", 0)
            return float(ts)
        if "nanosecond" in self._detail:
            return sec + frac / 1e9
        return sec + frac / 1e6

    def _check_leftover_bytes(self, reader) -> None:
        """scapy stops quietly at EOF; unparsed trailing bytes mean truncation."""
        try:
            fh = getattr(reader, "f", None)
            if fh is None:
                return
            pos = fh.tell()
            fh.seek(0, os.SEEK_END)
            end = fh.tell()
            if end > pos:
                self.meta.truncated = True
                self.meta.notes.append(
                    f"capture is truncated: {end - pos} unreadable trailing bytes "
                    f"(analysis covers the first {self.meta.packet_count} packets)")
        except (OSError, ValueError):
            pass

    __iter__ = iter_packets

    # -- internals -----------------------------------------------------------

    def _open(self):
        try:
            if self._fmt == "pcapng":
                from scapy.utils import RawPcapNgReader
                reader = RawPcapNgReader(self.path)
            else:
                from scapy.utils import RawPcapReader
                reader = RawPcapReader(self.path)
            # force first-block parse now so open errors surface here
            self._linktype = getattr(reader, "linktype", 1)
            return reader
        except (Scapy_Exception, OSError, EOFError) as e:
            raise CaptureError(f"failed to open '{self.path}': {e}") from e

    def _record_linktype(self, reader) -> None:
        try:
            lt = getattr(reader, "linktype", None)
            if lt is not None and isinstance(lt, int):
                self.meta.linktype = _LINKTYPES.get(lt, f"linktype {lt}")
            ifaces = getattr(reader, "interfaces", None)
            if isinstance(ifaces, list):
                self.meta.interfaces = [str(i) for i in ifaces]
        except Exception:
            pass

    def _update_meta(self, pkt: Packet) -> None:
        m = self.meta
        if m.packet_count == 0 or (m.first_ts is not None and pkt.ts < m.first_ts):
            m.first_ts = pkt.ts
        if m.last_ts is None or pkt.ts > m.last_ts:
            m.last_ts = pkt.ts
        m.packet_count += 1

    # -- fast manual dissection ----------------------------------------------
    #
    # Full scapy layer dissection costs ~1 ms/packet and dominates runtime
    # on large captures. The link/IP/TCP/UDP/ICMP/ARP headers are fixed-
    # offset structures, so they are parsed by hand; scapy is still used
    # for DNS (a genuinely complex parser) and as a full fallback for
    # anything the fast path does not recognize. Correctness is preserved
    # by the fallback plus the test suite, which exercises both paths.

    def _fast_dissect(self, raw: bytes, ts: float, frame: int = 0) -> Optional[Packet]:
        """Parse fixed-header layers by hand. Returns None → use fallback."""
        lt = self._linktype
        pkt = Packet(ts=ts, frame_len=len(raw), frame=frame)
        off = 0
        if lt == 1:                                    # Ethernet
            if len(raw) < 14:
                return None
            ethertype = int.from_bytes(raw[12:14], "big")
            pkt.mac_src, pkt.mac_dst = _mac(raw[6:12]), _mac(raw[0:6])
            off = 14
            while ethertype in (0x8100, 0x88A8):       # 802.1Q / QinQ tags
                if len(raw) < off + 4:
                    return None
                ethertype = int.from_bytes(raw[off + 2:off + 4], "big")
                off += 4
        elif lt in (101, 12):                          # raw IP
            ethertype = None
        elif lt == 113:                                # Linux cooked (SLL)
            if len(raw) < 16:
                return None
            ethertype = int.from_bytes(raw[14:16], "big")
            off = 16
        elif lt == 0:                                  # NULL/loopback
            if len(raw) < 4:
                return None
            fam = int.from_bytes(raw[0:4], "little")
            ethertype = {2: 0x0800, 24: 0x86dd, 30: 0x86dd}.get(fam)
            off = 4
            if ethertype is None:
                return None
        else:
            return None

        body = raw[off:]
        if ethertype is not None:
            if ethertype == 0x0806:                    # ARP
                return self._fast_arp(body, pkt)
            if ethertype == 0x0800:
                return self._fast_ipv4(body, pkt)
            if ethertype == 0x86dd:
                return self._fast_ipv6(body, pkt)
        else:
            if body[:1] == b"\x45" or (body[:1] and body[0] >> 4 == 4):
                return self._fast_ipv4(body, pkt)
            if body[:1] and body[0] >> 4 == 6:
                return self._fast_ipv6(body, pkt)
        pkt.proto = "other"
        pkt.payload_len = len(body)
        pkt.payload = body[: self.MAX_PAYLOAD_SLICE]
        return pkt

    def _fast_arp(self, body: bytes, pkt: Packet) -> Optional[Packet]:
        if len(body) < 28 or int.from_bytes(body[0:2], "big") != 1 \
                or int.from_bytes(body[2:4], "big") != 0x0800:
            return None
        op = int.from_bytes(body[6:8], "big")
        sha = _mac(body[8:14])
        spa = ".".join(str(b) for b in body[14:18])
        tha = _mac(body[18:24])
        tpa = ".".join(str(b) for b in body[24:28])
        pkt.proto, pkt.src, pkt.dst = "arp", spa, tpa
        if not pkt.mac_src:
            pkt.mac_src, pkt.mac_dst = sha, tha
        if op == 1:
            pkt.payload = f"who-has {tpa}? tell {spa}".encode()
        elif op == 2:
            pkt.payload = f"{spa} is-at {sha}".encode()
        else:
            pkt.payload = f"arp op={op}".encode()
        pkt.payload_len = len(pkt.payload)
        return pkt

    def _fast_ipv4(self, body: bytes, pkt: Packet) -> Optional[Packet]:
        if len(body) < 20 or body[0] >> 4 != 4:
            return None
        ihl = (body[0] & 0x0F) * 4
        if ihl < 20 or len(body) < ihl:
            return None
        total_len = int.from_bytes(body[2:4], "big")
        if total_len >= ihl and len(body) > total_len:
            body = body[:total_len]                    # strip Ethernet padding
        pkt.ip_version = 4
        pkt.src = ".".join(str(b) for b in body[12:16])
        pkt.dst = ".".join(str(b) for b in body[16:20])
        pkt.ip_id = int.from_bytes(body[4:6], "big")
        pkt.ip_ttl = body[8]
        frag_off = int.from_bytes(body[6:8], "big") & 0x1FFF
        if frag_off:                                   # non-first fragment
            pkt.proto = "ip-frag"
            return pkt
        l4 = body[ihl:]
        num = body[9]
        if num == 1:
            return self._fast_icmp(l4, pkt, version=4)
        if num == 6:
            return self._fast_tcp(l4, pkt)
        if num == 17:
            return self._fast_udp(l4, pkt)
        pkt.proto = f"ip-{num}"
        pkt.payload_len = len(l4)
        pkt.payload = l4[: self.MAX_PAYLOAD_SLICE]
        return pkt

    def _fast_ipv6(self, body: bytes, pkt: Packet) -> Optional[Packet]:
        if len(body) < 40 or body[0] >> 4 != 6:
            return None
        import socket as _socket
        plen = int.from_bytes(body[4:6], "big")
        nxt, off = body[6], 40
        end = min(len(body), 40 + plen) if plen else len(body)
        while nxt in (0, 43, 44, 60) and off + 2 <= end:   # ext headers
            if nxt == 44:                              # fragment: fixed 8B
                off += 8
            else:
                off += 8 + 8 * body[off + 1]
            if off + 2 > end:
                return None
            nxt = body[off]
        pkt.ip_version = 6
        try:
            pkt.src = _socket.inet_ntop(_socket.AF_INET6, body[8:24])
            pkt.dst = _socket.inet_ntop(_socket.AF_INET6, body[24:40])
        except (ValueError, OSError):
            return None
        l4 = body[off:end]
        if nxt == 58:
            return self._fast_icmp(l4, pkt, version=6)
        if nxt == 6:
            return self._fast_tcp(l4, pkt)
        if nxt == 17:
            return self._fast_udp(l4, pkt)
        pkt.proto = f"ipv6-{nxt}"
        pkt.payload_len = len(l4)
        pkt.payload = l4[: self.MAX_PAYLOAD_SLICE]
        return pkt

    def _fast_icmp(self, l4: bytes, pkt: Packet, version: int) -> Packet:
        pkt.proto = "icmp" if version == 4 else "icmp6"
        if not l4:
            pkt.icmp_type = -1
            return pkt
        pkt.icmp_type = l4[0]
        skip = 8 if (l4[0] in ((8, 0) if version == 4 else (128, 129))) else 4
        raw = l4[skip:] if len(l4) > skip else b""
        pkt.payload_len = len(raw)
        pkt.payload = raw[: self.MAX_PAYLOAD_SLICE]
        return pkt

    def _fast_tcp(self, l4: bytes, pkt: Packet) -> Optional[Packet]:
        if len(l4) < 20:
            return None
        pkt.proto = "tcp"
        pkt.sport, pkt.dport = struct.unpack("!HH", l4[0:4])
        pkt.tcp_seq = struct.unpack("!I", l4[4:8])[0]
        dataoff = (l4[12] >> 4) * 4
        if dataoff < 20 or dataoff > len(l4):
            return None
        f = l4[13]
        names = []
        if f & 0x01: names.append("F")
        if f & 0x02: names.append("S")
        if f & 0x04: names.append("R")
        if f & 0x08: names.append("P")
        if f & 0x10: names.append("A")
        if f & 0x20: names.append("U")
        pkt.tcp_flags = "".join(names)
        raw = l4[dataoff:]
        pkt.payload_len = len(raw)
        pkt.payload = raw[: self.MAX_PAYLOAD_SLICE]
        if 53 in (pkt.sport, pkt.dport) and raw:
            pkt.dns = self._dns_from_bytes(raw, pkt, tcp=True)
        return pkt

    def _fast_udp(self, l4: bytes, pkt: Packet) -> Optional[Packet]:
        if len(l4) < 8:
            return None
        pkt.proto = "udp"
        pkt.sport, pkt.dport = struct.unpack("!HH", l4[0:4])
        ulen = struct.unpack("!H", l4[4:6])[0]
        raw = l4[8:ulen] if 8 <= ulen <= len(l4) else l4[8:]
        pkt.payload_len = len(raw)
        pkt.payload = raw[: self.MAX_PAYLOAD_SLICE]
        if 53 in (pkt.sport, pkt.dport) and raw:
            pkt.dns = self._dns_from_bytes(raw, pkt, tcp=False)
        return pkt

    # -- scapy fallback dissection -------------------------------------------

    def _scapy_dissect(self, raw: bytes, ts: float, frame: int = 0) -> Packet:
        """Full scapy dissection for packets the fast path declined."""
        from scapy.config import conf as scapy_conf
        cls = None
        try:
            cls = scapy_conf.l2types.get(self._linktype)
        except Exception:
            cls = None
        try:
            sp = cls(raw) if cls is not None else ScapyPacket(raw)
        except Exception:
            sp = ScapyPacket(raw)
        pkt = Packet(ts=ts, frame_len=len(raw), frame=frame)
        if sp.haslayer("Ether"):
            eth = sp["Ether"]
            pkt.mac_src, pkt.mac_dst = str(eth.src), str(eth.dst)

        if sp.haslayer("ARP"):
            arp = sp["ARP"]
            pkt.proto, pkt.src, pkt.dst = "arp", str(arp.psrc), str(arp.pdst)
            pkt.payload = _arp_summary(arp).encode()
            return pkt

        if sp.haslayer("IP"):
            pkt.ip_version = 4
            pkt.src, pkt.dst = sp["IP"].src, sp["IP"].dst
            pkt.ip_id, pkt.ip_ttl = int(sp["IP"].id), int(sp["IP"].ttl)
        elif sp.haslayer("IPv6"):
            pkt.ip_version = 6
            pkt.src, pkt.dst = str(sp["IPv6"].src), str(sp["IPv6"].dst)
        else:
            pkt.proto = "other"
            return pkt

        if sp.haslayer("ICMP"):
            icmp = sp["ICMP"]
            pkt.proto = "icmp"
            pkt.icmp_type = int(icmp.type)
            raw_l4 = bytes(icmp.payload)
            pkt.payload, pkt.payload_len = raw_l4, len(raw_l4)
            return pkt

        if sp.haslayer("IPv6") and "ICMPv6" in sp.lastlayer().__class__.__name__:
            pkt.proto = "icmp6"
            last = sp.lastlayer()
            pkt.icmp_type = int(getattr(last, "type", -1))
            raw_l4 = bytes(last.payload)
            pkt.payload, pkt.payload_len = raw_l4[: self.MAX_PAYLOAD_SLICE], len(raw_l4)
            return pkt

        if sp.haslayer("TCP"):
            tcp = sp["TCP"]
            pkt.proto = "tcp"
            pkt.sport, pkt.dport = int(tcp.sport), int(tcp.dport)
            pkt.tcp_flags = _flags_str(tcp)
            pkt.tcp_seq = int(tcp.seq)
            raw_l4 = bytes(tcp.payload)
            pkt.payload_len = len(raw_l4)
            pkt.payload = raw_l4[: self.MAX_PAYLOAD_SLICE]
            if 53 in (pkt.sport, pkt.dport) and raw_l4:
                pkt.dns = self._dns_from_bytes(raw_l4, pkt, tcp=True)
            return pkt

        if sp.haslayer("UDP"):
            udp = sp["UDP"]
            pkt.proto = "udp"
            pkt.sport, pkt.dport = int(udp.sport), int(udp.dport)
            raw_l4 = bytes(udp.payload)
            pkt.payload_len = len(raw_l4)
            pkt.payload = raw_l4[: self.MAX_PAYLOAD_SLICE]
            if 53 in (pkt.sport, pkt.dport) and sp.haslayer("DNS"):
                pkt.dns = self._dns_from_scapy(sp["DNS"], pkt)
            return pkt

        pkt.proto = "other"
        raw_l4 = bytes(sp.payload)
        pkt.payload_len = len(raw_l4)
        pkt.payload = raw_l4[: self.MAX_PAYLOAD_SLICE]
        return pkt

    # -- DNS -----------------------------------------------------------------

    def _dns_from_bytes(self, raw: bytes, pkt: Packet, tcp: bool
                        ) -> Optional[DNSRecord]:
        """Parse DNS from a raw L4 payload (fast-path entry point)."""
        try:
            if tcp:
                return self._dns_from_tcp(raw, pkt)
            from scapy.layers.dns import DNS as ScapyDNS
            dns = ScapyDNS(raw)
            if dns is None or dns.qd is None:
                return None
            return self._dns_from_scapy(dns, pkt)
        except Exception:
            return None

    def _dns_from_scapy(self, dns, pkt: Packet) -> Optional[DNSRecord]:
        try:
            qd = dns.qd
            qname = _safe_ascii(bytes(qd.qname)) if qd is not None else ""
            qtype = QTYPES.get(int(qd.qtype) if qd is not None else 0, "TYPE?")
            rec = DNSRecord(
                ts=pkt.ts, client=pkt.src, server=pkt.dst, name=qname.rstrip("."),
                qtype=qtype,
                is_response=bool(dns.qr),
                response_code=RCODES.get(int(dns.rcode), f"RCODE{int(dns.rcode)}"),
                frame=pkt.frame,
            )
            if dns.qr:
                # scapy ≥2.7: an/ns/ar are PacketListFields (lists of DNSRR);
                # older releases chain them as layers — support both.
                answers = dns.an
                if isinstance(answers, list):
                    rr_iter = iter(answers)
                    rr = next(rr_iter, None)
                else:
                    rr = answers
                for _ in range(int(dns.ancount)):
                    if rr is None:
                        break
                    val = _rdata_str(rr)
                    if val:
                        rec.answers.append(val)
                        rec.answer_type = rec.answer_type or QTYPES.get(int(rr.type), "TYPE?")
                        rec.ttl = int(rr.ttl)
                    rr = next(rr_iter, None) if isinstance(answers, list) else rr.payload
            return rec
        except Exception:
            return None

    def _dns_from_tcp(self, raw: bytes, pkt: Packet) -> Optional[DNSRecord]:
        """DNS over TCP carries a 2-byte length prefix per message."""
        try:
            if len(raw) < 4:
                return None
            from scapy.layers.dns import DNS as ScapyDNS
            msg_len = int.from_bytes(raw[0:2], "big")
            if msg_len == 0 or msg_len > len(raw) - 2:
                msg_len = len(raw) - 2      # be lenient with hand-made captures
            dns = ScapyDNS(raw[2:2 + msg_len])
            if not dns.haslayer("DNS"):
                return None
            rec = self._dns_from_scapy(dns, pkt)
            if rec is not None:
                # direction: server→client when source port is 53
                if pkt.sport == 53:
                    rec.client, rec.server = pkt.dst, pkt.src
                else:
                    rec.client, rec.server = pkt.src, pkt.dst
            return rec
        except Exception:
            return None


def _flags_str(tcp) -> str:
    names = []
    for bit, name in ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"),
                      (0x10, "A"), (0x20, "U"), (0x40, "E"), (0x80, "C")):
        if int(tcp.flags) & bit:
            names.append(name)
    return "".join(names)


def _mac(b: bytes) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _arp_summary(arp) -> str:
    op = int(arp.op)
    if op == 1:
        return f"who-has {arp.pdst}? tell {arp.psrc}"
    if op == 2:
        return f"{arp.psrc} is-at {arp.hwsrc}"
    return f"arp op={op}"
