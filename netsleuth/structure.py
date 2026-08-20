"""Raw pcap/pcapng structure scanner.

Walks the capture's block/record chain directly (no packet decoding) to
establish file-level facts that scapy does not surface reliably:

* exact packet count and whether the file ends mid-record (truncation)
* interface names and link types (pcapng)
* timestamp bounds — without paying for full dissection

This runs in microseconds even for multi-GB captures because it only
follows length fields, never parses packet contents.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field

LINKTYPES = {
    0: "NULL/loopback", 1: "Ethernet", 6: "Token ring", 8: "SLIP", 9: "PPP",
    12: "Raw IP (BSD)", 101: "Raw IP", 105: "IEEE 802.11", 107: "FDDI",
    113: "Linux cooked (SLL)", 114: "Linux cooked v2 (SLL2)", 143: "DOCSIS",
}


@dataclass
class Structure:
    format: str = ""                 # pcap | pcapng
    packet_count: int = 0
    truncated: bool = False
    linktypes: list[str] = field(default_factory=list)
    interfaces: list[str] = field(default_factory=list)
    first_ts: float | None = None
    last_ts: float | None = None


def scan(path: str) -> Structure:
    """Walk a capture file's structure. Never raises for bad content —
    marks truncated=True instead (an empty/garbage file yields count 0)."""
    with open(path, "rb") as fh:
        head = fh.read(4)
        fh.seek(0)
        if head in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1",
                    b"\xa1\xb2\x3c\x4d"):
            return _scan_pcap(fh)
        if head == b"\x0a\x0d\x0d\x0a":
            return _scan_pcapng(fh)
        s = Structure(truncated=True)
        s.packet_count = 0
        return s


def _scan_pcap(fh) -> Structure:
    s = Structure(format="pcap")
    gh = fh.read(24)
    if len(gh) < 24:
        s.truncated = True
        return s
    magic = gh[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
    else:
        endian = ">"
    linktype = struct.unpack(endian + "I", gh[20:24])[0]
    s.linktypes = [LINKTYPES.get(linktype, f"linktype {linktype}")]

    cur_pos = fh.tell()
    fh.seek(0, 2)                      # SEEK_END
    file_end = fh.tell()
    fh.seek(cur_pos, 0)                # restore

    while True:
        ph = fh.read(16)
        if len(ph) == 0:
            return s                              # clean EOF
        if len(ph) < 16:
            s.truncated = True
            return s
        _ts_sec, _ts_frac, incl_len, _orig_len = struct.unpack(endian + "IIII", ph)
        ts = _ts_sec + (_ts_frac / 1e9 if magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
                        else _ts_frac / 1e6)
        if s.first_ts is None or ts < s.first_ts:
            s.first_ts = ts
        if s.last_ts is None or ts > s.last_ts:
            s.last_ts = ts
        if fh.tell() + incl_len > file_end:
            s.truncated = True
            s.packet_count += 1                   # partial packet still counted as attempted
            return s
        fh.seek(incl_len, 1)                      # SEEK_CUR (0-byte allocation)
        s.packet_count += 1


def _scan_pcapng(fh) -> Structure:
    s = Structure(format="pcapng")
    endian = "<"
    tsresols: list[float] = []                     # per-interface timestamp resolution

    while True:
        bh = fh.read(8)
        if len(bh) == 0:
            return s                               # clean EOF
        if len(bh) < 8:
            s.truncated = True
            return s
        btype = int.from_bytes(bh[:4], "little" if endian == "<" else "big")
        bom = b""
        if btype == 0x0A0D0D0A:                    # Section Header Block: BOM at offset 8
            bom = fh.read(4)
            if len(bom) < 4:
                s.truncated = True
                return s
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                s.truncated = True
                return s
        total = int.from_bytes(bh[4:8], "little" if endian == "<" else "big")
        if total < 12:
            s.truncated = True
            return s
        # body sits between the block header (+BOM for SHBs) and the trailing length
        body_len = total - 12 - (4 if bom else 0)
        body = fh.read(body_len)
        trailing = fh.read(4)
        if len(body) < body_len or len(trailing) < 4:
            s.truncated = True
            if btype == 6:
                s.packet_count += 1
            return s
        _apply_block(btype, body, endian, s, tsresols)


def _apply_block(btype: int, body: bytes, endian: str, s: Structure,
                 tsresols: list[float]) -> None:
    if btype == 1:                                 # Interface Description Block
        lt = int.from_bytes(body[0:2], "little" if endian == "<" else "big")
        s.linktypes.append(LINKTYPES.get(lt, f"linktype {lt}"))
        tsresols.append(_idb_tsresol(body, endian))
        name = _idb_name(body, endian)
        s.interfaces.append(name or f"interface {len(s.interfaces) + 1}")
    elif btype == 6:                               # Enhanced Packet Block
        s.packet_count += 1
        if len(body) >= 20:
            ifid = int.from_bytes(body[0:4], "little" if endian == "<" else "big")
            ts_high = int.from_bytes(body[4:8], "little" if endian == "<" else "big")
            ts_low = int.from_bytes(body[8:12], "little" if endian == "<" else "big")
            raw = (ts_high << 32) | ts_low
            res = tsresols[ifid] if ifid < len(tsresols) else 1e-6
            ts = raw * res
            if ts and ts < (1 << 62):
                if s.first_ts is None or ts < s.first_ts:
                    s.first_ts = ts
                if s.last_ts is None or ts > s.last_ts:
                    s.last_ts = ts


def _idb_name(body: bytes, endian: str) -> str:
    """Extract opt_name (code 2) from an IDB body."""
    # body = linktype(2) + reserved(2) + snaplen(4) + options...
    i = 8
    while i + 4 <= len(body):
        code, length = struct.unpack(endian + "HH", body[i:i + 4])
        if code == 0:
            return ""
        val = body[i + 4: i + 4 + length]
        if code == 2:
            return val.split(b"\x00")[0].decode("utf-8", "replace")
        i += 4 + length + (-length % 4)
    return ""


def _idb_tsresol(body: bytes, endian: str) -> float:
    """Timestamp resolution from IDB option 9 (default microseconds)."""
    i = 8
    while i + 5 <= len(body):
        code, length = struct.unpack(endian + "HH", body[i:i + 4])
        if code == 0:
            return 1e-6
        if code == 9 and length >= 1:
            b = body[i + 4]
            if b & 0x80:                           # negative power of ten
                return 10.0 ** -(b & 0x7F)
            return 2.0 ** -(b & 0x7F)
        i += 4 + length + (-length % 4)
    return 1e-6
