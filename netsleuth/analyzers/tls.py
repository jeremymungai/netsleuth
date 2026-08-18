"""TLS analyzer — metadata extraction without ever pretending to decrypt.

Parses TLS record/handshake structure from reassembled TCP streams:

* Client Hello: SNI, offered versions, cipher list, extensions, ALPN,
  and a JA3 fingerprint (Salesforce's open format, BSD-3 licensed —
  reimplemented here from the public spec).
* Server Hello: negotiated version, cipher, ALPN.
* Certificate messages: subject/issuer CN+O, validity window,
  self-signed detection via a minimal DER walk.

Anomalies in the *metadata* (e.g., no SNI, expired certs) are findings;
the encrypted payload itself is never claimed to be readable.
"""

from __future__ import annotations

import hashlib
import struct
from netsleuth.models import StreamData, TLSSession

# GREASE values (RFC 8701) must be excluded from fingerprints
GREASE = {0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a,
          0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada,
          0xeaea, 0xfafa}

VERSIONS = {0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1",
            0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


class HandshakeBuffer:
    """Reassembles TLS handshake messages that span record boundaries."""

    def __init__(self) -> None:
        self.buf = b""

    def records(self, data: bytes):
        """Yield (content_type, version, fragment) for each TLS record."""
        pos = 0
        while pos + 5 <= len(data):
            ctype = data[pos]
            ver = struct.unpack(">H", data[pos + 1:pos + 3])[0]
            ln = struct.unpack(">H", data[pos + 3:pos + 5])[0]
            if pos + 5 + ln > len(data):
                return                                  # truncated record
            yield ctype, ver, data[pos + 5:pos + 5 + ln]
            pos += 5 + ln

    def handshakes(self, data: bytes):
        """Yield (hs_type, body) for complete handshake messages."""
        self.buf += data
        pos = 0
        while pos + 4 <= len(self.buf):
            hs_type = self.buf[pos]
            ln = int.from_bytes(self.buf[pos + 1:pos + 4], "big")
            if pos + 4 + ln > len(self.buf):
                break
            yield hs_type, self.buf[pos + 4:pos + 4 + ln]
            pos += 4 + ln
        self.buf = self.buf[pos:]


class TLSParser:
    """State machine per stream: client hello → server hello → certs."""

    def __init__(self) -> None:
        self.session = TLSSession()

    # -- individual message parsers -----------------------------------------

    def parse_client_hello(self, body: bytes) -> None:
        s = self.session
        try:
            if len(body) < 43:
                return
            ver = struct.unpack(">H", body[0:2])[0]
            s.tls_version = VERSIONS.get(ver, hex(ver))
            pos = 2 + 32                             # version + random
            sid_len = body[pos]; pos += 1 + sid_len
            cs_len = struct.unpack(">H", body[pos:pos + 2])[0]; pos += 2
            ciphers = [struct.unpack(">H", body[i:i + 2])[0]
                       for i in range(pos, pos + cs_len, 2)]
            pos += cs_len
            comp_len = body[pos]; pos += 1 + comp_len
            exts, curves, formats = [], [], []
            sni = ""
            alpn = []
            versions = []
            if pos + 2 <= len(body):
                ext_total = struct.unpack(">H", body[pos:pos + 2])[0]
                pos += 2
                end = min(pos + ext_total, len(body))
                while pos + 4 <= end:
                    etype, elen = struct.unpack(">HH", body[pos:pos + 4])
                    edata = body[pos + 4:pos + 4 + elen]
                    exts.append(etype)
                    if etype == 0 and len(edata) >= 5:          # server_name
                        lst_len = struct.unpack(">H", edata[0:2])[0]
                        if lst_len and edata[2] == 0:
                            nlen = struct.unpack(">H", edata[3:5])[0]
                            raw_name = edata[5:5 + nlen]
                            try:
                                sni = raw_name.decode("idna")
                            except UnicodeError:
                                sni = raw_name.decode("utf-8", "replace")
                    elif etype == 10:                          # supported_groups
                        for i in range(0, len(edata) - 1, 2):
                            curves.append(struct.unpack(">H", edata[i:i + 2])[0])
                    elif etype == 11 and edata:               # ec_point_formats
                        formats = list(edata[1:1 + edata[0]])
                    elif etype == 16:                          # ALPN
                        q = 0
                        while q + 2 <= len(edata):
                            plen = edata[q]
                            alpn.append(edata[q + 1:q + 1 + plen].decode("latin-1"))
                            q += 1 + plen
                    elif etype == 43 and len(edata) >= 1:     # supported_versions
                        cnt = edata[0]
                        for i in range(1, min(1 + 2 * cnt, len(edata)) - 1, 2):
                            versions.append(struct.unpack(">H", edata[i:i + 2])[0])
                    pos += 4 + elen
            s.sni = sni
            s.alpn = alpn
            if versions:
                s.tls_version = ", ".join(
                    VERSIONS.get(v, hex(v)) for v in versions if v not in GREASE) or s.tls_version
            self._ja3(ver, ciphers, exts, curves, formats)
        except (struct.error, IndexError, UnicodeError) as e:
            s.errors.append(f"client hello parse error: {e}")

    def _ja3(self, version: int, ciphers: list[int], exts: list[int],
             curves: list[int], formats: list[int]) -> None:
        c = "-".join(str(x) for x in ciphers if x not in GREASE)
        e = "-".join(str(x) for x in exts if x not in GREASE)
        cu = "-".join(str(x) for x in curves if x not in GREASE)
        f = "-".join(str(x) for x in formats if x not in GREASE)
        clear = f"{version},{c},{e},{cu},{f}"
        self.session.ja3_clear = clear
        self.session.ja3 = hashlib.md5(clear.encode()).hexdigest()

    def parse_server_hello(self, body: bytes) -> None:
        s = self.session
        try:
            if len(body) < 36:
                return
            ver = struct.unpack(">H", body[0:2])[0]
            s.tls_version = VERSIONS.get(ver, hex(ver))
            pos = 2 + 32
            sid_len = body[pos]; pos += 1 + sid_len
            cipher = struct.unpack(">H", body[pos:pos + 2])[0]
            pos += 2 + 1
            # selected version may live in supported_versions ext (TLS 1.3)
            if pos + 2 <= len(body):
                ext_total = struct.unpack(">H", body[pos:pos + 2])[0]
                pos += 2
                end = min(pos + ext_total, len(body))
                while pos + 4 <= end:
                    etype, elen = struct.unpack(">HH", body[pos:pos + 4])
                    edata = body[pos + 4:pos + 4 + elen]
                    if etype == 43 and len(edata) >= 2:
                        v = struct.unpack(">H", edata[0:2])[0]
                        s.tls_version = VERSIONS.get(v, hex(v))
                    elif etype == 16 and edata:
                        plen = edata[0]
                        s.alpn = [edata[1:1 + plen].decode("latin-1")]
                    pos += 4 + elen
        except (struct.error, IndexError) as e:
            s.errors.append(f"server hello parse error: {e}")

    def parse_certificate(self, body: bytes) -> None:
        s = self.session
        try:
            if len(body) < 3 + 3:
                return
            chain_len = int.from_bytes(body[0:3], "big")
            pos = 3
            end = min(3 + chain_len, len(body))
            first = True
            while pos + 3 <= end:
                cert_len = int.from_bytes(body[pos:pos + 3], "big")
                der = body[pos + 3:pos + 3 + cert_len]
                if len(der) < cert_len:
                    break
                if first:
                    self._read_cert(der)
                    first = False
                pos += 3 + cert_len
        except (struct.error, IndexError) as e:
            s.errors.append(f"certificate parse error: {e}")

    def _read_cert(self, der: bytes) -> None:
        info = parse_x509_basics(der)
        if info is None:
            self.session.errors.append("unreadable certificate structure")
            return
        s = self.session
        s.cert_subject = info["subject"]
        s.cert_issuer = info["issuer"]
        s.cert_valid_from = info["not_before"]
        s.cert_valid_to = info["not_after"]
        s.cert_self_signed = info["self_signed"]


# --------------------------------------------------------------------- DER

def _der_walk(data: bytes, pos: int = 0):
    """Yield (tag, content_bytes, next_pos) for each TLV at one level."""
    while pos + 2 <= len(data):
        tag = data[pos]
        if tag & 0x1f == 0x1f:
            return                                   # high-tag-number: unsupported
        lbyte = data[pos + 1]
        if lbyte < 0x80:
            length, hdr = lbyte, 2
        else:
            n = lbyte & 0x7F
            if n == 0 or n > 4 or pos + 2 + n > len(data):
                return
            length = int.from_bytes(data[pos + 2:pos + 2 + n], "big")
            hdr = 2 + n
        if pos + hdr + length > len(data):
            return
        yield tag, data[pos + hdr:pos + hdr + length], pos + hdr + length
        pos = pos + hdr + length


_NAME_OIDS = {b"\x55\x04\x03": "CN", b"\x55\x04\x0a": "O", b"\x55\x04\x06": "C",
              b"\x55\x04\x07": "L", b"\x55\x04\x08": "ST", b"\x2a\x86\x48\x86\xf7\x0d\x01\x09\x01": "email"}


def _parse_name(content: bytes) -> dict[str, str]:
    """X.501 Name: SEQUENCE OF SET OF SEQUENCE{oid, value}."""
    out: dict[str, str] = {}
    for _t, rdn, _ in _der_walk(content):
        for _t2, atv, _2 in _der_walk(rdn):
            parts = list(_der_walk(atv))
            if len(parts) < 2:
                continue
            (oid_t, oid, _), (val_t, val, _) = parts[0], parts[1]
            key = _NAME_OIDS.get(oid)
            if not key:
                continue
            try:
                if val_t == 0x0c:                    # UTF8String
                    text = val.decode("utf-8")
                elif val_t == 0x13:                 # PrintableString
                    text = val.decode("ascii")
                elif val_t == 0x16:                 # IA5String
                    text = val.decode("ascii")
                elif val_t == 0x14:                 # BMPString
                    text = val.decode("utf-16-be")
                elif val_t == 0x1e:                 # BMPString (old tag)
                    text = val.decode("utf-16-be", "replace")
                else:
                    text = val.decode("latin-1", "replace")
            except UnicodeDecodeError:
                text = val.decode("latin-1", "replace")
            out[key] = text
    return out


def _fmt_name(d: dict[str, str]) -> str:
    order = ["C", "ST", "L", "O", "CN"]
    return ", ".join(f"{k}={d[k]}" for k in order if k in d)


def parse_x509_basics(der: bytes) -> dict | None:
    """Minimal X.509 walk: subject, issuer, validity. Returns None when the
    structure doesn't parse (malformed / non-DER certs are reported, not fatal)."""
    try:
        top = list(_der_walk(der))
        if not top or top[0][0] != 0x30:
            return None
        cert = top[0][1]
        fields = list(_der_walk(cert))
        if len(fields) < 3:
            return None
        # fields: [0] version (optional, context tag) → skip primitives
        idx = 0
        if fields[0][0] == 0xA0:
            idx = 1
        # serial, sigalg, issuer, validity, subject, spki, ...
        issuer_raw = fields[idx + 2][1]
        validity_raw = fields[idx + 3][1]
        subject_raw = fields[idx + 4][1]

        issuer = _parse_name(issuer_raw)
        subject = _parse_name(subject_raw)

        # Validity = SEQUENCE { notBefore, notAfter } in presentation order
        times = [v.decode("ascii", "replace") for _t, v, _ in _der_walk(validity_raw)]
        not_before = _fmt_time(times[0], 2 if len(times[0]) == 13 else 4) if len(times) >= 1 else ""
        not_after = _fmt_time(times[1], 2 if len(times[1]) == 13 else 4) if len(times) >= 2 else ""

        return {
            "subject": _fmt_name(subject), "issuer": _fmt_name(issuer),
            "not_before": not_before, "not_after": not_after,
            "self_signed": _fmt_name(subject) == _fmt_name(issuer) and bool(subject),
        }
    except (IndexError, ValueError):
        return None


def _fmt_time(raw: str, year_digits: int) -> str:
    digits = "".join(c for c in raw if c.isdigit())
    try:
        if year_digits == 2:
            yy = int(digits[0:2])
            year = 2000 + yy if yy < 50 else 1900 + yy
            rest = digits[2:]
        else:
            year = int(digits[0:4])
            rest = digits[4:]
        return f"{year:04d}-{rest[0:2]}-{rest[2:4]} {rest[4:6]}:{rest[6:8]}:{rest[8:10]}Z" \
            if len(rest) >= 10 else raw
    except (ValueError, IndexError):
        return raw


# --------------------------------------------------------------------- glue

class TLSAnalyzer:
    name = "tls"

    def __init__(self) -> None:
        self.sessions: list[TLSSession] = []

    def analyze(self, streams: list[StreamData]) -> None:
        for st in streams:
            looks_tls = (st.info.server_port in (443, 8443)
                         or (st.c2s[:1] == b"\x16" and len(st.c2s) >= 9
                             and st.c2s[5] == 0x01))
            if not looks_tls or not st.c2s:
                continue
            parser = TLSParser()
            parser.session.ts = st.info.start_ts
            parser.session.src = st.info.client
            parser.session.dst = st.info.server
            parser.session.dst_port = st.info.server_port

            hb_c2s = HandshakeBuffer()
            hb_s2c = HandshakeBuffer()
            for ctype, _ver, frag in hb_c2s.records(st.c2s):
                if ctype == 22:
                    for hs_type, body in hb_c2s.handshakes(frag):
                        if hs_type == 1:
                            parser.parse_client_hello(body)
            for ctype, _ver, frag in hb_s2c.records(st.s2c):
                if ctype == 22:
                    for hs_type, body in hb_s2c.handshakes(frag):
                        if hs_type == 2:
                            parser.parse_server_hello(body)
                        elif hs_type == 11:
                            parser.parse_certificate(body)
            if parser.session.sni or parser.session.ja3 or parser.session.errors:
                self.sessions.append(parser.session)
