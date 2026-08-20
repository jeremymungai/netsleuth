"""File carving: recover transferred files from captures.

Sources: HTTP response bodies, HTTP POST uploads (multipart), and SMTP
MIME attachments. Extracted files are typed by *magic bytes* (never by
filename), hashed (SHA-256/SHA-1/MD5), and written into a structured
output directory.

Security posture (docs/SECURITY.md has the full threat model):
  * filenames are reduced to a safe basename, length-capped, deduplicated;
  * the final path is verified to stay inside the output directory;
  * total carve budget is capped (default 1 GiB) against capture bombs;
  * files are written with no execute bit and never run.
"""

from __future__ import annotations

import hashlib
import os
import re
import unicodedata
from email import policy
from email.parser import BytesParser
from pathlib import Path

from netsleuth.models import Artifact, HTTPTransaction

MAX_TOTAL_CARVE_BYTES = 1024 * 1024 * 1024        # 1 GiB across a capture
_UNSAFE_CHARS = re.compile(r"[^A-Za-z0-9._\- ]")
_TRAVERSAL = re.compile(r"(?:^|/|\\)\.\.(?:/|\\|$)")


# --------------------------------------------------------------------- magic

_MAGIC: list[tuple[bytes, int, str]] = [
    (b"MZ", 0, "Windows PE executable"),
    (b"\x7fELF", 0, "ELF executable"),
    (b"\xca\xfe\xba\xbe", 0, "Mach-O / Java class"),
    (b"PK\x03\x04", 0, "ZIP archive (or Office/JAR)"),
    (b"Rar!\x1a\x07", 0, "RAR archive"),
    (b"7z\xbc\xaf\x27\x1c", 0, "7-Zip archive"),
    (b"\x1f\x8b", 0, "gzip archive"),
    (b"BZh", 0, "bzip2 archive"),
    (b"\xfd7zXZ\x00", 0, "XZ archive"),
    (b"%PDF", 0, "PDF document"),
    (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0, "MS Office (OLE2) document"),
    (b"SQLite format 3\x00", 0, "SQLite database"),
    (b"\x89PNG\r\n\x1a\n", 0, "PNG image"),
    (b"GIF87a", 0, "GIF image"),
    (b"GIF89a", 0, "GIF image"),
    (b"\xff\xd8\xff", 0, "JPEG image"),
    (b"BM", 0, "BMP image"),
    (b"RIFF", 0, "RIFF container (WAV/AVI/WebP)"),
    (b"ID3", 0, "MP3 audio"),
    (b"ftyp", 4, "MP4/MOV video"),
    (b"\xff\xfb", 0, "MPEG audio"),
    (b"\xd4\xc3\xb2\xa1", 0, "pcap capture"),
    (b"\x0a\x0d\x0d\x0a", 0, "pcapng capture"),
    (b"-----BEGIN CERTIFICATE-----", 0, "PEM certificate"),
    (b"-----BEGIN ", 0, "PEM armored data"),
    (b"<?xml", 0, "XML document"),
    (b"<!DOCTYPE html", 0, "HTML document"),
    (b"<!doctype html", 0, "HTML document"),
    (b"<html", 0, "HTML document"),
    (b"#!", 0, "script with shebang"),
    (b"\x00\x00\x00\x1c\x66\x74\x79\x70", 4, "MPEG-4 video"),
]


def detect_type(data: bytes) -> str:
    for magic, offset, name in _MAGIC:
        if len(data) >= offset + len(magic) and data[offset:offset + len(magic)] == magic:
            return name
    printable = sum(1 for b in data[:512] if 32 <= b < 127 or b in (9, 10, 13))
    if data and printable / min(len(data), 512) > 0.9:
        return "text"
    return "binary data"


# ---------------------------------------------------------------- filenames

def sanitize_filename(name: str, fallback: str = "unnamed") -> str:
    """Reduce an attacker-controlled filename to something safe to write."""
    name = unicodedata.normalize("NFKD", name)
    name = name.replace("\\", "/").rsplit("/", 1)[-1]           # basename only
    name = _UNSAFE_CHARS.sub("_", name).strip(". ")
    name = re.sub(r"\s+", "_", name)
    return name[:100] or fallback


class _Writer:
    """Sequential artifact writer enforcing safe paths and a size budget."""

    def __init__(self, out_dir: str, budget: int = MAX_TOTAL_CARVE_BYTES):
        self.dir = Path(out_dir).resolve()
        self.dir.mkdir(parents=True, exist_ok=True)
        self.budget = budget
        self.written = 0
        self.skipped = 0
        self._names: set[str] = set()
        self._counter = 0

    def write(self, data: bytes, preferred_name: str) -> tuple[str, int] | None:
        """Write bytes; returns (stored_name, bytes_written) or None if over budget."""
        if self.written + len(data) > self.budget:
            self.skipped += 1
            return None
        self._counter += 1
        base = sanitize_filename(preferred_name)
        name = f"{self._counter:04d}_{base}"
        i = 1
        while name in self._names:
            i += 1
            name = f"{self._counter:04d}_{i}_{base}"
        self._names.add(name)
        target = (self.dir / name).resolve()
        if not target.is_relative_to(self.dir):
            raise RuntimeError("path traversal blocked")        # defense in depth
        target.write_bytes(data)
        self.written += len(data)
        return name, len(data)


def _hashes(data: bytes) -> tuple[str, str, str]:
    return (hashlib.sha256(data).hexdigest(),
            hashlib.sha1(data).hexdigest(),
            hashlib.md5(data).hexdigest())


# ------------------------------------------------------------------- carvers

def carve_all(result, out_dir: str) -> list[Artifact]:
    """Carve from every source the result exposes."""
    writer = _Writer(out_dir)
    artifacts: list[Artifact] = []
    artifacts += _carve_http(result.http, writer)
    artifacts += _carve_smtp(result, writer)
    return artifacts


def _carve_http(transactions: list[HTTPTransaction], writer: _Writer) -> list[Artifact]:
    out: list[Artifact] = []
    for t in transactions:
        if t.resp_body:
            name = _http_filename(t)
            art = _emit(writer, t.resp_body, name, protocol="http",
                        src=t.host or "?", dst=t.client, ts=t.ts,
                        claimed=t.content_type_resp, stream=t.stream,
                        url=f"{t.host}{t.url}")
            if art:
                out.append(art)
        if t.req_body and (t.method in ("POST", "PUT")
                           and (b"filename=" in t.req_body
                                or "multipart/form-data" in t.content_type_req)):
            name = _multipart_filename(t.req_body) or f"upload_{t.stream}"
            art = _emit(writer, t.req_body, name, protocol="http-upload",
                        src=t.client, dst=t.host or "?", ts=t.ts,
                        claimed=t.content_type_req, stream=t.stream,
                        url=f"{t.host}{t.url}")
            if art:
                out.append(art)
    return out


def _http_filename(t: HTTPTransaction) -> str:
    base = t.path.rsplit("/", 1)[-1] or ""
    base = base.split("?")[0]
    if "." not in base:
        # invent an extension from content-type when the URL has none
        ext = {"text/html": ".html", "application/pdf": ".pdf",
               "image/png": ".png", "image/jpeg": ".jpg",
               "application/zip": ".zip", "application/json": ".json",
               "application/x-msdownload": ".exe",
               "application/octet-stream": ".bin"}.get(
            t.content_type_resp.split(";")[0].strip().lower(), "")
        base = (base or "body") + ext
    return base or "http_body"


def _multipart_filename(body: bytes) -> str:
    m = re.search(rb'filename="([^"]{1,200})"', body[:8192])
    return m.group(1).decode("latin-1", "replace") if m else ""


def _carve_smtp(result, writer: _Writer) -> list[Artifact]:
    out: list[Artifact] = []
    streams_by_idx = {s.info.index: s for s in result.stream_data}
    for mail in result.smtp_traffic:
        st = streams_by_idx.get(mail.get("stream", -1))
        if st is None or b"\r\n.\r\n" not in st.c2s:
            continue
        raw_mail = st.c2s.split(b"\r\n.\r\n")[0]
        # drop the SMTP command preamble; the message starts after DATA
        if b"\r\nDATA\r\n" in raw_mail:
            raw_mail = raw_mail.rsplit(b"\r\nDATA\r\n", 1)[1]
        try:
            msg = BytesParser(policy=policy.default).parsebytes(raw_mail)
        except Exception:
            continue
        for part in msg.walk():
            filename = part.get_filename()
            payload = part.get_payload(decode=True)
            if not filename or not payload:
                continue
            art = _emit(writer, payload, filename, protocol="smtp",
                        src=mail.get("from", "?"), dst=", ".join(mail.get("to", [])) or "?",
                        ts=st.info.start_ts,
                        claimed=part.get_content_type(), stream=st.info.index,
                        url="")
            if art:
                out.append(art)
    return out


def _emit(writer: _Writer, data: bytes, preferred_name: str, *, protocol: str,
          src: str, dst: str, ts, claimed: str, stream: int, url: str
          ) -> Artifact | None:
    written = writer.write(data, preferred_name)
    if written is None:
        return None
    name, size = written
    sha256, sha1, md5 = _hashes(data)
    return Artifact(
        filename=name, protocol=protocol, src=src, dst=dst, ts=ts,
        size=size, sha256=sha256, sha1=sha1, md5=md5,
        detected_type=detect_type(data), claimed_type=claimed.split(";")[0],
        stream=stream, url=url,
        stored_path=str(writer.dir / name),
    )
