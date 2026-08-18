"""HTTP analyzer — parses request/response pairs from reconstructed TCP streams.

Why streams instead of per-packet parsing: HTTP headers and bodies
regularly span many TCP segments; parsing the reassembled byte stream is
the only reliable approach (it is what Wireshark's "Follow TCP Stream"
gives you, automated).

Supports HTTP/1.0 and 1.1: keep-alive pipelining (many transactions per
stream), Content-Length and chunked bodies, and capped gzip/deflate
decompression. Response bodies are retained (up to a limit) so the
carver and secret scanner can work on them.
"""

from __future__ import annotations

import re
import zlib
from dataclasses import dataclass, field

from netsleuth.enrichment.ports import CLEARTEXT_HTTP_PORTS
from netsleuth.models import HTTPTransaction, StreamData

_REQ_LINE = re.compile(rb"([A-Za-z!#$%&'*+.^_`|~0-9-]+) (\S+) HTTP/(\d)\.(\d)\r?\n")
_RESP_LINE = re.compile(rb"HTTP/(\d)\.(\d) (\d{3})(?: ([^\r\n]*))?\r?\n")
_HEADER_END = b"\r\n\r\n"

MAX_BODY_RETAINED = 16 * 1024 * 1024       # 16 MiB per response body
MAX_DECOMPRESSED = 32 * 1024 * 1024        # decompression bomb guard
MAX_REQ_BODY_KEPT = 256 * 1024             # POST bodies kept for scanning


@dataclass
class _Message:
    start: int
    head: bytes
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    body_consumed: int = 0                 # bytes the body actually occupies


def _parse_head(buf: bytes, start: int, line_re: re.Pattern):
    """Parse one message head starting at ``start``. Returns (head_dict, end_offset) or None."""
    m = line_re.match(buf, start)
    if not m:
        return None
    end = buf.find(_HEADER_END, m.start())
    if end == -1:
        return None
    head_bytes = buf[m.start():end + 4]
    headers: dict[str, str] = {}
    for raw in head_bytes.split(b"\r\n")[1:]:
        if not raw or raw[:1] in (b" ", b"\t"):
            continue
        name, _, value = raw.partition(b":")
        if _:
            headers[name.decode("latin-1").strip().lower()] = \
                value.decode("latin-1").strip()
    return {"line": m, "headers": headers, "head_bytes": head_bytes,
            "start": m.start(), "end": end + 4}


def _take_body(buf: bytes, start: int, headers: dict[str, str],
                request: bool = False) -> tuple[bytes, int]:
    """Extract the body starting at ``start`` honoring framing rules.

    Returns (body_slice, total_framed_length) where total_framed_length
    is what the sender's framing implies (may exceed what was captured).
    """
    te = headers.get("transfer-encoding", "").lower()
    if "chunked" in te:
        chunks, pos, declared = [], start, 0
        while True:
            eol = buf.find(b"\r\n", pos)
            if eol == -1:
                break
            size_token = buf[pos:eol].split(b";")[0].strip()
            try:
                size = int(size_token or b"0", 16)
            except ValueError:
                break
            declared += size
            if size == 0:
                pos = eol + 2
                tail = buf.find(b"\r\n", pos)
                pos = (tail + 2) if tail != -1 else len(buf)
                break
            chunks.append(buf[eol + 2:eol + 2 + size])
            pos = eol + 2 + size + 2
        return b"".join(chunks), pos - start
    cl = headers.get("content-length")
    if cl is not None:
        try:
            n = int(cl)
        except ValueError:
            return b"", 0
        return buf[start:start + n], n + 0
    # no framing: responses may run to the end of the captured stream
    # (connection-close); a request without framing simply has no body, or
    # the next pipelined request would be swallowed as payload
    if request:
        return b"", 0
    return buf[start:], len(buf) - start


def _maybe_decompress(body: bytes, encoding: str) -> tuple[bytes, str]:
    """Decompress gzip/deflate with a hard output cap. Returns (body, note)."""
    if "gzip" in encoding or "deflate" in encoding:
        try:
            d = zlib.decompressobj(16 + zlib.MAX_WBITS if "gzip" in encoding
                                   else zlib.MAX_WBITS)
            out = d.decompress(body, MAX_DECOMPRESSED + 1)
            if len(out) > MAX_DECOMPRESSED:
                return out[:MAX_DECOMPRESSED], "gzip body truncated at 32 MiB (decompression-bomb guard)"
            return out, ""
        except zlib.error:
            return body, "compressed body could not be decompressed"
    return body, ""


class HTTPAnalyzer:
    name = "http"

    def __init__(self) -> None:
        self.transactions: list[HTTPTransaction] = []
        self.parse_notes: list[str] = []

    def analyze(self, streams: list[StreamData]) -> None:
        for st in streams:
            if not (st.c2s or st.s2c):
                continue
            if not self._looks_like_http(st):
                continue
            reqs = self._parse_direction(st.c2s, _REQ_LINE, request=True)
            resps = self._parse_direction(st.s2c, _RESP_LINE, request=False)
            for i, req in enumerate(reqs):
                resp = resps[i] if i < len(resps) else None
                self.transactions.append(self._build(st, req, resp))

    def _looks_like_http(self, st: StreamData) -> bool:
        if st.info.server_port in CLEARTEXT_HTTP_PORTS or st.info.client_port in CLEARTEXT_HTTP_PORTS:
            return True
        # content-based detection for HTTP on nonstandard ports (CTF favorite)
        return bool(_REQ_LINE.match(st.c2s[:8192]) or _RESP_LINE.match(st.s2c[:8192]))

    def _parse_direction(self, buf: bytes, line_re: re.Pattern,
                         request: bool = False) -> list[_Message]:
        out, pos = [], 0
        for _ in range(512):                   # sane cap per stream
            parsed = _parse_head(buf, pos, line_re)
            if parsed is None:
                break
            body, framed = _take_body(buf, parsed["end"], parsed["headers"],
                                      request=request)
            out.append(_Message(start=parsed["start"], head=parsed["head_bytes"],
                                headers=parsed["headers"], body=body,
                                body_consumed=max(framed, len(body))))
            # head is non-empty, so pos strictly increases each iteration
            pos = parsed["end"] + max(framed, len(body))
        return out

    def _build(self, st: StreamData, req: _Message, resp: _Message | None) -> HTTPTransaction:
        m = _REQ_LINE.match(req.head)
        method, target = (m.group(1).decode("latin-1"), m.group(2).decode("latin-1"))
        path, _, query = target.partition("?")
        host = req.headers.get("host", "")
        body = req.body[:MAX_REQ_BODY_KEPT]
        m_ver = _REQ_LINE.match(req.head)
        ver = (m_ver.group(3).decode() + "." + m_ver.group(4).decode()) if m_ver else ""
        t = HTTPTransaction(
            ts=st.info.start_ts, stream=st.info.index, client=st.info.client,
            host=host, method=method, url=target, path=path, query=query,
            user_agent=req.headers.get("user-agent", ""),
            content_type_req=req.headers.get("content-type", ""),
            auth_header=req.headers.get("authorization", ""),
            cookies=req.headers.get("cookie", ""),
            version=f"HTTP/{ver}" if ver else "",
            header_count=len(req.headers),
            req_body_len=len(req.body),
        )
        t.body_excerpt = body[:4096]
        t.req_body = body if len(body) <= MAX_REQ_BODY_KEPT else body[:MAX_REQ_BODY_KEPT]
        if resp is not None:
            rm = _RESP_LINE.match(resp.head)
            t.status = int(rm.group(3))
            t.content_type_resp = resp.headers.get("content-type", "")
            t.server_header = resp.headers.get("server", "")
            try:
                t.resp_content_length = int(resp.headers.get("content-length", "-1"))
            except ValueError:
                t.resp_content_length = -1
            body_bytes, note = _maybe_decompress(
                resp.body[:MAX_BODY_RETAINED], resp.headers.get("content-encoding", ""))
            if note:
                self.parse_notes.append(f"stream {st.info.index}: {note}")
            t.resp_body = body_bytes if len(body_bytes) <= MAX_BODY_RETAINED \
                else body_bytes[:MAX_BODY_RETAINED]
            t.resp_body_len = len(resp.body)
        return t
