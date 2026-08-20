"""Encoding detection and transformation-chain analysis.

Never decodes blindly: each candidate is validated (alphabet, length,
decode success, printable ratio) and reported with a confidence level.
For CTF work, chains are followed iteratively ("base64 inside hex inside
URL-encoding") so the analyst sees every step.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re
import string
import urllib.parse
import zlib
from dataclasses import dataclass, field

from netsleuth.analyzers.dns import shannon_entropy

_PRINTABLE = set(string.printable) - set("\x0b\x0c")
_B64_ALPHABET = set(string.ascii_letters + string.digits + "+/=")
_B32_ALPHABET = set(string.ascii_uppercase + "234567=")
_HEX_ALPHABET = set("0123456789abcdefABCDEF")
_PCT_SEQ = re.compile(r"%[0-9A-Fa-f]{2}")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    text = data.decode("latin-1")
    ok = sum(1 for c in text if c in _PRINTABLE)
    return ok / len(text)


@dataclass
class EncodingStep:
    encoding: str
    confidence: str
    decoded_preview: str = ""


@dataclass
class EncodingChain:
    original: str
    steps: list[EncodingStep] = field(default_factory=list)
    final: str = ""
    final_is_printable: bool = False

    @property
    def description(self) -> str:
        return " → ".join(s.encoding for s in self.steps) or "none"


def looks_like_base64(s: str) -> bool:
    stripped = s.rstrip("=")
    return (len(stripped) >= 8 and len(s) % 4 == 0
            and all(c in _B64_ALPHABET for c in s))


def looks_like_base32(s: str) -> bool:
    stripped = s.rstrip("=")
    return (len(stripped) >= 8 and len(s) % 8 == 0
            and all(c in _B32_ALPHABET for c in s))


def looks_like_hex(s: str) -> bool:
    return (len(s) >= 8 and len(s) % 2 == 0
            and all(c in _HEX_ALPHABET for c in s))


def looks_like_url_encoded(s: str) -> bool:
    return len(_PCT_SEQ.findall(s)) >= 2


def detect_encoding(s: str) -> EncodingStep | None:
    """Best-effort single-step detection with confidence, or None."""
    s = s.strip()
    if not s:
        return None

    if looks_like_url_encoded(s):
        decoded = urllib.parse.unquote(s)
        if decoded != s:
            return EncodingStep("URL-encoded", "high", decoded[:120])

    if looks_like_base32(s):
        try:
            raw = base64.b32decode(s, casefold=True)
            if _printable_ratio(raw) > 0.85:
                return EncodingStep("Base32", "high", raw.decode("latin-1")[:120])
        except (binascii.Error, ValueError):
            pass

    if looks_like_base64(s):
        try:
            raw = base64.b64decode(s, validate=True)
            ratio = _printable_ratio(raw)
            if raw[:2] == b"\x1f\x8b":
                return EncodingStep("Base64(gzip)", "high", "<gzip data>")
            if ratio > 0.85:
                ent = shannon_entropy(s)
                conf = "high" if (ent > 3.2 and ratio > 0.95) else "medium"
                return EncodingStep("Base64", conf, raw.decode("latin-1")[:120])
        except (binascii.Error, ValueError):
            pass

    if looks_like_hex(s):
        try:
            raw = bytes.fromhex(s)
            if raw[:2] == b"\x1f\x8b":
                return EncodingStep("Hex(gzip)", "high", "<gzip data>")
            if _printable_ratio(raw) > 0.85:
                return EncodingStep("Hex", "high", raw.decode("latin-1")[:120])
        except ValueError:
            pass

    return None


MAX_DECOMPRESSED_STEP = 16 * 1024 * 1024        # 16 MiB decompression ceiling


def _safe_decompress(data: bytes, wbits: int, max_size: int = MAX_DECOMPRESSED_STEP) -> bytes:
    """Decompress with strict output size bounding to block decompression bombs."""
    d = zlib.decompressobj(wbits)
    return d.decompress(data, max_size)


def decode_step(s: str, encoding: str) -> str:
    encoding = encoding.lower()
    if "url" in encoding:
        return urllib.parse.unquote(s)
    if "base32" in encoding:
        return base64.b32decode(s.strip(), casefold=True).decode("latin-1")
    if "base64" in encoding:
        blob = base64.b64decode(s.strip(), validate=False)
        if "gzip" in encoding:
            blob = _safe_decompress(blob, 16 + zlib.MAX_WBITS)
        return blob.decode("latin-1")
    if encoding.startswith("hex"):
        blob = bytes.fromhex(s.strip())
        if "gzip" in encoding:
            blob = _safe_decompress(blob, 16 + zlib.MAX_WBITS)
        return blob.decode("latin-1")
    if encoding == "gzip":
        return _safe_decompress(s.strip().encode("latin-1"),
                                16 + zlib.MAX_WBITS).decode("latin-1", "replace")
    if encoding == "zlib":
        return _safe_decompress(s.strip().encode("latin-1"),
                                zlib.MAX_WBITS).decode("latin-1", "replace")
    if encoding == "rot13":
        return codecs.decode(s, "rot_13")
    return s


def analyze_chain(s: str, max_depth: int = 3) -> EncodingChain:
    """Follow detect→decode iteratively while each step is confident."""
    chain = EncodingChain(original=s)
    current = s.strip()
    for _ in range(max_depth):
        step = detect_encoding(current)
        if step is None:
            break
        try:
            nxt = decode_step(current, step.encoding)
        except Exception:
            break
        chain.steps.append(step)
        chain.final = nxt
        current = nxt
        if _printable_ratio(nxt.encode("latin-1")) < 0.5:
            break
    if not chain.steps:
        chain.final = s
    chain.final_is_printable = _printable_ratio(chain.final.encode("latin-1")) > 0.9
    return chain


def xor_brute_prefix(blob: bytes, prefixes=(b"flag{", b"FLAG{", b"picoCTF{", b"CTF{",
                                             b"HTB{", b"THM{"),
                     max_len: int = 4096) -> list[tuple[int, str]]:
    """Try every single-byte XOR key looking for known flag prefixes.

    Returns [(key, decoded)] for every key that produces a flag-shaped
    string — a classic CTF technique, offered explicitly rather than
    hidden inside "smart" detection.
    """
    hits: list[tuple[int, str]] = []
    region = blob[:max_len]
    for key in range(1, 256):
        decoded = bytes(b ^ key for b in region)
        for pre in prefixes:
            idx = decoded.find(pre)
            if idx != -1:
                end = decoded.find(b"}", idx)
                if end != -1 and end - idx < 200:
                    try:
                        hits.append((key, decoded[idx:end + 1].decode("ascii")))
                    except UnicodeDecodeError:
                        pass
                    break
    return hits
