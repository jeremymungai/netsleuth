"""Printable string extraction with analyst-oriented ranking."""

from __future__ import annotations

import re
from dataclasses import dataclass

from netsleuth.analyzers.dns import shannon_entropy

_STRING_RE = re.compile(rb"[\x20-\x7e]{6,}")

_KEYWORDS = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_\-]?key|flag|auth|"
    r"credential|login|session|admin|root|private|key|bearer)\b")
_INTERESTING_EXT = re.compile(
    r"(?i)\.(?:zip|rar|7z|gz|tar|exe|dll|so|bin|php|asp|jsp|py|pl|sh|"
    r"pdf|docx?|xlsx?|pptx?|csv|json|xml|conf|cfg|ini|env|pem|key|pcap)$")


@dataclass
class ExtractedString:
    value: str
    score: int
    why: str
    source: str = ""


def extract_strings(data: bytes, source: str = "", limit: int = 20000
                    ) -> list[ExtractedString]:
    """Pull printable runs ≥6 chars out of raw bytes and rank them."""
    out: list[ExtractedString] = []
    seen: set[str] = set()
    for m in _STRING_RE.finditer(data[: limit * 128]):
        s = m.group().decode("ascii")
        if s in seen:
            continue
        seen.add(s)
        score, why = _score(s)
        out.append(ExtractedString(value=s, score=score, why=why, source=source))
    return out


def _score(s: str) -> tuple[int, str]:
    score = min(len(s), 60) // 6            # length: 0–10
    why = []
    if _KEYWORDS.search(s):
        score += 25
        why.append("credential-related keyword")
    if _INTERESTING_EXT.search(s):
        score += 10
        why.append("file path")
    if re.fullmatch(r"[A-Za-z0-9+/=]{16,}", s) or re.fullmatch(r"[0-9a-fA-F]{16,}", s):
        ent = shannon_entropy(s)
        score += int(ent * 4)
        if ent > 3.5:
            why.append(f"high-entropy encoded data ({ent:.1f} bits/char)")
    if s.lstrip().startswith(("<", "<?")):
        score += 8
        why.append("markup/script content")
    if "@" in s and re.search(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", s):
        score += 12
        why.append("email address")
    if s.startswith(("http://", "https://", "ftp://")):
        score += 10
        why.append("URL")
    return score, "; ".join(why) or "plain string"


def top_strings(data: bytes, source: str = "", n: int = 25) -> list[ExtractedString]:
    return sorted(extract_strings(data, source), key=lambda x: -x.score)[:n]
