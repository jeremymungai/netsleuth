"""Symbolic→bitstream mapping and candidate decoding.

Given a value sequence over a small alphabet, generate plausible
symbol→bit mappings, extract bitstreams, group bits into bytes (both
bit orders), decode, and score how structured the output is. Everything
is reported as a *candidate* — nothing here proves intent.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field

_PRINTABLE = set(string.printable) - set("\x0b\x0c")


def _printable_ratio(data: bytes) -> float:
    if not data:
        return 0.0
    text = data.decode("latin-1")
    return sum(1 for c in text if c in _PRINTABLE) / len(text)


@dataclass
class BitCandidate:
    mapping: dict[str, str]          # value → bit string
    bits: str
    bit_order: str                   # msb-first | lsb-first
    pad: str                         # leading | trailing (remainder bits dropped)
    data: bytes = b""
    decoded: str = ""
    printable: float = 0.0
    score: float = 0.0

    @property
    def mapping_text(self) -> str:
        return ", ".join(f"{v}→{b}" for v, b in self.mapping.items())


def mapping_candidates(values: list[str]) -> list[dict[str, str]]:
    """Symbol assignments to try, given the distinct values.

    Binary alphabets get both assignments (A=0/B=1 and the inverse).
    Larger power-of-two alphabets get first-appearance order and
    frequency order, each interpreted as k-bit codes (and the reversed
    code table — cheap to try, catches reversed enumerations).
    """
    distinct: list[str] = []
    for v in values:
        if v not in distinct:
            distinct.append(v)
    if len(distinct) < 2:
        return []
    k = (len(distinct) - 1).bit_length()      # bits per symbol
    if len(distinct) & (len(distinct) - 1) != 0 and len(distinct) != 2:
        # non-power-of-two alphabets: only try as binary pairs when exactly 2
        return []
    codes = [format(i, f"0{k}b") for i in range(len(distinct))]
    out: list[dict[str, str]] = []
    if len(distinct) == 2:
        out.append({distinct[0]: "0", distinct[1]: "1"})
        out.append({distinct[0]: "1", distinct[1]: "0"})
    else:
        out.append(dict(zip(distinct, codes)))
        out.append(dict(zip(distinct, codes[::-1])))
        freq = sorted(distinct, key=lambda v: (-values.count(v), v))
        out.append(dict(zip(freq, codes)))
    # dedupe identical mappings
    seen, uniq = set(), []
    for m in out:
        key = tuple(sorted(m.items()))
        if key not in seen:
            seen.add(key)
            uniq.append(m)
    return uniq


def bits_to_bytes(bits: str, bit_order: str, pad: str) -> bytes:
    usable = len(bits) - (len(bits) % 8)
    if pad == "leading":
        bits = bits[len(bits) - usable:] if usable else ""
    else:
        bits = bits[:usable]
    out = bytearray()
    for i in range(0, len(bits), 8):
        chunk = bits[i:i + 8]
        if bit_order == "lsb":
            chunk = chunk[::-1]
        out.append(int(chunk, 2))
    return bytes(out)


_SCORE_WORDS = ("flag", "ctf", "the ", "pass", "secret", "covert", "channel",
                "admin", "hello", "{", "}", "pico")


def score_bytes(data: bytes) -> float:
    """How structured does this byte string look? 0..1-ish heuristic."""
    ratio = _printable_ratio(data)
    score = ratio
    low = data.lower()
    hits = sum(1 for w in _SCORE_WORDS if w.encode() in low)
    score += min(hits * 0.05, 0.15)
    if data and all(32 <= b < 127 or b in (10, 13, 9) for b in data):
        score += 0.1
    if len(data) > 8 and len(set(data)) <= 2:
        # degenerate outputs (all 0x55 from sequential-ID parity, 'AAAA…')
        # are generator artifacts, not messages
        score -= 0.4
    return min(score, 1.0)


def decode_candidates(values: list[str]) -> list[BitCandidate]:
    """All mapping × order × padding attempts, ranked best-first."""
    out: list[BitCandidate] = []
    for mapping in mapping_candidates(values):
        try:
            bits = "".join(mapping[v] for v in values)
        except KeyError:
            continue
        for order in ("msb", "lsb"):
            for pad in ("trailing", "leading"):
                data = bits_to_bytes(bits, order, pad)
                if not data:
                    continue
                cand = BitCandidate(mapping=mapping, bits=bits, bit_order=order,
                                    pad=pad, data=data,
                                    decoded=data.decode("latin-1"),
                                    printable=_printable_ratio(data),
                                    score=score_bytes(data))
                out.append(cand)
    out.sort(key=lambda c: -c.score)
    return out
