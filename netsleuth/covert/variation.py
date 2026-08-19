"""Sequence variation analysis: is a field's value stream structured?

Pure functions over ordered value sequences — no protocol knowledge
here, which is what makes the engine generic over fields.
"""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass

# a syntactically valid hostname: dot-separated labels of letters/digits/
# hyphens, with an alphabetic (or punycode) TLD — values like this are
# real names being *used*, not data being *encoded*.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*"
    r"\.[a-z]{2,24}$|^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*"
    r"\.xn--[a-z0-9-]{2,59}$",
    re.IGNORECASE,
)


@dataclass
class VariationReport:
    cardinality: int
    counts: dict[str, int]
    transitions: int                 # value changes between neighbors
    expected_transitions: float      # if values were i.i.d. with these freqs
    transition_ratio: float          # observed / expected
    max_run: int                     # longest streak of one value
    entropy: float                   # bits/symbol of the value distribution
    length: int

    @property
    def pattern(self) -> str:
        if self.cardinality < 2:
            return "constant"
        if self.cardinality == 2:
            if self.transition_ratio >= 0.55 and self.max_run <= 8:
                return "two-state repeated sequence"
            if self.transition_ratio >= 0.55:
                return "two-state sequence (long runs)"
            return "two values, mostly separated"
        if self.cardinality <= 8 and self.transition_ratio >= 0.55:
            return f"low-cardinality ({self.cardinality}-state) repeated sequence"
        return "high-cardinality variation"


def all_hostnames(values: list[str]) -> bool:
    """True when every value in the alphabet is a syntactically valid
    hostname (contains a dot and ends in an alphabetic TLD).

    A field whose values are all real hostnames — an HTTP Host header
    cycling through ctldl.windowsupdate.com, x1.c.lencr.org, … — is a
    client *using* names, not encoding data in them. A true covert
    channel needs freely-chosen symbols (``a``, ``ab``, ``ba``, hex
    chunks…), which never look like dotted hostnames with TLDs. Used as
    a pre-filter before bit-mapping so name-like alphabets are never
    decoded.
    """
    return bool(values) and all(
        bool(v) and _HOSTNAME_RE.match(v) is not None for v in values)


def analyze_variation(values: list[str]) -> VariationReport:
    n = len(values)
    counts = dict(Counter(values))
    cardinality = len(counts)
    transitions = sum(1 for a, b in zip(values, values[1:]) if a != b)
    # expected transitions for independent draws with the observed frequencies
    p_sq = sum((c / n) ** 2 for c in counts.values())
    expected = max((n - 1) * (1 - p_sq), 1e-9)
    max_run = 1
    run = 1
    for a, b in zip(values, values[1:]):
        run = run + 1 if a == b else 1
        max_run = max(max_run, run)
    ent = -sum((c / n) * math.log2(c / n) for c in counts.values()) if n else 0.0
    return VariationReport(cardinality=cardinality, counts=counts,
                           transitions=transitions,
                           expected_transitions=expected,
                           transition_ratio=round(transitions / expected, 3),
                           max_run=max_run, entropy=round(ent, 3), length=n)


MIN_OBSERVATIONS = 16                # below this, patterns are coincidence
MIN_TRANSITION_RATIO = 0.5           # alternating-ish, not one block then another
MAX_CARDINALITY = 8                  # symbolic channels are low-cardinality


def is_interesting(rep: VariationReport) -> bool:
    """A field stream is worth decoding when it looks *chosen*, not natural.

    Natural variation is either constant, one-sided (a value change is
    an event), or high-cardinality (names, lengths, ports in normal
    use). Channels need enough symbols, few states, and active
    switching between them.
    """
    if rep.length < MIN_OBSERVATIONS:
        return False
    if rep.cardinality < 2 or rep.cardinality > MAX_CARDINALITY:
        return False
    if rep.transition_ratio < MIN_TRANSITION_RATIO:
        return False
    if rep.max_run > max(8, rep.length / 4):
        # a field that settles into one value carries almost no information
        return False
    return True
