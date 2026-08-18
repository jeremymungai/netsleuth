"""Covert-channel engine: field streams → variation → candidate decodings.

Pipeline: extract field streams → keep the *interesting* ones (small
alphabet, active switching) → try symbolic mappings and bit decodings →
keep candidates whose decoded output looks structured (printable, word
hits) → report with full provenance and honest assumptions. Fields that
vary but decode to noise are *not* reported as candidates — random
binary-looking variation is normal traffic, and the engine says so by
staying quiet rather than by guessing.
"""

from __future__ import annotations

from netsleuth.covert import encoding, fields, variation
from netsleuth.models import CovertCandidate

# decoded output must be at least this structured to be worth reporting.
# Short outputs are held to a stricter standard: random bits routinely luck
# into ~85% printable when only a handful of bytes are produced.
MIN_REPORT_SCORE = 0.72
MIN_PRINTABLE = 0.85
MIN_PRINTABLE_SHORT = 0.95          # outputs shorter than 8 bytes
SHORT_OUTPUT = 8

MAX_CANDIDATES = 8


def analyze_capture(result) -> list[CovertCandidate]:
    candidates: list[CovertCandidate] = []
    for stream in fields.extract_all(result):
        values = stream.value_list
        rep = variation.analyze_variation(values)
        if not variation.is_interesting(rep):
            continue
        best = None
        tried = []
        for cand in encoding.decode_candidates(values):
            tried.append(f"{cand.mapping_text} ({cand.bit_order}-first, "
                         f"drop-{cand.pad}) → printable {cand.printable:.2f}")
            floor = (MIN_PRINTABLE_SHORT if len(cand.data) < SHORT_OUTPUT
                     else MIN_PRINTABLE)
            if cand.score >= MIN_REPORT_SCORE and cand.printable >= floor:
                if best is None or cand.score > best.score:
                    best = cand
        if best is None:
            continue                      # structured field, but decodes to noise
        obs = stream.values
        frames = sorted({o.frame for o in obs if o.frame})[:2] + \
                 sorted({o.frame for o in obs if o.frame})[-2:]
        candidates.append(CovertCandidate(
            protocol=stream.protocol,
            field=stream.field,
            source=stream.source,
            observed_values=sorted(rep.counts, key=lambda v: -rep.counts[v]),
            value_counts=rep.counts,
            sequence=[o.value for o in obs[:48]],
            sequence_len=rep.length,
            pattern=rep.pattern,
            mapping=best.mapping_text,
            bits=best.bits[:64],
            bits_len=len(best.bits),
            byte_len=len(best.data),
            decoded=best.decoded[:400],
            printable_ratio=best.printable,
            confidence=_confidence(rep, best),
            first_ts=min(o.ts for o in obs),
            last_ts=max(o.ts for o in obs),
            frames=[f for f in frames if f],
            wireshark_filters=[stream.wireshark_filter],
            assumptions=[
                f"observations are ordered by time and belong to source "
                f"{stream.source}",
                f"the {stream.field} field is freely choosable by the sender",
                f"symbols were mapped as {best.mapping_text} and grouped "
                f"8 bits per byte ({best.bit_order}-first, dropping "
                f"{best.pad} remainder bits)",
                "only the best of all tried mappings is shown; the rest "
                "may also be meaningful",
            ],
            alternatives_considered=tried[:6],
        ))
    candidates.sort(key=lambda c: -c.printable_ratio)
    # keep the strongest per (protocol, field, source) — dedupe near-identical
    seen: set[tuple] = set()
    out: list[CovertCandidate] = []
    for c in candidates:
        key = (c.protocol, c.field, c.source)
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
        if len(out) >= MAX_CANDIDATES:
            break
    return out


def _confidence(rep, best) -> str:
    if rep.cardinality == 2 and rep.transition_ratio >= 0.8 \
            and best.printable >= 0.95 and len(best.data) >= 8:
        return "high"
    if rep.transition_ratio >= 0.55 and best.printable >= 0.85:
        return "medium"
    return "low"


EDUCATION = (
    "What a covert channel is: any mechanism that moves information "
    "through fields not meant to carry data — here, the *choice* of a "
    "protocol value rather than its payload. Why it evades casual "
    "inspection: every individual packet looks perfectly legal; only "
    "the sequence of choices across packets reveals the message. How "
    "the bits were extracted: the field's values were observed in "
    "chronological order, mapped to symbols, concatenated into a "
    "bitstream and regrouped 8 bits per byte. Reproduce it in "
    "Wireshark with the filter below, read the field by hand for each "
    "packet, write the sequence down and decode the same way — the "
    "table below records every assumption of that process."
)
