# Contributing to NetSleuth

Thanks for wanting to help — PRs and issues are both welcome.

## Ground rules

1. **Defensive only.** NetSleuth analyzes captures; it does not touch
   live networks. Features that send packets, exploit systems, or evade
   detection are out of scope and will be closed.
2. **Evidence with every detection.** A new detector ships with:
   - a test proving it fires on synthetic attack-shaped traffic,
   - a test proving benign traffic stays quiet,
   - evidence strings (concrete numbers, not adjectives),
   - a Wireshark display filter,
   - an explanation that names the benign look-alikes.
3. **No new hard dependencies** without a DESIGN.md entry justifying
   them against the alternatives (the current runtime set is four
   packages, on purpose).
4. **Malicious-input hardening is not optional** for anything that
   parses capture data: think filenames, sizes, encodings, HTML output.
   Extend the tests in the spirit of `test_extraction.py` /
   `test_reporting.py`.

## Workflow

```bash
pip install -e .[dev]
python -m pytest                 # everything must pass
python -m pytest tests/test_detection.py -q   # while iterating
```

- Keep the style of the surrounding code; comments explain *why*
  (constraints), never *what*.
- Run `python -m compileall netsleuth` before pushing (CI does too).
- Update `docs/` when behavior changes — the docs are the product.

## Adding a detector (the usual contribution)

1. Write the failing tests first (positive + negative).
2. Implement `detect_<name>(result) -> list[Finding]` in
   `netsleuth/detection/`, register it in `engine.py`.
3. Set severity/confidence per `docs/detection.md` conventions; add a
   MITRE mapping only if the technique genuinely fits.
4. If it needs new data, extend the analyzer — and remember detectors
   consume the *structured result*, never raw packets.

## Adding a protocol analyzer

Packet-fed analyzers implement `feed(pkt)` + `finalize()`; stream-fed
ones consume reassembled `StreamData` at finalize. Both write typed
records into `AnalysisResult` via `pipeline.py`. Fixtures for new
protocols are built in `tests/pcapfix.py` — synthetic, redistributable.

## Reporting bugs

Open an issue with: the NetSleuth version, Python version, OS, the
command you ran, and — if shareable — the smallest capture that
reproduces it (`--max-packets 200` plus your findings usually suffices).
For security issues, see docs/SECURITY.md (prefer private advisories).
