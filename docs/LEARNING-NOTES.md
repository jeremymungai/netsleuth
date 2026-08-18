# Learning Notes — what building NetSleuth taught me

The honest engineering diary: what worked, what broke, what I'd do
differently. (Companion to DESIGN.md, which records the decisions
themselves.)

## 1. "It passes in tests" can hide a broken product

The nastiest bug never failed a test: scapy doesn't register its
linktype/protocol bindings unless the layer modules are imported, and
my test fixtures imported `scapy.all` before any NetSleuth code ran —
silently healing the bug the real CLI path had. Everything dissected as
raw bytes in production while the suite stayed green.

**Lesson:** test the entry point you ship, not just the library. The
CLI tests would have caught it, but they also imported fixtures first.
The fix (explicit side-effect imports with a comment explaining *why*)
is the kind of landmine documentation comments are actually for.

## 2. Hand-built wire bytes beat library-generated fixtures

For TLS I built ClientHello records and DER certificates by hand in the
tests instead of letting a library emit them. It was slower to write —
and it caught real parser mistakes (a SNI offset bug, YAML-vs-regex
quote interactions, an idna codec that rejects `errors="replace"`).
Library-generated fixtures can only confirm you agree with the library,
not that you parse the spec.

## 3. Profiling before optimizing — then a 2.6× win

cProfile showed 60% of runtime inside scapy's recursive dissection, not
in "my" code. A hand-rolled fixed-offset dissector for the hot layers
(Ethernet/IP/TCP/UDP/ICMP/ARP) with scapy retained for DNS and fallback
took throughput from ~1.6k to ~4.2k packets/s — with all 93 tests
passing unchanged, which is the only reason it counts as a win.

**Lesson:** the fast path/fallback split is the pattern. You get speed
without betting correctness on it: anything unusual just takes the slow
road.

## 4. YAML and regex quoting is a designed footgun

Single-quoted YAML can't contain `'`; double-quoted YAML eats `\b`. A
credentials rule with `["\']` in it produced a parser error that took a
minute to understand and would take users longer. The fix was a
convention (use `\x27`/`\x22` in patterns) documented in every
signature file — conventions that absorb footguns are cheaper than
clever validators.

## 5. The interesting bugs are in the seams

Almost every failure lived at a boundary: scapy 2.7 turning `dns.an`
from a chained layer into a list (my walk handled both, but only
because the test forced the response path); a "zero-length HTTP body"
that my no-progress loop guard treated as a stuck parser (302s with
`Content-Length: 0` are everywhere); the ARP analyzer receiving the
*analyzer object* instead of its `.data` because the pipeline stored
eight different analyzer results and one line forgot the `.data`.
Boundaries are where tests must be densest.

## 6. Writing honest findings is a discipline, not a feature

Every detector's first draft said "possible X". The useful version says
possible X, *here are the numbers*, *here's what else looks like this*
(updaters beacon too), *here's the filter to check me*, and — the part
I kept having to rewrite — *here's what would make this benign*. The
negative tests (benign traffic must stay quiet) were as much work as
the detections, and they're the feature I'd defend hardest. An
unexplainable alert is noise wearing a suit.

## 7. What I'd do differently

- Der-DNS-TLS byte builders would live in a shared `wiregen` module
  from day one; the test files re-implement three variants of
  "build a TCP conversation."
- I'd add a `--list-modules` flag and think about module dependencies
  (`http` needs `streams`) before writing the pipeline, not during.
- The scoring formula would have been written down before the
  detectors, so they could log their contributions to it.
- pcapng got less love than pcap (fixtures are pcap-heavy); the next
  contribution I'd want is a pcapng-equivalent fixture family,
  including multi-interface files.

## 8. Small things that paid off

- Masking secrets by default made every screenshot of the tool
  shareable without redaction passes.
- The structure pre-scan (walking record headers without parsing
  packets) gave exact counts, truncation detection and interface names
  for ~zero cost.
- Making detectors pure functions over the result model meant testing
  detection math with plain object literals — no pcap fixtures needed
  for the hardest logic.
