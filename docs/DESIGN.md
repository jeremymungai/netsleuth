# NetSleuth — Design Document

This records every significant decision, why it was made, and what was
rejected. It doubles as the "rebuild benchmark": with this file you should
be able to reconstruct the project's architecture from scratch.

## 1. Product shape: CLI-first, reports as files

**Decision.** A Python CLI (`typer`) with rich terminal output, plus JSON /
Markdown / HTML report generation. No mandatory GUI.

**Why.** The audience (SOC, IR, CTF) lives in terminals and pipelines.
JSON output makes the tool scriptable (`netsleuth detect --json | jq`);
HTML gives portfolio/report-ready artifacts without maintaining a server.
A web dashboard stays on the roadmap as an *optional* layer over the same
JSON — the analysis engine never depends on it.

**Rejected.** FastAPI dashboard as a first-class citizen (extra deps,
hosting complexity, no value for CI); Electron-style app (licensing and
install weight for zero analysis gain).

## 2. Parsing: scapy for structure, hand-rolled where speed matters

**Decision.** scapy reads the files, but the hot dissection path
(Ethernet/IP/TCP/UDP/ICMP/ARP — all fixed-offset headers) is parsed by
hand from `RawPcapReader` bytes. scapy remains for: DNS message parsing
(a genuinely complex, compressed-name format we should not reimplement),
and a full fallback when the fast path declines a packet.

**Why.** Profiling showed ~60% of runtime inside scapy's recursive layer
dissection (~1 ms/packet). The hand-rolled path kept semantics identical
(all 93 tests pass unchanged) and took full-pipeline throughput from
~1,600 to ~4,200 packets/s on the same laptop.

**Rejected.**
- *Pure scapy (`PcapReader`)* — correct but 2.6× slower; measured, not guessed.
- *No scapy at all* — would require reimplementing DNS parsing (error-prone:
  name compression, casing, EDNS) and pcapng reading for marginal gain.
- *tshark as the parser* — excellent and fast, but adds a non-Python
  system dependency (Wireshark install) that breaks "pip install and go",
  especially on Windows and CI.

**Subtlety worth recording:** importing `scapy.utils` does *not* load
scapy's layer modules — `conf.l2types` stays empty and every link type
decodes as raw bytes, and UDP-53⇄DNS bindings never register. The tests
originally masked this because the fixtures import `scapy.all` first.
`capture.py` therefore side-effect-imports `scapy.layers.inet`, `inet6`
and `dns` explicitly.

## 3. Normalization boundary: everything downstream speaks `models.py`

**Decision.** `capture.py` is the *only* module that imports scapy. It
emits `Packet` dataclasses; analyzers emit typed dataclasses (`Flow`,
`DNSRecord`, `HTTPTransaction`, `Finding`, …).

**Why.** Two payoffs: (a) analyzers and detectors are unit-testable with
synthetic objects — no capture files needed to test detection math; (b) a
future parser swap (tshark backend) touches exactly one module.

## 4. Pipeline: one streaming pass, staged finalize

**Decision.**

```
stage 1 (per packet):  overview · dns · dhcp · arp · icmp · flow tracker · reassembler
stage 2:               stream finalize (order by first packet time)
stage 3:               http · tls · cleartext-creds  (consume reassembled streams)
stage 4:               carving (http bodies, MIME) · secret scanning (rules)
stage 5:               detection (16 detectors) · scoring · timeline
```

**Why.** Single-pass keeps memory flat for big captures: analyzers keep
aggregates, only the reassembler holds payloads (bounded). Stream-based
analysis must follow reassembly, so it can't be in the packet loop;
detectors consume the *structured result* (not packets), which is what
makes them pure functions.

**Rejected.** Multi-threaded analysis — the GIL plus per-packet fan-out
complexity isn't worth it until profiling shows analyzer-bound behavior
(it's parser-bound instead); `--threads` omitted rather than fake.

## 5. TCP reassembly

**Decision.** Per-direction segment store keyed by *relative* sequence
(= first SYN+1, or first data byte when the SYN wasn't captured), merged
at finalize: retransmits dropped, overlaps trimmed, gaps **counted but
not filled** (content after a gap is still returned, concatenated).

**Why.** Mirrors what "Follow TCP Stream" gives analysts — for CTF and
IR, partial content after a gap is usually better than nothing, and gap
counts surface capture-quality problems honestly.

**Rejected.** Filling gaps with markers (corrupts carved files);
full RFC-compliant reassembly with PAWS/timestamps (out of scope for
v0.1, documented); zero-window/proxy-style stream carving (no evidence
of need). Sequence wraparound handled for streams < 4 GiB via modular
relative arithmetic.

## 6. Detection philosophy: evidence, confidence, honesty

**Decision.** Findings are dataclasses that *must* carry: description,
plain-English "why it matters", evidence strings (concrete numbers),
affected hosts, timestamps, a Wireshark display filter, and confidence
(low/medium/high). Multi-signal detectors (DNS tunneling needs ≥2 of 5
signals) instead of single-keyword triggers. The risk score is
documented formula: `strongest severity weight + Σ(25% of the rest) ×
confidence multiplier`, capped at 100 — one CRITICAL alone means 90, and
noise findings can't out-shout real ones.

**Why.** The brief said it best: "EVIDENCE > assumptions, EXPLAINABILITY
> opaque scoring." Tests enforce the contract (every finding has
explanation + verification) and the negative space (benign traffic
produces no HIGH/CRITICAL findings).

**Rejected.** ML scoring (no training data, unexplainable); severity
sums that saturate on low-value noise; MITRE mappings forced onto every
finding (mapping only where the technique definition actually fits).

## 7. TLS: metadata only, minimal DER by hand

**Decision.** Parse record/handshake structure from reassembled streams:
SNI, offered/negotiated versions, ALPN, cipher lists → JA3 (GREASE-aware,
reimplemented from the public spec), certificate chain → a ~120-line DER
walk for subject/issuer CN/O and validity. No decryption, ever.

**Why.** Everything here is handshake-visible and factual; certificates
needed only 5 fields, which does not justify a `cryptography` dependency.
The stdlib has no X.509 parser (`ssl._test_decode_cert` is private and
file-based).

**Rejected.** `cryptography` (heavy C dependency for five fields);
claiming JA4 support in v0.1 (randomized-extension ordering rules are
easy to get subtly wrong — roadmap).

## 8. Rules: YAML files, namespaced override

**Decision.** Built-in signatures in `netsleuth/signatures/*.yaml`; user
files loaded with `--rules` (file or directory), ids namespaced by
filename stem, same-id override so users tune built-ins without forking;
`--pattern` compiles ad-hoc rules.

**Why.** Detection logic must be auditable and editable without touching
Python. YAML is readable and already a dependency-free format choice
given PyYAML is needed anyway… actually PyYAML is *the* reason the
dependency exists, and JSON lacked comments for regex documentation.

**Rejected.** TOML (awkward for regex-heavy data, escaping-wise);
embedding rules in Python (blocks no-code users); a rules DSL (YAGNI).

**Quoting rule that emerged:** patterns avoid literal quote characters
(regex `\x27`/`\x22`) because single-quoted YAML cannot contain `'` and
double-quoted YAML eats regex backslash escapes. Documented in every
signature file.

## 9. Security posture of the tool itself

**Decision.** Treat the capture as hostile input: sanitized basenames +
resolved-path containment in the carver; 1 GiB total carve budget, 16 MiB
per-body retention, 32 MiB decompression cap; 2 MiB per-direction scan
windows; HTML reports escape everything and embed no scripts/CDNs;
secrets masked in output unless `--reveal`; extracted files are written
byte-for-byte and never executed.

**Why.** A pcap is attacker-controlled data; the tool is routinely run
with elevated attention on captures that may have been crafted to attack
the analyst's tools. Full threat model in docs/SECURITY.md.

**Rejected.** Sandboxed carving (containers) — disproportionate for a
local CLI; regex timeouts — Python `re` has none, so the mitigation is
documented guidance on rule authoring.

## 10. Testing strategy

**Decision.** All fixtures synthetic, generated by scapy at test time
(`tests/pcapfix.py` keeps sequence/ack accounting realistic). Protocol
parsers are tested against *hand-built wire bytes* (TLS ClientHello, DER
certificates) — known-good by construction. Detection tests assert both
positive firing and negative quietness. CLI tested via typer's runner
including error paths and masking behavior.

**Why.** Redistributable (no licensed captures in the repo),
deterministic, and the byte-level fixtures catch parser drift that
library-generated fixtures would silently absorb.

## 11. What is deliberately NOT built (v0.1)

Live capture / active network features (out of scope, defensive tool);
SMB/Kerberos/LDAP deep parsing (identified-only, honest); IP fragment
reassembly (fragments flagged); web dashboard (roadmap); YARA (roadmap
— dependency cost not yet justified); Suricata rule import (roadmap).

Each omission is recorded so the README's feature list stays true.
