# Changelog

All notable changes are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/); versioning is
[SemVer](https://semver.org/).

## [0.2.0] — 2026-08-17

### Added
- **Covert-channel / protocol-metadata analysis engine** (`netsleuth covert`,
  CTF phase, findings, reports): generic field extractors (HTTP
  version/method/status/UA/Host/cookies/headers, DNS qtype/labels/TTL,
  TCP ports/flags/lengths, IP ID parity/TTL), variation analysis
  (cardinality, transition ratio, run lengths), symbolic→binary mapping
  with MSB/LSB bit-grouping, printable-scored candidate decodings with
  full provenance (values, sequence, mapping, bits, assumptions,
  Wireshark filters, frame references). Sequential-IP-ID and
  degenerate-output false-positive guards; benign-variation negative
  tests. Synthetic HTTP-version channel demo with ground truth
  (`examples/generate_covert.py`) and docs/covert-channels.md.
- HTTP parser: request pipelining beyond the first unframed request
  (no-framing requests now have empty bodies), 512-message cap.
- Packet model: IP ID/TTL extraction, frame numbers on DNS evidence.

## [0.1.0] — 2026-08-17

First public release: the complete offline analysis engine.

### Added
- **Ingestion**: pcap + pcapng (both endiannesses, µs/ns timestamps,
  gzip), magic-byte validation, structural pre-scan (exact packet
  count, truncation detection, interface names), streaming reader with
  a fast manual dissector (Ethernet/VLAN/IP/IPv6+ext/TCP/UDP/ICMP/ARP)
  and full scapy fallback — ~4k packets/s on a dev laptop.
- **Analyzers**: hosts/protocols/conversations (overview), DNS with
  per-domain tunneling telemetry, HTTP from reassembled streams
  (keep-alive, chunked, capped gzip), TLS metadata (SNI, ALPN, versions,
  GREASE-aware JA3, minimal-DER certificate fields), cleartext
  credentials (FTP/SMTP/IMAP/POP3/HTTP-Basic, banners, SMTP envelope),
  DHCP, ARP, ICMP.
- **TCP reassembly**: relative sequence numbers, retransmission/overlap
  handling, gap counting, per-direction buffering caps.
- **Extraction**: HTTP download/upload + SMTP MIME carving with
  magic-byte typing, SHA-256/SHA-1/MD5, sanitized names, path
  containment, 1 GiB budget; YAML rule engine for flags/credentials/
  keys (built-in signatures + `--rules` + `--pattern`); encoding chain
  analysis (URL/base64/base32/hex/gzip) and single-byte XOR sweep for
  CTF mode; ranked string extraction.
- **Detection**: 16 explainable detectors (SYN scan, host sweep, TCP/DNS
  beaconing with interval-CV statistics, DNS tunneling multi-signal,
  NXDOMAIN anomaly, TXT density, HTTP attack patterns via rules,
  cleartext credentials, ARP conflicts, ICMP data, secret material,
  bulk transfer, risky ports), documented 0–100 risk score, justified
  MITRE ATT&CK mappings, per-finding Wireshark filters.
- **Reporting**: rich console, JSON, Markdown, self-contained HTML
  (fully escaped, no scripts/external resources), filterable timeline,
  Wireshark companion kit.
- **CLI**: 14 commands (`analyze`, `summary`, `hosts`, `dns`, `http`,
  `tls`, `streams`, `stream`, `extract`, `secrets`, `ctf`, `detect`,
  `timeline`, `report`) with `--json`, `--verbose`, `--reveal`,
  `--rules`, `--max-packets`; guided 11-step analyze mode.
- **Demo & docs**: synthetic incident capture generator with a full
  investigation walkthrough; educational network-basics; design record;
  security threat model; rule-writing guide; benchmark script.
- **Tests**: 93 tests, all fixtures synthetic (scapy-built), covering
  both pcap and pcapng, malformed/truncated/empty inputs, detection
  positive *and negative* cases, CLI error paths, HTML-escaping proofs.
