# CLI Reference

Run as `netsleuth <command>` (installed) or `python -m netsleuth <command>`
(from the repo). `--help` on any command lists its options.

Exit codes: `0` success · `2` input/configuration error (bad file, bad
regex, missing `--output`) · findings never change the exit code.

## Global behavior

- Most commands accept `--json` for machine-readable output (stdout).
- `--max-packets N` stops ingestion early (0 = all) — handy on huge files.
- Focused commands (`dns`, `http`, `tls`, `streams`) only run the modules
  they need, which makes them much faster than `analyze`/`detect` on big
  captures.
- `--rules FILE|DIR` (secrets/detect/ctf/report/analyze) loads custom rule
  files on top of the built-ins.

## analyze — guided investigation

```
netsleuth analyze capture.pcap [-v] [--reveal] [--rules R] [--max-packets N]
```

The 11-step walkthrough: overview → hosts → DNS → suspicious connections
→ HTTP → TLS → extracted files → credentials/secrets → malicious
behavior → CTF candidates → Wireshark filter kit. `-v` prints full
evidence, MITRE mappings and verification steps for every finding.

## summary / hosts / dns / http / tls — views

- `summary` — file metadata, packet counts, duration, protocols, notes.
- `hosts [--limit N]` — hosts with network classification, DNS-learned
  hostnames, MAC vendors; top conversations.
- `dns [--limit N]` — per-domain query stats: NXDOMAIN counts, subdomain
  fan-out, resolved IPs, TXT counts, max label length/entropy (the
  tunneling telemetry).
- `http` — every recovered HTTP transaction (method, host/path, status,
  content type, sizes). Encrypted HTTPS shows up under `tls`, not here.
- `tls` — SNI, negotiated version, ALPN, JA3, certificate subject/issuer.

All accept `--json`.

## streams / stream — TCP conversations

```
netsleuth streams capture.pcap
netsleuth stream  capture.pcap 42 [--hex] [--max-bytes N]
```

`streams` indexes every reassembled conversation (endpoints, bytes per
direction, handshake/FIN status, gap counts). `stream` follows one —
like Wireshark's Follow TCP Stream — in text or hex. The stream index
matches Wireshark's `tcp.stream` numbering when capture order is
identical.

## extract — carve files

```
netsleuth extract capture.pcap --output DIR [--json]
```

Recovers HTTP download bodies, uploads and SMTP MIME attachments;
types them by magic bytes; computes SHA-256/SHA-1/MD5; writes them into
`DIR` (created). Filenames are sanitized; a 1 GiB total budget guards
against capture bombs. `--output` is required — carving is always
explicit. Files are never executed.

## secrets — rule-based hunting

```
netsleuth secrets capture.pcap [--pattern 'FLAG{.*?}'] [--reveal]
                                [--rules FILE] [--json]
```

Applies built-in + custom + ad-hoc regexes to streams, HTTP
lines/headers/bodies, DNS TXT and ICMP payloads. Values are masked in
output unless `--reveal`; JSON includes per-hit provenance (`source`,
`how`, Wireshark hints).

## ctf — competition helper

```
netsleuth ctf capture.pcap [--reveal] [--pattern P] [--rules R]
```

Flag candidates with discovery receipts → encoded-string decode chains
(URL/base64/base32/hex) → single-byte XOR sweep → hiding-spot checklist
(TXT records, long DNS names, ICMP payloads, unusual ports) → next
steps. Built to teach where evidence lives, not just to print flags.

## covert — protocol-metadata channels

```
netsleuth covert capture.pcap [--json] [--no-explain]
```

Generic covert-channel analysis: extracts per-host field sequences
(HTTP version/method/headers, DNS types/TTL, ports, IP ID/TTL), flags
systematic variation, tries symbolic→binary mappings and decodes
candidate bitstreams. Reports full derivations (values, mapping, bits,
decoded output, printable ratio, assumptions, Wireshark filter) —
structured variation that decodes to noise is deliberately not
reported. Concepts and manual workflow: docs/covert-channels.md.

## detect — findings & risk score

```
netsleuth detect capture.pcap [--verbose] [--json] [--rules R]
```

Runs all 16 detectors; prints the 0–100 score with its breakdown and
each finding's description, evidence, confidence, MITRE mapping and
Wireshark filter (`--verbose` adds explanation + verification text).

## timeline — chronology

```
netsleuth timeline capture.pcap [--host IP] [--kind dns|http|tls|tcp|file|detection]
                                [--severity MEDIUM|HIGH|CRITICAL] [--limit N]
```

Chronological events from all analyzers, filterable. `--json` returns up
to 1000 events with timestamps and filters.

## report — write it up

```
netsleuth report capture.pcap --format html|md|json [--output FILE] [--reveal]
```

Full investigation report. HTML is a single self-contained file (no
scripts, no CDNs — safe to open anywhere). Default output name:
`<capture>.<format>`.

## Version

```
netsleuth --version
```
