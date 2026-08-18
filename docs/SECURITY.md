# Security Policy — the tool as an attack surface

NetSleuth parses **hostile input for a living**: captures may be
crafted to attack the analyst's tools. This document is the threat
model and the controls in place. (For reporting vulnerabilities, see
the bottom of this file.)

## Trust boundary

```
untrusted:  capture file contents, rule files, --pattern values
trusted:    the analyst running the CLI, the output directory
```

Everything crossing that line is treated as attacker-controlled.

## Threats and controls

### 1. Path traversal via carved filenames
Filenames harvested from HTTP paths, `Content-Disposition`, and MIME
parts are reduced to a safe basename (unicode NFKD, illegal chars
mapped to `_`, length-capped), prefixed with a sequence number, and the
resolved write path is verified to remain inside the output directory.
A traversal that survives sanitization raises rather than writing.
Tests: `test_carve_sanitizes_evil_filenames`.

### 2. Resource exhaustion / capture bombs
- Decompression (gzip/deflate HTTP bodies) capped at 32 MiB output —
  the decompressor stops and reports a truncation note.
- Per-response body retention: 16 MiB; per-request body kept for
  scanning: 256 KiB.
- Per-packet analysis payload slice: 1 MiB.
- TCP reassembly buffer: 64 MiB per direction (excess is counted and
  reported, not stored).
- Total carve budget: 1 GiB per run.
- Secret-scan window: 2 MiB per stream direction.

### 3. Malicious content in reports (XSS)
Every capture-derived value in the HTML report passes through
`html.escape`. Reports embed CSS only — **no scripts, no external
resources, no CDNs** — so the file is inert when opened. Tests feed
`<script>` payloads through DNS names and HTTP hosts and assert escaped
output (`test_html_report_escapes_capture_content`).

### 4. Execution of extracted content
Carved files are written byte-for-byte and **never executed, opened or
analyzed by shelling out**. No subprocess is ever spawned with
capture-derived arguments anywhere in the codebase. (A review item:
keep it that way — grep for `subprocess`/`os.system` before releases.)

### 5. Credential hygiene in outputs
Passwords and secrets are masked in console/JSON/HTML/report output by
default; `--reveal` is the analyst's explicit choice. Evidence strings
inside findings also use masked forms.

### 6. Regex denial of service (user-supplied rules)
Python `re` has no timeout, so a pathological custom pattern can hang a
scan. Mitigation: built-in patterns are bounded (documented habits in
`writing-rules.md`), and this residual risk is documented rather than
hidden. Future work: optional rule-validation pass.

### 7. Malformed captures
Structural pre-scan + per-packet exception containment: a bad packet
falls back to a slower parse or is skipped with a note; a truncated
file is analyzed to the cut and flagged. The CLI returns a clean error
(exit code 2) for non-capture files.

### 8. Supply chain / dependencies
Four runtime dependencies (scapy, typer, rich, PyYAML), all mature and
widely audited; no post-install code execution in `pyproject.toml`.
CI installs exact published versions; dependency review belongs in
every PR touching `pyproject.toml`.

### 9. No network calls
NetSleuth performs **zero network activity**: no telemetry, no hash
lookups, no DNS resolution for enrichment. Any future optional lookup
feature must ship disabled by default and be audible in the CLI.

## Reporting a vulnerability

Please use GitHub's private security advisories (Report a vulnerability
on the Security tab) — or open an issue labeled `security` if advisories
are unavailable. Expect a response within a few days; credit given
unless you prefer otherwise.
