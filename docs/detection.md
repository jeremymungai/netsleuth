# The Detection Engine

Detectors are **pure functions over the analysis result** — they never
touch raw packets — registered in `detection/engine.py` and run in a
loop where a raising detector becomes an internal INFO finding instead
of an abort. Every finding carries: description, evidence list,
plain-English "why it matters", a manual-verification recipe, confidence
(low/medium/high), severity (INFO→CRITICAL), hosts, timestamps, a
Wireshark filter, and MITRE mappings *only where justified*.

Tests enforce two contracts: attacks fire, and benign traffic stays
quiet (`tests/test_detection.py`).

## Behaviors (`behaviors.py`)

**SYN scan.** A source with ≥10 SYN-only flows where fewer than 30% of
its connections complete handshakes. Evidence: distinct ports, example
ports, completion rate, scan window. MITRE T1046/T1595. The inverse
test — a host visiting six real services — does not fire.

**Host sweep.** One source contacting ≥20 distinct destination IPs on
the *same* port (the "one port, many hosts" complement of a port scan).
MITRE T1595.001.

**Risky ports.** Data-bearing conversations on ports associated with
offensive tooling (4444, 31337, 5555, …). Confidence LOW by design —
the finding itself explains that port numbers are weak indicators.

## Beaconing (`beaconing.py`)

For each (src, dst, port): collect connection start times, compute
inter-connection intervals, and measure regularity as the coefficient
of variation `CV = σ/μ`.

| Condition | Severity / confidence |
|---|---|
| ≥8 intervals and CV < 0.30 | HIGH / high |
| CV < 0.55 | MEDIUM / medium |
| CV < 0.90 **and** payload sizes uniform (CV < 0.5) | LOW / low |

The finding prints mean interval, jitter, observation window and size
uniformity, and its explanation explicitly names benign look-alikes
(updaters, NTP, monitoring). The negative tests assert irregular-interval
traffic and short series never fire. DNS variant: same math on query
times per (client, domain).

## DNS hunting (`dnshunt.py`)

**Tunneling** — per base domain, count independent signals:

1. max label length ≥ 32
2. max label entropy ≥ 3.6 bits/char
3. ≥ 25 unique subdomains
4. ≥ 4 TXT responses
5. left-most labels look Base32/Hex-encoded

One signal alone fires nothing (legitimate CDN traffic can trip any
single one); 2 signals → MEDIUM, ≥3 → HIGH. The finding lists example
queries and suggests decoding them — the evidence *is* the explanation.

**NXDOMAIN anomaly** — ≥15 NXDOMAINs and >50% failure rate for one
domain (DGA-style behavior; LOW confidence, correlated with the
querying host's other activity).

**TXT density** — a TXT record ≥60 chars with ≥4.2 bits/char entropy
(encoded-looking, vs. readable `v=spf1 -all`).

## HTTP hunting (`httphunt.py`)

Applies the rules in `signatures/suspicious_http.yaml` (extendable) to
request lines, user-agents, request bodies and response bodies.
Grouping is per rule id; findings quote the matched string and its
location verbatim so context can be judged. The explanation text is
per-kind and always includes the "what would confirm it" test (e.g.
SQLi: look for DB errors in responses). Cleartext HTTP Basic auth is a
standalone finding (observed fact, HIGH confidence); unusual methods
(TRACE/CONNECT/PUT/DELETE) are LOW.

## Misc (`misc.py`)

**ARP conflict** — one IP announced by ≥2 MACs (possible spoofing or
HA failover; MEDIUM confidence on a HIGH-severity lead). **ICMP data
channel** — echo requests ≥16 data bytes (LOW). **Cleartext
credentials** — factual HIGH finding; evidence shows masked passwords
even in verbose output. **Secret material** — private-key blocks
(CRITICAL) and API-key-shaped strings (HIGH/medium) promoted from the
secret scanner. **Bulk transfer** — ≥50 MB internal→external in one
conversation (LOW; volume heuristics are deliberately humble).

## Risk score (`scoring.py`)

```
contribution(f) = severity_weight(f) × confidence_multiplier(f)
                 (CRITICAL 90 · HIGH 65 · MEDIUM 35 · LOW 15 · INFO 0)
                 (high ×1.0 · medium ×0.7 · low ×0.4)
score = strongest + 25% of every other contribution, capped at 100
```

Properties worth stating: one CRITICAL alone scores 90; five LOW/INFOs
together can never reach even 20; a HIGH you only half-trust (medium
confidence) scores less than one you fully trust. The score is a triage
ordering, not a probability — every report says so.
