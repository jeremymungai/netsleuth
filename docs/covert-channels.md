# Covert Channels in Protocol Metadata — concepts and the NetSleuth engine

## What a covert channel is

A covert channel moves information through a mechanism that was never
meant to carry data. Instead of hiding a message *in* a payload (a file,
an HTTP body), the sender hides it in *how* the protocol behaves: which
of two legal values a field takes, packet by packet.

The classic teaching example is the one NetSleuth ships as a demo:
ordinary HTTP shopping requests, where the **HTTP version token** of
each request is chosen to be `HTTP/1.0` or `HTTP/1.1` according to one
bit of the hidden message. Every single packet is completely legal.
Proxy logs look normal. Only the *sequence* of choices leaks data.

## Why metadata channels evade casual inspection

- Each message is individually valid — nothing anomalous per-packet.
- The fields involved (version, query type, TTL, IP ID, port) are
  rarely examined, and their legitimate variation is expected.
- The bandwidth is tiny (1 bit per message), so exfiltrating a secret
  takes many messages — but a password or flag fits in a few hundred.

That's also the weakness you exploit when hunting them: a *real*
message has structure (printable ASCII, recognizable words), while
natural variation decodes to noise. The engine leans on exactly that.

## How the engine works

```
field extractors → per-(source, field) value sequences
      ↓
variation analysis: cardinality, transition ratio, run lengths
      ↓  (interesting = small alphabet + active switching + enough symbols)
symbolic mapping: A→0/B→1 (and the inverse); 4/8/16-value alphabets get
  k-bit codes in first-appearance and frequency order
      ↓
bitstream → bytes: MSB/LSB bit order × leading/trailing remainder drop
      ↓
scoring: printable ratio + word hits; degenerate outputs (all 0x55
  from sequential IP IDs) are penalized; short outputs need ~perfect
  printability (random bits easily fake 85% on 7 bytes)
      ↓
CovertCandidate with every assumption recorded — or silence
```

Key honesty rules, enforced in code and tests:

- **Structured variation that decodes to noise is not reported.** A
  field alternating beautifully is an observation; a *channel* claim
  needs decoded structure.
- **Benign generators are recognized.** Sequential IP IDs (Linux,
  scapy) alternate parity perfectly and decode to `UUUU…` — the
  extractor skips monotone ID sequences, and the scorer penalizes
  degenerate all-same-byte outputs.
- **The expected message is never hard-coded** anywhere in the engine —
  only in the tests and the demo generator's ground truth.

## What gets extracted

| Protocol | Fields (per source host, chronological) |
|---|---|
| HTTP | request version, method, response status, User-Agent, Host, first cookie name, request header count, body-length class |
| DNS | query type, label count, name-length class, response TTL class |
| TCP/IP | destination port, TCP flag set, frame-length class, IP ID parity, IP TTL |

Adding a field is one function + one line in `netsleuth/covert/fields.py`
— the variation/decoding machinery is field-agnostic by design.

## Using it

```bash
python examples/generate_covert.py              # synthetic channel demo
python -m netsleuth covert examples/covert.pcap # full derivation
python -m netsleuth ctf any.pcap                # covert phase included
python -m netsleuth detect any.pcap             # candidates → findings
```

JSON via `--json`; every candidate carries field, values, sequence,
mapping, bit/byte counts, decoded preview, printable ratio,
confidence, packet frames (when available), assumptions, the mappings
that were tried and rejected, and the Wireshark filter reproducing the
extraction — e.g. `http.request && ip.src == 192.168.1.50`, then read
the version token of each request in order and decode 8 bits per byte
yourself. That manual reproduction is the point: the engine shows its
work so you can check it.

## Recovering a channel by hand (the workflow the engine automates)

1. Filter Wireshark to the suspicious host's protocol traffic.
2. Read the suspect field of each message, in order → a value sequence.
3. Assign symbols (A=0, B=1 — or the inverse) and write the bitstring.
4. Group 8 bits per byte (try MSB-first; if garbage, LSB-first).
5. Decode as ASCII. Printable text → you likely have a message.
6. Sanity-check: could a benign cause (client pool, load balancer,
   sequential IDs) produce the same pattern? The engine's assumptions
   list and alternatives-considered field exist for this step.

## Limitations (stated plainly)

- Detection requires **repetition**: ≥16 observations of a field, and
  enough bits to decode (≥2 bytes). One-shot channels are invisible.
- Higher-radix channels (4/8/16 symbols) are decoded only with
  power-of-two alphabets in simple orders; exotic orderings are not
  searched.
- Timing channels (inter-packet delays) are handled by the *beaconing*
  detector's interval statistics, not by this engine.
- A candidate is a derivation, not a verdict: natural traffic can
  occasionally produce structured-looking decodes. The confidence
  level and assumptions are part of the finding; treat them as the
  starting point of an investigation, like every NetSleuth finding.
