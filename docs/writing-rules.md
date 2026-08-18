# Writing Detection Rules

Rules are YAML files of named regexes with metadata. Built-ins live in
`netsleuth/signatures/`; yours load with `--rules` (a file **or** a
directory of `*.yaml`). Same-id rules override built-ins, so tuning
beats forking.

## File format

```yaml
rules:
  - id: my.company.flag          # unique; your file's stem is prepended
    kind: flag                   # category shown to the analyst
    pattern: 'MYCTF\{[!-~]{4,}\}'  # Python re syntax, MULTILINE
    confidence: high             # low | medium | high
    score: 100                   # ranking weight (optional)
    description: company CTF flag format   # optional
```

The named group `(?P<value>…)` controls what is captured; otherwise the
whole match is reported.

## Where rules run

Streams (both directions, 2 MiB window), HTTP request lines / headers /
bodies, DNS TXT values, and ICMP payloads. Hits record their source
("TCP stream 12 (server→client, port 80)", "HTTP query string: …") and
a `how` receipt with a follow-up hint.

## The two quoting rules that matter

YAML single-quoted strings don't process backslashes (good for regex)
but cannot contain a literal `'`; double-quoted strings eat `\b`, `\s`
as YAML escapes (broken for regex). Therefore:

1. Wrap patterns in **single quotes**.
2. Use `\x27` / `\x22` for quote characters inside the regex — never
   literal `'` or `"`.

## Performance guidance

Python's `re` has no timeout; a catastrophic pattern on a 2 MiB stream
can hang the scan. Safe habits:

- Anchor or bound repetitions: `[!-~]{4,64}` not `.*` after a keyword.
- Avoid nested quantifiers over overlapping alphabets
  (`(a+)+` is the classic hang).
- Test on a large stream before shipping:
  `time netsleuth secrets big.pcap --rules my.yaml` — if it takes
  seconds instead of milliseconds, tighten the pattern.

## Examples

Flag for a specific event:

```yaml
rules:
  - id: myctf-2026
    kind: flag
    pattern: '(?P<value>MyCTF2026\{[A-Za-z0-9_]{6,40}\})'
    confidence: high
    score: 100
```

Internal indicator (domain + secret variable dump):

```yaml
rules:
  - id: corp.internal-domains
    kind: internal-domain
    pattern: '\b(?:corp|intranet|vpn)\.mycompany\.example\b'
    confidence: medium
    score: 25
  - id: corp.env-dump
    kind: env-secret
    pattern: '\bSTRIPE_(?:SECRET_)?KEY\s*=\s*sk_(?:test|live)_[0-9a-zA-Z]{16,}'
    confidence: high
    score: 95
```

Overriding a built-in (same id after namespacing — see
`netsleuth/rules.py` for the exact override key format):

```yaml
rules:
  - id: ctf.flag.named           # your file named custom.yaml → custom.ctf.flag.named
    kind: flag
    pattern: 'ONLYOURCTF\{[^}]{4,}\}'
```

> Note: overrides key on the *namespaced* id; check
> `rules.load_rules` docstring for the current scheme before relying on
> built-in replacement, or simply give your replacement a new id and
> disable the old behavior by out-ranking it (`score`).
