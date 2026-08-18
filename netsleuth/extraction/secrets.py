"""Secret / flag / interesting-data scanner.

Applies the rule set (built-in signatures + user rules + CLI --pattern)
to every place evidence hides in a capture:

* reconstructed TCP streams (both directions)
* HTTP request lines, queries, headers, request bodies, response bodies
* DNS TXT records
* ICMP echo payloads
* DHCP hostnames

Every hit records *where* it came from and *how* it was found — the CTF
mode's whole point is teaching where the evidence lives.
"""

from __future__ import annotations

from netsleuth import rules as rules_mod
from netsleuth.models import SecretMatch

MAX_SCAN_BYTES_PER_STREAM = 2 * 1024 * 1024        # 2 MiB scan window per direction
MAX_MATCHES = 500

_KIND_WEIGHT = {"flag": 0, "key-material": 1, "api-key": 2, "password": 3,
                "credential-uri": 4, "auth-header": 5, "token": 6,
                "session-id": 7, "command": 8, "env-secret": 9,
                "cryptocurrency": 10, "url": 11, "email": 12, "ip": 13,
                "custom": 5}


def scan(result, rules_paths: list[str] | None = None,
         extra_rule: rules_mod.Rule | None = None) -> list[SecretMatch]:
    rulebook = rules_mod.load_rules(rules_paths)
    if extra_rule is not None:
        rulebook[extra_rule.id] = extra_rule

    matches: list[SecretMatch] = []
    seen: dict[tuple[str, str], SecretMatch] = {}

    def hit(rule: rules_mod.Rule, value: str, source: str, protocol: str = "",
            ts=None, stream: int = -1, hosts=(), how: str = "") -> None:
        key = (rule.kind, value)
        if key in seen:
            return
        m = SecretMatch(kind=rule.kind, value=value, source=source,
                        protocol=protocol, ts=ts, stream=stream,
                        hosts=list(hosts), confidence=rule.confidence,
                        how=how or f"matched rule '{rule.id}' ({rule.kind})")
        seen[key] = m
        matches.append(m)

    # ---- TCP streams --------------------------------------------------------
    for st in result.stream_data:
        for direction, label in ((st.c2s, "client→server"), (st.s2c, "server→client")):
            window = direction[:MAX_SCAN_BYTES_PER_STREAM]
            if not window:
                continue
            text = window.decode("latin-1")
            hosts = [st.info.client, st.info.server]
            for rule in rulebook.values():
                for m in rule.regex.finditer(text):
                    value = (m.groupdict().get("value") or m.group(0))[:512]
                    hit(rule, value,
                        source=f"TCP stream {st.info.index} ({label}, port {st.info.server_port})",
                        protocol="tcp", ts=st.info.start_ts, stream=st.info.index,
                        hosts=hosts,
                        how=f"regex '{rule.id}' matched in reassembled stream "
                            f"({label}); open with: netsleuth stream {st.info.index}")

    # ---- HTTP metadata + bodies ---------------------------------------------
    for t in result.http:
        fields = [
            (f"{t.method} {t.host}{t.url}", "HTTP request line"),
            (t.user_agent, "HTTP User-Agent"),
            (t.auth_header, "HTTP Authorization header"),
            (t.cookies, "HTTP Cookie header"),
            (t.query, "HTTP query string"),
        ]
        if t.req_body:
            fields.append((t.req_body.decode("latin-1"), "HTTP request body"))
        if t.resp_body:
            fields.append((t.resp_body[:MAX_SCAN_BYTES_PER_STREAM].decode("latin-1"),
                           "HTTP response body"))
        hosts = [t.client, t.host or "?"]
        for text, where in fields:
            for rule in rulebook.values():
                for m in rule.regex.finditer(text):
                    value = (m.groupdict().get("value") or m.group(0))[:512]
                    hit(rule, value, source=f"{where}: {t.method} {t.host}{t.path}",
                        protocol="http", ts=t.ts, stream=t.stream, hosts=hosts,
                        how=f"regex '{rule.id}' matched in {where.lower()}; "
                            f"Wireshark: http.host == \"{t.host}\"")

    # ---- DNS TXT records ------------------------------------------------------
    if result.dns is not None:
        for q in result.dns.queries:
            if q.answer_type != "TXT":
                continue
            for val in q.answers:
                for rule in rulebook.values():
                    if rule.regex.search(val):
                        hit(rule, val[:512],
                            source=f"DNS TXT record for {q.name}",
                            protocol="dns", ts=q.ts, hosts=[q.client, q.server],
                            how=f"regex '{rule.id}' matched a TXT record; "
                                f"Wireshark: dns.txt contains \"{val[:40]}\"")

    # ---- ICMP payloads --------------------------------------------------------
    for obs in result.icmp:
        text = obs.payload.decode("latin-1")
        for rule in rulebook.values():
            for m in rule.regex.finditer(text):
                value = (m.groupdict().get("value") or m.group(0))[:512]
                hit(rule, value, source=f"ICMP {obs.icmp_type} {obs.src} → {obs.dst}",
                    protocol="icmp", ts=obs.ts, hosts=[obs.src, obs.dst],
                    how=f"regex '{rule.id}' matched ICMP echo payload; "
                        f"Wireshark: icmp && ip.addr == {obs.src}")

    matches.sort(key=lambda m: (_KIND_WEIGHT.get(m.kind, 50),
                                -len(m.value), m.source))
    return matches[:MAX_MATCHES]
