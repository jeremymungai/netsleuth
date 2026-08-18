"""HTTP-layer hunt: attack patterns, cleartext auth, odd methods.

Patterns come from signatures/suspicious_http.yaml (user-extendable).
A keyword never condemns traffic on its own — findings quote the exact
matched string and its location so the analyst judges context.
"""

from __future__ import annotations

from netsleuth import rules as rules_mod
from netsleuth.enrichment.mitre import mitre
from netsleuth.models import Confidence, Finding, Severity

_KIND_MITRE = {
    "traversal": ("T1083", "path traversal attempting to reach files "
                           "outside the web root"),
    "command-injection": ("T1059.004", "shell metacharacters followed by a "
                                       "shell command in an HTTP request"),
    "sql-injection": ("T1190", "SQL syntax in parameters typical of "
                               "injection probing"),
    "webshell": ("T1505.003", "request parameters executed as server-side code"),
    "upload": ("T1105", "transfer of executable content to a server"),
    "user-agent": ("T1071.001", "user-agent string of known attack tooling"),
}


def detect_attack_patterns(result) -> list[Finding]:
    rulebook = rules_mod.load_rules()
    http_rules = {r.id: r for r in rulebook.values() if r.id.startswith("http.")}
    hits: dict[str, list[tuple] ] = {}
    for t in result.http:
        surfaces = [(f"{t.method} {t.host}{t.url}", "request line"),
                    (t.user_agent, "User-Agent header")]
        if t.req_body:
            surfaces.append((t.req_body.decode("latin-1"), "request body"))
        if t.resp_body:
            surfaces.append((t.resp_body[:65536].decode("latin-1"), "response body"))
        for text, where in surfaces:
            for rule in http_rules.values():
                for m in rule.regex.finditer(text):
                    hits.setdefault(rule.id, []).append(
                        (t, where, m.group(0)[:160]))
    findings = []
    for rid, matches in hits.items():
        rule = http_rules[rid]
        kind = rule.kind
        severity = Severity.HIGH if kind in ("webshell", "command-injection",
                                             "sql-injection") else Severity.MEDIUM
        t0 = matches[0][0]
        sample = matches[0][2]
        uniq_urls = []
        for t, where, snip in matches:
            url = f"{t.method} {t.host}{t.path}"
            if url not in uniq_urls:
                uniq_urls.append(url)
        finding = Finding(
            id=f"http.{rid}",
            title=f"{kind.replace('-', ' ').title()} pattern in HTTP traffic",
            severity=severity,
            confidence=Confidence.HIGH if rule.confidence == "high" else Confidence.MEDIUM,
            description=(f"{len(matches)} match(es) of '{rid}' across "
                         f"{len(uniq_urls)} request(s); e.g. {sample!r} in "
                         f"{matches[0][1]} of {t0.method} {t0.host}{t0.path}"),
            explanation=(
                {
                    "traversal": "Repeated ../ sequences (raw or encoded) try to "
                                 "walk out of a web root and read system files. "
                                 "Some apps use them legitimately in URLs — "
                                 "check whether files were actually returned "
                                 "(look for 200 responses with file content).",
                    "command-injection": "Shell metacharacters followed by a "
                                         "command name in a parameter is the "
                                         "classic injection probe. Confirm by "
                                         "checking the response body for command "
                                         "output (uid=, directories, errors).",
                    "sql-injection": "SQL control tokens in parameters suggest "
                                     "injection testing. Look for database "
                                     "errors in responses — those confirm the "
                                     "backend processed the input.",
                    "xss": "Script-bearing parameters are XSS probes. Risk "
                           "depends on whether responses reflect them.",
                    "webshell": "Parameters being passed to system()/eval()-"
                                "style calls, or cmd=/bin/sh patterns, are the "
                                "signature of web shell traffic. Treat any "
                                "200-response as strong confirmation and hunt "
                                "for the shell file in uploads.",
                    "upload": "An uploaded file with a server-executable "
                              "extension (php/jsp/asp…) is how web shells get "
                              "placed. Cross-check subsequent requests to the "
                              "uploaded filename.",
                    "user-agent": "The client announced itself as known attack "
                                  "tooling. Some tools allow UA spoofing, so "
                                  "pair this with behavior, not the string alone.",
                }.get(kind, "Rule matched; inspect the quoted evidence in context.")),
            verification=(f'In Wireshark: http.request contains "{sample[:30]}" '
                          "or filter by the affected host, then examine both "
                          "request and response (Follow TCP Stream)."),
            evidence=[f"{w}: {snip!r}" for _t, w, snip in matches[:6]],
            hosts=sorted({t.client for t, _w, _s in matches} |
                         {t.host for t, _w, _s in matches if t.host}),
            protocol="http",
            first_ts=min((t.ts for t, _w, _s in matches if t.ts), default=None),
            wireshark_filters=[f'http.host == "{t0.host}"'] if t0.host else [],
            mitre=([mitre(*_KIND_MITRE[kind])] if kind in _KIND_MITRE else []),
        )
        findings.append(finding)
    return findings[:12]


def detect_cleartext_http_auth(result) -> list[Finding]:
    basics = [c for c in result.credentials if c.kind == "auth-header"]
    if not basics:
        return []
    c = basics[0]
    return [Finding(
        id="http.basic-auth-cleartext",
        title=f"HTTP Basic authentication sent in cleartext ({len(basics)} request(s))",
        severity=Severity.MEDIUM,
        confidence=Confidence.HIGH,
        description=(f"{c.client} sent Base64-encoded credentials to "
                     f"{c.server} over unencrypted HTTP."),
        explanation=(
            "HTTP Basic auth is username:password Base64-encoded — which is "
            "not encryption. Anyone on the path (or holding this capture) "
            "recovers the credentials by simply decoding the header. If this "
            "is your traffic, move the service behind TLS."),
        verification='In Wireshark: http.authorization matches "Basic" — '
                     "right-click the Authorization header value → Decode As "
                     "Base64, or run: netsleuth secrets <capture>",
        evidence=[f"Authorization: Basic … on stream {c.stream}"
                  for c in basics[:5]],
        hosts=[c.client, c.server],
        protocol="http",
        first_ts=c.ts,
        wireshark_filters=['http.authorization matches "Basic"'],
        mitre=[mitre("T1552.001", "credentials recoverable in cleartext from "
                                  "the capture")],
    )]


def detect_unusual_methods(result) -> list[Finding]:
    odd = [t for t in result.http if t.method in ("TRACE", "CONNECT", "TRACK",
                                                  "PUT", "DELETE", "PATCH")]
    if not odd:
        return []
    methods = sorted({t.method for t in odd})
    t0 = odd[0]
    return [Finding(
        id="http.unusual-methods",
        title=f"Uncommon HTTP methods used: {', '.join(methods)}",
        severity=Severity.LOW,
        confidence=Confidence.MEDIUM,
        description=(f"{len(odd)} request(s) used methods outside the usual "
                     f"GET/POST set."),
        explanation=(
            "TRACE can reflect credentials (XST), CONNECT proxies tunnels, "
            "and PUT/DELETE on unexpected endpoints often means someone is "
            "probing an API or trying to plant content. REST APIs use these "
            "methods legitimately — context decides."),
        verification=f"In Wireshark: http.request.method in {{{' '.join(methods)}}}",
        evidence=[f"{t.method} {t.host}{t.path} (status {t.status})"
                  for t in odd[:6]],
        hosts=sorted({t.client for t in odd} | {t.host for t in odd if t.host}),
        protocol="http",
        first_ts=min((t.ts for t in odd if t.ts), default=None),
        wireshark_filters=["http.request.method in "
                           f"{{{' '.join(methods)}}}"],
    )]
