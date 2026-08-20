"""Field extractors: turn an analysis result into named field streams.

Each extractor produces ``FieldStream`` records — one per (source host,
field name) — with the chronological value sequence and the Wireshark
filter that reproduces it. Extractors are registered in EXTRATRACTORS;
adding coverage for a new protocol or field is a new function plus one
registry line (see docs/covert-channels.md).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from netsleuth.models import Packet


@dataclass
class FieldObs:
    value: str
    ts: float
    frame: int                       # 0 when only stream-level refs exist


@dataclass
class FieldStream:
    protocol: str
    field: str
    source: str                      # originating host
    values: list[FieldObs] = field(default_factory=list)
    wireshark_filter: str = ""
    how_extracted: str = ""          # human explanation of the extraction

    @property
    def value_list(self) -> list[str]:
        return [o.value for o in self.values]


def _http_fields(result) -> list[FieldStream]:
    """Metadata fields of repeated HTTP requests/responses, per client."""
    streams: dict[tuple, FieldStream] = {}

    def fs(field: str, client: str, values, flt: str, how: str) -> FieldStream:
        key = (field, client)
        if key not in streams:
            streams[key] = FieldStream(protocol="http", field=field, source=client,
                                       wireshark_filter=flt, how_extracted=how)
        return streams[key]

    base = "http.request && ip.addr == {c}"
    for t in result.http:
        c = t.client or "?"
        fs("request version", c, [], base.format(c=c).replace("ip.addr", "ip.src"),
           "the HTTP/x.y token on each request line, in stream order").values.append(
            FieldObs(t.version, t.ts or 0.0, 0))
        fs("request method", c, [], f"http.request.method && ip.src == {c}",
           "the method token of each request").values.append(
            FieldObs(t.method, t.ts or 0.0, 0))
        fs("response status code", c, [],
           f"http.response && tcp.stream == {t.stream}",
           "the numeric status of each response paired to this client's requests"
           ).values.append(FieldObs(str(t.status), t.ts or 0.0, 0))
        if t.user_agent:
            fs("User-Agent", c, [], f"http.user_agent && ip.src == {c}",
               "the full User-Agent string of each request").values.append(
                FieldObs(t.user_agent, t.ts or 0.0, 0))
        fs("Host header", c, [], f"http.host && ip.src == {c}",
           "the Host header of each request").values.append(
            FieldObs(t.host, t.ts or 0.0, 0))
        fs("request header count", c, [], f"http.request && ip.src == {c}",
           "number of headers per request").values.append(
            FieldObs(str(t.header_count), t.ts or 0.0, 0))
        if t.cookies:
            first = t.cookies.split("=", 1)[0].strip()
            fs("first cookie name", c, [], f"http.cookie && ip.src == {c}",
               "name of the first cookie sent (cookies often carry state "
               "choices)").values.append(FieldObs(first, t.ts or 0.0, 0))
        cl = t.req_body_len if t.method in ("POST", "PUT") else max(t.resp_body_len, 0)
        fs("body length class", c, [], f"http && ip.src == {c}",
           "zero/nonzero/tens/hundreds… bucket of body sizes").values.append(
            FieldObs(_len_class(cl), t.ts or 0.0, 0))
    return list(streams.values())


def _len_class(n: int) -> str:
    if n == 0:
        return "0"
    if n < 10:
        return "1-9"
    if n < 100:
        return "10-99"
    if n < 1000:
        return "100-999"
    return "1000+"


def _dns_fields(result) -> list[FieldStream]:
    if result.dns is None:
        return []
    streams: dict[tuple, FieldStream] = {}

    def fs(field: str, client: str, flt: str, how: str) -> FieldStream:
        key = (field, client)
        if key not in streams:
            streams[key] = FieldStream(protocol="dns", field=field, source=client,
                                       wireshark_filter=flt, how_extracted=how)
        return streams[key]

    for q in result.dns.queries:
        c = q.client
        flt = f'dns.flags.response == 0 && ip.src == {c}'
        fs("query type", c, flt,
           "the QTYPE (A, TXT, MX…) chosen for each query").values.append(
            FieldObs(q.qtype, q.ts, q.frame))
        labels = q.name.rstrip(".").split(".") if q.name else []
        fs("label count", c, flt,
           "number of dot-separated labels per queried name").values.append(
            FieldObs(str(len(labels)), q.ts, q.frame))
        fs("name length class", c, flt,
           "bucketed length of the queried name").values.append(
            FieldObs(_len_class(len(q.name)), q.ts, q.frame))
        if q.is_response:
            fs("response TTL class", q.client,
               "dns.flags.response == 1 && ip.src == " + q.server,
               "bucketed TTL of answers (classic low-bandwidth channel)").values.append(
                FieldObs(_ttl_class(q.ttl), q.ts, q.frame))
    return list(streams.values())


def _ttl_class(ttl: int) -> str:
    if ttl == 0:
        return "0"
    if ttl < 64:
        return "1-63"
    if ttl < 128:
        return "64-127"
    if ttl < 256:
        return "128-255"
    return "256+"


def _tcp_ip_fields(collector, internal_ips: set[str] | None = None) -> list[FieldStream]:
    """Per-source TCP/IP metadata streams from the packet collector.

    TCP flags and IP ID/TTL are chosen by the sender's *kernel*, not by
    an application, so for external sources (CDNs, cloud front-ends) they
    are artifacts of that server's OS stack — an internal attacker
    cannot encode anything in them. Those fields are only analyzed for
    internal sources, where a compromised host could plausibly craft
    them.
    """
    internal_ips = internal_ips or set()
    out: list[FieldStream] = []

    def mk(field: str, src: str, values, flt: str, how: str) -> None:
        out.append(FieldStream(protocol="tcp", field=field, source=src,
                               values=values, wireshark_filter=flt,
                               how_extracted=how))

    for src, obs in collector.seqs.items():
        if internal_ips and src not in internal_ips:
            continue                        # external source: skip stack-owned fields
        tcp_obs = [o for o in obs if o.flags]
        if len(tcp_obs) >= 16:
            mk("destination port", src,
               [FieldObs(str(o.dport), o.ts, o.frame) for o in tcp_obs],
               f"ip.src == {src} && tcp",
               "destination port of each outbound TCP packet "
               "(port-knocking-style selection)")
            mk("TCP flag set", src,
               [FieldObs(o.flags, o.ts, o.frame) for o in tcp_obs],
               f"ip.src == {src} && tcp.flags",
               "TCP flag combination of each packet")
            mk("frame length class", src,
               [FieldObs(_len_class(o.length), o.ts, o.frame) for o in tcp_obs],
               f"ip.src == {src} && tcp",
               "bucketed packet size (size modulation channel)")
        ids = [o for o in obs if o.ip_id >= 0]
        if len(ids) >= 16 and not _sequential([o.ip_id for o in ids]):
            mk("IP ID parity", src,
               [FieldObs(str(o.ip_id & 1), o.ts, o.frame) for o in ids],
               f"ip.src == {src}",
               "low bit of the IPv4 identification field "
               "(a textbook covert channel)")
        ttls = [o for o in obs if o.ip_ttl > 0]
        if len(ttls) >= 16 and len({o.ip_ttl for o in ttls}) <= 8:
            mk("IP TTL", src,
               [FieldObs(str(o.ip_ttl), o.ts, o.frame) for o in ttls],
               f"ip.src == {src}",
               "IPv4 time-to-live value per packet (TTL is writable by "
               "any sender and rarely inspected)")
    return out


def _sequential(values: list[int], tolerance: float = 0.9) -> bool:
    """True when values mostly increment by a constant step (e.g. +1).

    Sequentially-assigned IP IDs (Linux, scapy) produce perfectly
    alternating parity — a benign generator that must not be reported
    as a covert channel just because it decodes to 'UUU…'.
    """
    if len(values) < 4:
        return False
    for step in (1, 2, 256):
        hits = sum(1 for a, b in zip(values, values[1:])
                   if 0 < b - a <= step)
        if hits / (len(values) - 1) >= tolerance:
            return True
    return False


def _internal_ips(result) -> set[str]:
    """Internal (RFC1918/link-local/ULA) addresses seen in the capture."""
    ov = getattr(result, "overview", None)
    hosts = getattr(ov, "hosts", None) or {}
    return {ip for ip, h in hosts.items() if h.is_internal}


def extract_all(result) -> list[FieldStream]:
    streams: list[FieldStream] = []
    streams += _http_fields(result)
    streams += _dns_fields(result)
    collector = getattr(result, "covert_collector", None)
    if collector is not None:
        streams += _tcp_ip_fields(collector, _internal_ips(result))
    return streams
