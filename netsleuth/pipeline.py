"""Analysis pipeline: one streaming pass, then staged finalization.

    capture file ──▶ CaptureReader ──▶ packet analyzers ──▶ stream reassembly
                                                            │
                        ┌───────────────────────────────────┤
                        ▼               ▼                   ▼
                    HTTP analyzer   TLS analyzer     cleartext analyzer
                        │               │                   │
                        ▼               ▼                   ▼
                     carver ────────▶ secret scanner ──▶ detection engine
                                                            │
                                              score · timeline · MITRE ──▶ result

Modules are opt-out via ``Options.modules`` so `netsleuth dns cap.pcap`
only pays for DNS work. The pipeline never loads the whole capture into
memory: packets stream through analyzers, and only reassembled TCP
payloads (bounded) are retained.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional

from netsleuth import capture
from netsleuth.analyzers import (  # noqa: F401  (imported for pipeline stages)
    arp as arp_mod, clearcreds, dhcp as dhcp_mod, dns as dns_mod,
    http as http_mod, icmp as icmp_mod, overview as overview_mod,
    tls as tls_mod,
)
from netsleuth.models import (
    Artifact, CaptureMeta, Credential, Finding, HTTPTransaction, RiskScore,
    SecretMatch, StreamData, StreamInfo, TimelineEvent, TLSSession,
)
from netsleuth.streams import StreamReassembler

ALL_MODULES = {"overview", "dns", "streams", "http", "tls", "creds", "dhcp",
               "arp", "icmp", "extract", "secrets", "detect", "covert"}


@dataclass
class Options:
    """Runtime switches shared by the pipeline stages."""

    max_packets: int = 0
    modules: Optional[set[str]] = None               # None → all
    extract_dir: Optional[str] = None                # where carved files go
    rules_paths: list[str] = field(default_factory=list)
    reveal_secrets: bool = False
    stream_buffer_limit: int = StreamReassembler.DEFAULT_LIMIT
    known_dcs: list[str] = field(default_factory=list)   # --dc overrides

    def wants(self, module: str) -> bool:
        return self.modules is None or module in self.modules


@dataclass
class AnalysisResult:
    meta: CaptureMeta
    overview: Optional[object] = None
    dns: Optional[object] = None
    dhcp: Optional[object] = None
    arp: Optional[object] = None
    icmp: list = field(default_factory=list)
    streams: list[StreamInfo] = field(default_factory=list)
    stream_data: list[StreamData] = field(default_factory=list)   # only when requested
    http: list[HTTPTransaction] = field(default_factory=list)
    tls: list[TLSSession] = field(default_factory=list)
    credentials: list[Credential] = field(default_factory=list)
    banners: dict[str, str] = field(default_factory=dict)
    smtp_traffic: list[dict] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    secrets: list[SecretMatch] = field(default_factory=list)
    covert: list = field(default_factory=list)          # CovertCandidate records
    covert_collector: object = None                     # per-packet metadata collector
    domain_controllers: set[str] = field(default_factory=set)   # auto-detected + --dc
    findings: list[Finding] = field(default_factory=list)
    events: list[TimelineEvent] = field(default_factory=list)
    score: RiskScore = field(default_factory=RiskScore)
    performance: dict = field(default_factory=dict)

    def to_dict(self, reveal_secrets: bool = False,
                include_stream_payloads: bool = False) -> dict:
        d: dict = {"meta": self.meta.to_dict()}
        if self.overview is not None:
            d["overview"] = self.overview.to_dict()
        if self.dns is not None:
            d["dns"] = self.dns.to_dict()
        if self.dhcp is not None:
            d["dhcp"] = [m.to_dict() for m in self.dhcp.messages]
        if self.arp is not None:
            d["arp"] = self.arp.to_dict()
        d["icmp"] = [i.to_dict() for i in self.icmp]
        d["streams"] = [s.to_dict() for s in self.streams]
        if include_stream_payloads:
            d["stream_payloads"] = [
                {"index": s.info.index,
                 "c2s": s.c2s[:65536].decode("latin-1"),
                 "s2c": s.s2c[:65536].decode("latin-1")}
                for s in self.stream_data]
        d["http"] = [t.to_dict() for t in self.http]
        d["tls"] = [t.to_dict() for t in self.tls]
        d["credentials"] = [c.to_dict(reveal=reveal_secrets) for c in self.credentials]
        d["banners"] = dict(self.banners)
        d["smtp"] = self.smtp_traffic
        d["artifacts"] = [a.to_dict() for a in self.artifacts]
        d["secrets"] = [s.to_dict(reveal=reveal_secrets) for s in self.secrets]
        d["covert"] = [c.to_dict() for c in self.covert]
        d["findings"] = [f.to_dict() for f in self.findings]
        d["events"] = [e.to_dict() for e in self.events]
        d["score"] = self.score.to_dict()
        d["performance"] = self.performance
        return d


class Pipeline:
    """Runs the full analysis for one capture file."""

    def __init__(self, path: str, options: Options | None = None):
        self.options = options or Options()
        self.reader = capture.CaptureReader(path, max_packets=self.options.max_packets)
        self.result = AnalysisResult(meta=self.reader.meta)

    def run(self, progress: Optional[Callable[[int], None]] = None) -> AnalysisResult:
        import time
        t0 = time.perf_counter()

        # ---- stage 1: streaming packet pass --------------------------------
        ov = overview_mod.OverviewAnalyzer() if self.options.wants("overview") else None
        dns = dns_mod.DNSAnalyzer() if self.options.wants("dns") else None
        dhcp = dhcp_mod.DHCPAnalyzer() if self.options.wants("dhcp") else None
        arp = arp_mod.ARPAnalyzer() if self.options.wants("arp") else None
        icmp = icmp_mod.ICMPAnalyzer() if self.options.wants("icmp") else None
        from netsleuth.analyzers import covert as covert_mod
        collector = covert_mod.CovertCollector()             if (self.options.wants("detect") or self.options.modules is None
                or "covert" in (self.options.modules or set())) else None
        reasm = StreamReassembler(self.options.stream_buffer_limit) \
            if self.options.wants("streams") or self.options.wants("http") \
            or self.options.wants("tls") or self.options.wants("creds") \
            or self.options.wants("secrets") or self.options.wants("extract") else None

        n = 0
        for pkt in self.reader:
            n += 1
            if ov is not None:
                ov.feed(pkt)
            if dns is not None:
                dns.feed(pkt)
            if dhcp is not None:
                dhcp.feed(pkt)
            if arp is not None:
                arp.feed(pkt)
            if icmp is not None:
                icmp.feed(pkt)
            if collector is not None:
                collector.feed(pkt)
            if reasm is not None:
                reasm.feed(pkt)
            if progress is not None and n % 500 == 0:
                progress(n)
        if progress is not None:
            progress(n)

        if ov is not None:
            self.result.overview = ov.data
        if dns is not None:
            self.result.dns = dns.data
            self._learn_hostnames()
        if dhcp is not None:
            self.result.dhcp = dhcp
        if arp is not None:
            self.result.arp = arp.data
        if icmp is not None:
            self.result.icmp = icmp.observations
        if collector is not None:
            self.result.covert_collector = collector

        # ---- stage 2: stream finalization ----------------------------------
        if reasm is not None:
            stream_data = reasm.finalize()
            self.result.streams = [s.info for s in stream_data]
            self.result.stream_data = stream_data

        # ---- stage 3: stream analyzers --------------------------------------
        if self.options.wants("http"):
            http = http_mod.HTTPAnalyzer()
            http.analyze(self.result.stream_data)
            self.result.http = http.transactions
        if self.options.wants("tls"):
            tls = tls_mod.TLSAnalyzer()
            tls.analyze(self.result.stream_data)
            self.result.tls = tls.sessions
        if self.options.wants("creds"):
            clear = clearcreds.ClearTextAnalyzer()
            clear.analyze(self.result.stream_data)
            self.result.credentials = clear.credentials
            self.result.banners = clear.banners
            self.result.smtp_traffic = clear.smtp_traffic

        # ---- stage 4: extraction --------------------------------------------
        if self.options.wants("extract") and self.options.extract_dir:
            from netsleuth.extraction import carve
            self.result.artifacts = carve.carve_all(
                self.result, self.options.extract_dir)
        if self.options.wants("secrets"):
            from netsleuth.extraction import secrets
            self.result.secrets = secrets.scan(self.result, self.options.rules_paths)

        # ---- stage 5: detection ---------------------------------------------
        if self.options.wants("detect"):
            from netsleuth.covert import analyze_capture
            self.result.covert = analyze_capture(self.result)
            from netsleuth.detection import dcs
            self.result.domain_controllers = \
                dcs.find_domain_controllers(self.result) \
                | set(self.options.known_dcs)
            from netsleuth.detection import engine
            self.result.findings = engine.run_detectors(self.result)
            from netsleuth.detection.scoring import score_findings
            self.result.score = score_findings(self.result.findings)
            from netsleuth.reporting.timeline import build_timeline
            self.result.events = build_timeline(self.result)

        t1 = time.perf_counter()
        self.result.performance = {
            "packets_processed": n,
            "wall_seconds": round(t1 - t0, 3),
            "packets_per_second": int(n / (t1 - t0)) if t1 > t0 else 0,
        }
        return self.result

    def _learn_hostnames(self) -> None:
        """Attach DNS-learned hostnames back onto overview hosts."""
        if self.result.overview is None or self.result.dns is None:
            return
        hosts = self.result.overview.hosts
        for q in self.result.dns.queries:
            if not q.is_response:
                continue
            for ans in q.answers:
                if ans in hosts:
                    hosts[ans].hostnames.add(q.name)
