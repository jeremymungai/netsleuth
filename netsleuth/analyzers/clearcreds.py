"""Cleartext protocol analyzer: credentials, banners, commands, mail data.

These protocols send passwords unencrypted on the wire — that is an
*observed fact* worth reporting (defensively!), and a goldmine in CTF
captures. The analyzer scans the reconstructed client→server byte
stream line by line for authentication commands and records the
server's response verdict where the protocol exposes one.
"""

from __future__ import annotations

import base64
import re

from netsleuth.models import Credential, StreamData

_FTP_PORTS = {21}
_SMTP_PORTS = {25, 587}
_POP3_PORTS = {110}
_IMAP_PORTS = {143}
_TELNET_PORTS = {23}

_FTP_USER = re.compile(rb"^USER (.+)$", re.I)
_FTP_PASS = re.compile(rb"^PASS (.+)$", re.I)
_POP_USER = re.compile(rb"^USER (.+)$", re.I)
_POP_PASS = re.compile(rb"^PASS (.+)$", re.I)
_IMAP_LOGIN = re.compile(rb"^\w+ LOGIN (\S+) (\S+)$", re.I)
_SMTP_AUTH_PLAIN = re.compile(rb"^AUTH PLAIN (\S+)$", re.I)
_SMTP_AUTH_LOGIN = re.compile(rb"^AUTH LOGIN$", re.I)
_SMTP_MAIL_FROM = re.compile(rb"^MAIL FROM:<([^>]*)>", re.I)
_SMTP_RCPT = re.compile(rb"^RCPT TO:<([^>]*)>", re.I)
_HTTP_BASIC = re.compile(rb"Basic ([A-Za-z0-9+/=]{8,})")


def _lines(buf: bytes, limit: int = 2000):
    for raw in buf.split(b"\r\n")[:limit]:
        yield raw.rstrip()


class ClearTextAnalyzer:
    name = "creds"

    def __init__(self) -> None:
        self.credentials: list[Credential] = []
        self.banners: dict[str, str] = {}            # "ip:port" → banner
        self.smtp_traffic: list[dict] = []           # per-stream mail metadata
        self.ftp_commands: list[dict] = []

    def analyze(self, streams: list[StreamData]) -> None:
        for st in streams:
            port = st.info.server_port
            if not st.c2s:
                continue
            if port in _FTP_PORTS:
                self._ftp(st)
            elif port in _SMTP_PORTS:
                self._smtp(st)
            elif port in _POP3_PORTS:
                self._pop3(st)
            elif port in _IMAP_PORTS:
                self._imap(st)
            elif port in _TELNET_PORTS:
                self._telnet(st)
            # SSH banner is server→client and works even with no c2s data
            if port == 22:
                self._ssh_banner(st)
            # HTTP Basic auth anywhere it appears (any port, incl. nonstandard)
            self._http_basic(st)

    # -- protocols -----------------------------------------------------------

    def _ftp(self, st: StreamData) -> None:
        user = pw = ""
        for line in _lines(st.c2s):
            m = _FTP_USER.match(line)
            if m:
                user = m.group(1).decode("latin-1", "replace")
            m = _FTP_PASS.match(line)
            if m:
                pw = m.group(1).decode("latin-1", "replace")
                self.credentials.append(Credential(
                    ts=st.info.start_ts, protocol="ftp", client=st.info.client,
                    server=st.info.server, username=user, password=pw,
                    stream=st.info.index))
            if line.upper().startswith(b"RETR ") or line.upper().startswith(b"STOR "):
                cmd, _, name = line.decode("latin-1", "replace").partition(" ")
                self.ftp_commands.append({
                    "stream": st.info.index, "cmd": cmd.upper(), "filename": name.strip(),
                    "client": st.info.client, "server": st.info.server})
        banner = st.s2c.split(b"\r\n")[0].decode("latin-1", "replace") if st.s2c else ""
        if banner.startswith("220"):
            self.banners[f"{st.info.server}:{st.info.server_port}"] = banner
        if b"230 " in st.s2c or b"230-" in st.s2c:    # login successful
            for c in reversed(self.credentials):
                if c.protocol == "ftp" and c.stream == st.info.index:
                    c.detail = "server accepted login (FTP 230)"
                    break

    def _pop3(self, st: StreamData) -> None:
        user = pw = ""
        for line in _lines(st.c2s):
            m = _POP_USER.match(line)
            if m:
                user = m.group(1).decode("latin-1", "replace")
            m = _POP_PASS.match(line)
            if m:
                pw = m.group(1).decode("latin-1", "replace")
                self.credentials.append(Credential(
                    ts=st.info.start_ts, protocol="pop3", client=st.info.client,
                    server=st.info.server, username=user, password=pw,
                    detail="+OK" if b"+OK" in st.s2c.split(b"\r\n")[-3:] else "",
                    stream=st.info.index))

    def _imap(self, st: StreamData) -> None:
        for line in _lines(st.c2s):
            m = _IMAP_LOGIN.match(line)
            if m:
                self.credentials.append(Credential(
                    ts=st.info.start_ts, protocol="imap", client=st.info.client,
                    server=st.info.server,
                    username=m.group(1).decode("latin-1", "replace"),
                    password=m.group(2).decode("latin-1", "replace"),
                    stream=st.info.index))

    def _smtp(self, st: StreamData) -> None:
        from_addr = ""
        rcpts: list[str] = []
        auth_user = auth_pass = ""
        lines = list(_lines(st.c2s))
        for i, line in enumerate(lines):
            m = _SMTP_MAIL_FROM.match(line)
            if m:
                from_addr = m.group(1).decode("latin-1", "replace")
            m = _SMTP_RCPT.match(line)
            if m:
                rcpts.append(m.group(1).decode("latin-1", "replace"))
            m = _SMTP_AUTH_PLAIN.match(line)
            if m:
                try:
                    dec = base64.b64decode(m.group(1))
                    _z, u, p = dec.split(b"\x00") if dec.count(b"\x00") == 2 else (b"", dec, b"")
                    auth_user = u.decode("latin-1", "replace")
                    auth_pass = p.decode("latin-1", "replace")
                except Exception:
                    pass
            if _SMTP_AUTH_LOGIN.match(line):
                # the next two client lines are base64 user and password
                if i + 2 < len(lines):
                    try:
                        auth_user = base64.b64decode(lines[i + 1]).decode("latin-1", "replace")
                        auth_pass = base64.b64decode(lines[i + 2]).decode("latin-1", "replace")
                    except Exception:
                        pass
        if auth_user or auth_pass:
            self.credentials.append(Credential(
                ts=st.info.start_ts, protocol="smtp", client=st.info.client,
                server=st.info.server, username=auth_user, password=auth_pass,
                kind="auth", stream=st.info.index))
        if from_addr or rcpts:
            self.smtp_traffic.append({
                "stream": st.info.index, "from": from_addr, "to": rcpts,
                "client": st.info.client, "server": st.info.server,
                "has_data": b"\r\n.\r\n" in st.c2s or st.c2s.rstrip().endswith(b"."),
            })

    def _telnet(self, st: StreamData) -> None:
        # telnet credentials require interactive guessing that no offline
        # parser can do reliably — we report the cleartext terminal itself,
        # which the detection layer flags as credential exposure risk.
        self.banners[f"{st.info.server}:{st.info.server_port}"] = "telnet (cleartext terminal)"

    def _ssh_banner(self, st: StreamData) -> None:
        if st.s2c and st.s2c.startswith(b"SSH-"):
            self.banners[f"{st.info.server}:{st.info.server_port}"] = \
                st.s2c.split(b"\r\n")[0].split(b"\n")[0].decode("latin-1", "replace")

    def _http_basic(self, st: StreamData) -> None:
        for line in _lines(st.c2s, 400):
            m = _HTTP_BASIC.search(line)
            if m:
                try:
                    dec = base64.b64decode(m.group(1)).decode("latin-1", "replace")
                    if ":" in dec:
                        u, p = dec.split(":", 1)
                        self.credentials.append(Credential(
                            ts=st.info.start_ts, protocol="http", client=st.info.client,
                            server=st.info.server, username=u, password=p,
                            kind="auth-header", detail="HTTP Basic authentication",
                            stream=st.info.index))
                except Exception:
                    continue
