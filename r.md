# NetSleuth Analysis Report

**Capture:** `C:\Users\hp\OneDrive\Documents\Wubba lubba dub dub\netsleuth\examples\demo.pcap`  
**Generated:** 2026-08-18 12:37 UTC  
**Risk score:** 100/100 (critical)

## Executive summary

- Capture contains **234 packets** over 940.1s (28.0 KB, pcap).
- **5 hosts** observed; 1 external.
- **8 finding(s)**, including 4 high/critical — see [Suspicious activity](#suspicious-activity).
- 2 interesting strings/secrets matched (see [Secrets](#secrets--flags)).

## Capture overview

| Field | Value |
|---|---|
| File | `C:\Users\hp\OneDrive\Documents\Wubba lubba dub dub\netsleuth\examples\demo.pcap` |
| Format | pcap |
| Size | 28.0 KB |
| Packets | 234 |
| First packet | 2025-08-17 23:20:00.000+00:00 |
| Last packet | 2025-08-17 23:35:40.069+00:00 |
| Duration | 940.070s |
| Link type | Ethernet |

> note: format detail: little-endian, microsecond

## Hosts

| IP | Network | Hostnames | Sent | Received |
|---|---|---|---|---|
| 192.168.1.50 | private | — | 11.6 KB | 12.8 KB |
| 198.51.100.66 | private | — | 1.7 KB | 3.0 KB |
| 203.0.113.66 | private | — | 4.7 KB | 733 B |
| 203.0.113.9 | private | files.example.com | 633 B | 4.4 KB |
| 8.8.8.8 | public | — | 5.8 KB | 3.4 KB |

### Top conversations

| A | B | Port | Proto | Packets | Bytes |
|---|---|---|---|---|---|
| 192.168.1.50 | 8.8.8.8 | 53 | udp | 62 | 6.7 KB |
| 192.168.1.50 | 203.0.113.66 | 80 | tcp | 10 | 4.2 KB |
| 192.168.1.50 | 203.0.113.66 | 80 | tcp | 8 | 283 B |
| 192.168.1.50 | 203.0.113.9 | 80 | tcp | 8 | 206 B |
| 192.168.1.50 | 203.0.113.9 | 21 | tcp | 8 | 142 B |
| 192.168.1.50 | 198.51.100.66 | 4444 | tcp | 5 | 84 B |
| 192.168.1.50 | 198.51.100.66 | 4444 | tcp | 5 | 84 B |
| 192.168.1.50 | 198.51.100.66 | 4444 | tcp | 5 | 84 B |
| 192.168.1.50 | 198.51.100.66 | 4444 | tcp | 5 | 84 B |
| 192.168.1.50 | 198.51.100.66 | 4444 | tcp | 5 | 84 B |
| 192.168.1.50 | 198.51.100.66 | 4444 | tcp | 5 | 84 B |
| 192.168.1.50 | 198.51.100.66 | 4444 | tcp | 5 | 84 B |

## DNS findings

31 queries, 31 responses, 0 NXDOMAIN, 30 TXT records.

| Domain | Queries | NX | Subdomains | Resolved | Max label/entropy |
|---|---|---|---|---|---|
| c2bad.example | 30 | 0 | 30 | — | 39 ch / 4.5 bpc |
| example.com | 1 | 0 | 1 | 203.0.113.9 | 7 ch / 0.0 bpc |

## HTTP findings

| Time | Method | Host + path | Status | Type | Bytes |
|---|---|---|---|---|---|
| 23:20:00 | GET | files.example.com/index.html | 200 | text/html | 44 |
| 23:34:35 | GET | bad.example/uploads/shell.php | 200 | text/html | 117 |
| 23:35:05 | GET | bad.example/payload/dropper.bin | 200 | application/octet-stream | 4098 |

## Cleartext credentials

| Time | Protocol | Client | Server | Username | Password |
|---|---|---|---|---|---|
| 23:21:02 | ftp | 192.168.1.50 | 203.0.113.9 | backup_admin | `S…! (11 chars)` |

> Passwords are masked in reports. Use `netsleuth secrets <pcap> --reveal` for the values.

## Covert-channel candidates

### TCP TCP flag set — 198.51.100.66 (confidence: medium)

- **Observed values:** `SA` ×12, `PA` ×12
- **Pattern:** two-state repeated sequence
- **Mapping:** SA→0, PA→1
- **Bitstream:** 24 bits → 3 bytes
- **Decoded:** `UUU`
- **Printable ratio:** 100%
- **Wireshark:** `ip.src == 198.51.100.66 && tcp.flags`

Assumptions:
- observations are ordered by time and belong to source 198.51.100.66
- the TCP flag set field is freely choosable by the sender
- symbols were mapped as SA→0, PA→1 and grouped 8 bits per byte (msb-first, dropping trailing remainder bits)
- only the best of all tried mappings is shown; the rest may also be meaningful

> Candidates are derivations, not verdicts — see `docs/covert-channels.md`.

## Suspicious activity

### [HIGH] Periodic connections: 192.168.1.50 → 198.51.100.66:4444 (12 connections, ~60.0s interval)  
_confidence: high_

192.168.1.50 connected to 198.51.100.66:4444 12 times with a mean interval of 60.0s and low timing variance (CV=0.00).

**Evidence:**
- connections: 12
- mean interval: 60.0s (jitter stddev 0.00s, CV 0.00)
- observation window: 660s (≈ 11 intervals)
- payload size uniformity: CV 0.00 across 12 data-bearing connections (sizes highly uniform)

**Why it matters:** Malware check-ins are often timer-driven, so their connection intervals are far more regular than human-driven traffic. BUT: software updaters, NTP clients, monitoring agents and messaging apps also produce regular traffic. This is an indicator to investigate, not evidence of compromise on its own. Check the destination's reputation and the stream content.

**MITRE ATT&CK:** `T1095` Non-Application Layer Protocol — regularly-timed repeated connections consistent with a C2 check-in schedule

**Wireshark:** `ip.addr == 198.51.100.66 && tcp.port == 4444`

**Verify manually:** In Wireshark: ip.addr == 198.51.100.66 && tcp.port == 4444 — look at the time column (Δtime) between connections.

### [HIGH] Cleartext FTP credentials observed (1 login(s))  
_confidence: high_

192.168.1.50 authenticated to 203.0.113.9 over unencrypted FTP; the capture contains the username and password in plaintext.

**Evidence:**
- ftp: user='backup_admin' password=S…! (11 chars)

**Why it matters:** FTP/SMTP/IMAP/POP3/telnet (and HTTP Basic) send credentials without encryption. This is an observed fact, not an inference: anyone with this capture can read them. If this is your own traffic, treat those passwords as compromised and move the protocol to its TLS variant (FTPS/SMTPS/IMAPS/HTTPS).

**MITRE ATT&CK:** `T1552.001` Unsecured Credentials: Credentials In Files — credentials readable in cleartext network traffic

**Wireshark:** `tcp.stream == 71`

**Verify manually:** In Wireshark: right-click any FTP packet → Follow → TCP Stream (tcp.stream == 71) — the USER/PASS lines are visible in the reassembled conversation.

### [HIGH] Possible DNS tunneling via c2bad.example  
_confidence: high_

30 queries to *.c2bad.example show unusually long labels (max 39 chars; normal hostnames rarely exceed ~25); high-entropy labels (max 4.529 bits/char — consistent with encoded data, not words); 30 unique subdomains queried (rapidly-changing left-hand parts); 30 txt responses (txt is the classic channel for tunnel replies).

**Evidence:**
- signals fired: 4
- example query: amgslht34px6zjixqsem3mn2wx7tzkc5wcwsxeq.t.c2bad.example
- example query: xncpn22tt7rp5rqpyfhg3nj4mrx6oa76ovzxnmq.t.c2bad.example
- example query: hxbrgzqywfxonwctxiib64dbqe2fd75sqmgqvky.t.c2bad.example

**Why it matters:** DNS tunneling encodes data (C2 commands or exfiltrated bytes) into hostname labels — e.g. NBSWY3DPFQQFO33SNRSC65LJMQ.tunnel.example.com. The encoding forces long, high-entropy, ever-changing subdomains, which is what these signals measure. Legitimate services (CDNs, load balancers) can also generate many subdomains — check whether the labels decode to something meaningful before calling it malicious.

**MITRE ATT&CK:** `T1071.004` Application Layer Protocol: DNS — DNS used as a data channel, `T1132.001` Data Encoding: Standard Encoding — hostname labels consistent with encoded data

**Wireshark:** `dns.qry.name contains "c2bad.example"`

**Verify manually:** In Wireshark: dns.qry.name contains "c2bad.example" — inspect the queried names; try Base32/Base64-decoding the left-most label of the longest ones.

### [HIGH] Possible port scan from 192.168.1.50 (68 connection attempts)  
_confidence: high_

192.168.1.50 sent SYN packets to 68 distinct ports on other hosts; only 18 handshakes completed.

**Evidence:**
- distinct destination ports probed: 68
- example ports: 20, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32…
- handshake completion rate: 18/68
- scan window: 0.3s

**Why it matters:** A SYN scan probes many ports quickly to find open services without completing connections. Legitimate software rarely touches dozens of ports on remote hosts in one burst — but load balancers and monitoring systems sometimes do, so check what 192.168.1.50 is before concluding.

**MITRE ATT&CK:** `T1046` Network Service Discovery — mass TCP SYN probing of many ports, `T1595` Active Scanning — active scanning behavior against network hosts

**Wireshark:** `ip.src == 192.168.1.50 && tcp.flags.syn == 1 && !tcp.flags.ack`

**Verify manually:** In Wireshark, filter for this source's SYN packets ("ip.src == 192.168.1.50 && tcp.flags.syn == 1 && !tcp.flags.ack") and check which ports answered SYN+ACK.

### [MEDIUM] Possible covert-channel candidate: tcp TCP flag set of 198.51.100.66  
_confidence: medium_

The TCP flag set field across 24 TCP messages from 198.51.100.66 varies over a small alphabet (SA, PA) in a two-state repeated sequence. Mapping the values to bits and grouping 8 per byte yields 3 bytes that decode to printable-looking output (100%).

**Evidence:**
- pattern: two-state repeated sequence
- mapping: SA→0, PA→1
- bitstream: 24 bits → 3 bytes
- decoded (first 120 chars): 'UUU'
- printable ratio: 1.00
- frames 92–150

**Why it matters:** Protocol metadata fields that the sender can freely choose (HTTP version, query type, TTL, port…) can carry hidden information by *value selection*: every packet is legal on its own, and only the sequence encodes data. This is an indicator, not proof — the same variation can occur naturally (client pools, load balancers). Judge by whether the decoded output is meaningful and whether the pattern persists. Full derivation: `netsleuth covert <pcap>`.

**MITRE ATT&CK:** `T1132.001` Data Encoding: Standard Encoding — information encoded into protocol field choices rather than payload, `T1095` Non-Application Layer Protocol — application/protocol metadata used as a covert data channel

**Wireshark:** `ip.src == 198.51.100.66 && tcp.flags`

**Verify manually:** In Wireshark: ip.src == 198.51.100.66 && tcp.flags — read the field of each packet in order, note the values (the engine observed: SA×12, PA×12), assign bits per the mapping and decode 8 bits per byte.

### [MEDIUM] Dense data in DNS TXT record for c2bad.example  
_confidence: medium_

TXT record carries 74 characters of high-entropy, encoded-looking data.

**Evidence:**
- TXT value (74 chars): [b'v1.0.6IUPNFNYOVO3WX33NIVIW63TYZXCQCWTNWXDCVLVPI5GFZIYQ6RP2EBEZJP5GHS4']…
- entropy: 4.9 bits/char

**Why it matters:** TXT records legitimately hold SPF/DKIM data, but those are readable strings like "v=spf1 -all". Long opaque blobs are how DNS-tunnel C2 replies and some malware configs travel. Try Base32/Base64-decoding the value.

**MITRE ATT&CK:** `T1071.004` Application Layer Protocol: DNS — data-bearing TXT records

**Wireshark:** `dns.qry.name == "c2bad.example" && dns.txt`

**Verify manually:** In Wireshark: dns.qry.name == "c2bad.example" && dns.txt

### [MEDIUM] ICMP echo requests carrying 312 bytes of data payload  
_confidence: low_

6 echo request(s) carry payloads of 52+ bytes (normal ping payloads are usually small and uniform).

**Evidence:**
- example payload (52 bytes): 'ZXhmaWwtY2h1bmstMDAtZorbzLnTIaDHLHs7l4BM/C4MhgQCDT8X'
- 192.168.1.50 → 198.51.100.66: 52 bytes
- 192.168.1.50 → 198.51.100.66: 52 bytes
- 192.168.1.50 → 198.51.100.66: 52 bytes
- 192.168.1.50 → 198.51.100.66: 52 bytes
- 192.168.1.50 → 198.51.100.66: 52 bytes

**Why it matters:** The ping protocol has no business carrying rich text/binary data. Large or varied payloads inside ICMP echo are how simple backdoors exfiltrate or beacon while slipping past port-based rules. Some monitoring tools do embed data, so read the payload before judging.

**MITRE ATT&CK:** `T1095` Non-Application Layer Protocol — ICMP echo used as a data channel, `T1048.003` Exfiltration Over Unencrypted Non-C2 Protocol — data moved over an unencrypted non-application protocol

**Wireshark:** `icmp.type == 8 && data.len >= 16`

**Verify manually:** In Wireshark: icmp && data.len >= 16, then inspect the echo data field.

### [MEDIUM] Traffic on commonly-abused port 4444 (Metasploit default handler)  
_confidence: low_

192.168.1.50 ↔ 198.51.100.66 exchanged data on port 4444, commonly associated with Metasploit default handler.

**Evidence:**
- connection 192.168.1.50 ↔ 198.51.100.66 port 4444

**Why it matters:** Ports like these are defaults for offensive tooling, but they are also used by legitimate software occasionally. The port number alone is a weak indicator — inspect the stream content before deciding.

**MITRE ATT&CK:** `T1571` Non-Standard Port — service communicating on a non-standard, tooling-associated port

**Wireshark:** `tcp.port == 4444`

**Verify manually:** In Wireshark: tcp.port == 4444, then right-click a packet → Follow → TCP Stream.

## Secrets & flags

| Kind | Value | Confidence | Source |
|---|---|---|---|
| flag | `picoCTF{…ams}` | high | TCP stream 84 (server→client, port 80) |
| command | `curl/7.81.0` | medium | TCP stream 84 (client→server, port 80) |

> Values masked; use `--reveal` on the CLI for full values.

## Timeline

| Time | Kind | Event |
|---|---|---|
| 23:20:00.000 | dns | DNS query 'files.example.com' (A) from 192.168.1.50 |
| 23:20:00.070 | http | HTTP GET files.example.com/index.html → 200 |
| 23:20:00.070 | tcp | TCP stream 0: 192.168.1.50:44001 → 203.0.113.9:80 (206 B) |
| 23:20:02.070 | detection | [HIGH] Possible port scan from 192.168.1.50 (68 connection attempts) **[HIGH]** |
| 23:21:02.070 | tcp | TCP stream 71: 192.168.1.50:45100 → 203.0.113.9:21 (142 B) |
| 23:21:02.070 | detection | [HIGH] Cleartext FTP credentials observed (1 login(s)) **[HIGH]** |
| 23:22:02.070 | tcp | TCP stream 72: 192.168.1.50:46000 → 198.51.100.66:4444 (84 B) |
| 23:22:02.070 | detection | [HIGH] Periodic connections: 192.168.1.50 → 198.51.100.66:4444 (12 connections, ~60.0s interval) **[HIGH]** |
| 23:22:02.070 | detection | [MEDIUM] Possible covert-channel candidate: tcp TCP flag set of 198.51.100.66 **[MEDIUM]** |
| 23:23:02.070 | tcp | TCP stream 73: 192.168.1.50:46001 → 198.51.100.66:4444 (84 B) |
| 23:24:02.070 | tcp | TCP stream 74: 192.168.1.50:46002 → 198.51.100.66:4444 (84 B) |
| 23:25:02.070 | tcp | TCP stream 75: 192.168.1.50:46003 → 198.51.100.66:4444 (84 B) |
| 23:26:02.070 | tcp | TCP stream 76: 192.168.1.50:46004 → 198.51.100.66:4444 (84 B) |
| 23:27:02.070 | tcp | TCP stream 77: 192.168.1.50:46005 → 198.51.100.66:4444 (84 B) |
| 23:28:02.070 | tcp | TCP stream 78: 192.168.1.50:46006 → 198.51.100.66:4444 (84 B) |
| 23:29:02.070 | tcp | TCP stream 79: 192.168.1.50:46007 → 198.51.100.66:4444 (84 B) |
| 23:30:02.070 | tcp | TCP stream 80: 192.168.1.50:46008 → 198.51.100.66:4444 (84 B) |
| 23:31:02.070 | tcp | TCP stream 81: 192.168.1.50:46009 → 198.51.100.66:4444 (84 B) |
| 23:32:02.070 | tcp | TCP stream 82: 192.168.1.50:46010 → 198.51.100.66:4444 (84 B) |
| 23:33:02.070 | tcp | TCP stream 83: 192.168.1.50:46011 → 198.51.100.66:4444 (84 B) |
| 23:34:02.070 | dns | DNS query 'amgslht34px6zjixqsem3mn2wx7tzkc5wcwsxeq.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.070 | detection | [HIGH] Possible DNS tunneling via c2bad.example **[HIGH]** |
| 23:34:02.170 | dns | DNS query 'xncpn22tt7rp5rqpyfhg3nj4mrx6oa76ovzxnmq.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.270 | dns | DNS query 'hxbrgzqywfxonwctxiib64dbqe2fd75sqmgqvky.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.370 | dns | DNS query '4ysr7vlfknuvutssf2ml65syd323773vbtgbepy.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.470 | dns | DNS query 'sfdqq5pwl54zu5m5zvb2cwwszxwyk4ztxpldtda.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.569 | dns | DNS query 'fp2e62apyztpmphsewtt4nhc4352jj46pdymodi.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.669 | dns | DNS query 'ppb2d2qcl7u76mdblhgjnzuusfn5q5cqjxydaay.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.769 | dns | DNS query 'ko5kprunfwe7vlk4f6hc3h76xfyu6ufftiq2wtq.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.869 | dns | DNS query '4j2hxrsmtsrkttcb5ege3myrx5iqfit6xk2sdna.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:02.969 | dns | DNS query '5hxi5qhfz542pi2gs65dgf6y5zlzirc2njjblpa.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.069 | dns | DNS query 'h4hbid4akjkopd5mrqv64t7ikd6dp2wrrs2rgfa.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.169 | dns | DNS query 'lwcvg3pzpvtfsaephsnyckmlw5srxexbw6lr52a.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.269 | dns | DNS query '7sv6qwe4xfsgd22eqmixnsc2gwqeyoc2jtedxka.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.369 | dns | DNS query 'p7m7rhbb674w2fntqwgyicf4iaz5hyziawflaoa.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.469 | dns | DNS query 'zjopthzqnx4o2iav4nvj4dzs56ze3origxh4rny.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.569 | dns | DNS query '42rszjew3t7g6647snhctptdynr56zxrleizh5i.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.669 | dns | DNS query 'dmq2q4ci6wbzjoo7bfqucxjx6646r5fcqu6fkyi.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.769 | dns | DNS query 'zqe7sfjkh32xliswvsyqzhn4adn7plkxqulpmfi.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.869 | dns | DNS query 'c7x3qi2nngbasz7i3tn33pdy6efvmgeb6tr4nfa.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:03.969 | dns | DNS query 'mvrhfsurf6gloz3dmq3dyoamloi2544ibz5bcva.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.069 | dns | DNS query 'pcfh3ajoe42mleafjgl2dnhnvmhxr3feogzbacy.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.169 | dns | DNS query 'ytpuv2rt4sgn6jodhctnls5axm2txau53hdcs7i.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.269 | dns | DNS query 'ajvxpqei5afdtrb32wsu7goubjoqj65va2v7hii.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.369 | dns | DNS query 'kiwwubw4xlzlaon5ebwugaldllo3htwkjahvpii.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.469 | dns | DNS query 'e3n57w77b6mtdqa2fqunwtzlv7liyzbsde6umgy.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.569 | dns | DNS query 'iijbf2vdaee6kgyscih4tlb5nzjh4ob2vlmttlq.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.669 | dns | DNS query 'ydgoeeveo5ibdb3ye3m5gw2euzzoctnjuuwnwiq.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.769 | dns | DNS query '5r33743vk6nd44ege4htxbrvrkdy5wumitzo73q.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.869 | dns | DNS query 'cp7xysm4h3vcod2bqsyldyzi5onyttab4aaw5wa.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:04.969 | dns | DNS query 'oxqi5ql6ojjzvw4mpmhev3gvcysxm3gcpyi25sq.t.c2bad.example' (A) from 192.168.1.50 |
| 23:34:35.069 | http | HTTP GET bad.example/uploads/shell.php → 200 |
| 23:34:35.069 | tcp | TCP stream 84: 192.168.1.50:47001 → 203.0.113.66:80 (283 B) |
| 23:35:05.069 | http | HTTP GET bad.example/payload/dropper.bin → 200 |
| 23:35:05.069 | tcp | TCP stream 85: 192.168.1.50:47002 → 203.0.113.66:80 (4271 B) |
| 23:35:35.069 | detection | [MEDIUM] ICMP echo requests carrying 312 bytes of data payload **[MEDIUM]** |

## Recommended manual investigation

**Verify findings**
- `ip.addr == 198.51.100.66 && tcp.port == 4444`
- `tcp.stream == 71`
- `dns.qry.name contains "c2bad.example"`
- `ip.src == 192.168.1.50 && tcp.flags.syn == 1 && !tcp.flags.ack`
- `ip.src == 198.51.100.66 && tcp.flags`
- `dns.qry.name == "c2bad.example" && dns.txt`
- `icmp.type == 8 && data.len >= 16`
- `tcp.port == 4444`

**Focus on top talkers**
- `ip.addr == 192.168.1.50`
- `ip.addr == 8.8.8.8`
- `ip.addr == 203.0.113.66`
- `ip.addr == 203.0.113.9`
- `ip.addr == 198.51.100.66`

**Top queried domains**
- `dns.qry.name contains "c2bad.example"`

**Streams with cleartext credentials**
- `tcp.stream == 71`

**File downloads over HTTP**
- `http.request.full_uri contains "/index.html"`
- `http.request.full_uri contains "/uploads/shell.php"`
- `http.request.full_uri contains "/payload/dropper.bin"`

**Streams on unusual ports**
- `tcp.stream == 71`
- `tcp.stream == 72`
- `tcp.stream == 73`
- `tcp.stream == 74`
- `tcp.stream == 75`
- `tcp.stream == 76`
- `tcp.stream == 77`
- `tcp.stream == 78`

---
_Generated by NetSleuth — findings are indicators with evidence and confidence, not verdicts._