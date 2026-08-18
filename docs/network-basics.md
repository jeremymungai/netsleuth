# Network Analysis Basics — the concepts NetSleuth uses, in plain English

You don't need networking experience to use NetSleuth, but its findings
make much more sense with the concepts. Each section explains the idea
first in everyday terms, then what it means when NetSleuth reports it.

## What is a packet?

Computers on a network talk in small messages called **packets** — like
individual postal letters, each with an address on the envelope and a
small amount of content inside. A web page you load is not one message;
it's hundreds of packets flowing both ways.

Every packet is layered like an onion:

| Layer | Question it answers | Example |
|---|---|---|
| Ethernet (layer 2) | which physical device? | MAC addresses `08:00:27:…` |
| IP (layer 3) | which computer, globally? | `192.168.1.50` |
| TCP/UDP (layer 4) | which program on that computer? | port `80` = web |
| Application (layer 5+) | what is being said? | HTTP, DNS, TLS… |

NetSleuth reads all the layers so you don't have to. The **port number**
is the key idea: an IP address reaches a machine, a port reaches a
specific service on it. Web servers listen on 80/443, mail on 25, DNS on
53. A "port" is just a number — but *which* number tells you a lot about
what's happening.

## What is a PCAP?

A **packet capture** (`.pcap` / `.pcapng`) is a recording of packets that
crossed a network cable — like a security-camera tape for network
traffic. It contains each packet plus the moment it was seen (its
timestamp). Analysts share captures as evidence; CTFs hide flags in them.

`.pcapng` ("next generation") is the newer format: it can hold multiple
interfaces, name them, and carry comments. NetSleuth reads both and
tells you if a capture is truncated (cut off mid-recording).

## IP addresses: who is inside, who is outside?

Some ranges are reserved for private networks — `10.x.x.x`,
`172.16–31.x.x`, `192.168.x.x`. Hosts there are "internal": your lab,
your office. Everything else is public internet. NetSleuth marks each
host internal/external because the *direction* of traffic matters:
an internal host talking OUT to a strange address is a different story
than something coming IN.

## TCP vs UDP — letters vs. phone calls

**UDP** is fire-and-forget: send the packet, hope it arrives. Fast, no
setup. DNS queries use UDP.

**TCP** is a phone call: connect first (the three-way handshake), then
talk, then hang up. The handshake is the famous `SYN → SYN-ACK → ACK`
exchange, and its packets have flag letters: `S` (start), `A`
(acknowledge), `F` (finish), `R` (reset/abort).

Why analysts care:
- A **SYN with no answer** = a knock on a closed/filtered door.
- Many SYNs to many ports, fast = a **port scan** (someone testing every
  door in the building).
- The handshake lets us reconstruct full **conversations** (next).

## Streams: what "follow TCP stream" really does

One HTTP request might be spread across 20 packets. **Stream
reassembly** stitches them back together in the right order using TCP's
sequence numbers (each packet says "my data starts at byte N"), dropping
duplicates (retransmissions). The result is one clean transcript of the
conversation in each direction — this is Wireshark's "Follow TCP
Stream", and it's how NetSleuth reads HTTP, FTP, and TLS handshakes
instead of packet fragments.

## DNS — the network's phone book

DNS turns names (`example.com`) into IP addresses. A **query** goes out,
a **response** comes back with answers. Two records matter most for
hunting:

- **A/AAAA** = "this name lives at this IP"
- **TXT** = free-form text attached to a name (used legitimately for
  email anti-spam, abused for smuggling data)

Suspicious DNS behaviors NetSleuth looks for:
- **Long, random subdomains** — `nbswy3dpfqqfo33s.evil.com`. Real
  hostnames are words; encoded data is long and high-entropy. That's
  **DNS tunneling**: malware exfiltrating data inside the names
  themselves, because DNS is almost always allowed through firewalls.
- **NXDOMAIN storms** — thousands of "domain doesn't exist" replies
  often mean malware guessing randomly-generated domains to find its
  command server (a DGA).
- **Perfectly regular queries** — same name, same interval, every 60
  seconds: beaconing over DNS.

Entropy, in one sentence: a measure of how "random-looking" text is —
English words ≈ 2–3 bits/char, random data ≈ 4+ bits/char.

## HTTP — the readable web

Unencrypted HTTP is plain text on the wire: a **request** (method +
path + headers) and a **response** (status + headers + body). Anyone
with the capture reads it — including passwords in POST bodies and
Basic-auth headers (base64 is *encoding*, not encryption!).

Things NetSleuth hunts in HTTP: `../` directory traversal, SQL tokens
(`' OR 1=1`), shell commands in parameters (`cmd=cat /etc/passwd`), web
shell shapes (`system($_GET['cmd'])`), attack-tool user-agents
(`sqlmap`), uploads of executable files.

## TLS/HTTPS — the unreadable web

TLS encrypts content; only the **handshake** (before encryption starts)
is visible. That metadata is still rich: the **SNI** (which hostname
the client wants), offered versions and ciphers, the server's
**certificate** (subject, issuer, validity, self-signed?), and a
fingerprint of the client's hello (**JA3**) — because malware's TLS
stacks often fingerprint differently than browsers. NetSleuth reports
exactly this metadata and never pretends to decrypt.

## Credentials in cleartext

FTP, SMTP, IMAP, POP3, telnet and HTTP-Basic send usernames and
passwords unencrypted. When NetSleuth reports "cleartext credentials",
that's not a guess — the capture literally contains them. That's a
finding (and in CTF, a gift).

## Indicators and behaviors (the hunting part)

An **indicator** (IOC) is a concrete clue: a bad IP, a domain, a hash.
A **behavior** is a *pattern of activity*: scanning, beaconing,
tunneling, exfiltration. NetSleuth focuses on behaviors because
indicators go stale but "workstation beacons every 60 seconds" never
stops being suspicious.

**Beaconing**: malware checking in with its controller on a timer.
Humans are irregular; timers aren't. NetSleuth measures the variance of
connection intervals (the "coefficient of variation") — near-zero
variance across 10+ connections is the signature. (So is your OS update
checker — which is why the finding says *indicator, not proof*.)

**Exfiltration**: data leaving. Signals NetSleuth weighs: bulk volume to
external hosts, DNS with data-shaped names, ICMP carrying payloads.

**Lateral movement**: an internal host scanning or logging into other
internal hosts — the pattern of an attacker expanding inside a network.

## MITRE ATT&CK in one paragraph

ATT&CK is a public catalog of attacker techniques with stable IDs
(T1046 = network scanning, T1071.004 = DNS as a command channel…).
Mapping findings to it lets defenders speak a shared language and
compare notes. NetSleuth maps *only* where the evidence actually fits,
and every mapping explains its reasoning.

## Verifying findings in Wireshark

Every NetSleuth finding ships with a **display filter** — the search
syntax Wireshark uses to select packets. Paste it into Wireshark's
filter bar to see the exact packets behind the finding:

```
ip.addr == 198.51.100.66          # everything involving this host
dns.qry.name contains "evil"      # DNS names containing "evil"
http.request.method == "POST"     # all POSTs
tcp.stream == 7                   # one conversation
```

That loop — tool finds, human verifies — is the whole point. NetSleuth
finds the needle; Wireshark lets you see it with your own eyes.
