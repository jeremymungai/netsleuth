# NetSleuth Command Showcase

Below is a curated list of commands showcasing the full capabilities of **NetSleuth**. You can use these examples to demonstrate the tool against any packet capture file.

### Initial Triage & Reconnaissance

Get a high-level summary of the capture file (packet counts, duration, etc.):
```bash
netsleuth summary example.pcap
```

Map out all hosts, conversations, and top talkers in the network:
```bash
netsleuth hosts example.pcap
```

Run a guided, 11-step interactive investigation of the capture:
```bash
netsleuth analyze example.pcap
```

### Protocol Specific Analysis

Inventory all DNS queries and detect potential DNS tunneling:
```bash
netsleuth dns example.pcap
```

Extract and view HTTP transactions directly from reassembled streams:
```bash
netsleuth http example.pcap
```

Analyze TLS metadata (SNI, JA3 fingerprints, certificate details) without decryption:
```bash
netsleuth tls example.pcap
```

### Deep Dive & Payload Extraction

List all reconstructed TCP streams in the capture:
```bash
netsleuth streams example.pcap
```

Follow a specific TCP stream (e.g., stream 42) to view its payload:
```bash
netsleuth stream example.pcap 42 --hex
```

Carve and extract files from the PCAP, automatically verifying magic bytes and hashing them:
```bash
netsleuth extract example.pcap -o ./extracted_files/
```

### Threat Hunting & Detection

Run the full detection engine to calculate a risk score and map to MITRE ATT&CK:
```bash
netsleuth detect example.pcap -v
```

Hunt for hidden secrets, credentials, API keys, and CTF flags:
```bash
netsleuth secrets example.pcap --reveal
```

Perform advanced metadata covert-channel analysis (finding data hidden in protocol headers):
```bash
netsleuth covert example.pcap
```

Generate a chronological timeline of all significant events and findings:
```bash
netsleuth timeline example.pcap --severity HIGH
```

### Reporting

Generate a standalone, interactive HTML report of the entire investigation:
```bash
netsleuth report example.pcap --format html --output report.html
```

Output findings in JSON format for integration with other SIEMs/dashboards:
```bash
netsleuth report example.pcap --format json --output report.json
```
