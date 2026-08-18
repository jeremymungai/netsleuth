# NetSleuth PCAP Analysis Showcase

This folder contains a comprehensive demonstration of the **NetSleuth** PCAP analysis and network threat hunting toolkit in action, analyzing a realistic network capture (`network.pcap`).

## Contents

*   **`network.pcap`**: The raw network capture file analyzed during this exercise.
*   **`detect_output.json`**: The structured JSON output from the NetSleuth detection engine, highlighting the core threat indicators and their risk scores.
*   **`covert_output.json`**: Detailed JSON output from the custom covert channel analyzer.
*   **`secrets_output.json`**: Results of the secrets and flag scanning engine.
*   **`hosts_output.json`**: Network inventory and endpoint behavior mapping.
*   **`analysis_results.md`**: A summarized, human-readable report of the findings.

## Key Findings Highlight

The analysis of `network.pcap` yielded several critical indicators of compromise:

1.  **Covert Channel Exfiltration**: The host `192.168.1.69` was found exfiltrating data via HTTP metadata manipulation (specifically, toggling between `HTTP/1.0` and `HTTP/1.1`, and altering `Host` headers). Decoding this bitstream revealed a hidden flag.
2.  **Command Injection**: High-confidence command injection payloads (e.g., `;ls`, `;id`) were detected targeting `192.168.48.134` over port 443.
3.  **Active Network Scanning**: A high-speed TCP SYN scan originated from `192.168.1.69` targeting port 8080.

## The Covert Channel Feature

A unique capability showcased here is the **Covert Channel** detection engine. This feature was custom-built and added to NetSleuth as a powerful extension for identifying advanced evasion techniques. 

It works by statistically analyzing protocol metadata fields (such as HTTP versions, DNS query types, or IP TTLs) that an attacker can freely choose. By observing small, repeated alphabets in these fields and mapping their sequence back to a bitstream, NetSleuth successfully decodes information that traditional payload-based IDS systems completely miss. This demonstrates not just a solid grasp of packet structure, but a deep understanding of advanced C2 hiding mechanisms.

## How to Reproduce

You can rerun the analysis yourself using the NetSleuth CLI:

```bash
# Run the main detection engine
netsleuth detect network.pcap -v

# Extract the covert channel bitstream
netsleuth covert network.pcap

# Search for embedded flags and command injections
netsleuth secrets network.pcap --reveal
```
