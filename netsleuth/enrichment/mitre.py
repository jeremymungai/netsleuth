"""Local MITRE ATT&CK technique catalog for mapping findings.

Only techniques NetSleuth can actually justify with observed evidence
are mapped — no force-fitting. The catalog is intentionally small and
local (no API calls); extend it in rules or code as detectors grow.
"""

from __future__ import annotations

from netsleuth.models import MitreRef

TECHNIQUES: dict[str, dict] = {
    "T1046": ("Discovery", "Network Service Discovery"),
    "T1595": ("Reconnaissance", "Active Scanning"),
    "T1595.001": ("Reconnaissance", "Active Scanning: Scanning IP Blocks"),
    "T1071.001": ("Command and Control", "Application Layer Protocol: Web Protocols"),
    "T1071.004": ("Command and Control", "Application Layer Protocol: DNS"),
    "T1095": ("Command and Control", "Non-Application Layer Protocol"),
    "T1132.001": ("Command and Control", "Data Encoding: Standard Encoding"),
    "T1571": ("Command and Control", "Non-Standard Port"),
    "T1573": ("Command and Control", "Encrypted Channel"),
    "T1105": ("Command and Control", "Ingress Tool Transfer"),
    "T1041": ("Exfiltration", "Exfiltration Over C2 Channel"),
    "T1048.003": ("Exfiltration", "Exfiltration Over Unencrypted Non-C2 Protocol"),
    "T1059": ("Execution", "Command and Scripting Interpreter"),
    "T1059.004": ("Execution", "Command and Scripting Interpreter: Unix Shell"),
    "T1083": ("Discovery", "File and Directory Discovery"),
    "T1190": ("Initial Access", "Exploit Public-Facing Application"),
    "T1505.003": ("Persistence", "Server Software Component: Web Shell"),
    "T1110": ("Credential Access", "Brute Force"),
    "T1552.001": ("Credential Access", "Unsecured Credentials: Credentials In Files"),
    "T1552.004": ("Credential Access", "Unsecured Credentials: Private Keys"),
    "T1557": ("Credential Access", "Adversary-in-the-Middle"),
}


def mitre(technique: str, why: str) -> MitreRef:
    tactic, name = TECHNIQUES.get(technique, ("", ""))
    return MitreRef(technique=technique, tactic=tactic, name=name, why=why)
