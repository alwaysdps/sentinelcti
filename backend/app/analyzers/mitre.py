"""Minimal MITRE ATT&CK association layer.

Scope and honesty caveat: this maps *observed static artefacts* (a string, a
URL shape, a file characteristic) to techniques those artefacts are commonly
associated with. It does not and cannot establish that a technique was
executed. Everything surfaced here is labelled a "potential technique
association" in the report for exactly that reason.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Technique:
    technique_id: str
    name: str
    tactic: str
    url: str


_CATALOG: dict[str, Technique] = {
    t.technique_id: t
    for t in (
        Technique("T1059", "Command and Scripting Interpreter", "Execution",
                  "https://attack.mitre.org/techniques/T1059/"),
        Technique("T1059.001", "PowerShell", "Execution",
                  "https://attack.mitre.org/techniques/T1059/001/"),
        Technique("T1059.003", "Windows Command Shell", "Execution",
                  "https://attack.mitre.org/techniques/T1059/003/"),
        Technique("T1059.004", "Unix Shell", "Execution",
                  "https://attack.mitre.org/techniques/T1059/004/"),
        Technique("T1027", "Obfuscated Files or Information", "Defense Evasion",
                  "https://attack.mitre.org/techniques/T1027/"),
        Technique("T1140", "Deobfuscate/Decode Files or Information", "Defense Evasion",
                  "https://attack.mitre.org/techniques/T1140/"),
        Technique("T1105", "Ingress Tool Transfer", "Command and Control",
                  "https://attack.mitre.org/techniques/T1105/"),
        Technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
                  "https://attack.mitre.org/techniques/T1071/001/"),
        Technique("T1547.001", "Registry Run Keys / Startup Folder", "Persistence",
                  "https://attack.mitre.org/techniques/T1547/001/"),
        Technique("T1053", "Scheduled Task/Job", "Execution",
                  "https://attack.mitre.org/techniques/T1053/"),
        Technique("T1490", "Inhibit System Recovery", "Impact",
                  "https://attack.mitre.org/techniques/T1490/"),
        Technique("T1112", "Modify Registry", "Defense Evasion",
                  "https://attack.mitre.org/techniques/T1112/"),
        Technique("T1218", "System Binary Proxy Execution", "Defense Evasion",
                  "https://attack.mitre.org/techniques/T1218/"),
        Technique("T1566.002", "Phishing: Spearphishing Link", "Initial Access",
                  "https://attack.mitre.org/techniques/T1566/002/"),
        Technique("T1583.001", "Acquire Infrastructure: Domains", "Resource Development",
                  "https://attack.mitre.org/techniques/T1583/001/"),
        Technique("T1036", "Masquerading", "Defense Evasion",
                  "https://attack.mitre.org/techniques/T1036/"),
        Technique("T1204.002", "User Execution: Malicious File", "Execution",
                  "https://attack.mitre.org/techniques/T1204/002/"),
        Technique("T1573", "Encrypted Channel", "Command and Control",
                  "https://attack.mitre.org/techniques/T1573/"),
    )
}


def resolve(technique_ids: list[str]) -> list[dict]:
    """Expand technique IDs into report-ready records, de-duplicated and sorted."""
    seen: dict[str, Technique] = {}
    for tid in technique_ids:
        technique = _CATALOG.get(tid)
        if technique and tid not in seen:
            seen[tid] = technique
    return [
        {
            "technique_id": t.technique_id,
            "name": t.name,
            "tactic": t.tactic,
            "url": t.url,
            "confidence": "potential association",
        }
        for t in sorted(seen.values(), key=lambda t: t.technique_id)
    ]


def known_ids() -> set[str]:
    return set(_CATALOG)
