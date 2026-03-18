"""
Public remediation taxonomy — maps aggregate categories to known frameworks.

Every category here is public knowledge from NIST, MITRE D3FEND, and RE&CT.
The ONLY private data is "does it work?" — that comes from ProofEngine
aggregate histograms. The catalog is the hint, the histogram is the signal.

Sources:
  - NIST SP 800-61r2: Computer Security Incident Handling Guide
  - MITRE D3FEND: https://d3fend.mitre.org/
  - RE&CT: https://atc-project.github.io/atc-react/
  - MITRE ATT&CK Mitigations: https://attack.mitre.org/mitigations/
"""
from __future__ import annotations


# ══════════════════════════════════════════════════════════════════════════════
# Remediation categories → public framework guidance
# ══════════════════════════════════════════════════════════════════════════════

REMEDIATION_TAXONOMY: dict[str, dict] = {
    "containment": {
        "description": "Limit blast radius and stop lateral movement",
        "nist_phase": "Containment (NIST SP 800-61r2 §3.3)",
        "d3fend": ["D3-NI (Network Isolation)", "D3-EI (Execution Isolation)"],
        "react": ["RA2001 (Isolate host)", "RA2003 (Block domain)", "RA2002 (Block IP)"],
        "typical_actions": [
            "Network segmentation / micro-segmentation",
            "Host isolation (EDR containment)",
            "Block C2 domains/IPs at firewall and DNS",
            "Disable compromised accounts",
            "Quarantine affected endpoints",
        ],
        "applies_to": ["T1021 (Remote Services)", "T1570 (Lateral Tool Transfer)",
                        "T1071 (Application Layer Protocol)", "T1486 (Data Encrypted for Impact)"],
    },
    "detection": {
        "description": "Improve ability to detect the attack technique",
        "nist_phase": "Detection & Analysis (NIST SP 800-61r2 §3.2)",
        "d3fend": ["D3-FA (File Analysis)", "D3-NTA (Network Traffic Analysis)",
                    "D3-PA (Process Analysis)", "D3-SYSMA (System Monitoring)"],
        "react": ["RA1001 (Deploy detection rule)", "RA1002 (Update SIEM correlation)",
                   "RA1003 (Enable additional logging)"],
        "typical_actions": [
            "Deploy Sigma/YARA detection rules",
            "Enable command-line / PowerShell logging",
            "Add network traffic analysis for C2 patterns",
            "Configure EDR behavioral detection policies",
            "Set up honey tokens / deception",
        ],
        "applies_to": ["T1059 (Command and Scripting)", "T1566 (Phishing)",
                        "T1078 (Valid Accounts)", "T1053 (Scheduled Task)"],
    },
    "eradication": {
        "description": "Remove attacker access and persistence mechanisms",
        "nist_phase": "Eradication (NIST SP 800-61r2 §3.4)",
        "d3fend": ["D3-CE (Credential Eviction)", "D3-PE (Process Eviction)",
                    "D3-FE (File Eviction)"],
        "react": ["RA3001 (Remove malware)", "RA3002 (Revoke credentials)",
                   "RA3003 (Remove persistence mechanism)"],
        "typical_actions": [
            "Force password reset for all compromised accounts",
            "Remove scheduled tasks / registry persistence",
            "Revoke and rotate API keys and tokens",
            "Clean or reimage affected systems",
            "Remove unauthorized software and tools",
        ],
        "applies_to": ["T1053 (Scheduled Task)", "T1547 (Boot/Logon Autostart)",
                        "T1136 (Create Account)", "T1098 (Account Manipulation)"],
    },
    "recovery": {
        "description": "Restore systems and data to operational state",
        "nist_phase": "Recovery (NIST SP 800-61r2 §3.4)",
        "d3fend": ["D3-RFS (Restore File from Shadow Copy)", "D3-BA (Backup)"],
        "react": ["RA4001 (Restore from backup)", "RA4002 (Rebuild system)",
                   "RA4003 (Verify data integrity)"],
        "typical_actions": [
            "Restore from known-good backups (verify integrity first)",
            "Rebuild compromised systems from golden images",
            "Validate data integrity with checksums",
            "Staged reconnection to network with monitoring",
            "Verify no persistence before reconnecting",
        ],
        "applies_to": ["T1490 (Inhibit System Recovery)", "T1486 (Data Encrypted for Impact)",
                        "T1561 (Disk Wipe)", "T1485 (Data Destruction)"],
    },
    "prevention": {
        "description": "Harden systems to prevent the technique from succeeding",
        "nist_phase": "Preparation (NIST SP 800-61r2 §3.1)",
        "d3fend": ["D3-AH (Application Hardening)", "D3-CH (Credential Hardening)",
                    "D3-PH (Platform Hardening)"],
        "react": ["RA5001 (Patch vulnerability)", "RA5002 (Harden configuration)",
                   "RA5003 (Implement MFA)"],
        "typical_actions": [
            "Implement MFA for all privileged accounts",
            "Apply security patches and updates",
            "Harden configurations (CIS benchmarks)",
            "Implement application allowlisting",
            "Deploy email security gateway (anti-phishing)",
        ],
        "applies_to": ["T1078 (Valid Accounts)", "T1190 (Exploit Public-Facing App)",
                        "T1566 (Phishing)", "T1133 (External Remote Services)"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# Technique-specific guidance — public MITRE ATT&CK mitigations
# ══════════════════════════════════════════════════════════════════════════════

TECHNIQUE_GUIDANCE: dict[str, dict] = {
    "T1566": {
        "name": "Phishing",
        "mitigations": ["M1049 (Antivirus/Antimalware)", "M1031 (Network Intrusion Prevention)",
                        "M1054 (Software Configuration)", "M1017 (User Training)"],
        "recommended_categories": ["prevention", "detection"],
    },
    "T1078": {
        "name": "Valid Accounts",
        "mitigations": ["M1027 (Password Policies)", "M1032 (Multi-factor Authentication)",
                        "M1026 (Privileged Account Management)"],
        "recommended_categories": ["prevention", "eradication"],
    },
    "T1059": {
        "name": "Command and Scripting Interpreter",
        "mitigations": ["M1042 (Disable or Remove Feature)", "M1038 (Execution Prevention)",
                        "M1049 (Antivirus/Antimalware)"],
        "recommended_categories": ["detection", "prevention"],
    },
    "T1059.001": {
        "name": "PowerShell",
        "mitigations": ["M1042 (Disable or Remove Feature)", "M1045 (Code Signing)",
                        "M1038 (Execution Prevention)"],
        "recommended_categories": ["detection", "prevention"],
    },
    "T1486": {
        "name": "Data Encrypted for Impact",
        "mitigations": ["M1053 (Data Backup)", "M1040 (Behavior Prevention on Endpoint)"],
        "recommended_categories": ["recovery", "containment"],
    },
    "T1490": {
        "name": "Inhibit System Recovery",
        "mitigations": ["M1053 (Data Backup)", "M1028 (Operating System Configuration)"],
        "recommended_categories": ["recovery", "detection"],
    },
    "T1021": {
        "name": "Remote Services",
        "mitigations": ["M1032 (Multi-factor Authentication)", "M1035 (Limit Access to Resource Over Network)",
                        "M1030 (Network Segmentation)"],
        "recommended_categories": ["containment", "prevention"],
    },
    "T1021.001": {
        "name": "Remote Desktop Protocol",
        "mitigations": ["M1032 (Multi-factor Authentication)", "M1035 (Limit Access to Resource Over Network)",
                        "M1030 (Network Segmentation)", "M1042 (Disable or Remove Feature)"],
        "recommended_categories": ["containment", "prevention"],
    },
    "T1053": {
        "name": "Scheduled Task/Job",
        "mitigations": ["M1026 (Privileged Account Management)", "M1028 (Operating System Configuration)",
                        "M1047 (Audit)"],
        "recommended_categories": ["eradication", "detection"],
    },
    "T1547": {
        "name": "Boot or Logon Autostart Execution",
        "mitigations": ["M1038 (Execution Prevention)", "M1047 (Audit)"],
        "recommended_categories": ["eradication", "detection"],
    },
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "mitigations": ["M1048 (Application Isolation and Sandboxing)", "M1050 (Exploit Protection)",
                        "M1051 (Update Software)", "M1030 (Network Segmentation)"],
        "recommended_categories": ["prevention", "containment"],
    },
    "T1133": {
        "name": "External Remote Services",
        "mitigations": ["M1032 (Multi-factor Authentication)", "M1035 (Limit Access to Resource Over Network)",
                        "M1030 (Network Segmentation)"],
        "recommended_categories": ["prevention", "containment"],
    },
    "T1048": {
        "name": "Exfiltration Over Alternative Protocol",
        "mitigations": ["M1031 (Network Intrusion Prevention)", "M1030 (Network Segmentation)",
                        "M1057 (Data Loss Prevention)"],
        "recommended_categories": ["detection", "containment"],
    },
    "T1071": {
        "name": "Application Layer Protocol",
        "mitigations": ["M1031 (Network Intrusion Prevention)", "M1030 (Network Segmentation)"],
        "recommended_categories": ["detection", "containment"],
    },
    "T1570": {
        "name": "Lateral Tool Transfer",
        "mitigations": ["M1037 (Filter Network Traffic)", "M1031 (Network Intrusion Prevention)"],
        "recommended_categories": ["containment", "detection"],
    },
    "T1136": {
        "name": "Create Account",
        "mitigations": ["M1030 (Network Segmentation)", "M1032 (Multi-factor Authentication)",
                        "M1026 (Privileged Account Management)"],
        "recommended_categories": ["eradication", "detection"],
    },
}


def get_remediation_guidance(category: str) -> dict | None:
    """Get public framework guidance for a remediation category."""
    return REMEDIATION_TAXONOMY.get(category)


def get_technique_guidance(technique_id: str) -> dict | None:
    """Get public MITRE ATT&CK mitigation guidance for a technique."""
    return TECHNIQUE_GUIDANCE.get(technique_id)


def enrich_remediation_hints(hints: dict, gap_technique_ids: list[str] | None = None) -> dict:
    """
    Enrich remediation hints with public taxonomy guidance.

    Takes the aggregate histogram data from ProofEngine and adds
    public framework references so consumers know exactly what
    each category means and what actions to take.
    """
    enriched = dict(hints)

    # Enrich each effective category with public guidance
    for cat_entry in enriched.get("most_effective_categories", []):
        cat = cat_entry.get("category", "")
        guidance = get_remediation_guidance(cat)
        if guidance:
            cat_entry["framework_ref"] = {
                "nist_phase": guidance["nist_phase"],
                "d3fend": guidance["d3fend"],
                "typical_actions": guidance["typical_actions"],
            }

    # Add technique-specific guidance for gaps
    if gap_technique_ids:
        technique_hints = []
        for tid in gap_technique_ids[:10]:
            guidance = get_technique_guidance(tid)
            if guidance:
                technique_hints.append({
                    "technique_id": tid,
                    "name": guidance["name"],
                    "mitigations": guidance["mitigations"],
                    "recommended_categories": guidance["recommended_categories"],
                })
            else:
                # Try parent technique (e.g., T1059.001 → T1059)
                parent = tid.split(".")[0] if "." in tid else None
                if parent:
                    guidance = get_technique_guidance(parent)
                    if guidance:
                        technique_hints.append({
                            "technique_id": tid,
                            "name": guidance["name"],
                            "mitigations": guidance["mitigations"],
                            "recommended_categories": guidance["recommended_categories"],
                        })
        if technique_hints:
            enriched["technique_guidance"] = technique_hints

    return enriched


__all__ = [
    "REMEDIATION_TAXONOMY",
    "TECHNIQUE_GUIDANCE",
    "get_remediation_guidance",
    "get_technique_guidance",
    "enrich_remediation_hints",
]
