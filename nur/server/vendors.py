"""
Vendor registry and scoring engine.

In-memory vendor metadata loaded from JSON data files, plus weighted scoring
ported from bakeoff's scoring module.
"""
from __future__ import annotations

import json
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ── Module-level caches ──────────────────────────────────────────────
_capabilities_cache: dict | None = None
_integrations_cache: dict | None = None
_mitre_cache: dict | None = None

# ── Vendor Registry ──────────────────────────────────────────────────

VENDOR_REGISTRY: dict[str, dict] = {
    # ── EDR / XDR ────────────────────────────────────────────────────
    "crowdstrike": {
        "display_name": "CrowdStrike Falcon",
        "category": "edr",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS", "HIPAA-BAA", "StateRAMP"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "HIPAA", "CMMC"],
        "insurance_carriers": ["Coalition", "Corvus", "At-Bay", "Beazley", "Chubb"],
        "known_issues": "July 2024 global IT outage -- faulty sensor content update caused BSOD on ~8.5M Windows devices",
        "typical_deploy_days": 12,
    },
    "sentinelone": {
        "display_name": "SentinelOne",
        "category": "edr",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS", "HIPAA-BAA"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CIS Controls"],
        "insurance_carriers": ["Coalition", "Corvus", "At-Bay"],
        "known_issues": "",
        "typical_deploy_days": 10,
    },
    "ms-defender": {
        "display_name": "Microsoft Defender for Endpoint",
        "category": "edr",
        "price_range": "Included in M365 E5",
        "certifications": ["SOC2-Type2", "FedRAMP-High", "ISO27001", "FIPS-140-2", "HIPAA", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "HIPAA", "FedRAMP"],
        "insurance_carriers": ["Coalition", "Beazley"],
        "known_issues": "Historical detection gaps in MITRE evaluations (2020-2022); improved in later rounds",
        "typical_deploy_days": 3,
    },
    "cortex-xdr": {
        "display_name": "Palo Alto Cortex XDR",
        "category": "edr",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS", "FIPS-140-2"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CMMC"],
        "insurance_carriers": ["Chubb", "Beazley"],
        "known_issues": "Complex licensing tiers. CVE-2021-3044 (Cortex XSOAR, CVSS 9.8)",
        "typical_deploy_days": 14,
    },
    "carbon-black": {
        "display_name": "VMware Carbon Black",
        "category": "edr",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "Product direction uncertainty since Broadcom acquisition of VMware (2023)",
        "typical_deploy_days": 21,
    },
    "sophos": {
        "display_name": "Sophos Intercept X",
        "category": "edr",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": ["Corvus"],
        "known_issues": "",
        "typical_deploy_days": 10,
    },
    "bitdefender": {
        "display_name": "Bitdefender GravityZone",
        "category": "edr",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001", "FedRAMP-Moderate"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "",
        "typical_deploy_days": 7,
    },
    "eset": {
        "display_name": "ESET Protect",
        "category": "edr",
        "price_range": "<$30/endpoint/yr",
        "certifications": ["ISO27001", "SOC2-Type2"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "",
        "typical_deploy_days": 7,
    },
    "trend-apex": {
        "display_name": "Trend Micro Apex One",
        "category": "edr",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001", "FedRAMP-Moderate"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS"],
        "insurance_carriers": [],
        "known_issues": "2019 data breach -- rogue employee sold customer data",
        "typical_deploy_days": 14,
    },
    "kaspersky": {
        "display_name": "Kaspersky Endpoint Security",
        "category": "edr",
        "price_range": "<$30/endpoint/yr",
        "certifications": ["ISO27001", "SOC2-Type2"],
        "compliance_frameworks": ["NIST CSF"],
        "insurance_carriers": [],
        "known_issues": "US government ban on Kaspersky products (2024)",
        "typical_deploy_days": 7,
    },
    # ── SIEM ─────────────────────────────────────────────────────────
    "splunk": {
        "display_name": "Splunk Enterprise Security",
        "category": "siem",
        "price_range": "Consumption-based",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS", "HIPAA"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "HIPAA"],
        "insurance_carriers": ["Chubb", "Beazley", "AIG"],
        "known_issues": "Cisco acquisition (2024). 2022 significant license price increases",
        "typical_deploy_days": 45,
    },
    "ms-sentinel": {
        "display_name": "Microsoft Sentinel",
        "category": "siem",
        "price_range": "Consumption-based",
        "certifications": ["SOC2-Type2", "FedRAMP-High", "ISO27001", "FIPS-140-2", "HIPAA", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "HIPAA", "FedRAMP"],
        "insurance_carriers": ["Coalition", "Beazley"],
        "known_issues": "",
        "typical_deploy_days": 14,
    },
    "qradar": {
        "display_name": "IBM QRadar",
        "category": "siem",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "FIPS-140-2", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CMMC"],
        "insurance_carriers": [],
        "known_issues": "IBM strategic shift to QRadar Cloud",
        "typical_deploy_days": 60,
    },
    "elastic-siem": {
        "display_name": "Elastic SIEM",
        "category": "siem",
        "price_range": "Open-source / consumption",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "",
        "typical_deploy_days": 28,
    },
    # ── CNAPP ────────────────────────────────────────────────────────
    "wiz": {
        "display_name": "Wiz",
        "category": "cnapp",
        "price_range": "Consumption-based",
        "certifications": ["SOC2-Type2", "ISO27001", "FedRAMP-Moderate"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": ["Coalition", "At-Bay", "Corvus"],
        "known_issues": "",
        "typical_deploy_days": 7,
    },
    "prisma-cloud": {
        "display_name": "Palo Alto Prisma Cloud",
        "category": "cnapp",
        "price_range": "Consumption-based",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CIS Controls"],
        "insurance_carriers": ["Chubb"],
        "known_issues": "",
        "typical_deploy_days": 21,
    },
    "snyk": {
        "display_name": "Snyk",
        "category": "cnapp",
        "price_range": "Consumption-based",
        "certifications": ["SOC2-Type2", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "",
        "typical_deploy_days": 7,
    },
    # ── IAM ──────────────────────────────────────────────────────────
    "okta": {
        "display_name": "Okta",
        "category": "iam",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS", "FIPS-140-2"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "HIPAA"],
        "insurance_carriers": ["Coalition", "At-Bay", "Corvus", "Beazley"],
        "known_issues": "2022 Lapsus$ breach. 2023 support system breach",
        "typical_deploy_days": 14,
    },
    "entra-id": {
        "display_name": "Microsoft Entra ID",
        "category": "iam",
        "price_range": "Included in M365",
        "certifications": ["SOC2-Type2", "FedRAMP-High", "ISO27001", "FIPS-140-2", "HIPAA", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "HIPAA", "FedRAMP"],
        "insurance_carriers": ["Coalition", "Beazley"],
        "known_issues": "",
        "typical_deploy_days": 3,
    },
    # ── PAM ──────────────────────────────────────────────────────────
    "cyberark-pam": {
        "display_name": "CyberArk PAM",
        "category": "pam",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "FIPS-140-2", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CMMC"],
        "insurance_carriers": ["Coalition", "Chubb", "Beazley", "AIG"],
        "known_issues": "",
        "typical_deploy_days": 45,
    },
    "beyondtrust": {
        "display_name": "BeyondTrust",
        "category": "pam",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "FIPS-140-2", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CMMC"],
        "insurance_carriers": ["Coalition", "Beazley"],
        "known_issues": "2024 Remote Support compromise used to access US Treasury systems",
        "typical_deploy_days": 30,
    },
    "hashicorp-vault": {
        "display_name": "HashiCorp Vault",
        "category": "pam",
        "price_range": "Open-source / enterprise",
        "certifications": ["SOC2-Type2", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "2023 license change to BSL. OpenBao fork created",
        "typical_deploy_days": 14,
    },
    # ── Email Security ───────────────────────────────────────────────
    "proofpoint": {
        "display_name": "Proofpoint",
        "category": "email",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "HIPAA", "PCI-DSS"],
        "insurance_carriers": ["Coalition", "Beazley", "Chubb"],
        "known_issues": "",
        "typical_deploy_days": 14,
    },
    "mimecast": {
        "display_name": "Mimecast",
        "category": "email",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001", "FedRAMP-Moderate"],
        "compliance_frameworks": ["NIST CSF", "HIPAA"],
        "insurance_carriers": ["Coalition"],
        "known_issues": "2021 breach via Mimecast-issued certificate",
        "typical_deploy_days": 14,
    },
    # ── ZTNA ─────────────────────────────────────────────────────────
    "zscaler": {
        "display_name": "Zscaler",
        "category": "ztna",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "FIPS-140-2", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS"],
        "insurance_carriers": ["Coalition", "At-Bay"],
        "known_issues": "",
        "typical_deploy_days": 21,
    },
    "cloudflare-zt": {
        "display_name": "Cloudflare Zero Trust",
        "category": "ztna",
        "price_range": "<$30/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001", "FedRAMP-Moderate", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS"],
        "insurance_carriers": ["Coalition", "At-Bay"],
        "known_issues": "",
        "typical_deploy_days": 1,
    },
    "cisco-duo": {
        "display_name": "Cisco Duo",
        "category": "ztna",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "FIPS-140-2"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "HIPAA"],
        "insurance_carriers": ["Coalition", "Corvus", "Beazley"],
        "known_issues": "",
        "typical_deploy_days": 7,
    },
    # ── Vulnerability Management ─────────────────────────────────────
    "tenable": {
        "display_name": "Tenable Nessus",
        "category": "vm",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-High", "ISO27001", "FIPS-140-2", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CIS Controls"],
        "insurance_carriers": ["Corvus", "Coalition"],
        "known_issues": "",
        "typical_deploy_days": 7,
    },
    "qualys": {
        "display_name": "Qualys",
        "category": "vm",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS", "CIS Controls"],
        "insurance_carriers": ["Corvus"],
        "known_issues": "2020 data breach via Accellion FTA vulnerability",
        "typical_deploy_days": 7,
    },
    "rapid7": {
        "display_name": "Rapid7 InsightVM",
        "category": "vm",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": ["Corvus"],
        "known_issues": "",
        "typical_deploy_days": 7,
    },
    # ── WAF ──────────────────────────────────────────────────────────
    "cloudflare-waf": {
        "display_name": "Cloudflare WAF",
        "category": "waf",
        "price_range": "<$30/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001", "FedRAMP-Moderate", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS"],
        "insurance_carriers": ["Coalition", "At-Bay"],
        "known_issues": "",
        "typical_deploy_days": 1,
    },
    "f5-waf": {
        "display_name": "F5 Advanced WAF",
        "category": "waf",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "FIPS-140-2", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS"],
        "insurance_carriers": [],
        "known_issues": "CVE-2022-1388 + CVE-2023-46747 (both CVSS 9.8, actively exploited)",
        "typical_deploy_days": 21,
    },
    "imperva": {
        "display_name": "Imperva WAF",
        "category": "waf",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "FedRAMP-Moderate", "ISO27001", "PCI-DSS"],
        "compliance_frameworks": ["NIST CSF", "PCI-DSS"],
        "insurance_carriers": [],
        "known_issues": "2019 data breach via misconfigured AWS S3 snapshot",
        "typical_deploy_days": 14,
    },
    # ── NDR ──────────────────────────────────────────────────────────
    "darktrace": {
        "display_name": "Darktrace",
        "category": "ndr",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "AI detection claims questioned. Taken private by Thoma Bravo (2023)",
        "typical_deploy_days": 14,
    },
    "vectra": {
        "display_name": "Vectra AI",
        "category": "ndr",
        "price_range": "$30-60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001"],
        "compliance_frameworks": ["NIST CSF", "CIS Controls"],
        "insurance_carriers": [],
        "known_issues": "",
        "typical_deploy_days": 14,
    },
    # ── Threat Intelligence ──────────────────────────────────────────
    "recorded-future": {
        "display_name": "Recorded Future",
        "category": "threat-intel",
        "price_range": ">$60/endpoint/yr",
        "certifications": ["SOC2-Type2", "ISO27001", "FedRAMP-Moderate"],
        "compliance_frameworks": ["NIST CSF", "CMMC"],
        "insurance_carriers": ["Chubb", "Beazley"],
        "known_issues": "Acquired by Mastercard (2024) for $2.65B",
        "typical_deploy_days": 14,
    },
}

# ── Source weights for scoring (ported from bakeoff) ─────────────────

SOURCE_WEIGHTS: dict[str, float] = {
    "mitre": 3.0,
    "mitre-attack-evals": 3.0,
    "av-test": 2.5,
    "selabs": 2.5,
    "cisa-kev": 2.0,
    "community": 1.5,
    "reddit": 1.0,
    "hackernews": 1.0,
    "g2": 0.8,
    "gartner": 0.8,
    "forrester": 0.8,
}
DEFAULT_WEIGHT = 1.0


# ── Vendor helpers ───────────────────────────────────────────────────

def get_vendor(vendor_id: str) -> dict | None:
    """Look up a vendor by slug. Returns dict with metadata or None."""
    return VENDOR_REGISTRY.get(vendor_id.lower())


def list_vendors(category: str | None = None) -> list[dict]:
    """List all vendors, optionally filtered by category."""
    out = []
    for vid, v in VENDOR_REGISTRY.items():
        if category and v["category"] != category.lower():
            continue
        out.append({"id": vid, **v})
    return out


# ── Data file loaders ────────────────────────────────────────────────

def load_capabilities() -> dict:
    global _capabilities_cache
    if _capabilities_cache is None:
        with open(DATA_DIR / "capabilities.json") as f:
            _capabilities_cache = json.load(f)
    return _capabilities_cache


def load_integrations() -> dict:
    global _integrations_cache
    if _integrations_cache is None:
        with open(DATA_DIR / "integrations.json") as f:
            _integrations_cache = json.load(f)
    return _integrations_cache


def load_mitre_map() -> dict:
    global _mitre_cache
    if _mitre_cache is None:
        with open(DATA_DIR / "mitre_map.json") as f:
            _mitre_cache = json.load(f)
    return _mitre_cache


# ── Scoring engine ───────────────────────────────────────────────────

def weighted_score(evals: list[dict]) -> float | None:
    """
    Compute weighted average score across evaluations.
    Each eval dict must have 'overall_score' and optionally 'source'.
    Returns None if no scoreable evaluations.
    """
    scoreable = [e for e in evals if e.get("overall_score") is not None]
    if not scoreable:
        return None

    numerator = 0.0
    denominator = 0.0
    for ev in scoreable:
        score = ev["overall_score"]
        source = ev.get("source", "community")
        weight = SOURCE_WEIGHTS.get(source, DEFAULT_WEIGHT)
        numerator += score * weight
        denominator += weight

    if denominator == 0:
        return None

    return round(numerator / denominator, 2)


def confidence_level(eval_count: int, source_count: int) -> str:
    """
    Return a confidence tier based on data coverage.
    """
    if eval_count >= 8 and source_count >= 5:
        return "high"
    if eval_count >= 4 and source_count >= 3:
        return "medium"
    if eval_count >= 3:
        return "low"
    return "insufficient"
