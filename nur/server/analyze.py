"""
Actionable intelligence analysis — fully trustless.

Takes a contribution, stores it in the DB (for aggregate computation),
commits it to the ProofEngine (for cryptographic proofs), then returns
intelligence derived ONLY from aggregates — never individual contributions.

Response source diagram::

    ┌─────────────────┐     ┌──────────────────┐     ┌─────────────────────┐
    │  ProofEngine     │     │  Template Logic   │     │  Public Taxonomy    │
    │  (aggregates)    │     │  (patterns)       │     │  (NIST/D3FEND)      │
    ├─────────────────┤     ├──────────────────┤     ├─────────────────────┤
    │ coverage_score   │     │ "Block C2 at FW"  │     │ containment: 87%    │
    │ detection_gaps[] │     │ "Deploy T1490"     │     │   → Network Isol.   │
    │ remediation_hints│     │ "Hunt in SIEM"     │     │   → Host Isolation  │
    │ contributor_count│     │                    │     │ T1490 mitigations   │
    │ ioc_type_distrib │     │                    │     │   → M1053 Backup    │
    └────────┬────────┘     └────────┬─────────┘     └──────────┬──────────┘
             │                       │                           │
             └───────────────────────┼───────────────────────────┘
                                     │
                              /analyze response
                                     │
                    ┌────────────────┴────────────────┐
                    │  NEVER in response:              │
                    │  - individual org actions         │
                    │  - sigma rules from specific orgs │
                    │  - "from_industry" attribution    │
                    │  - raw IOC values                 │
                    └─────────────────────────────────┘

Nothing in the response can be traced to an individual organization.
"""
from __future__ import annotations

import json
from typing import Any

from .db import Database
from .proofs import ProofEngine, translate_eval, translate_attack_map, translate_ioc_bundle
from .taxonomy import enrich_remediation_hints, get_technique_guidance


def detect_contribution_type(data: dict[str, Any]) -> str:
    """Detect the contribution type from the payload shape."""
    if "iocs" in data:
        return "ioc_bundle"
    if "techniques" in data:
        return "attack_map"
    if "vendor" in data or data.get("data", {}).get("vendor"):
        return "eval"
    raise ValueError("Cannot detect contribution type: missing 'iocs', 'techniques', or 'vendor' key")


async def analyze_ioc_bundle(data: dict[str, Any], db: Database, *, engine: ProofEngine | None = None) -> dict:
    """Analyze an IOC bundle — returns only aggregate counts, never individual match details."""
    # Store the contribution
    cid = await db.store_ioc_bundle(data)

    # Extract submitted hashes for aggregate matching
    iocs = data.get("iocs", [])
    hashes = [ioc.get("value_hash", "") for ioc in iocs if ioc.get("value_hash")]

    # Find matches — but we only use the COUNT, not individual match details
    matches = await db.get_ioc_matches(hashes, exclude_contribution_id=cid) if hashes else []
    shared_ioc_count = len(matches)

    # Aggregate IOC type distribution from matches (no org attribution)
    ioc_type_counts: dict[str, int] = {}
    for m in matches:
        t = m.get("ioc_type", "unknown")
        ioc_type_counts[t] = ioc_type_counts.get(t, 0) + 1

    # Proof layer
    receipt_dict = None
    if engine is not None:
        ioc_count, ioc_types = translate_ioc_bundle(data)
        receipt = engine.commit_ioc_bundle(ioc_count, ioc_types)
        receipt_dict = receipt.to_dict()

    if shared_ioc_count == 0:
        return {
            "status": "analyzed",
            "contribution_id": cid,
            "receipt": receipt_dict,
            "intelligence": {
                "campaign_match": False,
                "shared_ioc_count": 0,
                "ioc_type_distribution": {},
                "actions": [],
            },
        }

    # Template-based actions — derived from aggregate patterns, not individual orgs
    actions = []
    network_matches = ioc_type_counts.get("domain", 0) + ioc_type_counts.get("ip", 0)
    if network_matches > 0:
        actions.append({
            "priority": "critical",
            "action": "Block matching network indicators at firewall and DNS",
            "detail": (
                f"{network_matches} network IOCs (domains/IPs) match indicators "
                f"seen across other organizations in the collective"
            ),
        })

    hash_matches = ioc_type_counts.get("hash-sha256", 0) + ioc_type_counts.get("hash-md5", 0)
    if hash_matches > 0:
        actions.append({
            "priority": "high",
            "action": "Hunt for matching file hashes in your environment",
            "detail": (
                f"{hash_matches} file hash IOCs match the collective — "
                f"search SIEM/EDR logs for the last 30 days"
            ),
        })

    actions.append({
        "priority": "high",
        "action": "Hunt for related activity in your environment",
        "detail": (
            f"Cross-reference the {shared_ioc_count} matched IOCs with your "
            f"SIEM/EDR logs for the last 30 days"
        ),
    })

    return {
        "status": "analyzed",
        "contribution_id": cid,
        "receipt": receipt_dict,
        "intelligence": {
            "campaign_match": shared_ioc_count > 0,
            "shared_ioc_count": shared_ioc_count,
            "ioc_type_distribution": ioc_type_counts,
            "actions": actions,
        },
    }


async def analyze_attack_map(data: dict[str, Any], db: Database, *, engine: ProofEngine | None = None) -> dict:
    """Analyze an attack map — intelligence from ProofEngine histograms only."""
    # Store the contribution
    cid = await db.store_attack_map(data)

    tools = data.get("tools_in_scope", [])
    if isinstance(tools, str):
        try:
            tools = json.loads(tools)
        except (json.JSONDecodeError, TypeError):
            tools = []

    # Proof layer — commit first so histograms include this contribution
    receipt_dict = None
    if engine is not None:
        params = translate_attack_map(data)
        receipt = engine.commit_attack_map(**params)
        receipt_dict = receipt.to_dict()

    # === All intelligence comes from ProofEngine aggregates ===
    # Detection gaps: from ProofEngine technique coverage (histogram-based)
    detection_gaps = []
    coverage_score = 1.0
    techniques_seen = []

    if engine is not None and tools:
        coverage = engine.get_technique_coverage(tools)
        coverage_score = round(coverage.get("coverage_pct", 100) / 100, 2)
        techniques_seen = [t for t in engine._technique_freq.keys()]

        for gap in coverage.get("gap_details", []):
            gap_entry = {
                "technique_id": gap["technique_id"],
                "frequency": gap["frequency"],
                "your_tools_miss": True,
                "caught_by_count": len(gap.get("caught_by", [])),
            }
            # Enrich with public MITRE guidance
            tg = get_technique_guidance(gap["technique_id"])
            if tg:
                gap_entry["name"] = tg["name"]
                gap_entry["mitigations"] = tg["mitigations"]
                gap_entry["recommended_categories"] = tg["recommended_categories"]
            detection_gaps.append(gap_entry)
    else:
        # Fallback to DB for gap analysis when no engine
        gaps = await db.get_techniques_for_tools(tools, exclude_contribution_id=cid) if tools else []
        top_techniques = await db.get_top_techniques(50)
        techniques_seen = [t["technique_id"] for t in top_techniques]

        seen_ids = set()
        for g in gaps:
            tid = g["technique_id"]
            if tid in seen_ids:
                continue
            seen_ids.add(tid)
            caught_by = [t for t in g.get("detected_by", []) if t.lower() not in {t2.lower() for t2 in tools}]
            gap_entry = {
                "technique_id": tid,
                "frequency": 1,
                "your_tools_miss": True,
                "caught_by_count": len(caught_by),
            }
            tg = get_technique_guidance(tid)
            if tg:
                gap_entry["name"] = tg["name"]
                gap_entry["mitigations"] = tg["mitigations"]
                gap_entry["recommended_categories"] = tg["recommended_categories"]
            detection_gaps.append(gap_entry)
        coverage_score = round(
            max(0.0, 1.0 - (len(detection_gaps) / max(len(top_techniques), 1))),
            2,
        )

    # Template-based actions from aggregate gap analysis
    actions = []
    for i, gap in enumerate(detection_gaps[:5]):
        priority = "critical" if i == 0 else "high" if i < 3 else "medium"
        actions.append({
            "priority": priority,
            "action": f"Deploy {gap['technique_id']} detection",
            "detail": (
                f"Technique {gap['technique_id']} observed {gap['frequency']}x across the collective. "
                f"Your tools miss it. {gap['caught_by_count']} other tools detect it."
            ),
        })

    # Remediation hints from ProofEngine histograms (aggregate only)
    # These are category-level patterns, NOT individual org actions
    remediation_hints = {}
    if engine is not None:
        rem_stats = engine.get_remediation_stats()
        if rem_stats["total_actions"] > 0:
            # What categories of remediation are most effective across the collective
            effective_categories = []
            for cat, eff_map in rem_stats.get("by_category", {}).items():
                stopped = eff_map.get("stopped_attack", 0)
                slowed = eff_map.get("slowed_attack", 0)
                total = sum(eff_map.values())
                if total > 0:
                    effective_categories.append({
                        "category": cat,
                        "success_rate": round((stopped + slowed) / total, 2),
                        "total_reports": total,
                    })
            effective_categories.sort(key=lambda x: -x["success_rate"])

            if effective_categories:
                best = effective_categories[0]
                actions.insert(0, {
                    "priority": "critical",
                    "action": f"Prioritize {best['category']} — {int(best['success_rate'] * 100)}% success rate across the collective",
                    "detail": (
                        f"Across {rem_stats['attack_map_count']} attack reports, "
                        f"{best['category']} actions stopped or slowed attacks "
                        f"{int(best['success_rate'] * 100)}% of the time"
                    ),
                })

            gap_ids = [g["technique_id"] for g in detection_gaps]
            remediation_hints = enrich_remediation_hints({
                "most_effective_categories": effective_categories[:5],
                "severity_distribution": rem_stats.get("severity_distribution", {}),
                "typical_detect_time": rem_stats.get("time_to_detect", {}),
                "typical_contain_time": rem_stats.get("time_to_contain", {}),
                "total_attack_reports": rem_stats["attack_map_count"],
            }, gap_technique_ids=gap_ids)

    if not actions:
        actions.append({
            "priority": "info",
            "action": "Coverage looks good",
            "detail": (
                "No detection gaps found for your tools based on current "
                "collective intelligence. Continue monitoring for new threats."
            ),
        })

    return {
        "status": "analyzed",
        "contribution_id": cid,
        "receipt": receipt_dict,
        "intelligence": {
            "detection_gaps": detection_gaps,
            "coverage_score": coverage_score,
            "techniques_seen_by_others": techniques_seen[:50],
            "actions": actions,
            "remediation_hints": remediation_hints if remediation_hints else None,
        },
    }


async def analyze_eval_record(
    data: dict[str, Any],
    db: Database,
    *,
    engine: ProofEngine | None = None,
    contributor_profile_id: str | None = None,
) -> dict:
    """Analyze an eval record — aggregates only, no individual contribution details."""
    # Store the contribution
    cid = await db.store_eval_record(data)

    # Support both wire format and flat format
    d = data.get("data", data)
    vendor = d.get("vendor")
    category = d.get("category")
    your_score = d.get("overall_score")

    # Proof layer
    receipt_dict = None
    if engine is not None:
        vendor_t, category_t, values_t = translate_eval(data)
        receipt = engine.commit_contribution(
            vendor_t,
            category_t,
            values_t,
            contributor_profile_id=contributor_profile_id,
        )
        receipt_dict = receipt.to_dict()

    if not vendor:
        return {
            "status": "analyzed",
            "contribution_id": cid,
            "receipt": receipt_dict,
            "intelligence": {
                "your_vendor": None,
                "your_score": your_score,
                "category_avg": None,
                "percentile": None,
                "known_gaps_count": 0,
                "actions": [
                    {
                        "priority": "info",
                        "action": "No vendor specified",
                        "detail": "Submit with a vendor name to get comparative analysis.",
                    }
                ],
            },
        }

    # Get aggregate data (these are already aggregates, not individual records)
    aggregate = await db.get_vendor_aggregate(vendor)
    category_avg = await db.get_category_average(category) if category else None

    # Vendor gaps — aggregate technique gap count, not individual details
    vendor_gap_ids = await db.get_vendor_gaps(vendor)
    gaps_count = len(vendor_gap_ids)

    # ProofEngine aggregate if available
    engine_agg = None
    if engine is not None:
        engine_agg = engine.get_aggregate(vendor)

    if not aggregate and not engine_agg:
        return {
            "status": "analyzed",
            "contribution_id": cid,
            "receipt": receipt_dict,
            "intelligence": {
                "your_vendor": vendor,
                "your_score": your_score,
                "category_avg": category_avg,
                "percentile": None,
                "known_gaps_count": gaps_count,
                "actions": [
                    {
                        "priority": "info",
                        "action": "Baseline established",
                        "detail": (
                            f"First evaluation for {vendor}. Your contribution establishes "
                            f"the baseline. Future analyses will compare against this."
                        ),
                    }
                ],
            },
        }

    # Use ProofEngine aggregate if available (cryptographically verified)
    if engine_agg:
        avg_score = engine_agg.get("avg_overall_score")
        contributor_count = engine_agg.get("contributor_count", 0)
    else:
        avg_score = aggregate.get("avg_score") if aggregate else None
        contributor_count = aggregate.get("contributor_count", 0) if aggregate else 0

    # Simple percentile estimate
    if your_score is not None and avg_score is not None:
        if your_score > avg_score:
            percentile = 75
        elif your_score == avg_score:
            percentile = 50
        else:
            percentile = 25
    else:
        percentile = None

    # Template-based actions from aggregate patterns
    actions = []
    if gaps_count > 0:
        actions.append({
            "priority": "medium",
            "action": f"Supplement {vendor} — {gaps_count} known detection gaps",
            "detail": (
                f"{vendor} has {gaps_count} technique gaps reported across the collective. "
                f"Consider custom Sigma rules or a complementary tool."
            ),
        })

    if your_score is not None and avg_score is not None:
        if your_score >= avg_score:
            actions.append({
                "priority": "info",
                "action": f"{vendor} scores at or above average",
                "detail": (
                    f"Your score ({your_score}) vs collective average "
                    f"({round(avg_score, 1) if avg_score else '?'}) "
                    f"across {contributor_count} evaluations. "
                    f"{'Address detection gaps to maximize value.' if gaps_count > 0 else 'No known gaps detected.'}"
                ),
            })
        else:
            actions.append({
                "priority": "high",
                "action": f"Investigate {vendor} underperformance",
                "detail": (
                    f"Your score ({your_score}) is below the collective average "
                    f"({round(avg_score, 1)}) across {contributor_count} evaluations. "
                    f"Review configuration and deployment."
                ),
            })

    if not actions:
        actions.append({
            "priority": "info",
            "action": "Evaluation recorded",
            "detail": f"Your {vendor} evaluation has been added to the collective intelligence.",
        })

    return {
        "status": "analyzed",
        "contribution_id": cid,
        "receipt": receipt_dict,
        "intelligence": {
            "your_vendor": vendor,
            "your_score": your_score,
            "category_avg": round(category_avg, 1) if category_avg is not None else None,
            "percentile": percentile,
            "contributor_count": contributor_count,
            "known_gaps_count": gaps_count,
            "actions": actions,
        },
    }
