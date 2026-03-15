"""Tests for nur.integrations — peacetime integrations."""
from __future__ import annotations

import csv
import json
import os
import tempfile
from pathlib import Path

import pytest

from nur.integrations.asset_inventory import (
    ALIASES,
    import_from_csv,
    import_from_json,
    match_tool_to_vendor,
)
from nur.integrations.compliance import import_compliance_status
from nur.integrations.export import (
    export_csv,
    export_misp_event,
    export_navigator_layer,
    export_stix_bundle,
)
from nur.integrations.navigator import import_navigator_layer
from nur.integrations.rfp import generate_rfp_comparison
from nur.server.vendors import VENDOR_REGISTRY


# ── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


@pytest.fixture
def navigator_layer(tmp_dir):
    """A minimal ATT&CK Navigator layer JSON file."""
    layer = {
        "name": "Test Layer",
        "versions": {"layer": "4.5", "attack": "14", "navigator": "4.9.1"},
        "domain": "enterprise-attack",
        "techniques": [
            {"techniqueID": "T1566", "score": 100, "comment": "Covered by email gateway"},
            {"techniqueID": "T1190", "score": 80, "comment": "WAF deployed"},
            {"techniqueID": "T1486", "score": 10, "comment": "No EDR"},
            {"techniqueID": "T1021", "score": 0, "comment": ""},
        ],
    }
    p = tmp_dir / "layer.json"
    p.write_text(json.dumps(layer))
    return str(p)


@pytest.fixture
def csv_inventory(tmp_dir):
    """A CSV tool inventory file."""
    p = tmp_dir / "inventory.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["tool", "department", "status"])
        w.writerow(["CrowdStrike Falcon", "Security", "active"])
        w.writerow(["Splunk Enterprise Security", "SOC", "active"])
        w.writerow(["Okta", "IT", "active"])
        w.writerow(["Microsoft Word", "IT", "active"])  # not a security tool
    return str(p)


@pytest.fixture
def json_inventory(tmp_dir):
    """A JSON tool inventory file (list of strings)."""
    p = tmp_dir / "tools.json"
    p.write_text(json.dumps([
        "CrowdStrike Falcon",
        "Splunk",
        "Okta",
        "Microsoft Defender for Endpoint",
        "Some Random Tool",
    ]))
    return str(p)


@pytest.fixture
def compliance_json(tmp_dir):
    """A Drata-like compliance export."""
    data = {
        "controls": [
            {"id": "AC-1", "status": "passing", "framework": "NIST 800-53"},
            {"id": "AC-2", "status": "passing", "framework": "NIST 800-53"},
            {"id": "164.312", "status": "failing", "framework": "HIPAA"},
            {"id": "1.1", "status": "passing", "framework": "PCI-DSS"},
        ]
    }
    p = tmp_dir / "compliance.json"
    p.write_text(json.dumps(data))
    return str(p)


@pytest.fixture
def simple_compliance_json(tmp_dir):
    """A simple dict compliance file."""
    data = {"HIPAA": True, "PCI_DSS": False, "SOC2": True}
    p = tmp_dir / "simple.json"
    p.write_text(json.dumps(data))
    return str(p)


@pytest.fixture
def compliance_csv(tmp_dir):
    """A CSV compliance file."""
    p = tmp_dir / "compliance.csv"
    with open(p, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["framework", "control_id", "status"])
        w.writerow(["HIPAA", "164.312", "passing"])
        w.writerow(["HIPAA", "164.314", "failing"])
        w.writerow(["PCI-DSS", "1.1", "passing"])
    return str(p)


@pytest.fixture
def sample_contributions():
    """Sample contributions for export tests."""
    return [
        {
            "type": "ioc_bundle",
            "source": "test",
            "iocs": [
                {"type": "ip", "value": "192.168.1.1", "context": "C2 server"},
                {"type": "domain", "value": "evil.example.com", "context": "Phishing"},
                {"type": "hash_sha256", "value": "abc123def456", "context": "Malware"},
            ],
        },
        {
            "type": "eval_record",
            "vendor": "crowdstrike",
            "overall_score": 9.2,
            "source": "mitre",
        },
        {
            "type": "attack_map",
            "techniques": [
                {"technique_id": "T1566", "technique_name": "Phishing"},
                {"technique_id": "T1486", "technique_name": "Data Encrypted for Impact"},
            ],
        },
    ]


# ── match_tool_to_vendor ─────────────────────────────────────────────────────


class TestMatchToolToVendor:
    def test_exact_slug(self):
        assert match_tool_to_vendor("crowdstrike") == "crowdstrike"
        assert match_tool_to_vendor("splunk") == "splunk"
        assert match_tool_to_vendor("okta") == "okta"

    def test_case_insensitive_slug(self):
        assert match_tool_to_vendor("CrowdStrike") == "crowdstrike"
        assert match_tool_to_vendor("SPLUNK") == "splunk"

    def test_display_name_match(self):
        assert match_tool_to_vendor("CrowdStrike Falcon") == "crowdstrike"
        assert match_tool_to_vendor("Splunk Enterprise Security") == "splunk"
        assert match_tool_to_vendor("Microsoft Defender for Endpoint") == "ms-defender"

    def test_partial_match(self):
        assert match_tool_to_vendor("Falcon") == "crowdstrike"

    def test_alias_match(self):
        assert match_tool_to_vendor("MDE") == "ms-defender"
        assert match_tool_to_vendor("CS") == "crowdstrike"
        assert match_tool_to_vendor("S1") == "sentinelone"

    def test_none_for_unknown(self):
        assert match_tool_to_vendor("Microsoft Word") is None
        assert match_tool_to_vendor("TotallyFakeTool") is None

    def test_empty_returns_none(self):
        assert match_tool_to_vendor("") is None
        assert match_tool_to_vendor("  ") is None

    def test_all_aliases_resolve(self):
        """Every alias in the ALIASES dict should resolve to a valid vendor."""
        for alias, expected_slug in ALIASES.items():
            assert expected_slug in VENDOR_REGISTRY, (
                f"Alias {alias!r} -> {expected_slug!r} not in VENDOR_REGISTRY"
            )


# ── import_from_csv ──────────────────────────────────────────────────────────


class TestImportFromCSV:
    def test_basic_csv(self, csv_inventory):
        slugs = import_from_csv(csv_inventory)
        assert "crowdstrike" in slugs
        assert "splunk" in slugs
        assert "okta" in slugs

    def test_skips_unknown_tools(self, csv_inventory):
        slugs = import_from_csv(csv_inventory)
        # "Microsoft Word" should not match anything
        assert all(s in VENDOR_REGISTRY for s in slugs)

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            import_from_csv("/nonexistent/path.csv")

    def test_empty_csv(self, tmp_dir):
        p = tmp_dir / "empty.csv"
        p.write_text("tool\n")
        slugs = import_from_csv(str(p))
        assert slugs == []

    def test_no_matching_column(self, tmp_dir):
        p = tmp_dir / "wrong.csv"
        with open(p, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["department", "budget"])
            w.writerow(["IT", "100000"])
        slugs = import_from_csv(str(p))
        assert slugs == []


# ── import_from_json ─────────────────────────────────────────────────────────


class TestImportFromJSON:
    def test_list_of_strings(self, json_inventory):
        slugs = import_from_json(json_inventory)
        assert "crowdstrike" in slugs
        assert "splunk" in slugs
        assert "okta" in slugs
        assert "ms-defender" in slugs

    def test_list_of_dicts(self, tmp_dir):
        data = [
            {"tool": "CrowdStrike Falcon", "status": "active"},
            {"vendor": "Splunk", "status": "active"},
        ]
        p = tmp_dir / "dicts.json"
        p.write_text(json.dumps(data))
        slugs = import_from_json(str(p))
        assert "crowdstrike" in slugs
        assert "splunk" in slugs

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            import_from_json("/nonexistent/tools.json")

    def test_deduplicated(self, tmp_dir):
        data = ["CrowdStrike", "crowdstrike", "CrowdStrike Falcon", "CS"]
        p = tmp_dir / "dupes.json"
        p.write_text(json.dumps(data))
        slugs = import_from_json(str(p))
        assert slugs.count("crowdstrike") == 1


# ── import_navigator_layer ───────────────────────────────────────────────────


class TestImportNavigatorLayer:
    def test_returns_threat_model(self, navigator_layer):
        model = import_navigator_layer(navigator_layer)
        assert "coverage" in model
        assert "gaps" in model
        assert "coverage_score" in model
        assert "navigator_source" in model

    def test_navigator_source_metadata(self, navigator_layer):
        model = import_navigator_layer(navigator_layer)
        nav = model["navigator_source"]
        assert nav["layer_name"] == "Test Layer"
        assert nav["total_techniques"] == 4
        assert nav["covered_count"] == 2  # score > 50
        assert nav["gap_count"] == 2  # score <= 50

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            import_navigator_layer("/nonexistent/layer.json")

    def test_empty_techniques_raises(self, tmp_dir):
        p = tmp_dir / "empty.json"
        p.write_text(json.dumps({"techniques": []}))
        with pytest.raises(ValueError, match="no techniques"):
            import_navigator_layer(str(p))

    def test_vertical_parameter(self, navigator_layer):
        model = import_navigator_layer(navigator_layer, vertical="financial")
        assert model["vertical"] == "financial"


# ── import_compliance_status ─────────────────────────────────────────────────


class TestImportComplianceStatus:
    def test_structured_json(self, compliance_json):
        status = import_compliance_status(compliance_json)
        assert "NIST 800-53" in status
        assert status["NIST 800-53"] is True  # has passing controls
        assert "PCI-DSS" in status
        assert status["PCI-DSS"] is True

    def test_simple_json(self, simple_compliance_json):
        status = import_compliance_status(simple_compliance_json)
        assert status["HIPAA"] is True
        assert status["PCI-DSS"] is False
        assert status["SOC2"] is True

    def test_csv_format(self, compliance_csv):
        status = import_compliance_status(compliance_csv)
        assert "HIPAA" in status
        assert status["HIPAA"] is True  # at least one passing
        assert "PCI-DSS" in status
        assert status["PCI-DSS"] is True

    def test_file_not_found(self):
        with pytest.raises(FileNotFoundError):
            import_compliance_status("/nonexistent/compliance.json")

    def test_framework_normalization(self, tmp_dir):
        """Framework names should be normalized."""
        data = {"hipaa": True, "pci_dss": False, "nist csf": True}
        p = tmp_dir / "normalize.json"
        p.write_text(json.dumps(data))
        status = import_compliance_status(str(p))
        assert "HIPAA" in status
        assert "PCI-DSS" in status
        assert "NIST CSF" in status


# ── generate_rfp_comparison ──────────────────────────────────────────────────


class TestRFPComparison:
    def test_basic_comparison(self):
        result = generate_rfp_comparison(
            candidates=["crowdstrike", "sentinelone", "ms-defender"],
            category="edr",
        )
        assert result["category"] == "edr"
        assert len(result["candidates"]) == 3
        assert len(result["comparison_table"]) == 3
        assert result["recommendation"]  # non-empty

    def test_candidates_have_scores(self):
        result = generate_rfp_comparison(["crowdstrike", "sentinelone"])
        for c in result["candidates"]:
            assert c["found"] is True
            assert "scores" in c
            assert "overall" in c["scores"]

    def test_unknown_vendor(self):
        result = generate_rfp_comparison(["crowdstrike", "nonexistent-tool"])
        assert "nonexistent-tool" in result["not_found"]

    def test_single_candidate(self):
        result = generate_rfp_comparison(["crowdstrike"])
        assert len(result["comparison_table"]) == 1
        assert result["recommendation"]

    def test_sorted_by_score(self):
        result = generate_rfp_comparison(["crowdstrike", "sentinelone", "ms-defender"])
        scores = [r["overall"] for r in result["comparison_table"]]
        assert scores == sorted(scores, reverse=True)


# ── export_stix_bundle ───────────────────────────────────────────────────────


class TestExportSTIX:
    def test_returns_valid_json(self, sample_contributions):
        result = export_stix_bundle(sample_contributions)
        data = json.loads(result)
        assert data["type"] == "bundle"
        assert len(data["objects"]) > 0

    def test_has_identity(self, sample_contributions):
        data = json.loads(export_stix_bundle(sample_contributions))
        types = [o["type"] for o in data["objects"]]
        assert "identity" in types

    def test_iocs_become_indicators(self, sample_contributions):
        data = json.loads(export_stix_bundle(sample_contributions))
        indicators = [o for o in data["objects"] if o["type"] == "indicator"]
        assert len(indicators) == 3  # 3 IOCs in sample

    def test_attack_maps_become_attack_patterns(self, sample_contributions):
        data = json.loads(export_stix_bundle(sample_contributions))
        patterns = [o for o in data["objects"] if o["type"] == "attack-pattern"]
        assert len(patterns) == 2  # 2 techniques

    def test_empty_contributions(self):
        result = export_stix_bundle([])
        data = json.loads(result)
        # Should at least have the identity object
        assert data["type"] == "bundle"
        assert len(data["objects"]) == 1


# ── export_misp_event ────────────────────────────────────────────────────────


class TestExportMISP:
    def test_returns_valid_json(self, sample_contributions):
        result = export_misp_event(sample_contributions)
        data = json.loads(result)
        assert "Event" in data

    def test_has_attributes(self, sample_contributions):
        data = json.loads(export_misp_event(sample_contributions))
        attrs = data["Event"]["Attribute"]
        assert len(attrs) > 0

    def test_ioc_attributes(self, sample_contributions):
        data = json.loads(export_misp_event(sample_contributions))
        attrs = data["Event"]["Attribute"]
        types = [a["type"] for a in attrs]
        assert "ip-dst" in types
        assert "domain" in types


# ── export_csv ───────────────────────────────────────────────────────────────


class TestExportCSV:
    def test_returns_csv_string(self, sample_contributions):
        result = export_csv(sample_contributions)
        assert "type,value,category" in result

    def test_contains_ioc_rows(self, sample_contributions):
        result = export_csv(sample_contributions)
        assert "192.168.1.1" in result
        assert "evil.example.com" in result

    def test_empty_contributions(self):
        result = export_csv([])
        lines = result.strip().split("\n")
        assert len(lines) == 1  # header only


# ── export_navigator_layer ───────────────────────────────────────────────────


class TestExportNavigatorLayer:
    def test_returns_valid_navigator_json(self):
        from nur.threat_model import generate_threat_model
        model = generate_threat_model(["crowdstrike", "splunk"], vertical="healthcare")
        result = export_navigator_layer(model)
        data = json.loads(result)
        assert data["domain"] == "enterprise-attack"
        assert "techniques" in data
        assert len(data["techniques"]) > 0

    def test_covered_techniques_have_high_score(self):
        from nur.threat_model import generate_threat_model
        model = generate_threat_model(["crowdstrike", "splunk"], vertical="healthcare")
        data = json.loads(export_navigator_layer(model))
        covered_ids = set(model["coverage"].keys())
        for t in data["techniques"]:
            if t["techniqueID"] in covered_ids:
                assert t["score"] == 100

    def test_gap_techniques_have_low_score(self):
        from nur.threat_model import generate_threat_model
        model = generate_threat_model(["crowdstrike"], vertical="healthcare")
        data = json.loads(export_navigator_layer(model))
        gap_ids = {g["id"] for g in model["gaps"]}
        for t in data["techniques"]:
            if t["techniqueID"] in gap_ids:
                assert t["score"] == 25

    def test_roundtrip_navigator(self, tmp_dir):
        """Export a model as Navigator, re-import it, verify structure."""
        from nur.threat_model import generate_threat_model
        model = generate_threat_model(["crowdstrike", "splunk", "okta"], vertical="healthcare")
        layer_json = export_navigator_layer(model)

        # Write and re-import
        p = tmp_dir / "roundtrip.json"
        p.write_text(layer_json)
        reimported = import_navigator_layer(str(p), vertical="healthcare")

        assert "coverage" in reimported
        assert "gaps" in reimported
        assert reimported["navigator_source"]["layer_name"].startswith("Organization")
