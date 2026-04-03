"""
Tests for nur HIPAA Safe Harbor de-identification verification.

Covers:
  - verify_safe_harbor: compliant results and residual PII detection
  - strip_safe_harbor: removal of all HIPAA identifier patterns
  - verify_gdpr_recital26: re-identification risk assessment
  - SAFE_HARBOR_MAP: all 18 identifiers present with CFR references
"""
from __future__ import annotations

import pytest

from nur.deidentify import (
    HIPAASafeHarborStatus,
    IdentifierCheck,
    SAFE_HARBOR_MAP,
    strip_safe_harbor,
    verify_gdpr_recital26,
    verify_safe_harbor,
)


# ── SAFE_HARBOR_MAP coverage ───────────────────────────────────────────────────

class TestSafeHarborMap:
    """Verify all 18 HIPAA Safe Harbor identifiers are mapped."""

    def test_all_18_identifiers_present(self):
        assert len(SAFE_HARBOR_MAP) == 18

    def test_every_entry_has_cfr_reference(self):
        for key, entry in SAFE_HARBOR_MAP.items():
            assert "cfr_reference" in entry, f"Missing cfr_reference for {key}"
            assert entry["cfr_reference"].startswith("§164.514"), (
                f"Invalid CFR reference for {key}: {entry['cfr_reference']}"
            )

    def test_every_entry_has_method(self):
        for key, entry in SAFE_HARBOR_MAP.items():
            assert "method" in entry, f"Missing method for {key}"
            assert len(entry["method"]) > 0, f"Empty method for {key}"

    def test_every_entry_has_evidence(self):
        for key, entry in SAFE_HARBOR_MAP.items():
            assert "evidence" in entry, f"Missing evidence for {key}"

    def test_every_entry_has_status(self):
        for key, entry in SAFE_HARBOR_MAP.items():
            assert "default_status" in entry, f"Missing default_status for {key}"
            assert entry["default_status"] in ("removed", "not_applicable", "needs_review")

    def test_expected_identifiers(self):
        expected = {
            "names", "geographic_data", "dates", "phone_numbers", "fax_numbers",
            "email_addresses", "ssn", "medical_record_numbers",
            "health_plan_beneficiary_numbers", "account_numbers",
            "certificate_license_numbers", "vehicle_identifiers",
            "device_identifiers", "web_urls", "ip_addresses",
            "biometric_identifiers", "full_face_photographs",
            "other_unique_identifying_numbers",
        }
        assert set(SAFE_HARBOR_MAP.keys()) == expected


# ── strip_safe_harbor ──────────────────────────────────────────────────────────

class TestStripSafeHarbor:
    """Test enhanced stripping covers all HIPAA identifier patterns."""

    def test_ssn_removed(self):
        result = strip_safe_harbor("SSN is 123-45-6789")
        assert "123-45-6789" not in result
        assert "[SSN]" in result

    def test_medical_record_removed(self):
        result = strip_safe_harbor("MRN: ABC12345")
        assert "ABC12345" not in result
        assert "[MEDICAL_RECORD]" in result

    def test_medical_record_variant(self):
        result = strip_safe_harbor("Med Rec No 987654321")
        assert "987654321" not in result
        assert "[MEDICAL_RECORD]" in result

    def test_health_plan_id_removed(self):
        result = strip_safe_harbor("Member ID: XYZ789012")
        assert "XYZ789012" not in result
        assert "[HEALTH_PLAN_ID]" in result

    def test_account_number_removed(self):
        result = strip_safe_harbor("acct 1234567890123456")
        assert "1234567890123456" not in result
        assert "[ACCOUNT_NUM]" in result

    def test_vin_removed(self):
        result = strip_safe_harbor("VIN: 1HGCM82633A004352")
        assert "1HGCM82633A004352" not in result
        assert "[VIN]" in result

    def test_device_serial_removed(self):
        result = strip_safe_harbor("Device serial: ABC-123-DEF-456")
        assert "ABC-123-DEF-456" not in result
        assert "[DEVICE_SERIAL]" in result

    def test_email_still_removed(self):
        """Existing anonymize.py patterns still work through strip_safe_harbor."""
        result = strip_safe_harbor("Contact john@example.com")
        assert "john@example.com" not in result
        assert "[EMAIL]" in result

    def test_phone_still_removed(self):
        result = strip_safe_harbor("Call 555-123-4567")
        assert "555-123-4567" not in result

    def test_ip_still_removed(self):
        result = strip_safe_harbor("Server 192.168.1.1")
        assert "192.168.1.1" not in result

    def test_empty_passthrough(self):
        assert strip_safe_harbor("") == ""
        assert strip_safe_harbor("no pii here") == "no pii here"

    def test_multiple_identifiers_in_one_text(self):
        text = (
            "Patient SSN 123-45-6789, MRN: PAT001, "
            "email john@test.com, phone 555-123-4567"
        )
        result = strip_safe_harbor(text)
        assert "123-45-6789" not in result
        assert "PAT001" not in result
        assert "john@test.com" not in result
        assert "555-123-4567" not in result


# ── verify_safe_harbor ─────────────────────────────────────────────────────────

class TestVerifySafeHarbor:
    """Test Safe Harbor compliance verification."""

    def test_clean_contribution_is_compliant(self):
        """A properly anonymized contribution should pass."""
        clean_data = {
            "vendor": "CrowdStrike",
            "category": "edr",
            "overall_score": 8.5,
            "top_strength": "Good detection quality",
            "industry": "tech",
            "org_size": "1000-5000",
            "role_tier": "ciso",
        }
        result = verify_safe_harbor(clean_data)
        assert isinstance(result, HIPAASafeHarborStatus)
        assert result.compliant is True
        assert len(result.residual_risks) == 0

    def test_all_18_checks_present(self):
        result = verify_safe_harbor({"vendor": "Test"})
        assert len(result.identifier_checks) == 18

    def test_detects_residual_email(self):
        dirty_data = {
            "notes": "Contact admin@company.com for details",
        }
        result = verify_safe_harbor(dirty_data)
        assert result.compliant is False
        assert any("email" in r.lower() for r in result.residual_risks)

    def test_detects_residual_phone(self):
        dirty_data = {
            "notes": "Call 555-123-4567 for support",
        }
        result = verify_safe_harbor(dirty_data)
        assert result.compliant is False
        assert any("phone" in r.lower() for r in result.residual_risks)

    def test_detects_residual_ssn(self):
        dirty_data = {
            "notes": "Employee SSN is 123-45-6789",
        }
        result = verify_safe_harbor(dirty_data)
        assert result.compliant is False
        assert any("ssn" in r.lower() for r in result.residual_risks)

    def test_detects_residual_ip(self):
        dirty_data = {
            "notes": "Server at 10.0.0.1 was compromised",
        }
        result = verify_safe_harbor(dirty_data)
        assert result.compliant is False
        assert any("ipv4" in r.lower() for r in result.residual_risks)

    def test_replacement_tags_not_flagged(self):
        """Replacement tags like [EMAIL] should not trigger false positives."""
        clean_data = {
            "notes": "Contact [EMAIL] for details, IP was [IP_ADDR]",
        }
        result = verify_safe_harbor(clean_data)
        assert result.compliant is True

    def test_nested_dict_scanned(self):
        dirty_data = {
            "techniques": [
                {"notes": "admin@evil.com sent phishing"},
            ],
        }
        result = verify_safe_harbor(dirty_data)
        assert result.compliant is False

    def test_needs_review_status_on_residual(self):
        dirty_data = {"notes": "SSN 123-45-6789"}
        result = verify_safe_harbor(dirty_data)
        assert result.identifier_checks["ssn"].status == "needs_review"

    def test_compliant_recommendation(self):
        result = verify_safe_harbor({"vendor": "Test"})
        assert "clears" in result.recommendation.lower()

    def test_noncompliant_recommendation(self):
        result = verify_safe_harbor({"notes": "admin@test.com"})
        assert "not" in result.recommendation.lower()


# ── verify_gdpr_recital26 ─────────────────────────────────────────────────────

class TestVerifyGDPRRecital26:
    """Test GDPR Recital 26 re-identification risk assessment."""

    def test_returns_assessment_dict(self):
        result = verify_gdpr_recital26({"vendor": "Test", "overall_score": 8})
        assert isinstance(result, dict)
        assert "compliant" in result
        assert "standard" in result
        assert result["standard"] == "GDPR Recital 26"
        assert "assessment" in result

    def test_clean_data_is_compliant(self):
        clean = {
            "industry": "tech",
            "org_size": "1000-5000",
            "role_tier": "ciso",
            "overall_score": 8.5,
        }
        result = verify_gdpr_recital26(clean)
        assert result["compliant"] is True
        assert result["assessment"]["overall_risk"] == "very_low"

    def test_org_name_triggers_noncompliant(self):
        dirty = {
            "org_name": "Acme Corp",
            "overall_score": 8.5,
        }
        result = verify_gdpr_recital26(dirty)
        assert result["compliant"] is False

    def test_residual_pii_triggers_elevated_risk(self):
        dirty = {
            "notes": "Contact admin@corp.com",
        }
        result = verify_gdpr_recital26(dirty)
        assert result["assessment"]["overall_risk"] == "elevated"
        assert result["assessment"]["direct_identification"]["status"] == "fail"

    def test_all_assessment_vectors_present(self):
        result = verify_gdpr_recital26({"vendor": "Test"})
        assessment = result["assessment"]
        for vector in (
            "direct_identification",
            "indirect_identification",
            "timing_correlation",
            "contribution_pattern",
            "overall_risk",
            "recommendation",
        ):
            assert vector in assessment, f"Missing assessment vector: {vector}"

    def test_timing_and_pattern_always_pass(self):
        """Timing and contribution pattern are architectural — always pass."""
        result = verify_gdpr_recital26({"notes": "admin@test.com"})
        assert result["assessment"]["timing_correlation"]["status"] == "pass"
        assert result["assessment"]["contribution_pattern"]["status"] == "pass"
