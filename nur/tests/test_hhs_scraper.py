import pytest
from nur.feeds.hhs_breach import (
    RECENT_MAJOR_BREACHES,
    hhs_breach_to_nur_payload,
    HHSBreach,
)


class TestHHSBreachScraper:
    def test_breaches_have_techniques(self):
        for breach in RECENT_MAJOR_BREACHES:
            if breach.breach_type == "Hacking/IT Incident":
                assert len(breach.techniques) > 0

    def test_payload_format(self):
        payload = hhs_breach_to_nur_payload(RECENT_MAJOR_BREACHES[0])
        assert "techniques" in payload
        assert payload["source"] == "hhs-breach-portal"
        assert len(payload["techniques"]) > 0

    def test_severity_mapping(self):
        big_breach = HHSBreach("Test", "CA", "Provider", 5000000, "2024-01-01", "Hacking/IT Incident", "Network Server")
        payload = hhs_breach_to_nur_payload(big_breach)
        assert payload["severity"] == "critical"

        small_breach = HHSBreach("Test", "CA", "Provider", 500, "2024-01-01", "Theft", "Laptop")
        payload = hhs_breach_to_nur_payload(small_breach)
        assert payload["severity"] == "high"
