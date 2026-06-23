"""
Test Suite for Threat Intelligence Feeds Aggregator
Dimension A: Feature Expansion
Version: v23 - June 2026

Tests cover:
- Basic indicator addition and deduplication
- CVE entry handling
- IP reputation scoring
- Phishing URL management
- Querying and filtering
- Statistics tracking
- Export/Import functionality
- Expiration handling
"""

import json
import os
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

from neural_shield.feature_expansion_threat_intelligence_feeds_aggregator_v23_2026_june import (
    SeverityLevel,
    ThreatIndicator,
    ThreatIntelligenceAggregator,
    ThreatSource,
    ThreatType,
)


class TestSeverityLevel(unittest.TestCase):
    """Tests for SeverityLevel enum and CVSS mapping."""

    def test_cvss_critical(self):
        self.assertEqual(SeverityLevel.from_cvss(10.0), SeverityLevel.CRITICAL)
        self.assertEqual(SeverityLevel.from_cvss(9.0), SeverityLevel.CRITICAL)

    def test_cvss_high(self):
        self.assertEqual(SeverityLevel.from_cvss(8.9), SeverityLevel.HIGH)
        self.assertEqual(SeverityLevel.from_cvss(7.0), SeverityLevel.HIGH)

    def test_cvss_medium(self):
        self.assertEqual(SeverityLevel.from_cvss(6.9), SeverityLevel.MEDIUM)
        self.assertEqual(SeverityLevel.from_cvss(4.0), SeverityLevel.MEDIUM)

    def test_cvss_low(self):
        self.assertEqual(SeverityLevel.from_cvss(3.9), SeverityLevel.LOW)
        self.assertEqual(SeverityLevel.from_cvss(0.1), SeverityLevel.LOW)

    def test_cvss_info(self):
        self.assertEqual(SeverityLevel.from_cvss(0.0), SeverityLevel.INFO)


class TestThreatIndicator(unittest.TestCase):
    """Tests for ThreatIndicator dataclass."""

    def setUp(self):
        self.now = datetime.now(timezone.utc)
        self.indicator = ThreatIndicator(
            indicator_id="test123",
            indicator_value="192.168.1.1",
            threat_type=ThreatType.IP_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.ABUSEIPDB,
            confidence=0.85,
            first_seen=self.now,
            last_seen=self.now,
            description="Test IP",
            tags=["test"],
            metadata={"score": 85},
            ttl=3600
        )

    def test_is_expired_false(self):
        self.assertFalse(self.indicator.is_expired())

    def test_is_expired_true(self):
        old_time = self.now - timedelta(seconds=7200)
        self.indicator.last_seen = old_time
        self.assertTrue(self.indicator.is_expired())

    def test_to_dict(self):
        result = self.indicator.to_dict()
        self.assertEqual(result["indicator_id"], "test123")
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["confidence"], 0.85)
        self.assertIn("expired", result)


class TestThreatIntelligenceAggregator(unittest.TestCase):
    """Main test suite for ThreatIntelligenceAggregator."""

    def setUp(self):
        self.aggregator = ThreatIntelligenceAggregator()

    def test_initialization(self):
        stats = self.aggregator.get_statistics()
        self.assertEqual(stats["total_indicators"], 0)
        self.assertEqual(stats["active_indicators"], 0)

    def test_add_basic_indicator(self):
        result = self.aggregator.add_indicator(
            indicator_value="192.168.1.1",
            threat_type=ThreatType.IP_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.ABUSEIPDB,
            confidence=0.85
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(self.aggregator.get_statistics()["total_indicators"], 1)

    def test_add_cve_entry(self):
        indicator = self.aggregator.add_cve_entry(
            cve_id="CVE-2026-1234",
            cvss_score=9.8,
            description="Critical vulnerability",
            affected_products=["Product A", "Product B"]
        )
        
        self.assertEqual(indicator.severity, SeverityLevel.CRITICAL)
        self.assertIn("cve", indicator.tags)
        self.assertEqual(indicator.metadata["cvss_score"], 9.8)

    def test_add_ip_reputation_critical(self):
        indicator = self.aggregator.add_ip_reputation(
            ip_address="10.0.0.1",
            abuse_score=95,
            country="US",
            reports=50
        )
        
        self.assertEqual(indicator.severity, SeverityLevel.CRITICAL)
        self.assertEqual(indicator.confidence, 0.95)
        self.assertEqual(indicator.metadata["abuse_score"], 95)

    def test_add_ip_reputation_low(self):
        indicator = self.aggregator.add_ip_reputation(
            ip_address="10.0.0.2",
            abuse_score=5
        )
        
        self.assertEqual(indicator.severity, SeverityLevel.INFO)

    def test_add_phishing_url(self):
        indicator = self.aggregator.add_phishing_url(
            url="http://evil-phish.com/login",
            target_brand="PayPal",
            verified=True
        )
        
        self.assertEqual(indicator.threat_type, ThreatType.PHISHING)
        self.assertEqual(indicator.severity, SeverityLevel.HIGH)
        self.assertIn("verified", indicator.tags)
        self.assertGreaterEqual(indicator.confidence, 0.95)

    def test_deduplication(self):
        # Add same indicator twice
        self.aggregator.add_indicator(
            indicator_value="192.168.1.1",
            threat_type=ThreatType.IP_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.ABUSEIPDB,
            confidence=0.85
        )
        
        result = self.aggregator.add_indicator(
            indicator_value="192.168.1.1",
            threat_type=ThreatType.IP_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.ABUSEIPDB,
            confidence=0.85
        )
        
        self.assertIsNone(result)  # Duplicate returns None
        self.assertEqual(self.aggregator.get_statistics()["total_indicators"], 1)

    def test_deduplication_updates_confidence(self):
        # Add first with lower confidence
        self.aggregator.add_indicator(
            indicator_value="192.168.1.1",
            threat_type=ThreatType.IP_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.ABUSEIPDB,
            confidence=0.70
        )
        
        # Add duplicate with higher confidence
        self.aggregator.add_indicator(
            indicator_value="192.168.1.1",
            threat_type=ThreatType.IP_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.ABUSEIPDB,
            confidence=0.95
        )
        
        indicators = self.aggregator.query_indicators()
        self.assertEqual(indicators[0].confidence, 0.95)

    def test_case_normalization(self):
        self.aggregator.add_indicator(
            indicator_value="EVIL.COM",
            threat_type=ThreatType.DOMAIN_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.CUSTOM,
            confidence=0.9
        )
        
        result = self.aggregator.check_value("evil.com")
        self.assertIsNotNone(result)

    def test_query_by_threat_type(self):
        # Add mixed types
        self.aggregator.add_cve_entry("CVE-2026-0001", 7.5, "Test CVE")
        self.aggregator.add_ip_reputation("1.1.1.1", 80)
        self.aggregator.add_phishing_url("http://test.com")
        
        cves = self.aggregator.query_indicators(threat_type=ThreatType.CVE)
        self.assertEqual(len(cves), 1)
        self.assertEqual(cves[0].threat_type, ThreatType.CVE)

    def test_query_by_severity(self):
        self.aggregator.add_cve_entry("CVE-2026-0001", 9.8, "Critical")
        self.aggregator.add_cve_entry("CVE-2026-0002", 5.0, "Medium")
        
        critical = self.aggregator.query_indicators(severity=SeverityLevel.CRITICAL)
        self.assertEqual(len(critical), 1)

    def test_query_by_confidence(self):
        self.aggregator.add_indicator("test1", ThreatType.IOC, SeverityLevel.HIGH, 
                                     ThreatSource.CUSTOM, 0.5)
        self.aggregator.add_indicator("test2", ThreatType.IOC, SeverityLevel.HIGH, 
                                     ThreatSource.CUSTOM, 0.9)
        
        high_conf = self.aggregator.query_indicators(min_confidence=0.8)
        self.assertEqual(len(high_conf), 1)

    def test_query_limit(self):
        for i in range(10):
            self.aggregator.add_cve_entry(f"CVE-2026-{i:04d}", 7.5, f"Test {i}")
        
        results = self.aggregator.query_indicators(limit=5)
        self.assertEqual(len(results), 5)

    def test_check_value_found(self):
        self.aggregator.add_ip_reputation("192.168.1.100", 90)
        
        result = self.aggregator.check_value("192.168.1.100")
        self.assertIsNotNone(result)
        self.assertEqual(result.indicator_value, "192.168.1.100")

    def test_check_value_not_found(self):
        result = self.aggregator.check_value("10.0.0.255")
        self.assertIsNone(result)

    def test_statistics_by_severity(self):
        self.aggregator.add_cve_entry("CVE-1", 9.8, "Critical")
        self.aggregator.add_cve_entry("CVE-2", 7.5, "High")
        self.aggregator.add_cve_entry("CVE-3", 5.0, "Medium")
        
        stats = self.aggregator.get_statistics()
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_severity"]["high"], 1)
        self.assertEqual(stats["by_severity"]["medium"], 1)

    def test_statistics_by_source(self):
        self.aggregator.add_cve_entry("CVE-1", 7.5, "Test")
        self.aggregator.add_ip_reputation("1.1.1.1", 80)
        
        stats = self.aggregator.get_statistics()
        self.assertGreater(stats["by_source"]["cve_nvd"]["added"], 0)
        self.assertGreater(stats["by_source"]["abuseipdb"]["added"], 0)

    def test_cleanup_expired(self):
        # Add an already-expired indicator
        old_time = datetime.now(timezone.utc) - timedelta(days=2)
        self.aggregator.add_indicator(
            indicator_value="expired.com",
            threat_type=ThreatType.DOMAIN_REPUTATION,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.CUSTOM,
            confidence=0.9,
            last_seen=old_time,
            ttl=3600  # 1 hour TTL, definitely expired
        )
        
        self.aggregator.add_cve_entry("CVE-ACTIVE", 7.5, "Active CVE")
        
        initial_count = self.aggregator.get_statistics()["total_indicators"]
        removed = self.aggregator.cleanup_expired()
        
        self.assertEqual(removed, 1)
        self.assertEqual(
            self.aggregator.get_statistics()["total_indicators"],
            initial_count - 1
        )

    def test_export_import_json(self):
        # Add some data
        self.aggregator.add_cve_entry("CVE-2026-9999", 8.5, "Test export")
        self.aggregator.add_ip_reputation("10.0.0.5", 75)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            temp_path = f.name
        
        try:
            # Export
            self.aggregator.export_json(temp_path)
            
            # Verify file exists and has content
            self.assertTrue(os.path.exists(temp_path))
            with open(temp_path, 'r') as f:
                data = json.load(f)
            self.assertIn("indicators", data)
            self.assertGreater(len(data["indicators"]), 0)
            
            # Import into new aggregator
            new_aggregator = ThreatIntelligenceAggregator()
            imported = new_aggregator.import_json(temp_path)
            
            self.assertGreater(imported, 0)
            self.assertEqual(
                new_aggregator.get_statistics()["total_indicators"],
                self.aggregator.get_statistics()["total_indicators"]
            )
            
        finally:
            os.unlink(temp_path)

    def test_confidence_clamping(self):
        indicator = self.aggregator.add_indicator(
            indicator_value="test",
            threat_type=ThreatType.IOC,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.CUSTOM,
            confidence=1.5  # Should be clamped to 1.0
        )
        
        self.assertEqual(indicator.confidence, 1.0)
        
        indicator2 = self.aggregator.add_indicator(
            indicator_value="test2",
            threat_type=ThreatType.IOC,
            severity=SeverityLevel.HIGH,
            source=ThreatSource.CUSTOM,
            confidence=-0.5  # Should be clamped to 0.0
        )
        
        self.assertEqual(indicator2.confidence, 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
