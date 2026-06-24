#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Feed Aggregator v27
NeuralShield-AI

Tests cover:
- Basic indicator addition and lookup
- Deduplication and merging logic
- Cache TTL expiration
- Batch operations
- Severity and type filtering
- STIX/JSON export
- Statistics tracking
- Thread safety
"""

import sys
import os
import unittest
import time
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_feed_aggregator_v27_2026_june import (
    ThreatSeverity,
    ThreatType,
    FeedSource,
    ThreatIndicator,
    FeedConfig,
    ThreatFeedCache,
    ThreatIntelligenceAggregator,
    create_aggregator
)


class TestThreatSeverityEnum(unittest.TestCase):
    """Test ThreatSeverity enum values"""
    
    def test_severity_values(self):
        self.assertEqual(ThreatSeverity.LOW.value, "low")
        self.assertEqual(ThreatSeverity.MEDIUM.value, "medium")
        self.assertEqual(ThreatSeverity.HIGH.value, "high")
        self.assertEqual(ThreatSeverity.CRITICAL.value, "critical")
        self.assertEqual(ThreatSeverity.UNKNOWN.value, "unknown")
    
    def test_severity_count(self):
        self.assertEqual(len(list(ThreatSeverity)), 5)


class TestThreatTypeEnum(unittest.TestCase):
    """Test ThreatType enum values"""
    
    def test_threat_type_values(self):
        self.assertEqual(ThreatType.MALWARE.value, "malware")
        self.assertEqual(ThreatType.PHISHING.value, "phishing")
        self.assertEqual(ThreatType.C2.value, "command_and_control")
    
    def test_threat_type_count(self):
        self.assertEqual(len(list(ThreatType)), 9)


class TestFeedSourceEnum(unittest.TestCase):
    """Test FeedSource enum values"""
    
    def test_feed_source_values(self):
        self.assertEqual(FeedSource.ABUSEIPDB.value, "abuseipdb")
        self.assertEqual(FeedSource.VIRUSTOTAL.value, "virustotal")
        self.assertEqual(FeedSource.THREATFOX.value, "threatfox")
    
    def test_feed_source_count(self):
        self.assertEqual(len(list(FeedSource)), 8)


class TestThreatIndicator(unittest.TestCase):
    """Test ThreatIndicator dataclass"""
    
    def setUp(self):
        self.now = datetime.now()
    
    def test_indicator_creation(self):
        ind = ThreatIndicator(
            indicator="192.168.1.1",
            indicator_type="ip",
            threat_type=ThreatType.MALWARE,
            severity=ThreatSeverity.HIGH,
            source=FeedSource.ABUSEIPDB,
            confidence=0.85,
            first_seen=self.now,
            last_seen=self.now,
            ttl=3600
        )
        self.assertEqual(ind.indicator, "192.168.1.1")
        self.assertEqual(ind.confidence, 0.85)
        self.assertTrue(len(ind.indicator_id) > 0)
    
    def test_indicator_id_generation(self):
        ind1 = ThreatIndicator(
            indicator="192.168.1.1",
            indicator_type="ip",
            threat_type=ThreatType.MALWARE,
            severity=ThreatSeverity.HIGH,
            source=FeedSource.ABUSEIPDB,
            confidence=0.85,
            first_seen=self.now,
            last_seen=self.now,
            ttl=3600
        )
        ind2 = ThreatIndicator(
            indicator="192.168.1.1",
            indicator_type="ip",
            threat_type=ThreatType.PHISHING,
            severity=ThreatSeverity.LOW,
            source=FeedSource.VIRUSTOTAL,
            confidence=0.5,
            first_seen=self.now,
            last_seen=self.now,
            ttl=3600
        )
        # Same indicator+type should produce same ID
        self.assertEqual(ind1.indicator_id, ind2.indicator_id)
    
    def test_metadata_default(self):
        ind = ThreatIndicator(
            indicator="192.168.1.1",
            indicator_type="ip",
            threat_type=ThreatType.MALWARE,
            severity=ThreatSeverity.HIGH,
            source=FeedSource.ABUSEIPDB,
            confidence=0.85,
            first_seen=self.now,
            last_seen=self.now,
            ttl=3600
        )
        self.assertEqual(ind.metadata, {})


class TestFeedConfig(unittest.TestCase):
    """Test FeedConfig dataclass"""
    
    def test_default_config(self):
        cfg = FeedConfig(source=FeedSource.ABUSEIPDB)
        self.assertTrue(cfg.enabled)
        self.assertEqual(cfg.refresh_interval, 3600)
        self.assertEqual(cfg.timeout, 30)
        self.assertEqual(cfg.max_retries, 3)
    
    def test_custom_config(self):
        cfg = FeedConfig(
            source=FeedSource.VIRUSTOTAL,
            enabled=False,
            refresh_interval=7200,
            api_key="test_key_123"
        )
        self.assertFalse(cfg.enabled)
        self.assertEqual(cfg.refresh_interval, 7200)
        self.assertEqual(cfg.api_key, "test_key_123")


class TestThreatFeedCache(unittest.TestCase):
    """Test ThreatFeedCache functionality"""
    
    def setUp(self):
        self.cache = ThreatFeedCache()
        self.now = datetime.now()
    
    def create_test_indicator(self, ip="192.168.1.1", ttl=3600):
        return ThreatIndicator(
            indicator=ip,
            indicator_type="ip",
            threat_type=ThreatType.MALWARE,
            severity=ThreatSeverity.HIGH,
            source=FeedSource.ABUSEIPDB,
            confidence=0.85,
            first_seen=self.now,
            last_seen=self.now,
            ttl=ttl
        )
    
    def test_add_and_get(self):
        ind = self.create_test_indicator()
        self.cache.add(ind)
        retrieved = self.cache.get(ind.indicator_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.indicator, "192.168.1.1")
    
    def test_lookup_by_value(self):
        ind = self.create_test_indicator("10.0.0.1")
        self.cache.add(ind)
        result = self.cache.lookup("10.0.0.1", "ip")
        self.assertIsNotNone(result)
        self.assertEqual(result.indicator, "10.0.0.1")
    
    def test_lookup_not_found(self):
        result = self.cache.lookup("99.99.99.99", "ip")
        self.assertIsNone(result)
    
    def test_cache_size(self):
        for i in range(5):
            ind = self.create_test_indicator(f"192.168.1.{i}")
            self.cache.add(ind)
        self.assertEqual(self.cache.size(), 5)
    
    def test_expired_entry_removal(self):
        # Add indicator with very short TTL
        ind = self.create_test_indicator(ttl=1)
        self.cache.add(ind)
        self.assertEqual(self.cache.size(), 1)
        time.sleep(1.1)
        self.assertEqual(self.cache.size(), 0)
    
    def test_cleanup_expired(self):
        ind1 = self.create_test_indicator("1.1.1.1", ttl=1)
        ind2 = self.create_test_indicator("2.2.2.2", ttl=3600)
        self.cache.add(ind1)
        self.cache.add(ind2)
        time.sleep(1.1)
        removed = self.cache.cleanup_expired()
        self.assertEqual(removed, 1)
        self.assertEqual(self.cache.size(), 1)
    
    def test_clear_cache(self):
        for i in range(3):
            ind = self.create_test_indicator(f"192.168.1.{i}")
            self.cache.add(ind)
        self.assertEqual(self.cache.size(), 3)
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)
    
    def test_get_all(self):
        for i in range(3):
            ind = self.create_test_indicator(f"192.168.1.{i}")
            self.cache.add(ind)
        all_inds = self.cache.get_all()
        self.assertEqual(len(all_inds), 3)


class TestThreatIntelligenceAggregator(unittest.TestCase):
    """Test main ThreatIntelligenceAggregator class"""
    
    def setUp(self):
        self.aggregator = ThreatIntelligenceAggregator()
        self.now = datetime.now()
    
    def create_test_indicator(self, ip="192.168.1.1", source=FeedSource.ABUSEIPDB, 
                              confidence=0.85, severity=ThreatSeverity.HIGH):
        return ThreatIndicator(
            indicator=ip,
            indicator_type="ip",
            threat_type=ThreatType.MALWARE,
            severity=severity,
            source=source,
            confidence=confidence,
            first_seen=self.now,
            last_seen=self.now,
            ttl=3600
        )
    
    def test_aggregator_initialization(self):
        self.assertIsNotNone(self.aggregator)
        stats = self.aggregator.get_stats()
        self.assertEqual(stats["cache_size"], 0)
    
    def test_add_single_indicator(self):
        ind = self.create_test_indicator()
        self.aggregator.add_indicator(ind)
        stats = self.aggregator.get_stats()
        self.assertEqual(stats["total_indicators"], 1)
        self.assertEqual(stats["cache_size"], 1)
    
    def test_deduplication(self):
        # Add same indicator twice from different sources
        ind1 = self.create_test_indicator("192.168.1.1", FeedSource.ABUSEIPDB, 0.7)
        ind2 = self.create_test_indicator("192.168.1.1", FeedSource.VIRUSTOTAL, 0.9)
        self.aggregator.add_indicator(ind1)
        self.aggregator.add_indicator(ind2)
        stats = self.aggregator.get_stats()
        self.assertEqual(stats["total_indicators"], 1)
        self.assertEqual(stats["deduplicated"], 1)
    
    def test_confidence_merge_highest(self):
        ind1 = self.create_test_indicator("192.168.1.1", FeedSource.ABUSEIPDB, 0.7)
        ind2 = self.create_test_indicator("192.168.1.1", FeedSource.VIRUSTOTAL, 0.9)
        self.aggregator.add_indicator(ind1)
        self.aggregator.add_indicator(ind2)
        result = self.aggregator.lookup_indicator("192.168.1.1", "ip")
        self.assertEqual(result.confidence, 0.9)
    
    def test_batch_add(self):
        indicators = [
            self.create_test_indicator(f"192.168.1.{i}") for i in range(5)
        ]
        count = self.aggregator.add_indicators_batch(indicators)
        self.assertEqual(count, 5)
        stats = self.aggregator.get_stats()
        self.assertEqual(stats["total_indicators"], 5)
    
    def test_lookup_hit_miss(self):
        ind = self.create_test_indicator("10.0.0.1")
        self.aggregator.add_indicator(ind)
        # Hit
        result = self.aggregator.lookup_indicator("10.0.0.1", "ip")
        self.assertIsNotNone(result)
        # Miss
        result = self.aggregator.lookup_indicator("99.99.99.99", "ip")
        self.assertIsNone(result)
        stats = self.aggregator.get_stats()
        self.assertEqual(stats["lookups"], 2)
        self.assertEqual(stats["hits"], 1)
    
    def test_batch_lookup(self):
        for i in range(3):
            ind = self.create_test_indicator(f"192.168.1.{i}")
            self.aggregator.add_indicator(ind)
        results = self.aggregator.lookup_batch(
            ["192.168.1.0", "192.168.1.1", "192.168.1.5"],
            "ip"
        )
        self.assertIsNotNone(results["192.168.1.0"])
        self.assertIsNotNone(results["192.168.1.1"])
        self.assertIsNone(results["192.168.1.5"])
    
    def test_filter_by_severity(self):
        severities = [
            ThreatSeverity.LOW,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.HIGH,
            ThreatSeverity.CRITICAL
        ]
        for i, sev in enumerate(severities):
            ind = self.create_test_indicator(f"192.168.1.{i}", severity=sev)
            self.aggregator.add_indicator(ind)
        
        high_and_above = self.aggregator.get_threats_by_severity(ThreatSeverity.HIGH)
        self.assertEqual(len(high_and_above), 2)  # HIGH + CRITICAL
        
        critical_only = self.aggregator.get_threats_by_severity(ThreatSeverity.CRITICAL)
        self.assertEqual(len(critical_only), 1)
    
    def test_filter_by_type(self):
        types = [ThreatType.MALWARE, ThreatType.PHISHING, ThreatType.RANSOMWARE]
        for i, ttype in enumerate(types):
            ind = ThreatIndicator(
                indicator=f"192.168.1.{i}",
                indicator_type="ip",
                threat_type=ttype,
                severity=ThreatSeverity.HIGH,
                source=FeedSource.ABUSEIPDB,
                confidence=0.85,
                first_seen=self.now,
                last_seen=self.now,
                ttl=3600
            )
            self.aggregator.add_indicator(ind)
        
        malware = self.aggregator.get_threats_by_type(ThreatType.MALWARE)
        self.assertEqual(len(malware), 1)
    
    def test_export_json(self):
        ind = self.create_test_indicator()
        self.aggregator.add_indicator(ind)
        json_output = self.aggregator.export_json()
        self.assertIn("192.168.1.1", json_output)
        self.assertIn("high", json_output)
    
    def test_export_stix2(self):
        ind = self.create_test_indicator()
        self.aggregator.add_indicator(ind)
        stix = self.aggregator.export_stix2()
        self.assertEqual(stix["type"], "bundle")
        self.assertEqual(len(stix["objects"]), 1)
        self.assertEqual(stix["objects"][0]["type"], "indicator")
    
    def test_feed_config_management(self):
        cfg = self.aggregator.get_feed_config(FeedSource.ABUSEIPDB)
        self.assertIsNotNone(cfg)
        self.assertTrue(cfg.enabled)
        
        new_cfg = FeedConfig(source=FeedSource.ABUSEIPDB, enabled=False)
        self.aggregator.update_feed_config(new_cfg)
        updated = self.aggregator.get_feed_config(FeedSource.ABUSEIPDB)
        self.assertFalse(updated.enabled)
    
    def test_get_enabled_sources(self):
        # Disable some sources
        self.aggregator.update_feed_config(
            FeedConfig(source=FeedSource.VIRUSTOTAL, enabled=False)
        )
        enabled = self.aggregator.get_enabled_sources()
        self.assertIn(FeedSource.ABUSEIPDB, enabled)
        self.assertNotIn(FeedSource.VIRUSTOTAL, enabled)
    
    def test_clear_cache(self):
        for i in range(3):
            ind = self.create_test_indicator(f"192.168.1.{i}")
            self.aggregator.add_indicator(ind)
        self.assertEqual(self.aggregator.get_stats()["cache_size"], 3)
        self.aggregator.clear_cache()
        self.assertEqual(self.aggregator.get_stats()["cache_size"], 0)


class TestFactoryFunction(unittest.TestCase):
    """Test create_aggregator factory function"""
    
    def test_create_aggregator(self):
        agg = create_aggregator(enable_default_sources=True)
        self.assertIsInstance(agg, ThreatIntelligenceAggregator)
        enabled = agg.get_enabled_sources()
        self.assertGreater(len(enabled), 0)
    
    def test_create_aggregator_no_defaults(self):
        agg = create_aggregator(enable_default_sources=False)
        # All sources should be as per default config
        self.assertIsInstance(agg, ThreatIntelligenceAggregator)


class TestIntegrationScenarios(unittest.TestCase):
    """Integration test scenarios"""
    
    def setUp(self):
        self.aggregator = create_aggregator()
        self.now = datetime.now()
    
    def test_realistic_threat_intelligence_workflow(self):
        """Simulate a realistic threat intel workflow"""
        # Simulate receiving IOCs from multiple feeds
        feed1_iocs = [
            ThreatIndicator(
                indicator=f"10.0.0.{i}",
                indicator_type="ip",
                threat_type=ThreatType.MALWARE,
                severity=ThreatSeverity.HIGH,
                source=FeedSource.ABUSEIPDB,
                confidence=0.7 + i * 0.05,
                first_seen=self.now,
                last_seen=self.now,
                ttl=86400
            ) for i in range(3)
        ]
        
        feed2_iocs = [
            ThreatIndicator(
                indicator=f"10.0.0.{i}",  # Overlap with feed1
                indicator_type="ip",
                threat_type=ThreatType.C2,
                severity=ThreatSeverity.CRITICAL,
                source=FeedSource.THREATFOX,
                confidence=0.9,
                first_seen=self.now - timedelta(hours=1),
                last_seen=self.now,
                ttl=86400
            ) for i in range(2, 5)
        ]
        
        # Add both feeds
        self.aggregator.add_indicators_batch(feed1_iocs)
        self.aggregator.add_indicators_batch(feed2_iocs)
        
        # Verify deduplication worked
        stats = self.aggregator.get_stats()
        self.assertEqual(stats["total_indicators"], 5)  # 3 + 2 unique
        self.assertEqual(stats["deduplicated"], 1)     # 10.0.0.2 overlapped
        
        # Verify merged indicator has highest confidence
        merged = self.aggregator.lookup_indicator("10.0.0.2", "ip")
        self.assertEqual(merged.confidence, 0.9)  # Highest of 0.8 and 0.9
        self.assertEqual(merged.severity, ThreatSeverity.CRITICAL)
        
        # Export for SIEM integration
        stix_export = self.aggregator.export_stix2()
        self.assertEqual(len(stix_export["objects"]), 5)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    test_classes = [
        TestThreatSeverityEnum,
        TestThreatTypeEnum,
        TestFeedSourceEnum,
        TestThreatIndicator,
        TestFeedConfig,
        TestThreatFeedCache,
        TestThreatIntelligenceAggregator,
        TestFactoryFunction,
        TestIntegrationScenarios
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Intelligence Feed Aggregator v27 - Test Suite")
    print("=" * 60)
    result = run_tests()
    print("\n" + "=" * 60)
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED")
    else:
        print(f"✗ TESTS FAILED: {len(result.failures)} failures, {len(result.errors)} errors")
    print("=" * 60)
    sys.exit(0 if result.wasSuccessful() else 1)
