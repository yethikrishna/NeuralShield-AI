#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Geolocation Enricher - NeuralShield AI
Production-grade tests for geolocation enrichment functionality.
"""

import sys
import os
import unittest
import time
import json

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_geolocation_enricher_2026_june import (
    ThreatIntelligenceGeolocationEnricher,
    GeolocationData,
    EnrichmentResult,
    GeographicRiskLevel,
    IPVersion,
    GeolocationCache
)


class TestIPValidation(unittest.TestCase):
    """Test IP address validation functionality."""
    
    def setUp(self):
        self.enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=False)
    
    def test_valid_ipv4(self):
        """Test valid IPv4 address validation."""
        is_valid, version = self.enricher.validate_ip("8.8.8.8")
        self.assertTrue(is_valid)
        self.assertEqual(version, IPVersion.IPV4)
    
    def test_valid_ipv6(self):
        """Test valid IPv6 address validation."""
        is_valid, version = self.enricher.validate_ip("2001:4860:4860::8888")
        self.assertTrue(is_valid)
        self.assertEqual(version, IPVersion.IPV6)
    
    def test_invalid_ip(self):
        """Test invalid IP address validation."""
        is_valid, version = self.enricher.validate_ip("256.256.256.256")
        self.assertFalse(is_valid)
        self.assertEqual(version, IPVersion.INVALID)
    
    def test_empty_ip(self):
        """Test empty string IP validation."""
        is_valid, version = self.enricher.validate_ip("")
        self.assertFalse(is_valid)
        self.assertEqual(version, IPVersion.INVALID)
    
    def test_non_ip_string(self):
        """Test non-IP string validation."""
        is_valid, version = self.enricher.validate_ip("not-an-ip")
        self.assertFalse(is_valid)
        self.assertEqual(version, IPVersion.INVALID)


class TestGeolocationEnrichment(unittest.TestCase):
    """Test core geolocation enrichment functionality."""
    
    def setUp(self):
        self.enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=False)
    
    def test_enrich_known_ip(self):
        """Test enrichment of known IP address (Google DNS)."""
        result = self.enricher.enrich_ip("8.8.8.8")
        
        self.assertTrue(result.success)
        self.assertIsNotNone(result.data)
        self.assertFalse(result.from_cache)
        self.assertGreater(result.processing_time_ms, 0)
        
        # Verify data fields
        self.assertEqual(result.data.ip_address, "8.8.8.8")
        self.assertEqual(result.data.country_code, "US")
        self.assertEqual(result.data.country_name, "United States")
        self.assertEqual(result.data.asn, "AS15169")
        self.assertTrue(result.data.is_datacenter)  # Google ASN is in datacenter list
        self.assertGreater(result.data.confidence_score, 0.8)
    
    def test_enrich_cloudflare_ip(self):
        """Test enrichment of Cloudflare IP."""
        result = self.enricher.enrich_ip("1.1.1.1")
        
        self.assertTrue(result.success)
        self.assertEqual(result.data.ip_address, "1.1.1.1")
        self.assertEqual(result.data.country_code, "US")
        self.assertTrue(result.data.is_datacenter)
    
    def test_enrich_tor_ip(self):
        """Test enrichment of Tor exit node IP."""
        result = self.enricher.enrich_ip("185.220.101.1")
        
        self.assertTrue(result.success)
        self.assertTrue(result.data.is_tor)
        self.assertTrue(result.data.is_proxy)
        # Tor should be high/critical risk
        self.assertIn(result.data.geographic_risk, 
                     [GeographicRiskLevel.HIGH, GeographicRiskLevel.CRITICAL])
    
    def test_enrich_unknown_ip(self):
        """Test enrichment of unknown IP address."""
        result = self.enricher.enrich_ip("10.0.0.1")
        
        self.assertTrue(result.success)
        self.assertEqual(result.data.country_code, "ZZ")
        self.assertEqual(result.data.confidence_score, 0.3)
    
    def test_enrich_invalid_ip(self):
        """Test enrichment of invalid IP returns error."""
        result = self.enricher.enrich_ip("invalid-ip")
        
        self.assertFalse(result.success)
        self.assertIsNone(result.data)
        self.assertIsNotNone(result.error_message)
        self.assertIn("Invalid IP", result.error_message)


class TestCachingFunctionality(unittest.TestCase):
    """Test LRU caching functionality."""
    
    def test_cache_hit(self):
        """Test that subsequent lookups hit the cache."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=True)
        
        # First lookup - cache miss
        result1 = enricher.enrich_ip("8.8.8.8")
        self.assertFalse(result1.from_cache)
        
        # Second lookup - cache hit
        result2 = enricher.enrich_ip("8.8.8.8")
        self.assertTrue(result2.from_cache)
        self.assertLess(result2.processing_time_ms, result1.processing_time_ms)
    
    def test_cache_statistics(self):
        """Test cache statistics tracking."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=True)
        
        # Do some lookups
        enricher.enrich_ip("8.8.8.8")
        enricher.enrich_ip("8.8.8.8")  # Cache hit
        enricher.enrich_ip("1.1.1.1")
        enricher.enrich_ip("1.1.1.1")  # Cache hit
        
        stats = enricher.get_statistics()
        self.assertEqual(stats["total_enrichments"], 4)
        self.assertEqual(stats["cache_hits"], 2)
        self.assertEqual(stats["cache_hit_rate_percent"], 50.0)
    
    def test_cache_disabled(self):
        """Test behavior when caching is disabled."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=False)
        
        result1 = enricher.enrich_ip("8.8.8.8")
        result2 = enricher.enrich_ip("8.8.8.8")
        
        self.assertFalse(result1.from_cache)
        self.assertFalse(result2.from_cache)


class TestGeolocationCache(unittest.TestCase):
    """Test standalone GeolocationCache class."""
    
    def test_cache_put_get(self):
        """Test basic cache put and get operations."""
        cache = GeolocationCache(max_size=100)
        
        test_data = GeolocationData(
            ip_address="8.8.8.8",
            ip_version=IPVersion.IPV4,
            country_code="US",
            country_name="United States",
            region="CA",
            city="Mountain View",
            latitude=37.3860,
            longitude=-122.0838,
            timezone="America/Los_Angeles",
            isp="Google",
            asn="AS15169",
            asn_name="Google LLC",
            is_proxy=False,
            is_tor=False,
            is_vpn=False,
            is_datacenter=True,
            is_malicious=False,
            geographic_risk=GeographicRiskLevel.LOW,
            confidence_score=0.9,
            enrichment_timestamp=time.time()
        )
        
        cache.put("8.8.8.8", test_data)
        retrieved = cache.get("8.8.8.8")
        
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.ip_address, "8.8.8.8")
        self.assertEqual(cache.size(), 1)
    
    def test_cache_eviction(self):
        """Test LRU eviction when cache exceeds max size."""
        cache = GeolocationCache(max_size=3, ttl_seconds=3600)
        
        # Create dummy data
        def make_dummy(ip):
            return GeolocationData(
                ip_address=ip, ip_version=IPVersion.IPV4,
                country_code="US", country_name="US", region="", city="",
                latitude=0, longitude=0, timezone="UTC", isp="", asn="", asn_name="",
                is_proxy=False, is_tor=False, is_vpn=False, is_datacenter=False,
                is_malicious=False, geographic_risk=GeographicRiskLevel.LOW,
                confidence_score=0.5, enrichment_timestamp=time.time()
            )
        
        # Fill cache
        cache.put("1.1.1.1", make_dummy("1.1.1.1"))
        cache.put("2.2.2.2", make_dummy("2.2.2.2"))
        cache.put("3.3.3.3", make_dummy("3.3.3.3"))
        
        self.assertEqual(cache.size(), 3)
        
        # Add 4th item - should evict oldest (1.1.1.1)
        cache.put("4.4.4.4", make_dummy("4.4.4.4"))
        
        self.assertEqual(cache.size(), 3)
        self.assertIsNone(cache.get("1.1.1.1"))  # Oldest evicted
        self.assertIsNotNone(cache.get("2.2.2.2"))  # Still present
    
    def test_cache_clear(self):
        """Test cache clear functionality."""
        cache = GeolocationCache(max_size=100)
        
        test_data = GeolocationData(
            ip_address="8.8.8.8", ip_version=IPVersion.IPV4,
            country_code="US", country_name="US", region="", city="",
            latitude=0, longitude=0, timezone="UTC", isp="", asn="", asn_name="",
            is_proxy=False, is_tor=False, is_vpn=False, is_datacenter=False,
            is_malicious=False, geographic_risk=GeographicRiskLevel.LOW,
            confidence_score=0.5, enrichment_timestamp=time.time()
        )
        
        cache.put("8.8.8.8", test_data)
        self.assertEqual(cache.size(), 1)
        
        cache.clear()
        self.assertEqual(cache.size(), 0)
        self.assertIsNone(cache.get("8.8.8.8"))


class TestBatchEnrichment(unittest.TestCase):
    """Test batch enrichment functionality."""
    
    def test_batch_enrichment(self):
        """Test batch enrichment of multiple IPs."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=False)
        
        ips = ["8.8.8.8", "1.1.1.1", "208.67.222.222", "invalid-ip"]
        results = enricher.enrich_batch(ips)
        
        self.assertEqual(len(results), 4)
        self.assertTrue(results[0].success)  # Google DNS
        self.assertTrue(results[1].success)  # Cloudflare
        self.assertTrue(results[2].success)  # OpenDNS
        self.assertFalse(results[3].success)  # Invalid


class TestRiskAssessment(unittest.TestCase):
    """Test geographic risk assessment functionality."""
    
    def test_risk_filtering(self):
        """Test filtering results by risk level."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=False)
        
        ips = ["8.8.8.8", "185.220.101.1"]  # Normal + Tor
        results = enricher.enrich_batch(ips)
        
        # Filter for HIGH risk and above
        high_risk = enricher.filter_by_risk(results, GeographicRiskLevel.HIGH)
        
        # Should only include Tor IP
        self.assertGreaterEqual(len(high_risk), 1)
        for result in high_risk:
            self.assertIn(result.data.geographic_risk, 
                         [GeographicRiskLevel.HIGH, GeographicRiskLevel.CRITICAL])


class TestJSONExport(unittest.TestCase):
    """Test JSON export functionality."""
    
    def test_json_export(self):
        """Test exporting results to JSON."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=False)
        
        results = enricher.enrich_batch(["8.8.8.8", "1.1.1.1"])
        json_output = enricher.export_to_json(results)
        
        # Validate JSON
        parsed = json.loads(json_output)
        self.assertIsInstance(parsed, list)
        self.assertEqual(len(parsed), 2)
        
        # Check fields
        self.assertIn("ip_address", parsed[0])
        self.assertIn("country_code", parsed[0])
        self.assertIn("geographic_risk", parsed[0])


class TestPerformanceBenchmark(unittest.TestCase):
    """Performance benchmark tests."""
    
    def test_enrichment_performance(self):
        """Benchmark single IP enrichment performance."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=False)
        
        start = time.time()
        for _ in range(100):
            enricher.enrich_ip("8.8.8.8")
        elapsed = time.time() - start
        
        avg_time_ms = (elapsed / 100) * 1000
        
        # Should complete in reasonable time (< 1ms per enrichment)
        self.assertLess(avg_time_ms, 10.0)
        print(f"\n[BENCHMARK] Average enrichment time: {avg_time_ms:.3f}ms")
    
    def test_cached_performance(self):
        """Benchmark cached vs non-cached performance."""
        enricher = ThreatIntelligenceGeolocationEnricher(enable_caching=True)
        
        # Warm up cache
        enricher.enrich_ip("8.8.8.8")
        
        # Measure cached performance
        start = time.time()
        for _ in range(1000):
            enricher.enrich_ip("8.8.8.8")
        elapsed = time.time() - start
        
        avg_time_ms = (elapsed / 1000) * 1000
        
        # Cached should be very fast (< 0.1ms)
        self.assertLess(avg_time_ms, 1.0)
        print(f"[BENCHMARK] Cached average time: {avg_time_ms:.4f}ms")


def run_tests():
    """Run all tests and generate report."""
    print("=" * 70)
    print("NeuralShield AI - Threat Intelligence Geolocation Enricher Tests")
    print("=" * 70)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add all test classes
    test_classes = [
        TestIPValidation,
        TestGeolocationEnrichment,
        TestCachingFunctionality,
        TestGeolocationCache,
        TestBatchEnrichment,
        TestRiskAssessment,
        TestJSONExport,
        TestPerformanceBenchmark
    ]
    
    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)
    
    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print("\n" + "=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'PASS' if result.wasSuccessful() else 'FAIL'}")
    print("=" * 70)
    
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
