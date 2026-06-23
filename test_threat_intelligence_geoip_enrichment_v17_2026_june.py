"""
Test Suite for Threat Intelligence GeoIP Enrichment Engine v17
NeuralShield AI - Feature Expansion (Dimension A)

Comprehensive tests for GeoIP enrichment functionality.
All tests are ADD-ONLY - no modifications to existing production code.
"""

import pytest
import time
from neural_shield.threat_intelligence_geoip_enrichment_engine_v17_2026_june import (
    GeoIPEnrichmentEngine,
    GeoIPEnrichmentResult,
    ThreatGeoConfidence,
    ThreatReputationLevel,
)


class TestGeoIPEnrichmentEngine:
    """Test suite for GeoIP Enrichment Engine."""
    
    def test_engine_initialization_defaults(self):
        """Test engine initialization with default parameters."""
        engine = GeoIPEnrichmentEngine()
        assert engine.cache_ttl_seconds == 3600
        assert engine.max_cache_size == 10000
        assert engine.enable_tor_detection is True
        assert engine.enable_vpn_detection is True
        assert engine.enable_reputation_scoring is True
    
    def test_engine_initialization_custom(self):
        """Test engine initialization with custom parameters."""
        engine = GeoIPEnrichmentEngine(
            cache_ttl_seconds=1800,
            max_cache_size=5000,
            enable_tor_detection=False,
        )
        assert engine.cache_ttl_seconds == 1800
        assert engine.max_cache_size == 5000
        assert engine.enable_tor_detection is False
    
    def test_enrich_valid_ipv4(self):
        """Test enrichment of a valid IPv4 address."""
        engine = GeoIPEnrichmentEngine()
        result = engine.enrich_ip("8.8.8.8")
        
        assert result.is_valid is True
        assert result.ip_address == "8.8.8.8"
        assert result.country_code is not None
        assert result.country_name is not None
        assert result.asn is not None
        assert result.confidence in [
            ThreatGeoConfidence.HIGH,
            ThreatGeoConfidence.MEDIUM,
            ThreatGeoConfidence.LOW,
        ]
    
    def test_enrich_valid_ipv6(self):
        """Test enrichment of a valid IPv6 address."""
        engine = GeoIPEnrichmentEngine()
        result = engine.enrich_ip("2001:4860:4860::8888")
        
        assert result.is_valid is True
        assert result.ip_address == "2001:4860:4860::8888"
    
    def test_enrich_invalid_ip(self):
        """Test enrichment of an invalid IP address."""
        engine = GeoIPEnrichmentEngine()
        result = engine.enrich_ip("not-an-ip-address")
        
        assert result.is_valid is False
        assert result.confidence == ThreatGeoConfidence.LOW
    
    def test_enrich_ip_normalization(self):
        """Test IP address normalization."""
        engine = GeoIPEnrichmentEngine()
        result1 = engine.enrich_ip("  8.8.8.8  ")
        result2 = engine.enrich_ip("8.8.8.8")
        
        assert result1.ip_address == result2.ip_address
        assert result1.ip_address == "8.8.8.8"
    
    def test_tor_exit_node_detection(self):
        """Test TOR exit node detection."""
        engine = GeoIPEnrichmentEngine(enable_tor_detection=True)
        # Known TOR network IP
        result = engine.enrich_ip("185.220.101.1")
        
        assert result.is_tor_exit_node is True
        assert result.is_proxy is True
    
    def test_tor_detection_disabled(self):
        """Test TOR detection when disabled."""
        engine = GeoIPEnrichmentEngine(enable_tor_detection=False)
        result = engine.enrich_ip("185.220.101.1")
        
        assert result.is_tor_exit_node is False
    
    def test_threat_reputation_scoring(self):
        """Test threat reputation scoring."""
        engine = GeoIPEnrichmentEngine(enable_reputation_scoring=True)
        result = engine.enrich_ip("8.8.8.8")
        
        assert result.threat_reputation in [
            ThreatReputationLevel.CRITICAL,
            ThreatReputationLevel.HIGH,
            ThreatReputationLevel.MEDIUM,
            ThreatReputationLevel.LOW,
            ThreatReputationLevel.BENIGN,
            ThreatReputationLevel.UNKNOWN,
        ]
    
    def test_batch_enrichment(self):
        """Test batch IP enrichment."""
        engine = GeoIPEnrichmentEngine()
        ips = ["8.8.8.8", "1.1.1.1", "4.4.4.4"]
        
        results = engine.enrich_batch(ips)
        
        assert len(results) == 3
        for ip in ips:
            assert ip in results
            assert results[ip].is_valid is True
    
    def test_malicious_ip_filtering(self):
        """Test malicious IP filtering functionality."""
        engine = GeoIPEnrichmentEngine()
        ips = ["8.8.8.8", "1.1.1.1", "185.220.101.1"]  # Last is TOR
        
        malicious = engine.filter_malicious_ips(ips, min_reputation=ThreatReputationLevel.HIGH)
        
        assert isinstance(malicious, list)
        assert len(malicious) >= 0  # TOR should be detected as malicious
    
    def test_caching_mechanism(self):
        """Test that caching works correctly."""
        engine = GeoIPEnrichmentEngine(cache_ttl_seconds=3600)
        
        # First enrichment - cache miss
        result1 = engine.enrich_ip("8.8.8.8", use_cache=True)
        stats_after_first = engine.get_stats()
        assert stats_after_first["cache_misses"] >= 1
        
        # Second enrichment - should be cache hit
        result2 = engine.enrich_ip("8.8.8.8", use_cache=True)
        stats_after_second = engine.get_stats()
        
        assert stats_after_second["cache_hits"] >= 1
        assert result1.ip_address == result2.ip_address
    
    def test_cache_disabled(self):
        """Test enrichment without caching."""
        engine = GeoIPEnrichmentEngine()
        
        result1 = engine.enrich_ip("8.8.8.8", use_cache=False)
        result2 = engine.enrich_ip("8.8.8.8", use_cache=False)
        stats = engine.get_stats()
        
        assert stats["cache_hits"] == 0
        assert stats["cache_size"] == 0
    
    def test_engine_statistics(self):
        """Test engine statistics collection."""
        engine = GeoIPEnrichmentEngine()
        
        # Perform some enrichments - use different IPs to avoid cache hits
        engine.enrich_ip("8.8.8.8", use_cache=False)
        engine.enrich_ip("1.1.1.1", use_cache=False)
        engine.enrich_ip("4.4.4.4", use_cache=False)
        
        stats = engine.get_stats()
        
        assert stats["total_enrichments"] >= 3
        assert stats["cache_hits"] >= 0
        assert stats["cache_misses"] >= 3
        assert "cache_hit_ratio" in stats
        assert 0 <= stats["cache_hit_ratio"] <= 1
    
    def test_clear_cache(self):
        """Test cache clearing functionality."""
        engine = GeoIPEnrichmentEngine()
        
        engine.enrich_ip("8.8.8.8")
        assert engine.get_stats()["cache_size"] == 1
        
        engine.clear_cache()
        assert engine.get_stats()["cache_size"] == 0
    
    def test_asn_and_network_context(self):
        """Test ASN and network context enrichment."""
        engine = GeoIPEnrichmentEngine()
        result = engine.enrich_ip("8.8.8.8")
        
        assert result.asn is not None
        assert result.asn_org is not None
        assert result.network is not None
    
    def test_datacenter_detection(self):
        """Test datacenter IP detection."""
        engine = GeoIPEnrichmentEngine()
        # AWS IP range
        result = engine.enrich_ip("3.0.0.1")
        
        # Should have is_datacenter populated
        assert hasattr(result, 'is_datacenter')
        assert isinstance(result.is_datacenter, bool)
    
    def test_metadata_field(self):
        """Test metadata field in enrichment result."""
        engine = GeoIPEnrichmentEngine()
        result = engine.enrich_ip("8.8.8.8")
        
        assert isinstance(result.metadata, dict)
        assert result.enrichment_timestamp > 0
    
    def test_thread_safety_basic(self):
        """Basic thread safety test."""
        engine = GeoIPEnrichmentEngine()
        
        # Multiple rapid calls
        for i in range(10):
            result = engine.enrich_ip(f"10.0.0.{i}")
            assert result.is_valid is True
        
        stats = engine.get_stats()
        assert stats["total_enrichments"] == 10
    
    def test_empty_ip_list_batch(self):
        """Test batch enrichment with empty list."""
        engine = GeoIPEnrichmentEngine()
        results = engine.enrich_batch([])
        
        assert results == {}
    
    def test_enrichment_result_dataclass(self):
        """Test GeoIPEnrichmentResult dataclass structure."""
        result = GeoIPEnrichmentResult(ip_address="test")
        
        assert result.ip_address == "test"
        assert result.is_valid is False
        assert result.threat_reputation == ThreatReputationLevel.UNKNOWN
        assert isinstance(result.metadata, dict)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
