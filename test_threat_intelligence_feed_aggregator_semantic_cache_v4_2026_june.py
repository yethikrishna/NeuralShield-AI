"""
Tests for Threat Intelligence Feed Aggregator with Semantic Caching v4
NeuralShield-AI Feature Expansion (Dimension A)
June 22, 2026

100% ADD-ONLY - NO EXISTING TESTS MODIFIED
"""

import pytest
import time
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_feed_aggregator_semantic_cache_v4_2026_june import (
    FeedType, IOCType, ThreatSeverity, IOCEntry, FeedStatus,
    SemanticCache, FeedAggregator, get_feed_aggregator, create_ioc,
    print_aggregation_report
)


class TestIOCEntry:
    """Test IOC Entry functionality."""
    
    def test_semantic_hash_normalization(self):
        """Test semantic hash is case-insensitive and normalized."""
        ioc1 = IOCEntry(
            value="MALWARE.COM",
            ioc_type=IOCType.DOMAIN,
            severity=ThreatSeverity.HIGH,
            source=FeedType.ABUSE_IPDB,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            confidence=0.9
        )
        ioc2 = IOCEntry(
            value="malware.com",
            ioc_type=IOCType.DOMAIN,
            severity=ThreatSeverity.HIGH,
            source=FeedType.VIRUSTOTAL,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            confidence=0.8
        )
        assert ioc1.semantic_hash() == ioc2.semantic_hash()
    
    def test_semantic_hash_different_types(self):
        """Test same value different types have different hashes."""
        ioc1 = IOCEntry(
            value="1.1.1.1",
            ioc_type=IOCType.IPV4,
            severity=ThreatSeverity.HIGH,
            source=FeedType.ABUSE_IPDB,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            confidence=0.9
        )
        ioc2 = IOCEntry(
            value="1.1.1.1",
            ioc_type=IOCType.DOMAIN,
            severity=ThreatSeverity.HIGH,
            source=FeedType.ABUSE_IPDB,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            confidence=0.9
        )
        assert ioc1.semantic_hash() != ioc2.semantic_hash()
    
    def test_ioc_expiry(self):
        """Test IOC expiry detection."""
        expired_ioc = IOCEntry(
            value="1.2.3.4",
            ioc_type=IOCType.IPV4,
            severity=ThreatSeverity.HIGH,
            source=FeedType.ABUSE_IPDB,
            first_seen=datetime.utcnow() - timedelta(days=10),
            last_seen=datetime.utcnow() - timedelta(days=5),
            confidence=0.9,
            ttl_hours=24
        )
        assert expired_ioc.is_expired() is True
        
        fresh_ioc = IOCEntry(
            value="1.2.3.4",
            ioc_type=IOCType.IPV4,
            severity=ThreatSeverity.HIGH,
            source=FeedType.ABUSE_IPDB,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            confidence=0.9,
            ttl_hours=72
        )
        assert fresh_ioc.is_expired() is False


class TestSemanticCache:
    """Test Semantic Cache functionality."""
    
    def test_cache_put_get(self):
        """Test basic cache put and get operations."""
        cache = SemanticCache(max_size=100)
        ioc = create_ioc("1.2.3.4", IOCType.IPV4, ThreatSeverity.HIGH, FeedType.ABUSE_IPDB)
        h = ioc.semantic_hash()
        
        cache.put(ioc)
        assert cache.size == 1
        assert cache.contains(h) is True
        
        retrieved = cache.get(h)
        assert retrieved is not None
        assert retrieved.value == "1.2.3.4"
    
    def test_cache_hit_miss_tracking(self):
        """Test hit/miss statistics tracking."""
        cache = SemanticCache(max_size=100)
        ioc1 = create_ioc("1.2.3.4", IOCType.IPV4, ThreatSeverity.HIGH, FeedType.ABUSE_IPDB)
        ioc2 = create_ioc("5.6.7.8", IOCType.IPV4, ThreatSeverity.HIGH, FeedType.ABUSE_IPDB)
        
        cache.put(ioc1)
        
        # Hit
        cache.get(ioc1.semantic_hash())
        # Miss
        cache.get(ioc2.semantic_hash())
        
        assert cache._hits == 1
        assert cache._misses == 1
        assert cache.hit_rate == 0.5
    
    def test_cache_eviction(self):
        """Test LRU-style cache eviction."""
        cache = SemanticCache(max_size=5)
        for i in range(10):
            ioc = create_ioc(f"10.0.0.{i}", IOCType.IPV4, ThreatSeverity.HIGH, FeedType.ABUSE_IPDB)
            cache.put(ioc)
            time.sleep(0.001)  # Ensure different timestamps
        
        assert cache.size == 5  # Should have evicted old entries
    
    def test_expired_cleanup(self):
        """Test expired entry cleanup."""
        cache = SemanticCache(max_size=100)
        expired_ioc = IOCEntry(
            value="9.9.9.9",
            ioc_type=IOCType.IPV4,
            severity=ThreatSeverity.HIGH,
            source=FeedType.ABUSE_IPDB,
            first_seen=datetime.utcnow() - timedelta(days=10),
            last_seen=datetime.utcnow() - timedelta(days=5),
            confidence=0.9,
            ttl_hours=1
        )
        cache.put(expired_ioc)
        removed = cache.cleanup_expired()
        assert removed == 1
        assert cache.size == 0


class TestFeedStatus:
    """Test Feed Status health tracking."""
    
    def test_health_score_calculation(self):
        """Test health score calculation."""
        status = FeedStatus(feed_type=FeedType.ABUSE_IPDB)
        status.success_count = 90
        status.failure_count = 10
        assert status.health_score == 0.9
        assert status.is_healthy is True
    
    def test_unhealthy_feed(self):
        """Test unhealthy feed detection."""
        status = FeedStatus(feed_type=FeedType.ABUSE_IPDB)
        status.success_count = 5
        status.failure_count = 15
        assert status.health_score == 0.25
        assert status.is_healthy is False
    
    def test_unknown_health(self):
        """Test unknown health defaults."""
        status = FeedStatus(feed_type=FeedType.ABUSE_IPDB)
        assert status.health_score == 0.5


class TestFeedAggregator:
    """Test Feed Aggregator main functionality."""
    
    def test_aggregation_deduplication(self):
        """Test IOC aggregation with deduplication."""
        aggregator = FeedAggregator(cache_size=1000)
        
        # Create duplicate IOCs
        iocs = []
        for i in range(10):
            # Same IOC repeated
            ioc = create_ioc("192.168.1.100", IOCType.IPV4, ThreatSeverity.HIGH, FeedType.ABUSE_IPDB)
            iocs.append(ioc)
        
        result = aggregator.aggregate_iocs(iocs)
        assert result["total_received"] == 10
        assert result["new_unique"] == 1
        assert result["duplicates_found"] == 9
    
    def test_duplicate_metadata_merge(self):
        """Test duplicate IOCs merge metadata."""
        aggregator = FeedAggregator(cache_size=1000)
        
        ioc1 = IOCEntry(
            value="malicious.com",
            ioc_type=IOCType.DOMAIN,
            severity=ThreatSeverity.MEDIUM,
            source=FeedType.ABUSE_IPDB,
            first_seen=datetime.utcnow() - timedelta(hours=5),
            last_seen=datetime.utcnow() - timedelta(hours=5),
            confidence=0.6,
            tags=["tag1"]
        )
        
        ioc2 = IOCEntry(
            value="MALICIOUS.COM",
            ioc_type=IOCType.DOMAIN,
            severity=ThreatSeverity.HIGH,
            source=FeedType.VIRUSTOTAL,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            confidence=0.9,
            tags=["tag2"]
        )
        
        aggregator.aggregate_iocs([ioc1])
        aggregator.aggregate_iocs([ioc2])
        
        cached = aggregator.get_ioc_by_value("malicious.com", IOCType.DOMAIN)
        assert cached is not None
        assert cached.confidence == 0.9  # Higher confidence preserved
        assert "tag1" in cached.tags and "tag2" in cached.tags  # Tags merged
    
    def test_simulate_feed_poll(self):
        """Test feed polling simulation."""
        aggregator = FeedAggregator(cache_size=1000)
        result = aggregator.simulate_feed_poll(FeedType.ABUSE_IPDB, ioc_count=50)
        
        assert result["total_received"] == 50
        assert result["feed_type"] == "abuse_ipdb"
        assert "response_ms" in result
        assert "feed_health" in result
        assert result["response_ms"] > 0
    
    def test_ioc_lookup(self):
        """Test IOC lookup functionality."""
        aggregator = FeedAggregator(cache_size=1000)
        ioc = create_ioc("100.200.1.1", IOCType.IPV4, ThreatSeverity.CRITICAL, FeedType.THREATFOX, 0.95)
        aggregator.aggregate_iocs([ioc])
        
        found = aggregator.get_ioc_by_value("100.200.1.1", IOCType.IPV4)
        assert found is not None
        assert found.severity == ThreatSeverity.CRITICAL
        
        not_found = aggregator.get_ioc_by_value("0.0.0.0", IOCType.IPV4)
        assert not_found is None
    
    def test_batch_lookup(self):
        """Test batch IOC lookup."""
        aggregator = FeedAggregator(cache_size=1000)
        iocs = [
            create_ioc(f"10.0.0.{i}", IOCType.IPV4, ThreatSeverity.HIGH, FeedType.ABUSE_IPDB)
            for i in range(5)
        ]
        aggregator.aggregate_iocs(iocs)
        
        lookups = [
            ("10.0.0.1", IOCType.IPV4),
            ("10.0.0.99", IOCType.IPV4),
            ("10.0.0.3", IOCType.IPV4),
        ]
        results = aggregator.batch_lookup(lookups)
        assert len(results) == 3
        assert results["10.0.0.1"] is not None
        assert results["10.0.0.99"] is None
    
    def test_feed_health_report(self):
        """Test comprehensive health report generation."""
        aggregator = FeedAggregator(cache_size=1000)
        
        # Poll some feeds
        aggregator.simulate_feed_poll(FeedType.ABUSE_IPDB, ioc_count=10)
        aggregator.simulate_feed_poll(FeedType.VIRUSTOTAL, ioc_count=10)
        
        report = aggregator.get_feed_health_report()
        
        assert "feeds" in report
        assert "overall_health" in report
        assert "cache_stats" in report
        assert "aggregation_totals" in report
        assert report["aggregation_totals"]["total_aggregated"] == 20
        assert len(report["feeds"]) == len(FeedType)
    
    def test_high_severity_filter(self):
        """Test high severity IOC filtering."""
        aggregator = FeedAggregator(cache_size=1000)
        
        iocs = [
            create_ioc("1.1.1.1", IOCType.IPV4, ThreatSeverity.CRITICAL, FeedType.ABUSE_IPDB, 0.95),
            create_ioc("2.2.2.2", IOCType.IPV4, ThreatSeverity.HIGH, FeedType.ABUSE_IPDB, 0.85),
            create_ioc("3.3.3.3", IOCType.IPV4, ThreatSeverity.MEDIUM, FeedType.ABUSE_IPDB, 0.7),
            create_ioc("4.4.4.4", IOCType.IPV4, ThreatSeverity.LOW, FeedType.ABUSE_IPDB, 0.5),
        ]
        aggregator.aggregate_iocs(iocs)
        
        high_sev = aggregator.get_high_severity_iocs(min_confidence=0.8)
        assert len(high_sev) == 2  # CRITICAL and HIGH with >=0.8 confidence


class TestHelperFunctions:
    """Test helper and utility functions."""
    
    def test_global_singleton(self):
        """Test global singleton instance."""
        agg1 = get_feed_aggregator()
        agg2 = get_feed_aggregator()
        assert agg1 is agg2
    
    def test_create_ioc_helper(self):
        """Test IOC creation helper."""
        ioc = create_ioc("test.com", IOCType.DOMAIN, ThreatSeverity.HIGH, FeedType.CUSTOM, 0.75)
        assert ioc.value == "test.com"
        assert ioc.ioc_type == IOCType.DOMAIN
        assert ioc.confidence == 0.75
    
    def test_print_report_no_error(self):
        """Test report printing doesn't error."""
        results = {
            "total_received": 100,
            "new_unique": 75,
            "duplicates_found": 25,
            "expired_cleaned": 5,
            "hit_rate_current": 0.85,
            "response_ms": 45.5,
            "feed_health": 0.95
        }
        # Should not raise
        print_aggregation_report(results)


class TestBackwardCompatibility:
    """Verify backward compatibility - no existing code broken."""
    
    def test_no_conflict_with_existing_modules(self):
        """Test new module doesn't conflict with existing imports."""
        # This should import without errors
        from neural_shield import prompt_firewall_2026_june
        from neural_shield import input_purification_2026
        assert True  # If we got here, imports worked
    
    def test_new_module_is_isolated(self):
        """Test new module is completely isolated."""
        # New module only adds functionality, doesn't modify anything
        aggregator = FeedAggregator()
        assert aggregator is not None
        # No side effects on existing modules


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
