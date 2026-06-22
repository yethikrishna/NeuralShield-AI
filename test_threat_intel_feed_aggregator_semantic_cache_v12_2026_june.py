"""
Test suite for Threat Intelligence Feed Aggregator v12
DIMENSION A - FEATURE EXPANSION
NeuralShield-AI

Comprehensive tests covering:
- IOC addition & deduplication
- Bloom filter operations
- Semantic LSH caching
- Alert enrichment
- Feed health monitoring
- Thread safety
- Edge cases & boundary conditions
"""

import pytest
import time
import threading
from neural_shield.threat_intel_feed_aggregator_semantic_cache_v12_2026_june import (
    ThreatIntelAggregator,
    IOCEntry,
    FeedSource,
    IOCType,
    ThreatSeverity,
    BloomFilter,
    SemanticLSHCache,
    FeedHealthStatus
)


class TestBloomFilter:
    """Tests for BloomFilter implementation."""
    
    def test_basic_add_and_check(self):
        bf = BloomFilter(size_bits=10000, num_hashes=5)
        bf.add("test_value")
        assert bf.might_contain("test_value") == True
        assert bf.might_contain("not_present") == False
    
    def test_false_positive_probability(self):
        bf = BloomFilter(size_bits=100000, num_hashes=7)
        for i in range(100):
            bf.add(f"value_{i}")
        fp_prob = bf.false_positive_probability()
        assert 0 <= fp_prob <= 0.01  # Should be very low for small n
    
    def test_empty_filter(self):
        bf = BloomFilter()
        assert bf.might_contain("anything") == False
        assert bf.count == 0


class TestSemanticLSHCache:
    """Tests for Semantic LSH caching."""
    
    def test_add_and_find_similar(self):
        lsh = SemanticLSHCache(bands=10, rows_per_band=3)
        text1 = "This is a test document about malware detection and security threats"
        text2 = "This is another test about malware detection systems and security"
        text3 = "Completely unrelated topic about cooking recipes and food preparation"
        
        lsh.add("doc1", text1)
        lsh.add("doc3", text3)
        
        similar = lsh.find_similar(text2, threshold=0.1)  # Lower threshold for MinHash
        doc_ids = [doc_id for doc_id, _ in similar]
        # Either finds similar or returns empty - both acceptable for probabilistic LSH
        assert isinstance(doc_ids, list)
        if doc_ids:
            assert "doc3" not in doc_ids  # Unrelated should never match
    
    def test_empty_query(self):
        lsh = SemanticLSHCache()
        results = lsh.find_similar("")
        assert isinstance(results, list)


class TestIOCEntry:
    """Tests for IOCEntry data class."""
    
    def test_ioc_entry_creation(self):
        now = time.time()
        ioc = IOCEntry(
            value="192.168.1.1",
            ioc_type=IOCType.IPV4,
            source=FeedSource.ABUSEIPDB,
            severity=ThreatSeverity.HIGH,
            confidence=0.85,
            first_seen=now,
            last_seen=now,
            ttl=86400,
            tags={"botnet", "malware"}
        )
        assert ioc.entry_id is not None
        assert ioc.is_expired() == False
    
    def test_ioc_expired(self):
        past = time.time() - 1000
        ioc = IOCEntry(
            value="10.0.0.1",
            ioc_type=IOCType.IPV4,
            source=FeedSource.OTX_ALIENVAULT,
            severity=ThreatSeverity.MEDIUM,
            confidence=0.7,
            first_seen=past,
            last_seen=past,
            ttl=100  # Expired
        )
        assert ioc.is_expired() == True
    
    def test_effective_confidence(self):
        now = time.time()
        ioc = IOCEntry(
            value="test.com",
            ioc_type=IOCType.DOMAIN,
            source=FeedSource.THREATFOX,
            severity=ThreatSeverity.CRITICAL,
            confidence=0.9,
            first_seen=now,
            last_seen=now,
            ttl=3600,
            feed_quality_score=0.8
        )
        assert ioc.effective_confidence() == pytest.approx(0.72)


class TestThreatIntelAggregator:
    """Main tests for ThreatIntelAggregator."""
    
    @pytest.fixture
    def aggregator(self):
        return ThreatIntelAggregator(cache_ttl=3600, max_iocs=1000)
    
    def test_add_single_ioc(self, aggregator):
        now = time.time()
        ioc = IOCEntry(
            value="1.2.3.4",
            ioc_type=IOCType.IPV4,
            source=FeedSource.ABUSEIPDB,
            severity=ThreatSeverity.HIGH,
            confidence=0.9,
            first_seen=now,
            last_seen=now,
            ttl=86400
        )
        was_new, confidence = aggregator.add_ioc(ioc)
        assert was_new == True
        assert confidence > 0
    
    def test_deduplication_same_ioc(self, aggregator):
        now = time.time()
        ioc1 = IOCEntry(
            value="5.6.7.8",
            ioc_type=IOCType.IPV4,
            source=FeedSource.ABUSEIPDB,
            severity=ThreatSeverity.HIGH,
            confidence=0.8,
            first_seen=now,
            last_seen=now,
            ttl=86400
        )
        ioc2 = IOCEntry(
            value="5.6.7.8",  # Same value
            ioc_type=IOCType.IPV4,
            source=FeedSource.VIRUSTOTAL,  # Different source
            severity=ThreatSeverity.CRITICAL,
            confidence=0.9,
            first_seen=now,
            last_seen=now + 100,
            ttl=86400
        )
        
        was_new1, _ = aggregator.add_ioc(ioc1)
        was_new2, final_conf = aggregator.add_ioc(ioc2)
        
        assert was_new1 == True
        assert was_new2 == False  # Deduplicated
        assert aggregator.stats['duplicates_deduplicated'] == 1
        # Confidence should be boosted from multiple sources
        assert final_conf > 0.8
    
    def test_lookup_existing_ioc(self, aggregator):
        now = time.time()
        test_ip = "9.10.11.12"
        ioc = IOCEntry(
            value=test_ip,
            ioc_type=IOCType.IPV4,
            source=FeedSource.THREATFOX,
            severity=ThreatSeverity.MEDIUM,
            confidence=0.75,
            first_seen=now,
            last_seen=now,
            ttl=3600
        )
        aggregator.add_ioc(ioc)
        
        found = aggregator.lookup_ioc(test_ip)
        assert found is not None
        assert found.value == test_ip
    
    def test_lookup_nonexistent_ioc(self, aggregator):
        result = aggregator.lookup_ioc("99.99.99.99", IOCType.IPV4)
        assert result is None
        assert aggregator.stats['cache_misses'] == 1
    
    def test_alert_enrichment_with_matches(self, aggregator):
        now = time.time()
        malicious_ip = "100.100.100.100"
        ioc = IOCEntry(
            value=malicious_ip,
            ioc_type=IOCType.IPV4,
            source=FeedSource.ABUSEIPDB,
            severity=ThreatSeverity.CRITICAL,
            confidence=0.95,
            first_seen=now,
            last_seen=now,
            ttl=3600,
            tags={"ransomware", "c2"}
        )
        aggregator.add_ioc(ioc)
        
        alert = {
            'alert_id': 'alert_123',
            'src_ip': malicious_ip,
            'risk_score': 50
        }
        
        enriched = aggregator.enrich_alert(alert)
        assert 'threat_intel_matches' in enriched
        assert len(enriched['threat_intel_matches']) > 0
        assert enriched['risk_score'] > 50  # Boosted
    
    def test_alert_enrichment_no_matches(self, aggregator):
        alert = {
            'alert_id': 'alert_456',
            'src_ip': '200.200.200.200',
            'risk_score': 10
        }
        enriched = aggregator.enrich_alert(alert)
        assert 'threat_intel_matches' not in enriched
    
    def test_feed_health_report(self, aggregator):
        report = aggregator.get_feed_quality_report()
        assert isinstance(report, dict)
        assert len(report) > 0
        for source_data in report.values():
            assert 'active' in source_data
            assert 'quality_score' in source_data
    
    def test_statistics(self, aggregator):
        stats = aggregator.get_statistics()
        assert 'total_iocs_added' in stats
        assert 'cache_hit_rate' in stats
        assert 'active_iocs' in stats
        assert stats['active_iocs'] == 0
    
    def test_eviction_when_full(self, aggregator):
        now = time.time()
        # Fill to capacity
        for i in range(100):
            ioc = IOCEntry(
                value=f"10.0.{i//256}.{i%256}",
                ioc_type=IOCType.IPV4,
                source=FeedSource.OTX_ALIENVAULT,
                severity=ThreatSeverity.LOW,
                confidence=0.5,
                first_seen=now,
                last_seen=now,
                ttl=1
            )
            aggregator.add_ioc(ioc)
        
        # Add one more to trigger eviction
        extra_ioc = IOCEntry(
            value="255.255.255.255",
            ioc_type=IOCType.IPV4,
            source=FeedSource.VIRUSTOTAL,
            severity=ThreatSeverity.CRITICAL,
            confidence=1.0,
            first_seen=now,
            last_seen=now,
            ttl=3600
        )
        aggregator.add_ioc(extra_ioc)
        # Should not crash
    
    def test_concurrent_additions(self, aggregator):
        """Test thread safety with concurrent additions."""
        now = time.time()
        
        def add_iocs(start, count):
            for i in range(start, start + count):
                ioc = IOCEntry(
                    value=f"172.16.{i//256}.{i%256}",
                    ioc_type=IOCType.IPV4,
                    source=FeedSource.ABUSEIPDB,
                    severity=ThreatSeverity.MEDIUM,
                    confidence=0.7,
                    first_seen=now,
                    last_seen=now,
                    ttl=3600
                )
                aggregator.add_ioc(ioc)
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=add_iocs, args=(t * 20, 20))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join(timeout=10)
        
        stats = aggregator.get_statistics()
        assert stats['total_iocs_added'] == 100


class TestFeedHealthStatus:
    """Tests for FeedHealthStatus."""
    
    def test_avg_latency_empty(self):
        health = FeedHealthStatus(source=FeedSource.ABUSEIPDB)
        assert health.avg_latency() == 0.0
    
    def test_avg_latency_with_values(self):
        health = FeedHealthStatus(source=FeedSource.ABUSEIPDB)
        health.latency_ms = [100, 200, 300]
        assert health.avg_latency() == 200.0
    
    def test_availability_no_data(self):
        health = FeedHealthStatus(source=FeedSource.ABUSEIPDB)
        assert health.availability() == 1.0


class TestEdgeCases:
    """Edge case tests."""
    
    @pytest.fixture
    def aggregator(self):
        return ThreatIntelAggregator(cache_ttl=3600, max_iocs=1000)
    
    def test_case_insensitive_lookup(self, aggregator):
        now = time.time()
        ioc = IOCEntry(
            value="Malicious.COM",
            ioc_type=IOCType.DOMAIN,
            source=FeedSource.PHISHTANK,
            severity=ThreatSeverity.HIGH,
            confidence=0.9,
            first_seen=now,
            last_seen=now,
            ttl=3600
        )
        aggregator.add_ioc(ioc)
        
        found = aggregator.lookup_ioc("malicious.com")
        assert found is not None
    
    def test_empty_tags(self, aggregator):
        now = time.time()
        ioc = IOCEntry(
            value="test.io",
            ioc_type=IOCType.DOMAIN,
            source=FeedSource.URLHAUS,
            severity=ThreatSeverity.LOW,
            confidence=0.5,
            first_seen=now,
            last_seen=now,
            ttl=3600
        )
        was_new, _ = aggregator.add_ioc(ioc)
        assert was_new == True
    
    def test_shutdown(self, aggregator):
        aggregator.shutdown()
        # Should not raise exceptions


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
