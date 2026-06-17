"""
Test Suite for Threat Intelligence Bloom Filter
NeuralShield-AI - Production Grade Tests
"""

import pytest
import json
import threading
import time
from neural_shield.threat_intelligence_bloom_filter_2026_june import (
    BloomFilterConfig,
    BloomFilterStats,
    ThreatIntelligenceBloomFilter,
    IOCategorizer
)


class TestBloomFilterConfig:
    """Tests for BloomFilterConfig"""

    def test_config_calculation(self):
        """Test optimal parameter calculation"""
        config = BloomFilterConfig(
            expected_elements=10000,
            false_positive_rate=0.01
        )
        
        assert config.size_bits > 0
        assert config.num_hashes >= 2
        assert config.num_hashes <= 15

    def test_small_config(self):
        """Test with very small expected elements"""
        config = BloomFilterConfig(
            expected_elements=10,
            false_positive_rate=0.001
        )
        
        assert config.size_bits >= 64
        assert config.num_hashes >= 2


class TestIOCategorizer:
    """Tests for IOC categorization"""

    def test_md5_hash(self):
        """Test MD5 hash categorization"""
        assert IOCategorizer.categorize("d41d8cd98f00b204e9800998ecf8427e") == "HASH_MD5"

    def test_sha1_hash(self):
        """Test SHA1 hash categorization"""
        assert IOCategorizer.categorize("da39a3ee5e6b4b0d3255bfef95601890afd80709") == "HASH_SHA1"

    def test_sha256_hash(self):
        """Test SHA256 hash categorization"""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        assert IOCategorizer.categorize(sha256) == "HASH_SHA256"

    def test_ipv4(self):
        """Test IPv4 categorization"""
        assert IOCategorizer.categorize("192.168.1.1") == "IPV4"
        assert IOCategorizer.categorize("8.8.8.8") == "IPV4"

    def test_domain(self):
        """Test domain categorization"""
        assert IOCategorizer.categorize("malicious-domain.com") == "DOMAIN"
        assert IOCategorizer.categorize("evil.co.uk") == "DOMAIN"

    def test_url(self):
        """Test URL categorization"""
        assert IOCategorizer.categorize("http://bad-site.com/payload") == "URL"
        assert IOCategorizer.categorize("https://phishing.org/login") == "URL"
        assert IOCategorizer.categorize("www.fake-bank.com") == "URL"

    def test_unknown(self):
        """Test unknown categorization"""
        assert IOCategorizer.categorize("random-string-123") == "UNKNOWN"


class TestThreatIntelligenceBloomFilter:
    """Main tests for Bloom Filter"""

    @pytest.fixture
    def bloom_filter(self):
        """Create a standard bloom filter for testing"""
        config = BloomFilterConfig(
            expected_elements=1000,
            false_positive_rate=0.01
        )
        return ThreatIntelligenceBloomFilter(config)

    def test_add_and_check_ioc(self, bloom_filter):
        """Test basic add and check functionality"""
        test_ioc = "192.168.1.100"
        
        # Should not contain before adding
        assert bloom_filter.might_contain(test_ioc) is False
        
        # Add IOC
        result = bloom_filter.add_ioc(test_ioc, "IPV4")
        assert result is True
        
        # Should contain after adding
        assert bloom_filter.might_contain(test_ioc) is True

    def test_empty_ioc(self, bloom_filter):
        """Test handling of empty IOC"""
        assert bloom_filter.add_ioc("") is False
        assert bloom_filter.add_ioc(None) is False
        assert bloom_filter.might_contain("") is False

    def test_bulk_add(self, bloom_filter):
        """Test bulk IOC addition"""
        iocs = [
            ("10.0.0.1", "IPV4"),
            ("malware.exe", "DOMAIN"),
            ("d41d8cd98f00b204e9800998ecf8427e", "HASH_MD5"),
            ("https://phish.com", "URL"),
        ]
        
        count = bloom_filter.add_iocs_bulk(iocs)
        assert count == 4
        
        # Verify all were added
        for ioc, _ in iocs:
            assert bloom_filter.might_contain(ioc) is True

    def test_batch_check(self, bloom_filter):
        """Test batch IOC checking"""
        # Add some IOCs
        bloom_filter.add_ioc("1.1.1.1", "IPV4")
        bloom_filter.add_ioc("bad-domain.com", "DOMAIN")
        
        test_iocs = ["1.1.1.1", "good-domain.com", "bad-domain.com", "unknown-ioc"]
        results = bloom_filter.batch_check(test_iocs)
        
        assert len(results) == 4
        assert results["1.1.1.1"] is True
        assert results["bad-domain.com"] is True
        assert results["good-domain.com"] is False

    def test_get_stats(self, bloom_filter):
        """Test statistics generation"""
        # Empty stats
        stats = bloom_filter.get_stats()
        assert stats.total_elements_added == 0
        assert stats.capacity_used_percent == 0.0
        
        # Add elements
        for i in range(100):
            bloom_filter.add_ioc(f"ioc-{i}.test", "DOMAIN")
        
        stats = bloom_filter.get_stats()
        assert stats.total_elements_added == 100
        assert stats.capacity_used_percent > 0
        assert stats.memory_usage_bytes > 0
        assert stats.num_hashes > 0

    def test_serialize_deserialize(self, bloom_filter):
        """Test serialization and deserialization"""
        # Add some IOCs
        test_iocs = ["192.168.1.1", "malicious.com", "test-hash-123"]
        for ioc in test_iocs:
            bloom_filter.add_ioc(ioc)
        
        # Serialize
        serialized = bloom_filter.serialize()
        assert isinstance(serialized, str)
        assert len(serialized) > 0
        
        # Verify JSON is valid
        data = json.loads(serialized)
        assert "config" in data
        assert "bit_array" in data
        
        # Deserialize
        restored = ThreatIntelligenceBloomFilter.deserialize(serialized)
        
        # Verify restored filter contains the IOCs
        for ioc in test_iocs:
            assert restored.might_contain(ioc) is True
        
        # Verify stats match
        original_stats = bloom_filter.get_stats()
        restored_stats = restored.get_stats()
        assert original_stats.total_elements_added == restored_stats.total_elements_added

    def test_clear(self, bloom_filter):
        """Test clearing the filter"""
        bloom_filter.add_ioc("test-ioc-123", "DOMAIN")
        assert bloom_filter.might_contain("test-ioc-123") is True
        
        bloom_filter.clear()
        
        assert bloom_filter.might_contain("test-ioc-123") is False
        stats = bloom_filter.get_stats()
        assert stats.total_elements_added == 0

    def test_case_insensitive(self, bloom_filter):
        """Test that IOC checks are case-insensitive"""
        bloom_filter.add_ioc("Malicious-Domain.COM", "DOMAIN")
        
        # Different cases should all match
        assert bloom_filter.might_contain("malicious-domain.com") is True
        assert bloom_filter.might_contain("MALICIOUS-DOMAIN.COM") is True
        assert bloom_filter.might_contain("Malicious-Domain.Com") is True

    def test_thread_safety(self, bloom_filter):
        """Test thread-safe concurrent operations"""
        num_threads = 5
        iocs_per_thread = 100
        
        def add_iocs(thread_id):
            for i in range(iocs_per_thread):
                bloom_filter.add_ioc(f"thread-{thread_id}-ioc-{i}", "TEST")
        
        threads = []
        for t in range(num_threads):
            thread = threading.Thread(target=add_iocs, args=(t,))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        stats = bloom_filter.get_stats()
        assert stats.total_elements_added == num_threads * iocs_per_thread

    def test_whitespace_handling(self, bloom_filter):
        """Test whitespace handling in IOCs"""
        bloom_filter.add_ioc("  192.168.1.1  ", "IPV4")
        assert bloom_filter.might_contain("192.168.1.1") is True
        assert bloom_filter.might_contain("  192.168.1.1  ") is True


class TestFalsePositiveRate:
    """Tests for false positive rate verification"""

    def test_approximate_false_positive_rate(self):
        """Test that false positive rate is within expected bounds"""
        config = BloomFilterConfig(
            expected_elements=10000,
            false_positive_rate=0.01
        )
        bloom = ThreatIntelligenceBloomFilter(config)
        
        # Add 10,000 known IOCs
        for i in range(10000):
            bloom.add_ioc(f"known-malicious-{i}.com", "DOMAIN")
        
        # Test with 10,000 random (not added) IOCs
        false_positives = 0
        num_tests = 10000
        
        for i in range(num_tests):
            if bloom.might_contain(f"definitely-not-added-{i}.com"):
                false_positives += 1
        
        fp_rate = (false_positives / num_tests) * 100
        
        # Should be roughly around 1% (allow some variance)
        # This is a probabilistic test - should pass most of the time
        # We use a generous upper bound
        assert fp_rate < 5.0, f"False positive rate too high: {fp_rate}%"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
