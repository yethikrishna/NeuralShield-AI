"""
Test suite for Threat Intelligence Feed Aggregator v8
NeuralShield-AI Feature Expansion - June 2026
ADD-ONLY - NO EXISTING CODE MODIFIED
"""

import unittest
import tempfile
import os
import time
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intel_feed_aggregator_semantic_cache_v8_2026_june import (
    ThreatIntelFeedAggregator,
    BloomFilter,
    SemanticCache,
    IOCEntry,
    FeedType,
    IOCType,
    ThreatSeverity,
    get_aggregator,
)


class TestBloomFilter(unittest.TestCase):
    """Test Bloom filter deduplication functionality"""

    def test_bloom_filter_basic(self):
        """Test basic add and contains operations"""
        bf = BloomFilter(size=2**16, num_hashes=3)
        
        bf.add("test_value")
        self.assertIn("test_value", bf)
        self.assertNotIn("not_added", bf)

    def test_bloom_filter_no_false_negatives(self):
        """Test that added values are always found (no false negatives)"""
        bf = BloomFilter(size=2**16, num_hashes=3)
        test_values = [f"ioc_{i}" for i in range(100)]
        
        for v in test_values:
            bf.add(v)
        
        for v in test_values:
            self.assertIn(v, bf, f"False negative for {v}")

    def test_bloom_filter_count(self):
        """Test bloom filter count tracking"""
        bf = BloomFilter(size=2**16, num_hashes=3)
        self.assertEqual(bf.count, 0)
        
        bf.add("test1")
        bf.add("test2")
        self.assertEqual(bf.count, 2)

    def test_bloom_filter_fp_rate(self):
        """Test false positive rate calculation"""
        bf = BloomFilter(size=2**20, num_hashes=5)
        fp_rate = bf.estimated_false_positive_rate()
        self.assertGreaterEqual(fp_rate, 0.0)
        self.assertLessEqual(fp_rate, 1.0)


class TestSemanticCache(unittest.TestCase):
    """Test semantic caching functionality"""

    def test_cache_put_get(self):
        """Test basic cache operations"""
        cache = SemanticCache(cache_ttl=3600)
        
        cache.put("key1", "value1")
        self.assertEqual(cache.get("key1"), "value1")
        self.assertIsNone(cache.get("key2"))

    def test_cache_expiration(self):
        """Test cache TTL expiration"""
        cache = SemanticCache(cache_ttl=1)
        
        cache.put("temp_key", "temp_value")
        self.assertEqual(cache.get("temp_key"), "temp_value")
        
        time.sleep(1.1)
        self.assertIsNone(cache.get("temp_key"))

    def test_semantic_similarity(self):
        """Test LSH-based similarity search"""
        cache = SemanticCache()
        
        cache.put("APT29 threat actor campaign", "data1")
        cache.put("APT28 operation", "data2")
        cache.put("Emotet malware", "data3")
        
        similar = cache.find_similar("APT29 threat actor")
        self.assertGreater(len(similar), 0)

    def test_cache_cleanup(self):
        """Test expired entry cleanup"""
        cache = SemanticCache(cache_ttl=1)
        cache.put("expired1", "val1")
        cache.put("expired2", "val2")
        time.sleep(1.1)
        
        removed = cache.cleanup()
        self.assertEqual(removed, 2)


class TestIOCEntry(unittest.TestCase):
    """Test IOC entry data structure"""

    def test_ioc_creation(self):
        """Test IOC entry creation"""
        ioc = IOCEntry(
            value="192.168.1.1",
            ioc_type=IOCType.IPV4,
            source=FeedType.ABUSEIPDB,
            severity=ThreatSeverity.HIGH,
            first_seen=time.time(),
            last_seen=time.time(),
            confidence=0.9
        )
        self.assertEqual(ioc.value, "192.168.1.1")
        self.assertEqual(ioc.ioc_type, IOCType.IPV4)

    def test_ioc_to_dict(self):
        """Test IOC serialization"""
        ioc = IOCEntry(
            value="test.com",
            ioc_type=IOCType.DOMAIN,
            source=FeedType.THREATFOX,
            severity=ThreatSeverity.MEDIUM,
            first_seen=1000.0,
            last_seen=2000.0,
            confidence=0.8
        )
        d = ioc.to_dict()
        self.assertEqual(d["value"], "test.com")
        self.assertEqual(d["ioc_type"], "domain")
        self.assertEqual(d["confidence"], 0.8)

    def test_ioc_hashable(self):
        """Test that IOCs are hashable for set operations"""
        ioc1 = IOCEntry(
            value="1.1.1.1",
            ioc_type=IOCType.IPV4,
            source=FeedType.ABUSEIPDB,
            severity=ThreatSeverity.LOW,
            first_seen=0,
            last_seen=0,
            confidence=0.5
        )
        ioc_set = {ioc1}
        self.assertIn(ioc1, ioc_set)


class TestThreatIntelFeedAggregator(unittest.TestCase):
    """Main threat intelligence aggregator tests"""

    def setUp(self):
        self.aggregator = ThreatIntelFeedAggregator()

    def test_extract_iocs_ipv4(self):
        """Test IPv4 IOC extraction"""
        feed_text = """
        Malicious IPs detected:
        192.168.1.1 - C2 server
        10.0.0.255 - Scan source
        256.1.1.1 - Invalid (should be skipped)
        """
        
        iocs = self.aggregator.extract_iocs_from_text(feed_text, FeedType.ABUSEIPDB)
        
        ipv4_iocs = [i for i in iocs if i.ioc_type == IOCType.IPV4]
        self.assertGreaterEqual(len(ipv4_iocs), 2)
        
        values = [i.value for i in ipv4_iocs]
        self.assertIn("192.168.1.1", values)
        self.assertIn("10.0.0.255", values)
        self.assertNotIn("256.1.1.1", values)

    def test_extract_iocs_hash(self):
        """Test hash IOC extraction"""
        feed_text = """
        MD5: d41d8cd98f00b204e9800998ecf8427e
        SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
        SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        """
        
        iocs = self.aggregator.extract_iocs_from_text(feed_text, FeedType.MALWAREBAZAAR)
        
        md5_iocs = [i for i in iocs if i.ioc_type == IOCType.MD5]
        sha1_iocs = [i for i in iocs if i.ioc_type == IOCType.SHA1]
        sha256_iocs = [i for i in iocs if i.ioc_type == IOCType.SHA256]
        
        self.assertEqual(len(md5_iocs), 1)
        self.assertEqual(len(sha1_iocs), 1)
        self.assertEqual(len(sha256_iocs), 1)

    def test_ioc_deduplication(self):
        """Test that duplicate IOCs are filtered"""
        feed_text = "192.168.1.1 192.168.1.1 192.168.1.1"
        
        iocs1 = self.aggregator.extract_iocs_from_text(feed_text)
        iocs2 = self.aggregator.extract_iocs_from_text(feed_text)
        
        # Same text processed twice should yield fewer duplicates
        total_unique = len(set(i.value for i in iocs1 + iocs2))
        self.assertEqual(total_unique, 1)

    def test_check_ioc(self):
        """Test IOC lookup"""
        self.aggregator.extract_iocs_from_text("192.168.1.100")
        
        result = self.aggregator.check_ioc("192.168.1.100")
        self.assertIsNotNone(result)
        self.assertEqual(result.value, "192.168.1.100")
        
        not_found = self.aggregator.check_ioc("1.2.3.4")
        self.assertIsNone(not_found)

    def test_batch_check_iocs(self):
        """Test batch IOC checking"""
        self.aggregator.extract_iocs_from_text("10.0.0.1 10.0.0.2")
        
        results = self.aggregator.batch_check_iocs(["10.0.0.1", "10.0.0.2", "10.0.0.3"])
        
        self.assertIsNotNone(results["10.0.0.1"])
        self.assertIsNotNone(results["10.0.0.2"])
        self.assertIsNone(results["10.0.0.3"])

    def test_ioc_enrichment(self):
        """Test IOC context enrichment"""
        iocs = self.aggregator.extract_iocs_from_text("172.16.0.1")
        ioc = iocs[0]
        
        self.aggregator.enrich_with_context(
            ioc,
            threat_actor="APT29",
            ttp="T1059",
            metadata={"country": "RU", "industry": "Government"}
        )
        
        self.assertEqual(ioc.threat_actor, "APT29")
        self.assertEqual(ioc.ttp, "T1059")
        self.assertEqual(ioc.metadata["country"], "RU")

    def test_feed_health_report(self):
        """Test feed health monitoring"""
        self.aggregator.extract_iocs_from_text("1.1.1.1", FeedType.ABUSEIPDB)
        self.aggregator.extract_iocs_from_text("2.2.2.2", FeedType.VIRUSTOTAL)
        
        report = self.aggregator.get_feed_health_report()
        
        self.assertIn("feeds", report)
        self.assertIn("summary", report)
        self.assertIn("abuseipdb", report["feeds"])
        self.assertIn("virustotal", report["feeds"])

    def test_statistics(self):
        """Test statistics generation"""
        self.aggregator.extract_iocs_from_text("1.1.1.1 example.com d41d8cd98f00b204e9800998ecf8427e")
        
        stats = self.aggregator.get_statistics()
        
        self.assertGreaterEqual(stats["total_iocs"], 3)
        self.assertIn("ipv4", stats["by_type"])
        self.assertIn("domain", stats["by_type"])
        self.assertIn("md5", stats["by_type"])

    def test_export_database(self):
        """Test database export functionality"""
        self.aggregator.extract_iocs_from_text("192.168.1.50")
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            tmp_path = f.name
        
        try:
            self.aggregator.export_database(tmp_path)
            
            # Verify file exists and has content
            self.assertTrue(os.path.exists(tmp_path))
            self.assertGreater(os.path.getsize(tmp_path), 0)
        finally:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)

    def test_singleton_instance(self):
        """Test singleton aggregator"""
        agg1 = get_aggregator()
        agg2 = get_aggregator()
        self.assertIs(agg1, agg2)


class TestIntegrationWorkflows(unittest.TestCase):
    """Integration test for complete workflows"""

    def test_complete_threat_intel_workflow(self):
        """Test complete threat intel processing pipeline"""
        aggregator = ThreatIntelFeedAggregator()
        
        # Step 1: Process multiple feeds
        feed1 = "192.168.1.1 d41d8cd98f00b204e9800998ecf8427e"
        feed2 = "10.0.0.1 malicious-domain.com"
        
        iocs1 = aggregator.extract_iocs_from_text(feed1, FeedType.ABUSEIPDB)
        iocs2 = aggregator.extract_iocs_from_text(feed2, FeedType.THREATFOX)
        
        self.assertGreater(len(iocs1), 0)
        self.assertGreater(len(iocs2), 0)
        
        # Step 2: Enrich some IOCs
        for ioc in iocs1:
            aggregator.enrich_with_context(ioc, threat_actor="TestActor")
        
        # Step 3: Check lookup
        result = aggregator.check_ioc("192.168.1.1")
        self.assertIsNotNone(result)
        
        # Step 4: Get stats
        stats = aggregator.get_statistics()
        self.assertGreater(stats["total_iocs"], 0)
        
        # Step 5: Health report
        health = aggregator.get_feed_health_report()
        self.assertGreater(health["summary"]["total_iocs"], 0)


if __name__ == '__main__':
    unittest.main(verbosity=2)
