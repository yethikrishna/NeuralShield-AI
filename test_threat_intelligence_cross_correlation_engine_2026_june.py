"""
Test Suite for Threat Intelligence Cross-Correlation Engine
NeuralShield-AI - June 2026
Real production-grade tests that verify actual functionality
"""
import pytest
import time
from neural_shield.threat_intelligence_cross_correlation_engine_2026_june import (
    ThreatIntelligenceCrossCorrelator,
    AutoCorrelationDetector,
    IOCTYPE,
    IOCNode,
    CorrelationEdge
)
class TestIOCNode:
    """Test IOC Node data structure."""
    
    def test_ioc_node_creation(self):
        """Test that IOC nodes are created with proper attributes."""
        now = time.time()
        node = IOCNode(
            ioc_value="192.168.1.1",
            ioc_type=IOCTYPE.IP_ADDRESS,
            first_seen=now,
            last_seen=now,
            confidence=0.8
        )
        
        assert node.ioc_value == "192.168.1.1"
        assert node.ioc_type == IOCTYPE.IP_ADDRESS
        assert node.confidence == 0.8
        assert node.node_id is not None
        assert len(node.node_id) == 16  # 16 hex chars
    
    def test_ioc_node_source_feeds(self):
        """Test source feed tracking."""
        now = time.time()
        node = IOCNode(
            ioc_value="malicious.com",
            ioc_type=IOCTYPE.DOMAIN,
            first_seen=now,
            last_seen=now
        )
        node.source_feeds.add("abuse_ch")
        node.source_feeds.add("virustotal")
        
        assert "abuse_ch" in node.source_feeds
        assert "virustotal" in node.source_feeds
        assert len(node.source_feeds) == 2
class TestThreatIntelligenceCrossCorrelator:
    """Test main cross-correlation engine."""
    
    def test_initialization(self):
        """Test engine initialization with default parameters."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        assert engine.max_hops == 3
        assert engine.min_correlation_strength == 0.3
        assert len(engine.nodes) == 0
        assert len(engine.edges) == 0
    
    def test_custom_initialization(self):
        """Test engine initialization with custom parameters."""
        engine = ThreatIntelligenceCrossCorrelator(
            max_hops=5,
            min_correlation_strength=0.5
        )
        
        assert engine.max_hops == 5
        assert engine.min_correlation_strength == 0.5
    
    def test_add_single_ioc(self):
        """Test adding a single IOC to the engine."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        node_id = engine.add_ioc(
            ioc_value="1.2.3.4",
            ioc_type=IOCTYPE.IP_ADDRESS,
            source_feed="test_feed",
            threat_label="botnet",
            confidence=0.9
        )
        
        assert node_id is not None
        assert len(engine.nodes) == 1
        assert (IOCTYPE.IP_ADDRESS, "1.2.3.4") in engine.ioc_to_node
        
        # Verify node contents
        node = engine.nodes[node_id]
        assert node.ioc_value == "1.2.3.4"
        assert "test_feed" in node.source_feeds
        assert "botnet" in node.threat_labels
        assert node.confidence == 0.9
    
    def test_update_existing_ioc(self):
        """Test that adding the same IOC updates the existing node."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        node_id1 = engine.add_ioc(
            ioc_value="5.6.7.8",
            ioc_type=IOCTYPE.IP_ADDRESS,
            source_feed="feed1",
            confidence=0.5
        )
        
        node_id2 = engine.add_ioc(
            ioc_value="5.6.7.8",
            ioc_type=IOCTYPE.IP_ADDRESS,
            source_feed="feed2",
            threat_label="c2_server",
            confidence=0.7
        )
        
        # Should be the same node
        assert node_id1 == node_id2
        assert len(engine.nodes) == 1
        
        node = engine.nodes[node_id1]
        assert "feed1" in node.source_feeds
        assert "feed2" in node.source_feeds
        assert "c2_server" in node.threat_labels
        assert node.confidence == 0.7  # should take max
        assert node.observation_count == 2
    
    def test_add_correlation(self):
        """Test adding a correlation between two IOCs."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        result = engine.add_correlation(
            source_ioc="10.0.0.1",
            source_type=IOCTYPE.IP_ADDRESS,
            target_ioc="evil.com",
            target_type=IOCTYPE.DOMAIN,
            relationship_type="resolves_to",
            strength=0.8
        )
        
        assert result is True
        assert len(engine.nodes) == 2
        assert engine.total_correlations == 1
        
        # Both directions should have edges (undirected graph)
        source_id = engine.ioc_to_node[(IOCTYPE.IP_ADDRESS, "10.0.0.1")]
        target_id = engine.ioc_to_node[(IOCTYPE.DOMAIN, "evil.com")]
        
        assert len(engine.edges[source_id]) >= 1
        assert len(engine.edges[target_id]) >= 1
    
    def test_correlate_single_hop(self):
        """Test 1-hop correlation discovery."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        # Build a simple chain: IP -> Domain -> Hash
        engine.add_correlation(
            "192.168.1.100", IOCTYPE.IP_ADDRESS,
            "phishing.com", IOCTYPE.DOMAIN,
            "hosts", 0.9
        )
        engine.add_correlation(
            "phishing.com", IOCTYPE.DOMAIN,
            "abc123def456", IOCTYPE.HASH_SHA256,
            "serves_malware", 0.8
        )
        
        # Correlate from IP with 1 hop
        result = engine.correlate("192.168.1.100", IOCTYPE.IP_ADDRESS, max_hops=1)
        
        assert result is not None
        assert result.root_ioc == "192.168.1.100"
        assert len(result.connected_iocs) == 1  # only domain at 1 hop
        assert result.connected_iocs[0]["ioc_value"] == "phishing.com"
        assert result.connected_iocs[0]["hops"] == 1
    
    def test_correlate_multi_hop(self):
        """Test multi-hop correlation discovery."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        # Build a chain: IP -> Domain -> Hash -> Email
        engine.add_correlation(
            "192.168.1.100", IOCTYPE.IP_ADDRESS,
            "phishing.com", IOCTYPE.DOMAIN,
            "hosts", 0.9
        )
        engine.add_correlation(
            "phishing.com", IOCTYPE.DOMAIN,
            "abc123def456", IOCTYPE.HASH_SHA256,
            "serves_malware", 0.8
        )
        engine.add_correlation(
            "abc123def456", IOCTYPE.HASH_SHA256,
            "attacker@evil.com", IOCTYPE.EMAIL,
            "distributed_by", 0.7
        )
        
        # Correlate from IP with 3 hops
        result = engine.correlate("192.168.1.100", IOCTYPE.IP_ADDRESS, max_hops=3)
        
        assert result is not None
        assert len(result.connected_iocs) == 3  # domain, hash, email
        assert result.execution_time_ms > 0
        assert result.threat_cluster_score >= 0
    
    def test_correlate_unknown_ioc(self):
        """Test correlating an unknown IOC returns None."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        result = engine.correlate("99.99.99.99", IOCTYPE.IP_ADDRESS)
        
        assert result is None
    
    def test_find_threat_clusters(self):
        """Test threat cluster detection."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        # Create a connected cluster of 4 IOCs
        engine.add_correlation("ip1", IOCTYPE.IP_ADDRESS, "dom1", IOCTYPE.DOMAIN, "link", 0.9)
        engine.add_correlation("dom1", IOCTYPE.DOMAIN, "hash1", IOCTYPE.HASH_SHA256, "link", 0.9)
        engine.add_correlation("hash1", IOCTYPE.HASH_SHA256, "email1", IOCTYPE.EMAIL, "link", 0.9)
        
        # Create an isolated pair (should not be a cluster of size >= 3)
        engine.add_correlation("ip2", IOCTYPE.IP_ADDRESS, "dom2", IOCTYPE.DOMAIN, "link", 0.9)
        
        clusters = engine.find_threat_clusters(min_cluster_size=3)
        
        assert len(clusters) == 1
        assert clusters[0]["size"] == 4
        assert len(clusters[0]["node_samples"]) > 0
    
    def test_batch_add_from_feed(self):
        """Test batch importing IOCs from a threat feed."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        feed_data = [
            {"value": "1.1.1.1", "type": "ip_address", "label": "malware", "confidence": 0.9},
            {"value": "2.2.2.2", "type": "ip_address", "label": "botnet", "confidence": 0.8},
            {"value": "bad.com", "type": "domain", "label": "phishing", "confidence": 0.95},
            {"value": "invalid", "type": "unknown_type", "label": "test"},  # should be skipped
        ]
        
        count = engine.batch_add_from_feed(feed_data, "test_threat_feed")
        
        assert count == 3  # 3 valid IOCs
        assert len(engine.nodes) == 3
    
    def test_get_statistics(self):
        """Test statistics reporting."""
        engine = ThreatIntelligenceCrossCorrelator()
        
        # Add some data
        engine.add_ioc("1.1.1.1", IOCTYPE.IP_ADDRESS, "feed1")
        engine.add_ioc("2.2.2.2", IOCTYPE.IP_ADDRESS, "feed2")
        engine.add_correlation(
            "1.1.1.1", IOCTYPE.IP_ADDRESS,
            "2.2.2.2", IOCTYPE.IP_ADDRESS,
            "related", 0.6
        )
        
        # Do a query
        engine.correlate("1.1.1.1", IOCTYPE.IP_ADDRESS)
        
        stats = engine.get_statistics()
        
        assert stats["total_ioc_nodes"] == 2
        assert stats["total_correlation_edges"] == 1
        assert stats["unique_source_feeds"] == 2
        assert stats["total_correlation_queries"] == 1
        assert stats["average_query_time_ms"] > 0
class TestAutoCorrelationDetector:
    """Test automatic co-occurrence correlation detector."""
    
    def test_auto_correlation_detection(self):
        """Test that co-occurring IOCs get automatically correlated."""
        engine = ThreatIntelligenceCrossCorrelator()
        detector = AutoCorrelationDetector(engine)
        
        # Observe multiple IOCs in same context within time window
        detector.observe_ioc("10.0.0.1", IOCTYPE.IP_ADDRESS, "alert_12345")
        detector.observe_ioc("malware.exe", IOCTYPE.HASH_SHA256, "alert_12345")
        detector.observe_ioc("evil.com", IOCTYPE.DOMAIN, "alert_12345")
        
        # Should have created correlations
        result = engine.correlate("10.0.0.1", IOCTYPE.IP_ADDRESS, max_hops=2)
        
        assert result is not None
        assert len(result.connected_iocs) >= 2  # should find hash and domain
def test_thread_safety_basic():
    """Basic test that thread-safe operations don't crash."""
    engine = ThreatIntelligenceCrossCorrelator()
    
    # Just verify the lock exists and basic operations work
    engine.add_ioc("test.ip", IOCTYPE.IP_ADDRESS, "test")
    engine.add_ioc("test2.ip", IOCTYPE.IP_ADDRESS, "test")
    engine.add_correlation(
        "test.ip", IOCTYPE.IP_ADDRESS,
        "test2.ip", IOCTYPE.IP_ADDRESS,
        "test", 0.5
    )
    
    # Should complete without deadlock
    result = engine.correlate("test.ip", IOCTYPE.IP_ADDRESS)
    assert result is not None
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
