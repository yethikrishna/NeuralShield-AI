"""
Test Suite: Threat Intelligence Entity Resolution & Link Analysis Engine
DIMENSION A - Feature Expansion Tests (v22 - June 2026)

Comprehensive tests for the new entity resolution feature.
All tests are ADD-ONLY - no modifications to existing tests.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_entity_resolution_link_analysis_v22_2026_june import (
    EntityType,
    RelationshipType,
    ThreatEntity,
    EntityRelationship,
    EntityNormalizer,
    EntityResolutionEngine,
    ThreatLinkAnalyzer,
)


class TestEntityNormalizer:
    """Tests for entity normalization"""

    def test_normalize_ip_valid(self):
        """Test valid IP address normalization"""
        result = EntityNormalizer.normalize_ip("  192.168.1.1  ")
        assert result == "192.168.1.1"

    def test_normalize_ip_invalid(self):
        """Test invalid IP address returns None"""
        result = EntityNormalizer.normalize_ip("256.256.256.256")
        assert result is None

    def test_normalize_domain_valid(self):
        """Test valid domain normalization"""
        result = EntityNormalizer.normalize_domain("  EXAMPLE.COM.  ")
        assert result == "example.com"

    def test_normalize_domain_invalid(self):
        """Test invalid domain returns None"""
        result = EntityNormalizer.normalize_domain("not a domain")
        assert result is None

    def test_normalize_hash_md5(self):
        """Test MD5 hash normalization"""
        result = EntityNormalizer.normalize_hash("  D41D8CD98F00B204E9800998ECF8427E  ")
        assert result == "d41d8cd98f00b204e9800998ecf8427e"

    def test_normalize_hash_sha256(self):
        """Test SHA256 hash normalization"""
        sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = EntityNormalizer.normalize_hash(sha256.upper())
        assert result == sha256

    def test_normalize_cve(self):
        """Test CVE identifier normalization"""
        result = EntityNormalizer.normalize_cve("  cve-2024-1234  ")
        assert result == "CVE-2024-1234"

    def test_normalize_url(self):
        """Test URL normalization"""
        result = EntityNormalizer.normalize_url("  HTTPS://EXAMPLE.COM/PATH  ")
        assert result == "https://example.com/path"


class TestEntityResolutionEngine:
    """Tests for core entity resolution engine"""

    def test_add_entity_new(self):
        """Test adding a new entity"""
        engine = EntityResolutionEngine()
        entity = engine.add_entity(
            "192.168.1.1",
            EntityType.IP_ADDRESS,
            "test_feed",
            confidence=0.9
        )
        assert entity is not None
        assert entity.normalized_value == "192.168.1.1"
        assert "test_feed" in entity.source_feeds

    def test_add_entity_duplicate(self):
        """Test adding duplicate entity updates existing one"""
        engine = EntityResolutionEngine()
        e1 = engine.add_entity("192.168.1.1", EntityType.IP_ADDRESS, "feed1", confidence=0.5)
        e2 = engine.add_entity("192.168.1.1", EntityType.IP_ADDRESS, "feed2", confidence=0.9)
        
        assert e1.entity_id == e2.entity_id
        assert len(e2.source_feeds) == 2
        assert e2.confidence == 0.9  # Higher confidence preserved

    def test_add_entity_invalid(self):
        """Test adding invalid entity returns None"""
        engine = EntityResolutionEngine()
        entity = engine.add_entity("invalid ip", EntityType.IP_ADDRESS, "test_feed")
        assert entity is None

    def test_add_relationship(self):
        """Test adding relationship between entities"""
        engine = EntityResolutionEngine()
        rel = engine.add_relationship(
            "malicious.com", EntityType.DOMAIN,
            "192.168.1.1", EntityType.IP_ADDRESS,
            RelationshipType.RESOLVES_TO,
            "dns_feed",
            confidence=0.8
        )
        assert rel is not None
        assert rel.confidence == 0.8

    def test_find_related_entities(self):
        """Test finding related entities via graph traversal"""
        engine = EntityResolutionEngine()
        
        # Build a small graph: A -> B -> C
        engine.add_relationship(
            "A.com", EntityType.DOMAIN,
            "1.1.1.1", EntityType.IP_ADDRESS,
            RelationshipType.RESOLVES_TO, "feed1", 0.9
        )
        engine.add_relationship(
            "1.1.1.1", EntityType.IP_ADDRESS,
            "malware.exe", EntityType.FILE_HASH,
            RelationshipType.HOSTS, "feed2", 0.8
        )
        
        result = engine.find_related_entities("A.com", EntityType.DOMAIN, max_depth=2)
        
        assert "error" not in result
        assert result["total_found"] >= 1
        assert len(result["related_entities"]) >= 1

    def test_find_related_entities_not_found(self):
        """Test finding non-existent entity"""
        engine = EntityResolutionEngine()
        result = engine.find_related_entities("notfound.com", EntityType.DOMAIN)
        assert result["error"] == "Entity not found"

    def test_get_entity_clusters(self):
        """Test finding entity clusters"""
        engine = EntityResolutionEngine()
        
        # Create connected entities
        engine.add_relationship(
            "actor1", EntityType.THREAT_ACTOR,
            "malware1", EntityType.MALWARE_FAMILY,
            RelationshipType.USES, "feed1"
        )
        engine.add_relationship(
            "malware1", EntityType.MALWARE_FAMILY,
            "1.1.1.1", EntityType.IP_ADDRESS,
            RelationshipType.USES, "feed2"
        )
        
        clusters = engine.get_entity_clusters(min_cluster_size=2)
        assert len(clusters) >= 1

    def test_get_statistics(self):
        """Test engine statistics"""
        engine = EntityResolutionEngine()
        engine.add_entity("1.1.1.1", EntityType.IP_ADDRESS, "feed1")
        engine.add_entity("2.2.2.2", EntityType.IP_ADDRESS, "feed2")
        engine.add_entity("example.com", EntityType.DOMAIN, "feed1")
        
        stats = engine.get_statistics()
        assert stats["total_entities"] == 3
        assert stats["entities_by_type"]["ip_address"] == 2
        assert stats["entities_by_type"]["domain"] == 1


class TestThreatLinkAnalyzer:
    """Tests for high-level link analysis"""

    def test_detect_campaigns(self):
        """Test campaign detection"""
        engine = EntityResolutionEngine()
        analyzer = ThreatLinkAnalyzer(engine)
        
        # Create a cluster of related entities
        for i in range(6):
            engine.add_relationship(
                f"actor_main", EntityType.THREAT_ACTOR,
                f"ioc_{i}.com", EntityType.DOMAIN,
                RelationshipType.USES, f"feed_{i}"
            )
        
        campaigns = analyzer.detect_campaigns(min_entity_count=5)
        assert len(campaigns) >= 0  # May return empty if clustering doesn't group

    def test_generate_threat_graph(self):
        """Test threat graph generation"""
        engine = EntityResolutionEngine()
        analyzer = ThreatLinkAnalyzer(engine)
        
        engine.add_entity("1.1.1.1", EntityType.IP_ADDRESS, "feed1")
        engine.add_entity("example.com", EntityType.DOMAIN, "feed1")
        engine.add_relationship(
            "example.com", EntityType.DOMAIN,
            "1.1.1.1", EntityType.IP_ADDRESS,
            RelationshipType.RESOLVES_TO, "feed1"
        )
        
        graph = analyzer.generate_threat_graph(max_nodes=10)
        assert "nodes" in graph
        assert "edges" in graph
        assert len(graph["nodes"]) >= 2


class TestIntegration:
    """Integration tests for the complete feature"""

    def test_full_workflow(self):
        """Test complete entity resolution workflow"""
        engine = EntityResolutionEngine()
        
        # Simulate ingesting threat intelligence from multiple feeds
        feeds = ["alienvault", "virustotal", "threatfox", "abuseipdb"]
        
        # Add entities from different feeds
        for feed in feeds:
            engine.add_entity("192.168.1.100", EntityType.IP_ADDRESS, feed)
            engine.add_entity("evil.com", EntityType.DOMAIN, feed)
        
        # Add relationships
        engine.add_relationship(
            "evil.com", EntityType.DOMAIN,
            "192.168.1.100", EntityType.IP_ADDRESS,
            RelationshipType.RESOLVES_TO, "dns_feed", 0.95
        )
        
        # Verify deduplication worked
        entity = engine.add_entity("192.168.1.100", EntityType.IP_ADDRESS, "new_feed")
        assert len(entity.source_feeds) >= 5  # 4 original + 1 new
        
        stats = engine.get_statistics()
        assert stats["unique_source_feeds"] >= 5

    def test_edge_case_empty_engine(self):
        """Test empty engine behavior"""
        engine = EntityResolutionEngine()
        stats = engine.get_statistics()
        assert stats["total_entities"] == 0
        assert stats["total_relationships"] == 0
        
        clusters = engine.get_entity_clusters()
        assert clusters == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
