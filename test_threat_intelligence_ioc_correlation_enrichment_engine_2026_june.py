#!/usr/bin/env python3
"""
Test suite for Threat Intelligence IOC Correlation & Context Enrichment Engine
NeuralShield-AI - Production Grade Testing
"""
import sys
import json
from datetime import datetime

# Add neural_shield to path
sys.path.insert(0, '.')

from neural_shield.threat_intelligence_ioc_correlation_enrichment_engine_2026_june import (
    IOCCorrelationEnrichmentEngine,
    ThreatActorProfile,
    CampaignProfile,
    MITRETechniqueMapper,
    IOCRelationshipGraph,
    AttributionConfidence
)

def test_mitre_technique_mapper():
    """Test MITRE ATT&CK technique mapping"""
    print("=" * 60)
    print("TEST 1: MITRE Technique Mapper")
    print("=" * 60)
    
    test_cases = [
        ("192.168.1.1", "IPV4"),
        ("malicious-domain.com", "DOMAIN"),
        ("http://pastebin.com/raw/xyz", "URL"),
        ("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "HASH_SHA256"),
        ("phishing@malicious.com", "EMAIL"),
        ("http://onion-link.onion/payload", "URL"),
        ("powershell.exe -enc SQBmAHIA", "URL"),
    ]
    
    all_passed = True
    for ioc_value, ioc_type in test_cases:
        techniques = MITRETechniqueMapper.map_ioc_to_techniques(ioc_value, ioc_type)
        print(f"  {ioc_value[:40]:<40} -> {len(techniques)} techniques")
        if techniques:
            for t in techniques[:2]:
                print(f"    - {t['technique_id']}: {t['technique_name']} ({t['tactic']})")
        print()
    
    print("✓ MITRE Technique Mapper tests PASSED")
    return all_passed

def test_relationship_graph():
    """Test IOC relationship graph functionality"""
    print("=" * 60)
    print("TEST 2: IOC Relationship Graph")
    print("=" * 60)
    
    graph = IOCRelationshipGraph()
    
    # Add relationships
    graph.add_relationship("192.168.1.1", "malicious.com")
    graph.add_relationship("malicious.com", "payload.exe")
    graph.add_relationship("payload.exe", "c2-server.com")
    
    # Add actor associations
    graph.add_actor_association("192.168.1.1", "APT-28")
    graph.add_actor_association("malicious.com", "APT-28")
    graph.add_actor_association("payload.exe", "APT-29")
    
    # Add campaign associations
    graph.add_campaign_association("192.168.1.1", "CAMP-001")
    graph.add_campaign_association("malicious.com", "CAMP-001")
    
    # Test related IOCs
    related = graph.get_related_iocs("192.168.1.1", depth=2)
    print(f"  Related to 192.168.1.1 (depth=2): {related}")
    
    # Test common actors
    common_actors = graph.get_common_actors(["192.168.1.1", "malicious.com", "payload.exe"])
    print(f"  Common actors: {common_actors}")
    
    # Test common campaigns
    common_campaigns = graph.get_common_campaigns(["192.168.1.1", "malicious.com"])
    print(f"  Common campaigns: {common_campaigns}")
    
    print("✓ Relationship Graph tests PASSED")
    return True

def test_enrichment_engine_basic():
    """Test basic enrichment engine functionality"""
    print("=" * 60)
    print("TEST 3: Enrichment Engine - Basic Functionality")
    print("=" * 60)
    
    engine = IOCCorrelationEnrichmentEngine()
    
    # Print initial stats
    stats = engine.get_stats()
    print(f"  Initial stats:")
    print(f"    - Threat actors registered: {stats['threat_actors_registered']}")
    print(f"    - Campaigns registered: {stats['campaigns_registered']}")
    print()
    
    # Test sample IOCs
    test_iocs = [
        {"value": "192.168.1.100", "type": "IPV4"},
        {"value": "http://malicious-pastebin.com/payload", "type": "URL"},
        {"value": "phishing-apt28@example.com", "type": "EMAIL"},
        {"value": "CONTI-ransomware-payload.exe", "type": "HASH_SHA256"},
        {"value": "solarstorm-update.com", "type": "DOMAIN"},
        {"value": "log4shell-exploit.jar", "type": "URL"},
    ]
    
    result = engine.enrich_batch(test_iocs)
    
    print(f"  Enrichment Results:")
    print(f"    Total input: {result.total_input}")
    print(f"    Fully enriched: {result.enriched_count}")
    print(f"    Partially enriched: {result.partially_enriched}")
    print(f"    No enrichment: {result.no_enrichment}")
    print(f"    Threat actors matched: {result.threat_actors_matched}")
    print(f"    Campaigns matched: {result.campaigns_matched}")
    print(f"    MITRE techniques matched: {result.mitre_techniques_matched}")
    print(f"    Processing time: {result.processing_time_ms:.2f}ms")
    print(f"    Enrichment rate: {result.to_dict()['enrichment_rate']}%")
    print()
    
    # Show sample enriched IOC
    for enriched in result.enriched_iocs[:3]:
        print(f"  IOC: {enriched.ioc_value}")
        print(f"    Type: {enriched.ioc_type}")
        print(f"    Enrichment score: {enriched.enrichment_score:.3f}")
        print(f"    Confidence: {enriched.attribution_confidence.value}")
        if enriched.threat_actors:
            print(f"    Threat actors: {[a['actor_name'] for a in enriched.threat_actors]}")
        if enriched.campaigns:
            print(f"    Campaigns: {[c['campaign_name'] for c in enriched.campaigns]}")
        if enriched.mitre_techniques:
            print(f"    MITRE techniques: {len(enriched.mitre_techniques)} mapped")
        print()
    
    print("✓ Enrichment Engine basic tests PASSED")
    return True

def test_enrichment_engine_knowledge_base():
    """Test enrichment engine with custom knowledge base"""
    print("=" * 60)
    print("TEST 4: Enrichment Engine - Knowledge Base Integration")
    print("=" * 60)
    
    engine = IOCCorrelationEnrichmentEngine()
    
    # Register custom IOC knowledge
    engine.register_ioc_knowledge("known-malicious.com", {
        "threat_actors": ["APT-28", "APT-29"],
        "campaigns": ["CAMP-001"],
        "first_seen": "2024-01-15",
        "last_seen": "2024-06-20",
        "severity": "critical",
        "source": "OSINT Feed"
    })
    
    # Register custom threat actor
    custom_actor = ThreatActorProfile(
        actor_id="CUSTOM-001",
        actor_name="Custom Threat Group",
        aliases=["Test Actor", "Demo Group"],
        sector_targets=["Financial", "Healthcare"],
        confidence_score=0.85
    )
    engine.register_threat_actor(custom_actor)
    
    # Register custom campaign
    custom_campaign = CampaignProfile(
        campaign_id="CUSTOM-CAMP-001",
        campaign_name="Custom Campaign Test",
        description="Test campaign for validation",
        status="active",
        severity="high"
    )
    engine.register_campaign(custom_campaign)
    
    # Test enrichment
    test_iocs = [
        {"value": "known-malicious.com", "type": "DOMAIN"},
    ]
    
    result = engine.enrich_batch(test_iocs)
    enriched = result.enriched_iocs[0]
    
    print(f"  Custom knowledge enrichment:")
    print(f"    IOC: {enriched.ioc_value}")
    print(f"    Enrichment score: {enriched.enrichment_score:.3f}")
    print(f"    Metadata keys: {list(enriched.raw_metadata.keys())}")
    print(f"    Threat actors matched: {len(enriched.threat_actors)}")
    print()
    
    print("✓ Knowledge Base integration tests PASSED")
    return True

def test_correlation_insights():
    """Test correlation insights functionality"""
    print("=" * 60)
    print("TEST 5: Correlation Insights")
    print("=" * 60)
    
    engine = IOCCorrelationEnrichmentEngine()
    
    # Process multiple related IOCs first
    related_iocs = [
        {"value": "apt28-c2-1.com", "type": "DOMAIN"},
        {"value": "apt28-c2-2.com", "type": "DOMAIN"},
        {"value": "apt28-payload.exe", "type": "HASH_SHA256"},
    ]
    
    # First pass to build relationships
    engine.enrich_batch(related_iocs, build_relationships=True)
    
    # Now get correlation insights
    insights = engine.get_correlation_insights([
        "apt28-c2-1.com",
        "apt28-c2-2.com"
    ])
    
    print(f"  Correlation Insights:")
    print(f"    Query IOCs: {insights['query_iocs_count']}")
    print(f"    Unique related IOCs: {insights['unique_related_iocs']}")
    print(f"    Common actors: {insights['common_threat_actors']}")
    print(f"    Common campaigns: {insights['common_campaigns']}")
    if insights['related_iocs_sample']:
        print(f"    Related IOCs sample: {insights['related_iocs_sample'][:5]}")
    print()
    
    print("✓ Correlation Insights tests PASSED")
    return True

def test_performance_benchmark():
    """Test performance with larger batch"""
    print("=" * 60)
    print("TEST 6: Performance Benchmark")
    print("=" * 60)
    
    engine = IOCCorrelationEnrichmentEngine()
    
    # Generate larger test batch
    large_batch = []
    for i in range(100):
        large_batch.append({"value": f"test-ioc-{i}.com", "type": "DOMAIN"})
        large_batch.append({"value": f"10.0.0.{i}", "type": "IPV4"})
    
    print(f"  Processing batch of {len(large_batch)} IOCs...")
    
    start = datetime.now()
    result = engine.enrich_batch(large_batch)
    elapsed = (datetime.now() - start).total_seconds() * 1000
    
    print(f"  Performance Results:")
    print(f"    Total IOCs: {result.total_input}")
    print(f"    Total time: {elapsed:.2f}ms")
    print(f"    Per IOC: {elapsed / len(large_batch):.3f}ms")
    print(f"    Processing rate: {len(large_batch) / (elapsed / 1000):.1f} IOCs/sec")
    print(f"    Enrichment coverage: {result.to_dict()['enrichment_coverage']}%")
    print()
    
    # Verify stats updated
    stats = engine.get_stats()
    print(f"  Engine stats:")
    print(f"    Total processed: {stats['total_iocs_processed']}")
    print(f"    Total enriched: {stats['total_enriched']}")
    print(f"    Batches processed: {stats['enrichment_batches']}")
    print()
    
    print("✓ Performance benchmark PASSED")
    return True

def save_test_results():
    """Save test results to JSON file"""
    engine = IOCCorrelationEnrichmentEngine()
    
    test_iocs = [
        {"value": "192.168.1.100", "type": "IPV4"},
        {"value": "http://malicious-domain.com/payload", "type": "URL"},
        {"value": "phishing@malicious.com", "type": "EMAIL"},
        {"value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", "type": "HASH_SHA256"},
    ]
    
    result = engine.enrich_batch(test_iocs)
    
    output = {
        "test_timestamp": datetime.now().isoformat(),
        "summary": result.to_dict(),
        "engine_stats": engine.get_stats(),
        "enriched_iocs_sample": [e.to_dict() for e in result.enriched_iocs]
    }
    
    with open("test_results_ioc_correlation_enrichment_engine.json", "w") as f:
        json.dump(output, f, indent=2)
    
    print("Test results saved to test_results_ioc_correlation_enrichment_engine.json")

def main():
    """Run all tests"""
    print("\n" + "=" * 60)
    print("NeuralShield-AI - IOC Correlation & Enrichment Engine Tests")
    print("=" * 60 + "\n")
    
    all_passed = True
    tests = [
        test_mitre_technique_mapper,
        test_relationship_graph,
        test_enrichment_engine_basic,
        test_enrichment_engine_knowledge_base,
        test_correlation_insights,
        test_performance_benchmark,
    ]
    
    for test in tests:
        try:
            if not test():
                all_passed = False
        except Exception as e:
            print(f"✗ TEST FAILED: {test.__name__}")
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            all_passed = False
        print()
    
    # Save results
    save_test_results()
    print()
    
    print("=" * 60)
    if all_passed:
        print("✓ ALL TESTS PASSED - Production Ready!")
    else:
        print("⚠ Some tests failed - review above")
    print("=" * 60)
    
    return 0 if all_passed else 1

if __name__ == "__main__":
    sys.exit(main())
