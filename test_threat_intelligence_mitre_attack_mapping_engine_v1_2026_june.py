"""
Test suite for MITRE ATT&CK Mapping Engine v1
Production-grade tests with real threat intelligence scenarios
"""
import sys
import os
import json
import tempfile

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_mitre_attack_mapping_engine_v1_2026_june import (
    MITREAttackMappingEngine,
    MITRETactic,
    MITREAttackKnowledgeBase,
)


def test_knowledge_base_initialization():
    """Test knowledge base loads correctly"""
    kb = MITREAttackKnowledgeBase()
    techniques = kb.get_all_techniques()
    
    assert len(techniques) > 0, "Knowledge base should have techniques"
    print(f"✓ Knowledge base loaded with {len(techniques)} techniques")
    
    # Verify all tactics are represented
    tactics_found = set(t.tactic for t in techniques)
    assert len(tactics_found) == len(MITRETactic), "All tactics should be covered"
    print(f"✓ All {len(MITRETactic)} MITRE tactics covered")
    
    return True


def test_engine_initialization():
    """Test engine initialization"""
    engine = MITREAttackMappingEngine()
    
    stats = engine.get_stats()
    assert stats['kb_technique_count'] > 0
    assert stats['confidence_threshold'] == 0.15
    print("✓ Engine initialized successfully")
    
    return True


def test_ransomware_mapping():
    """Test ransomware threat mapping"""
    engine = MITREAttackMappingEngine()
    
    result = engine.map_threat(
        "THREAT-001",
        "Ransomware Campaign",
        "Attackers used phishing emails with malicious attachments. Encrypted user files with AES encryption and demanded bitcoin ransom. Deleted shadow copies to prevent recovery."
    )
    
    assert result.threat_id == "THREAT-001"
    assert result.technique_count > 0
    
    # Should match ransomware/impact techniques
    impact_matches = [t for t, c in result.matched_techniques if t.tactic == MITRETactic.IMPACT]
    assert len(impact_matches) > 0, "Should match Impact tactics"
    
    phishing_matches = [t for t, c in result.matched_techniques if t.technique_id == "T1566"]
    assert len(phishing_matches) > 0, "Should match Phishing technique"
    
    print(f"✓ Ransomware mapped to {result.technique_count} techniques")
    print(f"  Overall confidence: {result.overall_confidence}")
    
    return True


def test_credential_dumping_mapping():
    """Test credential access threat mapping"""
    engine = MITREAttackMappingEngine()
    
    result = engine.map_threat(
        "THREAT-002",
        "Credential Dumping Attack",
        "Adversary used mimikatz to dump LSASS memory and extract password hashes from SAM database. Performed pass-the-hash for lateral movement via RDP."
    )
    
    assert result.technique_count > 0
    
    credential_matches = [t for t, c in result.matched_techniques if t.tactic == MITRETactic.CREDENTIAL_ACCESS]
    assert len(credential_matches) > 0, "Should match Credential Access tactics"
    
    t1003_matches = [t for t, c in result.matched_techniques if t.technique_id == "T1003"]
    assert len(t1003_matches) > 0, "Should match OS Credential Dumping (T1003)"
    
    print(f"✓ Credential dumping mapped to {result.technique_count} techniques")
    
    return True


def test_batch_mapping():
    """Test batch threat mapping"""
    engine = MITREAttackMappingEngine()
    
    threats = [
        {
            'id': 'THREAT-B001',
            'title': 'Phishing Campaign',
            'description': 'Spearphishing emails targeting executives with malicious links'
        },
        {
            'id': 'THREAT-B002',
            'title': 'Data Exfiltration',
            'description': 'Data exfiltrated to cloud storage service over HTTPS channel'
        },
        {
            'id': 'THREAT-B003',
            'title': 'Lateral Movement',
            'description': 'Attackers used SMB and WMI to move laterally across network'
        }
    ]
    
    results = engine.batch_map(threats)
    
    assert len(results) == 3
    assert all(r.technique_count > 0 for r in results)
    
    print(f"✓ Batch mapping completed for {len(results)} threats")
    
    return True


def test_caching_functionality():
    """Test LRU caching functionality"""
    engine = MITREAttackMappingEngine(cache_size=100)
    
    # First call - cache miss
    result1 = engine.map_threat("CACHE-001", "Test Threat", "ransomware encryption")
    
    # Second call - should be cache hit
    result2 = engine.map_threat("CACHE-001", "Test Threat", "ransomware encryption")
    
    stats = engine.get_stats()
    assert stats['cache_hits'] >= 1
    assert stats['cache_hit_rate'] > 0
    
    print(f"✓ Caching working: hit rate = {stats['cache_hit_rate']}")
    
    return True


def test_heatmap_generation():
    """Test heatmap data generation"""
    engine = MITREAttackMappingEngine()
    
    threats = [
        {'id': 'H1', 'title': 'Ransomware', 'description': 'encrypt files delete backup'},
        {'id': 'H2', 'title': 'Phishing', 'description': 'email attachment malicious link'},
        {'id': 'H3', 'title': 'Lateral Movement', 'description': 'rdp smb psexec'},
    ]
    
    results = engine.batch_map(threats)
    heatmap = engine.generate_heatmap_data(results)
    
    assert heatmap['total_threats_analyzed'] == 3
    assert 'tactic_average_scores' in heatmap
    assert 'technique_frequency' in heatmap
    
    print(f"✓ Heatmap generated: {heatmap['total_technique_matches']} total matches")
    
    return True


def test_json_export():
    """Test JSON export functionality"""
    engine = MITREAttackMappingEngine()
    
    result = engine.map_threat(
        "EXPORT-001",
        "Test Export",
        "powershell execution with obfuscated commands"
    )
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    success = engine.export_to_json([result], temp_path)
    assert success, "Export should succeed"
    
    # Verify file contents
    with open(temp_path, 'r') as f:
        data = json.load(f)
    
    assert len(data) == 1
    assert data[0]['threat_id'] == "EXPORT-001"
    
    os.unlink(temp_path)
    print("✓ JSON export working correctly")
    
    return True


def test_confidence_scoring():
    """Test confidence scoring calibration"""
    engine = MITREAttackMappingEngine(confidence_threshold=0.0)
    
    # High confidence match
    result_high = engine.map_threat(
        "CONF-001",
        "Mimikatz Attack",
        "mimikatz dump lsass credentials password hash sam ntds"
    )
    
    # Low confidence (generic text)
    result_low = engine.map_threat(
        "CONF-002",
        "Generic Event",
        "something happened on the network computer system"
    )
    
    assert result_high.overall_confidence > result_low.overall_confidence
    print(f"✓ Confidence scoring calibrated")
    print(f"  High confidence: {result_high.overall_confidence}")
    print(f"  Low confidence: {result_low.overall_confidence}")
    
    return True


def test_tactic_distribution():
    """Test tactic distribution calculation"""
    engine = MITREAttackMappingEngine()
    
    result = engine.map_threat(
        "TACTIC-001",
        "Multi-stage Attack",
        "phishing email led to powershell execution. Adversary dumped credentials and moved laterally via RDP before exfiltrating data."
    )
    
    assert len(result.tactic_distribution) > 0
    assert all(isinstance(v, float) for v in result.tactic_distribution.values())
    
    tactics_with_score = [t for t, s in result.tactic_distribution.items() if s > 0]
    assert len(tactics_with_score) >= 3, "Should match multiple tactics"
    
    print(f"✓ Tactic distribution covers {len(tactics_with_score)} tactics")
    
    return True


def test_engine_statistics():
    """Test engine statistics tracking"""
    engine = MITREAttackMappingEngine()
    
    # Perform several mappings
    for i in range(5):
        engine.map_threat(f"STAT-{i}", f"Test {i}", "ransomware encrypt files")
    
    stats = engine.get_stats()
    
    assert stats['total_mappings'] == 5
    assert stats['avg_response_time_ms'] > 0
    assert 'cache_hit_rate' in stats
    assert 'avg_techniques_per_mapping' in stats
    
    print(f"✓ Statistics tracked correctly")
    print(f"  Total mappings: {stats['total_mappings']}")
    print(f"  Avg response time: {stats['avg_response_time_ms']:.2f}ms")
    
    return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("MITRE ATT&CK Mapping Engine v1 - Test Suite")
    print("=" * 60)
    
    tests = [
        test_knowledge_base_initialization,
        test_engine_initialization,
        test_ransomware_mapping,
        test_credential_dumping_mapping,
        test_batch_mapping,
        test_caching_functionality,
        test_heatmap_generation,
        test_json_export,
        test_confidence_scoring,
        test_tactic_distribution,
        test_engine_statistics,
    ]
    
    passed = 0
    failed = 0
    test_results = []
    
    for test in tests:
        try:
            test()
            passed += 1
            test_results.append({"test": test.__name__, "status": "PASSED"})
        except AssertionError as e:
            failed += 1
            print(f"✗ {test.__name__} FAILED: {e}")
            test_results.append({"test": test.__name__, "status": "FAILED", "error": str(e)})
        except Exception as e:
            failed += 1
            print(f"✗ {test.__name__} ERROR: {e}")
            test_results.append({"test": test.__name__, "status": "ERROR", "error": str(e)})
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save results
    result_data = {
        "test_date": "2026-06-21",
        "engine_version": "v1",
        "passed": passed,
        "failed": failed,
        "total": passed + failed,
        "test_results": test_results
    }
    
    with open("test_results_mitre_attack_mapping_engine_v1_2026_june.json", "w") as f:
        json.dump(result_data, f, indent=2)
    
    print(f"Results saved to test_results_mitre_attack_mapping_engine_v1_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
