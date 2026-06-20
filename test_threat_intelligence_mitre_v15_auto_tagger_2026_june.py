#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Auto-Tagging Engine with MITRE ATT&CK v15 Mapping
Production-grade validation tests
"""

import sys
import json
from datetime import datetime

# Add neural_shield to path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_mitre_v15_auto_tagger_2026_june import (
    ThreatIntelligenceAutoTagger,
    MITREv15TechniqueDatabase,
    IOCClassifier,
    IOCType,
    ThreatSeverity,
    MITREv15Tactics,
)


def test_mitre_database_initialization():
    """Test MITRE v15 database loads correctly"""
    print("Test 1: MITRE v15 Database Initialization")
    db = MITREv15TechniqueDatabase()
    
    assert len(db.techniques) > 0, "Database should have techniques"
    print(f"  ✓ Loaded {len(db.techniques)} MITRE techniques")
    
    # Verify specific techniques exist
    t1566 = db.get_technique("T1566")
    assert t1566 is not None, "Phishing technique should exist"
    assert t1566.name == "Phishing"
    assert t1566.tactic == MITREv15Tactics.INITIAL_ACCESS
    print(f"  ✓ Phishing (T1566) loaded with risk score: {t1566.risk_score}")
    
    # Test high-risk techniques
    high_risk = db.get_highest_risk_techniques(8.0)
    assert len(high_risk) > 0, "Should have high-risk techniques"
    print(f"  ✓ Found {len(high_risk)} high-risk techniques (>= 8.0)")
    
    print("  ✓ MITRE Database tests PASSED\n")


def test_ioc_classification():
    """Test IOC classification functionality"""
    print("Test 2: IOC Classification")
    
    # Test SHA256
    ioc_type, confidence = IOCClassifier.classify_ioc("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
    assert ioc_type == IOCType.SHA256
    assert confidence > 0.95
    print(f"  ✓ SHA256 hash classified correctly (confidence: {confidence})")
    
    # Test IP Address
    ioc_type, confidence = IOCClassifier.classify_ioc("192.168.1.1")
    assert ioc_type == IOCType.IP_ADDRESS
    print(f"  ✓ IP Address classified correctly (confidence: {confidence})")
    
    # Test Domain
    ioc_type, confidence = IOCClassifier.classify_ioc("malicious-domain.com")
    assert ioc_type == IOCType.DOMAIN
    print(f"  ✓ Domain classified correctly (confidence: {confidence})")
    
    # Test Email
    ioc_type, confidence = IOCClassifier.classify_ioc("phish@malicious.com")
    assert ioc_type == IOCType.EMAIL
    print(f"  ✓ Email classified correctly (confidence: {confidence})")
    
    # Test MD5
    ioc_type, confidence = IOCClassifier.classify_ioc("d41d8cd98f00b204e9800998ecf8427e")
    assert ioc_type == IOCType.MD5
    print(f"  ✓ MD5 hash classified correctly (confidence: {confidence})")
    
    # Test URL
    ioc_type, confidence = IOCClassifier.classify_ioc("https://malicious.com/payload.exe")
    assert ioc_type == IOCType.URL
    print(f"  ✓ URL classified correctly (confidence: {confidence})")
    
    print("  ✓ IOC Classification tests PASSED\n")


def test_ioc_extraction_from_text():
    """Test IOC extraction from raw text"""
    print("Test 3: IOC Extraction from Text")
    
    sample_text = """
    Malware analysis report:
    - SHA256: 5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
    - C2 IP: 103.224.182.251
    - Domain: evil-c2-server.net
    - Contact: attacker@darkweb.com
    """
    
    results = IOCClassifier.extract_iocs_from_text(sample_text)
    assert len(results) >= 4, f"Should extract at least 4 IOCs, got {len(results)}"
    print(f"  ✓ Extracted {len(results)} IOCs from text")
    
    for value, ioc_type, confidence in results:
        print(f"    - {value[:32]}... -> {ioc_type.name} (conf: {confidence})")
    
    print("  ✓ IOC Extraction tests PASSED\n")


def test_auto_tagging_basic():
    """Test basic auto-tagging functionality"""
    print("Test 4: Basic Auto-Tagging")
    
    tagger = ThreatIntelligenceAutoTagger()
    
    # Tag a malicious hash
    tagged = tagger.tag_ioc(
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        context="Ransomware sample detected in endpoint, encryption behavior observed"
    )
    
    assert tagged.ioc_type == IOCType.SHA256
    assert tagged.severity in [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]
    assert tagged.confidence > 0.9
    assert len(tagged.mitre_techniques) > 0
    assert len(tagged.tags) > 0
    
    print(f"  ✓ IOC tagged: {tagged.value[:16]}...")
    print(f"    Type: {tagged.ioc_type.name}")
    print(f"    Severity: {tagged.severity.name}")
    print(f"    Confidence: {tagged.confidence:.2f}")
    print(f"    MITRE Techniques: {len(tagged.mitre_techniques)}")
    print(f"    Tags applied: {len(tagged.tags)}")
    
    for tag in sorted(tagged.tags):
        print(f"      - {tag}")
    
    print("  ✓ Basic Auto-Tagging tests PASSED\n")


def test_mitre_mapping():
    """Test MITRE ATT&CK v15 mapping functionality"""
    print("Test 5: MITRE ATT&CK v15 Mapping")
    
    tagger = ThreatIntelligenceAutoTagger()
    
    # Test ransomware context mapping
    tagged = tagger.tag_ioc(
        "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2",
        context="RANSOMWARE: File encrypts user data, deletes backups, leaves ransom note"
    )
    
    ransomware_techniques = [t for t in tagged.mitre_techniques if t.technique_id in ["T1486", "T1490"]]
    assert len(ransomware_techniques) > 0, "Should map to ransomware techniques"
    
    print(f"  ✓ Ransomware context mapped to {len(ransomware_techniques)} impact techniques")
    
    for tech in tagged.mitre_techniques:
        print(f"    - {tech.technique_id}: {tech.name} (Risk: {tech.risk_score})")
        print(f"      Tactic: {tech.tactic.name}")
    
    # Test network C2 mapping
    tagged2 = tagger.tag_ioc("198.51.100.42", context="C2 server, beaconing observed every 30s")
    
    c2_techniques = [t for t in tagged2.mitre_techniques if t.tactic == MITREv15Tactics.COMMAND_AND_CONTROL]
    assert len(c2_techniques) > 0, "Should map to C2 tactics"
    print(f"  ✓ Network IOC mapped to {len(c2_techniques)} C2 techniques")
    
    print("  ✓ MITRE Mapping tests PASSED\n")


def test_batch_processing():
    """Test batch IOC processing"""
    print("Test 6: Batch Processing")
    
    tagger = ThreatIntelligenceAutoTagger()
    
    iocs = [
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        "192.168.100.50",
        "malicious-c2-domain.ru",
        "https://phishing-site.com/login",
        "d41d8cd98f00b204e9800998ecf8427e",
    ]
    
    results = tagger.batch_tag_iocs(iocs, context="Threat feed import")
    
    assert len(results) == len(iocs)
    print(f"  ✓ Batch processed {len(results)} IOCs")
    
    summary = tagger.get_threat_summary()
    print(f"  ✓ Summary generated:")
    print(f"    Total IOCs: {summary['total_iocs']}")
    print(f"    Average confidence: {summary['average_confidence']:.3f}")
    print(f"    Severity distribution: {summary['severity_distribution']}")
    print(f"    Type distribution: {summary['type_distribution']}")
    print(f"    MITRE Tactic distribution: {summary['mitre_tactic_distribution']}")
    
    print("  ✓ Batch Processing tests PASSED\n")


def test_stix_export():
    """Test STIX 2.1 export functionality"""
    print("Test 7: STIX 2.1 Export")
    
    tagger = ThreatIntelligenceAutoTagger()
    tagger.tag_ioc("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
    tagger.tag_ioc("10.0.0.1")
    
    stix_bundle = tagger.export_to_stix()
    
    assert stix_bundle["type"] == "bundle"
    assert len(stix_bundle["objects"]) == 2
    
    for obj in stix_bundle["objects"]:
        assert obj["type"] == "indicator"
        assert "spec_version" in obj
        assert "pattern" in obj
        assert "labels" in obj
    
    print(f"  ✓ Generated STIX 2.1 bundle with {len(stix_bundle['objects'])} indicators")
    print(f"  ✓ All objects have required STIX fields")
    
    print("  ✓ STIX Export tests PASSED\n")


def test_severity_calculation():
    """Test severity calculation logic"""
    print("Test 8: Severity Calculation")
    
    tagger = ThreatIntelligenceAutoTagger()
    
    # Hash should be HIGH severity
    tagged_hash = tagger.tag_ioc("5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8")
    assert tagged_hash.severity == ThreatSeverity.HIGH, f"Hash should be HIGH, got {tagged_hash.severity}"
    print(f"  ✓ Hash severity: {tagged_hash.severity.name}")
    
    # Email should be LOW severity
    tagged_email = tagger.tag_ioc("test@example.com")
    assert tagged_email.severity == ThreatSeverity.LOW, f"Email should be LOW, got {tagged_email.severity}"
    print(f"  ✓ Email severity: {tagged_email.severity.name}")
    
    print("  ✓ Severity Calculation tests PASSED\n")


def run_all_tests():
    """Run all test suites"""
    print("=" * 70)
    print("NeuralShield AI - Threat Intelligence Auto-Tagging Engine Tests")
    print("MITRE ATT&CK v15 Mapping - Production Validation")
    print("=" * 70 + "\n")
    
    start_time = datetime.now()
    
    try:
        test_mitre_database_initialization()
        test_ioc_classification()
        test_ioc_extraction_from_text()
        test_auto_tagging_basic()
        test_mitre_mapping()
        test_batch_processing()
        test_stix_export()
        test_severity_calculation()
        
        elapsed = (datetime.now() - start_time).total_seconds()
        
        print("=" * 70)
        print(f"ALL TESTS PASSED ✓ in {elapsed:.3f} seconds")
        print("=" * 70)
        
        # Save test results
        results = {
            "test_suite": "threat_intelligence_mitre_v15_auto_tagger",
            "status": "PASSED",
            "tests_executed": 8,
            "tests_passed": 8,
            "tests_failed": 0,
            "execution_time_seconds": elapsed,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_threat_intelligence_mitre_v15_auto_tagger.json", "w") as f:
            json.dump(results, f, indent=2)
        
        print(f"\nTest results saved to test_results_threat_intelligence_mitre_v15_auto_tagger.json")
        
        return True
        
    except AssertionError as e:
        print(f"\n❌ TEST FAILED: {e}")
        return False
    except Exception as e:
        print(f"\n❌ TEST ERROR: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return False


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
