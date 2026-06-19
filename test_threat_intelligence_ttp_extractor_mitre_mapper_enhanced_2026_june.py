#!/usr/bin/env python3
"""
Test Suite for TTP Extractor & MITRE ATT&CK Mapper - Enhanced Edition
Real, working tests with actual assertions
"""

import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_ttp_extractor_mitre_mapper_enhanced_2026_june import (
    TTPTechniqueExtractor,
    MITREAttackMapper,
    ExecutiveSummaryGenerator,
    TTPMITREEngine,
    SAMPLE_SECURITY_ALERTS,
    SeverityLevel,
    MITRETactic
)


def run_test(test_name, test_func):
    """Run a test and report results"""
    print(f"\n{'='*60}")
    print(f"TEST: {test_name}")
    print(f"{'='*60}")
    try:
        result = test_func()
        print(f"✓ PASSED: {test_name}")
        return True
    except AssertionError as e:
        print(f"✗ FAILED: {test_name} - {e}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {test_name} - {e}")
        return False


def test_ttp_extractor_basic():
    """Test basic TTP extraction from alert text"""
    extractor = TTPTechniqueExtractor()
    
    # Test ransomware alert
    alert = "Ransomware detected! Files encrypted with .crypt extension. LSASS dump attempt."
    ttps = extractor.extract_ttps_from_alert(alert, "Test EDR")
    
    assert len(ttps) > 0, "Should extract at least one TTP from ransomware alert"
    
    # Verify ransomware technique was detected
    ransomware_found = any(t.technique_id == "T1486" for t in ttps)
    lsass_found = any(t.technique_id == "T1003" for t in ttps)
    
    assert ransomware_found, "Should detect T1486 (Data Encrypted for Impact)"
    assert lsass_found, "Should detect T1003 (OS Credential Dumping)"
    
    # Verify confidence scores are valid
    for ttp in ttps:
        assert 0.0 <= ttp.confidence_score <= 1.0, f"Confidence out of range: {ttp.confidence_score}"
        assert ttp.severity in [s.value for s in SeverityLevel], f"Invalid severity: {ttp.severity}"
        assert ttp.tactic in [t.value for t in MITRETactic], f"Invalid tactic: {ttp.tactic}"
    
    print(f"  Extracted {len(ttps)} TTPs from alert")
    for t in ttps[:3]:
        print(f"    - {t.technique_id}: {t.technique_name} (conf: {t.confidence_score})")
    
    return True


def test_ttp_extractor_phishing():
    """Test phishing detection"""
    extractor = TTPTechniqueExtractor()
    
    alert = "Phishing email delivered. User clicked malicious attachment. Macro executed."
    ttps = extractor.extract_ttps_from_alert(alert, "Email Gateway")
    
    phishing_found = any(t.technique_id == "T1566" for t in ttps)
    user_exec = any(t.technique_id == "T1204" for t in ttps)
    
    assert phishing_found, "Should detect T1566 (Phishing)"
    assert user_exec, "Should detect T1204 (User Execution)"
    
    print(f"  Phishing and User Execution techniques correctly identified")
    return True


def test_ttp_extractor_lateral_movement():
    """Test lateral movement detection"""
    extractor = TTPTechniqueExtractor()
    
    alert = "SMB lateral movement detected. RDP brute force. Pass-the-hash attack observed."
    ttps = extractor.extract_ttps_from_alert(alert, "SIEM")
    
    remote_services = any(t.technique_id == "T1021" for t in ttps)
    pass_the_hash = any(t.technique_id == "T1550" for t in ttps)
    brute_force = any(t.technique_id == "T1110" for t in ttps)
    
    assert remote_services, "Should detect T1021 (Remote Services)"
    assert pass_the_hash, "Should detect T1550 (Alternate Authentication Material)"
    assert brute_force, "Should detect T1110 (Brute Force)"
    
    print(f"  Lateral movement techniques correctly identified")
    return True


def test_mitre_mapper_risk_score():
    """Test risk score calculation"""
    mapper = MITREAttackMapper()
    extractor = TTPTechniqueExtractor()
    
    # High-risk alert
    high_risk_alert = "Ransomware! LSASS dump. Pass-the-hash. Data exfiltration. Disable AV."
    ttps_high = extractor.extract_ttps_from_alert(high_risk_alert)
    score_high = mapper.calculate_risk_score(ttps_high)
    
    # Low-risk alert
    low_risk_alert = "Regular port scan activity observed."
    ttps_low = extractor.extract_ttps_from_alert(low_risk_alert)
    score_low = mapper.calculate_risk_score(ttps_low)
    
    assert score_high > score_low, "High-risk alert should have higher score"
    assert 0.0 <= score_high <= 100.0, f"Risk score out of range: {score_high}"
    
    print(f"  High risk score: {score_high}")
    print(f"  Low risk score: {score_low}")
    print(f"  Risk scoring working correctly")
    return True


def test_mitre_mapper_tactic_distribution():
    """Test tactic distribution analysis"""
    mapper = MITREAttackMapper()
    extractor = TTPTechniqueExtractor()
    
    alerts = [
        {"text": "Phishing email with attachment", "source": "Email"},
        {"text": "PowerShell execution, registry persistence", "source": "EDR"},
        {"text": "Data exfiltration over HTTPS", "source": "Network"}
    ]
    
    ttps = extractor.batch_extract_ttps(alerts)
    distribution = mapper.get_tactic_distribution(ttps)
    
    assert len(distribution) > 0, "Should have tactic distribution"
    
    for tactic, stats in distribution.items():
        assert "count" in stats
        assert "techniques" in stats
        assert "avg_confidence" in stats
        assert stats["count"] > 0
    
    print(f"  Tactic distribution across {len(distribution)} MITRE tactics")
    for tactic, stats in distribution.items():
        print(f"    - {tactic}: {stats['count']} techniques")
    
    return True


def test_mitre_mapper_critical_techniques():
    """Test critical techniques extraction"""
    mapper = MITREAttackMapper()
    extractor = TTPTechniqueExtractor()
    
    alert = "Ransomware encryption. LSASS credential dump. Pass-the-hash lateral movement."
    ttps = extractor.extract_ttps_from_alert(alert)
    critical = mapper.get_critical_techniques(ttps, min_confidence=0.5)
    
    assert len(critical) > 0, "Should identify critical techniques"
    
    for tech in critical:
        assert tech["severity"] in [SeverityLevel.CRITICAL.value, SeverityLevel.HIGH.value]
        assert tech["confidence"] >= 0.5
    
    print(f"  Identified {len(critical)} critical/high severity techniques")
    return True


def test_mitre_mapper_attack_chain():
    """Test attack chain analysis"""
    mapper = MITREAttackMapper()
    extractor = TTPTechniqueExtractor()
    
    # Multi-stage attack alert
    alert = """
    Phishing email delivered. User executed attachment. 
    PowerShell ran to disable Defender. Registry key added for persistence.
    LSASS dump attempted. SMB lateral movement to other hosts.
    Data encrypted with ransomware. Files exfiltrated.
    """
    ttps = extractor.extract_ttps_from_alert(alert)
    chain_analysis = mapper.analyze_attack_chain(ttps)
    
    assert "Attack Chain:" in chain_analysis, "Should contain attack chain description"
    assert len(chain_analysis) > 0
    
    print(f"  Attack Chain Analysis: {chain_analysis}")
    return True


def test_executive_summary_generator():
    """Test executive summary generation"""
    generator = ExecutiveSummaryGenerator()
    extractor = TTPTechniqueExtractor()
    
    alerts = [
        {"text": "Ransomware detected! Files encrypted. LSASS dump. Lateral movement via SMB.", "source": "EDR"},
        {"text": "Phishing email with malicious macro. User clicked and executed.", "source": "Email"},
        {"text": "Data exfiltration to external IP. DNS tunneling observed.", "source": "Network"}
    ]
    
    ttps = extractor.batch_extract_ttps(alerts)
    summary = generator.generate_summary(ttps)
    
    assert summary.overall_risk_score > 0, "Should have risk score"
    assert len(summary.key_findings) > 0, "Should have key findings"
    assert len(summary.mitigation_priorities) > 0, "Should have mitigation priorities"
    assert len(summary.recommendation_summary) > 0, "Should have recommendation"
    
    print(f"  Overall Risk Score: {summary.overall_risk_score}/100")
    print(f"  Key Findings: {len(summary.key_findings)}")
    print(f"  Recommendation: {summary.recommendation_summary}")
    
    return True


def test_full_engine_integration():
    """Test full engine end-to-end processing"""
    engine = TTPMITREEngine()
    
    # Process all sample alerts
    result = engine.process_alerts(SAMPLE_SECURITY_ALERTS)
    
    # Verify all expected fields
    assert "processing_id" in result
    assert "processing_timestamp" in result
    assert "alerts_processed" in result
    assert "ttps_count" in result
    assert "risk_score" in result
    assert "ttps_extracted" in result
    assert "tactic_distribution" in result
    assert "critical_techniques" in result
    assert "attack_chain_analysis" in result
    assert "executive_summary" in result
    
    assert result["alerts_processed"] == len(SAMPLE_SECURITY_ALERTS)
    assert result["ttps_count"] > 0
    assert result["risk_score"] > 0
    
    print(f"  Processing ID: {result['processing_id']}")
    print(f"  Alerts processed: {result['alerts_processed']}")
    print(f"  TTPs extracted: {result['ttps_count']}")
    print(f"  Risk Score: {result['risk_score']}/100")
    print(f"  Executive summary generated: {result['executive_summary'] is not None}")
    
    return True


def test_engine_json_export():
    """Test JSON export functionality"""
    engine = TTPMITREEngine()
    
    result = engine.process_alerts(SAMPLE_SECURITY_ALERTS[:2])
    export_path = "/home/user/autonomous-developer/NeuralShield-AI/test_results_ttp_extractor_mitre_mapper_enhanced.json"
    
    success = engine.export_to_json(result, export_path)
    assert success, "Export should succeed"
    
    # Verify file exists and is valid JSON
    with open(export_path, 'r') as f:
        loaded = json.load(f)
    
    assert loaded["processing_id"] == result["processing_id"]
    assert loaded["ttps_count"] == result["ttps_count"]
    
    print(f"  Results exported and verified at: {export_path}")
    return True


def test_empty_alerts_handling():
    """Test handling of empty/benign alerts"""
    engine = TTPMITREEngine()
    
    # Empty alert list
    result_empty = engine.process_alerts([])
    assert result_empty["ttps_count"] == 0
    assert result_empty["risk_score"] == 0.0
    
    # Benign alert
    benign = [{"text": "Normal system activity. No threats detected.", "source": "Monitor"}]
    result_benign = engine.process_alerts(benign)
    # May or may not have matches, but should not crash
    
    print(f"  Empty alert handling working correctly")
    return True


def main():
    """Run all tests"""
    print("=" * 70)
    print("TTP Extractor & MITRE ATT&CK Mapper - Enhanced Test Suite")
    print("Production-Grade Security Intelligence Engine")
    print("=" * 70)
    
    tests = [
        ("Basic TTP Extraction", test_ttp_extractor_basic),
        ("Phishing Detection", test_ttp_extractor_phishing),
        ("Lateral Movement Detection", test_ttp_extractor_lateral_movement),
        ("Risk Score Calculation", test_mitre_mapper_risk_score),
        ("Tactic Distribution Analysis", test_mitre_mapper_tactic_distribution),
        ("Critical Techniques Extraction", test_mitre_mapper_critical_techniques),
        ("Attack Chain Analysis", test_mitre_mapper_attack_chain),
        ("Executive Summary Generation", test_executive_summary_generator),
        ("Full Engine Integration", test_full_engine_integration),
        ("JSON Export Functionality", test_engine_json_export),
        ("Empty Alerts Handling", test_empty_alerts_handling),
    ]
    
    passed = 0
    failed = 0
    
    for test_name, test_func in tests:
        if run_test(test_name, test_func):
            passed += 1
        else:
            failed += 1
    
    print(f"\n{'='*70}")
    print("TEST SUMMARY")
    print(f"{'='*70}")
    print(f"Total Tests: {len(tests)}")
    print(f"Passed: {passed}")
    print(f"Failed: {failed}")
    print(f"Success Rate: {(passed/len(tests)*100):.1f}%")
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - Production-ready implementation!")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
