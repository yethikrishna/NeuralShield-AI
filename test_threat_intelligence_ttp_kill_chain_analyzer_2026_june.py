#!/usr/bin/env python3
"""
Test suite for TTP Kill Chain Analyzer
Production-grade testing with real attack scenarios
"""

import json
import sys
from datetime import datetime, timedelta

# Add the module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_ttp_kill_chain_analyzer_2026_june import (
    TTPKillChainAnalyzer,
    KillChainPhase,
    TTPAttackStep,
    KillChainAnalysis
)


def test_basic_initialization():
    """Test basic analyzer initialization"""
    print("Test 1: Basic Initialization")
    
    analyzer = TTPKillChainAnalyzer(time_window_hours=48)
    assert analyzer is not None
    assert len(analyzer.STANDARD_PROGRESSION) == 14
    assert len(analyzer.TRANSITION_MATRIX) > 0
    
    print("  ✓ Analyzer initialized successfully")
    print(f"  ✓ Standard progression has {len(analyzer.STANDARD_PROGRESSION)} phases")
    print(f"  ✓ Transition matrix has {len(analyzer.TRANSITION_MATRIX)} phase transitions")
    return True


def test_add_ttp_observation():
    """Test adding TTP observations"""
    print("\nTest 2: Add TTP Observations")
    
    analyzer = TTPKillChainAnalyzer()
    
    # Add reconnaissance observation
    obs_id = analyzer.add_ttp_observation(
        ttp_id="T1595",
        ttp_name="Active Scanning - Port Scan",
        phase="reconnaissance",
        source_ip="192.168.1.100",
        target_asset="web-server-01",
        confidence=0.92
    )
    
    assert obs_id is not None
    assert len(obs_id) == 16
    assert len(analyzer.ttp_database) == 1
    
    print("  ✓ TTP observation added successfully")
    print(f"  ✓ Observation ID: {obs_id}")
    print(f"  ✓ Database has {len(analyzer.ttp_database)} records")
    return True


def test_phase_detection_from_name():
    """Test automatic phase detection from TTP names"""
    print("\nTest 3: Phase Detection from TTP Names")
    
    analyzer = TTPKillChainAnalyzer()
    
    test_cases = [
        ("Port Scan detected from external IP", KillChainPhase.RECONNAISSANCE),
        ("Phishing email with malicious attachment", KillChainPhase.DELIVERY),
        ("CVE-2024-1234 exploit attempt", KillChainPhase.EXPLOITATION),
        ("Reverse shell callback to C2 server", KillChainPhase.COMMAND_AND_CONTROL),
        ("Pass-the-Hash attack detected", KillChainPhase.LATERAL_MOVEMENT),
        ("Data exfiltration via DNS tunneling", KillChainPhase.EXFILTRATION),
        ("Ransomware file encryption detected", KillChainPhase.ACTIONS_ON_OBJECTIVES),
    ]
    
    for ttp_name, expected_phase in test_cases:
        detected = analyzer._detect_phase_from_name(ttp_name)
        assert detected == expected_phase, f"Expected {expected_phase}, got {detected} for '{ttp_name}'"
        print(f"  ✓ '{ttp_name[:30]}...' -> {detected.value}")
    
    print("  ✓ All phase detections correct")
    return True


def test_kill_chain_analysis():
    """Test full kill chain analysis with simulated attack"""
    print("\nTest 4: Full Kill Chain Analysis")
    
    analyzer = TTPKillChainAnalyzer()
    source_ip = "10.0.0.50"
    
    # Simulate a multi-phase attack progression
    attack_steps = [
        ("T1595", "Port Scan - Nmap", "reconnaissance", "dmz-firewall"),
        ("T1566", "Phishing Email", "delivery", "exchange-server"),
        ("T1203", "Exploitation CVE-2024-1234", "exploitation", "workstation-07"),
        ("T1547", "Registry Persistence", "installation", "workstation-07"),
        ("T1071", "C2 Beaconing", "command_and_control", "workstation-07"),
        ("T1087", "Account Discovery", "discovery", "workstation-07"),
        ("T1555", "Credential Dumping", "credential_access", "workstation-07"),
        ("T1021", "SMB Lateral Movement", "lateral_movement", "database-server"),
    ]
    
    base_time = datetime.now() - timedelta(hours=6)
    for i, (ttp_id, ttp_name, phase, asset) in enumerate(attack_steps):
        analyzer.add_ttp_observation(
            ttp_id=ttp_id,
            ttp_name=ttp_name,
            phase=phase,
            timestamp=base_time + timedelta(minutes=i*30),
            source_ip=source_ip,
            target_asset=asset,
            confidence=0.85 + (i * 0.01)
        )
    
    analysis = analyzer.analyze_kill_chain(source_ip)
    
    assert analysis is not None
    assert analysis.chain_id == source_ip
    assert len(analysis.detected_phases) == 8
    assert analysis.completion_percentage > 50
    assert analysis.attack_progression_score > 50
    assert analysis.risk_level in ["HIGH", "CRITICAL"]
    assert len(analysis.recommended_actions) > 0
    assert len(analysis.predicted_next_phases) > 0
    
    print(f"  ✓ Analysis completed for chain: {analysis.chain_id}")
    print(f"  ✓ Detected phases: {len(analysis.detected_phases)}")
    print(f"  ✓ Completion: {analysis.completion_percentage}%")
    print(f"  ✓ Progression Score: {analysis.attack_progression_score}%")
    print(f"  ✓ Risk Level: {analysis.risk_level}")
    print(f"  ✓ Predicted next phases: {[p.value for p in analysis.predicted_next_phases]}")
    print(f"  ✓ Recommendations: {len(analysis.recommended_actions)} actions")
    
    return True


def test_prediction_engine():
    """Test next phase prediction capabilities"""
    print("\nTest 5: Attack Progression Prediction")
    
    analyzer = TTPKillChainAnalyzer()
    
    # Test prediction from C2 phase
    predictions = analyzer._predict_next_phases([KillChainPhase.COMMAND_AND_CONTROL])
    assert len(predictions) > 0
    assert KillChainPhase.DISCOVERY in predictions or KillChainPhase.PRIVILEGE_ESCALATION in predictions
    
    # Test prediction from lateral movement
    predictions2 = analyzer._predict_next_phases([KillChainPhase.LATERAL_MOVEMENT])
    assert len(predictions2) > 0
    assert KillChainPhase.COLLECTION in predictions2 or KillChainPhase.EXFILTRATION in predictions2
    
    print(f"  ✓ C2 -> Predicted: {[p.value for p in predictions]}")
    print(f"  ✓ Lateral Movement -> Predicted: {[p.value for p in predictions2]}")
    print("  ✓ Prediction engine working correctly")
    return True


def test_risk_level_calculation():
    """Test risk level calculation at different progression stages"""
    print("\nTest 6: Risk Level Calculation")
    
    analyzer = TTPKillChainAnalyzer()
    source_ip = "192.168.1.1"
    
    # Early stage attack (LOW risk)
    analyzer.add_ttp_observation("T1", "Early Scan", "reconnaissance", source_ip=source_ip)
    analysis = analyzer.analyze_kill_chain(source_ip)
    assert analysis.risk_level == "LOW"
    print(f"  ✓ Early attack (1 phase): {analysis.risk_level} risk")
    
    # Mid-stage attack (MEDIUM)
    analyzer2 = TTPKillChainAnalyzer()
    for phase in ["reconnaissance", "delivery", "exploitation"]:
        analyzer2.add_ttp_observation("T1", "Test", phase, source_ip="attacker-2")
    analysis2 = analyzer2.analyze_kill_chain("attacker-2")
    assert analysis2.risk_level in ["LOW", "MEDIUM"]
    print(f"  ✓ Mid attack (3 phases): {analysis2.risk_level} risk")
    
    # Advanced attack (HIGH/CRITICAL)
    analyzer3 = TTPKillChainAnalyzer()
    advanced_phases = [
        "reconnaissance", "delivery", "exploitation", "installation",
        "command_and_control", "discovery", "credential_access",
        "lateral_movement", "collection"
    ]
    for phase in advanced_phases:
        analyzer3.add_ttp_observation("T1", "Test", phase, source_ip="attacker-3")
    analysis3 = analyzer3.analyze_kill_chain("attacker-3")
    assert analysis3.risk_level in ["HIGH", "CRITICAL"]
    print(f"  ✓ Advanced attack (9 phases): {analysis3.risk_level} risk")
    
    return True


def test_json_export():
    """Test JSON export functionality"""
    print("\nTest 7: JSON Export")
    
    analyzer = TTPKillChainAnalyzer()
    analyzer.add_ttp_observation(
        ttp_id="T1001",
        ttp_name="Test Observation",
        phase="reconnaissance",
        source_ip="10.0.0.1",
        target_asset="test-server",
        confidence=0.95
    )
    
    json_output = analyzer.export_analysis_json("10.0.0.1")
    parsed = json.loads(json_output)
    
    assert "chain_id" in parsed
    assert "detected_phases" in parsed
    assert "risk_level" in parsed
    assert "recommended_actions" in parsed
    assert "ttp_sequence" in parsed
    
    print("  ✓ JSON export successful")
    print(f"  ✓ Export contains all required fields")
    print(f"  ✓ JSON is valid and parseable")
    return True


def test_multiple_attack_chains():
    """Test handling multiple concurrent attack chains"""
    print("\nTest 8: Multiple Attack Chains")
    
    analyzer = TTPKillChainAnalyzer()
    
    # Chain 1: External attacker
    analyzer.add_ttp_observation("T1", "Port Scan", "reconnaissance", source_ip="203.0.113.50")
    
    # Chain 2: Internal threat
    analyzer.add_ttp_observation("T2", "Data Access", "collection", source_ip="192.168.1.25")
    
    # Chain 3: Another attacker
    analyzer.add_ttp_observation("T3", "Phishing", "delivery", source_ip="198.51.100.10")
    
    summaries = analyzer.get_all_chain_summaries()
    
    assert len(summaries) >= 3
    print(f"  ✓ Tracking {len(summaries)} concurrent attack chains")
    for summary in summaries[:3]:
        print(f"    - Chain {summary['chain_id'][:15]}...: {summary['risk_level']} risk, {summary['progression_score']:.1f}% progression")
    
    print("  ✓ Multiple chain tracking working")
    return True


def test_empty_chain_handling():
    """Test handling of chains with no data"""
    print("\nTest 9: Empty Chain Handling")
    
    analyzer = TTPKillChainAnalyzer()
    analysis = analyzer.analyze_kill_chain("nonexistent_chain")
    
    assert analysis.completion_percentage == 0.0
    assert analysis.attack_progression_score == 0.0
    assert analysis.risk_level == "LOW"
    assert "No active attack" in analysis.recommended_actions[0]
    
    print("  ✓ Empty chain returns valid zero-risk analysis")
    print("  ✓ Graceful degradation working")
    return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("TTP KILL CHAIN ANALYZER - PRODUCTION TEST SUITE")
    print("=" * 60)
    print(f"Test Time: {datetime.now().isoformat()}")
    print()
    
    tests = [
        test_basic_initialization,
        test_add_ttp_observation,
        test_phase_detection_from_name,
        test_kill_chain_analysis,
        test_prediction_engine,
        test_risk_level_calculation,
        test_json_export,
        test_multiple_attack_chains,
        test_empty_chain_handling,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
        except Exception as e:
            print(f"  ✗ FAILED: {str(e)}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Write results
    result = {
        "test_timestamp": datetime.now().isoformat(),
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": (passed / len(tests)) * 100,
        "module": "threat_intelligence_ttp_kill_chain_analyzer_2026_june"
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_ttp_kill_chain_analyzer.json", "w") as f:
        json.dump(result, f, indent=2)
    
    print(f"Results written to test_results_ttp_kill_chain_analyzer.json")
    print(f"Success Rate: {result['success_rate']:.1f}%")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
