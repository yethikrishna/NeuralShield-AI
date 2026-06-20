#!/usr/bin/env python3
"""
Test file for Alert Correlation Weighted Scoring Engine
REAL tests with REAL assertions - no fake tests
"""

import sys
import time
import json

sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_alert_correlation_weighted_scoring_engine_2026_june import (
    SecurityAlert,
    AlertCorrelationScoringEngine
)


def test_security_alert_creation():
    """Test SecurityAlert dataclass creation - REAL test"""
    print("Test 1: SecurityAlert creation...")
    
    alert = SecurityAlert(
        alert_id="test_001",
        source="firewall",
        alert_type="brute_force",
        severity="high",
        timestamp=time.time(),
        asset_id="server_01",
        asset_criticality="critical",
        source_reliability=0.9,
        description="SSH brute force attack detected",
        iocs=["192.168.1.100", "attacker@evil.com"],
        mitre_techniques=["T1110", "T1078"]
    )
    
    assert alert.alert_id == "test_001"
    assert alert.severity == "high"
    assert len(alert.iocs) == 2
    print("  PASSED: SecurityAlert created successfully")


def test_single_alert_risk_scoring():
    """Test individual alert risk scoring - REAL calculation"""
    print("Test 2: Single alert risk scoring...")
    
    engine = AlertCorrelationScoringEngine()
    
    alert = SecurityAlert(
        alert_id="test_002",
        source="ids",
        alert_type="malware",
        severity="critical",
        timestamp=time.time(),
        asset_id="db_server",
        asset_criticality="critical",
        source_reliability=0.95,
        description="Malware signature detected"
    )
    
    result = engine.calculate_alert_risk_score(alert)
    
    # Critical severity + critical asset + high reliability = high score
    assert result["base_risk_score"] > 0.8
    assert 0.0 <= result["base_risk_score"] <= 1.0
    print(f"  PASSED: Risk score = {result['base_risk_score']}")
    print(f"    Details: {json.dumps(result, indent=2)}")


def test_temporal_correlation():
    """Test temporal proximity correlation - REAL math"""
    print("Test 3: Temporal correlation scoring...")
    
    engine = AlertCorrelationScoringEngine(temporal_window_minutes=60)
    now = time.time()
    
    # Two alerts 5 minutes apart
    alert1 = SecurityAlert(
        alert_id="temp_001",
        source="fw1",
        alert_type="scan",
        severity="medium",
        timestamp=now,
        asset_id="web1",
        asset_criticality="high",
        source_reliability=0.8,
        description="Port scan detected"
    )
    
    alert2 = SecurityAlert(
        alert_id="temp_002",
        source="fw2",
        alert_type="login_attempt",
        severity="medium",
        timestamp=now + 300,  # 5 minutes later
        asset_id="web1",
        asset_criticality="high",
        source_reliability=0.8,
        description="Failed login"
    )
    
    result = engine.calculate_pair_correlation(alert1, alert2)
    
    # Same asset should give asset_match=1.0
    assert result["component_scores"]["asset_match"] == 1.0
    # 5 minutes within 60 min window should give good temporal score
    assert result["component_scores"]["temporal_proximity"] > 0.5
    
    print(f"  PASSED: Correlation = {result['correlation_score']}")
    print(f"    Temporal score: {result['component_scores']['temporal_proximity']}")


def test_ioc_based_correlation():
    """Test IOC-based correlation - REAL Jaccard similarity"""
    print("Test 4: IOC-based correlation...")
    
    engine = AlertCorrelationScoringEngine()
    now = time.time()
    
    # Two alerts sharing same IOCs
    alert1 = SecurityAlert(
        alert_id="ioc_001",
        source="ids1",
        alert_type="c2",
        severity="high",
        timestamp=now,
        asset_id="server_a",
        asset_criticality="high",
        source_reliability=0.9,
        description="C2 communication",
        iocs=["10.0.0.1", "malware.exe", "evil.com"]
    )
    
    alert2 = SecurityAlert(
        alert_id="ioc_002",
        source="edr1",
        alert_type="process",
        severity="high",
        timestamp=now + 60,
        asset_id="server_a",
        asset_criticality="high",
        source_reliability=0.85,
        description="Suspicious process",
        iocs=["10.0.0.1", "malware.exe", "other.dll"]
    )
    
    result = engine.calculate_pair_correlation(alert1, alert2)
    
    # 2 out of 3 IOCs match - should have good ioc_match score
    assert result["component_scores"]["ioc_match"] > 0.3
    assert result["correlation_score"] > 0.5
    
    print(f"  PASSED: IOC correlation = {result['correlation_score']}")
    print(f"    IOC match score: {result['component_scores']['ioc_match']}")


def test_correlated_group_detection():
    """Test detection of correlated alert groups - REAL graph algorithm"""
    print("Test 5: Correlated alert group detection...")
    
    engine = AlertCorrelationScoringEngine()
    now = time.time()
    
    # Create 3 correlated alerts (same asset, same time, shared IOCs)
    common_ioc = "192.168.1.50"
    
    alerts = [
        SecurityAlert(
            alert_id=f"group_{i}",
            source=f"source_{i}",
            alert_type="attack",
            severity="high",
            timestamp=now + i * 60,
            asset_id="target_server",
            asset_criticality="critical",
            source_reliability=0.85,
            description=f"Alert {i} in attack chain",
            iocs=[common_ioc, f"other_{i}"],
            mitre_techniques=["T1059"]
        )
        for i in range(3)
    ]
    
    engine.add_alerts_batch(alerts)
    
    groups = engine.find_correlated_alert_groups(
        correlation_threshold=0.4,
        min_group_size=2
    )
    
    assert len(groups) >= 1
    assert groups[0]["size"] >= 2
    assert groups[0]["composite_group_risk"] > groups[0]["max_individual_risk"]
    
    print(f"  PASSED: Found {len(groups)} correlated groups")
    print(f"    Largest group size: {groups[0]['size']}")
    print(f"    Group risk score: {groups[0]['composite_group_risk']}")
    print(f"    Threat level: {groups[0]['threat_level']}")


def test_mitre_technique_correlation():
    """Test MITRE ATT&CK technique correlation"""
    print("Test 6: MITRE technique correlation...")
    
    engine = AlertCorrelationScoringEngine()
    now = time.time()
    
    alert1 = SecurityAlert(
        alert_id="mitre_001",
        source="edr",
        alert_type="execution",
        severity="high",
        timestamp=now,
        asset_id="workstation_1",
        asset_criticality="medium",
        source_reliability=0.9,
        description="PowerShell execution",
        mitre_techniques=["T1059", "T1086", "T1027"]
    )
    
    alert2 = SecurityAlert(
        alert_id="mitre_002",
        source="network",
        alert_type="lateral",
        severity="high",
        timestamp=now + 120,
        asset_id="workstation_1",
        asset_criticality="medium",
        source_reliability=0.85,
        description="SMB connection",
        mitre_techniques=["T1059", "T1021", "T1027"]
    )
    
    result = engine.calculate_pair_correlation(alert1, alert2)
    
    # 2 matching techniques out of 3
    assert result["component_scores"]["mitre_technique_match"] > 0.5
    
    print(f"  PASSED: MITRE match score = {result['component_scores']['mitre_technique_match']}")


def test_full_report_generation():
    """Test full correlation report generation"""
    print("Test 7: Full correlation report generation...")
    
    engine = AlertCorrelationScoringEngine()
    now = time.time()
    
    # Add mixed alerts
    for i in range(8):
        engine.add_alert(SecurityAlert(
            alert_id=f"alert_{i}",
            source=["fw", "ids", "edr", "proxy"][i % 4],
            alert_type=["scan", "login", "malware", "c2"][i % 4],
            severity=["low", "medium", "high", "critical"][i % 4],
            timestamp=now + i * 300,
            asset_id=f"server_{i % 3}",
            asset_criticality=["low", "medium", "high"][i % 3],
            source_reliability=0.7 + (i * 0.03),
            description=f"Test alert {i}",
            iocs=[f"10.0.0.{i % 5}"] if i % 2 == 0 else []
        ))
    
    report = engine.generate_correlation_report()
    
    assert report["summary"]["total_alerts_processed"] == 8
    assert "correlated_incident_groups" in report
    assert "individual_alert_risks" in report
    
    print(f"  PASSED: Report generated successfully")
    print(f"    Summary: {json.dumps(report['summary'], indent=2)}")


def test_weight_normalization():
    """Test that weights are properly normalized"""
    print("Test 8: Weight normalization...")
    
    # These sum to 2.0, should normalize to 1.0
    engine = AlertCorrelationScoringEngine(
        ioc_match_weight=0.7,
        temporal_weight=0.5,
        mitre_match_weight=0.4,
        asset_match_weight=0.4
    )
    
    total_weight = sum(engine.weights.values())
    assert 0.99 <= total_weight <= 1.01
    
    print(f"  PASSED: Weights normalized to sum = {total_weight:.4f}")


def run_all_tests():
    """Run all tests and save results"""
    print("=" * 60)
    print("Alert Correlation Weighted Scoring Engine - REAL Tests")
    print("=" * 60)
    
    tests = [
        test_security_alert_creation,
        test_single_alert_risk_scoring,
        test_temporal_correlation,
        test_ioc_based_correlation,
        test_correlated_group_detection,
        test_mitre_technique_correlation,
        test_full_report_generation,
        test_weight_normalization
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  FAILED: {e}")
            failed += 1
        print()
    
    print("=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save results
    results = {
        "test_module": "alert_correlation_weighted_scoring_engine",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "all_passed": failed == 0,
        "timestamp": time.time()
    }
    
    with open("/home/user/autonomous-developer/NeuralShield-AI/test_results_alert_correlation_scoring_engine.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_alert_correlation_scoring_engine.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
