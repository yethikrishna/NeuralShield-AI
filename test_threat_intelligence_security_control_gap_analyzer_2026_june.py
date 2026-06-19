#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Security Control Gap Analyzer
Real working tests - production grade
June 2026
"""

import sys
import os
import json
import time

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_security_control_gap_analyzer_2026_june import (
    SecurityControlGapAnalyzer,
    SecurityControl,
    DetectedThreat,
    ControlType,
    create_sample_controls,
    create_sample_threats
)


def run_tests():
    """Run all tests and generate report."""
    print("=" * 70)
    print("TEST SUITE: Security Control Gap Analyzer")
    print("=" * 70)
    
    test_results = []
    start_time = time.time()
    
    # Test 1: Basic initialization
    print("\n[TEST 1] Basic Initialization")
    try:
        analyzer = SecurityControlGapAnalyzer(
            min_effectiveness_threshold=0.6,
            high_risk_threshold=0.7,
            medium_risk_threshold=0.4
        )
        assert analyzer.min_effectiveness_threshold == 0.6
        assert len(analyzer.controls) == 0
        assert len(analyzer.threats) == 0
        print("  ✓ PASSED: Analyzer initialized correctly")
        test_results.append(("Initialization", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Initialization", "FAILED", str(e)))
    
    # Test 2: Add controls
    print("\n[TEST 2] Add Security Controls")
    try:
        analyzer = SecurityControlGapAnalyzer()
        controls = create_sample_controls()
        analyzer.add_controls_bulk(controls)
        assert len(analyzer.controls) == len(controls)
        print(f"  ✓ PASSED: Added {len(controls)} controls")
        test_results.append(("Add Controls", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Add Controls", "FAILED", str(e)))
    
    # Test 3: Add threats
    print("\n[TEST 3] Add Detected Threats")
    try:
        analyzer = SecurityControlGapAnalyzer()
        threats = create_sample_threats(count=50)
        analyzer.add_threats_bulk(threats)
        assert len(analyzer.threats) == 50
        print(f"  ✓ PASSED: Added {len(threats)} threats")
        test_results.append(("Add Threats", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Add Threats", "FAILED", str(e)))
    
    # Test 4: Full gap analysis
    print("\n[TEST 4] Full Gap Analysis")
    try:
        analyzer = SecurityControlGapAnalyzer()
        controls = create_sample_controls()
        threats = create_sample_threats(count=100)
        analyzer.add_controls_bulk(controls)
        analyzer.add_threats_bulk(threats)
        
        result = analyzer.analyze_gaps()
        
        assert result.total_controls_analyzed == len(controls)
        assert result.total_threats_analyzed == len(threats)
        assert result.overall_coverage_percent >= 0
        assert result.overall_coverage_percent <= 100
        assert result.processing_time_ms > 0
        
        print(f"  ✓ PASSED: Analysis completed successfully")
        print(f"    - Coverage: {result.overall_coverage_percent}%")
        print(f"    - Gaps found: {len(result.identified_gaps)}")
        print(f"    - Processing: {result.processing_time_ms}ms")
        test_results.append(("Gap Analysis", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Gap Analysis", "FAILED", str(e)))
    
    # Test 5: Coverage calculation
    print("\n[TEST 5] Technique Coverage Calculation")
    try:
        analyzer = SecurityControlGapAnalyzer()
        controls = create_sample_controls()
        analyzer.add_controls_bulk(controls)
        
        # Test specific technique coverage
        covered = analyzer._is_technique_covered("T1566")  # Phishing - should be covered
        not_covered = analyzer._is_technique_covered("T9999")  # Non-existent - not covered
        
        assert covered == True, "T1566 should be covered by email gateway"
        assert not_covered == False, "T9999 should not be covered"
        
        print("  ✓ PASSED: Technique coverage correctly calculated")
        test_results.append(("Coverage Calc", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Coverage Calc", "FAILED", str(e)))
    
    # Test 6: Risk scoring
    print("\n[TEST 6] Risk Score Calculation")
    try:
        analyzer = SecurityControlGapAnalyzer()
        
        # High threat count should give higher risk
        risk_high = analyzer._calculate_risk_score("T1486", 10)  # Ransomware with many threats
        risk_low = analyzer._calculate_risk_score("T1566", 1)
        
        assert risk_high > risk_low, "Higher threat count should increase risk"
        assert 0 <= risk_high <= 1.0, "Risk should be normalized 0-1"
        assert 0 <= risk_low <= 1.0, "Risk should be normalized 0-1"
        
        print(f"  ✓ PASSED: Risk scoring working correctly")
        print(f"    - High risk (ransomware, 10 incidents): {risk_high}")
        print(f"    - Low risk (phishing, 1 incident): {risk_low}")
        test_results.append(("Risk Scoring", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Risk Scoring", "FAILED", str(e)))
    
    # Test 7: Report generation
    print("\n[TEST 7] Coverage Report Generation")
    try:
        analyzer = SecurityControlGapAnalyzer()
        controls = create_sample_controls()
        threats = create_sample_threats(count=50)
        analyzer.add_controls_bulk(controls)
        analyzer.add_threats_bulk(threats)
        
        result = analyzer.analyze_gaps()
        report = analyzer.generate_coverage_report(result)
        
        assert len(report) > 0
        assert "SECURITY CONTROL GAP ANALYSIS REPORT" in report
        assert "Overall Coverage" in report
        
        print("  ✓ PASSED: Report generated successfully")
        test_results.append(("Report Gen", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Report Gen", "FAILED", str(e)))
    
    # Test 8: ControlGap to_dict
    print("\n[TEST 8] Data Serialization")
    try:
        from threat_intelligence_security_control_gap_analyzer_2026_june import ControlGap
        
        gap = ControlGap(
            gap_id="GAP_TEST_001",
            mitre_tactic="Execution",
            mitre_technique="T1059",
            risk_score=0.85,
            gap_severity="high",
            gap_description="Test gap",
            detected_incidents=5,
            recommended_controls=["EDR", "AV"],
            remediation_priority="high"
        )
        
        gap_dict = gap.to_dict()
        assert gap_dict["gap_id"] == "GAP_TEST_001"
        assert gap_dict["risk_score"] == 0.85
        assert isinstance(gap_dict, dict)
        
        print("  ✓ PASSED: Data serialization working")
        test_results.append(("Serialization", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Serialization", "FAILED", str(e)))
    
    # Test 9: Empty dataset handling
    print("\n[TEST 9] Empty Dataset Handling")
    try:
        analyzer = SecurityControlGapAnalyzer()
        result = analyzer.analyze_gaps()
        
        assert result.total_controls_analyzed == 0
        assert result.total_threats_analyzed == 0
        assert result.overall_coverage_percent >= 0
        
        print("  ✓ PASSED: Empty datasets handled correctly")
        test_results.append(("Empty Data", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Empty Data", "FAILED", str(e)))
    
    # Test 10: Control effectiveness threshold
    print("\n[TEST 10] Effectiveness Threshold Filtering")
    try:
        # Create analyzer with high threshold
        analyzer = SecurityControlGapAnalyzer(min_effectiveness_threshold=0.95)
        
        # Add a control with low effectiveness
        weak_control = SecurityControl(
            control_id="WEAK_001",
            name="Weak Control",
            control_type=ControlType.PREVENTIVE,
            description="Ineffective control",
            coverage_techniques=["T1566"],
            effectiveness_score=0.5,  # Below threshold
            deployment_status="active"
        )
        analyzer.add_control(weak_control)
        
        # Should NOT be considered covered due to low effectiveness
        is_covered = analyzer._is_technique_covered("T1566")
        assert is_covered == False, "Control below threshold should not count as coverage"
        
        print("  ✓ PASSED: Effectiveness threshold correctly filters weak controls")
        test_results.append(("Threshold Filter", "PASSED", ""))
    except Exception as e:
        print(f"  ✗ FAILED: {str(e)}")
        test_results.append(("Threshold Filter", "FAILED", str(e)))
    
    # Summary
    total_time = (time.time() - start_time) * 1000
    passed = sum(1 for r in test_results if r[1] == "PASSED")
    failed = len(test_results) - passed
    
    print("\n" + "=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(f"Total Tests:  {len(test_results)}")
    print(f"Passed:       {passed}")
    print(f"Failed:       {failed}")
    print(f"Total Time:   {total_time:.2f}ms")
    print("=" * 70)
    
    # Save results
    results_data = {
        "test_timestamp": time.time(),
        "module": "threat_intelligence_security_control_gap_analyzer_2026_june",
        "total_tests": len(test_results),
        "passed": passed,
        "failed": failed,
        "success_rate": round(passed / len(test_results) * 100, 2) if test_results else 0,
        "execution_time_ms": round(total_time, 2),
        "test_results": [
            {"test": r[0], "status": r[1], "error": r[2]}
            for r in test_results
        ]
    }
    
    with open("test_results_security_control_gap_analyzer.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    print(f"\nTest results saved to test_results_security_control_gap_analyzer.json")
    
    return results_data


if __name__ == "__main__":
    results = run_tests()
    sys.exit(0 if results["failed"] == 0 else 1)
