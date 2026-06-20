#!/usr/bin/env python3
"""
Test suite for CVSS v3.1 Score Calculator - NeuralShield-AI
Production-grade tests with real validation
June 2026
"""
import sys
import json
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')

from neural_shield.threat_intelligence_cve_cvss_score_calculator_2026_june import (
    CVSSv31Calculator,
    CVSSMetrics,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    CIAImpact,
    SeverityRating
)


def run_tests():
    print("=" * 60)
    print("NeuralShield-AI: CVSS v3.1 Score Calculator Tests")
    print("=" * 60)
    
    calculator = CVSSv31Calculator()
    all_passed = True
    test_results = []
    
    # Test 1: Critical RCE vulnerability
    print("\n[Test 1] Critical RCE Vulnerability (Log4j-style)")
    result = calculator.quick_score(
        av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"
    )
    print(f"  Vector: {result.vector_string}")
    print(f"  Base Score: {result.base_score}")
    print(f"  Severity: {result.base_severity.value}")
    print(f"  Priority: {result.priority_level}")
    
    test1_pass = result.base_score == 10.0 and result.base_severity == SeverityRating.CRITICAL
    print(f"  {'PASS' if test1_pass else 'FAIL'}: Expected 10.0 CRITICAL")
    all_passed &= test1_pass
    test_results.append({"test": "Critical RCE", "passed": test1_pass, "score": result.base_score})
    
    # Test 2: High severity privilege escalation
    print("\n[Test 2] High Privilege Escalation")
    result = calculator.quick_score(
        av="L", ac="L", pr="L", ui="N", s="C", c="H", i="H", a="H"
    )
    print(f"  Base Score: {result.base_score}")
    print(f"  Severity: {result.base_severity.value}")
    
    test2_pass = 7.0 <= result.base_score < 9.0 and result.base_severity == SeverityRating.HIGH
    print(f"  {'PASS' if test2_pass else 'FAIL'}: Expected HIGH severity")
    all_passed &= test2_pass
    test_results.append({"test": "Privilege Escalation", "passed": test2_pass, "score": result.base_score})
    
    # Test 3: Medium XSS vulnerability
    print("\n[Test 3] Medium XSS Vulnerability")
    result = calculator.quick_score(
        av="N", ac="L", pr="N", ui="R", s="C", c="L", i="L", a="N"
    )
    print(f"  Base Score: {result.base_score}")
    print(f"  Severity: {result.base_severity.value}")
    
    test3_pass = 4.0 <= result.base_score < 7.0 and result.base_severity == SeverityRating.MEDIUM
    print(f"  {'PASS' if test3_pass else 'FAIL'}: Expected MEDIUM severity")
    all_passed &= test3_pass
    test_results.append({"test": "XSS", "passed": test3_pass, "score": result.base_score})
    
    # Test 4: Low information disclosure
    print("\n[Test 4] Low Information Disclosure")
    result = calculator.quick_score(
        av="N", ac="L", pr="N", ui="N", s="U", c="L", i="N", a="N"
    )
    print(f"  Base Score: {result.base_score}")
    print(f"  Severity: {result.base_severity.value}")
    
    test4_pass = result.base_score < 4.0 and result.base_severity == SeverityRating.LOW
    print(f"  {'PASS' if test4_pass else 'FAIL'}: Expected LOW severity")
    all_passed &= test4_pass
    test_results.append({"test": "Info Disclosure", "passed": test4_pass, "score": result.base_score})
    
    # Test 5: No impact vulnerability
    print("\n[Test 5] No Impact (Safe)")
    result = calculator.quick_score(
        av="P", ac="H", pr="H", ui="R", s="U", c="N", i="N", a="N"
    )
    print(f"  Base Score: {result.base_score}")
    print(f"  Severity: {result.base_severity.value}")
    
    test5_pass = result.base_score == 0.0 and result.base_severity == SeverityRating.NONE
    print(f"  {'PASS' if test5_pass else 'FAIL'}: Expected NONE severity")
    all_passed &= test5_pass
    test_results.append({"test": "No Impact", "passed": test5_pass, "score": result.base_score})
    
    # Test 6: Temporal score calculation
    print("\n[Test 6] Temporal Score Calculation")
    metrics = CVSSMetrics(
        attack_vector=AttackVector.NETWORK,
        attack_complexity=AttackComplexity.LOW,
        privileges_required=PrivilegesRequired.NONE,
        user_interaction=UserInteraction.NONE,
        scope=Scope.CHANGED,
        confidentiality_impact=CIAImpact.HIGH,
        integrity_impact=CIAImpact.HIGH,
        availability_impact=CIAImpact.HIGH
    )
    result = calculator.calculate(metrics)
    print(f"  Base Score: {result.base_score}")
    print(f"  Temporal Score: {result.temporal_score}")
    
    test6_pass = result.temporal_score == result.base_score  # X = 1.0 multiplier
    print(f"  {'PASS' if test6_pass else 'FAIL'}: Temporal equals base when X")
    all_passed &= test6_pass
    test_results.append({"test": "Temporal Score", "passed": test6_pass, "score": result.temporal_score})
    
    # Test 7: Common profiles
    print("\n[Test 7] Common CVSS Profiles")
    profiles = calculator.get_common_cvss_profiles()
    print(f"  Profiles available: {len(profiles)}")
    for name, profile in profiles.items():
        print(f"    - {name}: {profile.base_score} ({profile.base_severity.value})")
    
    test7_pass = len(profiles) == 4
    print(f"  {'PASS' if test7_pass else 'FAIL'}: 4 common profiles")
    all_passed &= test7_pass
    test_results.append({"test": "Common Profiles", "passed": test7_pass})
    
    # Test 8: Batch calculation
    print("\n[Test 8] Batch Calculation")
    vulns = [
        {"cve_id": "CVE-2026-0001", "av": "N", "ac": "L", "pr": "N", "ui": "N", "s": "C", "c": "H", "i": "H", "a": "H"},
        {"cve_id": "CVE-2026-0002", "av": "N", "ac": "L", "pr": "N", "ui": "R", "s": "C", "c": "L", "i": "L", "a": "N"},
        {"cve_id": "CVE-2026-0003", "av": "L", "ac": "L", "pr": "L", "ui": "N", "s": "U", "c": "L", "i": "L", "a": "L"},
    ]
    batch_results = calculator.batch_calculate(vulns)
    print(f"  Processed: {len(batch_results)} vulnerabilities")
    for r in batch_results:
        print(f"    - {r['cve_id']}: {r['base_score']} ({r['base_severity']})")
    
    test8_pass = len(batch_results) == 3
    print(f"  {'PASS' if test8_pass else 'FAIL'}: Batch processed all")
    all_passed &= test8_pass
    test_results.append({"test": "Batch Calculation", "passed": test8_pass})
    
    # Test 9: Impact and Exploitability subscores
    print("\n[Test 9] Subscore Calculation")
    result = calculator.quick_score(
        av="N", ac="L", pr="N", ui="N", s="C", c="H", i="H", a="H"
    )
    print(f"  Impact Subscore: {result.impact_subscore:.2f}")
    print(f"  Exploitability Subscore: {result.exploitability_subscore:.2f}")
    
    test9_pass = result.impact_subscore > 0 and result.exploitability_subscore > 0
    print(f"  {'PASS' if test9_pass else 'FAIL'}: Subscores calculated")
    all_passed &= test9_pass
    test_results.append({"test": "Subscores", "passed": test9_pass})
    
    # Test 10: to_dict serialization
    print("\n[Test 10] JSON Serialization")
    result = calculator.quick_score(av="N", ac="L", pr="N", ui="N", s="U", c="H", i="H", a="H")
    result_dict = result.to_dict()
    json_str = json.dumps(result_dict, indent=2)
    print(f"  Serialized successfully: {len(json_str)} chars")
    
    test10_pass = "base_score" in result_dict and "vector_string" in result_dict
    print(f"  {'PASS' if test10_pass else 'FAIL'}: to_dict works")
    all_passed &= test10_pass
    test_results.append({"test": "Serialization", "passed": test10_pass})
    
    # Summary
    print("\n" + "=" * 60)
    passed_count = sum(1 for t in test_results if t["passed"])
    total_count = len(test_results)
    print(f"SUMMARY: {passed_count}/{total_count} tests passed")
    
    if all_passed:
        print("ALL TESTS PASSED ✓")
    else:
        print("SOME TESTS FAILED ✗")
        for t in test_results:
            if not t["passed"]:
                print(f"  FAILED: {t['test']}")
    
    print("=" * 60)
    
    # Save test results
    with open('/home/user/autonomous-developer/NeuralShield-AI/test_results_cve_cvss_calculator.json', 'w') as f:
        json.dump({
            "test_timestamp": __import__('datetime').datetime.now().isoformat(),
            "module": "threat_intelligence_cve_cvss_score_calculator_2026_june",
            "all_passed": all_passed,
            "passed_count": passed_count,
            "total_count": total_count,
            "results": test_results
        }, f, indent=2)
    
    return all_passed


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
