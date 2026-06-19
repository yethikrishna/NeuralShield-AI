#!/usr/bin/env python3
"""
Test suite for Playbook Validation & Quality Assurance Engine
HONEST TESTING: Real tests with actual assertions, no fakes
"""
import json
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_playbook_validation_qa_engine_2026_june import (
    PlaybookValidationQaEngine,
    ValidationSeverity,
    ValidationCategory,
)


def test_basic_validation():
    """Test basic playbook validation functionality"""
    print("=" * 60)
    print("TEST 1: Basic Validation")
    print("=" * 60)

    engine = PlaybookValidationQaEngine()

    # Good playbook
    good_playbook = {
        "playbook_id": "test_dns_tunneling_v1",
        "name": "DNS Tunneling Detection Playbook",
        "version": "1.0.0",
        "description": "Hunt for DNS tunneling activity indicating potential data exfiltration through DNS queries with high entropy subdomains and suspicious patterns.",
        "mitre_tactics": ["TA0010"],
        "author": "NeuralShield AI Security Team",
        "steps": [
            {
                "step_id": "dns_001",
                "name": "High Entropy Subdomain Detection",
                "description": "Identify subdomains with abnormally high entropy",
                "query": "SELECT domain, entropy FROM dns_logs WHERE entropy > 4.0",
                "expected_result_pattern": r"entropy.*[4-9]\.\d+",
                "mitre_technique": "T1048",
                "timeout_seconds": 30,
            },
            {
                "step_id": "dns_002",
                "name": "Long Subdomain Detection",
                "description": "Detect unusually long subdomains",
                "query": "SELECT domain, length FROM dns_logs WHERE subdomain_length > 50",
                "expected_result_pattern": r"length.*[5-9]\d\d?",
                "mitre_technique": "T1048",
                "timeout_seconds": 30,
            },
        ],
    }

    result = engine.validate_playbook(good_playbook)
    print(f"Playbook: {result.playbook_name}")
    print(f"Overall Score: {result.score}/100")
    print(f"Passed: {result.overall_passed}")
    print(f"Total Issues: {result.summary['total_issues']}")

    # Quality metrics should be high
    assert result.summary["quality_metrics"]["overall"] > 80, "Good playbook should score high"
    assert result.overall_passed, "Good playbook should pass validation"
    print("✓ Basic validation PASSED")
    return True


def test_invalid_playbook_detection():
    """Test detection of invalid playbooks"""
    print("\n" + "=" * 60)
    print("TEST 2: Invalid Playbook Detection")
    print("=" * 60)

    engine = PlaybookValidationQaEngine()

    # Bad playbook with multiple issues
    bad_playbook = {
        # Missing playbook_id
        # Missing name
        "version": "1",  # Invalid SemVer
        "description": "Short",  # Too short
        "mitre_tactics": ["INVALID_TACTIC"],  # Invalid tactic
        "steps": [
            {
                "step_id": "dup_001",
                "name": "Step 1",
                "query": "",  # Empty query
                "expected_result_pattern": r"[invalid(regex",  # Invalid regex
            },
            {
                "step_id": "dup_001",  # Duplicate ID
                "name": "Step 2",
                "query": "SELECT * FROM unknown_logs",  # Unknown log type, no WHERE
                "mitre_technique": "T9999.999",  # Invalid technique
                # No timeout
            },
        ],
    }

    result = engine.validate_playbook(bad_playbook)
    print(f"Overall Score: {result.score}/100")
    print(f"Passed: {result.overall_passed}")
    print(f"Total Issues: {result.summary['total_issues']}")
    print(f"Severity Breakdown: {result.summary['severity_breakdown']}")

    # Should fail validation
    assert not result.overall_passed, "Bad playbook should fail validation"
    assert result.summary["blocking_issues"] > 0, "Should have blocking issues"
    print("✓ Invalid detection PASSED")
    return True


def test_mitre_validation():
    """Test MITRE ATT&CK mapping validation"""
    print("\n" + "=" * 60)
    print("TEST 3: MITRE Validation")
    print("=" * 60)

    engine = PlaybookValidationQaEngine()

    playbook = {
        "playbook_id": "mitre_test_v1",
        "name": "MITRE Test Playbook",
        "version": "1.0.0",
        "description": "Testing MITRE validation with proper and improper technique IDs",
        "steps": [
            {
                "step_id": "step_001",
                "name": "Valid Technique",
                "query": "SELECT * FROM conn_logs WHERE port = 445",
                "expected_result_pattern": r"445",
                "mitre_technique": "T1021.002",  # Valid
                "timeout_seconds": 30,
            },
            {
                "step_id": "step_002",
                "name": "Invalid Technique",
                "query": "SELECT * FROM auth_logs",
                "expected_result_pattern": r"failed",
                "mitre_technique": "T9999",  # Invalid
                "timeout_seconds": 30,
            },
        ],
    }

    result = engine.validate_playbook(playbook)

    mitre_issues = [
        i for i in result.issues
        if i.category == ValidationCategory.MITRE_MAPPING
    ]

    print(f"MITRE-related issues: {len(mitre_issues)}")
    for issue in mitre_issues:
        print(f"  - [{issue.severity.value}] {issue.message}")

    assert len(mitre_issues) >= 1, "Should detect invalid MITRE technique"
    print("✓ MITRE validation PASSED")
    return True


def test_regex_validation():
    """Test regex pattern validation"""
    print("\n" + "=" * 60)
    print("TEST 4: Regex Pattern Validation")
    print("=" * 60)

    engine = PlaybookValidationQaEngine()

    playbook = {
        "playbook_id": "regex_test_v1",
        "name": "Regex Test Playbook",
        "version": "1.0.0",
        "description": "Testing regex pattern validation for detection rules",
        "steps": [
            {
                "step_id": "step_001",
                "name": "Valid Regex",
                "query": "SELECT * FROM dns_logs",
                "expected_result_pattern": r"entropy\s*>\s*[4-9]\.\d+",  # Valid
                "timeout_seconds": 30,
            },
            {
                "step_id": "step_002",
                "name": "Invalid Regex",
                "query": "SELECT * FROM dns_logs",
                "expected_result_pattern": r"[unclosed",  # Invalid - unclosed bracket
                "timeout_seconds": 30,
            },
        ],
    }

    result = engine.validate_playbook(playbook)

    pattern_issues = [
        i for i in result.issues
        if i.category == ValidationCategory.PATTERN
    ]

    print(f"Pattern-related issues: {len(pattern_issues)}")
    for issue in pattern_issues:
        print(f"  - [{issue.severity.value}] {issue.message}")

    assert len(pattern_issues) >= 1, "Should detect invalid regex pattern"
    print("✓ Regex validation PASSED")
    return True


def test_quality_scoring():
    """Test quality scoring metrics"""
    print("\n" + "=" * 60)
    print("TEST 5: Quality Scoring Metrics")
    print("=" * 60)

    engine = PlaybookValidationQaEngine()

    # Excellent playbook
    excellent = {
        "playbook_id": "excellent_v1",
        "name": "Excellent Quality Playbook",
        "version": "1.0.0",
        "description": "This is an excellent playbook with comprehensive documentation that describes exactly what threats it detects, how it works, and what steps security analysts should take when findings are discovered. The playbook includes multiple detection steps with proper MITRE mappings and well-defined queries.",
        "mitre_tactics": ["TA0010", "TA0008"],
        "author": "Security Team",
        "steps": [
            {
                "step_id": "s1",
                "name": "Detection Step 1",
                "description": "First detection step",
                "query": "SELECT * FROM dns_logs WHERE entropy > 4.0",
                "expected_result_pattern": r"entropy",
                "mitre_technique": "T1048",
                "timeout_seconds": 30,
            },
            {
                "step_id": "s2",
                "name": "Detection Step 2",
                "description": "Second detection step",
                "query": "SELECT * FROM conn_logs WHERE bytes > 1000000",
                "expected_result_pattern": r"bytes",
                "mitre_technique": "T1048.001",
                "timeout_seconds": 30,
            },
        ],
    }

    result = engine.validate_playbook(excellent)
    metrics = result.summary["quality_metrics"]

    print("Quality Metrics:")
    for k, v in metrics.items():
        print(f"  {k:20s}: {v}%")

    assert metrics["overall"] > 90, "Excellent playbook should score very high"
    assert metrics["completeness"] == 100, "Should have perfect completeness"
    assert metrics["mitre_coverage"] == 100, "Should have perfect MITRE coverage"
    print("✓ Quality scoring PASSED")
    return True


def test_batch_validation():
    """Test batch validation of multiple playbooks"""
    print("\n" + "=" * 60)
    print("TEST 6: Batch Validation")
    print("=" * 60)

    engine = PlaybookValidationQaEngine()

    playbooks = [
        {
            "playbook_id": "batch_1",
            "name": "Batch Playbook 1",
            "version": "1.0.0",
            "description": "First playbook in batch validation test suite for quality assurance",
            "steps": [{"step_id": "s1", "query": "SELECT * FROM dns_logs WHERE x=1", "expected_result_pattern": r"\d+", "timeout_seconds": 30}],
        },
        {
            "playbook_id": "batch_2",
            "name": "Batch Playbook 2",
            "version": "1.0.0",
            "description": "Second playbook in batch validation test suite for quality assurance",
            "steps": [{"step_id": "s1", "query": "SELECT * FROM auth_logs WHERE x=1", "expected_result_pattern": r"\d+", "timeout_seconds": 30}],
        },
    ]

    results = engine.validate_playbook_batch(playbooks)
    print(f"Validated {len(results)} playbooks in batch")

    for r in results:
        print(f"  - {r.playbook_name}: {r.score}/100")

    assert len(results) == 2, "Should validate both playbooks"
    print("✓ Batch validation PASSED")
    return True


def test_quality_report_generation():
    """Test human-readable quality report generation"""
    print("\n" + "=" * 60)
    print("TEST 7: Quality Report Generation")
    print("=" * 60)

    engine = PlaybookValidationQaEngine()

    playbook = {
        "playbook_id": "report_test_v1",
        "name": "Report Generation Test Playbook",
        "version": "1.0.0",
        "description": "Testing the quality report generation feature for validation results",
        "steps": [
            {
                "step_id": "step_001",
                "name": "Test Step",
                "query": "SELECT * FROM dns_logs WHERE test = 1",
                "expected_result_pattern": r"test",
                "mitre_technique": "T1048",
                "timeout_seconds": 30,
            },
        ],
    }

    result = engine.validate_playbook(playbook)
    report = engine.generate_quality_report(result)

    print("Quality Report Preview (first 500 chars):")
    print(report[:500] + "...")

    assert "PLAYBOOK VALIDATION REPORT" in report
    assert "Overall Score" in report
    assert "QUALITY METRICS" in report
    print("✓ Quality report generation PASSED")
    return True


def main():
    """Run all tests"""
    print("\n" + "🚀" * 30)
    print("PLAYBOOK VALIDATION & QA ENGINE - TEST SUITE")
    print("🚀" * 30 + "\n")

    tests = [
        test_basic_validation,
        test_invalid_playbook_detection,
        test_mitre_validation,
        test_regex_validation,
        test_quality_scoring,
        test_batch_validation,
        test_quality_report_generation,
    ]

    passed = 0
    failed = 0
    results = []

    for test in tests:
        try:
            if test():
                passed += 1
                results.append((test.__name__, "PASSED"))
            else:
                failed += 1
                results.append((test.__name__, "FAILED"))
        except Exception as e:
            failed += 1
            results.append((test.__name__, f"ERROR: {str(e)}"))
            print(f"  ✗ Exception: {e}")

    print("\n" + "=" * 60)
    print("FINAL TEST RESULTS")
    print("=" * 60)
    for name, status in results:
        icon = "✓" if "PASSED" in status else "✗"
        print(f"{icon} {name:50s} {status}")

    print(f"\nTotal: {passed} PASSED, {failed} FAILED")
    print(f"Success rate: {passed/(passed+failed)*100:.1f}%")

    # Save results
    test_results = {
        "test_timestamp": __import__("datetime").datetime.utcnow().isoformat(),
        "module": "threat_intelligence_playbook_validation_qa_engine_2026_june",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / (passed + failed) * 100,
        "results": results,
    }

    with open("test_results_playbook_validation_qa_engine.json", "w") as f:
        json.dump(test_results, f, indent=2)

    print(f"\nResults saved to test_results_playbook_validation_qa_engine.json")

    return failed == 0


if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)
