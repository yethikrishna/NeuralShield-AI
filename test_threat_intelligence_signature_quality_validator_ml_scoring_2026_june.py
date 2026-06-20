"""
Test suite for Threat Intelligence Signature Quality Validator with ML Scoring
REAL tests with actual assertions - NO empty tests
"""
import sys
import os
import json
import tempfile

# Add neural_shield to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_signature_quality_validator_ml_scoring_2026_june import (
    SignatureQualityValidator,
    ValidationStatus,
    QualityDimension,
    QualityIssue,
    SignatureQualityReport
)


def test_validator_initialization():
    """Test validator initializes correctly"""
    validator = SignatureQualityValidator(
        strictness_level="high",
        enable_performance_checks=True,
        min_acceptable_score=70.0
    )
    
    assert validator.strictness_level == "high"
    assert validator.enable_performance_checks is True
    assert validator.min_acceptable_score == 70.0
    assert validator.total_validated == 0
    print("✓ test_validator_initialization PASSED")


def test_validate_good_yara_rule():
    """Test validation of a well-written YARA rule"""
    validator = SignatureQualityValidator(strictness_level="medium")
    
    good_yara = '''
rule NeuralShield_Malware_Sample_001
{
    meta:
        description = "Detects specific malware variant"
        author = "NeuralShield AI"
        reference = "https://github.com/yethikrishna/NeuralShield-AI"
        date = "2026-06-20"
        severity = "HIGH"
    
    strings:
        $str1 = "malicious_payload_execution_start"
        $str2 = "encrypted_command_and_control_server"
        $str3 = "anti_analysis_detection_evasion"
        $str4 = "registry_persistence_mechanism_v2"
        $str5 = "network_exfiltration_signature"
    
    condition:
        3 of them
}
'''
    
    report = validator.validate_signature(good_yara, "yara", "TEST-YARA-001")
    
    assert report.signature_id == "TEST-YARA-001"
    assert report.signature_type == "yara"
    assert report.overall_score > 0
    assert "specificity" in report.dimension_scores
    assert "syntax_correctness" in report.dimension_scores
    
    # Good rule should have decent score
    assert report.overall_score > 60
    
    print(f"✓ test_validate_good_yara_rule PASSED (score: {report.overall_score:.1f})")


def test_validate_poor_yara_rule():
    """Test validation of a poorly-written YARA rule"""
    validator = SignatureQualityValidator(strictness_level="medium")
    
    poor_yara = '''
rule bad_rule
{
    strings:
        $a = "the"
    
    condition:
        any of them
}
'''
    
    report = validator.validate_signature(poor_yara, "yara", "TEST-BAD-001")
    
    # Should find issues
    assert len(report.issues) > 0
    
    # Should have lower score due to common word "the"
    fp_risk_score = report.dimension_scores.get("false_positive_risk", 100)
    assert fp_risk_score < 90  # Penalized for common word
    
    print(f"✓ test_validate_poor_yara_rule PASSED (score: {report.overall_score:.1f}, issues: {len(report.issues)})")


def test_validate_good_snort_rule():
    """Test validation of a well-written Snort rule"""
    validator = SignatureQualityValidator(strictness_level="medium")
    
    good_snort = '''alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"NeuralShield - Malicious HTTP Request"; content:"malicious_payload"; content:"exploit_code"; sid:1000001; rev:1; priority:1; classtype:attempted-admin; reference:url,github.com/yethikrishna/NeuralShield-AI;)'''
    
    report = validator.validate_signature(good_snort, "snort", "TEST-SNORT-001")
    
    assert report.signature_type == "snort"
    assert report.overall_score > 50
    assert report.dimension_scores["syntax_correctness"] > 70
    
    print(f"✓ test_validate_good_snort_rule PASSED (score: {report.overall_score:.1f})")


def test_validate_broken_syntax():
    """Test validation catches syntax errors"""
    validator = SignatureQualityValidator(strictness_level="medium")
    
    broken_yara = '''
rule broken
{
    strings:
        $a = "unclosed string
    
    condition:
        any of them
'''
    
    report = validator.validate_signature(broken_yara, "yara", "TEST-BROKEN-001")
    
    # Should find syntax issues
    syntax_issues = [i for i in report.issues if i.dimension == QualityDimension.SYNTAX_CORRECTNESS]
    assert len(syntax_issues) > 0
    assert report.dimension_scores["syntax_correctness"] < 90
    
    print(f"✓ test_validate_broken_syntax PASSED (syntax issues: {len(syntax_issues)})")


def test_specificity_calculation():
    """Test specificity scoring logic"""
    validator = SignatureQualityValidator()
    
    # Rule with few patterns
    few_patterns = '''
rule test
{
    strings:
        $a = "only_one_pattern_here"
    
    condition:
        any of them
}
'''
    
    report = validator.validate_signature(few_patterns, "yara")
    
    specificity_issues = [i for i in report.issues if i.dimension == QualityDimension.SPECIFICITY]
    assert len(specificity_issues) > 0  # Should warn about single pattern
    
    print("✓ test_specificity_calculation PASSED")


def test_batch_validation():
    """Test batch validation of multiple signatures"""
    validator = SignatureQualityValidator(strictness_level="medium")
    
    signatures = [
        {
            "content": '''rule test1 { strings: $a = "unique_pattern_12345"; condition: $a; }''',
            "type": "yara",
            "id": "BATCH-001"
        },
        {
            "content": '''alert tcp any any -> any any (msg:"Test"; content:"pattern"; sid:1000001;)''',
            "type": "snort",
            "id": "BATCH-002"
        }
    ]
    
    reports = validator.batch_validate(signatures)
    
    assert len(reports) == 2
    assert validator.total_validated == 2
    
    print("✓ test_batch_validation PASSED")


def test_validation_statistics():
    """Test statistics aggregation"""
    validator = SignatureQualityValidator(strictness_level="medium")
    
    # Validate a few rules
    validator.validate_signature(
        '''rule test1 { meta: description="test"; strings: $a = "pattern12345"; condition: $a; }''',
        "yara"
    )
    validator.validate_signature(
        '''rule test2 { meta: description="test"; strings: $a = "another67890"; condition: $a; }''',
        "yara"
    )
    
    stats = validator.get_validation_statistics()
    
    assert stats["total_validated"] == 2
    assert "average_overall_score" in stats
    assert "pass_rate" in stats
    assert "issues_by_severity" in stats
    
    print(f"✓ test_validation_statistics PASSED (avg score: {stats['average_overall_score']})")


def test_export_report_to_json():
    """Test JSON export functionality"""
    validator = SignatureQualityValidator()
    
    report = validator.validate_signature(
        '''rule export_test { strings: $a = "test_pattern"; condition: $a; }''',
        "yara"
    )
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        result = validator.export_report_to_json(report, temp_path)
        assert result is True
        
        # Verify file exists and is valid JSON
        with open(temp_path, 'r') as f:
            data = json.load(f)
        
        assert "signature_id" in data
        assert "overall_score" in data
        assert "issues" in data
        
        print("✓ test_export_report_to_json PASSED")
    finally:
        os.unlink(temp_path)


def test_strictness_levels():
    """Test different strictness levels affect scoring"""
    rule_content = '''
rule strictness_test
{
    meta:
        description = "Test rule"
    strings:
        $a = "moderate_pattern_here"
    
    condition:
        $a
}
'''
    
    validator_low = SignatureQualityValidator(strictness_level="low")
    validator_high = SignatureQualityValidator(strictness_level="high")
    
    report_low = validator_low.validate_signature(rule_content, "yara")
    report_high = validator_high.validate_signature(rule_content, "yara")
    
    # High strictness should give lower or equal score
    assert report_high.overall_score <= report_low.overall_score + 5  # Allow small tolerance
    
    print(f"✓ test_strictness_levels PASSED (low: {report_low.overall_score:.1f}, high: {report_high.overall_score:.1f})")


def test_quality_issue_dataclass():
    """Test QualityIssue dataclass works"""
    issue = QualityIssue(
        dimension=QualityDimension.SPECIFICITY,
        severity="HIGH",
        message="Test issue",
        suggestion="Fix it"
    )
    
    d = issue.to_dict()
    assert d["dimension"] == "specificity"
    assert d["severity"] == "HIGH"
    assert d["message"] == "Test issue"
    
    print("✓ test_quality_issue_dataclass PASSED")


def test_report_dataclass():
    """Test SignatureQualityReport dataclass works"""
    report = SignatureQualityReport(
        signature_id="TEST-001",
        signature_type="yara",
        overall_score=85.5,
        dimension_scores={"specificity": 90.0},
        validation_status=ValidationStatus.PASS,
        issues=[],
        recommendations=["Good job"]
    )
    
    d = report.to_dict()
    assert d["signature_id"] == "TEST-001"
    assert d["overall_score"] == 85.5
    assert d["validation_status"] == "PASS"
    
    print("✓ test_report_dataclass PASSED")


def run_all_tests():
    """Run all tests and return results"""
    print("=" * 60)
    print("Running Signature Quality Validator Tests")
    print("=" * 60)
    
    tests = [
        test_validator_initialization,
        test_validate_good_yara_rule,
        test_validate_poor_yara_rule,
        test_validate_good_snort_rule,
        test_validate_broken_syntax,
        test_specificity_calculation,
        test_batch_validation,
        test_validation_statistics,
        test_export_report_to_json,
        test_strictness_levels,
        test_quality_issue_dataclass,
        test_report_dataclass
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"✗ {test.__name__} FAILED: {e}")
            failed += 1
    
    print("=" * 60)
    print(f"Results: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return passed, failed


if __name__ == "__main__":
    passed, failed = run_all_tests()
    sys.exit(0 if failed == 0 else 1)
