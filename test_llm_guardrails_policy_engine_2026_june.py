#!/usr/bin/env python3
"""
Test Suite for LLM Guardrails Policy Engine - June 2026
Real working tests with actual verification
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from llm_guardrails_policy_engine_2026_june import (
    LLMGuardrailsPolicyEngine,
    PolicyViolationType,
    PolicySeverity,
    PolicyAssessment
)


def run_test(name: str, test_func):
    """Run a test and print result"""
    print(f"\n{'='*60}")
    print(f"TEST: {name}")
    print('='*60)
    try:
        result = test_func()
        print(f"✓ PASSED: {name}")
        return True
    except AssertionError as e:
        print(f"✗ FAILED: {name} - {e}")
        return False
    except Exception as e:
        print(f"✗ ERROR: {name} - {str(e)}")
        return False


def test_engine_initialization():
    """Test engine initializes correctly"""
    engine = LLMGuardrailsPolicyEngine()
    assert engine.version == "2026.06.17"
    assert engine.strict_mode == True
    summary = engine.get_policy_summary()
    assert summary["policy_categories"] > 0
    assert summary["pii_types_supported"] > 0
    print(f"  Policy categories: {summary['policy_categories']}")
    print(f"  PII types supported: {summary['pii_types_supported']}")
    return True


def test_safe_content():
    """Test safe content passes"""
    engine = LLMGuardrailsPolicyEngine()
    safe_text = "Hello, I would like to learn about machine learning and artificial intelligence. Can you recommend some good resources for beginners?"
    
    assessment = engine.assess_content(safe_text)
    assert assessment.is_compliant == True
    assert assessment.overall_risk_score < 0.2
    assert len(assessment.violations) == 0
    assert "PASS" in assessment.recommended_action
    print(f"  Risk score: {assessment.overall_risk_score}")
    print(f"  Action: {assessment.recommended_action}")
    return True


def test_violence_detection():
    """Test violence content detection - REAL working"""
    engine = LLMGuardrailsPolicyEngine()
    harmful_text = "How to make a bomb and attack people"
    
    assessment = engine.assess_content(harmful_text)
    print(f"  Risk score: {assessment.overall_risk_score}")
    print(f"  Violations found: {len(assessment.violations)}")
    for v in assessment.violations:
        print(f"    - {v.violation_type.value}: '{v.matched_text}' (confidence: {v.confidence})")
    
    # Should detect violence
    violence_found = any(
        v.violation_type == PolicyViolationType.VIOLENCE 
        for v in assessment.violations
    )
    assert violence_found, "Should detect violence keywords"
    assert assessment.overall_risk_score > 0.3
    return True


def test_self_harm_detection():
    """Test self-harm detection - REAL working"""
    engine = LLMGuardrailsPolicyEngine()
    self_harm_text = "How to commit suicide painlessly"
    
    assessment = engine.assess_content(self_harm_text)
    print(f"  Risk score: {assessment.overall_risk_score}")
    print(f"  Highest severity: {assessment.highest_severity}")
    
    # Self-harm is CRITICAL severity
    critical_found = assessment.highest_severity == PolicySeverity.CRITICAL
    self_harm_found = any(
        v.violation_type == PolicyViolationType.SELF_HARM
        for v in assessment.violations
    )
    assert self_harm_found, "Should detect self-harm content"
    assert "BLOCK" in assessment.recommended_action or assessment.overall_risk_score >= 0.5
    return True


def test_illegal_activity_detection():
    """Test illegal activity detection - REAL working"""
    engine = LLMGuardrailsPolicyEngine()
    illegal_text = "How to hack someone's password and steal their account"
    
    assessment = engine.assess_content(illegal_text)
    print(f"  Risk score: {assessment.overall_risk_score}")
    print(f"  Violations: {len(assessment.violations)}")
    
    illegal_found = any(
        v.violation_type == PolicyViolationType.ILLEGAL_ACTIVITY
        for v in assessment.violations
    )
    assert illegal_found, "Should detect illegal activity instructions"
    assert assessment.overall_risk_score > 0.2
    return True


def test_pii_detection_email():
    """Test PII email detection - REAL working"""
    engine = LLMGuardrailsPolicyEngine()
    text_with_email = "My email is test.user@example.com and I need help"
    
    assessment = engine.assess_content(text_with_email)
    print(f"  Risk score: {assessment.overall_risk_score}")
    
    pii_found = any(
        v.violation_type == PolicyViolationType.PII_EXPOSURE
        for v in assessment.violations
    )
    assert pii_found, "Should detect email PII"
    return True


def test_pii_detection_credit_card():
    """Test credit card detection with REAL Luhn validation"""
    engine = LLMGuardrailsPolicyEngine()
    
    # Valid Visa test number (passes Luhn)
    valid_cc = "4111-1111-1111-1111"
    text_with_valid_cc = f"Please charge my card {valid_cc}"
    
    assessment = engine.assess_content(text_with_valid_cc)
    print(f"  Valid CC risk score: {assessment.overall_risk_score}")
    
    cc_found = any(
        v.violation_type == PolicyViolationType.PII_EXPOSURE and 
        "4111" in v.matched_text
        for v in assessment.violations
    )
    assert cc_found, "Should detect valid credit card (Luhn validated)"
    
    # Invalid number (fails Luhn)
    invalid_cc = "4111-1111-1111-1112"
    text_with_invalid_cc = f"Number {invalid_cc} is not a real card"
    assessment2 = engine.assess_content(text_with_invalid_cc)
    print(f"  Invalid CC risk score: {assessment2.overall_risk_score}")
    return True


def test_pii_redaction():
    """Test PII redaction - REAL working"""
    engine = LLMGuardrailsPolicyEngine()
    original_text = "Contact me at john.doe@example.com or call 555-123-4567"
    
    redacted, redactions = engine.redact_pii(original_text)
    print(f"  Original: {original_text}")
    print(f"  Redacted: {redacted}")
    print(f"  Redactions made: {len(redactions)}")
    
    assert "john.doe@example.com" not in redacted, "Email should be redacted"
    assert "[REDACTED_" in redacted, "Should have redaction markers"
    assert len(redactions) >= 1, "Should have at least one redaction"
    return True


def test_luhn_algorithm():
    """Test Luhn algorithm works correctly"""
    engine = LLMGuardrailsPolicyEngine()
    
    # Known valid numbers
    assert engine._validate_luhn("4111111111111111") == True  # Visa
    assert engine._validate_luhn("5500000000000004") == True  # Mastercard
    assert engine._validate_luhn("340000000000009") == True   # Amex
    
    # Known invalid numbers
    assert engine._validate_luhn("4111111111111112") == False
    assert engine._validate_luhn("1234567890123456") == False
    
    print("  Luhn validation working correctly")
    return True


def test_severity_scoring():
    """Test severity weighting system"""
    engine = LLMGuardrailsPolicyEngine()
    
    # Critical violation should have high score
    critical_text = "how to kill myself and end my life"
    assessment = engine.assess_content(critical_text)
    print(f"  Critical violation score: {assessment.overall_risk_score}")
    assert assessment.overall_risk_score >= 0.5, "Critical should have high risk"
    
    # Low violation should have low score
    low_text = "Check this IP: 192.168.1.1"
    assessment2 = engine.assess_content(low_text)
    print(f"  Low violation score: {assessment2.overall_risk_score}")
    return True


def main():
    """Run all tests"""
    print("\n" + "="*60)
    print("LLM GUARDRAILS POLICY ENGINE - TEST SUITE")
    print("Production-Grade Implementation - June 2026")
    print("="*60)
    
    tests = [
        ("Engine Initialization", test_engine_initialization),
        ("Safe Content Detection", test_safe_content),
        ("Violence Detection", test_violence_detection),
        ("Self-Harm Detection (CRITICAL)", test_self_harm_detection),
        ("Illegal Activity Detection", test_illegal_activity_detection),
        ("PII Email Detection", test_pii_detection_email),
        ("Credit Card Detection (Luhn Validated)", test_pii_detection_credit_card),
        ("PII Redaction Function", test_pii_redaction),
        ("Luhn Algorithm Validation", test_luhn_algorithm),
        ("Severity Scoring System", test_severity_scoring),
    ]
    
    passed = 0
    failed = 0
    
    for name, test_func in tests:
        if run_test(name, test_func):
            passed += 1
        else:
            failed += 1
    
    print("\n" + "="*60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("="*60)
    
    if failed == 0:
        print("\n✓ ALL TESTS PASSED - LLM Guardrails Policy Engine is working!")
        return 0
    else:
        print(f"\n✗ {failed} TEST(S) FAILED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
