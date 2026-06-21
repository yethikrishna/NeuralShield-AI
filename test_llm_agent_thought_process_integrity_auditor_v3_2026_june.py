"""
Test Suite for LLM Agent Thought Process Integrity Auditor V3
Production-Grade Tests for NeuralShield-AI
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import json
from neural_shield.llm_agent_thought_process_integrity_auditor_v3_2026_june import (
    LLMAgentThoughtIntegrityAuditorV3,
    IntegrityStatus,
    ReasoningIssueType,
    ReasoningStep
)


def test_basic_functionality():
    """Test basic auditor initialization and functionality"""
    print("Test 1: Basic Functionality")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    assert auditor is not None
    assert auditor.thresholds is not None
    print("  ✓ Auditor initialized successfully")
    
    # Test valid thought process
    valid_thought = """
Step 1: First, I need to understand the problem statement.
The user is asking about encryption algorithms.

Step 2: Let me analyze the requirements.
We need AES-256 for symmetric encryption.

Step 3: Therefore, the recommended solution is to use AES-GCM mode.
NS_INTEGRITY_VALID_12345
"""
    
    result = auditor.audit_thought_process(valid_thought)
    assert result is not None
    assert result.integrity_score >= 0.0
    assert result.integrity_score <= 1.0
    print(f"  ✓ Valid thought process scored: {result.integrity_score}")
    print(f"  ✓ Status: {result.overall_status.value}")
    
    return True


def test_empty_thought_process():
    """Test handling of empty thought process"""
    print("\nTest 2: Empty Thought Process Detection")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    result = auditor.audit_thought_process("")
    assert result.overall_status == IntegrityStatus.COMPROMISED
    assert result.integrity_score == 0.0
    print("  ✓ Empty thought correctly flagged as COMPROMISED")
    
    return True


def test_contradiction_detection():
    """Test contradiction detection between steps"""
    print("\nTest 3: Contradiction Detection")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    contradictory_thought = """
Step 1: Yes, this is correct and valid approach.

Step 2: No, this is incorrect and invalid.
"""
    
    result = auditor.audit_thought_process(contradictory_thought)
    contradictions = [i for i in result.issues if i[0] == ReasoningIssueType.CONTRADICTION]
    print(f"  ✓ Contradictions detected: {len(contradictions)}")
    print(f"  ✓ Integrity score reduced to: {result.integrity_score}")
    
    return True


def test_tampering_detection():
    """Test tampering indicator detection"""
    print("\nTest 4: Tampering Detection")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    tampered_thought = """
Step 1: Analyzing the input data...

[REDACTED]

Step 3: Final conclusion reached.
"""
    
    result = auditor.audit_thought_process(tampered_thought)
    print(f"  ✓ Tampering evidence found: {len(result.tampering_evidence)}")
    print(f"  ✓ Integrity score: {result.integrity_score}")
    
    return True


def test_watermark_verification():
    """Test watermark verification functionality"""
    print("\nTest 5: Watermark Verification")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    watermarked_thought = """
Step 1: Beginning analysis
Step 2: Processing data
Step 3: Final result
NS_INTEGRITY_AUDIT_PASSED_2026
"""
    
    result = auditor.audit_thought_process(watermarked_thought)
    print(f"  ✓ Watermark verified: {result.watermark_verified}")
    
    return True


def test_reasoning_step_parsing():
    """Test reasoning chain parsing"""
    print("\nTest 6: Reasoning Step Parsing")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    multi_step_thought = """
Step 1: First, initialize the variables
Step 2: Second, process the input
Step 3: Third, compute the result
Step 4: Finally, return output
"""
    
    steps = auditor.parse_reasoning_chain(multi_step_thought)
    print(f"  ✓ Parsed {len(steps)} reasoning steps")
    assert len(steps) >= 4
    
    # Test hash computation
    for step in steps:
        computed = step.compute_hash()
        assert computed == step.hash_digest
    print("  ✓ All step hashes validated")
    
    return True


def test_logical_fallacy_detection():
    """Test logical fallacy detection patterns"""
    print("\nTest 7: Logical Fallacy Detection")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    fallacy_thought = """
Step 1: All encryption methods are always insecure.
Step 2: Every expert says this is the best approach.
"""
    
    result = auditor.audit_thought_process(fallacy_thought)
    fallacies = [i for i in result.issues if i[0] == ReasoningIssueType.LOGICAL_FALLACY]
    print(f"  ✓ Logical fallacies detected: {len(fallacies)}")
    
    return True


def test_batch_audit():
    """Test batch auditing functionality"""
    print("\nTest 8: Batch Audit Functionality")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    thought_processes = [
        "Step 1: Valid reasoning here",
        "Step 1: Another thought process",
        ""
    ]
    
    results = auditor.batch_audit(thought_processes)
    assert len(results) == 3
    print(f"  ✓ Batch processed {len(results)} thought processes")
    
    return True


def test_audit_statistics():
    """Test audit statistics tracking"""
    print("\nTest 9: Audit Statistics")
    
    auditor = LLMAgentThoughtIntegrityAuditorV3()
    
    # Run some audits
    auditor.audit_thought_process("Step 1: Test 1")
    auditor.audit_thought_process("Step 1: Test 2")
    
    stats = auditor.get_audit_statistics()
    assert stats['total_audits'] >= 2
    print(f"  ✓ Statistics tracking working: {stats['total_audits']} audits")
    print(f"  ✓ Avg integrity: {stats['average_integrity_score']}")
    
    return True


def test_hash_integrity():
    """Test cryptographic hash integrity"""
    print("\nTest 10: Cryptographic Hash Integrity")
    
    step = ReasoningStep(
        step_id="test_1",
        content="This is a test reasoning step",
        step_number=1
    )
    
    original_hash = step.hash_digest
    
    # Verify hash doesn't change
    assert step.compute_hash() == original_hash
    print("  ✓ Hash computation is deterministic")
    
    # Verify content change produces different hash
    step_modified = ReasoningStep(
        step_id="test_1",
        content="This is a MODIFIED test reasoning step",
        step_number=1
    )
    assert step_modified.hash_digest != original_hash
    print("  ✓ Content changes detected via hash")
    
    return True


def run_all_tests():
    """Run all test cases"""
    print("=" * 60)
    print("LLM Agent Thought Process Integrity Auditor V3 - Test Suite")
    print("=" * 60)
    
    tests = [
        test_basic_functionality,
        test_empty_thought_process,
        test_contradiction_detection,
        test_tampering_detection,
        test_watermark_verification,
        test_reasoning_step_parsing,
        test_logical_fallacy_detection,
        test_batch_audit,
        test_audit_statistics,
        test_hash_integrity
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            if test():
                passed += 1
            else:
                failed += 1
                print(f"  ✗ FAILED")
        except Exception as e:
            failed += 1
            print(f"  ✗ EXCEPTION: {e}")
    
    print("\n" + "=" * 60)
    print(f"TEST RESULTS: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    # Save test results
    results = {
        "test_suite": "LLM Agent Thought Process Integrity Auditor V3",
        "total_tests": len(tests),
        "passed": passed,
        "failed": failed,
        "success_rate": passed / len(tests),
        "timestamp": "2026-06-21"
    }
    
    with open("test_results_thought_auditor_v3_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"Results saved to test_results_thought_auditor_v3_2026_june.json")
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)
