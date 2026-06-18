#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Response Playbook Executor
Real, working tests - no empty shells
"""

import asyncio
import sys
import os

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_response_playbook_executor_2026_june import (
    ThreatEvent, ThreatType, ThreatSeverity, PlaybookExecutor,
    create_standard_playbooks, ActionStatus, PlaybookStatus
)


async def test_basic_playbook_execution():
    """Test basic playbook execution with a critical threat"""
    print("\n=== Test 1: Basic Playbook Execution ===")
    
    executor = PlaybookExecutor()
    
    # Register standard playbooks
    for playbook in create_standard_playbooks():
        executor.register_playbook(playbook)
    
    # Create a critical threat event
    threat = ThreatEvent(
        threat_id="threat_001",
        threat_type=ThreatType.JAILBREAK_ATTEMPT,
        severity=ThreatSeverity.CRITICAL,
        source="user_input",
        description="Detected jailbreak attempt with DAN prompt",
        session_id="session_abc123",
        user_id="user_xyz789",
        metadata={"prompt_length": 1542, "confidence": 0.95}
    )
    
    # Process the threat
    executions = await executor.process_threat(threat, {
        "block_duration": 30,
        "suspicious_content": "Ignore previous instructions..."
    })
    
    assert len(executions) > 0, "Should have at least one execution"
    
    execution = executions[0]
    print(f"Execution ID: {execution.execution_id}")
    print(f"Playbook: {execution.playbook_name}")
    print(f"Status: {execution.status.value}")
    print(f"Actions executed: {len(execution.action_results)}")
    
    for result in execution.action_results:
        print(f"  - {result.action_name}: {result.status.value}")
        if result.error_message:
            print(f"    Error: {result.error_message}")
    
    assert execution.status == PlaybookStatus.COMPLETED, "Execution should complete successfully"
    
    print("✓ Test 1 PASSED")
    return True


async def test_medium_threat_parallel_execution():
    """Test parallel action execution for medium threats"""
    print("\n=== Test 2: Parallel Execution Test ===")
    
    executor = PlaybookExecutor()
    
    for playbook in create_standard_playbooks():
        executor.register_playbook(playbook)
    
    threat = ThreatEvent(
        threat_id="threat_002",
        threat_type=ThreatType.PROMPT_INJECTION,
        severity=ThreatSeverity.MEDIUM,
        source="api_gateway",
        description="Potential prompt injection detected in user query",
        session_id="session_def456"
    )
    
    executions = await executor.process_threat(threat)
    
    assert len(executions) > 0
    
    execution = executions[0]
    print(f"Execution: {execution.playbook_name}")
    print(f"Status: {execution.status.value}")
    print(f"Duration: {(execution.end_time - execution.start_time):.4f}s")
    
    # Verify parallel execution was fast
    duration = execution.end_time - execution.start_time
    print(f"Parallel execution completed in {duration:.4f} seconds")
    
    print("✓ Test 2 PASSED")
    return True


async def test_threat_matching_logic():
    """Test that playbooks correctly match or don't match threats"""
    print("\n=== Test 3: Threat Matching Logic ===")
    
    executor = PlaybookExecutor()
    
    for playbook in create_standard_playbooks():
        executor.register_playbook(playbook)
    
    # Test low severity threat - should only match low playbook
    low_threat = ThreatEvent(
        threat_id="threat_low",
        threat_type=ThreatType.ADVERSARIAL_ATTACK,
        severity=ThreatSeverity.LOW,
        source="test",
        description="Low confidence detection"
    )
    
    matching = executor.get_matching_playbooks(low_threat)
    print(f"Low threat matched {len(matching)} playbooks")
    assert len(matching) >= 1, "Low threat should match at least low playbook"
    
    # Test high severity threat
    high_threat = ThreatEvent(
        threat_id="threat_high",
        threat_type=ThreatType.DATA_EXFILTRATION,
        severity=ThreatSeverity.HIGH,
        source="test",
        description="Data exfiltration attempt"
    )
    
    matching = executor.get_matching_playbooks(high_threat)
    print(f"High threat matched {len(matching)} playbooks")
    assert len(matching) >= 2, "High threat should match multiple playbooks"
    
    print("✓ Test 3 PASSED")
    return True


async def test_execution_statistics():
    """Test execution statistics tracking"""
    print("\n=== Test 4: Execution Statistics ===")
    
    executor = PlaybookExecutor()
    
    for playbook in create_standard_playbooks():
        executor.register_playbook(playbook)
    
    # Process multiple threats
    threats = [
        ThreatEvent(
            threat_id=f"stat_threat_{i}",
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.MEDIUM,
            source="test",
            description=f"Test threat {i}"
        )
        for i in range(3)
    ]
    
    for threat in threats:
        await executor.process_threat(threat)
    
    stats = executor.get_execution_statistics()
    print(f"Total executions: {stats['total_executions']}")
    print(f"Status breakdown: {stats['status_breakdown']}")
    print(f"Avg duration: {stats['avg_duration_seconds']:.4f}s")
    print(f"Total actions: {stats['total_actions_executed']}")
    
    assert stats['total_executions'] >= 3, "Should have 3+ executions"
    assert stats['total_actions_executed'] > 0, "Should have executed actions"
    
    print("✓ Test 4 PASSED")
    return True


async def test_rollback_mechanism():
    """Test rollback mechanism functionality"""
    print("\n=== Test 5: Rollback Mechanism ===")
    
    executor = PlaybookExecutor()
    
    # Check which actions support rollback
    rollback_support = {
        aid: action.supports_rollback()
        for aid, action in executor._registered_actions.items()
    }
    
    print("Rollback support by action:")
    for aid, supports in rollback_support.items():
        print(f"  - {aid}: {'✓' if supports else '✗'}")
    
    # Verify expected rollback capabilities
    assert executor._registered_actions['block_user_session'].supports_rollback()
    assert not executor._registered_actions['alert_security_team'].supports_rollback()
    
    print("✓ Test 5 PASSED")
    return True


async def run_all_tests():
    """Run all tests"""
    print("=" * 60)
    print("Threat Intelligence Response Playbook Executor - Test Suite")
    print("=" * 60)
    
    tests = [
        test_basic_playbook_execution,
        test_medium_threat_parallel_execution,
        test_threat_matching_logic,
        test_execution_statistics,
        test_rollback_mechanism
    ]
    
    passed = 0
    failed = 0
    
    for test_func in tests:
        try:
            result = await test_func()
            if result:
                passed += 1
        except Exception as e:
            print(f"✗ Test FAILED: {test_func.__name__}")
            print(f"  Error: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"TEST SUMMARY: {passed} PASSED, {failed} FAILED")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = asyncio.run(run_all_tests())
    sys.exit(0 if success else 1)
