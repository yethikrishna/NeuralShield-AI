"""
Test Suite for NeuralShield-AI Threat Intelligence Incident Playbook Executor
June 18, 2026

Production-grade tests verifying all functionality of the playbook executor.
"""

import asyncio
import pytest
import logging
import json
from datetime import datetime, timezone

import sys
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI/neural_shield')
from threat_intelligence_incident_playbook_executor_2026_june import (
    IncidentPlaybookExecutor,
    IncidentContext,
    IncidentType,
    SeverityLevel,
    PlaybookStatus,
    StepStatus,
    PlaybookLibrary
)


logging.basicConfig(level=logging.INFO)


class TestPlaybookLibrary:
    """Tests for the PlaybookLibrary class"""

    def test_library_initialization(self):
        """Test that library initializes with default playbooks"""
        library = PlaybookLibrary()
        matches = library.get_matching_playbooks(
            IncidentType.PROMPT_INJECTION,
            SeverityLevel.MEDIUM
        )
        assert len(matches) > 0
        assert "prompt_injection_response" in matches

    def test_severity_matching(self):
        """Test that severity matching works correctly"""
        library = PlaybookLibrary()
        
        # Critical should match medium+ playbooks
        matches = library.get_matching_playbooks(
            IncidentType.PROMPT_INJECTION,
            SeverityLevel.CRITICAL
        )
        assert "prompt_injection_response" in matches

    def test_incident_type_matching(self):
        """Test incident type matching"""
        library = PlaybookLibrary()
        
        matches = library.get_matching_playbooks(
            IncidentType.DATA_LEAKAGE,
            SeverityLevel.CRITICAL
        )
        assert "data_leakage_response" in matches

    def test_no_match_low_severity(self):
        """Test low severity doesn't trigger high severity playbooks"""
        library = PlaybookLibrary()
        
        # LOW severity shouldn't match CRITICAL-only playbooks
        matches = library.get_matching_playbooks(
            IncidentType.DATA_LEAKAGE,
            SeverityLevel.LOW
        )
        assert "data_leakage_response" not in matches


class TestIncidentPlaybookExecutor:
    """Tests for the IncidentPlaybookExecutor class"""

    @pytest.mark.asyncio
    async def test_executor_initialization(self):
        """Test executor initializes properly"""
        executor = IncidentPlaybookExecutor()
        assert executor.library is not None
        assert len(executor._built_in_actions) > 0

    @pytest.mark.asyncio
    async def test_create_playbook_steps(self):
        """Test playbook step creation"""
        executor = IncidentPlaybookExecutor()
        
        steps = executor.create_playbook_steps("prompt_injection_response")
        assert len(steps) > 0
        assert all(s.step_id for s in steps)
        assert all(s.name for s in steps)

    @pytest.mark.asyncio
    async def test_execute_prompt_injection_playbook(self):
        """Test full execution of prompt injection playbook"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-001",
            incident_type=IncidentType.PROMPT_INJECTION,
            severity=SeverityLevel.HIGH,
            source="user_input",
            description="Detected potential prompt injection attempt",
            metadata={"user_id": "user_123", "session_id": "sess_456"}
        )
        
        result = await executor.execute_playbook(context)
        
        assert result.execution_id is not None
        assert result.status == PlaybookStatus.COMPLETED
        assert len(result.steps) > 0
        assert all(s.status == StepStatus.SUCCEEDED for s in result.steps)
        assert result.started_at is not None
        assert result.completed_at is not None

    @pytest.mark.asyncio
    async def test_execute_data_leakage_playbook(self):
        """Test execution of data leakage response playbook"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-002",
            incident_type=IncidentType.DATA_LEAKAGE,
            severity=SeverityLevel.CRITICAL,
            source="model_output",
            description="Critical: Potential PII leakage detected",
            metadata={"user_id": "user_789", "pii_detected": True}
        )
        
        result = await executor.execute_playbook(context, "data_leakage_response")
        
        assert result.status == PlaybookStatus.COMPLETED
        assert len(result.steps) == 5  # 5 steps in data leakage playbook

    @pytest.mark.asyncio
    async def test_execute_rag_poisoning_playbook(self):
        """Test execution of RAG poisoning response playbook"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-003",
            incident_type=IncidentType.RAG_POISONING,
            severity=SeverityLevel.HIGH,
            source="rag_context",
            description="Detected poisoned document in RAG context",
            metadata={"document_id": "doc_123", "poison_score": 0.89}
        )
        
        result = await executor.execute_playbook(context)
        
        assert result.status == PlaybookStatus.COMPLETED
        assert result.playbook_name == "rag_poisoning_response"

    @pytest.mark.asyncio
    async def test_execute_model_extraction_playbook(self):
        """Test execution of model extraction defense playbook"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-004",
            incident_type=IncidentType.MODEL_EXTRACTION,
            severity=SeverityLevel.HIGH,
            source="api_gateway",
            description="Suspicious query patterns indicating extraction attempt",
            metadata={"query_rate": 150, "pattern_match": True}
        )
        
        result = await executor.execute_playbook(context)
        
        assert result.status == PlaybookStatus.COMPLETED
        assert result.playbook_name == "model_extraction_defense"

    @pytest.mark.asyncio
    async def test_auto_playbook_selection(self):
        """Test automatic playbook selection based on incident"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-005",
            incident_type=IncidentType.JAILBREAK_ATTEMPT,
            severity=SeverityLevel.MEDIUM,
            source="user_input",
            description="Jailbreak pattern detected"
        )
        
        result = await executor.execute_playbook(context)
        
        # Should auto-select prompt_injection_response for jailbreak
        assert result.playbook_name == "prompt_injection_response"
        assert result.status == PlaybookStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_execution_summary(self):
        """Test execution summary statistics"""
        executor = IncidentPlaybookExecutor()
        
        # Execute multiple playbooks
        for i in range(3):
            context = IncidentContext(
                incident_id=f"INC-TEST-{i}",
                incident_type=IncidentType.PROMPT_INJECTION,
                severity=SeverityLevel.MEDIUM,
                source="test",
                description=f"Test incident {i}"
            )
            await executor.execute_playbook(context)
        
        summary = executor.get_execution_summary()
        
        assert summary["total_executions"] == 3
        assert summary["total_steps_executed"] > 0
        assert summary["success_rate"] == 100.0
        assert summary["audit_log_entries"] > 0

    @pytest.mark.asyncio
    async def test_audit_log_export(self):
        """Test audit log export functionality"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-AUDIT-001",
            incident_type=IncidentType.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
            source="test",
            description="Audit test incident"
        )
        
        await executor.execute_playbook(context)
        
        log_json = executor.export_audit_log()
        log_data = json.loads(log_json)
        
        assert len(log_data) > 0
        assert "timestamp" in log_data[0]
        assert "action" in log_data[0]
        assert "context" in log_data[0]

    @pytest.mark.asyncio
    async def test_get_execution_by_id(self):
        """Test retrieving execution by ID"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-GET-001",
            incident_type=IncidentType.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
            source="test",
            description="Test retrieval"
        )
        
        result = await executor.execute_playbook(context)
        retrieved = executor.get_execution(result.execution_id)
        
        assert retrieved is not None
        assert retrieved.execution_id == result.execution_id
        assert retrieved.incident_context.incident_id == "INC-GET-001"

    @pytest.mark.asyncio
    async def test_builtin_actions_exist(self):
        """Test all built-in actions are available"""
        executor = IncidentPlaybookExecutor()
        
        expected_actions = [
            "log_incident",
            "block_user",
            "quarantine_session",
            "sanitize_output",
            "notify_administrators",
            "trigger_rate_limit",
            "capture_forensics",
            "isolate_context"
        ]
        
        for action in expected_actions:
            assert action in executor._built_in_actions
            assert callable(executor._built_in_actions[action])

    @pytest.mark.asyncio
    async def test_step_execution_timing(self):
        """Test that execution timing is recorded"""
        executor = IncidentPlaybookExecutor()
        
        context = IncidentContext(
            incident_id="INC-TIME-001",
            incident_type=IncidentType.PROMPT_INJECTION,
            severity=SeverityLevel.MEDIUM,
            source="test",
            description="Timing test"
        )
        
        result = await executor.execute_playbook(context)
        
        for step in result.steps:
            assert step.execution_time_ms >= 0.0
            assert step.status == StepStatus.SUCCEEDED


def run_tests():
    """Run all tests and report results"""
    print("=" * 70)
    print("NeuralShield-AI: Incident Playbook Executor - Test Suite")
    print("June 18, 2026")
    print("=" * 70)
    
    # Run library tests
    print("\n[1] Running PlaybookLibrary tests...")
    lib_tests = TestPlaybookLibrary()
    lib_tests.test_library_initialization()
    lib_tests.test_severity_matching()
    lib_tests.test_incident_type_matching()
    lib_tests.test_no_match_low_severity()
    print("    ✓ All PlaybookLibrary tests passed")
    
    # Run executor tests
    print("\n[2] Running IncidentPlaybookExecutor tests...")
    
    async def run_async_tests():
        executor_tests = TestIncidentPlaybookExecutor()
        await executor_tests.test_executor_initialization()
        await executor_tests.test_create_playbook_steps()
        await executor_tests.test_execute_prompt_injection_playbook()
        await executor_tests.test_execute_data_leakage_playbook()
        await executor_tests.test_execute_rag_poisoning_playbook()
        await executor_tests.test_execute_model_extraction_playbook()
        await executor_tests.test_auto_playbook_selection()
        await executor_tests.test_execution_summary()
        await executor_tests.test_audit_log_export()
        await executor_tests.test_get_execution_by_id()
        await executor_tests.test_builtin_actions_exist()
        await executor_tests.test_step_execution_timing()
        print("    ✓ All IncidentPlaybookExecutor tests passed")
    
    asyncio.run(run_async_tests())
    
    print("\n" + "=" * 70)
    print("ALL TESTS PASSED ✓")
    print("Feature: Threat Intelligence Incident Playbook Executor")
    print("Status: Production Ready")
    print("=" * 70)


if __name__ == "__main__":
    run_tests()
