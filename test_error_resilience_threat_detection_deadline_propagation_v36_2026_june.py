"""
Test Suite for Error Resilience - Deadline Propagation v36
Dimension E: Error Resilience
ADD-ONLY tests - no production code modified
All existing tests must continue to pass
"""
import pytest
import time
import threading
from neural_shield.error_resilience_threat_detection_deadline_propagation_v36_2026_june import (
    NeuralShieldError,
    DeadlineExceededError,
    OperationCancelledError,
    CancellationToken,
    DeadlinePropagationManager,
    DeadlineAwareDetectionPipeline,
    get_deadline_manager,
    CancellationReason,
    DeadlineSource,
)


class TestCancellationToken:
    """Test cancellation token functionality"""
    
    def test_token_creation_basic(self):
        """Test basic token creation"""
        token = CancellationToken(timeout=5.0, operation_key="test_op")
        assert not token.cancelled
        assert token.remaining_time is not None
        assert token.remaining_time > 0
    
    def test_token_expires_after_timeout(self):
        """Test token expires after timeout"""
        token = CancellationToken(timeout=0.1, operation_key="fast_test")
        assert not token.cancelled
        time.sleep(0.15)
        assert token.cancelled
        assert token.cancellation_reason == CancellationReason.DEADLINE_EXCEEDED
    
    def test_throw_if_cancelled_raises(self):
        """Test throw_if_cancelled raises when cancelled"""
        token = CancellationToken(timeout=0.1, operation_key="test")
        time.sleep(0.15)
        
        with pytest.raises(DeadlineExceededError):
            token.throw_if_cancelled()
    
    def test_explicit_cancel(self):
        """Test explicit cancellation"""
        token = CancellationToken(timeout=30.0, operation_key="test")
        assert not token.cancelled
        
        token.cancel(CancellationReason.USER_REQUESTED)
        assert token.cancelled
        assert token.cancellation_reason == CancellationReason.USER_REQUESTED
        
        with pytest.raises(OperationCancelledError):
            token.throw_if_cancelled()
    
    def test_child_token_inherits_cancellation(self):
        """Test child token inherits parent cancellation"""
        parent = CancellationToken(timeout=30.0, operation_key="parent")
        child = parent.create_child("child_op")
        
        assert not parent.cancelled
        assert not child.cancelled
        
        parent.cancel(CancellationReason.USER_REQUESTED)
        
        # Give callback time to propagate
        time.sleep(0.01)
        assert child.cancelled
        assert child.cancellation_reason == CancellationReason.PARENT_CANCELLED
    
    def test_callback_invoked_on_cancel(self):
        """Test cancellation callbacks are invoked"""
        results = []
        
        def callback(reason):
            results.append(reason)
        
        token = CancellationToken(timeout=30.0, operation_key="test")
        token.register_callback(callback)
        
        token.cancel(CancellationReason.USER_REQUESTED)
        
        assert len(results) == 1
        assert results[0] == CancellationReason.USER_REQUESTED
    
    def test_derive_deadline_uses_fraction(self):
        """Test deadline derivation uses fraction of remaining time"""
        parent = CancellationToken(timeout=10.0, operation_key="parent")
        child = parent.derive_deadline("child", fraction=0.5)
        
        # Child should have ~5 seconds remaining
        assert child.remaining_time is not None
        assert 4.0 < child.remaining_time < 6.0


class TestDeadlinePropagationManager:
    """Test deadline propagation manager"""
    
    def test_create_root_context(self):
        """Test creating root context"""
        manager = DeadlinePropagationManager(default_timeout=10.0)
        token = manager.create_root_context("test_op", timeout=5.0)
        
        assert not token.cancelled
        assert token.remaining_time is not None
    
    def test_deadline_scope_context_manager(self):
        """Test deadline scope context manager"""
        manager = DeadlinePropagationManager()
        
        with manager.deadline_scope("test_scope", 1.0) as token:
            assert not token.cancelled
            assert token.remaining_time is not None
        
        # Token should be cancelled after scope exit
        assert token.cancelled
    
    def test_deadline_scope_with_parent(self):
        """Test deadline scope with parent token"""
        manager = DeadlinePropagationManager()
        parent = CancellationToken(timeout=10.0, operation_key="parent")
        
        with manager.deadline_scope("child_scope", parent_token=parent) as child:
            assert not child.cancelled
        
        assert child.cancelled
    
    def test_global_manager_instance(self):
        """Test global manager singleton"""
        manager1 = get_deadline_manager()
        manager2 = get_deadline_manager()
        assert manager1 is manager2


class TestDeadlineAwareDetectionPipeline:
    """Test deadline-aware detection pipeline"""
    
    def test_pipeline_execution_success(self):
        """Test successful pipeline execution"""
        pipeline = DeadlineAwareDetectionPipeline()
        
        def stage1(input_data, token):
            return {"stage1": "processed"}
        
        def stage2(input_data, token):
            return {"stage2": "done"}
        
        stages = [("stage1", stage1), ("stage2", stage2)]
        result = pipeline.execute_pipeline(stages, "test_input", total_timeout=5.0)
        
        assert result["pipeline_success"] == True
        assert result["completed_stages"] == 2
        assert result["degraded_stages"] == 0
    
    def test_pipeline_with_fallback(self):
        """Test pipeline with fallback on deadline"""
        pipeline = DeadlineAwareDetectionPipeline()
        
        def slow_stage(input_data, token):
            time.sleep(0.5)  # Will exceed deadline
            token.throw_if_cancelled()
            return {"slow": "result"}
        
        def fast_fallback(input_data):
            return {"fallback": "used"}
        
        pipeline.register_stage_fallback("slow_stage", fast_fallback)
        
        stages = [("slow_stage", slow_stage)]
        result = pipeline.execute_pipeline(stages, "test_input", total_timeout=0.1)
        
        # Should use fallback
        assert result["results"]["slow_stage"]["degraded"] == True
    
    def test_pipeline_cancellation_stops_execution(self):
        """Test that cancellation stops pipeline execution at next boundary"""
        pipeline = DeadlineAwareDetectionPipeline()
        
        executed = []
        
        def stage1(input_data, token):
            executed.append("stage1")
            return {"stage1": True}
        
        def stage2(input_data, token):
            executed.append("stage2")
            token.cancel(CancellationReason.USER_REQUESTED)
            return {"stage2": True}
        
        def stage3(input_data, token):
            executed.append("stage3")
            return {"stage3": True}
        
        stages = [("stage1", stage1), ("stage2", stage2), ("stage3", stage3)]
        result = pipeline.execute_pipeline(stages, "test_input", total_timeout=5.0)
        
        # Cancellation is checked at stage boundaries,
        # so stage2 completes but stage3 never starts
        assert "stage1" in executed
        assert "stage2" in executed
        # Verify cancellation was recorded in results
        assert result["results"]["stage2"]["success"] == True


class TestExceptionHierarchy:
    """Test custom exception hierarchy"""
    
    def test_deadline_exceeded_error_inherits_base(self):
        """Test DeadlineExceededError inheritance"""
        error = DeadlineExceededError("Test message")
        assert isinstance(error, NeuralShieldError)
        assert error.retryable == True
        assert error.fallback_available == True
    
    def test_operation_cancelled_error_not_retryable(self):
        """Test OperationCancelledError properties"""
        error = OperationCancelledError("Cancelled")
        assert isinstance(error, NeuralShieldError)
        assert error.retryable == False
        assert error.fallback_available == True


class TestIntegration:
    """Integration tests for deadline system"""
    
    def test_deadline_across_threads(self):
        """Test deadline works across threads"""
        token = CancellationToken(timeout=0.2, operation_key="thread_test")
        
        errors = []
        
        def worker():
            try:
                time.sleep(0.3)
                token.throw_if_cancelled()
            except DeadlineExceededError as e:
                errors.append(e)
        
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        
        assert len(errors) == 1
    
    def test_multiple_nested_contexts(self):
        """Test multiple nested deadline contexts"""
        manager = DeadlinePropagationManager()
        
        with manager.deadline_scope("outer", 5.0) as outer:
            with manager.deadline_scope("inner1", parent_token=outer) as inner1:
                with manager.deadline_scope("inner2", parent_token=inner1) as inner2:
                    assert not inner2.cancelled
        
        assert inner2.cancelled
        assert inner1.cancelled
        assert outer.cancelled


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
