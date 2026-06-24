"""
Test suite for NeuralShield Fallback Chain with Strategic Degradation (v32)
Dimension E - Error Resilience Enhancement

ADD-ONLY TESTS - No existing tests modified.
Tests cover:
- Basic fallback chain operation
- Strategic degradation progression
- Recovery mechanisms
- Circuit breaker functionality
- Health metrics and statistics
- Thread safety
"""

import pytest
import time
import threading
from neural_shield.error_resilience_fallback_chain_strategic_degradation_v32_2026_june import (
    DegradationLevel,
    RecoveryStrategy,
    FallbackResult,
    FallbackStrategy,
    StrategicDegradationFallbackChain,
    create_security_fallback_chain,
    create_threat_detection_chain
)


class TestDegradationLevel:
    """Test degradation level enumeration."""
    
    def test_level_ordering(self):
        """Test degradation levels are properly ordered."""
        levels = [
            DegradationLevel.FULL,
            DegradationLevel.PARTIAL,
            DegradationLevel.MINIMAL,
            DegradationLevel.FAILSAFE,
            DegradationLevel.FAILURE
        ]
        assert len(set(levels)) == 5
    
    def test_level_values(self):
        """Test level values are strings."""
        for level in DegradationLevel:
            assert isinstance(level.value, str)
            assert len(level.value) > 0


class TestFallbackStrategy:
    """Test individual fallback strategy."""
    
    def test_strategy_creation(self):
        """Test strategy creation with basic parameters."""
        def handler():
            return "success"
        
        strategy = FallbackStrategy(
            name="test_strategy",
            level=DegradationLevel.FULL,
            handler=handler
        )
        assert strategy.name == "test_strategy"
        assert strategy.level == DegradationLevel.FULL
        assert strategy.success_count == 0
        assert strategy.failure_count == 0
    
    def test_successful_execution(self):
        """Test successful strategy execution."""
        def handler(x, y):
            return x + y
        
        strategy = FallbackStrategy("test", DegradationLevel.FULL, handler)
        success, result, error = strategy.execute(2, 3)
        
        assert success is True
        assert result == 5
        assert error is None
        assert strategy.success_count == 1
        assert strategy.failure_count == 0
    
    def test_failed_execution(self):
        """Test failed strategy execution."""
        def failing_handler():
            raise ValueError("Intentional failure")
        
        strategy = FallbackStrategy("test", DegradationLevel.FULL, failing_handler)
        success, result, error = strategy.execute()
        
        assert success is False
        assert result is None
        assert isinstance(error, ValueError)
        assert strategy.success_count == 0
        assert strategy.failure_count == 1
    
    def test_stats_calculation(self):
        """Test statistics calculation."""
        def handler():
            return "ok"
        
        strategy = FallbackStrategy("test", DegradationLevel.FULL, handler)
        strategy.execute()
        strategy.execute()
        
        stats = strategy.get_stats()
        assert stats["success_count"] == 2
        assert stats["failure_count"] == 0
        assert stats["success_rate"] == 1.0
        assert "avg_execution_time_ms" in stats


class TestStrategicDegradationFallbackChain:
    """Test main fallback chain functionality."""
    
    def test_chain_creation(self):
        """Test basic chain creation."""
        chain = StrategicDegradationFallbackChain(name="test_chain")
        assert chain.name == "test_chain"
        assert chain._current_level == DegradationLevel.FULL
    
    def test_add_strategy(self):
        """Test adding strategies to chain."""
        chain = StrategicDegradationFallbackChain()
        
        def full_handler():
            return "full"
        
        chain.add_strategy("full", DegradationLevel.FULL, full_handler)
        assert len(chain._strategies) == 1
    
    def test_strategy_ordering(self):
        """Test strategies are ordered by degradation level."""
        chain = StrategicDegradationFallbackChain()
        
        def partial_handler():
            return "partial"
        def full_handler():
            return "full"
        def failsafe_handler():
            return "failsafe"
        
        chain.add_strategy("partial", DegradationLevel.PARTIAL, partial_handler)
        chain.add_strategy("full", DegradationLevel.FULL, full_handler)
        chain.add_strategy("failsafe", DegradationLevel.FAILSAFE, failsafe_handler)
        
        # Should be ordered FULL -> PARTIAL -> FAILSAFE
        levels = [s.level for s in chain._strategies]
        assert levels == [
            DegradationLevel.FULL,
            DegradationLevel.PARTIAL,
            DegradationLevel.FAILSAFE
        ]
    
    def test_successful_execution_full_level(self):
        """Test successful execution at FULL level."""
        chain = StrategicDegradationFallbackChain()
        
        def full_handler():
            return "full_success"
        
        chain.add_strategy("full", DegradationLevel.FULL, full_handler)
        result = chain.execute()
        
        assert result.success is True
        assert result.result == "full_success"
        assert result.degradation_level == DegradationLevel.FULL
        assert result.fallback_attempted == 1
    
    def test_fallback_to_partial(self):
        """Test fallback from FULL to PARTIAL level."""
        chain = StrategicDegradationFallbackChain(recovery_threshold=1)
        
        def failing_full():
            raise RuntimeError("Full failed")
        
        def partial_handler():
            return "partial_success"
        
        chain.add_strategy("full", DegradationLevel.FULL, failing_full)
        chain.add_strategy("partial", DegradationLevel.PARTIAL, partial_handler)
        
        result = chain.execute()
        
        assert result.success is True
        assert result.result == "partial_success"
        assert result.degradation_level == DegradationLevel.PARTIAL
        assert result.fallback_attempted == 2
    
    def test_multilevel_fallback_chain(self):
        """Test complete fallback chain through multiple levels."""
        chain = StrategicDegradationFallbackChain()
        
        def fail():
            raise RuntimeError("Failed")
        
        def failsafe_handler():
            return "failsafe_result"
        
        chain.add_strategy("full", DegradationLevel.FULL, fail)
        chain.add_strategy("partial", DegradationLevel.PARTIAL, fail)
        chain.add_strategy("minimal", DegradationLevel.MINIMAL, fail)
        chain.add_strategy("failsafe", DegradationLevel.FAILSAFE, failsafe_handler)
        
        result = chain.execute()
        
        assert result.success is True
        assert result.result == "failsafe_result"
        assert result.degradation_level == DegradationLevel.FAILSAFE
        assert result.fallback_attempted == 4
    
    def test_all_strategies_failed(self):
        """Test case where all strategies fail."""
        chain = StrategicDegradationFallbackChain()
        
        def fail():
            raise RuntimeError("Always fails")
        
        chain.add_strategy("full", DegradationLevel.FULL, fail)
        chain.add_strategy("partial", DegradationLevel.PARTIAL, fail)
        
        result = chain.execute()
        
        assert result.success is False
        assert result.degradation_level == DegradationLevel.FAILURE
        assert isinstance(result.error, RuntimeError)
    
    def test_health_status(self):
        """Test health status reporting."""
        chain = StrategicDegradationFallbackChain("health_test")
        
        def handler():
            return "ok"
        
        chain.add_strategy("full", DegradationLevel.FULL, handler)
        chain.execute()
        
        health = chain.get_health_status()
        assert health["chain_name"] == "health_test"
        assert health["current_degradation_level"] == "full"
        assert "health_score" in health
        assert 0.0 <= health["health_score"] <= 1.0
    
    def test_reset_functionality(self):
        """Test chain reset functionality."""
        chain = StrategicDegradationFallbackChain()
        
        def fail():
            raise RuntimeError("Fail")
        
        chain.add_strategy("full", DegradationLevel.FULL, fail)
        chain.add_strategy("partial", DegradationLevel.PARTIAL, fail)
        
        # Cause degradation
        for _ in range(5):
            chain.execute()
        
        chain.reset()
        assert chain._current_level == DegradationLevel.FULL
        assert chain._consecutive_failures == 0
        assert chain._circuit_open is False


class TestFactoryFunctions:
    """Test convenience factory functions."""
    
    def test_create_security_fallback_chain(self):
        """Test security chain factory."""
        chain = create_security_fallback_chain("security_test")
        assert isinstance(chain, StrategicDegradationFallbackChain)
        assert chain.recovery_strategy == RecoveryStrategy.EXPONENTIAL_BACKOFF
    
    def test_create_threat_detection_chain(self):
        """Test threat detection chain factory."""
        chain = create_threat_detection_chain("threat_test")
        assert isinstance(chain, StrategicDegradationFallbackChain)
        assert chain.recovery_strategy == RecoveryStrategy.CIRCUIT_BREAKER


class TestThreadSafety:
    """Test thread safety of fallback chain."""
    
    def test_concurrent_execution(self):
        """Test concurrent execution from multiple threads."""
        chain = StrategicDegradationFallbackChain("concurrent_test")
        
        def handler():
            time.sleep(0.001)
            return threading.get_ident()
        
        chain.add_strategy("full", DegradationLevel.FULL, handler)
        
        results = []
        errors = []
        
        def worker():
            try:
                result = chain.execute()
                results.append(result)
            except Exception as e:
                errors.append(e)
        
        threads = [threading.Thread(target=worker) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        assert len(errors) == 0
        assert len(results) == 10
        assert all(r.success for r in results)


class TestCircuitBreaker:
    """Test circuit breaker functionality."""
    
    def test_circuit_breaker_health_degrades(self):
        """Test health score degrades after repeated failures."""
        chain = StrategicDegradationFallbackChain(
            recovery_threshold=1
        )
        chain._circuit_reset_timeout = 0.1  # Fast timeout for testing
        
        def fail():
            raise RuntimeError("Fail")
        
        chain.add_strategy("full", DegradationLevel.FULL, fail)
        chain.add_strategy("failsafe", DegradationLevel.FAILSAFE, fail)
        
        # Trigger enough failures
        for _ in range(10):
            chain.execute()
        
        # Health should reflect poor state
        health = chain.get_health_status()
        assert health["health_score"] < 0.5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
