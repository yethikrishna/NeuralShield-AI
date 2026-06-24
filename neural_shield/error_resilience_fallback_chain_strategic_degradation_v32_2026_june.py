"""
NeuralShield AI - Fallback Chain with Strategic Degradation (v32)
Dimension E - Error Resilience Enhancement

ADD-ONLY MODULE - No existing code modified, purely additive.
This module provides a sophisticated fallback chaining mechanism with
strategic degradation levels for graceful failure handling.

DEGRADATION LEVELS:
- FULL: Primary operation, full functionality
- PARTIAL: Reduced functionality but core features preserved  
- MINIMAL: Bare minimum functionality for basic operation
- FAILSAFE: Emergency mode, absolute minimum operation
- FAILURE: Complete failure, error propagation
"""

import time
import threading
from typing import Any, Callable, Dict, List, Optional, Tuple, Type, Union
from dataclasses import dataclass, field
from enum import Enum
from collections import deque
import logging

# Configure optional logging - OPT-IN only
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())


class DegradationLevel(Enum):
    """Degradation levels for strategic fallback progression."""
    FULL = "full"
    PARTIAL = "partial"
    MINIMAL = "minimal"
    FAILSAFE = "failsafe"
    FAILURE = "failure"


class RecoveryStrategy(Enum):
    """Recovery strategies after degradation."""
    IMMEDIATE_RETRY = "immediate_retry"
    EXPONENTIAL_BACKOFF = "exponential_backoff"
    CIRCUIT_BREAKER = "circuit_breaker"
    MANUAL_RECOVERY = "manual_recovery"


@dataclass
class FallbackResult:
    """Result container for fallback chain execution."""
    success: bool
    result: Any = None
    error: Optional[Exception] = None
    degradation_level: DegradationLevel = DegradationLevel.FULL
    fallback_attempted: int = 0
    execution_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DegradationHistory:
    """Tracks degradation events for pattern analysis."""
    timestamp: float
    level: DegradationLevel
    error_type: str
    recovery_time: Optional[float] = None


class FallbackStrategy:
    """Base class for individual fallback strategies."""
    
    def __init__(
        self,
        name: str,
        level: DegradationLevel,
        handler: Callable,
        timeout: Optional[float] = None,
        max_attempts: int = 1
    ):
        self.name = name
        self.level = level
        self.handler = handler
        self.timeout = timeout
        self.max_attempts = max_attempts
        self.success_count = 0
        self.failure_count = 0
        self.total_execution_time = 0.0
    
    def execute(self, *args, **kwargs) -> Tuple[bool, Any, Optional[Exception]]:
        """Execute this fallback strategy."""
        start_time = time.time()
        try:
            result = self.handler(*args, **kwargs)
            execution_time = (time.time() - start_time) * 1000
            self.success_count += 1
            self.total_execution_time += execution_time
            return True, result, None
        except Exception as e:
            execution_time = (time.time() - start_time) * 1000
            self.failure_count += 1
            self.total_execution_time += execution_time
            return False, None, e
    
    def get_stats(self) -> Dict[str, Any]:
        """Get performance statistics for this strategy."""
        total = self.success_count + self.failure_count
        return {
            "name": self.name,
            "level": self.level.value,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_count / total if total > 0 else 1.0,
            "avg_execution_time_ms": (
                self.total_execution_time / total if total > 0 else 0.0
            )
        }


class StrategicDegradationFallbackChain:
    """
    Main fallback chain manager with strategic degradation progression.
    
    Features:
    - Ordered fallback chain from FULL to FAILSAFE
    - Automatic degradation level progression
    - Recovery detection and automatic escalation
    - Health metrics and history tracking
    - Thread-safe operation
    """
    
    def __init__(
        self,
        name: str = "default_chain",
        recovery_strategy: RecoveryStrategy = RecoveryStrategy.EXPONENTIAL_BACKOFF,
        recovery_threshold: int = 3,
        history_size: int = 1000
    ):
        self.name = name
        self.recovery_strategy = recovery_strategy
        self.recovery_threshold = recovery_threshold
        self._lock = threading.RLock()
        self._strategies: List[FallbackStrategy] = []
        self._current_level = DegradationLevel.FULL
        self._consecutive_successes = 0
        self._consecutive_failures = 0
        self._history: deque = deque(maxlen=history_size)
        self._circuit_open = False
        self._circuit_open_time: Optional[float] = None
        self._circuit_reset_timeout = 60.0  # 60 seconds default
        
        logger.info(f"Initialized fallback chain: {name}")
    
    def add_strategy(
        self,
        name: str,
        level: DegradationLevel,
        handler: Callable,
        timeout: Optional[float] = None,
        max_attempts: int = 1
    ) -> 'StrategicDegradationFallbackChain':
        """Add a fallback strategy to the chain (ordered by degradation level)."""
        with self._lock:
            strategy = FallbackStrategy(name, level, handler, timeout, max_attempts)
            self._strategies.append(strategy)
            # Keep strategies ordered by degradation level
            level_order = {
                DegradationLevel.FULL: 0,
                DegradationLevel.PARTIAL: 1,
                DegradationLevel.MINIMAL: 2,
                DegradationLevel.FAILSAFE: 3,
                DegradationLevel.FAILURE: 4
            }
            self._strategies.sort(key=lambda s: level_order[s.level])
            logger.debug(f"Added strategy: {name} at level {level.value}")
            return self
    
    def _should_degrade(self) -> bool:
        """Determine if we should move to next degradation level."""
        return self._consecutive_failures >= self.recovery_threshold
    
    def _should_recover(self) -> bool:
        """Determine if we can recover to higher functionality level."""
        return self._consecutive_successes >= self.recovery_threshold
    
    def _escalate_degradation(self):
        """Move to next degradation level."""
        progression = [
            DegradationLevel.FULL,
            DegradationLevel.PARTIAL,
            DegradationLevel.MINIMAL,
            DegradationLevel.FAILSAFE
        ]
        current_idx = progression.index(self._current_level)
        if current_idx < len(progression) - 1:
            self._current_level = progression[current_idx + 1]
            self._consecutive_failures = 0
            logger.warning(f"Degraded to level: {self._current_level.value}")
            self._history.append(DegradationHistory(
                timestamp=time.time(),
                level=self._current_level,
                error_type="degradation_escalation"
            ))
    
    def _attempt_recovery(self):
        """Attempt to recover to higher functionality level."""
        progression = [
            DegradationLevel.FULL,
            DegradationLevel.PARTIAL,
            DegradationLevel.MINIMAL,
            DegradationLevel.FAILSAFE
        ]
        current_idx = progression.index(self._current_level)
        if current_idx > 0:
            self._current_level = progression[current_idx - 1]
            self._consecutive_successes = 0
            logger.info(f"Recovered to level: {self._current_level.value}")
    
    def _check_circuit_breaker(self) -> bool:
        """Check if circuit breaker should prevent execution."""
        if not self._circuit_open:
            return True
        
        # Check if reset timeout has passed
        if self._circuit_open_time and \
           time.time() - self._circuit_open_time > self._circuit_reset_timeout:
            self._circuit_open = False
            self._circuit_open_time = None
            logger.info("Circuit breaker reset - half-open state")
            return True
        
        return False
    
    def execute(self, *args, **kwargs) -> FallbackResult:
        """
        Execute the fallback chain with strategic degradation.
        
        Attempts strategies in order from current degradation level downward
        until one succeeds or all fail.
        """
        start_time = time.time()
        
        with self._lock:
            # Check circuit breaker
            if not self._check_circuit_breaker():
                return FallbackResult(
                    success=False,
                    error=RuntimeError("Circuit breaker is open"),
                    degradation_level=self._current_level,
                    execution_time_ms=(time.time() - start_time) * 1000,
                    metadata={"circuit_breaker": "open"}
                )
            
            # Get starting strategies based on current level
            level_order = {
                DegradationLevel.FULL: 0,
                DegradationLevel.PARTIAL: 1,
                DegradationLevel.MINIMAL: 2,
                DegradationLevel.FAILSAFE: 3
            }
            start_level_idx = level_order.get(self._current_level, 0)
            
            fallback_attempted = 0
            last_error: Optional[Exception] = None
            
            # Try each strategy in order
            for strategy in self._strategies:
                strategy_level_idx = level_order.get(strategy.level, 0)
                if strategy_level_idx < start_level_idx:
                    continue  # Skip levels above our current degradation
                
                fallback_attempted += 1
                
                for attempt in range(strategy.max_attempts):
                    success, result, error = strategy.execute(*args, **kwargs)
                    
                    if success:
                        self._consecutive_successes += 1
                        self._consecutive_failures = 0
                        
                        # Attempt recovery if doing well
                        if self._should_recover():
                            self._attempt_recovery()
                        
                        execution_time = (time.time() - start_time) * 1000
                        return FallbackResult(
                            success=True,
                            result=result,
                            degradation_level=strategy.level,
                            fallback_attempted=fallback_attempted,
                            execution_time_ms=execution_time,
                            metadata={
                                "strategy": strategy.name,
                                "attempt": attempt + 1,
                                "recovery_possible": self._current_level != DegradationLevel.FULL
                            }
                        )
                    last_error = error
            
            # All strategies failed
            self._consecutive_failures += 1
            self._consecutive_successes = 0
            
            # Escalate degradation if needed
            if self._should_degrade():
                self._escalate_degradation()
            
            # Open circuit if in FAILSAFE and still failing
            if self._current_level == DegradationLevel.FAILSAFE and \
               self._consecutive_failures >= self.recovery_threshold * 2:
                self._circuit_open = True
                self._circuit_open_time = time.time()
                logger.error("Circuit breaker OPENED - all strategies failing")
            
            execution_time = (time.time() - start_time) * 1000
            
            self._history.append(DegradationHistory(
                timestamp=time.time(),
                level=DegradationLevel.FAILURE,
                error_type=type(last_error).__name__ if last_error else "unknown"
            ))
            
            return FallbackResult(
                success=False,
                error=last_error,
                degradation_level=DegradationLevel.FAILURE,
                fallback_attempted=fallback_attempted,
                execution_time_ms=execution_time,
                metadata={"all_strategies_failed": True}
            )
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status of the fallback chain."""
        with self._lock:
            strategy_stats = [s.get_stats() for s in self._strategies]
            
            return {
                "chain_name": self.name,
                "current_degradation_level": self._current_level.value,
                "consecutive_successes": self._consecutive_successes,
                "consecutive_failures": self._consecutive_failures,
                "circuit_breaker_open": self._circuit_open,
                "recovery_strategy": self.recovery_strategy.value,
                "strategy_statistics": strategy_stats,
                "degradation_history_count": len(self._history),
                "health_score": self._calculate_health_score()
            }
    
    def _calculate_health_score(self) -> float:
        """Calculate overall health score (0.0 - 1.0)."""
        level_scores = {
            DegradationLevel.FULL: 1.0,
            DegradationLevel.PARTIAL: 0.75,
            DegradationLevel.MINIMAL: 0.5,
            DegradationLevel.FAILSAFE: 0.25,
            DegradationLevel.FAILURE: 0.0
        }
        
        base_score = level_scores.get(self._current_level, 0.0)
        
        # Penalize for circuit breaker
        if self._circuit_open:
            base_score *= 0.5
        
        # Penalize for consecutive failures
        failure_penalty = min(self._consecutive_failures * 0.05, 0.3)
        base_score = max(0.0, base_score - failure_penalty)
        
        return base_score
    
    def reset(self):
        """Reset the fallback chain to FULL functionality."""
        with self._lock:
            self._current_level = DegradationLevel.FULL
            self._consecutive_successes = 0
            self._consecutive_failures = 0
            self._circuit_open = False
            self._circuit_open_time = None
            logger.info(f"Fallback chain {self.name} reset to FULL functionality")


# Convenience factory functions
def create_security_fallback_chain(
    name: str = "security_chain"
) -> StrategicDegradationFallbackChain:
    """Create a pre-configured fallback chain for security operations."""
    return StrategicDegradationFallbackChain(
        name=name,
        recovery_strategy=RecoveryStrategy.EXPONENTIAL_BACKOFF,
        recovery_threshold=2,
        history_size=500
    )


def create_threat_detection_chain(
    name: str = "threat_detection"
) -> StrategicDegradationFallbackChain:
    """Create a fallback chain optimized for threat detection."""
    return StrategicDegradationFallbackChain(
        name=name,
        recovery_strategy=RecoveryStrategy.CIRCUIT_BREAKER,
        recovery_threshold=3,
        history_size=1000
    )


# Export public API
__all__ = [
    'DegradationLevel',
    'RecoveryStrategy',
    'FallbackResult',
    'FallbackStrategy',
    'StrategicDegradationFallbackChain',
    'create_security_fallback_chain',
    'create_threat_detection_chain'
]
