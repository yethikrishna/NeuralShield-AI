"""
NeuralShield AI - Threat Intelligence Feedback Loop Adaptive Learner
Production-grade implementation for real-world security operations

This module implements a closed-loop feedback system that:
1. Records analyst feedback on classification decisions
2. Automatically adapts feature weights based on feedback
3. Tracks model performance improvements over time
4. Provides drift detection and model health monitoring
5. Supports continuous learning without full retraining
"""
import re
import json
import math
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
import time
from datetime import datetime, timedelta


class FeedbackOutcome(Enum):
    """Actual outcome determined by analyst"""
    CONFIRMED_TRUE_POSITIVE = "confirmed_true_positive"
    CONFIRMED_FALSE_POSITIVE = "confirmed_false_positive"
    CONFIRMED_TRUE_NEGATIVE = "confirmed_true_negative"
    CONFIRMED_FALSE_NEGATIVE = "confirmed_false_negative"
    NEEDS_ADDITIONAL_CONTEXT = "needs_additional_context"


class ModelHealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADING = "degrading"
    REQUIRES_ATTENTION = "requires_attention"
    CRITICAL = "critical"


@dataclass
class FeedbackRecord:
    """Record of analyst feedback on a classification"""
    alert_id: str
    original_classification: str
    original_confidence: float
    analyst_outcome: FeedbackOutcome
    analyst_notes: str
    feature_scores_at_time: Dict[str, float]
    timestamp: float = field(default_factory=time.time)
    learning_applied: bool = False


@dataclass
class WeightAdjustment:
    """Record of a weight adjustment"""
    feature_name: str
    old_weight: float
    new_weight: float
    adjustment_magnitude: float
    reason: str
    timestamp: float
    feedback_count: int


@dataclass
class LearningMetrics:
    """Metrics on learning performance"""
    total_feedback_received: int
    feedback_by_outcome: Dict[str, int]
    accuracy_before_learning: float
    accuracy_after_learning: float
    total_weight_adjustments: int
    model_health_score: float
    health_status: ModelHealthStatus
    drift_detected: bool
    drift_severity: float
    learning_rate_current: float
    last_learning_timestamp: float


class ThreatIntelligenceFeedbackLoopLearner:
    """
    Closed-loop feedback system for adaptive threat intelligence classification.
    
    This engine implements online learning that adapts feature weights based on
    analyst feedback without requiring full model retraining. It tracks model
    performance, detects drift, and provides continuous improvement.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._get_default_config()
        
        # Feedback storage
        self.feedback_history: List[FeedbackRecord] = []
        self.feedback_by_alert: Dict[str, FeedbackRecord] = {}
        
        # Weight tracking
        self.current_weights: Dict[str, float] = self._get_initial_weights()
        self.weight_history: List[WeightAdjustment] = []
        
        # Performance tracking
        self.prediction_window: deque = deque(maxlen=self.config["performance_window_size"])
        self.accuracy_history: List[Tuple[float, float]] = []
        
        # Learning state
        self.feedback_since_last_learning = 0
        self.learning_iterations = 0
        self.current_learning_rate = self.config["initial_learning_rate"]
        
        # Feature error tracking
        self.feature_error_counts: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"false_positive_errors": 0, "false_negative_errors": 0, "total_samples": 0}
        )
        
        print(f"[FeedbackLoopLearner] Initialized with learning_rate={self.current_learning_rate}")
    
    def _get_default_config(self) -> Dict[str, Any]:
        return {
            # Learning parameters
            "initial_learning_rate": 0.05,
            "min_learning_rate": 0.005,
            "max_learning_rate": 0.15,
            "learning_rate_decay": 0.995,
            "feedback_threshold_for_learning": 10,
            
            # Performance tracking
            "performance_window_size": 500,
            "accuracy_history_limit": 100,
            
            # Weight constraints
            "min_feature_weight": 0.02,
            "max_feature_weight": 0.40,
            
            # Health monitoring
            "health_degradation_threshold": 0.10,
            "drift_detection_threshold": 0.15,
            
            # Feature list
            "features": [
                "known_whitelist_match",
                "historical_false_positive_pattern",
                "low_severity_indicator",
                "common_baseline_noise",
                "missing_context_indicators",
                "source_reliability_score",
            ],
            
            # Validation
            "weight_sum_target": 1.0,
            "weight_sum_tolerance": 0.02,
        }
    
    def _get_initial_weights(self) -> Dict[str, float]:
        """Get initial balanced feature weights"""
        return {
            "known_whitelist_match": 0.25,
            "historical_false_positive_pattern": 0.20,
            "low_severity_indicator": 0.10,
            "common_baseline_noise": 0.15,
            "missing_context_indicators": 0.10,
            "source_reliability_score": 0.20,
        }
    
    def record_feedback(
        self,
        alert_id: str,
        original_classification: str,
        original_confidence: float,
        analyst_outcome: FeedbackOutcome,
        feature_scores: Dict[str, float],
        analyst_notes: str = ""
    ) -> FeedbackRecord:
        """
        Record analyst feedback on a classification decision.
        
        Args:
            alert_id: Unique identifier for the alert
            original_classification: The model's original classification
            original_confidence: The model's original confidence score
            analyst_outcome: The actual outcome determined by analyst
            feature_scores: Individual feature scores at classification time
            analyst_notes: Optional analyst notes
            
        Returns:
            FeedbackRecord object
        """
        record = FeedbackRecord(
            alert_id=alert_id,
            original_classification=original_classification,
            original_confidence=original_confidence,
            analyst_outcome=analyst_outcome,
            analyst_notes=analyst_notes,
            feature_scores_at_time=feature_scores.copy()
        )
        
        self.feedback_history.append(record)
        self.feedback_by_alert[alert_id] = record
        self.feedback_since_last_learning += 1
        
        # Track prediction outcome
        self._record_prediction_outcome(record)
        
        # Track feature errors
        self._update_feature_error_stats(record)
        
        print(f"[FeedbackLoopLearner] Recorded feedback: alert={alert_id}, outcome={analyst_outcome.value}")
        
        # Check if we should trigger learning
        if self.feedback_since_last_learning >= self.config["feedback_threshold_for_learning"]:
            self._perform_adaptive_learning()
        
        return record
    
    def _record_prediction_outcome(self, record: FeedbackRecord):
        """Record prediction for accuracy tracking"""
        was_correct = self._was_prediction_correct(
            record.original_classification,
            record.analyst_outcome
        )
        self.prediction_window.append(was_correct)
    
    def _was_prediction_correct(
        self,
        classification: str,
        outcome: FeedbackOutcome
    ) -> bool:
        """Determine if original prediction was correct"""
        # Map classification to expected outcome
        positive_classifications = {"true_positive", "likely_true_positive"}
        negative_classifications = {"false_positive", "likely_false_positive"}
        
        predicted_positive = classification in positive_classifications
        predicted_negative = classification in negative_classifications
        
        # Check against actual outcome
        if outcome == FeedbackOutcome.CONFIRMED_TRUE_POSITIVE:
            return predicted_positive
        elif outcome == FeedbackOutcome.CONFIRMED_FALSE_POSITIVE:
            return predicted_negative
        elif outcome == FeedbackOutcome.CONFIRMED_TRUE_NEGATIVE:
            return predicted_negative
        elif outcome == FeedbackOutcome.CONFIRMED_FALSE_NEGATIVE:
            return predicted_positive
        
        return True  # Neutral case
    
    def _update_feature_error_stats(self, record: FeedbackRecord):
        """Update per-feature error statistics"""
        was_correct = self._was_prediction_correct(
            record.original_classification,
            record.analyst_outcome
        )
        
        for feature_name, score in record.feature_scores_at_time.items():
            stats = self.feature_error_counts[feature_name]
            stats["total_samples"] += 1
            
            if not was_correct:
                # Determine error type
                if record.analyst_outcome == FeedbackOutcome.CONFIRMED_FALSE_POSITIVE:
                    stats["false_positive_errors"] += 1
                elif record.analyst_outcome == FeedbackOutcome.CONFIRMED_FALSE_NEGATIVE:
                    stats["false_negative_errors"] += 1
    
    def _perform_adaptive_learning(self):
        """Perform online learning based on accumulated feedback"""
        print(f"[FeedbackLoopLearner] Starting adaptive learning iteration #{self.learning_iterations + 1}")
        print(f"[FeedbackLoopLearner] Processing {self.feedback_since_last_learning} new feedback records")
        
        adjustments_made = 0
        
        # Calculate per-feature error rates
        feature_performance = self._calculate_feature_performance()
        
        # Adjust weights based on performance
        for feature_name, performance in feature_performance.items():
            if performance["total_samples"] < 5:
                continue  # Not enough data to adjust
            
            old_weight = self.current_weights[feature_name]
            error_rate = performance["error_rate"]
            
            # Calculate adjustment: increase weight for good features, decrease for bad ones
            # Good features (low error rate) get weight increased
            # Bad features (high error rate) get weight decreased
            performance_factor = 1.0 - (2.0 * error_rate)  # Range: -1 to +1
            adjustment = performance_factor * self.current_learning_rate
            
            new_weight = old_weight + adjustment
            
            # Apply constraints
            new_weight = max(
                self.config["min_feature_weight"],
                min(self.config["max_feature_weight"], new_weight)
            )
            
            if abs(new_weight - old_weight) > 0.001:
                self.current_weights[feature_name] = new_weight
                self.weight_history.append(WeightAdjustment(
                    feature_name=feature_name,
                    old_weight=old_weight,
                    new_weight=new_weight,
                    adjustment_magnitude=abs(new_weight - old_weight),
                    reason=f"Error rate: {error_rate:.3f}, Performance factor: {performance_factor:.3f}",
                    timestamp=time.time(),
                    feedback_count=self.feedback_since_last_learning
                ))
                adjustments_made += 1
        
        # Normalize weights to maintain sum
        self._normalize_weights()
        
        # Decay learning rate
        self.current_learning_rate = max(
            self.config["min_learning_rate"],
            self.current_learning_rate * self.config["learning_rate_decay"]
        )
        
        # Record accuracy snapshot
        current_accuracy = self.calculate_current_accuracy()
        self.accuracy_history.append((time.time(), current_accuracy))
        if len(self.accuracy_history) > self.config["accuracy_history_limit"]:
            self.accuracy_history.pop(0)
        
        # Reset counters
        self.feedback_since_last_learning = 0
        self.learning_iterations += 1
        
        print(f"[FeedbackLoopLearner] Learning complete: {adjustments_made} weight adjustments")
        print(f"[FeedbackLoopLearner] Current accuracy: {current_accuracy:.3f}, Learning rate: {self.current_learning_rate:.4f}")
    
    def _calculate_feature_performance(self) -> Dict[str, Dict[str, Any]]:
        """Calculate performance metrics for each feature"""
        performance = {}
        
        for feature_name, stats in self.feature_error_counts.items():
            total = stats["total_samples"]
            if total == 0:
                continue
                
            total_errors = stats["false_positive_errors"] + stats["false_negative_errors"]
            error_rate = total_errors / total
            
            performance[feature_name] = {
                "total_samples": total,
                "false_positive_errors": stats["false_positive_errors"],
                "false_negative_errors": stats["false_negative_errors"],
                "error_rate": error_rate,
                "accuracy": 1.0 - error_rate
            }
        
        return performance
    
    def _normalize_weights(self):
        """Normalize weights to sum to approximately 1.0"""
        current_sum = sum(self.current_weights.values())
        target = self.config["weight_sum_target"]
        
        if abs(current_sum - target) > self.config["weight_sum_tolerance"]:
            scale_factor = target / current_sum
            for feature_name in self.current_weights:
                self.current_weights[feature_name] *= scale_factor
    
    def calculate_current_accuracy(self) -> float:
        """Calculate current accuracy over prediction window"""
        if not self.prediction_window:
            return 0.75  # Default baseline
        
        correct = sum(1 for outcome in self.prediction_window if outcome)
        return correct / len(self.prediction_window)
    
    def get_current_weights(self) -> Dict[str, float]:
        """Get current adapted feature weights"""
        return self.current_weights.copy()
    
    def calculate_model_health(self) -> Tuple[float, ModelHealthStatus, bool, float]:
        """
        Calculate model health score and status.
        
        Returns:
            (health_score, health_status, drift_detected, drift_severity)
        """
        if len(self.accuracy_history) < 2:
            return (0.85, ModelHealthStatus.HEALTHY, False, 0.0)
        
        # Calculate accuracy trend
        recent_accuracies = [acc for _, acc in self.accuracy_history[-10:]]
        older_accuracies = [acc for _, acc in self.accuracy_history[:-10]]
        
        if not older_accuracies:
            older_avg = recent_accuracies[0] if recent_accuracies else 0.75
        else:
            older_avg = sum(older_accuracies) / len(older_accuracies)
        
        recent_avg = sum(recent_accuracies) / len(recent_accuracies) if recent_accuracies else older_avg
        
        # Calculate degradation
        degradation = max(0, older_avg - recent_avg)
        drift_detected = degradation > self.config["drift_detection_threshold"]
        
        # Calculate health score (0-1)
        current_accuracy = self.calculate_current_accuracy()
        health_score = (
            (current_accuracy * 0.6) +
            (max(0, 1.0 - degradation * 2) * 0.3) +
            (min(1.0, len(self.feedback_history) / 100) * 0.1)
        )
        
        # Determine status
        if health_score >= 0.80:
            status = ModelHealthStatus.HEALTHY
        elif health_score >= 0.65:
            status = ModelHealthStatus.DEGRADING
        elif health_score >= 0.50:
            status = ModelHealthStatus.REQUIRES_ATTENTION
        else:
            status = ModelHealthStatus.CRITICAL
        
        return (health_score, status, drift_detected, degradation)
    
    def get_learning_metrics(self) -> LearningMetrics:
        """Get comprehensive learning metrics"""
        health_score, health_status, drift_detected, drift_severity = self.calculate_model_health()
        
        # Count feedback by outcome
        outcome_counts = defaultdict(int)
        for record in self.feedback_history:
            outcome_counts[record.analyst_outcome.value] += 1
        
        # Calculate accuracy improvement
        initial_accuracy = 0.75  # Baseline
        if self.accuracy_history:
            initial_accuracy = self.accuracy_history[0][1] if len(self.accuracy_history) > 0 else 0.75
        
        current_accuracy = self.calculate_current_accuracy()
        
        return LearningMetrics(
            total_feedback_received=len(self.feedback_history),
            feedback_by_outcome=dict(outcome_counts),
            accuracy_before_learning=initial_accuracy,
            accuracy_after_learning=current_accuracy,
            total_weight_adjustments=len(self.weight_history),
            model_health_score=health_score,
            health_status=health_status,
            drift_detected=drift_detected,
            drift_severity=drift_severity,
            learning_rate_current=self.current_learning_rate,
            last_learning_timestamp=self.weight_history[-1].timestamp if self.weight_history else 0
        )
    
    def get_weight_evolution_report(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get report on how weights have evolved"""
        evolution = defaultdict(list)
        
        for adjustment in self.weight_history:
            evolution[adjustment.feature_name].append({
                "timestamp": adjustment.timestamp,
                "old_weight": adjustment.old_weight,
                "new_weight": adjustment.new_weight,
                "change": adjustment.new_weight - adjustment.old_weight,
                "reason": adjustment.reason
            })
        
        return dict(evolution)
    
    def export_model_state(self) -> Dict[str, Any]:
        """Export current model state for persistence"""
        return {
            "current_weights": self.current_weights,
            "learning_iterations": self.learning_iterations,
            "current_learning_rate": self.current_learning_rate,
            "total_feedback": len(self.feedback_history),
            "current_accuracy": self.calculate_current_accuracy(),
            "feature_error_counts": dict(self.feature_error_counts),
            "export_timestamp": time.time(),
            "version": "1.0.0"
        }
    
    def import_model_state(self, state: Dict[str, Any]):
        """Import model state from previous export"""
        if "current_weights" in state:
            self.current_weights = state["current_weights"]
        if "learning_iterations" in state:
            self.learning_iterations = state["learning_iterations"]
        if "current_learning_rate" in state:
            self.current_learning_rate = state["current_learning_rate"]
        print(f"[FeedbackLoopLearner] Imported model state from {datetime.fromtimestamp(state.get('export_timestamp', time.time()))}")


# Convenience function for integration
def create_feedback_learner() -> ThreatIntelligenceFeedbackLoopLearner:
    """Factory function to create a feedback learner"""
    return ThreatIntelligenceFeedbackLoopLearner()


if __name__ == "__main__":
    # Demo and self-test
    print("=" * 60)
    print("NeuralShield AI - Feedback Loop Adaptive Learner Demo")
    print("=" * 60)
    
    learner = create_feedback_learner()
    
    # Simulate feedback
    print("\nSimulating analyst feedback...")
    
    feature_scores_example = {
        "known_whitelist_match": 0.1,
        "historical_false_positive_pattern": 0.3,
        "low_severity_indicator": 0.8,
        "common_baseline_noise": 0.2,
        "missing_context_indicators": 0.0,
        "source_reliability_score": 0.25,
    }
    
    # Simulate some correct and incorrect predictions
    test_cases = [
        # (alert_id, classification, confidence, outcome, description)
        ("alert_001", "likely_false_positive", 0.65, 
         FeedbackOutcome.CONFIRMED_FALSE_POSITIVE, "Correct FP identification"),
        ("alert_002", "true_positive", 0.15,
         FeedbackOutcome.CONFIRMED_TRUE_POSITIVE, "Correct TP identification"),
        ("alert_003", "likely_false_positive", 0.62,
         FeedbackOutcome.CONFIRMED_TRUE_POSITIVE, "False negative - missed real threat"),
        ("alert_004", "true_positive", 0.20,
         FeedbackOutcome.CONFIRMED_FALSE_POSITIVE, "False positive - incorrectly flagged"),
    ]
    
    for alert_id, classification, confidence, outcome, desc in test_cases:
        learner.record_feedback(
            alert_id=alert_id,
            original_classification=classification,
            original_confidence=confidence,
            analyst_outcome=outcome,
            feature_scores=feature_scores_example,
            analyst_notes=desc
        )
    
    # Show metrics
    print("\n" + "=" * 60)
    print("Learning Metrics")
    print("=" * 60)
    metrics = learner.get_learning_metrics()
    print(f"Total feedback received: {metrics.total_feedback_received}")
    print(f"Feedback distribution: {metrics.feedback_by_outcome}")
    print(f"Current accuracy: {metrics.accuracy_after_learning:.3f}")
    print(f"Model health score: {metrics.model_health_score:.3f}")
    print(f"Health status: {metrics.health_status.value}")
    print(f"Drift detected: {metrics.drift_detected}")
    print(f"Learning rate: {metrics.learning_rate_current:.4f}")
    
    print("\n" + "=" * 60)
    print("Current Adapted Feature Weights")
    print("=" * 60)
    for feature, weight in sorted(learner.get_current_weights().items(), key=lambda x: -x[1]):
        print(f"  {feature:45s} {weight:.4f}")
    
    print("\nDemo complete!")
