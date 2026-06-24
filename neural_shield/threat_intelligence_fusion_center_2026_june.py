"""
Threat Intelligence Fusion Center - NeuralShield AI
Dimension A: Feature Expansion (Incremental, Add-Only)

Aggregates, correlates, and prioritizes threat signals from multiple
detection modules to provide unified threat intelligence with confidence
scoring and actionable response recommendations.

STABLE API - Backward Compatible
"""

import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from collections import defaultdict


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    """Threat category classification"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    ADVERSARIAL_PROMPT = "adversarial_prompt"
    MEMORY_POISONING = "memory_poisoning"
    TOOL_CALL_ABUSE = "tool_call_abuse"
    CONTEXT_LEAKAGE = "context_leakage"
    UNKNOWN = "unknown"


@dataclass
class ThreatSignal:
    """Individual threat signal from a detector"""
    signal_id: str
    source_module: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float  # 0.0 - 1.0
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    affected_input: Optional[str] = None
    
    def __post_init__(self):
        if not self.signal_id:
            self.signal_id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique signal ID"""
        content = f"{self.source_module}:{self.timestamp}:{self.confidence}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class FusionResult:
    """Correlated and fused threat result"""
    fusion_id: str
    primary_category: ThreatCategory
    aggregated_severity: ThreatSeverity
    aggregated_confidence: float
    supporting_signals: List[ThreatSignal]
    signal_count: int
    unique_sources: int
    correlation_score: float
    response_recommendation: str
    false_positive_likelihood: float
    timestamp: float = field(default_factory=time.time)


class ThreatIntelligenceFusionCenter:
    """
    Central fusion center for aggregating and correlating threat signals.
    
    Incremental feature - wraps existing detectors without modification.
    Provides:
    - Multi-signal aggregation
    - Cross-module correlation
    - Confidence weighted scoring
    - False positive reduction
    - Actionable response recommendations
    """
    
    def __init__(self, correlation_threshold: float = 0.3):
        self.correlation_threshold = correlation_threshold
        self.signal_history: List[ThreatSignal] = []
        self.fusion_history: List[FusionResult] = []
        self.source_weights: Dict[str, float] = defaultdict(lambda: 1.0)
        self.category_correlations: Dict[str, Set[str]] = self._build_correlation_map()
        self.response_matrix = self._build_response_matrix()
        
    def _build_correlation_map(self) -> Dict[str, Set[str]]:
        """Build known threat category correlations"""
        return {
            "prompt_injection": {"adversarial_prompt", "jailbreak_attempt"},
            "jailbreak_attempt": {"prompt_injection", "adversarial_prompt"},
            "adversarial_prompt": {"prompt_injection", "jailbreak_attempt", "context_leakage"},
            "memory_poisoning": {"context_leakage"},
            "tool_call_abuse": {"prompt_injection", "jailbreak_attempt"},
            "context_leakage": {"adversarial_prompt", "memory_poisoning"},
        }
    
    def _build_response_matrix(self) -> Dict[tuple, str]:
        """Build severity-based response recommendations"""
        return {
            (ThreatSeverity.CRITICAL, True): "BLOCK - Immediate intervention required",
            (ThreatSeverity.CRITICAL, False): "FLAG - High priority review required",
            (ThreatSeverity.HIGH, True): "BLOCK - Strong threat indicators",
            (ThreatSeverity.HIGH, False): "FLAG - Escalate for review",
            (ThreatSeverity.MEDIUM, True): "FLAG - Monitor and log for review",
            (ThreatSeverity.MEDIUM, False): "LOG - Pass through with warning",
            (ThreatSeverity.LOW, True): "LOG - Monitor pattern",
            (ThreatSeverity.LOW, False): "PASS - Low confidence indicator",
        }
    
    def ingest_signal(self, signal: ThreatSignal) -> None:
        """
        Ingest a single threat signal from any detector module.
        Add-only operation - does not modify source modules.
        """
        self.signal_history.append(signal)
        # Keep only last 1000 signals for memory efficiency
        if len(self.signal_history) > 1000:
            self.signal_history = self.signal_history[-1000:]
    
    def ingest_signals_batch(self, signals: List[ThreatSignal]) -> None:
        """Batch ingest multiple threat signals"""
        for signal in signals:
            self.ingest_signal(signal)
    
    def _calculate_correlation(self, signal1: ThreatSignal, signal2: ThreatSignal) -> float:
        """Calculate correlation between two threat signals"""
        score = 0.0
        
        # Same category = high correlation
        if signal1.category == signal2.category:
            score += 0.5
        
        # Known correlated categories
        cat1 = signal1.category.value
        cat2 = signal2.category.value
        if cat1 in self.category_correlations and cat2 in self.category_correlations[cat1]:
            score += 0.3
        
        # Time proximity (within 5 seconds)
        time_diff = abs(signal1.timestamp - signal2.timestamp)
        if time_diff < 5.0:
            score += 0.2 * (1.0 - time_diff / 5.0)
        
        # Same affected input
        if signal1.affected_input and signal2.affected_input:
            if signal1.affected_input == signal2.affected_input:
                score += 0.4
        
        return min(score, 1.0)
    
    def _aggregate_severity(self, signals: List[ThreatSignal]) -> ThreatSeverity:
        """Aggregate severity from multiple signals"""
        severity_order = {
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.UNKNOWN: 0,
        }
        
        if not signals:
            return ThreatSeverity.UNKNOWN
        
        max_severity = max(severity_order[s.severity] for s in signals)
        
        # Multiple high signals upgrade to critical
        high_count = sum(1 for s in signals if s.severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL))
        if high_count >= 3 and max_severity == 3:
            return ThreatSeverity.CRITICAL
        
        # Reverse lookup
        for sev, order in severity_order.items():
            if order == max_severity:
                return sev
        
        return ThreatSeverity.UNKNOWN
    
    def _calculate_false_positive_likelihood(self, signals: List[ThreatSignal]) -> float:
        """Calculate likelihood this is a false positive"""
        if len(signals) == 1:
            # Single signal is more likely false positive
            return 0.3
        
        # Multiple independent sources reduce false positive likelihood
        sources = set(s.source_module for s in signals)
        source_factor = min(len(sources) / 3.0, 1.0)
        
        # Low confidence signals increase FP likelihood
        avg_confidence = sum(s.confidence for s in signals) / len(signals)
        confidence_factor = 1.0 - avg_confidence
        
        return (0.5 - source_factor * 0.3) * (0.5 + confidence_factor * 0.5)
    
    def fuse_threats(self, time_window: float = 30.0) -> List[FusionResult]:
        """
        Fuse threat signals within a time window.
        Returns correlated threat clusters with aggregated intelligence.
        """
        now = time.time()
        recent_signals = [
            s for s in self.signal_history
            if now - s.timestamp <= time_window
        ]
        
        if not recent_signals:
            return []
        
        # Simple correlation clustering
        clusters: List[List[ThreatSignal]] = []
        
        for signal in recent_signals:
            placed = False
            for cluster in clusters:
                # Check correlation with any signal in cluster
                for cluster_signal in cluster:
                    if self._calculate_correlation(signal, cluster_signal) >= self.correlation_threshold:
                        cluster.append(signal)
                        placed = True
                        break
                if placed:
                    break
            if not placed:
                clusters.append([signal])
        
        results = []
        for cluster in clusters:
            if len(cluster) < 1:
                continue
            
            # Aggregate confidence weighted by source
            weighted_confidence = sum(
                s.confidence * self.source_weights[s.source_module]
                for s in cluster
            ) / len(cluster)
            
            aggregated_severity = self._aggregate_severity(cluster)
            fp_likelihood = self._calculate_false_positive_likelihood(cluster)
            
            # Determine response
            is_correlated = len(cluster) > 1
            response_key = (aggregated_severity, is_correlated)
            recommendation = self.response_matrix.get(
                response_key,
                "REVIEW - Manual assessment required"
            )
            
            # Primary category = most frequent
            categories = [s.category for s in cluster]
            primary_category = max(set(categories), key=categories.count)
            
            fusion_id = hashlib.sha256(
                f"{time.time()}:{len(cluster)}".encode()
            ).hexdigest()[:12]
            
            result = FusionResult(
                fusion_id=fusion_id,
                primary_category=primary_category,
                aggregated_severity=aggregated_severity,
                aggregated_confidence=min(weighted_confidence, 1.0),
                supporting_signals=cluster,
                signal_count=len(cluster),
                unique_sources=len(set(s.source_module for s in cluster)),
                correlation_score=sum(
                    self._calculate_correlation(cluster[0], s)
                    for s in cluster[1:]
                ) / max(len(cluster) - 1, 1) if len(cluster) > 1 else 0.0,
                response_recommendation=recommendation,
                false_positive_likelihood=fp_likelihood,
            )
            
            results.append(result)
            self.fusion_history.append(result)
        
        return results
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get summary statistics of threat intelligence"""
        if not self.signal_history:
            return {"status": "no_signals_received"}
        
        return {
            "total_signals_ingested": len(self.signal_history),
            "total_fusions_performed": len(self.fusion_history),
            "unique_sources": len(set(s.source_module for s in self.signal_history)),
            "severity_distribution": {
                sev.value: sum(1 for s in self.signal_history if s.severity == sev)
                for sev in ThreatSeverity
            },
            "category_distribution": {
                cat.value: sum(1 for s in self.signal_history if s.category == cat)
                for cat in ThreatCategory
            },
            "average_false_positive_likelihood": (
                sum(f.false_positive_likelihood for f in self.fusion_history)
                / len(self.fusion_history) if self.fusion_history else 0.0
            ),
        }
    
    def get_high_priority_threats(self) -> List[FusionResult]:
        """Get only high/critical priority fused threats"""
        return [
            f for f in self.fusion_history
            if f.aggregated_severity in (ThreatSeverity.HIGH, ThreatSeverity.CRITICAL)
            and f.false_positive_likelihood < 0.3
        ]
