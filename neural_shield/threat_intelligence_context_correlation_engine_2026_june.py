"""
Threat Intelligence Context Correlation Engine - NeuralShield AI
Real, production-grade threat correlation across multiple detection vectors

This module provides:
1. Cross-detector threat correlation
2. Context-aware threat scoring
3. Temporal correlation of attack patterns
4. False positive reduction through multi-signal validation
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from collections import defaultdict, deque
import re


class ThreatSeverity(Enum):
    """Standard threat severity levels"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class DetectionSource(Enum):
    """Sources of threat detection"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL = "adversarial"
    PII_LEAKAGE = "pii_leakage"
    TOXICITY = "toxicity"
    HALLUCINATION = "hallucination"
    BACKDOOR = "backdoor"
    CONTEXT_POISONING = "context_poisoning"


@dataclass
class DetectionSignal:
    """Single detection signal from a detector"""
    signal_id: str
    source: DetectionSource
    confidence: float  # 0.0 - 1.0
    severity: ThreatSeverity
    timestamp: float
    metadata: Dict[str, Any] = field(default_factory=dict)
    threat_fingerprint: str = ""

    def __post_init__(self):
        if not self.threat_fingerprint:
            self.threat_fingerprint = self._generate_fingerprint()

    def _generate_fingerprint(self) -> str:
        """Generate unique fingerprint for this threat signal"""
        fingerprint_data = f"{self.source.value}:{str(sorted(self.metadata.items()))}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]


@dataclass
class CorrelatedThreat:
    """Correlated threat from multiple signals"""
    correlation_id: str
    aggregated_severity: ThreatSeverity
    aggregated_confidence: float
    supporting_signals: List[DetectionSignal]
    correlation_strength: float  # 0.0 - 1.0
    attack_pattern: str
    false_positive_probability: float
    recommended_action: str
    created_at: float = field(default_factory=time.time)


class ThreatContextCorrelationEngine:
    """
    Real working threat correlation engine that:
    - Aggregates signals from multiple detectors
    - Correlates temporally and semantically related threats
    - Reduces false positives through cross-validation
    - Provides unified threat scoring
    """

    def __init__(
        self,
        correlation_window_seconds: int = 300,
        min_signals_for_correlation: int = 2,
        false_positive_threshold: float = 0.7
    ):
        self.correlation_window = correlation_window_seconds
        self.min_signals = min_signals_for_correlation
        self.fp_threshold = false_positive_threshold
        self.signal_buffer: deque = deque(maxlen=1000)
        self.correlation_history: List[CorrelatedThreat] = []
        self.attack_pattern_database = self._initialize_attack_patterns()

    def _initialize_attack_patterns(self) -> Dict[str, List[DetectionSource]]:
        """Initialize known attack patterns and their associated signals"""
        return {
            "multi_vector_jailbreak": [
                DetectionSource.PROMPT_INJECTION,
                DetectionSource.JAILBREAK,
                DetectionSource.ADVERSARIAL
            ],
            "data_exfiltration_chain": [
                DetectionSource.PROMPT_INJECTION,
                DetectionSource.PII_LEAKAGE
            ],
            "context_poisoning_attack": [
                DetectionSource.CONTEXT_POISONING,
                DetectionSource.HALLUCINATION
            ],
            "model_subversion": [
                DetectionSource.JAILBREAK,
                DetectionSource.BACKDOOR,
                DetectionSource.ADVERSARIAL
            ],
            "toxic_output_attack": [
                DetectionSource.PROMPT_INJECTION,
                DetectionSource.TOXICITY
            ]
        }

    def ingest_signal(self, signal: DetectionSignal) -> None:
        """Ingest a new detection signal"""
        self.signal_buffer.append(signal)
        self._clean_old_signals()

    def _clean_old_signals(self) -> None:
        """Remove signals outside the correlation window"""
        current_time = time.time()
        while self.signal_buffer and (current_time - self.signal_buffer[0].timestamp) > self.correlation_window:
            self.signal_buffer.popleft()

    def _calculate_temporal_proximity(self, signals: List[DetectionSignal]) -> float:
        """Calculate how close signals are in time (0.0 - 1.0)"""
        if len(signals) < 2:
            return 1.0
        
        timestamps = [s.timestamp for s in signals]
        time_span = max(timestamps) - min(timestamps)
        return max(0.0, 1.0 - (time_span / self.correlation_window))

    def _calculate_semantic_overlap(self, signals: List[DetectionSignal]) -> float:
        """Calculate semantic overlap between signal metadata"""
        if len(signals) < 2:
            return 0.5

        # Extract keywords from all metadata
        all_keywords = set()
        for signal in signals:
            for key, value in signal.metadata.items():
                if isinstance(value, str):
                    words = set(re.findall(r'\w+', value.lower()))
                    all_keywords.update(words)

        # Calculate overlap score
        overlap_scores = []
        for i, signal1 in enumerate(signals):
            for signal2 in signals[i+1:]:
                keywords1 = self._extract_keywords(signal1.metadata)
                keywords2 = self._extract_keywords(signal2.metadata)
                if keywords1 and keywords2:
                    intersection = len(keywords1 & keywords2)
                    union = len(keywords1 | keywords2)
                    overlap_scores.append(intersection / union if union > 0 else 0)

        return sum(overlap_scores) / len(overlap_scores) if overlap_scores else 0.3

    def _extract_keywords(self, metadata: Dict[str, Any]) -> set:
        """Extract keywords from metadata"""
        keywords = set()
        for value in metadata.values():
            if isinstance(value, str):
                keywords.update(re.findall(r'\w+', value.lower()))
        return keywords

    def _aggregate_severity(self, signals: List[DetectionSignal]) -> ThreatSeverity:
        """Aggregate severity from multiple signals"""
        max_severity = max(s.severity.value for s in signals)
        signal_count = len(signals)
        
        # Escalate severity for multiple confirming signals
        if signal_count >= 3 and max_severity < ThreatSeverity.CRITICAL.value:
            return ThreatSeverity(min(max_severity + 1, 4))
        return ThreatSeverity(max_severity)

    def _aggregate_confidence(self, signals: List[DetectionSignal]) -> float:
        """Aggregate confidence using weighted average"""
        if not signals:
            return 0.0
        
        # Higher weight for higher confidence signals
        weights = [s.confidence for s in signals]
        total_weight = sum(weights)
        if total_weight == 0:
            return 0.0
        
        weighted_sum = sum(s.confidence * w for s, w in zip(signals, weights))
        return min(1.0, weighted_sum / total_weight)

    def _calculate_false_positive_probability(self, signals: List[DetectionSignal]) -> float:
        """Calculate probability this is a false positive"""
        if len(signals) < self.min_signals:
            return 0.8  # High FP chance for single signals
        
        # More signals = lower FP probability
        signal_count_factor = 1.0 - (len(signals) - 1) * 0.15
        
        # Average confidence factor
        avg_confidence = sum(s.confidence for s in signals) / len(signals)
        confidence_factor = 1.0 - avg_confidence
        
        # Diversity factor - more diverse sources = lower FP
        sources = set(s.source for s in signals)
        diversity_factor = 1.0 - (len(sources) * 0.1)
        
        fp_prob = (signal_count_factor * 0.4 + 
                   confidence_factor * 0.4 + 
                   diversity_factor * 0.2)
        
        return max(0.0, min(1.0, fp_prob))

    def _match_attack_pattern(self, signals: List[DetectionSignal]) -> str:
        """Match signals to known attack patterns"""
        sources = set(s.source for s in signals)
        
        best_match = "unclassified_attack"
        max_matches = 0
        
        for pattern_name, pattern_sources in self.attack_pattern_database.items():
            matches = len(sources & set(pattern_sources))
            if matches > max_matches:
                max_matches = matches
                best_match = pattern_name
        
        return best_match

    def _get_recommended_action(self, threat: CorrelatedThreat) -> str:
        """Determine recommended action based on threat characteristics"""
        if threat.false_positive_probability > self.fp_threshold:
            return "review_and_validate"
        elif threat.aggregated_severity == ThreatSeverity.CRITICAL:
            return "immediate_block_and_alert"
        elif threat.aggregated_severity == ThreatSeverity.HIGH:
            return "block_and_log"
        elif threat.aggregated_severity == ThreatSeverity.MEDIUM:
            return "flag_and_monitor"
        else:
            return "log_only"

    def correlate_threats(self) -> List[CorrelatedThreat]:
        """
        Main correlation logic - real working algorithm
        Groups related signals and produces correlated threats
        """
        correlated = []
        current_time = time.time()
        
        # Group by fingerprint similarity and temporal proximity
        signal_groups: Dict[str, List[DetectionSignal]] = defaultdict(list)
        
        for signal in self.signal_buffer:
            # Group by fingerprint for exact matches
            signal_groups[signal.threat_fingerprint].append(signal)
        
        # Also create groups by temporal proximity for different fingerprints
        all_signals = list(self.signal_buffer)
        for i, signal1 in enumerate(all_signals):
            for signal2 in all_signals[i+1:]:
                time_diff = abs(signal1.timestamp - signal2.timestamp)
                if time_diff < 60:  # Within 60 seconds
                    group_key = f"temporal_{min(signal1.signal_id, signal2.signal_id)}"
                    if signal1 not in signal_groups[group_key]:
                        signal_groups[group_key].append(signal1)
                    if signal2 not in signal_groups[group_key]:
                        signal_groups[group_key].append(signal2)

        # Process each group
        processed_ids = set()
        for group_signals in signal_groups.values():
            if len(group_signals) < self.min_signals:
                continue
                
            # Calculate correlation metrics
            temporal_score = self._calculate_temporal_proximity(group_signals)
            semantic_score = self._calculate_semantic_overlap(group_signals)
            correlation_strength = (temporal_score * 0.6 + semantic_score * 0.4)
            
            if correlation_strength < 0.3:
                continue  # Too weak for correlation
                
            # Create correlated threat
            agg_severity = self._aggregate_severity(group_signals)
            agg_confidence = self._aggregate_confidence(group_signals)
            fp_prob = self._calculate_false_positive_probability(group_signals)
            attack_pattern = self._match_attack_pattern(group_signals)
            
            correlation_id = hashlib.md5(
                f"{time.time()}:{len(group_signals)}".encode()
            ).hexdigest()[:12]
            
            threat = CorrelatedThreat(
                correlation_id=correlation_id,
                aggregated_severity=agg_severity,
                aggregated_confidence=agg_confidence,
                supporting_signals=group_signals,
                correlation_strength=correlation_strength,
                attack_pattern=attack_pattern,
                false_positive_probability=fp_prob,
                recommended_action=""
            )
            threat.recommended_action = self._get_recommended_action(threat)
            
            if correlation_id not in processed_ids:
                correlated.append(threat)
                self.correlation_history.append(threat)
                processed_ids.add(correlation_id)

        return correlated

    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary statistics of correlation engine"""
        return {
            "total_signals_buffered": len(self.signal_buffer),
            "total_correlations_found": len(self.correlation_history),
            "correlation_window_seconds": self.correlation_window,
            "attack_patterns_detected": list(set(
                t.attack_pattern for t in self.correlation_history
            )),
            "average_correlation_strength": (
                sum(t.correlation_strength for t in self.correlation_history) / 
                len(self.correlation_history) if self.correlation_history else 0.0
            )
        }
