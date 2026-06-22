"""
Cross-Module Threat Correlation Engine v12
NeuralShield-AI Feature Expansion (Dimension A)

Correlates threat signals across multiple detection modules to:
- Reduce false positives through multi-signal verification
- Improve detection confidence through ensemble scoring
- Identify complex attack patterns spanning module boundaries
- Generate unified threat assessments with contextual enrichment

This is a NEW module - wraps existing detectors, no core modifications.
All existing behavior is 100% preserved.
"""

import hashlib
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, deque


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class CorrelationStrength(Enum):
    """Strength of correlation between signals"""
    STRONG = "strong"
    MODERATE = "moderate"
    WEAK = "weak"
    NONE = "none"


@dataclass
class ThreatSignal:
    """Single threat detection signal from any module"""
    signal_id: str
    source_module: str
    threat_type: str
    severity: ThreatSeverity
    confidence: float  # 0.0 - 1.0
    timestamp: float
    context: Dict[str, Any] = field(default_factory=dict)
    affected_entities: Set[str] = field(default_factory=set)
    attack_indicators: Set[str] = field(default_factory=set)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "signal_id": self.signal_id,
            "source_module": self.source_module,
            "threat_type": self.threat_type,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "timestamp": self.timestamp,
            "context": self.context,
            "affected_entities": list(self.affected_entities),
            "attack_indicators": list(self.attack_indicators),
        }


@dataclass
class CorrelatedThreat:
    """Correlated threat from multiple signals"""
    correlation_id: str
    primary_threat_type: str
    aggregated_severity: ThreatSeverity
    aggregated_confidence: float
    supporting_signals: List[ThreatSignal]
    correlation_strength: CorrelationStrength
    attack_pattern: str
    risk_score: float
    recommended_actions: List[str]
    entities_involved: Set[str]
    first_seen: float
    last_seen: float
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "primary_threat_type": self.primary_threat_type,
            "aggregated_severity": self.aggregated_severity.value,
            "aggregated_confidence": self.aggregated_confidence,
            "supporting_signals_count": len(self.supporting_signals),
            "supporting_modules": list({s.source_module for s in self.supporting_signals}),
            "correlation_strength": self.correlation_strength.value,
            "attack_pattern": self.attack_pattern,
            "risk_score": self.risk_score,
            "recommended_actions": self.recommended_actions,
            "entities_involved": list(self.entities_involved),
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "signal_timeline": [(s.source_module, s.timestamp) for s in self.supporting_signals],
        }


class CrossModuleThreatCorrelator:
    """
    Cross-Module Threat Correlation Engine
    
    Correlates threat signals from multiple detection modules
    to identify complex attack patterns and reduce false positives.
    """
    
    # Known attack patterns and their signal combinations
    ATTACK_PATTERNS = {
        "multi_stage_prompt_injection": {
            "required_signals": {"prompt_injection", "context_chain_attack", "prompt_obfuscation"},
            "minimum_signals": 2,
            "severity_boost": 1.5,
        },
        "jailbreak_with_context_poisoning": {
            "required_signals": {"jailbreak_attempt", "conversation_poisoning", "role_play_attack"},
            "minimum_signals": 2,
            "severity_boost": 1.4,
        },
        "adversarial_evasion_chain": {
            "required_signals": {"adversarial_prompt", "prompt_evasion", "semantic_paraphrase"},
            "minimum_signals": 2,
            "severity_boost": 1.3,
        },
        "tool_call_hijack_attempt": {
            "required_signals": {"tool_call_validation", "prompt_injection", "thought_process_anomaly"},
            "minimum_signals": 2,
            "severity_boost": 1.6,
        },
        "rag_context_tampering": {
            "required_signals": {"rag_poisoning", "context_integrity", "hallucination_trigger"},
            "minimum_signals": 2,
            "severity_boost": 1.4,
        },
        "multimodal_injection_chain": {
            "required_signals": {"multimodal_injection", "steganography", "vlm_hijack"},
            "minimum_signals": 2,
            "severity_boost": 1.5,
        },
    }
    
    # Entity correlation rules - which entities indicate the same attack
    CORRELATION_ENTITY_TYPES = {
        "user_id", "session_id", "conversation_id", "ip_address",
        "prompt_hash", "embedding_signature", "tool_name",
    }
    
    def __init__(
        self,
        time_window_seconds: float = 300.0,
        min_signals_for_correlation: int = 2,
        false_positive_reduction_threshold: float = 0.7,
    ):
        self.time_window = time_window_seconds
        self.min_signals = min_signals_for_correlation
        self.fp_threshold = false_positive_reduction_threshold
        self.signal_buffer: deque = deque(maxlen=10000)
        self.entity_to_signals: Dict[str, List[str]] = defaultdict(list)
        self.correlation_cache: Dict[str, CorrelatedThreat] = {}
        self.correlation_stats = {
            "total_signals_processed": 0,
            "correlations_found": 0,
            "false_positives_reduced": 0,
            "patterns_identified": defaultdict(int),
        }
    
    def ingest_signal(
        self,
        source_module: str,
        threat_type: str,
        severity: ThreatSeverity,
        confidence: float,
        context: Optional[Dict[str, Any]] = None,
        affected_entities: Optional[Set[str]] = None,
        attack_indicators: Optional[Set[str]] = None,
    ) -> str:
        """
        Ingest a threat detection signal from any module.
        
        Returns: signal_id for reference
        """
        signal_id = f"sig_{uuid.uuid4().hex[:16]}"
        
        signal = ThreatSignal(
            signal_id=signal_id,
            source_module=source_module,
            threat_type=threat_type,
            severity=severity,
            confidence=max(0.0, min(1.0, confidence)),
            timestamp=time.time(),
            context=context or {},
            affected_entities=affected_entities or set(),
            attack_indicators=attack_indicators or set(),
        )
        
        self.signal_buffer.append(signal)
        self.correlation_stats["total_signals_processed"] += 1
        
        # Index by entities for fast correlation
        for entity in signal.affected_entities:
            self.entity_to_signals[entity].append(signal_id)
        
        return signal_id
    
    def _clean_old_signals(self) -> None:
        """Remove signals outside the time window"""
        cutoff = time.time() - self.time_window
        while self.signal_buffer and self.signal_buffer[0].timestamp < cutoff:
            old_signal = self.signal_buffer.popleft()
            for entity in old_signal.affected_entities:
                if entity in self.entity_to_signals:
                    if old_signal.signal_id in self.entity_to_signals[entity]:
                        self.entity_to_signals[entity].remove(old_signal.signal_id)
    
    def _calculate_entity_overlap(
        self, signal1: ThreatSignal, signal2: ThreatSignal
    ) -> Tuple[float, Set[str]]:
        """Calculate entity overlap between two signals"""
        common_entities = signal1.affected_entities & signal2.affected_entities
        all_entities = signal1.affected_entities | signal2.affected_entities
        
        if not all_entities:
            return 0.0, set()
        
        overlap_ratio = len(common_entities) / len(all_entities)
        return overlap_ratio, common_entities
    
    def _calculate_temporal_proximity(
        self, signal1: ThreatSignal, signal2: ThreatSignal
    ) -> float:
        """Calculate temporal proximity score (1.0 = same time, 0.0 = window edge)"""
        time_diff = abs(signal1.timestamp - signal2.timestamp)
        return max(0.0, 1.0 - (time_diff / self.time_window))
    
    def _determine_correlation_strength(
        self, entity_overlap: float, temporal_score: float, confidence_product: float
    ) -> CorrelationStrength:
        """Determine overall correlation strength"""
        composite_score = (
            entity_overlap * 0.5 +
            temporal_score * 0.3 +
            confidence_product * 0.2
        )
        
        if composite_score >= 0.7:
            return CorrelationStrength.STRONG
        elif composite_score >= 0.4:
            return CorrelationStrength.MODERATE
        elif composite_score >= 0.2:
            return CorrelationStrength.WEAK
        else:
            return CorrelationStrength.NONE
    
    def _aggregate_severity(self, signals: List[ThreatSignal]) -> ThreatSeverity:
        """Aggregate severity from multiple signals"""
        severity_order = {
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.LOW: 1,
            ThreatSeverity.INFO: 0,
        }
        reverse_order = {v: k for k, v in severity_order.items()}
        
        max_level = max(severity_order[s.severity] for s in signals)
        return reverse_order[max_level]
    
    def _aggregate_confidence(self, signals: List[ThreatSignal]) -> float:
        """
        Aggregate confidence using Dempster-Shafer inspired combination.
        Multiple agreeing signals boost confidence.
        """
        if not signals:
            return 0.0
        
        # Weighted average with boost for agreement
        confidences = [s.confidence for s in signals]
        avg_conf = sum(confidences) / len(confidences)
        
        # Agreement boost - more signals = higher boost
        agreement_boost = min(0.15, 0.05 * len(signals))
        variance = sum((c - avg_conf) ** 2 for c in confidences) / len(confidences)
        
        # Lower variance = higher agreement = higher boost
        consistency_factor = max(0.0, 1.0 - variance * 4)
        
        final_confidence = min(1.0, avg_conf + agreement_boost * consistency_factor)
        return round(final_confidence, 3)
    
    def _identify_attack_pattern(self, signals: List[ThreatSignal]) -> Tuple[str, float]:
        """Identify known attack patterns from signal combination"""
        signal_types = {s.threat_type for s in signals}
        
        best_pattern = "unclassified_correlated_threat"
        best_match_score = 0.0
        
        for pattern_name, pattern_rules in self.ATTACK_PATTERNS.items():
            matching = signal_types & pattern_rules["required_signals"]
            if len(matching) >= pattern_rules["minimum_signals"]:
                match_ratio = len(matching) / len(pattern_rules["required_signals"])
                if match_ratio > best_match_score:
                    best_match_score = match_ratio
                    best_pattern = pattern_name
        
        return best_pattern, best_match_score
    
    def _calculate_risk_score(
        self, severity: ThreatSeverity, confidence: float, signal_count: int
    ) -> float:
        """Calculate normalized risk score 0-100"""
        severity_weights = {
            ThreatSeverity.CRITICAL: 1.0,
            ThreatSeverity.HIGH: 0.75,
            ThreatSeverity.MEDIUM: 0.5,
            ThreatSeverity.LOW: 0.25,
            ThreatSeverity.INFO: 0.1,
        }
        
        base_score = severity_weights[severity] * 100
        confidence_factor = confidence
        volume_factor = min(1.0, 0.5 + (signal_count * 0.1))
        
        risk_score = base_score * confidence_factor * volume_factor
        return round(min(100.0, risk_score), 1)
    
    def _generate_recommendations(
        self, pattern: str, severity: ThreatSeverity, signals: List[ThreatSignal]
    ) -> List[str]:
        """Generate mitigation recommendations"""
        recommendations = []
        
        base_recommendations = {
            "multi_stage_prompt_injection": [
                "Block current user session",
                "Enable enhanced input sanitization",
                "Review conversation history for injection chains",
            ],
            "jailbreak_with_context_poisoning": [
                "Reset conversation context",
                "Enable constitutional classifier enforcement",
                "Flag user for elevated monitoring",
            ],
            "adversarial_evasion_chain": [
                "Apply prompt purification",
                "Enable embedding anomaly detection",
                "Increase detection sensitivity",
            ],
            "tool_call_hijack_attempt": [
                "Block tool execution immediately",
                "Audit all recent tool calls",
                "Enable strict tool call validation",
            ],
            "rag_context_tampering": [
                "Verify RAG context integrity",
                "Refresh document embeddings",
                "Check for poisoned training data",
            ],
            "multimodal_injection_chain": [
                "Block multimodal input processing",
                "Enable steganography detection",
                "Review image/audio content",
            ],
            "unclassified_correlated_threat": [
                "Monitor for additional threat signals",
                "Apply general input validation",
                "Log for further analysis",
            ],
        }
        
        recommendations.extend(base_recommendations.get(pattern, base_recommendations["unclassified_correlated_threat"]))
        
        if severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH):
            recommendations.append("Escalate to security operations team")
            recommendations.append("Capture full forensic evidence")
        
        return recommendations
    
    def run_correlation(self) -> List[CorrelatedThreat]:
        """
        Run full correlation analysis on buffered signals.
        
        Returns: List of correlated threats identified
        """
        self._clean_old_signals()
        
        if len(self.signal_buffer) < self.min_signals:
            return []
        
        signals_by_id = {s.signal_id: s for s in self.signal_buffer}
        correlated_groups: List[List[ThreatSignal]] = []
        processed = set()
        
        # Group signals by shared entities
        for entity, signal_ids in self.entity_to_signals.items():
            if len(signal_ids) >= self.min_signals:
                group = [signals_by_id[sid] for sid in signal_ids if sid in signals_by_id]
                if len(group) >= self.min_signals:
                    group_ids = {s.signal_id for s in group}
                    if not group_ids.issubset(processed):
                        correlated_groups.append(group)
                        processed.update(group_ids)
        
        results = []
        
        for group in correlated_groups:
            # Calculate pairwise correlations
            entity_overlap, common_entities = self._calculate_entity_overlap(
                group[0], group[-1]
            )
            temporal_score = self._calculate_temporal_proximity(group[0], group[-1])
            confidence_product = group[0].confidence * group[-1].confidence
            
            corr_strength = self._determine_correlation_strength(
                entity_overlap, temporal_score, confidence_product
            )
            
            if corr_strength == CorrelationStrength.NONE:
                continue
            
            # False positive reduction - single low-confidence signal doesn't correlate
            avg_conf = sum(s.confidence for s in group) / len(group)
            if len(group) == 2 and avg_conf < self.fp_threshold:
                self.correlation_stats["false_positives_reduced"] += 1
                continue
            
            # Build correlated threat
            agg_severity = self._aggregate_severity(group)
            agg_confidence = self._aggregate_confidence(group)
            pattern, pattern_score = self._identify_attack_pattern(group)
            risk_score = self._calculate_risk_score(agg_severity, agg_confidence, len(group))
            recommendations = self._generate_recommendations(pattern, agg_severity, group)
            
            all_entities = set()
            for s in group:
                all_entities.update(s.affected_entities)
            
            correlated = CorrelatedThreat(
                correlation_id=f"corr_{uuid.uuid4().hex[:16]}",
                primary_threat_type=pattern,
                aggregated_severity=agg_severity,
                aggregated_confidence=agg_confidence,
                supporting_signals=group,
                correlation_strength=corr_strength,
                attack_pattern=pattern,
                risk_score=risk_score,
                recommended_actions=recommendations,
                entities_involved=all_entities,
                first_seen=min(s.timestamp for s in group),
                last_seen=max(s.timestamp for s in group),
            )
            
            results.append(correlated)
            self.correlation_cache[correlated.correlation_id] = correlated
            self.correlation_stats["correlations_found"] += 1
            self.correlation_stats["patterns_identified"][pattern] += 1
        
        return results
    
    def get_correlation_by_id(self, correlation_id: str) -> Optional[CorrelatedThreat]:
        """Get a specific correlation result by ID"""
        return self.correlation_cache.get(correlation_id)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics"""
        return {
            "signals_currently_buffered": len(self.signal_buffer),
            **self.correlation_stats,
            "patterns_distribution": dict(self.correlation_stats["patterns_identified"]),
        }
    
    def generate_correlation_report(self) -> Dict[str, Any]:
        """Generate comprehensive correlation report"""
        correlations = list(self.correlation_cache.values())
        
        by_severity = defaultdict(int)
        by_pattern = defaultdict(int)
        by_strength = defaultdict(int)
        
        for corr in correlations:
            by_severity[corr.aggregated_severity.value] += 1
            by_pattern[corr.attack_pattern] += 1
            by_strength[corr.correlation_strength.value] += 1
        
        return {
            "report_timestamp": time.time(),
            "summary": self.get_stats(),
            "correlations_by_severity": dict(by_severity),
            "correlations_by_pattern": dict(by_pattern),
            "correlations_by_strength": dict(by_strength),
            "active_correlations": [c.to_dict() for c in correlations[-50:]],
        }


# Module export
__all__ = [
    "ThreatSeverity",
    "CorrelationStrength",
    "ThreatSignal",
    "CorrelatedThreat",
    "CrossModuleThreatCorrelator",
]
