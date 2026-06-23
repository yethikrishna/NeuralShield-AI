"""
Threat Intelligence Fusion Engine v20 - NeuralShield AI Security
DIMENSION A: Feature Expansion - Add-only, backward compatible

Aggregates and correlates threat signals from multiple security detectors
to provide comprehensive risk assessment and threat prioritization.

Features:
- Multi-signal threat correlation
- Composite risk scoring with weighted confidence
- Threat history tracking and trend analysis
- Cross-module threat pattern recognition
- False positive reduction via signal corroboration
- Opt-in only - disabled by default for backward compatibility
"""

import time
import hashlib
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum
from collections import defaultdict, deque


class ThreatCategory(Enum):
    """Standardized threat categories for unified classification."""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    ADVERSARIAL = "adversarial"
    PII_LEAKAGE = "pii_leakage"
    TOXICITY = "toxicity"
    HALLUCINATION = "hallucination"
    BACKDOOR = "backdoor"
    DATA_POISONING = "data_poisoning"
    MODEL_EXTRACTION = "model_extraction"
    UNKNOWN = "unknown"


class ThreatSeverity(Enum):
    """Standardized severity levels."""
    CRITICAL = 4
    HIGH = 3
    MEDIUM = 2
    LOW = 1
    INFO = 0


@dataclass
class ThreatSignal:
    """Single threat detection signal from any detector module."""
    signal_id: str
    source_module: str
    category: ThreatCategory
    severity: ThreatSeverity
    confidence: float  # 0.0 - 1.0
    timestamp: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)
    input_fingerprint: str = ""


@dataclass
class CorrelatedThreat:
    """Correlated threat event from multiple signals."""
    correlation_id: str
    primary_category: ThreatCategory
    composite_risk_score: float
    corroborating_signals: int
    signals: List[ThreatSignal]
    first_seen: float
    last_seen: float
    false_positive_probability: float
    recommended_action: str


class ThreatIntelligenceFusionEngine:
    """
    Main fusion engine for threat intelligence.
    
    ADD-ONLY FEATURE: This is a completely new module that wraps around
    existing detectors - no modification to existing code required.
    
    Usage is completely optional and opt-in:
        fusion = ThreatIntelligenceFusionEngine(enabled=True)
        fusion.add_signal(signal)
        assessment = fusion.get_risk_assessment()
    """
    
    def __init__(
        self,
        enabled: bool = False,  # Disabled by default for backward compatibility
        max_history_size: int = 10000,
        correlation_window_seconds: float = 300.0,
        false_positive_corroboration_threshold: int = 2,
    ):
        self.enabled = enabled
        self.max_history_size = max_history_size
        self.correlation_window = correlation_window_seconds
        self.fp_corroboration_threshold = false_positive_corroboration_threshold
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Signal storage
        self._signals: deque = deque(maxlen=max_history_size)
        self._signals_by_input: Dict[str, List[ThreatSignal]] = defaultdict(list)
        self._signals_by_category: Dict[ThreatCategory, List[ThreatSignal]] = defaultdict(list)
        
        # Correlation weights - can be customized
        self._category_weights = {
            ThreatCategory.PROMPT_INJECTION: 1.0,
            ThreatCategory.JAILBREAK: 1.2,
            ThreatCategory.ADVERSARIAL: 0.9,
            ThreatCategory.PII_LEAKAGE: 1.1,
            ThreatCategory.TOXICITY: 0.8,
            ThreatCategory.HALLUCINATION: 0.7,
            ThreatCategory.BACKDOOR: 1.3,
            ThreatCategory.DATA_POISONING: 1.1,
            ThreatCategory.MODEL_EXTRACTION: 1.0,
            ThreatCategory.UNKNOWN: 0.5,
        }
        
        # Statistics
        self._stats = {
            "total_signals_received": 0,
            "correlated_threats_found": 0,
            "false_positives_flagged": 0,
            "high_risk_events": 0,
        }
        
        # Known pattern signatures for cross-module recognition
        self._known_threat_patterns: Set[str] = set()

    def _generate_fingerprint(self, input_text: str) -> str:
        """Generate consistent fingerprint for input correlation."""
        return hashlib.sha256(input_text.encode('utf-8', errors='replace')).hexdigest()[:16]

    def add_signal(
        self,
        source_module: str,
        category: str,
        severity: str,
        confidence: float,
        input_text: str = "",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Add a threat detection signal to the fusion engine.
        
        Returns signal_id if engine is enabled, None otherwise.
        Completely backward compatible - safe to call even when disabled.
        """
        if not self.enabled:
            return None
            
        with self._lock:
            try:
                threat_cat = ThreatCategory(category)
            except ValueError:
                threat_cat = ThreatCategory.UNKNOWN
                
            try:
                threat_sev = ThreatSeverity[severity.upper()]
            except KeyError:
                threat_sev = ThreatSeverity.LOW
            
            signal_id = f"sig_{int(time.time() * 1000000)}_{hashlib.md5(source_module.encode()).hexdigest()[:8]}"
            
            signal = ThreatSignal(
                signal_id=signal_id,
                source_module=source_module,
                category=threat_cat,
                severity=threat_sev,
                confidence=max(0.0, min(1.0, confidence)),
                metadata=metadata or {},
                input_fingerprint=self._generate_fingerprint(input_text),
            )
            
            self._signals.append(signal)
            self._signals_by_input[signal.input_fingerprint].append(signal)
            self._signals_by_category[signal.category].append(signal)
            self._stats["total_signals_received"] += 1
            
            return signal_id

    def _calculate_composite_risk(self, signals: List[ThreatSignal]) -> float:
        """Calculate composite risk score from multiple signals."""
        if not signals:
            return 0.0
            
        weighted_sum = 0.0
        max_confidence = 0.0
        
        for signal in signals:
            severity_weight = signal.severity.value
            category_weight = self._category_weights.get(signal.category, 0.5)
            weighted_sum += severity_weight * category_weight * signal.confidence
            max_confidence = max(max_confidence, signal.confidence)
        
        # Corroboration bonus - multiple independent signals increase confidence
        corroboration_factor = min(2.0, 1.0 + (len(signals) - 1) * 0.15)
        base_score = weighted_sum / len(signals)
        
        # Normalize to 0-100 scale
        normalized = min(100.0, (base_score * corroboration_factor * 8.5))
        
        return round(normalized, 2)

    def _estimate_false_positive_prob(self, signals: List[ThreatSignal]) -> float:
        """Estimate probability this is a false positive based on corroboration."""
        unique_sources = len(set(s.source_module for s in signals))
        
        if unique_sources >= self.fp_corroboration_threshold:
            # Multiple independent detectors agree - low FP probability
            return max(0.01, 0.05 / unique_sources)
        elif len(signals) == 1:
            # Single signal - higher FP probability
            signal = signals[0]
            base_fp = 0.3 - (signal.confidence * 0.25)
            return max(0.05, base_fp)
        else:
            return 0.15

    def _get_recommended_action(self, risk_score: float, fp_prob: float) -> str:
        """Determine recommended action based on risk assessment."""
        if fp_prob > 0.25:
            return "REVIEW_RECOMMENDED"
        elif risk_score >= 80:
            return "BLOCK_IMMEDIATE"
        elif risk_score >= 60:
            return "FLAG_FOR_REVIEW"
        elif risk_score >= 40:
            return "LOG_AND_MONITOR"
        else:
            return "MONITOR_ONLY"

    def correlate_threats(self) -> List[CorrelatedThreat]:
        """
        Correlate related threat signals across modules.
        Groups signals by input fingerprint within the correlation window.
        """
        if not self.enabled:
            return []
            
        with self._lock:
            correlated = []
            now = time.time()
            window_start = now - self.correlation_window
            
            for fingerprint, signals in self._signals_by_input.items():
                # Filter to recent signals
                recent = [s for s in signals if s.timestamp >= window_start]
                if not recent:
                    continue
                    
                # Only correlate if multiple signals or high confidence single
                if len(recent) >= 1:
                    risk_score = self._calculate_composite_risk(recent)
                    fp_prob = self._estimate_false_positive_prob(recent)
                    
                    # Determine primary category (most frequent)
                    categories = [s.category for s in recent]
                    primary_cat = max(set(categories), key=categories.count)
                    
                    threat = CorrelatedThreat(
                        correlation_id=f"corr_{hashlib.md5(fingerprint.encode()).hexdigest()[:12]}",
                        primary_category=primary_cat,
                        composite_risk_score=risk_score,
                        corroborating_signals=len(set(s.source_module for s in recent)),
                        signals=recent,
                        first_seen=min(s.timestamp for s in recent),
                        last_seen=max(s.timestamp for s in recent),
                        false_positive_probability=round(fp_prob, 3),
                        recommended_action=self._get_recommended_action(risk_score, fp_prob),
                    )
                    correlated.append(threat)
                    
                    if risk_score >= 60:
                        self._stats["high_risk_events"] += 1
                    if fp_prob > 0.2:
                        self._stats["false_positives_flagged"] += 1
            
            self._stats["correlated_threats_found"] += len(correlated)
            return sorted(correlated, key=lambda t: t.composite_risk_score, reverse=True)

    def get_risk_assessment(self, input_text: str = "") -> Dict[str, Any]:
        """
        Get comprehensive risk assessment for current state or specific input.
        """
        if not self.enabled:
            return {
                "engine_enabled": True,
                "engine_enabled": False,
                "overall_risk_score": 0.0,
                "status": "opt_in_only",
                "message": "Fusion engine is disabled - pass enabled=True to activate",
            }
            
        with self._lock:
            threats = self.correlate_threats()
            
            if input_text:
                fingerprint = self._generate_fingerprint(input_text)
                input_threats = [t for t in threats if any(
                    s.input_fingerprint == fingerprint for s in t.signals
                )]
            else:
                input_threats = threats
            
            if not input_threats:
                overall_risk = 0.0
                top_threat = None
            else:
                overall_risk = max(t.composite_risk_score for t in input_threats)
                top_threat = input_threats[0]
            
            return {
                "engine_enabled": True,
                "engine_enabled": True,
                "overall_risk_score": overall_risk,
                "active_threats_count": len(input_threats),
                "high_risk_count": sum(1 for t in input_threats if t.composite_risk_score >= 60),
                "top_threat": {
                    "category": top_threat.primary_category.value if top_threat else None,
                    "risk_score": top_threat.composite_risk_score if top_threat else 0,
                    "corroboration": top_threat.corroborating_signals if top_threat else 0,
                    "recommended_action": top_threat.recommended_action if top_threat else "NONE",
                    "false_positive_prob": top_threat.false_positive_probability if top_threat else 0,
                } if top_threat else None,
                "statistics": self._stats.copy(),
                "category_breakdown": {
                    cat.value: len(sigs) for cat, sigs in self._signals_by_category.items()
                },
            }

    def get_trend_analysis(self, window_minutes: float = 60.0) -> Dict[str, Any]:
        """Get threat trend analysis over time window."""
        if not self.enabled:
            return {
                "engine_enabled": True,"engine_enabled": False}
            
        with self._lock:
            cutoff = time.time() - (window_minutes * 60)
            recent = [s for s in self._signals if s.timestamp >= cutoff]
            
            by_minute = defaultdict(int)
            for signal in recent:
                minute_bucket = int((signal.timestamp - cutoff) / 60)
                by_minute[minute_bucket] += 1
            
            return {
                "engine_enabled": True,
                "window_minutes": window_minutes,
                "signals_in_window": len(recent),
                "signals_per_minute": round(len(recent) / window_minutes, 2) if window_minutes > 0 else 0,
                "severity_breakdown": {
                    sev.name: sum(1 for s in recent if s.severity == sev)
                    for sev in ThreatSeverity
                },
                "trend_direction": "INCREASING" if len(by_minute) > 1 and 
                    sum(v for k, v in by_minute.items() if k >= len(by_minute) // 2) >
                    sum(v for k, v in by_minute.items() if k < len(by_minute) // 2)
                    else "STABLE" if len(by_minute) > 1 else "INSUFFICIENT_DATA",
            }

    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics."""
        with self._lock:
            return self._stats.copy()

    def reset(self) -> None:
        """Reset engine state (useful for testing)."""
        with self._lock:
            self._signals.clear()
            self._signals_by_input.clear()
            self._signals_by_category.clear()
            self._stats = {
                "total_signals_received": 0,
                "correlated_threats_found": 0,
                "false_positives_flagged": 0,
                "high_risk_events": 0,
            }


# Singleton instance for easy integration - lazy initialized
_global_fusion_engine: Optional[ThreatIntelligenceFusionEngine] = None


def get_global_fusion_engine() -> ThreatIntelligenceFusionEngine:
    """Get or create global fusion engine instance."""
    global _global_fusion_engine
    if _global_fusion_engine is None:
        _global_fusion_engine = ThreatIntelligenceFusionEngine(enabled=False)
    return _global_fusion_engine


def enable_fusion_engine() -> None:
    """Enable the global fusion engine."""
    get_global_fusion_engine().enabled = True


# Backward compatibility wrapper - safe no-op when called from old code
def report_threat_signal(*args, **kwargs) -> Optional[str]:
    """
    Backward compatible threat reporting function.
    Can be safely called from ANY existing module without modification.
    Does nothing unless explicitly enabled.
    """
    return get_global_fusion_engine().add_signal(*args, **kwargs)
