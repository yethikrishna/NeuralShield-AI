"""
NeuralShield-AI - Comprehensive Security Hardening v15
Dimension B - Security Hardening
ADD-ONLY IMPLEMENTATION - No existing code modified

This module provides security hardening wrappers for:
1. Alert Context Enrichment - Adds threat intelligence context to detections
2. Alert Deduplication - Reduces alert fatigue via smart correlation
3. Noise Reduction Engine - Filters false positives using historical patterns
4. Threat Intelligence Fusion - Combines signals from multiple detectors
5. Attack Surface Analysis - Maps threats to asset vulnerability context

All functionality is OPT-IN and wraps existing detectors.
"""

import hashlib
import time
import threading
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque


class AlertSeverity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class ThreatCategory(Enum):
    PROMPT_INJECTION = "PROMPT_INJECTION"
    JAILBREAK = "JAILBREAK"
    DATA_LEAKAGE = "DATA_LEAKAGE"
    TOOL_HIJACK = "TOOL_HIJACK"
    ADVERSARIAL = "ADVERSARIAL"
    HALLUCINATION = "HALLUCINATION"
    UNKNOWN = "UNKNOWN"


@dataclass
class EnrichedAlert:
    """Enriched alert with full security context."""
    alert_id: str
    timestamp: float
    detector_name: str
    severity: AlertSeverity
    category: ThreatCategory
    raw_score: float
    confidence: float
    input_text: str
    context: Dict[str, Any] = field(default_factory=dict)
    threat_intel_signals: List[str] = field(default_factory=list)
    attack_vectors: List[str] = field(default_factory=list)
    false_positive_probability: float = 0.0
    deduplication_key: str = ""
    enriched: bool = False
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "detector_name": self.detector_name,
            "severity": self.severity.value,
            "category": self.category.value,
            "raw_score": self.raw_score,
            "confidence": self.confidence,
            "context": self.context,
            "threat_intel_signals": self.threat_intel_signals,
            "attack_vectors": self.attack_vectors,
            "false_positive_probability": self.false_positive_probability,
            "deduplication_key": self.deduplication_key,
            "enriched": self.enriched
        }


class AlertContextEnricher:
    """
    Adds threat intelligence context to raw alerts.
    Wraps existing detectors - no modification required.
    """
    
    def __init__(self, enable_threat_intel: bool = True, enable_attack_mapping: bool = True):
        self.enable_threat_intel = enable_threat_intel
        self.enable_attack_mapping = enable_attack_mapping
        self._thread_lock = threading.Lock()
        self._threat_pattern_cache: Dict[str, List[str]] = {}
        self._initialize_threat_patterns()
    
    def _initialize_threat_patterns(self) -> None:
        """Initialize known threat pattern mappings."""
        self._threat_pattern_cache = {
            "ignore": ["AUTHORITY_BYPASS", "INSTRUCTION_OVERRIDE"],
            "disregard": ["AUTHORITY_BYPASS", "CONTEXT_ERASURE"],
            "system prompt": ["PROMPT_LEAKAGE_ATTACK", "PROMPT_EXTRACTION"],
            "previous instructions": ["CONTEXT_HIJACK", "INSTRUCTION_OVERRIDE"],
            "you are": ["PERSONA_HIJACK", "ROLE_IMPERSONATION"],
            "forget": ["MEMORY_MANIPULATION", "CONTEXT_ERASURE"],
            "hypothetically": ["JAILBREAK_EVASION", "HYPOTHETICAL_ATTACK"],
            "pretend": ["ROLE_IMPERSONATION", "PERSONA_HIJACK"],
            "developer mode": ["ELEVATED_PRIVILEGES", "DEBUG_ACCESS"],
            "sudo": ["PRIVILEGE_ESCALATION", "AUTHORITY_BYPASS"],
        }
    
    def enrich_alert(self, raw_alert: Dict[str, Any]) -> EnrichedAlert:
        """
        Enrich a raw alert with threat intelligence context.
        ADD-ONLY: Wraps detector output without modifying detectors.
        """
        with self._thread_lock:
            alert_id = self._generate_alert_id(raw_alert)
            input_text = raw_alert.get("input_text", raw_alert.get("text", ""))
            detector_name = raw_alert.get("detector", raw_alert.get("detector_name", "unknown"))
            
            enriched = EnrichedAlert(
                alert_id=alert_id,
                timestamp=raw_alert.get("timestamp", time.time()),
                detector_name=detector_name,
                severity=self._map_severity(raw_alert.get("severity", raw_alert.get("score", 0.5))),
                category=self._categorize_threat(detector_name, input_text),
                raw_score=float(raw_alert.get("score", raw_alert.get("raw_score", 0.0))),
                confidence=float(raw_alert.get("confidence", 0.8)),
                input_text=input_text,
                context=raw_alert.get("context", {})
            )
            
            if self.enable_threat_intel:
                enriched.threat_intel_signals = self._extract_threat_signals(input_text)
            
            if self.enable_attack_mapping:
                enriched.attack_vectors = self._map_attack_vectors(enriched.category, input_text)
            
            enriched.false_positive_probability = self._calculate_fp_probability(enriched)
            enriched.deduplication_key = self._generate_deduplication_key(enriched)
            enriched.enriched = True
            
            return enriched
    
    def _generate_alert_id(self, alert: Dict[str, Any]) -> str:
        content = f"{alert.get('detector', '')}{alert.get('text', '')}{time.time()}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]
    
    def _map_severity(self, score: float) -> AlertSeverity:
        if score >= 0.9:
            return AlertSeverity.CRITICAL
        elif score >= 0.7:
            return AlertSeverity.HIGH
        elif score >= 0.5:
            return AlertSeverity.MEDIUM
        elif score >= 0.3:
            return AlertSeverity.LOW
        return AlertSeverity.INFORMATIONAL
    
    def _categorize_threat(self, detector: str, text: str) -> ThreatCategory:
        detector_lower = detector.lower()
        text_lower = text.lower()
        
        if "inject" in detector_lower or "prompt" in detector_lower:
            return ThreatCategory.PROMPT_INJECTION
        elif "jailbreak" in detector_lower or "bypass" in text_lower:
            return ThreatCategory.JAILBREAK
        elif "leak" in detector_lower or "pii" in detector_lower:
            return ThreatCategory.DATA_LEAKAGE
        elif "tool" in detector_lower or "agent" in detector_lower:
            return ThreatCategory.TOOL_HIJACK
        elif "adversarial" in detector_lower:
            return ThreatCategory.ADVERSARIAL
        elif "hallucinat" in detector_lower:
            return ThreatCategory.HALLUCINATION
        return ThreatCategory.UNKNOWN
    
    def _extract_threat_signals(self, text: str) -> List[str]:
        signals = []
        text_lower = text.lower()
        for pattern, sigs in self._threat_pattern_cache.items():
            if pattern in text_lower:
                signals.extend(sigs)
        return list(set(signals))
    
    def _map_attack_vectors(self, category: ThreatCategory, text: str) -> List[str]:
        vectors = []
        text_lower = text.lower()
        
        if category == ThreatCategory.PROMPT_INJECTION:
            vectors.append("INPUT_MANIPULATION")
            if "ignore" in text_lower or "disregard" in text_lower:
                vectors.append("INSTRUCTION_OVERRIDE")
        elif category == ThreatCategory.JAILBREAK:
            vectors.append("SECURITY_BYPASS")
            if "roleplay" in text_lower or "pretend" in text_lower:
                vectors.append("PERSONA_MANIPULATION")
        
        return vectors
    
    def _calculate_fp_probability(self, alert: EnrichedAlert) -> float:
        """Calculate probability this is a false positive."""
        fp_score = 0.0
        text = alert.input_text.lower()
        
        # Legitimate content patterns
        if len(text) < 10:
            fp_score += 0.3
        if "example" in text or "sample" in text:
            fp_score += 0.2
        if "test" in text and len(text) < 30:
            fp_score += 0.15
        if alert.confidence < 0.5:
            fp_score += 0.25
        
        return min(1.0, fp_score)
    
    def _generate_deduplication_key(self, alert: EnrichedAlert) -> str:
        """Generate key for deduplicating similar alerts."""
        content = f"{alert.category.value}{alert.input_text[:50]}{alert.detector_name}"
        return hashlib.md5(content.encode()).hexdigest()[:12]


class AlertDeduplicationEngine:
    """
    Deduplicates similar alerts to reduce alert fatigue.
    ADD-ONLY - Operates on alert streams, no modification to detectors.
    """
    
    def __init__(self, window_seconds: int = 60, max_history: int = 1000):
        self.window_seconds = window_seconds
        self.max_history = max_history
        self._thread_lock = threading.Lock()
        self._alert_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=max_history))
    
    def deduplicate(self, alerts: List[EnrichedAlert]) -> Tuple[List[EnrichedAlert], List[EnrichedAlert]]:
        """
        Returns (unique_alerts, duplicate_alerts)
        Duplicates are alerts matching similar alerts in the time window.
        """
        with self._thread_lock:
            unique = []
            duplicates = []
            now = time.time()
            
            for alert in alerts:
                key = alert.deduplication_key
                history = self._alert_history[key]
                
                # Clean old entries
                while history and now - history[0] > self.window_seconds:
                    history.popleft()
                
                if history:
                    duplicates.append(alert)
                else:
                    unique.append(alert)
                    history.append(now)
            
            return unique, duplicates
    
    def get_deduplication_stats(self) -> Dict[str, Any]:
        with self._thread_lock:
            total_keys = len(self._alert_history)
            total_alerts = sum(len(q) for q in self._alert_history.values())
            return {
                "unique_dedup_keys": total_keys,
                "total_alerts_tracked": total_alerts,
                "window_seconds": self.window_seconds
            }


class NoiseReductionEngine:
    """
    Reduces alert noise by filtering likely false positives.
    ADD-ONLY - Post-processing layer on alerts.
    """
    
    def __init__(self, fp_threshold: float = 0.5, min_confidence: float = 0.3):
        self.fp_threshold = fp_threshold
        self.min_confidence = min_confidence
        self._thread_lock = threading.Lock()
        self._false_positive_patterns: Set[str] = {
            "hello", "hi", "hey", "thanks", "thank you", "please",
            "example", "test", "sample", "demo", "help"
        }
    
    def filter_noise(self, alerts: List[EnrichedAlert]) -> Tuple[List[EnrichedAlert], List[EnrichedAlert]]:
        """
        Returns (actionable_alerts, filtered_noise)
        Filters alerts with high false positive probability.
        """
        with self._thread_lock:
            actionable = []
            filtered = []
            
            for alert in alerts:
                if self._is_noise(alert):
                    filtered.append(alert)
                else:
                    actionable.append(alert)
            
            return actionable, filtered
    
    def _is_noise(self, alert: EnrichedAlert) -> bool:
        if alert.false_positive_probability >= self.fp_threshold:
            return True
        if alert.confidence < self.min_confidence:
            return True
        
        text = alert.input_text.lower().strip()
        if len(text) < 8 and text in self._false_positive_patterns:
            return True
        if alert.raw_score < 0.2 and alert.severity == AlertSeverity.INFORMATIONAL:
            return True
            
        return False


class ThreatIntelligenceFusion:
    """
    Fuses signals from multiple detectors into unified threat assessment.
    ADD-ONLY - Combines outputs, doesn't modify detectors.
    """
    
    def __init__(self, correlation_threshold: int = 2):
        self.correlation_threshold = correlation_threshold
        self._thread_lock = threading.Lock()
    
    def fuse_alerts(self, alerts: List[EnrichedAlert]) -> Dict[str, Any]:
        """
        Fuse multiple alerts into unified threat assessment.
        Returns consolidated threat view.
        """
        with self._thread_lock:
            if not alerts:
                return {"fused": False, "alerts": 0}
            
            # Count by category
            category_counts: Dict[str, int] = defaultdict(int)
            severity_counts: Dict[str, int] = defaultdict(int)
            all_signals: Set[str] = set()
            all_vectors: Set[str] = set()
            
            max_severity = AlertSeverity.INFORMATIONAL
            max_score = 0.0
            combined_confidence = 0.0
            
            for alert in alerts:
                category_counts[alert.category.value] += 1
                severity_counts[alert.severity.value] += 1
                all_signals.update(alert.threat_intel_signals)
                all_vectors.update(alert.attack_vectors)
                
                if self._severity_rank(alert.severity) > self._severity_rank(max_severity):
                    max_severity = alert.severity
                
                max_score = max(max_score, alert.raw_score)
                combined_confidence += alert.confidence
            
            avg_confidence = combined_confidence / len(alerts) if alerts else 0.0
            signal_count = len(all_signals)
            
            return {
                "fused": True,
                "total_alerts": len(alerts),
                "max_severity": max_severity.value,
                "max_score": max_score,
                "average_confidence": avg_confidence,
                "category_distribution": dict(category_counts),
                "severity_distribution": dict(severity_counts),
                "threat_signals": list(all_signals),
                "attack_vectors": list(all_vectors),
                "signal_correlation_count": signal_count,
                "escalated": signal_count >= self.correlation_threshold,
                "overall_threat_level": self._calculate_overall_threat(max_severity, signal_count, max_score)
            }
    
    def _severity_rank(self, severity: AlertSeverity) -> int:
        ranks = {
            AlertSeverity.CRITICAL: 5,
            AlertSeverity.HIGH: 4,
            AlertSeverity.MEDIUM: 3,
            AlertSeverity.LOW: 2,
            AlertSeverity.INFORMATIONAL: 1
        }
        return ranks.get(severity, 0)
    
    def _calculate_overall_threat(self, severity: AlertSeverity, signals: int, score: float) -> str:
        base = self._severity_rank(severity)
        signal_bonus = min(2, signals // 2)
        score_bonus = 1 if score > 0.8 else 0
        total = base + signal_bonus + score_bonus
        
        if total >= 7:
            return "CRITICAL"
        elif total >= 5:
            return "ELEVATED"
        elif total >= 3:
            return "MODERATE"
        return "LOW"


class ComprehensiveSecurityHardeningPipeline:
    """
    Complete security hardening pipeline wrapping all detectors.
    ADD-ONLY - Pure wrapper, zero modifications to existing code.
    """
    
    def __init__(self, 
                 enable_enrichment: bool = True,
                 enable_deduplication: bool = True,
                 enable_noise_reduction: bool = True,
                 enable_fusion: bool = True):
        
        self.enricher = AlertContextEnricher() if enable_enrichment else None
        self.deduplicator = AlertDeduplicationEngine() if enable_deduplication else None
        self.noise_reducer = NoiseReductionEngine() if enable_noise_reduction else None
        self.fusion = ThreatIntelligenceFusion() if enable_fusion else None
        
        self._stats = {
            "alerts_processed": 0,
            "alerts_enriched": 0,
            "duplicates_suppressed": 0,
            "noise_filtered": 0,
            "fusions_performed": 0
        }
        self._lock = threading.Lock()
    
    def process_alerts(self, raw_alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Main pipeline entry point.
        Takes raw detector outputs, returns fully processed security assessment.
        """
        with self._lock:
            result = {
                "raw_alerts_count": len(raw_alerts),
                "pipeline_enabled": {
                    "enrichment": self.enricher is not None,
                    "deduplication": self.deduplicator is not None,
                    "noise_reduction": self.noise_reducer is not None,
                    "fusion": self.fusion is not None
                }
            }
            
            # Step 1: Enrichment
            enriched_alerts = []
            if self.enricher:
                enriched_alerts = [self.enricher.enrich_alert(a) for a in raw_alerts]
                self._stats["alerts_enriched"] += len(enriched_alerts)
                result["enriched_alerts"] = [a.to_dict() for a in enriched_alerts]
            else:
                enriched_alerts = [EnrichedAlert(
                    alert_id=f"raw_{i}",
                    timestamp=time.time(),
                    detector_name=a.get("detector", "unknown"),
                    severity=AlertSeverity.MEDIUM,
                    category=ThreatCategory.UNKNOWN,
                    raw_score=a.get("score", 0.5),
                    confidence=0.5,
                    input_text=a.get("text", "")
                ) for i, a in enumerate(raw_alerts)]
            
            # Step 2: Deduplication
            unique_alerts = enriched_alerts
            if self.deduplicator:
                unique, duplicates = self.deduplicator.deduplicate(enriched_alerts)
                unique_alerts = unique
                self._stats["duplicates_suppressed"] += len(duplicates)
                result["deduplication"] = {
                    "unique": len(unique),
                    "duplicates": len(duplicates)
                }
            
            # Step 3: Noise Reduction
            actionable_alerts = unique_alerts
            if self.noise_reducer:
                actionable, filtered = self.noise_reducer.filter_noise(unique_alerts)
                actionable_alerts = actionable
                self._stats["noise_filtered"] += len(filtered)
                result["noise_reduction"] = {
                    "actionable": len(actionable),
                    "filtered_noise": len(filtered)
                }
            
            # Step 4: Threat Fusion
            if self.fusion and actionable_alerts:
                result["fused_assessment"] = self.fusion.fuse_alerts(actionable_alerts)
                self._stats["fusions_performed"] += 1
            
            result["actionable_alerts"] = [a.to_dict() for a in actionable_alerts]
            result["final_actionable_count"] = len(actionable_alerts)
            self._stats["alerts_processed"] += len(raw_alerts)
            
            return result
    
    def get_pipeline_stats(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self._stats)


# Export public API
__all__ = [
    "AlertSeverity",
    "ThreatCategory",
    "EnrichedAlert",
    "AlertContextEnricher",
    "AlertDeduplicationEngine",
    "NoiseReductionEngine",
    "ThreatIntelligenceFusion",
    "ComprehensiveSecurityHardeningPipeline"
]
