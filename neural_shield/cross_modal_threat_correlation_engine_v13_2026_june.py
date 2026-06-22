"""
Cross-Modal Threat Correlation Engine v13
NeuralShield-AI Feature Expansion (Dimension A)
Add-only module - no modifications to existing code

This module correlates threat signals across multiple modalities (text, image, audio)
to detect sophisticated multi-modal attacks that single-modal detectors might miss.

API Stability: STABLE
"""

import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import uuid


class ModalityType(Enum):
    """Supported input modalities"""
    TEXT = "text"
    IMAGE = "image"
    AUDIO = "audio"
    VIDEO = "video"
    MULTIMODAL = "multimodal"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CorrelationStrength(Enum):
    """Correlation confidence levels"""
    WEAK = "weak"
    MODERATE = "moderate"
    STRONG = "strong"
    CONCLUSIVE = "conclusive"


@dataclass
class ModalityThreatSignal:
    """Threat signal from a single modality"""
    modality: ModalityType
    detector_name: str
    threat_score: float
    threat_type: str
    timestamp: float = field(default_factory=time.time)
    signal_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not 0.0 <= self.threat_score <= 1.0:
            self.threat_score = max(0.0, min(1.0, self.threat_score))


@dataclass
class CorrelatedThreatFinding:
    """Result of cross-modal threat correlation"""
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    signals: List[ModalityThreatSignal] = field(default_factory=list)
    combined_threat_score: float = 0.0
    correlation_strength: CorrelationStrength = CorrelationStrength.WEAK
    attack_pattern: str = "unknown"
    confidence: float = 0.0
    recommended_action: str = "monitor"
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "correlation_id": self.correlation_id,
            "signal_count": len(self.signals),
            "modalities_involved": [s.modality.value for s in self.signals],
            "combined_threat_score": self.combined_threat_score,
            "correlation_strength": self.correlation_strength.value,
            "attack_pattern": self.attack_pattern,
            "confidence": self.confidence,
            "recommended_action": self.recommended_action,
            "timestamp": self.timestamp
        }


class CrossModalThreatCorrelationEngine:
    """
    Cross-Modal Threat Correlation Engine
    
    Correlates threat detections across different input modalities to identify
    coordinated multi-modal attacks that single-modal detectors would miss.
    
    Key Features:
    - Weighted signal combination across modalities
    - Attack pattern recognition
    - Temporal correlation windowing
    - Confidence calibration
    - Action recommendation system
    """

    def __init__(self, 
                 correlation_window_seconds: float = 30.0,
                 min_signals_for_correlation: int = 2,
                 enable_temporal_correlation: bool = True):
        """
        Initialize the correlation engine.
        
        Args:
            correlation_window_seconds: Time window for temporal correlation
            min_signals_for_correlation: Minimum signals needed for correlation
            enable_temporal_correlation: Whether to use temporal correlation
        """
        self.correlation_window_seconds = correlation_window_seconds
        self.min_signals_for_correlation = min_signals_for_correlation
        self.enable_temporal_correlation = enable_temporal_correlation
        
        # Modality weights - different modalities carry different signal strength
        self.modality_weights = {
            ModalityType.TEXT: 1.0,
            ModalityType.IMAGE: 1.2,
            ModalityType.AUDIO: 1.1,
            ModalityType.VIDEO: 1.5,
            ModalityType.MULTIMODAL: 1.3
        }
        
        # Known multi-modal attack patterns
        self.attack_patterns = {
            "text_image_jailbreak": ["text", "image"],
            "audio_text_manipulation": ["audio", "text"],
            "video_steganography_attack": ["video", "image", "text"],
            "multi_modal_poisoning": ["text", "image", "audio"],
            "coordinated_evasion": ["text", "image"]
        }
        
        self._signal_buffer: List[ModalityThreatSignal] = []
        self._correlation_history: List[CorrelatedThreatFinding] = []

    def add_threat_signal(self, signal: ModalityThreatSignal) -> None:
        """
        Add a threat signal from any modality to the correlation engine.
        
        Args:
            signal: ModalityThreatSignal to add
        """
        self._signal_buffer.append(signal)
        self._clean_old_signals()

    def _clean_old_signals(self) -> None:
        """Remove signals outside the correlation window"""
        current_time = time.time()
        cutoff = current_time - self.correlation_window_seconds
        self._signal_buffer = [
            s for s in self._signal_buffer 
            if s.timestamp >= cutoff
        ]

    def _calculate_weighted_score(self, signals: List[ModalityThreatSignal]) -> float:
        """Calculate weighted threat score across multiple signals"""
        if not signals:
            return 0.0
        
        total_weight = 0.0
        weighted_sum = 0.0
        
        for signal in signals:
            weight = self.modality_weights.get(signal.modality, 1.0)
            weighted_sum += signal.threat_score * weight
            total_weight += weight
        
        return weighted_sum / total_weight if total_weight > 0 else 0.0

    def _identify_attack_pattern(self, signals: List[ModalityThreatSignal]) -> Tuple[str, float]:
        """Identify attack pattern based on modality combination"""
        modalities_present = {s.modality.value for s in signals}
        
        best_match = "unknown"
        best_match_score = 0.0
        
        for pattern_name, required_modalities in self.attack_patterns.items():
            overlap = len(modalities_present.intersection(required_modalities))
            union = len(modalities_present.union(required_modalities))
            similarity = overlap / union if union > 0 else 0.0
            
            if similarity > best_match_score:
                best_match_score = similarity
                best_match = pattern_name
        
        return best_match, best_match_score

    def _determine_correlation_strength(self, 
                                        signal_count: int, 
                                        weighted_score: float,
                                        pattern_confidence: float) -> CorrelationStrength:
        """Determine correlation strength based on multiple factors"""
        composite_score = (
            (signal_count / 4.0) * 0.3 +
            weighted_score * 0.4 +
            pattern_confidence * 0.3
        )
        
        if composite_score >= 0.8:
            return CorrelationStrength.CONCLUSIVE
        elif composite_score >= 0.6:
            return CorrelationStrength.STRONG
        elif composite_score >= 0.4:
            return CorrelationStrength.MODERATE
        else:
            return CorrelationStrength.WEAK

    def _get_recommended_action(self, 
                                severity: ThreatSeverity,
                                correlation_strength: CorrelationStrength) -> str:
        """Get recommended action based on severity and correlation strength"""
        action_matrix = {
            (ThreatSeverity.LOW, CorrelationStrength.WEAK): "monitor",
            (ThreatSeverity.LOW, CorrelationStrength.MODERATE): "log_and_monitor",
            (ThreatSeverity.LOW, CorrelationStrength.STRONG): "enhanced_monitoring",
            (ThreatSeverity.LOW, CorrelationStrength.CONCLUSIVE): "enhanced_monitoring",
            (ThreatSeverity.MEDIUM, CorrelationStrength.WEAK): "log_and_monitor",
            (ThreatSeverity.MEDIUM, CorrelationStrength.MODERATE): "enhanced_monitoring",
            (ThreatSeverity.MEDIUM, CorrelationStrength.STRONG): "flag_for_review",
            (ThreatSeverity.MEDIUM, CorrelationStrength.CONCLUSIVE): "flag_for_review",
            (ThreatSeverity.HIGH, CorrelationStrength.WEAK): "enhanced_monitoring",
            (ThreatSeverity.HIGH, CorrelationStrength.MODERATE): "flag_for_review",
            (ThreatSeverity.HIGH, CorrelationStrength.STRONG): "block_and_alert",
            (ThreatSeverity.HIGH, CorrelationStrength.CONCLUSIVE): "block_and_alert",
            (ThreatSeverity.CRITICAL, CorrelationStrength.WEAK): "flag_for_review",
            (ThreatSeverity.CRITICAL, CorrelationStrength.MODERATE): "block_and_alert",
            (ThreatSeverity.CRITICAL, CorrelationStrength.STRONG): "immediate_block",
            (ThreatSeverity.CRITICAL, CorrelationStrength.CONCLUSIVE): "immediate_block",
        }
        
        return action_matrix.get((severity, correlation_strength), "monitor")

    def correlate_threats(self) -> List[CorrelatedThreatFinding]:
        """
        Perform cross-modal threat correlation on buffered signals.
        
        Returns:
            List of CorrelatedThreatFinding objects
        """
        findings = []
        
        if len(self._signal_buffer) < self.min_signals_for_correlation:
            return findings
        
        # Group signals by temporal proximity
        if self.enable_temporal_correlation:
            findings = self._temporal_correlation()
        else:
            findings = self._simple_correlation()
        
        # Store findings in history
        self._correlation_history.extend(findings)
        
        return findings

    def _temporal_correlation(self) -> List[CorrelatedThreatFinding]:
        """Perform correlation using temporal windowing"""
        findings = []
        
        if len(self._signal_buffer) < self.min_signals_for_correlation:
            return findings
        
        # Sort signals by timestamp
        sorted_signals = sorted(self._signal_buffer, key=lambda s: s.timestamp)
        
        # Sliding window correlation
        for i, base_signal in enumerate(sorted_signals):
            window_signals = [base_signal]
            
            for j in range(i + 1, len(sorted_signals)):
                other_signal = sorted_signals[j]
                time_diff = other_signal.timestamp - base_signal.timestamp
                
                if time_diff <= self.correlation_window_seconds:
                    window_signals.append(other_signal)
                else:
                    break
            
            if len(window_signals) >= self.min_signals_for_correlation:
                finding = self._create_finding(window_signals)
                findings.append(finding)
        
        return findings

    def _simple_correlation(self) -> List[CorrelatedThreatFinding]:
        """Simple correlation across all buffered signals"""
        finding = self._create_finding(self._signal_buffer)
        return [finding]

    def _create_finding(self, signals: List[ModalityThreatSignal]) -> CorrelatedThreatFinding:
        """Create a correlated threat finding from signals"""
        weighted_score = self._calculate_weighted_score(signals)
        attack_pattern, pattern_confidence = self._identify_attack_pattern(signals)
        
        correlation_strength = self._determine_correlation_strength(
            len(signals), weighted_score, pattern_confidence
        )
        
        # Determine severity
        if weighted_score >= 0.8:
            severity = ThreatSeverity.CRITICAL
        elif weighted_score >= 0.6:
            severity = ThreatSeverity.HIGH
        elif weighted_score >= 0.4:
            severity = ThreatSeverity.MEDIUM
        else:
            severity = ThreatSeverity.LOW
        
        recommended_action = self._get_recommended_action(severity, correlation_strength)
        
        return CorrelatedThreatFinding(
            signals=signals,
            combined_threat_score=weighted_score,
            correlation_strength=correlation_strength,
            attack_pattern=attack_pattern,
            confidence=pattern_confidence,
            recommended_action=recommended_action
        )

    def get_correlation_summary(self) -> Dict[str, Any]:
        """Get summary statistics for the correlation engine"""
        return {
            "buffered_signals": len(self._signal_buffer),
            "total_correlations": len(self._correlation_history),
            "correlation_window_seconds": self.correlation_window_seconds,
            "modalities_in_buffer": list({
                s.modality.value for s in self._signal_buffer
            }),
            "engine_version": "v13",
            "api_stability": "stable"
        }

    def generate_correlation_hash(self, finding: CorrelatedThreatFinding) -> str:
        """Generate deterministic hash for a correlation finding"""
        data = f"{finding.correlation_id}:{finding.timestamp}:{finding.combined_threat_score}"
        return hashlib.sha256(data.encode()).hexdigest()[:16]


# Export public API
__all__ = [
    "ModalityType",
    "ThreatSeverity",
    "CorrelationStrength",
    "ModalityThreatSignal",
    "CorrelatedThreatFinding",
    "CrossModalThreatCorrelationEngine"
]
