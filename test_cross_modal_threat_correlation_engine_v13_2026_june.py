"""
Test suite for Cross-Modal Threat Correlation Engine v13
NeuralShield-AI Feature Expansion (Dimension A)
Add-only tests - no modifications to existing tests
"""

import pytest
import time
from neural_shield.cross_modal_threat_correlation_engine_v13_2026_june import (
    ModalityType,
    ThreatSeverity,
    CorrelationStrength,
    ModalityThreatSignal,
    CorrelatedThreatFinding,
    CrossModalThreatCorrelationEngine
)


class TestModalityThreatSignal:
    """Tests for ModalityThreatSignal dataclass"""

    def test_signal_creation(self):
        """Test basic signal creation"""
        signal = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="prompt_injection_detector",
            threat_score=0.75,
            threat_type="prompt_injection"
        )
        assert signal.modality == ModalityType.TEXT
        assert signal.threat_score == 0.75
        assert signal.signal_id is not None

    def test_threat_score_clamping(self):
        """Test that threat scores are properly clamped to [0, 1]"""
        signal_high = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="test",
            threat_score=1.5,
            threat_type="test"
        )
        assert signal_high.threat_score == 1.0

        signal_low = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="test",
            threat_score=-0.5,
            threat_type="test"
        )
        assert signal_low.threat_score == 0.0


class TestCorrelatedThreatFinding:
    """Tests for CorrelatedThreatFinding dataclass"""

    def test_finding_to_dict(self):
        """Test conversion to dictionary"""
        finding = CorrelatedThreatFinding(
            combined_threat_score=0.85,
            correlation_strength=CorrelationStrength.STRONG,
            attack_pattern="text_image_jailbreak"
        )
        result = finding.to_dict()
        assert result["combined_threat_score"] == 0.85
        assert result["correlation_strength"] == "strong"
        assert "correlation_id" in result


class TestCrossModalThreatCorrelationEngine:
    """Tests for CrossModalThreatCorrelationEngine"""

    def test_engine_initialization(self):
        """Test engine initialization with default parameters"""
        engine = CrossModalThreatCorrelationEngine()
        assert engine.correlation_window_seconds == 30.0
        assert engine.min_signals_for_correlation == 2
        assert engine.enable_temporal_correlation == True

    def test_engine_custom_parameters(self):
        """Test engine initialization with custom parameters"""
        engine = CrossModalThreatCorrelationEngine(
            correlation_window_seconds=60.0,
            min_signals_for_correlation=3,
            enable_temporal_correlation=False
        )
        assert engine.correlation_window_seconds == 60.0
        assert engine.min_signals_for_correlation == 3
        assert engine.enable_temporal_correlation == False

    def test_add_threat_signal(self):
        """Test adding threat signals to the engine"""
        engine = CrossModalThreatCorrelationEngine()
        signal = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="test_detector",
            threat_score=0.5,
            threat_type="test"
        )
        engine.add_threat_signal(signal)
        summary = engine.get_correlation_summary()
        assert summary["buffered_signals"] == 1

    def test_no_correlation_with_insufficient_signals(self):
        """Test that no correlation is performed with too few signals"""
        engine = CrossModalThreatCorrelationEngine(min_signals_for_correlation=2)
        signal = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="test",
            threat_score=0.5,
            threat_type="test"
        )
        engine.add_threat_signal(signal)
        findings = engine.correlate_threats()
        assert len(findings) == 0

    def test_cross_modal_correlation_text_image(self):
        """Test correlation between text and image modalities"""
        engine = CrossModalThreatCorrelationEngine()
        
        # Add text threat signal
        text_signal = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="prompt_injection",
            threat_score=0.8,
            threat_type="jailbreak"
        )
        engine.add_threat_signal(text_signal)
        
        # Add image threat signal
        image_signal = ModalityThreatSignal(
            modality=ModalityType.IMAGE,
            detector_name="steganography",
            threat_score=0.7,
            threat_type="hidden_payload"
        )
        engine.add_threat_signal(image_signal)
        
        findings = engine.correlate_threats()
        assert len(findings) > 0
        
        # Should detect text_image_jailbreak pattern
        finding = findings[0]
        assert finding.attack_pattern == "text_image_jailbreak"
        assert finding.combined_threat_score > 0.0

    def test_weighted_score_calculation(self):
        """Test weighted score calculation across modalities"""
        engine = CrossModalThreatCorrelationEngine()
        
        signals = [
            ModalityThreatSignal(
                modality=ModalityType.TEXT,
                detector_name="text_detector",
                threat_score=0.5,
                threat_type="test"
            ),
            ModalityThreatSignal(
                modality=ModalityType.IMAGE,
                detector_name="image_detector",
                threat_score=0.5,
                threat_type="test"
            )
        ]
        
        weighted = engine._calculate_weighted_score(signals)
        # Weighted calculation: (0.5*1.0 + 0.5*1.2) / (1.0+1.2) = 1.1/2.2 = 0.5
        assert weighted == 0.5

    def test_attack_pattern_recognition(self):
        """Test attack pattern recognition"""
        engine = CrossModalThreatCorrelationEngine()
        
        signals = [
            ModalityThreatSignal(
                modality=ModalityType.TEXT,
                detector_name="test",
                threat_score=0.8,
                threat_type="test"
            ),
            ModalityThreatSignal(
                modality=ModalityType.IMAGE,
                detector_name="test",
                threat_score=0.8,
                threat_type="test"
            )
        ]
        
        pattern, confidence = engine._identify_attack_pattern(signals)
        assert pattern == "text_image_jailbreak"
        assert confidence > 0.0

    def test_correlation_strength_determination(self):
        """Test correlation strength determination"""
        engine = CrossModalThreatCorrelationEngine()
        
        # High confidence case
        strength = engine._determine_correlation_strength(4, 0.9, 0.9)
        assert strength == CorrelationStrength.CONCLUSIVE
        
        # Medium confidence case
        strength = engine._determine_correlation_strength(2, 0.5, 0.5)
        assert strength == CorrelationStrength.MODERATE
        
        # Low confidence case
        strength = engine._determine_correlation_strength(1, 0.1, 0.1)
        assert strength == CorrelationStrength.WEAK

    def test_recommended_action_matrix(self):
        """Test recommended action based on severity and correlation strength"""
        engine = CrossModalThreatCorrelationEngine()
        
        # Critical + Conclusive should be immediate block
        action = engine._get_recommended_action(
            ThreatSeverity.CRITICAL,
            CorrelationStrength.CONCLUSIVE
        )
        assert action == "immediate_block"
        
        # Low + Weak should be monitor
        action = engine._get_recommended_action(
            ThreatSeverity.LOW,
            CorrelationStrength.WEAK
        )
        assert action == "monitor"

    def test_temporal_window_cleanup(self):
        """Test that old signals are cleaned from buffer"""
        engine = CrossModalThreatCorrelationEngine(correlation_window_seconds=0.1)
        
        signal = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="test",
            threat_score=0.5,
            threat_type="test"
        )
        engine.add_threat_signal(signal)
        
        # Wait for signal to expire
        time.sleep(0.2)
        engine._clean_old_signals()
        
        summary = engine.get_correlation_summary()
        assert summary["buffered_signals"] == 0

    def test_correlation_hash_generation(self):
        """Test deterministic hash generation"""
        engine = CrossModalThreatCorrelationEngine()
        finding = CorrelatedThreatFinding(
            combined_threat_score=0.75,
            correlation_strength=CorrelationStrength.STRONG
        )
        hash1 = engine.generate_correlation_hash(finding)
        hash2 = engine.generate_correlation_hash(finding)
        assert hash1 == hash2
        assert len(hash1) == 16

    def test_correlation_summary(self):
        """Test correlation summary statistics"""
        engine = CrossModalThreatCorrelationEngine()
        
        signal = ModalityThreatSignal(
            modality=ModalityType.TEXT,
            detector_name="test",
            threat_score=0.5,
            threat_type="test"
        )
        engine.add_threat_signal(signal)
        
        summary = engine.get_correlation_summary()
        assert summary["buffered_signals"] == 1
        assert summary["engine_version"] == "v13"
        assert summary["api_stability"] == "stable"

    def test_multi_modal_correlation(self):
        """Test correlation across 3+ modalities"""
        engine = CrossModalThreatCorrelationEngine()
        
        signals = [
            ModalityThreatSignal(
                modality=ModalityType.TEXT,
                detector_name="text_detector",
                threat_score=0.85,
                threat_type="injection"
            ),
            ModalityThreatSignal(
                modality=ModalityType.IMAGE,
                detector_name="image_detector",
                threat_score=0.80,
                threat_type="steganography"
            ),
            ModalityThreatSignal(
                modality=ModalityType.AUDIO,
                detector_name="audio_detector",
                threat_score=0.75,
                threat_type="voice_manipulation"
            )
        ]
        
        for signal in signals:
            engine.add_threat_signal(signal)
        
        findings = engine.correlate_threats()
        assert len(findings) > 0
        
        finding = findings[0]
        assert finding.attack_pattern == "multi_modal_poisoning"
        assert finding.correlation_strength in [
            CorrelationStrength.STRONG,
            CorrelationStrength.CONCLUSIVE
        ]

    def test_simple_correlation_mode(self):
        """Test simple (non-temporal) correlation mode"""
        engine = CrossModalThreatCorrelationEngine(
            enable_temporal_correlation=False
        )
        
        for i in range(3):
            signal = ModalityThreatSignal(
                modality=ModalityType.TEXT,
                detector_name=f"detector_{i}",
                threat_score=0.7,
                threat_type="test"
            )
            engine.add_threat_signal(signal)
        
        findings = engine.correlate_threats()
        assert len(findings) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
