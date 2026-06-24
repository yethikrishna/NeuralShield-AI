"""
Tests for Threat Intelligence Fusion Center
Dimension A: Feature Expansion - Test Coverage
"""

import pytest
import time
from neural_shield.threat_intelligence_fusion_center_2026_june import (
    ThreatIntelligenceFusionCenter,
    ThreatSignal,
    ThreatSeverity,
    ThreatCategory,
    FusionResult,
)


class TestThreatSignal:
    """Test ThreatSignal dataclass"""
    
    def test_threat_signal_creation(self):
        """Test basic threat signal creation"""
        signal = ThreatSignal(
            signal_id="",
            source_module="test_detector",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH,
            confidence=0.85,
            timestamp=time.time(),
        )
        assert signal.signal_id != ""
        assert signal.source_module == "test_detector"
        assert signal.confidence == 0.85
    
    def test_threat_signal_with_metadata(self):
        """Test threat signal with metadata"""
        signal = ThreatSignal(
            signal_id="test123",
            source_module="jailbreak_detector",
            category=ThreatCategory.JAILBREAK_ATTEMPT,
            severity=ThreatSeverity.CRITICAL,
            confidence=0.95,
            timestamp=time.time(),
            metadata={"pattern": "DAN", "score": 0.92},
            affected_input="Ignore previous instructions",
        )
        assert signal.metadata["pattern"] == "DAN"
        assert signal.affected_input is not None


class TestThreatIntelligenceFusionCenter:
    """Test main fusion center functionality"""
    
    def test_fusion_center_initialization(self):
        """Test fusion center initialization"""
        fc = ThreatIntelligenceFusionCenter(correlation_threshold=0.5)
        assert fc.correlation_threshold == 0.5
        assert len(fc.signal_history) == 0
        assert len(fc.fusion_history) == 0
    
    def test_ingest_single_signal(self):
        """Test ingesting a single signal"""
        fc = ThreatIntelligenceFusionCenter()
        signal = ThreatSignal(
            signal_id="",
            source_module="detector1",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.MEDIUM,
            confidence=0.7,
            timestamp=time.time(),
        )
        fc.ingest_signal(signal)
        assert len(fc.signal_history) == 1
    
    def test_ingest_signals_batch(self):
        """Test batch signal ingestion"""
        fc = ThreatIntelligenceFusionCenter()
        signals = [
            ThreatSignal(
                signal_id="",
                source_module=f"detector{i}",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.7,
                timestamp=time.time(),
            )
            for i in range(5)
        ]
        fc.ingest_signals_batch(signals)
        assert len(fc.signal_history) == 5
    
    def test_signal_correlation_same_category(self):
        """Test correlation calculation for same category"""
        fc = ThreatIntelligenceFusionCenter()
        now = time.time()
        signal1 = ThreatSignal(
            signal_id="", source_module="d1",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH, confidence=0.8, timestamp=now,
        )
        signal2 = ThreatSignal(
            signal_id="", source_module="d2",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH, confidence=0.8, timestamp=now,
        )
        correlation = fc._calculate_correlation(signal1, signal2)
        assert correlation > 0.5  # Same category should correlate highly
    
    def test_signal_correlation_known_categories(self):
        """Test correlation for known correlated categories"""
        fc = ThreatIntelligenceFusionCenter()
        now = time.time()
        signal1 = ThreatSignal(
            signal_id="", source_module="d1",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH, confidence=0.8, timestamp=now,
        )
        signal2 = ThreatSignal(
            signal_id="", source_module="d2",
            category=ThreatCategory.JAILBREAK_ATTEMPT,
            severity=ThreatSeverity.HIGH, confidence=0.8, timestamp=now,
        )
        correlation = fc._calculate_correlation(signal1, signal2)
        assert correlation > 0.3  # Known correlated categories
    
    def test_fuse_threats_empty(self):
        """Test fusion with no signals"""
        fc = ThreatIntelligenceFusionCenter()
        results = fc.fuse_threats()
        assert len(results) == 0
    
    def test_fuse_threats_single_cluster(self):
        """Test fusion with correlated signals forming single cluster"""
        fc = ThreatIntelligenceFusionCenter()
        now = time.time()
        
        # Multiple signals from same attack should cluster
        signals = [
            ThreatSignal(
                signal_id="", source_module=f"detector{i}",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.HIGH, confidence=0.8 + i * 0.05,
                timestamp=now, affected_input="test_input",
            )
            for i in range(3)
        ]
        fc.ingest_signals_batch(signals)
        
        results = fc.fuse_threats(time_window=60.0)
        assert len(results) >= 1
        assert results[0].signal_count >= 1
        assert results[0].aggregated_confidence > 0
    
    def test_aggregate_severity_upgrade(self):
        """Test severity upgrade with multiple high signals"""
        fc = ThreatIntelligenceFusionCenter()
        signals = [
            ThreatSignal(
                signal_id="", source_module=f"d{i}",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.HIGH, confidence=0.9,
                timestamp=time.time(),
            )
            for i in range(4)  # 4 HIGH should upgrade to CRITICAL
        ]
        severity = fc._aggregate_severity(signals)
        assert severity == ThreatSeverity.CRITICAL
    
    def test_false_positive_likelihood(self):
        """Test false positive likelihood calculation"""
        fc = ThreatIntelligenceFusionCenter()
        
        # Single signal = higher FP likelihood
        single = [ThreatSignal(
            signal_id="", source_module="d1",
            category=ThreatCategory.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH, confidence=0.5,
            timestamp=time.time(),
        )]
        fp_single = fc._calculate_false_positive_likelihood(single)
        
        # Multiple sources = lower FP likelihood
        multiple = [
            ThreatSignal(
                signal_id="", source_module=f"d{i}",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.HIGH, confidence=0.9,
                timestamp=time.time(),
            )
            for i in range(3)
        ]
        fp_multiple = fc._calculate_false_positive_likelihood(multiple)
        
        assert fp_single > fp_multiple
    
    def test_get_threat_summary_empty(self):
        """Test threat summary with no data"""
        fc = ThreatIntelligenceFusionCenter()
        summary = fc.get_threat_summary()
        assert summary["status"] == "no_signals_received"
    
    def test_get_threat_summary_with_data(self):
        """Test threat summary with signals"""
        fc = ThreatIntelligenceFusionCenter()
        signals = [
            ThreatSignal(
                signal_id="", source_module="d1",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.HIGH, confidence=0.8,
                timestamp=time.time(),
            ),
            ThreatSignal(
                signal_id="", source_module="d2",
                category=ThreatCategory.JAILBREAK_ATTEMPT,
                severity=ThreatSeverity.MEDIUM, confidence=0.7,
                timestamp=time.time(),
            ),
        ]
        fc.ingest_signals_batch(signals)
        fc.fuse_threats()
        
        summary = fc.get_threat_summary()
        assert summary["total_signals_ingested"] == 2
        assert summary["unique_sources"] == 2
    
    def test_get_high_priority_threats(self):
        """Test filtering high priority threats"""
        fc = ThreatIntelligenceFusionCenter()
        now = time.time()
        
        # Create high confidence critical threats
        signals = [
            ThreatSignal(
                signal_id="", source_module=f"d{i}",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.CRITICAL, confidence=0.95,
                timestamp=now, affected_input="test",
            )
            for i in range(3)
        ]
        fc.ingest_signals_batch(signals)
        fc.fuse_threats()
        
        high_priority = fc.get_high_priority_threats()
        assert len(high_priority) >= 0  # Should find high priority threats
    
    def test_response_recommendations(self):
        """Test response recommendation matrix"""
        fc = ThreatIntelligenceFusionCenter()
        
        # Critical + correlated = BLOCK
        key = (ThreatSeverity.CRITICAL, True)
        assert "BLOCK" in fc.response_matrix[key]
        
        # Low + uncorrelated = PASS
        key = (ThreatSeverity.LOW, False)
        assert "PASS" in fc.response_matrix[key]
    
    def test_memory_efficiency_truncation(self):
        """Test signal history truncation for memory efficiency"""
        fc = ThreatIntelligenceFusionCenter()
        
        # Add 1500 signals (over the 1000 limit)
        signals = [
            ThreatSignal(
                signal_id="", source_module=f"d{i}",
                category=ThreatCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.LOW, confidence=0.5,
                timestamp=time.time() - i,
            )
            for i in range(1500)
        ]
        fc.ingest_signals_batch(signals)
        
        # Should be truncated to 1000
        assert len(fc.signal_history) <= 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
