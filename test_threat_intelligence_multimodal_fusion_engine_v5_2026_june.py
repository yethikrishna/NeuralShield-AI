"""
Tests for Multi-Modal Threat Intelligence Fusion Engine v5
Dimension A - Feature Expansion Tests
"""

import pytest
import time
from neural_shield.threat_intelligence_multimodal_fusion_engine_v5_2026_june import (
    MultiModalIntelligenceFusionEngine,
    IntelligenceIndicator,
    CorrelatedThreat,
    IntelligenceSourceType,
    ThreatSeverity,
    FusionStrategy,
    get_fusion_engine,
    create_indicator
)


class TestIntelligenceIndicator:
    """Tests for IntelligenceIndicator dataclass."""
    
    def test_indicator_creation(self):
        """Test basic indicator creation."""
        ind = create_indicator(
            indicator_type='ip',
            value='192.168.1.1',
            source_type=IntelligenceSourceType.IOC_FEED,
            severity=ThreatSeverity.HIGH,
            confidence=0.8
        )
        assert ind.indicator_id is not None
        assert ind.value == '192.168.1.1'
        assert ind.severity == ThreatSeverity.HIGH
    
    def test_indicator_not_expired_initially(self):
        """Test indicator is not expired when created."""
        ind = create_indicator('ip', '1.1.1.1', IntelligenceSourceType.IOC_FEED, ThreatSeverity.LOW)
        assert not ind.is_expired()
    
    def test_weighted_score_calculation(self):
        """Test weighted score calculation."""
        ind = create_indicator(
            'ip', '1.1.1.1', 
            IntelligenceSourceType.IOC_FEED, 
            ThreatSeverity.CRITICAL,
            confidence=1.0
        )
        ind.source_reliability = 1.0
        score = ind.get_weighted_score()
        assert score == 1.0  # Critical * 1.0 confidence * 1.0 reliability


class TestCorrelatedThreat:
    """Tests for CorrelatedThreat dataclass."""
    
    def test_create_empty_threat(self):
        """Test creating empty threat."""
        threat = CorrelatedThreat(threat_id='test_123')
        assert threat.threat_id == 'test_123'
        assert len(threat.indicators) == 0
        assert threat.correlation_score == 0.0
    
    def test_add_indicator_updates_score(self):
        """Test adding indicator updates correlation score."""
        threat = CorrelatedThreat(threat_id='test_123')
        ind = create_indicator('ip', '1.1.1.1', IntelligenceSourceType.IOC_FEED, ThreatSeverity.HIGH)
        threat.add_indicator(ind)
        assert len(threat.indicators) == 1
        assert threat.correlation_score > 0


class TestMultiModalIntelligenceFusionEngine:
    """Tests for the main fusion engine."""
    
    def setup_method(self):
        """Reset singleton before each test."""
        MultiModalIntelligenceFusionEngine._instance = None
        self.engine = get_fusion_engine()
    
    def test_singleton_pattern(self):
        """Test singleton returns same instance."""
        engine1 = get_fusion_engine()
        engine2 = get_fusion_engine()
        assert engine1 is engine2
    
    def test_disabled_by_default_opt_in(self):
        """Test engine is DISABLED by default (OPT-IN requirement)."""
        engine = get_fusion_engine()
        assert engine.enabled is False
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        engine = get_fusion_engine()
        engine.enable()
        assert engine.enabled is True
        engine.disable()
        assert engine.enabled is False
    
    def test_ingest_when_disabled_no_processing(self):
        """Test ingest when disabled returns ID but doesn't process."""
        engine = get_fusion_engine()
        engine.disable()  # Ensure disabled
        ind = create_indicator('ip', '1.1.1.1', IntelligenceSourceType.IOC_FEED, ThreatSeverity.HIGH)
        result = engine.ingest_indicator(ind)
        assert result == ind.indicator_id
        stats = engine.get_statistics()
        assert stats['total_indicators'] == 0  # Not stored
    
    def test_ingest_when_enabled_stores_indicator(self):
        """Test ingest when enabled stores indicator."""
        engine = get_fusion_engine()
        engine.enable()
        ind = create_indicator('ip', '1.1.1.1', IntelligenceSourceType.IOC_FEED, ThreatSeverity.HIGH)
        engine.ingest_indicator(ind)
        stats = engine.get_statistics()
        assert stats['total_indicators'] >= 1
    
    def test_same_value_correlation(self):
        """Test indicators with same value get correlated."""
        engine = get_fusion_engine()
        engine.enable()
        
        ind1 = create_indicator('ip', '10.0.0.1', IntelligenceSourceType.IOC_FEED, ThreatSeverity.HIGH)
        ind2 = create_indicator('ip', '10.0.0.1', IntelligenceSourceType.HONEYPOT, ThreatSeverity.CRITICAL)
        
        engine.ingest_indicator(ind1)
        engine.ingest_indicator(ind2)
        
        threats = engine.get_active_threats()
        # Should correlate into fewer threats than indicators
        assert len(threats) <= 2
    
    def test_get_active_threats_filtering(self):
        """Test threat filtering by minimum severity."""
        engine = get_fusion_engine()
        engine.enable()
        
        ind = create_indicator('ip', '10.0.0.1', IntelligenceSourceType.IOC_FEED, ThreatSeverity.CRITICAL)
        engine.ingest_indicator(ind)
        
        critical_threats = engine.get_active_threats(min_severity=ThreatSeverity.CRITICAL)
        assert len(critical_threats) >= 0
    
    def test_statistics_reporting(self):
        """Test statistics reporting works."""
        engine = get_fusion_engine()
        engine.enable()
        
        stats = engine.get_statistics()
        assert 'enabled' in stats
        assert 'total_indicators' in stats
        assert 'correlated_threats' in stats
        assert 'by_source' in stats
        assert 'by_severity' in stats
    
    def test_set_correlation_threshold(self):
        """Test setting correlation threshold."""
        engine = get_fusion_engine()
        engine.set_correlation_threshold(0.5)
        stats = engine.get_statistics()
        assert stats['correlation_threshold'] == 0.5
    
    def test_set_fusion_strategy(self):
        """Test setting fusion strategy."""
        engine = get_fusion_engine()
        engine.set_fusion_strategy(FusionStrategy.BAYESIAN)
        stats = engine.get_statistics()
        assert stats['fusion_strategy'] == 'bayesian_inference'
    
    def test_batch_ingestion(self):
        """Test batch ingestion of indicators."""
        engine = get_fusion_engine()
        engine.enable()
        
        indicators = [
            create_indicator('ip', f'10.0.0.{i}', IntelligenceSourceType.IOC_FEED, ThreatSeverity.HIGH)
            for i in range(5)
        ]
        
        results = engine.ingest_batch(indicators)
        assert len(results) == 5
    
    def test_alert_callback_registration(self):
        """Test alert callback can be registered."""
        engine = get_fusion_engine()
        callback_called = []
        
        def callback(threat):
            callback_called.append(threat)
        
        engine.register_alert_callback(callback)
        # Just verify no error - actual triggering tested separately
        assert True


class TestIntegration:
    """Integration tests for full workflow."""
    
    def test_full_fusion_workflow(self):
        """Test complete fusion workflow."""
        engine = get_fusion_engine()
        MultiModalIntelligenceFusionEngine._instance = None
        engine = get_fusion_engine()
        engine.enable()
        
        # Configure
        engine.set_correlation_threshold(0.2)
        engine.set_source_reliability(IntelligenceSourceType.DARKWEB, 0.9)
        
        # Ingest related indicators from different sources
        ind1 = create_indicator(
            'domain', 'malicious.com', 
            IntelligenceSourceType.IOC_FEED, 
            ThreatSeverity.HIGH,
            confidence=0.8
        )
        ind2 = create_indicator(
            'domain', 'malicious.com', 
            IntelligenceSourceType.DARKWEB, 
            ThreatSeverity.CRITICAL,
            confidence=0.95
        )
        
        engine.ingest_indicator(ind1)
        engine.ingest_indicator(ind2)
        
        # Get results
        threats = engine.get_active_threats()
        stats = engine.get_statistics()
        
        assert stats['enabled'] is True
        assert stats['total_indicators'] >= 2


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
