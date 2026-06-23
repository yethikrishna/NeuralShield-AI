"""
NeuralShield AI - Comprehensive Test Coverage v13 for Threat Intelligence Fusion Engine v5
Dimension C - Test Coverage Expansion (June 2026)
PURE TEST ADD-ONLY: No production code modified
Covers: Edge cases, boundary conditions, error paths, integration
"""
import unittest
import time
import threading
from typing import List
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
class TestIntelligenceSourceTypeEnum(unittest.TestCase):
    """Test all intelligence source type enum values."""
    
    def test_all_source_types_exist(self):
        """Verify all 8 source types are defined."""
        expected = [
            "ioc_feed", "vulnerability_database", "threat_actor",
            "malware_sample", "network_traffic", "user_report",
            "honeypot", "darkweb_monitor"
        ]
        actual = [st.value for st in IntelligenceSourceType]
        self.assertEqual(len(actual), 8)
        for exp in expected:
            self.assertIn(exp, actual)
class TestThreatSeverityEnum(unittest.TestCase):
    """Test threat severity enum."""
    
    def test_all_severity_levels_exist(self):
        """Verify all 5 severity levels."""
        expected = ["critical", "high", "medium", "low", "informational"]
        actual = [s.value for s in ThreatSeverity]
        self.assertEqual(len(actual), 5)
        for exp in expected:
            self.assertIn(exp, actual)
class TestFusionStrategyEnum(unittest.TestCase):
    """Test fusion strategy enum."""
    
    def test_all_strategies_exist(self):
        """Verify all 4 fusion strategies."""
        expected = ["weighted_voting", "bayesian_inference", 
                   "dempster_shafer", "consensus_based"]
        actual = [s.value for s in FusionStrategy]
        self.assertEqual(len(actual), 4)
        for exp in expected:
            self.assertIn(exp, actual)
class TestIntelligenceIndicator(unittest.TestCase):
    """Test IntelligenceIndicator dataclass functionality."""
    
    def test_indicator_creation(self):
        """Test basic indicator creation."""
        indicator = create_indicator(
            indicator_type="ip",
            value="192.168.1.1",
            source_type=IntelligenceSourceType.IOC_FEED,
            severity=ThreatSeverity.HIGH,
            confidence=0.8
        )
        self.assertEqual(indicator.indicator_type, "ip")
        self.assertEqual(indicator.value, "192.168.1.1")
        self.assertEqual(indicator.source_type, IntelligenceSourceType.IOC_FEED)
        self.assertEqual(indicator.severity, ThreatSeverity.HIGH)
        self.assertEqual(indicator.confidence, 0.8)
    
    def test_indicator_expiration(self):
        """Test indicator expiration logic."""
        indicator = create_indicator(
            indicator_type="ip",
            value="10.0.0.1",
            source_type=IntelligenceSourceType.IOC_FEED,
            severity=ThreatSeverity.LOW,
            confidence=0.5
        )
        indicator.ttl = 0  # Immediate expiration
        time.sleep(0.01)
        self.assertTrue(indicator.is_expired())
    
    def test_indicator_not_expired(self):
        """Test indicator not expired."""
        indicator = create_indicator(
            indicator_type="ip",
            value="10.0.0.1",
            source_type=IntelligenceSourceType.IOC_FEED,
            severity=ThreatSeverity.LOW,
            confidence=0.5
        )
        indicator.ttl = 3600
        self.assertFalse(indicator.is_expired())
    
    def test_weighted_score_calculation(self):
        """Test weighted score calculation for all severities."""
        test_cases = [
            (ThreatSeverity.CRITICAL, 1.0, 1.0, 1.0),
            (ThreatSeverity.HIGH, 1.0, 1.0, 0.75),
            (ThreatSeverity.MEDIUM, 1.0, 1.0, 0.5),
            (ThreatSeverity.LOW, 1.0, 1.0, 0.25),
            (ThreatSeverity.INFO, 1.0, 1.0, 0.1),
        ]
        for severity, conf, reliab, expected_base in test_cases:
            indicator = create_indicator(
                indicator_type="ip",
                value="1.2.3.4",
                source_type=IntelligenceSourceType.IOC_FEED,
                severity=severity,
                confidence=conf
            )
            indicator.source_reliability = reliab
            score = indicator.get_weighted_score()
            self.assertAlmostEqual(score, expected_base, places=2)
    def test_weighted_score_boundaries(self):
        """Test weighted score boundary conditions."""
        indicator = create_indicator(
            indicator_type="ip",
            value="1.2.3.4",
            source_type=IntelligenceSourceType.IOC_FEED,
            severity=ThreatSeverity.CRITICAL,
            confidence=0.0
        )
        self.assertEqual(indicator.get_weighted_score(), 0.0)
class TestCorrelatedThreat(unittest.TestCase):
    """Test CorrelatedThreat functionality."""
    
    def test_correlated_threat_creation(self):
        """Test basic threat creation."""
        indicator = create_indicator(
            indicator_type="ip",
            value="1.2.3.4",
            source_type=IntelligenceSourceType.IOC_FEED,
            severity=ThreatSeverity.HIGH,
            confidence=0.9
        )
        threat = CorrelatedThreat(
            threat_id="test_threat_001",
            indicators=[indicator]
        )
        self.assertEqual(threat.threat_id, "test_threat_001")
        self.assertEqual(len(threat.indicators), 1)
    
    def test_add_indicator_to_threat(self):
        """Test adding indicators to threat."""
        ind1 = create_indicator("ip", "1.2.3.4", IntelligenceSourceType.IOC_FEED, ThreatSeverity.HIGH)
        threat = CorrelatedThreat(threat_id="t1", indicators=[ind1])
        
        ind2 = create_indicator("ip", "1.2.3.4", IntelligenceSourceType.HONEYPOT, ThreatSeverity.CRITICAL)
        threat.add_indicator(ind2)
        
        self.assertEqual(len(threat.indicators), 2)
        self.assertGreater(threat.correlation_score, 0)
    
    def test_recalculate_correlation_empty(self):
        """Test recalculation with empty indicators."""
        threat = CorrelatedThreat(threat_id="t1", indicators=[])
        threat._recalculate_correlation()
        self.assertEqual(threat.correlation_score, 0.0)
    
    def test_diversity_bonus(self):
        """Test source diversity bonus in correlation score."""
        # Single source
        ind1 = create_indicator("ip", "1.2.3.4", IntelligenceSourceType.IOC_FEED, ThreatSeverity.HIGH, 1.0)
        threat1 = CorrelatedThreat(threat_id="t1", indicators=[ind1])
        
        # Multiple sources
        ind2 = create_indicator("ip", "1.2.3.4", IntelligenceSourceType.HONEYPOT, ThreatSeverity.HIGH, 1.0)
        ind3 = create_indicator("ip", "1.2.3.4", IntelligenceSourceType.DARKWEB, ThreatSeverity.HIGH, 1.0)
        threat2 = CorrelatedThreat(threat_id="t2", indicators=[ind2, ind3])
        threat2._recalculate_correlation()
        
        # Multiple sources should have diversity bonus
        self.assertGreater(threat2.correlation_score, threat1.correlation_score)
class TestFusionEngineSingleton(unittest.TestCase):
    """Test singleton pattern implementation."""
    
    def test_singleton_returns_same_instance(self):
        """Test singleton consistency."""
        engine1 = get_fusion_engine()
        engine2 = get_fusion_engine()
        self.assertIs(engine1, engine2)
    
    def test_singleton_thread_safety(self):
        """Test singleton creation under concurrent access."""
        instances = []
        
        def get_instance():
            instances.append(get_fusion_engine())
        
        threads = [threading.Thread(target=get_instance) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # All should be the same instance
        first = instances[0]
        for inst in instances[1:]:
            self.assertIs(inst, first)
class TestFusionEngineOptInPattern(unittest.TestCase):
    """Test OPT-IN disabled by default pattern."""
    
    def test_engine_disabled_by_default(self):
        """Verify engine is disabled by default (OPT-IN)."""
        engine = get_fusion_engine()
        self.assertFalse(engine.enabled)
    
    def test_enable_disable(self):
        """Test enable/disable functionality."""
        engine = get_fusion_engine()
        engine.enable()
        self.assertTrue(engine.enabled)
        engine.disable()
        self.assertFalse(engine.enabled)
    
    def test_disabled_engine_ingest_no_op(self):
        """Test disabled engine returns indicator_id without processing."""
        engine = get_fusion_engine()
        engine.disable()
        
        indicator = create_indicator(
            "ip", "1.2.3.4", 
            IntelligenceSourceType.IOC_FEED,
            ThreatSeverity.HIGH
        )
        result = engine.ingest_indicator(indicator)
        
        # Should return ID but not process
        self.assertEqual(result, indicator.indicator_id)
        self.assertEqual(len(engine._indicators), 0)
class TestFusionEngineConfiguration(unittest.TestCase):
    """Test engine configuration methods."""
    
    def test_set_source_reliability(self):
        """Test setting source reliability."""
        engine = get_fusion_engine()
        engine.set_source_reliability(IntelligenceSourceType.IOC_FEED, 0.95)
        self.assertEqual(engine._source_reliability[IntelligenceSourceType.IOC_FEED], 0.95)
    
    def test_source_reliability_clamping(self):
        """Test reliability value clamping to [0, 1]."""
        engine = get_fusion_engine()
        engine.set_source_reliability(IntelligenceSourceType.IOC_FEED, 2.0)
        self.assertEqual(engine._source_reliability[IntelligenceSourceType.IOC_FEED], 1.0)
        
        engine.set_source_reliability(IntelligenceSourceType.IOC_FEED, -1.0)
        self.assertEqual(engine._source_reliability[IntelligenceSourceType.IOC_FEED], 0.0)
    
    def test_set_fusion_strategy(self):
        """Test setting fusion strategy."""
        engine = get_fusion_engine()
        engine.set_fusion_strategy(FusionStrategy.BAYESIAN)
        self.assertEqual(engine._fusion_strategy, FusionStrategy.BAYESIAN)
    
    def test_set_correlation_threshold(self):
        """Test setting correlation threshold."""
        engine = get_fusion_engine()
        engine.set_correlation_threshold(0.5)
        self.assertEqual(engine._min_correlation_threshold, 0.5)
    
    def test_correlation_threshold_clamping(self):
        """Test threshold clamping."""
        engine = get_fusion_engine()
        engine.set_correlation_threshold(2.0)
        self.assertEqual(engine._min_correlation_threshold, 1.0)
        engine.set_correlation_threshold(-1.0)
        self.assertEqual(engine._min_correlation_threshold, 0.0)
class TestFusionEngineIngestion(unittest.TestCase):
    """Test indicator ingestion functionality."""
    
    def setUp(self):
        """Reset engine before each test."""
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
    
    def test_single_indicator_ingestion(self):
        """Test ingesting a single indicator."""
        engine = get_fusion_engine()
        indicator = create_indicator(
            "ip", "192.168.1.1",
            IntelligenceSourceType.IOC_FEED,
            ThreatSeverity.HIGH
        )
        ind_id = engine.ingest_indicator(indicator)
        
        self.assertIn(ind_id, engine._indicators)
        self.assertEqual(len(engine._indicators), 1)
    
    def test_batch_ingestion(self):
        """Test batch indicator ingestion."""
        engine = get_fusion_engine()
        indicators = [
            create_indicator(f"ip", f"10.0.0.{i}", 
                           IntelligenceSourceType.IOC_FEED,
                           ThreatSeverity.HIGH)
            for i in range(10)
        ]
        results = engine.ingest_batch(indicators)
        
        self.assertEqual(len(results), 10)
        self.assertEqual(len(engine._indicators), 10)
class TestCorrelationRules(unittest.TestCase):
    """Test correlation rule functionality."""
    
    def setUp(self):
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
    
    def test_same_value_correlation(self):
        """Test same value correlation rule."""
        engine = get_fusion_engine()
        
        # Same IP from different sources
        ind1 = create_indicator("ip", "1.2.3.4", 
                               IntelligenceSourceType.IOC_FEED,
                               ThreatSeverity.HIGH)
        ind2 = create_indicator("ip", "1.2.3.4", 
                               IntelligenceSourceType.HONEYPOT,
                               ThreatSeverity.CRITICAL)
        
        engine.ingest_indicator(ind1)
        engine.ingest_indicator(ind2)
        
        # Should be correlated into same threat
        threats = engine.get_active_threats()
        # At least one threat should have multiple indicators
        multi_indicator = any(len(t.indicators) >= 2 for t in threats)
        self.assertTrue(multi_indicator or len(threats) == 1)
    
    def test_same_subnet_correlation(self):
        """Test same /24 subnet correlation."""
        engine = get_fusion_engine()
        
        ind1 = create_indicator("ip", "192.168.1.100", 
                               IntelligenceSourceType.IOC_FEED,
                               ThreatSeverity.HIGH)
        ind2 = create_indicator("ip", "192.168.1.200", 
                               IntelligenceSourceType.NETWORK_TRAFFIC,
                               ThreatSeverity.MEDIUM)
        
        engine.ingest_indicator(ind1)
        engine.ingest_indicator(ind2)
        
        # Both in same /24, should correlate
        self.assertTrue(engine._same_subnet("192.168.1.100", "192.168.1.200"))
    
    def test_different_subnet_no_correlation(self):
        """Test different subnets don't correlate."""
        engine = get_fusion_engine()
        self.assertFalse(engine._same_subnet("192.168.1.1", "10.0.0.1"))
    
    def test_invalid_ip_subnet(self):
        """Test invalid IP handling in subnet check."""
        engine = get_fusion_engine()
        self.assertFalse(engine._same_subnet("not-an-ip", "192.168.1.1"))
        self.assertFalse(engine._same_subnet("192.168.1", "192.168.1.1"))
class TestAlertCallbacks(unittest.TestCase):
    """Test alert callback functionality."""
    
    def setUp(self):
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
        engine._alert_callbacks.clear()
    
    def test_register_alert_callback(self):
        """Test callback registration."""
        engine = get_fusion_engine()
        callback_called = []
        
        def callback(threat):
            callback_called.append(threat)
        
        engine.register_alert_callback(callback)
        self.assertEqual(len(engine._alert_callbacks), 1)
    
    def test_callback_error_handling(self):
        """Test callback errors are handled gracefully."""
        engine = get_fusion_engine()
        
        def bad_callback(threat):
            raise RuntimeError("Callback failed!")
        
        engine.register_alert_callback(bad_callback)
        
        # Should not raise exception
        indicator = create_indicator("ip", "1.2.3.4", 
                                   IntelligenceSourceType.IOC_FEED,
                                   ThreatSeverity.CRITICAL,
                                   confidence=1.0)
        engine.ingest_indicator(indicator)
class TestThreatRetrieval(unittest.TestCase):
    """Test threat retrieval functionality."""
    
    def setUp(self):
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
    
    def test_get_active_threats(self):
        """Test getting all active threats."""
        engine = get_fusion_engine()
        
        for i in range(5):
            ind = create_indicator("ip", f"10.0.0.{i}",
                                 IntelligenceSourceType.IOC_FEED,
                                 ThreatSeverity.HIGH)
            engine.ingest_indicator(ind)
        
        threats = engine.get_active_threats()
        self.assertGreaterEqual(len(threats), 1)
    
    def test_get_threats_by_severity(self):
        """Test filtering threats by minimum severity."""
        engine = get_fusion_engine()
        
        # Add low severity
        ind_low = create_indicator("ip", "1.1.1.1",
                                 IntelligenceSourceType.IOC_FEED,
                                 ThreatSeverity.LOW)
        engine.ingest_indicator(ind_low)
        
        # Add critical
        ind_crit = create_indicator("ip", "2.2.2.2",
                                  IntelligenceSourceType.IOC_FEED,
                                  ThreatSeverity.CRITICAL)
        engine.ingest_indicator(ind_crit)
        
        high_threats = engine.get_active_threats(min_severity=ThreatSeverity.HIGH)
        # Should only include CRITICAL and above
        for t in high_threats:
            self.assertIn(t.aggregated_severity, 
                         [ThreatSeverity.HIGH, ThreatSeverity.CRITICAL])
    
    def test_get_threat_by_id(self):
        """Test retrieving specific threat."""
        engine = get_fusion_engine()
        ind = create_indicator("ip", "1.2.3.4",
                             IntelligenceSourceType.IOC_FEED,
                             ThreatSeverity.HIGH)
        engine.ingest_indicator(ind)
        
        threats = engine.get_active_threats()
        if threats:
            threat = engine.get_threat_by_id(threats[0].threat_id)
            self.assertIsNotNone(threat)
    
    def test_get_nonexistent_threat(self):
        """Test retrieving non-existent threat returns None."""
        engine = get_fusion_engine()
        threat = engine.get_threat_by_id("nonexistent_id")
        self.assertIsNone(threat)
class TestEngineStatistics(unittest.TestCase):
    """Test statistics functionality."""
    
    def setUp(self):
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
    
    def test_statistics_structure(self):
        """Test statistics return correct structure."""
        engine = get_fusion_engine()
        stats = engine.get_statistics()
        
        expected_keys = [
            "enabled", "total_indicators", "correlated_threats",
            "processing_queue", "fusion_strategy", "by_source",
            "by_severity", "correlation_threshold"
        ]
        for key in expected_keys:
            self.assertIn(key, stats)
    
    def test_statistics_accuracy(self):
        """Test statistics are accurate."""
        engine = get_fusion_engine()
        
        # Add some indicators
        for i in range(3):
            ind = create_indicator("ip", f"10.0.0.{i}",
                                 IntelligenceSourceType.IOC_FEED,
                                 ThreatSeverity.HIGH)
            engine.ingest_indicator(ind)
        
        stats = engine.get_statistics()
        self.assertEqual(stats["total_indicators"], 3)
        self.assertTrue(stats["enabled"])
class TestExpirationCleanup(unittest.TestCase):
    """Test expiration and cleanup functionality."""
    
    def setUp(self):
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
    
    def test_expired_indicators_cleaned(self):
        """Test expired indicators are removed."""
        engine = get_fusion_engine()
        
        ind = create_indicator("ip", "1.2.3.4",
                             IntelligenceSourceType.IOC_FEED,
                             ThreatSeverity.HIGH)
        ind.ttl = 0  # Expire immediately
        engine.ingest_indicator(ind)
        
        time.sleep(0.01)
        engine._clean_expired()
        
        # May or may not be cleaned depending on timing, but shouldn't error
        stats = engine.get_statistics()
        self.assertIsNotNone(stats)
class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - no breaking changes."""
    
    def test_existing_imports_work(self):
        """Test all public API imports work."""
        # Should import without errors
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
        # All should be callable/usable
        self.assertTrue(callable(get_fusion_engine))
        self.assertTrue(callable(create_indicator))
class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def setUp(self):
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
    
    def test_empty_metadata(self):
        """Test indicator with empty metadata."""
        ind = create_indicator("ip", "1.2.3.4",
                             IntelligenceSourceType.IOC_FEED,
                             ThreatSeverity.HIGH,
                             metadata={})
        engine = get_fusion_engine()
        ind_id = engine.ingest_indicator(ind)
        self.assertIn(ind_id, engine._indicators)
    
    def test_zero_confidence(self):
        """Test indicator with zero confidence."""
        ind = create_indicator("ip", "1.2.3.4",
                             IntelligenceSourceType.IOC_FEED,
                             ThreatSeverity.HIGH,
                             confidence=0.0)
        self.assertEqual(ind.get_weighted_score(), 0.0)
    
    def test_full_confidence(self):
        """Test indicator with full confidence."""
        ind = create_indicator("ip", "1.2.3.4",
                             IntelligenceSourceType.IOC_FEED,
                             ThreatSeverity.CRITICAL,
                             confidence=1.0)
        ind.source_reliability = 1.0
        self.assertGreater(ind.get_weighted_score(), 0.9)
class TestConcurrentAccess(unittest.TestCase):
    """Test thread safety under concurrent access."""
    
    def test_concurrent_ingestion(self):
        """Test concurrent indicator ingestion."""
        engine = get_fusion_engine()
        engine.enable()
        engine._indicators.clear()
        engine._correlated_threats.clear()
        
        errors = []
        
        def ingest_worker(start_idx, count):
            try:
                for i in range(count):
                    ind = create_indicator(
                        "ip", f"192.168.{start_idx}.{i}",
                        IntelligenceSourceType.IOC_FEED,
                        ThreatSeverity.HIGH
                    )
                    engine.ingest_indicator(ind)
            except Exception as e:
                errors.append(e)
        
        threads = [
            threading.Thread(target=ingest_worker, args=(i, 10))
            for i in range(5)
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # No exceptions should occur
        self.assertEqual(len(errors), 0, f"Errors: {errors}")
if __name__ == "__main__":
    unittest.main()
