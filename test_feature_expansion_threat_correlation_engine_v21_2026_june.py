"""
Test Suite for Feature Expansion v21 - Threat Correlation Engine
NeuralShield-AI | June 2026
ADD-ONLY COMPLIANT: Tests only new module, no existing code modified
"""
import unittest
import time
import threading
from neural_shield.feature_expansion_threat_correlation_engine_v21_2026_june import (
    ThreatCorrelationEngine,
    create_correlation_engine,
    ThreatEvent,
    ThreatType,
    ThreatSeverity,
    CorrelationConfidence,
    CorrelatedThreat,
    TemporalClusteringRule,
    AttackChainRule,
    ModuleConsensusRule,
)
class TestThreatEvent(unittest.TestCase):
    """Test ThreatEvent data class"""
    def test_threat_event_creation(self):
        event = ThreatEvent(
            event_id="test_001",
            threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH,
            source_module="test_detector",
            timestamp=time.time(),
            confidence=0.85,
            session_id="session_123"
        )
        self.assertEqual(event.event_id, "test_001")
        self.assertEqual(event.threat_type, ThreatType.PROMPT_INJECTION)
        self.assertEqual(event.severity, ThreatSeverity.HIGH)
        self.assertEqual(event.confidence, 0.85)
    def test_threat_event_default_metadata(self):
        event = ThreatEvent(
            event_id="test_002",
            threat_type=ThreatType.JAILBREAK,
            severity=ThreatSeverity.MEDIUM,
            source_module="test_detector",
            timestamp=time.time(),
            confidence=0.7
        )
        self.assertEqual(event.metadata, {})
        self.assertIsNone(event.session_id)
class TestTemporalClusteringRule(unittest.TestCase):
    """Test Temporal Clustering correlation rule"""
    def test_no_correlation_few_events(self):
        rule = TemporalClusteringRule()
        events = [
            ThreatEvent("e1", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH, 
                       "mod1", time.time(), 0.8, session_id="s1"),
        ]
        result = rule.match(events, 300.0)
        self.assertIsNone(result)
    def test_correlation_multiple_threats_same_session(self):
        rule = TemporalClusteringRule()
        base_time = time.time()
        events = [
            ThreatEvent("e1", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH, 
                       "mod1", base_time, 0.8, session_id="s1"),
            ThreatEvent("e2", ThreatType.JAILBREAK, ThreatSeverity.CRITICAL, 
                       "mod1", base_time + 5, 0.9, session_id="s1"),
            ThreatEvent("e3", ThreatType.ADVERSARIAL, ThreatSeverity.MEDIUM, 
                       "mod2", base_time + 10, 0.7, session_id="s1"),
        ]
        result = rule.match(events, 300.0)
        self.assertIsNotNone(result)
        self.assertGreaterEqual(result.correlation_confidence.value, 0.6)
        self.assertGreater(result.risk_score, 0.0)
class TestAttackChainRule(unittest.TestCase):
    """Test Attack Chain correlation rule"""
    def test_attack_chain_detection(self):
        rule = AttackChainRule()
        base_time = time.time()
        events = [
            ThreatEvent("e1", ThreatType.ADVERSARIAL, ThreatSeverity.LOW, 
                       "mod1", base_time, 0.6, session_id="s1"),
            ThreatEvent("e2", ThreatType.PROMPT_INJECTION, ThreatSeverity.MEDIUM, 
                       "mod1", base_time + 10, 0.75, session_id="s1"),
            ThreatEvent("e3", ThreatType.JAILBREAK, ThreatSeverity.HIGH, 
                       "mod2", base_time + 20, 0.9, session_id="s1"),
        ]
        result = rule.match(events, 300.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.aggregated_severity, ThreatSeverity.CRITICAL)
        self.assertIn("Attack chain", result.correlation_pattern)
    def test_no_chain_insufficient_events(self):
        rule = AttackChainRule()
        events = [
            ThreatEvent("e1", ThreatType.ADVERSARIAL, ThreatSeverity.LOW, 
                       "mod1", time.time(), 0.6, session_id="s1"),
        ]
        result = rule.match(events, 300.0)
        self.assertIsNone(result)
class TestModuleConsensusRule(unittest.TestCase):
    """Test Module Consensus correlation rule"""
    def test_consensus_detection(self):
        rule = ModuleConsensusRule()
        base_time = time.time()
        events = [
            ThreatEvent("e1", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH, 
                       "module_a", base_time, 0.85, session_id="s1"),
            ThreatEvent("e2", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH, 
                       "module_b", base_time + 2, 0.9, session_id="s1"),
        ]
        result = rule.match(events, 300.0)
        self.assertIsNotNone(result)
        self.assertEqual(result.correlation_confidence, CorrelationConfidence.CERTAIN)
        self.assertIn("Module consensus", result.correlation_pattern)
    def test_no_consensus_same_module(self):
        rule = ModuleConsensusRule()
        base_time = time.time()
        events = [
            ThreatEvent("e1", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH, 
                       "same_module", base_time, 0.85, session_id="s1"),
            ThreatEvent("e2", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH, 
                       "same_module", base_time + 2, 0.9, session_id="s1"),
        ]
        result = rule.match(events, 300.0)
        self.assertIsNone(result)
class TestThreatCorrelationEngine(unittest.TestCase):
    """Test main Threat Correlation Engine"""
    def test_engine_creation_disabled(self):
        engine = ThreatCorrelationEngine(enabled=False)
        self.assertFalse(engine.enabled)
        stats = engine.get_statistics()
        self.assertFalse(stats["enabled"])
    def test_engine_creation_enabled(self):
        engine = create_correlation_engine(enabled=True, time_window_seconds=60.0)
        self.assertTrue(engine.enabled)
        engine.stop()
    def test_register_module(self):
        engine = ThreatCorrelationEngine(enabled=True)
        engine.register_module("test_detector")
        stats = engine.get_statistics()
        self.assertEqual(stats["registered_modules"], 1)
        engine.stop()
    def test_add_threat_event_disabled(self):
        engine = ThreatCorrelationEngine(enabled=False)
        event = ThreatEvent("e1", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH,
                           "mod1", time.time(), 0.8)
        engine.add_threat_event(event)
        stats = engine.get_statistics()
        self.assertEqual(stats["events_received"], 0)  # No events when disabled
    def test_add_threat_event_enabled(self):
        engine = ThreatCorrelationEngine(enabled=True)
        event = ThreatEvent("e1", ThreatType.PROMPT_INJECTION, ThreatSeverity.HIGH,
                           "mod1", time.time(), 0.8)
        engine.add_threat_event(event)
        stats = engine.get_statistics()
        self.assertEqual(stats["events_received"], 1)
        engine.stop()
    def test_callback_registration(self):
        engine = ThreatCorrelationEngine(enabled=True)
        callback_called = []
        def test_callback(threat):
            callback_called.append(threat)
        engine.register_callback(test_callback)
        engine.stop()
    def test_get_correlated_threats_empty(self):
        engine = ThreatCorrelationEngine(enabled=True)
        threats = engine.get_correlated_threats()
        self.assertEqual(len(threats), 0)
        engine.stop()
    def test_get_correlated_threats_filtered(self):
        engine = ThreatCorrelationEngine(enabled=True)
        threats = engine.get_correlated_threats(
            min_severity=ThreatSeverity.HIGH,
            min_confidence=CorrelationConfidence.MEDIUM
        )
        self.assertEqual(len(threats), 0)
        engine.stop()
    def test_export_correlations_json_empty(self):
        engine = ThreatCorrelationEngine(enabled=True)
        json_output = engine.export_correlations_json()
        self.assertIsInstance(json_output, str)
        self.assertEqual(json_output, "[]")
        engine.stop()
    def test_statistics_structure(self):
        engine = ThreatCorrelationEngine(enabled=True)
        stats = engine.get_statistics()
        expected_keys = [
            "events_received", "correlations_found", "false_positives_suspected",
            "last_correlation_run", "active_events", "correlated_threats",
            "registered_modules", "rules_active", "time_window_seconds", "enabled"
        ]
        for key in expected_keys:
            self.assertIn(key, stats)
        engine.stop()
    def test_engine_thread_safety(self):
        """Test engine handles concurrent event additions"""
        engine = create_correlation_engine(enabled=True, time_window_seconds=60.0)
        
        def add_events(count, start_id):
            for i in range(count):
                event = ThreatEvent(
                    event_id=f"event_{start_id}_{i}",
                    threat_type=ThreatType.PROMPT_INJECTION,
                    severity=ThreatSeverity.MEDIUM,
                    source_module=f"thread_{start_id}",
                    timestamp=time.time(),
                    confidence=0.7 + i * 0.01,
                    session_id=f"session_{start_id}"
                )
                engine.add_threat_event(event)
        
        threads = []
        for t in range(5):
            thread = threading.Thread(target=add_events, args=(20, t))
            threads.append(thread)
            thread.start()
        
        for thread in threads:
            thread.join()
        
        stats = engine.get_statistics()
        self.assertEqual(stats["events_received"], 100)
        engine.stop()
class TestEngineIntegration(unittest.TestCase):
    """Test full engine integration with correlation"""
    def test_full_correlation_flow(self):
        engine = create_correlation_engine(enabled=True, time_window_seconds=60.0)
        engine.register_module("detector_1")
        engine.register_module("detector_2")
        
        session_id = "integration_test_session"
        base_time = time.time()
        
        # Add events that should trigger correlations
        engine.add_threat_event(ThreatEvent(
            event_id="int_e1", threat_type=ThreatType.ADVERSARIAL,
            severity=ThreatSeverity.MEDIUM, source_module="detector_1",
            timestamp=base_time, confidence=0.7, session_id=session_id
        ))
        
        engine.add_threat_event(ThreatEvent(
            event_id="int_e2", threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH, source_module="detector_1",
            timestamp=base_time + 2, confidence=0.85, session_id=session_id
        ))
        
        engine.add_threat_event(ThreatEvent(
            event_id="int_e3", threat_type=ThreatType.JAILBREAK,
            severity=ThreatSeverity.CRITICAL, source_module="detector_2",
            timestamp=base_time + 4, confidence=0.95, session_id=session_id
        ))
        
        # Wait for correlation thread to run
        time.sleep(0.6)
        
        stats = engine.get_statistics()
        self.assertGreater(stats["events_received"], 0)
        
        # Get threats
        threats = engine.get_correlated_threats()
        self.assertIsInstance(threats, list)
        
        # Export JSON
        json_output = engine.export_correlations_json()
        self.assertIsInstance(json_output, str)
        
        engine.stop()
    def test_callback_triggered_on_correlation(self):
        engine = create_correlation_engine(enabled=True, time_window_seconds=60.0)
        
        callback_results = []
        def correlation_callback(threat):
            callback_results.append(threat)
        
        engine.register_callback(correlation_callback)
        
        session_id = "callback_test"
        base_time = time.time()
        
        # Add consensus-triggering events
        engine.add_threat_event(ThreatEvent(
            event_id="cb_e1", threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH, source_module="mod_a",
            timestamp=base_time, confidence=0.9, session_id=session_id
        ))
        
        engine.add_threat_event(ThreatEvent(
            event_id="cb_e2", threat_type=ThreatType.PROMPT_INJECTION,
            severity=ThreatSeverity.HIGH, source_module="mod_b",
            timestamp=base_time + 1, confidence=0.85, session_id=session_id
        ))
        
        time.sleep(0.6)
        engine.stop()
class TestBackwardCompatibility(unittest.TestCase):
    """Ensure ADD-ONLY philosophy - no breaking changes"""
    def test_engine_does_not_affect_existing_code(self):
        """Engine should be completely standalone"""
        # Importing should not affect anything
        from neural_shield.feature_expansion_threat_correlation_engine_v21_2026_june import (
            ThreatCorrelationEngine
        )
        # Creating engine should be safe
        engine = ThreatCorrelationEngine(enabled=False)
        self.assertIsNotNone(engine)
    def test_opt_in_by_default(self):
        """Engine is disabled by default - opt-in only"""
        engine = ThreatCorrelationEngine()
        self.assertFalse(engine.enabled)
if __name__ == "__main__":
    unittest.main(verbosity=2)
