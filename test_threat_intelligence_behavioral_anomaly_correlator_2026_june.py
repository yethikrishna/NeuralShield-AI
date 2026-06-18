"""
Test suite for Threat Intelligence Behavioral Anomaly Correlator
Production-grade tests with real-world threat scenarios
"""
import pytest
import time
import uuid
from neural_shield.threat_intelligence_behavioral_anomaly_correlator_2026_june import (
    ThreatIntelligenceBehavioralAnomalyCorrelator,
    AnomalyEvent,
    CorrelatedAnomaly,
    BehavioralSequence
)


class TestThreatIntelligenceBehavioralAnomalyCorrelator:
    """Test suite for behavioral anomaly correlator"""
    
    @pytest.fixture
    def correlator(self):
        """Create a fresh correlator instance for each test"""
        return ThreatIntelligenceBehavioralAnomalyCorrelator()
    
    @pytest.fixture
    def sample_anomalies(self):
        """Create sample anomaly events for testing"""
        base_time = time.time()
        return [
            AnomalyEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                source_feed="network_ids",
                timestamp=base_time,
                anomaly_type="port_scan",
                severity=0.6,
                entity_id="192.168.1.100",
                entity_type="ip",
                confidence=0.85
            ),
            AnomalyEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                source_feed="network_ids",
                timestamp=base_time + 60,
                anomaly_type="brute_force",
                severity=0.75,
                entity_id="192.168.1.100",
                entity_type="ip",
                confidence=0.9
            ),
            AnomalyEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                source_feed="endpoint_edr",
                timestamp=base_time + 120,
                anomaly_type="malware_execution",
                severity=0.9,
                entity_id="192.168.1.100",
                entity_type="ip",
                confidence=0.95
            ),
            AnomalyEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                source_feed="dns_monitor",
                timestamp=base_time + 180,
                anomaly_type="c2_traffic",
                severity=0.85,
                entity_id="192.168.1.100",
                entity_type="ip",
                confidence=0.88
            ),
            AnomalyEvent(
                event_id=f"evt_{uuid.uuid4().hex[:8]}",
                source_feed="unrelated_feed",
                timestamp=base_time + 10000,
                anomaly_type="phishing",
                severity=0.7,
                entity_id="10.0.0.50",
                entity_type="ip",
                confidence=0.8
            )
        ]
    
    def test_initialization(self, correlator):
        """Test proper initialization of the correlator"""
        assert correlator is not None
        assert correlator._stats['total_anomalies_processed'] == 0
        assert correlator._stats['correlations_found'] == 0
        assert len(correlator.anomaly_buffer) == 0
        assert len(correlator.entity_anomaly_map) == 0
    
    def test_add_single_anomaly(self, correlator):
        """Test adding a single anomaly event"""
        anomaly = AnomalyEvent(
            event_id="test_001",
            source_feed="test_feed",
            timestamp=time.time(),
            anomaly_type="port_scan",
            severity=0.5,
            entity_id="1.2.3.4",
            entity_type="ip",
            confidence=0.8
        )
        
        correlator.add_anomaly(anomaly)
        
        assert correlator._stats['total_anomalies_processed'] == 1
        assert len(correlator.anomaly_buffer) == 1
        assert correlator.anomaly_buffer[0].event_id == "test_001"
        assert "1.2.3.4" in correlator.entity_anomaly_map
    
    def test_add_anomalies_batch(self, correlator, sample_anomalies):
        """Test batch addition of anomalies"""
        correlator.add_anomalies_batch(sample_anomalies)
        
        assert correlator._stats['total_anomalies_processed'] == 5
        assert len(correlator.anomaly_buffer) == 5
        assert len(correlator.entity_anomaly_map) == 2  # Two different IPs
    
    def test_temporal_correlation_calculation(self, correlator):
        """Test temporal correlation scoring"""
        base_time = time.time()
        
        event1 = AnomalyEvent(
            event_id="e1", source_feed="f1", timestamp=base_time,
            anomaly_type="scan", severity=0.5, entity_id="1.1.1.1", entity_type="ip"
        )
        event2 = AnomalyEvent(
            event_id="e2", source_feed="f2", timestamp=base_time + 60,
            anomaly_type="scan", severity=0.5, entity_id="2.2.2.2", entity_type="ip"
        )
        event3 = AnomalyEvent(
            event_id="e3", source_feed="f3", timestamp=base_time + 10000,
            anomaly_type="scan", severity=0.5, entity_id="3.3.3.3", entity_type="ip"
        )
        
        # Events within window should have positive correlation
        score_close = correlator._calculate_temporal_correlation(event1, event2, 3600)
        assert score_close > 0
        
        # Events outside window should have zero correlation
        score_far = correlator._calculate_temporal_correlation(event1, event3, 3600)
        assert score_far == 0.0
    
    def test_entity_correlation_calculation(self, correlator):
        """Test entity-based correlation scoring"""
        event1 = AnomalyEvent(
            event_id="e1", source_feed="f1", timestamp=time.time(),
            anomaly_type="scan", severity=0.5, entity_id="1.1.1.1", entity_type="ip"
        )
        event2 = AnomalyEvent(
            event_id="e2", source_feed="f2", timestamp=time.time(),
            anomaly_type="scan", severity=0.5, entity_id="1.1.1.1", entity_type="ip"
        )
        event3 = AnomalyEvent(
            event_id="e3", source_feed="f3", timestamp=time.time(),
            anomaly_type="scan", severity=0.5, entity_id="2.2.2.2", entity_type="ip"
        )
        
        # Same entity should have higher correlation
        score_same = correlator._calculate_entity_correlation(event1, event2)
        score_diff = correlator._calculate_entity_correlation(event1, event3)
        
        assert score_same > score_diff
        assert score_same > 0
    
    def test_find_correlations_same_entity(self, correlator, sample_anomalies):
        """Test finding correlations for same entity across time"""
        correlator.add_anomalies_batch(sample_anomalies)
        
        correlations = correlator.find_correlations(
            time_window_seconds=3600,
            min_correlation_score=0.3
        )
        
        assert len(correlations) > 0
        assert all(isinstance(c, CorrelatedAnomaly) for c in correlations)
        assert all(0.0 <= c.correlation_score <= 1.0 for c in correlations)
        assert all(0.0 <= c.overall_severity <= 1.0 for c in correlations)
    
    def test_find_correlations_with_entity_filter(self, correlator, sample_anomalies):
        """Test correlation finding with specific entity filter"""
        correlator.add_anomalies_batch(sample_anomalies)
        
        # Filter for the main attack IP
        correlations = correlator.find_correlations(
            time_window_seconds=3600,
            entity_filter="192.168.1.100"
        )
        
        assert len(correlations) > 0
        
        # Filter for unrelated IP (only one event, should have no correlations)
        correlations_unrelated = correlator.find_correlations(
            time_window_seconds=3600,
            entity_filter="10.0.0.50"
        )
        
        assert len(correlations_unrelated) == 0
    
    def test_attack_phase_detection(self, correlator):
        """Test MITRE ATT&CK phase detection"""
        # Reconnaissance indicators
        phase1 = correlator._determine_attack_phase(['port_scan', 'dns_enum'])
        assert phase1 == 'reconnaissance'
        
        # Execution indicators
        phase2 = correlator._determine_attack_phase(['malware_execution', 'command_injection'])
        assert phase2 == 'execution'
        
        # Unknown phase
        phase3 = correlator._determine_attack_phase(['unknown_type'])
        assert phase3 == 'unknown'
    
    def test_mitre_technique_generation(self, correlator):
        """Test MITRE technique mapping"""
        events = [
            AnomalyEvent(
                event_id="e1", source_feed="f1", timestamp=time.time(),
                anomaly_type="port_scan", severity=0.5, entity_id="1.1.1.1", entity_type="ip"
            ),
            AnomalyEvent(
                event_id="e2", source_feed="f2", timestamp=time.time(),
                anomaly_type="phishing", severity=0.7, entity_id="2.2.2.2", entity_type="domain"
            )
        ]
        
        techniques = correlator._generate_mitre_techniques(events)
        
        assert len(techniques) > 0
        assert 'T1046' in techniques  # Port scan
        assert 'T1566' in techniques  # Phishing
    
    def test_recommendations_generation(self, correlator):
        """Test context-aware recommendation generation"""
        high_severity_recs = correlator._generate_recommendations(0.9, 'impact')
        medium_severity_recs = correlator._generate_recommendations(0.5, 'reconnaissance')
        
        assert len(high_severity_recs) > 0
        assert len(medium_severity_recs) > 0
        
        # High severity should include immediate response
        assert any('Immediate' in rec for rec in high_severity_recs)
    
    def test_behavioral_sequence_detection(self, correlator, sample_anomalies):
        """Test behavioral attack sequence detection"""
        sequences = correlator._detect_behavioral_sequence(sample_anomalies, 3600)
        
        assert len(sequences) > 0
        assert all(isinstance(s, BehavioralSequence) for s in sequences)
        assert all(len(s.events) >= 3 for s in sequences)
        assert all(0.0 <= s.rarity_score <= 1.0 for s in sequences)
    
    def test_get_entity_anomaly_history(self, correlator, sample_anomalies):
        """Test retrieving anomaly history for specific entities"""
        correlator.add_anomalies_batch(sample_anomalies)
        
        history = correlator.get_entity_anomaly_history("192.168.1.100")
        
        assert len(history) == 4
        assert all(e.entity_id == "192.168.1.100" for e in history)
        # Should be sorted newest first
        assert history[0].timestamp >= history[-1].timestamp
    
    def test_correlation_statistics(self, correlator, sample_anomalies):
        """Test statistics generation"""
        correlator.add_anomalies_batch(sample_anomalies)
        correlator.find_correlations()
        
        stats = correlator.get_correlation_statistics()
        
        assert 'processing_stats' in stats
        assert 'feed_statistics' in stats
        assert 'unique_entities_tracked' in stats
        assert stats['processing_stats']['total_anomalies_processed'] == 5
        assert stats['unique_entities_tracked'] == 2
    
    def test_threat_summary_generation(self, correlator, sample_anomalies):
        """Test threat summary report generation"""
        correlator.add_anomalies_batch(sample_anomalies)
        correlator.find_correlations()
        
        summary = correlator.generate_threat_summary()
        
        assert 'summary_timestamp' in summary
        assert 'overall_threat_level' in summary
        assert 'active_correlations' in summary
        assert 'high_severity_incidents' in summary
        assert 'recommended_priority_actions' in summary
        assert summary['overall_threat_level'] in ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    def test_correlation_id_uniqueness(self, correlator, sample_anomalies):
        """Test that correlation IDs are unique"""
        correlator.add_anomalies_batch(sample_anomalies)
        correlations = correlator.find_correlations()
        
        correlation_ids = [c.correlation_id for c in correlations]
        assert len(correlation_ids) == len(set(correlation_ids))
    
    def test_threat_actor_fingerprint(self, correlator, sample_anomalies):
        """Test threat actor fingerprint generation"""
        correlator.add_anomalies_batch(sample_anomalies)
        correlations = correlator.find_correlations()
        
        if correlations:
            assert correlations[0].threat_actor_fingerprint is not None
            assert len(correlations[0].threat_actor_fingerprint) == 16  # 16 hex chars
    
    def test_supporting_evidence_structure(self, correlator, sample_anomalies):
        """Test supporting evidence structure in correlations"""
        correlator.add_anomalies_batch(sample_anomalies)
        correlations = correlator.find_correlations()
        
        if correlations:
            evidence = correlations[0].supporting_evidence
            assert len(evidence) > 0
            assert all('type' in e for e in evidence)
            assert all('value' in e for e in evidence)
            assert all('description' in e for e in evidence)
    
    def test_buffer_maintenance(self, correlator):
        """Test that anomaly buffer maintains size limit"""
        # Add many anomalies
        base_time = time.time()
        for i in range(15000):  # More than 10000 limit
            anomaly = AnomalyEvent(
                event_id=f"evt_{i}",
                source_feed="test",
                timestamp=base_time + i,
                anomaly_type="scan",
                severity=0.5,
                entity_id=f"10.0.0.{i % 256}",
                entity_type="ip"
            )
            correlator.add_anomaly(anomaly)
        
        # Buffer should be capped at 10000
        assert len(correlator.anomaly_buffer) <= 10000
        # But stats should reflect all processed
        assert correlator._stats['total_anomalies_processed'] == 15000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
