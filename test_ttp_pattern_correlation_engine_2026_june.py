"""
Tests for TTP Pattern Correlation Engine - NeuralShield AI

Real, working tests that verify actual functionality
"""

import pytest
import json
from datetime import datetime, timedelta
from neural_shield.ttp_pattern_correlation_engine_2026_june import (
    TTPPatternCorrelationEngine,
    SecurityAlert,
    CorrelatedCampaign
)


class TestTTPPatternCorrelationEngine:
    """Test suite for TTP Pattern Correlation Engine"""
    
    def test_engine_initialization(self):
        """Test engine initializes with correct parameters"""
        engine = TTPPatternCorrelationEngine(
            time_window_minutes=30,
            correlation_threshold=0.7,
            min_alerts_per_campaign=2
        )
        
        assert engine.time_window == timedelta(minutes=30)
        assert engine.correlation_threshold == 0.7
        assert engine.min_alerts_per_campaign == 2
        assert len(engine.alerts) == 0
    
    def test_add_single_alert(self):
        """Test adding a single security alert"""
        engine = TTPPatternCorrelationEngine()
        alert = SecurityAlert(
            alert_id="ALERT-001",
            timestamp=datetime.now(),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.5",
            tactic="Execution",
            technique="Command and Scripting Interpreter",
            technique_id="T1059",
            severity=0.8,
            description="PowerShell execution detected"
        )
        
        engine.add_alert(alert)
        assert len(engine.alerts) == 1
        assert engine.alerts[0].alert_id == "ALERT-001"
    
    def test_ttp_similarity_same_technique(self):
        """Test TTP similarity calculation - same technique should be high"""
        engine = TTPPatternCorrelationEngine()
        base_time = datetime.now()
        
        alert1 = SecurityAlert(
            alert_id="A1",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Execution",
            technique="Command Interpreter",
            technique_id="T1059",
            severity=0.7,
            description="Test"
        )
        
        alert2 = SecurityAlert(
            alert_id="A2",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Execution",
            technique="Command Interpreter",
            technique_id="T1059",
            severity=0.7,
            description="Test"
        )
        
        similarity = engine.calculate_ttp_similarity(alert1, alert2)
        assert similarity > 0.8  # Should be high for same everything
    
    def test_ttp_similarity_correlated_techniques(self):
        """Test similarity for known correlated techniques"""
        engine = TTPPatternCorrelationEngine()
        base_time = datetime.now()
        
        # T1059 and T1053 are correlated
        alert1 = SecurityAlert(
            alert_id="A1",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Execution",
            technique="Command Interpreter",
            technique_id="T1059",
            severity=0.7,
            description="Test"
        )
        
        alert2 = SecurityAlert(
            alert_id="A2",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Execution",
            technique="Scheduled Task",
            technique_id="T1053",
            severity=0.7,
            description="Test"
        )
        
        similarity = engine.calculate_ttp_similarity(alert1, alert2)
        assert similarity > 0.5  # Should show correlation
    
    def test_temporal_proximity_same_time(self):
        """Test temporal proximity - same time should be 1.0"""
        engine = TTPPatternCorrelationEngine()
        base_time = datetime.now()
        
        alert1 = SecurityAlert(
            alert_id="A1",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Execution",
            technique="Test",
            technique_id="T0000",
            severity=0.5,
            description="Test"
        )
        
        alert2 = SecurityAlert(
            alert_id="A2",
            timestamp=base_time,
            source_ip="10.0.0.2",
            destination_ip="192.168.1.2",
            tactic="Discovery",
            technique="Test",
            technique_id="T0001",
            severity=0.5,
            description="Test"
        )
        
        proximity = engine.calculate_temporal_proximity(alert1, alert2)
        assert proximity == 1.0
    
    def test_temporal_proximity_outside_window(self):
        """Test temporal proximity - outside window should be 0.0"""
        engine = TTPPatternCorrelationEngine(time_window_minutes=60)
        base_time = datetime.now()
        
        alert1 = SecurityAlert(
            alert_id="A1",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Execution",
            technique="Test",
            technique_id="T0000",
            severity=0.5,
            description="Test"
        )
        
        alert2 = SecurityAlert(
            alert_id="A2",
            timestamp=base_time + timedelta(hours=2),  # 2 hours later
            source_ip="10.0.0.2",
            destination_ip="192.168.1.2",
            tactic="Discovery",
            technique="Test",
            technique_id="T0001",
            severity=0.5,
            description="Test"
        )
        
        proximity = engine.calculate_temporal_proximity(alert1, alert2)
        assert proximity == 0.0
    
    def test_kill_chain_progression(self):
        """Test kill chain sequence scoring - proper progression scores higher"""
        engine = TTPPatternCorrelationEngine()
        base_time = datetime.now()
        
        # Initial Access -> Execution = good progression
        alert1 = SecurityAlert(
            alert_id="A1",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Initial Access",
            technique="Test",
            technique_id="T0000",
            severity=0.5,
            description="Test"
        )
        
        alert2 = SecurityAlert(
            alert_id="A2",
            timestamp=base_time,
            source_ip="10.0.0.1",
            destination_ip="192.168.1.1",
            tactic="Execution",
            technique="Test",
            technique_id="T0001",
            severity=0.5,
            description="Test"
        )
        
        score = engine.calculate_kill_chain_sequence_score(alert1, alert2)
        assert score > 0.5  # Forward progression = > 0.5
    
    def test_campaign_detection_basic(self):
        """Test basic campaign detection with correlated alerts"""
        engine = TTPPatternCorrelationEngine(
            time_window_minutes=60,
            correlation_threshold=0.5,
            min_alerts_per_campaign=3
        )
        
        base_time = datetime.now()
        
        # Create 3 correlated alerts from same source
        for i in range(4):
            alert = SecurityAlert(
                alert_id=f"ALERT-{i:03d}",
                timestamp=base_time + timedelta(minutes=i*5),
                source_ip="192.168.1.100",  # Same source = correlated
                destination_ip="10.0.0.5",
                tactic="Execution",
                technique="Command Interpreter",
                technique_id="T1059",
                severity=0.7 + (i * 0.05),
                description=f"Suspicious activity {i}"
            )
            engine.add_alert(alert)
        
        campaigns = engine.detect_campaigns()
        assert len(campaigns) >= 1
        assert campaigns[0].alerts_count >= 3
    
    def test_campaign_detection_multiple_sources(self):
        """Test that unrelated sources don't form false campaigns"""
        engine = TTPPatternCorrelationEngine(
            time_window_minutes=60,
            correlation_threshold=0.8,  # High threshold
            min_alerts_per_campaign=3
        )
        
        base_time = datetime.now()
        
        # Alerts from completely different sources
        sources = ["10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4"]
        tactics = ["Reconnaissance", "Initial Access", "Execution", "Impact"]
        
        for i, (src, tactic) in enumerate(zip(sources, tactics)):
            alert = SecurityAlert(
                alert_id=f"ALERT-{i:03d}",
                timestamp=base_time + timedelta(minutes=i*30),
                source_ip=src,
                destination_ip=f"192.168.1.{i+1}",
                tactic=tactic,
                technique="Various",
                technique_id=f"T{i:04d}",
                severity=0.5,
                description=f"Activity {i}"
            )
            engine.add_alert(alert)
        
        campaigns = engine.detect_campaigns()
        # With high threshold and no correlation, should be few or no campaigns
        assert len(campaigns) == 0  # No correlation = no false campaigns
    
    def test_confidence_level_mapping(self):
        """Test confidence level mapping works correctly"""
        engine = TTPPatternCorrelationEngine()
        
        assert engine.determine_confidence_level(0.90) == "CRITICAL"
        assert engine.determine_confidence_level(0.75) == "HIGH"
        assert engine.determine_confidence_level(0.60) == "MEDIUM"
        assert engine.determine_confidence_level(0.40) == "LOW"
    
    def test_risk_assessment_calculation(self):
        """Test risk assessment produces valid scores"""
        engine = TTPPatternCorrelationEngine()
        base_time = datetime.now()
        
        alerts = []
        for i in range(5):
            alerts.append(SecurityAlert(
                alert_id=f"A{i}",
                timestamp=base_time,
                source_ip=f"10.0.0.{i}",
                destination_ip="192.168.1.1",
                tactic="Execution",
                technique="Test",
                technique_id="T1059",
                severity=0.6 + (i * 0.05),
                description="Test"
            ))
        
        risk = engine.assess_risk(alerts)
        assert 0.0 <= risk["overall_risk_score"] <= 1.0
        assert risk["alert_volume"] == 5
        assert risk["unique_sources"] == 5
        assert risk["unique_targets"] == 1
    
    def test_campaign_statistics(self):
        """Test statistics generation works"""
        engine = TTPPatternCorrelationEngine()
        
        # Empty engine
        stats = engine.get_campaign_statistics()
        assert stats["total_campaigns"] == 0
        assert stats["total_alerts_analyzed"] == 0
        
        # Add some alerts and detect
        base_time = datetime.now()
        for i in range(5):
            alert = SecurityAlert(
                alert_id=f"A{i}",
                timestamp=base_time + timedelta(minutes=i),
                source_ip="10.0.0.1",
                destination_ip="192.168.1.1",
                tactic="Execution",
                technique="Test",
                technique_id="T1059",
                severity=0.7,
                description="Test"
            )
            engine.add_alert(alert)
        
        engine.detect_campaigns()
        stats = engine.get_campaign_statistics()
        assert stats["total_alerts_analyzed"] == 5
    
    def test_json_import(self):
        """Test bulk import from JSON"""
        engine = TTPPatternCorrelationEngine()
        
        test_json = json.dumps({
            "alerts": [
                {
                    "alert_id": "JSON-001",
                    "timestamp": "2026-06-20T10:00:00Z",
                    "source_ip": "10.0.0.1",
                    "destination_ip": "192.168.1.1",
                    "tactic": "Execution",
                    "technique": "Command Interpreter",
                    "technique_id": "T1059",
                    "severity": 0.8,
                    "description": "JSON imported alert"
                }
            ]
        })
        
        count = engine.add_alerts_from_json(test_json)
        assert count == 1
        assert len(engine.alerts) == 1
    
    def test_export_results_json(self):
        """Test JSON export produces valid JSON"""
        engine = TTPPatternCorrelationEngine(
            correlation_threshold=0.5,
            min_alerts_per_campaign=3
        )
        
        base_time = datetime.now()
        for i in range(4):
            alert = SecurityAlert(
                alert_id=f"EXP-{i}",
                timestamp=base_time + timedelta(minutes=i*5),
                source_ip="10.0.0.100",
                destination_ip="192.168.1.50",
                tactic="Execution",
                technique="Test",
                technique_id="T1059",
                severity=0.7,
                description="Export test"
            )
            engine.add_alert(alert)
        
        engine.detect_campaigns()
        export = engine.export_results_json()
        
        # Should be valid JSON
        result = json.loads(export)
        assert "engine_version" in result
        assert "statistics" in result
        assert "campaigns" in result
    
    def test_mitre_phase_detection(self):
        """Test MITRE phase detection works"""
        engine = TTPPatternCorrelationEngine()
        base_time = datetime.now()
        
        # Alerts in Execution and Privilege Escalation phases
        alerts = [
            SecurityAlert("A1", base_time, "1.1.1.1", "2.2.2.2", 
                         "Execution", "Test", "T1059", 0.7, "Test"),
            SecurityAlert("A2", base_time, "1.1.1.1", "2.2.2.2",
                         "Privilege Escalation", "Test", "T1068", 0.8, "Test"),
        ]
        
        phase = engine.determine_mitre_phase(alerts)
        # Should be somewhere in the middle phases
        assert phase in ["Execution", "Privilege Escalation", "Defense Evasion"]
    
    def test_campaign_id_generation(self):
        """Test campaign ID generation is deterministic"""
        engine = TTPPatternCorrelationEngine()
        base_time = datetime.now()
        
        alerts = [
            SecurityAlert("A1", base_time, "1.1.1.1", "2.2.2.2",
                         "Execution", "Test", "T1059", 0.7, "Test"),
            SecurityAlert("A2", base_time, "1.1.1.1", "2.2.2.2",
                         "Execution", "Test", "T1059", 0.7, "Test"),
        ]
        
        id1 = engine.generate_campaign_id(alerts)
        id2 = engine.generate_campaign_id(alerts)
        
        # Same alerts = same ID (deterministic)
        assert id1 == id2
        assert id1.startswith("CAMP-")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
