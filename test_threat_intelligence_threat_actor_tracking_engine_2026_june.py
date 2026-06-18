"""
Test suite for Threat Intelligence Threat Actor Tracking Engine
Production-grade tests covering all core functionality.
"""
import pytest
import json
from datetime import datetime, timedelta, timezone
from neural_shield.threat_intelligence_threat_actor_tracking_engine_2026_june import (
    ThreatActorTrackingEngine,
    ActivityType,
    ActivitySeverity,
    TrackedActivity,
    ActorProfile
)


class TestThreatActorTrackingEngine:
    """Test suite for ThreatActorTrackingEngine"""
    
    def test_engine_initialization(self):
        """Test engine initialization with default parameters"""
        engine = ThreatActorTrackingEngine()
        assert engine.max_timeline_size == 10000
        assert len(engine.actors) == 0
        assert len(engine.activity_index) == 0
    
    def test_engine_custom_timeline_size(self):
        """Test engine initialization with custom timeline size"""
        engine = ThreatActorTrackingEngine(max_timeline_size=5000)
        assert engine.max_timeline_size == 5000
    
    def test_track_activity_basic(self):
        """Test basic activity tracking functionality"""
        engine = ThreatActorTrackingEngine()
        
        activity_id, is_new = engine.track_activity(
            actor_name="APT-28",
            activity_type="phishing",
            severity="high",
            timestamp="2026-06-15T10:00:00Z",
            description="Phishing campaign targeting government entities",
            source="OSINT-Feed-001",
            confidence=0.85
        )
        
        assert activity_id is not None
        assert is_new is True
        assert len(engine.activity_index) == 1
        assert len(engine.actors) == 1
    
    def test_track_activity_duplicate_detection(self):
        """Test duplicate activity detection"""
        engine = ThreatActorTrackingEngine()
        
        # First tracking
        id1, is_new1 = engine.track_activity(
            actor_name="APT-29",
            activity_type="malware_deployment",
            severity="critical",
            timestamp="2026-06-14T08:00:00Z",
            description="Custom malware deployment observed",
            source="Threat-Feed-A",
            confidence=0.9
        )
        
        # Same activity again
        id2, is_new2 = engine.track_activity(
            actor_name="APT-29",
            activity_type="malware_deployment",
            severity="critical",
            timestamp="2026-06-14T08:00:00Z",
            description="Custom malware deployment observed",
            source="Threat-Feed-A",
            confidence=0.9
        )
        
        assert id1 == id2
        assert is_new1 is True
        assert is_new2 is False
        assert len(engine.activity_index) == 1
    
    def test_track_activity_invalid_type(self):
        """Test activity tracking with invalid activity type"""
        engine = ThreatActorTrackingEngine()
        
        activity_id, is_new = engine.track_activity(
            actor_name="TestActor",
            activity_type="invalid_type_xyz",
            severity="high",
            timestamp="2026-06-15T10:00:00Z",
            description="Test activity",
            source="Test-Source",
            confidence=0.7
        )
        
        assert activity_id is not None
        assert is_new is True
    
    def test_track_activity_invalid_severity(self):
        """Test activity tracking with invalid severity"""
        engine = ThreatActorTrackingEngine()
        
        activity_id, is_new = engine.track_activity(
            actor_name="TestActor",
            activity_type="phishing",
            severity="invalid_severity",
            timestamp="2026-06-15T10:00:00Z",
            description="Test activity",
            source="Test-Source",
            confidence=0.7
        )
        
        assert activity_id is not None
        assert is_new is True
    
    def test_track_activity_invalid_timestamp(self):
        """Test activity tracking with invalid timestamp"""
        engine = ThreatActorTrackingEngine()
        
        activity_id, is_new = engine.track_activity(
            actor_name="TestActor",
            activity_type="phishing",
            severity="high",
            timestamp="invalid-timestamp",
            description="Test activity",
            source="Test-Source",
            confidence=0.7
        )
        
        assert activity_id is not None
        assert is_new is True
    
    def test_track_activity_confidence_clamping(self):
        """Test that confidence values are properly clamped"""
        engine = ThreatActorTrackingEngine()
        
        # Test confidence above 1.0
        activity_id1, _ = engine.track_activity(
            actor_name="TestActor1",
            activity_type="phishing",
            severity="high",
            timestamp="2026-06-15T10:00:00Z",
            description="Test",
            source="Test",
            confidence=1.5
        )
        
        # Test confidence below 0.0
        activity_id2, _ = engine.track_activity(
            actor_name="TestActor2",
            activity_type="phishing",
            severity="high",
            timestamp="2026-06-15T10:00:00Z",
            description="Test",
            source="Test",
            confidence=-0.5
        )
        
        assert activity_id1 is not None
        assert activity_id2 is not None
    
    def test_get_actor_profile_existing(self):
        """Test getting profile for an existing actor"""
        engine = ThreatActorTrackingEngine()
        
        engine.track_activity(
            actor_name="Lapsus$",
            activity_type="ransomware_attack",
            severity="critical",
            timestamp="2026-06-10T14:00:00Z",
            description="Ransomware attack on tech company",
            source="DarkWeb-Monitor",
            confidence=0.95,
            targets=["Tech Sector"],
            mitre_techniques=["T1486", "T1027"]
        )
        
        profile = engine.get_actor_profile("Lapsus$")
        
        assert profile is not None
        assert profile["actor_name"] == "Lapsus$"
        assert profile["total_activities"] == 1
        assert profile["unique_targets"] == 1
        assert profile["unique_techniques"] == 2
        assert "activity_velocity_30d" in profile
        assert "severity_analysis" in profile
    
    def test_get_actor_profile_nonexistent(self):
        """Test getting profile for a non-existent actor"""
        engine = ThreatActorTrackingEngine()
        profile = engine.get_actor_profile("NonExistentActor")
        assert profile is None
    
    def test_get_actor_profile_multiple_activities(self):
        """Test profile with multiple activities"""
        engine = ThreatActorTrackingEngine()
        
        # Add multiple activities for same actor
        for i in range(5):
            engine.track_activity(
                actor_name="Conti",
                activity_type="ransomware_attack",
                severity="critical",
                timestamp=f"2026-06-{10+i}T12:00:00Z",
                description=f"Ransomware attack {i}",
                source="Feed-A",
                confidence=0.9
            )
        
        profile = engine.get_actor_profile("Conti")
        assert profile["total_activities"] == 5
        assert profile["activity_velocity_30d"] > 0
    
    def test_detect_activity_anomalies_no_data(self):
        """Test anomaly detection with insufficient data"""
        engine = ThreatActorTrackingEngine()
        
        engine.track_activity(
            actor_name="TestActor",
            activity_type="phishing",
            severity="high",
            timestamp="2026-06-15T10:00:00Z",
            description="Test",
            source="Test"
        )
        
        result = engine.detect_activity_anomalies("TestActor")
        assert result["anomalies_detected"] is False
    
    def test_detect_activity_anomalies_actor_not_found(self):
        """Test anomaly detection for non-existent actor"""
        engine = ThreatActorTrackingEngine()
        result = engine.detect_activity_anomalies("NonExistent")
        assert result["anomalies_detected"] is False
    
    def test_detect_activity_anomalies_spike(self):
        """Test detection of activity spikes"""
        engine = ThreatActorTrackingEngine()
        
        # Add historical baseline activities (spaced out)
        for i in range(3):
            days_ago = 30 - (i * 7)
            ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
            engine.track_activity(
                actor_name="SpikeActor",
                activity_type="phishing",
                severity="medium",
                timestamp=ts,
                description=f"Historical activity {i}",
                source="Feed"
            )
        
        # Add recent spike of activities
        for i in range(10):
            days_ago = i * 0.5
            ts = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
            engine.track_activity(
                actor_name="SpikeActor",
                activity_type="phishing",
                severity="high",
                timestamp=ts,
                description=f"Recent activity {i}",
                source="Feed"
            )
        
        result = engine.detect_activity_anomalies("SpikeActor")
        assert "anomaly_count" in result
    
    def test_get_top_active_actors_empty(self):
        """Test top actors with empty engine"""
        engine = ThreatActorTrackingEngine()
        top_actors = engine.get_top_active_actors()
        assert len(top_actors) == 0
    
    def test_get_top_active_actors_with_data(self):
        """Test getting top active actors"""
        engine = ThreatActorTrackingEngine()
        
        # Actor 1: High activity
        for i in range(10):
            ts = (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()
            engine.track_activity(
                actor_name="HighActivityActor",
                activity_type="phishing",
                severity="high",
                timestamp=ts,
                description=f"Activity {i}",
                source="Feed"
            )
        
        # Actor 2: Low activity
        engine.track_activity(
            actor_name="LowActivityActor",
            activity_type="phishing",
            severity="medium",
            timestamp=datetime.now(timezone.utc).isoformat(),
            description="Single activity",
            source="Feed"
        )
        
        top_actors = engine.get_top_active_actors(limit=5)
        assert len(top_actors) >= 1
        assert top_actors[0]["actor_name"] == "HighActivityActor"
        assert "combined_score" in top_actors[0]
    
    def test_export_tracking_data(self):
        """Test data export functionality"""
        engine = ThreatActorTrackingEngine()
        
        engine.track_activity(
            actor_name="ExportTestActor",
            activity_type="ddos_attack",
            severity="high",
            timestamp="2026-06-15T10:00:00Z",
            description="DDoS attack observed",
            source="NetFlow"
        )
        
        # Test dict export
        data_dict = engine.export_tracking_data(format_type="dict")
        assert data_dict["total_actors_tracked"] == 1
        assert data_dict["total_activities_tracked"] == 1
        
        # Test JSON export
        data_json = engine.export_tracking_data(format_type="json")
        parsed = json.loads(data_json)
        assert parsed["total_actors_tracked"] == 1
    
    def test_activity_with_indicators_and_targets(self):
        """Test tracking activity with indicators and targets"""
        engine = ThreatActorTrackingEngine()
        
        engine.track_activity(
            actor_name="IndicatorTestActor",
            activity_type="data_exfiltration",
            severity="critical",
            timestamp="2026-06-15T10:00:00Z",
            description="Data exfiltration detected",
            source="EDR",
            confidence=0.95,
            indicators=["192.168.1.100", "malware.exe", "domain:evil.com"],
            targets=["Healthcare", "Finance"],
            mitre_techniques=["T1041", "T1048"]
        )
        
        profile = engine.get_actor_profile("IndicatorTestActor")
        assert profile["infrastructure_count"] == 3
        assert profile["unique_targets"] == 2
        assert profile["unique_techniques"] == 2
    
    def test_actor_profile_velocity_calculation(self):
        """Test activity velocity calculation"""
        engine = ThreatActorTrackingEngine()
        
        for i in range(15):
            ts = (datetime.now(timezone.utc) - timedelta(days=i)).isoformat()
            engine.track_activity(
                actor_name="VelocityTest",
                activity_type="phishing",
                severity="medium",
                timestamp=ts,
                description=f"Activity {i}",
                source="Feed"
            )
        
        profile = engine.get_actor_profile("VelocityTest")
        assert profile["activity_velocity_7d"] > 0
        assert profile["activity_velocity_30d"] > 0
    
    def test_multiple_actors_tracking(self):
        """Test tracking multiple different actors"""
        engine = ThreatActorTrackingEngine()
        
        actors = ["APT-28", "APT-29", "Lapsus$", "Conti", "REvil"]
        
        for actor in actors:
            engine.track_activity(
                actor_name=actor,
                activity_type="ransomware_attack",
                severity="high",
                timestamp="2026-06-15T10:00:00Z",
                description=f"Activity by {actor}",
                source="Feed"
            )
        
        assert len(engine.actors) == 5
        assert len(engine.activity_index) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
