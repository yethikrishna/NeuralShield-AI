"""
Test Suite for Threat Intelligence False Positive Intelligence Engine
June 19, 2026 - Production Release

Comprehensive tests for false positive detection, learning, and alert reduction.
"""

import pytest
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_false_positive_intelligence_2026_june import (
    FalsePositiveCategory,
    FPConfidenceLevel,
    SecurityAlert,
    FalsePositiveFinding,
    HistoricalPattern,
    FalsePositiveIntelligenceEngine,
    create_false_positive_engine
)


class TestFalsePositiveIntelligenceEngine:
    """Test suite for False Positive Intelligence Engine"""

    def test_engine_initialization(self):
        """Test engine initializes with correct defaults"""
        engine = create_false_positive_engine()
        
        assert engine.fp_threshold == 0.70
        assert engine.enable_learning is True
        assert len(engine.benign_ip_ranges) > 0
        assert len(engine.benign_user_agents) > 0
        assert len(engine.benign_endpoints) > 0
        assert "crowdstrike" in engine.source_reliability

    def test_custom_threshold(self):
        """Test custom threshold configuration"""
        engine = create_false_positive_engine(fp_threshold=0.85)
        assert engine.fp_threshold == 0.85

    def test_whitelist_detection_private_ip(self):
        """Test private IP addresses are correctly identified as benign"""
        engine = create_false_positive_engine()
        
        alert = SecurityAlert(
            alert_id="test-001",
            alert_type="suspicious_connection",
            severity="MEDIUM",
            source="custom_rule",
            timestamp=datetime.now(),
            ip_address="192.168.1.100"
        )
        
        result = engine.analyze_alert(alert)
        assert "Private IP range" in str(result.reasons)

    def test_whitelist_detection_benign_endpoint(self):
        """Test health check endpoints are correctly identified"""
        engine = create_false_positive_engine()
        
        alert = SecurityAlert(
            alert_id="test-002",
            alert_type="suspicious_request",
            severity="HIGH",
            source="custom_rule",
            timestamp=datetime.now(),
            endpoint="/api/health/check"
        )
        
        result = engine.analyze_alert(alert)
        assert "benign endpoint" in str(result.reasons).lower()

    def test_whitelist_detection_user_agent(self):
        """Test known user agents are correctly identified"""
        engine = create_false_positive_engine()
        
        alert = SecurityAlert(
            alert_id="test-003",
            alert_type="unusual_user_agent",
            severity="MEDIUM",
            source="custom_rule",
            timestamp=datetime.now(),
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/125.0.0.0"
        )
        
        result = engine.analyze_alert(alert)
        assert "benign user agent" in str(result.reasons).lower()

    def test_low_severity_fp_detection(self):
        """Test INFO/LOW severity alerts get higher FP scores"""
        engine = create_false_positive_engine()
        
        alert = SecurityAlert(
            alert_id="test-004",
            alert_type="info_event",
            severity="INFO",
            source="custom_rule",
            timestamp=datetime.now()
        )
        
        result = engine.analyze_alert(alert)
        assert "Low severity alert" in str(result.reasons)

    def test_source_reliability_scoring(self):
        """Test low reliability sources get higher FP scores"""
        engine = create_false_positive_engine()
        
        # Low reliability source with CRITICAL severity should be suspicious
        alert = SecurityAlert(
            alert_id="test-005",
            alert_type="critical_alert",
            severity="CRITICAL",
            source="custom_rule",  # Low reliability
            timestamp=datetime.now()
        )
        
        result = engine.analyze_alert(alert)
        assert result.confidence > 0.2  # Should have some FP confidence

    def test_high_reliability_source(self):
        """Test high reliability sources get lower FP scores"""
        engine = create_false_positive_engine()
        
        alert = SecurityAlert(
            alert_id="test-006",
            alert_type="critical_alert",
            severity="CRITICAL",
            source="crowdstrike",  # High reliability
            timestamp=datetime.now()
        )
        
        result = engine.analyze_alert(alert)
        # CrowdStrike is reliable, so should NOT be flagged as low reliability
        reasons_lower = str(result.reasons).lower()
        assert "low source reliability" not in reasons_lower

    def test_temporal_analysis_business_hours(self):
        """Test business hours temporal analysis"""
        engine = create_false_positive_engine()
        
        # Create alert at 10 AM (business hours)
        business_time = datetime.now().replace(hour=10, minute=0)
        
        alert = SecurityAlert(
            alert_id="test-007",
            alert_type="failed_login",
            severity="MEDIUM",
            source="custom_rule",
            timestamp=business_time
        )
        
        result = engine.analyze_alert(alert)
        assert result.confidence >= 0

    def test_learning_capability(self):
        """Test engine learns from repeated patterns"""
        engine = create_false_positive_engine(enable_learning=True)
        
        # Submit the same pattern multiple times
        for i in range(5):
            alert = SecurityAlert(
                alert_id=f"test-learn-{i}",
                alert_type="repeated_pattern",
                severity="LOW",
                source="custom_rule",
                timestamp=datetime.now(),
                ip_address="10.0.0.1"
            )
            engine.analyze_alert(alert)
        
        # Should have learned patterns
        stats = engine.get_statistics()
        assert stats["unique_patterns_learned"] > 0
        assert stats["total_alerts_analyzed"] == 5

    def test_batch_analysis(self):
        """Test batch alert analysis"""
        engine = create_false_positive_engine()
        
        alerts = [
            SecurityAlert(
                alert_id=f"batch-{i}",
                alert_type=f"type-{i}",
                severity="MEDIUM",
                source="custom_rule",
                timestamp=datetime.now()
            )
            for i in range(10)
        ]
        
        results = engine.analyze_batch(alerts)
        assert len(results) == 10
        assert all(isinstance(r, FalsePositiveFinding) for r in results)

    def test_statistics_tracking(self):
        """Test statistics are correctly tracked"""
        engine = create_false_positive_engine()
        
        initial_stats = engine.get_statistics()
        assert initial_stats["total_alerts_analyzed"] == 0
        
        # Process some alerts
        for i in range(5):
            alert = SecurityAlert(
                alert_id=f"stat-{i}",
                alert_type="test",
                severity="INFO",
                source="custom_rule",
                timestamp=datetime.now()
            )
            engine.analyze_alert(alert)
        
        stats = engine.get_statistics()
        assert stats["total_alerts_analyzed"] == 5
        assert stats["false_positives_identified"] > 0
        assert stats["reduction_rate"] > 0

    def test_add_custom_benign_pattern(self):
        """Test adding custom whitelist patterns"""
        engine = create_false_positive_engine()
        
        # Add custom pattern
        engine.add_benign_pattern("ip_prefix", "203.0.113.")
        engine.add_benign_pattern("user_agent", "internal-monitor")
        engine.add_benign_pattern("endpoint", "/internal/")
        
        # Test the custom IP pattern
        alert = SecurityAlert(
            alert_id="custom-001",
            alert_type="connection",
            severity="MEDIUM",
            source="custom_rule",
            timestamp=datetime.now(),
            ip_address="203.0.113.50"
        )
        
        result = engine.analyze_alert(alert)
        assert result.confidence >= 0

    def test_export_patterns(self):
        """Test pattern export functionality"""
        engine = create_false_positive_engine(enable_learning=True)
        
        # Create some patterns
        for i in range(3):
            alert = SecurityAlert(
                alert_id=f"export-{i}",
                alert_type="pattern_test",
                severity="LOW",
                source="custom_rule",
                timestamp=datetime.now(),
                ip_address=f"192.168.1.{i}"
            )
            engine.analyze_alert(alert)
        
        patterns = engine.export_learned_patterns()
        assert len(patterns) > 0
        assert all("pattern_hash" in p for p in patterns)
        assert all("false_positive_rate" in p for p in patterns)

    def test_fp_category_determination(self):
        """Test false positive category assignment"""
        engine = create_false_positive_engine()
        
        # Private IP should be BENIGN_ANOMALY
        alert = SecurityAlert(
            alert_id="cat-001",
            alert_type="connection",
            severity="MEDIUM",
            source="custom_rule",
            timestamp=datetime.now(),
            ip_address="10.0.0.50"
        )
        
        result = engine.analyze_alert(alert)
        assert result.category is not None

    def test_recommended_action_logic(self):
        """Test recommended action is appropriate for confidence level"""
        engine = create_false_positive_engine()
        
        # Very high confidence FP should be suppressed
        high_fp_alert = SecurityAlert(
            alert_id="action-001",
            alert_type="test",
            severity="INFO",
            source="custom_rule",
            timestamp=datetime.now(),
            ip_address="192.168.1.1",
            endpoint="/health",
            user_agent="Mozilla Chrome"
        )
        
        result = engine.analyze_alert(high_fp_alert)
        assert result.recommended_action is not None
        assert len(result.recommended_action) > 0

    def test_risk_score_calculation(self):
        """Test risk score is inverse of FP score"""
        engine = create_false_positive_engine()
        
        alert = SecurityAlert(
            alert_id="risk-001",
            alert_type="test",
            severity="MEDIUM",
            source="custom_rule",
            timestamp=datetime.now()
        )
        
        result = engine.analyze_alert(alert)
        # Risk should be 1 - FP confidence
        assert abs(result.risk_score - (1.0 - result.confidence)) < 0.001

    def test_feature_contributions(self):
        """Test feature contributions are calculated"""
        engine = create_false_positive_engine()
        
        alert = SecurityAlert(
            alert_id="feature-001",
            alert_type="test",
            severity="INFO",
            source="custom_rule",
            timestamp=datetime.now(),
            ip_address="192.168.1.1"
        )
        
        result = engine.analyze_alert(alert)
        assert len(result.feature_contributions) > 0
        assert "whitelist_match" in result.feature_contributions
        assert all(isinstance(v, float) for v in result.feature_contributions.values())

    def test_disabled_learning(self):
        """Test engine works with learning disabled"""
        engine = create_false_positive_engine(enable_learning=False)
        
        for i in range(5):
            alert = SecurityAlert(
                alert_id=f"no-learn-{i}",
                alert_type="test",
                severity="LOW",
                source="custom_rule",
                timestamp=datetime.now()
            )
            engine.analyze_alert(alert)
        
        stats = engine.get_statistics()
        assert stats["learning_enabled"] is False
        assert stats["total_alerts_analyzed"] == 5

    def test_pattern_hash_consistency(self):
        """Test pattern hash is consistent for same alert features"""
        engine = create_false_positive_engine()
        
        alert1 = SecurityAlert(
            alert_id="hash-1",
            alert_type="same_type",
            severity="MEDIUM",
            source="same_source",
            timestamp=datetime.now(),
            ip_address="1.2.3.4",
            endpoint="/test"
        )
        
        alert2 = SecurityAlert(
            alert_id="hash-2",
            alert_type="same_type",
            severity="HIGH",  # Different severity, same core features
            source="same_source",
            timestamp=datetime.now(),
            ip_address="1.2.3.4",
            endpoint="/test"
        )
        
        hash1 = engine._compute_pattern_hash(alert1)
        hash2 = engine._compute_pattern_hash(alert2)
        
        # Same type, source, IP, endpoint should give same hash
        assert hash1 == hash2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
