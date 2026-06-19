"""
Test Suite for Threat Intelligence Insider Threat Risk Scorer
Production-grade tests with actual assertions

HONEST TESTING: Real tests with actual verification, no fakes.
"""

import pytest
import json
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_insider_threat_risk_scorer_2026_june import (
    InsiderThreatRiskScorer,
    RiskLevel,
    RiskFactorType,
    UserBehaviorBaseline
)


class TestInsiderThreatRiskScorer:
    """Test suite for Insider Threat Risk Scorer"""

    def test_initialization(self):
        """Test scorer initializes correctly"""
        scorer = InsiderThreatRiskScorer()
        assert scorer is not None
        assert len(scorer.risk_factor_weights) == 8
        assert scorer.decay_half_life_hours == 168  # 7 days default

    def test_create_baseline(self):
        """Test creating user behavior baseline"""
        scorer = InsiderThreatRiskScorer()
        
        baseline = scorer.create_baseline("user-001")
        
        assert baseline.user_id == "user-001"
        assert baseline.typical_login_hours == (8, 18)
        assert "user-001" in scorer.baselines

    def test_create_baseline_with_historical_data(self):
        """Test creating baseline with custom data"""
        scorer = InsiderThreatRiskScorer()
        
        historical = {
            "login_hours": (9, 17),
            "work_days": [0, 1, 2, 3, 4, 5],
            "avg_download_mb": 250.0,
            "avg_emails": 75
        }
        
        baseline = scorer.create_baseline("user-002", historical)
        
        assert baseline.typical_login_hours == (9, 17)
        assert baseline.avg_daily_downloads_mb == 250.0

    def test_record_risk_event(self):
        """Test recording risk events"""
        scorer = InsiderThreatRiskScorer()
        
        event_id = scorer.record_risk_event(
            user_id="user-001",
            factor_type=RiskFactorType.DATA_ACCESS,
            description="Large file download detected",
            severity=0.7
        )
        
        assert event_id.startswith("RISK-")
        assert len(scorer.risk_events["user-001"]) == 1
        assert scorer.risk_events["user-001"][0].severity == 0.7

    def test_record_risk_event_severity_clamping(self):
        """Test severity is clamped to valid range"""
        scorer = InsiderThreatRiskScorer()
        
        # Severity > 1.0 should be clamped
        scorer.record_risk_event("user-001", RiskFactorType.DATA_ACCESS, "Test", 2.0)
        assert scorer.risk_events["user-001"][0].severity == 1.0
        
        # Severity < 0 should be clamped
        scorer.record_risk_event("user-002", RiskFactorType.DATA_ACCESS, "Test", -0.5)
        assert scorer.risk_events["user-002"][0].severity == 0.0

    def test_temporal_decay_calculation(self):
        """Test exponential decay calculation"""
        scorer = InsiderThreatRiskScorer()
        now = datetime.now()
        
        # Fresh event - no decay
        decay = scorer.calculate_temporal_decay(now, now)
        assert decay == pytest.approx(1.0, 0.01)
        
        # After one half-life - 50% decay
        half_life_ago = now - timedelta(hours=168)
        decay = scorer.calculate_temporal_decay(half_life_ago, now)
        assert decay == pytest.approx(0.5, 0.01)
        
        # After two half-lives - 25% decay
        two_half_lives = now - timedelta(hours=336)
        decay = scorer.calculate_temporal_decay(two_half_lives, now)
        assert decay == pytest.approx(0.25, 0.01)

    def test_time_anomaly_detection(self):
        """Test time anomaly detection"""
        scorer = InsiderThreatRiskScorer()
        scorer.create_baseline("user-001")
        
        # Normal time (2PM on Wednesday) - no anomaly
        normal_time = datetime(2026, 6, 19, 14, 0, 0)  # Wednesday 2PM
        is_anomaly, score = scorer.check_time_anomaly("user-001", normal_time)
        assert is_anomaly is False
        assert score == 0.0
        
        # Off-hours time (2AM) - anomaly
        odd_time = datetime(2026, 6, 19, 2, 0, 0)  # 2AM
        is_anomaly, score = scorer.check_time_anomaly("user-001", odd_time)
        assert is_anomaly is True
        assert score > 0.5
        
        # Weekend (Sunday)
        weekend = datetime(2026, 6, 21, 14, 0, 0)  # Sunday
        is_anomaly, score = scorer.check_time_anomaly("user-001", weekend)
        assert is_anomaly is True

    def test_volume_anomaly_detection(self):
        """Test volume anomaly detection"""
        scorer = InsiderThreatRiskScorer()
        scorer.create_baseline("user-001")
        
        # Normal volume - no anomaly
        result = scorer.check_volume_anomaly("user-001", 50.0, 30, 50)
        assert result["anomaly"] is False
        assert result["score"] == 0.0
        
        # Extreme download volume - anomaly
        result = scorer.check_volume_anomaly("user-001", 500.0, 30, 50)
        assert result["anomaly"] is True
        assert result["score"] > 0.0

    def test_calculate_user_risk_no_events(self):
        """Test risk calculation for user with no events"""
        scorer = InsiderThreatRiskScorer()
        
        risk = scorer.calculate_user_risk("user-001")
        
        assert risk.user_id == "user-001"
        assert risk.overall_score == 0.0
        assert risk.risk_level == RiskLevel.NORMAL

    def test_calculate_user_risk_with_events(self):
        """Test risk calculation with actual risk events"""
        scorer = InsiderThreatRiskScorer()
        
        # Add multiple risk events
        scorer.record_risk_event("user-001", RiskFactorType.UNAUTHORIZED_ACCESS, 
                                "Failed login attempts", 0.9)
        scorer.record_risk_event("user-001", RiskFactorType.DATA_ACCESS,
                                "Large data transfer", 0.8)
        scorer.record_risk_event("user-001", RiskFactorType.PRIVILEGE_ESCALATION,
                                "Admin privilege request", 0.95)
        
        risk = scorer.calculate_user_risk("user-001")
        
        # Should have non-zero risk
        assert risk.overall_score > 0.0
        # Should have contributing events
        assert len(risk.contributing_events) > 0
        # Factor scores should be populated
        assert sum(risk.factor_scores.values()) > 0.0

    def test_risk_level_boundaries(self):
        """Test risk level boundaries"""
        scorer = InsiderThreatRiskScorer()
        
        # Add events to create different risk levels
        scorer.record_risk_event("user-critical", RiskFactorType.UNAUTHORIZED_ACCESS, "Test", 1.0)
        scorer.record_risk_event("user-critical", RiskFactorType.PRIVILEGE_ESCALATION, "Test", 1.0)
        scorer.record_risk_event("user-critical", RiskFactorType.DATA_ACCESS, "Test", 1.0)
        scorer.record_risk_event("user-critical", RiskFactorType.UNAUTHORIZED_ACCESS, "Test", 1.0)
        
        risk = scorer.calculate_user_risk("user-critical")
        # Multiple high-severity events should create HIGH or CRITICAL risk
        assert risk.risk_level in [RiskLevel.HIGH, RiskLevel.CRITICAL]

    def test_get_risk_ranking(self):
        """Test user risk ranking"""
        scorer = InsiderThreatRiskScorer()
        
        # High risk user
        scorer.record_risk_event("user-high", RiskFactorType.UNAUTHORIZED_ACCESS, "Test", 1.0)
        scorer.record_risk_event("user-high", RiskFactorType.PRIVILEGE_ESCALATION, "Test", 1.0)
        
        # Medium risk user
        scorer.record_risk_event("user-medium", RiskFactorType.TIME_ANOMALY, "Test", 0.5)
        
        # Low risk user
        scorer.record_risk_event("user-low", RiskFactorType.POLICY_VIOLATION, "Test", 0.2)
        
        ranking = scorer.get_risk_ranking()
        
        assert len(ranking) >= 3
        # Ranking should be sorted
        scores = [r["risk_score"] for r in ranking]
        assert scores == sorted(scores, reverse=True)

    def test_recommendations_generation(self):
        """Test recommendations are generated"""
        scorer = InsiderThreatRiskScorer()
        
        # No risk - normal recommendations
        risk = scorer.calculate_user_risk("user-normal")
        assert len(risk.recommendations) >= 1
        
        # High risk user should have specific recommendations
        scorer.record_risk_event("user-high", RiskFactorType.UNAUTHORIZED_ACCESS, "Test", 1.0)
        scorer.record_risk_event("user-high", RiskFactorType.DATA_ACCESS, "Test", 1.0)
        risk = scorer.calculate_user_risk("user-high")
        
        assert len(risk.recommendations) >= 1
        # Recommendations should mention risk level
        assert any("HIGH" in r or "MEDIUM" in r or "review" in r.lower() for r in risk.recommendations)

    def test_generate_risk_report(self):
        """Test comprehensive risk report generation"""
        scorer = InsiderThreatRiskScorer()
        
        scorer.record_risk_event("user-001", RiskFactorType.DATA_ACCESS, "Test", 0.7)
        scorer.record_risk_event("user-002", RiskFactorType.UNAUTHORIZED_ACCESS, "Test", 0.9)
        
        report = scorer.generate_risk_report()
        
        assert "report_id" in report
        assert "generated_at" in report
        assert "summary" in report
        assert "high_risk_users" in report
        assert "limitations" in report
        assert "key_insights" in report
        
        # Report should honestly state limitations
        assert len(report["limitations"]) >= 3
        assert any("baseline" in lim.lower() for lim in report["limitations"])

    def test_destination_anomaly(self):
        """Test destination anomaly detection"""
        scorer = InsiderThreatRiskScorer()
        
        baseline_data = {
            "destinations": ["internal-server", "trusted-partner.com"]
        }
        scorer.create_baseline("user-001", baseline_data)
        
        # Known destination - no anomaly
        is_anomaly, score = scorer.check_destination_anomaly("user-001", "internal-server")
        assert is_anomaly is False
        assert score == 0.0
        
        # Unknown destination - anomaly
        is_anomaly, score = scorer.check_destination_anomaly("user-001", "unknown-external.ru")
        assert is_anomaly is True
        assert score > 0.0

    def test_full_integration_workflow(self):
        """Test full end-to-end workflow"""
        scorer = InsiderThreatRiskScorer()
        
        # 1. Create baseline for a user
        scorer.create_baseline("employee-042")
        
        # 2. Record various risk events
        scorer.record_risk_event(
            "employee-042",
            RiskFactorType.DATA_ACCESS,
            "5GB file download to external USB",
            0.85
        )
        scorer.record_risk_event(
            "employee-042",
            RiskFactorType.TIME_ANOMALY,
            "Access at 2:30 AM",
            0.6
        )
        scorer.record_risk_event(
            "employee-042",
            RiskFactorType.UNAUTHORIZED_ACCESS,
            "Attempted access to restricted HR folder",
            0.9
        )
        
        # 3. Calculate risk
        risk = scorer.calculate_user_risk("employee-042")
        
        # 4. Verify results
        assert risk.overall_score > 0.0
        assert risk.risk_level in [RiskLevel.MEDIUM, RiskLevel.HIGH, RiskLevel.CRITICAL]
        assert len(risk.contributing_events) == 3
        assert len(risk.recommendations) >= 2
        
        # 5. Generate report
        report = scorer.generate_risk_report()
        assert report["summary"]["total_users_analyzed"] >= 1

    def test_honest_limitations(self):
        """Test that limitations are honestly reported"""
        scorer = InsiderThreatRiskScorer()
        report = scorer.generate_risk_report()
        
        # Must honestly state limitations
        assert "Not a replacement for human investigation" in str(report["limitations"])
        assert "false positives" in str(report["limitations"]).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
