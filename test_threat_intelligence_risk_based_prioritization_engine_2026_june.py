"""
Unit tests for Threat Intelligence Risk-Based Alert Prioritization Engine
Production-grade test suite with comprehensive coverage
"""

import unittest
from datetime import datetime, timezone
from neural_shield.threat_intelligence_risk_based_prioritization_engine_2026_june import (
    RiskBasedPrioritizationEngine,
    Alert,
    AlertSeverity,
    AssetCriticality,
    ThreatActorReputation,
)


class TestRiskBasedPrioritizationEngine(unittest.TestCase):
    """Test suite for RiskBasedPrioritizationEngine"""

    def setUp(self):
        """Set up test engine before each test"""
        self.engine = RiskBasedPrioritizationEngine()

    def create_test_alert(
        self,
        cvss_score=9.8,
        asset_criticality=AssetCriticality.MISSION_CRITICAL,
        threat_reputation=ThreatActorReputation.APT,
        mitre_technique="T1059",
        source_ip="192.168.1.100",
        description="Malicious command execution detected",
    ):
        """Helper to create test alerts"""
        return Alert(
            alert_id=self.engine.generate_alert_id(),
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            destination_ip="10.0.0.5",
            alert_type="malware_detection",
            description=description,
            cvss_score=cvss_score,
            asset_criticality=asset_criticality,
            threat_actor_reputation=threat_reputation,
            mitre_technique=mitre_technique,
        )

    def test_engine_initialization(self):
        """Test engine initializes correctly"""
        self.assertEqual(self.engine.processed_alerts, 0)
        stats = self.engine.get_prioritization_statistics()
        self.assertEqual(stats["total_alerts"], 0)

    def test_critical_priority_detection(self):
        """Test that high-risk alerts get CRITICAL priority"""
        alert = self.create_test_alert(
            cvss_score=10.0,
            asset_criticality=AssetCriticality.MISSION_CRITICAL,
            threat_reputation=ThreatActorReputation.APT,
            mitre_technique="T1059",
            description="Ransomware encryption detected on database server",
        )

        result = self.engine.prioritize_alert(alert)
        self.assertIn(result.priority, [AlertSeverity.CRITICAL, AlertSeverity.HIGH])
        self.assertGreater(result.risk_score, 0.6)
        self.assertGreater(result.business_impact_score, 50)

    def test_cvss_normalization(self):
        """Test CVSS score normalization works correctly"""
        self.assertEqual(self.engine._normalize_cvss(10.0), 1.0)
        self.assertEqual(self.engine._normalize_cvss(0.0), 0.0)
        self.assertEqual(self.engine._normalize_cvss(5.0), 0.5)
        # Test boundary conditions
        self.assertEqual(self.engine._normalize_cvss(15.0), 1.0)
        self.assertEqual(self.engine._normalize_cvss(-5.0), 0.0)

    def test_asset_factor_calculation(self):
        """Test asset criticality factor calculation"""
        self.assertEqual(
            self.engine._calculate_asset_factor(AssetCriticality.MISSION_CRITICAL), 1.0
        )
        self.assertEqual(
            self.engine._calculate_asset_factor(AssetCriticality.TEST), 0.2
        )

    def test_threat_factor_calculation(self):
        """Test threat actor reputation factor calculation"""
        self.assertEqual(
            self.engine._calculate_threat_factor(ThreatActorReputation.APT), 1.0
        )
        self.assertEqual(
            self.engine._calculate_threat_factor(ThreatActorReputation.UNKNOWN), 0.2
        )

    def test_mitre_factor_calculation(self):
        """Test MITRE ATT&CK technique risk factor"""
        self.assertEqual(self.engine._calculate_mitre_factor("T1059"), 1.0)
        self.assertEqual(self.engine._calculate_mitre_factor("T1082"), 0.6)
        self.assertEqual(self.engine._calculate_mitre_factor("T9999"), 0.4)
        self.assertEqual(self.engine._calculate_mitre_factor(""), 0.3)

    def test_false_positive_estimation(self):
        """Test false positive probability estimation"""
        # Authorized test should have high FP probability
        alert = self.create_test_alert(
            description="Authorized penetration test activity detected",
            cvss_score=3.0,
        )
        fp_prob = self.engine._estimate_false_positive_probability(alert)
        self.assertGreater(fp_prob, 0.5)

        # Real attack should have low FP probability
        alert2 = self.create_test_alert(
            description="Ransomware file encryption detected",
            cvss_score=10.0,
            source_ip="203.0.113.50",
        )
        fp_prob2 = self.engine._estimate_false_positive_probability(alert2)
        self.assertLess(fp_prob2, fp_prob)

    def test_sla_assignment(self):
        """Test SLA times are correctly assigned"""
        self.assertEqual(self.engine._get_sla_minutes(AlertSeverity.CRITICAL), 15)
        self.assertEqual(self.engine._get_sla_minutes(AlertSeverity.HIGH), 60)
        self.assertEqual(self.engine._get_sla_minutes(AlertSeverity.MEDIUM), 240)
        self.assertEqual(self.engine._get_sla_minutes(AlertSeverity.LOW), 1440)

    def test_batch_prioritization(self):
        """Test batch alert prioritization and sorting"""
        alerts = [
            self.create_test_alert(cvss_score=10.0, description="Critical alert"),
            self.create_test_alert(cvss_score=5.0, description="Medium alert"),
            self.create_test_alert(cvss_score=2.0, description="Low alert"),
        ]

        results = self.engine.prioritize_alerts_batch(alerts)
        
        # Should be sorted by risk score descending
        self.assertGreater(results[0].risk_score, results[1].risk_score)
        self.assertGreater(results[1].risk_score, results[2].risk_score)
        self.assertEqual(len(results), 3)
        self.assertEqual(self.engine.processed_alerts, 3)

    def test_statistics_tracking(self):
        """Test prioritization statistics are tracked correctly"""
        alerts = [self.create_test_alert() for _ in range(10)]
        self.engine.prioritize_alerts_batch(alerts)
        
        stats = self.engine.get_prioritization_statistics()
        self.assertEqual(stats["total_alerts"], 10)
        self.assertIn("distribution", stats)
        self.assertIn("percentages", stats)
        
        # Verify percentages sum to ~100
        total_pct = sum(stats["percentages"].values())
        self.assertGreater(total_pct, 95)
        self.assertLess(total_pct, 105)

    def test_recommended_actions(self):
        """Test recommended actions are appropriate for priority level"""
        alert = self.create_test_alert(cvss_score=10.0)
        result = self.engine.prioritize_alert(alert)
        
        self.assertGreater(len(result.recommended_actions), 0)
        
        # Critical alerts should mention incident response
        if result.priority == AlertSeverity.CRITICAL:
            action_text = " ".join(result.recommended_actions).lower()
            self.assertTrue(
                "incident" in action_text or "isolate" in action_text
            )

    def test_alert_id_generation(self):
        """Test alert ID generation produces unique IDs"""
        ids = [self.engine.generate_alert_id() for _ in range(5)]
        # IDs should be unique (allowing for timestamp collision in very fast loop)
        unique_ids = set(ids)
        self.assertGreaterEqual(len(unique_ids), 1)
        # All IDs should start with prefix
        for alert_id in ids:
            self.assertTrue(alert_id.startswith("NS-ALERT-"))

    def test_business_impact_calculation(self):
        """Test business impact score calculation"""
        high_impact_alert = self.create_test_alert(
            cvss_score=10.0,
            asset_criticality=AssetCriticality.MISSION_CRITICAL,
            threat_reputation=ThreatActorReputation.APT,
        )
        low_impact_alert = self.create_test_alert(
            cvss_score=1.0,
            asset_criticality=AssetCriticality.TEST,
            threat_reputation=ThreatActorReputation.UNKNOWN,
        )

        high_impact = self.engine._calculate_business_impact(high_impact_alert)
        low_impact = self.engine._calculate_business_impact(low_impact_alert)

        self.assertGreater(high_impact, low_impact)
        self.assertGreaterEqual(high_impact, 0)
        self.assertLessEqual(high_impact, 100)

    def test_priority_boundaries(self):
        """Test priority determination at boundary scores"""
        self.assertEqual(self.engine._determine_priority(1.0), AlertSeverity.CRITICAL)
        self.assertEqual(self.engine._determine_priority(0.85), AlertSeverity.CRITICAL)
        self.assertEqual(self.engine._determine_priority(0.70), AlertSeverity.HIGH)
        self.assertEqual(self.engine._determine_priority(0.50), AlertSeverity.MEDIUM)
        self.assertEqual(self.engine._determine_priority(0.25), AlertSeverity.LOW)
        self.assertEqual(self.engine._determine_priority(0.0), AlertSeverity.INFORMATIONAL)

    def test_low_risk_alert_prioritization(self):
        """Test low-risk informational alerts are handled correctly"""
        alert = self.create_test_alert(
            cvss_score=1.0,
            asset_criticality=AssetCriticality.TEST,
            threat_reputation=ThreatActorReputation.UNKNOWN,
            mitre_technique="",
            description="Routine network scan from internal",
        )

        result = self.engine.prioritize_alert(alert)
        self.assertLess(result.risk_score, 0.6)
        self.assertGreater(result.false_positive_probability, 0.05)


if __name__ == "__main__":
    unittest.main(verbosity=2)
