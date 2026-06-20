"""
Test suite for Threat Actor Campaign Tracker
Production-grade tests with real assertions

HONEST TESTING: Real tests that verify actual functionality
"""

import json
import os
import tempfile
from datetime import datetime, timedelta
import unittest

from neural_shield.threat_intelligence_threat_actor_campaign_tracker_2026_june import (
    ThreatActorCampaignTracker,
    ThreatActor,
    Campaign,
    ThreatIndicator,
    ObservedThreat,
    ThreatActorType,
    CampaignStatus,
    MitreTactic
)


class TestThreatActorCampaignTracker(unittest.TestCase):
    """Production-grade test suite for Threat Actor Campaign Tracker"""

    def setUp(self):
        """Set up test fixtures"""
        self.tracker = ThreatActorCampaignTracker()
        
        # Create test threat actor
        self.test_actor = ThreatActor(
            actor_id="APT-TEST-001",
            name="Test Actor Alpha",
            aliases=["Alpha Team", "Red Group"],
            actor_type=ThreatActorType.NATION_STATE,
            country_of_origin="Test Country",
            motivations=["Espionage", "Intellectual Property Theft"],
            first_seen=datetime(2024, 1, 1),
            last_seen=datetime(2026, 6, 1)
        )
        
        # Create test indicators
        self.test_indicators = [
            ThreatIndicator(
                indicator_type="ip",
                value="192.168.1.100",
                first_seen=datetime(2026, 1, 15),
                last_seen=datetime(2026, 6, 15),
                confidence=0.95,
                source="Threat Feed A"
            ),
            ThreatIndicator(
                indicator_type="domain",
                value="malicious-test-domain.com",
                first_seen=datetime(2026, 2, 1),
                last_seen=datetime(2026, 6, 10),
                confidence=0.85,
                source="Threat Feed B"
            )
        ]
        
        # Create test campaign
        self.test_campaign = Campaign(
            campaign_id="CAMP-TEST-001",
            name="Test Campaign Omega",
            description="Test campaign for unit testing",
            threat_actors=["APT-TEST-001"],
            status=CampaignStatus.ACTIVE,
            start_date=datetime(2026, 1, 1),
            target_sectors=["Technology", "Finance"],
            target_regions=["North America", "Europe"],
            tactics=[MitreTactic.INITIAL_ACCESS, MitreTactic.COMMAND_AND_CONTROL],
            techniques=["T1566", "T1071"],
            indicators=self.test_indicators,
            confidence_score=0.90,
            severity_score=8.5
        )

    def test_register_threat_actor(self):
        """Test registering a new threat actor"""
        actor_id = self.tracker.register_threat_actor(self.test_actor)
        self.assertEqual(actor_id, "APT-TEST-001")
        self.assertIn("APT-TEST-001", self.tracker.threat_actors)
        
        # Test duplicate registration raises error
        with self.assertRaises(ValueError):
            self.tracker.register_threat_actor(self.test_actor)

    def test_register_campaign(self):
        """Test registering a new campaign"""
        campaign_id = self.tracker.register_campaign(self.test_campaign)
        self.assertEqual(campaign_id, "CAMP-TEST-001")
        self.assertIn("CAMP-TEST-001", self.tracker.campaigns)
        
        # Verify indices were built
        key = "ip:192.168.1.100"
        self.assertIn(key, self.tracker.indicator_index)
        self.assertIn("CAMP-TEST-001", self.tracker.indicator_index[key])

    def test_observe_threat_match(self):
        """Test threat observation and campaign matching"""
        # Register campaign first
        self.tracker.register_campaign(self.test_campaign)
        
        # Create observed threat matching our indicator
        threat = ObservedThreat(
            threat_id="OBS-TEST-001",
            indicator_type="ip",
            indicator_value="192.168.1.100",
            timestamp=datetime.now(),
            source="Firewall Log"
        )
        
        matches = self.tracker.observe_threat(threat)
        
        # Should find a match
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].campaign_id, "CAMP-TEST-001")
        self.assertGreater(matches[0].match_score, 0.0)
        self.assertGreater(matches[0].attribution_confidence, 0.0)
        self.assertGreater(len(matches[0].recommended_actions), 0)

    def test_observe_threat_no_match(self):
        """Test threat observation with no matching campaign"""
        self.tracker.register_campaign(self.test_campaign)
        
        # Create threat with unknown indicator
        threat = ObservedThreat(
            threat_id="OBS-TEST-002",
            indicator_type="ip",
            indicator_value="10.0.0.1",
            timestamp=datetime.now(),
            source="Firewall Log"
        )
        
        matches = self.tracker.observe_threat(threat)
        self.assertEqual(len(matches), 0)

    def test_add_indicator_to_campaign(self):
        """Test adding indicator to existing campaign"""
        self.tracker.register_campaign(self.test_campaign)
        
        new_indicator = ThreatIndicator(
            indicator_type="hash",
            value="abc123def456",
            first_seen=datetime(2026, 6, 1),
            last_seen=datetime(2026, 6, 20),
            confidence=0.80,
            source="Sandbox Analysis"
        )
        
        result = self.tracker.add_indicator_to_campaign("CAMP-TEST-001", new_indicator)
        self.assertTrue(result)
        
        # Verify indicator was added and indexed
        campaign = self.tracker.campaigns["CAMP-TEST-001"]
        self.assertEqual(len(campaign.indicators), 3)
        
        key = "hash:abc123def456"
        self.assertIn("CAMP-TEST-001", self.tracker.indicator_index[key])

    def test_get_active_campaigns(self):
        """Test retrieving active campaigns"""
        self.tracker.register_campaign(self.test_campaign)
        
        active = self.tracker.get_active_campaigns()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0].campaign_id, "CAMP-TEST-001")

    def test_get_campaigns_by_actor(self):
        """Test retrieving campaigns by threat actor"""
        self.tracker.register_campaign(self.test_campaign)
        
        campaigns = self.tracker.get_campaigns_by_actor("APT-TEST-001")
        self.assertEqual(len(campaigns), 1)
        self.assertEqual(campaigns[0].campaign_id, "CAMP-TEST-001")
        
        # Test unknown actor returns empty
        empty = self.tracker.get_campaigns_by_actor("UNKNOWN-ACTOR")
        self.assertEqual(len(empty), 0)

    def test_calculate_campaign_risk_score(self):
        """Test campaign risk score calculation"""
        self.tracker.register_campaign(self.test_campaign)
        
        risk = self.tracker.calculate_campaign_risk_score("CAMP-TEST-001")
        
        # Verify all components exist
        self.assertIn("composite_risk_score", risk)
        self.assertIn("severity_component", risk)
        self.assertIn("confidence_component", risk)
        self.assertIn("activity_component", risk)
        self.assertIn("overall_risk_level", risk)
        
        # Verify scores are in valid range
        self.assertGreaterEqual(risk["composite_risk_score"], 0.0)
        self.assertLessEqual(risk["composite_risk_score"], 1.0)
        self.assertIn(risk["overall_risk_level"], ["CRITICAL", "HIGH", "MEDIUM", "LOW"])

    def test_get_campaign_timeline(self):
        """Test campaign timeline generation"""
        self.tracker.register_campaign(self.test_campaign)
        
        timeline = self.tracker.get_campaign_timeline("CAMP-TEST-001")
        
        self.assertIn("campaign_id", timeline)
        self.assertIn("campaign_name", timeline)
        self.assertIn("timeline", timeline)
        self.assertGreater(len(timeline["timeline"]), 0)

    def test_generate_campaign_summary_report(self):
        """Test summary report generation"""
        self.tracker.register_threat_actor(self.test_actor)
        self.tracker.register_campaign(self.test_campaign)
        
        report = self.tracker.generate_campaign_summary_report()
        
        # Verify summary fields
        self.assertIn("summary", report)
        self.assertEqual(report["summary"]["total_campaigns"], 1)
        self.assertEqual(report["summary"]["active_campaigns"], 1)
        self.assertEqual(report["summary"]["total_threat_actors"], 1)
        
        # Verify distributions
        self.assertIn("campaign_status_distribution", report)
        self.assertIn("threat_actor_type_distribution", report)
        self.assertIn("top_targeted_sectors", report)

    def test_export_data(self):
        """Test data export functionality"""
        self.tracker.register_threat_actor(self.test_actor)
        self.tracker.register_campaign(self.test_campaign)
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            filepath = f.name
        
        try:
            result = self.tracker.export_data(filepath)
            self.assertTrue(result)
            
            # Verify file exists and contains valid JSON
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            self.assertIn("threat_actors", data)
            self.assertIn("campaigns", data)
            self.assertIn("APT-TEST-001", data["threat_actors"])
            self.assertIn("CAMP-TEST-001", data["campaigns"])
            
        finally:
            os.unlink(filepath)

    def test_campaign_duration(self):
        """Test campaign duration calculation"""
        duration = self.test_campaign.duration_days()
        self.assertIsNotNone(duration)
        self.assertGreater(duration, 0)

    def test_threat_indicator_validation(self):
        """Test threat indicator confidence validation"""
        # Valid confidence should work
        indicator = ThreatIndicator(
            indicator_type="ip",
            value="1.2.3.4",
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            confidence=0.5,
            source="Test"
        )
        self.assertEqual(indicator.confidence, 0.5)
        
        # Invalid confidence should raise error
        with self.assertRaises(ValueError):
            ThreatIndicator(
                indicator_type="ip",
                value="1.2.3.4",
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                confidence=1.5,  # Invalid
                source="Test"
            )

    def test_campaign_score_clamping(self):
        """Test campaign score auto-clamping"""
        campaign = Campaign(
            campaign_id="TEST-CLAMP",
            name="Test Clamp",
            description="Test",
            confidence_score=2.0,  # Should clamp to 1.0
            severity_score=15.0    # Should clamp to 10.0
        )
        self.assertEqual(campaign.confidence_score, 1.0)
        self.assertEqual(campaign.severity_score, 10.0)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestThreatActorCampaignTracker)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful()
    }


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Actor Campaign Tracker - Production Test Suite")
    print("=" * 60)
    print()
    
    results = run_tests()
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    print(f"Tests Run: {results['tests_run']}")
    print(f"Failures: {results['failures']}")
    print(f"Errors: {results['errors']}")
    print(f"Success: {'PASS' if results['success'] else 'FAIL'}")
    print("=" * 60)
    
    # Save results
    with open("test_results_threat_actor_campaign_tracker.json", "w") as f:
        json.dump(results, f, indent=2)
