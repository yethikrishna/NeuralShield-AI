"""
Test suite for Threat Actor Campaign Tracker
HONEST TESTING: Real tests that verify actual functionality
"""

import json
import unittest
from datetime import datetime, timedelta
from neural_shield.threat_intelligence_threat_actor_campaign_tracker_2026_june import (
    ThreatActorCampaignTracker,
    IndicatorOfCompromise,
    IOCType,
    CampaignStatus
)


class TestIndicatorOfCompromise(unittest.TestCase):
    """Test IOC validation and functionality"""

    def test_valid_ip_ioc(self):
        """Test valid IP address IOC"""
        ioc = IndicatorOfCompromise(
            value="192.168.1.1",
            ioc_type=IOCType.IP,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9
        )
        self.assertIsNotNone(ioc.get_id())

    def test_valid_domain_ioc(self):
        """Test valid domain IOC"""
        ioc = IndicatorOfCompromise(
            value="malicious-domain.com",
            ioc_type=IOCType.DOMAIN,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.8
        )
        self.assertIsNotNone(ioc.get_id())

    def test_valid_hash_ioc(self):
        """Test valid file hash IOC"""
        ioc = IndicatorOfCompromise(
            value="5d41402abc4b2a76b9719d911017c592",
            ioc_type=IOCType.HASH,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=1.0
        )
        self.assertIsNotNone(ioc.get_id())

    def test_invalid_confidence_raises_error(self):
        """Test invalid confidence raises ValueError"""
        with self.assertRaises(ValueError):
            IndicatorOfCompromise(
                value="192.168.1.1",
                ioc_type=IOCType.IP,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                source="test",
                confidence=1.5  # Invalid
            )

    def test_invalid_ip_format_raises_error(self):
        """Test invalid IP format raises ValueError"""
        with self.assertRaises(ValueError):
            IndicatorOfCompromise(
                value="not-an-ip",
                ioc_type=IOCType.IP,
                first_seen=datetime.now(),
                last_seen=datetime.now(),
                source="test",
                confidence=0.9
            )


class TestThreatActorCampaignTracker(unittest.TestCase):
    """Test main campaign tracker functionality"""

    def setUp(self):
        self.tracker = ThreatActorCampaignTracker()

    def test_create_campaign(self):
        """Test campaign creation works"""
        campaign = self.tracker.create_campaign(
            name="Test Campaign Alpha",
            threat_actor="APT-TEST",
            description="Test campaign for unit testing"
        )
        
        self.assertIsNotNone(campaign.campaign_id)
        self.assertEqual(campaign.name, "Test Campaign Alpha")
        self.assertEqual(campaign.threat_actor, "APT-TEST")
        self.assertEqual(campaign.status, CampaignStatus.EMERGING)

    def test_create_campaign_with_iocs(self):
        """Test campaign creation with initial IOCs"""
        iocs = [
            IndicatorOfCompromise(
                value="10.0.0.1",
                ioc_type=IOCType.IP,
                first_seen=datetime.now() - timedelta(days=5),
                last_seen=datetime.now(),
                source="test-feed",
                confidence=0.95,
                ttp_tags=["T1071", "T1043"]
            )
        ]
        
        campaign = self.tracker.create_campaign(
            name="Campaign with IOCs",
            threat_actor="APT-TEST",
            initial_iocs=iocs
        )
        
        self.assertEqual(len(campaign.iocs), 1)
        self.assertIn("T1071", campaign.ttps)

    def test_add_ioc_to_campaign(self):
        """Test adding IOC to existing campaign"""
        campaign = self.tracker.create_campaign(
            name="Test Campaign",
            threat_actor="APT-TEST"
        )
        
        ioc = IndicatorOfCompromise(
            value="evil.com",
            ioc_type=IOCType.DOMAIN,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.8
        )
        
        result = self.tracker.add_ioc_to_campaign(campaign.campaign_id, ioc)
        self.assertTrue(result)
        self.assertEqual(len(campaign.iocs), 1)

    def test_add_ioc_to_nonexistent_campaign_returns_false(self):
        """Test adding IOC to non-existent campaign fails gracefully"""
        ioc = IndicatorOfCompromise(
            value="evil.com",
            ioc_type=IOCType.DOMAIN,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.8
        )
        result = self.tracker.add_ioc_to_campaign("non-existent-id", ioc)
        self.assertFalse(result)

    def test_find_campaigns_by_ioc(self):
        """Test finding campaigns by IOC"""
        ioc_value = "192.168.100.100"
        ioc = IndicatorOfCompromise(
            value=ioc_value,
            ioc_type=IOCType.IP,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9
        )
        
        campaign = self.tracker.create_campaign(
            name="IOC Search Test",
            threat_actor="APT-TEST",
            initial_iocs=[ioc]
        )
        
        found = self.tracker.find_campaigns_by_ioc(ioc_value, IOCType.IP)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].campaign_id, campaign.campaign_id)

    def test_find_campaigns_by_ttp(self):
        """Test finding campaigns by TTP"""
        ioc = IndicatorOfCompromise(
            value="test.com",
            ioc_type=IOCType.DOMAIN,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9,
            ttp_tags=["T1059", "T1027"]
        )
        
        self.tracker.create_campaign(
            name="TTP Search Test",
            threat_actor="APT-TEST",
            initial_iocs=[ioc]
        )
        
        found = self.tracker.find_campaigns_by_ttp("T1059")
        self.assertEqual(len(found), 1)

    def test_campaign_similarity_calculation(self):
        """Test actual similarity calculation between campaigns"""
        # Create two campaigns with some overlap
        shared_ttp = "T1071"
        ioc1 = IndicatorOfCompromise(
            value="1.1.1.1",
            ioc_type=IOCType.IP,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9,
            ttp_tags=[shared_ttp, "T1043"]
        )
        ioc2 = IndicatorOfCompromise(
            value="2.2.2.2",
            ioc_type=IOCType.IP,
            first_seen=datetime.now(),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9,
            ttp_tags=[shared_ttp, "T1059"]
        )
        
        c1 = self.tracker.create_campaign("Campaign A", "APT-1", initial_iocs=[ioc1])
        c2 = self.tracker.create_campaign("Campaign B", "APT-2", initial_iocs=[ioc2])
        
        similarity = self.tracker.calculate_campaign_similarity(c1.campaign_id, c2.campaign_id)
        
        self.assertIn("overall_similarity", similarity)
        self.assertIn("ttp_similarity", similarity)
        self.assertIn("shared_ttp_count", similarity)
        self.assertEqual(similarity["shared_ttp_count"], 1)  # They share T1071
        self.assertIsInstance(similarity["overall_similarity"], float)
        self.assertTrue(0 <= similarity["overall_similarity"] <= 1)

    def test_campaign_timeline_generation(self):
        """Test timeline generation works"""
        iocs = [
            IndicatorOfCompromise(
                value=f"10.0.0.{i}",
                ioc_type=IOCType.IP,
                first_seen=datetime.now() - timedelta(days=i),
                last_seen=datetime.now(),
                source="test",
                confidence=0.9
            )
            for i in range(3)
        ]
        
        campaign = self.tracker.create_campaign(
            "Timeline Test",
            "APT-TEST",
            initial_iocs=iocs
        )
        
        timeline = self.tracker.get_campaign_timeline(campaign.campaign_id)
        self.assertEqual(len(timeline), 3)
        self.assertIn("timestamp", timeline[0])
        self.assertIn("ioc_value", timeline[0])

    def test_get_active_campaigns(self):
        """Test active campaign detection"""
        # Create campaign with recent activity
        recent_ioc = IndicatorOfCompromise(
            value="active.com",
            ioc_type=IOCType.DOMAIN,
            first_seen=datetime.now() - timedelta(days=2),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9
        )
        self.tracker.create_campaign("Active Campaign", "APT-ACTIVE", initial_iocs=[recent_ioc])
        
        active = self.tracker.get_active_campaigns(active_window_days=30)
        self.assertGreaterEqual(len(active), 1)

    def test_generate_campaign_report(self):
        """Test campaign report generation"""
        campaign = self.tracker.create_campaign(
            "Report Test",
            "APT-TEST",
            description="Test campaign for reporting"
        )
        
        report = self.tracker.generate_campaign_report(campaign.campaign_id)
        
        self.assertIn("campaign_name", report)
        self.assertIn("threat_actor", report)
        self.assertIn("status", report)
        self.assertIn("duration_days", report)
        self.assertIn("ioc_summary", report)
        self.assertIn("ttp_count", report)

    def test_export_all_data(self):
        """Test data export functionality"""
        self.tracker.create_campaign("Export Test 1", "APT-1")
        self.tracker.create_campaign("Export Test 2", "APT-2")
        
        export = self.tracker.export_all_data()
        
        self.assertIn("total_campaigns", export)
        self.assertIn("total_iocs_indexed", export)
        self.assertIn("campaigns", export)
        self.assertGreaterEqual(export["total_campaigns"], 2)

    def test_campaign_duration_calculation(self):
        """Test actual duration calculation"""
        old_ioc = IndicatorOfCompromise(
            value="old.com",
            ioc_type=IOCType.DOMAIN,
            first_seen=datetime.now() - timedelta(days=10),
            last_seen=datetime.now(),
            source="test",
            confidence=0.9
        )
        
        campaign = self.tracker.create_campaign(
            "Duration Test",
            "APT-TEST",
            initial_iocs=[old_ioc]
        )
        
        duration = campaign.get_campaign_duration_days()
        self.assertGreaterEqual(duration, 10)

    def test_activity_velocity_calculation(self):
        """Test activity velocity calculation"""
        iocs = [
            IndicatorOfCompromise(
                value=f"recent-{i}.com",
                ioc_type=IOCType.DOMAIN,
                first_seen=datetime.now() - timedelta(days=i),
                last_seen=datetime.now(),
                source="test",
                confidence=0.9
            )
            for i in range(5)
        ]
        
        campaign = self.tracker.create_campaign(
            "Velocity Test",
            "APT-TEST",
            initial_iocs=iocs
        )
        
        velocity = campaign.get_activity_velocity(window_days=7)
        # 5 IOCs in 7 days = ~0.714 per day
        self.assertAlmostEqual(velocity, 5/7, places=3)


def run_tests_and_save_results():
    """Run tests and save honest results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestIndicatorOfCompromise)
    suite.addTests(loader.loadTestsFromTestCase(TestThreatActorCampaignTracker))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save honest test results
    test_results = {
        "test_timestamp": datetime.now().isoformat(),
        "module_tested": "threat_intelligence_threat_actor_campaign_tracker_2026_june",
        "tests_run": result.testsRun,
        "tests_failed": len(result.failures),
        "tests_errored": len(result.errors),
        "tests_skipped": len(result.skipped),
        "all_passed": result.wasSuccessful(),
        "failures": [str(f[0]) for f in result.failures],
        "errors": [str(e[0]) for e in result.errors]
    }
    
    with open("test_results_threat_actor_campaign_tracker.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("HONEST TESTING: Threat Actor Campaign Tracker")
    print("=" * 60)
    result = run_tests_and_save_results()
    print("\n" + "=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
