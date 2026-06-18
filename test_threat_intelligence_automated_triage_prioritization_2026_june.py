#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Automated Triage & Prioritization Engine
Production-Grade Tests - June 19, 2026
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

import unittest
from datetime import datetime, timedelta
from threat_intelligence_automated_triage_prioritization_2026_june import (
    ThreatIntelligenceTriageEngine,
    ThreatSeverity,
    SLALevel,
    TriageStatus,
    TriageResult,
)


class TestThreatIntelligenceTriageEngine(unittest.TestCase):
    """Test suite for the automated triage engine."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.engine = ThreatIntelligenceTriageEngine()
    
    def test_engine_initialization(self):
        """Test engine initializes correctly with default config."""
        self.assertIsNotNone(self.engine.config)
        self.assertIsNotNone(self.engine.triage_history)
        self.assertIsNotNone(self.engine.triage_queue)
        self.assertEqual(len(self.engine.triage_history), 0)
        self.assertEqual(len(self.engine.triage_queue), 0)
    
    def test_generate_threat_id(self):
        """Test deterministic threat ID generation."""
        threat_data = {"type": "malware", "indicator": "192.168.1.1"}
        threat_id1 = self.engine.generate_threat_id(threat_data)
        threat_id2 = self.engine.generate_threat_id(threat_data)
        
        self.assertEqual(threat_id1, threat_id2)
        self.assertTrue(threat_id1.startswith("THREAT-"))
        self.assertEqual(len(threat_id1), 23)  # THREAT- + 16 hex chars
    
    def test_calculate_cvss_score(self):
        """Test CVSS score calculation."""
        # Critical CVSS
        cvss_high = {"base_score": 10.0}
        score = self.engine.calculate_cvss_score(cvss_high)
        self.assertEqual(score, 100.0)
        
        # Medium CVSS
        cvss_medium = {"base_score": 5.0}
        score = self.engine.calculate_cvss_score(cvss_medium)
        self.assertEqual(score, 50.0)
        
        # Default case
        score = self.engine.calculate_cvss_score({})
        self.assertEqual(score, 50.0)
    
    def test_calculate_mitre_score(self):
        """Test MITRE ATT&CK score calculation."""
        # High impact techniques
        mitre_high = {
            "techniques": ["T1003", "T1055"],  # Credential Dumping, Process Injection
            "tactics": ["privilege-escalation", "credential-access"]
        }
        score = self.engine.calculate_mitre_score(mitre_high)
        self.assertGreater(score, 80)
        
        # Default case (no techniques)
        score = self.engine.calculate_mitre_score({})
        self.assertEqual(score, 50.0)
    
    def test_calculate_confidence_score(self):
        """Test confidence score based on source quality."""
        # Premium source
        threat_premium = {"source": "virustotal", "num_sources": 3}
        score = self.engine.calculate_confidence_score(threat_premium)
        self.assertGreater(score, 90)
        
        # Low quality source
        threat_low = {"source": "user_report", "num_sources": 1}
        score = self.engine.calculate_confidence_score(threat_low)
        self.assertLess(score, 70)
    
    def test_calculate_business_impact_score(self):
        """Test business impact calculation."""
        # Critical assets
        threat_critical = {
            "affected_assets": [
                {"type": "domain_controller"},
                {"type": "database_server"}
            ]
        }
        score = self.engine.calculate_business_impact_score(threat_critical)
        self.assertEqual(score, 100)
        
        # No assets
        score = self.engine.calculate_business_impact_score({})
        self.assertEqual(score, 50.0)
    
    def test_calculate_timeliness_score(self):
        """Test timeliness score calculation."""
        # Very recent threat
        threat_recent = {"first_seen": datetime.now().isoformat()}
        score = self.engine.calculate_timeliness_score(threat_recent)
        self.assertGreaterEqual(score, 90)
        
        # Old threat
        threat_old = {"first_seen": (datetime.now() - timedelta(days=7)).isoformat()}
        score = self.engine.calculate_timeliness_score(threat_old)
        self.assertLessEqual(score, 50)
    
    def test_calculate_false_positive_probability(self):
        """Test false positive probability calculation."""
        # Likely real threat
        threat_real = {
            "source": "mandiant",
            "num_sources": 5,
            "affected_assets": [{"type": "database_server"}]
        }
        fp_prob = self.engine.calculate_false_positive_probability(threat_real)
        self.assertLess(fp_prob, 0.3)
        
        # Likely false positive (test pattern, single source, no assets)
        threat_fp = {
            "source": "user_report",
            "num_sources": 1,
            "indicator": "test-attack-123"
        }
        fp_prob = self.engine.calculate_false_positive_probability(threat_fp)
        self.assertGreater(fp_prob, 0.2)
    
    def test_determine_severity(self):
        """Test severity determination from priority score."""
        self.assertEqual(self.engine.determine_severity(95.0), ThreatSeverity.CRITICAL)
        self.assertEqual(self.engine.determine_severity(80.0), ThreatSeverity.HIGH)
        self.assertEqual(self.engine.determine_severity(60.0), ThreatSeverity.MEDIUM)
        self.assertEqual(self.engine.determine_severity(35.0), ThreatSeverity.LOW)
        self.assertEqual(self.engine.determine_severity(10.0), ThreatSeverity.INFORMATIONAL)
    
    def test_determine_sla(self):
        """Test SLA level determination."""
        self.assertEqual(self.engine.determine_sla(ThreatSeverity.CRITICAL), SLALevel.IMMEDIATE)
        self.assertEqual(self.engine.determine_sla(ThreatSeverity.HIGH), SLALevel.URGENT)
        self.assertEqual(self.engine.determine_sla(ThreatSeverity.MEDIUM), SLALevel.STANDARD)
    
    def test_triage_critical_threat(self):
        """Test triage of a critical threat."""
        critical_threat = {
            "cvss": {"base_score": 10.0},
            "mitre": {
                "techniques": ["T1003", "T1055"],
                "tactics": ["credential-access", "exfiltration"]
            },
            "source": "mandiant",
            "num_sources": 5,
            "affected_assets": [{"type": "domain_controller"}],
            "first_seen": datetime.now().isoformat(),
            "threat_types": ["ransomware", "data_exfiltration"]
        }
        
        result = self.engine.triage_threat(critical_threat)
        
        self.assertIsInstance(result, TriageResult)
        self.assertEqual(result.final_severity, ThreatSeverity.CRITICAL)
        self.assertTrue(result.escalation_recommended)
        self.assertEqual(result.sla_level, SLALevel.IMMEDIATE)
        self.assertGreater(result.priority_score, 85)
        self.assertIn("threat_id", result.__dict__)
        self.assertGreater(len(result.recommended_actions), 0)
        self.assertIn("Verify backup integrity", " ".join(result.recommended_actions))
    
    def test_triage_medium_threat(self):
        """Test triage of a medium severity threat."""
        medium_threat = {
            "cvss": {"base_score": 5.0},
            "mitre": {"techniques": ["T1083"], "tactics": ["discovery"]},
            "source": "open_source",
            "num_sources": 2,
            "affected_assets": [{"type": "workstation"}],
            "first_seen": (datetime.now() - timedelta(hours=12)).isoformat(),
            "threat_types": ["reconnaissance"]
        }
        
        result = self.engine.triage_threat(medium_threat)
        
        self.assertIn(result.final_severity, [ThreatSeverity.MEDIUM, ThreatSeverity.LOW])
        self.assertFalse(result.escalation_recommended)
        self.assertIsNotNone(result.priority_score)
    
    def test_batch_triage(self):
        """Test batch triage of multiple threats."""
        threats = [
            {
                "cvss": {"base_score": 10.0},
                "mitre": {"techniques": ["T1003"]},
                "source": "mandiant",
                "num_sources": 3,
                "affected_assets": [{"type": "database_server"}],
                "first_seen": datetime.now().isoformat(),
            },
            {
                "cvss": {"base_score": 5.0},
                "mitre": {"techniques": ["T1083"]},
                "source": "open_source",
                "num_sources": 1,
                "affected_assets": [{"type": "workstation"}],
                "first_seen": (datetime.now() - timedelta(days=3)).isoformat(),
            },
            {
                "cvss": {"base_score": 7.5},
                "mitre": {"techniques": ["T1059"]},
                "source": "crowdstrike",
                "num_sources": 4,
                "affected_assets": [{"type": "web_server"}],
                "first_seen": (datetime.now() - timedelta(hours=2)).isoformat(),
            }
        ]
        
        results = self.engine.batch_triage(threats)
        
        self.assertEqual(len(results), 3)
        self.assertEqual(len(self.engine.triage_history), 3)
        self.assertEqual(len(self.engine.triage_queue), 3)
        
        # Verify all results are TriageResult objects
        for result in results:
            self.assertIsInstance(result, TriageResult)
    
    def test_get_triage_queue(self):
        """Test getting prioritized triage queue."""
        # Add some threats
        threats = [
            {"cvss": {"base_score": 10.0}, "source": "mandiant", "num_sources": 3},
            {"cvss": {"base_score": 3.0}, "source": "open_source", "num_sources": 1},
        ]
        self.engine.batch_triage(threats)
        
        # Get full queue
        queue = self.engine.get_triage_queue()
        self.assertEqual(len(queue), 2)
        
        # Verify priority ordering (highest first)
        self.assertGreater(queue[0].priority_score, queue[1].priority_score)
    
    def test_get_triage_statistics(self):
        """Test triage statistics generation."""
        threats = [
            {"cvss": {"base_score": 10.0}, "source": "mandiant", "num_sources": 3},
            {"cvss": {"base_score": 5.0}, "source": "open_source", "num_sources": 1},
            {"cvss": {"base_score": 7.5}, "source": "crowdstrike", "num_sources": 2},
        ]
        self.engine.batch_triage(threats)
        
        stats = self.engine.get_triage_statistics()
        
        self.assertEqual(stats["total_triaged"], 3)
        self.assertIn("severity_distribution", stats)
        self.assertIn("escalation_rate", stats)
        self.assertIn("average_priority_score", stats)
        self.assertIn("queue_length", stats)
        self.assertEqual(stats["queue_length"], 3)
    
    def test_update_triage_status(self):
        """Test updating triage status."""
        threat = {"cvss": {"base_score": 7.0}, "source": "virustotal"}
        result = self.engine.triage_threat(threat)
        threat_id = result.threat_id
        
        # Update to investigating
        success = self.engine.update_triage_status(threat_id, TriageStatus.INVESTIGATING)
        self.assertTrue(success)
        self.assertEqual(self.engine.triage_history[threat_id].status, TriageStatus.INVESTIGATING)
        
        # Update to resolved - should remove from queue
        success = self.engine.update_triage_status(threat_id, TriageStatus.RESOLVED)
        self.assertTrue(success)
        self.assertNotIn(threat_id, self.engine.triage_queue)
        
        # Non-existent threat
        success = self.engine.update_triage_status("NONEXISTENT", TriageStatus.RESOLVED)
        self.assertFalse(success)
    
    def test_recommendations_based_on_threat_type(self):
        """Test threat-type specific recommendations."""
        # Ransomware threat
        ransomware_threat = {
            "cvss": {"base_score": 9.0},
            "source": "mandiant",
            "threat_types": ["ransomware"]
        }
        result = self.engine.triage_threat(ransomware_threat)
        self.assertIn(
            "Verify backup integrity and offline status",
            result.recommended_actions
        )
        
        # Phishing threat
        phishing_threat = {
            "cvss": {"base_score": 6.0},
            "source": "open_source",
            "threat_types": ["phishing"]
        }
        result = self.engine.triage_threat(phishing_threat)
        self.assertIn(
            "Notify email security team for blocking",
            result.recommended_actions
        )
    
    def test_risk_and_mitigating_factors(self):
        """Test risk and mitigating factor identification."""
        threat = {
            "cvss": {"base_score": 9.5},
            "mitre": {"techniques": ["T1003"], "tactics": ["credential-access"]},
            "source": "mandiant",
            "num_sources": 1,  # Single source = mitigating factor
            "affected_assets": [{"type": "domain_controller"}],
            "first_seen": datetime.now().isoformat(),
        }
        
        result = self.engine.triage_threat(threat)
        
        # Should have risk factors
        self.assertGreater(len(result.risk_factors), 0)
        
        # Should have mitigating factor for single source
        self.assertIn("Single source only", result.mitigating_factors)


def run_tests():
    """Run all tests and return results."""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestThreatIntelligenceTriageEngine)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 70)
    print("Threat Intelligence Automated Triage & Prioritization Engine - Test Suite")
    print("Production-Grade Implementation - June 19, 2026")
    print("=" * 70)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 70)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'PASS' if result.wasSuccessful() else 'FAIL'}")
    print("=" * 70)
    
    sys.exit(0 if result.wasSuccessful() else 1)
