#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Alert Correlation Context Enricher v75
NeuralShield AI - Security Module Tests

Tests cover:
- Alert enrichment functionality
- Correlation engine behavior
- IOC extraction
- MITRE mapping
- Statistics tracking
- Thread safety
"""

import json
import time
import threading
import unittest
from neural_shield.threat_intelligence_alert_correlation_context_enricher_v75_2026_june import (
    AlertCorrelationContextEnricher,
    AlertSeverity,
    AlertType,
    EnrichmentSource,
    EnrichedAlert
)


class TestAlertCorrelationContextEnricher(unittest.TestCase):
    """Main test class for the enricher module"""

    def setUp(self):
        """Set up test fixtures"""
        self.enricher = AlertCorrelationContextEnricher(correlation_window=3600)

    def test_module_import(self):
        """Test that module imports correctly"""
        self.assertIsNotNone(AlertCorrelationContextEnricher)
        self.assertIsNotNone(AlertSeverity)
        self.assertIsNotNone(AlertType)
        self.assertIsNotNone(EnrichmentSource)
        self.assertIsNotNone(EnrichedAlert)

    def test_enricher_initialization(self):
        """Test enricher initialization"""
        self.assertEqual(self.enricher.processed_count, 0)
        stats = self.enricher.get_enrichment_statistics()
        self.assertEqual(stats["total_processed"], 0)
        self.assertEqual(stats["enrichment_version"], "v75")

    def test_process_single_alert(self):
        """Test processing a single alert"""
        raw_alert = {
            "alert_type": "prompt_injection",
            "severity": "high",
            "source_ip": "192.168.1.100",
            "message": "Malicious prompt detected",
            "confidence": 0.8,
            "target": "production_database"
        }

        result = self.enricher.process_alert(raw_alert)

        self.assertIn("alert_id", result)
        self.assertIn("enrichment_data", result)
        self.assertEqual(result["severity"], "high")
        self.assertEqual(result["alert_type"], "prompt_injection")
        self.assertGreater(result["confidence_score"], 0.5)
        self.assertIn("llm_attacker", result["threat_actor_tags"])

    def test_alert_id_generation(self):
        """Test deterministic alert ID generation"""
        alert1 = {"alert_type": "malware_detection", "source_ip": "10.0.0.1"}
        alert2 = {"alert_type": "malware_detection", "source_ip": "10.0.0.1"}

        result1 = self.enricher.process_alert(alert1)
        result2 = self.enricher.process_alert(alert2)

        # Same content should produce same ID
        self.assertEqual(result1["alert_id"], result2["alert_id"])

    def test_ioc_extraction(self):
        """Test IOC extraction from alerts"""
        alert_with_iocs = {
            "alert_type": "malware_detection",
            "message": "Detected hash d41d8cd98f00b204e9800998ecf8427e from IP 8.8.8.8",
            "url": "http://malicious-example.com/payload"
        }

        result = self.enricher.process_alert(alert_with_iocs)

        ioc_types = [ioc["type"] for ioc in result["ioc_matches"]]
        self.assertIn("ipv4", ioc_types)
        self.assertIn("md5", ioc_types)
        self.assertIn("url", ioc_types)

    def test_mitre_technique_mapping(self):
        """Test MITRE ATT&CK technique mapping"""
        alert = {
            "alert_type": "prompt_injection",
            "severity": "critical"
        }

        result = self.enricher.process_alert(alert)
        self.assertGreater(len(result["mitre_techniques"]), 0)

    def test_asset_criticality_assessment(self):
        """Test asset criticality assessment"""
        # Critical asset
        critical_alert = {
            "alert_type": "unauthorized_access",
            "target": "production_database_pii"
        }
        result = self.enricher.process_alert(critical_alert)
        self.assertEqual(
            result["enrichment_data"]["asset_criticality"],
            "critical"
        )

        # Low criticality asset
        low_alert = {
            "alert_type": "unauthorized_access",
            "target": "dev_test_server"
        }
        result = self.enricher.process_alert(low_alert)
        # Should not be critical
        self.assertIn(
            result["enrichment_data"]["asset_criticality"],
            ["low", "medium"]
        )

    def test_ip_enrichment(self):
        """Test IP address enrichment"""
        # Private IP
        private_alert = {
            "alert_type": "network_anomaly",
            "source_ip": "192.168.1.1"
        }
        result = self.enricher.process_alert(private_alert)
        self.assertTrue(result["enrichment_data"]["source_ip_info"]["is_private"])

        # External IP
        external_alert = {
            "alert_type": "network_anomaly",
            "source_ip": "8.8.8.8"
        }
        result = self.enricher.process_alert(external_alert)
        self.assertTrue(result["enrichment_data"]["source_ip_info"]["is_external"])

    def test_alert_correlation(self):
        """Test alert correlation functionality"""
        # Process multiple alerts from same source IP
        for i in range(5):
            alert = {
                "alert_type": "network_anomaly",
                "source_ip": "10.0.0.50",
                "sequence": i,
                "timestamp": time.time()
            }
            self.enricher.process_alert(alert)

        clusters = self.enricher.get_correlation_clusters()
        self.assertIsInstance(clusters, list)

    def test_batch_processing(self):
        """Test batch alert processing"""
        alerts = [
            {"alert_type": "malware_detection", "severity": "high"},
            {"alert_type": "unauthorized_access", "severity": "medium"},
            {"alert_type": "data_exfiltration", "severity": "critical"},
        ]

        results = self.enricher.process_alerts_batch(alerts)
        self.assertEqual(len(results), 3)
        self.assertEqual(self.enricher.processed_count, 3)

    def test_high_confidence_filtering(self):
        """Test high confidence alert filtering"""
        # Process some alerts
        for i in range(10):
            alert = {
                "alert_type": "prompt_injection",
                "confidence": 0.9 if i < 5 else 0.2,
                "sequence": i
            }
            self.enricher.process_alert(alert)

        high_conf = self.enricher.get_high_confidence_alerts(min_confidence=0.7)
        self.assertGreaterEqual(len(high_conf), 5)

    def test_false_positive_probability(self):
        """Test false positive probability calculation"""
        # Low severity alerts have higher FP chance
        low_severity = {
            "alert_type": "network_anomaly",
            "severity": "low",
            "confidence": 0.2
        }
        result = self.enricher.process_alert(low_severity)
        self.assertGreater(result["false_positive_probability"], 0.0)

    def test_threat_actor_tagging(self):
        """Test threat actor tagging"""
        ransomware_alert = {
            "alert_type": "malware_detection",
            "message": "ransomware detected, encrypting files for bitcoin payment"
        }
        result = self.enricher.process_alert(ransomware_alert)
        self.assertIn("ransomware", result["threat_actor_tags"])

    def test_enrichment_statistics(self):
        """Test enrichment statistics tracking"""
        alerts = [
            {"alert_type": "prompt_injection", "severity": "critical"},
            {"alert_type": "jailbreak_attempt", "severity": "high"},
            {"alert_type": "network_anomaly", "severity": "low"},
        ]

        for alert in alerts:
            self.enricher.process_alert(alert)

        stats = self.enricher.get_enrichment_statistics()
        self.assertEqual(stats["total_processed"], 3)
        self.assertIn("critical", stats["severity_distribution"])
        self.assertIn("prompt_injection", stats["severity_distribution"])

    def test_thread_safety(self):
        """Test thread safety of alert processing"""
        def process_alerts():
            for i in range(10):
                alert = {
                    "alert_type": "network_anomaly",
                    "thread_id": threading.get_ident(),
                    "seq": i
                }
                self.enricher.process_alert(alert)

        threads = [threading.Thread(target=process_alerts) for _ in range(5)]

        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(self.enricher.processed_count, 50)

    def test_unknown_alert_type_handling(self):
        """Test handling of unknown alert types"""
        alert = {
            "alert_type": "unknown_custom_type",
            "severity": "medium"
        }
        # Should not raise exception
        result = self.enricher.process_alert(alert)
        self.assertIsNotNone(result)

    def test_unknown_severity_handling(self):
        """Test handling of unknown severity levels"""
        alert = {
            "alert_type": "malware_detection",
            "severity": "custom_severity"
        }
        # Should not raise exception, defaults to medium
        result = self.enricher.process_alert(alert)
        self.assertEqual(result["severity"], "medium")

    def test_empty_alert_handling(self):
        """Test handling of empty/minimal alert"""
        alert = {}
        result = self.enricher.process_alert(alert)
        self.assertIsNotNone(result)
        self.assertIn("alert_id", result)

    def test_temporal_context_analysis(self):
        """Test temporal context analysis"""
        alert = {
            "alert_type": "network_anomaly",
            "timestamp": time.time()
        }
        result = self.enricher.process_alert(alert)
        temporal = result["enrichment_data"]["temporal_context"]
        self.assertIn("hour_of_day", temporal)
        self.assertIn("is_business_hours", temporal)
        self.assertIn("is_weekend", temporal)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromTestCase(TestAlertCorrelationContextEnricher)
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "was_successful": result.wasSuccessful()
    }


if __name__ == "__main__":
    print("Running Threat Intelligence Alert Correlation Context Enricher v75 Tests")
    print("=" * 70)
    results = run_tests()
    print("=" * 70)
    print(f"Tests Run: {results['tests_run']}")
    print(f"Failures: {results['failures']}")
    print(f"Errors: {results['errors']}")
    print(f"Success: {results['was_successful']}")

    # Save test results
    with open("test_results_alert_correlation_enricher_v75_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
