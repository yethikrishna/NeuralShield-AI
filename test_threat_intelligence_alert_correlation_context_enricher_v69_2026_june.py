"""
Test Suite for NeuralShield AI - Threat Intelligence Alert Correlation & Context Enricher v69
Comprehensive tests covering all core functionality
"""
import json
import time
import unittest
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_alert_correlation_context_enricher_v69_2026_june import (
    AlertContextEnricher, SecurityAlert, AlertSeverity,
    IOCEnrichmentEngine, AlertCorrelationEngine,
    CompositeSeverityScorer, FalsePositiveAnalyzer,
    ResponseRecommendationEngine
)


class TestIOCEnrichmentEngine(unittest.TestCase):
    """Test IOC enrichment functionality"""
    
    def setUp(self):
        self.engine = IOCEnrichmentEngine()
    
    def test_private_ip_enrichment(self):
        """Test enrichment of private IP addresses"""
        result = self.engine.enrich_ip("192.168.1.1")
        self.assertTrue(result["is_private"])
        self.assertFalse(result["is_malicious"])
    
    def test_public_ip_enrichment(self):
        """Test enrichment of public IP addresses"""
        result = self.engine.enrich_ip("8.8.8.8")
        self.assertFalse(result["is_private"])
        self.assertFalse(result["is_malicious"])
    
    def test_tor_exit_node_enrichment(self):
        """Test enrichment of known Tor exit nodes"""
        result = self.engine.enrich_ip("185.220.101.1")
        self.assertTrue(result["is_tor_exit"])
        self.assertIn("tor_exit_node", result["threat_tags"])
    
    def test_malicious_ip_range(self):
        """Test enrichment of IPs in known malicious ranges"""
        result = self.engine.enrich_ip("192.168.100.50")
        self.assertTrue(result["is_malicious"])
        self.assertIn("known_malicious_range", result["threat_tags"])
    
    def test_invalid_ip(self):
        """Test handling of invalid IP addresses"""
        result = self.engine.enrich_ip("invalid_ip")
        self.assertIn("error", result)
    
    def test_malicious_domain(self):
        """Test malicious domain enrichment"""
        result = self.engine.enrich_domain("malicious-example.com")
        self.assertTrue(result["is_malicious"])


class TestAlertCorrelationEngine(unittest.TestCase):
    """Test alert correlation functionality"""
    
    def setUp(self):
        self.engine = AlertCorrelationEngine(time_window_seconds=300)
    
    def test_add_alert(self):
        """Test adding alert to buffer"""
        alert = SecurityAlert(
            alert_id="test-001",
            timestamp=time.time(),
            source_ip="192.168.1.100",
            destination_ip="10.0.0.1",
            source_port=12345,
            destination_port=80,
            alert_type="port_scan",
            raw_severity=AlertSeverity.MEDIUM,
            description="Port scan detected"
        )
        self.engine.add_alert(alert)
        self.assertEqual(len(self.engine.alert_buffer), 1)
    
    def test_same_source_ip_correlation(self):
        """Test correlation of alerts from same source IP"""
        base_time = time.time()
        
        # Add first alert
        alert1 = SecurityAlert(
            alert_id="corr-001",
            timestamp=base_time,
            source_ip="192.168.1.200",
            destination_ip="10.0.0.1",
            source_port=10000,
            destination_port=80,
            alert_type="port_scan",
            raw_severity=AlertSeverity.LOW,
            description="Scan 1"
        )
        self.engine.add_alert(alert1)
        
        # Test correlation on second alert from same IP
        alert2 = SecurityAlert(
            alert_id="corr-002",
            timestamp=base_time + 10,
            source_ip="192.168.1.200",
            destination_ip="10.0.0.2",
            source_port=10001,
            destination_port=443,
            alert_type="port_scan",
            raw_severity=AlertSeverity.LOW,
            description="Scan 2"
        )
        
        correlated, boost = self.engine.find_correlated_alerts(alert2)
        self.assertGreater(len(correlated), 0)
        self.assertGreater(boost, 0)


class TestCompositeSeverityScorer(unittest.TestCase):
    """Test composite severity scoring"""
    
    def setUp(self):
        self.scorer = CompositeSeverityScorer()
    
    def test_critical_base_severity(self):
        """Test critical severity base scoring"""
        alert = SecurityAlert(
            alert_id="sev-001",
            timestamp=time.time(),
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=None,
            destination_port=None,
            alert_type="malware",
            raw_severity=AlertSeverity.CRITICAL,
            description="Critical malware detected"
        )
        
        score = self.scorer.calculate_score(alert, {}, 0, 0)
        self.assertEqual(score, 1.0)
    
    def test_severity_with_malicious_ip(self):
        """Test severity boost from malicious IP"""
        alert = SecurityAlert(
            alert_id="sev-002",
            timestamp=time.time(),
            source_ip="192.168.100.50",
            destination_ip="10.0.0.1",
            source_port=None,
            destination_port=None,
            alert_type="c2_connection",
            raw_severity=AlertSeverity.HIGH,
            description="C2 connection attempt"
        )
        
        enrichment = {
            "source_ip_enrichment": {"is_malicious": True, "is_tor_exit": False}
        }
        
        score = self.scorer.calculate_score(alert, enrichment, 0, 0)
        self.assertGreater(score, 0.75)  # Should be boosted above HIGH base


class TestFalsePositiveAnalyzer(unittest.TestCase):
    """Test false probability analysis"""
    
    def setUp(self):
        self.analyzer = FalsePositiveAnalyzer()
    
    def test_private_scan_fp_probability(self):
        """Test higher FP probability for private IP scanning"""
        alert = SecurityAlert(
            alert_id="fp-001",
            timestamp=time.time(),
            source_ip="192.168.1.10",
            destination_ip="192.168.1.20",
            source_port=None,
            destination_port=None,
            alert_type="port_scan",
            raw_severity=AlertSeverity.LOW,
            description="Internal port scan"
        )
        
        enrichment = {
            "source_ip_enrichment": {"is_private": True, "reputation_score": 100},
            "destination_ip_enrichment": {"is_private": True}
        }
        
        fp_prob = self.analyzer.analyze(alert, enrichment)
        self.assertGreater(fp_prob, 0.2)


class TestResponseRecommendationEngine(unittest.TestCase):
    """Test response recommendation generation"""
    
    def setUp(self):
        self.engine = ResponseRecommendationEngine()
    
    def test_critical_severity_recommendations(self):
        """Test recommendations for critical severity alerts"""
        alert = SecurityAlert(
            alert_id="rec-001",
            timestamp=time.time(),
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=None,
            destination_port=None,
            alert_type="ransomware",
            raw_severity=AlertSeverity.CRITICAL,
            description="Ransomware execution detected"
        )
        
        enriched = type('EnrichedMock', (), {
            'base_alert': alert,
            'composite_severity': 0.95,
            'correlated_alerts': [],
            'false_positive_probability': 0.0
        })()
        
        recs = self.engine.generate_recommendations(enriched)
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("IMMEDIATE" in r for r in recs))


class TestAlertContextEnricher(unittest.TestCase):
    """Main enrichment engine tests"""
    
    def setUp(self):
        self.enricher = AlertContextEnricher(correlation_window=300)
    
    def test_single_alert_enrichment(self):
        """Test enrichment of a single alert"""
        alert = SecurityAlert(
            alert_id="enrich-001",
            timestamp=time.time(),
            source_ip="185.220.101.1",  # Tor exit node
            destination_ip="10.0.0.50",
            source_port=45678,
            destination_port=22,
            alert_type="brute_force_ssh",
            raw_severity=AlertSeverity.HIGH,
            description="SSH brute force attack from Tor exit node",
            asset_id="server-prod-01"
        )
        
        result = self.enricher.enrich_alert(alert)
        
        # Verify enrichment
        self.assertIsNotNone(result)
        self.assertEqual(result.base_alert.alert_id, "enrich-001")
        self.assertGreater(result.composite_severity, 0)
        self.assertLessEqual(result.composite_severity, 1.0)
        self.assertGreater(len(result.response_recommendations), 0)
        
        # Verify Tor enrichment worked
        self.assertTrue(result.enrichment_data["source_ip_enrichment"]["is_tor_exit"])
    
    def test_attack_chain_detection(self):
        """Test attack chain position detection"""
        alert = SecurityAlert(
            alert_id="chain-001",
            timestamp=time.time(),
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=None,
            destination_port=None,
            alert_type="data_exfiltration",
            raw_severity=AlertSeverity.HIGH,
            description="Large data transfer to external server"
        )
        
        result = self.enricher.enrich_alert(alert)
        self.assertEqual(result.attack_chain_position, "exfiltration")
    
    def test_batch_enrichment(self):
        """Test batch alert enrichment"""
        alerts = []
        for i in range(5):
            alerts.append(SecurityAlert(
                alert_id=f"batch-{i:03d}",
                timestamp=time.time() + i,
                source_ip=f"10.0.0.{100+i}",
                destination_ip="192.168.1.1",
                source_port=10000+i,
                destination_port=80,
                alert_type="http_request",
                raw_severity=AlertSeverity.LOW,
                description=f"Test alert {i}"
            ))
        
        results = self.enricher.batch_enrich(alerts)
        self.assertEqual(len(results), 5)
    
    def test_correlation_across_alerts(self):
        """Test that related alerts get correlated"""
        base_time = time.time()
        
        # First alert
        alert1 = SecurityAlert(
            alert_id="corr-test-001",
            timestamp=base_time,
            source_ip="172.16.0.100",
            destination_ip="192.168.1.50",
            source_port=50000,
            destination_port=3389,
            alert_type="rdp_brute_force",
            raw_severity=AlertSeverity.MEDIUM,
            description="RDP brute force attempt"
        )
        self.enricher.enrich_alert(alert1)
        
        # Second alert from same source
        alert2 = SecurityAlert(
            alert_id="corr-test-002",
            timestamp=base_time + 5,
            source_ip="172.16.0.100",
            destination_ip="192.168.1.51",
            source_port=50001,
            destination_port=3389,
            alert_type="rdp_brute_force",
            raw_severity=AlertSeverity.MEDIUM,
            description="Second RDP brute force attempt"
        )
        result2 = self.enricher.enrich_alert(alert2)
        
        # Second alert should have correlation
        self.assertGreater(len(result2.correlated_alerts), 0)
    
    def test_stats_generation(self):
        """Test statistics generation"""
        # Process some alerts
        for i in range(3):
            alert = SecurityAlert(
                alert_id=f"stats-{i}",
                timestamp=time.time(),
                source_ip=f"1.1.1.{i}",
                destination_ip="2.2.2.2",
                source_port=None,
                destination_port=None,
                alert_type="test",
                raw_severity=AlertSeverity.LOW,
                description="Test"
            )
            self.enricher.enrich_alert(alert)
        
        stats = self.enricher.get_stats()
        self.assertIn("processed_count", stats)
        self.assertEqual(stats["processed_count"], 3)
        self.assertIn("average_composite_severity", stats)
    
    def test_export_functionality(self):
        """Test enriched alerts export"""
        alert = SecurityAlert(
            alert_id="export-001",
            timestamp=time.time(),
            source_ip="1.1.1.1",
            destination_ip="2.2.2.2",
            source_port=None,
            destination_port=None,
            alert_type="test",
            raw_severity=AlertSeverity.MEDIUM,
            description="Test export"
        )
        self.enricher.enrich_alert(alert)
        
        export_json = self.enricher.export_enriched_alerts()
        data = json.loads(export_json)
        self.assertIsInstance(data, list)
        self.assertGreater(len(data), 0)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    suite.addTests(loader.loadTestsFromTestCase(TestIOCEnrichmentEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestAlertCorrelationEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestCompositeSeverityScorer))
    suite.addTests(loader.loadTestsFromTestCase(TestFalsePositiveAnalyzer))
    suite.addTests(loader.loadTestsFromTestCase(TestResponseRecommendationEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestAlertContextEnricher))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Generate results JSON
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "module": "threat_intelligence_alert_correlation_context_enricher_v69",
        "version": "69.0.0",
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "success": result.wasSuccessful(),
        "test_cases": [
            "IOCEnrichmentEngine",
            "AlertCorrelationEngine",
            "CompositeSeverityScorer",
            "FalsePositiveAnalyzer",
            "ResponseRecommendationEngine",
            "AlertContextEnricher"
        ]
    }
    
    return results


if __name__ == "__main__":
    print("=" * 70)
    print("NeuralShield AI - Alert Correlation & Context Enricher v69 - Test Suite")
    print("=" * 70)
    print()
    
    results = run_tests()
    
    print()
    print("=" * 70)
    print("TEST SUMMARY")
    print("=" * 70)
    print(json.dumps(results, indent=2))
    
    # Save results
    with open("test_results_alert_correlation_context_enricher_v69_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    print(f"\nResults saved to test_results_alert_correlation_context_enricher_v69_2026_june.json")
