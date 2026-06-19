#!/usr/bin/env python3
"""
Test Suite for Threat Intelligence Subdomain Discovery Engine - NeuralShield AI
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

import unittest
import json
from datetime import datetime
from threat_intelligence_subdomain_discovery_engine_2026_june import (
    SubdomainDiscoveryEngine,
    DiscoveryStatus,
    DiscoveredSubdomain,
    DiscoveryResult
)


class TestSubdomainDiscoveryEngine(unittest.TestCase):
    """Production-grade tests for Subdomain Discovery Engine"""
    
    @classmethod
    def setUpClass(cls):
        cls.engine = SubdomainDiscoveryEngine()
    
    def test_engine_initialization(self):
        """Test engine initialization"""
        self.assertEqual(self.engine.timeout, 5.0)
        self.assertEqual(self.engine.max_retries, 3)
        self.assertGreater(len(self.engine.COMMON_SUBDOMAINS), 100)
        self.assertIsInstance(self.engine._dns_cache, dict)
    
    def test_generate_discovery_id(self):
        """Test discovery ID generation"""
        discovery_id = self.engine._generate_discovery_id()
        self.assertEqual(len(discovery_id), 16)
        self.assertIsInstance(discovery_id, str)
    
    def test_dns_query_real_domain(self):
        """Test actual DNS query on real domain"""
        result = self.engine._dns_query("google.com", "A")
        self.assertIsNotNone(result)
        self.assertIsInstance(result, list)
    
    def test_dns_query_nonexistent_domain(self):
        """Test DNS query on nonexistent domain"""
        result = self.engine._dns_query("nonexistent-domain-12345.invalid", "A")
        self.assertIsNone(result)
    
    def test_wildcard_detection(self):
        """Test wildcard DNS detection"""
        # This domain likely doesn't have wildcard
        result = self.engine._detect_wildcard("example.com")
        self.assertIsInstance(result, bool)
    
    def test_cloud_provider_detection(self):
        """Test cloud provider detection"""
        ips = ["1.2.3.4"]
        cnames = ["server.amazonaws.com"]
        provider = self.engine._detect_cloud_provider("test.example.com", ips, cnames)
        self.assertEqual(provider, "AWS")
    
    def test_permutation_generation(self):
        """Test permutation generation"""
        bases = ["api", "www"]
        permutations = self.engine._generate_permutations(bases)
        self.assertGreater(len(permutations), 0)
        self.assertIsInstance(permutations, set)
    
    def test_discover_subdomains_smoke_test(self):
        """Smoke test for main discovery function (limited)"""
        result = self.engine.discover_subdomains(
            "example.com",
            use_wordlist=True,
            use_permutations=False,
            max_subdomains=5
        )
        self.assertIsInstance(result, DiscoveryResult)
        self.assertEqual(result.target_domain, "example.com")
        self.assertGreater(result.total_discovered, 0)
    
    def test_generate_attack_surface_report(self):
        """Test attack surface report generation"""
        result = self.engine.discover_subdomains(
            "example.com",
            use_wordlist=True,
            use_permutations=False,
            max_subdomains=3
        )
        report = self.engine.generate_attack_surface_report(result)
        self.assertIsInstance(report, dict)
        self.assertIn("summary", report)
        self.assertIn("cloud_provider_distribution", report)
    
    def test_get_discovery_stats(self):
        """Test discovery stats"""
        stats = self.engine.get_discovery_stats()
        self.assertIsInstance(stats, dict)
        self.assertEqual(stats["engine"], "SubdomainDiscoveryEngine")
        self.assertIn("wordlist_size", stats)


def run_tests():
    print("=" * 60)
    print("NeuralShield AI - Threat Intelligence Subdomain Discovery Engine Tests")
    print("=" * 60)
    
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    suite.addTests(loader.loadTestsFromTestCase(TestSubdomainDiscoveryEngine))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    report = {
        "test_module": "threat_intelligence_subdomain_discovery_engine_2026_june",
        "timestamp": datetime.now().isoformat(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "honest_note": "Tests perform real DNS network queries - results depend on network environment"
    }
    
    with open("test_results_subdomain_discovery.json", "w") as f:
        json.dump(report, f, indent=2)
    
    print("\n" + "=" * 60)
    print(f"Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print("=" * 60)
    return result.wasSuccessful()


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
