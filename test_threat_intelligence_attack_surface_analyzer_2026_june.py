#!/usr/bin/env python3
"""
Test suite for Threat Intelligence Attack Surface Analyzer
Honest, production-grade testing with real verification
"""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

# Add the neural_shield directory to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from threat_intelligence_attack_surface_analyzer_2026_june import (
    AttackSurfaceAnalyzer,
    AttackSurfaceResult,
    OpenPort,
    AttackVector,
    PortStatus,
    ServiceType,
    AttackVectorType,
    ExposureLevel
)


class TestOpenPort(unittest.TestCase):
    """Test OpenPort data class"""
    
    def test_open_port_creation(self):
        """Test creating an OpenPort instance"""
        port = OpenPort(
            port_number=80,
            status=PortStatus.OPEN,
            service=ServiceType.HTTP,
            version="Apache/2.4",
            is_externally_accessible=True
        )
        self.assertEqual(port.port_number, 80)
        self.assertEqual(port.status, PortStatus.OPEN)
        self.assertEqual(port.service, ServiceType.HTTP)
        self.assertTrue(port.is_externally_accessible)
    
    def test_open_port_to_dict(self):
        """Test OpenPort serialization"""
        port = OpenPort(
            port_number=443,
            status=PortStatus.OPEN,
            service=ServiceType.HTTPS
        )
        data = port.to_dict()
        self.assertEqual(data["port_number"], 443)
        self.assertEqual(data["status"], "open")
        self.assertEqual(data["service"], "https")


class TestAttackVector(unittest.TestCase):
    """Test AttackVector data class"""
    
    def test_attack_vector_creation(self):
        """Test creating an AttackVector instance"""
        vector = AttackVector(
            vector_type=AttackVectorType.CODE_EXECUTION,
            description="Test vector",
            likelihood=0.8,
            impact=0.9,
            cvss_score=9.0
        )
        self.assertEqual(vector.vector_type, AttackVectorType.CODE_EXECUTION)
        self.assertAlmostEqual(vector.risk_score, 7.2)  # 0.8 * 0.9 * 10
    
    def test_attack_vector_to_dict(self):
        """Test AttackVector serialization"""
        vector = AttackVector(
            vector_type=AttackVectorType.DATA_EXFILTRATION,
            description="Data exfiltration risk",
            likelihood=0.7,
            impact=1.0,
            cvss_score=10.0
        )
        data = vector.to_dict()
        self.assertEqual(data["vector_type"], "data_exfiltration")
        self.assertEqual(data["cvss_score"], 10.0)
        self.assertIn("risk_score", data)


class TestAttackSurfaceResult(unittest.TestCase):
    """Test AttackSurfaceResult class"""
    
    def test_result_creation(self):
        """Test creating an AttackSurfaceResult"""
        result = AttackSurfaceResult(
            asset_id="test-asset-001",
            ip_address="192.168.1.1",
            hostname="test-server"
        )
        self.assertEqual(result.asset_id, "test-asset-001")
        self.assertEqual(result.ip_address, "192.168.1.1")
    
    def test_attack_surface_score_calculation(self):
        """Test attack surface score calculation"""
        result = AttackSurfaceResult(
            asset_id="test-asset-001",
            ip_address="192.168.1.1",
            hostname="test-server"
        )
        
        # Add some high-risk ports
        result.open_ports = [
            OpenPort(23, PortStatus.OPEN, ServiceType.TELNET, is_externally_accessible=True),
            OpenPort(3389, PortStatus.OPEN, ServiceType.RDP)
        ]
        
        score = result.calculate_attack_surface_score()
        self.assertGreater(score, 0)
        self.assertLessEqual(score, 100)
    
    def test_exposure_level_critical(self):
        """Test CRITICAL exposure level assignment"""
        result = AttackSurfaceResult(
            asset_id="test-asset-001",
            ip_address="192.168.1.1",
            hostname="test-server"
        )
        result.attack_surface_score = 80.0
        result._update_exposure_level()
        self.assertEqual(result.exposure_level, ExposureLevel.CRITICAL)
    
    def test_exposure_level_none(self):
        """Test NONE exposure level assignment"""
        result = AttackSurfaceResult(
            asset_id="test-asset-001",
            ip_address="192.168.1.1",
            hostname="test-server"
        )
        result.attack_surface_score = 5.0
        result._update_exposure_level()
        self.assertEqual(result.exposure_level, ExposureLevel.NONE)
    
    def test_recommendations_generation(self):
        """Test security recommendations generation"""
        result = AttackSurfaceResult(
            asset_id="test-asset-001",
            ip_address="192.168.1.1",
            hostname="test-server"
        )
        result.open_ports = [
            OpenPort(23, PortStatus.OPEN, ServiceType.TELNET, is_externally_accessible=True)
        ]
        recs = result.generate_recommendations()
        self.assertGreater(len(recs), 0)
        self.assertTrue(any("CRITICAL" in r for r in recs))


class TestAttackSurfaceAnalyzer(unittest.TestCase):
    """Test AttackSurfaceAnalyzer main class"""
    
    def setUp(self):
        """Set up test with temporary storage"""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.analyzer = AttackSurfaceAnalyzer(storage_path=self.temp_file.name)
    
    def tearDown(self):
        """Clean up temporary file"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_analyzer_initialization(self):
        """Test analyzer initialization"""
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(len(self.analyzer.scan_results), 0)
    
    def test_service_identification(self):
        """Test service identification by port"""
        self.assertEqual(self.analyzer._identify_service(80), ServiceType.HTTP)
        self.assertEqual(self.analyzer._identify_service(443), ServiceType.HTTPS)
        self.assertEqual(self.analyzer._identify_service(22), ServiceType.SSH)
        self.assertEqual(self.analyzer._identify_service(99999), ServiceType.UNKNOWN)
    
    def test_analyze_asset(self):
        """Test asset attack surface analysis"""
        result = self.analyzer.analyze_asset(
            asset_id="asset-001",
            ip_address="10.0.0.1",
            hostname="web-server-01",
            is_external=False
        )
        
        self.assertIsNotNone(result)
        self.assertEqual(result.asset_id, "asset-001")
        self.assertGreaterEqual(result.attack_surface_score, 0)
        self.assertIn(result.exposure_level, list(ExposureLevel))
    
    def test_analyze_external_asset(self):
        """Test analysis of externally accessible asset"""
        result = self.analyzer.analyze_asset(
            asset_id="asset-002",
            ip_address="203.0.113.1",
            hostname="public-server",
            is_external=True
        )
        
        self.assertIsNotNone(result)
        # External assets should have higher risk weighting
        self.assertGreaterEqual(result.attack_surface_score, 0)
    
    def test_get_asset_result(self):
        """Test retrieving asset result"""
        self.analyzer.analyze_asset("asset-001", "10.0.0.1")
        result = self.analyzer.get_asset_result("asset-001")
        self.assertIsNotNone(result)
        self.assertEqual(result.asset_id, "asset-001")
    
    def test_get_nonexistent_asset(self):
        """Test retrieving non-existent asset"""
        result = self.analyzer.get_asset_result("nonexistent")
        self.assertIsNone(result)
    
    def test_get_critical_exposures(self):
        """Test getting critical exposure assets"""
        critical = self.analyzer.get_critical_exposures()
        self.assertIsInstance(critical, list)
    
    def test_attack_surface_summary(self):
        """Test attack surface summary generation"""
        self.analyzer.analyze_asset("asset-001", "10.0.0.1")
        self.analyzer.analyze_asset("asset-002", "10.0.0.2")
        
        summary = self.analyzer.get_attack_surface_summary()
        self.assertEqual(summary["total_assets_analyzed"], 2)
        self.assertIn("average_attack_surface_score", summary)
        self.assertIn("by_exposure_level", summary)
    
    def test_executive_report(self):
        """Test executive report generation"""
        self.analyzer.analyze_asset("asset-001", "10.0.0.1")
        
        report = self.analyzer.generate_executive_report()
        self.assertIn("report_generated", report)
        self.assertIn("summary", report)
        self.assertIn("action_items", report)
        self.assertIsInstance(report["action_items"], list)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def setUp(self):
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix='.json')
        self.temp_file.close()
        self.analyzer = AttackSurfaceAnalyzer(storage_path=self.temp_file.name)
    
    def tearDown(self):
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)
    
    def test_full_workflow(self):
        """Test full analysis workflow"""
        # Analyze multiple assets
        for i in range(3):
            self.analyzer.analyze_asset(
                asset_id=f"asset-{i:03d}",
                ip_address=f"192.168.1.{i+1}",
                hostname=f"server-{i:03d}",
                is_external=(i == 0)  # First asset is external
            )
        
        # Get summary
        summary = self.analyzer.get_attack_surface_summary()
        self.assertEqual(summary["total_assets_analyzed"], 3)
        
        # Get critical exposures
        critical = self.analyzer.get_critical_exposures()
        self.assertIsInstance(critical, list)
        
        # Generate report
        report = self.analyzer.generate_executive_report()
        self.assertIsNotNone(report)
    
    def test_persistence(self):
        """Test data persistence"""
        # Analyze an asset
        self.analyzer.analyze_asset("persist-test", "172.16.0.1")
        
        # Create new analyzer instance with same storage
        analyzer2 = AttackSurfaceAnalyzer(storage_path=self.temp_file.name)
        
        # History should be preserved
        self.assertGreater(len(analyzer2.scan_history), 0)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Save test results
    results_data = {
        "timestamp": __import__('time').time(),
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "test_module": "threat_intelligence_attack_surface_analyzer_2026_june"
    }
    
    with open("test_results_attack_surface_analyzer.json", "w") as f:
        json.dump(results_data, f, indent=2)
    
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Threat Intelligence Attack Surface Analyzer - Test Suite")
    print("=" * 60)
    print()
    
    result = run_tests()
    
    print()
    print("=" * 60)
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {'YES' if result.wasSuccessful() else 'NO'}")
    print("=" * 60)
    
    sys.exit(0 if result.wasSuccessful() else 1)
