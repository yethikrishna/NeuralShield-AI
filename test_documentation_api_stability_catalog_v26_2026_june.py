"""
Test Suite for NeuralShield-AI Documentation & API Stability Catalog v26
Tests verify documentation integrity, stability markers, and catalog functionality.

DIMENSION F: Documentation & API Stability
No production code modified - only tests and documentation.
"""

import unittest
import json
from neural_shield.comprehensive_api_documentation_stability_catalog_v26_2026_june import (
    NeuralShieldAPICatalog,
    StabilityLevel,
    APIDocumentation
)


class TestNeuralShieldAPICatalog(unittest.TestCase):
    """Test suite for the API documentation catalog"""
    
    def setUp(self):
        """Initialize catalog for each test"""
        self.catalog = NeuralShieldAPICatalog()
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors"""
        self.assertIsNotNone(self.catalog)
        self.assertGreater(len(self.catalog._catalog), 0)
    
    def test_catalog_contains_documentation(self):
        """Test catalog contains expected API entries"""
        expected_apis = [
            "AdvancedJailbreakDetector",
            "GraphBasedJailbreakDetector",
            "ContextAwarePromptInjectionDefender",
            "PromptInjectionSandbox",
            "HallucinationDetector",
            "AgentToolCallValidator",
            "AgentMemorySafetyGuardian"
        ]
        
        for api_name in expected_apis:
            with self.subTest(api=api_name):
                doc = self.catalog.get_documentation(api_name)
                self.assertIsNotNone(doc, f"Missing documentation for {api_name}")
                self.assertIsInstance(doc, APIDocumentation)
    
    def test_stability_levels_are_valid(self):
        """Test all APIs have valid stability levels"""
        valid_stabilities = {
            StabilityLevel.STABLE,
            StabilityLevel.BETA,
            StabilityLevel.EXPERIMENTAL,
            StabilityLevel.DEPRECATED
        }
        
        for api_name, doc in self.catalog._catalog.items():
            with self.subTest(api=api_name):
                self.assertIn(doc.stability, valid_stabilities)
    
    def test_stability_summary(self):
        """Test stability summary generation"""
        summary = self.catalog.get_stability_summary()
        
        self.assertIn("STABLE", summary)
        self.assertIn("BETA", summary)
        self.assertIn("EXPERIMENTAL", summary)
        self.assertIn("DEPRECATED", summary)
        
        total = sum(summary.values())
        self.assertEqual(total, len(self.catalog._catalog))
    
    def test_list_all_apis(self):
        """Test listing APIs with optional filtering"""
        all_apis = self.catalog.list_all_apis()
        self.assertEqual(len(all_apis), len(self.catalog._catalog))
        
        stable_apis = self.catalog.list_all_apis(StabilityLevel.STABLE)
        self.assertGreater(len(stable_apis), 0)
        
        beta_apis = self.catalog.list_all_apis(StabilityLevel.BETA)
        self.assertGreater(len(beta_apis), 0)
    
    def test_get_documentation_returns_none_for_unknown(self):
        """Test get_documentation returns None for unknown APIs"""
        doc = self.catalog.get_documentation("NonExistentAPI")
        self.assertIsNone(doc)
    
    def test_documentation_fields_are_populated(self):
        """Test all documentation fields have meaningful content"""
        for api_name, doc in self.catalog._catalog.items():
            with self.subTest(api=api_name):
                # Required fields
                self.assertTrue(doc.class_name)
                self.assertTrue(doc.module_name)
                self.assertTrue(doc.description)
                self.assertGreater(len(doc.primary_methods), 0)
                self.assertGreater(len(doc.method_signatures), 0)
                self.assertTrue(doc.usage_example)
                self.assertIsInstance(doc.thread_safe, bool)
                
                # Description should be substantial
                self.assertGreater(len(doc.description), 20)
                
                # Usage example should contain Python code
                self.assertIn("import", doc.usage_example.lower())
    
    def test_generate_markdown_report(self):
        """Test markdown report generation"""
        report = self.catalog.generate_markdown_report()
        
        self.assertIsInstance(report, str)
        self.assertGreater(len(report), 1000)
        
        # Report should contain key sections
        self.assertIn("API Documentation Catalog", report)
        self.assertIn("Stability Summary", report)
        self.assertIn("STABLE", report)
        self.assertIn("BETA", report)
        self.assertIn("Complete API Documentation", report)
    
    def test_export_json(self):
        """Test JSON export functionality"""
        json_output = self.catalog.export_json()
        
        # Should be valid JSON
        data = json.loads(json_output)
        self.assertIsInstance(data, dict)
        self.assertEqual(len(data), len(self.catalog._catalog))
        
        # Check structure
        for api_name, api_data in data.items():
            self.assertIn("class_name", api_data)
            self.assertIn("stability", api_data)
            self.assertIn("description", api_data)
            self.assertIn("thread_safe", api_data)
            self.assertIn("performance_notes", api_data)
    
    def test_stable_apis_have_comprehensive_docs(self):
        """STABLE APIs should have particularly comprehensive documentation"""
        stable_apis = self.catalog.list_all_apis(StabilityLevel.STABLE)
        
        for api_name in stable_apis:
            doc = self.catalog.get_documentation(api_name)
            with self.subTest(api=api_name):
                # STABLE APIs should have parameter documentation
                self.assertGreater(len(doc.parameters), 0)
                # STABLE APIs should have return value documentation
                self.assertGreater(len(doc.return_values), 0)
                # STABLE APIs should document exceptions
                self.assertGreater(len(doc.exceptions), 0)
    
    def test_method_signatures_match_primary_methods(self):
        """Test method signatures match declared primary methods"""
        for api_name, doc in self.catalog._catalog.items():
            with self.subTest(api=api_name):
                # Each primary method should have a signature
                for method in doc.primary_methods:
                    # Method might be in signature dict with full signature
                    found = any(method in sig for sig in doc.method_signatures.keys())
                    self.assertTrue(found, f"Missing signature for {method} in {api_name}")
    
    def test_performance_notes_present(self):
        """All APIs should have performance notes"""
        for api_name, doc in self.catalog._catalog.items():
            with self.subTest(api=api_name):
                self.assertTrue(doc.performance_notes)
                self.assertGreater(len(doc.performance_notes), 10)
    
    def test_since_version_format(self):
        """Test since_version follows semantic version format"""
        for api_name, doc in self.catalog._catalog.items():
            with self.subTest(api=api_name):
                self.assertTrue(doc.since_version)
                # Should be date-based versioning
                parts = doc.since_version.split(".")
                self.assertEqual(len(parts), 3)


class TestStabilityLevelEnum(unittest.TestCase):
    """Test stability level enumeration"""
    
    def test_stability_level_values(self):
        """Test stability level values are correct"""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.BETA.value, "BETA")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
    
    def test_stability_level_iterable(self):
        """Test can iterate through stability levels"""
        levels = list(StabilityLevel)
        self.assertEqual(len(levels), 4)


if __name__ == "__main__":
    # Run tests
    suite = unittest.TestLoader().loadTestsFromTestCase(TestNeuralShieldAPICatalog)
    suite.addTests(unittest.TestLoader().loadTestsFromTestCase(TestStabilityLevelEnum))
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    print(f"\n{'='*60}")
    print(f"Tests Run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"{'='*60}")
    
    if result.wasSuccessful():
        print("✓ All documentation catalog tests passed!")
    else:
        print("✗ Some tests failed")
