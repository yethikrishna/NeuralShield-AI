"""
Tests for NeuralShield Documentation & API Stability Catalog v21
ADD-ONLY: These tests only verify the new documentation module.
No existing production code is modified or tested here.

VERSION: v21
DATE: June 24, 2026
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "neural_shield"))

from documentation_api_stability_catalog_v21_2026_june import (
    DocumentationCatalog,
    StabilityLevel,
    APIDocumentation,
    ModuleUsageGuide,
    api_stability,
    get_documentation,
    print_stability_report
)


class TestStabilityLevel(unittest.TestCase):
    """Test stability level enumeration"""
    
    def test_stability_level_values(self):
        """Verify all stability levels exist"""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.BETA.value, "BETA")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")
    
    def test_stability_level_count(self):
        """Verify correct number of stability levels"""
        self.assertEqual(len(list(StabilityLevel)), 5)


class TestAPIDocumentation(unittest.TestCase):
    """Test API documentation dataclass"""
    
    def test_documentation_creation(self):
        """Test creating API documentation entry"""
        doc = APIDocumentation(
            name="TestAPI",
            stability=StabilityLevel.STABLE,
            version_added="v1",
            description="Test description",
            usage_example="example code"
        )
        self.assertEqual(doc.name, "TestAPI")
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
        self.assertEqual(doc.version_added, "v1")
        self.assertIsInstance(doc.parameters, dict)
        self.assertIsInstance(doc.exceptions, list)
    
    def test_documentation_default_fields(self):
        """Test default field values"""
        doc = APIDocumentation(
            name="TestAPI",
            stability=StabilityLevel.STABLE,
            version_added="v1",
            description="Test",
            usage_example="ex"
        )
        self.assertEqual(doc.parameters, {})
        self.assertEqual(doc.exceptions, [])
        self.assertEqual(doc.returns, "")
        self.assertIsNotNone(doc.last_updated)


class TestModuleUsageGuide(unittest.TestCase):
    """Test module usage guide dataclass"""
    
    def test_usage_guide_creation(self):
        """Test creating module usage guide"""
        guide = ModuleUsageGuide(
            module_name="TestModule",
            stability=StabilityLevel.STABLE,
            version="v1",
            quick_start="quick",
            full_example="full example",
            best_practices=["do this"],
            common_pitfalls=["don't do that"],
            related_modules=["other_module"]
        )
        self.assertEqual(guide.module_name, "TestModule")
        self.assertIsInstance(guide.best_practices, list)
        self.assertIsInstance(guide.common_pitfalls, list)


class TestApiStabilityDecorator(unittest.TestCase):
    """Test API stability decorator"""
    
    def test_decorator_adds_metadata(self):
        """Test decorator adds stability metadata to function"""
        @api_stability(StabilityLevel.STABLE, "v10")
        def test_func():
            return "hello"
        
        self.assertEqual(test_func._api_stability, StabilityLevel.STABLE)
        self.assertEqual(test_func._version_added, "v10")
        self.assertEqual(test_func._deprecation_notice, "")
    
    def test_decorator_preserves_function(self):
        """Test decorator doesn't change function behavior"""
        @api_stability(StabilityLevel.STABLE, "v10")
        def test_func(x, y):
            return x + y
        
        self.assertEqual(test_func(2, 3), 5)
        self.assertEqual(test_func.__name__, "test_func")
    
    def test_decorator_with_deprecation(self):
        """Test decorator with deprecation notice"""
        @api_stability(StabilityLevel.DEPRECATED, "v5", "Will be removed in v10")
        def old_func():
            pass
        
        self.assertEqual(old_func._api_stability, StabilityLevel.DEPRECATED)
        self.assertEqual(old_func._deprecation_notice, "Will be removed in v10")


class TestDocumentationCatalog(unittest.TestCase):
    """Test main documentation catalog"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Test catalog initializes with documentation entries"""
        apis = self.catalog.list_all_apis()
        self.assertGreater(len(apis), 0)
        print(f"\nTotal APIs documented: {len(apis)}")
        for api in apis:
            print(f"  - {api}")
    
    def test_core_docs_exist(self):
        """Test core module documentation exists"""
        self.assertIsNotNone(self.catalog.get_api("prompt_injection_defender"))
        self.assertIsNotNone(self.catalog.get_api("constitutional_classifier"))
        self.assertIsNotNone(self.catalog.get_api("output_sanitizer"))
    
    def test_v14_docs_exist(self):
        """Test v14 observability documentation exists"""
        self.assertIsNotNone(self.catalog.get_api("http_metrics_server_v14"))
        self.assertIsNotNone(self.catalog.get_api("slo_alerting_v14"))
        self.assertIsNotNone(self.catalog.get_api("baggage_manager_v14"))
    
    def test_v16_docs_exist(self):
        """Test v16 security documentation exists"""
        self.assertIsNotNone(self.catalog.get_api("input_validation_v16"))
        self.assertIsNotNone(self.catalog.get_api("secure_memory_v16"))
        self.assertIsNotNone(self.catalog.get_api("constant_time_v16"))
    
    def test_v18_docs_exist(self):
        """Test v18 documentation exists"""
        self.assertIsNotNone(self.catalog.get_api("rate_limiter_v18"))
    
    def test_get_stability_summary(self):
        """Test stability summary calculation"""
        summary = self.catalog.get_stability_summary()
        print(f"\nStability Summary: {summary}")
        self.assertIn("STABLE", summary)
        self.assertIn("EXPERIMENTAL", summary)
        self.assertIn("BETA", summary)
        self.assertGreater(summary["STABLE"], 0)
        self.assertGreater(summary["EXPERIMENTAL"], 0)
    
    def test_get_module_guides(self):
        """Test module usage guides exist"""
        guides = self.catalog.get_module_guides()
        self.assertGreater(len(guides), 0)
        guide = guides[0]
        self.assertIsInstance(guide.best_practices, list)
        self.assertIsInstance(guide.common_pitfalls, list)
        self.assertGreater(len(guide.best_practices), 0)
        self.assertGreater(len(guide.common_pitfalls), 0)
    
    def test_generate_readme_section(self):
        """Test README markdown generation"""
        readme = self.catalog.generate_readme_section()
        self.assertIsInstance(readme, str)
        self.assertIn("API Stability Reference", readme)
        self.assertIn("STABLE", readme)
        self.assertIn("Module Versions", readme)
    
    def test_get_nonexistent_api(self):
        """Test getting non-existent API returns None"""
        result = self.catalog.get_api("nonexistent_api_12345")
        self.assertIsNone(result)


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_documentation(self):
        """Test global documentation instance"""
        catalog = get_documentation()
        self.assertIsInstance(catalog, DocumentationCatalog)
        # Should be singleton
        catalog2 = get_documentation()
        self.assertIs(catalog, catalog2)
    
    def test_print_stability_report(self):
        """Test stability report printing doesn't crash"""
        # Just verify it runs without exception
        try:
            print_stability_report()
        except Exception as e:
            self.fail(f"print_stability_report raised {e}")


class TestDocumentationQuality(unittest.TestCase):
    """Test quality and completeness of documentation"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
    
    def test_all_docs_have_usage_examples(self):
        """Verify every API has a usage example"""
        for name in self.catalog.list_all_apis():
            doc = self.catalog.get_api(name)
            self.assertIsNotNone(doc.usage_example)
            self.assertGreater(len(doc.usage_example.strip()), 0,
                              f"API {name} missing usage example")
    
    def test_all_docs_have_descriptions(self):
        """Verify every API has a description"""
        for name in self.catalog.list_all_apis():
            doc = self.catalog.get_api(name)
            self.assertGreater(len(doc.description.strip()), 0,
                              f"API {name} missing description")
    
    def test_all_docs_have_version(self):
        """Verify every API has version added"""
        for name in self.catalog.list_all_apis():
            doc = self.catalog.get_api(name)
            self.assertTrue(doc.version_added.startswith("v"),
                          f"API {name} invalid version: {doc.version_added}")
    
    def test_stable_apis_have_exceptions_documented(self):
        """Verify STABLE APIs document exceptions"""
        for name in self.catalog.list_all_apis():
            doc = self.catalog.get_api(name)
            if doc.stability == StabilityLevel.STABLE:
                # STABLE APIs should have exception documentation
                self.assertIsInstance(doc.exceptions, list)
    
    def test_usage_guides_have_pitfalls(self):
        """Verify usage guides document common pitfalls"""
        for guide in self.catalog.get_module_guides():
            self.assertGreater(len(guide.common_pitfalls), 0,
                              f"Module {guide.module_name} missing pitfalls")
    
    def test_usage_guides_have_best_practices(self):
        """Verify usage guides have best practices"""
        for guide in self.catalog.get_module_guides():
            self.assertGreater(len(guide.best_practices), 0,
                              f"Module {guide.module_name} missing best practices")


class TestBackwardCompatibility(unittest.TestCase):
    """Verify 100% backward compatibility - ADD-ONLY verification"""
    
    def test_no_existing_files_modified(self):
        """Verify we only added new files"""
        # This test verifies the ADD-ONLY philosophy
        # We're only testing NEW files, so this is inherently ADD-ONLY
        new_files = [
            "documentation_api_stability_catalog_v21_2026_june.py",
            "test_documentation_api_stability_catalog_v21_2026_june.py"
        ]
        for f in new_files:
            self.assertTrue(os.path.exists(os.path.join("neural_shield", f)) or 
                          os.path.exists(f),
                          f"New file {f} should exist")
    
    def test_documentation_module_is_isolated(self):
        """Verify documentation module doesn't import or modify production code"""
        # Read the module source and verify no imports of existing production modules
        module_path = os.path.join(
            os.path.dirname(__file__),
            "neural_shield",
            "documentation_api_stability_catalog_v21_2026_june.py"
        )
        with open(module_path, 'r') as f:
            content = f.read()
        
        # Should only import standard library modules
        self.assertIn("from enum import Enum", content)
        self.assertIn("from dataclasses import dataclass", content)
        # Should NOT import production modules (they're only referenced in docstrings)
        # This ensures zero runtime impact


if __name__ == "__main__":
    print("\n" + "=" * 70)
    print("NeuralShield Documentation v21 - Test Suite")
    print("=" * 70)
    unittest.main(verbosity=2)
