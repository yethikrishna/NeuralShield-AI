"""
Test Suite for NeuralShield API Stability Documentation Framework v3
====================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. Stability level enums work correctly
2. API decorators apply metadata correctly
3. Catalog registration and querying work
4. Compatibility matrix generation works
5. No breaking changes to existing code
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

import unittest
import warnings
from datetime import datetime

from api_stability_documentation_framework_v3_2026_june import (
    StabilityLevel,
    SupportLevel,
    APIMetadata,
    UsageExample,
    stable_api,
    experimental_api,
    deprecated_api,
    APIStabilityCatalog,
    get_api_catalog,
    get_stability_report,
    get_standard_examples
)


class TestStabilityEnums(unittest.TestCase):
    """Test stability and support level enumerations"""
    
    def test_stability_level_values(self):
        """Verify all stability levels are defined"""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.BETA.value, "BETA")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.LEGACY.value, "LEGACY")
    
    def test_support_level_values(self):
        """Verify all support levels are defined"""
        self.assertEqual(SupportLevel.FULL_SUPPORT.value, "FULL_SUPPORT")
        self.assertEqual(SupportLevel.SECURITY_ONLY.value, "SECURITY_ONLY")
        self.assertEqual(SupportLevel.MAINTENANCE.value, "MAINTENANCE")
        self.assertEqual(SupportLevel.COMMUNITY.value, "COMMUNITY")


class TestAPIMetadata(unittest.TestCase):
    """Test API metadata dataclass"""
    
    def test_metadata_creation(self):
        """Test basic metadata creation"""
        metadata = APIMetadata(
            name="TestAPI",
            stability=StabilityLevel.STABLE,
            support=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            since_version="1.0.0",
            description="Test API"
        )
        self.assertEqual(metadata.name, "TestAPI")
        self.assertEqual(metadata.stability, StabilityLevel.STABLE)
        self.assertEqual(metadata.version, "1.0.0")
    
    def test_metadata_defaults(self):
        """Test metadata default values"""
        metadata = APIMetadata(
            name="TestAPI",
            stability=StabilityLevel.STABLE,
            support=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            since_version="1.0.0",
            description="Test API"
        )
        self.assertIsNotNone(metadata.last_updated)
        self.assertEqual(metadata.tags, [])
        self.assertEqual(metadata.limitations, [])
        self.assertFalse(metadata.thread_safe)


class TestStabilityDecorators(unittest.TestCase):
    """Test stability decorator functionality"""
    
    def test_stable_api_decorator(self):
        """Test stable_api decorator applies metadata"""
        @stable_api(version="2.0.0", since="1.0.0")
        def test_function():
            """Test function docstring"""
            return True
        
        self.assertTrue(hasattr(test_function, '__api_metadata__'))
        self.assertEqual(test_function.__api_metadata__.stability, StabilityLevel.STABLE)
        self.assertTrue(test_function())  # Function still works
    
    def test_experimental_api_decorator(self):
        """Test experimental_api decorator"""
        @experimental_api(version="0.5.0")
        def experimental_func():
            return "experimental"
        
        self.assertEqual(
            experimental_func.__api_metadata__.stability,
            StabilityLevel.EXPERIMENTAL
        )
        self.assertEqual(experimental_func(), "experimental")
    
    def test_deprecated_api_decorator(self):
        """Test deprecated_api decorator emits warning"""
        @deprecated_api(version="2.0.0", removal_in="3.0.0", replacement="NewAPI")
        def old_function():
            return "deprecated"
        
        self.assertEqual(
            old_function.__api_metadata__.stability,
            StabilityLevel.DEPRECATED
        )
        
        # Verify warning is emitted
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_function()
            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[-1].category, DeprecationWarning))
            self.assertIn("deprecated", str(w[-1].message).lower())
        
        self.assertEqual(result, "deprecated")
    
    def test_decorator_preserves_functionality(self):
        """Verify decorators don't break original function behavior"""
        @stable_api(version="1.0.0")
        def add(a, b):
            return a + b
        
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(10, 20), 30)


class TestAPIStabilityCatalog(unittest.TestCase):
    """Test central API catalog functionality"""
    
    def setUp(self):
        self.catalog = APIStabilityCatalog()
    
    def test_catalog_initialized(self):
        """Test catalog initializes with standard APIs"""
        self.assertGreater(len(self.catalog._apis), 0)
    
    def test_register_api(self):
        """Test registering new API"""
        initial_count = len(self.catalog._apis)
        self.catalog.register_api(APIMetadata(
            name="NewTestAPI",
            stability=StabilityLevel.STABLE,
            support=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            since_version="1.0.0",
            description="New test API"
        ))
        self.assertEqual(len(self.catalog._apis), initial_count + 1)
    
    def test_get_api_metadata(self):
        """Test retrieving API metadata"""
        metadata = self.catalog.get_api_metadata("PromptInjectionDetector")
        self.assertIsNotNone(metadata)
        self.assertEqual(metadata.name, "PromptInjectionDetector")
        self.assertEqual(metadata.stability, StabilityLevel.STABLE)
    
    def test_list_apis_by_stability(self):
        """Test filtering APIs by stability level"""
        stable_apis = self.catalog.list_apis_by_stability(StabilityLevel.STABLE)
        experimental_apis = self.catalog.list_apis_by_stability(StabilityLevel.EXPERIMENTAL)
        
        self.assertGreater(len(stable_apis), 0)
        self.assertGreater(len(experimental_apis), 0)
        
        for api in stable_apis:
            self.assertEqual(api.stability, StabilityLevel.STABLE)
    
    def test_get_compatibility_matrix(self):
        """Test compatibility matrix generation"""
        matrix = self.catalog.get_compatibility_matrix()
        self.assertIn("total_apis", matrix)
        self.assertIn("by_stability", matrix)
        self.assertIn("apis", matrix)
        self.assertGreater(matrix["total_apis"], 0)
    
    def test_generate_readme_section(self):
        """Test README section generation"""
        readme = self.catalog.generate_readme_section()
        self.assertIsInstance(readme, str)
        self.assertIn("API Stability Overview", readme)
        self.assertIn("STABLE", readme)
        self.assertIn("EXPERIMENTAL", readme)


class TestGlobalFunctions(unittest.TestCase):
    """Test global convenience functions"""
    
    def test_get_api_catalog(self):
        """Test global catalog singleton"""
        catalog1 = get_api_catalog()
        catalog2 = get_api_catalog()
        self.assertIs(catalog1, catalog2)  # Same instance
    
    def test_get_stability_report(self):
        """Test stability report generation"""
        report = get_stability_report()
        self.assertEqual(report["report_version"], "3.0.0")
        self.assertEqual(report["framework"], "NeuralShield AI Security")
        self.assertIn("compatibility_matrix", report)
    
    def test_get_standard_examples(self):
        """Test usage examples retrieval"""
        examples = get_standard_examples()
        self.assertIsInstance(examples, dict)
        self.assertGreater(len(examples), 0)
        
        for api_name, api_examples in examples.items():
            for example in api_examples:
                self.assertIsInstance(example.title, str)
                self.assertIsInstance(example.code, str)


class TestUsageExamples(unittest.TestCase):
    """Test usage example dataclass"""
    
    def test_usage_example_creation(self):
        """Test example creation"""
        example = UsageExample(
            title="Test Example",
            description="Test description",
            code="print('hello')",
            expected_output="hello",
            complexity="BASIC"
        )
        self.assertEqual(example.title, "Test Example")
        self.assertEqual(example.complexity, "BASIC")
    
    def test_example_default_complexity(self):
        """Test default complexity value"""
        example = UsageExample(
            title="Test",
            description="Test",
            code="test"
        )
        self.assertEqual(example.complexity, "BASIC")


class TestBackwardCompatibility(unittest.TestCase):
    """Verify no breaking changes - module is ADD-ONLY"""
    
    def test_no_import_side_effects(self):
        """Importing module doesn't break anything"""
        # This would fail if there were import errors
        import api_stability_documentation_framework_v3_2026_june
        self.assertIsNotNone(api_stability_documentation_framework_v3_2026_june)
    
    def test_module_self_test(self):
        """Run module's self-test via __main__"""
        # Just verify it doesn't crash
        import api_stability_documentation_framework_v3_2026_june as module
        report = module.get_stability_report()
        self.assertIsNotNone(report)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    return runner.run(suite)


if __name__ == "__main__":
    print("=" * 60)
    print("NeuralShield API Stability Documentation Framework v3 Tests")
    print("DIMENSION F: Documentation & API Stability")
    print("=" * 60)
    
    result = run_tests()
    
    print("\n" + "=" * 60)
    print(f"Tests Passed: {result.testsRun - len(result.failures) - len(result.errors)}/{result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print("=" * 60)
    
    if result.wasSuccessful():
        print("✓ ALL TESTS PASSED - Dimension F Implementation Successful")
    else:
        print("✗ SOME TESTS FAILED")
        sys.exit(1)
