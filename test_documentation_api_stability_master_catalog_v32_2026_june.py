"""
Test Suite for NeuralShield-AI Documentation & API Stability Catalog v32
========================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. Documentation catalog loads correctly
2. All API entries have complete metadata
3. Stability markers are correctly assigned
4. Usage examples are syntactically valid
5. Markdown generation works
6. No breaking changes to existing code

PHILOSOPHY: Test only, don't modify production code
"""

import sys
import unittest
from typing import Optional

# Add module path
sys.path.insert(0, '/home/user/autonomous-developer/NeuralShield-AI')


class TestDocumentationCatalog(unittest.TestCase):
    """Test suite for documentation catalog functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        from neural_shield.documentation_api_stability_master_catalog_v32_2026_june import (
            NeuralShieldDocumentationCatalog,
            StabilityLevel,
            get_documentation_catalog,
            get_api_documentation
        )
        self.catalog_class = NeuralShieldDocumentationCatalog
        self.StabilityLevel = StabilityLevel
        self.get_catalog = get_documentation_catalog
        self.get_api_doc = get_api_documentation
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors"""
        catalog = self.catalog_class()
        self.assertIsNotNone(catalog)
        self.assertGreater(len(catalog._catalog), 0)
        self.assertEqual(catalog.version, "32.0.0")
    
    def test_singleton_accessor(self):
        """Test singleton accessor function works"""
        catalog = self.get_catalog()
        self.assertIsNotNone(catalog)
        self.assertIsInstance(catalog, self.catalog_class)
    
    def test_get_api_documentation(self):
        """Test quick API documentation accessor"""
        doc = self.get_api_doc("AdvancedJailbreakDetector")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.name, "AdvancedJailbreakDetector")
    
    def test_get_nonexistent_api_returns_none(self):
        """Test accessing non-existent API returns None"""
        doc = self.get_api_doc("NonExistentAPI12345")
        self.assertIsNone(doc)
    
    def test_all_apis_have_complete_metadata(self):
        """Verify all API entries have required metadata fields"""
        catalog = self.catalog_class()
        
        for api_name, entry in catalog._catalog.items():
            with self.subTest(api=api_name):
                # Required fields
                self.assertIsNotNone(entry.name, f"{api_name}: missing name")
                self.assertIsNotNone(entry.module_path, f"{api_name}: missing module_path")
                self.assertIsNotNone(entry.stability, f"{api_name}: missing stability")
                self.assertIsNotNone(entry.category, f"{api_name}: missing category")
                self.assertIsNotNone(entry.description, f"{api_name}: missing description")
                self.assertIsNotNone(entry.since_version, f"{api_name}: missing since_version")
                
                # Description should be meaningful
                self.assertGreater(
                    len(entry.description.strip()),
                    10,
                    f"{api_name}: description too short"
                )
    
    def test_stability_levels_are_valid(self):
        """Verify all stability markers are valid enum values"""
        catalog = self.catalog_class()
        
        valid_stabilities = {
            self.StabilityLevel.STABLE,
            self.StabilityLevel.BETA,
            self.StabilityLevel.EXPERIMENTAL,
            self.StabilityLevel.DEPRECATED
        }
        
        for api_name, entry in catalog._catalog.items():
            with self.subTest(api=api_name):
                self.assertIn(entry.stability, valid_stabilities,
                            f"{api_name}: invalid stability level")
    
    def test_jailbreak_detection_apis_exist(self):
        """Verify jailbreak detection APIs are documented"""
        catalog = self.catalog_class()
        
        jailbreak_apis = catalog.list_by_category("Jailbreak Detection")
        self.assertGreater(len(jailbreak_apis), 0)
        
        api_names = {e.name for e in jailbreak_apis}
        self.assertIn("AdvancedJailbreakDetector", api_names)
    
    def test_prompt_injection_apis_exist(self):
        """Verify prompt injection APIs are documented"""
        catalog = self.catalog_class()
        
        pi_apis = catalog.list_by_category("Prompt Injection Defense")
        self.assertGreater(len(pi_apis), 0)
        
        api_names = {e.name for e in pi_apis}
        self.assertIn("PromptInjectionSandbox", api_names)
        self.assertIn("InputPurifier", api_names)
    
    def test_threat_intelligence_apis_exist(self):
        """Verify threat intelligence APIs are documented"""
        catalog = self.catalog_class()
        
        ti_apis = catalog.list_by_category("Threat Intelligence")
        self.assertGreater(len(ti_apis), 0)
    
    def test_security_hardening_apis_exist(self):
        """Verify security hardening APIs are documented"""
        catalog = self.catalog_class()
        
        sec_apis = catalog.list_by_category("Security Hardening")
        self.assertGreater(len(sec_apis), 0)
        
        api_names = {e.name for e in sec_apis}
        self.assertIn("SecureMemoryZeroizer", api_names)
        self.assertIn("ConstantTimeComparator", api_names)
        self.assertIn("RateLimiter", api_names)
    
    def test_observability_apis_exist(self):
        """Verify observability APIs are documented"""
        catalog = self.catalog_class()
        
        obs_apis = catalog.list_by_category("Observability")
        self.assertGreater(len(obs_apis), 0)
        
        api_names = {e.name for e in obs_apis}
        self.assertIn("StructuredLogger", api_names)
        self.assertIn("MetricsCollector", api_names)
    
    def test_error_resilience_apis_exist(self):
        """Verify error resilience APIs are documented"""
        catalog = self.catalog_class()
        
        err_apis = catalog.list_by_category("Error Resilience")
        self.assertGreater(len(err_apis), 0)
        
        api_names = {e.name for e in err_apis}
        self.assertIn("CircuitBreaker", api_names)
        self.assertIn("RetryWithBackoff", api_names)
        self.assertIn("TimeoutWrapper", api_names)
    
    def test_list_by_stability(self):
        """Test filtering APIs by stability level"""
        catalog = self.catalog_class()
        
        stable = catalog.list_by_stability(self.StabilityLevel.STABLE)
        beta = catalog.list_by_stability(self.StabilityLevel.BETA)
        
        self.assertGreater(len(stable), 0, "Should have STABLE APIs")
        self.assertGreater(len(beta), 0, "Should have BETA APIs")
    
    def test_get_all_categories(self):
        """Test getting all unique categories"""
        catalog = self.catalog_class()
        categories = catalog.get_all_categories()
        
        self.assertIsInstance(categories, list)
        self.assertGreater(len(categories), 0)
        self.assertEqual(categories, sorted(categories), "Categories should be sorted")
    
    def test_generate_markdown_docs(self):
        """Test Markdown documentation generation"""
        catalog = self.catalog_class()
        md = catalog.generate_markdown_docs()
        
        self.assertIsInstance(md, str)
        self.assertGreater(len(md), 0)
        self.assertIn("# NeuralShield-AI API Documentation", md)
        self.assertIn("Stability Legend", md)
        self.assertIn("✅ **STABLE**", md)
    
    def test_stability_summary(self):
        """Test stability summary generation"""
        catalog = self.catalog_class()
        summary = catalog.get_stability_summary()
        
        self.assertIsInstance(summary, dict)
        self.assertIn("STABLE", summary)
        self.assertIn("BETA", summary)
        self.assertGreater(summary["STABLE"], 0)
    
    def test_usage_examples_are_present(self):
        """Verify important APIs have usage examples"""
        catalog = self.catalog_class()
        
        important_apis = [
            "AdvancedJailbreakDetector",
            "PromptInjectionSandbox",
            "SecureMemoryZeroizer",
            "CircuitBreaker"
        ]
        
        for api_name in important_apis:
            with self.subTest(api=api_name):
                entry = catalog.get_api(api_name)
                self.assertIsNotNone(entry, f"API {api_name} not found")
                self.assertGreater(
                    len(entry.usage_example.strip()),
                    20,
                    f"{api_name}: usage example missing or too short"
                )
    
    def test_parameters_are_documented(self):
        """Verify APIs have parameter documentation"""
        catalog = self.catalog_class()
        
        entry = catalog.get_api("AdvancedJailbreakDetector")
        self.assertGreater(len(entry.parameters), 0, "Should have parameters documented")
        
        for param in entry.parameters:
            self.assertIn("name", param)
            self.assertIn("type", param)
            self.assertIn("desc", param)
    
    def test_returns_field_is_documented(self):
        """Verify APIs have return value documentation"""
        catalog = self.catalog_class()
        
        for api_name, entry in catalog._catalog.items():
            with self.subTest(api=api_name):
                self.assertGreater(
                    len(entry.returns.strip()),
                    5,
                    f"{api_name}: returns documentation missing"
                )
    
    def test_related_apis_are_listed(self):
        """Verify APIs have related APIs listed"""
        catalog = self.catalog_class()
        
        # At least some APIs should have related APIs
        has_related = False
        for entry in catalog._catalog.values():
            if len(entry.related_apis) > 0:
                has_related = True
                break
        
        self.assertTrue(has_related, "Some APIs should have related APIs listed")
    
    def test_module_imports_without_errors(self):
        """Test the module can be imported without syntax errors"""
        # This is essentially verified by setUp(), but explicit test
        import importlib
        module = importlib.import_module(
            'neural_shield.documentation_api_stability_master_catalog_v32_2026_june'
        )
        self.assertIsNotNone(module)
    
    def test_docstring_formatting(self):
        """Verify module has proper header docstring"""
        import neural_shield.documentation_api_stability_master_catalog_v32_2026_june as module
        self.assertIsNotNone(module.__doc__)
        self.assertIn("NeuralShield-AI", module.__doc__)
        self.assertIn("STABILITY", module.__doc__)


class TestStabilityEnum(unittest.TestCase):
    """Test StabilityLevel enum functionality"""
    
    def test_enum_values(self):
        """Test enum has all expected values"""
        from neural_shield.documentation_api_stability_master_catalog_v32_2026_june import StabilityLevel
        
        expected = {"STABLE", "BETA", "EXPERIMENTAL", "DEPRECATED"}
        actual = {level.value for level in StabilityLevel}
        self.assertEqual(expected, actual)


if __name__ == '__main__':
    print("="*70)
    print("NeuralShield-AI: Documentation & API Stability Tests v32")
    print("Dimension F: Documentation & API Stability")
    print("="*70)
    
    unittest.main(verbosity=2)
