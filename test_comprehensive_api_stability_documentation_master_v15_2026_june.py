"""
Tests for NeuralShield-AI Comprehensive API Stability Documentation Catalog v15
Session 115 - Dimension F Implementation
"""

import unittest
import json
from neural_shield.comprehensive_api_stability_documentation_master_v15_2026_june import (
    NeuralShieldDocumentationCatalog,
    StabilityLevel,
    ModuleCategory,
    APIDocumentation,
    ModuleSummary,
)


class TestStabilityLevelEnum(unittest.TestCase):
    """Test StabilityLevel enum values."""
    
    def test_stability_levels_exist(self):
        """All four stability levels should be defined."""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")


class TestModuleCategoryEnum(unittest.TestCase):
    """Test ModuleCategory enum values."""
    
    def test_module_categories_exist(self):
        """All module categories should be defined."""
        categories = [
            ModuleCategory.THREAT_DETECTION,
            ModuleCategory.INPUT_SANITIZATION,
            ModuleCategory.OUTPUT_PROTECTION,
            ModuleCategory.AGENT_SECURITY,
            ModuleCategory.OBSERVABILITY,
            ModuleCategory.ERROR_RESILIENCE,
            ModuleCategory.SECURITY_HARDENING,
            ModuleCategory.THREAT_INTELLIGENCE,
            ModuleCategory.INTEGRATION,
        ]
        for cat in categories:
            self.assertIsNotNone(cat.value)


class TestNeuralShieldDocumentationCatalogBasics(unittest.TestCase):
    """Test basic catalog initialization and core functionality."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_catalog_initializes(self):
        """Catalog should initialize without errors."""
        self.assertIsNotNone(self.catalog)
    
    def test_catalog_has_modules(self):
        """Catalog should have registered modules."""
        modules = self.catalog.list_all_modules()
        self.assertGreater(len(modules), 0)
    
    def test_catalog_has_apis(self):
        """Catalog should have registered APIs."""
        apis = self.catalog.list_all_apis()
        self.assertGreater(len(apis), 0)
    
    def test_get_module_summary_exists(self):
        """Should get existing module summary."""
        summary = self.catalog.get_module_summary("prompt_firewall")
        self.assertIsNotNone(summary)
        self.assertEqual(summary.stability, StabilityLevel.STABLE)
    
    def test_get_module_summary_nonexistent(self):
        """Should return None for nonexistent module."""
        summary = self.catalog.get_module_summary("nonexistent_module_xyz")
        self.assertIsNone(summary)
    
    def test_get_api_documentation_exists(self):
        """Should get existing API documentation."""
        doc = self.catalog.get_api_documentation("PromptFirewall.scan")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
    
    def test_get_api_documentation_nonexistent(self):
        """Should return None for nonexistent API."""
        doc = self.catalog.get_api_documentation("NonexistentClass.method")
        self.assertIsNone(doc)


class TestStabilityFiltering(unittest.TestCase):
    """Test API filtering by stability level."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_filter_stable_apis(self):
        """Should filter and return only STABLE APIs."""
        stable_apis = self.catalog.list_all_apis(StabilityLevel.STABLE)
        self.assertGreater(len(stable_apis), 0)
        for api in stable_apis:
            self.assertEqual(api.stability, StabilityLevel.STABLE)
    
    def test_filter_experimental_apis(self):
        """Should filter and return only EXPERIMENTAL APIs."""
        experimental_apis = self.catalog.list_all_apis(StabilityLevel.EXPERIMENTAL)
        for api in experimental_apis:
            self.assertEqual(api.stability, StabilityLevel.EXPERIMENTAL)


class TestCategoryFiltering(unittest.TestCase):
    """Test module filtering by category."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_filter_threat_detection(self):
        """Should filter threat detection modules."""
        modules = self.catalog.list_all_modules(ModuleCategory.THREAT_DETECTION)
        for mod in modules:
            self.assertEqual(mod.category, ModuleCategory.THREAT_DETECTION)
    
    def test_filter_security_hardening(self):
        """Should filter security hardening modules."""
        modules = self.catalog.list_all_modules(ModuleCategory.SECURITY_HARDENING)
        for mod in modules:
            self.assertEqual(mod.category, ModuleCategory.SECURITY_HARDENING)


class TestStabilitySummary(unittest.TestCase):
    """Test stability summary statistics."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_stability_summary_structure(self):
        """Summary should have all required fields."""
        summary = self.catalog.get_stability_summary()
        required_fields = [
            "catalog_version",
            "generated_at",
            "total_apis",
            "total_modules",
            "stability_breakdown",
            "stable_apis",
            "experimental_apis",
        ]
        for field in required_fields:
            self.assertIn(field, summary)
    
    def test_stability_summary_counts(self):
        """Counts should be accurate."""
        summary = self.catalog.get_stability_summary()
        self.assertEqual(summary["total_apis"], len(self.catalog.list_all_apis()))
        self.assertEqual(summary["total_modules"], len(self.catalog.list_all_modules()))
        self.assertGreater(summary["stable_apis"], 0)


class TestJsonExport(unittest.TestCase):
    """Test JSON export functionality."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_export_to_json(self):
        """Should export valid JSON."""
        json_str = self.catalog.export_to_json()
        data = json.loads(json_str)
        
        self.assertIn("catalog_version", data)
        self.assertIn("modules", data)
        self.assertIn("apis", data)
        self.assertGreater(len(data["modules"]), 0)
        self.assertGreater(len(data["apis"]), 0)


class TestReadmeGeneration(unittest.TestCase):
    """Test README Markdown generation."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_generate_readme_section(self):
        """Should generate non-empty Markdown."""
        md = self.catalog.generate_readme_section()
        self.assertIsInstance(md, str)
        self.assertGreater(len(md), 0)
        self.assertIn("API Stability Reference", md)
        self.assertIn("STABLE", md)
        self.assertIn("EXPERIMENTAL", md)


class TestAPIDocumentationFields(unittest.TestCase):
    """Test that all documented APIs have required fields."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_all_apis_have_signature(self):
        """Every API should have a signature field."""
        for api in self.catalog.list_all_apis():
            self.assertGreater(len(api.signature), 0)
            self.assertGreater(len(api.description), 0)
            self.assertIsNotNone(api.stability)
            self.assertIsNotNone(api.category)
    
    def test_all_apis_have_since_version(self):
        """Every API should have since_version."""
        for api in self.catalog.list_all_apis():
            self.assertGreater(len(api.since_version), 0)
    
    def test_thread_safe_flag(self):
        """Thread safe flag should be boolean."""
        for api in self.catalog.list_all_apis():
            self.assertIsInstance(api.thread_safe, bool)


class TestModuleDocumentationFields(unittest.TestCase):
    """Test that all documented modules have required fields."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_all_modules_have_description(self):
        """Every module should have a description."""
        for mod in self.catalog.list_all_modules():
            self.assertGreater(len(mod.description), 0)
            self.assertGreater(len(mod.module_name), 0)
            self.assertIsNotNone(mod.stability)
            self.assertIsNotNone(mod.category)
    
    def test_all_modules_have_test_coverage(self):
        """Every module should have test_coverage field."""
        for mod in self.catalog.list_all_modules():
            self.assertIn(mod.test_coverage, ["HIGH", "MEDIUM", "LOW"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
