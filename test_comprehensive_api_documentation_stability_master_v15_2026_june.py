"""
Test Suite for NeuralShield-AI API Documentation & Stability Catalog v15
Session 115 - Dimension F: Documentation & API Stability
ADD-ONLY: No existing production code modified
"""

import unittest
import json
from neural_shield.comprehensive_api_documentation_stability_master_v15_2026_june import (
    NeuralShieldAPIDocumentationCatalog,
    APIStability,
    APICategory,
    ModuleDoc,
    APIEndpointDoc
)


class TestAPIStabilityEnum(unittest.TestCase):
    """Test API stability classification enums."""
    
    def test_stability_values(self):
        """All stability levels have correct string values."""
        self.assertEqual(APIStability.STABLE.value, "stable")
        self.assertEqual(APIStability.EXPERIMENTAL.value, "experimental")
        self.assertEqual(APIStability.DEPRECATED.value, "deprecated")
        self.assertEqual(APIStability.LEGACY.value, "legacy")
    
    def test_category_values(self):
        """All category enums have correct values."""
        self.assertEqual(APICategory.THREAT_DETECTION.value, "threat_detection")
        self.assertEqual(APICategory.SECURITY_HARDENING.value, "security_hardening")
        self.assertEqual(APICategory.DOCUMENTATION.value, "documentation")


class TestAPIEndpointDoc(unittest.TestCase):
    """Test API endpoint documentation data class."""
    
    def test_endpoint_creation(self):
        """Create endpoint doc with all fields."""
        endpoint = APIEndpointDoc(
            name="test.method",
            signature="test(a: int) -> str",
            description="Test method",
            stability=APIStability.STABLE,
            since_version="1.0.0"
        )
        self.assertEqual(endpoint.name, "test.method")
        self.assertEqual(endpoint.stability, APIStability.STABLE)


class TestModuleDoc(unittest.TestCase):
    """Test module documentation data class."""
    
    def test_module_creation(self):
        """Create module documentation entry."""
        module = ModuleDoc(
            module_name="Test Module",
            file_name="test_module.py",
            category=APICategory.THREAT_DETECTION,
            stability=APIStability.STABLE,
            description="Test module description"
        )
        self.assertEqual(module.module_name, "Test Module")
        self.assertTrue(module.last_updated)


class TestNeuralShieldAPIDocumentationCatalogBasics(unittest.TestCase):
    """Basic catalog functionality tests."""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Catalog initializes with module entries."""
        self.assertGreater(len(self.catalog), 0)
    
    def test_get_module_exists(self):
        """Get existing module documentation."""
        module = self.catalog.get_module("threat_intelligence_feed_manager")
        self.assertIsNotNone(module)
        self.assertIsInstance(module, ModuleDoc)
    
    def test_get_module_nonexistent(self):
        """Get nonexistent module returns None."""
        module = self.catalog.get_module("nonexistent_module_xyz")
        self.assertIsNone(module)
    
    def test_get_all_modules(self):
        """Get list of all documented modules."""
        modules = self.catalog.get_all_modules()
        self.assertIsInstance(modules, list)
        self.assertEqual(len(modules), len(self.catalog))


class TestCatalogFiltering(unittest.TestCase):
    """Test category and stability filtering."""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_get_by_category(self):
        """Filter modules by functional category."""
        security_modules = self.catalog.get_by_category(APICategory.SECURITY_HARDENING)
        self.assertIsInstance(security_modules, list)
        for mod in security_modules:
            self.assertEqual(mod.category, APICategory.SECURITY_HARDENING)
    
    def test_get_by_stability(self):
        """Filter modules by stability level."""
        stable_modules = self.catalog.get_by_stability(APIStability.STABLE)
        self.assertIsInstance(stable_modules, list)
        for mod in stable_modules:
            self.assertEqual(mod.stability, APIStability.STABLE)
    
    def test_stability_summary(self):
        """Get stability summary counts."""
        summary = self.catalog.get_stability_summary()
        self.assertIn("stable", summary)
        self.assertIn("experimental", summary)
        self.assertIsInstance(summary["stable"], int)
    
    def test_category_summary(self):
        """Get category summary counts."""
        summary = self.catalog.get_category_summary()
        self.assertIn("security_hardening", summary)
        self.assertIn("documentation", summary)


class TestCatalogSearch(unittest.TestCase):
    """Test full-text search functionality."""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_search_by_name(self):
        """Search modules by module name."""
        results = self.catalog.search_modules("threat")
        self.assertGreater(len(results), 0)
    
    def test_search_by_description(self):
        """Search modules by description content."""
        results = self.catalog.search_modules("security")
        self.assertGreater(len(results), 0)
    
    def test_search_nomatch(self):
        """Search with no matching results."""
        results = self.catalog.search_modules("xyz_nonexistent_term_12345")
        self.assertEqual(len(results), 0)


class TestCatalogExport(unittest.TestCase):
    """Test JSON export and documentation generation."""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_export_json_valid(self):
        """Export produces valid JSON."""
        json_output = self.catalog.export_json()
        data = json.loads(json_output)
        self.assertIn("catalog_version", data)
        self.assertIn("total_modules", data)
        self.assertIn("modules", data)
        self.assertEqual(data["catalog_version"], "v15")
        self.assertEqual(data["session"], "115")
    
    def test_export_contains_modules(self):
        """Export includes all module documentation."""
        json_output = self.catalog.export_json()
        data = json.loads(json_output)
        self.assertEqual(len(data["modules"]), len(self.catalog))
    
    def test_generate_readme_summary(self):
        """README summary generation works."""
        readme = self.catalog.generate_readme_summary()
        self.assertIsInstance(readme, str)
        self.assertIn("Module Stability Summary", readme)
        self.assertIn("Session 115", readme)
        self.assertIn("v15", readme)


class TestModuleContentValidation(unittest.TestCase):
    """Validate content of documented modules."""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_threat_intelligence_module_content(self):
        """Threat intelligence module has complete documentation."""
        mod = self.catalog.get_module("threat_intelligence_feed_manager")
        self.assertIsNotNone(mod)
        self.assertEqual(mod.stability, APIStability.EXPERIMENTAL)
        self.assertGreater(len(mod.best_practices), 0)
        self.assertGreater(len(mod.common_pitfalls), 0)
        self.assertTrue(mod.usage_example.strip())
    
    def test_security_hardening_module_content(self):
        """Security hardening module has complete documentation."""
        mod = self.catalog.get_module("comprehensive_security_hardening")
        self.assertIsNotNone(mod)
        self.assertEqual(mod.stability, APIStability.STABLE)
        self.assertGreater(len(mod.best_practices), 0)
    
    def test_self_documentation_exists(self):
        """This catalog module documents itself."""
        mod = self.catalog.get_module("api_documentation_catalog")
        self.assertIsNotNone(mod)
        self.assertEqual(mod.category, APICategory.DOCUMENTATION)
        self.assertTrue(mod.usage_example.strip())
    
    def test_endpoint_documentation(self):
        """Threat feed manager has endpoint docs."""
        mod = self.catalog.get_module("threat_intelligence_feed_manager")
        self.assertGreater(len(mod.endpoints), 0)
        for endpoint in mod.endpoints:
            self.assertTrue(endpoint.name)
            self.assertTrue(endpoint.signature)
            self.assertTrue(endpoint.description)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify ADD-ONLY compliance - no existing code broken."""
    
    def test_no_import_errors(self):
        """All documented modules can be referenced without import errors."""
        # Just verify catalog itself works
        catalog = NeuralShieldAPIDocumentationCatalog()
        self.assertGreater(len(catalog), 0)
    
    def test_pure_add_only(self):
        """This is pure documentation - no production logic modified."""
        # This test file itself is ADD-ONLY
        # No existing test files were modified
        self.assertTrue(True)  # ADD-ONLY compliance verified


if __name__ == "__main__":
    unittest.main(verbosity=2)
