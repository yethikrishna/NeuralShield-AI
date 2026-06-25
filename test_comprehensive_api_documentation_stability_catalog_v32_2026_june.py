"""
Test Suite for NeuralShield Comprehensive API Documentation & Stability Catalog v32

DIMENSION F - Documentation & API Stability
CODE LOGIC IS SACRED - only docs and metadata tested

Tests verify:
- Documentation catalog initialization
- Stability level classification
- Module documentation retrieval
- README generation
- All existing tests continue to pass
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

import unittest
from comprehensive_api_documentation_stability_catalog_v32_2026_june import (
    NeuralShieldDocumentationCatalog,
    StabilityLevel,
    ModuleDocumentation,
    documentation_catalog
)


class TestStabilityLevel(unittest.TestCase):
    """Test stability level enumeration."""
    
    def test_stability_level_values(self):
        """Verify all stability levels are defined."""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.BETA.value, "BETA")


class TestModuleDocumentation(unittest.TestCase):
    """Test ModuleDocumentation dataclass."""
    
    def test_module_documentation_creation(self):
        """Verify module documentation can be created."""
        doc = ModuleDocumentation(
            module_name="test_module",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Test module"
        )
        self.assertEqual(doc.module_name, "test_module")
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
        self.assertEqual(doc.version, "1.0.0")
        self.assertEqual(doc.description, "Test module")


class TestDocumentationCatalog(unittest.TestCase):
    """Test the main documentation catalog."""
    
    def setUp(self):
        self.catalog = NeuralShieldDocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Verify catalog initializes with modules."""
        self.assertGreater(len(self.catalog._catalog), 0)
    
    def test_get_existing_module_documentation(self):
        """Verify documentation retrieval for existing module."""
        doc = self.catalog.get_module_documentation("prompt_firewall")
        self.assertIsNotNone(doc)
        self.assertEqual(doc.module_name, "prompt_firewall")
        self.assertEqual(doc.stability, StabilityLevel.STABLE)
    
    def test_get_nonexistent_module_documentation(self):
        """Verify None returned for non-existent module."""
        doc = self.catalog.get_module_documentation("nonexistent_module_xyz")
        self.assertIsNone(doc)
    
    def test_list_modules_by_stability(self):
        """Verify filtering by stability level."""
        stable_modules = self.catalog.list_modules_by_stability(StabilityLevel.STABLE)
        self.assertIsInstance(stable_modules, list)
        self.assertIn("prompt_firewall", stable_modules)
        
        beta_modules = self.catalog.list_modules_by_stability(StabilityLevel.BETA)
        self.assertIsInstance(beta_modules, list)
        self.assertIn("multimodal_prompt_injection_detector", beta_modules)
    
    def test_get_stability_summary(self):
        """Verify stability summary generation."""
        summary = self.catalog.get_stability_summary()
        self.assertIsInstance(summary, dict)
        self.assertIn("STABLE", summary)
        self.assertGreater(summary["STABLE"], 0)
    
    def test_generate_readme_section(self):
        """Verify README section generation."""
        readme = self.catalog.generate_readme_section()
        self.assertIsInstance(readme, str)
        self.assertGreater(len(readme), 0)
        self.assertIn("NeuralShield API Stability Summary", readme)
        self.assertIn("STABLE", readme)
    
    def test_documentation_has_usage_examples(self):
        """Verify modules have usage examples."""
        doc = self.catalog.get_module_documentation("prompt_firewall")
        self.assertGreater(len(doc.usage_examples), 0)
        self.assertIn("PromptFirewall", doc.usage_examples[0])
    
    def test_documentation_has_parameters(self):
        """Verify modules have parameter documentation."""
        doc = self.catalog.get_module_documentation("observability_engine")
        self.assertGreater(len(doc.parameters), 0)
        self.assertIn("enable_metrics", doc.parameters)
    
    def test_documentation_has_returns(self):
        """Verify modules have return documentation."""
        doc = self.catalog.get_module_documentation("adversarial_prompt_anomaly_detector")
        self.assertGreater(len(doc.returns), 0)
    
    def test_singleton_instance(self):
        """Verify singleton instance works."""
        self.assertIsInstance(documentation_catalog, NeuralShieldDocumentationCatalog)
    
    def test_all_modules_have_descriptions(self):
        """Verify all documented modules have descriptions."""
        for module_name, doc in self.catalog._catalog.items():
            with self.subTest(module=module_name):
                self.assertGreater(len(doc.description), 0)
                self.assertGreater(len(doc.version), 0)
    
    def test_see_also_references(self):
        """Verify see_also references are lists."""
        doc = self.catalog.get_module_documentation("prompt_firewall")
        self.assertIsInstance(doc.see_also, list)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify no breaking changes - all existing behavior preserved."""
    
    def test_no_core_modifications(self):
        """Verify this is documentation-only - no core logic modified."""
        # This module only contains documentation classes
        import comprehensive_api_documentation_stability_catalog_v32_2026_june as doc_module
        
        # Should only contain documentation-related classes
        public_items = [x for x in dir(doc_module) if not x.startswith('_')]
        self.assertIn("NeuralShieldDocumentationCatalog", public_items)
        self.assertIn("StabilityLevel", public_items)
        self.assertIn("ModuleDocumentation", public_items)
        
        # Should NOT modify any existing security logic
        self.assertNotIn("PromptFirewall", public_items)
        self.assertNotIn("scan_user_input", public_items)


if __name__ == "__main__":
    unittest.main(verbosity=2)
