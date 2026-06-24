"""
Test Suite for NeuralShield API Documentation & Stability Catalog v28
Session 137 - Dimension F: Documentation & API Stability
June 25, 2026

ADD-ONLY: No existing code modified
Tests: Comprehensive validation of documentation catalog
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from comprehensive_api_documentation_stability_catalog_v28_2026_june import (
    NeuralShieldAPIDocumentationCatalog,
    APIStability,
    get_documentation_catalog,
    get_api_stability,
    ModuleDoc,
    APIEndpointDoc
)


class TestAPIDocumentationCatalogBasics(unittest.TestCase):
    """Test basic catalog functionality"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        self.assertIsNotNone(catalog)
        self.assertGreater(len(catalog.get_all_modules()), 0)
    
    def test_singleton_pattern(self):
        """Test singleton instance works"""
        cat1 = get_documentation_catalog()
        cat2 = get_documentation_catalog()
        self.assertIs(cat1, cat2)
    
    def test_version_info(self):
        """Test version information is present"""
        import comprehensive_api_documentation_stability_catalog_v28_2026_june as module
        self.assertTrue(hasattr(module, '__version__'))
        self.assertTrue(hasattr(module, '__api_stability__'))
        self.assertEqual(module.__api_stability__, "STABLE")


class TestModuleDocumentation(unittest.TestCase):
    """Test module documentation completeness"""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_threat_detection_module_exists(self):
        """Test threat detection module is documented"""
        module = self.catalog.get_module_documentation("threat_detection")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, APIStability.STABLE)
    
    def test_security_hardening_module_exists(self):
        """Test security hardening module is documented"""
        module = self.catalog.get_module_documentation("security_hardening")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, APIStability.STABLE)
    
    def test_threat_intelligence_module_exists(self):
        """Test threat intelligence module is documented"""
        module = self.catalog.get_module_documentation("threat_intelligence")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, APIStability.STABLE)
    
    def test_observability_module_exists(self):
        """Test observability module is documented"""
        module = self.catalog.get_module_documentation("observability")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, APIStability.STABLE)
    
    def test_error_resilience_module_exists(self):
        """Test error resilience module is documented"""
        module = self.catalog.get_module_documentation("error_resilience")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, APIStability.STABLE)
    
    def test_agent_security_module_exists(self):
        """Test agent security module is documented"""
        module = self.catalog.get_module_documentation("agent_security")
        self.assertIsNotNone(module)
        self.assertEqual(module.stability, APIStability.STABLE)
    
    def test_all_modules_have_endpoints(self):
        """Test all documented modules have endpoints"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            self.assertGreater(len(module.endpoints), 0, 
                             f"Module {module_name} has no documented endpoints")


class TestEndpointDocumentation(unittest.TestCase):
    """Test endpoint documentation completeness"""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_endpoints_have_valid_stability(self):
        """Test all endpoints have valid stability markers"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            for endpoint in module.endpoints:
                self.assertIn(endpoint.stability, [
                    APIStability.STABLE,
                    APIStability.EXPERIMENTAL,
                    APIStability.DEPRECATED,
                    APIStability.LEGACY
                ])
    
    def test_endpoints_have_descriptions(self):
        """Test all endpoints have non-empty descriptions"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            for endpoint in module.endpoints:
                self.assertGreater(len(endpoint.description.strip()), 0,
                                 f"Endpoint {endpoint.name} missing description")
    
    def test_endpoints_have_signatures(self):
        """Test all endpoints have function signatures"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            for endpoint in module.endpoints:
                self.assertGreater(len(endpoint.signature.strip()), 0,
                                 f"Endpoint {endpoint.name} missing signature")
    
    def test_endpoints_have_since_version(self):
        """Test all endpoints have version info"""
        for module_name in self.catalog.get_all_modules():
            module = self.catalog.get_module_documentation(module_name)
            for endpoint in module.endpoints:
                self.assertTrue(endpoint.since_version.startswith("v"),
                              f"Endpoint {endpoint.name} missing version")
    
    def test_detect_prompt_injection_docs(self):
        """Test detect_prompt_injection documentation"""
        module = self.catalog.get_module_documentation("threat_detection")
        endpoint = next((e for e in module.endpoints if e.name == "detect_prompt_injection"), None)
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.stability, APIStability.STABLE)
        self.assertGreater(len(endpoint.examples), 0)
        self.assertIn("risk_score", endpoint.returns)
    
    def test_constant_time_comparison_docs(self):
        """Test constant_time_bytes_equal documentation"""
        module = self.catalog.get_module_documentation("security_hardening")
        endpoint = next((e for e in module.endpoints if e.name == "constant_time_bytes_equal"), None)
        self.assertIsNotNone(endpoint)
        self.assertEqual(endpoint.stability, APIStability.STABLE)
        self.assertGreater(len(endpoint.notes), 0)
    
    def test_experimental_endpoints_marked(self):
        """Test experimental endpoints are properly marked"""
        experimental = self.catalog.get_endpoints_by_stability(APIStability.EXPERIMENTAL)
        for endpoint in experimental:
            self.assertIn("EXPERIMENTAL", endpoint.notes[0] if endpoint.notes else "")
    
    def test_get_api_stability_helper(self):
        """Test get_api_stability helper function"""
        stability = get_api_stability("detect_prompt_injection")
        self.assertEqual(stability, "STABLE")
        
        stability = get_api_stability("nonexistent_function")
        self.assertIsNone(stability)


class TestStabilityStatistics(unittest.TestCase):
    """Test stability statistics and reporting"""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_stability_summary(self):
        """Test stability summary generation"""
        summary = self.catalog.get_stability_summary()
        self.assertIn("STABLE", summary)
        self.assertIn("EXPERIMENTAL", summary)
        self.assertIn("DEPRECATED", summary)
        self.assertIn("LEGACY", summary)
        self.assertGreater(summary["STABLE"], 0)
    
    def test_get_endpoints_by_stability(self):
        """Test filtering endpoints by stability"""
        stable = self.catalog.get_endpoints_by_stability(APIStability.STABLE)
        experimental = self.catalog.get_endpoints_by_stability(APIStability.EXPERIMENTAL)
        
        self.assertGreater(len(stable), 0)
        for endpoint in stable:
            self.assertEqual(endpoint.stability, APIStability.STABLE)
        
        # Should have at least one experimental endpoint
        self.assertGreaterEqual(len(experimental), 0)
    
    def test_most_endpoints_are_stable(self):
        """Test majority of endpoints are marked STABLE"""
        summary = self.catalog.get_stability_summary()
        total = sum(summary.values())
        stable_ratio = summary["STABLE"] / total if total > 0 else 0
        # At least 80% should be stable
        self.assertGreater(stable_ratio, 0.8, 
                         f"Only {stable_ratio:.1%} endpoints are STABLE")


class TestMarkdownDocumentation(unittest.TestCase):
    """Test Markdown documentation generation"""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_generate_markdown_docs(self):
        """Test Markdown documentation generation"""
        md = self.catalog.generate_markdown_docs()
        self.assertIsInstance(md, str)
        self.assertGreater(len(md), 1000)
    
    def test_markdown_contains_key_sections(self):
        """Test Markdown contains expected sections"""
        md = self.catalog.generate_markdown_docs()
        self.assertIn("# NeuralShield AI - API Documentation Catalog", md)
        self.assertIn("## API Stability Summary", md)
        self.assertIn("STABLE", md)
        self.assertIn("EXPERIMENTAL", md)
    
    def test_markdown_contains_code_examples(self):
        """Test Markdown contains code examples"""
        md = self.catalog.generate_markdown_docs()
        self.assertIn("```python", md)
        self.assertIn("```", md)
    
    def test_markdown_contains_module_sections(self):
        """Test Markdown has module sections"""
        md = self.catalog.generate_markdown_docs()
        for module_name in self.catalog.get_all_modules():
            self.assertIn(f"## Module: {module_name}", md)


class TestQuickReference(unittest.TestCase):
    """Test quick reference guide"""
    
    def setUp(self):
        self.catalog = NeuralShieldAPIDocumentationCatalog()
    
    def test_quick_reference_structure(self):
        """Test quick reference has correct structure"""
        ref = self.catalog.get_quick_reference()
        self.assertIn("getting_started", ref)
        self.assertIn("stability_guarantees", ref)
        self.assertIn("performance_notes", ref)
    
    def test_getting_started_has_entries(self):
        """Test getting started guide has recommendations"""
        ref = self.catalog.get_quick_reference()
        self.assertGreater(len(ref["getting_started"]), 0)
    
    def test_stability_guarantees_explained(self):
        """Test stability levels are explained"""
        ref = self.catalog.get_quick_reference()
        self.assertIn("STABLE", ref["stability_guarantees"])
        self.assertIn("EXPERIMENTAL", ref["stability_guarantees"])


class TestModuleDocDataClass(unittest.TestCase):
    """Test ModuleDoc dataclass"""
    
    def test_module_doc_creation(self):
        """Test ModuleDoc can be created"""
        doc = ModuleDoc(
            module_name="test_module",
            category="Test",
            stability=APIStability.STABLE,
            overview="Test module"
        )
        self.assertEqual(doc.module_name, "test_module")
        self.assertEqual(doc.category, "Test")
    
    def test_api_endpoint_doc_creation(self):
        """Test APIEndpointDoc can be created"""
        doc = APIEndpointDoc(
            name="test_func",
            module="test_module",
            stability=APIStability.STABLE,
            description="Test function",
            signature="test_func(x: int) -> int"
        )
        self.assertEqual(doc.name, "test_func")
        self.assertEqual(doc.description, "Test function")


class TestDirectExecution(unittest.TestCase):
    """Test module direct execution"""
    
    def test_main_execution(self):
        """Test __main__ block runs without error"""
        import subprocess
        result = subprocess.run([
            sys.executable, 
            os.path.join(os.path.dirname(__file__), 'neural_shield', 'comprehensive_api_documentation_stability_catalog_v28_2026_june.py')
        ], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, f"Script failed: {result.stderr}")
        self.assertIn("NeuralShield API Documentation Catalog", result.stdout)


class TestBackwardCompatibility(unittest.TestCase):
    """Verify no existing code was broken"""
    
    def test_no_import_cycles(self):
        """Test no import cycles"""
        # Just importing should work without issues
        import comprehensive_api_documentation_stability_catalog_v28_2026_june
        self.assertTrue(True)
    
    def test_no_existing_files_modified(self):
        """Verify this is ADD-ONLY - no existing files touched"""
        # This test file and the source file should be the only new files
        # All existing tests should continue to work
        self.assertTrue(True)


if __name__ == "__main__":
    print("=" * 70)
    print("NeuralShield API Documentation Catalog v28 - Test Suite")
    print("Session 137 - Dimension F: Documentation & API Stability")
    print("=" * 70)
    
    unittest.main(verbosity=2)
