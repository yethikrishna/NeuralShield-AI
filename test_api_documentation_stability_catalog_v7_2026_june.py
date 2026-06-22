"""
Test Suite for NeuralShield-AI API Documentation & Stability Catalog v7
DIMENSION F: Documentation & API Stability
ADD-ONLY IMPLEMENTATION - NO EXISTING CODE MODIFIED
"""

import unittest
import json
from neural_shield.api_documentation_stability_catalog_v7_2026_june import (
    StabilityLevel,
    APIEndpoint,
    APIDocumentationCatalog,
    get_documentation_catalog,
    get_api_stability,
    is_api_deprecated,
    get_stable_apis,
)


class TestStabilityLevel(unittest.TestCase):
    """Test StabilityLevel enumeration."""
    
    def test_stability_level_values(self):
        """Test all stability levels exist."""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")
    
    def test_stability_level_string_conversion(self):
        """Test string conversion works correctly."""
        self.assertEqual(str(StabilityLevel.STABLE), "STABLE")
        self.assertEqual(str(StabilityLevel.EXPERIMENTAL), "EXPERIMENTAL")


class TestAPIEndpoint(unittest.TestCase):
    """Test APIEndpoint dataclass."""
    
    def test_api_endpoint_creation(self):
        """Test APIEndpoint creation with all fields."""
        endpoint = APIEndpoint(
            name="TestAPI.method",
            module="test_module",
            signature="method(x: int) -> str",
            docstring="Test method",
            stability=StabilityLevel.STABLE,
        )
        self.assertEqual(endpoint.name, "TestAPI.method")
        self.assertEqual(endpoint.module, "test_module")
        self.assertEqual(endpoint.stability, StabilityLevel.STABLE)
    
    def test_api_endpoint_to_dict(self):
        """Test serialization to dictionary."""
        endpoint = APIEndpoint(
            name="TestAPI.method",
            module="test_module",
            signature="method(x: int) -> str",
            docstring="Test method",
            stability=StabilityLevel.STABLE,
            tags={"test", "core"},
        )
        data = endpoint.to_dict()
        self.assertEqual(data["name"], "TestAPI.method")
        self.assertEqual(data["stability"], "STABLE")
        self.assertIn("test", data["tags"])
        self.assertIn("core", data["tags"])


class TestAPIDocumentationCatalog(unittest.TestCase):
    """Test main documentation catalog."""
    
    def setUp(self):
        """Create fresh catalog for each test."""
        self.catalog = APIDocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Test catalog initializes with standard APIs."""
        self.assertGreater(len(self.catalog._apis), 0)
        self.assertGreater(len(self.catalog._modules), 0)
    
    def test_register_api(self):
        """Test registering a new API."""
        initial_count = len(self.catalog._apis)
        self.catalog.register_api(
            name="NewAPI.test",
            module="new_module",
            signature="test() -> None",
            docstring="Test API",
            stability=StabilityLevel.STABLE,
        )
        self.assertEqual(len(self.catalog._apis), initial_count + 1)
    
    def test_get_api(self):
        """Test retrieving API documentation."""
        api = self.catalog.get_api("PromptInjectionDetector.detect")
        self.assertIsNotNone(api)
        self.assertEqual(api.name, "PromptInjectionDetector.detect")
        self.assertEqual(api.stability, StabilityLevel.STABLE)
    
    def test_get_api_not_found(self):
        """Test retrieving non-existent API."""
        api = self.catalog.get_api("NonExistent.API")
        self.assertIsNone(api)
    
    def test_search_apis(self):
        """Test API search functionality."""
        results = self.catalog.search_apis("prompt")
        self.assertGreater(len(results), 0)
        for api in results:
            self.assertTrue(
                "prompt" in api.name.lower() or
                "prompt" in api.module.lower()
            )
    
    def test_search_by_tag(self):
        """Test search by tag."""
        results = self.catalog.search_apis("experimental")
        self.assertGreater(len(results), 0)
    
    def test_get_apis_by_stability(self):
        """Test filtering APIs by stability level."""
        stable = self.catalog.get_apis_by_stability(StabilityLevel.STABLE)
        experimental = self.catalog.get_apis_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated = self.catalog.get_apis_by_stability(StabilityLevel.DEPRECATED)
        internal = self.catalog.get_apis_by_stability(StabilityLevel.INTERNAL)
        
        self.assertGreater(len(stable), 0)
        self.assertGreater(len(experimental), 0)
        self.assertGreater(len(deprecated), 0)
        self.assertGreater(len(internal), 0)
    
    def test_get_apis_by_tag(self):
        """Test getting APIs by specific tag."""
        core_apis = self.catalog.get_apis_by_tag("core")
        self.assertGreater(len(core_apis), 0)
    
    def test_get_modules(self):
        """Test getting list of documented modules."""
        modules = self.catalog.get_modules()
        self.assertIsInstance(modules, list)
        self.assertGreater(len(modules), 0)
    
    def test_export_json(self):
        """Test JSON export functionality."""
        json_output = self.catalog.export_json()
        data = json.loads(json_output)
        self.assertIn("total_apis", data)
        self.assertIn("stability_counts", data)
        self.assertIn("apis", data)
        self.assertEqual(data["total_apis"], len(self.catalog._apis))
    
    def test_export_markdown(self):
        """Test Markdown export functionality."""
        md_output = self.catalog.export_markdown()
        self.assertIn("# NeuralShield-AI API Reference", md_output)
        self.assertIn("## Stability Legend", md_output)
        self.assertIn("STABLE", md_output)
        self.assertIn("EXPERIMENTAL", md_output)
    
    def test_stability_summary(self):
        """Test stability summary generation."""
        summary = self.catalog.get_stability_summary()
        self.assertIn("STABLE", summary)
        self.assertIn("EXPERIMENTAL", summary)
        self.assertIn("DEPRECATED", summary)
        self.assertIn("INTERNAL", summary)
        self.assertGreater(summary["STABLE"], 0)


class TestGlobalConvenienceFunctions(unittest.TestCase):
    """Test global convenience functions."""
    
    def test_get_documentation_catalog_singleton(self):
        """Test singleton pattern works."""
        cat1 = get_documentation_catalog()
        cat2 = get_documentation_catalog()
        self.assertIs(cat1, cat2)
    
    def test_get_api_stability(self):
        """Test getting API stability level."""
        stability = get_api_stability("PromptInjectionDetector.detect")
        self.assertEqual(stability, "STABLE")
    
    def test_get_api_stability_not_found(self):
        """Test getting stability for non-existent API."""
        stability = get_api_stability("NonExistent.API")
        self.assertIsNone(stability)
    
    def test_is_api_deprecated(self):
        """Test deprecated API detection."""
        self.assertTrue(is_api_deprecated("LegacyDetector.check"))
        self.assertFalse(is_api_deprecated("PromptInjectionDetector.detect"))
        self.assertFalse(is_api_deprecated("NonExistent.API"))
    
    def test_get_stable_apis(self):
        """Test getting list of stable APIs."""
        stable = get_stable_apis()
        self.assertIsInstance(stable, list)
        self.assertGreater(len(stable), 0)
        self.assertIn("PromptInjectionDetector.detect", stable)


class TestAPIStabilityClassification(unittest.TestCase):
    """Verify correct stability classification for all APIs."""
    
    def setUp(self):
        self.catalog = get_documentation_catalog()
    
    def test_core_apis_are_stable(self):
        """Verify all core detection APIs are marked STABLE."""
        core_apis = [
            "PromptInjectionDetector.detect",
            "PromptSanitizer.sanitize",
            "JailbreakDetector.analyze",
            "OutputSanitizer.redact_pii",
            "RAGPoisoningDetector.scan_context",
        ]
        for api_name in core_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(
                api.stability, StabilityLevel.STABLE,
                f"API {api_name} should be STABLE"
            )
    
    def test_agent_apis_are_experimental(self):
        """Verify agent security APIs are marked EXPERIMENTAL."""
        agent_apis = [
            "AgentToolCallValidator.validate",
            "AgentMemorySafetyGuardian.scan_memory",
            "ThoughtProcessAuditor.audit",
        ]
        for api_name in agent_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(
                api.stability, StabilityLevel.EXPERIMENTAL,
                f"API {api_name} should be EXPERIMENTAL"
            )
    
    def test_multimodal_apis_are_experimental(self):
        """Verify multimodal APIs are marked EXPERIMENTAL."""
        multimodal_apis = [
            "MultimodalPromptInjectionDetector.analyze_image",
            "SteganographyDetector.scan",
        ]
        for api_name in multimodal_apis:
            api = self.catalog.get_api(api_name)
            self.assertIsNotNone(api, f"API {api_name} not found")
            self.assertEqual(
                api.stability, StabilityLevel.EXPERIMENTAL,
                f"API {api_name} should be EXPERIMENTAL"
            )
    
    def test_internal_apis_marked_internal(self):
        """Verify internal APIs are correctly marked."""
        api = self.catalog.get_api("PatternMatcher._compile_patterns")
        self.assertIsNotNone(api)
        self.assertEqual(api.stability, StabilityLevel.INTERNAL)
    
    def test_deprecated_apis_have_notice(self):
        """Verify deprecated APIs have deprecation notices."""
        api = self.catalog.get_api("LegacyDetector.check")
        self.assertIsNotNone(api)
        self.assertEqual(api.stability, StabilityLevel.DEPRECATED)
        self.assertGreater(len(api.deprecation_notice), 0)


class TestDocumentationQuality(unittest.TestCase):
    """Test quality and completeness of API documentation."""
    
    def setUp(self):
        self.catalog = get_documentation_catalog()
    
    def test_all_apis_have_docstrings(self):
        """Verify every API has a non-empty docstring."""
        for api in self.catalog._apis.values():
            self.assertGreater(
                len(api.docstring.strip()), 0,
                f"API {api.name} missing docstring"
            )
    
    def test_all_apis_have_signatures(self):
        """Verify every API has a signature."""
        for api in self.catalog._apis.values():
            self.assertGreater(
                len(api.signature.strip()), 0,
                f"API {api.name} missing signature"
            )
    
    def test_stable_apis_have_since_version(self):
        """Verify STABLE APIs have version information."""
        for api in self.catalog.get_apis_by_stability(StabilityLevel.STABLE):
            self.assertGreater(
                len(api.since_version), 0,
                f"STABLE API {api.name} missing since_version"
            )
    
    def test_deprecated_apis_have_notice(self):
        """Verify all DEPRECATED APIs have deprecation notices."""
        for api in self.catalog.get_apis_by_stability(StabilityLevel.DEPRECATED):
            self.assertGreater(
                len(api.deprecation_notice), 0,
                f"DEPRECATED API {api.name} missing notice"
            )
    
    def test_all_apis_have_tags(self):
        """Verify all APIs have at least one classification tag."""
        for api in self.catalog._apis.values():
            self.assertGreater(
                len(api.tags), 0,
                f"API {api.name} has no classification tags"
            )


class TestExportIntegrity(unittest.TestCase):
    """Test export functionality integrity."""
    
    def setUp(self):
        self.catalog = get_documentation_catalog()
    
    def test_json_export_valid_json(self):
        """Verify JSON export produces valid JSON."""
        json_str = self.catalog.export_json()
        try:
            data = json.loads(json_str)
        except json.JSONDecodeError:
            self.fail("JSON export produced invalid JSON")
        
        self.assertIsInstance(data["total_apis"], int)
        self.assertIsInstance(data["apis"], list)
        self.assertEqual(len(data["apis"]), data["total_apis"])
    
    def test_markdown_export_contains_all_sections(self):
        """Verify Markdown export contains all expected sections."""
        md = self.catalog.export_markdown()
        required_sections = [
            "NeuralShield-AI API Reference",
            "Stability Legend",
            "STABLE APIs",
            "EXPERIMENTAL APIs",
            "DEPRECATED APIs",
            "INTERNAL APIs",
        ]
        for section in required_sections:
            self.assertIn(section, md, f"Missing section: {section}")
    
    def test_markdown_contains_code_examples(self):
        """Verify Markdown export contains code examples."""
        md = self.catalog.export_markdown()
        self.assertIn("```python", md)
        self.assertIn("```", md)


if __name__ == "__main__":
    unittest.main(verbosity=2)
