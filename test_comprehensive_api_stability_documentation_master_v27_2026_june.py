"""
Test Suite for NeuralShield-AI API Stability Documentation v27
SESSION: 127
DIMENSION: F - Documentation & API Stability
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from comprehensive_api_stability_documentation_master_v27_2026_june import (
    StabilityLevel,
    APIEndpoint,
    NeuralShieldAPIStabilityCatalog,
    get_stability_catalog,
    api_stability
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"
    
    def test_stability_level_count(self):
        assert len(list(StabilityLevel)) == 4


class TestAPIEndpoint:
    """Test APIEndpoint dataclass"""
    
    def test_api_endpoint_creation(self):
        endpoint = APIEndpoint(
            name="TestAPI",
            module="test_module",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test description"
        )
        assert endpoint.name == "TestAPI"
        assert endpoint.stability == StabilityLevel.STABLE
        assert endpoint.version_introduced == "1.0.0"
    
    def test_api_endpoint_defaults(self):
        endpoint = APIEndpoint(
            name="TestAPI",
            module="test_module",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0"
        )
        assert endpoint.version_deprecated is None
        assert endpoint.deprecation_scheduled is None
        assert endpoint.description == ""
        assert isinstance(endpoint.parameters, dict)
        assert isinstance(endpoint.exceptions, list)
        assert isinstance(endpoint.compatibility_notes, list)


class TestNeuralShieldAPIStabilityCatalog:
    """Test main API stability catalog"""
    
    def setup_method(self):
        self.catalog = NeuralShieldAPIStabilityCatalog()
    
    def test_catalog_initialization(self):
        assert self.catalog.catalog_version == "27.0.0"
        assert self.catalog.generated_at is not None
    
    def test_catalog_has_apis(self):
        apis = self.catalog.list_apis()
        assert len(apis) > 0
        print(f"Total APIs documented: {len(apis)}")
    
    def test_get_api_exists(self):
        api = self.catalog.get_api("prompt_injection_detector")
        assert api is not None
        assert api.name == "PromptInjectionDetector"
        assert api.stability == StabilityLevel.STABLE
    
    def test_get_api_not_exists(self):
        api = self.catalog.get_api("nonexistent_api_xyz")
        assert api is None
    
    def test_list_apis_filter_stable(self):
        stable_apis = self.catalog.list_apis(StabilityLevel.STABLE)
        assert len(stable_apis) > 0
        for api in stable_apis:
            assert api.stability == StabilityLevel.STABLE
    
    def test_list_apis_filter_experimental(self):
        experimental_apis = self.catalog.list_apis(StabilityLevel.EXPERIMENTAL)
        for api in experimental_apis:
            assert api.stability == StabilityLevel.EXPERIMENTAL
    
    def test_list_apis_filter_deprecated(self):
        deprecated_apis = self.catalog.list_apis(StabilityLevel.DEPRECATED)
        for api in deprecated_apis:
            assert api.stability == StabilityLevel.DEPRECATED
    
    def test_stability_summary(self):
        summary = self.catalog.get_stability_summary()
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert "LEGACY" in summary
        assert summary["STABLE"] > 0
    
    def test_generate_markdown_docs(self):
        md = self.catalog.generate_markdown_docs()
        assert md is not None
        assert len(md) > 0
        assert "# NeuralShield-AI API Stability Documentation" in md
        assert "STABLE" in md
    
    def test_core_detection_apis_present(self):
        assert self.catalog.get_api("prompt_injection_detector") is not None
        assert self.catalog.get_api("jailbreak_detector") is not None
        assert self.catalog.get_api("adversarial_anomaly_detector") is not None
    
    def test_output_sanitization_apis_present(self):
        assert self.catalog.get_api("output_sanitizer") is not None
        assert self.catalog.get_api("watermark_provenance") is not None
    
    def test_security_hardening_apis_present(self):
        assert self.catalog.get_api("secure_memory") is not None
        assert self.catalog.get_api("constant_time_compare") is not None
        assert self.catalog.get_api("rate_limiter") is not None
    
    def test_deprecated_apis_marked(self):
        legacy = self.catalog.get_api("legacy_detector")
        assert legacy is not None
        assert legacy.stability == StabilityLevel.DEPRECATED
        assert legacy.version_deprecated is not None
        assert legacy.deprecation_scheduled is not None
        assert legacy.migration_guide != ""
    
    def test_api_metadata_complete(self):
        for api in self.catalog.list_apis():
            assert api.name != ""
            assert api.module != ""
            assert api.version_introduced != ""
            assert api.description != ""
    
    def test_deprecated_apis_have_migration(self):
        for api in self.catalog.list_apis(StabilityLevel.DEPRECATED):
            assert api.migration_guide != ""


class TestSingleton:
    """Test singleton catalog access"""
    
    def test_get_stability_catalog_singleton(self):
        cat1 = get_stability_catalog()
        cat2 = get_stability_catalog()
        assert cat1 is cat2
    
    def test_singleton_returns_valid_catalog(self):
        catalog = get_stability_catalog()
        assert isinstance(catalog, NeuralShieldAPIStabilityCatalog)
        assert len(catalog.list_apis()) > 0


class TestStabilityDecorator:
    """Test @api_stability decorator"""
    
    def test_decorator_marks_function(self):
        @api_stability(StabilityLevel.STABLE, since="2.0.0")
        def test_func():
            return "test"
        
        assert hasattr(test_func, "_api_stability")
        assert test_func._api_stability["level"] == StabilityLevel.STABLE
        assert test_func._api_stability["since"] == "2.0.0"
        assert test_func._api_stability["documented"] is True
    
    def test_decorator_preserves_function(self):
        @api_stability(StabilityLevel.STABLE, since="2.0.0")
        def test_func(x):
            return x * 2
        
        assert test_func(5) == 10  # Function still works


class TestDocumentationQuality:
    """Test documentation quality standards"""
    
    def setup_method(self):
        self.catalog = NeuralShieldAPIStabilityCatalog()
    
    def test_no_empty_descriptions(self):
        for api in self.catalog.list_apis():
            assert len(api.description.strip()) > 0, \
                f"API {api.name} has empty description"
    
    def test_version_format_valid(self):
        for api in self.catalog.list_apis():
            parts = api.version_introduced.split(".")
            assert len(parts) >= 2, f"API {api.name} invalid version format"
    
    def test_module_names_are_valid(self):
        for api in self.catalog.list_apis():
            assert " " not in api.module, f"API {api.name} has invalid module name"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
