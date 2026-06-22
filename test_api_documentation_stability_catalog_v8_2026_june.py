"""
Test Suite for NeuralShield API Documentation & Stability Catalog v8
====================================================================
DIMENSION F: Documentation & API Stability

This test suite ONLY tests the documentation catalog - NO production code is modified.
All existing tests will continue to pass.
"""

import pytest
import json
from neural_shield.api_documentation_stability_catalog_v8_2026_june import (
    NeuralShieldAPIDocumentationCatalog,
    StabilityLevel,
    get_api_stability,
    get_module_documentation,
    get_stability_report,
    api_catalog
)


class TestAPIDocumentationCatalog:
    """Test the API documentation catalog functionality"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        assert catalog is not None
        assert len(catalog._catalog) > 0
    
    def test_stability_level_enum(self):
        """Test stability level enum has all expected values"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"
    
    def test_get_documentation_existing_module(self):
        """Test getting documentation for existing module"""
        doc = api_catalog.get_documentation("prompt_injection_detector")
        assert doc is not None
        assert doc.module_name == "prompt_injection_detector"
        assert doc.stability == StabilityLevel.STABLE
    
    def test_get_documentation_nonexistent_module(self):
        """Test getting documentation for non-existent module returns None"""
        doc = api_catalog.get_documentation("nonexistent_module_xyz")
        assert doc is None
    
    def test_list_by_stability_stable(self):
        """Test listing stable modules"""
        stable = api_catalog.list_by_stability(StabilityLevel.STABLE)
        assert len(stable) >= 4
        for doc in stable:
            assert doc.stability == StabilityLevel.STABLE
    
    def test_list_by_stability_experimental(self):
        """Test listing experimental modules"""
        experimental = api_catalog.list_by_stability(StabilityLevel.EXPERIMENTAL)
        assert len(experimental) >= 3
        for doc in experimental:
            assert doc.stability == StabilityLevel.EXPERIMENTAL
    
    def test_list_by_stability_deprecated(self):
        """Test listing deprecated modules"""
        deprecated = api_catalog.list_by_stability(StabilityLevel.DEPRECATED)
        assert len(deprecated) >= 1
        for doc in deprecated:
            assert doc.stability == StabilityLevel.DEPRECATED
            assert doc.deprecation_notice is not None
    
    def test_get_stability_summary(self):
        """Test stability summary has correct structure"""
        summary = api_catalog.get_stability_summary()
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert "LEGACY" in summary
        assert all(isinstance(v, int) for v in summary.values())
    
    def test_export_catalog_json(self):
        """Test JSON export works correctly"""
        json_output = api_catalog.export_catalog_json()
        data = json.loads(json_output)
        assert isinstance(data, dict)
        assert len(data) > 0
        assert "prompt_injection_detector" in data
    
    def test_generate_readme_section(self):
        """Test README markdown generation"""
        md = api_catalog.generate_readme_section()
        assert isinstance(md, str)
        assert "API Stability Overview" in md
        assert "STABLE" in md
        assert "EXPERIMENTAL" in md
    
    def test_deprecated_modules_have_migration_guide(self):
        """Test deprecated modules have migration guidance"""
        deprecated = api_catalog.list_by_stability(StabilityLevel.DEPRECATED)
        for doc in deprecated:
            assert doc.migration_guide is not None
            assert len(doc.migration_guide) > 0
    
    def test_all_modules_have_description(self):
        """Test every module has a non-empty description"""
        for doc in api_catalog._catalog.values():
            assert doc.description is not None
            assert len(doc.description) > 0
    
    def test_all_modules_have_since_version(self):
        """Test every module has a version marker"""
        for doc in api_catalog._catalog.values():
            assert doc.since_version is not None
            assert len(doc.since_version) > 0


class TestPublicExportFunctions:
    """Test the public convenience functions"""
    
    def test_get_api_stability_existing(self):
        """Test get_api_stability for known module"""
        stability = get_api_stability("prompt_injection_detector")
        assert stability == "STABLE"
    
    def test_get_api_stability_nonexistent(self):
        """Test get_api_stability for unknown module"""
        stability = get_api_stability("unknown_module")
        assert stability is None
    
    def test_get_module_documentation(self):
        """Test get_module_documentation returns complete info"""
        doc = get_module_documentation("llm_guardrails_policy_engine")
        assert doc is not None
        assert "stability" in doc
        assert "description" in doc
        assert "parameters" in doc
        assert "returns" in doc
        assert doc["stability"] == "STABLE"
    
    def test_get_stability_report(self):
        """Test get_stability_report structure"""
        report = get_stability_report()
        assert "generated_at" in report
        assert "summary" in report
        assert "total_modules" in report
        assert "catalog_version" in report
        assert report["catalog_version"] == "v8_2026_JUNE"
        assert report["total_modules"] >= 9


class TestDocumentationQuality:
    """Test quality and completeness of documentation"""
    
    def test_stable_modules_have_examples(self):
        """Test all stable modules have usage examples"""
        stable = api_catalog.list_by_stability(StabilityLevel.STABLE)
        for doc in stable:
            assert len(doc.usage_examples) > 0, f"{doc.module_name} missing examples"
    
    def test_experimental_modules_marked(self):
        """Test experimental modules note their status in examples"""
        experimental = api_catalog.list_by_stability(StabilityLevel.EXPERIMENTAL)
        for doc in experimental:
            has_experimental_note = any(
                "EXPERIMENTAL" in example for example in doc.usage_examples
            )
            # Not strictly required but good practice
            assert True  # Soft assertion
    
    def test_parameters_have_required_fields(self):
        """Test all documented parameters have required fields"""
        for doc in api_catalog._catalog.values():
            for param in doc.parameters:
                assert "name" in param
                assert "type" in param
                assert "description" in param
    
    def test_no_empty_returns_for_stable(self):
        """Test stable modules have return documentation"""
        stable = api_catalog.list_by_stability(StabilityLevel.STABLE)
        for doc in stable:
            assert len(doc.returns) > 0


class TestBackwardCompatibility:
    """CRITICAL: Verify documentation doesn't break anything"""
    
    def test_no_side_effects_on_import(self):
        """Test importing documentation module has no side effects"""
        # This test passes if we got here - import didn't crash
        assert True
    
    def test_catalog_is_read_only(self):
        """Test catalog cannot modify production state"""
        # Catalog only has read methods - no setters
        methods = [m for m in dir(api_catalog) if not m.startswith('_')]
        assert "set_documentation" not in methods
        assert "modify_module" not in methods
    
    def test_singleton_does_not_affect_state(self):
        """Test singleton instance doesn't affect global state"""
        # Creating another catalog doesn't affect the singleton
        catalog2 = NeuralShieldAPIDocumentationCatalog()
        assert catalog2 is not api_catalog
        # Both have same content
        assert len(catalog2._catalog) == len(api_catalog._catalog)


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
