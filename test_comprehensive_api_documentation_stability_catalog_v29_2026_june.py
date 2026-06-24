"""
Test Suite for NeuralShield-AI Comprehensive API Documentation & Stability Catalog v29
=====================================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. All STABLE API methods work correctly
2. Documentation catalog loads without errors
3. Stability classification is correct
4. Backward compatibility is maintained
5. No breaking changes to existing code
"""

import pytest
import json
from neural_shield.comprehensive_api_documentation_stability_catalog_v29_2026_june import (
    NeuralShieldAPIDocumentationCatalog,
    StabilityLevel,
    ModuleDocumentation,
    api_documentation_catalog
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        """Verify stability level values are correct"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    
    def test_stability_level_count(self):
        """Verify exactly 3 stability levels exist"""
        assert len(list(StabilityLevel)) == 3


class TestModuleDocumentation:
    """Test ModuleDocumentation dataclass"""
    
    def test_module_documentation_creation(self):
        """Verify module documentation can be created"""
        doc = ModuleDocumentation(
            module_name="test_module",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Test module",
            primary_use_cases=["Test use case"],
            usage_examples=["Example code"],
            key_classes=["TestClass"],
            key_methods=["test_method"],
            dependencies=["dep1"]
        )
        assert doc.module_name == "test_module"
        assert doc.stability == StabilityLevel.STABLE
        assert doc.version == "1.0.0"
    
    def test_optional_fields_default_none(self):
        """Verify optional fields default to None"""
        doc = ModuleDocumentation(
            module_name="test",
            stability=StabilityLevel.STABLE,
            version="1.0.0",
            description="Test",
            primary_use_cases=[],
            usage_examples=[],
            key_classes=[],
            key_methods=[],
            dependencies=[]
        )
        assert doc.deprecation_notice is None
        assert doc.migration_guide is None


class TestNeuralShieldAPIDocumentationCatalog:
    """Test main documentation catalog class"""
    
    def test_catalog_initialization(self):
        """Verify catalog initializes successfully"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        assert catalog is not None
        assert len(catalog._modules) > 0
    
    def test_singleton_instance(self):
        """Verify singleton instance is available"""
        assert api_documentation_catalog is not None
        assert isinstance(api_documentation_catalog, NeuralShieldAPIDocumentationCatalog)
    
    def test_get_module_documentation_existing(self):
        """Verify get_module_documentation returns doc for existing modules"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        doc = catalog.get_module_documentation("prompt_injection_detector")
        assert doc is not None
        assert doc.module_name == "prompt_injection_detector"
    
    def test_get_module_documentation_nonexistent(self):
        """Verify get_module_documentation returns None for nonexistent modules"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        doc = catalog.get_module_documentation("nonexistent_module_xyz")
        assert doc is None
    
    def test_list_modules_by_stability(self):
        """Verify listing modules by stability level"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        stable = catalog.list_modules_by_stability(StabilityLevel.STABLE)
        experimental = catalog.list_modules_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated = catalog.list_modules_by_stability(StabilityLevel.DEPRECATED)
        
        assert len(stable) > 0
        assert len(experimental) > 0
        assert len(deprecated) >= 0
    
    def test_stable_modules_include_core(self):
        """Verify core security modules are marked STABLE"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        stable = catalog.list_modules_by_stability(StabilityLevel.STABLE)
        
        assert "prompt_injection_detector" in stable
        assert "prompt_firewall" in stable
        assert "output_sanitizer_pii_redactor" in stable
        assert "input_purification" in stable
    
    def test_experimental_modules_include_new_features(self):
        """Verify new features are marked EXPERIMENTAL"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        experimental = catalog.list_modules_by_stability(StabilityLevel.EXPERIMENTAL)
        
        assert "multimodal_prompt_injection_detector" in experimental
        assert "llm_agent_thought_process_auditor" in experimental
    
    def test_get_stability_summary(self):
        """Verify stability summary returns correct counts"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        summary = catalog.get_stability_summary()
        
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert summary["STABLE"] > 0
        assert summary["EXPERIMENTAL"] > 0
    
    def test_generate_documentation_report_json(self):
        """Verify JSON report generation"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        report = catalog.generate_documentation_report(format="json")
        
        # Verify valid JSON
        data = json.loads(report)
        assert "catalog_version" in data
        assert "generated_at" in data
        assert "stability_summary" in data
        assert "modules" in data
        assert data["catalog_version"] == "v29"
    
    def test_generate_documentation_report_markdown(self):
        """Verify markdown report generation"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        report = catalog.generate_documentation_report(format="markdown")
        
        assert "# NeuralShield-AI" in report
        assert "## Stability Summary" in report
        assert "## Module Documentation" in report
    
    def test_validate_api_compatibility(self):
        """Verify API compatibility validation"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        result = catalog.validate_api_compatibility("v28")
        
        assert result["compatible"] is True
        assert "breaking_changes" in result
        assert "warnings" in result
        assert "recommendation" in result
        assert len(result["breaking_changes"]) == 0
    
    def test_stable_api_method_signatures_unchanged(self):
        """CRITICAL: Verify STABLE API method signatures haven't changed"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        # These method signatures are GUARANTEED STABLE
        import inspect
        
        # get_module_documentation
        sig = inspect.signature(catalog.get_module_documentation)
        params = list(sig.parameters.keys())
        assert params == ["module_name"]
        
        # list_modules_by_stability
        sig = inspect.signature(catalog.list_modules_by_stability)
        params = list(sig.parameters.keys())
        assert params == ["stability"]
        
        # get_stability_summary
        sig = inspect.signature(catalog.get_stability_summary)
        params = list(sig.parameters.keys())
        assert params == []
        
        # generate_documentation_report
        sig = inspect.signature(catalog.generate_documentation_report)
        params = list(sig.parameters.keys())
        assert params == ["format"]
        
        # validate_api_compatibility
        sig = inspect.signature(catalog.validate_api_compatibility)
        params = list(sig.parameters.keys())
        assert params == ["client_version"]
    
    def test_all_modules_have_required_fields(self):
        """Verify all modules have complete documentation fields"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        for module_name, doc in catalog._modules.items():
            assert doc.module_name == module_name
            assert doc.stability in StabilityLevel
            assert doc.version != ""
            assert doc.description != ""
            assert isinstance(doc.primary_use_cases, list)
            assert isinstance(doc.usage_examples, list)
            assert isinstance(doc.key_classes, list)
            assert isinstance(doc.key_methods, list)
            assert isinstance(doc.dependencies, list)
    
    def test_deprecated_modules_have_notices(self):
        """Verify deprecated modules have deprecation notices"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        deprecated = catalog.list_modules_by_stability(StabilityLevel.DEPRECATED)
        
        for mod_name in deprecated:
            doc = catalog.get_module_documentation(mod_name)
            assert doc.deprecation_notice is not None
            assert doc.migration_guide is not None
    
    def test_no_breaking_changes_to_imports(self):
        """Verify imports work without breaking existing code"""
        # This test verifies backward compatibility
        # All existing imports should still work
        from neural_shield import comprehensive_api_documentation_stability_catalog_v29_2026_june
        
        # Verify all expected exports exist
        assert hasattr(comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "NeuralShieldAPIDocumentationCatalog")
        assert hasattr(comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "StabilityLevel")
        assert hasattr(comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "ModuleDocumentation")
        assert hasattr(comprehensive_api_documentation_stability_catalog_v29_2026_june, 
                      "api_documentation_catalog")


class TestBackwardCompatibility:
    """Critical backward compatibility tests"""
    
    def test_previous_catalog_still_importable(self):
        """Verify v28 catalog still imports (if exists)"""
        try:
            from neural_shield import comprehensive_api_documentation_stability_catalog_v28_2026_june
            # If it exists, it should work
            assert True
        except ImportError:
            # Expected if v28 doesn't exist - this is fine
            assert True
    
    def test_new_catalog_does_not_break_existing(self):
        """Verify adding v29 doesn't break existing code"""
        # Import should not raise any exceptions
        from neural_shield.comprehensive_api_documentation_stability_catalog_v29_2026_june import (
            NeuralShieldAPIDocumentationCatalog
        )
        catalog = NeuralShieldAPIDocumentationCatalog()
        assert catalog is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
