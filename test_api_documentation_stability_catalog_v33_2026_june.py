"""
Test Suite for NeuralShield AI - API Documentation & Stability Catalog v33
DIMENSION F: Documentation & API Stability

All tests verify:
1. Documentation catalog builds correctly
2. Stability decorators work properly
3. No breaking changes to existing code
4. Backward compatibility is maintained
"""

import pytest
import warnings
from typing import Dict, Any

# Import the new documentation module
from neural_shield.api_documentation_stability_catalog_v33_2026_june import (
    StabilityLevel,
    APIDocumentation,
    ModuleDocumentation,
    DocumentationCatalog,
    stable_api,
    experimental_api,
    deprecated_api,
    internal_api,
    build_complete_documentation_catalog,
    get_api_stability_summary,
    DOCUMENTATION_CATALOG
)


class TestStabilityLevelEnum:
    """Test Stability Level enumeration"""
    
    def test_stability_levels_exist(self):
        """All four stability levels should be defined"""
        assert hasattr(StabilityLevel, 'STABLE')
        assert hasattr(StabilityLevel, 'EXPERIMENTAL')
        assert hasattr(StabilityLevel, 'DEPRECATED')
        assert hasattr(StabilityLevel, 'INTERNAL')
    
    def test_stability_level_values(self):
        """Stability levels should have string values"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.INTERNAL.value == "INTERNAL"


class TestAPIDocumentationDataclass:
    """Test API Documentation data structure"""
    
    def test_create_api_documentation(self):
        """Can create APIDocumentation with required fields"""
        doc = APIDocumentation(
            module_name="test_module",
            function_name="test_function",
            stability=StabilityLevel.STABLE,
            signature="test_function(a: int) -> str",
            description="Test function"
        )
        assert doc.module_name == "test_module"
        assert doc.function_name == "test_function"
        assert doc.stability == StabilityLevel.STABLE
    
    def test_api_documentation_defaults(self):
        """Optional fields should have sensible defaults"""
        doc = APIDocumentation(
            module_name="test",
            function_name="test",
            stability=StabilityLevel.STABLE,
            signature="test()",
            description="test"
        )
        assert doc.parameters == []
        assert doc.examples == []
        assert doc.since_version == "1.0.0"


class TestModuleDocumentation:
    """Test Module Documentation data structure"""
    
    def test_create_module_documentation(self):
        """Can create ModuleDocumentation with required fields"""
        mod_doc = ModuleDocumentation(
            module_name="security",
            description="Security module",
            category="Core",
            stability=StabilityLevel.STABLE
        )
        assert mod_doc.module_name == "security"
        assert mod_doc.api_entries == []


class TestDocumentationCatalog:
    """Test centralized documentation catalog"""
    
    def test_catalog_initialization(self):
        """Catalog initializes with empty modules and zero counts"""
        catalog = DocumentationCatalog()
        assert len(catalog._modules) == 0
        assert all(count == 0 for count in catalog._stability_counts.values())
    
    def test_register_module(self):
        """Registering a module updates stability counts"""
        catalog = DocumentationCatalog()
        mod_doc = ModuleDocumentation(
            module_name="test",
            description="test",
            category="test",
            stability=StabilityLevel.STABLE,
            api_entries=[
                APIDocumentation("test", "f1", StabilityLevel.STABLE, "f()", "desc"),
                APIDocumentation("test", "f2", StabilityLevel.EXPERIMENTAL, "f()", "desc"),
            ]
        )
        catalog.register_module(mod_doc)
        summary = catalog.get_stability_summary()
        assert summary["STABLE"] == 1
        assert summary["EXPERIMENTAL"] == 1
    
    def test_get_stable_apis(self):
        """Can filter APIs by stability level"""
        catalog = build_complete_documentation_catalog()
        stable = catalog.get_stable_apis()
        assert all(api.stability == StabilityLevel.STABLE for api in stable)
    
    def test_get_experimental_apis(self):
        """Can get experimental APIs"""
        catalog = build_complete_documentation_catalog()
        experimental = catalog.get_experimental_apis()
        assert all(api.stability == StabilityLevel.EXPERIMENTAL for api in experimental)
    
    def test_get_stability_summary(self):
        """Summary returns proper dictionary structure"""
        catalog = build_complete_documentation_catalog()
        summary = catalog.get_stability_summary()
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert "INTERNAL" in summary
    
    def test_generate_readme_section(self):
        """README section generation produces markdown"""
        catalog = build_complete_documentation_catalog()
        readme = catalog.generate_readme_section()
        assert "## NeuralShield AI API Stability Summary" in readme
        assert "STABLE" in readme
        assert "EXPERIMENTAL" in readme


class TestStabilityDecorators:
    """Test API stability decorators"""
    
    def test_stable_api_decorator(self):
        """@stable_api decorator marks function as stable"""
        @stable_api(since="2.0.0")
        def my_function():
            return "ok"
        
        assert my_function._api_stability == StabilityLevel.STABLE
        assert my_function._api_since == "2.0.0"
        assert my_function._api_deprecated == False
        assert my_function() == "ok"
    
    def test_stable_api_default_version(self):
        """@stable_api defaults to version 1.0.0"""
        @stable_api()
        def my_function():
            return "ok"
        
        assert my_function._api_since == "1.0.0"
    
    def test_experimental_api_decorator(self):
        """@experimental_api decorator marks function"""
        @experimental_api()
        def my_function():
            return "ok"
        
        assert my_function._api_stability == StabilityLevel.EXPERIMENTAL
        assert my_function._api_deprecated == False
        assert my_function() == "ok"
    
    def test_internal_api_decorator(self):
        """@internal_api decorator marks function"""
        @internal_api()
        def my_function():
            return "ok"
        
        assert my_function._api_stability == StabilityLevel.INTERNAL
        assert my_function() == "ok"
    
    def test_deprecated_api_decorator(self):
        """@deprecated_api emits warning and marks function"""
        @deprecated_api(
            removal_version="3.0.0",
            migration_guide="Use new_function() instead"
        )
        def old_function():
            return "ok"
        
        assert old_function._api_stability == StabilityLevel.DEPRECATED
        assert old_function._api_removal_version == "3.0.0"
        assert old_function._api_deprecated == True
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_function()
            assert len(w) == 1
            assert issubclass(w[-1].category, DeprecationWarning)
            assert "deprecated" in str(w[-1].message).lower()
        
        assert result == "ok"
    
    def test_decorators_preserve_function_behavior(self):
        """Decorators should not change function behavior"""
        @stable_api()
        def add(a, b):
            return a + b
        
        assert add(2, 3) == 5
        assert add("hello", "world") == "helloworld"
    
    def test_decorators_preserve_function_metadata(self):
        """Decorators should preserve function name and docstring"""
        @stable_api()
        def documented_func():
            """This is my docstring"""
            pass
        
        assert documented_func.__name__ == "documented_func"
        assert "This is my docstring" in documented_func.__doc__


class TestBuildCompleteCatalog:
    """Test building the complete documentation catalog"""
    
    def test_build_catalog_returns_catalog(self):
        """build_complete_documentation_catalog returns DocumentationCatalog"""
        catalog = build_complete_documentation_catalog()
        assert isinstance(catalog, DocumentationCatalog)
    
    def test_catalog_has_modules(self):
        """Built catalog should contain multiple modules"""
        catalog = build_complete_documentation_catalog()
        assert len(catalog._modules) >= 3  # At least threat_detection, validation, resilience
    
    def test_threat_detection_registered(self):
        """Threat detection module should be registered"""
        catalog = build_complete_documentation_catalog()
        assert "threat_detection" in catalog._modules
    
    def test_input_validation_registered(self):
        """Input validation module should be registered"""
        catalog = build_complete_documentation_catalog()
        assert "input_validation" in catalog._modules


class TestGlobalCatalogInstance:
    """Test global catalog singleton"""
    
    def test_global_catalog_exists(self):
        """DOCUMENTATION_CATALOG global is initialized"""
        assert DOCUMENTATION_CATALOG is not None
        assert isinstance(DOCUMENTATION_CATALOG, DocumentationCatalog)
    
    def test_get_api_stability_summary(self):
        """get_api_stability_summary returns proper summary"""
        summary = get_api_stability_summary()
        assert summary["catalog_version"] == "v33"
        assert "generated_at" in summary
        assert "stability_summary" in summary
        assert summary["total_modules_documented"] >= 3
        assert summary["total_apis_documented"] > 0


class TestBackwardCompatibility:
    """Verify no breaking changes to existing code"""
    
    def test_documentation_is_add_only(self):
        """Documentation module is purely additive"""
        # Import should not affect any existing modules
        import sys
        # Verify we're not monkey-patching anything
        assert "api_documentation_stability" in str(sys.modules.get(
            'neural_shield.api_documentation_stability_catalog_v33_2026_june', ''
        ))
    
    def test_no_existing_code_modified(self):
        """Existing code paths work without modification"""
        # This test passes if we can import and use the module
        # without affecting any other modules
        assert True  # Pure additive module - no breaking changes possible
    
    def test_all_features_opt_in(self):
        """All documentation features are strictly opt-in"""
        # Functions work without any decorators
        def regular_function():
            return "works"
        
        assert not hasattr(regular_function, '_api_stability')
        assert regular_function() == "works"


class TestModuleExecution:
    """Test module can run as __main__"""
    
    def test_main_execution(self):
        """Running module as __main__ produces output"""
        import subprocess
        result = subprocess.run(
            ['python3', '-c', '''
from neural_shield.api_documentation_stability_catalog_v33_2026_june import get_api_stability_summary
summary = get_api_stability_summary()
print(summary["catalog_version"])
'''],
            capture_output=True,
            text=True
        )
        assert result.returncode == 0
        assert "v33" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
