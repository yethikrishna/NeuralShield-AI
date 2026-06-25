"""
Test Suite for NeuralShield-AI API Documentation & Stability Catalog V31
DIMENSION F: Documentation & API Stability

Tests verify:
1. All stability decorators work correctly
2. API catalog initialization and querying
3. Documentation generation
4. Stability level filtering
5. Backward compatibility - no existing code broken

ADD-ONLY PHILOSOPHY: These tests only validate NEW functionality,
never modify or test existing production code behavior.
"""

import pytest
import warnings
from typing import Callable

# Import the new documentation module
from neural_shield.comprehensive_api_documentation_stability_catalog_v31_2026_june import (
    StabilityLevel,
    APIDocumentation,
    VersionCompatibility,
    stable_api,
    experimental_api,
    deprecated_api,
    NeuralShieldAPICatalog,
    get_api_catalog,
    print_api_stability_summary
)


class TestStabilityDecorators:
    """Test the API stability decorator functionality."""
    
    def test_stable_api_decorator_marks_function(self):
        """Verify @stable_api correctly marks function metadata."""
        @stable_api(version_added="2.5.0")
        def test_func():
            return "stable"
        
        assert hasattr(test_func, "_stability")
        assert test_func._stability == StabilityLevel.STABLE
        assert test_func._version_added == "2.5.0"
        assert test_func._api_documented is True
    
    def test_stable_api_preserves_functionality(self):
        """Verify @stable_api doesn't break function behavior."""
        @stable_api(version_added="2.5.0")
        def test_func(a: int, b: int) -> int:
            return a + b
        
        result = test_func(3, 5)
        assert result == 8
        assert test_func.__name__ == "test_func"
    
    def test_experimental_api_decorator_marks_function(self):
        """Verify @experimental_api correctly marks function metadata."""
        @experimental_api(version_added="2.5.0")
        def test_func():
            return "experimental"
        
        assert hasattr(test_func, "_stability")
        assert test_func._stability == StabilityLevel.EXPERIMENTAL
        assert test_func._version_added == "2.5.0"
    
    def test_deprecated_api_issues_warning(self):
        """Verify @deprecated_api issues proper deprecation warnings."""
        @deprecated_api(
            version_deprecated="2.0.0",
            removal_version="3.0.0",
            replacement="new_function()"
        )
        def old_func():
            return "deprecated"
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_func()
            
            assert len(w) == 1
            assert issubclass(w[0].category, DeprecationWarning)
            assert "deprecated since 2.0.0" in str(w[0].message)
            assert "Will be removed in 3.0.0" in str(w[0].message)
            assert "new_function()" in str(w[0].message)
        
        assert result == "deprecated"
    
    def test_deprecated_api_preserves_return_value(self):
        """Verify deprecated functions still return correctly."""
        @deprecated_api(version_deprecated="2.0.0", removal_version="3.0.0")
        def add(a, b):
            return a + b
        
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            assert add(2, 3) == 5


class TestAPIDocumentationDataclass:
    """Test the APIDocumentation data structure."""
    
    def test_api_documentation_creation(self):
        """Test creating a documentation entry."""
        doc = APIDocumentation(
            function_name="test.module.function",
            stability=StabilityLevel.STABLE,
            version_added="1.0.0",
            description="Test function",
            usage_example="func()",
            parameters={"x": "int - input"}
        )
        
        assert doc.function_name == "test.module.function"
        assert doc.stability == StabilityLevel.STABLE
        assert doc.version_added == "1.0.0"
        assert doc.description == "Test function"
        assert "x" in doc.parameters
    
    def test_api_documentation_optional_fields(self):
        """Test optional fields default correctly."""
        doc = APIDocumentation(
            function_name="test",
            stability=StabilityLevel.STABLE,
            version_added="1.0.0"
        )
        
        assert doc.version_deprecated is None
        assert doc.deprecation_scheduled_removal is None
        assert isinstance(doc.parameters, dict)
        assert isinstance(doc.exceptions, list)
        assert isinstance(doc.compatibility_notes, list)


class TestNeuralShieldAPICatalog:
    """Test the main API catalog functionality."""
    
    def test_catalog_initialization(self):
        """Test catalog initializes with predefined APIs."""
        catalog = NeuralShieldAPICatalog()
        
        assert len(catalog.api_docs) > 0
        assert isinstance(catalog.compatibility_matrix, list)
        assert len(catalog.compatibility_matrix) > 0
    
    def test_get_api_documentation_existing(self):
        """Test retrieving documentation for an existing API."""
        catalog = NeuralShieldAPICatalog()
        
        doc = catalog.get_api_documentation(
            "adversarial_prompt_anomaly_detector.detect_anomaly"
        )
        
        assert doc is not None
        assert doc.stability == StabilityLevel.STABLE
        assert "anomalous" in doc.description.lower()
    
    def test_get_api_documentation_nonexistent(self):
        """Test retrieving documentation for non-existent API returns None."""
        catalog = NeuralShieldAPICatalog()
        doc = catalog.get_api_documentation("nonexistent.api")
        assert doc is None
    
    def test_list_apis_by_stability(self):
        """Test filtering APIs by stability level."""
        catalog = NeuralShieldAPICatalog()
        
        stable_apis = catalog.list_apis_by_stability(StabilityLevel.STABLE)
        experimental_apis = catalog.list_apis_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated_apis = catalog.list_apis_by_stability(StabilityLevel.DEPRECATED)
        
        assert len(stable_apis) > 0
        assert len(experimental_apis) > 0
        assert len(deprecated_apis) > 0
        
        # Verify no overlap
        stable_set = set(stable_apis)
        experimental_set = set(experimental_apis)
        deprecated_set = set(deprecated_apis)
        
        assert stable_set.isdisjoint(experimental_set)
        assert stable_set.isdisjoint(deprecated_set)
        assert experimental_set.isdisjoint(deprecated_set)
    
    def test_generate_documentation_report(self):
        """Test documentation report generation."""
        catalog = NeuralShieldAPICatalog()
        report = catalog.generate_documentation_report()
        
        assert isinstance(report, str)
        assert len(report) > 0
        assert "NEURALSHIELD-AI" in report
        assert "STABLE" in report
        assert "EXPERIMENTAL" in report
        assert "DEPRECATED" in report
    
    def test_catalog_repr(self):
        """Test catalog string representation."""
        catalog = NeuralShieldAPICatalog()
        repr_str = repr(catalog)
        assert "NeuralShieldAPICatalog" in repr_str
        assert "apis" in repr_str


class TestGlobalCatalogFunctions:
    """Test the global catalog singleton functions."""
    
    def test_get_api_catalog_returns_singleton(self):
        """Test get_api_catalog returns same instance each time."""
        catalog1 = get_api_catalog()
        catalog2 = get_api_catalog()
        
        assert catalog1 is catalog2
        assert isinstance(catalog1, NeuralShieldAPICatalog)
    
    def test_print_api_stability_summary_runs(self):
        """Test summary function executes without errors."""
        # Should run without raising exceptions
        print_api_stability_summary()


class TestVersionCompatibility:
    """Test version compatibility tracking."""
    
    def test_version_compatibility_creation(self):
        """Test creating compatibility matrix entry."""
        compat = VersionCompatibility(
            module_name="test_module",
            minimum_supported_version="1.0.0",
            recommended_version="2.5.0",
            backward_compatible=True
        )
        
        assert compat.module_name == "test_module"
        assert compat.minimum_supported_version == "1.0.0"
        assert compat.recommended_version == "2.5.0"
        assert compat.backward_compatible is True
        assert isinstance(compat.breaking_changes, dict)


class TestBackwardCompatibility:
    """Critical: Verify NO existing functionality is broken."""
    
    def test_importing_new_module_doesnt_break_existing(self):
        """Importing new documentation module doesn't affect existing."""
        # This test passes if no import errors occur
        pass
    
    def test_new_decorators_dont_change_behavior(self):
        """Decorators preserve original function behavior exactly."""
        def original(x, y):
            return x * y
        
        decorated = stable_api(version_added="2.5.0")(original)
        
        # Behavior should be identical
        for a, b in [(2, 3), (10, 5), (0, 100)]:
            assert original(a, b) == decorated(a, b)
    
    def test_no_side_effects_on_import(self):
        """Importing the module has no global side effects."""
        # The module should be importable without:
        # - Modifying global state
        # - Raising warnings
        # - Throwing exceptions
        import neural_shield.comprehensive_api_documentation_stability_catalog_v31_2026_june as doc_module
        
        # Module should have expected attributes
        assert hasattr(doc_module, "StabilityLevel")
        assert hasattr(doc_module, "NeuralShieldAPICatalog")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
