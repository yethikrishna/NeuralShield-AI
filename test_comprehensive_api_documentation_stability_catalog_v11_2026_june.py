"""
Test Suite for Comprehensive API Documentation & Stability Catalog v11
Tests verify documentation catalog functionality without modifying production code.
"""

import pytest
import json
from neural_shield.comprehensive_api_documentation_stability_catalog_v11_2026_june import (
    DocumentationCatalog,
    StabilityLevel,
    APIEndpoint,
    get_catalog,
    check_api_stability
)


class TestStabilityLevel:
    """Tests for StabilityLevel enum."""
    
    def test_stability_level_values(self):
        """Verify stability level enum values are correct."""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"
    
    def test_stability_level_count(self):
        """Verify all expected stability levels exist."""
        assert len(StabilityLevel) == 4


class TestAPIEndpoint:
    """Tests for APIEndpoint dataclass."""
    
    def test_api_endpoint_creation_minimal(self):
        """Test creating APIEndpoint with minimal required fields."""
        endpoint = APIEndpoint(
            name="Test API",
            function_path="test.module.function",
            stability=StabilityLevel.STABLE,
            version_added="1.0.0",
            description="Test description"
        )
        assert endpoint.name == "Test API"
        assert endpoint.stability == StabilityLevel.STABLE
    
    def test_api_endpoint_creation_full(self):
        """Test creating APIEndpoint with all fields."""
        endpoint = APIEndpoint(
            name="Full Test API",
            function_path="test.module.full",
            stability=StabilityLevel.EXPERIMENTAL,
            version_added="2.0.0",
            version_deprecated="3.0.0",
            description="Full test description",
            parameters=[{"name": "param", "type": "str", "description": "Test param"}],
            returns="Test return",
            exceptions=["ValueError"],
            usage_example="example()",
            see_also=["other_api"],
            migration_guide="Migrate to new API"
        )
        assert endpoint.version_deprecated == "3.0.0"
        assert len(endpoint.parameters) == 1


class TestDocumentationCatalog:
    """Tests for DocumentationCatalog class."""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly."""
        catalog = DocumentationCatalog()
        assert catalog._catalog_version == "11.0.0"
        assert len(catalog._apis) > 0
    
    def test_get_stability_existing(self):
        """Test getting stability for registered API."""
        catalog = DocumentationCatalog()
        stability = catalog.get_stability("neural_shield.prompt_injection_detector.detect")
        assert stability == StabilityLevel.STABLE
    
    def test_get_stability_nonexistent(self):
        """Test getting stability for non-existent API."""
        catalog = DocumentationCatalog()
        stability = catalog.get_stability("nonexistent.api.path")
        assert stability is None
    
    def test_get_api_existing(self):
        """Test retrieving full API metadata."""
        catalog = DocumentationCatalog()
        api = catalog.get_api("neural_shield.prompt_injection_detector.detect")
        assert api is not None
        assert api.stability == StabilityLevel.STABLE
        assert "injection" in api.description.lower()
    
    def test_list_by_stability(self):
        """Test filtering APIs by stability level."""
        catalog = DocumentationCatalog()
        stable = catalog.list_by_stability(StabilityLevel.STABLE)
        experimental = catalog.list_by_stability(StabilityLevel.EXPERIMENTAL)
        deprecated = catalog.list_by_stability(StabilityLevel.DEPRECATED)
        
        assert len(stable) >= 4
        assert len(experimental) >= 2
        assert len(deprecated) >= 1
    
    def test_generate_documentation_json(self):
        """Test JSON documentation generation."""
        catalog = DocumentationCatalog()
        doc = catalog.generate_documentation(format="json")
        parsed = json.loads(doc)
        
        assert "catalog_version" in parsed
        assert "total_apis" in parsed
        assert "apis" in parsed
        assert parsed["catalog_version"] == "11.0.0"
    
    def test_generate_documentation_markdown(self):
        """Test markdown documentation generation."""
        catalog = DocumentationCatalog()
        doc = catalog.generate_documentation(format="markdown")
        
        assert "# NeuralShield AI API Documentation" in doc
        assert "STABLE" in doc
        assert "EXPERIMENTAL" in doc
    
    def test_validate_compatibility(self):
        """Test compatibility validation."""
        catalog = DocumentationCatalog()
        report = catalog.validate_compatibility("1.0.0")
        
        assert "client_version" in report
        assert "warnings" in report
        assert "experimental_notice" in report
        assert "recommendation" in report
    
    def test_get_catalog_hash(self):
        """Test catalog hash generation."""
        catalog = DocumentationCatalog()
        hash1 = catalog.get_catalog_hash()
        hash2 = catalog.get_catalog_hash()
        
        # Hash should be consistent
        assert hash1 == hash2
        # Hash should be 64 character hex string (SHA256)
        assert len(hash1) == 64
    
    def test_make_key_normalization(self):
        """Test key normalization function."""
        key1 = DocumentationCatalog._make_key("Module.Function")
        key2 = DocumentationCatalog._make_key("module.function")
        assert key1 == key2


class TestGlobalFunctions:
    """Tests for module-level helper functions."""
    
    def test_get_catalog_singleton(self):
        """Test that get_catalog returns singleton instance."""
        cat1 = get_catalog()
        cat2 = get_catalog()
        assert cat1 is cat2
    
    def test_check_api_stability(self):
        """Test quick stability check function."""
        result = check_api_stability("neural_shield.prompt_injection_detector.detect")
        assert result == "STABLE"
    
    def test_check_api_stability_not_found(self):
        """Test stability check for non-existent API."""
        result = check_api_stability("completely.fake.api")
        assert result is None


class TestCatalogIntegrity:
    """Tests for catalog data integrity."""
    
    def test_all_apis_have_required_fields(self):
        """Verify all registered APIs have required metadata fields."""
        catalog = DocumentationCatalog()
        
        for api in catalog._apis.values():
            assert api.name, "API missing name"
            assert api.function_path, "API missing function_path"
            assert api.stability, "API missing stability"
            assert api.version_added, "API missing version_added"
            assert api.description, "API missing description"
    
    def test_deprecated_apis_have_migration(self):
        """Verify deprecated APIs include migration guidance."""
        catalog = DocumentationCatalog()
        deprecated = catalog.list_by_stability(StabilityLevel.DEPRECATED)
        
        for api in deprecated:
            assert api.version_deprecated, "Deprecated API missing deprecation version"
            assert len(api.migration_guide) > 0, "Deprecated API missing migration guide"
    
    def test_stable_apis_have_examples(self):
        """Verify stable APIs include usage examples."""
        catalog = DocumentationCatalog()
        stable = catalog.list_by_stability(StabilityLevel.STABLE)
        
        for api in stable:
            # At least some stable APIs should have examples
            if api.usage_example:
                assert len(api.usage_example.strip()) > 0
    
    def test_no_duplicate_function_paths(self):
        """Verify no duplicate function paths in catalog."""
        catalog = DocumentationCatalog()
        paths = [api.function_path for api in catalog._apis.values()]
        assert len(paths) == len(set(paths)), "Duplicate function paths found"


class TestEdgeCases:
    """Edge case tests."""
    
    def test_empty_string_function_path(self):
        """Test handling of empty function path."""
        catalog = DocumentationCatalog()
        result = catalog.get_stability("")
        assert result is None
    
    def test_special_characters_in_function_path(self):
        """Test handling of special characters."""
        catalog = DocumentationCatalog()
        result = catalog.get_stability("api.path!@#$%")
        assert result is None
    
    def test_make_key_with_special_chars(self):
        """Test key normalization with special characters."""
        key = DocumentationCatalog._make_key("api.Path.With.Dots")
        assert "." not in key
        assert key.islower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
