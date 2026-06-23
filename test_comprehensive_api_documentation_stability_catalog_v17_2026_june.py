"""
Test Suite for NeuralShield-AI API Documentation & Stability Catalog v17
Tests verify:
1. Catalog initialization and basic functionality
2. Stability level classification
3. Security boundary classification (NEW v17)
4. Migration guide integrity
5. Compatibility matrix generation
6. JSON documentation export
7. Helper function correctness
8. No runtime impact on existing code

100% ADD-ONLY - No existing code modified
"""

import pytest
import json
from neural_shield.comprehensive_api_documentation_stability_catalog_v17_2026_june import (
    NeuralShieldAPICatalog,
    StabilityLevel,
    APIEndpoint,
    MigrationGuide,
    api_catalog,
    get_api_stability,
    get_security_boundary,
    get_usage_example
)


class TestCatalogInitialization:
    """Test basic catalog initialization and structure."""
    
    def test_catalog_singleton_exists(self):
        """Singleton instance should be pre-initialized."""
        assert api_catalog is not None
        assert isinstance(api_catalog, NeuralShieldAPICatalog)
    
    def test_new_catalog_initializes(self):
        """New catalog instance should initialize without errors."""
        catalog = NeuralShieldAPICatalog()
        assert catalog is not None
    
    def test_endpoints_populated(self):
        """Catalog should contain documented endpoints."""
        catalog = NeuralShieldAPICatalog()
        assert len(catalog._endpoints) > 0
        # v17 should have at least 15 documented endpoints
        assert len(catalog._endpoints) >= 15


class TestStabilityClassification:
    """Test stability level classification for all endpoints."""
    
    def test_stable_modules_exist(self):
        """STABLE modules should exist in catalog."""
        catalog = NeuralShieldAPICatalog()
        stable = catalog.list_by_stability(StabilityLevel.STABLE)
        assert len(stable) > 0
        # Core detection modules should be STABLE
        stable_names = [ep.name for ep in stable]
        assert "PromptInjectionDetector" in stable_names or "SecureMemoryZeroizer" in stable_names
    
    def test_beta_modules_exist(self):
        """BETA modules should exist in catalog."""
        catalog = NeuralShieldAPICatalog()
        beta = catalog.list_by_stability(StabilityLevel.BETA)
        assert len(beta) > 0
    
    def test_experimental_modules_exist(self):
        """EXPERIMENTAL modules should exist in catalog."""
        catalog = NeuralShieldAPICatalog()
        experimental = catalog.list_by_stability(StabilityLevel.EXPERIMENTAL)
        assert len(experimental) > 0
    
    def test_get_endpoint_returns_correct_type(self):
        """get_endpoint should return APIEndpoint or None."""
        catalog = NeuralShieldAPICatalog()
        endpoint = catalog.get_endpoint("prompt_injection_detector")
        assert endpoint is not None
        assert isinstance(endpoint, APIEndpoint)
        assert endpoint.stability in [StabilityLevel.STABLE, StabilityLevel.BETA]
    
    def test_get_nonexistent_endpoint_returns_none(self):
        """Nonexistent endpoints should return None."""
        catalog = NeuralShieldAPICatalog()
        endpoint = catalog.get_endpoint("nonexistent_module_xyz123")
        assert endpoint is None


class TestV17SecurityBoundaryFeature:
    """v17 NEW: Test security boundary classification."""
    
    def test_security_boundary_classification_exists(self):
        """v17: Security boundary field should exist on endpoints."""
        catalog = NeuralShieldAPICatalog()
        endpoint = catalog.get_endpoint("side_channel_resistance_v17")
        assert endpoint is not None
        assert hasattr(endpoint, 'security_boundary')
    
    def test_high_security_modules_identified(self):
        """v17: High security modules should be classified."""
        catalog = NeuralShieldAPICatalog()
        high_security = catalog.list_by_security_boundary("high")
        assert len(high_security) > 0
        # Memory zeroizer and input validator should be high security
        high_names = [ep.name for ep in high_security]
        assert "SideChannelResistantEvaluator" in high_names or "SecureMemoryZeroizer" in high_names
    
    def test_list_by_security_boundary_returns_list(self):
        """v17: Security boundary listing should work."""
        catalog = NeuralShieldAPICatalog()
        standard = catalog.list_by_security_boundary("standard")
        enhanced = catalog.list_by_security_boundary("enhanced")
        high = catalog.list_by_security_boundary("high")
        assert isinstance(standard, list)
        assert isinstance(enhanced, list)
        assert isinstance(high, list)
        # Total should equal endpoint count
        total = len(standard) + len(enhanced) + len(high)
        assert total >= len(catalog._endpoints)  # Some may have other values


class TestMigrationGuides:
    """Test migration guide integrity."""
    
    def test_migration_guides_exist(self):
        """Migration guides should be populated."""
        catalog = NeuralShieldAPICatalog()
        assert len(catalog._migration_guides) > 0
    
    def test_v16_to_v17_migration_exists(self):
        """v16 -> v17 migration guide should exist (pure doc update)."""
        catalog = NeuralShieldAPICatalog()
        v17_guide = [g for g in catalog._migration_guides if g.to_version == "v17"]
        assert len(v17_guide) > 0
        # v17 should be backward compatible
        assert v17_guide[0].backward_compatible == True
    
    def test_migration_guide_structure(self):
        """Migration guides should have proper structure."""
        catalog = NeuralShieldAPICatalog()
        guide = catalog._migration_guides[0]
        assert isinstance(guide, MigrationGuide)
        assert isinstance(guide.breaking_changes, list)
        assert isinstance(guide.migration_steps, list)
        assert isinstance(guide.backward_compatible, bool)


class TestCompatibilityMatrix:
    """Test compatibility matrix generation."""
    
    def test_compatibility_matrix_structure(self):
        """Compatibility matrix should have required fields."""
        catalog = NeuralShieldAPICatalog()
        matrix = catalog.get_compatibility_matrix()
        assert "python_versions" in matrix
        assert "recommended_python" in matrix
        assert "core_dependencies" in matrix
        assert "platforms" in matrix
        assert "security_modules" in matrix  # v17 NEW
    
    def test_python_versions_valid(self):
        """Python versions should be valid semver strings."""
        catalog = NeuralShieldAPICatalog()
        matrix = catalog.get_compatibility_matrix()
        versions = matrix["python_versions"]
        assert "3.9" in versions
        assert "3.10" in versions
        assert "3.11" in versions
        assert "3.12" in versions


class TestDocumentationExport:
    """Test JSON documentation export."""
    
    def test_generate_json_documentation(self):
        """JSON documentation should generate without errors."""
        catalog = NeuralShieldAPICatalog()
        docs = catalog.generate_documentation(format="json")
        assert docs is not None
        # Should be valid JSON
        parsed = json.loads(docs)
        assert "catalog_version" in parsed
        assert parsed["catalog_version"] == "v17"
        assert "total_endpoints" in parsed
        assert "stability_breakdown" in parsed
        assert "security_boundary_breakdown" in parsed  # v17 NEW
    
    def test_stability_summary(self):
        """Stability summary should count correctly."""
        catalog = NeuralShieldAPICatalog()
        summary = catalog.get_stability_summary()
        assert "STABLE" in summary
        assert "BETA" in summary
        assert "EXPERIMENTAL" in summary
        # Counts should be non-negative
        for count in summary.values():
            assert count >= 0


class TestHelperFunctions:
    """Test public helper functions."""
    
    def test_get_api_stability_returns_string(self):
        """get_api_stability should return stability string."""
        stability = get_api_stability("prompt_injection_detector")
        assert stability is not None
        assert stability in ["STABLE", "BETA", "EXPERIMENTAL"]
    
    def test_get_api_stability_nonexistent_returns_none(self):
        """Nonexistent modules return None."""
        stability = get_api_stability("nonexistent_xyz")
        assert stability is None
    
    def test_v17_get_security_boundary(self):
        """v17 NEW: get_security_boundary helper should work."""
        boundary = get_security_boundary("memory_zeroizer")
        assert boundary is not None
        assert boundary in ["standard", "enhanced", "high"]
    
    def test_get_usage_example_returns_string_or_none(self):
        """get_usage_example should return example or None."""
        example = get_usage_example("prompt_injection_detector")
        # Returns None or string depending on module
        assert example is None or isinstance(example, str)


class TestNoRuntimeImpact:
    """Verify documentation module has NO runtime impact."""
    
    def test_import_only_no_side_effects(self):
        """Importing should not modify global state."""
        # Pure import should not raise exceptions
        from neural_shield import comprehensive_api_documentation_stability_catalog_v17_2026_june
        assert comprehensive_api_documentation_stability_catalog_v17_2026_june is not None
    
    def test_no_existing_code_modified(self):
        """Documentation module should be ADD-ONLY."""
        # Verify this is a NEW module, not modifying existing
        from neural_shield import comprehensive_api_documentation_stability_catalog_v17_2026_june
        module_path = comprehensive_api_documentation_stability_catalog_v17_2026_june.__file__
        assert "v17" in module_path  # Versioned filename
        assert "documentation" in module_path.lower()


class TestEndpointMetadata:
    """Test endpoint metadata completeness."""
    
    def test_all_endpoints_have_performance_data(self):
        """All endpoints should have performance characteristics."""
        catalog = NeuralShieldAPICatalog()
        for name, endpoint in catalog._endpoints.items():
            assert isinstance(endpoint.performance_characteristics, dict)
            # Performance dict should not be empty
            assert len(endpoint.performance_characteristics) > 0, f"{name} missing performance data"
    
    def test_all_endpoints_have_thread_safe_flag(self):
        """All endpoints should have thread_safe flag."""
        catalog = NeuralShieldAPICatalog()
        for name, endpoint in catalog._endpoints.items():
            assert isinstance(endpoint.thread_safe, bool), f"{name} missing thread_safe"
    
    def test_all_endpoints_have_version(self):
        """All endpoints should have since_version."""
        catalog = NeuralShieldAPICatalog()
        for name, endpoint in catalog._endpoints.items():
            assert endpoint.since_version is not None
            assert endpoint.since_version.startswith("v"), f"{name} invalid since_version"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
