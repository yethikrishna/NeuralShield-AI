"""
Test Suite for NeuralShield-AI Comprehensive API Stability Catalog v4
June 2026 Release

Tests verify:
- Catalog initialization and module registration
- Stability level queries and filtering
- Report generation accuracy
- Backward compatibility guarantees
- Endpoint documentation integrity
"""

import pytest
import json
from typing import Dict, Any

from neural_shield.comprehensive_api_stability_documentation_catalog_v4_2026_june import (
    NeuralShieldAPIStabilityCatalog,
    StabilityLevel,
    APIModule,
    APIEndpoint,
    get_stability_report,
    is_module_stable,
    get_all_stable_apis,
    API_CATALOG
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.BETA.value == "BETA"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    
    def test_stability_level_order(self):
        # Verify stability progression order
        levels = list(StabilityLevel)
        assert len(levels) == 4


class TestAPIModule:
    """Test APIModule dataclass"""
    
    def test_api_module_creation(self):
        module = APIModule(
            name="TestModule",
            stability=StabilityLevel.STABLE,
            module_path="test.module",
            description="Test description",
            first_release="2026.6.0",
            last_updated="2026.6.22",
            maintainer="Test Team"
        )
        assert module.name == "TestModule"
        assert module.stability == StabilityLevel.STABLE
        assert module.test_coverage == 0.0  # Default
        assert module.tags == []  # Default
    
    def test_api_module_with_all_fields(self):
        module = APIModule(
            name="FullModule",
            stability=StabilityLevel.BETA,
            module_path="full.module",
            description="Full test module",
            first_release="2026.5.0",
            last_updated="2026.6.22",
            maintainer="Full Team",
            tags=["test", "beta"],
            test_coverage=85.5,
            performance_sla={"p50_ms": 10.0}
        )
        assert len(module.tags) == 2
        assert module.test_coverage == 85.5
        assert module.performance_sla["p50_ms"] == 10.0


class TestAPIEndpoint:
    """Test APIEndpoint dataclass"""
    
    def test_api_endpoint_creation(self):
        endpoint = APIEndpoint(
            name="test_endpoint",
            module="TestModule",
            signature="test(a: str) -> bool",
            stability=StabilityLevel.STABLE,
            description="Test endpoint",
            parameters=[{"name": "a", "type": "str", "required": True}],
            return_type="bool"
        )
        assert endpoint.name == "test_endpoint"
        assert endpoint.examples == []  # Default
        assert endpoint.exceptions == []  # Default


class TestNeuralShieldAPIStabilityCatalog:
    """Test main catalog class"""
    
    def test_catalog_initialization(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        assert catalog.VERSION == "2026.6.22"
        assert catalog.CATALOG_VERSION == "v4"
        assert len(catalog.modules) > 0
        assert len(catalog.endpoints) > 0
    
    def test_catalog_has_core_modules(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        # Verify key STABLE modules exist
        core_modules = [
            "AdvancedJailbreakDetector2026",
            "ConstitutionalClassifier2026",
            "ContextAwarePromptInjectionDefender",
            "PromptInjectionSandbox",
            "ErrorResilienceComprehensiveEnhancedV2"
        ]
        for module_name in core_modules:
            assert module_name in catalog.modules
            assert catalog.modules[module_name].stability == StabilityLevel.STABLE
    
    def test_get_module_stability(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        # STABLE module
        stability = catalog.get_module_stability("AdvancedJailbreakDetector2026")
        assert stability == StabilityLevel.STABLE
        # BETA module
        stability = catalog.get_module_stability("PromptInjectionProvenanceTrackerV3")
        assert stability == StabilityLevel.BETA
        # Non-existent module
        stability = catalog.get_module_stability("NonExistentModule")
        assert stability is None
    
    def test_get_stable_modules(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        stable = catalog.get_stable_modules()
        assert len(stable) > 0
        assert "AdvancedJailbreakDetector2026" in stable
        # Verify no BETA modules in stable list
        assert "PromptInjectionProvenanceTrackerV3" not in stable
    
    def test_get_beta_modules(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        beta = catalog.get_beta_modules()
        assert len(beta) > 0
        # BETA modules should be in beta list
        assert "PromptInjectionProvenanceTrackerV3" in beta
        # STABLE modules should NOT be in beta list
        assert "AdvancedJailbreakDetector2026" not in beta
    
    def test_get_experimental_modules(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        experimental = catalog.get_experimental_modules()
        assert len(experimental) > 0
        assert "CrossModalPromptInjectionDetector" in experimental
        assert "MultiTurnJailbreakDefender" in experimental
    
    def test_generate_stability_report(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        report = catalog.generate_stability_report()
        
        # Verify report structure
        assert "catalog_version" in report
        assert "framework_version" in report
        assert "generated_at" in report
        assert "summary" in report
        assert "average_test_coverage" in report
        
        # Verify summary counts
        summary = report["summary"]
        assert summary["total_modules"] == (
            summary["stable"] + summary["beta"] + 
            summary["experimental"] + summary["deprecated"]
        )
        
        # Verify test coverage is reasonable
        assert report["average_test_coverage"] > 70.0
        assert report["average_test_coverage"] < 100.0
    
    def test_compatibility_matrix(self):
        catalog = NeuralShieldAPIStabilityCatalog()
        matrix = catalog.get_compatibility_matrix()
        
        assert "2026.6.x_compatible" in matrix
        assert "2026.5.x_compatible" in matrix
        assert "breaking_changes_since_2026.5" in matrix
        
        # CRITICAL: No breaking changes - INCREMENTAL PHILOSOPHY
        assert len(matrix["breaking_changes_since_2026.5"]) == 0
    
    def test_module_metadata_integrity(self):
        """Verify all modules have complete metadata"""
        catalog = NeuralShieldAPIStabilityCatalog()
        
        for name, module in catalog.modules.items():
            # Required fields must not be empty
            assert module.name, f"Module {name} missing name"
            assert module.module_path, f"Module {name} missing path"
            assert module.description, f"Module {name} missing description"
            assert module.first_release, f"Module {name} missing first_release"
            assert module.last_updated, f"Module {name} missing last_updated"
            assert module.maintainer, f"Module {name} missing maintainer"
            
            # Version format validation
            assert len(module.first_release.split(".")) >= 2
            assert len(module.last_updated.split(".")) >= 2
            
            # Test coverage must be realistic
            assert module.test_coverage >= 0.0
            assert module.test_coverage <= 100.0
    
    def test_endpoint_integrity(self):
        """Verify all endpoints have complete documentation"""
        catalog = NeuralShieldAPIStabilityCatalog()
        
        for name, endpoint in catalog.endpoints.items():
            assert endpoint.name, f"Endpoint {name} missing name"
            assert endpoint.module, f"Endpoint {name} missing module"
            assert endpoint.signature, f"Endpoint {name} missing signature"
            assert endpoint.description, f"Endpoint {name} missing description"
            assert endpoint.return_type, f"Endpoint {name} missing return_type"
            assert len(endpoint.parameters) >= 0
    
    def test_performance_sla_present(self):
        """Verify STABLE modules have performance SLAs"""
        catalog = NeuralShieldAPIStabilityCatalog()
        
        for name, module in catalog.modules.items():
            if module.stability == StabilityLevel.STABLE:
                assert module.performance_sla is not None, \
                    f"STABLE module {name} missing performance SLA"
                assert "p50_ms" in module.performance_sla
                assert "p99_ms" in module.performance_sla
                assert "throughput" in module.performance_sla


class TestConvenienceFunctions:
    """Test module-level convenience functions"""
    
    def test_get_stability_report(self):
        report = get_stability_report()
        assert report is not None
        assert "summary" in report
    
    def test_is_module_stable(self):
        assert is_module_stable("AdvancedJailbreakDetector2026") is True
        assert is_module_stable("PromptInjectionProvenanceTrackerV3") is False
        assert is_module_stable("NonExistent") is False
    
    def test_get_all_stable_apis(self):
        stable = get_all_stable_apis()
        assert len(stable) > 0
        assert "AdvancedJailbreakDetector2026" in stable


class TestIncrementalBuildPhilosophy:
    """CRITICAL: Verify incremental build philosophy is maintained"""
    
    def test_no_deprecated_modules_yet(self):
        """No modules should be deprecated yet - we only add, not remove"""
        catalog = NeuralShieldAPIStabilityCatalog()
        deprecated = [m for m in catalog.modules.values() 
                     if m.stability == StabilityLevel.DEPRECATED]
        assert len(deprecated) == 0, "No deprecations yet - ADD-ONLY philosophy"
    
    def test_all_stable_modules_backward_compatible(self):
        """All STABLE modules from 2026.5.x are still present"""
        catalog = NeuralShieldAPIStabilityCatalog()
        # Modules that were STABLE in 2026.5.x must still exist
        june_2026_stable = [
            "AdvancedJailbreakDetector2026",
            "ConstitutionalClassifier2026",
            "ContextAwarePromptInjectionDefender",
            "PromptInjectionSandbox",
            "PromptInjectionSemanticParaphraseDetector",
            "GraphBasedJailbreakDetector",
            "ModelDriftMonitoringAlertingSystem",
            "HallucinationDetector2026",
            "MITREAttackV15CoverageAnalyzer",
            "APIGatewaySecurityValidator2026",
            "InputPurificationPoisoning2026",
            "OutputSanitizerPIIRedactor2026"
        ]
        for module_name in june_2026_stable:
            assert module_name in catalog.modules, \
                f"Backward compatibility broken: {module_name} removed"
            assert catalog.modules[module_name].stability == StabilityLevel.STABLE, \
                f"Module {module_name} stability downgraded"
    
    def test_singleton_consistency(self):
        """Verify singleton instance works correctly"""
        report1 = API_CATALOG.generate_stability_report()
        report2 = get_stability_report()
        # Same data should be returned
        assert report1["summary"]["total_modules"] == report2["summary"]["total_modules"]


class TestReportSerialization:
    """Test report can be serialized for API responses"""
    
    def test_report_json_serializable(self):
        report = get_stability_report()
        # Should serialize without errors
        json_str = json.dumps(report, indent=2)
        assert json_str is not None
        assert len(json_str) > 0
    
    def test_report_no_circular_references(self):
        report = get_stability_report()
        # This would fail with circular references
        parsed = json.loads(json.dumps(report))
        assert parsed is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
