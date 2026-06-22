"""
Test Suite for NeuralShield-AI Comprehensive API Stability Documentation Catalog v10

Tests cover:
- Catalog initialization and basic functionality
- Stability level enumeration
- Module documentation retrieval
- Stability filtering
- Markdown and JSON export
- Singleton pattern
"""

import pytest
import json
from neural_shield.comprehensive_api_stability_documentation_catalog_v10_2026_june import (
    NeuralShieldAPIDocumentationCatalog,
    StabilityLevel,
    APIEndpointDoc,
    ModuleDoc,
    get_documentation_catalog
)


class TestStabilityLevel:
    """Test StabilityLevel enumeration"""
    
    def test_stability_level_values(self):
        """Test all stability levels exist with correct values"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.INTERNAL.value == "INTERNAL"
        assert StabilityLevel.MAINTENANCE.value == "MAINTENANCE"
    
    def test_stability_level_count(self):
        """Test correct number of stability levels"""
        assert len(StabilityLevel) == 5


class TestAPIEndpointDoc:
    """Test APIEndpointDoc dataclass"""
    
    def test_endpoint_doc_creation(self):
        """Test creating endpoint documentation"""
        doc = APIEndpointDoc(
            name="test_function",
            module="test_module",
            stability=StabilityLevel.STABLE,
            since_version="1.0.0",
            description="Test function",
            parameters=[{"name": "param1", "type": "str"}],
            returns="Dict",
            examples=["test_function('input')"],
            exceptions=["ValueError"],
            thread_safe=True
        )
        
        assert doc.name == "test_function"
        assert doc.stability == StabilityLevel.STABLE
        assert doc.since_version == "1.0.0"
        assert len(doc.parameters) == 1
        assert len(doc.examples) == 1
        assert doc.thread_safe is True
    
    def test_endpoint_doc_defaults(self):
        """Test default values work correctly"""
        doc = APIEndpointDoc(
            name="test",
            module="mod",
            stability=StabilityLevel.STABLE,
            since_version="1.0.0",
            description="Test"
        )
        
        assert doc.parameters == []
        assert doc.examples == []
        assert doc.returns == ""
        assert doc.thread_safe is True


class TestModuleDoc:
    """Test ModuleDoc dataclass"""
    
    def test_module_doc_creation(self):
        """Test creating module documentation"""
        endpoint = APIEndpointDoc(
            name="func",
            module="mod",
            stability=StabilityLevel.STABLE,
            since_version="1.0.0",
            description="Function"
        )
        
        mod_doc = ModuleDoc(
            module_name="test_module",
            stability=StabilityLevel.STABLE,
            category="Test",
            overview="Test module overview",
            endpoints=[endpoint]
        )
        
        assert mod_doc.module_name == "test_module"
        assert mod_doc.category == "Test"
        assert len(mod_doc.endpoints) == 1


class TestNeuralShieldAPIDocumentationCatalog:
    """Test main documentation catalog class"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        assert catalog.catalog_version == "10.0.0"
        assert catalog.last_updated is not None
        assert len(catalog.modules) > 0
    
    def test_catalog_modules_populated(self):
        """Test all expected modules are in catalog"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        expected_modules = [
            "advanced_jailbreak_detector",
            "constitutional_classifier",
            "prompt_injection_context_analyzer",
            "prompt_firewall",
            "agent_tool_call_validator",
            "agent_memory_safety_guardian",
            "adversarial_prompt_anomaly_detector",
            "adversarial_embedding_perturbation_detector",
            "observability_engine",
            "error_resilience_engine"
        ]
        
        for module in expected_modules:
            assert module in catalog.modules, f"Missing module: {module}"
    
    def test_get_module_documentation(self):
        """Test retrieving module documentation"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        doc = catalog.get_module_documentation("prompt_firewall")
        assert doc is not None
        assert doc.stability == StabilityLevel.STABLE
        assert doc.category == "Prompt Injection Defense"
    
    def test_get_nonexistent_module(self):
        """Test retrieving non-existent module returns None"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        doc = catalog.get_module_documentation("nonexistent_module_xyz")
        assert doc is None
    
    def test_get_all_modules_by_stability(self):
        """Test filtering modules by stability level"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        stable_modules = catalog.get_all_modules_by_stability(StabilityLevel.STABLE)
        experimental_modules = catalog.get_all_modules_by_stability(StabilityLevel.EXPERIMENTAL)
        
        assert len(stable_modules) > 0
        assert len(experimental_modules) > 0
        
        for mod in stable_modules:
            assert mod.stability == StabilityLevel.STABLE
        
        for mod in experimental_modules:
            assert mod.stability == StabilityLevel.EXPERIMENTAL
    
    def test_get_stability_summary(self):
        """Test stability summary calculation"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        summary = catalog.get_stability_summary()
        
        assert "STABLE" in summary
        assert "EXPERIMENTAL" in summary
        assert "DEPRECATED" in summary
        assert "INTERNAL" in summary
        assert "MAINTENANCE" in summary
        
        assert summary["STABLE"] > 0
        assert summary["EXPERIMENTAL"] > 0
    
    def test_generate_markdown_docs(self):
        """Test markdown documentation generation"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        md = catalog.generate_markdown_docs()
        
        assert isinstance(md, str)
        assert len(md) > 0
        assert "# NeuralShield-AI API Documentation Catalog v10" in md
        assert "## Stability Legend" in md
        assert "🟢" in md  # Stable icon
        assert "🟡" in md  # Experimental icon
        assert "prompt_firewall" in md
    
    def test_export_json(self):
        """Test JSON export functionality"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        json_output = catalog.export_json()
        
        # Parse and validate JSON
        data = json.loads(json_output)
        
        assert "catalog_version" in data
        assert data["catalog_version"] == "10.0.0"
        assert "last_updated" in data
        assert "modules" in data
        assert len(data["modules"]) > 0
        
        # Check module structure
        for mod_name, mod_data in data["modules"].items():
            assert "stability" in mod_data
            assert "category" in mod_data
            assert "endpoints_count" in mod_data
    
    def test_experimental_modules_marked(self):
        """Test experimental modules are properly identified"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        embedding_module = catalog.get_module_documentation(
            "adversarial_embedding_perturbation_detector"
        )
        
        assert embedding_module is not None
        assert embedding_module.stability == StabilityLevel.EXPERIMENTAL
        
        # Check endpoints have deprecation notice
        for endpoint in embedding_module.endpoints:
            assert endpoint.deprecation_notice is not None
            assert endpoint.description is not None
            assert "EXPERIMENTAL" in endpoint.description
    
    def test_stable_modules_have_endpoints(self):
        """Test stable modules have documented endpoints"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        stable_modules = catalog.get_all_modules_by_stability(StabilityLevel.STABLE)
        
        for mod in stable_modules:
            assert len(mod.endpoints) > 0, f"Module {mod.module_name} has no endpoints"
    
    def test_endpoint_performance_notes(self):
        """Test endpoints have performance documentation where applicable"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        
        jailbreak_module = catalog.get_module_documentation("advanced_jailbreak_detector")
        assert jailbreak_module is not None
        
        # Find endpoint with performance notes
        endpoint_with_perf = None
        for ep in jailbreak_module.endpoints:
            if len(ep.performance_notes) > 0:
                endpoint_with_perf = ep
                break
        
        assert endpoint_with_perf is not None, "No endpoint has performance notes"
        assert "latency" in endpoint_with_perf.performance_notes.lower()


class TestSingletonFunction:
    """Test singleton catalog accessor"""
    
    def test_get_documentation_catalog_returns_instance(self):
        """Test singleton function returns catalog instance"""
        catalog = get_documentation_catalog()
        
        assert isinstance(catalog, NeuralShieldAPIDocumentationCatalog)
    
    def test_get_documentation_catalog_same_instance(self):
        """Test singleton function returns same instance"""
        catalog1 = get_documentation_catalog()
        catalog2 = get_documentation_catalog()
        
        assert catalog1 is catalog2


class TestIntegration:
    """Integration tests for documentation catalog"""
    
    def test_full_catalog_workflow(self):
        """Test complete catalog usage workflow"""
        # Get catalog
        catalog = get_documentation_catalog()
        
        # Get stability summary
        summary = catalog.get_stability_summary()
        
        # Get stable modules
        stable = catalog.get_all_modules_by_stability(StabilityLevel.STABLE)
        
        # Get specific module
        module = catalog.get_module_documentation("prompt_firewall")
        
        # Generate docs
        md = catalog.generate_markdown_docs()
        json_out = catalog.export_json()
        
        # Verify all operations succeeded
        assert summary["STABLE"] == len(stable)
        assert module is not None
        assert len(md) > 0
        assert len(json_out) > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
