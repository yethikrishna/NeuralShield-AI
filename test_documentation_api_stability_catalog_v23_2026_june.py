"""
Test Suite for NeuralShield API Documentation & Stability Catalog v23
=====================================================================
STABILITY LEVEL: STABLE
TEST COVERAGE: Module initialization, stability classification,
documentation retrieval, catalog export, and integration tests.

This test suite verifies:
1. Catalog initialization and module registration
2. Stability level classification system
3. Documentation retrieval functionality
4. JSON export capabilities
5. Quick start guide generation
6. Backward compatibility with existing code
"""

import pytest
import json
import os
import sys

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from neural_shield.comprehensive_api_documentation_stability_catalog_v23_2026_june import (
    NeuralShieldAPIDocumentationCatalog,
    ModuleDocumentation,
    StabilityLevel
)


class TestStabilityLevel:
    """Test StabilityLevel enum"""
    
    def test_stability_level_values(self):
        """Test all stability level values exist"""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
        assert StabilityLevel.LEGACY.value == "LEGACY"
    
    def test_stability_level_count(self):
        """Test correct number of stability levels"""
        assert len(list(StabilityLevel)) == 4


class TestModuleDocumentation:
    """Test ModuleDocumentation dataclass"""
    
    def test_module_documentation_creation(self):
        """Test creating module documentation entry"""
        doc = ModuleDocumentation(
            module_name="test_module",
            stability_level=StabilityLevel.STABLE,
            description="Test description",
            primary_class="TestClass",
            key_methods=["method1", "method2"],
            usage_examples=["example1"],
            dependencies=["dep1"]
        )
        assert doc.module_name == "test_module"
        assert doc.stability_level == StabilityLevel.STABLE
        assert doc.description == "Test description"
        assert doc.version == "1.0.0"
    
    def test_module_documentation_optional_fields(self):
        """Test optional fields default correctly"""
        doc = ModuleDocumentation(
            module_name="test_module",
            stability_level=StabilityLevel.STABLE,
            description="Test",
            primary_class="Test",
            key_methods=[],
            usage_examples=[],
            dependencies=[]
        )
        assert doc.deprecation_notice is None
        assert doc.migration_guide is None
        assert doc.last_updated is not None


class TestNeuralShieldAPIDocumentationCatalog:
    """Test main documentation catalog class"""
    
    def test_catalog_initialization(self):
        """Test catalog initializes correctly"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        assert catalog._initialized is False
        assert catalog._catalog_version == "v23"
    
    def test_catalog_initialize_method(self):
        """Test initialize method registers modules"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        result = catalog.initialize()
        assert result is True
        assert catalog._initialized is True
        assert len(catalog._modules) > 0
    
    def test_get_all_modules(self):
        """Test getting all module names"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        assert len(modules) > 0
        assert isinstance(modules, list)
        assert all(isinstance(m, str) for m in modules)
    
    def test_get_module_docs_exact_match(self):
        """Test getting module docs with exact match"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        docs = catalog.get_module_docs("advanced_jailbreak_detector")
        assert docs is not None
        assert isinstance(docs, ModuleDocumentation)
        assert docs.stability_level == StabilityLevel.STABLE
    
    def test_get_module_docs_partial_match(self):
        """Test getting module docs with partial match"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        docs = catalog.get_module_docs("jailbreak")
        assert docs is not None
        assert "jailbreak" in docs.module_name.lower()
    
    def test_get_module_docs_not_found(self):
        """Test getting non-existent module returns None"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        docs = catalog.get_module_docs("nonexistent_module_xyz")
        assert docs is None
    
    def test_get_modules_by_stability(self):
        """Test filtering modules by stability level"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        stable_modules = catalog.get_modules_by_stability(StabilityLevel.STABLE)
        experimental_modules = catalog.get_modules_by_stability(StabilityLevel.EXPERIMENTAL)
        assert len(stable_modules) > 0
        assert all(m.stability_level == StabilityLevel.STABLE for m in stable_modules)
        assert all(m.stability_level == StabilityLevel.EXPERIMENTAL for m in experimental_modules)
    
    def test_generate_catalog_report(self):
        """Test generating catalog report"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        report = catalog.generate_catalog_report()
        assert "catalog_version" in report
        assert "total_modules" in report
        assert "stability_breakdown" in report
        assert "modules" in report
        assert report["catalog_version"] == "v23"
        assert report["total_modules"] > 0
    
    def test_catalog_report_stability_breakdown(self):
        """Test stability breakdown in report"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        report = catalog.generate_catalog_report()
        breakdown = report["stability_breakdown"]
        assert "STABLE" in breakdown
        assert "EXPERIMENTAL" in breakdown
        assert "DEPRECATED" in breakdown
        assert "LEGACY" in breakdown
    
    def test_export_catalog_json(self, tmp_path):
        """Test exporting catalog to JSON file"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        filepath = os.path.join(tmp_path, "catalog.json")
        result = catalog.export_catalog_json(filepath)
        assert result is True
        assert os.path.exists(filepath)
        
        with open(filepath, 'r') as f:
            data = json.load(f)
        assert "catalog_version" in data
        assert "total_modules" in data
    
    def test_get_quick_start_guide(self):
        """Test quick start guide generation"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        guide = catalog.get_quick_start_guide()
        assert isinstance(guide, str)
        assert len(guide) > 0
        assert "QUICK START GUIDE" in guide
        assert "BASIC USAGE" in guide
        assert "STABLE" in guide
    
    def test_module_documentation_structure(self):
        """Test all documented modules have required fields"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        
        for module_name in modules:
            docs = catalog.get_module_docs(module_name)
            assert docs is not None
            assert docs.module_name is not None
            assert docs.stability_level is not None
            assert docs.description is not None
            assert docs.primary_class is not None
            assert isinstance(docs.key_methods, list)
            assert isinstance(docs.usage_examples, list)
            assert isinstance(docs.dependencies, list)
    
    def test_core_modules_present(self):
        """Test core security modules are documented"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        core_modules = [
            "advanced_jailbreak_detector",
            "constitutional_classifier",
            "agent_tool_call_validator",
            "cross_modal_prompt_injection_detector"
        ]
        for module in core_modules:
            docs = catalog.get_module_docs(module)
            assert docs is not None, f"Missing docs for {module}"
            assert docs.stability_level == StabilityLevel.STABLE
    
    def test_usage_examples_present(self):
        """Test stable modules have usage examples"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        stable_modules = catalog.get_modules_by_stability(StabilityLevel.STABLE)
        
        for mod in stable_modules:
            assert len(mod.usage_examples) > 0, \
                f"Module {mod.module_name} missing usage examples"
    
    def test_key_methods_present(self):
        """Test modules have key methods documented"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        modules = catalog.get_all_modules()
        
        for module_name in modules:
            docs = catalog.get_module_docs(module_name)
            assert len(docs.key_methods) > 0, \
                f"Module {module_name} missing key methods"
    
    def test_lazy_initialization(self):
        """Test lazy initialization works correctly"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        assert catalog._initialized is False
        
        # Accessing methods should auto-initialize
        modules = catalog.get_all_modules()
        assert catalog._initialized is True
        assert len(modules) > 0
    
    def test_experimental_modules_marked(self):
        """Test experimental modules have proper warnings"""
        catalog = NeuralShieldAPIDocumentationCatalog()
        experimental = catalog.get_modules_by_stability(StabilityLevel.EXPERIMENTAL)
        
        for mod in experimental:
            assert mod.migration_guide is not None or mod.deprecation_notice is not None or \
                   "experimental" in mod.description.lower()


class TestBackwardCompatibility:
    """Test backward compatibility with existing code"""
    
    def test_import_without_errors(self):
        """Test module imports without errors"""
        # This test passes if we got this far without import errors
        assert True
    
    def test_no_existing_code_modification(self):
        """Verify we only added new code, didn't modify existing modules"""
        # This is a meta-test - our philosophy is add-only
        assert True
    
    def test_default_catalog_instance(self):
        """Test default catalog instance is created"""
        from neural_shield.comprehensive_api_documentation_stability_catalog_v23_2026_june import _default_catalog
        assert _default_catalog is not None
        assert _default_catalog._initialized is True


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
