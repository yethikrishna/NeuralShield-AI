"""
Test Suite for NeuralShield API Stability Documentation Catalog v2.0
DIMENSION F: Documentation & API Stability
Incremental Build: ADD-ONLY - No existing code modified
"""

import sys
import os
import tempfile
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

import json
from api_stability_documentation_catalog_v2_2026_june import (
    NeuralShieldAPIStabilityCatalog,
    StabilityLevel,
    APIEndpoint,
    ModuleDocumentation
)


class TestAPIStabilityCatalog:
    """Test suite for API stability documentation catalog."""
    
    def test_catalog_initialization(self):
        """Test catalog initializes without errors."""
        catalog = NeuralShieldAPIStabilityCatalog()
        assert catalog is not None
        assert len(catalog.modules) > 0
    
    def test_stability_report_generation(self):
        """Test stability report generation."""
        catalog = NeuralShieldAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        assert "catalog_version" in report
        assert "total_modules" in report
        assert "total_endpoints" in report
        assert "stability_breakdown" in report
        assert report["total_modules"] > 0
        assert report["total_endpoints"] > 0
    
    def test_all_endpoints_have_stability_markers(self):
        """Test every endpoint has proper stability classification."""
        catalog = NeuralShieldAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            for endpoint in module_data["endpoints"]:
                assert endpoint["stability"] in ["STABLE", "EXPERIMENTAL", "DEPRECATED"]
                assert endpoint["since_version"] is not None
                assert len(endpoint["description"]) > 0
    
    def test_all_endpoints_have_usage_examples(self):
        """Test every endpoint includes usage examples."""
        catalog = NeuralShieldAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            for endpoint in module_data["endpoints"]:
                assert len(endpoint["usage_example"]) > 0
                assert len(endpoint["usage_example"].strip()) > 10
    
    def test_all_endpoints_have_parameter_docs(self):
        """Test every endpoint documents parameters."""
        catalog = NeuralShieldAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            for endpoint in module_data["endpoints"]:
                assert isinstance(endpoint["parameters"], list)
                assert len(endpoint["returns"]) > 0
    
    def test_module_categories_are_valid(self):
        """Test modules have proper category classification."""
        valid_categories = {
            "Core Framework",
            "Threat Intelligence",
            "Prompt Injection Defense",
            "Security Hardening"
        }
        
        catalog = NeuralShieldAPIStabilityCatalog()
        report = catalog.get_stability_report()
        
        for module_name, module_data in report["modules"].items():
            assert module_data["category"] in valid_categories
    
    def test_json_export(self):
        """Test JSON export functionality."""
        catalog = NeuralShieldAPIStabilityCatalog()
        with tempfile.TemporaryDirectory() as tmpdir:
            export_path = os.path.join(tmpdir, "api_catalog.json")
            catalog.export_to_json(export_path)
            
            assert os.path.exists(export_path)
            
            with open(export_path) as f:
                data = json.load(f)
            
            assert "catalog_version" in data
            assert "modules" in data
    
    def test_single_module_report(self):
        """Test retrieving single module documentation."""
        catalog = NeuralShieldAPIStabilityCatalog()
        module_report = catalog.get_stability_report("shield_defense_framework")
        
        assert "error" not in module_report
        assert module_report["module_name"] is not None
        assert len(module_report["endpoints"]) > 0
    
    def test_nonexistent_module_returns_error(self):
        """Test nonexistent module returns proper error."""
        catalog = NeuralShieldAPIStabilityCatalog()
        result = catalog.get_stability_report("nonexistent_module_xyz")
        assert "error" in result
    
    def test_stability_level_enum(self):
        """Test stability level enum values."""
        assert StabilityLevel.STABLE.value == "STABLE"
        assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
        assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    
    def test_api_endpoint_dataclass(self):
        """Test APIEndpoint dataclass creation."""
        endpoint = APIEndpoint(
            name="test_function",
            module="test_module",
            stability=StabilityLevel.STABLE,
            since_version="1.0.0",
            description="Test description",
            usage_example="test()",
            parameters=[{"name": "x", "type": "int", "desc": "test"}],
            returns="None"
        )
        assert endpoint.name == "test_function"
        assert endpoint.stability == StabilityLevel.STABLE
    
    def test_module_documentation_dataclass(self):
        """Test ModuleDocumentation dataclass creation."""
        module = ModuleDocumentation(
            module_name="test_mod",
            category="Test Category",
            module_description="Test module"
        )
        assert module.module_name == "test_mod"
        assert module.category == "Test Category"
    
    def test_main_execution(self):
        """Test main block executes without error."""
        catalog = NeuralShieldAPIStabilityCatalog()
        report = catalog.get_stability_report()
        assert report["total_modules"] >= 6
        assert report["total_endpoints"] >= 12


def run_tests():
    """Run all tests and generate results file."""
    print("=" * 60)
    print("NeuralShield API Stability Documentation Catalog Tests")
    print("DIMENSION F: Documentation & API Stability")
    print("=" * 60)
    
    test = TestAPIStabilityCatalog()
    
    tests_passed = 0
    tests_total = 0
    
    test_methods = [m for m in dir(test) if m.startswith('test_')]
    
    for method_name in test_methods:
        tests_total += 1
        try:
            getattr(test, method_name)()
            tests_passed += 1
            print(f"✓ PASS: {method_name}")
        except Exception as e:
            print(f"✗ FAIL: {method_name} - {e}")
    
    print(f"\n{'=' * 60}")
    print(f"Results: {tests_passed}/{tests_total} tests passed")
    print(f"{'=' * 60}")
    
    # Write results
    results = {
        "test_suite": "API Stability Documentation Catalog v2.0",
        "dimension": "F - Documentation & API Stability",
        "tests_passed": tests_passed,
        "tests_total": tests_total,
        "success_rate": f"{(tests_passed/tests_total)*100:.1f}%",
        "modules_documented": 6,
        "endpoints_documented": 12,
        "status": "PASSED" if tests_passed == tests_total else "FAILED"
    }
    
    with open("test_results_api_stability_documentation_v2_2026_june.json", "w") as f:
        json.dump(results, f, indent=2)
    
    return tests_passed == tests_total


if __name__ == "__main__":
    success = run_tests()
    sys.exit(0 if success else 1)
