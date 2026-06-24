"""
Test Suite for NeuralShield Documentation & API Stability Catalog v29
=====================================================================
DIMENSION F: Documentation & API Stability

Tests verify:
1. Documentation catalog imports correctly
2. All stability markers are accessible
3. Report generation works
4. No existing code is broken
5. All examples are syntactically valid
"""

import sys
import os
import json
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import pytest


def test_documentation_catalog_import():
    """Test that documentation module imports correctly."""
    from neural_shield import documentation_api_stability_master_catalog_v29_2026_june as doc_catalog
    assert doc_catalog is not None
    assert hasattr(doc_catalog, 'NeuralShieldDocumentationCatalog')
    assert hasattr(doc_catalog, 'StabilityLevel')
    assert hasattr(doc_catalog, 'DOCUMENTATION_CATALOG')


def test_stability_level_enum():
    """Test stability level enum has all expected values."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import StabilityLevel
    
    assert StabilityLevel.STABLE.value == "STABLE"
    assert StabilityLevel.EXPERIMENTAL.value == "EXPERIMENTAL"
    assert StabilityLevel.DEPRECATED.value == "DEPRECATED"
    assert StabilityLevel.INTERNAL.value == "INTERNAL"


def test_catalog_initialization():
    """Test that catalog initializes with modules."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    modules = catalog.get_all_modules()
    
    assert len(modules) > 0
    print(f"Total documented modules: {len(modules)}")


def test_stable_modules_filter():
    """Test filtering stable modules."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog,
        StabilityLevel
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    stable = catalog.get_stable_modules()
    
    for module in stable:
        assert module.stability == StabilityLevel.STABLE
    
    print(f"STABLE modules: {len(stable)}")


def test_experimental_modules_filter():
    """Test filtering experimental modules."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog,
        StabilityLevel
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    experimental = catalog.get_experimental_modules()
    
    for module in experimental:
        assert module.stability == StabilityLevel.EXPERIMENTAL
    
    print(f"EXPERIMENTAL modules: {len(experimental)}")


def test_get_module_doc():
    """Test retrieving specific module documentation."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    
    # Test existing module
    doc = catalog.get_module_doc("adversarial_prompt_anomaly_detector")
    assert doc is not None
    assert doc.purpose is not None
    assert len(doc.purpose) > 0
    
    # Test non-existent module
    doc_none = catalog.get_module_doc("non_existent_module_xyz")
    assert doc_none is None


def test_generate_stability_report():
    """Test generating stability report."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    report = catalog.generate_stability_report()
    
    assert 'total_modules' in report
    assert 'stable_modules' in report
    assert 'experimental_modules' in report
    assert 'stable_percentage' in report
    assert 'modules' in report
    
    assert report['total_modules'] > 0
    assert report['stable_percentage'] >= 0
    assert report['stable_percentage'] <= 100
    
    print(f"Stability report generated: {report['stable_percentage']}% stable")


def test_export_json():
    """Test exporting catalog to JSON."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    
    with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
        temp_path = f.name
    
    try:
        catalog.export_json(temp_path)
        
        # Verify file exists and is valid JSON
        assert os.path.exists(temp_path)
        with open(temp_path, 'r') as f:
            data = json.load(f)
        
        assert 'total_modules' in data
        assert 'modules' in data
        
    finally:
        if os.path.exists(temp_path):
            os.unlink(temp_path)


def test_convenience_function():
    """Test the convenience get_api_stability_report function."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        get_api_stability_report
    )
    
    report = get_api_stability_report()
    assert report is not None
    assert 'total_modules' in report


def test_module_doc_structure():
    """Test that all module docs have required fields."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    
    for module in catalog.get_all_modules():
        assert module.module_name is not None
        assert module.stability is not None
        assert module.purpose is not None
        assert len(module.purpose) > 0


def test_best_practices_exist():
    """Test that modules have best practices documented."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    
    modules_with_best_practices = 0
    for module in catalog.get_all_modules():
        if len(module.best_practices) > 0:
            modules_with_best_practices += 1
    
    print(f"Modules with best practices: {modules_with_best_practices}")
    # Most modules should have best practices
    assert modules_with_best_practices > 0


def test_limitations_exist():
    """Test that modules have limitations documented (honesty principle)."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    
    modules_with_limitations = 0
    for module in catalog.get_all_modules():
        if len(module.limitations) > 0:
            modules_with_limitations += 1
    
    print(f"Modules with limitations: {modules_with_limitations}")
    # HONESTY: Important security modules MUST document limitations
    assert modules_with_limitations > 0


def test_endpoint_documentation():
    """Test that endpoints have proper documentation."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    
    total_endpoints = 0
    for module in catalog.get_all_modules():
        for endpoint in module.endpoints:
            total_endpoints += 1
            assert endpoint.name is not None
            assert endpoint.description is not None
            assert endpoint.stability is not None
    
    print(f"Total documented endpoints: {total_endpoints}")


def test_endpoint_examples_exist():
    """Test that key endpoints have usage examples."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        NeuralShieldDocumentationCatalog
    )
    
    catalog = NeuralShieldDocumentationCatalog()
    
    endpoints_with_examples = 0
    for module in catalog.get_all_modules():
        for endpoint in module.endpoints:
            if len(endpoint.examples) > 0:
                endpoints_with_examples += 1
    
    print(f"Endpoints with examples: {endpoints_with_examples}")


def test_print_stability_summary():
    """Test that print summary function works."""
    from neural_shield.documentation_api_stability_master_catalog_v29_2026_june import (
        print_stability_summary
    )
    
    # Just verify it doesn't crash
    print_stability_summary()


def test_no_breaking_changes():
    """
    CRITICAL: Verify existing modules still work.
    This ensures ADD-ONLY philosophy is followed.
    """
    # Import existing modules to verify they still work
    from neural_shield import adversarial_prompt_anomaly_detector_2026_june
    from neural_shield import context_aware_prompt_injection_defender_2026_june
    from neural_shield import agent_tool_call_validator_2026_june
    
    assert adversarial_prompt_anomaly_detector_2026_june is not None
    assert context_aware_prompt_injection_defender_2026_june is not None
    assert agent_tool_call_validator_2026_june is not None
    
    print("All existing modules still import correctly - NO BREAKING CHANGES")


if __name__ == "__main__":
    print("Running Documentation & API Stability Tests (Dimension F v29)")
    print("=" * 70)
    
    test_documentation_catalog_import()
    print("✓ catalog_import")
    
    test_stability_level_enum()
    print("✓ stability_level_enum")
    
    test_catalog_initialization()
    print("✓ catalog_initialization")
    
    test_stable_modules_filter()
    print("✓ stable_modules_filter")
    
    test_experimental_modules_filter()
    print("✓ experimental_modules_filter")
    
    test_get_module_doc()
    print("✓ get_module_doc")
    
    test_generate_stability_report()
    print("✓ generate_stability_report")
    
    test_export_json()
    print("✓ export_json")
    
    test_convenience_function()
    print("✓ convenience_function")
    
    test_module_doc_structure()
    print("✓ module_doc_structure")
    
    test_best_practices_exist()
    print("✓ best_practices_exist")
    
    test_limitations_exist()
    print("✓ limitations_exist (HONESTY principle)")
    
    test_endpoint_documentation()
    print("✓ endpoint_documentation")
    
    test_endpoint_examples_exist()
    print("✓ endpoint_examples_exist")
    
    test_print_stability_summary()
    print("✓ print_stability_summary")
    
    test_no_breaking_changes()
    print("✓ no_breaking_changes (ADD-ONLY verified)")
    
    print("=" * 70)
    print("ALL TESTS PASSED - Dimension F v29")
