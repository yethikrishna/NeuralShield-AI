"""
Test Suite for NeuralShield-AI Documentation & Stability Catalog v13
====================================================================
Comprehensive tests covering all functionality in the v13 documentation system.
All tests are ADD-ONLY - no existing tests modified.
"""

import unittest
import warnings
import json
from typing import Any

# Import the new module
from neural_shield.comprehensive_api_documentation_master_v13_2026_june import (
    StabilityLevel,
    APIExample,
    APIStabilityInfo,
    stable,
    experimental,
    deprecated,
    DocumentationCatalogV13,
    get_documentation_catalog,
)


class TestStabilityLevelEnum(unittest.TestCase):
    """Test StabilityLevel enumeration."""
    
    def test_stability_level_values(self):
        """Test all stability levels have correct string values."""
        self.assertEqual(str(StabilityLevel.STABLE), "stable")
        self.assertEqual(str(StabilityLevel.EXPERIMENTAL), "experimental")
        self.assertEqual(str(StabilityLevel.DEPRECATED), "deprecated")
        self.assertEqual(str(StabilityLevel.INTERNAL), "internal")
    
    def test_stability_level_comparison(self):
        """Test stability level comparison works."""
        self.assertNotEqual(StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL)
        self.assertEqual(StabilityLevel.STABLE, StabilityLevel.STABLE)


class TestAPIExampleDataclass(unittest.TestCase):
    """Test APIExample dataclass functionality."""
    
    def test_example_creation(self):
        """Test APIExample can be created with required fields."""
        example = APIExample(
            title="Test Example",
            code="print('hello')",
            description="Test description"
        )
        self.assertEqual(example.title, "Test Example")
        self.assertEqual(example.code, "print('hello')")
        self.assertEqual(example.description, "Test description")
    
    def test_example_defaults(self):
        """Test APIExample optional field defaults."""
        example = APIExample(title="Test", code="code")
        self.assertEqual(example.description, "")
        self.assertEqual(example.expected_output, "")


class TestAPIStabilityInfo(unittest.TestCase):
    """Test APIStabilityInfo dataclass functionality."""
    
    def test_api_info_creation_minimal(self):
        """Test creating APIStabilityInfo with minimal fields."""
        info = APIStabilityInfo(
            module_name="test_module",
            method_name="test_method",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test API"
        )
        self.assertEqual(info.module_name, "test_module")
        self.assertEqual(info.stability, StabilityLevel.STABLE)
    
    def test_api_info_to_dict(self):
        """Test conversion to dictionary format."""
        info = APIStabilityInfo(
            module_name="test",
            method_name="func",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test",
            examples=[APIExample(title="Ex", code="x")]
        )
        d = info.to_dict()
        self.assertIn("module", d)
        self.assertIn("stability", d)
        self.assertIn("examples", d)
        self.assertEqual(d["stability"], "stable")


class TestStabilityDecorators(unittest.TestCase):
    """Test stability marker decorators."""
    
    def test_stable_decorator_metadata(self):
        """Test @stable decorator attaches correct metadata."""
        @stable(version="13.0.0", description="Test function")
        def test_func(x: int) -> int:
            return x * 2
        
        self.assertEqual(test_func.__api_stability__, StabilityLevel.STABLE)
        self.assertEqual(test_func.__api_version__, "13.0.0")
        self.assertEqual(test_func(5), 10)  # Function still works
    
    def test_experimental_decorator_metadata(self):
        """Test @experimental decorator attaches correct metadata."""
        @experimental(version="13.0.0")
        def test_func() -> str:
            return "experimental"
        
        self.assertEqual(test_func.__api_stability__, StabilityLevel.EXPERIMENTAL)
        self.assertEqual(test_func(), "experimental")
    
    def test_deprecated_decorator_warning(self):
        """Test @deprecated decorator emits warning."""
        @deprecated(
            version="12.0.0",
            removal_version="15.0.0",
            alternative="new_func"
        )
        def old_func() -> str:
            return "old"
        
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_func()
            
            self.assertEqual(len(w), 1)
            self.assertTrue(issubclass(w[-1].category, DeprecationWarning))
            self.assertIn("deprecated", str(w[-1].message).lower())
        
        self.assertEqual(result, "old")


class TestDocumentationCatalogV13(unittest.TestCase):
    """Test DocumentationCatalogV13 core functionality."""
    
    def setUp(self):
        """Create fresh catalog for each test."""
        self.catalog = DocumentationCatalogV13()
    
    def test_empty_catalog(self):
        """Test empty catalog initialization."""
        self.assertEqual(len(self.catalog._apis), 0)
        self.assertEqual(len(self.catalog.get_by_stability(StabilityLevel.STABLE)), 0)
    
    def test_register_api(self):
        """Test registering an API in the catalog."""
        info = APIStabilityInfo(
            module_name="test",
            method_name="api",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test",
            categories=["core", "test"]
        )
        self.catalog.register(info)
        self.assertEqual(len(self.catalog._apis), 1)
    
    def test_get_by_stability(self):
        """Test filtering APIs by stability level."""
        for i, level in enumerate([StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL]):
            self.catalog.register(APIStabilityInfo(
                module_name=f"mod{i}",
                method_name=f"api{i}",
                stability=level,
                version_introduced="1.0.0",
                description=f"API {i}"
            ))
        
        stable = self.catalog.get_by_stability(StabilityLevel.STABLE)
        experimental = self.catalog.get_by_stability(StabilityLevel.EXPERIMENTAL)
        
        self.assertEqual(len(stable), 1)
        self.assertEqual(len(experimental), 1)
    
    def test_get_by_category(self):
        """Test filtering APIs by category."""
        self.catalog.register(APIStabilityInfo(
            module_name="mod1",
            method_name="api1",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test",
            categories=["core", "detection"]
        ))
        self.catalog.register(APIStabilityInfo(
            module_name="mod2",
            method_name="api2",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test",
            categories=["core", "crypto"]
        ))
        
        detection = self.catalog.get_by_category("detection")
        core = self.catalog.get_by_category("core")
        
        self.assertEqual(len(detection), 1)
        self.assertEqual(len(core), 2)
    
    def test_get_all_categories(self):
        """Test getting all unique categories."""
        self.catalog.register(APIStabilityInfo(
            module_name="mod",
            method_name="api",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test",
            categories=["a", "b", "c"]
        ))
        
        cats = self.catalog.get_all_categories()
        self.assertEqual(cats, {"a", "b", "c"})
    
    def test_generate_markdown_reference(self):
        """Test Markdown reference generation."""
        self.catalog.register(APIStabilityInfo(
            module_name="test_mod",
            method_name="test_api",
            stability=StabilityLevel.STABLE,
            version_introduced="13.0.0",
            description="Test API description",
            categories=["test"],
            parameters={"x": "Input value"},
            return_value="Processed value"
        ))
        
        md = self.catalog.generate_markdown_reference()
        
        self.assertIn("# NeuralShield-AI API Reference", md)
        self.assertIn("STABLE APIs", md)
        self.assertIn("test_api", md)
        self.assertIn("Test API description", md)
        self.assertIn("Parameters", md)
    
    def test_export_json(self):
        """Test JSON export functionality."""
        self.catalog.register(APIStabilityInfo(
            module_name="mod",
            method_name="api",
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0",
            description="Test"
        ))
        
        json_str = self.catalog.export_json()
        data = json.loads(json_str)
        
        self.assertEqual(data["catalog_version"], "13.0.0")
        self.assertEqual(data["total_apis"], 1)
        self.assertIn("apis", data)
    
    def test_get_stability_report(self):
        """Test stability coverage report."""
        for i in range(3):
            self.catalog.register(APIStabilityInfo(
                module_name=f"mod{i}",
                method_name=f"api{i}",
                stability=StabilityLevel.STABLE,
                version_introduced="1.0.0",
                description=f"API {i}",
                categories=[f"cat{i}"]
            ))
        
        report = self.catalog.get_stability_report()
        
        self.assertEqual(report["total_apis"], 3)
        self.assertEqual(report["stable"], 3)
        self.assertEqual(report["experimental"], 0)
        self.assertIn("categories", report)


class TestSingletonCatalog(unittest.TestCase):
    """Test singleton catalog instance."""
    
    def test_get_documentation_catalog_returns_same_instance(self):
        """Test singleton pattern works correctly."""
        cat1 = get_documentation_catalog()
        cat2 = get_documentation_catalog()
        
        self.assertIs(cat1, cat2)
    
    def test_singleton_has_preloaded_apis(self):
        """Test singleton catalog comes with APIs pre-registered."""
        catalog = get_documentation_catalog()
        
        # Should have multiple APIs registered
        self.assertGreater(len(catalog._apis), 5)
        
        # Should have stable and experimental APIs
        stable = catalog.get_by_stability(StabilityLevel.STABLE)
        experimental = catalog.get_by_stability(StabilityLevel.EXPERIMENTAL)
        
        self.assertGreater(len(stable), 0)
        self.assertGreater(len(experimental), 0)


class TestBackwardCompatibility(unittest.TestCase):
    """Test backward compatibility - new module coexists with old."""
    
    def test_no_import_conflicts(self):
        """Test importing doesn't conflict with existing modules."""
        # Should import without errors
        from neural_shield.comprehensive_api_documentation_master_v13_2026_june import (
            StabilityLevel, DocumentationCatalogV13
        )
        self.assertIsNotNone(StabilityLevel)
        self.assertIsNotNone(DocumentationCatalogV13)
    
    def test_decorators_preserve_function_behavior(self):
        """Test decorated functions behave exactly like originals."""
        @stable(version="13.0.0")
        def add(a: int, b: int) -> int:
            return a + b
        
        # Function behavior unchanged
        self.assertEqual(add(2, 3), 5)
        self.assertEqual(add(-1, 1), 0)
        
        # Metadata attached
        self.assertTrue(hasattr(add, '__api_stability__'))


class TestEdgeCases(unittest.TestCase):
    """Test edge cases and boundary conditions."""
    
    def test_empty_markdown_generation(self):
        """Test Markdown generation with empty catalog."""
        catalog = DocumentationCatalogV13()
        md = catalog.generate_markdown_reference()
        
        self.assertIn("Total APIs Documented", md)
        self.assertIn("0", md)
    
    def test_large_catalog_performance(self):
        """Test catalog handles many registrations."""
        catalog = DocumentationCatalogV13()
        
        # Register many APIs
        for i in range(50):
            catalog.register(APIStabilityInfo(
                module_name=f"mod{i}",
                method_name=f"api{i}",
                stability=StabilityLevel.STABLE,
                version_introduced=f"{i}.0.0",
                description=f"API {i}"
            ))
        
        self.assertEqual(len(catalog._apis), 50)
        report = catalog.get_stability_report()
        self.assertEqual(report["total_apis"], 50)
    
    def test_json_export_empty(self):
        """Test JSON export with empty catalog."""
        catalog = DocumentationCatalogV13()
        json_str = catalog.export_json()
        data = json.loads(json_str)
        
        self.assertEqual(data["total_apis"], 0)
        self.assertEqual(len(data["apis"]), 0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
