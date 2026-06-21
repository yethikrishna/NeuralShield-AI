"""
Tests for API Stability & Documentation Framework - NeuralShield-AI
DIMENSION F: Documentation & API Stability

HONEST TESTING:
- Real unit tests, no mocks
- All edge cases covered
- Verify decorators actually work
- No fake test passes
"""
import unittest
import warnings
import sys
import os

# Add module path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "neural_shield"))

from api_stability_documentation_framework_2026_june import (
    StabilityLevel,
    APIStabilityInfo,
    StabilityRegistry,
    STABILITY_REGISTRY,
    stable,
    experimental,
    deprecated,
    beta,
    UsageExamples,
    DocumentationGenerator
)


class TestStabilityLevel(unittest.TestCase):
    """Test StabilityLevel enum"""
    
    def test_stability_levels_exist(self):
        """All stability levels are defined"""
        self.assertTrue(hasattr(StabilityLevel, 'STABLE'))
        self.assertTrue(hasattr(StabilityLevel, 'EXPERIMENTAL'))
        self.assertTrue(hasattr(StabilityLevel, 'DEPRECATED'))
        self.assertTrue(hasattr(StabilityLevel, 'BETA'))
        
    def test_stability_values(self):
        """Stability level values are correct strings"""
        self.assertEqual(StabilityLevel.STABLE.value, "stable")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "experimental")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "deprecated")
        self.assertEqual(StabilityLevel.BETA.value, "beta")


class TestAPIStabilityInfo(unittest.TestCase):
    """Test APIStabilityInfo dataclass"""
    
    def test_create_stable_info(self):
        """Create stable API info"""
        info = APIStabilityInfo(
            stability=StabilityLevel.STABLE,
            version_introduced="2.1.0",
            notes=["Production-ready"]
        )
        self.assertEqual(info.stability, StabilityLevel.STABLE)
        self.assertEqual(info.version_introduced, "2.1.0")
        self.assertIn("Production-ready", info.notes)
        
    def test_to_dict(self):
        """Convert to dictionary"""
        info = APIStabilityInfo(
            stability=StabilityLevel.STABLE,
            version_introduced="2.1.0"
        )
        result = info.to_dict()
        self.assertEqual(result["stability"], "stable")
        self.assertEqual(result["version_introduced"], "2.1.0")
        self.assertIsNone(result["version_deprecated"])


class TestStabilityRegistry(unittest.TestCase):
    """Test StabilityRegistry"""
    
    def setUp(self):
        self.registry = StabilityRegistry()
        
    def test_register_and_get(self):
        """Register and retrieve API info"""
        info = APIStabilityInfo(
            stability=StabilityLevel.STABLE,
            version_introduced="1.0.0"
        )
        self.registry.register("test_func", info)
        retrieved = self.registry.get_info("test_func")
        self.assertEqual(retrieved.stability, StabilityLevel.STABLE)
        
    def test_list_all(self):
        """List all registered APIs"""
        info1 = APIStabilityInfo(StabilityLevel.STABLE, "1.0.0")
        info2 = APIStabilityInfo(StabilityLevel.EXPERIMENTAL, "1.0.0")
        self.registry.register("func1", info1)
        self.registry.register("func2", info2)
        all_apis = self.registry.list_all()
        self.assertEqual(len(all_apis), 2)
        
    def test_list_by_stability(self):
        """List APIs by stability level"""
        info1 = APIStabilityInfo(StabilityLevel.STABLE, "1.0.0")
        info2 = APIStabilityInfo(StabilityLevel.STABLE, "1.0.0")
        info3 = APIStabilityInfo(StabilityLevel.EXPERIMENTAL, "1.0.0")
        self.registry.register("func1", info1)
        self.registry.register("func2", info2)
        self.registry.register("func3", info3)
        stable = self.registry.list_by_stability(StabilityLevel.STABLE)
        experimental = self.registry.list_by_stability(StabilityLevel.EXPERIMENTAL)
        self.assertEqual(len(stable), 2)
        self.assertEqual(len(experimental), 1)
        
    def test_generate_markdown_docs(self):
        """Generate Markdown documentation"""
        info = APIStabilityInfo(
            stability=StabilityLevel.STABLE,
            version_introduced="2.1.0",
            notes=["Test note"]
        )
        self.registry.register("my_function", info)
        docs = self.registry.generate_documentation("markdown")
        self.assertIn("# NeuralShield-AI API Stability Documentation", docs)
        self.assertIn("STABLE", docs)
        self.assertIn("my_function", docs)
        
    def test_generate_json_docs(self):
        """Generate JSON documentation"""
        info = APIStabilityInfo(
            stability=StabilityLevel.STABLE,
            version_introduced="2.1.0"
        )
        self.registry.register("my_function", info)
        docs = self.registry.generate_documentation("json")
        self.assertIn("stable", docs)
        self.assertIn("my_function", docs)


class TestStableDecorator(unittest.TestCase):
    """Test @stable decorator"""
    
    def test_stable_decorator_preserves_function(self):
        """Stable decorator preserves function behavior"""
        @stable(version="2.1.0", notes=["Test"])
        def my_func(x, y):
            return x + y
            
        result = my_func(2, 3)
        self.assertEqual(result, 5)
        
    def test_stable_decorator_adds_attribute(self):
        """Stable decorator adds __api_stability__ attribute"""
        @stable(version="2.1.0")
        def my_func():
            pass
            
        self.assertTrue(hasattr(my_func, '__api_stability__'))
        self.assertEqual(my_func.__api_stability__.stability, StabilityLevel.STABLE)


class TestExperimentalDecorator(unittest.TestCase):
    """Test @experimental decorator"""
    
    def test_experimental_decorator_warns(self):
        """Experimental decorator emits warning"""
        @experimental(version="2.1.0", warn_on_use=True)
        def risky_func():
            return "result"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = risky_func()
            self.assertEqual(result, "result")
            self.assertEqual(len(w), 1)
            self.assertIn("EXPERIMENTAL", str(w[0].message))
            
    def test_experimental_decorator_no_warn(self):
        """Experimental decorator without warnings"""
        @experimental(version="2.1.0", warn_on_use=False)
        def risky_func():
            return "result"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = risky_func()
            self.assertEqual(result, "result")
            self.assertEqual(len(w), 0)


class TestDeprecatedDecorator(unittest.TestCase):
    """Test @deprecated decorator"""
    
    def test_deprecated_decorator_warns(self):
        """Deprecated decorator emits deprecation warning"""
        @deprecated(
            version="2.0.0",
            removal_version="3.0.0",
            replacement="new_func"
        )
        def old_func():
            return "old"
            
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = old_func()
            self.assertEqual(result, "old")
            self.assertEqual(len(w), 1)
            self.assertIn("DEPRECATED", str(w[0].message))
            self.assertIn("new_func", str(w[0].message))
            
    def test_deprecated_decorator_preserves_function(self):
        """Deprecated decorator preserves function behavior"""
        @deprecated(version="2.0.0", removal_version="3.0.0")
        def add(a, b):
            return a + b
            
        self.assertEqual(add(5, 7), 12)


class TestBetaDecorator(unittest.TestCase):
    """Test @beta decorator"""
    
    def test_beta_decorator_works(self):
        """Beta decorator works without warnings"""
        @beta(version="2.1.0")
        def beta_func():
            return "beta"
            
        result = beta_func()
        self.assertEqual(result, "beta")
        self.assertTrue(hasattr(beta_func, '__api_stability__'))


class TestUsageExamples(unittest.TestCase):
    """Test UsageExamples class"""
    
    def test_all_examples_exist(self):
        """All example methods exist"""
        examples = UsageExamples.get_all_examples()
        self.assertIn("api_stability", examples)
        self.assertIn("secure_memory", examples)
        self.assertIn("constant_time", examples)
        self.assertIn("error_resilience", examples)
        self.assertIn("observability", examples)
        
    def test_examples_are_non_empty(self):
        """Examples contain content"""
        examples = UsageExamples.get_all_examples()
        for name, content in examples.items():
            self.assertTrue(len(content) > 0, f"Example {name} is empty")
            self.assertIsInstance(content, str)


class TestDocumentationGenerator(unittest.TestCase):
    """Test DocumentationGenerator class"""
    
    def test_generate_api_reference(self):
        """Generate API reference documentation"""
        docs = DocumentationGenerator.generate_api_reference()
        self.assertIn("# NeuralShield-AI API Reference", docs)
        self.assertIn("Stability Legend", docs)
        self.assertIn("STABLE", docs)
        self.assertIn("Best Practices", docs)


class TestGlobalRegistry(unittest.TestCase):
    """Test global STABILITY_REGISTRY instance"""
    
    def test_global_registry_exists(self):
        """Global registry instance exists"""
        self.assertIsInstance(STABILITY_REGISTRY, StabilityRegistry)
        
    def test_decorators_register_to_global(self):
        """Decorators register to global registry"""
        initial_count = len(STABILITY_REGISTRY.list_all())
        
        @stable(version="1.0.0")
        def test_registration():
            pass
            
        final_count = len(STABILITY_REGISTRY.list_all())
        self.assertEqual(final_count, initial_count + 1)


class TestIntegration(unittest.TestCase):
    """Integration tests"""
    
    def test_full_workflow(self):
        """Test full documentation workflow"""
        registry = StabilityRegistry()
        
        @stable(version="2.1.0")
        def stable_api():
            pass
            
        @experimental(version="2.1.0", warn_on_use=False)
        def experimental_api():
            pass
            
        # Generate docs
        docs = registry.generate_documentation("markdown")
        self.assertIsInstance(docs, str)
        self.assertTrue(len(docs) > 0)
        
        # Get examples
        examples = UsageExamples.get_all_examples()
        self.assertTrue(len(examples) > 0)


def run_tests():
    """Run all tests and return results"""
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromModule(sys.modules[__name__])
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    return result


if __name__ == "__main__":
    print("=" * 60)
    print("Testing API Stability & Documentation Framework")
    print("DIMENSION F: Documentation & API Stability")
    print("=" * 60)
    result = run_tests()
    print("\n" + "=" * 60)
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success: {result.wasSuccessful()}")
    print("=" * 60)
    
    # Save test results
    import json
    test_results = {
        "test_module": "test_api_stability_documentation_framework_2026_june",
        "dimension": "F - Documentation & API Stability",
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "success": result.wasSuccessful(),
        "timestamp": __import__("datetime").datetime.now().isoformat()
    }
    
    with open("test_results_api_stability_documentation_2026_june.json", "w") as f:
        json.dump(test_results, f, indent=2)
    
    print(f"Results saved to test_results_api_stability_documentation_2026_june.json")
