"""
Test Suite for Documentation & API Stability Catalog v30
Dimension: F - Documentation & API Stability
Date: 2026-06-25

Tests verify:
1. Catalog initialization and module registration
2. Stability level enumeration
3. API endpoint documentation completeness
4. Documentation retrieval functions
5. Stability report generation
6. Singleton pattern correctness
7. Type hints and dataclass validation
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'neural_shield'))

from documentation_api_stability_master_catalog_v30_2026_june import (
    StabilityLevel,
    APIEndpoint,
    ModuleDocumentation,
    DocumentationCatalog,
    get_documentation_catalog,
    print_api_stability_report,
    __api_stability__,
)


class TestStabilityLevel(unittest.TestCase):
    """Test StabilityLevel enumeration"""
    
    def test_stability_level_values(self):
        """Verify all stability levels exist"""
        self.assertEqual(StabilityLevel.STABLE.value, "STABLE")
        self.assertEqual(StabilityLevel.EXPERIMENTAL.value, "EXPERIMENTAL")
        self.assertEqual(StabilityLevel.DEPRECATED.value, "DEPRECATED")
        self.assertEqual(StabilityLevel.INTERNAL.value, "INTERNAL")
    
    def test_stability_level_str(self):
        """Verify string conversion"""
        self.assertEqual(str(StabilityLevel.STABLE), "STABLE")
        self.assertEqual(str(StabilityLevel.EXPERIMENTAL), "EXPERIMENTAL")


class TestAPIEndpoint(unittest.TestCase):
    """Test APIEndpoint dataclass"""
    
    def test_api_endpoint_creation_minimal(self):
        """Test minimal endpoint creation"""
        endpoint = APIEndpoint(
            name="test.func",
            module="test_module",
            stability=StabilityLevel.STABLE,
            since_version="v1",
            description="Test function"
        )
        self.assertEqual(endpoint.name, "test.func")
        self.assertEqual(endpoint.stability, StabilityLevel.STABLE)
        self.assertEqual(endpoint.parameters, [])
        self.assertEqual(endpoint.examples, [])
    
    def test_api_endpoint_creation_full(self):
        """Test full endpoint creation with all fields"""
        endpoint = APIEndpoint(
            name="test.func",
            module="test_module",
            stability=StabilityLevel.STABLE,
            since_version="v1",
            description="Test function",
            parameters=[{"name": "x", "type": "int", "desc": "Input"}],
            returns="int",
            examples=["example code"],
            notes=["important note"],
            deprecation_notice="Use new_func instead",
            deprecation_scheduled="v3.0",
            migration_guide="See docs"
        )
        self.assertEqual(len(endpoint.parameters), 1)
        self.assertEqual(endpoint.returns, "int")
        self.assertEqual(endpoint.deprecation_notice, "Use new_func instead")


class TestModuleDocumentation(unittest.TestCase):
    """Test ModuleDocumentation dataclass"""
    
    def test_module_documentation_creation(self):
        """Test module documentation creation"""
        module = ModuleDocumentation(
            module_name="test_module",
            category="Test",
            stability=StabilityLevel.STABLE,
            overview="Test overview",
            getting_started="Getting started guide"
        )
        self.assertEqual(module.module_name, "test_module")
        self.assertEqual(module.category, "Test")
        self.assertEqual(module.endpoints, [])
        self.assertEqual(module.best_practices, [])
    
    def test_module_add_endpoints(self):
        """Test adding endpoints to module"""
        module = ModuleDocumentation(
            module_name="test",
            category="Test",
            stability=StabilityLevel.STABLE
        )
        endpoint = APIEndpoint(
            name="func",
            module="test",
            stability=StabilityLevel.STABLE,
            since_version="v1",
            description="Test"
        )
        module.endpoints.append(endpoint)
        self.assertEqual(len(module.endpoints), 1)


class TestDocumentationCatalog(unittest.TestCase):
    """Test main DocumentationCatalog class"""
    
    def setUp(self):
        """Create fresh catalog for each test"""
        self.catalog = DocumentationCatalog()
    
    def test_catalog_initialization(self):
        """Verify catalog initializes with all modules"""
        modules = self.catalog.get_all_modules()
        self.assertGreater(len(modules), 0)
        self.assertIn("prompt_injection", modules)
        self.assertIn("threat_intelligence", modules)
        self.assertIn("security_hardening", modules)
        self.assertIn("error_resilience", modules)
        self.assertIn("observability", modules)
        self.assertIn("adversarial_detection", modules)
        self.assertIn("feature_expansion", modules)
    
    def test_get_module_docs_existing(self):
        """Test retrieving existing module docs"""
        docs = self.catalog.get_module_docs("prompt_injection")
        self.assertIsNotNone(docs)
        self.assertEqual(docs.module_name, "prompt_injection")
        self.assertEqual(docs.category, "Core Detection")
        self.assertEqual(docs.stability, StabilityLevel.STABLE)
    
    def test_get_module_docs_nonexistent(self):
        """Test retrieving non-existent module"""
        docs = self.catalog.get_module_docs("nonexistent_module")
        self.assertIsNone(docs)
    
    def test_module_docs_have_endpoints(self):
        """Verify all modules have documented endpoints"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(
                len(docs.endpoints), 0,
                f"Module {module_name} has no documented endpoints"
            )
    
    def test_endpoints_have_required_fields(self):
        """Verify all endpoints have required documentation fields"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            for endpoint in docs.endpoints:
                self.assertIsNotNone(endpoint.name)
                self.assertIsNotNone(endpoint.module)
                self.assertIsNotNone(endpoint.stability)
                self.assertIsNotNone(endpoint.since_version)
                self.assertIsNotNone(endpoint.description)
                self.assertGreater(len(endpoint.name), 0)
                self.assertGreater(len(endpoint.description), 0)
    
    def test_stability_summary(self):
        """Test stability summary calculation"""
        summary = self.catalog.get_stability_summary()
        self.assertIn("STABLE", summary)
        self.assertIn("EXPERIMENTAL", summary)
        self.assertIn("DEPRECATED", summary)
        self.assertIn("INTERNAL", summary)
        
        total = sum(summary.values())
        self.assertGreater(total, 0)
        # Most endpoints should be STABLE
        self.assertGreater(summary["STABLE"], summary.get("EXPERIMENTAL", 0))
    
    def test_print_stability_report(self):
        """Test stability report generation (no exceptions)"""
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            self.catalog.print_stability_report()
        
        output = f.getvalue()
        self.assertIn("NEURALSHIELD-AI API STABILITY REPORT", output)
        self.assertIn("STABLE", output)
        self.assertIn("EXPERIMENTAL", output)
        self.assertIn("prompt_injection", output)
        self.assertIn("threat_intelligence", output)
    
    def test_module_has_overview(self):
        """Verify modules have overview documentation"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(
                len(docs.overview.strip()), 0,
                f"Module {module_name} missing overview"
            )
    
    def test_module_has_getting_started(self):
        """Verify modules have getting started guides"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(
                len(docs.getting_started.strip()), 0,
                f"Module {module_name} missing getting started"
            )
    
    def test_module_has_best_practices(self):
        """Verify modules have best practices"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(
                len(docs.best_practices), 0,
                f"Module {module_name} missing best practices"
            )
    
    def test_module_has_common_pitfalls(self):
        """Verify modules have common pitfalls documentation"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            self.assertGreater(
                len(docs.common_pitfalls), 0,
                f"Module {module_name} missing common pitfalls"
            )
    
    def test_experimental_endpoints_marked(self):
        """Verify experimental endpoints are properly marked"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            for endpoint in docs.endpoints:
                if endpoint.stability == StabilityLevel.EXPERIMENTAL:
                    # Experimental endpoints should have warning notes
                    has_warning = any(
                        "EXPERIMENTAL" in note or "experimental" in note.lower()
                        for note in endpoint.notes
                    )
                    self.assertTrue(
                        has_warning,
                        f"Experimental endpoint {endpoint.name} missing warning note"
                    )


class TestSingletonPattern(unittest.TestCase):
    """Test singleton catalog instance"""
    
    def test_get_documentation_catalog_returns_same_instance(self):
        """Verify singleton pattern works"""
        cat1 = get_documentation_catalog()
        cat2 = get_documentation_catalog()
        self.assertIs(cat1, cat2)
    
    def test_singleton_has_modules(self):
        """Verify singleton has populated modules"""
        catalog = get_documentation_catalog()
        self.assertGreater(len(catalog.get_all_modules()), 0)


class TestPrintApiStabilityReport(unittest.TestCase):
    """Test convenience print function"""
    
    def test_print_api_stability_report(self):
        """Test print function works without errors"""
        import io
        import contextlib
        
        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            print_api_stability_report()
        
        output = f.getvalue()
        self.assertIn("API STABILITY REPORT", output)
        self.assertIn("STABLE", output)


class TestApiStabilityMarkers(unittest.TestCase):
    """Test module-level API stability markers"""
    
    def test_api_stability_markers_exist(self):
        """Verify __api_stability__ exists"""
        self.assertIsInstance(__api_stability__, dict)
        self.assertGreater(len(__api_stability__), 0)
    
    def test_all_exports_have_stability(self):
        """Verify all exports have stability markers"""
        import documentation_api_stability_master_catalog_v30_2026_june as module
        for export in module.__all__:
            self.assertIn(
                export, __api_stability__,
                f"Export {export} missing stability marker"
            )
    
    def test_all_markers_are_valid(self):
        """Verify all stability markers are valid levels"""
        valid_markers = {"STABLE", "EXPERIMENTAL", "DEPRECATED", "INTERNAL"}
        for name, marker in __api_stability__.items():
            self.assertIn(
                marker, valid_markers,
                f"Invalid stability marker for {name}: {marker}"
            )


class TestPromptInjectionDocumentation(unittest.TestCase):
    """Specific tests for prompt injection module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("prompt_injection")
    
    def test_prompt_injection_endpoints(self):
        """Verify prompt injection endpoints documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(
            any("detect" in name for name in endpoint_names),
            "Missing detect endpoint"
        )
        self.assertTrue(
            any("analyze_chain" in name for name in endpoint_names),
            "Missing chain analysis endpoint"
        )
        self.assertTrue(
            any("decode" in name.lower() for name in endpoint_names),
            "Missing obfuscation decoder endpoint"
        )


class TestThreatIntelligenceDocumentation(unittest.TestCase):
    """Specific tests for threat intelligence module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("threat_intelligence")
    
    def test_threat_intelligence_endpoints(self):
        """Verify key TI endpoints documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(any("extract" in name for name in endpoint_names))
        self.assertTrue(any("correlate" in name for name in endpoint_names))
        self.assertTrue(any("classify" in name for name in endpoint_names))
        self.assertTrue(any("map" in name for name in endpoint_names))
    
    def test_experimental_classifier(self):
        """Verify false positive classifier is marked EXPERIMENTAL"""
        classifier = [
            e for e in self.docs.endpoints 
            if "FalsePositiveClassifier" in e.name
        ][0]
        self.assertEqual(classifier.stability, StabilityLevel.EXPERIMENTAL)


class TestSecurityHardeningDocumentation(unittest.TestCase):
    """Specific tests for security hardening module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("security_hardening")
    
    def test_security_endpoints(self):
        """Verify key security endpoints documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(any("constant_time_compare" in name for name in endpoint_names))
        self.assertTrue(any("secure_zeroize" in name for name in endpoint_names))
        self.assertTrue(any("check_rate_limit" in name for name in endpoint_names))
    
    def test_all_security_stable(self):
        """All security endpoints should be STABLE"""
        for endpoint in self.docs.endpoints:
            self.assertEqual(
                endpoint.stability, StabilityLevel.STABLE,
                f"Security endpoint {endpoint.name} should be STABLE"
            )


class TestErrorResilienceDocumentation(unittest.TestCase):
    """Specific tests for error resilience module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("error_resilience")
    
    def test_resilience_endpoints(self):
        """Verify key resilience endpoints documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(any("RetryWithBackoff" in name for name in endpoint_names))
        self.assertTrue(any("CircuitBreaker" in name for name in endpoint_names))
        self.assertTrue(any("timeout" in name for name in endpoint_names))


class TestObservabilityDocumentation(unittest.TestCase):
    """Specific tests for observability module docs"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
        self.docs = self.catalog.get_module_docs("observability")
    
    def test_observability_endpoints(self):
        """Verify key observability endpoints documented"""
        endpoint_names = [e.name for e in self.docs.endpoints]
        self.assertTrue(any("MetricsCollector" in name for name in endpoint_names))
        self.assertTrue(any("DistributedTracer" in name for name in endpoint_names))
        self.assertTrue(any("HealthCheckFramework" in name for name in endpoint_names))


class TestDocumentationQuality(unittest.TestCase):
    """Quality tests for documentation"""
    
    def setUp(self):
        self.catalog = DocumentationCatalog()
    
    def test_endpoints_have_notes_or_examples(self):
        """Verify endpoints have either notes or examples"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            for endpoint in docs.endpoints:
                has_content = len(endpoint.notes) > 0 or len(endpoint.examples) > 0
                self.assertTrue(
                    has_content,
                    f"Endpoint {endpoint.name} needs notes or examples"
                )
    
    def test_endpoint_descriptions_not_too_short(self):
        """Verify endpoint descriptions are meaningful"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            for endpoint in docs.endpoints:
                self.assertGreater(
                    len(endpoint.description), 10,
                    f"Endpoint {endpoint.name} description too short"
                )
    
    def test_since_version_format(self):
        """Verify since_version follows vN format"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            for endpoint in docs.endpoints:
                self.assertTrue(
                    endpoint.since_version.startswith("v"),
                    f"Endpoint {endpoint.name} since_version should start with 'v'"
                )
    
    def test_parameter_documentation(self):
        """Verify documented parameters have all fields"""
        for module_name in self.catalog.get_all_modules():
            docs = self.catalog.get_module_docs(module_name)
            for endpoint in docs.endpoints:
                for param in endpoint.parameters:
                    self.assertIn("name", param)
                    self.assertIn("type", param)
                    self.assertIn("desc", param)


if __name__ == "__main__":
    unittest.main(verbosity=2)
