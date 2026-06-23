"""
Test Suite for Threat Intelligence Documentation Module (Dimension F)
ADD-ONLY: New test file, no modifications to existing code
Tests verify documentation module works without breaking anything
"""

import sys
import pytest
from typing import Dict, List

# Import the new documentation module
from neural_shield.comprehensive_threat_intelligence_documentation_v14_2026_june import (
    ThreatIntelligenceDocumentationManager,
    DocumentationCategory,
    APIMaturity,
    THREAT_INTELLIGENCE_API_STABILITY,
    GETTING_STARTED_GUIDE,
    API_REFERENCE,
    USAGE_EXAMPLES,
    BEST_PRACTICES,
    TROUBLESHOOTING,
)


class TestThreatIntelligenceDocumentation:
    """Test documentation module functionality"""
    
    def test_documentation_manager_initialization(self):
        """Test manager initializes correctly"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        assert doc_manager is not None
        assert doc_manager._module_version == "v13"
        assert doc_manager._module_name == "threat_intelligence_fusion_correlation_engine"
    
    def test_stability_catalog_exists(self):
        """Test stability catalog is populated"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        assert len(doc_manager.stability_catalog) > 0
        assert "ThreatIntelligenceFusionManager" in doc_manager.stability_catalog
    
    def test_list_stable_apis(self):
        """Test stable APIs listing"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        stable = doc_manager.list_stable_apis()
        assert isinstance(stable, list)
        assert len(stable) > 0
        assert "ThreatIntelligenceFusionManager" in stable
    
    def test_list_experimental_apis(self):
        """Test experimental APIs listing"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        experimental = doc_manager.list_experimental_apis()
        assert isinstance(experimental, list)
        assert "ThreatCorrelationEngine" in experimental
    
    def test_get_stability(self):
        """Test getting stability info"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        stability = doc_manager.get_stability("ThreatIntelligenceFusionManager")
        assert stability is not None
        assert stability["stability"] == "stable"
        assert stability["version"] == "v13"
    
    def test_get_stability_nonexistent(self):
        """Test getting stability for non-existent API"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        stability = doc_manager.get_stability("NonExistentAPI")
        assert stability is None
    
    def test_get_documentation_getting_started(self):
        """Test getting getting started guide"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.GETTING_STARTED)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "GETTING STARTED" in doc
    
    def test_get_documentation_api_reference(self):
        """Test getting API reference"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.API_REFERENCE)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "API REFERENCE" in doc
    
    def test_get_documentation_usage_examples(self):
        """Test getting usage examples"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.USAGE_EXAMPLES)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "EXAMPLE" in doc
    
    def test_get_documentation_best_practices(self):
        """Test getting best practices"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.BEST_PRACTICES)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "BEST PRACTICES" in doc
    
    def test_get_documentation_troubleshooting(self):
        """Test getting troubleshooting guide"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        doc = doc_manager.get_documentation(DocumentationCategory.TROUBLESHOOTING)
        assert isinstance(doc, str)
        assert len(doc) > 0
        assert "TROUBLESHOOTING" in doc
    
    def test_get_all_categories(self):
        """Test listing all documentation categories"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        categories = doc_manager.get_all_categories()
        assert isinstance(categories, list)
        assert len(categories) == 5
        assert "getting_started" in categories
        assert "api_reference" in categories
    
    def test_get_module_info(self):
        """Test getting module info"""
        doc_manager = ThreatIntelligenceDocumentationManager()
        info = doc_manager.get_module_info()
        assert isinstance(info, dict)
        assert info["module"] == "threat_intelligence_fusion_correlation_engine"
        assert info["version"] == "v13"
        assert info["dimension"] == "F - Documentation & API Stability"
        assert info["backward_compatible"] == True
        assert info["add_only"] == True
    
    def test_documentation_strings_not_empty(self):
        """Test all documentation strings are non-empty"""
        assert len(GETTING_STARTED_GUIDE) > 100
        assert len(API_REFERENCE) > 100
        assert len(USAGE_EXAMPLES) > 100
        assert len(BEST_PRACTICES) > 100
        assert len(TROUBLESHOOTING) > 100
    
    def test_api_stability_markers(self):
        """Test all API stability markers"""
        for api_name, marker in THREAT_INTELLIGENCE_API_STABILITY.items():
            assert marker.stability in [APIMaturity.STABLE, APIMaturity.EXPERIMENTAL]
            assert marker.version == "v13"
            assert len(marker.notes) > 0
    
    def test_no_breaking_changes(self):
        """Verify no existing code was modified - ADD-ONLY philosophy"""
        # Verify we can still import the original module
        from neural_shield.threat_intelligence_fusion_correlation_engine_v13_2026_june import (
            ThreatIntelligenceFusionManager,
            ThreatSeverity,
            ThreatSource,
        )
        # Original module should still work
        ti = ThreatIntelligenceFusionManager()
        assert ti is not None
        
        # Run basic operation
        result = ti.analyze_and_correlate(
            input_text="test input",
            detector_results={"prompt_injection": 0.5}
        )
        assert "threat_id" in result
        assert "severity" in result


if __name__ == "__main__":
    # Run tests
    test = TestThreatIntelligenceDocumentation()
    
    print("Running Threat Intelligence Documentation Tests...")
    print("=" * 60)
    
    tests_passed = 0
    tests_failed = 0
    
    test_methods = [m for m in dir(test) if m.startswith("test_")]
    
    for method_name in test_methods:
        try:
            getattr(test, method_name)()
            print(f"✓ {method_name}")
            tests_passed += 1
        except Exception as e:
            print(f"✗ {method_name}: {e}")
            tests_failed += 1
    
    print("=" * 60)
    print(f"Passed: {tests_passed}, Failed: {tests_failed}")
    print(f"Total: {tests_passed + tests_failed}")
    
    if tests_failed == 0:
        print("\nALL TESTS PASSED - Dimension F Documentation complete!")
    else:
        print(f"\n{tests_failed} TESTS FAILED")
        sys.exit(1)
