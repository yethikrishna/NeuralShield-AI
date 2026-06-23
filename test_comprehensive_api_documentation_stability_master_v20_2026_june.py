"""
Test suite for Comprehensive API Documentation & Stability Catalog v20
June 2026 Release

Tests verify:
1. API stability registry functionality
2. Docstring template generation
3. Usage example catalog
4. Stability report generation
"""

import pytest
import logging
from neural_shield.comprehensive_api_documentation_stability_master_v20_2026_june import (
    StabilityLevel,
    APIMetadata,
    APIStabilityRegistry,
    api_registry,
    DocstringTemplate,
    UsageExampleCatalog,
)


class TestStabilityLevel:
    """Test StabilityLevel enum."""
    
    def test_stability_level_values(self):
        """Verify all stability levels exist."""
        assert StabilityLevel.STABLE.value == "stable"
        assert StabilityLevel.EXPERIMENTAL.value == "experimental"
        assert StabilityLevel.DEPRECATED.value == "deprecated"
        assert StabilityLevel.BETA.value == "beta"
        assert StabilityLevel.LEGACY.value == "legacy"


class TestAPIMetadata:
    """Test APIMetadata dataclass."""
    
    def test_metadata_creation(self):
        """Test basic metadata creation."""
        metadata = APIMetadata(
            name="test_func",
            stability=StabilityLevel.STABLE,
            version_added="1.0.0",
            description="Test function"
        )
        assert metadata.name == "test_func"
        assert metadata.stability == StabilityLevel.STABLE
        assert metadata.version_added == "1.0.0"
    
    def test_metadata_with_deprecation(self):
        """Test metadata with deprecation info."""
        metadata = APIMetadata(
            name="old_func",
            stability=StabilityLevel.DEPRECATED,
            version_added="0.5.0",
            version_deprecated="1.0.0",
            replacement="new_func",
            deprecation_reason="Better implementation available"
        )
        assert metadata.replacement == "new_func"
        assert metadata.version_deprecated == "1.0.0"


class TestAPIStabilityRegistry:
    """Test APIStabilityRegistry functionality."""
    
    def setup_method(self):
        """Fresh registry for each test."""
        self.registry = APIStabilityRegistry()
    
    def test_mark_stable(self):
        """Test marking API as stable."""
        @self.registry.mark_stable(version="1.0.0")
        def stable_func():
            return "ok"
        
        result = stable_func()
        assert result == "ok"
        
        # Registry should have at least one stable API
        stable_apis = self.registry.list_by_stability(StabilityLevel.STABLE)
        assert len(stable_apis) >= 1
        assert stable_apis[0].stability == StabilityLevel.STABLE
    
    def test_mark_experimental(self, caplog):
        """Test marking API as experimental."""
        @self.registry.mark_experimental(version="1.0.0")
        def experimental_func():
            return "ok"
        
        with caplog.at_level(logging.WARNING):
            result = experimental_func()
        
        assert result == "ok"
        assert "EXPERIMENTAL API" in caplog.text
        
        # Registry should have at least one experimental API
        experimental_apis = self.registry.list_by_stability(StabilityLevel.EXPERIMENTAL)
        assert len(experimental_apis) >= 1
        assert experimental_apis[0].stability == StabilityLevel.EXPERIMENTAL
    
    def test_mark_deprecated(self, caplog):
        """Test marking API as deprecated."""
        @self.registry.mark_deprecated(version="1.0.0", replacement="new_func")
        def deprecated_func():
            return "ok"
        
        with caplog.at_level(logging.WARNING):
            result = deprecated_func()
        
        assert result == "ok"
        assert "DEPRECATED API" in caplog.text
        assert "new_func" in caplog.text
        
        # Registry should have at least one deprecated API
        deprecated_apis = self.registry.list_by_stability(StabilityLevel.DEPRECATED)
        assert len(deprecated_apis) >= 1
        assert deprecated_apis[0].stability == StabilityLevel.DEPRECATED
    
    def test_list_by_stability(self):
        """Test listing APIs by stability level."""
        @self.registry.mark_stable(version="1.0.0")
        def func1(): pass
        
        @self.registry.mark_stable(version="1.0.0")
        def func2(): pass
        
        @self.registry.mark_experimental(version="1.0.0")
        def func3(): pass
        
        stable = self.registry.list_by_stability(StabilityLevel.STABLE)
        experimental = self.registry.list_by_stability(StabilityLevel.EXPERIMENTAL)
        
        assert len(stable) == 2
        assert len(experimental) == 1
    
    def test_generate_stability_report(self):
        """Test stability report generation."""
        @self.registry.mark_stable(version="1.0.0")
        def func1(): pass
        
        report = self.registry.generate_stability_report()
        
        assert "NEURALSHIELD-AI API STABILITY REPORT" in report
        assert "STABLE" in report
        assert "EXPERIMENTAL" in report
        assert "DEPRECATED" in report
        assert "Total APIs Registered" in report
    
    def test_get_api_metadata_not_found(self):
        """Test getting non-existent metadata."""
        metadata = self.registry.get_api_metadata("nonexistent")
        assert metadata is None


class TestDocstringTemplate:
    """Test DocstringTemplate generation."""
    
    def test_detector_class_template(self):
        """Test detector class docstring template."""
        docstring = DocstringTemplate.detector_class(
            "PromptInjectionDetector",
            "Prompt Injection Attacks",
            "95-99%"
        )
        
        assert "PromptInjectionDetector" in docstring
        assert "Prompt Injection Attacks" in docstring
        assert "95-99%" in docstring
        assert "USAGE EXAMPLE:" in docstring
        assert "INPUTS:" in docstring
        assert "OUTPUTS:" in docstring
        assert "API STABILITY:" in docstring
    
    def test_security_module_template(self):
        """Test security module docstring template."""
        docstring = DocstringTemplate.security_module(
            "MemoryProtector",
            "Secure Memory Management"
        )
        
        assert "MemoryProtector" in docstring
        assert "Secure Memory Management" in docstring
        assert "SECURITY PROPERTIES:" in docstring
        assert "Side Channel Resistant" in docstring
        assert "Constant Time Operations" in docstring


class TestUsageExampleCatalog:
    """Test UsageExampleCatalog."""
    
    def test_get_quickstart_examples(self):
        """Test quickstart examples."""
        examples = UsageExampleCatalog.get_quickstart_examples()
        
        assert "basic_prompt_injection" in examples
        assert "multimodal_protection" in examples
        assert "agent_tool_validation" in examples
        
        # Verify examples contain valid code
        assert "from neural_shield import" in examples["basic_prompt_injection"]
        assert "NeuralShield()" in examples["basic_prompt_injection"]
    
    def test_get_integration_examples(self):
        """Test integration examples."""
        examples = UsageExampleCatalog.get_integration_examples()
        
        assert "langchain_integration" in examples
        assert "fastapi_middleware" in examples
        
        assert "LangChainShield" in examples["langchain_integration"]
        assert "FastAPI" in examples["fastapi_middleware"]


class TestGlobalRegistry:
    """Test global registry instance."""
    
    def test_global_registry_exists(self):
        """Verify global registry is instantiated."""
        assert api_registry is not None
        assert isinstance(api_registry, APIStabilityRegistry)


class TestBackwardCompatibility:
    """Verify no breakage to existing patterns."""
    
    def setup_method(self):
        """Fresh registry for each test."""
        self.registry = APIStabilityRegistry()
    
    def test_decorated_function_preserves_signature(self):
        """Test decorated functions work the same."""
        @self.registry.mark_stable(version="1.0.0")
        def add(a, b):
            return a + b
        
        assert add(2, 3) == 5
        assert add.__name__ == "add"
    
    def test_decorated_class_works(self):
        """Test class decoration."""
        @self.registry.mark_stable(version="1.0.0")
        class TestClass:
            def method(self):
                return "test"
        
        instance = TestClass()
        assert instance.method() == "test"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
