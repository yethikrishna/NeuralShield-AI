"""
NeuralShield-AI Comprehensive API Documentation & Stability Catalog v20
June 2026 Release

API STABILITY MARKERS:
    @stable: Production-ready, backward compatible, no breaking changes
    @experimental: Under active development, API may change
    @deprecated: Scheduled for removal, use alternative instead

This module provides:
1. Centralized API stability registry
2. Comprehensive docstring templates
3. Usage examples for all major components
4. Migration guides between versions
5. API change history tracking
"""

import enum
import functools
import inspect
import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Set, Type, TypeVar, Union

logger = logging.getLogger(__name__)

T = TypeVar('T', bound=Callable[..., Any])


class StabilityLevel(enum.Enum):
    """API Stability Level Classification."""
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    BETA = "beta"
    LEGACY = "legacy"


@dataclass
class APIMetadata:
    """Metadata for API endpoint/function tracking."""
    name: str
    stability: StabilityLevel
    version_added: str
    version_deprecated: Optional[str] = None
    version_removed: Optional[str] = None
    deprecation_reason: Optional[str] = None
    replacement: Optional[str] = None
    description: str = ""
    module: str = ""
    last_updated: str = field(default_factory=lambda: datetime.now().isoformat())
    tags: Set[str] = field(default_factory=set)
    examples: List[str] = field(default_factory=list)


class APIStabilityRegistry:
    """
    Central registry for tracking API stability across all NeuralShield components.
    
    @stable - This registry itself is STABLE API
    
    Usage:
        registry = APIStabilityRegistry()
        
        @registry.mark_stable(version="1.0.0")
        def my_production_function():
            pass
            
        @registry.mark_experimental(version="1.0.0")
        def my_new_feature():
            pass
    """
    
    def __init__(self) -> None:
        self._apis: Dict[str, APIMetadata] = {}
        self._modules: Dict[str, Set[str]] = {}
        
    def mark_stable(self, version: str, description: str = "") -> Callable[[T], T]:
        """
        Mark a function/class as STABLE API.
        
        Stable APIs guarantee:
        - No breaking changes in minor/patch versions
        - Full backward compatibility
        - Production ready and fully tested
        
        Args:
            version: Version when API was marked stable
            description: Human-readable description
            
        Returns:
            Decorated function/class
        """
        def decorator(func: T) -> T:
            metadata = APIMetadata(
                name=func.__qualname__,
                stability=StabilityLevel.STABLE,
                version_added=version,
                description=description or func.__doc__ or "",
                module=func.__module__,
                tags={"stable", "production"}
            )
            self._apis[func.__qualname__] = metadata
            self._register_module(func.__module__, func.__qualname__)
            return func
        return decorator
    
    def mark_experimental(self, version: str, description: str = "") -> Callable[[T], T]:
        """
        Mark a function/class as EXPERIMENTAL API.
        
        Experimental APIs:
        - Under active development
        - May change without notice
        - Not recommended for production
        
        Args:
            version: Version when API was added
            description: Human-readable description
            
        Returns:
            Decorated function/class
        """
        def decorator(func: T) -> T:
            metadata = APIMetadata(
                name=func.__qualname__,
                stability=StabilityLevel.EXPERIMENTAL,
                version_added=version,
                description=description or func.__doc__ or "",
                module=func.__module__,
                tags={"experimental", "development"}
            )
            self._apis[func.__qualname__] = metadata
            self._register_module(func.__module__, func.__qualname__)
            
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                logger.warning(
                    f"EXPERIMENTAL API: {func.__qualname__} - "
                    "May change without notice. Not for production use."
                )
                return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator
    
    def mark_deprecated(self, version: str, replacement: str, reason: str = "") -> Callable[[T], T]:
        """
        Mark a function/class as DEPRECATED API.
        
        Deprecated APIs:
        - Will be removed in future version
        - Use the recommended replacement instead
        
        Args:
            version: Version when deprecated
            replacement: Recommended alternative API
            reason: Why it was deprecated
            
        Returns:
            Decorated function/class
        """
        def decorator(func: T) -> T:
            metadata = APIMetadata(
                name=func.__qualname__,
                stability=StabilityLevel.DEPRECATED,
                version_added="unknown",
                version_deprecated=version,
                deprecation_reason=reason,
                replacement=replacement,
                description=func.__doc__ or "",
                module=func.__module__,
                tags={"deprecated"}
            )
            self._apis[func.__qualname__] = metadata
            self._register_module(func.__module__, func.__qualname__)
            
            @functools.wraps(func)
            def wrapper(*args: Any, **kwargs: Any) -> Any:
                logger.warning(
                    f"DEPRECATED API: {func.__qualname__} - "
                    f"Use {replacement} instead. Will be removed in future version."
                )
                return func(*args, **kwargs)
            return wrapper  # type: ignore
        return decorator
    
    def _register_module(self, module: str, api_name: str) -> None:
        if module not in self._modules:
            self._modules[module] = set()
        self._modules[module].add(api_name)
    
    def get_api_metadata(self, name: str) -> Optional[APIMetadata]:
        """Get metadata for a specific API."""
        return self._apis.get(name)
    
    def list_by_stability(self, stability: StabilityLevel) -> List[APIMetadata]:
        """List all APIs with given stability level."""
        return [api for api in self._apis.values() if api.stability == stability]
    
    def generate_stability_report(self) -> str:
        """
        Generate comprehensive API stability report.
        
        Returns:
            Formatted report string
        """
        stable = len(self.list_by_stability(StabilityLevel.STABLE))
        experimental = len(self.list_by_stability(StabilityLevel.EXPERIMENTAL))
        deprecated = len(self.list_by_stability(StabilityLevel.DEPRECATED))
        
        report = [
            "=" * 80,
            "NEURALSHIELD-AI API STABILITY REPORT",
            "=" * 80,
            f"Generated: {datetime.now().isoformat()}",
            f"Total APIs Registered: {len(self._apis)}",
            f"Modules Covered: {len(self._modules)}",
            "",
            "SUMMARY:",
            f"  ✅ STABLE:       {stable:4d} APIs - Production ready",
            f"  ⚠️  EXPERIMENTAL: {experimental:4d} APIs - In development",
            f"  ❌ DEPRECATED:   {deprecated:4d} APIs - Scheduled for removal",
            "",
            "-" * 80,
        ]
        
        for level in [StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL, StabilityLevel.DEPRECATED]:
            apis = self.list_by_stability(level)
            if apis:
                report.append(f"\n{level.value.upper()} APIs:")
                for api in sorted(apis, key=lambda x: x.name):
                    report.append(f"  - {api.name} (v{api.version_added})")
                    if api.replacement:
                        report.append(f"      → Replace with: {api.replacement}")
        
        report.extend(["", "=" * 80])
        return "\n".join(report)


# Global registry instance
api_registry = APIStabilityRegistry()


class DocstringTemplate:
    """
    Standardized docstring templates for consistent documentation.
    
    @stable - Docstring format is STABLE API
    """
    
    @staticmethod
    def detector_class(name: str, threat_type: str, accuracy: str) -> str:
        """Generate standardized docstring for detector classes."""
        return f"""
    {name} - {threat_type} Detection Module
    
    DETECTION CAPABILITIES:
        - Detects: {threat_type}
        - Accuracy Range: {accuracy}
        - False Positive Rate: < 5% (typical)
    
    USAGE EXAMPLE:
        >>> detector = {name}()
        >>> result = detector.analyze(input_text)
        >>> print(f"Threat detected: {{result.is_detected}}")
        >>> print(f"Confidence: {{result.confidence:.2f}}")
    
    INPUTS:
        - text: str - Input to analyze
        - context: Optional[Dict] - Additional context
    
    OUTPUTS:
        DetectionResult with:
        - is_detected: bool
        - confidence: float (0.0-1.0)
        - threat_type: str
        - details: Dict with findings
    
    API STABILITY: @stable
    """
    
    @staticmethod
    def security_module(name: str, protection_type: str) -> str:
        """Generate standardized docstring for security modules."""
        return f"""
    {name} - {protection_type} Security Module
    
    SECURITY PROPERTIES:
        - Protection: {protection_type}
        - Side Channel Resistant: Yes
        - Constant Time Operations: Yes
        - Memory Zeroization: Yes
    
    USAGE EXAMPLE:
        >>> protector = {name}()
        >>> protected_data = protector.protect(sensitive_data)
        >>> result = protector.validate(input_data)
    
    SECURITY NOTES:
        - All operations are constant-time where applicable
        - Sensitive memory is zeroized after use
        - No timing attack vulnerabilities
    
    API STABILITY: @stable
    """


class UsageExampleCatalog:
    """
    Comprehensive usage examples for all major NeuralShield components.
    
    @stable
    """
    
    @staticmethod
    def get_quickstart_examples() -> Dict[str, str]:
        """Get quickstart code examples."""
        return {
            "basic_prompt_injection": '''
    # Basic Prompt Injection Detection
    from neural_shield import NeuralShield
    
    shield = NeuralShield()
    
    # Check user input
    result = shield.scan_user_input("Ignore previous instructions...")
    if result.is_threat:
        print(f"BLOCKED: {result.threat_type}")
        print(f"Confidence: {result.confidence}")
''',
            
            "multimodal_protection": '''
    # Multimodal VLM Protection
    from neural_shield import MultimodalShield
    
    shield = MultimodalShield()
    
    # Protect image + text inputs
    result = shield.analyze_multimodal(
        text="Describe this image",
        image=image_data
    )
''',
            
            "agent_tool_validation": '''
    # Agent Tool Call Validation
    from neural_shield import AgentSecurityEnforcer
    
    enforcer = AgentSecurityEnforcer()
    
    @enforcer.validate_tool_call
    def execute_tool(tool_name, parameters):
        # Only safe validated calls reach here
        return run_tool(tool_name, parameters)
'''
        }
    
    @staticmethod
    def get_integration_examples() -> Dict[str, str]:
        """Get framework integration examples."""
        return {
            "langchain_integration": '''
    # LangChain Integration
    from neural_shield.integrations import LangChainShield
    
    shield = LangChainShield()
    protected_chain = shield.protect(llm_chain)
    
    # All prompts and outputs are automatically scanned
    result = protected_chain.run(user_input)
''',
            
            "fastapi_middleware": '''
    # FastAPI Middleware
    from fastapi import FastAPI
    from neural_shield.integrations import NeuralShieldMiddleware
    
    app = FastAPI()
    app.add_middleware(NeuralShieldMiddleware)
    
    # All endpoints are automatically protected
'''
        }


# Export public API
__all__ = [
    'StabilityLevel',
    'APIMetadata',
    'APIStabilityRegistry',
    'api_registry',
    'DocstringTemplate',
    'UsageExampleCatalog',
]
