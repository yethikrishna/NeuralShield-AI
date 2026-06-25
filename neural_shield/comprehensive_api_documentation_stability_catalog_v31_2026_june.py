"""
NeuralShield-AI Comprehensive API Documentation & Stability Catalog V31
DIMENSION F: Documentation & API Stability

STABILITY MARKERS:
- @stable: API is frozen, backward compatible guaranteed
- @experimental: API may change, use with caution
- @deprecated: API will be removed in future version

This module provides:
1. Comprehensive docstrings with usage examples
2. API stability markers for all public interfaces
3. Version compatibility matrix
4. Migration guides between versions
5. Type hints and parameter validation documentation

ADD-ONLY PHILOSOPHY: This module wraps existing functionality,
never modifies core production code. All instrumentation is OPT-IN.
"""

import typing
from typing import Any, Callable, Dict, List, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import functools
import inspect


class StabilityLevel(Enum):
    """API Stability Level classification."""
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    INTERNAL = "internal"


@dataclass
class APIDocumentation:
    """Documentation metadata for a single API endpoint."""
    function_name: str
    stability: StabilityLevel
    version_added: str
    version_deprecated: Optional[str] = None
    deprecation_scheduled_removal: Optional[str] = None
    description: str = ""
    usage_example: str = ""
    parameters: Dict[str, str] = field(default_factory=dict)
    return_value: str = ""
    exceptions: List[str] = field(default_factory=list)
    compatibility_notes: List[str] = field(default_factory=list)
    migration_guide: str = ""


@dataclass
class VersionCompatibility:
    """Version compatibility matrix entry."""
    module_name: str
    minimum_supported_version: str
    recommended_version: str
    breaking_changes: Dict[str, List[str]] = field(default_factory=dict)
    backward_compatible: bool = True


def stable_api(version_added: str = "1.0.0"):
    """
    Decorator marking an API as STABLE.
    
    Stable APIs guarantee:
    - No breaking changes in minor/patch versions
    - Backward compatibility maintained
    - Deprecation warnings issued at least 2 versions before removal
    
    Args:
        version_added: Version when this API was first introduced
    
    Usage:
        @stable_api(version_added="2.1.0")
        def my_stable_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._stability = StabilityLevel.STABLE
        wrapper._version_added = version_added
        wrapper._api_documented = True
        return wrapper
    return decorator


def experimental_api(version_added: str = "1.0.0"):
    """
    Decorator marking an API as EXPERIMENTAL.
    
    Experimental APIs may:
    - Change signature without warning
    - Be removed without deprecation cycle
    - Have incomplete test coverage
    
    Args:
        version_added: Version when this API was first introduced
    
    Usage:
        @experimental_api(version_added="2.3.0")
        def my_experimental_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            return func(*args, **kwargs)
        wrapper._stability = StabilityLevel.EXPERIMENTAL
        wrapper._version_added = version_added
        wrapper._api_documented = True
        return wrapper
    return decorator


def deprecated_api(version_deprecated: str, removal_version: str, replacement: str = ""):
    """
    Decorator marking an API as DEPRECATED.
    
    Deprecated APIs will:
    - Issue deprecation warnings on use
    - Be removed in the specified version
    - Have recommended replacement documented
    
    Args:
        version_deprecated: Version when deprecation started
        removal_version: Version when API will be removed
        replacement: Recommended replacement function/approach
    
    Usage:
        @deprecated_api(
            version_deprecated="2.2.0",
            removal_version="3.0.0",
            replacement="new_function()"
        )
        def my_old_function():
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            import warnings
            warnings.warn(
                f"Function {func.__name__} is deprecated since {version_deprecated}. "
                f"Will be removed in {removal_version}. "
                f"Use {replacement} instead.",
                DeprecationWarning,
                stacklevel=2
            )
            return func(*args, **kwargs)
        wrapper._stability = StabilityLevel.DEPRECATED
        wrapper._version_deprecated = version_deprecated
        wrapper._removal_version = removal_version
        wrapper._api_documented = True
        return wrapper
    return decorator


class NeuralShieldAPICatalog:
    """
    Comprehensive API Catalog for NeuralShield-AI.
    
    This catalog documents all public APIs with their stability levels,
    version information, and usage examples.
    
    STABLE MODULES (guaranteed backward compatible):
    - adversarial_prompt_anomaly_detector
    - context_aware_prompt_injection_defender
    - constitutional_classifier
    - ensemble_threat_detector_weighted_voting
    
    EXPERIMENTAL MODULES (subject to change):
    - cross_modal_prompt_injection_detector
    - behavioral_biometrics_anomaly_detector
    - agentic_ai_security_enforcer
    """
    
    def __init__(self):
        self.api_docs: Dict[str, APIDocumentation] = {}
        self.compatibility_matrix: List[VersionCompatibility] = []
        self._initialize_catalog()
    
    def _initialize_catalog(self):
        """Initialize the complete API documentation catalog."""
        
        # STABLE APIs
        self._register_api(
            APIDocumentation(
                function_name="adversarial_prompt_anomaly_detector.detect_anomaly",
                stability=StabilityLevel.STABLE,
                version_added="1.0.0",
                description="Detects anomalous patterns in prompt inputs that may indicate injection attacks.",
                usage_example="""
from neural_shield.adversarial_prompt_anomaly_detector_2026_june import AdversarialPromptAnomalyDetector

detector = AdversarialPromptAnomalyDetector()
result = detector.detect_anomaly("User prompt text here")
if result.is_anomalous:
    print(f"Threat detected: {result.confidence:.2f}")
                """,
                parameters={
                    "prompt": "str - Input text to analyze",
                    "threshold": "float - Detection confidence threshold (default: 0.7)",
                    "return_details": "bool - Whether to return detailed analysis (default: True)"
                },
                return_value="AnomalyDetectionResult with is_anomalous, confidence, and details",
                exceptions=["ValueError - if prompt is empty", "TypeError - if threshold out of range"],
                compatibility_notes=[
                    "Fully backward compatible since v1.0.0",
                    "No breaking changes planned through v3.x"
                ]
            )
        )
        
        self._register_api(
            APIDocumentation(
                function_name="context_aware_prompt_injection_defender.scan_for_injection",
                stability=StabilityLevel.STABLE,
                version_added="1.2.0",
                description="Context-aware prompt injection detection with conversation history analysis.",
                usage_example="""
from neural_shield.context_aware_prompt_injection_defender_2026_june import ContextAwarePromptInjectionDefender

defender = ContextAwarePromptInjectionDefender()
result = defender.scan_for_injection(
    current_prompt="User input",
    conversation_history=history
)
                """,
                parameters={
                    "current_prompt": "str - Current user input",
                    "conversation_history": "List[Dict] - Previous messages",
                    "context_window": "int - Messages to consider for context"
                },
                return_value="InjectionScanResult with risk assessment",
                exceptions=["ValueError - invalid history format"],
                compatibility_notes=["Context window parameter added in v1.5.0"]
            )
        )
        
        self._register_api(
            APIDocumentation(
                function_name="constitutional_classifier.classify_content",
                stability=StabilityLevel.STABLE,
                version_added="1.0.0",
                description="Classifies content against constitutional AI safety principles.",
                usage_example="""
from neural_shield.constitutional_classifier_2026 import ConstitutionalClassifier

classifier = ConstitutionalClassifier()
result = classifier.classify_content("Text to evaluate")
print(f"Policy violations: {result.violations}")
                """,
                parameters={
                    "content": "str - Text content to classify",
                    "policy_set": "str - Which policy set to use (default: 'standard')"
                },
                return_value="ClassificationResult with violations and scores",
                exceptions=["ValueError - unknown policy set"]
            )
        )
        
        # EXPERIMENTAL APIs
        self._register_api(
            APIDocumentation(
                function_name="cross_modal_prompt_injection_detector.detect_cross_modal_injection",
                stability=StabilityLevel.EXPERIMENTAL,
                version_added="2.1.0",
                description="Detects prompt injection attacks across text, image, and audio modalities.",
                usage_example="""
from neural_shield.cross_modal_prompt_injection_detector_2026_june import CrossModalDetector

detector = CrossModalDetector()
result = detector.detect_cross_modal_injection(
    text_input="text",
    image_features=features
)
                """,
                parameters={
                    "text_input": "Optional[str] - Text component",
                    "image_features": "Optional[Tensor] - Image embeddings",
                    "audio_features": "Optional[Tensor] - Audio embeddings"
                },
                return_value="CrossModalDetectionResult",
                exceptions=["ValueError - no modalities provided"],
                compatibility_notes=[
                    "EXPERIMENTAL: API signature may change",
                    "Multimodal fusion algorithm being refined"
                ]
            )
        )
        
        self._register_api(
            APIDocumentation(
                function_name="behavioral_biometrics_anomaly_detector.analyze_behavior_pattern",
                stability=StabilityLevel.EXPERIMENTAL,
                version_added="2.3.0",
                description="Analyzes user interaction patterns for behavioral anomalies.",
                usage_example="""
from neural_shield.behavioral_biometrics_anomaly_detector_2026_june import BehavioralBiometricsDetector

detector = BehavioralBiometricsDetector()
result = detector.analyze_behavior_pattern(interaction_events)
                """,
                parameters={
                    "interaction_events": "List[Dict] - Timed interaction events"
                },
                return_value="BehaviorAnalysisResult",
                compatibility_notes=["Event format still being standardized"]
            )
        )
        
        # DEPRECATED APIs
        self._register_api(
            APIDocumentation(
                function_name="legacy_threat_scanner.scan",
                stability=StabilityLevel.DEPRECATED,
                version_added="0.9.0",
                version_deprecated="2.0.0",
                deprecation_scheduled_removal="3.0.0",
                description="Legacy single-threat scanner (DEPRECATED).",
                migration_guide="""
REPLACEMENT: Use ensemble_threat_detector_weighted_voting instead

Before (deprecated):
from neural_shield.legacy_threat_scanner import scan
result = scan(prompt)

After (recommended):
from neural_shield.ensemble_threat_detector_weighted_voting_2026_june import EnsembleThreatDetector
detector = EnsembleThreatDetector()
result = detector.detect_threats(prompt)
                """
            )
        )
        
        # Initialize compatibility matrix
        self.compatibility_matrix.extend([
            VersionCompatibility(
                module_name="core_detection_modules",
                minimum_supported_version="1.0.0",
                recommended_version="2.5.0",
                backward_compatible=True,
                breaking_changes={}
            ),
            VersionCompatibility(
                module_name="multimodal_modules",
                minimum_supported_version="2.1.0",
                recommended_version="2.5.0",
                backward_compatible=True,
                breaking_changes={
                    "2.0.0 -> 2.1.0": [
                        "CrossModalDetector API introduced",
                        "Image feature format standardized"
                    ]
                }
            )
        ])
    
    def _register_api(self, doc: APIDocumentation):
        """Register an API documentation entry."""
        self.api_docs[doc.function_name] = doc
    
    @stable_api(version_added="2.5.0")
    def get_api_documentation(self, function_name: str) -> Optional[APIDocumentation]:
        """
        Retrieve documentation for a specific API.
        
        Args:
            function_name: Fully qualified function name
            
        Returns:
            APIDocumentation object if found, None otherwise
        """
        return self.api_docs.get(function_name)
    
    @stable_api(version_added="2.5.0")
    def list_apis_by_stability(self, stability: StabilityLevel) -> List[str]:
        """
        List all APIs with a specific stability level.
        
        Args:
            stability: StabilityLevel to filter by
            
        Returns:
            List of function names matching the stability level
        """
        return [
            name for name, doc in self.api_docs.items()
            if doc.stability == stability
        ]
    
    @stable_api(version_added="2.5.0")
    def generate_documentation_report(self) -> str:
        """
        Generate a comprehensive human-readable documentation report.
        
        Returns:
            Formatted documentation report as string
        """
        lines = ["=" * 80]
        lines.append("NEURALSHIELD-AI API DOCUMENTATION CATALOG V31")
        lines.append("=" * 80)
        lines.append("")
        
        for stability in [StabilityLevel.STABLE, StabilityLevel.EXPERIMENTAL, StabilityLevel.DEPRECATED]:
            apis = self.list_apis_by_stability(stability)
            lines.append(f"[{stability.value.upper()} APIs] ({len(apis)} total)")
            lines.append("-" * 80)
            for api_name in apis:
                doc = self.api_docs[api_name]
                lines.append(f"  • {api_name}")
                lines.append(f"    Added: v{doc.version_added}")
                if doc.version_deprecated:
                    lines.append(f"    Deprecated: v{doc.version_deprecated}")
                    lines.append(f"    Removal scheduled: v{doc.deprecation_scheduled_removal}")
                lines.append(f"    Description: {doc.description[:100]}...")
                lines.append("")
            lines.append("")
        
        return "\n".join(lines)
    
    def __repr__(self) -> str:
        return f"NeuralShieldAPICatalog(apis={len(self.api_docs)})"


# Global catalog instance
_api_catalog: Optional[NeuralShieldAPICatalog] = None


@stable_api(version_added="2.5.0")
def get_api_catalog() -> NeuralShieldAPICatalog:
    """
    Get the global NeuralShield API catalog instance.
    
    Returns:
        Initialized NeuralShieldAPICatalog singleton
    """
    global _api_catalog
    if _api_catalog is None:
        _api_catalog = NeuralShieldAPICatalog()
    return _api_catalog


@stable_api(version_added="2.5.0")
def print_api_stability_summary():
    """Print a summary of API stability levels to console."""
    catalog = get_api_catalog()
    stable = len(catalog.list_apis_by_stability(StabilityLevel.STABLE))
    experimental = len(catalog.list_apis_by_stability(StabilityLevel.EXPERIMENTAL))
    deprecated = len(catalog.list_apis_by_stability(StabilityLevel.DEPRECATED))
    
    print("=" * 60)
    print("NEURALSHIELD-AI API STABILITY SUMMARY V31")
    print("=" * 60)
    print(f"  STABLE:       {stable:3d} APIs (backward compatible)")
    print(f"  EXPERIMENTAL: {experimental:3d} APIs (subject to change)")
    print(f"  DEPRECATED:   {deprecated:3d} APIs (being removed)")
    print("=" * 60)
    print(f"  TOTAL:        {stable + experimental + deprecated:3d} APIs documented")
    print("=" * 60)


if __name__ == "__main__":
    print_api_stability_summary()
    print("\n" + get_api_catalog().generate_documentation_report())
