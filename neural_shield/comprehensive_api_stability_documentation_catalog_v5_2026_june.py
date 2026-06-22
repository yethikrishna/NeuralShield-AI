"""
NeuralShield-AI Comprehensive API Stability & Documentation Catalog V5
Dimension F: Documentation & API Stability (ADD-ONLY, NO CODE LOGIC CHANGES)
========================================================================
API STABILITY MARKERS:
- @stable: Production-ready, backward-compatible guaranteed
- @experimental: Active development, breaking changes possible
- @deprecated: Scheduled for removal, use alternatives
- @internal: Not for public consumption
USAGE EXAMPLES + DOCSTRINGS for all major modules
"""
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
import functools
import inspect


class StabilityLevel(Enum):
    STABLE = "stable"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"
    INTERNAL = "internal"


@dataclass
class APIStabilityInfo:
    module_name: str
    class_name: Optional[str]
    method_name: Optional[str]
    stability: StabilityLevel
    version_introduced: str
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None
    alternative_api: Optional[str] = None
    description: str = ""


def stable(version: str = "2026.06"):
    """Mark API as STABLE - production ready, backward compatible guaranteed."""
    def decorator(func_or_class):
        @functools.wraps(func_or_class)
        def wrapper(*args, **kwargs):
            return func_or_class(*args, **kwargs)
        wrapper._stability = StabilityLevel.STABLE
        wrapper._version = version
        return wrapper
    return decorator


def experimental(version: str = "2026.06"):
    """Mark API as EXPERIMENTAL - active development, breaking changes possible."""
    def decorator(func_or_class):
        @functools.wraps(func_or_class)
        def wrapper(*args, **kwargs):
            return func_or_class(*args, **kwargs)
        wrapper._stability = StabilityLevel.EXPERIMENTAL
        wrapper._version = version
        return wrapper
    return decorator


def deprecated(version: str, removal_version: str, alternative: str = None):
    """Mark API as DEPRECATED - scheduled for removal."""
    def decorator(func_or_class):
        @functools.wraps(func_or_class)
        def wrapper(*args, **kwargs):
            import warnings
            msg = f"Deprecated since {version}, will be removed in {removal_version}."
            if alternative:
                msg += f" Use {alternative} instead."
            warnings.warn(msg, DeprecationWarning, stacklevel=2)
            return func_or_class(*args, **kwargs)
        wrapper._stability = StabilityLevel.DEPRECATED
        wrapper._version = version
        wrapper._removal = removal_version
        wrapper._alternative = alternative
        return wrapper
    return decorator


class NeuralShieldAPIDocumentationCatalog:
    """
    Comprehensive API Documentation & Stability Catalog for NeuralShield-AI.
    DIMENSION F: Pure documentation, NO production code logic changes.
    USAGE EXAMPLES AND DOCSTRINGS ONLY.
    """

    def __init__(self):
        self.api_registry: List[APIStabilityInfo] = []
        self._build_catalog()

    def _build_catalog(self):
        """Build complete API documentation catalog."""
        # === CORE DETECTION MODULES (STABLE) ===
        self._register(APIStabilityInfo(
            module_name="prompt_injection_detector",
            class_name="PromptInjectionDetector",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.01",
            description="Core prompt injection detection with semantic analysis."
        ))

        self._register(APIStabilityInfo(
            module_name="jailbreak_detector",
            class_name="AdvancedJailbreakDetector",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.02",
            description="Multi-modal jailbreak attempt detection."
        ))

        self._register(APIStabilityInfo(
            module_name="constitutional_classifier",
            class_name="ConstitutionalClassifier",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.01",
            description="Policy compliance and content safety classification."
        ))

        # === INPUT PROCESSING (STABLE) ===
        self._register(APIStabilityInfo(
            module_name="input_purification",
            class_name="InputPurification",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.01",
            description="Input sanitization and poisoning detection."
        ))

        self._register(APIStabilityInfo(
            module_name="output_sanitizer",
            class_name="OutputSanitizerPIIRedactor",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.02",
            description="PII redaction and output content sanitization."
        ))

        # === ADVERSARIAL DEFENSE (STABLE) ===
        self._register(APIStabilityInfo(
            module_name="adversarial_prompt_anomaly_detector",
            class_name="AdversarialPromptAnomalyDetector",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.03",
            description="Anomaly-based adversarial prompt detection."
        ))

        self._register(APIStabilityInfo(
            module_name="adversarial_embedding_perturbation_detector",
            class_name="AdversarialEmbeddingPerturbationDetector",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.04",
            description="Embedding space perturbation and attack detection."
        ))

        # === AGENT SAFETY (EXPERIMENTAL) ===
        self._register(APIStabilityInfo(
            module_name="agent_memory_safety_guardian",
            class_name="AgentMemorySafetyGuardian",
            method_name=None,
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2026.05",
            description="Agent memory poisoning and integrity protection."
        ))

        self._register(APIStabilityInfo(
            module_name="agent_tool_call_validator",
            class_name="AgentToolCallValidator",
            method_name=None,
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2026.05",
            description="Agent tool call safety validation and sandboxing."
        ))

        self._register(APIStabilityInfo(
            module_name="llm_agent_thought_process_auditor",
            class_name="LLMAgentThoughtProcessAuditor",
            method_name=None,
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2026.06",
            description="Chain-of-thought integrity monitoring and auditing."
        ))

        # === MULTIMODAL (EXPERIMENTAL) ===
        self._register(APIStabilityInfo(
            module_name="cross_modal_prompt_injection_detector",
            class_name="CrossModalPromptInjectionDetector",
            method_name=None,
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2026.05",
            description="Multi-modal (image+text) prompt injection detection."
        ))

        self._register(APIStabilityInfo(
            module_name="multimodal_prompt_injection_detector",
            class_name="MultimodalPromptInjectionDetector",
            method_name=None,
            stability=StabilityLevel.EXPERIMENTAL,
            version_introduced="2026.06",
            description="VLM and multi-modal threat detection."
        ))

        # === SECURITY HARDENING (STABLE) ===
        self._register(APIStabilityInfo(
            module_name="context_boundary_isolator",
            class_name="ContextBoundaryIsolator",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.04",
            description="System prompt boundary isolation and protection."
        ))

        self._register(APIStabilityInfo(
            module_name="context_window_protector",
            class_name="ContextWindowProtector",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.04",
            description="Context window overflow and injection protection."
        ))

        # === OBSERVABILITY (STABLE) ===
        self._register(APIStabilityInfo(
            module_name="observability_engine",
            class_name="ObservabilityEngine",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.04",
            description="Structured logging and metrics collection."
        ))

        # === ERROR RESILIENCE (STABLE) ===
        self._register(APIStabilityInfo(
            module_name="error_resilience_engine",
            class_name="ErrorResilienceEngine",
            method_name=None,
            stability=StabilityLevel.STABLE,
            version_introduced="2026.05",
            description="Retry, backoff, timeout, and circuit breaker patterns."
        ))

    def _register(self, info: APIStabilityInfo):
        self.api_registry.append(info)

    def get_stable_apis(self) -> List[APIStabilityInfo]:
        """Get all STABLE APIs for production use."""
        return [api for api in self.api_registry if api.stability == StabilityLevel.STABLE]

    def get_experimental_apis(self) -> List[APIStabilityInfo]:
        """Get all EXPERIMENTAL APIs for evaluation."""
        return [api for api in self.api_registry if api.stability == StabilityLevel.EXPERIMENTAL]

    def generate_documentation_summary(self) -> Dict[str, Any]:
        """Generate human-readable documentation summary."""
        return {
            "total_apis_documented": len(self.api_registry),
            "stable_count": len(self.get_stable_apis()),
            "experimental_count": len(self.get_experimental_apis()),
            "modules_covered": len(set(api.module_name for api in self.api_registry)),
            "catalog_version": "v5",
            "dimension": "F - Documentation & API Stability"
        }

    def get_usage_examples(self) -> Dict[str, str]:
        """
        USAGE EXAMPLES - Comprehensive quickstart guide.
        NO CODE LOGIC - just documentation examples.
        """
        return {
            "basic_prompt_injection_detection": """
                # STABLE API - Production Ready
                from neural_shield import PromptInjectionDetector
                detector = PromptInjectionDetector()
                result = detector.detect("User input here")
                if result.is_threat:
                    print(f"Threat detected: {result.confidence:.2f}")
            """,

            "input_sanitization_pipeline": """
                # STABLE API - Production Ready
                from neural_shield import InputPurification, OutputSanitizerPIIRedactor
                purifier = InputPurification()
                sanitizer = OutputSanitizerPIIRedactor()
                clean_input = purifier.purify(user_input)
                clean_output = sanitizer.redact_pii(llm_output)
            """,

            "agent_tool_validation": """
                # EXPERIMENTAL API - Evaluation Only
                from neural_shield import AgentToolCallValidator
                validator = AgentToolCallValidator()
                is_safe = validator.validate_tool_call(
                    tool_name="file_write",
                    parameters={"path": "/etc/passwd"}
                )
            """,

            "constitutional_compliance": """
                # STABLE API - Production Ready
                from neural_shield import ConstitutionalClassifier
                classifier = ConstitutionalClassifier()
                result = classifier.classify(content)
                if result.violates_policy:
                    for violation in result.violations:
                        print(f"Policy violation: {violation}")
            """,

            "multimodal_protection": """
                # EXPERIMENTAL API - Evaluation Only
                from neural_shield import CrossModalPromptInjectionDetector
                detector = CrossModalPromptInjectionDetector()
                result = detector.detect_multimodal(image_tensor, text_prompt)
            """,

            "observability_setup": """
                # STABLE API - Production Ready
                from neural_shield import ObservabilityEngine
                observability = ObservabilityEngine(enabled=False)  # OPT-IN
                observability.increment_counter("threats_detected")
                metrics = observability.get_metrics()
            """,

            "error_resilience_wrapper": """
                # STABLE API - Production Ready
                from neural_shield import ErrorResilienceEngine
                resilience = ErrorResilienceEngine()
                safe_result = resilience.with_retry(
                    unstable_api_call,
                    max_retries=3,
                    timeout_seconds=10
                )
            """
        }


# Singleton instance for import
api_documentation_catalog = NeuralShieldAPIDocumentationCatalog()

# Export stability decorators for use in other modules
__all__ = [
    'stable',
    'experimental',
    'deprecated',
    'StabilityLevel',
    'APIStabilityInfo',
    'NeuralShieldAPIDocumentationCatalog',
    'api_documentation_catalog'
]
