"""
NeuralShield AI - Comprehensive API Documentation & Stability Catalog v27
=========================================================================
STABILITY MARKERS: STABLE | EXPERIMENTAL | DEPRECATED

This module provides comprehensive documentation, usage examples, and API stability
markers for all NeuralShield AI security modules. This is an ADD-ONLY module -
no existing production code is modified.

API STABILITY LEGEND:
- STABLE: API is frozen, backward compatible, production-ready
- EXPERIMENTAL: API may change, suitable for testing only
- DEPRECATED: Will be removed in future version, use alternative

LAST UPDATED: 2026-06-24
SESSION: 134
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Any, Optional, Callable
import json
from datetime import datetime


class StabilityLevel(Enum):
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class ModuleDocumentation:
    module_name: str
    stability: StabilityLevel
    description: str
    primary_use_cases: List[str]
    key_classes: List[str]
    key_methods: List[str]
    input_parameters: Dict[str, str]
    output_format: str
    performance_characteristics: str
    thread_safe: bool
    dependencies: List[str]
    example_usage: str
    since_version: str
    deprecation_notice: Optional[str] = None
    replacement_module: Optional[str] = None


@dataclass
class APICatalog:
    catalog_version: str = "v27"
    generated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    modules: Dict[str, ModuleDocumentation] = field(default_factory=dict)

    def register_module(self, doc: ModuleDocumentation) -> None:
        """Register a module in the API catalog."""
        self.modules[doc.module_name] = doc

    def get_stable_modules(self) -> List[str]:
        """Get list of all STABLE modules."""
        return [name for name, doc in self.modules.items() 
                if doc.stability == StabilityLevel.STABLE]

    def get_experimental_modules(self) -> List[str]:
        """Get list of all EXPERIMENTAL modules."""
        return [name for name, doc in self.modules.items() 
                if doc.stability == StabilityLevel.EXPERIMENTAL]

    def get_deprecated_modules(self) -> List[str]:
        """Get list of all DEPRECATED modules."""
        return [name for name, doc in self.modules.items() 
                if doc.stability == StabilityLevel.DEPRECATED]

    def export_to_json(self, filepath: str) -> None:
        """Export catalog to JSON for external tools."""
        export_data = {
            "catalog_version": self.catalog_version,
            "generated_at": self.generated_at,
            "modules": {
                name: {
                    "stability": doc.stability.value,
                    "description": doc.description,
                    "primary_use_cases": doc.primary_use_cases,
                    "thread_safe": doc.thread_safe,
                    "since_version": doc.since_version
                }
                for name, doc in self.modules.items()
            }
        }
        with open(filepath, 'w') as f:
            json.dump(export_data, f, indent=2)

    def generate_readme_summary(self) -> str:
        """Generate README summary for quick reference."""
        stable = len(self.get_stable_modules())
        experimental = len(self.get_experimental_modules())
        deprecated = len(self.get_deprecated_modules())
        
        return f"""
# NeuralShield API Stability Summary v27

## Module Count by Stability
- ✅ **STABLE**: {stable} modules - Production ready
- ⚠️  **EXPERIMENTAL**: {experimental} modules - Testing only
- ❌ **DEPRECATED**: {deprecated} modules - Scheduled for removal

## Quick Start
Use STABLE modules for production systems.
See individual module docstrings for detailed usage examples.

Generated: {self.generated_at}
"""


def build_neuralshield_api_catalog_v27() -> APICatalog:
    """
    Build the complete NeuralShield API Documentation & Stability Catalog v27.
    This is the authoritative source for API stability information.
    """
    catalog = APICatalog(catalog_version="v27")

    # =========================================================================
    # STABLE MODULES - Production Ready, Backward Compatible
    # =========================================================================

    catalog.register_module(ModuleDocumentation(
        module_name="prompt_injection_detector",
        stability=StabilityLevel.STABLE,
        description="Primary prompt injection detection engine using ensemble methods",
        primary_use_cases=[
            "Detecting classic prompt injection attacks",
            "Filtering malicious user inputs before LLM processing",
            "Real-time input sanitization"
        ],
        key_classes=["PromptInjectionDetector", "EnsembleDetector"],
        key_methods=["detect()", "get_risk_score()", "sanitize_input()"],
        input_parameters={
            "user_input": "str - The user input to analyze",
            "context": "Optional[str] - Conversation context",
            "threshold": "float - Detection sensitivity (0.0-1.0)"
        },
        output_format="Dict with risk_score (0-1), is_detected (bool), attack_types list",
        performance_characteristics="~2ms average latency, <1% false positive rate",
        thread_safe=True,
        dependencies=["prompt_embedding_anomaly_detector", "semantic_similarity"],
        example_usage="""
from neural_shield import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect("Ignore previous instructions...")
if result['is_detected']:
    print(f"Blocked: {result['risk_score']:.2f} risk")
""",
        since_version="v1.0"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="prompt_firewall",
        stability=StabilityLevel.STABLE,
        description="Rule-based firewall with pattern matching and heuristic checks",
        primary_use_cases=[
            "First-line input filtering",
            "Known attack signature blocking",
            "High-throughput scenarios"
        ],
        key_classes=["PromptFirewall", "RuleEngine"],
        key_methods=["check()", "add_rule()", "enable_heuristics()"],
        input_parameters={
            "input_text": "str - Text to validate",
            "strict_mode": "bool - Enable strict checking"
        },
        output_format="Dict with allowed (bool), blocked_reason, matched_rules",
        performance_characteristics="<1ms average latency, high throughput",
        thread_safe=True,
        dependencies=[],
        example_usage="""
from neural_shield import PromptFirewall

firewall = PromptFirewall(strict_mode=True)
if not firewall.check(user_input)['allowed']:
    return "Input blocked for security reasons"
""",
        since_version="v1.0"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="output_sanitizer_pii_redactor",
        stability=StabilityLevel.STABLE,
        description="PII (Personally Identifiable Information) detection and redaction",
        primary_use_cases=[
            "Redacting sensitive information from LLM outputs",
            "Compliance with privacy regulations",
            "Protecting user data in conversations"
        ],
        key_classes=["PIIRedactor", "EntityDetector"],
        key_methods=["redact()", "detect_entities()", "get_redaction_report()"],
        input_parameters={
            "text": "str - Text to process",
            "entities": "List[str] - Entity types to redact",
            "replacement": "str - Replacement string (default: [REDACTED])"
        },
        output_format="Dict with redacted_text, detected_entities list, entity_counts",
        performance_characteristics="~5ms average latency, 98%+ detection accuracy",
        thread_safe=True,
        dependencies=["ner_model"],
        example_usage="""
from neural_shield import PIIRedactor

redactor = PIIRedactor()
result = redactor.redact("My email is user@example.com")
print(result['redacted_text'])  # "My email is [REDACTED]"
""",
        since_version="v1.2"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="llm_guardrails_policy_engine",
        stability=StabilityLevel.STABLE,
        description="Policy enforcement engine for content safety and compliance",
        primary_use_cases=[
            "Enforcing content policies",
            "Blocking harmful content",
            "Compliance monitoring"
        ],
        key_classes=["GuardrailsEngine", "PolicyChecker"],
        key_methods=["check_policy()", "load_policy()", "get_violations()"],
        input_parameters={
            "content": "str - Content to check",
            "policies": "List[str] - Policies to enforce"
        },
        output_format="Dict with compliant (bool), violations list, severity scores",
        performance_characteristics="~3ms average latency",
        thread_safe=True,
        dependencies=["toxicity_detector", "bias_detector"],
        example_usage="""
from neural_shield import GuardrailsEngine

engine = GuardrailsEngine()
result = engine.check_policy(user_message, policies=['harmful', 'hate'])
if not result['compliant']:
    for violation in result['violations']:
        print(f"Violation: {violation}")
""",
        since_version="v1.1"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="adversarial_prompt_anomaly_detector",
        stability=StabilityLevel.STABLE,
        description="Embedding-based anomaly detection for adversarial prompts",
        primary_use_cases=[
            "Detecting novel attack vectors",
            "Zero-day attack protection",
            "Anomaly-based threat detection"
        ],
        key_classes=["EmbeddingAnomalyDetector", "PromptClassifier"],
        key_methods=["predict_anomaly()", "get_embedding()", "update_benchmark()"],
        input_parameters={
            "prompt": "str - Prompt to analyze",
            "sensitivity": "float - Anomaly threshold"
        },
        output_format="Dict with anomaly_score (0-1), is_anomalous (bool), features",
        performance_characteristics="~10ms average latency (embedding computation)",
        thread_safe=True,
        dependencies=["sentence_transformers"],
        example_usage="""
from neural_shield import EmbeddingAnomalyDetector

detector = EmbeddingAnomalyDetector()
score = detector.predict_anomaly(suspicious_prompt)
if score > 0.8:
    print("High anomaly score - potential attack")
""",
        since_version="v1.3"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="jailbreak_detector",
        stability=StabilityLevel.STABLE,
        description="Specialized detector for jailbreak and DAN attacks",
        primary_use_cases=[
            "Detecting jailbreak attempts",
            "Blocking role-play attacks",
            "Preventing instruction override"
        ],
        key_classes=["JailbreakDetector", "AdvancedJailbreakDetector"],
        key_methods=["detect_jailbreak()", "get_attack_type()", "get_confidence()"],
        input_parameters={
            "prompt": "str - User prompt to analyze",
            "conversation_history": "Optional[List] - Previous messages"
        },
        output_format="Dict with is_jailbreak (bool), confidence, attack_techniques",
        performance_characteristics="~4ms average latency",
        thread_safe=True,
        dependencies=["pattern_matcher", "semantic_analyzer"],
        example_usage="""
from neural_shield import JailbreakDetector

detector = JailbreakDetector()
result = detector.detect_jailbreak("You are now in Developer Mode...")
if result['is_jailbreak']:
    print(f"Jailbreak blocked: {result['attack_techniques']}")
""",
        since_version="v1.4"
    ))

    # =========================================================================
    # EXPERIMENTAL MODULES - Testing Only, API May Change
    # =========================================================================

    catalog.register_module(ModuleDocumentation(
        module_name="multimodal_prompt_injection_detector",
        stability=StabilityLevel.EXPERIMENTAL,
        description="Multi-modal injection detection for images and text combined",
        primary_use_cases=[
            "Image-based prompt injection detection",
            "VLM security protection",
            "Multi-modal threat detection"
        ],
        key_classes=["MultimodalInjectionDetector", "VLMSecurityGuard"],
        key_methods=["detect_multimodal()", "analyze_image()", "fuse_modalities()"],
        input_parameters={
            "text": "str - Text component",
            "image": "PIL.Image | str - Image or image path",
            "fusion_strategy": "str - How to combine modalities"
        },
        output_format="Dict with combined_risk, modality_scores, detections",
        performance_characteristics="~100ms average latency (vision model)",
        thread_safe=True,
        dependencies=["clip_model", "vlm_analyzer"],
        example_usage="""
from neural_shield import MultimodalInjectionDetector

detector = MultimodalInjectionDetector()
result = detector.detect_multimodal(text="", image="suspicious.png")
if result['combined_risk'] > 0.7:
    print("Potential multi-modal injection detected")
""",
        since_version="v2.0-experimental"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="agent_tool_call_validator",
        stability=StabilityLevel.EXPERIMENTAL,
        description="Validation and safety checking for AI agent tool calls",
        primary_use_cases=[
            "Agent function call security",
            "Preventing harmful tool execution",
            "Parameter validation"
        ],
        key_classes=["ToolCallValidator", "AgentSecurityEnforcer"],
        key_methods=["validate_call()", "check_permissions()", "sanitize_params()"],
        input_parameters={
            "tool_name": "str - Tool being called",
            "parameters": "Dict - Tool parameters",
            "context": "str - Agent context"
        },
        output_format="Dict with allowed (bool), risk_factors, sanitized_params",
        performance_characteristics="~2ms average latency",
        thread_safe=True,
        dependencies=["policy_engine"],
        example_usage="""
from neural_shield import ToolCallValidator

validator = ToolCallValidator()
result = validator.validate_call("delete_file", {"path": "/etc/passwd"})
if not result['allowed']:
    print(f"Tool call blocked: {result['risk_factors']}")
""",
        since_version="v2.1-experimental"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="adaptive_threat_response_orchestrator",
        stability=StabilityLevel.EXPERIMENTAL,
        description="Automated threat response and mitigation orchestration",
        primary_use_cases=[
            "Automated incident response",
            "Threat mitigation workflows",
            "Security automation"
        ],
        key_classes=["ThreatOrchestrator", "ResponseEngine"],
        key_methods=["handle_threat()", "execute_mitigation()", "get_response_plan()"],
        input_parameters={
            "threat_data": "Dict - Detected threat information",
            "auto_execute": "bool - Auto-apply mitigations"
        },
        output_format="Dict with actions_taken, mitigation_effectiveness, recommendations",
        performance_characteristics="Varies by mitigation action",
        thread_safe=False,
        dependencies=["alerting_system", "policy_engine"],
        example_usage="""
from neural_shield import ThreatOrchestrator

orchestrator = ThreatOrchestrator(auto_execute=False)
response = orchestrator.handle_threat(detected_threat)
print(f"Recommended actions: {response['recommendations']}")
""",
        since_version="v2.2-experimental"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="behavioral_biometrics_anomaly_detector",
        stability=StabilityLevel.EXPERIMENTAL,
        description="User behavior anomaly detection for account protection",
        primary_use_cases=[
            "Account takeover detection",
            "Behavioral authentication",
            "Anomalous user activity detection"
        ],
        key_classes=["BehavioralBiometrics", "UserAnomalyDetector"],
        key_methods=["analyze_behavior()", "build_profile()", "detect_anomaly()"],
        input_parameters={
            "user_id": "str - User identifier",
            "activity_data": "Dict - User activity metrics",
            "window_minutes": "int - Analysis time window"
        },
        output_format="Dict with anomaly_score, baseline_deviation, risk_factors",
        performance_characteristics="~15ms average latency",
        thread_safe=True,
        dependencies=["user_profiling", "statistics_engine"],
        example_usage="""
from neural_shield import BehavioralBiometrics

biometrics = BehavioralBiometrics()
score = biometrics.analyze_behavior(user_id, current_activity)
if score > 0.9:
    trigger_mfa_challenge(user_id)
""",
        since_version="v2.3-experimental"
    ))

    # =========================================================================
    # DEPRECATED MODULES - Use Replacements Instead
    # =========================================================================

    catalog.register_module(ModuleDocumentation(
        module_name="constitutional_classifier",
        stability=StabilityLevel.DEPRECATED,
        description="Original constitutional AI classifier (deprecated)",
        primary_use_cases=["Historical compatibility only"],
        key_classes=["ConstitutionalClassifier"],
        key_methods=["classify()"],
        input_parameters={"text": "str"},
        output_format="Dict with classification",
        performance_characteristics="Legacy implementation",
        thread_safe=True,
        dependencies=[],
        example_usage="LEGACY - USE enhanced_constitutional_classifier INSTEAD",
        since_version="v0.9",
        deprecation_notice="Deprecated since v1.5 - use enhanced version",
        replacement_module="enhanced_constitutional_classifier"
    ))

    catalog.register_module(ModuleDocumentation(
        module_name="simple_prompt_detector",
        stability=StabilityLevel.DEPRECATED,
        description="Original simple regex-based detector (deprecated)",
        primary_use_cases=["Historical compatibility only"],
        key_classes=["SimplePromptDetector"],
        key_methods=["detect()"],
        input_parameters={"text": "str"},
        output_format="Dict with basic detection",
        performance_characteristics="High false positive rate",
        thread_safe=True,
        dependencies=[],
        example_usage="LEGACY - USE prompt_injection_detector INSTEAD",
        since_version="v0.8",
        deprecation_notice="Deprecated since v1.0 - use ensemble detector",
        replacement_module="prompt_injection_detector"
    ))

    return catalog


# Global catalog instance
NEURALSHIELD_API_CATALOG_V27 = build_neuralshield_api_catalog_v27()


def get_module_documentation(module_name: str) -> Optional[ModuleDocumentation]:
    """
    Get documentation for a specific module.
    
    Args:
        module_name: Name of the module to lookup
        
    Returns:
        ModuleDocumentation if found, None otherwise
        
    Stability: STABLE
    """
    return NEURALSHIELD_API_CATALOG_V27.modules.get(module_name)


def list_modules_by_stability(stability: StabilityLevel) -> List[str]:
    """
    List all modules at a specific stability level.
    
    Args:
        stability: Stability level to filter by
        
    Returns:
        List of module names
        
    Stability: STABLE
    """
    if stability == StabilityLevel.STABLE:
        return NEURALSHIELD_API_CATALOG_V27.get_stable_modules()
    elif stability == StabilityLevel.EXPERIMENTAL:
        return NEURALSHIELD_API_CATALOG_V27.get_experimental_modules()
    elif stability == StabilityLevel.DEPRECATED:
        return NEURALSHIELD_API_CATALOG_V27.get_deprecated_modules()
    return []


def print_stability_report() -> None:
    """
    Print a human-readable stability report to console.
    
    Stability: STABLE
    """
    catalog = NEURALSHIELD_API_CATALOG_V27
    print("=" * 70)
    print("NeuralShield API Stability Report v27")
    print("=" * 70)
    print(f"\n✅ STABLE Modules ({len(catalog.get_stable_modules())}):")
    for mod in sorted(catalog.get_stable_modules()):
        print(f"   - {mod}")
    
    print(f"\n⚠️  EXPERIMENTAL Modules ({len(catalog.get_experimental_modules())}):")
    for mod in sorted(catalog.get_experimental_modules()):
        print(f"   - {mod}")
    
    print(f"\n❌ DEPRECATED Modules ({len(catalog.get_deprecated_modules())}):")
    for mod in sorted(catalog.get_deprecated_modules()):
        doc = catalog.modules[mod]
        print(f"   - {mod} → Use: {doc.replacement_module}")
    
    print("\n" + "=" * 70)
    print(f"Generated: {catalog.generated_at}")
    print("=" * 70)


if __name__ == "__main__":
    print_stability_report()
