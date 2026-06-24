"""
NeuralShield AI - API Documentation & Stability Master Catalog v29
=================================================================

API STABILITY MARKERS:
- @STABLE: Production-ready, backward-compatible, no breaking changes
- @EXPERIMENTAL: New feature, subject to change, use with caution
- @DEPRECATED: Scheduled for removal, migrate to alternatives
- @INTERNAL: Not for public consumption, implementation detail

This module provides comprehensive documentation, usage examples,
and API stability metadata for all NeuralShield security modules.

ADD-ONLY PHILOSOPHY: This module is purely additive - no existing
code is modified, only documented and wrapped with metadata.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import inspect
import json


class StabilityLevel(Enum):
    """API stability classification levels."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"


@dataclass
class APIEndpointDoc:
    """Documentation metadata for a single API endpoint."""
    name: str
    module: str
    stability: StabilityLevel
    description: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_path: Optional[str] = None


@dataclass
class ModuleDoc:
    """Documentation metadata for an entire module."""
    module_name: str
    stability: StabilityLevel
    purpose: str
    endpoints: List[APIEndpointDoc] = field(default_factory=list)
    usage_guide: str = ""
    best_practices: List[str] = field(default_factory=list)
    limitations: List[str] = field(default_factory=list)


class NeuralShieldDocumentationCatalog:
    """
    @STABLE
    Master documentation and API stability catalog for NeuralShield AI.
    
    Provides:
    - API stability markers for all public endpoints
    - Comprehensive usage examples
    - Migration guides for deprecated APIs
    - Best practices documentation
    """
    
    def __init__(self):
        self._modules: Dict[str, ModuleDoc] = {}
        self._build_catalog()
    
    def _build_catalog(self) -> None:
        """Build the complete documentation catalog."""
        self._add_threat_detection_modules()
        self._add_prompt_injection_modules()
        self._add_agent_security_modules()
        self._add_observability_modules()
        self._add_error_resilience_modules()
    
    def _add_threat_detection_modules(self) -> None:
        """Add threat detection module documentation."""
        
        # Adversarial Prompt Anomaly Detector
        self._modules["adversarial_prompt_anomaly_detector"] = ModuleDoc(
            module_name="adversarial_prompt_anomaly_detector_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Detect anomalous and potentially malicious prompts using statistical analysis",
            usage_guide="""
            Usage Guide:
            ------------
            1. Initialize detector with default or custom thresholds
            2. Call detect_anomaly() with user prompt text
            3. Check anomaly_score and is_malicious flags
            4. Use get_risk_assessment() for detailed breakdown
            
            Ideal for: Input validation gates, pre-processing filters
            """,
            best_practices=[
                "Always run in conjunction with other detectors (defense in depth)",
                "Calibrate thresholds for your specific use case",
                "Log all high-anomaly prompts for audit purposes",
                "Use ensemble voting across multiple detection engines"
            ],
            limitations=[
                "Cannot detect all zero-day attack vectors",
                "May have false positives on creative/novel inputs",
                "Requires sufficient context for accurate detection"
            ],
            endpoints=[
                APIEndpointDoc(
                    name="detect_anomaly",
                    module="adversarial_prompt_anomaly_detector_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Analyze prompt text for anomaly patterns",
                    parameters=[
                        {"name": "prompt_text", "type": "str", "desc": "Input prompt to analyze"},
                        {"name": "context", "type": "Optional[Dict]", "desc": "Additional context metadata"}
                    ],
                    returns="AnomalyResult with score (0.0-1.0) and flags",
                    examples=[
                        """
                        detector = AdversarialPromptAnomalyDetector()
                        result = detector.detect_anomaly("User prompt here")
                        if result.is_malicious:
                            log_threat(result)
                        """
                    ]
                ),
                APIEndpointDoc(
                    name="get_risk_assessment",
                    module="adversarial_prompt_anomaly_detector_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Get detailed risk factor breakdown",
                    returns="Dict of risk categories and scores"
                )
            ]
        )
        
        # Behavioral Biometrics Anomaly Detector
        self._modules["behavioral_biometrics_anomaly_detector"] = ModuleDoc(
            module_name="behavioral_biometrics_anomaly_detector_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Detect anomalies in user interaction patterns and typing behavior",
            best_practices=[
                "Establish baseline behavior during normal usage",
                "Combine with content-based detection",
                "Respect user privacy - anonymize biometric data"
            ],
            limitations=[
                "Requires sufficient interaction history",
                "Not effective for single-shot attacks"
            ]
        )
    
    def _add_prompt_injection_modules(self) -> None:
        """Add prompt injection defense module documentation."""
        
        # Context-Aware Prompt Injection Defender
        self._modules["context_aware_prompt_injection_defender"] = ModuleDoc(
            module_name="context_aware_prompt_injection_defender_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Context-aware prompt injection detection with semantic analysis",
            usage_guide="""
            Usage Guide:
            ------------
            This is the PRIMARY recommended module for prompt injection defense.
            
            Key Features:
            - Semantic pattern matching
            - Context window boundary enforcement
            - System prompt integrity verification
            - Instruction override detection
            
            Integration: Place as middleware between user input and LLM call
            """,
            best_practices=[
                "Enable strict mode for high-security environments",
                "Always verify system prompt integrity",
                "Check for instruction escape patterns",
                "Maintain audit log of all blocked attempts"
            ],
            endpoints=[
                APIEndpointDoc(
                    name="scan_for_injection",
                    module="context_aware_prompt_injection_defender_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Primary injection scanning endpoint",
                    parameters=[
                        {"name": "user_input", "type": "str", "desc": "Raw user input"},
                        {"name": "system_prompt", "type": "str", "desc": "Current system prompt"},
                        {"name": "strict_mode", "type": "bool", "desc": "Enable strict scanning"}
                    ],
                    returns="InjectionScanResult with risk assessment",
                    examples=[
                        """
                        defender = ContextAwarePromptInjectionDefender()
                        result = defender.scan_for_injection(
                            user_input=user_msg,
                            system_prompt=SYSTEM_PROMPT,
                            strict_mode=True
                        )
                        if result.blocked:
                            return "Request cannot be processed"
                        """
                    ]
                )
            ]
        )
        
        # Cross-Modal Prompt Injection Detector
        self._modules["cross_modal_prompt_injection_detector"] = ModuleDoc(
            module_name="cross_modal_prompt_injection_detector_2026_june",
            stability=StabilityLevel.EXPERIMENTAL,
            purpose="Detect prompt injection attacks across text, image, and audio modalities",
            best_practices=[
                "EXPERIMENTAL: API may change in future versions",
                "Multimodal support is actively being improved",
                "Extract text from images before scanning",
                "Validate all multimodal inputs separately"
            ]
        )
    
    def _add_agent_security_modules(self) -> None:
        """Add agent security module documentation."""
        
        # Agent Tool Call Validator
        self._modules["agent_tool_call_validator"] = ModuleDoc(
            module_name="agent_tool_call_validator_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Validate and sanitize AI agent tool calls before execution",
            usage_guide="""
            Usage Guide:
            ------------
            Critical for agentic AI systems. Validates:
            1. Tool existence and permissions
            2. Parameter types and ranges
            3. Dangerous operation detection
            4. Rate limiting and quotas
            
            Place this as the LAST gate before tool execution.
            """,
            best_practices=[
                "Define explicit allowlists for tools and parameters",
                "Set maximum execution time per tool",
                "Log ALL tool calls (successful and blocked)",
                "Implement circuit breakers for repeated failures"
            ],
            limitations=[
                "Cannot prevent all logical abuse of valid tools",
                "Requires explicit tool schema definitions"
            ],
            endpoints=[
                APIEndpointDoc(
                    name="validate_tool_call",
                    module="agent_tool_call_validator_2026_june",
                    stability=StabilityLevel.STABLE,
                    description="Validate a proposed tool call",
                    parameters=[
                        {"name": "tool_name", "type": "str", "desc": "Name of tool to call"},
                        {"name": "parameters", "type": "Dict", "desc": "Tool parameters"},
                        {"name": "context", "type": "Dict", "desc": "Execution context"}
                    ],
                    returns="ValidationResult with allow/block decision"
                )
            ]
        )
        
        # Agent Memory Safety Guardian
        self._modules["agent_memory_safety_guardian"] = ModuleDoc(
            module_name="agent_memory_safety_guardian_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Protect agent memory from poisoning and exfiltration attacks",
            best_practices=[
                "Scan all memory writes and reads",
                "Detect data exfiltration patterns",
                "Implement memory compartmentalization"
            ]
        )
    
    def _add_observability_modules(self) -> None:
        """Add observability module documentation."""
        
        self._modules["observability_structured_logging"] = ModuleDoc(
            module_name="observability_distributed_tracing_correlation_v15_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Distributed tracing and correlation for security observability",
            usage_guide="""
            Usage Guide:
            ------------
            OPT-IN instrumentation - disabled by default.
            
            To enable:
            1. Import SecurityTracer
            2. Initialize with your config
            3. Use decorators or context managers
            
            No performance impact when disabled.
            """,
            best_practices=[
                "Use trace IDs across all service boundaries",
                "Sample appropriately in high-throughput systems",
                "Include security context in all traces"
            ]
        )
    
    def _add_error_resilience_modules(self) -> None:
        """Add error resilience module documentation."""
        
        self._modules["error_resilience_circuit_breaker"] = ModuleDoc(
            module_name="error_resilience_adaptive_concurrency_qos_v30_2026_june",
            stability=StabilityLevel.STABLE,
            purpose="Adaptive concurrency control, QoS, and circuit breaker patterns",
            usage_guide="""
            Usage Guide:
            ------------
            Wrap security-critical operations to prevent cascade failures.
            
            Features:
            - Automatic circuit breaking on repeated failures
            - Adaptive concurrency limits
            - Quality of Service prioritization
            - Graceful degradation fallback paths
            """,
            best_practices=[
                "Define clear fallback behaviors",
                "Set appropriate timeouts for each operation",
                "Monitor circuit breaker state metrics",
                "Test failure scenarios explicitly"
            ]
        )
    
    def get_module_doc(self, module_name: str) -> Optional[ModuleDoc]:
        """
        @STABLE
        Get documentation for a specific module.
        
        Args:
            module_name: Name of the module to lookup
            
        Returns:
            ModuleDoc if found, None otherwise
        """
        return self._modules.get(module_name)
    
    def get_all_modules(self) -> List[ModuleDoc]:
        """
        @STABLE
        Get list of all documented modules.
        """
        return list(self._modules.values())
    
    def get_stable_modules(self) -> List[ModuleDoc]:
        """
        @STABLE
        Get all modules marked STABLE for production use.
        """
        return [m for m in self._modules.values() 
                if m.stability == StabilityLevel.STABLE]
    
    def get_experimental_modules(self) -> List[ModuleDoc]:
        """
        @STABLE
        Get all modules marked EXPERIMENTAL.
        """
        return [m for m in self._modules.values() 
                if m.stability == StabilityLevel.EXPERIMENTAL]
    
    def generate_stability_report(self) -> Dict[str, Any]:
        """
        @STABLE
        Generate comprehensive API stability report.
        """
        total = len(self._modules)
        stable = len(self.get_stable_modules())
        experimental = len(self.get_experimental_modules())
        
        return {
            "total_modules": total,
            "stable_modules": stable,
            "experimental_modules": experimental,
            "stable_percentage": round(stable / total * 100, 1) if total > 0 else 0,
            "modules": [
                {
                    "name": m.module_name,
                    "stability": m.stability.value,
                    "purpose": m.purpose
                }
                for m in self._modules.values()
            ]
        }
    
    def export_json(self, filepath: str) -> None:
        """
        @STABLE
        Export documentation catalog to JSON file.
        """
        report = self.generate_stability_report()
        with open(filepath, 'w') as f:
            json.dump(report, f, indent=2)


# Global instance for easy import
DOCUMENTATION_CATALOG = NeuralShieldDocumentationCatalog()


def get_api_stability_report() -> Dict[str, Any]:
    """
    @STABLE
    Convenience function to get API stability report.
    
    Returns:
        Comprehensive stability report dictionary
    """
    return DOCUMENTATION_CATALOG.generate_stability_report()


def print_stability_summary() -> None:
    """
    @STABLE
    Print human-readable API stability summary.
    """
    report = get_api_stability_report()
    print("=" * 60)
    print("NeuralShield AI - API Stability Summary v29")
    print("=" * 60)
    print(f"Total Modules:      {report['total_modules']}")
    print(f"STABLE:             {report['stable_modules']} ({report['stable_percentage']}%)")
    print(f"EXPERIMENTAL:       {report['experimental_modules']}")
    print()
    print("Module Stability Breakdown:")
    print("-" * 60)
    for mod in report['modules']:
        print(f"  [{mod['stability']:12}] {mod['name']}")
    print("=" * 60)


if __name__ == "__main__":
    print_stability_summary()
