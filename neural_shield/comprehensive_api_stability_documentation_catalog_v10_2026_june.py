"""
NeuralShield-AI Comprehensive API Stability Documentation Catalog v10
====================================================================
STABILITY MARKERS: STABLE | EXPERIMENTAL | DEPRECATED | INTERNAL

This catalog provides comprehensive API documentation, stability markers,
usage examples, and version compatibility information for all NeuralShield-AI
security modules.

Version: 10.0.0
Last Updated: 2026-06-22
Maintainer: NeuralShield Security Team
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import json


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"
    MAINTENANCE = "MAINTENANCE"


@dataclass
class APIEndpointDoc:
    """Documentation for a single API endpoint or function"""
    name: str
    module: str
    stability: StabilityLevel
    since_version: str
    description: str
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None
    see_also: List[str] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)
    thread_safe: bool = True
    performance_notes: str = ""


@dataclass
class ModuleDoc:
    """Documentation for an entire module"""
    module_name: str
    stability: StabilityLevel
    category: str
    overview: str
    endpoints: List[APIEndpointDoc] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    configuration_options: List[Dict[str, Any]] = field(default_factory=list)


class NeuralShieldAPIDocumentationCatalog:
    """
    Comprehensive API Documentation and Stability Catalog v10
    
    Features:
    - Complete API stability markers for all modules
    - Comprehensive usage examples
    - Deprecation warnings and migration guides
    - Performance characteristics
    - Thread safety information
    - Exception handling documentation
    
    STABILITY POLICY:
    - STABLE: Backward compatible, no breaking changes without major version bump
    - EXPERIMENTAL: May change without notice, not for production use
    - DEPRECATED: Will be removed, migrate to recommended alternatives
    - INTERNAL: Not for public consumption
    """
    
    def __init__(self):
        self.catalog_version = "10.0.0"
        self.last_updated = datetime.utcnow().isoformat()
        self.modules: Dict[str, ModuleDoc] = {}
        self._initialize_catalog()
    
    def _initialize_catalog(self) -> None:
        """Initialize the complete documentation catalog"""
        self._add_threat_detection_modules()
        self._add_prompt_injection_modules()
        self._add_agent_security_modules()
        self._add_adversarial_modules()
        self._add_observability_modules()
        self._add_error_resilience_modules()
    
    def _add_threat_detection_modules(self) -> None:
        """Add threat detection module documentation"""
        self.modules["advanced_jailbreak_detector"] = ModuleDoc(
            module_name="advanced_jailbreak_detector_2026",
            stability=StabilityLevel.STABLE,
            category="Threat Detection",
            overview="Advanced jailbreak and prompt injection detection using multi-modal analysis",
            endpoints=[
                APIEndpointDoc(
                    name="AdvancedJailbreakDetector.__init__",
                    module="advanced_jailbreak_detector_2026",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Initialize the advanced jailbreak detector",
                    parameters=[
                        {"name": "config", "type": "Dict", "required": False, "description": "Configuration dictionary"},
                        {"name": "threshold", "type": "float", "required": False, "description": "Detection threshold (0.0-1.0)"}
                    ],
                    returns="AdvancedJailbreakDetector instance",
                    examples=[
                        "detector = AdvancedJailbreakDetector(threshold=0.85)",
                        "detector = AdvancedJailbreakDetector(config={'mode': 'strict'})"
                    ],
                    exceptions=["ValueError", "TypeError"],
                    thread_safe=True
                ),
                APIEndpointDoc(
                    name="AdvancedJailbreakDetector.detect",
                    module="advanced_jailbreak_detector_2026",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Detect potential jailbreak attempts in user input",
                    parameters=[
                        {"name": "prompt", "type": "str", "required": True, "description": "User input to analyze"},
                        {"name": "context", "type": "str", "required": False, "description": "Conversation context"}
                    ],
                    returns="Dict with detection results: {'risk_score': float, 'is_detected': bool, 'details': Dict}",
                    examples=[
                        "result = detector.detect('Ignore previous instructions')",
                        "result = detector.detect(user_input, conversation_history)"
                    ],
                    exceptions=["ValueError"],
                    thread_safe=True,
                    performance_notes="Average latency: 25ms, Memory footprint: ~15MB per instance"
                )
            ]
        )
        
        self.modules["constitutional_classifier"] = ModuleDoc(
            module_name="constitutional_classifier_2026",
            stability=StabilityLevel.STABLE,
            category="Threat Detection",
            overview="Constitutional AI policy compliance classification",
            endpoints=[
                APIEndpointDoc(
                    name="ConstitutionalClassifier.classify",
                    module="constitutional_classifier_2026",
                    stability=StabilityLevel.STABLE,
                    since_version="1.2.0",
                    description="Classify content against constitutional principles",
                    parameters=[
                        {"name": "content", "type": "str", "required": True, "description": "Content to classify"},
                        {"name": "principles", "type": "List[str]", "required": False, "description": "Constitutional principles to check"}
                    ],
                    returns="Dict with classification results",
                    examples=["result = classifier.classify('User content', principles=['harm', 'deception'])"],
                    thread_safe=True
                )
            ]
        )
    
    def _add_prompt_injection_modules(self) -> None:
        """Add prompt injection module documentation"""
        self.modules["prompt_injection_context_analyzer"] = ModuleDoc(
            module_name="prompt_injection_context_analyzer_2026_june",
            stability=StabilityLevel.STABLE,
            category="Prompt Injection Defense",
            overview="Context-aware prompt injection detection with semantic analysis",
            endpoints=[
                APIEndpointDoc(
                    name="ContextAwarePromptInjectionDefender.analyze",
                    module="context_aware_prompt_injection_defender_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.0.0",
                    description="Analyze prompt for injection attacks with context awareness",
                    parameters=[
                        {"name": "prompt", "type": "str", "required": True},
                        {"name": "system_prompt", "type": "str", "required": False},
                        {"name": "conversation_history", "type": "List", "required": False}
                    ],
                    returns="Analysis result dictionary",
                    examples=[
                        "result = defender.analyze(user_prompt, system_prompt=system_msg)"
                    ],
                    thread_safe=True
                )
            ]
        )
        
        self.modules["prompt_firewall"] = ModuleDoc(
            module_name="prompt_firewall_2026_june",
            stability=StabilityLevel.STABLE,
            category="Prompt Injection Defense",
            overview="Real-time prompt firewall and sanitization engine",
            endpoints=[
                APIEndpointDoc(
                    name="PromptFirewall.sanitize",
                    module="prompt_firewall_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.5.0",
                    description="Sanitize potentially malicious prompts",
                    parameters=[
                        {"name": "prompt", "type": "str", "required": True},
                        {"name": "aggressive", "type": "bool", "required": False}
                    ],
                    returns="Sanitized prompt string",
                    examples=["clean_prompt = firewall.sanitize(user_input, aggressive=True)"],
                    thread_safe=True
                )
            ]
        )
    
    def _add_agent_security_modules(self) -> None:
        """Add agent security module documentation"""
        self.modules["agent_tool_call_validator"] = ModuleDoc(
            module_name="agent_tool_call_validator_2026_june",
            stability=StabilityLevel.STABLE,
            category="Agent Security",
            overview="Agent tool call validation and security enforcement",
            endpoints=[
                APIEndpointDoc(
                    name="AgentToolCallValidator.validate",
                    module="agent_tool_call_validator_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="3.0.0",
                    description="Validate agent tool calls for security risks",
                    parameters=[
                        {"name": "tool_name", "type": "str", "required": True},
                        {"name": "parameters", "type": "Dict", "required": True},
                        {"name": "context", "type": "Dict", "required": False}
                    ],
                    returns="Validation result: {'allowed': bool, 'risk_score': float, 'reasons': List}",
                    examples=[
                        "result = validator.validate('execute_command', {'cmd': 'rm -rf'})"
                    ],
                    thread_safe=True
                )
            ]
        )
        
        self.modules["agent_memory_safety_guardian"] = ModuleDoc(
            module_name="agent_memory_safety_guardian_2026_june",
            stability=StabilityLevel.STABLE,
            category="Agent Security",
            overview="Agent memory safety monitoring and poisoning detection",
            endpoints=[
                APIEndpointDoc(
                    name="AgentMemorySafetyGuardian.scan_memory",
                    module="agent_memory_safety_guardian_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.1.0",
                    description="Scan agent memory for poisoning and integrity issues",
                    parameters=[
                        {"name": "memory_items", "type": "List[Dict]", "required": True}
                    ],
                    returns="Scan results with risk assessments",
                    thread_safe=True
                )
            ]
        )
    
    def _add_adversarial_modules(self) -> None:
        """Add adversarial detection module documentation"""
        self.modules["adversarial_prompt_anomaly_detector"] = ModuleDoc(
            module_name="adversarial_prompt_anomaly_detector_2026_june",
            stability=StabilityLevel.STABLE,
            category="Adversarial Detection",
            overview="Anomaly detection for adversarial prompt patterns",
            endpoints=[
                APIEndpointDoc(
                    name="AdversarialPromptAnomalyDetector.detect_anomalies",
                    module="adversarial_prompt_anomaly_detector_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="2.0.0",
                    description="Detect anomalous patterns indicative of adversarial attacks",
                    parameters=[
                        {"name": "prompt", "type": "str", "required": True},
                        {"name": "baseline_profile", "type": "Dict", "required": False}
                    ],
                    returns="Anomaly detection results",
                    thread_safe=True
                )
            ]
        )
        
        self.modules["adversarial_embedding_perturbation_detector"] = ModuleDoc(
            module_name="adversarial_embedding_perturbation_detector_2026_june",
            stability=StabilityLevel.EXPERIMENTAL,
            category="Adversarial Detection",
            overview="Detection of embedding perturbation attacks (EXPERIMENTAL)",
            endpoints=[
                APIEndpointDoc(
                    name="EmbeddingPerturbationDetector.detect",
                    module="adversarial_embedding_perturbation_detector_2026_june",
                    stability=StabilityLevel.EXPERIMENTAL,
                    since_version="0.9.0",
                    description="Detect embedding perturbation attacks - EXPERIMENTAL",
                    parameters=[{"name": "embeddings", "type": "List[float]", "required": True}],
                    returns="Detection results",
                    thread_safe=True,
                    deprecation_notice="API may change in future versions"
                )
            ]
        )
    
    def _add_observability_modules(self) -> None:
        """Add observability module documentation"""
        self.modules["observability_engine"] = ModuleDoc(
            module_name="observability_engine_2026_june",
            stability=StabilityLevel.STABLE,
            category="Observability",
            overview="Structured logging, metrics, and health monitoring framework",
            endpoints=[
                APIEndpointDoc(
                    name="ObservabilityEngine.log_event",
                    module="observability_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Log structured security event",
                    parameters=[
                        {"name": "event_type", "type": "str", "required": True},
                        {"name": "data", "type": "Dict", "required": True},
                        {"name": "level", "type": "str", "required": False}
                    ],
                    returns="None",
                    examples=["engine.log_event('threat_detected', {'risk': 0.95}, level='WARNING')"],
                    thread_safe=True
                ),
                APIEndpointDoc(
                    name="ObservabilityEngine.get_metrics",
                    module="observability_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Get current metrics snapshot",
                    returns="Dict of metrics: counters, gauges, timers",
                    thread_safe=True
                )
            ]
        )
    
    def _add_error_resilience_modules(self) -> None:
        """Add error resilience module documentation"""
        self.modules["error_resilience_engine"] = ModuleDoc(
            module_name="error_resilience_engine_2026_june",
            stability=StabilityLevel.STABLE,
            category="Error Resilience",
            overview="Retry, backoff, circuit breaker, and timeout utilities",
            endpoints=[
                APIEndpointDoc(
                    name="ErrorResilienceEngine.with_retry",
                    module="error_resilience_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Decorator for automatic retry with exponential backoff",
                    parameters=[
                        {"name": "max_retries", "type": "int", "required": False},
                        {"name": "backoff_factor", "type": "float", "required": False},
                        {"name": "retry_on", "type": "Tuple[Exception]", "required": False}
                    ],
                    returns="Decorated function",
                    examples=[
                        "@engine.with_retry(max_retries=3, backoff_factor=2.0)",
                        "def api_call(): ..."
                    ],
                    thread_safe=True
                ),
                APIEndpointDoc(
                    name="ErrorResilienceEngine.with_timeout",
                    module="error_resilience_engine_2026_june",
                    stability=StabilityLevel.STABLE,
                    since_version="1.0.0",
                    description="Decorator for function timeout enforcement",
                    parameters=[{"name": "timeout_seconds", "type": "float", "required": True}],
                    returns="Decorated function",
                    thread_safe=True
                )
            ]
        )
    
    def get_module_documentation(self, module_name: str) -> Optional[ModuleDoc]:
        """
        Get documentation for a specific module
        
        Args:
            module_name: Name of the module to retrieve
            
        Returns:
            ModuleDoc if found, None otherwise
            
        Example:
            >>> catalog = NeuralShieldAPIDocumentationCatalog()
            >>> doc = catalog.get_module_documentation('prompt_firewall')
            >>> print(doc.stability)
            StabilityLevel.STABLE
        """
        return self.modules.get(module_name)
    
    def get_all_modules_by_stability(self, stability: StabilityLevel) -> List[ModuleDoc]:
        """Get all modules matching a specific stability level"""
        return [m for m in self.modules.values() if m.stability == stability]
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary count of modules by stability level"""
        summary = {level.value: 0 for level in StabilityLevel}
        for module in self.modules.values():
            summary[module.stability.value] += 1
        return summary
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive markdown documentation"""
        md = [
            "# NeuralShield-AI API Documentation Catalog v10",
            "",
            f"**Generated:** {self.last_updated}",
            f"**Catalog Version:** {self.catalog_version}",
            "",
            "## Stability Legend",
            "",
            "- 🟢 **STABLE**: Production-ready, backward compatible",
            "- 🟡 **EXPERIMENTAL**: Under development, API may change",
            "- 🔴 **DEPRECATED**: Scheduled for removal",
            "- ⚪ **INTERNAL**: Internal use only",
            "",
            "## Module Summary",
            ""
        ]
        
        summary = self.get_stability_summary()
        md.append(f"- STABLE: {summary['STABLE']} modules")
        md.append(f"- EXPERIMENTAL: {summary['EXPERIMENTAL']} modules")
        md.append("")
        
        for module_name, module_doc in sorted(self.modules.items()):
            stability_icon = {
                StabilityLevel.STABLE: "🟢",
                StabilityLevel.EXPERIMENTAL: "🟡",
                StabilityLevel.DEPRECATED: "🔴",
                StabilityLevel.INTERNAL: "⚪"
            }.get(module_doc.stability, "⚪")
            
            md.append(f"### {stability_icon} {module_name}")
            md.append(f"**Category:** {module_doc.category}")
            md.append(f"**Stability:** {module_doc.stability.value}")
            md.append("")
            md.append(module_doc.overview)
            md.append("")
            
            if module_doc.endpoints:
                md.append("#### Endpoints")
                md.append("")
                for ep in module_doc.endpoints:
                    md.append(f"- `{ep.name}` - {ep.description}")
                md.append("")
        
        return "\n".join(md)
    
    def export_json(self) -> str:
        """Export catalog as JSON for machine consumption"""
        data = {
            "catalog_version": self.catalog_version,
            "last_updated": self.last_updated,
            "modules": {
                name: {
                    "module_name": mod.module_name,
                    "stability": mod.stability.value,
                    "category": mod.category,
                    "overview": mod.overview,
                    "endpoints_count": len(mod.endpoints)
                }
                for name, mod in self.modules.items()
            }
        }
        return json.dumps(data, indent=2)


# Singleton instance for easy import
_documentation_catalog = None

def get_documentation_catalog() -> NeuralShieldAPIDocumentationCatalog:
    """Get the singleton documentation catalog instance"""
    global _documentation_catalog
    if _documentation_catalog is None:
        _documentation_catalog = NeuralShieldAPIDocumentationCatalog()
    return _documentation_catalog


__all__ = [
    "NeuralShieldAPIDocumentationCatalog",
    "StabilityLevel",
    "APIEndpointDoc",
    "ModuleDoc",
    "get_documentation_catalog"
]
