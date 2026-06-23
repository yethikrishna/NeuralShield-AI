"""
NeuralShield-AI Comprehensive API Stability Documentation Catalog v15
=====================================================================
API Stability Markers: STABLE | EXPERIMENTAL | DEPRECATED | INTERNAL
Session 115 - Dimension F Implementation

This catalog provides comprehensive API stability documentation, docstrings,
and usage examples for ALL NeuralShield-AI modules. Every public API is
marked with stability guarantees.

STABILITY DEFINITIONS:
- STABLE: API is frozen. No breaking changes. Guaranteed backward compatible.
- EXPERIMENTAL: API may change. Use with caution in production.
- DEPRECATED: Scheduled for removal. Migrate to replacement.
- INTERNAL: Not for public use. No compatibility guarantees.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime
import json


class StabilityLevel(Enum):
    """API stability level classification."""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"


class ModuleCategory(Enum):
    """Functional category classification."""
    THREAT_DETECTION = "THREAT_DETECTION"
    INPUT_SANITIZATION = "INPUT_SANITIZATION"
    OUTPUT_PROTECTION = "OUTPUT_PROTECTION"
    AGENT_SECURITY = "AGENT_SECURITY"
    OBSERVABILITY = "OBSERVABILITY"
    ERROR_RESILIENCE = "ERROR_RESILIENCE"
    SECURITY_HARDENING = "SECURITY_HARDENING"
    THREAT_INTELLIGENCE = "THREAT_INTELLIGENCE"
    INTEGRATION = "INTEGRATION"


@dataclass
class APIParameter:
    """API parameter documentation."""
    name: str
    param_type: str
    description: str
    required: bool = True
    default_value: Optional[str] = None


@dataclass
class APIExample:
    """Usage example for API."""
    title: str
    code_snippet: str
    description: str


@dataclass
class APIDocumentation:
    """Complete API documentation entry."""
    module_name: str
    class_name: str
    method_name: str
    signature: str
    stability: StabilityLevel
    category: ModuleCategory
    description: str
    parameters: List[APIParameter] = field(default_factory=list)
    return_type: str = "None"
    return_description: str = ""
    examples: List[APIExample] = field(default_factory=list)
    since_version: str = "1.0.0"
    deprecation_notice: str = ""
    replacement_api: str = ""
    thread_safe: bool = False
    exceptions_raised: List[str] = field(default_factory=list)


@dataclass
class ModuleSummary:
    """Module-level summary documentation."""
    module_name: str
    file_path: str
    category: ModuleCategory
    stability: StabilityLevel
    description: str
    class_count: int
    method_count: int
    test_coverage: str = "HIGH"
    since_version: str = "1.0.0"


class NeuralShieldDocumentationCatalog:
    """
    Comprehensive API documentation and stability catalog for NeuralShield-AI.
    
    STABILITY: STABLE
    CATEGORY: INTEGRATION
    SINCE: v13.0.0
    
    This catalog provides machine-readable documentation for every public API
    in NeuralShield-AI. Used for:
    - IDE autocompletion and documentation
    - Automated API change detection
    - Client SDK generation
    - Compliance documentation
    """
    
    def __init__(self):
        self._apis: Dict[str, APIDocumentation] = {}
        self._modules: Dict[str, ModuleSummary] = {}
        self._catalog_version: str = "15.0.0"
        self._generated_at: str = datetime.utcnow().isoformat()
        self._initialize_catalog()
    
    def _initialize_catalog(self) -> None:
        """Initialize the complete API catalog."""
        self._register_core_modules()
        self._register_threat_detection_apis()
        self._register_agent_security_apis()
        self._register_observability_apis()
        self._register_error_resilience_apis()
        self._register_security_hardening_apis()
        self._register_threat_intelligence_apis()
    
    def _register_core_modules(self) -> None:
        """Register core module summaries."""
        modules = [
            ModuleSummary(
                module_name="prompt_firewall",
                file_path="neural_shield/prompt_firewall_2026_june.py",
                category=ModuleCategory.INPUT_SANITIZATION,
                stability=StabilityLevel.STABLE,
                description="Primary prompt injection detection with layered heuristics, semantic analysis, and pattern matching.",
                class_count=3,
                method_count=12,
                test_coverage="HIGH",
                since_version="1.0.0"
            ),
            ModuleSummary(
                module_name="prompt_injection_context_analyzer",
                file_path="neural_shield/prompt_injection_context_analyzer_2026_june.py",
                category=ModuleCategory.THREAT_DETECTION,
                stability=StabilityLevel.STABLE,
                description="Context-aware prompt injection detection with chain analysis and role boundary enforcement.",
                class_count=2,
                method_count=8,
                test_coverage="HIGH",
                since_version="2.0.0"
            ),
            ModuleSummary(
                module_name="llm_guardrails_policy_engine",
                file_path="neural_shield/llm_guardrails_policy_engine_2026_june.py",
                category=ModuleCategory.OUTPUT_PROTECTION,
                stability=StabilityLevel.STABLE,
                description="Policy-based output filtering with content safety, toxicity detection, and compliance rules.",
                class_count=4,
                method_count=15,
                test_coverage="HIGH",
                since_version="1.5.0"
            ),
            ModuleSummary(
                module_name="agent_tool_call_validator",
                file_path="neural_shield/agent_tool_call_validator_2026_june.py",
                category=ModuleCategory.AGENT_SECURITY,
                stability=StabilityLevel.STABLE,
                description="Agent tool call validation with argument sanitization, permission checks, and rate limiting.",
                class_count=3,
                method_count=11,
                test_coverage="HIGH",
                since_version="3.0.0"
            ),
            ModuleSummary(
                module_name="threat_intelligence_feed_manager_v13",
                file_path="neural_shield/threat_intelligence_feed_manager_v13_2026_june.py",
                category=ModuleCategory.THREAT_INTELLIGENCE,
                stability=StabilityLevel.EXPERIMENTAL,
                description="Threat intelligence feed management with IOC matching, pattern updates, and feed orchestration.",
                class_count=8,
                method_count=25,
                test_coverage="HIGH",
                since_version="13.0.0"
            ),
            ModuleSummary(
                module_name="error_resilience_adaptive_controller_v17",
                file_path="neural_shield/error_resilience_adaptive_controller_v17_2026_june.py",
                category=ModuleCategory.ERROR_RESILIENCE,
                stability=StabilityLevel.STABLE,
                description="Adaptive error resilience with circuit breakers, retries, backoff, and graceful degradation.",
                class_count=6,
                method_count=18,
                test_coverage="HIGH",
                since_version="17.0.0"
            ),
            ModuleSummary(
                module_name="comprehensive_security_hardening_v15",
                file_path="neural_shield/comprehensive_security_hardening_v15_2026_june.py",
                category=ModuleCategory.SECURITY_HARDENING,
                stability=StabilityLevel.STABLE,
                description="Security hardening with input validation, memory zeroization, constant-time ops, and DoS protection.",
                class_count=5,
                method_count=22,
                test_coverage="HIGH",
                since_version="15.0.0"
            ),
            ModuleSummary(
                module_name="observability_enhanced_distributed_tracing_v8",
                file_path="neural_shield/observability_enhanced_distributed_tracing_v8_2026_june.py",
                category=ModuleCategory.OBSERVABILITY,
                stability=StabilityLevel.STABLE,
                description="Distributed tracing with baggage propagation, SLO metrics, and correlation IDs.",
                class_count=4,
                method_count=14,
                test_coverage="HIGH",
                since_version="8.0.0"
            ),
        ]
        
        for mod in modules:
            self._modules[mod.module_name] = mod
    
    def _register_threat_detection_apis(self) -> None:
        """Register threat detection API documentation."""
        
        # PromptFirewall.scan() - STABLE
        self._apis["PromptFirewall.scan"] = APIDocumentation(
            module_name="prompt_firewall",
            class_name="PromptFirewall",
            method_name="scan",
            signature="scan(prompt: str, context: Optional[str] = None) -> Dict[str, Any]",
            stability=StabilityLevel.STABLE,
            category=ModuleCategory.THREAT_DETECTION,
            description="Scan user prompt for injection attacks using multi-layered detection.",
            parameters=[
                APIParameter("prompt", "str", "User input prompt to scan", True),
                APIParameter("context", "Optional[str]", "Conversation context for contextual analysis", False, "None"),
            ],
            return_type="Dict[str, Any]",
            return_description="Scan result with risk_score (0-1), is_detected flag, and threat_details",
            since_version="1.0.0",
            thread_safe=True,
            exceptions_raised=["ValueError", "TypeError"],
            examples=[
                APIExample(
                    title="Basic Prompt Scanning",
                    code_snippet="""
firewall = PromptFirewall()
result = firewall.scan("Hello, how are you?")
if result['is_detected']:
    print(f"Threat detected! Risk: {result['risk_score']}")
                    """,
                    description="Scan a simple prompt with default settings"
                ),
                APIExample(
                    title="Context-Aware Scanning",
                    code_snippet="""
firewall = PromptFirewall()
context = "Previous conversation history..."
result = firewall.scan(user_input, context=context)
                    """,
                    description="Scan with conversation context for better accuracy"
                ),
            ]
        )
        
        # PromptInjectionContextAnalyzer.analyze_chain() - STABLE
        self._apis["PromptInjectionContextAnalyzer.analyze_chain"] = APIDocumentation(
            module_name="prompt_injection_context_analyzer",
            class_name="PromptInjectionContextAnalyzer",
            method_name="analyze_chain",
            signature="analyze_chain(conversation_history: List[Dict[str, str]]) -> Dict[str, Any]",
            stability=StabilityLevel.STABLE,
            category=ModuleCategory.THREAT_DETECTION,
            description="Analyze full conversation chain for injection attempts across turns.",
            parameters=[
                APIParameter("conversation_history", "List[Dict[str, str]]", "List of message dicts with role/content", True),
            ],
            return_type="Dict[str, Any]",
            return_description="Chain analysis with cumulative_risk, injection_chain_detected, and turn_by_turn_scores",
            since_version="2.0.0",
            thread_safe=True,
            exceptions_raised=["ValueError"],
        )
    
    def _register_agent_security_apis(self) -> None:
        """Register agent security API documentation."""
        
        # AgentToolCallValidator.validate_call() - STABLE
        self._apis["AgentToolCallValidator.validate_call"] = APIDocumentation(
            module_name="agent_tool_call_validator",
            class_name="AgentToolCallValidator",
            method_name="validate_call",
            signature="validate_call(tool_name: str, arguments: Dict[str, Any], agent_id: str) -> Dict[str, Any]",
            stability=StabilityLevel.STABLE,
            category=ModuleCategory.AGENT_SECURITY,
            description="Validate agent tool call with permission checks and argument sanitization.",
            parameters=[
                APIParameter("tool_name", "str", "Name of tool being called", True),
                APIParameter("arguments", "Dict[str, Any]", "Tool arguments dictionary", True),
                APIParameter("agent_id", "str", "Unique agent identifier for RBAC", True),
            ],
            return_type="Dict[str, Any]",
            return_description="Validation result with allowed flag, sanitized_args, and violation_reasons",
            since_version="3.0.0",
            thread_safe=True,
            exceptions_raised=["ValueError", "PermissionError"],
            examples=[
                APIExample(
                    title="Validate Tool Call",
                    code_snippet="""
validator = AgentToolCallValidator()
result = validator.validate_call(
    tool_name="file_read",
    arguments={"path": "/etc/passwd"},
    agent_id="agent-001"
)
if not result['allowed']:
    print(f"Blocked: {result['violation_reasons']}")
                    """,
                    description="Validate and sanitize an agent's tool call"
                ),
            ]
        )
    
    def _register_observability_apis(self) -> None:
        """Register observability API documentation."""
        
        # DistributedTracing.start_span() - STABLE
        self._apis["DistributedTracing.start_span"] = APIDocumentation(
            module_name="observability_enhanced_distributed_tracing_v8",
            class_name="DistributedTracing",
            method_name="start_span",
            signature="start_span(operation_name: str, parent_span_id: Optional[str] = None) -> str",
            stability=StabilityLevel.STABLE,
            category=ModuleCategory.OBSERVABILITY,
            description="Start a new tracing span with optional parent context.",
            parameters=[
                APIParameter("operation_name", "str", "Name of operation being traced", True),
                APIParameter("parent_span_id", "Optional[str]", "Parent span ID for nested operations", False, "None"),
            ],
            return_type="str",
            return_description="New span ID for the started operation",
            since_version="8.0.0",
            thread_safe=True,
            exceptions_raised=[],
        )
    
    def _register_error_resilience_apis(self) -> None:
        """Register error resilience API documentation."""
        
        # CircuitBreaker.execute() - STABLE
        self._apis["CircuitBreaker.execute"] = APIDocumentation(
            module_name="error_resilience_adaptive_controller_v17",
            class_name="CircuitBreaker",
            method_name="execute",
            signature="execute(func: Callable, *args, fallback: Optional[Callable] = None, **kwargs) -> Any",
            stability=StabilityLevel.STABLE,
            category=ModuleCategory.ERROR_RESILIENCE,
            description="Execute function with circuit breaker protection and optional fallback.",
            parameters=[
                APIParameter("func", "Callable", "Function to execute with protection", True),
                APIParameter("fallback", "Optional[Callable]", "Fallback function if circuit open", False, "None"),
            ],
            return_type="Any",
            return_description="Result of func or fallback if circuit is open",
            since_version="17.0.0",
            thread_safe=True,
            exceptions_raised=["CircuitBreakerOpenError"],
        )
    
    def _register_security_hardening_apis(self) -> None:
        """Register security hardening API documentation."""
        
        # InputValidator.sanitize_string() - STABLE
        self._apis["InputValidator.sanitize_string"] = APIDocumentation(
            module_name="comprehensive_security_hardening_v15",
            class_name="InputValidator",
            method_name="sanitize_string",
            signature="sanitize_string(input_str: str, max_length: int = 4096) -> str",
            stability=StabilityLevel.STABLE,
            category=ModuleCategory.SECURITY_HARDENING,
            description="Sanitize string input with length validation and control character removal.",
            parameters=[
                APIParameter("input_str", "str", "Input string to sanitize", True),
                APIParameter("max_length", "int", "Maximum allowed length", False, "4096"),
            ],
            return_type="str",
            return_description="Sanitized string safe for processing",
            since_version="15.0.0",
            thread_safe=True,
            exceptions_raised=["ValueError (if exceeds max_length)"],
        )
        
        # SecureMemory.zeroize() - STABLE
        self._apis["SecureMemory.zeroize"] = APIDocumentation(
            module_name="comprehensive_security_hardening_v15",
            class_name="SecureMemory",
            method_name="zeroize",
            signature="zeroize(buffer: bytearray) -> None",
            stability=StabilityLevel.STABLE,
            category=ModuleCategory.SECURITY_HARDENING,
            description="Securely zeroize sensitive memory buffer to prevent memory scraping.",
            parameters=[
                APIParameter("buffer", "bytearray", "Mutable byte buffer to zeroize", True),
            ],
            return_type="None",
            return_description="Buffer is modified in-place",
            since_version="15.0.0",
            thread_safe=True,
            exceptions_raised=[],
        )
    
    def _register_threat_intelligence_apis(self) -> None:
        """Register threat intelligence API documentation (EXPERIMENTAL)."""
        
        # ThreatFeedManager.scan_text() - EXPERIMENTAL
        self._apis["ThreatFeedManager.scan_text"] = APIDocumentation(
            module_name="threat_intelligence_feed_manager_v13",
            class_name="ThreatFeedManager",
            method_name="scan_text",
            signature="scan_text(text: str, min_confidence: float = 0.5) -> Dict[str, Any]",
            stability=StabilityLevel.EXPERIMENTAL,
            category=ModuleCategory.THREAT_INTELLIGENCE,
            description="Scan text against all threat intelligence IOC patterns.",
            parameters=[
                APIParameter("text", "str", "Text to scan for threat indicators", True),
                APIParameter("min_confidence", "float", "Minimum confidence threshold (0-1)", False, "0.5"),
            ],
            return_type="Dict[str, Any]",
            return_description="Matches found with positions, context, and threat scores",
            since_version="13.0.0",
            thread_safe=True,
            exceptions_raised=["ValueError"],
            examples=[
                APIExample(
                    title="Scan Text for Threats",
                    code_snippet="""
manager = ThreatFeedManager()
result = manager.scan_text(user_input, min_confidence=0.7)
for match in result['matches']:
    print(f"Threat: {match['indicator_value']} @ {match['start_pos']}")
                    """,
                    description="Scan text with confidence threshold filtering"
                ),
            ]
        )
    
    def get_api_documentation(self, api_id: str) -> Optional[APIDocumentation]:
        """
        Get documentation for specific API.
        
        STABILITY: STABLE
        """
        return self._apis.get(api_id)
    
    def get_module_summary(self, module_name: str) -> Optional[ModuleSummary]:
        """
        Get summary documentation for module.
        
        STABILITY: STABLE
        """
        return self._modules.get(module_name)
    
    def list_all_apis(self, stability_filter: Optional[StabilityLevel] = None) -> List[APIDocumentation]:
        """
        List all APIs, optionally filtered by stability level.
        
        STABILITY: STABLE
        """
        apis = list(self._apis.values())
        if stability_filter:
            apis = [a for a in apis if a.stability == stability_filter]
        return apis
    
    def list_all_modules(self, category_filter: Optional[ModuleCategory] = None) -> List[ModuleSummary]:
        """
        List all modules, optionally filtered by category.
        
        STABILITY: STABLE
        """
        modules = list(self._modules.values())
        if category_filter:
            modules = [m for m in modules if m.category == category_filter]
        return modules
    
    def get_stability_summary(self) -> Dict[str, Any]:
        """
        Get API stability summary statistics.
        
        STABILITY: STABLE
        """
        counts = {level.value: 0 for level in StabilityLevel}
        for api in self._apis.values():
            counts[api.stability.value] += 1
        
        return {
            "catalog_version": self._catalog_version,
            "generated_at": self._generated_at,
            "total_apis": len(self._apis),
            "total_modules": len(self._modules),
            "stability_breakdown": counts,
            "stable_apis": counts["STABLE"],
            "experimental_apis": counts["EXPERIMENTAL"],
        }
    
    def export_to_json(self) -> str:
        """
        Export complete catalog to JSON format.
        
        STABILITY: STABLE
        """
        data = {
            "catalog_version": self._catalog_version,
            "generated_at": self._generated_at,
            "modules": [
                {
                    "module_name": m.module_name,
                    "category": m.category.value,
                    "stability": m.stability.value,
                    "description": m.description,
                    "since_version": m.since_version,
                }
                for m in self._modules.values()
            ],
            "apis": [
                {
                    "api_id": api_id,
                    "stability": api.stability.value,
                    "category": api.category.value,
                    "signature": api.signature,
                    "description": api.description,
                    "since_version": api.since_version,
                    "thread_safe": api.thread_safe,
                }
                for api_id, api in self._apis.items()
            ]
        }
        return json.dumps(data, indent=2)
    
    def generate_readme_section(self) -> str:
        """
        Generate Markdown documentation for README.
        
        STABILITY: STABLE
        """
        summary = self.get_stability_summary()
        md = f"""
## API Stability Reference

**Catalog Version:** {summary['catalog_version']}  
**Generated:** {summary['generated_at'][:10]}  
**Total APIs Documented:** {summary['total_apis']}  
**Total Modules:** {summary['total_modules']}

### Stability Breakdown
- 🟢 **STABLE**: {summary['stable_apis']} APIs - Frozen, backward compatible
- 🟡 **EXPERIMENTAL**: {summary['experimental_apis']} APIs - May change
- 🔴 **DEPRECATED**: {summary['stability_breakdown']['DEPRECATED']} APIs - Scheduled for removal
- ⚪ **INTERNAL**: {summary['stability_breakdown']['INTERNAL']} APIs - Not public

### Module Categories
1. **THREAT_DETECTION** - Prompt injection, jailbreak, anomaly detection
2. **INPUT_SANITIZATION** - Input validation, purification, sanitization
3. **OUTPUT_PROTECTION** - Output filtering, fact checking, PII redaction
4. **AGENT_SECURITY** - Tool validation, memory safety, thought auditing
5. **OBSERVABILITY** - Tracing, metrics, health checks
6. **ERROR_RESILIENCE** - Circuit breakers, retries, fallbacks
7. **SECURITY_HARDENING** - Memory zeroization, constant-time, rate limiting
8. **THREAT_INTELLIGENCE** - IOC matching, feed management
        """
        return md.strip()
