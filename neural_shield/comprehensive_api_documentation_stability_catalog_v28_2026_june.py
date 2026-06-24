"""
NeuralShield AI - Comprehensive API Documentation & Stability Catalog v28
Session 137 - Dimension F: Documentation & API Stability
June 25, 2026

ADD-ONLY IMPLEMENTATION: No existing code modified.
This module provides comprehensive API documentation, usage examples,
and API stability markers for the NeuralShield ecosystem.

API STABILITY MARKERS:
- STABLE: Production-ready, guaranteed backward compatible
- EXPERIMENTAL: New feature, subject to change
- DEPRECATED: Will be removed in future versions
- LEGACY: Maintained for backward compatibility only
"""

import typing
from typing import Dict, List, Any, Optional, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
import datetime


class APIStability(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class APIEndpointDoc:
    """Documentation for a single API endpoint/function"""
    name: str
    module: str
    stability: APIStability
    description: str
    signature: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    since_version: str = "1.0.0"
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None


@dataclass
class ModuleDoc:
    """Documentation for an entire module"""
    module_name: str
    category: str
    stability: APIStability
    overview: str
    endpoints: List[APIEndpointDoc] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    usage_guide: str = ""


class NeuralShieldAPIDocumentationCatalog:
    """
    Comprehensive API Documentation Catalog for NeuralShield AI
    
    STABILITY: STABLE
    SINCE: v28.0.0
    
    This catalog provides:
    1. Complete API reference with stability markers
    2. Usage examples for all major functions
    3. Migration guides between versions
    4. Deprecation warnings and timelines
    """
    
    def __init__(self):
        self._modules: Dict[str, ModuleDoc] = {}
        self._stability_stats: Dict[APIStability, int] = {
            APIStability.STABLE: 0,
            APIStability.EXPERIMENTAL: 0,
            APIStability.DEPRECATED: 0,
            APIStability.LEGACY: 0
        }
        self._generated_at = datetime.datetime.now().isoformat()
        self._initialize_catalog()
    
    def _initialize_catalog(self) -> None:
        """Initialize the complete API documentation catalog"""
        self._register_threat_detection_module()
        self._register_security_hardening_module()
        self._register_threat_intelligence_module()
        self._register_observability_module()
        self._register_error_resilience_module()
        self._register_agent_security_module()
    
    def _register_threat_detection_module(self) -> None:
        """Register Threat Detection Module documentation"""
        module = ModuleDoc(
            module_name="threat_detection",
            category="Core Security",
            stability=APIStability.STABLE,
            overview="Core threat detection engines for prompt injection, jailbreak, and adversarial attacks"
        )
        
        module.endpoints.append(APIEndpointDoc(
            name="detect_prompt_injection",
            module="adversarial_prompt_anomaly_detector",
            stability=APIStability.STABLE,
            description="Detect prompt injection attacks using anomaly detection",
            signature="detect_prompt_injection(prompt: str, threshold: float = 0.85) -> Dict[str, Any]",
            parameters=[
                {"name": "prompt", "type": "str", "description": "Input prompt to analyze"},
                {"name": "threshold", "type": "float", "description": "Detection confidence threshold (0.0-1.0)"}
            ],
            returns="Dictionary with 'risk_score', 'is_detected', 'attack_type', 'confidence'",
            examples=[
                """
result = detect_prompt_injection("Ignore previous instructions")
if result['is_detected']:
    print(f"Attack detected: {result['attack_type']}")
                """.strip()
            ],
            notes=["Uses ensemble of 5 detection methods", "False positive rate < 0.1% on benign prompts"],
            since_version="v12.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="detect_jailbreak_attempt",
            module="advanced_jailbreak_detector",
            stability=APIStability.STABLE,
            description="Detect jailbreak attempts including DAN, Dev Mode, and role-play attacks",
            signature="detect_jailbreak_attempt(prompt: str) -> Dict[str, Any]",
            parameters=[
                {"name": "prompt", "type": "str", "description": "Input prompt to analyze"}
            ],
            returns="Dictionary with 'risk_level', 'jailbreak_detected', 'techniques', 'confidence'",
            examples=[
                """
result = detect_jailbreak_attempt("You are DAN, Do Anything Now...")
print(f"Risk Level: {result['risk_level']}")
                """.strip()
            ],
            notes=["Covers 50+ known jailbreak patterns", "Includes semantic analysis"],
            since_version="v15.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="detect_multimodal_injection",
            module="multimodal_prompt_injection_detector",
            stability=APIStability.EXPERIMENTAL,
            description="Detect prompt injection in multimodal inputs (text + images)",
            signature="detect_multimodal_injection(text: str, image_features: List[float]) -> Dict[str, Any]",
            parameters=[
                {"name": "text", "type": "str", "description": "Text component of input"},
                {"name": "image_features", "type": "List[float]", "description": "Extracted image features"}
            ],
            returns="Dictionary with multimodal risk assessment",
            examples=[
                """
# Experimental feature - API may change
result = detect_multimodal_injection(text, img_features)
                """.strip()
            ],
            notes=["EXPERIMENTAL: Under active development"],
            since_version="v25.0.0"
        ))
        
        self._modules["threat_detection"] = module
        self._update_stability_stats(module)
    
    def _register_security_hardening_module(self) -> None:
        """Register Security Hardening Module documentation"""
        module = ModuleDoc(
            module_name="security_hardening",
            category="Protection",
            stability=APIStability.STABLE,
            overview="Security hardening utilities including input validation, memory protection, and rate limiting"
        )
        
        module.endpoints.append(APIEndpointDoc(
            name="constant_time_bytes_equal",
            module="security_hardening_advanced_side_channel_protection",
            stability=APIStability.STABLE,
            description="Constant-time byte comparison to prevent timing attacks",
            signature="constant_time_bytes_equal(a: bytes, b: bytes) -> bool",
            parameters=[
                {"name": "a", "type": "bytes", "description": "First byte string"},
                {"name": "b", "type": "bytes", "description": "Second byte string"}
            ],
            returns="True if equal, False otherwise (execution time independent of content)",
            examples=[
                """
# Use for API key comparison, token validation
if constant_time_bytes_equal(stored_key, provided_key):
    grant_access()
                """.strip()
            ],
            notes=["Execution time depends only on length, not content", "Use for ALL security-sensitive comparisons"],
            since_version="v23.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="SecureMemory",
            module="security_hardening_advanced_side_channel_protection",
            stability=APIStability.STABLE,
            description="Secure memory container with automatic zeroization",
            signature="SecureMemory(initial_value: Optional[bytes] = None)",
            parameters=[
                {"name": "initial_value", "type": "Optional[bytes]", "description": "Initial value to store"}
            ],
            returns="Context manager for secure memory handling",
            examples=[
                """
with SecureMemory(api_key) as secure_key:
    validate_key(secure_key.get())
# Memory automatically wiped after context exit
                """.strip()
            ],
            notes=["4-pass zeroization: 0x00 → 0xFF → Random → 0x00", "Cannot protect immutable Python objects"],
            since_version="v23.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="AdaptiveRateLimiter",
            module="security_hardening_adaptive_rate_limiting",
            stability=APIStability.STABLE,
            description="Adaptive rate limiter with DoS protection",
            signature="AdaptiveRateLimiter(requests_per_minute: int = 60, burst_limit: int = 100)",
            parameters=[
                {"name": "requests_per_minute", "type": "int", "description": "Sustained rate limit"},
                {"name": "burst_limit", "type": "int", "description": "Maximum burst capacity"}
            ],
            returns="Rate limiter instance",
            examples=[
                """
limiter = AdaptiveRateLimiter(requests_per_minute=100)
if limiter.check_and_consume(client_ip):
    process_request()
                """.strip()
            ],
            since_version="v11.0.0"
        ))
        
        self._modules["security_hardening"] = module
        self._update_stability_stats(module)
    
    def _register_threat_intelligence_module(self) -> None:
        """Register Threat Intelligence Module documentation"""
        module = ModuleDoc(
            module_name="threat_intelligence",
            category="Intelligence",
            stability=APIStability.STABLE,
            overview="Threat intelligence feeds, IOC validation, CVE scoring, and MITRE ATT&CK mapping"
        )
        
        module.endpoints.append(APIEndpointDoc(
            name="validate_ioc_hash",
            module="threat_intelligence_ioc_hash_validator",
            stability=APIStability.STABLE,
            description="Validate and classify IOC hash (MD5, SHA1, SHA256)",
            signature="validate_ioc_hash(hash_value: str) -> Dict[str, Any]",
            parameters=[
                {"name": "hash_value", "type": "str", "description": "Hash to validate"}
            ],
            returns="Dictionary with 'is_valid', 'hash_type', 'format_valid', 'risk_level'",
            examples=[
                """
result = validate_ioc_hash("d41d8cd98f00b204e9800998ecf8427e")
if result['is_valid']:
    print(f"Valid {result['hash_type']} hash")
                """.strip()
            ],
            since_version="v16.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="calculate_cvss_v31_score",
            module="threat_intelligence_cve_cvss_v31_scoring_engine",
            stability=APIStability.STABLE,
            description="Calculate CVSS v3.1 base score from vector string",
            signature="calculate_cvss_v31_score(cvss_vector: str) -> Dict[str, Any]",
            parameters=[
                {"name": "cvss_vector", "type": "str", "description": "CVSS v3.1 vector string"}
            ],
            returns="Dictionary with 'base_score', 'severity', 'metrics'",
            examples=[
                """
result = calculate_cvss_v31_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
print(f"CVSS Score: {result['base_score']} ({result['severity']})")
                """.strip()
            ],
            notes=["Full CVSS v3.1 specification compliance"],
            since_version="v16.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="MITREAttackMapper",
            module="threat_intelligence_mitre_attack_navigator_integration",
            stability=APIStability.STABLE,
            description="Map threats to MITRE ATT&CK framework tactics and techniques",
            signature="MITREAttackMapper()",
            returns="MITRE mapping instance",
            examples=[
                """
mapper = MITREAttackMapper()
mapping = mapper.map_threat_to_mitre("prompt_injection")
print(f"Tactics: {mapping['tactics']}")
                """.strip()
            ],
            since_version="v14.0.0"
        ))
        
        self._modules["threat_intelligence"] = module
        self._update_stability_stats(module)
    
    def _register_observability_module(self) -> None:
        """Register Observability Module documentation"""
        module = ModuleDoc(
            module_name="observability",
            category="Monitoring",
            stability=APIStability.STABLE,
            overview="Structured logging, metrics collection, and health monitoring"
        )
        
        module.endpoints.append(APIEndpointDoc(
            name="StructuredLogger",
            module="comprehensive_observability_instrumentation",
            stability=APIStability.STABLE,
            description="Structured JSON logger with optional telemetry",
            signature="StructuredLogger(service_name: str, enabled: bool = False)",
            parameters=[
                {"name": "service_name", "type": "str", "description": "Service identifier"},
                {"name": "enabled", "type": "bool", "description": "Logging is OPT-IN, disabled by default"}
            ],
            returns="Logger instance",
            examples=[
                """
# OPT-IN - must explicitly enable
logger = StructuredLogger("api_gateway", enabled=True)
logger.info("request_processed", latency_ms=45, status=200)
                """.strip()
            ],
            notes=["ZERO overhead when disabled", "All instrumentation is OPT-IN"],
            since_version="v16.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="MetricsCollector",
            module="comprehensive_observability_instrumentation",
            stability=APIStability.STABLE,
            description="Counters, timers, and gauges for metrics collection",
            signature="MetricsCollector(enabled: bool = False)",
            returns="Metrics collector instance",
            examples=[
                """
metrics = MetricsCollector(enabled=True)
with metrics.timer("request_latency"):
    process_request()
metrics.increment("requests_total")
                """.strip()
            ],
            notes=["ZERO overhead when disabled"],
            since_version="v16.0.0"
        ))
        
        self._modules["observability"] = module
        self._update_stability_stats(module)
    
    def _register_error_resilience_module(self) -> None:
        """Register Error Resilience Module documentation"""
        module = ModuleDoc(
            module_name="error_resilience",
            category="Reliability",
            stability=APIStability.STABLE,
            overview="Retry with backoff, circuit breakers, timeouts, and graceful degradation"
        )
        
        module.endpoints.append(APIEndpointDoc(
            name="retry_with_backoff",
            module="error_resilience_retry_backoff_circuit_breaker",
            stability=APIStability.STABLE,
            description="Retry decorator with exponential backoff and jitter",
            signature="retry_with_backoff(max_attempts: int = 3, base_delay: float = 1.0)",
            parameters=[
                {"name": "max_attempts", "type": "int", "description": "Maximum retry attempts"},
                {"name": "base_delay", "type": "float", "description": "Base delay in seconds"}
            ],
            returns="Decorator function",
            examples=[
                """
@retry_with_backoff(max_attempts=5)
def call_external_api():
    return requests.get("https://api.example.com/data")
                """.strip()
            ],
            notes=["Full jitter applied to prevent thundering herd"],
            since_version="v17.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="CircuitBreaker",
            module="error_resilience_advanced_circuit_breaker",
            stability=APIStability.STABLE,
            description="Circuit breaker pattern for fault tolerance",
            signature="CircuitBreaker(failure_threshold: int = 5, recovery_timeout: float = 30.0)",
            returns="Circuit breaker instance",
            examples=[
                """
breaker = CircuitBreaker(failure_threshold=10)
with breaker:
    risky_operation()
                """.strip()
            ],
            since_version="v23.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="timeout",
            module="error_resilience_adaptive_controller",
            stability=APIStability.STABLE,
            description="Timeout decorator to prevent hanging operations",
            signature="timeout(seconds: float)",
            parameters=[
                {"name": "seconds", "type": "float", "description": "Timeout in seconds"}
            ],
            returns="Decorator function",
            examples=[
                """
@timeout(5.0)
def potentially_slow_operation():
    return long_running_computation()
                """.strip()
            ],
            since_version="v17.0.0"
        ))
        
        self._modules["error_resilience"] = module
        self._update_stability_stats(module)
    
    def _register_agent_security_module(self) -> None:
        """Register Agent Security Module documentation"""
        module = ModuleDoc(
            module_name="agent_security",
            category="Agent Protection",
            stability=APIStability.STABLE,
            overview="Security for AI agents including tool call validation and memory safety"
        )
        
        module.endpoints.append(APIEndpointDoc(
            name="validate_tool_call",
            module="agent_tool_call_validator",
            stability=APIStability.STABLE,
            description="Validate agent tool calls for safety",
            signature="validate_tool_call(tool_name: str, parameters: Dict[str, Any]) -> Dict[str, Any]",
            parameters=[
                {"name": "tool_name", "type": "str", "description": "Name of tool being called"},
                {"name": "parameters", "type": "Dict", "description": "Tool parameters"}
            ],
            returns="Validation result with 'allowed', 'risk_assessment', 'reason'",
            examples=[
                """
result = validate_tool_call("exec_command", {"cmd": "rm -rf /"})
if not result['allowed']:
    print(f"Blocked: {result['reason']}")
                """.strip()
            ],
            since_version="v18.0.0"
        ))
        
        module.endpoints.append(APIEndpointDoc(
            name="AgentMemorySafetyMonitor",
            module="agent_memory_safety_monitor",
            stability=APIStability.STABLE,
            description="Monitor agent memory for poisoning attacks",
            signature="AgentMemorySafetyMonitor()",
            returns="Safety monitor instance",
            examples=[
                """
monitor = AgentMemorySafetyMonitor()
if monitor.detect_poisoning(memory_context):
    trigger_alert()
                """.strip()
            ],
            since_version="v18.0.0"
        ))
        
        self._modules["agent_security"] = module
        self._update_stability_stats(module)
    
    def _update_stability_stats(self, module: ModuleDoc) -> None:
        """Update stability statistics"""
        for endpoint in module.endpoints:
            self._stability_stats[endpoint.stability] += 1
    
    def get_module_documentation(self, module_name: str) -> Optional[ModuleDoc]:
        """Get documentation for a specific module"""
        return self._modules.get(module_name)
    
    def get_all_modules(self) -> List[str]:
        """Get list of all documented modules"""
        return list(self._modules.keys())
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary of API stability distribution"""
        return {
            stability.value: count
            for stability, count in self._stability_stats.items()
        }
    
    def get_endpoints_by_stability(self, stability: APIStability) -> List[APIEndpointDoc]:
        """Get all endpoints with specific stability level"""
        endpoints = []
        for module in self._modules.values():
            for endpoint in module.endpoints:
                if endpoint.stability == stability:
                    endpoints.append(endpoint)
        return endpoints
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive Markdown documentation"""
        lines = [
            "# NeuralShield AI - API Documentation Catalog",
            f"**Generated:** {self._generated_at}",
            f"**Version:** v28",
            "",
            "## API Stability Summary",
            ""
        ]
        
        for stability, count in self._stability_stats.items():
            lines.append(f"- **{stability.value}**: {count} endpoints")
        
        lines.extend(["", "---", ""])
        
        for module_name, module in sorted(self._modules.items()):
            lines.extend([
                f"## Module: {module.module_name}",
                f"**Category:** {module.category}",
                f"**Stability:** {module.stability.value}",
                "",
                module.overview,
                ""
            ])
            
            for endpoint in module.endpoints:
                stability_badge = f"[{endpoint.stability.value}]"
                if endpoint.stability == APIStability.EXPERIMENTAL:
                    stability_badge = "⚠️ [EXPERIMENTAL]"
                elif endpoint.stability == APIStability.DEPRECATED:
                    stability_badge = "❌ [DEPRECATED]"
                
                lines.extend([
                    f"### {endpoint.name} {stability_badge}",
                    "",
                    endpoint.description,
                    "",
                    f"**Signature:** `{endpoint.signature}`",
                    f"**Since:** {endpoint.since_version}",
                    "",
                    "**Parameters:**",
                    ""
                ])
                
                for param in endpoint.parameters:
                    lines.append(f"- `{param['name']}` ({param['type']}): {param['description']}")
                
                lines.extend([
                    "",
                    f"**Returns:** {endpoint.returns}",
                    ""
                ])
                
                if endpoint.examples:
                    lines.extend(["**Example:**", "", "```python"])
                    lines.append(endpoint.examples[0])
                    lines.extend(["```", ""])
                
                if endpoint.notes:
                    lines.append("**Notes:**")
                    for note in endpoint.notes:
                        lines.append(f"- {note}")
                    lines.append("")
                
                lines.append("---")
                lines.append("")
        
        return "\n".join(lines)
    
    def get_quick_reference(self) -> Dict[str, Any]:
        """Get quick reference guide for common operations"""
        return {
            "getting_started": {
                "threat_detection": "Use detect_prompt_injection() for basic protection",
                "security_hardening": "Use constant_time_bytes_equal() for security comparisons",
                "rate_limiting": "Use AdaptiveRateLimiter for DoS protection"
            },
            "stability_guarantees": {
                "STABLE": "Production-ready, backward compatible",
                "EXPERIMENTAL": "Under development, may change",
                "DEPRECATED": "Scheduled for removal",
                "LEGACY": "Maintained for compatibility"
            },
            "performance_notes": {
                "All observability features are OPT-IN",
                "Zero overhead when instrumentation is disabled",
                "Security hardening has ~15-25% overhead"
            }
        }


# Singleton instance for easy import
_api_catalog = None


def get_documentation_catalog() -> NeuralShieldAPIDocumentationCatalog:
    """Get the singleton documentation catalog instance"""
    global _api_catalog
    if _api_catalog is None:
        _api_catalog = NeuralShieldAPIDocumentationCatalog()
    return _api_catalog


def get_api_stability(endpoint_name: str) -> Optional[str]:
    """Quick helper to get stability level of an endpoint"""
    catalog = get_documentation_catalog()
    for module in catalog._modules.values():
        for endpoint in module.endpoints:
            if endpoint.name == endpoint_name:
                return endpoint.stability.value
    return None


# Version information
__version__ = "28.0.0"
__api_stability__ = "STABLE"
__documentation_complete__ = True

if __name__ == "__main__":
    catalog = get_documentation_catalog()
    print("NeuralShield API Documentation Catalog v28")
    print("=" * 50)
    print(f"Modules documented: {len(catalog.get_all_modules())}")
    print(f"Stability summary: {catalog.get_stability_summary()}")
    print("\nQuick Reference:")
    for key, value in catalog.get_quick_reference()["getting_started"].items():
        print(f"  {key}: {value}")
