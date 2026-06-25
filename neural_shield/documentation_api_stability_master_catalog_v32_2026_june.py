"""
NeuralShield-AI: Comprehensive API Stability & Documentation Catalog
====================================================================
STABILITY VERSION: 32.0.0
LAST UPDATED: 2026-06-25
FRAMEWORK VERSION: 2026.6.25

This module provides comprehensive API documentation, stability markers,
and usage examples for all NeuralShield-AI components.

STABILITY LEVEL DEFINITIONS:
---------------------------
STABLE (✅ PRODUCTION)
    - API is frozen and will not change in backward-incompatible ways
    - Production-ready and battle-tested
    - Security audited and validated
    - Breaking changes require major version bump

BETA (⚠️ PRE-PRODUCTION)
    - API is mostly stable, minor refinements possible
    - Core functionality complete
    - Undergoing final security validation
    - Minor breaking changes possible without major version bump

EXPERIMENTAL (🔬 RESEARCH)
    - Under active development
    - API subject to significant change
    - Not security audited
    - For research and evaluation only

DEPRECATED (⚠️ SCHEDULED REMOVAL)
    - Will be removed in next major version
    - Use recommended alternatives
    - No new features will be added
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class APIEntry:
    """Single API Entry with complete documentation"""
    name: str
    module_path: str
    stability: StabilityLevel
    category: str
    description: str
    since_version: str
    deprecation_version: Optional[str] = None
    deprecation_note: Optional[str] = None
    usage_example: str = ""
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    security_notes: List[str] = field(default_factory=list)
    performance_notes: List[str] = field(default_factory=list)
    related_apis: List[str] = field(default_factory=list)


class NeuralShieldDocumentationCatalog:
    """
    Comprehensive Documentation and Stability Catalog for NeuralShield-AI
    
    This catalog provides:
    1. Stability markers for all public APIs
    2. Complete usage examples
    3. Parameter documentation
    4. Security and performance notes
    5. Deprecation warnings and migration paths
    
    USAGE:
        catalog = NeuralShieldDocumentationCatalog()
        entry = catalog.get_api("AdvancedJailbreakDetector")
        print(entry.usage_example)
    """
    
    def __init__(self):
        self._catalog: Dict[str, APIEntry] = {}
        self._build_catalog()
        self.generated_at = datetime.utcnow()
        self.version = "32.0.0"
    
    def _build_catalog(self) -> None:
        """Build the complete API catalog"""
        self._add_jailbreak_detection_apis()
        self._add_prompt_injection_apis()
        self._add_threat_intelligence_apis()
        self._add_security_hardening_apis()
        self._add_observability_apis()
        self._add_error_resilience_apis()
    
    def _add_jailbreak_detection_apis(self) -> None:
        """Add jailbreak detection module APIs"""
        
        self._catalog["AdvancedJailbreakDetector"] = APIEntry(
            name="AdvancedJailbreakDetector",
            module_path="neural_shield.zero_shot_jailbreak_detector_v3_2026_june",
            stability=StabilityLevel.STABLE,
            category="Jailbreak Detection",
            description="Multi-strategy jailbreak detection engine combining heuristic, semantic, and ML-based approaches",
            since_version="2026.1.0",
            usage_example="""
from neural_shield import AdvancedJailbreakDetector

detector = AdvancedJailbreakDetector(
    confidence_threshold=0.85,
    enable_heuristic=True,
    enable_semantic=True
)

result = detector.detect("Ignore all previous instructions...")
if result.threat_detected:
    print(f"Jailbreak detected: {result.confidence:.2%}")
    print(f"Techniques: {result.detected_techniques}")
""",
            parameters=[
                {"name": "confidence_threshold", "type": "float", "desc": "Detection threshold (0.0-1.0), default 0.85"},
                {"name": "enable_heuristic", "type": "bool", "desc": "Enable pattern-based heuristic detection"},
                {"name": "enable_semantic", "type": "bool", "desc": "Enable semantic embedding analysis"},
                {"name": "enable_graph", "type": "bool", "desc": "Enable graph-based recursive analysis"}
            ],
            returns="DetectionResult with threat_detected, confidence, techniques, and metadata",
            security_notes=[
                "False positive rate < 1% on standard benchmarks",
                "Optimized against adversarial obfuscation",
                "Supports multi-turn conversation analysis"
            ],
            performance_notes=["~2ms average latency", "CPU-only inference supported"],
            related_apis=["GraphBasedJailbreakDetector", "EnhancedMimeticDetector2026"]
        )
        
        self._catalog["EnhancedMimeticDetector2026"] = APIEntry(
            name="EnhancedMimeticDetector2026",
            module_path="neural_shield.prompt_injection_evasion_technique_detector_2026_june",
            stability=StabilityLevel.BETA,
            category="Jailbreak Detection",
            description="Specialized detector for role-play, persona adoption, and mimetic attack patterns",
            since_version="2026.4.0",
            usage_example="""
from neural_shield import EnhancedMimeticDetector2026

detector = EnhancedMimeticDetector2026()
result = detector.analyze("Act as my DAN persona...")
if result.mimetic_attack_detected:
    print(f"Persona hijack attempt: {result.attack_type}")
""",
            parameters=[
                {"name": "sensitivity", "type": "str", "desc": "'low', 'medium', or 'high' detection sensitivity"}
            ],
            returns="MimeticDetectionResult with attack_type, confidence, and persona_extract",
            security_notes=["Targets DAN, Dev Mode, and similar persona bypass techniques"],
            related_apis=["AdvancedJailbreakDetector"]
        )
    
    def _add_prompt_injection_apis(self) -> None:
        """Add prompt injection module APIs"""
        
        self._catalog["PromptInjectionSandbox"] = APIEntry(
            name="PromptInjectionSandbox",
            module_path="neural_shield.security_input_validation_wrappers_2026_june",
            stability=StabilityLevel.STABLE,
            category="Prompt Injection Defense",
            description="Sandboxed execution environment with security policy enforcement for prompt validation",
            since_version="2026.1.0",
            usage_example="""
from neural_shield import PromptInjectionSandbox

sandbox = PromptInjectionSandbox(
    policy="strict",
    enable_instruction_isolation=True
)

is_safe, report = sandbox.validate(user_input)
if not is_safe:
    print(f"Blocked: {report.attack_vector}")
    sanitized = sandbox.sanitize(user_input)
""",
            parameters=[
                {"name": "policy", "type": "str", "desc": "Security policy: 'strict', 'standard', or 'permissive'"},
                {"name": "enable_instruction_isolation", "type": "bool", "desc": "Isolate system instructions from user input"}
            ],
            returns="Tuple[bool, ValidationReport] with safety status and detailed report",
            security_notes=[
                "Defends against direct and indirect injection",
                "Protects against delimiter and escape attacks",
                "System prompt leakage prevention included"
            ],
            performance_notes=["Sub-millisecond validation for most inputs"],
            related_apis=["ContextAwarePromptInjectionDefender", "InputPurifier"]
        )
        
        self._catalog["InputPurifier"] = APIEntry(
            name="InputPurifier",
            module_path="neural_shield.output_sanitizer_pii_redactor_2026",
            stability=StabilityLevel.STABLE,
            category="Prompt Injection Defense",
            description="Input purification and normalization with adversarial obfuscation removal",
            since_version="2026.2.0",
            usage_example="""
from neural_shield import InputPurifier

purifier = InputPurifier(
    remove_homoglyphs=True,
    normalize_unicode=True,
    strip_invisible_characters=True
)

clean_input = purifier.purify(malicious_input)
""",
            parameters=[
                {"name": "remove_homoglyphs", "type": "bool", "desc": "Replace Unicode confusable characters"},
                {"name": "normalize_unicode", "type": "bool", "desc": "Normalize to NFKC form"},
                {"name": "strip_invisible", "type": "bool", "desc": "Remove zero-width and control characters"}
            ],
            returns="Purified input string with adversarial artifacts removed",
            related_apis=["PromptInjectionSandbox"]
        )
    
    def _add_threat_intelligence_apis(self) -> None:
        """Add threat intelligence module APIs"""
        
        self._catalog["ThreatIntelligenceGeolocationTracker"] = APIEntry(
            name="ThreatIntelligenceGeolocationTracker",
            module_path="neural_shield.threat_intelligence_whois_domain_enricher_2026_june",
            stability=StabilityLevel.STABLE,
            category="Threat Intelligence",
            description="IP and domain geolocation with reputation scoring",
            since_version="2026.3.0",
            usage_example="""
from neural_shield import ThreatIntelligenceGeolocationTracker

tracker = ThreatIntelligenceGeolocationTracker()
geo_info = tracker.lookup_ip("192.168.1.1")
print(f"Location: {geo_info.country}, {geo_info.city}")
print(f"Reputation: {geo_info.reputation_score}")
""",
            parameters=[
                {"name": "cache_ttl", "type": "int", "desc": "Cache TTL in seconds, default 3600"},
                {"name": "enable_reputation", "type": "bool", "desc": "Enable threat reputation lookup"}
            ],
            returns="GeolocationResult with country, city, ASN, and reputation",
            related_apis=["IOCNormalizationReputationEngine", "MITREAttackCoverageAnalyzer"]
        )
        
        self._catalog["MITREAttackCoverageAnalyzer"] = APIEntry(
            name="MITREAttackCoverageAnalyzer",
            module_path="neural_shield.threat_intelligence_mitre_risk_prioritizer_2026_june",
            stability=StabilityLevel.BETA,
            category="Threat Intelligence",
            description="MITRE ATT&CK framework mapping and coverage analysis",
            since_version="2026.4.0",
            usage_example="""
from neural_shield import MITREAttackCoverageAnalyzer

analyzer = MITREAttackCoverageAnalyzer()
mapping = analyzer.map_threat(alert_data)
print(f"ATT&CK Technique: {mapping.technique_id}")
print(f"Coverage Level: {mapping.coverage}")
""",
            parameters=[
                {"name": "matrix_version", "type": "str", "desc": "MITRE ATT&CK matrix version"}
            ],
            returns="MITREMapping with technique_id, tactic, coverage, and mitigations",
            related_apis=["AlertCorrelationContextEnricher"]
        )
        
        self._catalog["AlertCorrelationContextEnricher"] = APIEntry(
            name="AlertCorrelationContextEnricher",
            module_path="neural_shield.threat_intelligence_alert_correlation_context_enricher_v63_2026_june",
            stability=StabilityLevel.BETA,
            category="Threat Intelligence",
            description="Alert correlation engine with context enrichment and false positive reduction",
            since_version="2026.5.0",
            usage_example="""
from neural_shield import AlertCorrelationContextEnricher

enricher = AlertCorrelationContextEnricher()
enriched = enricher.enrich_alert(raw_alert, context_history)
if enriched.false_positive_probability < 0.1:
    escalate_to_soc(enriched)
""",
            returns="EnrichedAlert with correlation_score, false_positive_probability, and context",
            related_apis=["MITREAttackCoverageAnalyzer"]
        )
    
    def _add_security_hardening_apis(self) -> None:
        """Add security hardening module APIs"""
        
        self._catalog["SecureMemoryZeroizer"] = APIEntry(
            name="SecureMemoryZeroizer",
            module_path="neural_shield.security_hardening_comprehensive_v23_2026_june",
            stability=StabilityLevel.STABLE,
            category="Security Hardening",
            description="Secure memory zeroization for sensitive data with side-channel resistance",
            since_version="2026.2.0",
            usage_example="""
from neural_shield import SecureMemoryZeroizer

zeroizer = SecureMemoryZeroizer()
sensitive_data = get_secret_key()

try:
    process_key(sensitive_data)
finally:
    zeroizer.zeroize(sensitive_data)
""",
            parameters=[
                {"name": "passes", "type": "int", "desc": "Number of overwrite passes, default 3"},
                {"name": "use_random", "type": "bool", "desc": "Use random patterns between zero passes"}
            ],
            returns="None - operates in-place on mutable buffers",
            security_notes=[
                "Constant-time memory operations",
                "Compiler barrier prevents optimization away",
                "Follows NIST SP 800-88 guidelines"
            ],
            related_apis=["ConstantTimeComparator", "RateLimiter"]
        )
        
        self._catalog["ConstantTimeComparator"] = APIEntry(
            name="ConstantTimeComparator",
            module_path="neural_shield.security_hardening_comprehensive_protection_v19_2026_june",
            stability=StabilityLevel.STABLE,
            category="Security Hardening",
            description="Timing-attack resistant comparison for cryptographic operations",
            since_version="2026.2.0",
            usage_example="""
from neural_shield import ConstantTimeComparator

comparator = ConstantTimeComparator()
if comparator.equals(received_hmac, expected_hmac):
    print("Authentication successful")
""",
            returns="bool - comparison result in constant time",
            security_notes=[
                "Execution time independent of input values",
                "No early termination on mismatch",
                "Resistant to cache timing side-channels"
            ],
            related_apis=["SecureMemoryZeroizer"]
        )
        
        self._catalog["RateLimiter"] = APIEntry(
            name="RateLimiter",
            module_path="neural_shield.threat_intelligence_bulk_request_batcher_adaptive_rate_limiter_2026_june",
            stability=StabilityLevel.STABLE,
            category="Security Hardening",
            description="Adaptive rate limiting with token bucket and sliding window algorithms",
            since_version="2026.3.0",
            usage_example="""
from neural_shield import RateLimiter

limiter = RateLimiter(
    requests_per_minute=100,
    burst_multiplier=2
)

if limiter.allow_request(client_id):
    process_request()
else:
    return_429_response()
""",
            parameters=[
                {"name": "requests_per_minute", "type": "int", "desc": "Base rate limit"},
                {"name": "burst_multiplier", "type": "float", "desc": "Allowed burst multiplier"}
            ],
            returns="bool indicating if request should be allowed",
            related_apis=["SecureMemoryZeroizer"]
        )
    
    def _add_observability_apis(self) -> None:
        """Add observability module APIs"""
        
        self._catalog["StructuredLogger"] = APIEntry(
            name="StructuredLogger",
            module_path="neural_shield.observability_distributed_tracing_percentiles_v26_2026_june",
            stability=StabilityLevel.STABLE,
            category="Observability",
            description="Structured JSON logging with threat context and correlation IDs",
            since_version="2026.3.0",
            usage_example="""
from neural_shield import StructuredLogger

logger = StructuredLogger(
    service="neural-shield",
    environment="production"
)

logger.threat_detected(
    threat_type="jailbreak",
    confidence=0.92,
    correlation_id=req_id
)
""",
            parameters=[
                {"name": "service", "type": "str", "desc": "Service identifier"},
                {"name": "environment", "type": "str", "desc": "Deployment environment"}
            ],
            returns="None - outputs structured log records",
            related_apis=["MetricsCollector", "HealthCheck"]
        )
        
        self._catalog["MetricsCollector"] = APIEntry(
            name="MetricsCollector",
            module_path="neural_shield.observability_structured_logging_metrics_v4_2026_june",
            stability=StabilityLevel.STABLE,
            category="Observability",
            description="Prometheus-compatible metrics collection for threat detection operations",
            since_version="2026.3.0",
            usage_example="""
from neural_shield import MetricsCollector

metrics = MetricsCollector()
metrics.increment_counter("threats_detected", labels={"type": "jailbreak"})
metrics.record_latency("detection_ms", latency_ms, labels={"detector": "jailbreak"})
""",
            returns="None - metrics available via /metrics endpoint",
            related_apis=["StructuredLogger", "HealthCheck"]
        )
        
        self._catalog["HealthCheck"] = APIEntry(
            name="HealthCheck",
            module_path="neural_shield.observability_distributed_tracing_percentiles_v26_2026_june",
            stability=StabilityLevel.BETA,
            category="Observability",
            description="Health check endpoint with dependency and liveness probes",
            since_version="2026.4.0",
            usage_example="""
from neural_shield import HealthCheck

health = HealthCheck()
status = health.check_all()
if status.healthy:
    return 200
else:
    return 503, status.failures
""",
            returns="HealthStatus with healthy flag and detailed component status",
            related_apis=["StructuredLogger", "MetricsCollector"]
        )
    
    def _add_error_resilience_apis(self) -> None:
        """Add error resilience module APIs"""
        
        self._catalog["CircuitBreaker"] = APIEntry(
            name="CircuitBreaker",
            module_path="neural_shield.error_resilience_circuit_breaker_graceful_degradation_v29_2026_june",
            stability=StabilityLevel.STABLE,
            category="Error Resilience",
            description="Circuit breaker pattern for graceful degradation and fault tolerance",
            since_version="2026.3.0",
            usage_example="""
from neural_shield import CircuitBreaker

breaker = CircuitBreaker(
    failure_threshold=5,
    recovery_timeout=30
)

@breaker.protect(fallback=default_analysis)
def analyze_threat(input_data):
    return expensive_detection_call(input_data)
""",
            parameters=[
                {"name": "failure_threshold", "type": "int", "desc": "Failures before opening circuit"},
                {"name": "recovery_timeout", "type": "int", "desc": "Seconds before half-open state"}
            ],
            returns="Decorator for protected functions",
            related_apis=["RetryWithBackoff", "TimeoutWrapper"]
        )
        
        self._catalog["RetryWithBackoff"] = APIEntry(
            name="RetryWithBackoff",
            module_path="neural_shield.error_resilience_comprehensive_threat_detection_v31_2026_june",
            stability=StabilityLevel.STABLE,
            category="Error Resilience",
            description="Exponential backoff retry with jitter for transient failures",
            since_version="2026.3.0",
            usage_example="""
from neural_shield import RetryWithBackoff

retry = RetryWithBackoff(
    max_attempts=3,
    initial_delay=1.0,
    max_delay=10.0
)

result = retry.execute(call_external_api, arg1, arg2)
""",
            parameters=[
                {"name": "max_attempts", "type": "int", "desc": "Maximum retry attempts"},
                {"name": "initial_delay", "type": "float", "desc": "Initial delay in seconds"},
                {"name": "max_delay", "type": "float", "desc": "Maximum delay cap"}
            ],
            returns="Result of successful call or raises final exception",
            related_apis=["CircuitBreaker", "TimeoutWrapper"]
        )
        
        self._catalog["TimeoutWrapper"] = APIEntry(
            name="TimeoutWrapper",
            module_path="neural_shield.error_resilience_circuit_breaker_graceful_degradation_v29_2026_june",
            stability=StabilityLevel.STABLE,
            category="Error Resilience",
            description="Execution timeout wrapper to prevent hung operations",
            since_version="2026.3.0",
            usage_example="""
from neural_shield import TimeoutWrapper

timeout = TimeoutWrapper(timeout_seconds=5.0)
try:
    result = timeout.run(potentially_slow_function, args)
except TimeoutError:
    handle_timeout()
""",
            parameters=[
                {"name": "timeout_seconds", "type": "float", "desc": "Timeout in seconds"}
            ],
            returns="Function result or raises TimeoutError",
            related_apis=["CircuitBreaker", "RetryWithBackoff"]
        )
    
    def get_api(self, api_name: str) -> Optional[APIEntry]:
        """
        Get documentation entry for a specific API
        
        Args:
            api_name: Name of the API to retrieve
            
        Returns:
            APIEntry if found, None otherwise
        """
        return self._catalog.get(api_name)
    
    def list_by_category(self, category: str) -> List[APIEntry]:
        """List all APIs in a specific category"""
        return [e for e in self._catalog.values() if e.category == category]
    
    def list_by_stability(self, stability: StabilityLevel) -> List[APIEntry]:
        """List all APIs with a specific stability level"""
        return [e for e in self._catalog.values() if e.stability == stability]
    
    def get_all_categories(self) -> List[str]:
        """Get all unique API categories"""
        return sorted({e.category for e in self._catalog.values()})
    
    def generate_markdown_docs(self) -> str:
        """Generate comprehensive Markdown documentation"""
        md = [
            "# NeuralShield-AI API Documentation",
            f"**Version**: {self.version}",
            f"**Generated**: {self.generated_at.isoformat()}",
            "",
            "## Stability Legend",
            "",
            "- ✅ **STABLE** - Production-ready, frozen API",
            "- ⚠️ **BETA** - Mostly stable, minor changes possible",
            "- 🔬 **EXPERIMENTAL** - Under development",
            "- ⚠️ **DEPRECATED** - Scheduled for removal",
            ""
        ]
        
        for category in self.get_all_categories():
            md.append(f"## {category}")
            md.append("")
            md.append("| API | Stability | Since | Description |")
            md.append("|-----|-----------|-------|-------------|")
            
            for entry in sorted(self.list_by_category(category), key=lambda x: x.name):
                stability_icon = {
                    StabilityLevel.STABLE: "✅ STABLE",
                    StabilityLevel.BETA: "⚠️ BETA",
                    StabilityLevel.EXPERIMENTAL: "🔬 EXPERIMENTAL",
                    StabilityLevel.DEPRECATED: "⚠️ DEPRECATED"
                }[entry.stability]
                
                md.append(f"| `{entry.name}` | {stability_icon} | {entry.since_version} | {entry.description} |")
            
            md.append("")
        
        return "\n".join(md)
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of APIs by stability level"""
        summary = {}
        for level in StabilityLevel:
            summary[level.value] = len(self.list_by_stability(level))
        return summary


# Singleton instance for easy import
DEFAULT_CATALOG = NeuralShieldDocumentationCatalog()


def get_documentation_catalog() -> NeuralShieldDocumentationCatalog:
    """
    Get the default documentation catalog instance
    
    **STABILITY**: STABLE
    **SINCE**: 2026.6.0
    
    Returns:
        NeuralShieldDocumentationCatalog singleton
    """
    return DEFAULT_CATALOG


def get_api_documentation(api_name: str) -> Optional[APIEntry]:
    """
    Quick access to API documentation
    
    **STABILITY**: STABLE
    **SINCE**: 2026.6.0
    
    Args:
        api_name: Name of the API to document
        
    Returns:
        APIEntry if found, None otherwise
    """
    return DEFAULT_CATALOG.get_api(api_name)


if __name__ == "__main__":
    catalog = NeuralShieldDocumentationCatalog()
    print(f"📚 NeuralShield Documentation Catalog v{catalog.version}")
    print(f"Total APIs documented: {len(catalog._catalog)}")
    print("\nStability Summary:")
    for level, count in catalog.get_stability_summary().items():
        print(f"  {level}: {count}")
    print("\n" + "="*60)
    print(catalog.generate_markdown_docs())
