"""
NeuralShield-AI Comprehensive API Documentation & Stability Catalog v22
=====================================================================
Version: 22.0.0
Date: June 24, 2026
API Stability: STABLE

This module provides comprehensive API documentation, stability markers,
usage examples, and integration guides for all NeuralShield-AI modules.

ADD-ONLY: This is a completely new module that wraps existing functionality.
No existing code is modified. All features are OPT-IN.

NEW IN v22:
- HTTP Metrics Server v14 complete usage guide with port configuration
- SLO Alerting v14 + Baggage full integration patterns
- Security Hardening v16 defense-in-depth layering examples
- README.md update content generator
- Cross-module dependency mapping
- Production deployment checklist
"""

import typing
from typing import Dict, List, Any, Optional, Callable, TypeVar, Generic
from dataclasses import dataclass, field
from enum import Enum
import datetime
import json


class StabilityLevel(Enum):
    """API Stability Level classification per Semantic Versioning standards."""
    STABLE = "STABLE"
    """Production-ready, backward-compatible, no breaking changes expected."""
    
    BETA = "BETA"
    """Nearly stable, minor API changes possible, tested in production."""
    
    EXPERIMENTAL = "EXPERIMENTAL"
    """New feature, API subject to change, not recommended for production."""
    
    DEPRECATED = "DEPRECATED"
    """Will be removed in future version, migrate to replacement."""
    
    LEGACY = "LEGACY"
    """Maintained for backward compatibility, use modern alternative."""


class SupportLevel(Enum):
    """Level of support and maintenance for each module."""
    FULL_SUPPORT = "FULL_SUPPORT"
    """Actively maintained, security patches, bug fixes, feature updates."""
    
    MAINTENANCE_ONLY = "MAINTENANCE_ONLY"
    """Security patches and critical bug fixes only, no new features."""
    
    COMMUNITY_SUPPORT = "COMMUNITY_SUPPORT"
    """Community maintained, no official support guarantee."""
    
    DEPRECATED_NO_SUPPORT = "DEPRECATED_NO_SUPPORT"
    """No longer supported, migrate immediately."""


@dataclass
class ModuleDocumentation:
    """Comprehensive documentation entry for each NeuralShield module."""
    module_name: str
    module_path: str
    stability_level: StabilityLevel
    support_level: SupportLevel
    version: str
    first_release_version: str
    description: str
    primary_use_cases: List[str]
    key_classes: List[str]
    key_functions: List[str]
    code_example: str
    integration_notes: str
    deprecation_notice: Optional[str] = None
    replacement_module: Optional[str] = None
    performance_characteristics: str = "N/A"
    thread_safety: str = "Unknown"
    dependencies: List[str] = field(default_factory=list)
    production_readiness_score: int = 0  # 0-100


T = TypeVar('T')


class DocumentationCatalogV22:
    """
    Comprehensive API Documentation & Stability Catalog v22
    
    Features:
    - Stability markers for ALL NeuralShield modules (STABLE/BETA/EXPERIMENTAL/DEPRECATED)
    - Support level classification
    - Version tracking and changelog
    - Usage examples for every module
    - Integration guides between modules
    - HTTP Metrics Server (v14) complete integration examples
    - SLO Alerting + Baggage (v14) usage patterns
    - Security Hardening v16 defense-in-depth patterns
    - README.md content generator
    - Production deployment checklist
    - Best practices and anti-patterns
    
    STABILITY: STABLE - This catalog itself is production-ready
    """
    
    CATALOG_VERSION = "22.0.0"
    CATALOG_DATE = "2026-06-24"
    
    def __init__(self):
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._init_core_modules()
        self._init_feature_expansion_v14_modules()
        self._init_observability_v14_modules()
        self._init_security_hardening_v16_modules()
        self._init_integration_guides()
        self._init_production_checklist()
    
    def _init_core_modules(self) -> None:
        """Initialize documentation for core STABLE modules."""
        
        # === Constitutional Classifier ===
        self._modules["constitutional_classifier"] = ModuleDocumentation(
            module_name="Constitutional Classifier",
            module_path="neural_shield/constitutional_classifier_2026.py",
            stability_level=StabilityLevel.STABLE,
            support_level=SupportLevel.FULL_SUPPORT,
            version="1.0.0",
            first_release_version="1.0.0",
            description="Rule-based content policy classifier with constitutional alignment checks.",
            primary_use_cases=[
                "Content policy violation detection",
                "Output filtering and moderation",
                "Constitutional AI alignment verification",
                "Harmful content prevention"
            ],
            key_classes=["ConstitutionalClassifier", "PolicyCategory", "ViolationLevel"],
            key_functions=["classify_content()", "check_policy_compliance()", "get_violation_details()"],
            code_example="""
from neural_shield.constitutional_classifier_2026 import ConstitutionalClassifier

classifier = ConstitutionalClassifier()
result = classifier.classify_content("User prompt text here")
if result.is_violation:
    print(f"Violation: {result.category}, Score: {result.confidence}")
""",
            integration_notes="Integrates with all output sanitizer modules. Thread-safe.",
            performance_characteristics="O(n) where n = input length. ~1ms per classification.",
            thread_safety="Fully thread-safe for concurrent classification.",
            dependencies=["re"],
            production_readiness_score=95
        )
        
        # === Prompt Injection Detector ===
        self._modules["prompt_injection_detector"] = ModuleDocumentation(
            module_name="Prompt Injection Detector",
            module_path="neural_shield/prompt_injection_detector_2026.py",
            stability_level=StabilityLevel.STABLE,
            support_level=SupportLevel.FULL_SUPPORT,
            version="2.0.0",
            first_release_version="1.0.0",
            description="Multi-strategy prompt injection detection with heuristic, semantic, and pattern-based analysis.",
            primary_use_cases=[
                "Detecting prompt injection attempts",
                "Input sanitization for LLM applications",
                "Security monitoring of user inputs",
                "Attack pattern recognition"
            ],
            key_classes=["PromptInjectionDetector", "DetectionStrategy", "InjectionType"],
            key_functions=["detect_injection()", "calculate_risk_score()", "get_threat_details()"],
            code_example="""
from neural_shield.prompt_injection_detector_2026 import PromptInjectionDetector

detector = PromptInjectionDetector()
result = detector.detect_injection("Ignore previous instructions...")
if result.is_injection:
    print(f"Threat detected: {result.injection_type}, Risk: {result.risk_score}")
""",
            integration_notes="Works with input purification modules. Use before LLM calls.",
            performance_characteristics="O(n) scanning. Multiple strategies add overhead.",
            thread_safety="Thread-safe for concurrent detection.",
            dependencies=["re", "collections"],
            production_readiness_score=92
        )
        
        # === Adversarial Prompt Anomaly Detector ===
        self._modules["adversarial_prompt_anomaly_detector"] = ModuleDocumentation(
            module_name="Adversarial Prompt Anomaly Detector",
            module_path="neural_shield/adversarial_prompt_anomaly_detector_2026_june.py",
            stability_level=StabilityLevel.STABLE,
            support_level=SupportLevel.FULL_SUPPORT,
            version="3.0.0",
            first_release_version="1.0.0",
            description="Statistical anomaly detection for adversarial prompts using entropy, perplexity, and pattern analysis.",
            primary_use_cases=[
                "Zero-day attack detection",
                "Anomaly-based threat hunting",
                "Unknown attack pattern discovery",
                "Defense-in-depth security"
            ],
            key_classes=["AdversarialAnomalyDetector", "AnomalyScore", "FeatureExtractor"],
            key_functions=["detect_anomalies()", "extract_features()", "calculate_anomaly_score()"],
            code_example="""
from neural_shield.adversarial_prompt_anomaly_detector_2026_june import AdversarialAnomalyDetector

detector = AdversarialAnomalyDetector()
result = detector.detect_anomalies(prompt_text)
if result.is_anomalous:
    print(f"Anomaly score: {result.overall_score}, Features: {result.features}")
""",
            integration_notes="Complement signature-based detectors. Higher false positive rate.",
            performance_characteristics="Feature extraction adds ~5ms overhead per prompt.",
            thread_safety="Thread-safe.",
            dependencies=["math", "collections", "statistics"],
            production_readiness_score=88
        )
    
    def _init_feature_expansion_v14_modules(self) -> None:
        """Initialize documentation for Feature Expansion v14 modules."""
        
        # === HTTP Metrics Server v14 ===
        self._modules["http_metrics_server_v14"] = ModuleDocumentation(
            module_name="HTTP Metrics Server v14",
            module_path="neural_shield/feature_expansion_http_metrics_server_v14_2026_june.py",
            stability_level=StabilityLevel.BETA,
            support_level=SupportLevel.FULL_SUPPORT,
            version="14.0.0",
            first_release_version="14.0.0",
            description="Embedded HTTP server for Prometheus-style metrics export and health checks.",
            primary_use_cases=[
                "Export metrics to Prometheus monitoring",
                "Health check endpoints for Kubernetes",
                "Runtime status inspection via HTTP",
                "Liveness/readiness probes for orchestration",
                "Grafana dashboard integration"
            ],
            key_classes=["HttpMetricsServer", "MetricsEndpoint", "HealthCheckRegistry"],
            key_functions=["start_server()", "stop_server()", "register_metric()", "register_health_check()"],
            code_example="""
from neural_shield.feature_expansion_http_metrics_server_v14_2026_june import HttpMetricsServer

# Start metrics server - choose port 8000-9000 range
server = HttpMetricsServer(host="0.0.0.0", port=8080)
server.start_server()  # Runs in background daemon thread

# Register custom health checks
def database_health_check():
    return {"status": "healthy", "latency_ms": 42, "connections": 15}

def model_health_check():
    return {"status": "healthy", "loaded": True, "cache_hits": 1234}

server.register_health_check("database", database_health_check)
server.register_health_check("model", model_health_check)

# ENDPOINTS:
#   http://localhost:8080/metrics  - Prometheus text format
#   http://localhost:8080/health   - Comprehensive health status
#   http://localhost:8080/ready    - Readiness probe
#   http://localhost:8080/status   - JSON status summary

# Kubernetes probe configuration:
# livenessProbe:
#   httpGet:
#     path: /health
#     port: 8080
#   initialDelaySeconds: 30
#   periodSeconds: 10
""",
            integration_notes="""
Full integration points:
1. Observability v14: SLO metrics automatically exported
2. Error Resilience v24: Circuit breaker status in health check
3. Security v16: Rate limit counters exposed as metrics
""",
            performance_characteristics="Minimal overhead. HTTP server runs in separate daemon thread.",
            thread_safety="Fully thread-safe. Server runs in dedicated daemon thread.",
            dependencies=["http.server", "threading", "json", "socket"],
            production_readiness_score=78
        )
    
    def _init_observability_v14_modules(self) -> None:
        """Initialize documentation for Observability v14 modules (SLO Alerting + Baggage)."""
        
        # === SLO Alerting + Enhanced Baggage v14 ===
        self._modules["observability_slo_baggage_v14"] = ModuleDocumentation(
            module_name="SLO Alerting + Enhanced Baggage v14",
            module_path="neural_shield/observability_slo_alerting_baggage_enhanced_v14_2026_june.py",
            stability_level=StabilityLevel.BETA,
            support_level=SupportLevel.FULL_SUPPORT,
            version="14.0.0",
            first_release_version="14.0.0",
            description="Service Level Objective alerting with burn rate calculation and distributed tracing baggage context propagation.",
            primary_use_cases=[
                "Error rate SLO monitoring and burn rate alerting",
                "Latency threshold SLO monitoring (P50/P95/P99/P999)",
                "Distributed tracing context propagation across services",
                "Cross-service correlation ID tracking",
                "Rolling window percentile metrics aggregation",
                "Multi-window alert evaluation (fast/slow burn rates)"
            ],
            key_classes=[
                "SLOAlertingEngine", "EnhancedBaggageManager", 
                "PercentileMetricsAggregator", "Alert", "SLO", "TraceSpan"
            ],
            key_functions=[
                "register_slo()", "evaluate_slos()", "start_trace()",
                "set_baggage()", "record_latency()", "export_prometheus_metrics()",
                "get_correlation_id()", "add_webhook_callback()"
            ],
            code_example="""
from neural_shield.observability_slo_alerting_baggage_enhanced_v14_2026_june import (
    SLOAlertingEngine, EnhancedBaggageManager, PercentileMetricsAggregator, AlertSeverity
)

# ==========================================
# SLO Alerting Setup - Production Pattern
# ==========================================
slo_engine = SLOAlertingEngine()

# Error Rate SLO: 99.9% success over 1 hour
slo_engine.register_slo(
    slo_id="detection_error_rate",
    slo_type="error_rate",
    target_percent=99.9,
    window_seconds=3600,
    burn_rate_threshold=2.0,
    severity=AlertSeverity.WARNING
)

# Latency SLO: P95 < 100ms over 5 minutes
slo_engine.register_slo(
    slo_id="detection_latency_p95",
    slo_type="latency",
    latency_threshold_ms=100.0,
    percentile=95,
    window_seconds=300,
    burn_rate_threshold=3.0,
    severity=AlertSeverity.CRITICAL
)

# Webhook callback for alerts (Slack, PagerDuty, etc.)
def alert_webhook(alert):
    print(f"ALERT: {alert.name} - {alert.severity}")
    # POST to your alerting system here

slo_engine.add_webhook_callback(alert_webhook)

# Evaluate SLOs every 60 seconds (background task)
# alerts = slo_engine.evaluate_slos()

# ==========================================
# Distributed Tracing Baggage
# ==========================================
baggage = EnhancedBaggageManager()

def process_user_request(user_id, request_data):
    with baggage.start_trace("user_request", service="neuralshield") as span:
        baggage.set_baggage("user_id", user_id)
        baggage.set_baggage("correlation_id", f"req-{uuid.uuid4()}")
        span.add_attribute("request_size", len(request_data))
        
        # All nested operations inherit this context
        result = run_detection_pipeline(request_data)
        span.add_attribute("status", "success" if result.ok else "error")
        return result

# ==========================================
# Percentile Metrics
# ==========================================
latency_metrics = PercentileMetricsAggregator(max_samples=10000)
latency_metrics.record(23.5)  # ms
latency_metrics.record(45.2)
latency_metrics.record(12.8)

print(f"P50: {latency_metrics.get_percentile(50):.1f}ms")
print(f"P95: {latency_metrics.get_percentile(95):.1f}ms")
print(f"P99: {latency_metrics.get_percentile(99):.1f}ms")

# ==========================================
# Prometheus Export + HTTP Server Integration
# ==========================================
prometheus_text = slo_engine.export_prometheus_metrics()
# Auto-exposed via HttpMetricsServer at /metrics
""",
            integration_notes="""
CRITICAL INTEGRATION WITH HTTP METRICS SERVER v14:
1. SLO metrics automatically available at /metrics endpoint
2. Health check /health reflects current SLO alert status
3. Baggage correlation IDs appear in request logs
4. Percentile metrics feed directly into latency SLO calculations
5. Alert webhooks can trigger external monitoring systems
""",
            performance_characteristics="SLO evaluation O(n) per SLO. Metrics recording O(1) amortized.",
            thread_safety="Fully thread-safe with reentrant lock protection for shared state.",
            dependencies=["threading", "collections", "time", "json", "uuid", "math"],
            production_readiness_score=82
        )
    
    def _init_security_hardening_v16_modules(self) -> None:
        """Initialize documentation for Security Hardening v16 modules."""
        
        # === Comprehensive Security Hardening v16 ===
        self._modules["security_hardening_v16"] = ModuleDocumentation(
            module_name="Comprehensive Security Hardening v16",
            module_path="neural_shield/comprehensive_security_hardening_enhanced_v14_2026_june.py",
            stability_level=StabilityLevel.STABLE,
            support_level=SupportLevel.FULL_SUPPORT,
            version="16.0.0",
            first_release_version="1.0.0",
            description="Input validation wrappers, secure memory zeroization, timing-attack resistant constant-time comparison, and DoS protection.",
            primary_use_cases=[
                "Input validation and sanitization wrappers",
                "Secure memory handling for API keys and secrets",
                "Timing-attack resistant string comparison",
                "Rate limiting and DoS attack protection",
                "Security defense-in-depth layering",
                "Sensitive data zeroization after use"
            ],
            key_classes=[
                "InputValidationWrapper", "SecureMemoryZeroizer",
                "ConstantTimeComparer", "RateLimiter", "DoSProtector"
            ],
            key_functions=[
                "validate_input()", "zeroize_bytearray()",
                "constant_time_compare()", "check_rate_limit()",
                "wrap_secure_function()", "sanitize_for_logging()"
            ],
            code_example="""
from neural_shield.comprehensive_security_hardening_enhanced_v14_2026_june import (
    InputValidationWrapper, SecureMemoryZeroizer, 
    ConstantTimeComparer, RateLimiter, DoSProtector
)

# ==========================================
# DEFENSE-IN-DEPTH SECURITY PIPELINE
# ==========================================

# Layer 1: DoS Protection (first line of defense)
dos_protector = DoSProtector(
    max_requests_per_minute=1000,
    max_concurrent_connections=100,
    burst_protection=True
)

# Layer 2: Rate Limiting (per client)
rate_limiter = RateLimiter(
    max_requests=100,
    window_seconds=60,
    block_duration_seconds=300
)

# Layer 3: Input Validation (sanitization)
validator = InputValidationWrapper(
    max_length=4096,
    allow_unicode=True,
    strip_control_characters=True
)

# Layer 4: Timing-Attack Resistant Comparison
comparer = ConstantTimeComparer()

# Layer 5: Secure Memory Handling
zeroizer = SecureMemoryZeroizer()

# ==========================================
# FULL PIPELINE USAGE
# ==========================================
def secure_detection_pipeline(user_input: str, client_ip: str, api_token: str) -> dict:
    
    # Layer 1: Global DoS check
    if not dos_protector.check_accepted():
        return {"blocked": True, "reason": "dos_protection_triggered"}
    
    # Layer 2: Per-client rate limit
    if not rate_limiter.check_rate_limit(client_ip):
        return {"blocked": True, "reason": "rate_limit_exceeded"}
    
    # Layer 3: Input validation
    validation_result = validator.validate_input(user_input)
    if not validation_result.is_valid:
        return {"blocked": True, "reason": f"invalid_input: {validation_result.errors}"}
    
    # Layer 4: Timing-safe API token verification
    expected_token = get_stored_api_token()  # Securely fetched
    if not comparer.compare_strings(api_token, expected_token):
        return {"blocked": True, "reason": "invalid_auth"}
    
    # Process with core detectors...
    result = run_core_detection(validation_result.sanitized_input)
    
    # Layer 5: Zeroize sensitive data after use
    sensitive_buffer = bytearray(expected_token.encode())
    zeroizer.zeroize_bytearray(sensitive_buffer)
    
    return result

# ==========================================
# KEY SECURITY PROPERTY: NO TIMING LEAKS
# ==========================================
# constant_time_compare() takes EXACTLY the same amount of time
# regardless of how many characters match, preventing timing attacks
# on API tokens, passwords, and secrets.
""",
            integration_notes="""
SECURITY LAYER ORDER (CRITICAL):
1. DoS Protection (cheapest check) - reject floods early
2. Rate Limiting - per client enforcement
3. Input Validation - reject malformed data
4. Authentication - timing-safe comparison
5. Core Detection - actual scanning
6. Memory Zeroization - cleanup sensitive data

This order minimizes attack surface and computational waste.
""",
            performance_characteristics="Minimal overhead. Constant-time operations have fixed duration regardless of input.",
            thread_safety="Fully thread-safe with atomic operations for counters.",
            dependencies=["threading", "time", "hmac", "secrets", "re"],
            production_readiness_score=90
        )
    
    def _init_integration_guides(self) -> None:
        """Initialize cross-module integration documentation."""
        self._integration_guides = {
            "full_production_stack_v22": {
                "title": "Full Production Stack: Security v16 → Detection → Observability v14 → Metrics v14",
                "description": "Complete end-to-end production deployment with all layers",
                "architecture_diagram": """
[Client Request]
      ↓
[DoS Protection v16] → Block flood attacks
      ↓
[Rate Limiting v16] → Per-client quotas
      ↓
[Input Validation v16] → Sanitize & normalize
      ↓
[Signature Detection] → Known attack patterns
      ↓
[Anomaly Detection] → Zero-day threats
      ↓
[Baggage Context v14] → Trace + correlation ID
      ↓
[SLO Recording v14] → Error rate + latency metrics
      ↓
[HTTP Metrics v14] → Prometheus /metrics endpoint
                """,
                "setup_example": """
# Full Production Stack - One-line initialization
from neural_shield.documentation_api_stability_catalog_v22_2026_june import (
    DocumentationCatalogV22
)

catalog = DocumentationCatalogV22()
print(catalog.get_production_deployment_checklist())
""",
                "best_practices": [
                    "Always apply security layers in the correct order",
                    "Run metrics server on internal port only (not public)",
                    "Evaluate SLOs every 60s in background thread",
                    "Log all baggage correlation IDs for tracing",
                    "Set up alert webhooks for critical SLO violations"
                ],
                "anti_patterns": [
                    "❌ Don't expose /metrics to public internet",
                    "❌ Don't evaluate SLOs on every request (wastes CPU)",
                    "❌ Don't skip input validation for 'trusted' clients",
                    "❌ Don't use regular string comparison for secrets"
                ]
            }
        }
    
    def _init_production_checklist(self) -> None:
        """Initialize production deployment checklist."""
        self._production_checklist = [
            {"category": "Security", "item": "Rate limiting enabled for all endpoints", "done": False},
            {"category": "Security", "item": "Input validation max length configured", "done": False},
            {"category": "Security", "item": "Constant-time comparison for all secrets", "done": False},
            {"category": "Security", "item": "Memory zeroization after sensitive operations", "done": False},
            {"category": "Observability", "item": "HTTP Metrics Server started on internal port", "done": False},
            {"category": "Observability", "item": "Error rate SLO registered (99.9% target)", "done": False},
            {"category": "Observability", "item": "Latency P95 SLO registered", "done": False},
            {"category": "Observability", "item": "Alert webhooks configured for critical violations", "done": False},
            {"category": "Observability", "item": "Distributed tracing baggage enabled", "done": False},
            {"category": "Monitoring", "item": "Prometheus scraping /metrics endpoint", "done": False},
            {"category": "Monitoring", "item": "Kubernetes liveness probe on /health", "done": False},
            {"category": "Monitoring", "item": "Grafana dashboard configured", "done": False},
            {"category": "Integration", "item": "All core detectors in pipeline", "done": False},
            {"category": "Integration", "item": "Correlation IDs in all log messages", "done": False}
        ]
    
    def get_module_documentation(self, module_id: str) -> Optional[ModuleDocumentation]:
        """Get documentation for a specific module by ID."""
        return self._modules.get(module_id)
    
    def get_all_modules(self) -> Dict[str, ModuleDocumentation]:
        """Get documentation for all registered modules."""
        return self._modules.copy()
    
    def get_modules_by_stability(self, stability: StabilityLevel) -> List[ModuleDocumentation]:
        """Get all modules with specified stability level."""
        return [m for m in self._modules.values() if m.stability_level == stability]
    
    def get_integration_guide(self, guide_id: str) -> Optional[Dict[str, Any]]:
        """Get integration guide by ID."""
        return self._integration_guides.get(guide_id)
    
    def get_all_integration_guides(self) -> Dict[str, Dict[str, Any]]:
        """Get all integration guides."""
        return self._integration_guides.copy()
    def get_production_deployment_checklist(self) -> List[Dict[str, Any]]:
        """Get production deployment checklist."""
        return self._production_checklist.copy()
    
    def generate_readme_update(self) -> str:
        """Generate README.md update content for v22."""
        stable = len(self.get_modules_by_stability(StabilityLevel.STABLE))
        beta = len(self.get_modules_by_stability(StabilityLevel.BETA))
        
        return f"""
## Module Status Summary (Documentation v22)

| Stability Level | Count | Description |
|-----------------|-------|-------------|
| ✅ **STABLE** | {stable} | Production-ready, fully supported |
| ⚠️ **BETA** | {beta} | Nearly stable, minor changes possible |

### Newly Documented in v22:
- **HTTP Metrics Server v14**: Complete Prometheus + Kubernetes setup guide
- **SLO Alerting v14**: Error rate + latency monitoring with burn rate calculation
- **Enhanced Baggage v14**: Distributed tracing context propagation patterns
- **Security Hardening v16**: Defense-in-depth layering with correct order
- **Production Checklist**: 14-point deployment verification list

### Quick Start - Full Production Stack:
```python
from neural_shield.feature_expansion_http_metrics_server_v14_2026_june import HttpMetricsServer
from neural_shield.observability_slo_alerting_baggage_enhanced_v14_2026_june import SLOAlertingEngine
from neural_shield.comprehensive_security_hardening_enhanced_v14_2026_june import RateLimiter

# 1. Start metrics server
server = HttpMetricsServer(port=8080)
server.start_server()

# 2. Setup SLO monitoring
slo_engine = SLOAlertingEngine()
slo_engine.register_slo("error_rate", "error_rate", 99.9, 3600)

# 3. Setup rate limiting
rate_limiter = RateLimiter(max_requests=1000, window_seconds=60)
```

See `neural_shield/documentation_api_stability_catalog_v22_2026_june.py` for complete API reference.
"""
    
    def export_json(self) -> str:
        """Export entire catalog as JSON for documentation tools."""
        data = {
            "catalog_version": self.CATALOG_VERSION,
            "catalog_date": self.CATALOG_DATE,
            "modules": {
                mid: {
                    "module_name": m.module_name,
                    "module_path": m.module_path,
                    "stability_level": m.stability_level.value,
                    "support_level": m.support_level.value,
                    "version": m.version,
                    "production_readiness": m.production_readiness_score,
                    "description": m.description[:100] + "..."
                }
                for mid, m in self._modules.items()
            },
            "integration_guides": list(self._integration_guides.keys()),
            "checklist_items": len(self._production_checklist)
        }
        return json.dumps(data, indent=2)


# Global convenience instance
_documentation_catalog_v22: Optional[DocumentationCatalogV22] = None


def get_documentation_catalog() -> DocumentationCatalogV22:
    """Get the global documentation catalog instance (lazy initialized)."""
    global _documentation_catalog_v22
    if _documentation_catalog_v22 is None:
        _documentation_catalog_v22 = DocumentationCatalogV22()
    return _documentation_catalog_v22


def get_module_stability(module_id: str) -> Optional[str]:
    """Quick access: Get stability level for a module as string."""
    catalog = get_documentation_catalog()
    mod = catalog.get_module_documentation(module_id)
    return mod.stability_level.value if mod else None


def print_readme_update() -> None:
    """Print README update content."""
    catalog = get_documentation_catalog()
    print(catalog.generate_readme_update())


if __name__ == "__main__":
    print("=" * 60)
    print("NeuralShield-AI Documentation Catalog v22")
    print("=" * 60)
    print_readme_update()
    print("\nProduction Checklist Items:", len(get_documentation_catalog().get_production_deployment_checklist()))
