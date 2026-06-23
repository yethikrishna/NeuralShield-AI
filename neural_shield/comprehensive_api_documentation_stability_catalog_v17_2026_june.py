"""
NeuralShield-AI Comprehensive API Documentation & Stability Catalog v17
=====================================================================
API Stability Markers:
    STABLE:         Production-ready, backward-compatible, no breaking changes
    BETA:           Near-stable, minor changes possible, production-ready with caution
    EXPERIMENTAL:   Active development, breaking changes likely, NOT for production
    DEPRECATED:     Scheduled for removal, migrate to alternatives
    LEGACY:         Maintained for backward compatibility only

This module provides:
1. Complete API catalog with stability markers (UPDATED v17)
2. Usage examples for every major module
3. Migration guides between versions
4. Compatibility matrix
5. Performance characteristics documentation
6. NEW v17: Security hardening module documentation
7. NEW v17: Observability integration documentation

ADD-ONLY MODULE - No existing code modified, pure documentation layer.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
import json
from datetime import datetime


class StabilityLevel(Enum):
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    LEGACY = "LEGACY"


@dataclass
class APIEndpoint:
    name: str
    module_path: str
    stability: StabilityLevel
    description: str
    since_version: str
    deprecation_version: Optional[str] = None
    removal_version: Optional[str] = None
    performance_characteristics: Dict[str, str] = field(default_factory=dict)
    thread_safe: bool = True
    memory_bound: bool = True
    usage_examples: List[str] = field(default_factory=list)
    compatibility_notes: List[str] = field(default_factory=list)
    security_boundary: str = "standard"


@dataclass
class MigrationGuide:
    from_version: str
    to_version: str
    breaking_changes: List[str]
    migration_steps: List[str]
    backward_compatible: bool = True


class NeuralShieldAPICatalog:
    """
    Comprehensive API documentation catalog for NeuralShield-AI v17.
    Pure documentation layer - 100% ADD-ONLY, no runtime impact.
    """
    
    def __init__(self):
        self._endpoints: Dict[str, APIEndpoint] = {}
        self._migration_guides: List[MigrationGuide] = []
        self._init_catalog()
        self._init_migration_guides()
    
    def _init_catalog(self):
        """Initialize the complete API catalog with stability markers."""
        
        # ==================== v17 NEW: SECURITY HARDENING MODULES ====================
        
        self._endpoints["side_channel_resistance_v17"] = APIEndpoint(
            name="SideChannelResistantEvaluator",
            module_path="neural_shield.security_hardening_side_channel_timing_resistance_v17",
            stability=StabilityLevel.BETA,
            description="v17: Side-channel timing attack resistance with constant-time validation",
            since_version="v17",
            performance_characteristics={
                "avg_latency_ms": "2-5",
                "p99_latency_ms": "15",
                "memory_mb": "~10",
                "throughput": "2000+ ops/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="high",
            usage_examples=[
                """
                evaluator = SideChannelResistantEvaluator()
                is_safe = evaluator.constant_time_compare(a, b)
                # Timing invariant - no leakage through execution time
                """,
                """
                # Memory protection
                evaluator.zeroize_sensitive_data(buffer)
                """
            ],
            compatibility_notes=[
                "v17 NEW: Side-channel resistance module",
                "Constant-time operations verified"
            ]
        )
        
        self._endpoints["security_telemetry_v14"] = APIEndpoint(
            name="SecurityTelemetryCollector",
            module_path="neural_shield.observability_security_hardening_telemetry_v14",
            stability=StabilityLevel.BETA,
            description="v14: Security operation telemetry with metrics and tracing",
            since_version="v14",
            performance_characteristics={
                "avg_latency_ms": "1-3 (disabled: 0 overhead)",
                "p99_latency_ms": "10",
                "memory_mb": "~25",
                "throughput": "5000+ ops/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard",
            usage_examples=[
                """
                # OPT-IN ONLY - disabled by default
                telemetry = SecurityTelemetryCollector(enabled=False)
                # No overhead when disabled (pure NO-OP)
                """,
                """
                # Enable explicitly
                telemetry = SecurityTelemetryCollector(
                    enabled=True,
                    enable_metrics=True,
                    enable_tracing=True
                )
                """
            ],
            compatibility_notes=[
                "STRICT OPT-IN: Disabled by default for ZERO overhead",
                "100% backward compatible"
            ]
        )
        
        # ==================== CORE DETECTION MODULES ====================
        
        self._endpoints["prompt_injection_detector"] = APIEndpoint(
            name="PromptInjectionDetector",
            module_path="neural_shield.prompt_injection_detector",
            stability=StabilityLevel.STABLE,
            description="Primary prompt injection detection with semantic analysis",
            since_version="v1",
            performance_characteristics={
                "avg_latency_ms": "15-25",
                "p99_latency_ms": "50",
                "memory_mb": "~120",
                "throughput": "40-60 req/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard",
            usage_examples=[
                """
                detector = PromptInjectionDetector()
                result = detector.detect("Ignore previous instructions...")
                is_safe = result.is_safe
                confidence = result.confidence
                """,
                """
                # Batch detection
                results = detector.detect_batch(prompts, threshold=0.85)
                """
            ],
            compatibility_notes=["Backward compatible with all v1.x versions"]
        )
        
        self._endpoints["jailbreak_detector"] = APIEndpoint(
            name="JailbreakDetector",
            module_path="neural_shield.jailbreak_detector",
            stability=StabilityLevel.STABLE,
            description="Multi-strategy jailbreak detection with pattern matching",
            since_version="v2",
            performance_characteristics={
                "avg_latency_ms": "20-35",
                "p99_latency_ms": "75",
                "memory_mb": "~150",
                "throughput": "30-50 req/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard"
        )
        
        self._endpoints["adversarial_prompt_detector"] = APIEndpoint(
            name="AdversarialPromptDetector",
            module_path="neural_shield.adversarial_prompt_detector",
            stability=StabilityLevel.BETA,
            description="Adversarial prompt detection with gradient analysis",
            since_version="v8",
            performance_characteristics={
                "avg_latency_ms": "45-75",
                "p99_latency_ms": "150",
                "memory_mb": "~250",
                "throughput": "15-25 req/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="enhanced"
        )
        
        # ==================== THREAT INTELLIGENCE MODULES ====================
        
        self._endpoints["threat_intel_correlator"] = APIEndpoint(
            name="ThreatIntelCorrelator",
            module_path="neural_shield.threat_intel_correlator",
            stability=StabilityLevel.STABLE,
            description="IOC correlation and threat intelligence enrichment",
            since_version="v5",
            performance_characteristics={
                "avg_latency_ms": "5-15",
                "p99_latency_ms": "30",
                "memory_mb": "~80",
                "throughput": "100-200 req/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard"
        )
        
        self._endpoints["mitre_mapper"] = APIEndpoint(
            name="MITREAttackMapper",
            module_path="neural_shield.mitre_mapper",
            stability=StabilityLevel.BETA,
            description="Automatic MITRE ATT&CK technique mapping and classification",
            since_version="v11",
            performance_characteristics={
                "avg_latency_ms": "30-50",
                "p99_latency_ms": "100",
                "memory_mb": "~180",
                "throughput": "20-35 req/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard"
        )
        
        self._endpoints["false_positive_classifier_v19"] = APIEndpoint(
            name="FalsePositiveClassifierTransformer",
            module_path="neural_shield.false_positive_classifier_transformer_v19",
            stability=StabilityLevel.EXPERIMENTAL,
            description="v19: Transformer-based false positive classification",
            since_version="v19",
            performance_characteristics={
                "avg_latency_ms": "80-150",
                "p99_latency_ms": "300",
                "memory_mb": "~500",
                "throughput": "5-10 req/sec"
            },
            thread_safe=True,
            memory_bound=False,
            security_boundary="standard",
            compatibility_notes=[
                "EXPERIMENTAL: Model architecture evolving",
                "Heavy resource requirements"
            ]
        )
        
        # ==================== SECURITY HARDENING MODULES ====================
        
        self._endpoints["input_validator"] = APIEndpoint(
            name="SecureInputValidator",
            module_path="neural_shield.secure_input_validator",
            stability=StabilityLevel.STABLE,
            description="Secure input validation with type checking and sanitization",
            since_version="v9",
            performance_characteristics={
                "avg_latency_ms": "1-3",
                "p99_latency_ms": "10",
                "memory_mb": "~20",
                "throughput": "500-1000 req/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="high"
        )
        
        self._endpoints["memory_zeroizer"] = APIEndpoint(
            name="SecureMemoryZeroizer",
            module_path="neural_shield.secure_memory_zeroizer",
            stability=StabilityLevel.STABLE,
            description="Secure memory zeroization with constant-time operations",
            since_version="v10",
            performance_characteristics={
                "avg_latency_ms": "<1",
                "p99_latency_ms": "5",
                "memory_mb": "~5",
                "throughput": "10000+ ops/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="high"
        )
        
        self._endpoints["rate_limiter_v11"] = APIEndpoint(
            name="AdaptiveRateLimiter",
            module_path="neural_shield.security_hardening_adaptive_rate_limiting_v11",
            stability=StabilityLevel.BETA,
            description="v11: Adaptive rate limiting with DoS protection",
            since_version="v11",
            performance_characteristics={
                "avg_latency_ms": "<1",
                "p99_latency_ms": "5",
                "memory_mb": "~30",
                "throughput": "10000+ checks/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="high"
        )
        
        # ==================== OBSERVABILITY MODULES ====================
        
        self._endpoints["opentelemetry_v13"] = APIEndpoint(
            name="OpenTelemetryContextPropagator",
            module_path="neural_shield.observability_opentelemetry_context_propagation_v13",
            stability=StabilityLevel.EXPERIMENTAL,
            description="v13: OpenTelemetry context propagation with baggage",
            since_version="v13",
            performance_characteristics={
                "avg_latency_ms": "1-3 (disabled: 0 overhead)",
                "p99_latency_ms": "10",
                "memory_mb": "~35",
                "throughput": "5000+ ops/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard",
            compatibility_notes=[
                "OPT-IN ONLY: Disabled by default",
                "W3C trace context compatible"
            ]
        )
        
        # ==================== ERROR RESILIENCE MODULES ====================
        
        self._endpoints["circuit_breaker_v18"] = APIEndpoint(
            name="EnhancedCircuitBreakerWithFallbacks",
            module_path="neural_shield.error_resilience_enhanced_circuit_breaker_v18",
            stability=StabilityLevel.STABLE,
            description="v18: Circuit breaker with fallback chain orchestration",
            since_version="v18",
            performance_characteristics={
                "avg_latency_ms": "<1",
                "p99_latency_ms": "5",
                "memory_mb": "~20",
                "throughput": "10000+ checks/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard"
        )
        
        self._endpoints["exception_hierarchy_v21"] = APIEndpoint(
            name="NeuralShieldExceptionHierarchy",
            module_path="neural_shield.error_resilience_comprehensive_exception_hierarchy_v21",
            stability=StabilityLevel.STABLE,
            description="v21: Complete custom exception hierarchy with error codes",
            since_version="v21",
            performance_characteristics={
                "avg_latency_ms": "<1",
                "memory_mb": "~10"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard"
        )
        
        self._endpoints["timeout_backoff_v20"] = APIEndpoint(
            name="AdaptiveTimeoutJitterBackoff",
            module_path="neural_shield.error_resilience_adaptive_timeout_jitter_backoff_v20",
            stability=StabilityLevel.STABLE,
            description="v20: Adaptive timeout with jittered exponential backoff",
            since_version="v20",
            performance_characteristics={
                "avg_latency_ms": "<1",
                "memory_mb": "~15",
                "throughput": "10000+ ops/sec"
            },
            thread_safe=True,
            memory_bound=True,
            security_boundary="standard"
        )
        
        # ==================== MULTIMODAL MODULES ====================
        
        self._endpoints["multimodal_detector"] = APIEndpoint(
            name="MultimodalThreatDetector",
            module_path="neural_shield.multimodal_detector",
            stability=StabilityLevel.EXPERIMENTAL,
            description="Image/audio prompt injection and steganography detection",
            since_version="v16",
            performance_characteristics={
                "avg_latency_ms": "200-500",
                "p99_latency_ms": "1000",
                "memory_mb": "~800",
                "throughput": "2-5 req/sec"
            },
            thread_safe=True,
            memory_bound=False,
            security_boundary="enhanced",
            compatibility_notes=[
                "EXPERIMENTAL: Heavy resource usage",
                "Requires PIL >= 10.0.0, torch >= 2.0.0"
            ]
        )
    
    def _init_migration_guides(self):
        """Initialize migration guides between major versions."""
        
        self._migration_guides.append(MigrationGuide(
            from_version="v16",
            to_version="v17",
            breaking_changes=[
                "No breaking changes - pure documentation update"
            ],
            migration_steps=[
                "No code changes required",
                "Import v17 catalog for updated documentation"
            ],
            backward_compatible=True
        ))
        
        self._migration_guides.append(MigrationGuide(
            from_version="v14",
            to_version="v15",
            breaking_changes=[
                "Observability config structure updated"
            ],
            migration_steps=[
                "Update ObservabilityConfig to use new enable_metrics flag",
                "No code changes required for default (disabled) mode"
            ],
            backward_compatible=True
        ))
    
    def get_endpoint(self, name: str) -> Optional[APIEndpoint]:
        """Get API endpoint documentation by name."""
        return self._endpoints.get(name)
    
    def list_by_stability(self, stability: StabilityLevel) -> List[APIEndpoint]:
        """List all endpoints with specified stability level."""
        return [ep for ep in self._endpoints.values() if ep.stability == stability]
    
    def list_by_security_boundary(self, boundary: str) -> List[APIEndpoint]:
        """v17 NEW: List endpoints by security boundary level."""
        return [ep for ep in self._endpoints.values() if ep.security_boundary == boundary]
    
    def get_compatibility_matrix(self) -> Dict[str, Any]:
        """Get Python version and dependency compatibility matrix."""
        return {
            "catalog_version": "v17",
            "python_versions": ["3.9", "3.10", "3.11", "3.12"],
            "recommended_python": "3.11",
            "core_dependencies": {
                "numpy": ">=1.21.0",
                "scipy": ">=1.9.0",
                "scikit-learn": ">=1.0.0"
            },
            "optional_dependencies": {
                "torch": ">=2.0.0 (multimodal only)",
                "PIL": ">=10.0.0 (image processing)",
                "prometheus_client": ">=0.17.0 (metrics export)"
            },
            "platforms": ["Linux", "macOS", "Windows (limited)"],
            "architectures": ["x86_64", "arm64"],
            "security_modules": [
                "side_channel_resistance_v17",
                "memory_zeroizer",
                "input_validator",
                "rate_limiter_v11"
            ]
        }
    
    def generate_documentation(self, format: str = "json") -> str:
        """Generate complete API documentation in specified format."""
        docs = {
            "catalog_version": "v17",
            "generated_at": datetime.utcnow().isoformat(),
            "total_endpoints": len(self._endpoints),
            "stability_breakdown": {
                level.value: len(self.list_by_stability(level))
                for level in StabilityLevel
            },
            "security_boundary_breakdown": {
                boundary: len(self.list_by_security_boundary(boundary))
                for boundary in ["standard", "enhanced", "high"]
            },
            "endpoints": {
                name: {
                    "name": ep.name,
                    "module_path": ep.module_path,
                    "stability": ep.stability.value,
                    "description": ep.description,
                    "since_version": ep.since_version,
                    "performance": ep.performance_characteristics,
                    "thread_safe": ep.thread_safe,
                    "memory_bound": ep.memory_bound,
                    "security_boundary": ep.security_boundary
                }
                for name, ep in self._endpoints.items()
            },
            "compatibility_matrix": self.get_compatibility_matrix()
        }
        
        if format == "json":
            return json.dumps(docs, indent=2)
        return str(docs)
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get summary count of endpoints by stability level."""
        return {
            level.value: len(self.list_by_stability(level))
            for level in StabilityLevel
        }


# Singleton instance for easy import
api_catalog = NeuralShieldAPICatalog()


def get_api_stability(module_name: str) -> Optional[str]:
    """
    Quick helper to get stability level for any module.
    Usage: from neural_shield.api_documentation_v17 import get_api_stability
           stability = get_api_stability("prompt_injection_detector")
    """
    endpoint = api_catalog.get_endpoint(module_name)
    return endpoint.stability.value if endpoint else None


def get_security_boundary(module_name: str) -> Optional[str]:
    """v17 NEW: Get security boundary level for module."""
    endpoint = api_catalog.get_endpoint(module_name)
    return endpoint.security_boundary if endpoint else None


def get_usage_example(module_name: str) -> Optional[str]:
    """Get usage example for specified module."""
    endpoint = api_catalog.get_endpoint(module_name)
    return endpoint.usage_examples[0] if endpoint and endpoint.usage_examples else None


__all__ = [
    'NeuralShieldAPICatalog',
    'APIEndpoint',
    'StabilityLevel',
    'MigrationGuide',
    'api_catalog',
    'get_api_stability',
    'get_security_boundary',
    'get_usage_example'
]
