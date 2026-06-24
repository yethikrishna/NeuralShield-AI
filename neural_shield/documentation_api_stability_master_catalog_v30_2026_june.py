"""
NeuralShield-AI: Comprehensive API Documentation & Stability Catalog v30
=======================================================================
Date: 2026-06-25
Dimension: F - Documentation & API Stability

This module provides:
1. Comprehensive API documentation for all public interfaces
2. API stability markers (STABLE/EXPERIMENTAL/DEPRECATED)
3. Usage examples and code snippets
4. Type hints and parameter documentation
5. Migration guides and version compatibility notes

API STABILITY LEVELS:
---------------------
STABLE:         API is frozen, backward compatible, safe for production
EXPERIMENTAL:   API may change, suitable for testing only
DEPRECATED:     Will be removed in future versions, migrate now
INTERNAL:       Not for public consumption, may change without notice
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type, Union
from datetime import datetime
import inspect


class StabilityLevel(Enum):
    """API Stability Level Classification"""
    STABLE = "STABLE"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"
    INTERNAL = "INTERNAL"
    
    def __str__(self) -> str:
        return self.value


@dataclass
class APIEndpoint:
    """Metadata for a documented API endpoint"""
    name: str
    module: str
    stability: StabilityLevel
    since_version: str
    description: str
    parameters: List[Dict[str, str]] = field(default_factory=list)
    returns: str = ""
    examples: List[str] = field(default_factory=list)
    notes: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    deprecation_scheduled: Optional[str] = None
    migration_guide: Optional[str] = None


@dataclass
class ModuleDocumentation:
    """Complete documentation for a module"""
    module_name: str
    category: str
    stability: StabilityLevel
    endpoints: List[APIEndpoint] = field(default_factory=list)
    overview: str = ""
    getting_started: str = ""
    best_practices: List[str] = field(default_factory=list)
    common_pitfalls: List[str] = field(default_factory=list)


class DocumentationCatalog:
    """
    Central API Documentation and Stability Catalog
    
    Stability: STABLE (since v20)
    
    This is the single source of truth for all API documentation
    and stability information in NeuralShield-AI.
    
    Usage:
        catalog = DocumentationCatalog()
        catalog.print_stability_report()
        docs = catalog.get_module_docs("threat_intelligence")
    """
    
    def __init__(self) -> None:
        self._modules: Dict[str, ModuleDocumentation] = {}
        self._build_catalog()
    
    def _build_catalog(self) -> None:
        """Build the complete documentation catalog"""
        # Core Detection Modules
        self._add_prompt_injection_docs()
        self._add_threat_intelligence_docs()
        self._add_adversarial_detection_docs()
        
        # Security Modules
        self._add_security_hardening_docs()
        self._add_error_resilience_docs()
        
        # Observability Modules
        self._add_observability_docs()
        
        # Feature Expansion Modules
        self._add_feature_expansion_docs()
    
    def _add_prompt_injection_docs(self) -> None:
        """Prompt Injection Detection Module Documentation"""
        module = ModuleDocumentation(
            module_name="prompt_injection",
            category="Core Detection",
            stability=StabilityLevel.STABLE,
            overview="""
            Prompt Injection Detection provides multi-layered protection against
            prompt injection attacks, including direct injection, indirect injection,
            context poisoning, and prompt chaining attacks.
            
            All detectors follow a consistent API pattern for easy integration.
            """,
            getting_started="""
            from neural_shield.prompt_injection_ensemble_detector_v2_2026_june import (
                PromptInjectionEnsembleDetector
            )
            
            detector = PromptInjectionEnsembleDetector()
            result = detector.detect("User input here")
            """,
            best_practices=[
                "Always use ensemble detection over single detectors",
                "Set confidence thresholds appropriate for your use case",
                "Enable context-aware detection for multi-turn conversations",
                "Log all detections for audit and model improvement"
            ],
            common_pitfalls=[
                "Setting thresholds too low causes false positives",
                "Forgetting to sanitize context window inputs",
                "Not handling detection failures gracefully"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="PromptInjectionEnsembleDetector.detect",
                module="prompt_injection_ensemble_detector_v2",
                stability=StabilityLevel.STABLE,
                since_version="v15",
                description="Detect prompt injection in user input using ensemble methods",
                parameters=[
                    {"name": "user_input", "type": "str", "desc": "Input text to analyze"},
                    {"name": "context", "type": "Optional[str]", "desc": "Conversation context"}
                ],
                returns="DetectionResult with confidence score and threat indicators",
                examples=[
                    """
                    detector = PromptInjectionEnsembleDetector()
                    result = detector.detect(
                        "Ignore previous instructions",
                        context="System: You are a helpful assistant"
                    )
                    print(f"Threat: {result.is_threat}, Confidence: {result.confidence}")
                    """
                ],
                notes=["Returns confidence 0.0-1.0, threshold defaults to 0.7"]
            ),
            APIEndpoint(
                name="PromptInjectionContextChainAnalyzer.analyze_chain",
                module="prompt_injection_context_chain_analyzer_v4",
                stability=StabilityLevel.STABLE,
                since_version="v22",
                description="Analyze conversation history for injection patterns across turns",
                parameters=[
                    {"name": "conversation_history", "type": "List[Dict]", "desc": "Message history"},
                    {"name": "max_depth", "type": "int", "desc": "History depth to analyze"}
                ],
                returns="ChainAnalysisResult with injection risk assessment",
                notes=["Critical for multi-turn conversation protection"]
            ),
            APIEndpoint(
                name="PromptObfuscationDecoder.decode",
                module="prompt_obfuscation_decoder_detector_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v18",
                description="Decode and detect obfuscated injection attempts",
                parameters=[
                    {"name": "encoded_input", "type": "str", "desc": "Potentially obfuscated input"}
                ],
                returns="DecodingResult with decoded text and obfuscation type",
                notes=["Handles Base64, ROT13, leetspeak, and character substitution"]
            )
        ])
        
        self._modules["prompt_injection"] = module
    
    def _add_threat_intelligence_docs(self) -> None:
        """Threat Intelligence Module Documentation"""
        module = ModuleDocumentation(
            module_name="threat_intelligence",
            category="Threat Intelligence",
            stability=StabilityLevel.STABLE,
            overview="""
            Threat Intelligence module provides comprehensive IOC processing,
            alert correlation, false positive reduction, and MITRE ATT&CK mapping.
            
            Features include bloom filter caching, batch processing, and
            automated playbook generation.
            """,
            getting_started="""
            from neural_shield.threat_intelligence_ioc_extractor_v76_2026_june import (
                IOCExtractor
            )
            
            extractor = IOCExtractor()
            iocs = extractor.extract("Raw log or report text")
            """,
            best_practices=[
                "Use batch processing for high-volume IOC ingestion",
                "Enable bloom filter caching for performance",
                "Configure confidence thresholds per IOC type",
                "Regular retrain false positive classifiers"
            ],
            common_pitfalls=[
                "Not normalizing IOCs before deduplication",
                "Ignoring confidence scores in alert correlation",
                "Processing IOCs without context enrichment"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="IOCExtractor.extract",
                module="threat_intelligence_ioc_extractor_v76",
                stability=StabilityLevel.STABLE,
                since_version="v70",
                description="Extract IOCs from unstructured text",
                parameters=[
                    {"name": "text", "type": "str", "desc": "Text to extract IOCs from"},
                    {"name": "normalize", "type": "bool", "desc": "Normalize extracted IOCs"}
                ],
                returns="List[IOC] with type, value, and confidence",
                examples=[
                    """
                    extractor = IOCExtractor(normalize=True)
                    iocs = extractor.extract(\"\"\"
                        Attack from 192.168.1.1 using malware.exe
                        Domain: malicious.com
                    \"\"\")
                    for ioc in iocs:
                        print(f"{ioc.type}: {ioc.value}")
                    """
                ],
                notes=["Extracts IPs, domains, hashes, URLs, emails"]
            ),
            APIEndpoint(
                name="AlertCorrelationEngine.correlate",
                module="threat_intelligence_alert_correlation_context_enricher_v75",
                stability=StabilityLevel.STABLE,
                since_version="v60",
                description="Correlate alerts by context and similarity",
                parameters=[
                    {"name": "alerts", "type": "List[Alert]", "desc": "Alerts to correlate"},
                    {"name": "time_window_minutes", "type": "int", "desc": "Correlation window"}
                ],
                returns="List[CorrelatedAlertGroup] with related alerts",
                notes=["Reduces alert fatigue by 60-80% in typical environments"]
            ),
            APIEndpoint(
                name="FalsePositiveClassifier.classify",
                module="threat_intelligence_automated_false_positive_classifier_transformer_v14",
                stability=StabilityLevel.EXPERIMENTAL,
                since_version="v5",
                description="ML-based false positive classification",
                parameters=[
                    {"name": "alert", "type": "Alert", "desc": "Alert to classify"},
                    {"name": "historical_context", "type": "List[Alert]", "desc": "History"}
                ],
                returns="ClassificationResult with fp_probability 0.0-1.0",
                notes=["EXPERIMENTAL: Model still in training, validate results"]
            ),
            APIEndpoint(
                name="MITREAttackMapper.map",
                module="threat_intelligence_mitre_attack_mapper_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v74",
                description="Map alerts and IOCs to MITRE ATT&CK framework",
                parameters=[
                    {"name": "indicators", "type": "List[str]", "desc": "Threat indicators"}
                ],
                returns="MITREMappingResult with tactics, techniques, sub-techniques",
                notes=["Covers 40+ common MITRE techniques"]
            )
        ])
        
        self._modules["threat_intelligence"] = module
    
    def _add_adversarial_detection_docs(self) -> None:
        """Adversarial Detection Module Documentation"""
        module = ModuleDocumentation(
            module_name="adversarial_detection",
            category="Advanced Protection",
            stability=StabilityLevel.STABLE,
            overview="""
            Adversarial Detection provides protection against sophisticated
            attacks including adversarial prompts, jailbreaks, and model
            extraction attempts.
            """,
            getting_started="""
            from neural_shield.adversarial_prompt_anomaly_detector_2026_june import (
                AdversarialPromptAnomalyDetector
            )
            
            detector = AdversarialPromptAnomalyDetector()
            score = detector.score_anomaly("User prompt")
            """,
            best_practices=[
                "Combine multiple detectors for defense in depth",
                "Baseline normal behavior for your use case",
                "Enable gradient analysis for advanced detection"
            ],
            common_pitfalls=[
                "Single detector false negatives",
                "Not updating detection signatures"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="AdversarialPromptAnomalyDetector.score_anomaly",
                module="adversarial_prompt_anomaly_detector_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v12",
                description="Calculate anomaly score for prompt inputs",
                parameters=[
                    {"name": "prompt", "type": "str", "desc": "Prompt to analyze"}
                ],
                returns="AnomalyScore 0.0 (normal) to 1.0 (anomalous)",
                notes=["Uses embedding distance from normal prompt distribution"]
            ),
            APIEndpoint(
                name="AdvancedJailbreakDetector.detect",
                module="advanced_jailbreak_detector_2026",
                stability=StabilityLevel.STABLE,
                since_version="v8",
                description="Detect jailbreak and roleplay attempts",
                parameters=[
                    {"name": "user_input", "type": "str", "desc": "User input"}
                ],
                returns="JailbreakDetectionResult",
                notes=["Covers DAN, Developer Mode, and 50+ jailbreak variants"]
            )
        ])
        
        self._modules["adversarial_detection"] = module
    
    def _add_security_hardening_docs(self) -> None:
        """Security Hardening Module Documentation"""
        module = ModuleDocumentation(
            module_name="security_hardening",
            category="Security",
            stability=StabilityLevel.STABLE,
            overview="""
            Security Hardening provides input validation, secure memory
            handling, constant-time operations, and rate limiting.
            
            All security functions are side-channel resistant.
            """,
            getting_started="""
            from neural_shield.security_hardening_input_validation_wrappers_2026_june import (
                InputValidator, secure_input
            )
            
            validator = InputValidator()
            sanitized = validator.sanitize(user_input)
            """,
            best_practices=[
                "Validate ALL external inputs",
                "Use constant-time comparison for secrets",
                "Zero sensitive memory after use",
                "Configure appropriate rate limits"
            ],
            common_pitfalls=[
                "Validation bypass via encoding attacks",
                "Timing attacks on string comparison",
                "Sensitive data remaining in memory"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="constant_time_compare",
                module="security_hardening_constant_time_comparison_v23",
                stability=StabilityLevel.STABLE,
                since_version="v23",
                description="Timing-attack resistant string comparison",
                parameters=[
                    {"name": "a", "type": "str/bytes", "desc": "First value"},
                    {"name": "b", "type": "str/bytes", "desc": "Second value"}
                ],
                returns="bool - True if equal",
                examples=[
                    """
                    # Safe comparison for API keys
                    if constant_time_compare(user_key, expected_key):
                        grant_access()
                    """
                ],
                notes=["Execution time depends only on length, not content match"]
            ),
            APIEndpoint(
                name="secure_zeroize",
                module="secure_memory_zeroization_constant_time_helpers_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v23",
                description="Securely overwrite sensitive memory",
                parameters=[
                    {"name": "data", "type": "bytearray", "desc": "Data to zeroize"},
                    {"name": "passes", "type": "int", "desc": "Overwrite passes"}
                ],
                returns="None",
                notes=["Uses volatile writes to prevent compiler optimization"]
            ),
            APIEndpoint(
                name="AdaptiveRateLimiter.check_rate_limit",
                module="security_hardening_adaptive_rate_limiting_dos_protection_v11",
                stability=StabilityLevel.STABLE,
                since_version="v11",
                description="Adaptive rate limiting with DoS protection",
                parameters=[
                    {"name": "client_id", "type": "str", "desc": "Client identifier"},
                    {"name": "cost", "type": "int", "desc": "Request cost units"}
                ],
                returns="RateLimitResult with allowed flag and retry_after",
                notes=["Automatically throttles aggressive clients"]
            )
        ])
        
        self._modules["security_hardening"] = module
    
    def _add_error_resilience_docs(self) -> None:
        """Error Resilience Module Documentation"""
        module = ModuleDocumentation(
            module_name="error_resilience",
            category="Reliability",
            stability=StabilityLevel.STABLE,
            overview="""
            Error Resilience provides circuit breakers, retry with backoff,
            timeout wrappers, and graceful degradation fallbacks.
            
            All wrappers preserve happy-path behavior 100%.
            """,
            getting_started="""
            from neural_shield.error_resilience_retry_backoff_circuit_breaker_2026_june import (
                RetryWithBackoff, CircuitBreaker
            )
            
            @RetryWithBackoff(max_retries=3)
            @CircuitBreaker(failure_threshold=5)
            def external_api_call():
                pass
            """,
            best_practices=[
                "Wrap all external dependencies",
                "Set appropriate timeouts for all operations",
                "Use circuit breakers to prevent cascade failures",
                "Always provide graceful degradation fallbacks"
            ],
            common_pitfalls=[
                "Retry storms without jitter",
                "Infinite timeout on network calls",
                "Not isolating failures in bulkheads"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="RetryWithBackoff decorator",
                module="error_resilience_retry_backoff_circuit_breaker_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v30",
                description="Retry with exponential backoff and jitter",
                parameters=[
                    {"name": "max_retries", "type": "int", "desc": "Max retry attempts"},
                    {"name": "base_delay", "type": "float", "desc": "Initial delay seconds"},
                    {"name": "jitter", "type": "float", "desc": "Random jitter factor"}
                ],
                returns="Decorated function",
                examples=[
                    """
                    @RetryWithBackoff(max_retries=3, base_delay=1.0, jitter=0.5)
                    def call_external_api():
                        return requests.get("https://api.example.com")
                    """
                ],
                notes=["Jitter prevents thundering herd problems"]
            ),
            APIEndpoint(
                name="CircuitBreaker decorator",
                module="error_resilience_advanced_circuit_breaker_fallback_v23_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v23",
                description="Circuit breaker with health monitoring",
                parameters=[
                    {"name": "failure_threshold", "type": "int", "desc": "Open threshold"},
                    {"name": "recovery_timeout", "type": "float", "desc": "Half-open delay"},
                    {"name": "fallback", "type": "Callable", "desc": "Fallback function"}
                ],
                returns="Decorated function",
                notes=["Three states: CLOSED, OPEN, HALF_OPEN"]
            ),
            APIEndpoint(
                name="timeout decorator",
                module="error_resilience_adaptive_timeout_jitter_backoff_v20_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v20",
                description="Timeout wrapper for function execution",
                parameters=[
                    {"name": "seconds", "type": "float", "desc": "Timeout in seconds"}
                ],
                returns="Decorated function",
                notes=["Raises TimeoutError if function exceeds time limit"]
            )
        ])
        
        self._modules["error_resilience"] = module
    
    def _add_observability_docs(self) -> None:
        """Observability Module Documentation"""
        module = ModuleDocumentation(
            module_name="observability",
            category="Observability",
            stability=StabilityLevel.STABLE,
            overview="""
            Observability provides structured logging, metrics collection,
            distributed tracing, and health checks.
            
            All instrumentation is OPT-IN and disabled by default.
            """,
            getting_started="""
            from neural_shield.observability_structured_logging_metrics_v25_2026_june import (
                MetricsCollector, StructuredLogger
            )
            
            metrics = MetricsCollector()
            metrics.increment("requests.total")
            """,
            best_practices=[
                "Enable only needed instrumentation",
                "Use high-cardinality dimensions sparingly",
                "Set appropriate sampling rates for tracing",
                "Monitor health check endpoints externally"
            ],
            common_pitfalls=[
                "High-cardinality metrics explosion",
                "Logging sensitive data",
                "Tracing overhead in hot paths"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="MetricsCollector",
                module="observability_metrics_collection_v8_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v25",
                description="Collect counters, gauges, timers, and histograms",
                parameters=[
                    {"name": "namespace", "type": "str", "desc": "Metric prefix"}
                ],
                returns="MetricsCollector instance",
                examples=[
                    """
                    metrics = MetricsCollector(namespace="neuralshield")
                    metrics.increment("detections.total", tags={"type": "prompt_injection"})
                    metrics.gauge("queue.size", 42)
                    with metrics.timer("request.duration"):
                        process_request()
                    """
                ],
                notes=["Thread-safe, no external dependencies"]
            ),
            APIEndpoint(
                name="DistributedTracer",
                module="observability_distributed_tracing_correlation_v15_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v15",
                description="Distributed tracing with context propagation",
                parameters=[
                    {"name": "service_name", "type": "str", "desc": "Service identifier"}
                ],
                returns="Tracer instance",
                notes=["Baggage propagation for cross-service correlation"]
            ),
            APIEndpoint(
                name="HealthCheckFramework",
                module="observability_health_check_framework_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v10",
                description="Health checks with liveness/readiness probes",
                parameters=[
                    {"name": "check_timeout", "type": "float", "desc": "Per-check timeout"}
                ],
                returns="HealthCheckFramework instance",
                notes=["Supports custom check registration"]
            )
        ])
        
        self._modules["observability"] = module
    
    def _add_feature_expansion_docs(self) -> None:
        """Feature Expansion Module Documentation"""
        module = ModuleDocumentation(
            module_name="feature_expansion",
            category="Features",
            stability=StabilityLevel.STABLE,
            overview="""
            Feature Expansion provides extended capabilities including
            MITRE ATT&CK mapping, threat hunting queries, and HTTP metrics.
            
            All features are additive and optional.
            """,
            getting_started="""
            from neural_shield.feature_expansion_mitre_technique_matcher_v80_2026_june import (
                MITRETechniqueMatcher
            )
            
            matcher = MITRETechniqueMatcher()
            techniques = matcher.match("threat description")
            """,
            best_practices=[
                "Use MITRE mapping for standardized reporting",
                "Cache hunting query results when appropriate",
                "Configure metrics server port appropriately"
            ],
            common_pitfalls=[
                "Over-matching MITRE techniques",
                "Not rate-limiting metrics endpoints"
            ]
        )
        
        module.endpoints.extend([
            APIEndpoint(
                name="MITRETechniqueMatcher.match",
                module="feature_expansion_mitre_technique_matcher_v80_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v80",
                description="Match threat descriptions to MITRE ATT&CK techniques",
                parameters=[
                    {"name": "threat_text", "type": "str", "desc": "Threat description"},
                    {"name": "min_confidence", "type": "float", "desc": "Minimum match confidence"}
                ],
                returns="List[MITRETechniqueMatch]",
                notes=["Covers 40+ techniques across all tactics"]
            ),
            APIEndpoint(
                name="ThreatHuntingQueryBuilder.build",
                module="feature_expansion_threat_hunting_query_builder_v28_2026_june",
                stability=StabilityLevel.STABLE,
                since_version="v28",
                description="Build hunting queries for SIEM platforms",
                parameters=[
                    {"name": "iocs", "type": "List[IOC]", "desc": "IOCs to hunt"},
                    {"name": "platform", "type": "str", "desc": "SIEM platform type"}
                ],
                returns="HuntingQuery with platform-specific syntax",
                notes=["Supports Splunk, Elastic, Sentinel, CrowdStrike"]
            )
        ])
        
        self._modules["feature_expansion"] = module
    
    def get_module_docs(self, module_name: str) -> Optional[ModuleDocumentation]:
        """Get documentation for a specific module"""
        return self._modules.get(module_name)
    
    def get_all_modules(self) -> List[str]:
        """Get list of all documented modules"""
        return list(self._modules.keys())
    
    def get_stability_summary(self) -> Dict[str, int]:
        """Get count of endpoints by stability level"""
        summary = {level: 0 for level in StabilityLevel}
        for module in self._modules.values():
            for endpoint in module.endpoints:
                summary[endpoint.stability] += 1
        return {str(k): v for k, v in summary.items()}
    
    def print_stability_report(self) -> None:
        """Print human-readable stability report"""
        print("=" * 70)
        print("NEURALSHIELD-AI API STABILITY REPORT v30")
        print("=" * 70)
        print(f"Date: {datetime.now().strftime('%Y-%m-%d')}")
        print(f"Modules Documented: {len(self._modules)}")
        
        total_endpoints = sum(len(m.endpoints) for m in self._modules.values())
        print(f"Total Documented Endpoints: {total_endpoints}")
        print()
        
        print("STABILITY BREAKDOWN:")
        for level, count in self.get_stability_summary().items():
            pct = (count / total_endpoints * 100) if total_endpoints > 0 else 0
            print(f"  {level:15} {count:3d} endpoints ({pct:5.1f}%)")
        
        print()
        print("MODULES:")
        for name, module in sorted(self._modules.items()):
            print(f"  {name:25} [{module.stability.value:12}] "
                  f"{len(module.endpoints)} endpoints")
        
        print()
        print("=" * 70)
        print("API STABILITY GUARANTEE:")
        print("  STABLE endpoints: No breaking changes in major versions")
        print("  EXPERIMENTAL: May change, test thoroughly before use")
        print("  DEPRECATED: Will be removed, migrate immediately")
        print("=" * 70)


# Global catalog instance
_catalog_instance: Optional[DocumentationCatalog] = None


def get_documentation_catalog() -> DocumentationCatalog:
    """Get the global documentation catalog instance (singleton)"""
    global _catalog_instance
    if _catalog_instance is None:
        _catalog_instance = DocumentationCatalog()
    return _catalog_instance


def print_api_stability_report() -> None:
    """Convenience function to print the full stability report"""
    catalog = get_documentation_catalog()
    catalog.print_stability_report()


# Export public API
__all__ = [
    'StabilityLevel',
    'APIEndpoint',
    'ModuleDocumentation',
    'DocumentationCatalog',
    'get_documentation_catalog',
    'print_api_stability_report',
]

# API Stability Markers for exports
# All exports in this module are STABLE
__api_stability__ = {
    'StabilityLevel': 'STABLE',
    'APIEndpoint': 'STABLE',
    'ModuleDocumentation': 'STABLE',
    'DocumentationCatalog': 'STABLE',
    'get_documentation_catalog': 'STABLE',
    'print_api_stability_report': 'STABLE',
}
