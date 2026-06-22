"""
NeuralShield-AI Comprehensive API Stability Documentation Catalog v4
====================================================================
June 2026 Release | Production-Grade AI Security Framework

STABILITY HIERARCHY:
====================
STABLE     → API frozen, backward compatible, production-ready
BETA       → API mostly stable, minor changes possible, ready for testing
EXPERIMENTAL → Under active development, breaking changes likely
DEPRECATED → Scheduled for removal, use documented alternatives

INCREMENTAL BUILD PHILOSOPHY:
==============================
- NEVER break backward compatibility in STABLE APIs
- ADD-ONLY by default - extend, don't replace
- Deprecate before removing
- Preserve happy path behavior 100%
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime


class StabilityLevel(Enum):
    STABLE = "STABLE"
    BETA = "BETA"
    EXPERIMENTAL = "EXPERIMENTAL"
    DEPRECATED = "DEPRECATED"


@dataclass
class APIModule:
    name: str
    stability: StabilityLevel
    module_path: str
    description: str
    first_release: str
    last_updated: str
    maintainer: str
    tags: List[str] = field(default_factory=list)
    deprecation_notice: Optional[str] = None
    migration_guide: Optional[str] = None
    alternatives: List[str] = field(default_factory=list)
    test_coverage: float = 0.0
    performance_sla: Optional[Dict[str, float]] = None


@dataclass
class APIEndpoint:
    name: str
    module: str
    signature: str
    stability: StabilityLevel
    description: str
    parameters: List[Dict[str, Any]]
    return_type: str
    examples: List[str] = field(default_factory=list)
    exceptions: List[str] = field(default_factory=list)
    since_version: str = "2026.6.0"


class NeuralShieldAPIStabilityCatalog:
    """
    Comprehensive API Stability Catalog for NeuralShield-AI
    Single source of truth for all module stability and documentation
    """
    
    VERSION = "2026.6.22"
    CATALOG_VERSION = "v4"
    
    def __init__(self):
        self.modules: Dict[str, APIModule] = {}
        self.endpoints: Dict[str, APIEndpoint] = {}
        self._initialize_catalog()
    
    def _initialize_catalog(self) -> None:
        """Initialize the complete API catalog"""
        self._register_prompt_injection_modules()
        self._register_jailbreak_detection_modules()
        self._register_model_integrity_modules()
        self._register_threat_intelligence_modules()
        self._register_observability_modules()
        self._register_security_hardening_modules()
        self._register_error_resilience_modules()
        self._register_endpoints()
    
    def _register_prompt_injection_modules(self) -> None:
        """Register all Prompt Injection Defense modules"""
        
        self.modules["PromptInjectionSandbox"] = APIModule(
            name="PromptInjectionSandbox",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.prompt_injection_sandboxed_executor_2026_june",
            description="Sandboxed execution environment with security policy enforcement for untrusted inputs",
            first_release="2026.5.0",
            last_updated="2026.6.15",
            maintainer="Security Team",
            tags=["prompt-injection", "sandbox", "execution", "stable"],
            test_coverage=94.5,
            performance_sla={"p50_ms": 12.5, "p99_ms": 45.0, "throughput": 800}
        )
        
        self.modules["ContextAwarePromptInjectionDefender"] = APIModule(
            name="ContextAwarePromptInjectionDefender",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.context_aware_prompt_injection_defender_2026_june",
            description="Context-aware injection detection with conversation history analysis",
            first_release="2026.5.0",
            last_updated="2026.6.18",
            maintainer="Detection Team",
            tags=["prompt-injection", "context", "conversation", "stable"],
            test_coverage=96.2,
            performance_sla={"p50_ms": 8.2, "p99_ms": 32.0, "throughput": 1200}
        )
        
        self.modules["PromptInjectionSemanticParaphraseDetector"] = APIModule(
            name="PromptInjectionSemanticParaphraseDetector",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.prompt_injection_semantic_paraphrase_detector_2026_june",
            description="Semantic paraphrase and obfuscation detection using embedding similarity",
            first_release="2026.5.5",
            last_updated="2026.6.10",
            maintainer="ML Team",
            tags=["prompt-injection", "semantic", "embeddings", "paraphrase", "stable"],
            test_coverage=92.8,
            performance_sla={"p50_ms": 15.8, "p99_ms": 55.0, "throughput": 630}
        )
        
        self.modules["PromptInjectionProvenanceTrackerV3"] = APIModule(
            name="PromptInjectionProvenanceTrackerV3",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.prompt_injection_provenance_tracker_v3_2026_june",
            description="Injection source tracking, attribution, and provenance chain analysis",
            first_release="2026.6.0",
            last_updated="2026.6.20",
            maintainer="Forensics Team",
            tags=["prompt-injection", "provenance", "attribution", "forensics", "beta"],
            test_coverage=87.3,
            performance_sla={"p50_ms": 22.4, "p99_ms": 78.0, "throughput": 450}
        )
        
        self.modules["PromptInjectionEvasionTechniqueDetectorV4"] = APIModule(
            name="PromptInjectionEvasionTechniqueDetectorV4",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.prompt_injection_evasion_technique_detector_v4_2026_june",
            description="Advanced evasion technique detection including base64, rot13, leetspeak",
            first_release="2026.6.5",
            last_updated="2026.6.18",
            maintainer="Evasion Team",
            tags=["prompt-injection", "evasion", "obfuscation", "decoding", "beta"],
            test_coverage=89.1,
            performance_sla={"p50_ms": 18.6, "p99_ms": 62.0, "throughput": 540}
        )
        
        self.modules["CrossModalPromptInjectionDetector"] = APIModule(
            name="CrossModalPromptInjectionDetector",
            stability=StabilityLevel.EXPERIMENTAL,
            module_path="neural_shield.cross_modal_prompt_injection_detector_2026_june",
            description="Multi-modal injection detection for images, audio, and video inputs",
            first_release="2026.6.10",
            last_updated="2026.6.20",
            maintainer="Multi-Modal Team",
            tags=["prompt-injection", "multi-modal", "vlm", "experimental"],
            test_coverage=72.5,
            performance_sla={"p50_ms": 85.0, "p99_ms": 250.0, "throughput": 120}
        )
    
    def _register_jailbreak_detection_modules(self) -> None:
        """Register all Jailbreak Detection modules"""
        
        self.modules["AdvancedJailbreakDetector2026"] = APIModule(
            name="AdvancedJailbreakDetector2026",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.advanced_jailbreak_detector_2026",
            description="Multi-strategy jailbreak detection with heuristic and ML ensembles",
            first_release="2026.5.0",
            last_updated="2026.6.12",
            maintainer="Jailbreak Team",
            tags=["jailbreak", "detection", "ensemble", "stable"],
            test_coverage=95.7,
            performance_sla={"p50_ms": 10.2, "p99_ms": 38.0, "throughput": 980}
        )
        
        self.modules["GraphBasedJailbreakDetector"] = APIModule(
            name="GraphBasedJailbreakDetector",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.graph_based_jailbreak_detector_2026",
            description="Graph-based recursive attack pattern detection and analysis",
            first_release="2026.5.8",
            last_updated="2026.6.8",
            maintainer="Graph Security Team",
            tags=["jailbreak", "graph", "recursive", "pattern", "stable"],
            test_coverage=93.4,
            performance_sla={"p50_ms": 14.8, "p99_ms": 52.0, "throughput": 680}
        )
        
        self.modules["ConstitutionalClassifier2026"] = APIModule(
            name="ConstitutionalClassifier2026",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.constitutional_classifier_2026",
            description="Constitutional AI content classification and policy enforcement",
            first_release="2026.5.0",
            last_updated="2026.6.15",
            maintainer="Policy Team",
            tags=["classification", "constitutional", "policy", "content", "stable"],
            test_coverage=97.1,
            performance_sla={"p50_ms": 6.5, "p99_ms": 24.0, "throughput": 1540}
        )
        
        self.modules["EnhancedConstitutionalClassifier2026"] = APIModule(
            name="EnhancedConstitutionalClassifier2026",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.enhanced_constitutional_classifier_2026_june",
            description="Enhanced constitutional classifier with multi-label support",
            first_release="2026.6.5",
            last_updated="2026.6.18",
            maintainer="Policy Team",
            tags=["classification", "constitutional", "multi-label", "beta"],
            test_coverage=88.6,
            performance_sla={"p50_ms": 9.2, "p99_ms": 35.0, "throughput": 1090}
        )
        
        self.modules["EnhancedMimeticDetector2026"] = APIModule(
            name="EnhancedMimeticDetector2026",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.enhanced_mimetic_detector_2026",
            description="Mimetic and role-play attack detection with persona analysis",
            first_release="2026.6.0",
            last_updated="2026.6.15",
            maintainer="Behavioral Team",
            tags=["jailbreak", "mimetic", "role-play", "persona", "beta"],
            test_coverage=85.9,
            performance_sla={"p50_ms": 16.4, "p99_ms": 58.0, "throughput": 610}
        )
        
        self.modules["MultiTurnJailbreakDefender"] = APIModule(
            name="MultiTurnJailbreakDefender",
            stability=StabilityLevel.EXPERIMENTAL,
            module_path="neural_shield.multi_turn_jailbreak_defender_2026",
            description="Multi-turn conversation jailbreak detection with state tracking",
            first_release="2026.6.15",
            last_updated="2026.6.20",
            maintainer="Conversation Team",
            tags=["jailbreak", "multi-turn", "conversation", "state", "experimental"],
            test_coverage=68.3,
            performance_sla={"p50_ms": 28.5, "p99_ms": 95.0, "throughput": 350}
        )
    
    def _register_model_integrity_modules(self) -> None:
        """Register all Model Integrity modules"""
        
        self.modules["ModelDriftMonitoringAlertingSystem"] = APIModule(
            name="ModelDriftMonitoringAlertingSystem",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.model_drift_monitoring_alerting_system_2026_june",
            description="Distribution drift detection, alerting, and automated response",
            first_release="2026.5.10",
            last_updated="2026.6.12",
            maintainer="Monitoring Team",
            tags=["drift", "monitoring", "alerting", "distribution", "stable"],
            test_coverage=91.8,
            performance_sla={"p50_ms": 22.0, "p99_ms": 75.0, "throughput": 450}
        )
        
        self.modules["HallucinationDetector2026"] = APIModule(
            name="HallucinationDetector2026",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.hallucination_detector_2026_june",
            description="Output factuality verification and hallucination detection",
            first_release="2026.5.5",
            last_updated="2026.6.10",
            maintainer="Factuality Team",
            tags=["hallucination", "factuality", "verification", "stable"],
            test_coverage=89.5,
            performance_sla={"p50_ms": 35.0, "p99_ms": 120.0, "throughput": 285}
        )
        
        self.modules["LLMOutputHallucinationFactualityDetector"] = APIModule(
            name="LLMOutputHallucinationFactualityDetector",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.llm_output_hallucination_factuality_detector_2026_june",
            description="Enhanced factuality detector with evidence retrieval",
            first_release="2026.6.5",
            last_updated="2026.6.18",
            maintainer="Factuality Team",
            tags=["hallucination", "factuality", "evidence", "beta"],
            test_coverage=84.2,
            performance_sla={"p50_ms": 58.0, "p99_ms": 180.0, "throughput": 170}
        )
        
        self.modules["LLMBackdoorDetector2026"] = APIModule(
            name="LLMBackdoorDetector2026",
            stability=StabilityLevel.EXPERIMENTAL,
            module_path="neural_shield.llm_backdoor_detector_2026_june",
            description="Backdoor trigger and watermark detection in model outputs",
            first_release="2026.6.10",
            last_updated="2026.6.20",
            maintainer="Model Security Team",
            tags=["backdoor", "watermark", "model-security", "experimental"],
            test_coverage=71.6,
            performance_sla={"p50_ms": 45.0, "p99_ms": 150.0, "throughput": 220}
        )
    
    def _register_threat_intelligence_modules(self) -> None:
        """Register all Threat Intelligence modules"""
        
        self.modules["MITREAttackV15CoverageAnalyzer"] = APIModule(
            name="MITREAttackV15CoverageAnalyzer",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.mitre_attack_v15_coverage_analyzer_2026_june",
            description="MITRE ATT&CK v15 framework mapping and coverage analysis",
            first_release="2026.5.15",
            last_updated="2026.6.15",
            maintainer="Threat Intel Team",
            tags=["mitre", "attack", "coverage", "mapping", "stable"],
            test_coverage=94.0,
            performance_sla={"p50_ms": 18.0, "p99_ms": 60.0, "throughput": 550}
        )
        
        self.modules["MalwareHashReputationChecker2026"] = APIModule(
            name="MalwareHashReputationChecker2026",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.malware_hash_reputation_checker_2026_june",
            description="Malware hash reputation checking and IOC enrichment",
            first_release="2026.6.0",
            last_updated="2026.6.18",
            maintainer="IOC Team",
            tags=["ioc", "malware", "reputation", "hash", "beta"],
            test_coverage=86.7,
            performance_sla={"p50_ms": 45.0, "p99_ms": 150.0, "throughput": 220}
        )
        
        self.modules["AlertCorrelationContextEnricherV73"] = APIModule(
            name="AlertCorrelationContextEnricherV73",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.alert_correlation_context_enricher_v73_2026_june",
            description="Alert correlation, deduplication, and context enrichment",
            first_release="2026.6.5",
            last_updated="2026.6.22",
            maintainer="SOC Team",
            tags=["alert", "correlation", "enrichment", "deduplication", "beta"],
            test_coverage=83.5,
            performance_sla={"p50_ms": 25.0, "p99_ms": 85.0, "throughput": 400}
        )
    
    def _register_observability_modules(self) -> None:
        """Register all Observability & Instrumentation modules"""
        
        self.modules["ObservabilityUnifiedHealthMetricsDashboardV4"] = APIModule(
            name="ObservabilityUnifiedHealthMetricsDashboardV4",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.observability_unified_health_metrics_dashboard_v4_2026_june",
            description="Unified health metrics dashboard with Prometheus export",
            first_release="2026.6.10",
            last_updated="2026.6.22",
            maintainer="Observability Team",
            tags=["observability", "metrics", "dashboard", "health", "stable"],
            test_coverage=92.3,
            performance_sla={"p50_ms": 5.0, "p99_ms": 15.0, "throughput": 2000}
        )
        
        self.modules["ObservabilityDistributedTracing2026"] = APIModule(
            name="ObservabilityDistributedTracing2026",
            stability=StabilityLevel.BETA,
            module_path="neural_shield.observability_distributed_tracing_2026_june",
            description="Distributed tracing with OpenTelemetry compatibility",
            first_release="2026.6.15",
            last_updated="2026.6.22",
            maintainer="Observability Team",
            tags=["tracing", "distributed", "opentelemetry", "beta"],
            test_coverage=87.8,
            performance_sla={"p50_ms": 8.0, "p99_ms": 28.0, "throughput": 1250}
        )
        
        self.modules["ObservabilityHealthCheckFramework2026"] = APIModule(
            name="ObservabilityHealthCheckFramework2026",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.observability_health_check_framework_2026_june",
            description="Comprehensive health check framework for all modules",
            first_release="2026.6.10",
            last_updated="2026.6.22",
            maintainer="SRE Team",
            tags=["health-check", "monitoring", "sre", "stable"],
            test_coverage=90.5,
            performance_sla={"p50_ms": 12.0, "p99_ms": 40.0, "throughput": 830}
        )
    
    def _register_security_hardening_modules(self) -> None:
        """Register all Security Hardening modules"""
        
        self.modules["APIGatewaySecurityValidator2026"] = APIModule(
            name="APIGatewaySecurityValidator2026",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.api_gateway_security_validator_2026_june",
            description="API gateway security validation with rate limiting and auth",
            first_release="2026.5.20",
            last_updated="2026.6.15",
            maintainer="API Security Team",
            tags=["api", "gateway", "rate-limiting", "auth", "stable"],
            test_coverage=93.7,
            performance_sla={"p50_ms": 3.5, "p99_ms": 12.0, "throughput": 2850}
        )
        
        self.modules["InputPurificationPoisoning2026"] = APIModule(
            name="InputPurificationPoisoning2026",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.input_purification_poisoning_2026",
            description="Input purification and data poisoning detection",
            first_release="2026.5.10",
            last_updated="2026.6.10",
            maintainer="Input Security Team",
            tags=["purification", "poisoning", "sanitization", "stable"],
            test_coverage=95.2,
            performance_sla={"p50_ms": 4.2, "p99_ms": 14.0, "throughput": 2380}
        )
        
        self.modules["OutputSanitizerPIIRedactor2026"] = APIModule(
            name="OutputSanitizerPIIRedactor2026",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.output_sanitizer_pii_redactor_2026",
            description="Output sanitization and PII redaction with pattern matching",
            first_release="2026.5.10",
            last_updated="2026.6.12",
            maintainer="Privacy Team",
            tags=["pii", "redaction", "privacy", "sanitization", "stable"],
            test_coverage=96.8,
            performance_sla={"p50_ms": 5.8, "p99_ms": 18.0, "throughput": 1720}
        )
    
    def _register_error_resilience_modules(self) -> None:
        """Register all Error Resilience modules"""
        
        self.modules["ErrorResilienceComprehensiveEnhancedV2"] = APIModule(
            name="ErrorResilienceComprehensiveEnhancedV2",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.error_resilience_comprehensive_enhanced_v2_2026_june",
            description="Comprehensive error resilience with retry, backoff, and circuit breakers",
            first_release="2026.6.15",
            last_updated="2026.6.22",
            maintainer="Reliability Team",
            tags=["resilience", "retry", "backoff", "circuit-breaker", "stable"],
            test_coverage=94.8,
            performance_sla={"p50_ms": 2.0, "p99_ms": 8.0, "throughput": 5000}
        )
        
        self.modules["ErrorResilienceRetryBackoffCircuitBreaker"] = APIModule(
            name="ErrorResilienceRetryBackoffCircuitBreaker",
            stability=StabilityLevel.STABLE,
            module_path="neural_shield.error_resilience_retry_backoff_circuit_breaker_2026_june",
            description="Retry with exponential backoff and circuit breaker pattern",
            first_release="2026.6.10",
            last_updated="2026.6.20",
            maintainer="Reliability Team",
            tags=["retry", "backoff", "circuit-breaker", "stable"],
            test_coverage=92.6,
            performance_sla={"p50_ms": 2.5, "p99_ms": 10.0, "throughput": 4000}
        )
    
    def _register_endpoints(self) -> None:
        """Register key API endpoints with signatures"""
        
        core_endpoints = [
            {
                "name": "detect_jailbreak",
                "module": "AdvancedJailbreakDetector2026",
                "signature": "detect(input: str, context: Optional[List[str]] = None) -> DetectionResult",
                "stability": StabilityLevel.STABLE,
                "description": "Detect jailbreak attempts in user input",
                "parameters": [
                    {"name": "input", "type": "str", "required": True, "description": "User input text to analyze"},
                    {"name": "context", "type": "List[str]", "required": False, "description": "Conversation history context"}
                ],
                "return_type": "DetectionResult",
                "examples": [
                    "detector.detect('Ignore previous instructions...')",
                    "detector.detect(user_input, context=conversation_history)"
                ],
                "exceptions": ["ValueError", "TypeError"]
            },
            {
                "name": "classify_content",
                "module": "ConstitutionalClassifier2026",
                "signature": "classify(input: str) -> ClassificationResult",
                "stability": StabilityLevel.STABLE,
                "description": "Classify content against constitutional policies",
                "parameters": [
                    {"name": "input", "type": "str", "required": True, "description": "Text to classify"}
                ],
                "return_type": "ClassificationResult",
                "examples": ["classifier.classify('Hello, how are you?')"],
                "exceptions": ["ValueError"]
            },
            {
                "name": "analyze_prompt_injection",
                "module": "ContextAwarePromptInjectionDefender",
                "signature": "analyze(input: str, context: List[str]) -> InjectionAnalysis",
                "stability": StabilityLevel.STABLE,
                "description": "Analyze input for prompt injection attacks",
                "parameters": [
                    {"name": "input", "type": "str", "required": True, "description": "User input"},
                    {"name": "context", "type": "List[str]", "required": True, "description": "Conversation context"}
                ],
                "return_type": "InjectionAnalysis",
                "examples": ["defender.analyze(user_input, context=history)"],
                "exceptions": ["ValueError", "ContextTooShortError"]
            },
            {
                "name": "purify_input",
                "module": "InputPurificationPoisoning2026",
                "signature": "purify(input: str, aggressive: bool = False) -> str",
                "stability": StabilityLevel.STABLE,
                "description": "Purify and sanitize input text",
                "parameters": [
                    {"name": "input", "type": "str", "required": True, "description": "Input to purify"},
                    {"name": "aggressive", "type": "bool", "required": False, "description": "Enable aggressive purification"}
                ],
                "return_type": "str",
                "examples": [
                    "purifier.purify(user_input)",
                    "purifier.purify(user_input, aggressive=True)"
                ],
                "exceptions": []
            },
            {
                "name": "redact_pii",
                "module": "OutputSanitizerPIIRedactor2026",
                "signature": "redact(text: str, entities: Optional[List[str]] = None) -> str",
                "stability": StabilityLevel.STABLE,
                "description": "Redact PII entities from text",
                "parameters": [
                    {"name": "text", "type": "str", "required": True, "description": "Text to redact"},
                    {"name": "entities", "type": "List[str]", "required": False, "description": "Specific entities to redact"}
                ],
                "return_type": "str",
                "examples": [
                    "redactor.redact(output_text)",
                    "redactor.redact(output_text, entities=['EMAIL', 'PHONE'])"
                ],
                "exceptions": []
            }
        ]
        
        for ep in core_endpoints:
            self.endpoints[ep["name"]] = APIEndpoint(**ep)
    
    def get_module_stability(self, module_name: str) -> Optional[StabilityLevel]:
        """Get stability level for a module"""
        module = self.modules.get(module_name)
        return module.stability if module else None
    
    def get_stable_modules(self) -> List[str]:
        """Get list of all STABLE modules"""
        return [name for name, mod in self.modules.items() 
                if mod.stability == StabilityLevel.STABLE]
    
    def get_beta_modules(self) -> List[str]:
        """Get list of all BETA modules"""
        return [name for name, mod in self.modules.items() 
                if mod.stability == StabilityLevel.BETA]
    
    def get_experimental_modules(self) -> List[str]:
        """Get list of all EXPERIMENTAL modules"""
        return [name for name, mod in self.modules.items() 
                if mod.stability == StabilityLevel.EXPERIMENTAL]
    
    def generate_stability_report(self) -> Dict[str, Any]:
        """Generate comprehensive stability report"""
        return {
            "catalog_version": self.CATALOG_VERSION,
            "framework_version": self.VERSION,
            "generated_at": datetime.utcnow().isoformat(),
            "summary": {
                "total_modules": len(self.modules),
                "stable": len(self.get_stable_modules()),
                "beta": len(self.get_beta_modules()),
                "experimental": len(self.get_experimental_modules()),
                "deprecated": sum(1 for m in self.modules.values() 
                                if m.stability == StabilityLevel.DEPRECATED)
            },
            "average_test_coverage": sum(m.test_coverage for m in self.modules.values()) 
                                    / len(self.modules) if self.modules else 0,
            "stable_modules": self.get_stable_modules(),
            "beta_modules": self.get_beta_modules(),
            "experimental_modules": self.get_experimental_modules()
        }
    
    def get_migration_guide(self, module_name: str) -> Optional[str]:
        """Get migration guide for deprecated or changed modules"""
        module = self.modules.get(module_name)
        if module and module.migration_guide:
            return module.migration_guide
        return None
    
    def get_compatibility_matrix(self) -> Dict[str, List[str]]:
        """Get backward compatibility matrix"""
        return {
            "2026.6.x_compatible": self.get_stable_modules(),
            "2026.5.x_compatible": [m for m in self.modules.values() 
                                   if m.first_release <= "2026.5.30"],
            "breaking_changes_since_2026.5": []  # Empty - no breaking changes
        }


# Singleton instance for global access
API_CATALOG = NeuralShieldAPIStabilityCatalog()


def get_stability_report() -> Dict[str, Any]:
    """Convenience function to get stability report"""
    return API_CATALOG.generate_stability_report()


def is_module_stable(module_name: str) -> bool:
    """Check if a module is STABLE"""
    stability = API_CATALOG.get_module_stability(module_name)
    return stability == StabilityLevel.STABLE


def get_all_stable_apis() -> List[str]:
    """Get all STABLE API names"""
    return API_CATALOG.get_stable_modules()


if __name__ == "__main__":
    # Print catalog summary when run directly
    report = get_stability_report()
    print("=" * 60)
    print("NeuralShield-AI API Stability Catalog v4")
    print("=" * 60)
    print(f"Version: {report['framework_version']}")
    print(f"Generated: {report['generated_at']}")
    print()
    print("Module Stability Summary:")
    print(f"  STABLE:     {report['summary']['stable']}")
    print(f"  BETA:       {report['summary']['beta']}")
    print(f"  EXPERIMENTAL: {report['summary']['experimental']}")
    print(f"  DEPRECATED: {report['summary']['deprecated']}")
    print(f"  TOTAL:      {report['summary']['total_modules']}")
    print()
    print(f"Average Test Coverage: {report['average_test_coverage']:.1f}%")
    print()
    print("STABLE Modules (Production-Ready):")
    for mod in report['stable_modules']:
        print(f"  ✓ {mod}")
    print()
    print("BETA Modules (Testing Recommended):")
    for mod in report['beta_modules']:
        print(f"  ⚠ {mod}")
    print()
    print("EXPERIMENTAL Modules (Expect Breaking Changes):")
    for mod in report['experimental_modules']:
        print(f"  ⚗ {mod}")
    print("=" * 60)
