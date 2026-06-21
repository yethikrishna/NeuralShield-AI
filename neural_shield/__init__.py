"""
NeuralShield-AI - AI Security Defense Framework
June 2026 - Enhanced with Jailbreak Detection, Constitutional Classifiers, Input Purification
+ System Prompt Leakage Detection (June 19, 2026)
+ Model Drift Monitoring and Alerting System (June 20, 2026)
"""

# Model Drift Monitoring and Alerting System (June 20, 2026)
from .model_drift_monitoring_alerting_system_2026_june import (
    ModelDriftMonitor,
    BaselineManager,
    DistributionComparator,
    DriftMetrics,
    Alert,
    create_drift_monitor,
    verify_drift_monitor
)

"""
+ Threat Intelligence Geolocation Tracker (June 20, 2026)
+ Incident Response Automation Engine (June 20, 2026)
"""
from .threat_intelligence_incident_response_automation_engine_2026_june import (
    IncidentResponseAutomationEngine,
    IncidentEvent,
    IncidentType,
    IncidentSeverity,
    MITRETactic,
    MITRETechnique,
    ResponseActionType,
    MITREMapping,
    ResponseAction,
    IncidentResponseResult
)
from .system_prompt_leakage_detector_2026_june import SystemPromptLeakageDetector, LeakageType, LeakageDetectionResult
from .prompt_injection_sandboxed_executor_2026_june import (
    PromptInjectionSandbox,
    SandboxSecurityLevel,
    SandboxLimits,
    ViolationSeverity,
    ViolationType,
    SandboxExecutionResult,
    SecurityViolation
)
from .enhanced_mimetic_detector_2026 import EnhancedMimeticDetector2026
from .threat_intelligence_geolocation_tracker_2026_june import (
    ThreatIntelligenceGeolocationTracker,
    GeolocationCache,
    Coordinates,
    IPVersion,
    ThreatReputation,
    NetworkType,
    GeolocationResult
)
from .constitutional_classifier_2026 import (
    ConstitutionalClassifier2026,
    ConstitutionalInputClassifier,
    ConstitutionalOutputClassifier,
    AgentSecurityGuard2026,
    HarmCategory,
    ClassificationResult
)
from .input_purification_2026 import InputPurifier, AgentSecurityMonitor
from .memory_poisoning_detector_2026 import MemoryPoisoningDetector
from .rag_poisoning_detector_2026 import RAGPoisoningDetector, AdaptiveAttackDefender, MultiModalSecurityGate
from .advanced_jailbreak_detector_2026 import (
    AdvancedJailbreakDetector,
    PromptShield2026,
    AttackType,
    DetectionResult
)

__all__ = [
    "EnhancedMimeticDetector2026",
    "ConstitutionalClassifier2026",
    "ConstitutionalInputClassifier",
    "ConstitutionalOutputClassifier",
    "AgentSecurityGuard2026",
    "HarmCategory",
    "ClassificationResult",
    "InputPurifier",
    "AgentSecurityMonitor",
    "MemoryPoisoningDetector",
    "RAGPoisoningDetector",
    "AdaptiveAttackDefender",
    "MultiModalSecurityGate",
    "AdvancedJailbreakDetector",
    "PromptShield2026",
    "AttackType",
    "DetectionResult",
]

__version__ = "2026.6.17.2"
from .shield_defense_framework_2026 import SHIELDDefenseFramework, ThreatCategory, ThreatAssessment
from .graph_based_jailbreak_detector_2026 import (
    GraphBasedJailbreakDetector,
    RecursiveJailbreakDetector,
    TokenNode,
    GraphEdge
)
from .multi_turn_jailbreak_defender_2026 import (
    MultiTurnJailbreakDetector,
    ConversationDefenseEngine,
    MultiTurnAttackType,
    ConversationContextTracker,
    MultiTurnDetectionResult,
    ConversationTurn
)

__all__.extend([
    "MultiTurnJailbreakDetector",
    "ConversationDefenseEngine",
    "MultiTurnAttackType",
    "ConversationContextTracker",
    "MultiTurnDetectionResult",
    "ConversationTurn",
])

__version__ = "2026.6.17.4"

# VLM Attention Hijacking Defense (HKUST & Shanghai Jiao Tong University 2026)
from .vlm_attention_hijacking_defense_2026 import (
    VLMAttentionHijackDefender,
    AttentionHijackType,
    AttentionHijackAssessment
)
__all__.extend([
    "VLMAttentionHijackDefender",
    "AttentionHijackType",
    "AttentionHijackAssessment"
])

# ProAct Active Defense (Microsoft Research May 2026)
from .proact_active_defense_2026 import (
    ProActActiveDefender,
    DeceptionStrategy,
    DeceptionResult
)
__all__.extend([
    "ProActActiveDefender",
    "DeceptionStrategy",
    "DeceptionResult"
])

__version__ = "2026.6.17.5"
from .realtime_adversarial_detector_2026 import RealTimeAdversarialDetector, AdversarialType, RealTimeAssessment
from .enhanced_constitutional_classifier_2026_june import EnhancedConstitutionalClassifier, HarmCategory, ClassificationResult

# Threat Intelligence Correlation Engine (June 2026 Production Release)
from .threat_intelligence_correlator_2026_june import (
    ThreatIntelligenceCorrelator,
    DetectionSignal,
    CorrelatedThreat,
    AttackPattern,
    CorrelationConfidence
)
__all__.extend([
    "ThreatIntelligenceCorrelator",
    "DetectionSignal",
    "CorrelatedThreat",
    "AttackPattern",
    "CorrelationConfidence"
])

# Adversarial Prompt Robustness Scorer (June 2026 Production Release)
from .adversarial_robustness_scorer_2026_june import (
    AdversarialRobustnessScorer,
    AttackVector,
    RiskLevel,
    RobustnessScore,
    VulnerabilityFinding
)
__all__.extend([
    "AdversarialRobustnessScorer",
    "AttackVector",
    "RiskLevel",
    "RobustnessScore",
    "VulnerabilityFinding"
])

# LLM Output Sanitizer & PII Redactor (June 2026 Production Release)
from .output_sanitizer_pii_redactor_2026 import (
    OutputSanitizer,
    PIIRedactor,
    PIIType,
    HarmCategory,
    RedactionLevel,
    PIIDetection,
    SanitizationResult
)
__all__.extend([
    "OutputSanitizer",
    "PIIRedactor",
    "PIIType",
    "HarmCategory",
    "RedactionLevel",
    "PIIDetection",
    "SanitizationResult"
])
# Semantic Prompt Injection Detector (June 2026 Production Release)
from .semantic_prompt_injection_detector_2026_june import (
    SemanticPromptInjectionDetector,
    InjectionType,
    RiskLevel,
    InjectionFinding,
    InjectionDetectionResult
)
__all__.extend([
    "SemanticPromptInjectionDetector",
    "InjectionType",
    "RiskLevel",
    "InjectionFinding",
    "InjectionDetectionResult"
])
__version__ = "2026.6.17.9"

# Chain-of-Thought Prompt Injection Detector (June 2026 Production Release)
from .cot_prompt_injection_detector_2026_june import (
    ChainOfThoughtInjectionDetector,
    CoTAttackType,
    CoTDetectionResult,
    InjectionFinding
)
__all__.extend([
    "ChainOfThoughtInjectionDetector",
    "CoTAttackType",
    "CoTDetectionResult",
    "InjectionFinding"
])
__version__ = "2026.6.17.11"
# LLM Hallucination Detector (June 2026 Production Release)
from .hallucination_detector_2026_june import (
    HallucinationDetector2026,
    HallucinationType,
    HallucinationFinding,
    HallucinationDetectionResult
)
__all__.extend([
    "HallucinationDetector2026",
    "HallucinationType",
    "HallucinationFinding",
    "HallucinationDetectionResult"
])
__version__ = "2026.6.17.12"
# Model Extraction Attack Detector (June 2026 Production Release)
from .model_extraction_detector_2026_june import (
    ModelExtractionDetector,
    ExtractionAttackType,
    RiskLevel,
    ExtractionFinding,
    ExtractionDetectionResult,
    QueryPatternAnalyzer,
    MembershipInferenceDetector
)
__all__.extend([
    "ModelExtractionDetector",
    "ExtractionAttackType",
    "RiskLevel",
    "ExtractionFinding",
    "ExtractionDetectionResult",
    "QueryPatternAnalyzer",
    "MembershipInferenceDetector"
])
__version__ = "2026.6.17.13"

# Prompt Confusion Matrix Detector (June 2026 Production Release)
from .prompt_confusion_detector_2026_june import (
    PromptConfusionDetector,
    ConfusionAttackType,
    ConfusionRiskLevel,
    ConfusionFinding,
    ConfusionDetectionResult
)
__all__.extend([
    "PromptConfusionDetector",
    "ConfusionAttackType",
    "ConfusionRiskLevel",
    "ConfusionFinding",
    "ConfusionDetectionResult"
])
__version__ = "2026.6.17.15"
# LLM Agent Tool Call Security Validator (June 2026 Production Release)
from .agent_tool_call_validator_2026_june import (
    AgentToolCallValidator,
    ToolCallAttackType,
    ValidationRiskLevel,
    ToolCallFinding,
    ToolCallValidationResult
)
__all__.extend([
    "AgentToolCallValidator",
    "ToolCallAttackType",
    "ValidationRiskLevel",
    "ToolCallFinding",
    "ToolCallValidationResult"
])
__version__ = "2026.6.17.16"
# Multimodal Prompt Injection Detector (June 2026 Production Release)
from .multimodal_prompt_injection_detector_2026_june import (
    MultimodalPromptInjectionDetector,
    MultimodalAttackType,
    MultimodalRiskLevel,
    MultimodalInjectionFinding,
    MultimodalDetectionResult
)
__all__.extend([
    "MultimodalPromptInjectionDetector",
    "MultimodalAttackType",
    "MultimodalRiskLevel",
    "MultimodalInjectionFinding",
    "MultimodalDetectionResult"
])
__version__ = "2026.6.17.18"

# Behavioral Biometrics Anomaly Detector (June 2026 Production Release)
from .behavioral_biometrics_anomaly_detector_2026_june import (
    BehavioralBiometricsAnomalyDetector,
    AnomalyType,
    RiskLevel,
    BehavioralFinding,
    BehavioralDetectionResult,
    InteractionEvent,
    UserBehavioralBaseline,
)
__all__.extend([
    "BehavioralBiometricsAnomalyDetector",
    "AnomalyType",
    "RiskLevel",
    "BehavioralFinding",
    "BehavioralDetectionResult",
    "InteractionEvent",
    "UserBehavioralBaseline",
])
__version__ = "2026.6.17.20"
# Zero-Shot Threat Classifier (June 2026 Production Release)
# Novel attack detection without training data
from .zero_shot_threat_classifier_2026_june import (
    ZeroShotThreatClassifier,
    ThreatCategory,
    ConfidenceLevel,
    ThreatFinding,
    ClassificationResult
)
__all__.extend([
    "ZeroShotThreatClassifier",
    "ThreatCategory",
    "ConfidenceLevel",
    "ThreatFinding",
    "ClassificationResult"
])

# Security Metrics & Analytics Dashboard (June 2026 Production Release)
# Real-time security analytics, scoring, and reporting dashboard
from .security_metrics_analytics_dashboard_2026_june import (
    SecurityLevel,
    MetricType,
    AlertSeverity,
    MetricDataPoint,
    DashboardAlert,
    SecurityScore,
    TrendAnalysis,
    DashboardReport,
    SecurityAnalyticsDashboard,
    create_security_dashboard
)
__all__.extend([
    "SecurityLevel",
    "MetricType",
    "AlertSeverity",
    "MetricDataPoint",
    "DashboardAlert",
    "SecurityScore",
    "TrendAnalysis",
    "DashboardReport",
    "SecurityAnalyticsDashboard",
    "create_security_dashboard"
])
__version__ = "2026.6.17.26"
# Prompt Firewall 2026 (June 2026 Production Release)
# Multi-layer AI security protection against prompt injection
from .prompt_firewall_2026_june import (
    PromptFirewall2026,
    FirewallThreatLevel,
    AttackVector,
    FirewallFinding,
    FirewallResult
)
__all__.extend([
    "PromptFirewall2026",
    "FirewallThreatLevel",
    "AttackVector",
    "FirewallFinding",
    "FirewallResult"
])
# LLM Backdoor Attack Detector (June 2026 Production Release)
# Detects trojan triggers, character injection, and dataset poisoning
from .llm_backdoor_detector_2026_june import (
    LLMBackdoorDetector2026,
    BackdoorType,
    BackdoorRiskLevel,
    BackdoorFinding,
    BackdoorDetectionResult
)
__all__.extend([
    "LLMBackdoorDetector2026",
    "BackdoorType",
    "BackdoorRiskLevel",
    "BackdoorFinding",
    "BackdoorDetectionResult"
])
__version__ = "2026.6.17.28"
# Threat Response Orchestrator (June 2026 Production Release)
# Automated response coordination across all security detectors
from .threat_response_orchestrator_2026_june import (
    ThreatResponseOrchestrator,
    ResponsePolicy,
    ThreatSeverity,
    ResponseAction,
    ThreatIncident,
    ResponseResult
)
__all__.extend([
    "ThreatResponseOrchestrator",
    "ResponsePolicy",
    "ThreatSeverity",
    "ResponseAction",
    "ThreatIncident",
    "ResponseResult"
])
__version__ = "2026.6.17.29"

# Context Window Protector (June 2026 Production Release)
# Protects system prompt boundaries and context window from injection attacks
from .context_window_protector_2026_june import (
    ContextWindowProtector,
    BoundaryAttackType,
    ProtectionLevel,
    BoundaryFingerprint,
    BoundaryViolation,
    ProtectionResult
)
__all__.extend([
    "ContextWindowProtector",
    "BoundaryAttackType",
    "ProtectionLevel",
    "BoundaryFingerprint",
    "BoundaryViolation",
    "ProtectionResult"
])
__version__ = "2026.6.17.30"
# Threat Intelligence Feed Aggregator (June 2026 Production Release)
# Multi-source threat feed aggregation, signature caching, and real-time scoring
from .threat_intelligence_feed_aggregator_2026_june import (
    ThreatIntelligenceAggregator,
    ThreatFeedCache,
    ThreatSignature,
    ThreatMatch,
    AggregationResult,
    ThreatSource,
    ThreatSeverity,
    ThreatCategory,
    create_threat_intelligence_aggregator
)
__all__.extend([
    "ThreatIntelligenceAggregator",
    "ThreatFeedCache",
    "ThreatSignature",
    "ThreatMatch",
    "AggregationResult",
    "ThreatSource",
    "ThreatSeverity",
    "ThreatCategory",
    "create_threat_intelligence_aggregator"
])
__version__ = "2026.6.18.1"
# MITRE ATT&CK Threat Mapper (June 18, 2026 Production Release)
# Maps threats to MITRE ATT&CK framework tactics, techniques, and mitigations
from .threat_intelligence_mitre_attack_mapper_2026_june import (
    ThreatIntelligenceMITREAttackMapper,
    MITRETactic,
    MITRETechnique,
    MITREMapping,
    Mitigation,
    ThreatMappingResult,
    create_mitre_attack_mapper
)
__all__.extend([
    "ThreatIntelligenceMITREAttackMapper",
    "MITRETactic",
    "MITRETechnique",
    "MITREMapping",
    "Mitigation",
    "ThreatMappingResult",
    "create_mitre_attack_mapper",
])
__version__ = "2026.6.18.2"
# Adversarial Prompt Fuzzer (June 2026 Production Release)
# Real fuzz testing framework for adversarial prompt robustness evaluation
from .adversarial_prompt_fuzzer_2026_june import (
    AdversarialPromptFuzzer,
    FuzzerAttackType,
    FuzzSeverity,
    MutationStrategy,
    FuzzTestCase,
    FuzzResult,
    FuzzReport,
    create_adversarial_fuzzer
)
__all__.extend([
    "AdversarialPromptFuzzer",
    "FuzzerAttackType",
    "FuzzSeverity",
    "MutationStrategy",
    "FuzzTestCase",
    "FuzzResult",
    "FuzzReport",
    "create_adversarial_fuzzer"
])
__version__ = "2026.6.17.32"
# LLM Backdoor Watermark Detector (June 2026 Production Release)
# Detects hidden watermarks, backdoor triggers, and steganographic data
from .llm_backdoor_watermark_detector_2026_june import (
    LLMBackdoorWatermarkDetector,
    WatermarkType,
    WatermarkConfidence,
    WatermarkFinding,
    WatermarkDetectionResult,
    create_watermark_detector
)
__all__.extend([
    "LLMBackdoorWatermarkDetector",
    "WatermarkType",
    "WatermarkConfidence",
    "WatermarkFinding",
    "WatermarkDetectionResult",
    "create_watermark_detector"
])
__version__ = "2026.6.17.34"
# System Prompt Watermarking & Leakage Detector (June 2026 Production Release)
# Invisible watermark embedding and system prompt leakage detection
from .system_prompt_watermark_leakage_detector_2026_june import (
    SystemPromptWatermarker,
    SystemPromptLeakageDetector,
    WatermarkStrategy,
    LeakageType,
    VerificationStatus,
    WatermarkInfo,
    LeakageFinding,
    WatermarkDetectionResult,
    create_watermark_protection
)
__all__.extend([
    "SystemPromptWatermarker",
    "SystemPromptLeakageDetector",
    "WatermarkStrategy",
    "LeakageType",
    "VerificationStatus",
    "WatermarkInfo",
    "LeakageFinding",
    "WatermarkDetectionResult",
    "create_watermark_protection"
])
__version__ = "2026.6.17.35"

# RAG Context Integrity Verifier (June 2026 Production Release)
# Cryptographic integrity verification for RAG context chains
from .rag_context_integrity_verifier_2026_june import (
    RAGContextIntegrityVerifier,
    ContextChunk,
    IntegrityStatus,
    TamperType,
    IntegrityFinding,
    IntegrityVerificationResult,
    create_integrity_verifier
)
__all__.extend([
    "RAGContextIntegrityVerifier",
    "ContextChunk",
    "IntegrityStatus",
    "TamperType",
    "IntegrityFinding",
    "IntegrityVerificationResult",
    "create_integrity_verifier"
])
__version__ = "2026.6.17.36"
# RAG Context Integrity Verifier (June 17, 2026 Production Release)
# Cryptographic integrity verification for RAG context chunks
from .rag_context_integrity_verifier_2026_june import (
    RAGContextIntegrityVerifier,
    ContextChunk,
    IntegrityStatus,
    TamperType,
    IntegrityFinding,
    IntegrityVerificationResult,
    create_integrity_verifier
)
__all__.extend([
    "RAGContextIntegrityVerifier",
    "ContextChunk",
    "IntegrityStatus",
    "TamperType",
    "IntegrityFinding",
    "IntegrityVerificationResult",
    "create_integrity_verifier"
])
__version__ = "2026.6.17.36"
# Agent Memory Safety Monitor (June 17, 2026 Production Release)
# Real-time agent memory access monitoring, boundary protection, and poisoning detection
from .agent_memory_safety_monitor_2026_june import (
    AgentMemorySafetyMonitor,
    MemoryAccessType,
    MemoryRiskLevel,
    MemoryAttackType,
    MemoryAccessEvent,
    MemoryFinding,
    MemorySafetyResult,
    MemoryRegion,
    create_memory_safety_monitor
)
__all__.extend([
    "AgentMemorySafetyMonitor",
    "MemoryAccessType",
    "MemoryRiskLevel",
    "MemoryAttackType",
    "MemoryAccessEvent",
    "MemoryFinding",
    "MemorySafetyResult",
    "MemoryRegion",
    "create_memory_safety_monitor"
])
# Conversation History Poisoning Detector (June 18, 2026 Production Release)
# Multi-turn conversation poisoning detection with gradual attack recognition
from .conversation_history_poisoning_detector_2026_june import (
    ConversationHistoryPoisoningDetector,
    ConversationTurn,
    PoisoningAttackType,
    PoisoningIndicator,
    PoisoningDetectionResult,
    SeverityLevel
)
__all__.extend([
    "ConversationHistoryPoisoningDetector",
    "ConversationTurn",
    "PoisoningAttackType",
    "PoisoningIndicator",
    "PoisoningDetectionResult",
    "SeverityLevel"
])
__version__ = "2026.6.18.3"
# Threat Intelligence Signature Version Control & Rollback Manager (June 18, 2026 Production Release)
# Semantic versioning, atomic rollback, deployment validation, and integrity verification
from .threat_intelligence_signature_version_control_2026_june import (
    ThreatIntelSignatureVersionControl,
    SignatureType,
    DeploymentStatus,
    SignatureVersion,
    RollbackResult,
    VersionDiff
)
__all__.extend([
    "ThreatIntelSignatureVersionControl",
    "SignatureType",
    "DeploymentStatus",
    "SignatureVersion",
    "RollbackResult",
    "VersionDiff"
])
__version__ = "2026.6.18.7"
# Threat Intelligence Batch Processor (June 18, 2026 Production Release)
# Batch IOC processing, deduplication, enrichment, and parallel processing
from .threat_intelligence_batch_processor_2026_june import (
    BatchStatus,
    IOCType,
    BatchResult,
    BatchJob,
    ThreatIntelligenceBatchProcessor
)
__all__.extend([
    "BatchStatus",
    "IOCType",
    "BatchResult",
    "BatchJob",
    "ThreatIntelligenceBatchProcessor"
])
__version__ = "2026.6.18.3"
# Threat Intelligence Threat Actor Profiler (June 18, 2026 Production Release)
# Comprehensive threat actor profiling, TTP matching, and MITRE ATT&CK mapping
from .threat_intelligence_threat_actor_profiler_2026_june import (
    ThreatActorProfiler,
    ThreatActorType,
    ThreatActorSophistication,
    ThreatMotivation,
    ThreatActorProfile,
    AttributionResult,
)
__all__.extend([
    "ThreatActorProfiler",
    "ThreatActorType",
    "ThreatActorSophistication",
    "ThreatMotivation",
    "ThreatActorProfile",
    "AttributionResult",
])
__version__ = "2026.6.18.3"
from .security_rate_limiter_circuit_breaker_2026_june import SecurityRateLimiter, RateLimitResult, CircuitState
# API Gateway Security Validator (June 17, 2026 Production Release)
# Production-grade API security middleware for LLM endpoint protection
from .api_gateway_security_validator_2026_june import (
    APIGatewaySecurityValidator,
    APIAttackType,
    SecurityRiskLevel,
    SecurityFinding,
    APIValidationResult,
    ValidatedRequest,
    create_api_security_validator
)
__all__.extend([
    "APIGatewaySecurityValidator",
    "APIAttackType",
    "SecurityRiskLevel",
    "SecurityFinding",
    "APIValidationResult",


])
__version__ = "2026.6.17.45"

# Security Policy Compliance Auditor (June 17, 2026 Production Release)
# Real security policy enforcement, compliance scoring, and violation auditing
from .security_policy_compliance_auditor_2026_june import (
    SecurityPolicyComplianceAuditor,
    PolicySeverity,
    PolicyCategory,
    PolicyViolation,
    ComplianceResult,
    SecurityPolicy
)
__all__.extend([
    "SecurityPolicyComplianceAuditor",
    "PolicySeverity",
    "PolicyCategory",
    "PolicyViolation",
    "ComplianceResult",
    "SecurityPolicy"
])





# Security Audit Logging & Forensics Engine (June 17, 2026 Production Release)
# Tamper-evident hash-chained audit logging with cryptographic integrity
from .security_audit_forensics_engine_2026_june import (
    SecurityAuditForensicsEngine,
    AuditEventType,
    AuditSeverity,
    IntegrityStatus,
    AuditEvent,
    ForensicsQuery,
    IntegrityReport,
    AuditLogSummary,
    create_audit_engine
)
from .threat_intelligence_auto_updater_2026_june import (
    ThreatIntelligenceAutoUpdater,
    UpdateStatus,
    ThreatSignature,
    CacheEntry,
)
__all__.extend([
    "ThreatIntelligenceAutoUpdater",
    "UpdateStatus",
    "ThreatSignature",
    "CacheEntry",
])
__version__ = "2026.6.17.40"
# Threat Context Enricher (June 17, 2026 Production Release)
# Real-time threat context enrichment with IP reputation, geolocation, and threat intelligence
from .threat_context_enricher_2026_june import (
    ThreatContextEnricher,
    ThreatSeverity,
    ThreatCategory,
    EnrichedContext
)
__all__.extend([
    "ThreatContextEnricher",
    "ThreatSeverity",
    "ThreatCategory",
    "EnrichedContext"
])
__version__ = "2026.6.17.41"

# Threat Intelligence OSINT Enricher (June 17, 2026 Production Release)
# Open Source Intelligence context enrichment with IP/domain reputation, geolocation, WHOIS, and threat actor attribution
from .threat_intelligence_osint_enricher_2026_june import (
    ThreatIntelligenceOSINTEnricher,
    OSINTEnrichmentResult,
    IOCType,
    ThreatActorType,
)
__all__.extend([
    "ThreatIntelligenceOSINTEnricher",
    "OSINTEnrichmentResult",
    "IOCType",
    "ThreatActorType",
])
__version__ = "2026.6.17.42"

# Prompt Embedding Anomaly Detector (June 17, 2026 Production Release)
# Real character n-gram embedding with cosine similarity for anomaly detection
from .prompt_embedding_anomaly_detector_2026_june import (
    PromptEmbeddingAnomalyDetector,
    AnomalyType,
    AnomalySeverity,
    AnomalyFinding,
    EmbeddingAnomalyResult,
    create_embedding_anomaly_detector
)
__all__.extend([
    "PromptEmbeddingAnomalyDetector",
    "AnomalyType",
    "AnomalySeverity",
    "AnomalyFinding",
    "EmbeddingAnomalyResult",
    "create_embedding_anomaly_detector"
])
__version__ = "2026.6.17.46"

# Threat Intelligence Cache with TTL (June 17, 2026 Production Release)
# Production-grade thread-safe TTL caching for threat intelligence lookups
from .threat_intelligence_cache_2026_june import (
    ThreatIntelligenceCache,
    CacheEntryStatus,
    CacheEntry
)
__all__.extend([
    "ThreatIntelligenceCache",
    "CacheEntryStatus",
    "CacheEntry"
])
__version__ = "2026.6.17.47"
# Threat Intelligence Orchestrator with Adaptive Learning (June 18, 2026 Production Release)
# Multi-source threat aggregation, Bayesian confidence scoring, adaptive ML pattern learning
from .threat_intelligence_orchestrator_adaptive_2026_june import (
    ThreatIntelligenceOrchestrator,
    ThreatSeverity,
    ThreatCategory,
    IOC,
    ThreatMatch,
    OrchestratorResult,
    BayesianConfidenceEngine,
    AdaptivePatternLearner
)
__all__.extend([
    "ThreatIntelligenceOrchestrator",
    "ThreatSeverity",
    "ThreatCategory",
    "IOC",
    "ThreatMatch",
    "OrchestratorResult",
    "BayesianConfidenceEngine",
    "AdaptivePatternLearner"
])
# Threat Intelligence Automated Feeder (June 18, 2026 Production Release)
# Multi-source automated threat intelligence ingestion, normalization, deduplication, and health monitoring
from .threat_intelligence_automated_feeder_2026_june import (
    ThreatIntelligenceAutomatedFeeder,
    FeedSource,
    FeedStatus,
    FeedConfiguration,
    RawThreatIndicator,
    FeedHealthMetrics
)
__all__.extend([
    "ThreatIntelligenceAutomatedFeeder",
    "FeedSource",
    "FeedStatus",
    "FeedConfiguration",
    "RawThreatIndicator",
    "FeedHealthMetrics"
])
__version__ = "2026.6.18.2"

__version__ = "2026.6.18.1"
# Real-Time Prompt Sanitization Engine (June 18, 2026 Production Release)
# Multi-layer input sanitization: XSS, SQL injection, command injection, prompt injection, homoglyph defense
from .realtime_prompt_sanitization_engine_2026_june import (
    PromptSanitizationEngine,
    InjectionType,
    SanitizationLevel,
    InjectionFinding,
    SanitizationResult,
    HomoglyphDefender,
    create_prompt_sanitizer
)
from .threat_intelligence_auto_learning_classifier_2026_june import (
    ThreatIntelligenceAutoLearningClassifier,
    ThreatCategory,
    LearningOutcome
)
__all__.extend([
    "PromptSanitizationEngine",
    "InjectionType",
    "SanitizationLevel",
    "InjectionFinding",
    "SanitizationResult",
    "HomoglyphDefender",
    "create_prompt_sanitizer",
    "ThreatIntelligenceAutoLearningClassifier",
    "ThreatCategory",
    "LearningOutcome"
])

from .llm_output_toxicity_bias_detector_2026_june import (
    LLMOutputSafetyAnalyzer,
    HarmCategory,
    SeverityLevel,
    HarmFinding,
    ContentSafetyResult,
    ToxicityDetector,
    BiasDetector,
    HarmfulContentDetector,
    create_safety_analyzer
)
__all__.extend([
    "LLMOutputSafetyAnalyzer",
    "HarmCategory",
    "SeverityLevel",
    "HarmFinding",
    "ContentSafetyResult",
    "ToxicityDetector",
    "BiasDetector",
    "HarmfulContentDetector",
    "create_safety_analyzer"
])

# Threat Intelligence Vector Similarity Search (June 18, 2026 Production Release)
# TF-IDF vector similarity search for threat pattern matching
from .threat_intelligence_vector_similarity_search_2026_june import (
    ThreatVectorSimilarityEngine,
    SimilarityMethod,
    ThreatSeverity,
    ThreatCategory,
    ThreatSignature,
    SimilarityMatch,
    SimilaritySearchResult,
    TFIDFVectorizer,
    SimilarityCalculator,
    ThreatSignatureDatabase,
    create_threat_similarity_engine
)
__all__.extend([
    "ThreatVectorSimilarityEngine",
    "SimilarityMethod",
    "ThreatSeverity",
    "ThreatCategory",
    "ThreatSignature",
    "SimilarityMatch",
    "SimilaritySearchResult",
    "TFIDFVectorizer",
    "SimilarityCalculator",
    "ThreatSignatureDatabase",
    "create_threat_similarity_engine"
])

# Context-Aware Prompt Injection Defender (June 18, 2026 Production Release)
# Multi-layered prompt injection detection with context awareness
from .context_aware_prompt_injection_defender_2026_june import (
    ContextAwarePromptInjectionDefender,
    InjectionType,
    RiskLevel,
    InjectionFinding,
    ConversationTurn,
    InjectionDetectionResult,
    PatternBasedDetector,
    ObfuscationDetector,
    ContextIntegrityMonitor
)
__all__.extend([
    "ContextAwarePromptInjectionDefender",
    "InjectionType",
    "RiskLevel",
    "InjectionFinding",
    "ConversationTurn",
    "InjectionDetectionResult",
    "PatternBasedDetector",
    "ObfuscationDetector",
    "ContextIntegrityMonitor"
])

# Prompt Injection Evasion Detector - June 18 2026
from .prompt_injection_evasion_detector_2026_june import (
    PromptInjectionEvasionDetector,
    EvasionType,
    EvasionDetectionResult
)
__all__.extend([
    "PromptInjectionEvasionDetector",
    "EvasionType",
    "EvasionDetectionResult"
])
# Threat Intelligence Auto-Blacklisting Engine (June 18, 2026)
# Automated threat blacklisting with confidence-based auto-flagging
from .threat_intelligence_auto_blacklist_engine_2026_june import (
    ThreatIntelligenceAutoBlacklistEngine,
    BlacklistSeverity,
    BlacklistSource,
    BlacklistEntry,
    BlacklistStats
)
__all__.extend([
    "ThreatIntelligenceAutoBlacklistEngine",
    "BlacklistSeverity",
    "BlacklistSource",
    "BlacklistEntry",
    "BlacklistStats"
])
__version__ = "2026.6.18.1"
__version__ = "2026.6.18.2"

# Threat Intelligence Auto-Tagging & MITRE ATT&CK Mapper (June 18, 2026)
# Automated threat classification, tagging, and MITRE ATT&CK framework mapping
from .threat_intelligence_auto_tagger_mitre_2026_june import (
    ThreatIntelligenceAutoTagger,
    ThreatTag,
    MITREAttackTactic,
    MITREAttackTechnique,
    AutoTagConfidence,
    MITREMapping,
    AutoTagResult,
    TaggingRule,
    create_threat_tagger
)
__all__.extend([
    "ThreatIntelligenceAutoTagger",
    "ThreatTag",
    "MITREAttackTactic",
    "MITREAttackTechnique",
    "AutoTagConfidence",
    "MITREMapping",
    "AutoTagResult",
    "TaggingRule",
    "create_threat_tagger"
])
__version__ = "2026.6.18.3"

# VLM Visual Prompt Injection Detector (June 18, 2026 Production Release)
# Detects hidden prompt injections in visual inputs: steganography, QR codes, micro-text, metadata
from .vlm_visual_prompt_injection_detector_2026_june import (
    VLMVisualPromptInjectionDetector,
    VisualInjectionType,
    DetectionConfidence,
    VisualInjectionFinding,
    VisualDetectionResult,
    create_visual_injection_detector
)
__all__.extend([
    "VLMVisualPromptInjectionDetector",
    "VisualInjectionType",
    "DetectionConfidence",
    "VisualInjectionFinding",
    "VisualDetectionResult",
    "create_visual_injection_detector"
])
__version__ = "2026.6.18.4"
# Output Integrity Watermarker & Provenance Tracker (June 18, 2026 Production Release)
# Cryptographic watermarking, tamper detection, and provenance tracking for LLM outputs
from .output_integrity_watermarker_provenance_2026_june import (
    OutputIntegrityWatermarker,
    WatermarkType,
    TamperVerdict,
    WatermarkMetadata,
    WatermarkResult,
    VerificationResult
)
__all__.extend([
    "OutputIntegrityWatermarker",
    "WatermarkType",
    "TamperVerdict",
    "WatermarkMetadata",
    "WatermarkResult",
    "VerificationResult"
])
# Threat Intelligence Geolocation Enricher (June 18, 2026 Production Release)
# IP geolocation enrichment, geographic risk assessment, and threat intelligence mapping
from .threat_intelligence_geolocation_enricher_2026_june import (
    ThreatIntelligenceGeolocationEnricher,
    GeolocationData,
    EnrichmentResult,
    GeographicRiskLevel,
    IPVersion
)
__all__.extend([
    "ThreatIntelligenceGeolocationEnricher",
    "GeolocationData",
    "EnrichmentResult",
    "GeographicRiskLevel",
    "IPVersion"
])
# Threat Intelligence Whitelist Validator (June 18, 2026 Production Release)
# IP, domain, and URL whitelist validation with CIDR support, caching, and confidence scoring
from .threat_intelligence_whitelist_validator_2026_june import (
    ThreatIntelligenceWhitelistValidator,
    WhitelistType,
    ValidationResult,
    WhitelistEntry,
    ValidationReport
)
__all__.extend([
    "ThreatIntelligenceWhitelistValidator",
    "WhitelistType",
    "ValidationResult",
    "WhitelistEntry",
    "ValidationReport"
])
__version__ = "2026.6.18.5"
__version__ = "2026.6.18.4"

# Threat Intelligence Reputation Scorer (June 18, 2026 Production Release)
# Multi-factor reputation scoring for IPs, domains, and URLs with caching and confidence calibration
from .threat_intelligence_reputation_scorer_2026_june import (
    ThreatIntelligenceReputationScorer,
    ReputationCategory,
    EntityType,
    ReputationFactors,
    ReputationScore
)
__all__.extend([
    "ThreatIntelligenceReputationScorer",
    "ReputationCategory",
    "EntityType",
    "ReputationFactors",
    "ReputationScore"
])
__version__ = "2026.6.18.6"

# Ensemble Threat Detector with Weighted Voting (June 18, 2026 Production Release)
# Multi-detector ensemble with dynamic weight adjustment and confidence calibration
from .ensemble_threat_detector_weighted_voting_2026_june import (
    DetectorType,
    ThreatSeverity,
    DetectorResult,
    EnsembleDecision,
    DetectorPerformance,
    BaseThreatDetector,
    PatternMatchingDetector,
    EntropyAnomalyDetector,
    KeywordFrequencyDetector,
    ConstitutionalHeuristicDetector,
    EnsembleThreatDetector,
    create_ensemble_threat_detector,
)
__all__.extend([
    "DetectorType",
    "ThreatSeverity",
    "DetectorResult",
    "EnsembleDecision",
    "DetectorPerformance",
    "BaseThreatDetector",
    "PatternMatchingDetector",
    "EntropyAnomalyDetector",
    "KeywordFrequencyDetector",
    "ConstitutionalHeuristicDetector",
    "EnsembleThreatDetector",
    "create_ensemble_threat_detector",
])
__version__ = "2026.6.18.7"

# Threat Intelligence MITRE ATT&CK Executive Report Generator (June 18, 2026 Production Release)
# Executive-level security reporting with risk scoring, compliance assessment, and mitigation roadmap
from .threat_intelligence_mitre_executive_reporter_2026_june import (
    ThreatIntelligenceMITREExecutiveReporter,
    ReportSeverity,
    MITRETactic,
    ComplianceFramework,
    MITRETechniqueFinding,
    ExecutiveSummary,
    RiskTrend,
    ComplianceGap,
    ExecutiveReportResult,
    create_mitre_executive_reporter
)
__all__.extend([
    "ThreatIntelligenceMITREExecutiveReporter",
    "ReportSeverity",
    "MITRETactic",
    "ComplianceFramework",
    "MITRETechniqueFinding",
    "ExecutiveSummary",
    "RiskTrend",
    "ComplianceGap",
    "ExecutiveReportResult",
    "create_mitre_executive_reporter"
])
__version__ = "2026.6.18.7"

# MITRE ATT&CK Executive Dashboard Reporter (June 18, 2026 Production Release)
# Executive-level cybersecurity reporting, risk scoring, and C-suite dashboard
from .threat_intelligence_mitre_executive_dashboard_2026_june import (
    MITREExecutiveDashboardReporter,
    RiskLevel,
    MITRETactic,
    ThreatEvent,
    ExecutiveSummary,
    create_executive_dashboard
)
__all__.extend([
    "MITREExecutiveDashboardReporter",
    "RiskLevel",
    "MITRETactic",
    "ThreatEvent",
    "ExecutiveSummary",
    "create_executive_dashboard"
])
__version__ = "2026.6.18.8"
# Threat Intelligence Webhook Alert Dispatcher (June 18, 2026 Production Release)
# Multi-platform security alert dispatcher with Slack, Teams, Discord support
from .threat_intelligence_webhook_alert_dispatcher_2026_june import (
    ThreatIntelligenceWebhookAlertDispatcher,
    WebhookPlatform,
    AlertSeverity,
    AlertStatus,
    AuthenticationType,
    WebhookEndpoint,
    SecurityAlert,
    AlertDeliveryRecord,
    CircuitBreaker,
    RateLimiter,
    create_webhook_dispatcher
)
__all__.extend([
    "ThreatIntelligenceWebhookAlertDispatcher",
    "WebhookPlatform",
    "AlertSeverity",
    "AlertStatus",
    "AuthenticationType",
    "WebhookEndpoint",
    "SecurityAlert",
    "AlertDeliveryRecord",
    "CircuitBreaker",
    "RateLimiter",
    "create_webhook_dispatcher"
])
__version__ = "2026.6.18.4"


# Threat Intelligence Automated Response Orchestrator (June 18, 2026 Production Release)
# Automated security incident response, playbook execution, and mitigation workflow
from .threat_intelligence_automated_response_orchestrator_2026_june import (
    AutomatedResponseOrchestrator,
    IncidentSeverity,
    ResponseStatus,
    ResponseActionType,
    PlaybookTrigger,
    ThreatIndicator,
    ResponseAction,
    SecurityIncident,
    ResponsePlaybook,
    create_response_orchestrator
)
__all__.extend([
    "AutomatedResponseOrchestrator",
    "IncidentSeverity",
    "ResponseStatus",
    "ResponseActionType",
    "PlaybookTrigger",
    "ThreatIndicator",
    "ResponseAction",
    "SecurityIncident",
    "ResponsePlaybook",
    "create_response_orchestrator"
])
__version__ = "2026.6.18.5"
# Threat Intelligence Incident Triage & Escalation Engine (June 18, 2026 Production Release)
# Automated incident triage, severity scoring, SLA compliance, and escalation management
from .threat_intelligence_incident_triage_escalation_2026_june import (
    IncidentSeverity,
    IncidentStatus,
    IncidentCategory,
    ResponseTeam,
    ThreatIndicator,
    EscalationEvent,
    SLACompliance,
    Incident,
    TriageResult,
    SeverityScoringEngine,
    IncidentTriageEngine,
    IncidentEscalationManager,
    IncidentTriageEscalationEngine,
    create_incident_triage_engine
)
__all__.extend([
    "IncidentSeverity",
    "IncidentStatus",
    "IncidentCategory",
    "ResponseTeam",
    "ThreatIndicator",
    "EscalationEvent",
    "SLACompliance",
    "Incident",
    "TriageResult",
    "SeverityScoringEngine",
    "IncidentTriageEngine",
    "IncidentEscalationManager",
    "IncidentTriageEscalationEngine",
    "create_incident_triage_engine"
])
from .threat_intelligence_incident_playbook_executor_2026_june import (
    IncidentPlaybookExecutor,
    IncidentContext,
    PlaybookExecution,
    PlaybookStep,
    PlaybookLibrary,
    PlaybookStatus,
    StepStatus,
    SeverityLevel,
    IncidentType
)
__all__.extend([
    "IncidentPlaybookExecutor",
    "IncidentContext",
    "PlaybookExecution",
    "PlaybookStep",
    "PlaybookLibrary",
    "PlaybookStatus",
    "StepStatus",
    "SeverityLevel",
    "IncidentType"
])
__version__ = "2026.6.18.4"
# Threat Intelligence Historical Anomaly Detector (June 18, 2026 Production Release)
# Real-time historical baseline tracking, Z-score & IQR outlier detection, multi-dimensional anomaly scoring
from .threat_intelligence_historical_anomaly_detector_2026_june import (
    HistoricalAnomalyDetector,
    BaselineWindow,
    AnomalyType,
    AnomalySeverity,
    AnomalyDetectionResult
)
__all__.extend([
    "HistoricalAnomalyDetector",
    "BaselineWindow",
    "AnomalyType",
    "AnomalySeverity",
    "AnomalyDetectionResult"
])
__version__ = "2026.6.18.5"


# Threat Intelligence Historical Baseline Analyzer (June 18, 2026 Production Release)
# Statistical baseline establishment, real-time anomaly detection, baseline drift monitoring
from .threat_intelligence_historical_baseline_analyzer_2026_june import (
    ThreatIntelligenceHistoricalBaselineAnalyzer,
    BaselineMetrics,
    AnomalyResult
)
__all__.extend([
    "ThreatIntelligenceHistoricalBaselineAnalyzer",
    "BaselineMetrics",
    "AnomalyResult"
])

# Threat Intelligence False Positive Reducer (June 18, 2026 Production Release)
# Statistical false positive reduction, historical pattern matching, multi-detector consensus
from .threat_intelligence_false_positive_reducer_2026_june import (
    ThreatIntelligenceFalsePositiveReducer,
    ReductionResult,
    FalsePositiveCategory,
    HistoricalFalsePositive
)
__all__.extend([
    "ThreatIntelligenceFalsePositiveReducer",
    "ReductionResult",
    "FalsePositiveCategory",
    "HistoricalFalsePositive"
])

# Threat Intelligence IOC Normalizer (June 18, 2026 Production Release)
# IOC normalization, validation, defanging/refanging, type detection, batch processing
from .threat_intelligence_ioc_normalizer_2026_june import (
    ThreatIntelligenceIOCNormalizer,
    NormalizedIOC,
    NormalizationStats,
    IOType,
    DefangMethod
)
__all__.extend([
    "ThreatIntelligenceIOCNormalizer",
    "NormalizedIOC",
    "NormalizationStats",
    "IOType",
    "DefangMethod"
])

# Threat Intelligence MITRE Heatmap Generator (June 18, 2026 Production Release)
# MITRE ATT&CK heatmap generation, risk scoring, color coding, dashboard export
from .threat_intelligence_mitre_heatmap_generator_2026_june import (
    MITREHeatmapGenerator,
    HeatmapGenerationResult,
    HeatmapCell,
    HeatmapColor,
    MITRETactic
)
__all__.extend([
    "MITREHeatmapGenerator",
    "HeatmapGenerationResult",
    "HeatmapCell",
    "HeatmapColor",
    "MITRETactic"
])

# Threat Intelligence Temporal Pattern Analyzer (June 18, 2026 Production Release)
# Time-based pattern detection, anomaly spikes, periodic patterns, emerging trends, burst detection
from .threat_intelligence_temporal_pattern_analyzer_2026_june import (
    TemporalPatternAnalyzer,
    TemporalEvent,
    DetectedPattern,
    AnomalyResult,
    PatternType,
    ThreatSeverity
)
__all__.extend([
    "TemporalPatternAnalyzer",
    "TemporalEvent",
    "DetectedPattern",
    "AnomalyResult",
    "PatternType",
    "ThreatSeverity"
])

# Threat Intelligence Anomaly Sequence Detector (June 18, 2026 Production Release)
# Sequence anomaly detection, sliding window analysis, Markov chain transitions, pattern rarity
from .threat_intelligence_anomaly_sequence_detector_2026_june import (
    ThreatIntelligenceAnomalySequenceDetector
)
__all__.extend([
    "ThreatIntelligenceAnomalySequenceDetector"
])

# Threat Intelligence Predictive Forecaster (June 18, 2026 Production Release)
# Time-series forecasting, exponential smoothing, anomaly prediction, risk forecasting
from .threat_intelligence_predictive_forecaster_2026_june import (
    ThreatIntelligencePredictiveForecaster,
    ThreatDataPoint,
    ForecastResult,
    ExponentialSmoothing,
    MovingAverageForecaster
)
__all__.extend([
    "ThreatIntelligencePredictiveForecaster",
    "ThreatDataPoint",
    "ForecastResult",
    "ExponentialSmoothing",
    "MovingAverageForecaster"
])

# Threat Intelligence CVE Lookup Scanner (June 18, 2026 Production Release)
# CVE extraction, format validation, CVSS severity scoring, vulnerability assessment, caching
from .threat_intelligence_cve_lookup_scanner_2026_june import (
    ThreatIntelligenceCVELookupScanner,
    CVSSSeverity,
    CVEMatch,
    VulnerabilityAssessment
)
__all__.extend([
    "ThreatIntelligenceCVELookupScanner",
    "CVSSSeverity",
    "CVEMatch",
    "VulnerabilityAssessment"
])

__version__ = "2026.6.18.12"

# Threat Intelligence IOC Hash Validator (June 18, 2026 Production Release)
# Hash format validation, type auto-detection, whitelist/blacklist, duplicate detection, enrichment
from .threat_intelligence_ioc_hash_validator_2026_june import (
    IOCHashValidator,
    HashType,
    HashValidationStatus,
    HashValidationResult
)
__all__.extend([
    "IOCHashValidator",
    "HashType",
    "HashValidationStatus",
    "HashValidationResult"
])

# Prompt Obfuscation Decoder & Detector (June 18, 2026 Production Release)
# Base64/Hex/ROT13/URL encoding detection, nested obfuscation decoding,
# Unicode/character substitution detection, hidden injection analysis
from .prompt_obfuscation_decoder_detector_2026_june import (
    PromptObfuscationDecoderDetector,
    ThreatLevel,
    ObfuscationType,
    ObfuscationMatch,
    ObfuscationAnalysisResult
)
__all__.extend([
    "PromptObfuscationDecoderDetector",
    "ThreatLevel",
    "ObfuscationType",
    "ObfuscationMatch",
    "ObfuscationAnalysisResult"
])

# Threat Intelligence Signature Pattern Learner (June 18, 2026)
from .threat_intelligence_signature_pattern_learner_2026_june import (
    ThreatSignaturePatternLearner,
    SignatureType,
    ConfidenceLevel,
    LearnedSignature
)
__all__.extend([
    "ThreatSignaturePatternLearner",
    "SignatureType",
    "ConfidenceLevel",
    "LearnedSignature"
])

# Threat Intelligence Vulnerability Priority Scanner (June 18, 2026 Production Release)
# CVSS v3.1 scoring, exploit maturity assessment, business impact analysis,
# intelligent remediation prioritization with SLA windows
from .threat_intelligence_vulnerability_priority_scanner_2026_june import (
    VulnerabilityPriorityScanner,
    CVSSAttackVector,
    CVSSAttackComplexity,
    CVSSPrivilegesRequired,
    CVSSUserInteraction,
    CVSSScope,
    CVSSImpact,
    ExploitMaturity,
    AssetCriticality,
    RemediationPriority,
    CVSSVector,
    Vulnerability,
    VulnerabilityAssessment,
    create_vulnerability_scanner
)
__all__.extend([
    "VulnerabilityPriorityScanner",
    "CVSSAttackVector",
    "CVSSAttackComplexity",
    "CVSSPrivilegesRequired",
    "CVSSUserInteraction",
    "CVSSScope",
    "CVSSImpact",
    "ExploitMaturity",
    "AssetCriticality",
    "RemediationPriority",
    "CVSSVector",
    "Vulnerability",
    "VulnerabilityAssessment",
    "create_vulnerability_scanner"
])
__version__ = "2026.6.18.15"

# Threat Intelligence Continuous Learning Pipeline (June 19, 2026 Production Release)
# Incremental learning, automated feature extraction, model versioning,
# continuous training with validation and performance monitoring
from .threat_intelligence_continuous_learning_pipeline_2026_june import (
    ThreatFeatureExtractor,
    IncrementalThreatModel,
    ContinuousLearningPipeline,
    ThreatSample,
    ModelVersion,
    TrainingResult
)
__all__.extend([
    "ThreatFeatureExtractor",
    "IncrementalThreatModel",
    "ContinuousLearningPipeline",
    "ThreatSample",
    "ModelVersion",
    "TrainingResult"
])
# Threat Intelligence Threat Actor Tracking Engine (June 19, 2026 Production Release)
# Threat actor activity tracking, anomaly detection, campaign evolution,
# velocity scoring, and predictive activity forecasting
from .threat_intelligence_threat_actor_tracking_engine_2026_june import (
    ThreatActorTrackingEngine,
    ActivityType,
    ActivitySeverity,
    TrackedActivity,
    ActorProfile
)
__all__.extend([
    "ThreatActorTrackingEngine",
    "ActivityType",
    "ActivitySeverity",
    "TrackedActivity",
    "ActorProfile"
])

from .threat_intelligence_mitre_heatmap_visualizer_2026_june import (
    MITREHeatmapVisualizer,
    MITRETactic,
    SeverityLevel,
    HeatmapCell,
    HeatmapResult
)
__all__.extend([
    "MITREHeatmapVisualizer",
    "MITRETactic",
    "SeverityLevel",
    "HeatmapCell",
    "HeatmapResult"
])
# Threat Intelligence Hunting Query Performance Optimizer (June 19, 2026 Production Release)
# Real query optimization, cost analysis, execution benchmarking, performance tuning
from .threat_intelligence_hunting_query_performance_optimizer_2026_june import (
    ThreatHuntingQueryOptimizer,
    QueryType,
    OptimizationLevel,
    QueryCostMetrics,
    OptimizedQuery,
    QueryBenchmarkResult
)
__all__.extend([
    "ThreatHuntingQueryOptimizer",
    "QueryType",
    "OptimizationLevel",
    "QueryCostMetrics",
    "OptimizedQuery",
    "QueryBenchmarkResult"
])

__version__ = "2026.6.19.9"
from .threat_intelligence_exploit_path_prediction_engine_2026_june import ExploitPathPredictionEngine, Vulnerability, Asset, ExploitPath, ExploitLikelihood, AttackVector

# Threat Intelligence Alert Deduplication Engine (June 19, 2026 Production Release)
# Real alert deduplication, noise reduction, alert storm detection
from .threat_intelligence_alert_deduplication_engine_2026_june import (
    Alert,
    AlertSeverity,
    AlertStatus,
    DeduplicationStrategy,
    NoiseType,
    AlertGroup,
    DeduplicationMetrics,
    AlertBaseline,
    AlertDeduplicationEngine,
    ExactMatchDeduplicationPolicy,
    FuzzySimilarityDeduplicationPolicy,
    AlertStormDetectionPolicy,
    create_alert_deduplication_engine
)
__all__.extend([
    "Alert",
    "AlertSeverity",
    "AlertStatus",
    "DeduplicationStrategy",
    "NoiseType",
    "AlertGroup",
    "DeduplicationMetrics",
    "AlertBaseline",
    "AlertDeduplicationEngine",
    "ExactMatchDeduplicationPolicy",
    "FuzzySimilarityDeduplicationPolicy",
    "AlertStormDetectionPolicy",
    "create_alert_deduplication_engine"
])

__version__ = "2026.6.19.10"

# Threat Intelligence Context Similarity Engine (June 19, 2026 Production Release)
# TF-IDF based alert similarity scoring, duplicate detection, and false positive reduction
from .threat_intelligence_context_similarity_engine_2026_june import (
    AlertContext,
    TFIDFVectorizer,
    ContextSimilarityEngine,
    cosine_similarity
)
__all__.extend([
    "AlertContext",
    "TFIDFVectorizer",
    "ContextSimilarityEngine",
    "cosine_similarity"
])
__version__ = "2026.6.19.22"


# Prompt Template Injection Detector (June 20, 2026 Production Release)
# Detects Jinja2/Mustache template injection, variable poisoning, and filter attacks
from .prompt_template_injection_detector_2026_june import (
    TemplateInjectionType,
    TemplateInjectionRiskLevel,
    TemplateInjectionFinding,
    TemplateVariable,
    TemplateInjectionDetectionResult,
    PromptTemplateInjectionDetector,
    create_template_injection_detector
)
__all__.extend([
    "TemplateInjectionType",
    "TemplateInjectionRiskLevel",
    "TemplateInjectionFinding",
    "TemplateVariable",
    "TemplateInjectionDetectionResult",
    "PromptTemplateInjectionDetector",
    "create_template_injection_detector"
])
__version__ = "2026.6.20.1"


# Prompt Chaining Attack Detector (June 20, 2026 Production Release)
# Detects multi-turn prompt chaining, split instructions, and gradual role takeover
from .prompt_chaining_attack_detector_2026_june import (
    ChainingAttackType,
    ChainingDetectionResult,
    PromptChainingAttackDetector
)
__all__.extend([
    "ChainingAttackType",
    "ChainingDetectionResult",
    "PromptChainingAttackDetector"
])
__version__ = "2026.6.20.2"


# Threat Intelligence Threat Feed Health Monitor (June 20, 2026 Production Release)
# Real-time threat feed health monitoring, anomaly detection, and health scoring
from .threat_intelligence_threat_feed_health_monitor_2026_june import (
    ThreatFeedHealthMonitor,
    FeedStatus,
    HealthIssueType,
    FeedHealthMetrics,
    FeedPullResult
)
__all__.extend([
    "ThreatFeedHealthMonitor",
    "FeedStatus",
    "HealthIssueType",
    "FeedHealthMetrics",
    "FeedPullResult"
])
__version__ = "2026.6.20.3"

# Prompt Injection Evasion Technique Detector (June 20, 2026 Production Release)
# Detects Base64/hex/URL encoding, homoglyphs, zero-width chars, leetspeak, ROT ciphers
from .prompt_injection_evasion_technique_detector_2026_june import (
    PromptInjectionEvasionTechniqueDetector,
    EvasionTechniqueType,
    EvasionThreatLevel,
    DecodedPayload,
    EvasionDetectionResult
)
__all__.extend([
    "PromptInjectionEvasionTechniqueDetector",
    "EvasionTechniqueType",
    "EvasionThreatLevel",
    "DecodedPayload",
    "EvasionDetectionResult"
])

# Threat Actor Campaign Tracker (June 20, 2026 Production Release)
# Tracks and correlates threat actor campaigns across IOCs, timelines, and TTP patterns
from .threat_intelligence_threat_actor_campaign_tracker_2026_june import (
    ThreatActorCampaignTracker,
    IndicatorOfCompromise,
    ThreatCampaign,
    CampaignStatus,
    IOCType
)
__all__.extend([
    "ThreatActorCampaignTracker",
    "IndicatorOfCompromise",
    "ThreatCampaign",
    "CampaignStatus",
    "IOCType"
])
__version__ = "2026.6.20.4"


# Threat Intelligence Automated Classification Engine (June 20, 2026)
from .threat_intelligence_automated_classification_engine_2026_june import (
    ThreatIntelligenceClassifier,
    SeverityLevel,
    ThreatCategory,
    ClassificationResult
)
__all__.extend([
    "ThreatIntelligenceClassifier",
    "SeverityLevel",
    "ThreatCategory",
    "ClassificationResult"
])



# Vulnerability Exploit Prediction Engine (June 20, 2026)
# CVSS v3.1 Scoring + EPSS Exploit Prediction + Risk Prioritization
from .threat_intelligence_vulnerability_exploit_prediction_engine_2026_june import (
    VulnerabilityExploitPredictor,
    CVSSv31Scorer,
    EPSSPredictor,
    CVSSVector,
    CVSSAttackVector,
    CVSSAttackComplexity,
    CVSSPrivilegesRequired,
    CVSSUserInteraction,
    CVSSScope,
    CVSSImpact,
    ExploitMaturity,
    RemediationLevel,
    ReportConfidence,
    VulnerabilitySeverity,
    ExploitStatus,
    CVSSScores,
    ExploitPrediction,
    Vulnerability,
    PredictionResult,
    create_exploit_predictor,
    verify_exploit_predictor
)
__all__.extend([
    "VulnerabilityExploitPredictor",
    "CVSSv31Scorer",
    "EPSSPredictor",
    "CVSSVector",
    "CVSSAttackVector",
    "CVSSAttackComplexity",
    "CVSSPrivilegesRequired",
    "CVSSUserInteraction",
    "CVSSScope",
    "CVSSImpact",
    "ExploitMaturity",
    "RemediationLevel",
    "ReportConfidence",
    "VulnerabilitySeverity",
    "ExploitStatus",
    "CVSSScores",
    "ExploitPrediction",
    "Vulnerability",
    "PredictionResult",
    "create_exploit_predictor",
    "verify_exploit_predictor"
])
__version__ = "2026.6.20.5"


# IOC Batch Processor with ML False Positive Reduction (June 20, 2026 - Session 32)
from .threat_intelligence_ioc_batch_processor_ml_enhanced_2026_june import (
    IOCBatchProcessor,
    IOCTYPE,
    IOCSeverity,
    ProcessedIOC,
)
__all__.extend([
    "IOCBatchProcessor",
    "IOCTYPE",
    "IOCSeverity",
    "ProcessedIOC",
])
__version__ = "2026.6.20.7"


# LLM Agent Memory Safety Guardian (June 20, 2026 Production Release)
# Real working memory protection against poisoning, injection, and leakage
from .llm_agent_memory_safety_guardian_2026_june import (
    LLMAgentMemorySafetyGuardian,
    MemoryThreatType,
    MemorySafetyLevel,
    MemoryChunk,
    MemoryThreatFinding,
    MemorySafetyResult,
    create_memory_safety_guardian,
    verify_memory_guardian_works
)
__all__.extend([
    "LLMAgentMemorySafetyGuardian",
    "MemoryThreatType",
    "MemorySafetyLevel",
    "MemoryChunk",
    "MemoryThreatFinding",
    "MemorySafetyResult",
    "create_memory_safety_guardian",
    "verify_memory_guardian_works"
])
# Threat Intelligence Semantic Search Cache Optimizer (June 20, 2026 Production Release)
# Multi-layer caching, semantic similarity matching, intelligent prefetching, performance monitoring
from .threat_intelligence_semantic_search_cache_optimizer_2026_june import (
    SemanticSearchCacheOptimizer,
    LRUCache,
    CacheEntry,
    CacheMetrics,
    CacheStrategy,
    CachePerformanceResult,
    create_cache_optimizer,
    run_semantic_cache_benchmark
)
__all__.extend([
    "SemanticSearchCacheOptimizer",
    "LRUCache",
    "CacheEntry",
    "CacheMetrics",
    "CacheStrategy",
    "CachePerformanceResult",
    "create_cache_optimizer",
    "run_semantic_cache_benchmark"
])

# Phishing URL Classifier Enhanced (June 21, 2026)
from .threat_intelligence_phishing_url_classifier_enhanced_2026_june import (
    PhishingURLClassifierEnhanced,
    URLClassificationResult,
    URLFeatures
)
__all__.extend([
    "PhishingURLClassifierEnhanced",
    "URLClassificationResult",
    "URLFeatures"
])

# Threat Intelligence CVE CVSS v3.1 Scoring Engine (June 21, 2026)
from .threat_intelligence_cve_cvss_v31_scoring_engine_2026_june import (
    CVSSv31Calculator,
    AttackVector,
    AttackComplexity,
    PrivilegesRequired,
    UserInteraction,
    Scope,
    ConfidentialityImpact,
    IntegrityImpact,
    AvailabilityImpact,
    ExploitCodeMaturity,
    RemediationLevel,
    ReportConfidence,
    SeverityRating
)
__all__.extend([
    "CVSSv31Calculator",
    "AttackVector",
    "AttackComplexity",
    "PrivilegesRequired",
    "UserInteraction",
    "Scope",
    "ConfidentialityImpact",
    "IntegrityImpact",
    "AvailabilityImpact",
    "ExploitCodeMaturity",
    "RemediationLevel",
    "ReportConfidence",
    "SeverityRating"
])
# Threat Intelligence Semantic Similarity Search Engine v5 (June 21, 2026)
from .threat_intelligence_semantic_similarity_search_engine_v5_2026_june import (
    ThreatIntelligenceSemanticSimilaritySearchV5,
    LRUTieredCache,
    NGramTokenizer,
    TFIDFCalculator,
    cosine_similarity,
    SAMPLE_IOC_DATASET
)
__all__.extend([
    "ThreatIntelligenceSemanticSimilaritySearchV5",
    "LRUTieredCache",
    "NGramTokenizer",
    "TFIDFCalculator",
    "cosine_similarity",
    "SAMPLE_IOC_DATASET"
])

# + Geolocation IP Enrichment Engine v2 (June 21, 2026)
from .threat_intelligence_geolocation_ip_enrichment_engine_v2_2026_june import (
    GeolocationIPEnrichmentEngine,
    IPType,
    IPReputation,
    ThreatLevel,
    GeolocationData,
    IPEnrichmentResult,
    LRUCache,
    create_geolocation_enrichment_engine,
    verify_geolocation_enrichment_engine
)
__all__.extend([
    "GeolocationIPEnrichmentEngine",
    "IPType",
    "IPReputation",
    "ThreatLevel",
    "GeolocationData",
    "IPEnrichmentResult",
    "LRUCache",
    "create_geolocation_enrichment_engine",
    "verify_geolocation_enrichment_engine"
])

__version__ = "2026.6.21.55"

# + Automated False Positive Classifier Transformer V11 (June 21, 2026)
from .threat_intelligence_automated_false_positive_classifier_transformer_v11_2026_june import (
    FalsePositiveClassifierV11,
    AlertFeatures,
    AlertSeverity,
    AlertType,
    ClassificationResult,
    PlattScaler,
    TransformerFeatureAttention,
    create_fp_classifier_v11,
    verify_fp_classifier_v11
)
__all__.extend([
    "FalsePositiveClassifierV11",
    "AlertFeatures",
    "AlertSeverity",
    "AlertType",
    "ClassificationResult",
    "PlattScaler",
    "TransformerFeatureAttention",
    "create_fp_classifier_v11",
    "verify_fp_classifier_v11"
])

# + Geolocation IP Enrichment Engine V3 (June 21, 2026)
from .threat_intelligence_geolocation_ip_enrichment_v3_2026_june import (
    GeolocationIPEnrichmentEngineV3,
    IPEnrichmentResult,
    ASNIntelligence,
    ThreatFeedMatch,
    HistoricalThreatRecord,
    EnrichmentCache,
    AdaptiveRateLimiter,
    ThreatFeedDatabase,
    IPVersion,
    ThreatReputation,
    NetworkType,
    ASNReputation,
    ThreatFeedSource,
    Coordinates,
    create_ip_enrichment_engine,
    verify_enrichment_engine
)
__all__.extend([
    "GeolocationIPEnrichmentEngineV3",
    "IPEnrichmentResult",
    "ASNIntelligence",
    "ThreatFeedMatch",
    "HistoricalThreatRecord",
    "EnrichmentCache",
    "AdaptiveRateLimiter",
    "ThreatFeedDatabase",
    "IPVersion",
    "ThreatReputation",
    "NetworkType",
    "ASNReputation",
    "ThreatFeedSource",
    "Coordinates",
    "create_ip_enrichment_engine",
    "verify_enrichment_engine"
])
# + Context-Aware Alert Deduplication Engine v5 (June 21, 2026)
from .threat_intelligence_alert_deduplication_context_similarity_v5_2026_june import (
    Alert,
    TextSimilarityScorer,
    IOCExtractor,
    BloomFilter,
    ContextAwareDeduplicationEngineV5
)
__all__.extend([
    "Alert",
    "TextSimilarityScorer",
    "IOCExtractor",
    "BloomFilter",
    "ContextAwareDeduplicationEngineV5"
])
__version__ = "2026.6.21.57"
__version__ = "2026.6.21.59"
