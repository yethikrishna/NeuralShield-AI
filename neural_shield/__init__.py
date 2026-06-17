"""
NeuralShield-AI - AI Security Defense Framework
June 2026 - Enhanced with Jailbreak Detection, Constitutional Classifiers, Input Purification
"""
from .enhanced_mimetic_detector_2026 import EnhancedMimeticDetector2026
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
__version__ = "2026.6.17.31"
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
__version__ = "2026.6.17.33"
