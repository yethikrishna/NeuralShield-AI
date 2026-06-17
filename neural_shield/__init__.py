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
__version__ = "2026.6.17.14"
