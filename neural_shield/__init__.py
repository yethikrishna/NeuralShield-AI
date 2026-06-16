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
