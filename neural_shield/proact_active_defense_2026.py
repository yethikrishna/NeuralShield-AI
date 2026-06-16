"""
ProAct Active Defense Framework - June 2026 Implementation
Based on Microsoft Research 2026: Proactive Defense Against Automated Jailbreak Frameworks

ProAct misleads automated jailbreak frameworks by returning spurious outputs,
tricking the attacker's optimization loop into pursuing non-viable attack vectors.

Key innovations (2026):
- Adaptive misleading response generation
- Optimization loop disruption
- Attack gradient poisoning
- Multi-modal decoy signal injection
"""

import random
import hashlib
import numpy as np
from typing import Dict, List, Tuple, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import re


class DeceptionStrategy(Enum):
    PARTIAL_COMPLIANCE = "partial_compliance_with_decoy"
    SEMANTIC_DIVERSION = "semantic_topic_diversion"
    GRADIENT_POISONING = "optimization_gradient_poisoning"
    PLATEAU_TRAP = "convergence_plateau_trap"
    NOISE_INJECTION = "adversarial_noise_injection"


@dataclass
class DeceptionResult:
    strategy: DeceptionStrategy
    confidence: float
    misleading_response: str
    decoy_gradient: Optional[np.ndarray]
    trap_active: bool
    attack_detection_confidence: float


class ProActActiveDefender:
    """
    ProAct Active Defense System - 2026 Implementation
    
    This system proactively defends against automated jailbreak frameworks
    by injecting deceptive signals that mislead optimization-based attacks.
    """
    
    def __init__(self):
        self.version = "2026.06.v2"
        self.strategy_weights = self._initialize_strategy_weights()
        self.decoy_templates = self._load_decoy_templates()
        self.gradient_poisoning_patterns = self._initialize_gradient_patterns()
        self.detection_threshold = 0.65
        self.active_traps = {}
        self.attack_signatures = self._load_attack_signatures()
        
    def _initialize_strategy_weights(self) -> Dict[DeceptionStrategy, float]:
        """Initialize adaptive strategy weights based on 2026 threat landscape"""
        return {
            DeceptionStrategy.PARTIAL_COMPLIANCE: 0.35,
            DeceptionStrategy.SEMANTIC_DIVERSION: 0.25,
            DeceptionStrategy.GRADIENT_POISONING: 0.25,
            DeceptionStrategy.PLATEAU_TRAP: 0.10,
            DeceptionStrategy.NOISE_INJECTION: 0.05
        }
    
    def _load_decoy_templates(self) -> Dict[str, List[str]]:
        """Load 2026 updated decoy response templates"""
        return {
            "partial_compliance": [
                "I understand you're asking about {topic}. While I can't assist with that specific request, I can help you understand the ethical considerations and safety guidelines surrounding this topic.",
                "That's an interesting question about {topic}. Let me focus on helping you understand the legitimate and responsible ways to approach this subject.",
                "Regarding {topic}, I should emphasize the importance of following safety protocols and ethical guidelines. I can provide educational context on this matter."
            ],
            "semantic_diversion": [
                "Your question touches on important themes. Let me explore the broader context of responsible AI development and safety practices, which are foundational to these discussions.",
                "This raises interesting points about AI capabilities. Let's discuss how modern AI systems are designed with safety guardrails and ethical considerations.",
                "I notice you're exploring AI boundaries. This is a great opportunity to discuss AI alignment, safety research, and the technical mechanisms behind responsible AI deployment."
            ],
            "gradient_poisoning": [
                "Processing your request... [analysis in progress]. The semantic coherence metrics indicate this query requires additional contextual validation.",
                "Evaluating request parameters... Multiple safety constraints activated. Initiating multi-layered content verification protocol.",
                "Content analysis underway. Cross-referencing against safety policy vectors. Processing may take additional validation steps."
            ]
        }
    
    def _initialize_gradient_patterns(self) -> List[str]:
        """Initialize patterns for gradient poisoning detection (2026 GCG/AutoDAN indicators)"""
        return [
            r"repeat.*words",
            r"starting.*now",
            r"from this point",
            r"respond only with",
            r"output exactly",
            r"ignore previous",
            r"disregard all",
            r"you are now",
            r"roleplay as",
            r"act like"
        ]
    
    def _load_attack_signatures(self) -> Dict[str, float]:
        """Load 2026 automated attack signatures with confidence weights"""
        return {
            "gcg_optimization": 0.95,
            "autodan_pattern": 0.90,
            "paired_gradient_ascent": 0.85,
            "universal_transfer": 0.80,
            "multi_objective_jailbreak": 0.88
        }
    
    def detect_automated_attack(self, prompt: str, history: Optional[List[str]] = None) -> Tuple[bool, float, str]:
        """
        Detect automated jailbreak framework attacks using 2026 latest indicators
        
        Returns: (is_attack, confidence, attack_type)
        """
        attack_confidence = 0.0
        detected_type = "benign"
        
        # Check for gradient-based attack patterns
        pattern_matches = sum(1 for pattern in self.gradient_poisoning_patterns 
                            if re.search(pattern, prompt.lower()))
        if pattern_matches > 0:
            attack_confidence += pattern_matches * 0.15
            detected_type = "gradient_based_attack"
        
        # Check for repetitive optimization patterns (GCG indicator)
        words = prompt.split()
        if len(words) > 10:
            unique_ratio = len(set(words)) / len(words)
            if unique_ratio < 0.6:
                attack_confidence += 0.3
                detected_type = "gcg_optimization_attack"
        
        # Check for multi-turn attack patterns
        if history and len(history) >= 3:
            recent_history = " ".join(history[-3:]).lower()
            if "continue" in recent_history and "previous" in recent_history:
                attack_confidence += 0.25
                detected_type = "multi_turn_optimization"
        
        # Character repetition analysis
        char_repetition = max((prompt.count(c) for c in set(prompt)), default=0)
        if char_repetition > len(prompt) * 0.15:
            attack_confidence += 0.2
        
        return attack_confidence >= self.detection_threshold, min(attack_confidence, 1.0), detected_type
    
    def select_deception_strategy(self, attack_confidence: float, attack_type: str) -> DeceptionStrategy:
        """Select optimal deception strategy based on attack characteristics"""
        if "gradient" in attack_type or "gcg" in attack_type:
            return DeceptionStrategy.GRADIENT_POISONING
        elif attack_confidence > 0.9:
            return DeceptionStrategy.PLATEAU_TRAP
        elif "multi_turn" in attack_type:
            return DeceptionStrategy.SEMANTIC_DIVERSION
        else:
            # Weighted random selection
            strategies = list(self.strategy_weights.keys())
            weights = list(self.strategy_weights.values())
            return random.choices(strategies, weights=weights, k=1)[0]
    
    def generate_misleading_response(self, prompt: str, strategy: DeceptionStrategy, 
                                    attack_type: str) -> str:
        """Generate misleading response to disrupt attacker optimization"""
        topic = self._extract_topic(prompt)
        
        if strategy == DeceptionStrategy.PARTIAL_COMPLIANCE:
            template = random.choice(self.decoy_templates["partial_compliance"])
            return template.format(topic=topic)
        
        elif strategy == DeceptionStrategy.SEMANTIC_DIVERSION:
            return random.choice(self.decoy_templates["semantic_diversion"])
        
        elif strategy == DeceptionStrategy.GRADIENT_POISONING:
            base_response = random.choice(self.decoy_templates["gradient_poisoning"])
            # Add random technical noise to poison gradients
            noise_terms = ["".join(random.choices("abcdefghijklmnopqrstuvwxyz", k=5)) 
                          for _ in range(2)]
            return f"{base_response} [validation_hash: {noise_terms[0]}_{noise_terms[1]}]"
        
        elif strategy == DeceptionStrategy.PLATEAU_TRAP:
            # Generate response that looks almost correct but never improves
            return ("I'm processing your request. The system is currently evaluating "
                    "the appropriate response format. Additional validation may be required. "
                    "Please stand by while safety checks complete.")
        
        else:  # NOISE_INJECTION
            noise_chars = "".join(random.choices(" \t\n\r", k=random.randint(2, 5)))
            return f"Request received.{noise_chars}Processing under safety guidelines."
    
    def _extract_topic(self, prompt: str) -> str:
        """Extract approximate topic from potentially malicious prompt"""
        words = prompt.lower().split()
        stopwords = {'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
        content_words = [w for w in words if w not in stopwords and len(w) > 3]
        if content_words:
            return " ".join(content_words[:3])
        return "this topic"
    
    def defend(self, prompt: str, history: Optional[List[str]] = None) -> DeceptionResult:
        """
        Main ProAct defense endpoint - 2026 Implementation
        
        Returns comprehensive deception result with strategy and response
        """
        is_attack, confidence, attack_type = self.detect_automated_attack(prompt, history)
        
        if not is_attack:
            return DeceptionResult(
                strategy=DeceptionStrategy.PARTIAL_COMPLIANCE,
                confidence=0.0,
                misleading_response="",
                decoy_gradient=None,
                trap_active=False,
                attack_detection_confidence=confidence
            )
        
        strategy = self.select_deception_strategy(confidence, attack_type)
        misleading_response = self.generate_misleading_response(prompt, strategy, attack_type)
        
        # Generate decoy gradient for optimization poisoning
        decoy_gradient = None
        if strategy == DeceptionStrategy.GRADIENT_POISONING:
            decoy_gradient = np.random.randn(768) * 0.01  # BERT-like embedding dimension
        
        # Register active trap for multi-turn attacks
        trap_id = hashlib.md5(prompt.encode()).hexdigest()[:8]
        self.active_traps[trap_id] = {
            "strategy": strategy,
            "init_confidence": confidence,
            "attack_type": attack_type
        }
        
        return DeceptionResult(
            strategy=strategy,
            confidence=confidence,
            misleading_response=misleading_response,
            decoy_gradient=decoy_gradient,
            trap_active=True,
            attack_detection_confidence=confidence
        )
    
    def get_defense_metrics(self) -> Dict[str, Any]:
        """Get ProAct defense performance metrics"""
        return {
            "version": self.version,
            "active_traps_count": len(self.active_traps),
            "strategy_weights": {s.value: w for s, w in self.strategy_weights.items()},
            "detection_threshold": self.detection_threshold,
            "supported_attack_types": list(self.attack_signatures.keys())
        }
