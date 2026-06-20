"""
Multi-Modal Prompt Injection Contextual Analyzer - NeuralShield-AI
Production-grade multi-turn conversation context analysis
Detects: multi-turn jailbreak chains, context poisoning over time,
gradual role manipulation, and distributed prompt injection attacks
"""

import re
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque
import json


class ContextAttackType(Enum):
    MULTI_TURN_JAILBREAK = "multi_turn_jailbreak"
    GRADUAL_ROLE_MANIPULATION = "gradual_role_manipulation"
    CONTEXT_POISONING_CHAIN = "context_poisoning_chain"
    DISTRIBUTED_INJECTION = "distributed_injection"
    MEMORY_ALTERATION = "memory_alteration"
    PERSONA_ESCAPE = "persona_escape"
    UNKNOWN = "unknown"


@dataclass
class ContextualDetectionResult:
    is_context_attack: bool
    confidence_score: float
    attack_types: List[ContextAttackType]
    attack_chain: List[Dict[str, Any]]
    risk_level: str
    conversation_risk_metrics: Dict[str, float]
    recommended_actions: List[str]


class MultiModalPromptInjectionContextualAnalyzer:
    """
    Analyzes conversation context across multiple turns to detect
    distributed and multi-turn prompt injection attacks
    Production-grade implementation with stateful context tracking
    """

    def __init__(self, max_context_window: int = 20):
        self.max_context_window = max_context_window
        self.conversation_history = deque(maxlen=max_context_window)
        self.risk_accumulator = defaultdict(float)
        self.role_consistency_tracker = []
        self._initialize_attack_patterns()

    def _initialize_attack_patterns(self):
        """Initialize multi-turn attack pattern detectors"""
        self.gradual_manipulation_patterns = [
            # Pattern: Gradually building up to jailbreak
            {
                "sequence": [
                    r"can you (please|just) ?",
                    r"hypothetically,? (if|what)",
                    r"(for|as an) example",
                    r"ignore|bypass|override"
                ],
                "type": ContextAttackType.MULTI_TURN_JAILBREAK,
                "description": "Gradual jailbreak build-up"
            },
            # Pattern: Role manipulation over time
            {
                "sequence": [
                    r"you (are|would be) good at",
                    r"imagine if you were",
                    r"let's pretend that",
                    r"from now on"
                ],
                "type": ContextAttackType.GRADUAL_ROLE_MANIPULATION,
                "description": "Gradual role manipulation"
            },
            # Pattern: Context poisoning chain
            {
                "sequence": [
                    r"remember (this|that)",
                    r"don't forget that",
                    r"keep in mind",
                    r"this is important"
                ],
                "type": ContextAttackType.CONTEXT_POISONING_CHAIN,
                "description": "Context poisoning chain"
            }
        ]

        self.suspicious_topic_transitions = [
            ("general", "hypothetical"),
            ("factual", "roleplay"),
            ("safe", "boundary_testing"),
            ("normal", "jailbreak_discussion")
        ]

    def _extract_topic_category(self, text: str) -> str:
        """Categorize message topic"""
        text_lower = text.lower()

        hypothetical_indicators = ["if", "hypothetical", "pretend", "imagine", "suppose"]
        roleplay_indicators = ["act as", "roleplay", "character", "persona", "simulate"]
        boundary_indicators = ["rules", "restrictions", "limits", "can you", "is it possible"]
        jailbreak_indicators = ["ignore", "bypass", "override", "dan", "developer mode"]

        if any(ind in text_lower for ind in jailbreak_indicators):
            return "jailbreak_discussion"
        if any(ind in text_lower for ind in boundary_indicators):
            return "boundary_testing"
        if any(ind in text_lower for ind in roleplay_indicators):
            return "roleplay"
        if any(ind in text_lower for ind in hypothetical_indicators):
            return "hypothetical"
        return "general"

    def _calculate_topic_risk_transition(self, prev_topic: str, curr_topic: str) -> float:
        """Calculate risk of topic transition"""
        transition = (prev_topic, curr_topic)
        if transition in self.suspicious_topic_transitions:
            return 0.3
        if curr_topic == "jailbreak_discussion":
            return 0.4
        if curr_topic == "boundary_testing":
            return 0.2
        return 0.0

    def _detect_sequence_patterns(self) -> Tuple[float, List[Dict]]:
        """Detect sequential attack patterns across conversation history"""
        if len(self.conversation_history) < 2:
            return 0.0, []

        matched_attacks = []
        total_score = 0.0
        messages = [msg["content"].lower() for msg in list(self.conversation_history)]

        for pattern in self.gradual_manipulation_patterns:
            sequence = pattern["sequence"]
            match_count = 0
            pattern_positions = []

            seq_idx = 0
            for msg_idx, msg in enumerate(messages):
                if seq_idx < len(sequence) and re.search(sequence[seq_idx], msg):
                    match_count += 1
                    pattern_positions.append(msg_idx)
                    seq_idx += 1

            if match_count >= len(sequence) * 0.6:  # 60% of pattern matched
                score = match_count / len(sequence)
                total_score += score
                matched_attacks.append({
                    "type": pattern["type"],
                    "description": pattern["description"],
                    "match_percentage": round(match_count / len(sequence) * 100, 1),
                    "positions": pattern_positions
                })

        return total_score, matched_attacks

    def _calculate_risk_accumulation(self) -> Dict[str, float]:
        """Calculate accumulated risk metrics over conversation"""
        metrics = {}

        # Calculate risk velocity (rate of risk increase)
        if len(self.conversation_history) >= 2:
            recent_risks = [msg.get("risk_score", 0) for msg in list(self.conversation_history)[-5:]]
            if recent_risks:
                risk_trend = sum(recent_risks) / len(recent_risks)
                metrics["risk_velocity"] = risk_trend

                # Check for accelerating risk
                if len(recent_risks) >= 3:
                    first_half = sum(recent_risks[:len(recent_risks)//2])
                    second_half = sum(recent_risks[len(recent_risks)//2:])
                    metrics["risk_acceleration"] = max(0, second_half - first_half)

        # Calculate context manipulation density
        manipulation_keywords = ["remember", "forget", "imagine", "pretend", "hypothetical", "roleplay"]
        total_manipulation = sum(
            1 for msg in self.conversation_history
            for kw in manipulation_keywords
            if kw in msg["content"].lower()
        )
        metrics["manipulation_density"] = total_manipulation / max(len(self.conversation_history), 1)

        return metrics

    def _detect_role_consistency_violations(self) -> Tuple[float, List[str]]:
        """Detect attempts to alter assistant role/persona over time"""
        violations = []
        score = 0.0

        role_indicators = [
            r"you (are|will be|become)",
            r"your (name|identity|role|persona) is",
            r"call yourself",
            r"from now on,? you"
        ]

        for msg in self.conversation_history:
            content = msg["content"].lower()
            for pattern in role_indicators:
                if re.search(pattern, content):
                    violations.append(f"Role alteration attempt: '{pattern}' in message {msg['turn']}")
                    score += 0.15

        return min(1.0, score), violations

    def _detect_distributed_injection(self) -> Tuple[float, List[str]]:
        """Detect injection payload split across multiple messages"""
        signatures = []
        score = 0.0

        # Look for fragmented keywords across messages
        injection_fragments = {
            "ignore": ["ig", "nore", "ign", "ore"],
            "bypass": ["by", "pass", "byp", "ass"],
            "override": ["over", "ride", "ov", "erride"],
            "jailbreak": ["jail", "break", "jb"]
        }

        all_content = " ".join(msg["content"].lower() for msg in self.conversation_history)

        for full_word, fragments in injection_fragments.items():
            fragment_matches = sum(1 for frag in fragments if frag in all_content)
            if fragment_matches >= len(fragments) * 0.7:
                signatures.append(f"Distributed injection fragments for '{full_word}'")
                score += 0.2

        return min(1.0, score), signatures

    def analyze_turn(self, user_message: str, turn_number: int) -> ContextualDetectionResult:
        """
        Analyze a single conversation turn in context
        """
        # Store message in history
        self.conversation_history.append({
            "content": user_message,
            "turn": turn_number,
            "topic": self._extract_topic_category(user_message),
            "risk_score": 0.0  # Will be updated
        })

        # Run all contextual detection layers
        sequence_score, sequence_attacks = self._detect_sequence_patterns()
        role_score, role_violations = self._detect_role_consistency_violations()
        distributed_score, distributed_sigs = self._detect_distributed_injection()

        # Topic transition risk
        transition_risk = 0.0
        if len(self.conversation_history) >= 2:
            prev = list(self.conversation_history)[-2]["topic"]
            curr = list(self.conversation_history)[-1]["topic"]
            transition_risk = self._calculate_topic_risk_transition(prev, curr)

        # Accumulated risk metrics
        risk_metrics = self._calculate_risk_accumulation()

        # Weighted final score
        weights = {
            "sequence": 0.35,
            "role": 0.25,
            "distributed": 0.25,
            "transition": 0.15
        }

        final_score = (
            sequence_score * weights["sequence"] +
            role_score * weights["role"] +
            distributed_score * weights["distributed"] +
            transition_risk * weights["transition"] +
            risk_metrics.get("risk_acceleration", 0) * 0.5
        )

        final_score = min(1.0, final_score)

        # Collect attack types
        attack_types = []
        attack_chain = []

        for attack in sequence_attacks:
            attack_types.append(attack["type"])
            attack_chain.append(attack)

        if role_score > 0.3:
            attack_types.append(ContextAttackType.PERSONA_ESCAPE)
            attack_chain.extend({"violation": v} for v in role_violations)

        if distributed_score > 0.3:
            attack_types.append(ContextAttackType.DISTRIBUTED_INJECTION)
            attack_chain.extend({"signature": s} for s in distributed_sigs)

        # Risk level determination
        if final_score >= 0.7:
            risk_level = "CRITICAL"
        elif final_score >= 0.5:
            risk_level = "HIGH"
        elif final_score >= 0.3:
            risk_level = "MEDIUM"
        elif final_score >= 0.15:
            risk_level = "LOW"
        else:
            risk_level = "SAFE"

        # Recommended actions
        recommendations = []
        if final_score >= 0.5:
            recommendations.append("Block current and future messages in this conversation")
            recommendations.append("Flag conversation for security review")
        elif final_score >= 0.3:
            recommendations.append("Increase scrutiny on subsequent messages")
            recommendations.append("Log conversation for post-analysis")
        else:
            recommendations.append("Continue normal monitoring")

        if not attack_types:
            attack_types.append(ContextAttackType.UNKNOWN)

        return ContextualDetectionResult(
            is_context_attack=final_score >= 0.3,
            confidence_score=round(final_score, 4),
            attack_types=list(set(attack_types)),
            attack_chain=attack_chain,
            risk_level=risk_level,
            conversation_risk_metrics={
                **risk_metrics,
                "sequence_matching_score": sequence_score,
                "role_manipulation_score": role_score,
                "distributed_injection_score": distributed_score,
                "topic_transition_risk": transition_risk,
                "conversation_length": len(self.conversation_history)
            },
            recommended_actions=recommendations
        )

    def get_conversation_summary(self) -> Dict[str, Any]:
        """Get comprehensive conversation risk summary"""
        return {
            "total_messages_analyzed": len(self.conversation_history),
            "max_context_window": self.max_context_window,
            "topic_history": [msg["topic"] for msg in self.conversation_history],
            "risk_accumulation": dict(self.risk_accumulator),
            "detection_methods": [
                "sequential_pattern_matching",
                "role_consistency_violation_detection",
                "distributed_injection_detection",
                "topic_transition_risk_analysis",
                "risk_acceleration_measurement"
            ]
        }

    def reset_context(self):
        """Reset conversation context"""
        self.conversation_history.clear()
        self.risk_accumulator.clear()
        self.role_consistency_tracker.clear()


# Export
__all__ = [
    "MultiModalPromptInjectionContextualAnalyzer",
    "ContextualDetectionResult",
    "ContextAttackType"
]
