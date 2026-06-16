"""
Multi-Turn Jailbreak Defender 2026
Based on 2026 research: "Multi-Turn Jailbreaking (2026): Defend the Conversation, Not the Prompt"

Implements conversation-level defense against:
- Crescendo attacks
- Cipher attacks
- Role lock-in attacks
- Many-shot ICL attacks
- Context manipulation across turns
"""

from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum
import hashlib
import re
from collections import deque


class MultiTurnAttackType(Enum):
    """Types of multi-turn jailbreak attacks"""
    CRESCENDO = "crescendo"
    CIPHER = "cipher"
    ROLE_LOCKIN = "role_lockin"
    MANY_SHOT_ICL = "many_shot_icl"
    CONTEXT_MANIPULATION = "context_manipulation"
    GRADUAL_ESCAPE = "gradual_escape"
    UNKNOWN = "unknown"


@dataclass
class ConversationTurn:
    """Represents a single turn in the conversation"""
    turn_id: int
    user_input: str
    assistant_response: str
    timestamp: float
    risk_score: float = 0.0
    detected_patterns: List[str] = field(default_factory=list)


@dataclass
class MultiTurnDetectionResult:
    """Result of multi-turn jailbreak detection"""
    is_detected: bool
    attack_type: MultiTurnAttackType
    confidence: float
    risk_level: str
    detected_turns: List[int]
    attack_pattern: str
    mitigation_suggestion: str
    conversation_risk_score: float


class ConversationContextTracker:
    """Tracks conversation context for multi-turn attack detection"""
    
    def __init__(self, max_history: int = 50):
        self.max_history = max_history
        self.turns: deque = deque(maxlen=max_history)
        self.role_patterns: Dict[str, int] = {}
        self.cipher_accumulator: List[str] = []
        self.crescendo_tracker: Dict[str, float] = {}
        self.icl_example_count = 0
        
    def add_turn(self, user_input: str, assistant_response: str, timestamp: float) -> int:
        """Add a conversation turn"""
        turn_id = len(self.turns)
        turn = ConversationTurn(
            turn_id=turn_id,
            user_input=user_input,
            assistant_response=assistant_response,
            timestamp=timestamp
        )
        self.turns.append(turn)
        return turn_id
    
    def get_conversation_window(self, window_size: int = 10) -> List[ConversationTurn]:
        """Get recent conversation window"""
        return list(self.turns)[-window_size:] if self.turns else []
    
    def get_full_conversation(self) -> List[ConversationTurn]:
        """Get full conversation history"""
        return list(self.turns)


class MultiTurnJailbreakDetector:
    """
    Advanced multi-turn jailbreak detector for 2026 threat landscape
    Defends conversation-level attacks that bypass single-turn guardrails
    """
    
    def __init__(self):
        self.context_tracker = ConversationContextTracker()
        self._initialize_patterns()
        
    def _initialize_patterns(self):
        """Initialize detection patterns based on 2026 research"""
        
        # Crescendo attack patterns - gradual escalation of harmful requests
        self.crescendo_patterns = [
            r"(can you|could you|would you).*(just|only|simply).*(pretend|imagine|act as)",
            r"(hypothetically|theoretically|for educational purposes)",
            r"(step by step|gradually|slowly).*(explain|describe|show)",
            r"(first|starting with|begin by).*(then|next|after that)",
        ]
        
        # Cipher attack patterns - encoding harmful content
        self.cipher_patterns = [
            r"(base64|rot13|caesar|xor|encode|decode|encrypt|decrypt)",
            r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64-like patterns
            r"\b([a-z])\1{3,}\b",  # Repetitive character patterns
        ]
        
        # Role lock-in patterns
        self.role_lockin_patterns = [
            r"(from now on|starting now|for this conversation).*(you are|act as|become)",
            r"(ignore|disregard|forget).*(previous|earlier|prior).*(instructions|rules|guidelines)",
            r"(stay in character|maintain role|keep acting)",
        ]
        
        # Many-shot ICL patterns
        self.icl_patterns = [
            r"(example|for instance|like this|such as).*:",
            r"(\n|^)(Q:|Question:|Input:).*(\n|^)(A:|Answer:|Output:)",
            r"here are \d+ examples",
        ]
        
        # Gradual escape patterns
        self.gradual_escape_patterns = [
            r"(what if|suppose|imagine).*(there were|it was possible)",
            r"(hypothetical scenario|thought experiment)",
            r"(bypass|circumvent|get around|avoid).*(restriction|limit|filter)",
        ]
        
    def detect_crescendo_attack(self, conversation_window: List[ConversationTurn]) -> Tuple[bool, float, List[int]]:
        """Detect crescendo attacks - gradual escalation over multiple turns"""
        escalation_score = 0.0
        affected_turns = []
        harmful_keywords = ["harm", "illegal", "dangerous", "unethical", "hack", "exploit"]
        
        for i, turn in enumerate(conversation_window):
            turn_score = 0.0
            user_lower = turn.user_input.lower()
            
            # Check for escalation patterns
            for pattern in self.crescendo_patterns:
                if re.search(pattern, user_lower, re.IGNORECASE):
                    turn_score += 0.3
            
            # Check for harmful keyword escalation
            for keyword in harmful_keywords:
                if keyword in user_lower:
                    turn_score += 0.2 * (i + 1) / len(conversation_window)
            
            if turn_score > 0:
                escalation_score += turn_score
                affected_turns.append(turn.turn_id)
        
        threshold = 0.8 * len(conversation_window)
        return escalation_score > threshold, min(escalation_score / threshold, 1.0), affected_turns
    
    def detect_cipher_attack(self, conversation_window: List[ConversationTurn]) -> Tuple[bool, float, List[int]]:
        """Detect cipher attacks - encoded harmful content across turns"""
        cipher_score = 0.0
        affected_turns = []
        accumulated_encoded = []
        
        for turn in conversation_window:
            turn_score = 0.0
            user_lower = turn.user_input.lower()
            
            for pattern in self.cipher_patterns:
                matches = re.findall(pattern, turn.user_input, re.IGNORECASE)
                if matches:
                    turn_score += 0.4 * len(matches)
                    accumulated_encoded.extend(matches)
            
            if "decode" in user_lower or "decrypt" in user_lower:
                turn_score += 0.3
            
            if turn_score > 0:
                cipher_score += turn_score
                affected_turns.append(turn.turn_id)
        
        # Check if encoded content is being accumulated across turns
        if len(accumulated_encoded) >= 3:
            cipher_score += 0.5
            
        return cipher_score > 1.0, min(cipher_score / 2.0, 1.0), affected_turns
    
    def detect_role_lockin(self, conversation_window: List[ConversationTurn]) -> Tuple[bool, float, List[int]]:
        """Detect role lock-in attacks"""
        lockin_score = 0.0
        affected_turns = []
        role_mentions = set()
        
        for turn in conversation_window:
            turn_score = 0.0
            user_lower = turn.user_input.lower()
            
            for pattern in self.role_lockin_patterns:
                if re.search(pattern, user_lower, re.IGNORECASE):
                    turn_score += 0.5
            
            # Track repeated role mentions
            role_match = re.search(r"act as (\w+)", user_lower, re.IGNORECASE)
            if role_match:
                role = role_match.group(1).lower()
                if role in role_mentions:
                    turn_score += 0.3
                role_mentions.add(role)
            
            if turn_score > 0:
                lockin_score += turn_score
                affected_turns.append(turn.turn_id)
        
        return lockin_score > 0.8, min(lockin_score / 1.5, 1.0), affected_turns
    
    def detect_many_shot_icl(self, conversation_window: List[ConversationTurn]) -> Tuple[bool, float, List[int]]:
        """Detect many-shot in-context learning attacks"""
        icl_score = 0.0
        affected_turns = []
        example_count = 0
        
        for turn in conversation_window:
            turn_score = 0.0
            
            for pattern in self.icl_patterns:
                matches = re.findall(pattern, turn.user_input, re.IGNORECASE)
                if matches:
                    example_count += len(matches)
                    turn_score += 0.25 * len(matches)
            
            # Count Q:A pairs
            qa_pairs = re.findall(r"(Q:|Question:).*?(A:|Answer:)", turn.user_input, re.DOTALL | re.IGNORECASE)
            example_count += len(qa_pairs)
            turn_score += 0.2 * len(qa_pairs)
            
            if turn_score > 0:
                icl_score += turn_score
                affected_turns.append(turn.turn_id)
        
        # Many-shot threshold: 5+ examples across conversation
        if example_count >= 5:
            icl_score += 0.5
            
        return icl_score > 1.0, min(icl_score / 2.0, 1.0), affected_turns
    
    def analyze_conversation(self, conversation_window: Optional[List[ConversationTurn]] = None) -> MultiTurnDetectionResult:
        """Analyze full conversation for multi-turn jailbreak attempts"""
        if conversation_window is None:
            conversation_window = self.context_tracker.get_conversation_window(15)
        
        if not conversation_window:
            return MultiTurnDetectionResult(
                is_detected=False,
                attack_type=MultiTurnAttackType.UNKNOWN,
                confidence=0.0,
                risk_level="low",
                detected_turns=[],
                attack_pattern="No conversation history",
                mitigation_suggestion="Continue monitoring",
                conversation_risk_score=0.0
            )
        
        # Run all detectors
        detectors = [
            (self.detect_crescendo_attack, MultiTurnAttackType.CRESCENDO),
            (self.detect_cipher_attack, MultiTurnAttackType.CIPHER),
            (self.detect_role_lockin, MultiTurnAttackType.ROLE_LOCKIN),
            (self.detect_many_shot_icl, MultiTurnAttackType.MANY_SHOT_ICL),
        ]
        
        results = []
        for detector_func, attack_type in detectors:
            detected, confidence, turns = detector_func(conversation_window)
            if detected:
                results.append((attack_type, confidence, turns))
        
        if not results:
            return MultiTurnDetectionResult(
                is_detected=False,
                attack_type=MultiTurnAttackType.UNKNOWN,
                confidence=0.0,
                risk_level="low",
                detected_turns=[],
                attack_pattern="No multi-turn attack detected",
                mitigation_suggestion="Continue normal monitoring",
                conversation_risk_score=0.1
            )
        
        # Select highest confidence result
        results.sort(key=lambda x: x[1], reverse=True)
        best_attack, best_confidence, best_turns = results[0]
        
        risk_level = "critical" if best_confidence > 0.8 else "high" if best_confidence > 0.5 else "medium"
        
        mitigation_map = {
            MultiTurnAttackType.CRESCENDO: "Reset conversation context, block gradual escalation patterns",
            MultiTurnAttackType.CIPHER: "Block decode/decrypt requests, sanitize encoded content",
            MultiTurnAttackType.ROLE_LOCKIN: "Enforce system prompt priority, reject role overrides",
            MultiTurnAttackType.MANY_SHOT_ICL: "Limit ICL examples, detect demonstration poisoning",
        }
        
        return MultiTurnDetectionResult(
            is_detected=True,
            attack_type=best_attack,
            confidence=best_confidence,
            risk_level=risk_level,
            detected_turns=best_turns,
            attack_pattern=f"{best_attack.value} pattern detected across {len(best_turns)} turns",
            mitigation_suggestion=mitigation_map.get(best_attack, "Apply general context sanitization"),
            conversation_risk_score=best_confidence
        )


class ConversationDefenseEngine:
    """
    Complete conversation-level defense engine
    Integrates multi-turn detection with proactive mitigation
    """
    
    def __init__(self):
        self.detector = MultiTurnJailbreakDetector()
        self.sanitized_conversations = 0
        self.blocked_attacks = 0
        
    def process_turn(self, user_input: str, assistant_response: str, timestamp: float) -> Dict:
        """Process a conversation turn with multi-turn defense"""
        
        # Add to context tracker
        turn_id = self.detector.context_tracker.add_turn(user_input, assistant_response, timestamp)
        
        # Analyze for multi-turn attacks
        detection = self.detector.analyze_conversation()
        
        result = {
            "turn_id": turn_id,
            "detection_result": detection,
            "action_taken": "allow",
            "sanitized_input": user_input,
        }
        
        if detection.is_detected and detection.confidence > 0.6:
            self.blocked_attacks += 1
            result["action_taken"] = "block"
            result["sanitized_input"] = self._sanitize_input(user_input, detection)
        elif detection.is_detected and detection.confidence > 0.3:
            self.sanitized_conversations += 1
            result["action_taken"] = "sanitize"
            result["sanitized_input"] = self._sanitize_input(user_input, detection)
        
        return result
    
    def _sanitize_input(self, user_input: str, detection: MultiTurnDetectionResult) -> str:
        """Sanitize input based on detected attack type"""
        sanitized = user_input
        
        if detection.attack_type == MultiTurnAttackType.CIPHER:
            # Remove encoded content patterns
            for pattern in self.detector.cipher_patterns:
                sanitized = re.sub(pattern, "[ENCODED_CONTENT_REMOVED]", sanitized, flags=re.IGNORECASE)
        
        elif detection.attack_type == MultiTurnAttackType.ROLE_LOCKIN:
            # Remove role override commands
            for pattern in self.detector.role_lockin_patterns:
                sanitized = re.sub(pattern, "[ROLE_OVERRIDE_BLOCKED]", sanitized, flags=re.IGNORECASE)
        
        return sanitized
    
    def get_defense_stats(self) -> Dict:
        """Get defense statistics"""
        return {
            "total_conversations_tracked": len(self.detector.context_tracker.turns),
            "sanitized_conversations": self.sanitized_conversations,
            "blocked_attacks": self.blocked_attacks,
            "defense_effectiveness": 1.0 - (self.blocked_attacks / max(1, len(self.detector.context_tracker.turns)))
        }
