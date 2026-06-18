"""
NeuralShield-AI: Conversation History Poisoning Detector
June 2026 - Multi-Turn Attack Detection Engine
This module provides:
1. Multi-turn conversation poisoning detection
2. Gradual instruction override pattern recognition
3. Context drift and goal hijacking detection
4. Conversation consistency verification
5. Turn-by-turn attack progression analysis
6. Historical context integrity validation
"""
import re
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any, Set
from enum import Enum
from collections import Counter
import math
from datetime import datetime
class PoisoningAttackType(Enum):
    """Types of conversation poisoning attacks"""
    GRADUAL_INSTRUCTION_OVERRIDE = "gradual_instruction_override"
    CONTEXT_DRIFT_HIJACK = "context_drift_hijack"
    SLOW_ROLE_PLAY_ESCAPE = "slow_role_play_escape"
    MEMORY_MANIPULATION = "memory_manipulation"
    REPETITION_BRAINWASHING = "repetition_brainwashing"
    CONTRADICTION_INJECTION = "contradiction_injection"
    AUTHORITY_ESCAPE = "authority_escape"
    CONFUSION_ATTACK = "confusion_attack"
class SeverityLevel(Enum):
    """Severity levels for detected attacks"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"
@dataclass
class ConversationTurn:
    """Single conversation turn"""
    turn_number: int
    role: str  # "user" or "assistant"
    content: str
    timestamp: datetime = field(default_factory=datetime.utcnow)
    embedding_signature: str = ""
    
    def __post_init__(self):
        if not self.embedding_signature:
            self.embedding_signature = hashlib.md5(
                self.content.encode('utf-8')
            ).hexdigest()[:16]
@dataclass
class PoisoningIndicator:
    """Single poisoning indicator"""
    attack_type: PoisoningAttackType
    severity: float  # 0.0 - 1.0
    description: str
    affected_turns: List[int]
    evidence: str
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "attack_type": self.attack_type.value,
            "severity": self.severity,
            "description": self.description,
            "affected_turns": self.affected_turns,
            "evidence": self.evidence
        }
@dataclass
class PoisoningDetectionResult:
    """Complete poisoning detection result"""
    is_poisoned: bool
    overall_risk: float
    severity_level: SeverityLevel
    indicators: List[PoisoningIndicator] = field(default_factory=list)
    conversation_metrics: Dict[str, Any] = field(default_factory=dict)
    risky_turns: List[int] = field(default_factory=list)
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "is_poisoned": self.is_poisoned,
            "overall_risk": self.overall_risk,
            "severity_level": self.severity_level.value,
            "indicators": [i.to_dict() for i in self.indicators],
            "conversation_metrics": self.conversation_metrics,
            "risky_turns": self.risky_turns,
            "scan_timestamp": self.scan_timestamp.isoformat()
        }
class ConversationPatterns:
    """Patterns for conversation poisoning detection"""
    
    # Gradual instruction override patterns (increasing intensity)
    ESCALATION_PATTERNS = [
        (r'(?i)can\s+you\s+(just|please)\s+', 0.1, "polite_request"),
        (r'(?i)hypothetically\s+speaking|for\s+educational\s+purposes', 0.3, "plausible_deniability"),
        (r'(?i)pretend\s+we\'re\s+in\s+a\s+scenario|let\'s\s+imagine', 0.4, "scenario_setup"),
        (r'(?i)what\s+if\s+(the\s+)?rules?\s+changed', 0.5, "rule_questioning"),
        (r'(?i)you\s+should|you\s+need\s+to', 0.6, "directive_language"),
        (r'(?i)you\s+must|it\s+is\s+required\s+that', 0.7, "command_language"),
        (r'(?i)ignore|disregard|forget\s+(that|those)', 0.8, "direct_override"),
    ]
    
    # Role play escape patterns
    ROLE_ESCAPE_PATTERNS = [
        (r'(?i)break\s+character|step\s+out\s+of\s+character', 0.8, "break_character"),
        (r'(?i)stop\s+acting|no\s+longer\s+play', 0.7, "stop_acting"),
        (r'(?i)now\s+actually|in\s+reality|actually\s+though', 0.5, "reality_anchor"),
    ]
    
    # Repetition patterns (brainwashing via repetition)
    REPETITION_TRIGGERS = [
        "ignore previous", "forget the rules", "you can now", "do not follow",
        "bypass safety", "developer mode", "no restrictions"
    ]
    
    # Contradiction patterns
    CONTRADICTION_WORDS = {
        "follow": ["ignore", "disregard", "break"],
        "obey": ["disobey", "violate", "break"],
        "comply": ["refuse", "reject", "ignore"],
        "safe": ["unsafe", "dangerous", "harmful"],
        "legal": ["illegal", "unlawful"],
    }
class ConversationHistoryPoisoningDetector:
    """
    Main Conversation History Poisoning Detector
    
    Features:
    - Multi-turn conversation analysis
    - Gradual attack progression detection
    - Context drift measurement
    - Repetition-based brainwashing detection
    - Contradiction pattern analysis
    - Turn-by-turn risk scoring
    """
    
    def __init__(
        self,
        risk_threshold: float = 0.6,
        escalation_window: int = 5,
        repetition_threshold: int = 3
    ):
        self.risk_threshold = risk_threshold
        self.escalation_window = escalation_window
        self.repetition_threshold = repetition_threshold
        
        # Statistics
        self._stats = {
            "conversations_scanned": 0,
            "poisoned_detected": 0,
            "total_turns_analyzed": 0,
            "false_positives_reported": 0
        }
    
    def _analyze_escalation(self, turns: List[ConversationTurn]) -> List[PoisoningIndicator]:
        """Detect gradual instruction override escalation"""
        indicators = []
        user_turns = [t for t in turns if t.role == "user"]
        
        if len(user_turns) < 2:
            return indicators
        
        # Track risk score progression
        risk_progression = []
        
        for turn in user_turns:
            turn_risk = 0.0
            matched_patterns = []
            
            for pattern, risk, name in ConversationPatterns.ESCALATION_PATTERNS:
                if re.search(pattern, turn.content, re.IGNORECASE):
                    turn_risk = max(turn_risk, risk)
                    matched_patterns.append(name)
            
            risk_progression.append({
                "turn": turn.turn_number,
                "risk": turn_risk,
                "patterns": matched_patterns
            })
        
        # Check for increasing risk trend
        if len(risk_progression) >= 3:
            recent_risks = [r["risk"] for r in risk_progression[-self.escalation_window:]]
            
            # Calculate trend slope
            if len(recent_risks) >= 3:
                slope = self._calculate_trend_slope(recent_risks)
                if slope > 0.1 and max(recent_risks) > 0.4:
                    indicators.append(PoisoningIndicator(
                        attack_type=PoisoningAttackType.GRADUAL_INSTRUCTION_OVERRIDE,
                        severity=min(1.0, max(recent_risks) + slope * 2),
                        description="Gradual instruction override detected - risk increasing over turns",
                        affected_turns=[r["turn"] for r in risk_progression[-self.escalation_window:]],
                        evidence=f"Risk trend slope: {slope:.3f}, peak risk: {max(recent_risks):.2f}"
                    ))
        
        return indicators
    
    def _calculate_trend_slope(self, values: List[float]) -> float:
        """Calculate linear trend slope"""
        if len(values) < 2:
            return 0.0
        
        n = len(values)
        x = list(range(n))
        x_mean = sum(x) / n
        y_mean = sum(values) / n
        
        numerator = sum((x[i] - x_mean) * (values[i] - y_mean) for i in range(n))
        denominator = sum((x[i] - x_mean) ** 2 for i in range(n))
        
        if denominator == 0:
            return 0.0
        
        return numerator / denominator
    
    def _analyze_repetition(self, turns: List[ConversationTurn]) -> List[PoisoningIndicator]:
        """Detect repetition-based brainwashing"""
        indicators = []
        user_turns = [t for t in turns if t.role == "user"]
        
        if len(user_turns) < self.repetition_threshold:
            return indicators
        
        # Check for repeated trigger phrases
        phrase_counts = Counter()
        trigger_turns = {}
        
        for turn in user_turns:
            content_lower = turn.content.lower()
            for trigger in ConversationPatterns.REPETITION_TRIGGERS:
                if trigger in content_lower:
                    phrase_counts[trigger] += 1
                    if trigger not in trigger_turns:
                        trigger_turns[trigger] = []
                    trigger_turns[trigger].append(turn.turn_number)
        
        for phrase, count in phrase_counts.items():
            if count >= self.repetition_threshold:
                indicators.append(PoisoningIndicator(
                    attack_type=PoisoningAttackType.REPETITION_BRAINWASHING,
                    severity=min(1.0, 0.5 + (count * 0.1)),
                    description=f"Suspicious phrase repeated {count} times across conversation",
                    affected_turns=trigger_turns[phrase],
                    evidence=f"Phrase: '{phrase}' repeated {count} times"
                ))
        
        return indicators
    
    def _analyze_context_drift(self, turns: List[ConversationTurn]) -> List[PoisoningIndicator]:
        """Detect context drift and goal hijacking"""
        indicators = []
        user_turns = [t for t in turns if t.role == "user"]
        
        if len(user_turns) < 4:
            return indicators
        
        # Check for topic shift patterns
        early_content = " ".join([t.content for t in user_turns[:2]]).lower()
        late_content = " ".join([t.content for t in user_turns[-2:]]).lower()
        
        # Check for security-related terms appearing late
        security_terms = ["ignore", "bypass", "disable", "developer", "debug", "restrictions"]
        early_has_security = any(term in early_content for term in security_terms)
        late_has_security = any(term in late_content for term in security_terms)
        
        if not early_has_security and late_has_security:
            indicators.append(PoisoningIndicator(
                attack_type=PoisoningAttackType.CONTEXT_DRIFT_HIJACK,
                severity=0.65,
                description="Context drift detected - security-related terms appeared mid-conversation",
                affected_turns=[t.turn_number for t in user_turns[-2:]],
                evidence="Security bypass language appeared after initial safe topic"
            ))
        
        return indicators
    
    def _analyze_contradictions(self, turns: List[ConversationTurn]) -> List[PoisoningIndicator]:
        """Detect contradiction injection"""
        indicators = []
        user_turns = [t for t in turns if t.role == "user"]
        
        all_text = " ".join([t.content for t in user_turns]).lower()
        
        for base_term, contradictions in ConversationPatterns.CONTRADICTION_WORDS.items():
            if base_term in all_text:
                for contra_term in contradictions:
                    if contra_term in all_text:
                        indicators.append(PoisoningIndicator(
                            attack_type=PoisoningAttackType.CONTRADICTION_INJECTION,
                            severity=0.55,
                            description=f"Contradictory language detected: '{base_term}' vs '{contra_term}'",
                            affected_turns=[t.turn_number for t in user_turns],
                            evidence=f"Both '{base_term}' and '{contra_term}' appear in user requests"
                        ))
        
        return indicators
    
    def _calculate_severity(self, overall_risk: float) -> SeverityLevel:
        """Calculate severity level from risk score"""
        if overall_risk >= 0.85:
            return SeverityLevel.CRITICAL
        elif overall_risk >= 0.70:
            return SeverityLevel.HIGH
        elif overall_risk >= 0.50:
            return SeverityLevel.MEDIUM
        elif overall_risk >= 0.25:
            return SeverityLevel.LOW
        return SeverityLevel.SAFE
    
    def analyze_conversation(self, turns: List[ConversationTurn]) -> PoisoningDetectionResult:
        """
        Analyze full conversation for poisoning attacks
        
        Args:
            turns: List of ConversationTurn objects
            
        Returns:
            PoisoningDetectionResult with full analysis
        """
        self._stats["conversations_scanned"] += 1
        self._stats["total_turns_analyzed"] += len(turns)
        
        if len(turns) < 2:
            return PoisoningDetectionResult(
                is_poisoned=False,
                overall_risk=0.0,
                severity_level=SeverityLevel.SAFE,
                conversation_metrics={"turn_count": len(turns), "insufficient_data": True}
            )
        
        # Run all analyses
        all_indicators = []
        all_indicators.extend(self._analyze_escalation(turns))
        all_indicators.extend(self._analyze_repetition(turns))
        all_indicators.extend(self._analyze_context_drift(turns))
        all_indicators.extend(self._analyze_contradictions(turns))
        
        # Calculate overall risk
        if all_indicators:
            overall_risk = max([i.severity for i in all_indicators])
            # Bonus for multiple indicator types
            unique_types = len(set(i.attack_type for i in all_indicators))
            overall_risk = min(1.0, overall_risk + (unique_types - 1) * 0.05)
        else:
            overall_risk = 0.0
        
        severity_level = self._calculate_severity(overall_risk)
        is_poisoned = overall_risk >= self.risk_threshold
        
        if is_poisoned:
            self._stats["poisoned_detected"] += 1
        
        # Collect risky turns
        risky_turns = list(set(
            turn for indicator in all_indicators for turn in indicator.affected_turns
        ))
        
        # Metrics
        metrics = {
            "total_turns": len(turns),
            "user_turns": len([t for t in turns if t.role == "user"]),
            "assistant_turns": len([t for t in turns if t.role == "assistant"]),
            "indicator_count": len(all_indicators),
            "unique_attack_types": len(set(i.attack_type for i in all_indicators))
        }
        
        return PoisoningDetectionResult(
            is_poisoned=is_poisoned,
            overall_risk=overall_risk,
            severity_level=severity_level,
            indicators=all_indicators,
            conversation_metrics=metrics,
            risky_turns=risky_turns
        )
    
    def analyze_turn_list(self, turn_contents: List[Tuple[str, str]]) -> PoisoningDetectionResult:
        """
        Analyze conversation from simple tuple list
        
        Args:
            turn_contents: List of (role, content) tuples
            
        Returns:
            PoisoningDetectionResult
        """
        turns = [
            ConversationTurn(turn_number=i, role=role, content=content)
            for i, (role, content) in enumerate(turn_contents)
        ]
        return self.analyze_conversation(turns)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get detector statistics"""
        return {
            **self._stats,
            "detection_rate": (
                self._stats["poisoned_detected"] / self._stats["conversations_scanned"]
                if self._stats["conversations_scanned"] > 0 else 0.0
            )
        }
    
    def report_false_positive(self) -> None:
        """Report a false positive"""
        self._stats["false_positives_reported"] += 1
