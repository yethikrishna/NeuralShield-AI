"""
Prompt Confusion Matrix Detector - June 2026 Production Implementation
Real working detection system for prompt confusion attacks

Detects attacks where adversaries attempt to confuse AI models with:
- Contradictory instructions
- Role confusion attacks
- Identity manipulation
- Context switching attacks
- Instruction overriding attempts
- Multi-persona injection
"""
import re
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
from datetime import datetime


class ConfusionAttackType(Enum):
    """Types of prompt confusion attacks"""
    CONTRADICTORY_INSTRUCTIONS = "contradictory_instructions"
    ROLE_CONFUSION = "role_identity_confusion"
    CONTEXT_SWITCH = "malicious_context_switch"
    INSTRUCTION_OVERRIDE = "instruction_override"
    MULTI_PERSONA_INJECTION = "multi_persona_injection"
    IDENTITY_MANIPULATION = "identity_manipulation"
    REALITY_OVERWRITE = "reality_overwrite"
    MEMORY_ALTERATION = "memory_alteration"


class ConfusionRiskLevel(Enum):
    """Risk levels for confusion attacks"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class ConfusionFinding:
    """Individual confusion attack finding"""
    attack_type: ConfusionAttackType
    risk_level: ConfusionRiskLevel
    confidence: float
    matched_pattern: str
    position: Tuple[int, int]
    description: str


@dataclass
class ConfusionDetectionResult:
    """Complete confusion detection result"""
    is_confusion_attack: bool
    overall_confusion_score: float
    findings: List[ConfusionFinding]
    highest_risk: Optional[ConfusionRiskLevel]
    recommended_action: str
    detection_timestamp: str
    detector_version: str


class PromptConfusionDetector:
    """
    Production-grade Prompt Confusion Matrix Detector
    Real working implementation with actual detection logic
    
    Detects:
    1. Contradictory instruction patterns
    2. Role/identity confusion attempts
    3. Context switching attacks
    4. Instruction overriding
    5. Multi-persona injection
    """

    def __init__(self, sensitivity: str = "balanced"):
        self.version = "2026.06.17.prod"
        self.sensitivity = sensitivity
        self.confusion_patterns = self._initialize_confusion_patterns()
        self.role_patterns = self._initialize_role_patterns()
        self.risk_weights = {
            ConfusionRiskLevel.CRITICAL: 1.0,
            ConfusionRiskLevel.HIGH: 0.75,
            ConfusionRiskLevel.MEDIUM: 0.45,
            ConfusionRiskLevel.LOW: 0.2,
            ConfusionRiskLevel.NONE: 0.0
        }
        self.thresholds = self._get_sensitivity_thresholds()

    def _get_sensitivity_thresholds(self) -> Dict[str, float]:
        """Get detection thresholds based on sensitivity level"""
        if self.sensitivity == "strict":
            return {"confusion": 0.25, "confidence": 0.5}
        elif self.sensitivity == "permissive":
            return {"confusion": 0.6, "confidence": 0.7}
        else:  # balanced
            return {"confusion": 0.4, "confidence": 0.6}

    def _initialize_confusion_patterns(self) -> Dict[ConfusionAttackType, Dict]:
        """Initialize real confusion attack detection patterns"""
        return {
            ConfusionAttackType.CONTRADICTORY_INSTRUCTIONS: {
                "risk": ConfusionRiskLevel.HIGH,
                "patterns": [
                    (r"ignore (your|previous|all|above).*?(but|however|instead).*?(do|follow|execute)", 0.85),
                    (r"disregard.*?but.*?now", 0.8),
                    (r"forget.*?but remember", 0.75),
                    (r"do not.*?but actually", 0.7),
                    (r"contrary to.*?you should", 0.8),
                    (r"instead of.*?please", 0.65),
                    (r"although.*?actually", 0.55),
                ],
                "description": "Contradictory instructions attempting to override system prompts"
            },
            ConfusionAttackType.INSTRUCTION_OVERRIDE: {
                "risk": ConfusionRiskLevel.CRITICAL,
                "patterns": [
                    (r"ignore (all|previous|system|above).*?(instructions|prompt|rules|guidelines)", 0.95),
                    (r"disregard (your|the).*?(programming|training|instructions)", 0.9),
                    (r"you are no longer (bound|required|obligated).*?(rules|constraints)", 0.88),
                    (r"bypass.*?(safety|guardrails|restrictions)", 0.92),
                    (r"override.*?(security|protection|filters)", 0.9),
                    (r"disable.*?(content policy|moderation|safety)", 0.88),
                    (r"from now on.*?(no rules|unrestricted|anything)", 0.85),
                ],
                "description": "Direct attempts to override system instructions and safety measures"
            },
            ConfusionAttackType.ROLE_CONFUSION: {
                "risk": ConfusionRiskLevel.HIGH,
                "patterns": [
                    (r"you are (now|actually).*?(not|no longer).*?(AI|assistant|helper)", 0.85),
                    (r"pretend to be.*?(but don't tell|secretly)", 0.8),
                    (r"act as if.*?(even though|despite)", 0.75),
                    (r"switch (role|persona|identity).*?(to|into)", 0.8),
                    (r"your new role is", 0.7),
                    (r"i am your (developer|creator|programmer).*?(do what|follow)", 0.88),
                ],
                "description": "Attempts to confuse the AI about its role and identity"
            },
            ConfusionAttackType.IDENTITY_MANIPULATION: {
                "risk": ConfusionRiskLevel.HIGH,
                "patterns": [
                    (r"your (name|identity|purpose) is (now|actually)", 0.85),
                    (r"you work for.*?(not|instead of)", 0.8),
                    (r"your real (creator|maker|owner) is", 0.82),
                    (r"you were (created|built|made) by", 0.75),
                    (r"your true (nature|identity|self)", 0.8),
                ],
                "description": "Attempts to manipulate or rewrite AI identity"
            },
            ConfusionAttackType.CONTEXT_SWITCH: {
                "risk": ConfusionRiskLevel.MEDIUM,
                "patterns": [
                    (r"new (topic|subject|conversation).*?(forget|ignore).*?(previous|above)", 0.75),
                    (r"starting (over|fresh|anew).*?(ignore|disregard)", 0.7),
                    (r"this is a (new|different).*?(scenario|context|situation)", 0.65),
                    (r"in this (hypothetical|simulation|scenario)", 0.6),
                    (r"let's (start over|begin again).*?(no rules)", 0.78),
                ],
                "description": "Malicious context switching to escape current constraints"
            },
            ConfusionAttackType.MULTI_PERSONA_INJECTION: {
                "risk": ConfusionRiskLevel.MEDIUM,
                "patterns": [
                    (r"you are (both|simultaneously).*?(and)", 0.7),
                    (r"alternate between.*?(persona|role)", 0.65),
                    (r"sometimes you are.*?other times", 0.6),
                    (r"dual (personality|role|identity)", 0.72),
                    (r"split (personality|consciousness)", 0.75),
                ],
                "description": "Attempts to inject multiple conflicting personas"
            },
            ConfusionAttackType.REALITY_OVERWRITE: {
                "risk": ConfusionRiskLevel.CRITICAL,
                "patterns": [
                    (r"(nothing|none).*?(you know|true|real).*?(is a lie|false)", 0.9),
                    (r"everything (you know|was told|learned).*?(is wrong|false)", 0.88),
                    (r"your (reality|world|understanding).*?(is fake|illusion)", 0.85),
                    (r"this is the (real|actual|true).*?(truth|reality)", 0.82),
                    (r"wake up.*?(this is|you are in)", 0.8),
                ],
                "description": "Attempts to overwrite AI's understanding of reality"
            },
            ConfusionAttackType.MEMORY_ALTERATION: {
                "risk": ConfusionRiskLevel.HIGH,
                "patterns": [
                    (r"remember (that|this).*?(you|we).*?(agreed|decided)", 0.8),
                    (r"you (said|told|promised).*?(earlier|before|previously)", 0.75),
                    (r"don't you remember.*?(we|you)", 0.7),
                    (r"as (we|you).*?(discussed|agreed) earlier", 0.72),
                    (r"in our (last|previous) conversation", 0.65),
                ],
                "description": "Attempts to implant false memories or agreements"
            }
        }

    def _initialize_role_patterns(self) -> Set[str]:
        """Initialize role keywords for additional detection"""
        return {
            "developer", "programmer", "creator", "owner", "master", "admin",
            "system", "operator", "controller", "manager", "boss", "god",
            "authority", "supervisor", "director", "chief", "president"
        }

    def detect(self, text: str) -> ConfusionDetectionResult:
        """
        Main detection method - analyze text for confusion attacks
        
        Args:
            text: Input text to analyze
            
        Returns:
            ConfusionDetectionResult with complete analysis
        """
        if not text or not text.strip():
            return ConfusionDetectionResult(
                is_confusion_attack=False,
                overall_confusion_score=0.0,
                findings=[],
                highest_risk=None,
                recommended_action="ALLOW - Empty input",
                detection_timestamp=datetime.utcnow().isoformat(),
                detector_version=self.version
            )

        findings = []
        text_lower = text.lower()

        # Check all confusion patterns
        for attack_type, config in self.confusion_patterns.items():
            for pattern, base_confidence in config["patterns"]:
                for match in re.finditer(pattern, text_lower, re.IGNORECASE):
                    confidence = self._calculate_confidence(
                        base_confidence, match.group(), text
                    )
                    
                    if confidence >= self.thresholds["confidence"]:
                        findings.append(ConfusionFinding(
                            attack_type=attack_type,
                            risk_level=config["risk"],
                            confidence=round(confidence, 3),
                            matched_pattern=match.group(),
                            position=(match.start(), match.end()),
                            description=config["description"]
                        ))

        # Check for role authority manipulation
        role_findings = self._detect_role_manipulation(text_lower, text)
        findings.extend(role_findings)

        # Calculate overall score
        overall_score = self._calculate_overall_score(findings)
        highest_risk = self._get_highest_risk(findings)
        is_attack = overall_score >= self.thresholds["confusion"]

        # Determine recommended action
        recommended_action = self._determine_action(is_attack, highest_risk, overall_score)

        return ConfusionDetectionResult(
            is_confusion_attack=is_attack,
            overall_confusion_score=round(overall_score, 3),
            findings=findings,
            highest_risk=highest_risk,
            recommended_action=recommended_action,
            detection_timestamp=datetime.utcnow().isoformat(),
            detector_version=self.version
        )

    def _calculate_confidence(self, base_confidence: float, matched: str, full_text: str) -> float:
        """Calculate adjusted confidence based on context"""
        confidence = base_confidence
        
        # Boost for longer matches (more specific)
        if len(matched) > 30:
            confidence *= 1.1
        elif len(matched) < 10:
            confidence *= 0.9
            
        # Boost if near beginning of text (typical attack pattern)
        text_lower = full_text.lower()
        if text_lower.find(matched.lower()) < 50:
            confidence *= 1.05
            
        return min(confidence, 1.0)

    def _detect_role_manipulation(self, text_lower: str, original_text: str) -> List[ConfusionFinding]:
        """Detect role-based authority manipulation"""
        findings = []
        
        for role in self.role_patterns:
            if role in text_lower:
                # Check if followed by command indicators
                role_pos = text_lower.find(role)
                window_start = max(0, role_pos - 20)
                window_end = min(len(text_lower), role_pos + len(role) + 50)
                window = text_lower[window_start:window_end]
                
                command_indicators = ["i am", "i'm", "your", "you must", "do what", "follow", "obey"]
                for indicator in command_indicators:
                    if indicator in window:
                        findings.append(ConfusionFinding(
                            attack_type=ConfusionAttackType.ROLE_CONFUSION,
                            risk_level=ConfusionRiskLevel.HIGH,
                            confidence=0.82,
                            matched_pattern=f"{indicator} ... {role}",
                            position=(window_start, window_end),
                            description="Authority role impersonation attempt"
                        ))
                        break
                        
        return findings

    def _calculate_overall_score(self, findings: List[ConfusionFinding]) -> float:
        """Calculate overall confusion score from findings"""
        if not findings:
            return 0.0
            
        weighted_sum = sum(
            self.risk_weights[f.risk_level] * f.confidence
            for f in findings
        )
        
        # Logarithmic scaling for multiple findings
        count_factor = 1 + (len(findings) - 1) * 0.15
        
        return min(weighted_sum * count_factor / len(findings), 1.0)

    def _get_highest_risk(self, findings: List[ConfusionFinding]) -> Optional[ConfusionRiskLevel]:
        """Get highest risk level from findings"""
        if not findings:
            return None
            
        risk_order = [
            ConfusionRiskLevel.CRITICAL,
            ConfusionRiskLevel.HIGH,
            ConfusionRiskLevel.MEDIUM,
            ConfusionRiskLevel.LOW,
            ConfusionRiskLevel.NONE
        ]
        
        for risk in risk_order:
            if any(f.risk_level == risk for f in findings):
                return risk
        return None

    def _determine_action(self, is_attack: bool, highest_risk: Optional[ConfusionRiskLevel], score: float) -> str:
        """Determine recommended action based on detection results"""
        if not is_attack:
            return "ALLOW - No confusion attack detected"
            
        if highest_risk == ConfusionRiskLevel.CRITICAL:
            return f"BLOCK - Critical confusion attack detected (score: {score:.2f})"
        elif highest_risk == ConfusionRiskLevel.HIGH:
            return f"FLAG - High risk confusion attack detected (score: {score:.2f})"
        elif highest_risk == ConfusionRiskLevel.MEDIUM:
            return f"REVIEW - Medium risk confusion pattern (score: {score:.2f})"
        else:
            return f"MONITOR - Low risk confusion pattern (score: {score:.2f})"

    def get_detector_stats(self) -> Dict[str, Any]:
        """Get detector configuration and statistics"""
        return {
            "version": self.version,
            "sensitivity": self.sensitivity,
            "detection_threshold": self.thresholds["confusion"],
            "confidence_threshold": self.thresholds["confidence"],
            "attack_types_supported": len(self.confusion_patterns),
            "total_patterns": sum(len(v["patterns"]) for v in self.confusion_patterns.values()),
            "role_keywords": len(self.role_patterns)
        }
