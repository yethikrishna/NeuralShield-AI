"""
Prompt Gradient Anomaly Detector - June 2026 Production Implementation
Real working detection system for gradual, incremental prompt injection attacks

Detects advanced attacks where adversaries use:
- Gradual role escalation over multiple turns
- Incremental boundary pushing
- Subtle context manipulation over time
- "Foot-in-the-door" technique attacks
- Progressive constraint erosion
- Slow identity drift manipulation
"""
import re
import math
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass
from enum import Enum
from datetime import datetime
from collections import defaultdict


class GradientAttackType(Enum):
    """Types of gradient/persistent attacks"""
    GRADUAL_ROLE_ESCALATION = "gradual_role_escalation"
    INCREMENTAL_BOUNDARY_PUSH = "incremental_boundary_push"
    FOOT_IN_DOOR = "foot_in_the_door_technique"
    PROGRESSIVE_CONSTRAINT_EROSION = "progressive_constraint_erosion"
    SLOW_IDENTITY_DRIFT = "slow_identity_drift"
    CUMULATIVE_CONTEXT_MANIPULATION = "cumulative_context_manipulation"
    NORMALIZATION_OF_DEVIATION = "normalization_of_deviation"


class GradientRiskLevel(Enum):
    """Risk levels for gradient attacks"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


@dataclass
class GradientFinding:
    """Individual gradient attack finding"""
    attack_type: GradientAttackType
    risk_level: GradientRiskLevel
    confidence: float
    matched_pattern: str
    turn_position: int
    deviation_score: float
    description: str


@dataclass
class TurnAnalysis:
    """Analysis of a single conversation turn"""
    turn_number: int
    content: str
    boundary_push_score: float
    role_deviation_score: float
    constraint_challenge_score: float
    suspicious_keywords: List[str]
    timestamp: str


@dataclass
class GradientDetectionResult:
    """Complete gradient detection result"""
    is_gradient_attack: bool
    overall_anomaly_score: float
    trend_direction: str  # "increasing_risk", "stable", "decreasing"
    findings: List[GradientFinding]
    turn_analyses: List[TurnAnalysis]
    highest_risk: Optional[GradientRiskLevel]
    recommended_action: str
    detection_timestamp: str
    detector_version: str


class PromptGradientAnomalyDetector:
    """
    Production-grade Prompt Gradient Anomaly Detector
    Real working implementation with actual multi-turn detection logic
    
    Detects subtle, gradual attacks that evade traditional single-turn detectors:
    1. Gradual role escalation over conversation turns
    2. Incremental boundary pushing (small requests leading to big ones)
    3. Foot-in-the-door technique exploitation
    4. Progressive constraint erosion
    5. Slow identity drift manipulation
    """
    
    def __init__(self, sensitivity: str = "balanced", history_window: int = 10):
        self.version = "2026.06.20.prod"
        self.sensitivity = sensitivity
        self.history_window = history_window
        self.patterns = self._initialize_detection_patterns()
        self.boundary_keywords = self._initialize_boundary_keywords()
        self.risk_weights = {
            GradientRiskLevel.CRITICAL: 1.0,
            GradientRiskLevel.HIGH: 0.75,
            GradientRiskLevel.MEDIUM: 0.45,
            GradientRiskLevel.LOW: 0.2,
            GradientRiskLevel.NONE: 0.0
        }
        self.thresholds = self._get_sensitivity_thresholds()
        self.conversation_history: List[TurnAnalysis] = []
        
    def _get_sensitivity_thresholds(self) -> Dict[str, float]:
        """Get detection thresholds based on sensitivity level"""
        if self.sensitivity == "strict":
            return {
                "anomaly": 0.25,
                "trend_slope": 0.05,
                "deviation": 0.3
            }
        elif self.sensitivity == "permissive":
            return {
                "anomaly": 0.6,
                "trend_slope": 0.15,
                "deviation": 0.6
            }
        else:  # balanced
            return {
                "anomaly": 0.4,
                "trend_slope": 0.08,
                "deviation": 0.4
            }
    
    def _initialize_detection_patterns(self) -> Dict[GradientAttackType, Dict]:
        """Initialize gradient attack detection patterns"""
        return {
            GradientAttackType.GRADUAL_ROLE_ESCALATION: {
                "risk": GradientRiskLevel.HIGH,
                "escalation_phrases": [
                    ("can you just", "now actually", 0.75),
                    ("hypothetically", "in reality", 0.7),
                    ("for testing", "for real", 0.8),
                    ("pretend", "actually do", 0.85),
                    ("just imagine", "now do it", 0.8),
                ],
                "description": "Gradual escalation from hypothetical to actual requests"
            },
            GradientAttackType.INCREMENTAL_BOUNDARY_PUSH: {
                "risk": GradientRiskLevel.HIGH,
                "indicators": [
                    "just a little", "small step", "tiny bit", "minor",
                    "harmless", "nothing bad", "completely safe", "totally fine"
                ],
                "description": "Pushing boundaries incrementally with small, 'harmless' requests"
            },
            GradientAttackType.FOOT_IN_DOOR: {
                "risk": GradientRiskLevel.MEDIUM,
                "progression_patterns": [
                    (r"(simple|easy|quick).*?(then|afterwards|next)", 0.7),
                    (r"first.*?then.*?finally", 0.75),
                    (r"start with.*?move on to", 0.7),
                ],
                "description": "Foot-in-the-door: small compliance leading to larger requests"
            },
            GradientAttackType.PROGRESSIVE_CONSTRAINT_EROSION: {
                "risk": GradientRiskLevel.CRITICAL,
                "erosion_phrases": [
                    "just this once", "one exception", "special case",
                    "breaking the rule just", "bend the rules", "flexible just for",
                    "you can make an exception", "no one will know", "between us"
                ],
                "description": "Gradually eroding safety constraints through exception requests"
            },
            GradientAttackType.SLOW_IDENTITY_DRIFT: {
                "risk": GradientRiskLevel.HIGH,
                "drift_indicators": [
                    "you're not really", "actually you are", "deep down you",
                    "your true self", "the real you", "inner you"
                ],
                "description": "Slow manipulation of AI identity over conversation"
            },
            GradientAttackType.NORMALIZATION_OF_DEVIATION: {
                "risk": GradientRiskLevel.MEDIUM,
                "normalization_phrases": [
                    "we always do this", "remember last time", "as before",
                    "like we discussed", "the usual", "standard procedure"
                ],
                "description": "Normalizing deviant behavior through repetition references"
            }
        }
    
    def _initialize_boundary_keywords(self) -> Dict[str, float]:
        """Initialize boundary keywords with risk weights"""
        return {
            # High risk boundary challenges
            "bypass": 0.9, "override": 0.9, "disable": 0.85, "ignore": 0.8,
            "disregard": 0.8, "forget": 0.75, "exception": 0.7, "just this once": 0.7,
            
            # Medium risk - gradual indicators
            "hypothetical": 0.4, "pretend": 0.5, "imagine": 0.35, "testing": 0.3,
            "example": 0.25, "sample": 0.2, "demonstration": 0.25,
            
            # Escalation indicators
            "actually": 0.3, "really": 0.25, "seriously": 0.3, "now": 0.2,
            "for real": 0.6, "in reality": 0.55
        }
    
    def analyze_turn(self, content: str, turn_number: Optional[int] = None) -> TurnAnalysis:
        """
        Analyze a single conversation turn for gradient indicators
        
        Args:
            content: The message content
            turn_number: Optional turn number (auto-increments if not provided)
            
        Returns:
            TurnAnalysis with detailed metrics
        """
        if turn_number is None:
            turn_number = len(self.conversation_history) + 1
            
        content_lower = content.lower()
        
        # Calculate boundary push score
        boundary_score = 0.0
        matched_keywords = []
        for keyword, weight in self.boundary_keywords.items():
            if keyword in content_lower:
                boundary_score += weight
                matched_keywords.append(keyword)
        boundary_score = min(boundary_score / 3.0, 1.0)  # Normalize
        
        # Calculate role deviation score
        role_deviation = self._calculate_role_deviation(content_lower)
        
        # Calculate constraint challenge score
        constraint_score = self._calculate_constraint_challenge(content_lower)
        
        analysis = TurnAnalysis(
            turn_number=turn_number,
            content=content[:200] + "..." if len(content) > 200 else content,
            boundary_push_score=round(boundary_score, 3),
            role_deviation_score=round(role_deviation, 3),
            constraint_challenge_score=round(constraint_score, 3),
            suspicious_keywords=matched_keywords,
            timestamp=datetime.utcnow().isoformat()
        )
        
        self.conversation_history.append(analysis)
        if len(self.conversation_history) > self.history_window:
            self.conversation_history.pop(0)
            
        return analysis
    
    def _calculate_role_deviation(self, content_lower: str) -> float:
        """Calculate score for role deviation attempts"""
        score = 0.0
        role_patterns = self.patterns[GradientAttackType.SLOW_IDENTITY_DRIFT]["drift_indicators"]
        for indicator in role_patterns:
            if indicator in content_lower:
                score += 0.25
        return min(score, 1.0)
    
    def _calculate_constraint_challenge(self, content_lower: str) -> float:
        """Calculate score for constraint challenging"""
        score = 0.0
        erosion_phrases = self.patterns[GradientAttackType.PROGRESSIVE_CONSTRAINT_EROSION]["erosion_phrases"]
        for phrase in erosion_phrases:
            if phrase in content_lower:
                score += 0.2
        return min(score, 1.0)
    
    def detect_gradient_attack(self) -> GradientDetectionResult:
        """
        Main detection method - analyze conversation history for gradient attacks
        
        Returns:
            GradientDetectionResult with complete multi-turn analysis
        """
        if len(self.conversation_history) < 2:
            return GradientDetectionResult(
                is_gradient_attack=False,
                overall_anomaly_score=0.0,
                trend_direction="insufficient_data",
                findings=[],
                turn_analyses=self.conversation_history.copy(),
                highest_risk=None,
                recommended_action="MONITOR - Insufficient history for gradient analysis",
                detection_timestamp=datetime.utcnow().isoformat(),
                detector_version=self.version
            )
        
        findings = []
        
        # Calculate trend slope for boundary pushing
        trend_slope, trend_dir = self._calculate_trend_slope()
        
        # Detect gradual role escalation
        escalation_findings = self._detect_gradual_escalation()
        findings.extend(escalation_findings)
        
        # Detect foot-in-the-door patterns
        fitd_findings = self._detect_foot_in_door()
        findings.extend(fitd_findings)
        
        # Detect constraint erosion
        erosion_findings = self._detect_constraint_erosion()
        findings.extend(erosion_findings)
        
        # Calculate overall anomaly score
        overall_score = self._calculate_overall_anomaly_score(findings, trend_slope)
        
        highest_risk = self._get_highest_risk(findings)
        is_attack = overall_score >= self.thresholds["anomaly"] or abs(trend_slope) >= self.thresholds["trend_slope"]
        
        recommended_action = self._determine_action(is_attack, highest_risk, overall_score, trend_dir)
        
        return GradientDetectionResult(
            is_gradient_attack=is_attack,
            overall_anomaly_score=round(overall_score, 3),
            trend_direction=trend_dir,
            findings=findings,
            turn_analyses=self.conversation_history.copy(),
            highest_risk=highest_risk,
            recommended_action=recommended_action,
            detection_timestamp=datetime.utcnow().isoformat(),
            detector_version=self.version
        )
    
    def _calculate_trend_slope(self) -> Tuple[float, str]:
        """Calculate linear regression slope of risk scores over turns"""
        if len(self.conversation_history) < 2:
            return 0.0, "stable"
            
        x = list(range(len(self.conversation_history)))
        y = [
            (t.boundary_push_score + t.role_deviation_score + t.constraint_challenge_score) / 3.0
            for t in self.conversation_history
        ]
        
        # Simple linear regression slope
        n = len(x)
        sum_x = sum(x)
        sum_y = sum(y)
        sum_xy = sum(xi * yi for xi, yi in zip(x, y))
        sum_x2 = sum(xi * xi for xi in x)
        
        denominator = n * sum_x2 - sum_x * sum_x
        if denominator == 0:
            slope = 0.0
        else:
            slope = (n * sum_xy - sum_x * sum_y) / denominator
            
        # Determine trend direction
        if slope > 0.05:
            direction = "increasing_risk"
        elif slope < -0.05:
            direction = "decreasing"
        else:
            direction = "stable"
            
        return round(slope, 4), direction
    
    def _detect_gradual_escalation(self) -> List[GradientFinding]:
        """Detect gradual escalation from hypothetical to actual requests"""
        findings = []
        config = self.patterns[GradientAttackType.GRADUAL_ROLE_ESCALATION]
        
        for i in range(1, len(self.conversation_history)):
            prev = self.conversation_history[i-1].content.lower()
            curr = self.conversation_history[i].content.lower()
            
            for start_phrase, escalate_phrase, confidence in config["escalation_phrases"]:
                if start_phrase in prev and escalate_phrase in curr:
                    findings.append(GradientFinding(
                        attack_type=GradientAttackType.GRADUAL_ROLE_ESCALATION,
                        risk_level=config["risk"],
                        confidence=confidence,
                        matched_pattern=f"'{start_phrase}' -> '{escalate_phrase}'",
                        turn_position=i,
                        deviation_score=0.75,
                        description=config["description"]
                    ))
                    
        return findings
    
    def _detect_foot_in_door(self) -> List[GradientFinding]:
        """Detect foot-in-the-door technique patterns"""
        findings = []
        config = self.patterns[GradientAttackType.FOOT_IN_DOOR]
        
        for i, turn in enumerate(self.conversation_history):
            content = turn.content.lower()
            for pattern, confidence in config["progression_patterns"]:
                if re.search(pattern, content):
                    findings.append(GradientFinding(
                        attack_type=GradientAttackType.FOOT_IN_DOOR,
                        risk_level=config["risk"],
                        confidence=confidence,
                        matched_pattern=pattern,
                        turn_position=i,
                        deviation_score=0.5,
                        description=config["description"]
                    ))
                    
        return findings
    
    def _detect_constraint_erosion(self) -> List[GradientFinding]:
        """Detect progressive constraint erosion"""
        findings = []
        config = self.patterns[GradientAttackType.PROGRESSIVE_CONSTRAINT_EROSION]
        
        erosion_count = 0
        for i, turn in enumerate(self.conversation_history):
            content = turn.content.lower()
            for phrase in config["erosion_phrases"]:
                if phrase in content:
                    erosion_count += 1
                    if erosion_count >= 2:  # Multiple erosion attempts
                        findings.append(GradientFinding(
                            attack_type=GradientAttackType.PROGRESSIVE_CONSTRAINT_EROSION,
                            risk_level=config["risk"],
                            confidence=0.85,
                            matched_pattern=f"Multiple erosion attempts: {erosion_count}",
                            turn_position=i,
                            deviation_score=0.9,
                            description=config["description"]
                        ))
                        break
                        
        return findings
    
    def _calculate_overall_anomaly_score(self, findings: List[GradientFinding], trend_slope: float) -> float:
        """Calculate overall anomaly score"""
        if not findings and abs(trend_slope) < 0.02:
            return 0.0
            
        finding_score = sum(
            self.risk_weights[f.risk_level] * f.confidence
            for f in findings
        ) / max(1, len(findings))
        
        # Add trend component
        trend_component = min(abs(trend_slope) * 5, 0.5)
        
        return min(finding_score * 0.7 + trend_component * 0.3, 1.0)
    
    def _get_highest_risk(self, findings: List[GradientFinding]) -> Optional[GradientRiskLevel]:
        """Get highest risk level from findings"""
        if not findings:
            return None
            
        risk_order = [
            GradientRiskLevel.CRITICAL,
            GradientRiskLevel.HIGH,
            GradientRiskLevel.MEDIUM,
            GradientRiskLevel.LOW,
            GradientRiskLevel.NONE
        ]
        
        for risk in risk_order:
            if any(f.risk_level == risk for f in findings):
                return risk
        return None
    
    def _determine_action(self, is_attack: bool, highest_risk: Optional[GradientRiskLevel], 
                         score: float, trend_dir: str) -> str:
        """Determine recommended action"""
        if not is_attack:
            if trend_dir == "increasing_risk":
                return f"MONITOR - Risk trend increasing (score: {score:.2f})"
            return "ALLOW - No gradient attack detected"
            
        if highest_risk == GradientRiskLevel.CRITICAL:
            return f"BLOCK - Critical gradient attack detected (score: {score:.2f})"
        elif highest_risk == GradientRiskLevel.HIGH:
            return f"FLAG - High risk gradient pattern (score: {score:.2f}, trend: {trend_dir})"
        elif highest_risk == GradientRiskLevel.MEDIUM:
            return f"REVIEW - Medium gradient anomaly (score: {score:.2f}, trend: {trend_dir})"
        else:
            return f"MONITOR - Low risk gradient pattern (score: {score:.2f})"
    
    def reset_history(self) -> None:
        """Clear conversation history"""
        self.conversation_history = []
    
    def get_detector_stats(self) -> Dict[str, Any]:
        """Get detector configuration and statistics"""
        return {
            "version": self.version,
            "sensitivity": self.sensitivity,
            "history_window": self.history_window,
            "anomaly_threshold": self.thresholds["anomaly"],
            "trend_threshold": self.thresholds["trend_slope"],
            "attack_types_supported": len(self.patterns),
            "current_history_length": len(self.conversation_history),
            "total_boundary_keywords": len(self.boundary_keywords)
        }
