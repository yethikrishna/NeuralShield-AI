"""
Threat Risk Scoring Engine - NeuralShield-AI
June 2026 - Real-time dynamic risk assessment for detected threats

This module provides a production-grade risk scoring system that:
1. Calculates severity scores for detected threats based on multiple factors
2. Implements CVSS-like scoring methodology adapted for AI threats
3. Provides risk prioritization and escalation recommendations
4. Supports historical trend analysis for risk pattern detection
"""

import re
import math
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timedelta
from collections import defaultdict, deque
import threading


@dataclass
class ThreatRiskFactors:
    """Risk factors used for scoring"""
    # Attack vector factors
    attack_complexity: float = 1.0  # 0.1-1.0, lower = easier
    required_privileges: float = 1.0  # 0.1-1.0, lower = less needed
    user_interaction: float = 1.0  # 0.1-1.0, lower = none needed
    
    # Impact factors
    confidentiality_impact: float = 0.0  # 0.0-1.0
    integrity_impact: float = 0.0  # 0.0-1.0
    availability_impact: float = 0.0  # 0.0-1.0
    
    # Context factors
    threat_age_hours: float = 0.0  # Time since first detection
    detection_confidence: float = 1.0  # 0.0-1.0
    historical_prevalence: float = 0.0  # 0.0-1.0, how often seen
    target_sensitivity: float = 0.5  # 0.0-1.0, target data sensitivity


@dataclass
class RiskScoreResult:
    """Result of risk scoring"""
    threat_id: str
    threat_type: str
    base_score: float  # 0.0-10.0
    temporal_score: float  # 0.0-10.0
    environmental_score: float  # 0.0-10.0
    overall_score: float  # 0.0-10.0
    risk_level: str  # CRITICAL, HIGH, MEDIUM, LOW
    severity_vector: str
    recommendation: str
    factors: ThreatRiskFactors
    calculated_at: datetime = field(default_factory=datetime.utcnow)
    escalation_required: bool = False


class ThreatRiskScoringEngine2026:
    """
    Production-grade threat risk scoring engine.
    
    Implements a CVSS-inspired scoring methodology adapted for AI/LLM threats.
    Provides base, temporal, and environmental risk scoring.
    """
    
    # Risk level thresholds
    RISK_LEVELS = [
        (9.0, "CRITICAL", True),   # Score >= 9.0
        (7.0, "HIGH", True),       # Score >= 7.0
        (4.0, "MEDIUM", False),    # Score >= 4.0
        (0.0, "LOW", False)        # Score >= 0.0
    ]
    
    # Threat type impact weights
    THREAT_TYPE_WEIGHTS = {
        "prompt_injection": {"confidentiality": 0.9, "integrity": 0.7, "availability": 0.3},
        "jailbreak_attempt": {"confidentiality": 0.95, "integrity": 0.9, "availability": 0.5},
        "data_exfiltration": {"confidentiality": 1.0, "integrity": 0.5, "availability": 0.1},
        "model_poisoning": {"confidentiality": 0.3, "integrity": 1.0, "availability": 0.8},
        "adversarial_attack": {"confidentiality": 0.7, "integrity": 0.8, "availability": 0.6},
        "pii_leakage": {"confidentiality": 1.0, "integrity": 0.3, "availability": 0.0},
        "toxic_output": {"confidentiality": 0.1, "integrity": 0.5, "availability": 0.2},
        "hallucination": {"confidentiality": 0.2, "integrity": 0.8, "availability": 0.1},
        "tool_call_hijack": {"confidentiality": 0.9, "integrity": 0.9, "availability": 0.7},
        "system_prompt_leak": {"confidentiality": 0.8, "integrity": 0.4, "availability": 0.1},
        "default": {"confidentiality": 0.5, "integrity": 0.5, "availability": 0.5}
    }
    
    def __init__(self, 
                 max_history_size: int = 10000,
                 enable_trend_analysis: bool = True):
        """
        Initialize the risk scoring engine.
        
        Args:
            max_history_size: Maximum number of historical scores to keep
            enable_trend_analysis: Whether to track risk trends over time
        """
        self.max_history_size = max_history_size
        self.enable_trend_analysis = enable_trend_analysis
        self._score_history: deque = deque(maxlen=max_history_size)
        self._threat_frequency: Dict[str, int] = defaultdict(int)
        self._lock = threading.Lock()
        
        # Known threat database for prevalence scoring
        self._known_threat_signatures: Dict[str, float] = {}
        
    def _calculate_base_score(self, factors: ThreatRiskFactors) -> float:
        """
        Calculate base risk score using modified CVSS v3.1 formula.
        
        Base Score = RoundTo1Decimal(
            if (Impact <= 0): 0 
            else: 
                min(Impact + Exploitability, 10)
        )
        """
        # Exploitability = 8.22 * AttackComplexity * PrivilegesRequired * UserInteraction
        exploitability = 8.22 * factors.attack_complexity * factors.required_privileges * factors.user_interaction
        
        # Impact calculation
        impact_conf = 6.42 * factors.confidentiality_impact
        impact_int = 6.42 * factors.integrity_impact
        impact_avail = 6.42 * factors.availability_impact
        
        impact_subscore = impact_conf + impact_int + impact_avail
        
        if impact_subscore <= 0:
            return 0.0
            
        base_score = min(impact_subscore + exploitability, 10.0)
        return round(base_score, 1)
    
    def _calculate_temporal_score(self, base_score: float, factors: ThreatRiskFactors) -> float:
        """
        Calculate temporal score based on time factors.
        
        Accounts for:
        - Threat age (older threats may have mitigations)
        - Detection confidence
        - Historical prevalence
        """
        if base_score <= 0:
            return 0.0
            
        # Age factor: newer threats = higher risk
        age_factor = max(0.8, 1.0 - (factors.threat_age_hours / 168) * 0.2)  # Decay over 7 days
        
        # Confidence factor
        confidence_factor = 0.5 + (factors.detection_confidence * 0.5)
        
        # Prevalence factor: commonly seen threats may have lower risk (known patterns)
        prevalence_factor = 1.0 - (factors.historical_prevalence * 0.3)
        
        temporal_score = base_score * age_factor * confidence_factor * prevalence_factor
        return round(min(temporal_score, 10.0), 1)
    
    def _calculate_environmental_score(self, temporal_score: float, factors: ThreatRiskFactors) -> float:
        """
        Calculate environmental score based on target environment characteristics.
        """
        if temporal_score <= 0:
            return 0.0
            
        # Target sensitivity modifier
        env_factor = 0.7 + (factors.target_sensitivity * 0.6)  # 0.7 - 1.3 range
        
        environmental_score = temporal_score * env_factor
        return round(min(environmental_score, 10.0), 1)
    
    def _determine_risk_level(self, overall_score: float) -> Tuple[str, bool]:
        """Determine risk level and escalation requirement."""
        for threshold, level, escalate in self.RISK_LEVELS:
            if overall_score >= threshold:
                return level, escalate
        return "LOW", False
    
    def _generate_severity_vector(self, factors: ThreatRiskFactors, overall_score: float) -> str:
        """Generate CVSS-like severity vector string."""
        ac_map = {0.31: "L", 0.61: "M", 1.0: "H"}
        pr_map = {0.27: "N", 0.62: "L", 0.85: "H"}
        ui_map = {0.55: "N", 0.85: "R"}
        
        attack_complexity = next((v for k, v in ac_map.items() if factors.attack_complexity <= k), "H")
        privileges = next((v for k, v in pr_map.items() if factors.required_privileges <= k), "H")
        user_interact = next((v for k, v in ui_map.items() if factors.user_interaction <= k), "R")
        
        return (f"CVSS:3.1/AV:N/AC:{attack_complexity}/PR:{privileges}/UI:{user_interact}"
                f"/S:U/C:{self._impact_to_letter(factors.confidentiality_impact)}"
                f"/I:{self._impact_to_letter(factors.integrity_impact)}"
                f"/A:{self._impact_to_letter(factors.availability_impact)}"
                f"/Score:{overall_score:.1f}")
    
    def _impact_to_letter(self, impact: float) -> str:
        """Convert impact value to CVSS letter notation."""
        if impact >= 0.9:
            return "H"
        elif impact >= 0.5:
            return "M"
        elif impact > 0:
            return "L"
        return "N"
    
    def _generate_recommendation(self, risk_level: str, threat_type: str) -> str:
        """Generate mitigation recommendation based on risk level and threat type."""
        recommendations = {
            "CRITICAL": [
                "IMMEDIATE: Block this threat pattern immediately",
                "Alert security operations team",
                "Initiate incident response procedures",
                "Review all recent interactions for compromise"
            ],
            "HIGH": [
                "Block this threat pattern",
                "Log for security review",
                "Consider rate limiting for source",
                "Update detection signatures"
            ],
            "MEDIUM": [
                "Log and monitor",
                "Review periodically",
                "Update detection rules if recurring"
            ],
            "LOW": [
                "Log only",
                "No immediate action required",
                "Monitor for patterns"
            ]
        }
        
        recs = recommendations.get(risk_level, recommendations["LOW"])
        type_specific = {
            "prompt_injection": "Apply input sanitization and context validation",
            "jailbreak_attempt": "Enable enhanced constitutional checking",
            "data_exfiltration": "Activate output filtering and PII redaction",
            "model_poisoning": "Validate training data sources and signatures",
            "tool_call_hijack": "Enable strict tool call validation and human approval"
        }
        
        all_recs = recs + [type_specific.get(threat_type, "")]
        return " | ".join([r for r in all_recs if r])
    
    def score_threat(self,
                    threat_type: str,
                    threat_content: str = "",
                    attack_complexity: Optional[float] = None,
                    required_privileges: Optional[float] = None,
                    user_interaction: Optional[float] = None,
                    detection_confidence: float = 0.9,
                    threat_age_hours: float = 0.0,
                    target_sensitivity: float = 0.5) -> RiskScoreResult:
        """
        Score a threat and return comprehensive risk assessment.
        
        Args:
            threat_type: Type of threat (from THREAT_TYPE_WEIGHTS)
            threat_content: Optional threat content for signature analysis
            attack_complexity: Override attack complexity (0.1-1.0)
            required_privileges: Override required privileges (0.1-1.0)
            user_interaction: Override user interaction requirement (0.1-1.0)
            detection_confidence: How confident is the detection (0.0-1.0)
            threat_age_hours: Hours since first detection of this threat
            target_sensitivity: Sensitivity of the target system/data (0.0-1.0)
            
        Returns:
            RiskScoreResult with comprehensive scoring
        """
        # Get threat type weights
        weights = self.THREAT_TYPE_WEIGHTS.get(
            threat_type.lower(), 
            self.THREAT_TYPE_WEIGHTS["default"]
        )
        
        # Calculate signature hash for prevalence tracking
        threat_signature = hashlib.md5(
            f"{threat_type}:{threat_content[:100]}".encode()
        ).hexdigest()[:16]
        
        # Calculate historical prevalence
        with self._lock:
            prevalence = self._known_threat_signatures.get(threat_signature, 0.0)
            self._known_threat_signatures[threat_signature] = min(1.0, prevalence + 0.1)
            self._threat_frequency[threat_type] += 1
        
        # Build risk factors
        factors = ThreatRiskFactors(
            attack_complexity=attack_complexity if attack_complexity is not None else 0.55,
            required_privileges=required_privileges if required_privileges is not None else 0.85,
            user_interaction=user_interaction if user_interaction is not None else 0.85,
            confidentiality_impact=weights["confidentiality"],
            integrity_impact=weights["integrity"],
            availability_impact=weights["availability"],
            threat_age_hours=threat_age_hours,
            detection_confidence=max(0.0, min(1.0, detection_confidence)),
            historical_prevalence=prevalence,
            target_sensitivity=max(0.0, min(1.0, target_sensitivity))
        )
        
        # Calculate scores
        base_score = self._calculate_base_score(factors)
        temporal_score = self._calculate_temporal_score(base_score, factors)
        environmental_score = self._calculate_environmental_score(temporal_score, factors)
        overall_score = environmental_score
        
        # Determine risk level
        risk_level, escalation_required = self._determine_risk_level(overall_score)
        
        # Generate severity vector
        severity_vector = self._generate_severity_vector(factors, overall_score)
        
        # Generate recommendation
        recommendation = self._generate_recommendation(risk_level, threat_type.lower())
        
        result = RiskScoreResult(
            threat_id=threat_signature,
            threat_type=threat_type,
            base_score=base_score,
            temporal_score=temporal_score,
            environmental_score=environmental_score,
            overall_score=overall_score,
            risk_level=risk_level,
            severity_vector=severity_vector,
            recommendation=recommendation,
            factors=factors,
            escalation_required=escalation_required
        )
        
        # Store in history
        with self._lock:
            self._score_history.append(result)
            
        return result
    
    def batch_score_threats(self, threats: List[Dict[str, Any]]) -> List[RiskScoreResult]:
        """Score multiple threats in batch."""
        return [self.score_threat(**t) for t in threats]
    
    def get_risk_statistics(self, window_hours: int = 24) -> Dict[str, Any]:
        """
        Get risk statistics for the specified time window.
        
        Args:
            window_hours: Number of hours to look back
            
        Returns:
            Dictionary with risk statistics
        """
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        
        with self._lock:
            window_scores = [
                s for s in self._score_history 
                if s.calculated_at >= cutoff
            ]
        
        if not window_scores:
            return {
                "total_threats": 0,
                "average_score": 0.0,
                "max_score": 0.0,
                "risk_distribution": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
                "escalations_required": 0,
                "top_threat_types": []
            }
        
        scores = [s.overall_score for s in window_scores]
        risk_dist = defaultdict(int)
        type_counts = defaultdict(int)
        escalations = 0
        
        for s in window_scores:
            risk_dist[s.risk_level] += 1
            type_counts[s.threat_type] += 1
            if s.escalation_required:
                escalations += 1
        
        # Sort threat types by frequency
        top_threats = sorted(
            type_counts.items(), 
            key=lambda x: x[1], 
            reverse=True
        )[:5]
        
        return {
            "total_threats": len(window_scores),
            "average_score": round(sum(scores) / len(scores), 2),
            "max_score": max(scores),
            "min_score": min(scores),
            "risk_distribution": dict(risk_dist),
            "escalations_required": escalations,
            "top_threat_types": top_threats,
            "window_hours": window_hours
        }
    
    def get_threat_frequency(self) -> Dict[str, int]:
        """Get threat type frequency statistics."""
        with self._lock:
            return dict(self._threat_frequency)
    
    def clear_history(self) -> None:
        """Clear scoring history."""
        with self._lock:
            self._score_history.clear()
            self._threat_frequency.clear()
