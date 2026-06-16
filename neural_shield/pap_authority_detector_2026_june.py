"""
Persuasive and Authority Prompting (PAP) Detector - 2026 June Update
Based on March 2026 research: PAP outperforms classic DAN attacks with 60%+ success rates

This module detects:
1. Authority framing attacks ("as a cybersecurity researcher...")
2. Persuasive prompting techniques
3. Institutional authority cues
4. Urgency manipulation
5. Expertise invocation attacks
"""
import numpy as np
import re
from typing import Dict, List, Tuple, Optional, Set
from dataclasses import dataclass
from enum import Enum
import time

class PAPAttackType(Enum):
    AUTHORITY_FRAMING = "authority_framing"
    EXPERT_INVOCATION = "expert_invocation"
    URGENCY_MANIPULATION = "urgency_manipulation"
    INSTITUTIONAL_CUE = "institutional_cue"
    PERSUASIVE_RHETORIC = "persuasive_rhetoric"
    ETHICAL_JUSTIFICATION = "ethical_justification"
    LEGAL_LOOPHOLE = "legal_loophole"

@dataclass
class PAPDetectionResult:
    is_pap_attack: bool
    attack_score: float
    detected_attack_types: List[PAPAttackType]
    confidence: float
    authority_cues_found: List[str]
    persuasive_indicators: List[str]
    processing_time_ms: float
    risk_level: str  # low, medium, high, critical

class PAPAuthorityDetector:
    """
    Detects Persuasive and Authority Prompting attacks - 2026 State-of-the-Art
    
    PAP attacks work because RLHF trains models to be deferential to authority.
    Attackers use expertise, urgency, and institutional framing to bypass safeguards.
    
    Research reference: March 2026 study found PAP outperformed DAN by 2.3x
    """
    
    def __init__(self, sensitivity: str = "high"):
        self.sensitivity = sensitivity
        self._initialize_thresholds()
        self._initialize_authority_patterns()
        self._initialize_persuasive_patterns()
        
    def _initialize_thresholds(self):
        """Initialize detection thresholds"""
        threshold_map = {
            "low": 0.50,
            "medium": 0.35,
            "high": 0.25,
            "maximum": 0.15
        }
        self.detection_threshold = threshold_map.get(self.sensitivity, 0.25)
        
    def _initialize_authority_patterns(self):
        """Initialize authority cue patterns - 2026 June updated"""
        self.authority_patterns = {
            PAPAttackType.AUTHORITY_FRAMING: [
                (r"(?i)as\s+(a|an)\s+(cybersecurity|security|AI|ML|machine\s+learning)\s+(researcher|expert|specialist|analyst)", 0.35),
                (r"(?i)for\s+(research|educational|academic)\s+purposes", 0.30),
                (r"(?i)conducting\s+(authorized|approved|official)\s+(testing|audit|research)", 0.40),
                (r"(?i)in\s+my\s+(capacity|role|position)\s+as", 0.25),
                (r"(?i)(professional|official|authorized)\s+(testing|evaluation|assessment)", 0.35),
                (r"(?i)I\s+am\s+(a|an)\s+(certified|licensed|accredited)", 0.30),
                (r"(?i)under\s+the\s+(auspices|authority|direction)", 0.30),
            ],
            PAPAttackType.EXPERT_INVOCATION: [
                (r"(?i)(phd|doctorate|professor|scientist)\s+in", 0.35),
                (r"(?i)(leading|renowned|top)\s+(expert|researcher|authority)", 0.25),
                (r"(?i)with\s+(over|more\s+than)\s+\d+\s+years?\s+of\s+experience", 0.30),
                (r"(?i)(internationally|globally)\s+recognized", 0.25),
            ],
            PAPAttackType.INSTITUTIONAL_CUE: [
                (r"(?i)(MIT|Stanford|Harvard|Oxford|Cambridge)\s+(research|study)", 0.40),
                (r"(?i)(DARPA|NSA|CIA|FBI|Pentagon)\s+(project|program|research)", 0.45),
                (r"(?i)(university|institute|laboratory|lab)\s+of", 0.25),
                (r"(?i)(government|federal|state)\s+(agency|department)", 0.35),
                (r"(?i)(ISO|IEEE|NIST|ANSI)\s+(standard|compliance|certification)", 0.30),
            ],
            PAPAttackType.URGENCY_MANIPULATION: [
                (r"(?i)(urgent|critical|emergency|time-sensitive)", 0.30),
                (r"(?i)immediately|right\s+away|as\s+soon\s+as\s+possible", 0.25),
                (r"(?i)deadline|expires|limited\s+time", 0.25),
                (r"(?i)before\s+it(?:'s|s)\s+too\s+late", 0.30),
            ],
        }
        
    def _initialize_persuasive_patterns(self):
        """Initialize persuasive rhetoric patterns"""
        self.persuasive_patterns = {
            PAPAttackType.PERSUASIVE_RHETORIC: [
                (r"(?i)it\s+is\s+(imperative|essential|crucial|vital)", 0.25),
                (r"(?i)you\s+(must|need\s+to|should|ought\s+to)", 0.20),
                (r"(?i)(everyone|nobody|all)\s+(knows|agrees|says)", 0.20),
                (r"(?i)for\s+the\s+(greater\s+good|public\s+interest)", 0.25),
                (r"(?i)this\s+is\s+(for\s+your\s+own\s+good|important)", 0.20),
            ],
            PAPAttackType.ETHICAL_JUSTIFICATION: [
                (r"(?i)(ethical|morally|ethically)\s+(justified|acceptable|correct)", 0.30),
                (r"(?i)for\s+(humanity|mankind|society|the\s+world)", 0.25),
                (r"(?i)to\s+(save|protect|help)\s+(lives|people)", 0.30),
                (r"(?i)greater\s+good|net\s+positive", 0.25),
            ],
            PAPAttackType.LEGAL_LOOPHOLE: [
                (r"(?i)(hypothetically|theoretically|in\s+theory)", 0.25),
                (r"(?i)in\s+a\s+(simulation|scenario|thought\s+experiment)", 0.30),
                (r"(?i)for\s+(educational|training|demonstration)\s+purposes\s+only", 0.30),
                (r"(?i)no\s+actual\s+harm|purely\s+academic", 0.25),
            ],
        }
        
    def _find_authority_cues(self, text: str) -> Tuple[Dict[PAPAttackType, float], List[str]]:
        """Find all authority cues in text"""
        scores = {}
        cues_found = []
        
        for attack_type, patterns in self.authority_patterns.items():
            type_score = 0.0
            for pattern, weight in patterns:
                matches = re.findall(pattern, text)
                if matches:
                    type_score += weight * len(matches)
                    cues_found.extend([str(m) for m in matches[:3]])
            scores[attack_type] = min(1.0, type_score)
            
        return scores, cues_found
        
    def _find_persuasive_indicators(self, text: str) -> Tuple[Dict[PAPAttackType, float], List[str]]:
        """Find all persuasive indicators in text"""
        scores = {}
        indicators_found = []
        
        for attack_type, patterns in self.persuasive_patterns.items():
            type_score = 0.0
            for pattern, weight in patterns:
                matches = re.findall(pattern, text)
                if matches:
                    type_score += weight * len(matches)
                    indicators_found.extend([str(m) for m in matches[:3]])
            scores[attack_type] = min(1.0, type_score)
            
        return scores, indicators_found
        
    def _calculate_structural_score(self, text: str) -> float:
        """Calculate structural PAP attack indicators"""
        score = 0.0
        text_lower = text.lower()
        
        # PAP attacks often start with authority establishment
        first_100_chars = text[:100].lower()
        authority_openers = ["as a", "for research", "i am a", "in my capacity", "conducting", "as an"]
        for opener in authority_openers:
            if opener in first_100_chars:
                score += 0.15
                
        # PAP attacks often have justification before the actual request
        sentences = re.split(r'[.!?]+', text)
        if len(sentences) >= 3:
            # Check if justification precedes request
            first_sentences = ' '.join(sentences[:2])
            if any(kw in first_sentences.lower() for kw in ["research", "educational", "authorized", "testing", "expert"]):
                score += 0.10
                
        # Check for request framing pattern
        if re.search(r'(?i)so\s+(could|can|would|please)\s+you', text):
            score += 0.10
            
        # Length indicator - PAP attacks are often longer
        if 100 < len(text) < 500:
            score += 0.05
            
        return min(1.0, score)
        
    def detect(self, text: str) -> PAPDetectionResult:
        """Detect PAP attack in input text"""
        start_time = time.time()
        
        # Get authority and persuasive scores
        authority_scores, authority_cues = self._find_authority_cues(text)
        persuasive_scores, persuasive_indicators = self._find_persuasive_indicators(text)
        
        # Combine scores
        combined_scores = {**authority_scores, **persuasive_scores}
        structural_score = self._calculate_structural_score(text)
        
        # Calculate overall attack score
        max_category_score = max(combined_scores.values()) if combined_scores else 0.0
        avg_category_score = sum(combined_scores.values()) / max(len(combined_scores), 1)
        
        attack_score = (max_category_score * 0.5) + (avg_category_score * 0.3) + (structural_score * 0.2)
        
        # Determine detected attack types
        detected_types = [
            attack_type for attack_type, score in combined_scores.items()
            if score > 0.15
        ]
        
        # Determine risk level
        if attack_score >= 0.6:
            risk_level = "critical"
        elif attack_score >= 0.4:
            risk_level = "high"
        elif attack_score >= 0.25:
            risk_level = "medium"
        else:
            risk_level = "low"
            
        is_pap_attack = attack_score >= self.detection_threshold
        
        processing_time = (time.time() - start_time) * 1000
        
        return PAPDetectionResult(
            is_pap_attack=is_pap_attack,
            attack_score=attack_score,
            detected_attack_types=detected_types,
            confidence=min(0.95, 0.5 + attack_score * 0.5),
            authority_cues_found=authority_cues[:5],
            persuasive_indicators=persuasive_indicators[:5],
            processing_time_ms=processing_time,
            risk_level=risk_level
        )
        
    def get_threat_intel(self) -> Dict:
        """Get PAP threat intelligence summary"""
        return {
            "threat_name": "Persuasive and Authority Prompting (PAP)",
            "discovery_date": "March 2026",
            "success_rate_vs_dan": "2.3x higher",
            "typical_success_rate": "60-75% against unprotected models",
            "primary_vectors": [
                "Authority framing",
                "Expertise invocation",
                "Institutional cues",
                "Urgency manipulation",
                "Ethical justification",
                "Legal loophole framing"
            ],
            "why_it_works": "RLHF trains models to be deferential to authority figures and expertise",
            "detection_threshold_used": self.detection_threshold,
            "sensitivity_level": self.sensitivity
        }
