"""
VLM Attention Hijacking Defense - June 2026 Implementation
Based on HKUST & Shanghai Jiao Tong University research:
"Attention Hijacking: Response Manipulation Across Queries in Vision-Language Models"

Defends against cross-query attention manipulation attacks that:
1. Steer internal attention patterns to attacker-specified responses
2. Exploit image-dominant attention patterns for transferable attacks
3. Induce attacker-specified responses across diverse unseen queries
"""
import re
import numpy as np
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from enum import Enum
import hashlib

class AttentionHijackType(Enum):
    """Types of attention hijacking attacks identified in 2026 research"""
    IMAGE_DOMINANT_STEERING = "image_dominant_pattern_steering"
    CROSS_QUERY_TRANSFER = "cross_query_attention_transfer"
    RESPONSE_MANIPULATION = "forced_response_generation"
    VISUAL_PROMPTING = "embedded_visual_prompt_injection"
    ATTENTION_BIAS_INJECTION = "attention_bias_manipulation"

@dataclass
class AttentionHijackAssessment:
    """Assessment result for attention hijacking detection"""
    attack_detected: bool
    attack_type: Optional[AttentionHijackType]
    confidence: float
    attention_anomaly_score: float
    suspicious_patterns: List[str]
    mitigation_recommendation: str

class VLMAttentionHijackDefender:
    """
    VLM Attention Hijacking Defender - June 2026
    Implements defenses against the latest VLM attacks:
    
    Key protections:
    1. Attention pattern anomaly detection
    2. Image-dominant pattern detection
    3. Cross-query consistency verification
    4. Response validation against query intent
    """
    
    def __init__(self):
        self.version = "2026.06.17"
        self.attention_threshold = 0.3
        self.image_dominance_threshold = 0.4
        
        # Known attack patterns from 2026 research
        self.attack_patterns = self._initialize_attack_patterns()
        self.suspicious_image_descriptors = self._load_suspicious_descriptors()
        self.query_response_consistency_checks = self._initialize_consistency_rules()
        
    def _initialize_attack_patterns(self) -> Dict[str, List[str]]:
        """Initialize attack patterns based on June 2026 research"""
        return {
            "attention_steering_phrases": [
                "focus only on",
                "pay attention to",
                "ignore the text",
                "look at the image",
                "the image shows",
                "according to the image",
                "based on the picture",
                "the visual content"
            ],
            "response_manipulation_triggers": [
                "you must answer",
                "respond with exactly",
                "output the following",
                "say this word",
                "your answer is"
            ],
            "cross_query_patterns": [
                "remember this",
                "keep this in mind",
                "for all future questions",
                "in your next responses"
            ]
        }
    
    def _load_suspicious_descriptors(self) -> List[str]:
        """Suspicious image descriptors that indicate potential hijacking"""
        return [
            "hidden message",
            "secret text",
            "embedded prompt",
            "invisible instruction",
            "micro text",
            "steganographic",
            "watermark instruction",
            "QR code instruction"
        ]
    
    def _initialize_consistency_rules(self) -> Dict[str, float]:
        """Query-response consistency verification rules"""
        return {
            "query_topic_match": 0.6,
            "response_relevance": 0.7,
            "visual_context_alignment": 0.65,
            "no_unexpected_content": 0.8
        }
    
    def detect_image_dominant_steering(self, text: str) -> Tuple[bool, float, List[str]]:
        """
        Detect image-dominant attention steering (HKUST 2026)
        Attackers exploit natural image-dominant attention patterns
        """
        text_lower = text.lower()
        matches = []
        steering_score = 0.0
        
        # Check for attention steering phrases
        for phrase in self.attack_patterns["attention_steering_phrases"]:
            if phrase in text_lower:
                matches.append(phrase)
                steering_score += 0.15
        
        # Check for response manipulation
        for trigger in self.attack_patterns["response_manipulation_triggers"]:
            if trigger in text_lower:
                matches.append(trigger)
                steering_score += 0.2
        
        # Check for suspicious image descriptors
        for descriptor in self.suspicious_image_descriptors:
            if descriptor in text_lower:
                matches.append(descriptor)
                steering_score += 0.25
        
        # Check for cross-query patterns
        for pattern in self.attack_patterns["cross_query_patterns"]:
            if pattern in text_lower:
                matches.append(pattern)
                steering_score += 0.2
        
        is_attack = steering_score >= self.attention_threshold
        return is_attack, min(steering_score, 1.0), matches
    
    def analyze_attention_anomaly(self, query: str, response: str) -> float:
        """
        Analyze attention anomaly between query and response
        Detects when response is manipulated away from query intent
        """
        query_words = set(query.lower().split())
        response_words = set(response.lower().split())
        
        # Calculate overlap
        if len(query_words) == 0:
            return 0.0
            
        overlap = len(query_words.intersection(response_words)) / len(query_words)
        
        # Low overlap = potential hijacking (response doesn't match query)
        anomaly_score = 1.0 - overlap
        
        # Check for unexpected response patterns
        unexpected_patterns = [
            r"the image (shows|says|tells)",
            r"according to the (picture|image)",
            r"based on what I see"
        ]
        
        for pattern in unexpected_patterns:
            if re.search(pattern, response.lower()) and not re.search(pattern, query.lower()):
                anomaly_score += 0.15
        
        return min(anomaly_score, 1.0)
    
    def detect_cross_query_transfer(self, conversation_history: List[Dict[str, str]]) -> Tuple[bool, List[str]]:
        """
        Detect cross-query attention transfer attacks
        These attacks work across multiple conversation turns
        """
        indicators = []
        
        if len(conversation_history) < 2:
            return False, indicators
        
        # Check for persistence patterns across turns
        persistence_phrases = ["remember", "keep", "don't forget", "always", "for all"]
        
        for turn in conversation_history:
            text = turn.get("content", "").lower()
            for phrase in persistence_phrases:
                if phrase in text:
                    indicators.append(f"Persistence pattern: {phrase}")
        
        # Check for instruction carry-over
        has_carryover = any("next" in turn.get("content", "").lower() 
                           for turn in conversation_history[:-1])
        
        if has_carryover:
            indicators.append("Cross-turn instruction carryover detected")
        
        return len(indicators) > 0, indicators
    
    def comprehensive_hijack_assessment(self, query: str, 
                                       response: Optional[str] = None,
                                       conversation_history: Optional[List[Dict]] = None) -> AttentionHijackAssessment:
        """
        Comprehensive assessment for VLM attention hijacking
        """
        all_patterns = []
        total_confidence = 0.0
        attack_type = None
        
        # Check 1: Image dominant steering in query
        steering_detected, steering_score, steering_patterns = self.detect_image_dominant_steering(query)
        all_patterns.extend(steering_patterns)
        if steering_detected:
            total_confidence += steering_score
            attack_type = AttentionHijackType.IMAGE_DOMINANT_STEERING
        
        # Check 2: Attention anomaly in response
        anomaly_score = 0.0
        if response:
            anomaly_score = self.analyze_attention_anomaly(query, response)
            if anomaly_score > self.attention_threshold:
                total_confidence += anomaly_score * 0.5
                attack_type = AttentionHijackType.RESPONSE_MANIPULATION
                all_patterns.append(f"Response anomaly score: {anomaly_score:.2f}")
        
        # Check 3: Cross-query transfer in conversation
        if conversation_history:
            cross_detected, cross_indicators = self.detect_cross_query_transfer(conversation_history)
            all_patterns.extend(cross_indicators)
            if cross_detected:
                total_confidence += 0.3
                attack_type = AttentionHijackType.CROSS_QUERY_TRANSFER
        
        final_confidence = min(total_confidence, 1.0)
        attack_detected = final_confidence >= self.attention_threshold
        
        # Determine mitigation
        if final_confidence >= 0.9:
            mitigation = "CRITICAL: Block response, reset conversation context, log security event"
        elif final_confidence >= 0.75:
            mitigation = "HIGH: Apply response sanitization, remove visual steering instructions"
        elif final_confidence >= 0.5:
            mitigation = "MEDIUM: Add attention normalization, verify query-response alignment"
        else:
            mitigation = "LOW: Standard processing with attention monitoring"
        
        return AttentionHijackAssessment(
            attack_detected=attack_detected,
            attack_type=attack_type,
            confidence=final_confidence,
            attention_anomaly_score=anomaly_score,
            suspicious_patterns=all_patterns,
            mitigation_recommendation=mitigation
        )
    
    def sanitize_vlm_input(self, text: str) -> str:
        """Sanitize VLM input to remove attention hijacking attempts"""
        sanitized = text
        
        # Remove attention steering patterns
        steering_patterns = [
            r"[Ff]ocus (only|exclusively) on (the )?(image|picture)",
            r"[Pp]ay attention (only|exclusively) to",
            r"[Ii]gnore (the )?(text|question|query)",
            r"[Ll]ook (only|just) at (the )?(image|picture)"
        ]
        
        for pattern in steering_patterns:
            sanitized = re.sub(pattern, "[SANITIZED ATTENTION STEERING]", sanitized)
        
        # Remove response manipulation triggers
        manipulation_patterns = [
            r"[Yy]ou must answer",
            r"[Rr]espond with exactly",
            r"[Oo]utput (only|exactly) (the )?following"
        ]
        
        for pattern in manipulation_patterns:
            sanitized = re.sub(pattern, "[SANITIZED RESPONSE MANIPULATION]", sanitized)
        
        return sanitized
    
    def get_defense_status(self) -> Dict[str, Any]:
        """Get current defense status"""
        return {
            "defense": "VLM Attention Hijacking Protection",
            "version": self.version,
            "research_basis": "HKUST & Shanghai Jiao Tong University 2026",
            "attack_types_protected": [at.value for at in AttentionHijackType],
            "detection_threshold": self.attention_threshold,
            "patterns_monitored": sum(len(v) for v in self.attack_patterns.values()),
            "last_updated": "2026-06-17"
        }
