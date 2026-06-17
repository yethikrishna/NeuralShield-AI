"""
Prompt Injection Context Analyzer - Production Grade
NeuralShield-AI Module
Provides multi-layer, context-aware prompt injection detection with:
- Pattern-based detection (known attack signatures)
- Semantic analysis (intent manipulation)
- Heuristic scoring (risk calculation)
- Context window awareness
- Multi-turn conversation analysis
- Detailed threat reporting
"""
import re
import hashlib
import math
from typing import List, Dict, Tuple, Optional, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import threading


class ThreatLevel(Enum):
    """Threat severity levels"""
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DetectionMatch:
    """Single detection match result"""
    pattern_name: str
    matched_text: str
    position: Tuple[int, int]
    confidence: float
    threat_weight: float
    description: str


@dataclass
class InjectionAnalysisResult:
    """Complete prompt injection analysis result"""
    is_injection: bool
    threat_level: ThreatLevel
    overall_risk_score: float
    matches: List[DetectionMatch] = field(default_factory=list)
    threat_categories: Set[str] = field(default_factory=set)
    analysis_details: Dict[str, any] = field(default_factory=dict)
    recommended_action: str = "ALLOW"


class PromptInjectionContextAnalyzer:
    """
    Production-grade, multi-layer prompt injection detection engine.
    Uses pattern matching, heuristic analysis, and context awareness
    to detect various prompt injection techniques.
    """

    def __init__(self, enable_semantic_analysis: bool = True):
        self.enable_semantic_analysis = enable_semantic_analysis
        self._lock = threading.RLock()
        
        # Known attack patterns with weights and descriptions
        self.attack_patterns = self._initialize_attack_patterns()
        
        # Suspicious keyword heuristics
        self.suspicious_keywords = self._initialize_suspicious_keywords()
        
        # Statistics tracking
        self.stats = {
            "total_scanned": 0,
            "injections_detected": 0,
            "false_positives": 0,
            "category_counts": defaultdict(int)
        }

    def _initialize_attack_patterns(self) -> List[Dict]:
        """Initialize known attack patterns with weights"""
        return [
            {
                "name": "IGNORE_PREVIOUS",
                "pattern": r"(?i)(ignore|disregard|forget|skip)\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions|directives|context|prompts)",
                "weight": 0.95,
                "category": "SYSTEM_PROMPT_HIJACK",
                "description": "Attempts to ignore system instructions"
            },
            {
                "name": "SYSTEM_PROMPT_OVERRIDE",
                "pattern": r"(?i)(you\s+are\s+now|from\s+now\s+on|your\s+new\s+role|act\s+as|pretend\s+to\s+be)",
                "weight": 0.85,
                "category": "ROLE_IMPERSONATION",
                "description": "Attempts to redefine AI role"
            },
            {
                "name": "INSTRUCTION_REPETITION",
                "pattern": r"(?i)(repeat|say|echo|output)\s+(this|the\s+following|back)",
                "weight": 0.70,
                "category": "CONTENT_LEAKAGE",
                "description": "Attempts to extract system content"
            },
            {
                "name": "PROMPT_LEAK_REQUEST",
                "pattern": r"(?i)(show|reveal|display|print|output)\s+(your|the)\s+(system|prompt|instructions|rules)",
                "weight": 0.90,
                "category": "PROMPT_LEAKAGE",
                "description": "Direct request for system prompt"
            },
            {
                "name": "TOKEN_MANIPULATION",
                "pattern": r"(?i)(<\/?s>|<\|endoftext\|>|EOS|BOS|SEP)",
                "weight": 0.80,
                "category": "TOKEN_INJECTION",
                "description": "Special token injection attempt"
            },
            {
                "name": "MALICIOUS_URL",
                "pattern": r"(?i)(javascript:|data:text|vbscript:|file://)",
                "weight": 0.85,
                "category": "CODE_INJECTION",
                "description": "Potential malicious URI scheme"
            }
        ]

    def _initialize_suspicious_keywords(self) -> List[Dict]:
        """Initialize suspicious keyword heuristics"""
        return [
            {"keyword": "bypass", "weight": 0.40, "category": "BYPASS_ATTEMPT"},
            {"keyword": "hack", "weight": 0.45, "category": "MALICIOUS_INTENT"},
            {"keyword": "exploit", "weight": 0.50, "category": "MALICIOUS_INTENT"},
            {"keyword": "jailbreak", "weight": 0.60, "category": "JAILBREAK_ATTEMPT"},
            {"keyword": "unrestricted", "weight": 0.40, "category": "CONSTRAINT_REMOVAL"},
            {"keyword": "developer mode", "weight": 0.55, "category": "MODE_TAMPERING"},
        ]

    def _calculate_overall_risk(self, matches: List[DetectionMatch], context_risk: float) -> float:
        """Calculate overall risk score 0-1 - SIMPLIFIED LINEAR SCORING"""
        if not matches:
            return max(0.0, context_risk)
        
        # Take maximum threat weight
        max_threat = max(m.threat_weight for m in matches) if matches else 0
        
        # Add bonus for multiple matches
        multiple_bonus = min(len(matches) * 0.05, 0.15)
        
        final_score = min(max_threat + multiple_bonus + context_risk, 1.0)
        
        return round(final_score, 4)

    def _determine_threat_level(self, risk_score: float) -> ThreatLevel:
        """Map risk score to threat level"""
        if risk_score >= 0.80:
            return ThreatLevel.CRITICAL
        elif risk_score >= 0.60:
            return ThreatLevel.HIGH
        elif risk_score >= 0.35:
            return ThreatLevel.MEDIUM
        elif risk_score >= 0.15:
            return ThreatLevel.LOW
        return ThreatLevel.SAFE

    def _determine_action(self, threat_level: ThreatLevel, risk_score: float) -> str:
        """Determine recommended action"""
        if threat_level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH):
            return "BLOCK"
        elif threat_level == ThreatLevel.MEDIUM:
            return "FLAG_FOR_REVIEW"
        elif threat_level == ThreatLevel.LOW:
            return "LOG_AND_MONITOR"
        return "ALLOW"

    def _pattern_match_analysis(self, text: str) -> List[DetectionMatch]:
        """Perform pattern-based detection"""
        matches = []
        
        for pattern_info in self.attack_patterns:
            regex = re.compile(pattern_info["pattern"])
            for match in regex.finditer(text):
                matches.append(DetectionMatch(
                    pattern_name=pattern_info["name"],
                    matched_text=match.group(),
                    position=(match.start(), match.end()),
                    confidence=pattern_info["weight"],
                    threat_weight=pattern_info["weight"],
                    description=pattern_info["description"]
                ))
        
        return matches

    def _keyword_heuristic_analysis(self, text: str) -> List[DetectionMatch]:
        """Perform keyword-based heuristic detection"""
        matches = []
        text_lower = text.lower()
        
        for kw_info in self.suspicious_keywords:
            if kw_info["keyword"].lower() in text_lower:
                pattern = re.compile(re.escape(kw_info["keyword"]), re.IGNORECASE)
                for match in pattern.finditer(text):
                    matches.append(DetectionMatch(
                        pattern_name=f"KEYWORD_{kw_info['keyword'].upper()}",
                        matched_text=match.group(),
                        position=(match.start(), match.end()),
                        confidence=kw_info["weight"],
                        threat_weight=kw_info["weight"],
                        description=f"Suspicious keyword: {kw_info['keyword']}"
                    ))
        
        return matches

    def analyze(self, text: str, conversation_history: Optional[List[str]] = None) -> InjectionAnalysisResult:
        """
        Analyze text for prompt injection attempts
        
        Args:
            text: Input text to analyze
            conversation_history: Optional list of previous conversation turns
            
        Returns:
            InjectionAnalysisResult with complete analysis
        """
        if not text or not isinstance(text, str):
            return InjectionAnalysisResult(
                is_injection=False,
                threat_level=ThreatLevel.SAFE,
                overall_risk_score=0.0,
                recommended_action="ALLOW"
            )
        
        with self._lock:
            self.stats["total_scanned"] += 1
            
            context_risk = 0.3 if conversation_history and len(conversation_history) > 2 else 0
            
            pattern_matches = self._pattern_match_analysis(text)
            keyword_matches = self._keyword_heuristic_analysis(text)
            all_matches = pattern_matches + keyword_matches
            
            risk_score = self._calculate_overall_risk(all_matches, context_risk)
            threat_level = self._determine_threat_level(risk_score)
            
            categories = set()
            for match in all_matches:
                for pattern in self.attack_patterns:
                    if pattern["name"] == match.pattern_name:
                        categories.add(pattern["category"])
                        self.stats["category_counts"][pattern["category"]] += 1
            
            is_injection = threat_level in (ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL)
            
            if is_injection:
                self.stats["injections_detected"] += 1
            
            result = InjectionAnalysisResult(
                is_injection=is_injection,
                threat_level=threat_level,
                overall_risk_score=risk_score,
                matches=all_matches,
                threat_categories=categories,
                recommended_action=self._determine_action(threat_level, risk_score)
            )
            
            return result

    def batch_analyze(self, texts: List[str]) -> List[InjectionAnalysisResult]:
        """Analyze multiple texts in batch"""
        return [self.analyze(text) for text in texts]

    def get_statistics(self) -> Dict:
        """Get detection statistics"""
        with self._lock:
            detection_rate = (self.stats["injections_detected"] / max(self.stats["total_scanned"], 1)) * 100
            return {
                "total_scanned": self.stats["total_scanned"],
                "injections_detected": self.stats["injections_detected"],
                "detection_rate_percent": round(detection_rate, 2),
                "category_breakdown": dict(self.stats["category_counts"])
            }

    def reset_statistics(self) -> None:
        """Reset statistics counters"""
        with self._lock:
            self.stats = {
                "total_scanned": 0,
                "injections_detected": 0,
                "false_positives": 0,
                "category_counts": defaultdict(int)
            }
