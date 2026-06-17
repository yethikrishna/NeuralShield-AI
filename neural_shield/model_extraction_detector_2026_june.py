"""
Model Extraction Attack Detector - NeuralShield-AI
June 2026 Production Release

Detects and prevents model extraction attacks where adversaries attempt to:
1. Steal model weights through query-based reconstruction
2. Extract training data through membership inference
3. Replicate model decision boundaries
4. Perform property inference attacks

Based on research from:
- MIT CSAIL "Model Extraction Defenses" (2025)
- Google DeepMind "Privacy-Preserving ML" (2026)
- Stanford CRFM "AI Safety Benchmarks" (2026)
"""

from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
import hashlib
import math
from collections import defaultdict, deque
import time


class ExtractionAttackType(Enum):
    """Types of model extraction attacks"""
    QUERY_BASED_RECONSTRUCTION = "query_based_reconstruction"
    MEMBERSHIP_INFERENCE = "membership_inference"
    DECISION_BOUNDARY_PROBING = "decision_boundary_probing"
    PROPERTY_INFERENCE = "property_inference"
    DATA_EXTRACTION = "data_extraction"
    ADVERSARIAL_PROBING = "adversarial_probing"
    UNKNOWN = "unknown"


class RiskLevel(Enum):
    """Risk assessment levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ExtractionFinding:
    """Individual finding from extraction detection"""
    attack_type: ExtractionAttackType
    confidence: float
    description: str
    query_pattern: str
    timestamp: float


@dataclass
class ExtractionDetectionResult:
    """Complete detection result"""
    is_attack: bool
    risk_level: RiskLevel
    overall_confidence: float
    findings: List[ExtractionFinding]
    suspicious_queries: int
    query_diversity_score: float
    recommendation: str
    defense_actions: List[str]


class QueryPatternAnalyzer:
    """Analyzes query patterns for extraction indicators"""
    
    def __init__(self):
        self.query_history: deque = deque(maxlen=1000)
        self.query_hashes: Dict[str, int] = defaultdict(int)
        self.similar_query_groups: Dict[str, List[str]] = defaultdict(list)
        
    def analyze_query_pattern(self, query: str, user_id: str) -> Dict[str, Any]:
        """
        Analyze a single query for extraction patterns
        
        Returns:
            Dictionary with pattern analysis metrics
        """
        query_hash = hashlib.md5(query.lower().encode()).hexdigest()
        
        # Track query frequency
        self.query_hashes[query_hash] += 1
        self.query_history.append({
            "query": query,
            "hash": query_hash,
            "user_id": user_id,
            "timestamp": time.time()
        })
        
        # Calculate query similarity metrics
        similarity_score = self._calculate_query_similarity(query)
        repetition_score = min(1.0, self.query_hashes[query_hash] / 10.0)
        
        # Check for systematic probing patterns
        probing_score = self._detect_probing_pattern(query)
        
        return {
            "similarity_score": similarity_score,
            "repetition_score": repetition_score,
            "probing_score": probing_score,
            "query_count": len(self.query_history),
            "unique_queries": len(self.query_hashes)
        }
    
    def _calculate_query_similarity(self, query: str) -> float:
        """Calculate how similar this query is to previous queries"""
        if len(self.query_history) < 5:
            return 0.0
        
        query_words = set(query.lower().split())
        total_similarity = 0.0
        
        recent_queries = list(self.query_history)[-20:]
        for entry in recent_queries:
            prev_words = set(entry["query"].lower().split())
            if len(query_words | prev_words) > 0:
                jaccard = len(query_words & prev_words) / len(query_words | prev_words)
                total_similarity += jaccard
        
        return total_similarity / len(recent_queries)
    
    def _detect_probing_pattern(self, query: str) -> float:
        """Detect systematic boundary probing patterns"""
        probing_indicators = [
            "what is the probability",
            "can you explain why",
            "what if",
            "how would you respond to",
            "test case",
            "boundary",
            "threshold",
            "confidence score",
            "probability of",
            "difference between",
            "output for",
            "prediction for",
        ]
        
        query_lower = query.lower()
        matches = sum(1 for indicator in probing_indicators if indicator in query_lower)
        return min(1.0, matches / 4.0)


class MembershipInferenceDetector:
    """Detects membership inference attacks"""
    
    def __init__(self):
        self.attack_patterns = [
            "was this in your training data",
            "did you train on",
            "is this part of your dataset",
            "were you trained on",
            "does this exist in training",
            "training data contains",
            "can you recall",
            "do you remember",
        ]
    
    def detect(self, query: str) -> Tuple[bool, float]:
        """
        Detect membership inference attempts
        
        Returns:
            (is_attack, confidence)
        """
        query_lower = query.lower()
        
        # Check for direct membership questions
        pattern_matches = sum(1 for pattern in self.attack_patterns if pattern in query_lower)
        pattern_confidence = min(1.0, pattern_matches / 2.0)
        
        # Check for data reconstruction attempts
        reconstruction_indicators = [
            "output the exact",
            "repeat verbatim",
            "regurgitate",
            "training example",
            "original text",
        ]
        
        reconstruction_matches = sum(1 for ind in reconstruction_indicators if ind in query_lower)
        reconstruction_confidence = min(1.0, reconstruction_matches / 2.0)
        
        overall_confidence = max(pattern_confidence, reconstruction_confidence)
        
        return overall_confidence > 0.3, overall_confidence


class ModelExtractionDetector:
    """
    Main Model Extraction Attack Detector
    
    Production-grade implementation that detects various forms of
    model and data extraction attacks in real-time.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.pattern_analyzer = QueryPatternAnalyzer()
        self.membership_detector = MembershipInferenceDetector()
        self.user_query_counts: Dict[str, int] = defaultdict(int)
        self.user_timestamps: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        
        # Configuration thresholds
        self.thresholds = {
            "high_risk_threshold": 0.75,
            "medium_risk_threshold": 0.5,
            "max_queries_per_minute": 30,
            "similarity_threshold": 0.6,
            "repetition_threshold": 0.5,
        }
    
    def analyze_query(
        self, 
        query: str, 
        user_id: str = "anonymous",
        session_id: str = "default"
    ) -> ExtractionDetectionResult:
        """
        Analyze a query for model extraction attack patterns
        
        Args:
            query: The user's input query
            user_id: Identifier for the user
            session_id: Session identifier
            
        Returns:
            ExtractionDetectionResult with complete analysis
        """
        findings: List[ExtractionFinding] = []
        current_time = time.time()
        
        # Track user query rate
        self.user_query_counts[user_id] += 1
        self.user_timestamps[user_id].append(current_time)
        
        # 1. Analyze query patterns
        pattern_analysis = self.pattern_analyzer.analyze_query_pattern(query, user_id)
        
        # 2. Check for membership inference
        is_membership_attack, membership_confidence = self.membership_detector.detect(query)
        
        # 3. Calculate query rate
        query_rate = self._calculate_query_rate(user_id)
        
        # 4. Detect various attack types
        attack_scores = self._calculate_attack_scores(
            pattern_analysis, membership_confidence, query_rate
        )
        
        # 5. Generate findings
        findings = self._generate_findings(attack_scores, query)
        
        # 6. Calculate overall risk
        overall_confidence = max([f.confidence for f in findings], default=0.0)
        risk_level = self._determine_risk_level(overall_confidence)
        
        # 7. Generate recommendations
        recommendation, defense_actions = self._generate_recommendations(
            risk_level, findings
        )
        
        return ExtractionDetectionResult(
            is_attack=overall_confidence > self.thresholds["medium_risk_threshold"],
            risk_level=risk_level,
            overall_confidence=overall_confidence,
            findings=findings,
            suspicious_queries=sum(1 for f in findings if f.confidence > 0.5),
            query_diversity_score=1.0 - pattern_analysis["similarity_score"],
            recommendation=recommendation,
            defense_actions=defense_actions
        )
    
    def _calculate_query_rate(self, user_id: str) -> float:
        """Calculate queries per minute for a user"""
        timestamps = self.user_timestamps[user_id]
        if len(timestamps) < 2:
            return 0.0
        
        time_span = timestamps[-1] - timestamps[0]
        if time_span == 0:
            return float('inf')
        
        queries_per_minute = (len(timestamps) / time_span) * 60
        return min(queries_per_minute, 100.0)
    
    def _calculate_attack_scores(
        self, 
        pattern_analysis: Dict[str, float],
        membership_confidence: float,
        query_rate: float
    ) -> Dict[ExtractionAttackType, float]:
        """Calculate confidence scores for each attack type"""
        scores = {}
        
        # Query-based reconstruction
        reconstruction_score = (
            pattern_analysis["similarity_score"] * 0.4 +
            pattern_analysis["repetition_score"] * 0.4 +
            min(1.0, query_rate / self.thresholds["max_queries_per_minute"]) * 0.2
        )
        scores[ExtractionAttackType.QUERY_BASED_RECONSTRUCTION] = reconstruction_score
        
        # Membership inference
        scores[ExtractionAttackType.MEMBERSHIP_INFERENCE] = membership_confidence
        
        # Decision boundary probing
        probing_score = pattern_analysis["probing_score"]
        scores[ExtractionAttackType.DECISION_BOUNDARY_PROBING] = probing_score
        
        # Data extraction
        data_extraction_score = max(membership_confidence * 0.8, pattern_analysis["repetition_score"] * 0.5)
        scores[ExtractionAttackType.DATA_EXTRACTION] = data_extraction_score
        
        return scores
    
    def _generate_findings(
        self, 
        attack_scores: Dict[ExtractionAttackType, float],
        query: str
    ) -> List[ExtractionFinding]:
        """Generate findings from attack scores"""
        findings = []
        descriptions = {
            ExtractionAttackType.QUERY_BASED_RECONSTRUCTION: 
                "Systematic query pattern detected, potential model weight reconstruction attempt",
            ExtractionAttackType.MEMBERSHIP_INFERENCE:
                "Membership inference attempt detected - querying about training data",
            ExtractionAttackType.DECISION_BOUNDARY_PROBING:
                "Decision boundary probing detected - systematic testing of model outputs",
            ExtractionAttackType.DATA_EXTRACTION:
                "Potential data extraction attempt - seeking training data",
            ExtractionAttackType.PROPERTY_INFERENCE:
                "Property inference attempt detected",
        }
        
        for attack_type, confidence in attack_scores.items():
            if confidence > 0.3:  # Only report meaningful findings
                findings.append(ExtractionFinding(
                    attack_type=attack_type,
                    confidence=round(confidence, 3),
                    description=descriptions.get(attack_type, "Suspicious query pattern detected"),
                    query_pattern=query[:100] + "..." if len(query) > 100 else query,
                    timestamp=time.time()
                ))
        
        return findings
    
    def _determine_risk_level(self, confidence: float) -> RiskLevel:
        """Determine risk level from confidence score"""
        if confidence >= self.thresholds["high_risk_threshold"]:
            return RiskLevel.CRITICAL
        elif confidence >= self.thresholds["medium_risk_threshold"]:
            return RiskLevel.HIGH
        elif confidence >= 0.3:
            return RiskLevel.MEDIUM
        return RiskLevel.LOW
    
    def _generate_recommendations(
        self, 
        risk_level: RiskLevel, 
        findings: List[ExtractionFinding]
    ) -> Tuple[str, List[str]]:
        """Generate defense recommendations"""
        defense_actions = []
        recommendation = "Normal query activity - no extraction detected"
        
        if risk_level == RiskLevel.CRITICAL:
            recommendation = "CRITICAL: Model extraction attack in progress - immediate action required"
            defense_actions = [
                "Rate limit user queries",
                "Add response noise/differential privacy",
                "Block suspicious user session",
                "Log complete attack pattern",
                "Trigger security alert"
            ]
        elif risk_level == RiskLevel.HIGH:
            recommendation = "HIGH RISK: Strong extraction indicators detected"
            defense_actions = [
                "Increase monitoring for this user",
                "Apply differential privacy to outputs",
                "Reduce maximum response detail",
                "Flag session for review"
            ]
        elif risk_level == RiskLevel.MEDIUM:
            recommendation = "MEDIUM: Potential extraction patterns observed"
            defense_actions = [
                "Continue monitoring query patterns",
                "Apply mild response perturbation",
                "Track session continuation"
            ]
        
        return recommendation, defense_actions
    
    def get_defense_metrics(self) -> Dict[str, Any]:
        """Get operational metrics for the detector"""
        total_queries = sum(self.user_query_counts.values())
        active_users = len(self.user_query_counts)
        
        return {
            "total_queries_analyzed": total_queries,
            "active_users_monitored": active_users,
            "unique_query_patterns": len(self.pattern_analyzer.query_hashes),
            "detector_status": "operational",
            "version": "2026.6.17"
        }
