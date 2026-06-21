"""
NeuralShield-AI: Threat Intelligence Hunting Query Explainability Engine v1
Production-grade implementation for explaining hunting query matches and detections.
Provides transparent, human-readable explanations for why security rules and queries trigger.

Features:
- Query match reasoning and explanation generation
- Pattern matching breakdown with confidence scoring
- Rule execution trace and decision path visualization
- False positive risk assessment and mitigation suggestions
- Query optimization recommendations
- Batch explanation processing with caching
- Export to structured JSON for SIEM integration
"""
import re
import hashlib
import threading
import time
import json
from collections import OrderedDict, defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from functools import lru_cache


class ExplanationType(Enum):
    PATTERN_MATCH = "pattern_match"
    ANOMALY_DETECTION = "anomaly_detection"
    BEHAVIORAL = "behavioral"
    CORRELATION = "correlation"
    THRESHOLD = "threshold"
    SIGNATURE = "signature"


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MatchComponent:
    component_id: str
    pattern: str
    matched_value: str
    confidence: float
    description: str
    start_pos: int = 0
    end_pos: int = 0


@dataclass
class ExplanationResult:
    query_id: str
    query_name: str
    explanation_type: ExplanationType
    overall_confidence: float
    risk_level: RiskLevel
    match_components: List[MatchComponent] = field(default_factory=list)
    reasoning: List[str] = field(default_factory=list)
    false_positive_indicators: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    execution_trace: List[Dict[str, Any]] = field(default_factory=list)
    processing_time_ms: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class HuntingQueryExplainabilityEngine:
    """
    Production-grade hunting query explainability engine that provides
    transparent reasoning for security detections.
    """
    
    def __init__(self, cache_size: int = 10000):
        self.cache_size = cache_size
        self._lock = threading.RLock()
        self._explanation_cache = OrderedDict()
        self._stats = defaultdict(int)
        self._pattern_library = self._initialize_pattern_library()
        self._false_positive_patterns = self._initialize_fp_patterns()
        self._recommendation_rules = self._initialize_recommendation_rules()
        self._initialized_at = datetime.utcnow()
    
    def _initialize_pattern_library(self) -> Dict[str, Dict[str, Any]]:
        """Initialize security pattern library with explanation metadata."""
        return {
            "suspicious_process": {
                "patterns": [
                    r"(powershell|cmd)\.exe.*-enc",
                    r"rundll32\.exe.*javascript",
                    r"mshta\.exe.*http",
                    r"regsvr32\.exe.*\/s.*http",
                    r"certutil\.exe.*-urlcache"
                ],
                "description": "Suspicious process execution patterns",
                "explanation": "Living-off-the-land binary (LoLBins) execution detected",
                "risk_level": RiskLevel.HIGH
            },
            "network_anomaly": {
                "patterns": [
                    r"outbound.*port.*(4444|139|445|3389).*external",
                    r"dns.*query.*random.*subdomain",
                    r"multiple.*failed.*authentication",
                    r"unusual.*user-agent.*curl|wget|python"
                ],
                "description": "Network anomaly patterns",
                "explanation": "Unusual network behavior detected",
                "risk_level": RiskLevel.MEDIUM
            },
            "registry_modification": {
                "patterns": [
                    r"reg.*add.*HKLM.*Run",
                    r"reg.*add.*HKCU.*Run",
                    r"registry.*Image File Execution Options",
                    r"DisableRealtimeMonitoring.*1"
                ],
                "description": "Suspicious registry modifications",
                "explanation": "Persistence or security disable attempt detected",
                "risk_level": RiskLevel.HIGH
            },
            "file_system": {
                "patterns": [
                    r"file.*created.*temp.*\.exe",
                    r"file.*created.*%appdata%.*\.dll",
                    r"extension.*renamed.*txt.*exe",
                    r"macro.*enabled.*document.*downloaded"
                ],
                "description": "Suspicious filesystem activity",
                "explanation": "Potential malware staging or execution detected",
                "risk_level": RiskLevel.MEDIUM
            },
            "credential_access": {
                "patterns": [
                    r"lsass\.exe.*memory.*read",
                    r"mimikatz|sekurlsa",
                    r"procdump.*lsass",
                    r"ntds\.dit.*export"
                ],
                "description": "Credential access patterns",
                "explanation": "Credential theft or dumping activity detected",
                "risk_level": RiskLevel.CRITICAL
            },
            "lateral_movement": {
                "patterns": [
                    r"wmic.*process.*call.*create",
                    r"winrs.*remote",
                    r"psexec.*\\\\",
                    r"smb.*connection.*admin\\$"
                ],
                "description": "Lateral movement patterns",
                "explanation": "Potential lateral movement attempt detected",
                "risk_level": RiskLevel.HIGH
            }
        }
    
    def _initialize_fp_patterns(self) -> List[Dict[str, Any]]:
        """Initialize false positive indicator patterns."""
        return [
            {
                "pattern": r"administrator.*legitimate",
                "indicator": "Admin activity context present",
                "weight": 0.3
            },
            {
                "pattern": r"backup.*maintenance",
                "indicator": "Maintenance/backup context",
                "weight": 0.25
            },
            {
                "pattern": r"software.*installation",
                "indicator": "Software installation context",
                "weight": 0.2
            },
            {
                "pattern": r"test.*development",
                "indicator": "Test/development environment",
                "weight": 0.35
            },
            {
                "pattern": r"known.*vendor.*signed",
                "indicator": "Known signed vendor binary",
                "weight": 0.4
            },
            {
                "pattern": r"whitelisted.*approved",
                "indicator": "Whitelisted application",
                "weight": 0.45
            }
        ]
    
    def _initialize_recommendation_rules(self) -> Dict[str, List[str]]:
        """Initialize mitigation and optimization recommendations."""
        return {
            "suspicious_process": [
                "Enable process command-line logging for full visibility",
                "Implement application whitelisting for critical systems",
                "Review parent-child process relationships",
                "Check for unusual working directories"
            ],
            "network_anomaly": [
                "Implement network segmentation",
                "Enable DNS query logging",
                "Review firewall and proxy logs",
                "Consider geo-IP blocking for suspicious regions"
            ],
            "registry_modification": [
                "Enable registry change auditing",
                "Implement registry monitoring tools",
                "Review persistence mechanisms regularly",
                "Consider application control policies"
            ],
            "credential_access": [
                "Enable LSA protection",
                "Implement Credential Guard",
                "Restrict debug privileges",
                "Monitor LSASS memory access"
            ],
            "lateral_movement": [
                "Disable unnecessary remote administration tools",
                "Implement network segmentation",
                "Enable detailed SMB logging",
                "Review privileged group memberships"
            ],
            "default": [
                "Tune query thresholds to reduce noise",
                "Add contextual enrichment fields",
                "Implement frequency analysis baselines",
                "Consider whitelisting known benign activity"
            ]
        }
    
    @lru_cache(maxsize=1000)
    def _calculate_pattern_confidence(self, pattern: str, matched_text: str, context_length: int) -> float:
        """Calculate confidence score for a pattern match."""
        base_confidence = 0.7
        
        # Pattern specificity scoring
        pattern_length = len(pattern)
        if pattern_length > 30:
            base_confidence += 0.15
        elif pattern_length > 20:
            base_confidence += 0.1
        elif pattern_length > 10:
            base_confidence += 0.05
        
        # Context scoring
        if context_length > 100:
            base_confidence += 0.05
        
        # Special character density (regex specificity)
        special_chars = len(re.findall(r'[.*+?^${}()|\[\]\\]', pattern))
        if special_chars > 3:
            base_confidence += 0.05
        
        return min(base_confidence, 1.0)
    
    def _extract_match_context(self, full_text: str, match_start: int, match_end: int, context_chars: int = 50) -> str:
        """Extract contextual text around a match."""
        context_start = max(0, match_start - context_chars)
        context_end = min(len(full_text), match_end + context_chars)
        
        prefix = "..." if context_start > 0 else ""
        suffix = "..." if context_end < len(full_text) else ""
        
        return prefix + full_text[context_start:context_end] + suffix
    
    def explain_query_match(
        self,
        query_id: str,
        query_name: str,
        raw_event_data: str,
        query_patterns: Optional[List[str]] = None,
        explanation_type: ExplanationType = ExplanationType.SIGNATURE
    ) -> ExplanationResult:
        """
        Generate a detailed explanation for a hunting query match.
        
        Args:
            query_id: Unique query identifier
            query_name: Human-readable query name
            raw_event_data: Raw event/log data that triggered the match
            query_patterns: Optional list of patterns to check (uses library if None)
            explanation_type: Type of detection being explained
        
        Returns:
            ExplanationResult with full reasoning and breakdown
        """
        start_time = time.time()
        
        result = ExplanationResult(
            query_id=query_id,
            query_name=query_name,
            explanation_type=explanation_type,
            overall_confidence=0.0,
            risk_level=RiskLevel.LOW
        )
        
        execution_trace = []
        
        # Step 1: Pattern matching phase
        execution_trace.append({
            "phase": "pattern_matching",
            "status": "started",
            "timestamp": datetime.utcnow().isoformat()
        })
        
        patterns_to_check = query_patterns or []
        if not patterns_to_check:
            # Use pattern library
            for category, info in self._pattern_library.items():
                for pattern in info["patterns"]:
                    patterns_to_check.append((pattern, category, info))
        
        matched_categories = set()
        total_confidence = 0.0
        match_count = 0
        
        for pattern_item in patterns_to_check:
            if isinstance(pattern_item, tuple):
                pattern, category, info = pattern_item
            else:
                pattern = pattern_item
                category = "custom"
                info = {"description": "Custom pattern", "explanation": "Custom pattern matched"}
            
            try:
                regex = re.compile(pattern, re.IGNORECASE)
                for match in regex.finditer(raw_event_data):
                    confidence = self._calculate_pattern_confidence(
                        pattern, match.group(), len(raw_event_data)
                    )
                    
                    component = MatchComponent(
                        component_id=f"match_{hashlib.md5(pattern.encode()).hexdigest()[:8]}",
                        pattern=pattern,
                        matched_value=match.group(),
                        confidence=confidence,
                        description=info["explanation"],
                        start_pos=match.start(),
                        end_pos=match.end()
                    )
                    result.match_components.append(component)
                    
                    if category != "custom":
                        matched_categories.add(category)
                    
                    total_confidence += confidence
                    match_count += 1
                    
                    execution_trace.append({
                        "phase": "pattern_match_found",
                        "pattern": pattern[:50],
                        "confidence": confidence,
                        "matched_value": match.group()[:50]
                    })
            
            except re.error as e:
                execution_trace.append({
                    "phase": "pattern_error",
                    "pattern": pattern[:50],
                    "error": str(e)
                })
        
        execution_trace.append({
            "phase": "pattern_matching",
            "status": "completed",
            "matches_found": match_count
        })
        
        # Step 2: Calculate overall confidence and risk
        if match_count > 0:
            result.overall_confidence = total_confidence / match_count
            
            # Determine risk level based on matched categories
            max_risk = RiskLevel.LOW
            for category in matched_categories:
                if category in self._pattern_library:
                    cat_risk = self._pattern_library[category]["risk_level"]
                    if (cat_risk == RiskLevel.CRITICAL or
                        (cat_risk == RiskLevel.HIGH and max_risk != RiskLevel.CRITICAL) or
                        (cat_risk == RiskLevel.MEDIUM and max_risk == RiskLevel.LOW)):
                        max_risk = cat_risk
            result.risk_level = max_risk
        else:
            result.overall_confidence = 0.0
            result.risk_level = RiskLevel.LOW
        
        # Step 3: Generate reasoning
        result.reasoning = self._generate_reasoning(result, raw_event_data)
        
        # Step 4: Check for false positive indicators
        result.false_positive_indicators = self._check_false_positive_indicators(raw_event_data)
        
        # Adjust confidence based on FP indicators
        fp_factor = len(result.false_positive_indicators) * 0.1
        result.overall_confidence = max(0.1, result.overall_confidence - fp_factor)
        
        # Step 5: Generate recommendations
        result.recommendations = self._generate_recommendations(matched_categories, result)
        
        result.execution_trace = execution_trace
        result.processing_time_ms = (time.time() - start_time) * 1000
        
        # Cache the result
        with self._lock:
            cache_key = hashlib.md5(f"{query_id}:{raw_event_data[:1000]}".encode()).hexdigest()
            self._explanation_cache[cache_key] = result
            if len(self._explanation_cache) > self.cache_size:
                self._explanation_cache.popitem(last=False)
            self._stats["total_explanations_generated"] += 1
        
        return result
    
    def _generate_reasoning(self, result: ExplanationResult, raw_event: str) -> List[str]:
        """Generate human-readable reasoning for the detection."""
        reasoning = []
        
        if not result.match_components:
            reasoning.append("No specific pattern matches were identified.")
            return reasoning
        
        # Summary reasoning
        reasoning.append(
            f"Detection triggered with {result.overall_confidence:.1%} overall confidence "
            f"based on {len(result.match_components)} pattern match(es)."
        )
        
        # Individual match reasoning
        for i, component in enumerate(result.match_components[:3], 1):
            context = self._extract_match_context(raw_event, component.start_pos, component.end_pos, 30)
            reasoning.append(
                f"Match {i}: '{component.matched_value}' matched pattern '{component.pattern[:40]}...' "
                f"with {component.confidence:.1%} confidence. Context: {context}"
            )
        
        if len(result.match_components) > 3:
            reasoning.append(f"... and {len(result.match_components) - 3} additional pattern matches.")
        
        # Risk assessment
        reasoning.append(
            f"Risk level assessed as {result.risk_level.value.upper()} based on matched threat categories."
        )
        
        return reasoning
    
    def _check_false_positive_indicators(self, raw_event: str) -> List[str]:
        """Check for indicators that suggest potential false positive."""
        indicators = []
        
        for fp_info in self._false_positive_patterns:
            try:
                if re.search(fp_info["pattern"], raw_event, re.IGNORECASE):
                    indicators.append(fp_info["indicator"])
            except re.error:
                continue
        
        return indicators
    
    def _generate_recommendations(self, categories: Set[str], result: ExplanationResult) -> List[str]:
        """Generate mitigation and optimization recommendations."""
        recommendations = []
        
        # Category-specific recommendations
        for category in categories:
            if category in self._recommendation_rules:
                recommendations.extend(self._recommendation_rules[category][:2])
        
        # False positive mitigation
        if result.false_positive_indicators:
            recommendations.append(
                f"Review potential false positive indicators: {', '.join(result.false_positive_indicators)}"
            )
            recommendations.append(
                "Consider adding exception rules for known benign activity patterns."
            )
        
        # Confidence-based recommendations
        if result.overall_confidence < 0.5:
            recommendations.append(
                "Low confidence detection - consider refining query patterns or adding additional filters."
            )
        elif result.overall_confidence < 0.7:
            recommendations.append(
                "Medium confidence detection - verify with additional contextual data sources."
            )
        
        # Default recommendations if none
        if not recommendations:
            recommendations.extend(self._recommendation_rules["default"][:2])
        
        return list(OrderedDict.fromkeys(recommendations))[:6]  # Deduplicate and limit
    
    def batch_explain(
        self,
        query_matches: List[Dict[str, Any]]
    ) -> List[ExplanationResult]:
        """Process multiple query matches in batch."""
        results = []
        for match in query_matches:
            result = self.explain_query_match(
                query_id=match.get("query_id", "unknown"),
                query_name=match.get("query_name", "Unknown Query"),
                raw_event_data=match.get("raw_event", ""),
                query_patterns=match.get("patterns"),
                explanation_type=ExplanationType(match.get("type", "signature"))
            )
            results.append(result)
        
        with self._lock:
            self._stats["batch_processing_runs"] += 1
        
        return results
    
    def export_to_json(self, result: ExplanationResult) -> str:
        """Export explanation result to JSON format."""
        return json.dumps({
            "query_id": result.query_id,
            "query_name": result.query_name,
            "explanation_type": result.explanation_type.value,
            "overall_confidence": result.overall_confidence,
            "risk_level": result.risk_level.value,
            "match_components": [
                {
                    "component_id": c.component_id,
                    "pattern": c.pattern,
                    "matched_value": c.matched_value,
                    "confidence": c.confidence,
                    "description": c.description
                } for c in result.match_components
            ],
            "reasoning": result.reasoning,
            "false_positive_indicators": result.false_positive_indicators,
            "recommendations": result.recommendations,
            "processing_time_ms": result.processing_time_ms,
            "timestamp": result.timestamp
        }, indent=2)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine performance statistics."""
        with self._lock:
            return {
                "total_explanations_generated": self._stats["total_explanations_generated"],
                "batch_processing_runs": self._stats["batch_processing_runs"],
                "cache_size": len(self._explanation_cache),
                "cache_max_size": self.cache_size,
                "pattern_categories": len(self._pattern_library),
                "initialized_at": self._initialized_at.isoformat(),
                "uptime_seconds": (datetime.utcnow() - self._initialized_at).total_seconds()
            }


# Export main class
__all__ = [
    "HuntingQueryExplainabilityEngine",
    "ExplanationResult",
    "MatchComponent",
    "ExplanationType",
    "RiskLevel"
]
