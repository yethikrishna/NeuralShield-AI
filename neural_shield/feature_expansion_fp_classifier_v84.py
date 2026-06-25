"""
Threat Intelligence Automated False Positive Classifier v84
DIMENSION A - Feature Expansion (June 2026)

ADD-ONLY MODULE - No modifications to existing code
Backward compatible: 100%
"""

import hashlib
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict


class FalsePositiveCategory(Enum):
    LEGITIMATE_TRAFFIC = "legitimate_traffic"
    KNOWN_GOOD = "known_good"
    INTERNAL_SERVICE = "internal_service"
    CDN_CLOUD_PROVIDER = "cdn_cloud_provider"
    RESEARCH_SCANNER = "research_scanner"
    UNCERTAIN = "uncertain"
    LIKELY_TRUE_POSITIVE = "likely_true_positive"


@dataclass
class ClassificationResult:
    ioc_value: str
    ioc_type: str
    category: FalsePositiveCategory
    confidence_score: float
    risk_adjusted_score: float
    feature_contributions: Dict[str, float] = field(default_factory=dict)
    reasoning: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0
    version: str = "v84_2026_june"
    
    def is_likely_false_positive(self, threshold: float = 0.7) -> bool:
        return self.confidence_score >= threshold
    
    def is_likely_true_positive(self, threshold: float = 0.3) -> bool:
        return self.confidence_score <= threshold


@dataclass
class IOCContext:
    source_feed: str = "unknown"
    user_agent: Optional[str] = None
    internal_network: bool = False
    historical_seen_count: int = 0
    associated_alerts: int = 0
    organization_risk_appetite: float = 0.5


class EnsembleFalsePositiveClassifier:
    VERSION = "v84_2026_june"
    
    KNOWN_GOOD_USER_AGENTS = {"googlebot", "bingbot", "slurp", "duckduckbot"}
    RESEARCH_SCANNER_PATTERNS = ["shodan", "censys", "zoomeye", "virustotal"]
    
    FEATURE_WEIGHTS = {
        "known_good_user_agent": 0.90,
        "research_scanner": 0.85,
        "internal_network": 0.88,
        "private_rfc1918": 0.98,
        "localhost": 0.99,
        "high_historical_volume": 0.75,
    }
    
    def __init__(self, risk_appetite: float = 0.5):
        self.risk_appetite = max(0.0, min(1.0, risk_appetite))
        self.classification_cache: Dict[str, Tuple[ClassificationResult, float]] = {}
        self.cache_ttl_seconds = 3600
        self.processing_stats = defaultdict(int)
        self.feature_distribution = defaultdict(int)
        
    def _is_private_ip(self, ip: str) -> bool:
        if ip == "127.0.0.1" or ip == "::1":
            return True
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        first = int(parts[0])
        second = int(parts[1]) if len(parts) > 1 else 0
        if first == 10:
            return True
        if first == 172 and 16 <= second <= 31:
            return True
        if first == 192 and second == 168:
            return True
        if first >= 224:
            return True
        return False
    
    def _extract_ip_features(self, ioc_value: str, context: IOCContext) -> Dict[str, float]:
        features = {}
        if self._is_private_ip(ioc_value):
            if ioc_value == "127.0.0.1":
                features["localhost"] = 1.0
            else:
                features["private_rfc1918"] = 1.0
        if context.internal_network:
            features["internal_network"] = 1.0
        if context.historical_seen_count > 1000:
            features["high_historical_volume"] = min(1.0, context.historical_seen_count / 5000)
        return features
    
    def _extract_user_agent_features(self, context: IOCContext) -> Dict[str, float]:
        features = {}
        if not context.user_agent:
            return features
        ua_lower = context.user_agent.lower()
        for bot in self.KNOWN_GOOD_USER_AGENTS:
            if bot in ua_lower:
                features["known_good_user_agent"] = 1.0
                break
        for scanner in self.RESEARCH_SCANNER_PATTERNS:
            if scanner in ua_lower:
                features["research_scanner"] = 1.0
                break
        return features
    
    def _calibrate_confidence(self, raw_score: float) -> float:
        calibrated = 1.0 / (1.0 + pow(2.71828, -8 * (raw_score - 0.5)))
        risk_factor = (self.risk_appetite - 0.5) * 0.3
        return max(0.0, min(1.0, calibrated + risk_factor))
    
    def classify_ioc(
        self,
        ioc_value: str,
        ioc_type: str = "ip",
        context: Optional[IOCContext] = None
    ) -> ClassificationResult:
        start_time = time.time()
        context = context or IOCContext()
        
        cache_key = hashlib.md5(f"{ioc_value}:{ioc_type}".encode()).hexdigest()
        if cache_key in self.classification_cache:
            cached_result, timestamp = self.classification_cache[cache_key]
            if time.time() - timestamp < self.cache_ttl_seconds:
                self.processing_stats["cache_hits"] += 1
                return cached_result
        
        features: Dict[str, float] = {}
        if ioc_type == "ip":
            features.update(self._extract_ip_features(ioc_value, context))
        features.update(self._extract_user_agent_features(context))
        
        raw_score = 0.0
        total_weight = 0.0
        feature_contributions = {}
        
        for feature, value in features.items():
            weight = self.FEATURE_WEIGHTS.get(feature, 0.5)
            contribution = value * weight
            raw_score += contribution
            total_weight += weight
            feature_contributions[feature] = contribution
            self.feature_distribution[feature] += 1
        
        if total_weight > 0:
            raw_score = raw_score / total_weight
        
        confidence_score = self._calibrate_confidence(raw_score)
        risk_adjusted = confidence_score * (1.0 - (self.risk_appetite * 0.2))
        
        if confidence_score >= 0.85:
            if "private_rfc1918" in features or "localhost" in features:
                category = FalsePositiveCategory.INTERNAL_SERVICE
            elif "known_good_user_agent" in features:
                category = FalsePositiveCategory.CDN_CLOUD_PROVIDER
            elif "research_scanner" in features:
                category = FalsePositiveCategory.RESEARCH_SCANNER
            else:
                category = FalsePositiveCategory.KNOWN_GOOD
        elif confidence_score >= 0.6:
            category = FalsePositiveCategory.LEGITIMATE_TRAFFIC
        elif confidence_score >= 0.4:
            category = FalsePositiveCategory.UNCERTAIN
        else:
            category = FalsePositiveCategory.LIKELY_TRUE_POSITIVE
        
        reasoning = []
        if confidence_score >= 0.7:
            reasoning.append(f"High confidence false positive: {confidence_score:.3f}")
        elif confidence_score <= 0.3:
            reasoning.append(f"Likely true positive: {confidence_score:.3f}")
        
        processing_time = (time.time() - start_time) * 1000
        
        result = ClassificationResult(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            category=category,
            confidence_score=round(confidence_score, 4),
            risk_adjusted_score=round(risk_adjusted, 4),
            feature_contributions={k: round(v, 4) for k, v in feature_contributions.items()},
            reasoning=reasoning,
            processing_time_ms=round(processing_time, 2)
        )
        
        self.classification_cache[cache_key] = (result, time.time())
        self.processing_stats["total_classified"] += 1
        
        return result
    
    def classify_batch(
        self,
        iocs: List[Tuple[str, str]],
        context: Optional[IOCContext] = None
    ) -> List[ClassificationResult]:
        results = []
        for ioc_value, ioc_type in iocs:
            results.append(self.classify_ioc(ioc_value, ioc_type, context))
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        return {
            "version": self.VERSION,
            "total_classified": self.processing_stats["total_classified"],
            "cache_hits": self.processing_stats["cache_hits"],
            "cache_size": len(self.classification_cache),
            "feature_distribution": dict(self.feature_distribution),
            "risk_appetite": self.risk_appetite,
        }


__all__ = [
    "EnsembleFalsePositiveClassifier",
    "ClassificationResult",
    "IOCContext",
    "FalsePositiveCategory",
]
