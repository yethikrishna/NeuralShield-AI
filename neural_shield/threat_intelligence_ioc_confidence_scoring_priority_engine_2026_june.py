"""
NeuralShield AI - Threat Intelligence IOC Confidence Scoring & Priority Ranking Engine
Production-grade implementation for IOC (Indicator of Compromise) scoring and prioritization

Features:
- ML-inspired weighted confidence scoring
- Multi-factor priority ranking
- Source reliability assessment
- Temporal decay calculation
- Threat actor association weighting
- Batch processing with optimization
- Confidence calibration
"""

import hashlib
import re
import math
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import json


class IOType(Enum):
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH = "hash"
    EMAIL = "email"
    FILENAME = "filename"


class SourceReliability(Enum):
    GOVERNMENT = 0.95
    COMMERCIAL_PREMIUM = 0.90
    OPEN_SOURCE_TRUSTED = 0.80
    OPEN_SOURCE_COMMUNITY = 0.65
    UNKNOWN = 0.40
    USER_REPORTED = 0.30


class ThreatSeverity(Enum):
    CRITICAL = 1.0
    HIGH = 0.8
    MEDIUM = 0.6
    LOW = 0.3
    INFO = 0.1


@dataclass
class IOCEntry:
    value: str
    ioc_type: IOType
    source: str
    first_seen: datetime
    last_seen: datetime
    threat_actor: Optional[str] = None
    severity: ThreatSeverity = ThreatSeverity.MEDIUM
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    seen_count: int = 1


@dataclass
class ScoredIOC:
    ioc: IOCEntry
    confidence_score: float
    priority_score: float
    priority_rank: str
    decay_factor: float
    source_score: float
    temporal_score: float
    frequency_score: float
    threat_actor_score: float
    severity_score: float
    processing_timestamp: datetime = field(default_factory=datetime.utcnow)


class IOCConfidenceScoringEngine:
    """
    Production-grade IOC Confidence Scoring and Priority Ranking Engine
    
    Uses multi-factor weighted scoring inspired by ML classification models:
    - Source reliability (30% weight)
    - Temporal freshness (25% weight)
    - Observation frequency (20% weight)
    - Threat actor association (15% weight)
    - Severity classification (10% weight)
    """
    
    WEIGHTS = {
        "source": 0.30,
        "temporal": 0.25,
        "frequency": 0.20,
        "threat_actor": 0.15,
        "severity": 0.10
    }
    
    SOURCE_RELIABILITY_MAP = {
        "nist": SourceReliability.GOVERNMENT,
        "cisa": SourceReliability.GOVERNMENT,
        "mandiant": SourceReliability.COMMERCIAL_PREMIUM,
        "fireeye": SourceReliability.COMMERCIAL_PREMIUM,
        "crowdstrike": SourceReliability.COMMERCIAL_PREMIUM,
        "alienvault": SourceReliability.OPEN_SOURCE_TRUSTED,
        "virustotal": SourceReliability.OPEN_SOURCE_TRUSTED,
        "abuseipdb": SourceReliability.OPEN_SOURCE_COMMUNITY,
        "community": SourceReliability.OPEN_SOURCE_COMMUNITY,
    }
    
    KNOWN_THREAT_ACTORS = {
        "apt28": 0.95, "apt29": 0.95, "lapsus$": 0.90,
        "conti": 0.90, "ransomware": 0.85, "phishing": 0.75
    }
    
    def __init__(self, decay_half_life_days: int = 30):
        self.decay_half_life = decay_half_life_days
        self.processed_iocs: Dict[str, ScoredIOC] = {}
        self.processing_stats = {
            "total_processed": 0,
            "high_confidence": 0,
            "medium_confidence": 0,
            "low_confidence": 0
        }
    
    def _calculate_source_score(self, source: str) -> float:
        """Calculate reliability score based on IOC source"""
        source_lower = source.lower().strip()
        
        for key, reliability in self.SOURCE_RELIABILITY_MAP.items():
            if key in source_lower:
                return reliability.value
        
        return SourceReliability.UNKNOWN.value
    
    def _calculate_temporal_score(self, last_seen: datetime, 
                                  first_seen: Optional[datetime] = None) -> float:
        """Calculate temporal freshness score with exponential decay"""
        now = datetime.utcnow()
        days_since_last_seen = (now - last_seen).total_seconds() / 86400
        
        # Exponential decay: score = 0.5^(days / half_life)
        decay_factor = math.pow(0.5, days_since_last_seen / self.decay_half_life)
        
        # Bonus for recently active IOCs
        if days_since_last_seen < 1:
            decay_factor = min(1.0, decay_factor + 0.15)
        elif days_since_last_seen < 7:
            decay_factor = min(1.0, decay_factor + 0.05)
        
        return max(0.01, min(1.0, decay_factor))
    
    def _calculate_frequency_score(self, seen_count: int) -> float:
        """Calculate score based on observation frequency using sigmoid function"""
        # Sigmoid-like curve: 1 observation = 0.3, 5+ = 0.9+
        normalized = 1.0 - math.exp(-seen_count / 3.0)
        return max(0.1, min(1.0, normalized))
    
    def _calculate_threat_actor_score(self, threat_actor: Optional[str]) -> float:
        """Calculate score based on known threat actor association"""
        if not threat_actor:
            return 0.3  # Default neutral score
        
        actor_lower = threat_actor.lower().strip()
        
        for actor, score in self.KNOWN_THREAT_ACTORS.items():
            if actor in actor_lower:
                return score
        
        # Unknown but named threat actor
        return 0.6
    
    def _calculate_severity_score(self, severity: ThreatSeverity) -> float:
        """Map severity enum to numerical score"""
        return severity.value
    
    def calculate_confidence_score(self, ioc: IOCEntry) -> Tuple[float, Dict[str, float]]:
        """
        Calculate overall confidence score using weighted multi-factor model
        
        Returns:
            Tuple of (overall_score, component_scores_dict)
        """
        source_score = self._calculate_source_score(ioc.source)
        temporal_score = self._calculate_temporal_score(ioc.last_seen, ioc.first_seen)
        frequency_score = self._calculate_frequency_score(ioc.seen_count)
        threat_actor_score = self._calculate_threat_actor_score(ioc.threat_actor)
        severity_score = self._calculate_severity_score(ioc.severity)
        
        component_scores = {
            "source": source_score,
            "temporal": temporal_score,
            "frequency": frequency_score,
            "threat_actor": threat_actor_score,
            "severity": severity_score
        }
        
        # Weighted sum
        overall = sum(
            component_scores[factor] * self.WEIGHTS[factor]
            for factor in self.WEIGHTS
        )
        
        return round(overall, 4), component_scores
    
    def calculate_priority_score(self, confidence: float, component_scores: Dict[str, float]) -> float:
        """
        Calculate priority score - emphasizes recency and severity more than confidence
        """
        priority_weights = {
            "source": 0.15,
            "temporal": 0.35,  # Higher weight for recency
            "frequency": 0.15,
            "threat_actor": 0.15,
            "severity": 0.20   # Higher weight for severity
        }
        
        priority = sum(
            component_scores[factor] * priority_weights[factor]
            for factor in priority_weights
        )
        
        return round(priority, 4)
    
    def _get_priority_rank(self, priority_score: float) -> str:
        """Map numerical priority to categorical rank"""
        if priority_score >= 0.85:
            return "CRITICAL"
        elif priority_score >= 0.70:
            return "HIGH"
        elif priority_score >= 0.50:
            return "MEDIUM"
        elif priority_score >= 0.30:
            return "LOW"
        else:
            return "INFORMATIONAL"
    
    def process_ioc(self, ioc: IOCEntry) -> ScoredIOC:
        """Process a single IOC through the scoring engine"""
        confidence, components = self.calculate_confidence_score(ioc)
        priority = self.calculate_priority_score(confidence, components)
        
        scored_ioc = ScoredIOC(
            ioc=ioc,
            confidence_score=confidence,
            priority_score=priority,
            priority_rank=self._get_priority_rank(priority),
            decay_factor=components["temporal"],
            source_score=components["source"],
            temporal_score=components["temporal"],
            frequency_score=components["frequency"],
            threat_actor_score=components["threat_actor"],
            severity_score=components["severity"]
        )
        
        # Cache and update stats
        ioc_hash = hashlib.md5(ioc.value.encode()).hexdigest()
        self.processed_iocs[ioc_hash] = scored_ioc
        
        self.processing_stats["total_processed"] += 1
        if confidence >= 0.7:
            self.processing_stats["high_confidence"] += 1
        elif confidence >= 0.4:
            self.processing_stats["medium_confidence"] += 1
        else:
            self.processing_stats["low_confidence"] += 1
        
        return scored_ioc
    
    def process_batch(self, iocs: List[IOCEntry], 
                      prioritize: bool = True) -> List[ScoredIOC]:
        """Process a batch of IOCs efficiently"""
        results = [self.process_ioc(ioc) for ioc in iocs]
        
        if prioritize:
            results.sort(key=lambda x: x.priority_score, reverse=True)
        
        return results
    
    def get_high_priority_iocs(self, threshold: float = 0.7) -> List[ScoredIOC]:
        """Get all IOCs above specified priority threshold"""
        return [
            scored for scored in self.processed_iocs.values()
            if scored.priority_score >= threshold
        ]
    
    def get_processing_statistics(self) -> Dict[str, Any]:
        """Get comprehensive processing statistics"""
        total = self.processing_stats["total_processed"]
        if total == 0:
            return self.processing_stats
        
        stats = dict(self.processing_stats)
        stats.update({
            "high_confidence_pct": round(stats["high_confidence"] / total * 100, 2),
            "medium_confidence_pct": round(stats["medium_confidence"] / total * 100, 2),
            "low_confidence_pct": round(stats["low_confidence"] / total * 100, 2),
            "unique_iocs_processed": len(self.processed_iocs)
        })
        return stats
    
    def export_results_json(self, filepath: str) -> bool:
        """Export all scored IOCs to JSON file"""
        try:
            export_data = []
            for scored in self.processed_iocs.values():
                export_data.append({
                    "ioc_value": scored.ioc.value,
                    "ioc_type": scored.ioc.ioc_type.value,
                    "confidence_score": scored.confidence_score,
                    "priority_score": scored.priority_score,
                    "priority_rank": scored.priority_rank,
                    "source": scored.ioc.source,
                    "last_seen": scored.ioc.last_seen.isoformat(),
                    "component_scores": {
                        "source": scored.source_score,
                        "temporal": scored.temporal_score,
                        "frequency": scored.frequency_score,
                        "threat_actor": scored.threat_actor_score,
                        "severity": scored.severity_score
                    }
                })
            
            with open(filepath, 'w') as f:
                json.dump({
                    "generated_at": datetime.utcnow().isoformat(),
                    "statistics": self.get_processing_statistics(),
                    "scored_iocs": export_data
                }, f, indent=2)
            return True
        except Exception:
            return False


# Validation utilities
def validate_ioc_format(value: str, ioc_type: IOType) -> bool:
    """Validate IOC format matches expected type"""
    patterns = {
        IOType.IP_ADDRESS: r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',
        IOType.DOMAIN: r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$',
        IOType.HASH: r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$',
        IOType.EMAIL: r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    }
    
    if ioc_type not in patterns:
        return True  # Skip validation for types without patterns
    
    return bool(re.match(patterns[ioc_type], value))
