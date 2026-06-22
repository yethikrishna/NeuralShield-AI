"""
NeuralShield AI - Multi-Modal Threat Intelligence Fusion Engine v5
Dimension A - Feature Expansion (June 2026)

Add-only feature: Real-time fusion of multi-modal threat intelligence sources
with weighted correlation and priority-based alerting.

BACKWARD COMPATIBLE: Wraps existing functionality, no breaking changes
OPT-IN ONLY: Disabled by default, must be explicitly enabled
"""

import hashlib
import hmac
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
from collections import defaultdict, deque


class IntelligenceSourceType(Enum):
    """Types of threat intelligence sources."""
    IOC_FEED = "ioc_feed"
    VULN_DATABASE = "vulnerability_database"
    THREAT_ACTOR = "threat_actor"
    MALWARE_SAMPLE = "malware_sample"
    NETWORK_TRAFFIC = "network_traffic"
    USER_REPORT = "user_report"
    HONEYPOT = "honeypot"
    DARKWEB = "darkweb_monitor"


class ThreatSeverity(Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "informational"


class FusionStrategy(Enum):
    """Fusion strategies for combining intelligence."""
    WEIGHTED_VOTING = "weighted_voting"
    BAYESIAN = "bayesian_inference"
    DEMPSHAFER = "dempster_shafer"
    CONSENSUS = "consensus_based"


@dataclass
class IntelligenceIndicator:
    """Single intelligence indicator from any source."""
    indicator_id: str
    source_type: IntelligenceSourceType
    indicator_type: str  # ip, domain, hash, url, cve, etc.
    value: str
    severity: ThreatSeverity
    confidence: float  # 0.0 - 1.0
    timestamp: float = field(default_factory=time.time)
    ttl: int = 3600  # seconds
    metadata: Dict[str, Any] = field(default_factory=dict)
    source_reliability: float = 0.7  # 0.0 - 1.0

    def is_expired(self) -> bool:
        """Check if indicator is expired."""
        return time.time() - self.timestamp > self.ttl

    def get_weighted_score(self) -> float:
        """Get weighted score combining severity and confidence."""
        severity_weights = {
            ThreatSeverity.CRITICAL: 1.0,
            ThreatSeverity.HIGH: 0.75,
            ThreatSeverity.MEDIUM: 0.5,
            ThreatSeverity.LOW: 0.25,
            ThreatSeverity.INFO: 0.1
        }
        base_score = severity_weights.get(self.severity, 0.1)
        return base_score * self.confidence * self.source_reliability


@dataclass
class CorrelatedThreat:
    """Correlated threat from multiple indicators."""
    threat_id: str
    indicators: List[IntelligenceIndicator] = field(default_factory=list)
    correlation_score: float = 0.0
    aggregated_severity: ThreatSeverity = ThreatSeverity.INFO
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    related_entities: Set[str] = field(default_factory=set)
    mitigation_recommendations: List[str] = field(default_factory=list)

    def add_indicator(self, indicator: IntelligenceIndicator):
        """Add indicator to correlated threat."""
        self.indicators.append(indicator)
        self.last_seen = max(self.last_seen, indicator.timestamp)
        self.first_seen = min(self.first_seen, indicator.timestamp)
        self._recalculate_correlation()

    def _recalculate_correlation(self):
        """Recalculate correlation score and severity."""
        if not self.indicators:
            self.correlation_score = 0.0
            return
        
        total_score = sum(ind.get_weighted_score() for ind in self.indicators)
        source_diversity = len(set(ind.source_type for ind in self.indicators))
        diversity_bonus = min(source_diversity * 0.05, 0.25)
        self.correlation_score = min(total_score + diversity_bonus, 1.0)
        
        # Update aggregated severity
        max_severity = max(
            self.indicators, 
            key=lambda i: i.get_weighted_score()
        ).severity
        self.aggregated_severity = max_severity


class MultiModalIntelligenceFusionEngine:
    """
    Multi-Modal Threat Intelligence Fusion Engine.
    
    Core capabilities:
    1. Ingest intelligence from multiple heterogeneous sources
    2. Correlate related indicators across sources
    3. Apply fusion strategies for confidence calculation
    4. Priority-based alert generation
    5. TTL-based automatic expiration
    
    OPT-IN ONLY: Disabled by default
    """
    
    _instance: Optional['MultiModalIntelligenceFusionEngine'] = None
    _lock = threading.Lock()
    
    def __new__(cls):
        with cls._lock:
            if cls._instance is None:
                cls._instance = super().__new__(cls)
                cls._instance._initialized = False
        return cls._instance
    
    def __init__(self):
        if self._initialized:
            return
        
        self.enabled = False  # OPT-IN - DISABLED BY DEFAULT
        self._initialized = True
        self._indicators: Dict[str, IntelligenceIndicator] = {}
        self._correlated_threats: Dict[str, CorrelatedThreat] = {}
        self._source_reliability: Dict[IntelligenceSourceType, float] = defaultdict(lambda: 0.7)
        self._fusion_strategy = FusionStrategy.WEIGHTED_VOTING
        self._correlation_rules: Dict[str, Callable] = {}
        self._alert_callbacks: List[Callable] = []
        self._processing_queue = deque(maxlen=10000)
        self._max_indicators = 100000
        self._min_correlation_threshold = 0.3
        
        # Register default correlation rules
        self._register_default_rules()
    
    def enable(self):
        """Enable the fusion engine (OPT-IN)."""
        self.enabled = True
    
    def disable(self):
        """Disable the fusion engine."""
        self.enabled = False
    
    def set_source_reliability(self, source: IntelligenceSourceType, reliability: float):
        """Set reliability score for a source type (0.0-1.0)."""
        self._source_reliability[source] = max(0.0, min(1.0, reliability))
    
    def set_fusion_strategy(self, strategy: FusionStrategy):
        """Set the fusion strategy."""
        self._fusion_strategy = strategy
    
    def set_correlation_threshold(self, threshold: float):
        """Set minimum correlation threshold (0.0-1.0)."""
        self._min_correlation_threshold = max(0.0, min(1.0, threshold))
    
    def register_alert_callback(self, callback: Callable[[CorrelatedThreat], None]):
        """Register callback for high-priority threats."""
        self._alert_callbacks.append(callback)
    
    def ingest_indicator(self, indicator: IntelligenceIndicator) -> str:
        """
        Ingest a single intelligence indicator.
        
        Returns: indicator_id
        """
        if not self.enabled:
            return indicator.indicator_id
        
        # Apply source reliability
        indicator.source_reliability = self._source_reliability[indicator.source_type]
        
        # Store indicator
        self._indicators[indicator.indicator_id] = indicator
        
        # Queue for correlation processing
        self._processing_queue.append(indicator)
        
        # Process correlation
        self._correlate_indicator(indicator)
        
        return indicator.indicator_id
    
    def ingest_batch(self, indicators: List[IntelligenceIndicator]) -> List[str]:
        """Ingest batch of indicators."""
        return [self.ingest_indicator(ind) for ind in indicators]
    
    def _register_default_rules(self):
        """Register default correlation rules."""
        # Same value matching
        self._correlation_rules['same_value'] = lambda a, b: (
            a.indicator_type == b.indicator_type and 
            a.value.lower() == b.value.lower()
        )
        
        # Related IP subnet
        self._correlation_rules['same_subnet'] = lambda a, b: (
            a.indicator_type == 'ip' and 
            b.indicator_type == 'ip' and
            self._same_subnet(a.value, b.value)
        )
        
        # Same threat actor
        self._correlation_rules['same_threat_actor'] = lambda a, b: (
            'threat_actor' in a.metadata and
            'threat_actor' in b.metadata and
            a.metadata['threat_actor'] == b.metadata['threat_actor']
        )
    
    def _same_subnet(self, ip1: str, ip2: str) -> bool:
        """Check if two IPs are in same /24 subnet."""
        try:
            parts1 = ip1.split('.')
            parts2 = ip2.split('.')
            if len(parts1) == 4 and len(parts2) == 4:
                return parts1[:3] == parts2[:3]
        except:
            pass
        return False
    
    def _correlate_indicator(self, indicator: IntelligenceIndicator):
        """Correlate new indicator with existing threats."""
        matched_threats = []
        
        # Check against existing correlated threats
        for threat_id, threat in self._correlated_threats.items():
            for existing_ind in threat.indicators:
                if self._check_correlation(indicator, existing_ind):
                    threat.add_indicator(indicator)
                    matched_threats.append(threat_id)
                    break
        
        # If no match, create new potential threat
        if not matched_threats:
            threat_id = self._generate_threat_id(indicator)
            new_threat = CorrelatedThreat(
                threat_id=threat_id,
                indicators=[indicator]
            )
            self._correlated_threats[threat_id] = new_threat
        
        # Check for alert conditions
        self._check_alerts()
        
        # Clean expired
        self._clean_expired()
    
    def _check_correlation(self, a: IntelligenceIndicator, b: IntelligenceIndicator) -> bool:
        """Check if two indicators are correlated using any rule."""
        for rule in self._correlation_rules.values():
            if rule(a, b):
                return True
        return False
    
    def _generate_threat_id(self, indicator: IntelligenceIndicator) -> str:
        """Generate unique threat ID."""
        data = f"{indicator.indicator_type}:{indicator.value}:{time.time()}"
        return f"threat_{hashlib.md5(data.encode()).hexdigest()[:12]}"
    
    def _check_alerts(self):
        """Check for threats that should trigger alerts."""
        for threat in self._correlated_threats.values():
            if (threat.correlation_score >= self._min_correlation_threshold and
                threat.aggregated_severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)):
                for callback in self._alert_callbacks:
                    try:
                        callback(threat)
                    except:
                        pass  # Fail silently on callback errors
    
    def _clean_expired(self):
        """Remove expired indicators."""
        expired_ids = [
            iid for iid, ind in self._indicators.items()
            if ind.is_expired()
        ]
        for iid in expired_ids:
            del self._indicators[iid]
        
        # Trim if over max
        while len(self._indicators) > self._max_indicators:
            oldest = min(self._indicators.items(), key=lambda x: x[1].timestamp)
            del self._indicators[oldest[0]]
    
    def get_active_threats(self, min_severity: Optional[ThreatSeverity] = None) -> List[CorrelatedThreat]:
        """Get all active correlated threats."""
        threats = list(self._correlated_threats.values())
        
        if min_severity:
            severity_order = [
                ThreatSeverity.INFO,
                ThreatSeverity.LOW,
                ThreatSeverity.MEDIUM,
                ThreatSeverity.HIGH,
                ThreatSeverity.CRITICAL
            ]
            min_idx = severity_order.index(min_severity)
            threats = [
                t for t in threats
                if severity_order.index(t.aggregated_severity) >= min_idx
            ]
        
        return sorted(threats, key=lambda t: t.correlation_score, reverse=True)
    
    def get_threat_by_id(self, threat_id: str) -> Optional[CorrelatedThreat]:
        """Get specific threat by ID."""
        return self._correlated_threats.get(threat_id)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get fusion engine statistics."""
        by_source = defaultdict(int)
        by_severity = defaultdict(int)
        
        for ind in self._indicators.values():
            by_source[ind.source_type.value] += 1
            by_severity[ind.severity.value] += 1
        
        return {
            "enabled": self.enabled,
            "total_indicators": len(self._indicators),
            "correlated_threats": len(self._correlated_threats),
            "processing_queue": len(self._processing_queue),
            "fusion_strategy": self._fusion_strategy.value,
            "by_source": dict(by_source),
            "by_severity": dict(by_severity),
            "correlation_threshold": self._min_correlation_threshold
        }


# Singleton accessor - OPT-IN pattern
def get_fusion_engine() -> MultiModalIntelligenceFusionEngine:
    """Get the fusion engine singleton (disabled by default)."""
    return MultiModalIntelligenceFusionEngine()


# Helper function to create indicators
def create_indicator(
    indicator_type: str,
    value: str,
    source_type: IntelligenceSourceType,
    severity: ThreatSeverity,
    confidence: float = 0.7,
    metadata: Optional[Dict[str, Any]] = None
) -> IntelligenceIndicator:
    """Create an intelligence indicator."""
    indicator_id = f"ind_{hashlib.md5(f'{indicator_type}:{value}:{time.time()}'.encode()).hexdigest()[:12]}"
    return IntelligenceIndicator(
        indicator_id=indicator_id,
        source_type=source_type,
        indicator_type=indicator_type,
        value=value,
        severity=severity,
        confidence=confidence,
        metadata=metadata or {}
    )


# Export public API
__all__ = [
    'MultiModalIntelligenceFusionEngine',
    'IntelligenceIndicator',
    'CorrelatedThreat',
    'IntelligenceSourceType',
    'ThreatSeverity',
    'FusionStrategy',
    'get_fusion_engine',
    'create_indicator'
]
