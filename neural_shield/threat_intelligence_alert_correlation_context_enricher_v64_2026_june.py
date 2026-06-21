"""
Threat Intelligence Alert Correlation & Context Enrichment Engine v64
Production-grade implementation for NeuralShield-AI

Version 64 enhancements:
- Multi-stage correlation pipeline with weighted scoring
- MITRE ATT&CK v15 technique mapping and enrichment
- IOC batch deduplication with bloom filter optimization
- Geolocation IP enrichment with caching
- Asset risk context integration
- False positive reduction via confidence calibration
- Real-time performance metrics
- Thread-safe concurrent processing
"""

import hashlib
import json
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from enum import Enum


class AlertSeverity(Enum):
    """Alert severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class CorrelationConfidence(Enum):
    """Correlation confidence levels"""
    VERY_HIGH = 0.95
    HIGH = 0.80
    MEDIUM = 0.60
    LOW = 0.40
    UNLIKELY = 0.20


@dataclass
class Alert:
    """Data class representing a security alert"""
    alert_id: str
    timestamp: float
    source: str
    title: str
    description: str
    severity: AlertSeverity
    iocs: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    asset_id: Optional[str] = None
    raw_data: Dict[str, Any] = field(default_factory=dict)
    confidence_score: float = 1.0
    enriched: bool = False
    
    def get_severity_weight(self) -> float:
        """Get numeric weight for severity"""
        weights = {
            AlertSeverity.CRITICAL: 1.0,
            AlertSeverity.HIGH: 0.8,
            AlertSeverity.MEDIUM: 0.5,
            AlertSeverity.LOW: 0.2,
            AlertSeverity.INFORMATIONAL: 0.1
        }
        return weights.get(self.severity, 0.1)


@dataclass
class CorrelatedAlertGroup:
    """Group of correlated alerts"""
    group_id: str
    alerts: List[Alert] = field(default_factory=list)
    correlation_score: float = 0.0
    confidence_level: CorrelationConfidence = CorrelationConfidence.LOW
    mitre_coverage: Set[str] = field(default_factory=set)
    unique_iocs: Set[str] = field(default_factory=set)
    attack_chain_hypothesis: str = ""
    created_at: float = field(default_factory=time.time)
    
    def add_alert(self, alert: Alert, contribution_score: float) -> None:
        """Add an alert to the correlation group"""
        self.alerts.append(alert)
        self.unique_iocs.update(alert.iocs)
        self.mitre_coverage.update(alert.mitre_techniques)
        self._recalculate_score()
    
    def _recalculate_score(self) -> None:
        """Recalculate correlation score based on group characteristics"""
        if not self.alerts:
            self.correlation_score = 0.0
            return
        
        # Time proximity factor
        timestamps = [a.timestamp for a in self.alerts]
        time_span = max(timestamps) - min(timestamps)
        time_factor = max(0, 1.0 - (time_span / 3600))  # Decay over 1 hour
        
        # IOC overlap factor
        ioc_overlap = len(self.unique_iocs) / max(1, sum(len(a.iocs) for a in self.alerts))
        
        # MITRE technique coherence
        mitre_factor = min(1.0, len(self.mitre_coverage) / 5.0)
        
        # Severity weighted average
        severity_avg = sum(a.get_severity_weight() for a in self.alerts) / len(self.alerts)
        
        # Combined score
        self.correlation_score = (
            time_factor * 0.35 +
            ioc_overlap * 0.25 +
            mitre_factor * 0.20 +
            severity_avg * 0.20
        )
        
        # Set confidence level
        if self.correlation_score >= 0.80:
            self.confidence_level = CorrelationConfidence.VERY_HIGH
        elif self.correlation_score >= 0.60:
            self.confidence_level = CorrelationConfidence.HIGH
        elif self.correlation_score >= 0.40:
            self.confidence_level = CorrelationConfidence.MEDIUM
        elif self.correlation_score >= 0.20:
            self.confidence_level = CorrelationConfidence.LOW
        else:
            self.confidence_level = CorrelationConfidence.UNLIKELY


class BloomFilter:
    """
    Simple bloom filter implementation for efficient IOC deduplication.
    Production-grade with configurable false positive rate.
    """
    
    def __init__(self, size_bits: int = 100000, num_hashes: int = 5):
        self.size = size_bits
        self.num_hashes = num_hashes
        self.bit_array: bytearray = bytearray((size_bits + 7) // 8)
        self._count = 0
    
    def _get_hashes(self, item: str) -> List[int]:
        """Generate multiple hash positions"""
        hashes = []
        for i in range(self.num_hashes):
            h = hashlib.sha256(f"{item}{i}".encode()).hexdigest()
            hashes.append(int(h, 16) % self.size)
        return hashes
    
    def add(self, item: str) -> None:
        """Add an item to the filter"""
        for pos in self._get_hashes(item):
            byte_idx, bit_idx = pos // 8, pos % 8
            self.bit_array[byte_idx] |= (1 << bit_idx)
        self._count += 1
    
    def might_contain(self, item: str) -> bool:
        """Check if item might be in filter (False = definitely not, True = maybe)"""
        for pos in self._get_hashes(item):
            byte_idx, bit_idx = pos // 8, pos % 8
            if not (self.bit_array[byte_idx] & (1 << bit_idx)):
                return False
        return True
    
    def estimated_false_positive_rate(self) -> float:
        """Calculate estimated false positive rate"""
        n = self._count
        k = self.num_hashes
        m = self.size
        return (1 - (1 - 1/m) ** (k * n)) ** k


class GeolocationCache:
    """
    Cached geolocation lookup service with TTL.
    Production-grade with memory-efficient caching.
    """
    
    def __init__(self, max_cache_size: int = 10000, ttl_seconds: int = 86400):
        self.max_cache_size = max_cache_size
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = threading.Lock()
        
        # Mock geolocation database
        self._mock_geo_db = self._init_mock_db()
    
    def _init_mock_db(self) -> Dict[str, Dict[str, Any]]:
        """Initialize mock geolocation data"""
        return {
            "192.168.1.1": {"country": "US", "city": "New York", "asn": "AS12345", "isp": "Local ISP", "threat_score": 15},
            "10.0.0.1": {"country": "US", "city": "San Francisco", "asn": "AS54321", "isp": "Cloud Provider", "threat_score": 5},
            "172.16.0.1": {"country": "DE", "city": "Berlin", "asn": "AS99999", "isp": "European ISP", "threat_score": 45},
            "8.8.8.8": {"country": "US", "city": "Mountain View", "asn": "AS15169", "isp": "Google", "threat_score": 0},
            "1.1.1.1": {"country": "US", "city": "Los Angeles", "asn": "AS13335", "isp": "Cloudflare", "threat_score": 0},
        }
    
    def lookup(self, ip_address: str) -> Dict[str, Any]:
        """Lookup geolocation for an IP address"""
        with self._lock:
            # Check cache
            if ip_address in self._cache:
                result, timestamp = self._cache[ip_address]
                if time.time() - timestamp < self.ttl:
                    return result
                # Expired - remove
                del self._cache[ip_address]
            
            # Perform lookup (mock)
            result = self._mock_geo_db.get(ip_address, {
                "country": "UNKNOWN",
                "city": "UNKNOWN",
                "asn": "UNKNOWN",
                "isp": "UNKNOWN",
                "threat_score": 50
            })
            
            # Cache result
            if len(self._cache) >= self.max_cache_size:
                # Simple FIFO eviction
                oldest_key = next(iter(self._cache))
                del self._cache[oldest_key]
            
            self._cache[ip_address] = (result, time.time())
            return result


class AssetRiskContextProvider:
    """
    Provides asset risk context for enrichment.
    Production-grade with criticality scoring.
    """
    
    CRITICALITY_WEIGHTS = {
        "critical": 1.0,
        "high": 0.7,
        "medium": 0.4,
        "low": 0.1
    }
    
    def __init__(self):
        self._asset_db = self._init_asset_db()
        self._lock = threading.Lock()
    
    def _init_asset_db(self) -> Dict[str, Dict[str, Any]]:
        """Initialize mock asset database"""
        return {
            "asset-001": {"name": "Primary Database", "criticality": "critical", "business_impact": "high", "data_sensitivity": "pii"},
            "asset-002": {"name": "Web Server", "criticality": "high", "business_impact": "medium", "data_sensitivity": "internal"},
            "asset-003": {"name": "Development Server", "criticality": "medium", "business_impact": "low", "data_sensitivity": "public"},
            "asset-004": {"name": "Backup Server", "criticality": "high", "business_impact": "high", "data_sensitivity": "confidential"},
        }
    
    def get_asset_context(self, asset_id: str) -> Dict[str, Any]:
        """Get risk context for an asset"""
        with self._lock:
            return self._asset_db.get(asset_id, {
                "name": "Unknown Asset",
                "criticality": "low",
                "business_impact": "low",
                "data_sensitivity": "unknown"
            })
    
    def calculate_asset_risk_multiplier(self, asset_id: str) -> float:
        """Calculate risk multiplier based on asset criticality"""
        context = self.get_asset_context(asset_id)
        criticality = context.get("criticality", "low")
        return self.CRITICALITY_WEIGHTS.get(criticality, 0.1)


class AlertCorrelationContextEnricherV64:
    """
    Production-grade Alert Correlation & Context Enrichment Engine v64.
    
    Key features:
    1. Multi-stage alert correlation with weighted scoring
    2. IOC deduplication using bloom filters
    3. IP geolocation enrichment with caching
    4. Asset risk context integration
    5. MITRE ATT&CK technique mapping
    6. False positive confidence calibration
    7. Real-time performance metrics
    8. Thread-safe concurrent processing
    """
    
    def __init__(self, correlation_window_seconds: int = 3600,
                 min_correlation_score: float = 0.3,
                 enable_bloom_filter: bool = True,
                 enable_geolocation: bool = True,
                 enable_asset_context: bool = True):
        """
        Initialize the correlation engine.
        
        Args:
            correlation_window_seconds: Time window for correlation (default: 1 hour)
            min_correlation_score: Minimum score to form correlation group
            enable_bloom_filter: Enable IOC deduplication bloom filter
            enable_geolocation: Enable IP geolocation enrichment
            enable_asset_context: Enable asset risk context enrichment
        """
        self.correlation_window = correlation_window_seconds
        self.min_correlation_score = min_correlation_score
        
        # Alert storage
        self._alerts: Dict[str, Alert] = {}
        self._correlation_groups: List[CorrelatedAlertGroup] = []
        self._alert_queue: deque = deque()
        
        # Enrichment services
        self.ioc_bloom_filter = BloomFilter() if enable_bloom_filter else None
        self.geolocation = GeolocationCache() if enable_geolocation else None
        self.asset_context = AssetRiskContextProvider() if enable_asset_context else None
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Performance metrics
        self._metrics = {
            "total_alerts_processed": 0,
            "alerts_enriched": 0,
            "correlation_groups_created": 0,
            "iocs_deduplicated": 0,
            "false_positives_filtered": 0,
            "avg_processing_time_ms": 0.0,
            "total_processing_time_ms": 0.0
        }
        
        # MITRE technique database
        self._mitre_db = self._init_mitre_database()
    
    def _init_mitre_database(self) -> Dict[str, Dict[str, Any]]:
        """Initialize MITRE ATT&CK technique database"""
        return {
            "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "score": 8},
            "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion", "score": 7},
            "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control", "score": 6},
            "T1046": {"name": "Network Service Scanning", "tactic": "Discovery", "score": 5},
            "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "score": 9},
            "T1566": {"name": "Phishing", "tactic": "Initial Access", "score": 8},
            "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery", "score": 4},
            "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation", "score": 9},
        }
    
    def process_alert(self, alert: Alert) -> Dict[str, Any]:
        """
        Process a single alert: enrich, deduplicate, correlate.
        
        Returns:
            Processing result with enrichment and correlation data
        """
        start_time = time.time()
        
        with self._lock:
            self._metrics["total_alerts_processed"] += 1
            
            # Step 1: IOC deduplication
            deduped_iocs = self._deduplicate_iocs(alert.iocs)
            alert.iocs = deduped_iocs
            
            # Step 2: Enrichment
            enrichment_data = self._enrich_alert(alert)
            alert.enriched = True
            
            # Step 3: False positive calibration
            calibrated_score = self._calibrate_confidence(alert, enrichment_data)
            alert.confidence_score = calibrated_score
            
            # Step 4: Correlation
            correlation_result = self._correlate_alert(alert)
            
            # Store alert
            self._alerts[alert.alert_id] = alert
            self._alert_queue.append((time.time(), alert.alert_id))
            
            # Update metrics
            processing_time = (time.time() - start_time) * 1000
            self._metrics["total_processing_time_ms"] += processing_time
            self._metrics["avg_processing_time_ms"] = (
                self._metrics["total_processing_time_ms"] / 
                self._metrics["total_alerts_processed"]
            )
            
            return {
                "alert_id": alert.alert_id,
                "enriched": alert.enriched,
                "confidence_score": round(alert.confidence_score, 4),
                "enrichment_data": enrichment_data,
                "correlation": correlation_result,
                "processing_time_ms": round(processing_time, 2)
            }
    
    def _deduplicate_iocs(self, iocs: List[str]) -> List[str]:
        """Deduplicate IOCs using bloom filter"""
        if not self.ioc_bloom_filter:
            return list(set(iocs))
        
        deduped = []
        for ioc in iocs:
            if not self.ioc_bloom_filter.might_contain(ioc):
                self.ioc_bloom_filter.add(ioc)
                deduped.append(ioc)
            else:
                self._metrics["iocs_deduplicated"] += 1
        
        return deduped
    
    def _enrich_alert(self, alert: Alert) -> Dict[str, Any]:
        """Perform all enrichment steps"""
        enrichment = {
            "geolocation": {},
            "asset_context": {},
            "mitre_enrichment": {},
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }
        
        # Geolocation enrichment
        if self.geolocation and alert.source_ip:
            enrichment["geolocation"]["source_ip"] = self.geolocation.lookup(alert.source_ip)
        if self.geolocation and alert.destination_ip:
            enrichment["geolocation"]["destination_ip"] = self.geolocation.lookup(alert.destination_ip)
        
        # Asset context enrichment
        if self.asset_context and alert.asset_id:
            enrichment["asset_context"] = self.asset_context.get_asset_context(alert.asset_id)
        
        # MITRE technique enrichment
        for technique in alert.mitre_techniques:
            if technique in self._mitre_db:
                enrichment["mitre_enrichment"][technique] = self._mitre_db[technique]
        
        self._metrics["alerts_enriched"] += 1
        return enrichment
    
    def _calibrate_confidence(self, alert: Alert, enrichment: Dict[str, Any]) -> float:
        """Calibrate alert confidence to reduce false positives"""
        base_score = alert.confidence_score
        
        # Adjust based on geolocation threat score
        geo_threat = 0.5
        if enrichment["geolocation"].get("source_ip"):
            geo_threat = enrichment["geolocation"]["source_ip"].get("threat_score", 50) / 100.0
        
        # Adjust based on asset criticality
        asset_multiplier = 1.0
        if enrichment["asset_context"]:
            asset_id = alert.asset_id or "unknown"
            asset_multiplier = self.asset_context.calculate_asset_risk_multiplier(asset_id) if self.asset_context else 1.0
        
        # Adjust based on MITRE technique severity
        mitre_severity = 0.5
        if enrichment["mitre_enrichment"]:
            scores = [t.get("score", 5) for t in enrichment["mitre_enrichment"].values()]
            mitre_severity = sum(scores) / (len(scores) * 10) if scores else 0.5
        
        # Weighted combination
        calibrated = (
            base_score * 0.4 +
            geo_threat * 0.25 +
            asset_multiplier * 0.2 +
            mitre_severity * 0.15
        )
        
        # Filter very low confidence alerts
        if calibrated < 0.2:
            self._metrics["false_positives_filtered"] += 1
        
        return max(0.0, min(1.0, calibrated))
    
    def _correlate_alert(self, alert: Alert) -> Dict[str, Any]:
        """Correlate alert with existing alerts"""
        result = {
            "correlated": False,
            "group_id": None,
            "matched_alerts": 0,
            "correlation_score": 0.0
        }
        
        # Find existing groups to join
        best_group = None
        best_score = 0.0
        
        for group in self._correlation_groups:
            # Check time window
            if alert.timestamp - group.created_at > self.correlation_window:
                continue
            
            # Calculate correlation score
            score = self._calculate_correlation_score(alert, group)
            
            if score > best_score and score >= self.min_correlation_score:
                best_score = score
                best_group = group
        
        if best_group:
            best_group.add_alert(alert, best_score)
            result.update({
                "correlated": True,
                "group_id": best_group.group_id,
                "matched_alerts": len(best_group.alerts),
                "correlation_score": round(best_score, 4),
                "confidence_level": best_group.confidence_level.value
            })
        else:
            # Create new correlation group
            new_group = CorrelatedAlertGroup(
                group_id=f"group-{hashlib.md5(alert.alert_id.encode()).hexdigest()[:12]}"
            )
            new_group.add_alert(alert, 1.0)
            self._correlation_groups.append(new_group)
            self._metrics["correlation_groups_created"] += 1
            
            result.update({
                "correlated": True,
                "group_id": new_group.group_id,
                "matched_alerts": 1,
                "correlation_score": 1.0,
                "new_group": True
            })
        
        return result
    
    def _calculate_correlation_score(self, alert: Alert, group: CorrelatedAlertGroup) -> float:
        """Calculate correlation score between alert and group"""
        score = 0.0
        factors = 0
        
        # IOC overlap
        alert_iocs = set(alert.iocs)
        group_iocs = group.unique_iocs
        if alert_iocs and group_iocs:
            overlap = len(alert_iocs & group_iocs) / len(alert_iocs | group_iocs)
            score += overlap * 0.4
            factors += 1
        
        # MITRE technique overlap
        alert_mitre = set(alert.mitre_techniques)
        group_mitre = group.mitre_coverage
        if alert_mitre and group_mitre:
            overlap = len(alert_mitre & group_mitre) / len(alert_mitre | group_mitre)
            score += overlap * 0.3
            factors += 1
        
        # Source similarity
        group_sources = {a.source for a in group.alerts}
        if alert.source in group_sources:
            score += 0.2
            factors += 1
        
        return score / max(1, factors)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get performance metrics"""
        with self._lock:
            return {
                "version": "v64",
                "timestamp": datetime.utcnow().isoformat() + "Z",
                "metrics": self._metrics.copy(),
                "active_alerts": len(self._alerts),
                "correlation_groups": len(self._correlation_groups),
                "bloom_filter_fp_rate": (
                    round(self.ioc_bloom_filter.estimated_false_positive_rate() * 100, 4)
                    if self.ioc_bloom_filter else 0
                )
            }
    
    def cleanup_expired(self) -> int:
        """Clean up expired alerts from correlation window"""
        cutoff = time.time() - self.correlation_window
        removed = 0
        
        with self._lock:
            # Remove old correlation groups
            self._correlation_groups = [
                g for g in self._correlation_groups 
                if g.created_at >= cutoff
            ]
            removed = len(self._correlation_groups) - len(self._correlation_groups)
            
            # Reset bloom filter periodically
            if self.ioc_bloom_filter:
                self.ioc_bloom_filter = BloomFilter()
        
        return removed
