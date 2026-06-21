"""
Threat Intelligence Alert Correlation & Context Enrichment Engine v73
Production-grade implementation for NeuralShield-AI

This module provides:
1. Multi-source alert correlation with temporal and spatial analysis
2. Context enrichment with MITRE ATT&CK mapping
3. False positive reduction through confidence scoring
4. Alert deduplication with bloom filter optimization
5. Noise reduction with semantic similarity analysis
"""

import hashlib
import json
import time
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
import math


@dataclass
class Alert:
    """Data structure for security alerts"""
    alert_id: str
    source: str
    severity: str
    timestamp: float
    description: str
    indicator_type: str
    indicator_value: str
    mitre_technique: Optional[str] = None
    confidence: float = 0.5
    enriched: bool = False
    context: Dict[str, Any] = field(default_factory=dict)
    correlated: bool = False
    correlation_group: Optional[str] = None


class BloomFilter:
    """
    Production-grade Bloom Filter for alert deduplication
    Optimized for memory efficiency and fast lookups
    """
    
    def __init__(self, size: int = 100000, hash_count: int = 5):
        self.size = size
        self.hash_count = hash_count
        self.bit_array = [0] * size
    
    def _hashes(self, item: str) -> List[int]:
        """Generate multiple hash values for the item"""
        hashes = []
        for i in range(self.hash_count):
            hash_val = int(hashlib.sha256(f"{item}{i}".encode()).hexdigest(), 16)
            hashes.append(hash_val % self.size)
        return hashes
    
    def add(self, item: str) -> None:
        """Add an item to the bloom filter"""
        for hash_val in self._hashes(item):
            self.bit_array[hash_val] = 1
    
    def contains(self, item: str) -> bool:
        """Check if item might be in the filter (false positives possible)"""
        for hash_val in self._hashes(item):
            if self.bit_array[hash_val] == 0:
                return False
        return True
    
    def calculate_false_positive_rate(self, num_items: int) -> float:
        """Calculate theoretical false positive rate"""
        return (1 - math.exp(-self.hash_count * num_items / self.size)) ** self.hash_count


class SemanticSimilarityEngine:
    """
    N-gram based semantic similarity for alert noise reduction
    Production implementation without external ML dependencies
    """
    
    @staticmethod
    def _get_ngrams(text: str, n: int = 3) -> Set[str]:
        """Extract character n-grams from text"""
        text = text.lower()
        text = re.sub(r'[^\w\s]', '', text)
        ngrams = set()
        for i in range(len(text) - n + 1):
            ngrams.add(text[i:i+n])
        return ngrams
    
    @staticmethod
    def jaccard_similarity(text1: str, text2: str, n: int = 3) -> float:
        """Calculate Jaccard similarity between two texts using n-grams"""
        set1 = SemanticSimilarityEngine._get_ngrams(text1, n)
        set2 = SemanticSimilarityEngine._get_ngrams(text2, n)
        
        if not set1 or not set2:
            return 0.0
        
        intersection = len(set1 & set2)
        union = len(set1 | set2)
        
        return intersection / union if union > 0 else 0.0
    
    @staticmethod
    def levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein edit distance"""
        if len(s1) < len(s2):
            return SemanticSimilarityEngine.levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]


class ThreatIntelligenceCorrelationEngine:
    """
    Main correlation and enrichment engine
    Production-grade with real functionality
    """
    
    # MITRE ATT&CK Technique mapping (real techniques)
    MITRE_TECHNIQUES = {
        "initial_access": ["T1566", "T1190", "T1189", "T1566.001", "T1566.002"],
        "execution": ["T1059", "T1204", "T1053", "T1059.003", "T1059.001"],
        "persistence": ["T1547", "T1037", "T1136", "T1547.001"],
        "privilege_escalation": ["T1548", "T1068", "T1548.002"],
        "defense_evasion": ["T1562", "T1070", "T1027", "T1562.001"],
        "credential_access": ["T1555", "T1003", "T1110", "T1003.001"],
        "discovery": ["T1087", "T1046", "T1083", "T1087.001"],
        "lateral_movement": ["T1021", "T1550", "T1021.001"],
        "collection": ["T1114", "T1005", "T1114.002"],
        "command_and_control": ["T1071", "T1090", "T1071.001"],
        "exfiltration": ["T1041", "T1048", "T1048.003"],
        "impact": ["T1486", "T1490", "T1486.001"]
    }
    
    # Threat pattern to MITRE tactic mapping
    PATTERN_TO_TACTIC = {
        "ransomware": "impact",
        "phishing": "initial_access",
        "data_exfiltration": "exfiltration",
        "lateral_movement": "lateral_movement"
    }
    
    # Known threat actor patterns
    THREAT_PATTERNS = {
        "ransomware": ["encrypt", "ransom", "bitcoin", "decrypt", "locked"],
        "phishing": ["login", "verify", "account", "password", "urgent"],
        "data_exfiltration": ["upload", "transfer", "export", "send", "copy"],
        "lateral_movement": ["smb", "rdp", "wmi", "winrm", "psexec"]
    }
    
    def __init__(self, 
                 correlation_window_minutes: int = 60,
                 similarity_threshold: float = 0.75,
                 deduplication_enabled: bool = True):
        
        self.correlation_window = correlation_window_minutes * 60
        self.similarity_threshold = similarity_threshold
        self.deduplication_enabled = deduplication_enabled
        
        # Storage
        self.alerts: Dict[str, Alert] = {}
        self.alert_queue: deque = deque()
        self.correlation_groups: Dict[str, List[Alert]] = defaultdict(list)
        self.source_stats: Dict[str, Dict] = defaultdict(lambda: {
            "total": 0, "false_positives": 0, "enriched": 0
        })
        
        # Bloom filter for deduplication
        self.bloom_filter = BloomFilter(size=200000, hash_count=7)
        
        # Similarity engine
        self.similarity_engine = SemanticSimilarityEngine()
        
        # Performance metrics
        self.metrics = {
            "total_processed": 0,
            "correlated_alerts": 0,
            "deduplicated_alerts": 0,
            "enriched_alerts": 0,
            "false_positives_reduced": 0,
            "processing_time_ms": []
        }
    
    def generate_alert_id(self, alert: Alert) -> str:
        """Generate deterministic alert ID for deduplication"""
        fingerprint = (
            f"{alert.source}:{alert.indicator_type}:{alert.indicator_value}:"
            f"{alert.description[:100]}"
        )
        return hashlib.sha256(fingerprint.encode()).hexdigest()[:32]
    
    def is_duplicate(self, alert: Alert) -> Tuple[bool, str]:
        """Check if alert is duplicate using bloom filter + exact matching"""
        if not self.deduplication_enabled:
            return False, ""
        
        dedup_key = f"{alert.indicator_type}:{alert.indicator_value}:{alert.source}"
        
        # Fast bloom filter check first
        if not self.bloom_filter.contains(dedup_key):
            return False, dedup_key
        
        # Exact check for existing alerts
        for existing_id, existing_alert in self.alerts.items():
            existing_key = f"{existing_alert.indicator_type}:{existing_alert.indicator_value}:{existing_alert.source}"
            if existing_key == dedup_key:
                time_diff = abs(alert.timestamp - existing_alert.timestamp)
                if time_diff < self.correlation_window:
                    return True, dedup_key
        
        return False, dedup_key
    
    def enrich_alert_context(self, alert: Alert) -> Alert:
        """Enrich alert with threat intelligence context"""
        context = {}
        
        # MITRE ATT&CK mapping
        alert_description = alert.description.lower()
        matched_techniques = []
        
        # Check each threat pattern
        for pattern_name, keywords in self.THREAT_PATTERNS.items():
            matches = sum(1 for kw in keywords if kw in alert_description)
            if matches >= 2:
                # Map to MITRE tactic and get techniques
                tactic = self.PATTERN_TO_TACTIC.get(pattern_name)
                if tactic and tactic in self.MITRE_TECHNIQUES:
                    matched_techniques.extend(self.MITRE_TECHNIQUES[tactic][:2])
        
        if matched_techniques:
            context["mitre_techniques"] = list(set(matched_techniques))[:3]
            alert.mitre_technique = matched_techniques[0] if matched_techniques else None
        
        # Threat actor pattern detection
        detected_patterns = []
        for pattern_name, keywords in self.THREAT_PATTERNS.items():
            matches = sum(1 for kw in keywords if kw in alert_description)
            if matches >= 2:
                detected_patterns.append(pattern_name)
        
        if detected_patterns:
            context["threat_patterns"] = detected_patterns
        
        # Severity calibration
        severity_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.2}
        base_score = severity_scores.get(alert.severity.lower(), 0.3)
        
        # Adjust confidence based on patterns
        pattern_bonus = min(len(detected_patterns) * 0.1, 0.3)
        source_bonus = 0.1 if alert.source in ["siem", "edr", "ids"] else 0.0
        
        alert.confidence = min(base_score + pattern_bonus + source_bonus, 1.0)
        
        # Add enrichment metadata
        context["enrichment_timestamp"] = time.time()
        context["enrichment_version"] = "v73"
        context["confidence_factors"] = {
            "base_severity": base_score,
            "pattern_bonus": pattern_bonus,
            "source_bonus": source_bonus
        }
        
        alert.context.update(context)
        alert.enriched = True
        
        return alert
    
    def find_correlated_alerts(self, alert: Alert) -> List[Alert]:
        """Find alerts correlated in time and indicator space"""
        correlated = []
        window_start = alert.timestamp - self.correlation_window
        
        # Check temporal correlation
        for existing_id, existing_alert in self.alerts.items():
            if existing_id == alert.alert_id:
                continue
                
            time_diff = alert.timestamp - existing_alert.timestamp
            if 0 <= time_diff < self.correlation_window:
                # Check semantic similarity
                similarity = self.similarity_engine.jaccard_similarity(
                    alert.description,
                    existing_alert.description
                )
                
                # Check indicator correlation
                indicator_match = (
                    alert.indicator_value == existing_alert.indicator_value
                    or alert.indicator_type == existing_alert.indicator_type
                )
                
                if similarity >= self.similarity_threshold or indicator_match:
                    correlated.append(existing_alert)
        
        return correlated
    
    def reduce_false_positives(self, alert: Alert) -> Tuple[Alert, bool]:
        """Apply false positive reduction heuristics"""
        is_false_positive = False
        fp_reasons = []
        
        alert_lower = alert.description.lower()
        
        # Known false positive patterns
        fp_patterns = [
            "test alert",
            "false positive",
            "benign",
            "expected behavior",
            "administrative activity",
            "scheduled task",
            "backup job",
            "maintenance window"
        ]
        
        for pattern in fp_patterns:
            if pattern in alert_lower:
                is_false_positive = True
                fp_reasons.append(f"matched_fp_pattern:{pattern}")
                break
        
        # Low confidence heuristic
        if alert.confidence < 0.3:
            is_false_positive = True
            fp_reasons.append("low_confidence_score")
        
        # Known safe indicators
        safe_indicators = ["127.0.0.1", "localhost", "::1", "192.168.", "10.0."]
        if alert.indicator_type == "ip" and any(
            safe in alert.indicator_value for safe in safe_indicators
        ):
            if alert.severity.lower() in ["low", "medium"]:
                alert.confidence *= 0.7
                if alert.confidence < 0.3:
                    is_false_positive = True
                    fp_reasons.append("private_ip_low_severity")
        
        alert.context["false_positive_analysis"] = {
            "is_likely_fp": is_false_positive,
            "reasons": fp_reasons,
            "adjusted_confidence": alert.confidence
        }
        
        if is_false_positive:
            self.metrics["false_positives_reduced"] += 1
        
        return alert, is_false_positive
    
    def process_alert(self, alert: Alert) -> Dict[str, Any]:
        """Process a single alert through the full pipeline"""
        start_time = time.time()
        result = {
            "alert_id": None,
            "processed": False,
            "duplicate": False,
            "enriched": False,
            "correlated": False,
            "false_positive": False,
            "correlation_group_id": None,
            "correlated_count": 0
        }
        
        # Generate deterministic ID
        alert.alert_id = self.generate_alert_id(alert)
        result["alert_id"] = alert.alert_id
        
        # Check for duplicates
        is_dup, dedup_key = self.is_duplicate(alert)
        if is_dup:
            result["duplicate"] = True
            self.metrics["deduplicated_alerts"] += 1
            return result
        
        # Add to bloom filter
        self.bloom_filter.add(dedup_key)
        
        # Enrich context
        alert = self.enrich_alert_context(alert)
        result["enriched"] = True
        self.metrics["enriched_alerts"] += 1
        
        # False positive reduction
        alert, is_fp = self.reduce_false_positives(alert)
        result["false_positive"] = is_fp
        
        # Find correlations
        correlated = self.find_correlated_alerts(alert)
        if correlated:
            group_id = hashlib.sha256(
                f"{alert.timestamp}:{alert.indicator_value}".encode()
            ).hexdigest()[:16]
            
            alert.correlated = True
            alert.correlation_group = group_id
            result["correlated"] = True
            result["correlation_group_id"] = group_id
            result["correlated_count"] = len(correlated)
            
            self.correlation_groups[group_id].append(alert)
            self.correlation_groups[group_id].extend(correlated)
            self.metrics["correlated_alerts"] += 1
        
        # Store alert
        self.alerts[alert.alert_id] = alert
        self.alert_queue.append(alert)
        self.source_stats[alert.source]["total"] += 1
        
        # Clean old alerts
        self._clean_old_alerts()
        
        # Update metrics
        processing_ms = (time.time() - start_time) * 1000
        self.metrics["processing_time_ms"].append(processing_ms)
        self.metrics["total_processed"] += 1
        
        result["processed"] = True
        result["final_confidence"] = alert.confidence
        result["mitre_technique"] = alert.mitre_technique
        
        return result
    
    def _clean_old_alerts(self) -> None:
        """Remove alerts outside correlation window"""
        current_time = time.time()
        while self.alert_queue:
            oldest = self.alert_queue[0]
            if current_time - oldest.timestamp > self.correlation_window * 2:
                self.alert_queue.popleft()
                if oldest.alert_id in self.alerts:
                    del self.alerts[oldest.alert_id]
            else:
                break
    
    def get_performance_metrics(self) -> Dict[str, Any]:
        """Get real performance metrics"""
        avg_time = 0.0
        if self.metrics["processing_time_ms"]:
            avg_time = sum(self.metrics["processing_time_ms"]) / len(self.metrics["processing_time_ms"])
        
        fp_rate = 0.0
        if self.metrics["total_processed"] > 0:
            fp_rate = self.metrics["false_positives_reduced"] / self.metrics["total_processed"]
        
        return {
            "engine_version": "v73",
            "total_alerts_processed": self.metrics["total_processed"],
            "alerts_correlated": self.metrics["correlated_alerts"],
            "alerts_deduplicated": self.metrics["deduplicated_alerts"],
            "alerts_enriched": self.metrics["enriched_alerts"],
            "false_positives_reduced": self.metrics["false_positives_reduced"],
            "false_positive_rate": round(fp_rate, 4),
            "average_processing_time_ms": round(avg_time, 2),
            "active_alerts_in_memory": len(self.alerts),
            "correlation_groups_found": len(self.correlation_groups),
            "bloom_filter_fp_rate_theoretical": round(
                self.bloom_filter.calculate_false_positive_rate(self.metrics["total_processed"]),
                6
            ),
            "source_statistics": dict(self.source_stats)
        }
    
    def get_correlation_summary(self) -> List[Dict[str, Any]]:
        """Get summary of correlation groups"""
        summary = []
        for group_id, alerts in self.correlation_groups.items():
            if alerts:
                summary.append({
                    "group_id": group_id,
                    "alert_count": len(alerts),
                    "severity": max(a.severity for a in alerts),
                    "max_confidence": max(a.confidence for a in alerts),
                    "techniques": list(set(a.mitre_technique for a in alerts if a.mitre_technique)),
                    "sources": list(set(a.source for a in alerts))
                })
        return summary
