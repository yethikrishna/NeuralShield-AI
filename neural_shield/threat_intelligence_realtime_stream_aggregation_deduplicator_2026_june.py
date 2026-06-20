"""
NeuralShield-AI: Threat Intelligence Real-Time Stream Aggregation & Intelligent Deduplication Engine
June 2026 Production-Grade Implementation

This module provides real-time aggregation of IOCs (Indicators of Compromise)
from multiple threat feeds with intelligent deduplication using:
- Content-based hashing for exact matches
- Fuzzy matching for similar IOCs
- Temporal decay for stale indicators
- Confidence scoring aggregation
"""

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple
from collections import defaultdict
from datetime import datetime, timedelta
from enum import Enum
import re


class IOCTYPE(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


@dataclass
class IOCEntry:
    value: str
    ioc_type: IOCTYPE
    source: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    confidence: float = 0.0
    severity: str = "medium"
    tags: List[str] = field(default_factory=list)
    feed_count: int = 1
    content_hash: str = ""

    def __post_init__(self):
        if not self.content_hash:
            self.content_hash = hashlib.sha256(
                f"{self.value.lower().strip()}|{self.ioc_type.value}".encode()
            ).hexdigest()[:16]


class RealTimeIOCAggregator:
    """
    Real-time IOC aggregation with intelligent deduplication.
    
    Features:
    - Exact match deduplication via content hashing
    - Fuzzy matching for similar domains/URLs
    - Confidence aggregation across multiple feeds
    - Temporal decay for automatic stale IOC removal
    - Thread-safe operations
    """

    def __init__(
        self,
        decay_hours: int = 72,
        confidence_threshold: float = 0.3,
        enable_fuzzy_matching: bool = True
    ):
        self.decay_hours = decay_hours
        self.confidence_threshold = confidence_threshold
        self.enable_fuzzy_matching = enable_fuzzy_matching
        
        # Primary storage: hash -> IOCEntry
        self.ioc_store: Dict[str, IOCEntry] = {}
        
        # Secondary indexes
        self.type_index: Dict[IOCTYPE, Set[str]] = defaultdict(set)
        self.source_index: Dict[str, Set[str]] = defaultdict(set)
        self.value_index: Dict[str, str] = {}  # normalized_value -> hash
        
        # Statistics
        self.stats = {
            "total_received": 0,
            "total_unique": 0,
            "total_duplicates": 0,
            "fuzzy_matches": 0,
            "feeds_aggregated": set()
        }
        
        self._lock = threading.RLock()
        self._start_cleanup_thread()

    def add_ioc(
        self,
        value: str,
        ioc_type: IOCTYPE,
        source: str,
        confidence: float = 0.5,
        severity: str = "medium",
        tags: Optional[List[str]] = None
    ) -> Tuple[bool, str]:
        """
        Add an IOC to the aggregator. Returns (is_new, content_hash)
        """
        with self._lock:
            self.stats["total_received"] += 1
            self.stats["feeds_aggregated"].add(source)
            
            normalized_value = self._normalize_value(value, ioc_type)
            content_hash = hashlib.sha256(
                f"{normalized_value}|{ioc_type.value}".encode()
            ).hexdigest()[:16]
            
            # Check for exact match
            if content_hash in self.ioc_store:
                existing = self.ioc_store[content_hash]
                existing.last_seen = time.time()
                existing.feed_count += 1
                existing.confidence = min(1.0, existing.confidence + confidence * 0.2)
                if tags:
                    existing.tags = list(set(existing.tags + tags))
                self.stats["total_duplicates"] += 1
                return False, content_hash
            
            # Check for fuzzy match (if enabled)
            if self.enable_fuzzy_matching and ioc_type in [IOCTYPE.DOMAIN, IOCTYPE.URL]:
                fuzzy_match = self._find_fuzzy_match(normalized_value, ioc_type)
                if fuzzy_match:
                    existing = self.ioc_store[fuzzy_match]
                    existing.last_seen = time.time()
                    existing.feed_count += 1
                    existing.confidence = min(1.0, existing.confidence + confidence * 0.15)
                    self.stats["fuzzy_matches"] += 1
                    self.stats["total_duplicates"] += 1
                    return False, fuzzy_match
            
            # New unique IOC
            ioc_entry = IOCEntry(
                value=normalized_value,
                ioc_type=ioc_type,
                source=source,
                confidence=confidence,
                severity=severity,
                tags=tags or [],
                content_hash=content_hash
            )
            
            self.ioc_store[content_hash] = ioc_entry
            self.type_index[ioc_type].add(content_hash)
            self.source_index[source].add(content_hash)
            self.value_index[normalized_value] = content_hash
            self.stats["total_unique"] += 1
            
            return True, content_hash

    def batch_add_iocs(self, iocs: List[Dict]) -> Dict:
        """
        Batch add multiple IOCs. Returns statistics.
        """
        results = {"added": 0, "duplicates": 0, "hashes": []}
        
        for ioc in iocs:
            try:
                is_new, h = self.add_ioc(
                    value=ioc["value"],
                    ioc_type=IOCTYPE(ioc["type"]),
                    source=ioc.get("source", "unknown"),
                    confidence=ioc.get("confidence", 0.5),
                    severity=ioc.get("severity", "medium"),
                    tags=ioc.get("tags")
                )
                results["hashes"].append(h)
                if is_new:
                    results["added"] += 1
                else:
                    results["duplicates"] += 1
            except Exception as e:
                continue
        
        return results

    def get_unique_iocs(
        self,
        min_confidence: float = 0.0,
        ioc_type: Optional[IOCTYPE] = None,
        max_age_hours: Optional[int] = None
    ) -> List[Dict]:
        """
        Get all unique IOCs with optional filtering
        """
        with self._lock:
            cutoff = time.time() - (max_age_hours * 3600) if max_age_hours else 0
            results = []
            
            for entry in self.ioc_store.values():
                if entry.confidence < min_confidence:
                    continue
                if ioc_type and entry.ioc_type != ioc_type:
                    continue
                if cutoff and entry.last_seen < cutoff:
                    continue
                    
                results.append({
                    "value": entry.value,
                    "type": entry.ioc_type.value,
                    "source": entry.source,
                    "first_seen": datetime.fromtimestamp(entry.first_seen).isoformat(),
                    "last_seen": datetime.fromtimestamp(entry.last_seen).isoformat(),
                    "confidence": round(entry.confidence, 3),
                    "severity": entry.severity,
                    "tags": entry.tags,
                    "feed_occurrences": entry.feed_count,
                    "content_hash": entry.content_hash
                })
            
            return sorted(results, key=lambda x: x["confidence"], reverse=True)

    def get_statistics(self) -> Dict:
        """Get aggregation statistics"""
        with self._lock:
            return {
                "timestamp": datetime.now().isoformat(),
                "total_iocs_received": self.stats["total_received"],
                "unique_iocs": self.stats["total_unique"],
                "duplicates_filtered": self.stats["total_duplicates"],
                "fuzzy_merged": self.stats["fuzzy_matches"],
                "deduplication_rate": round(
                    self.stats["total_duplicates"] / max(1, self.stats["total_received"]) * 100, 2
                ),
                "active_feeds": len(self.stats["feeds_aggregated"]),
                "feed_names": list(self.stats["feeds_aggregated"]),
                "by_type": {
                    t.value: len(hashes) for t, hashes in self.type_index.items()
                },
                "by_source": {
                    src: len(hashes) for src, hashes in self.source_index.items()
                }
            }

    def _normalize_value(self, value: str, ioc_type: IOCTYPE) -> str:
        """Normalize IOC values for consistent matching"""
        value = value.lower().strip()
        
        if ioc_type == IOCTYPE.DOMAIN:
            value = re.sub(r'^www\.', '', value)
            value = value.rstrip('.')
        
        elif ioc_type == IOCTYPE.URL:
            value = re.sub(r'^https?://', '', value)
            value = re.sub(r'/$', '', value)
        
        elif ioc_type in [IOCTYPE.MD5, IOCTYPE.SHA1, IOCTYPE.SHA256]:
            value = value.replace(':', '').replace('-', '')
        
        return value

    def _find_fuzzy_match(self, value: str, ioc_type: IOCTYPE) -> Optional[str]:
        """Find fuzzy matches for domains/URLs"""
        if ioc_type == IOCTYPE.DOMAIN:
            base_domain = self._extract_base_domain(value)
            for existing_value, content_hash in self.value_index.items():
                if base_domain in existing_value or existing_value in base_domain:
                    if len(value) > 8 and len(existing_value) > 8:
                        similarity = self._jaccard_similarity(value, existing_value)
                        if similarity > 0.85:
                            return content_hash
        return None

    def _extract_base_domain(self, domain: str) -> str:
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    def _jaccard_similarity(self, s1: str, s2: str) -> float:
        set1 = set(s1)
        set2 = set(s2)
        return len(set1 & set2) / len(set1 | set2)

    def _cleanup_stale_iocs(self):
        """Background thread to remove stale IOCs"""
        while True:
            try:
                time.sleep(3600)  # Run every hour
                with self._lock:
                    cutoff = time.time() - (self.decay_hours * 3600)
                    stale_hashes = [
                        h for h, entry in self.ioc_store.items()
                        if entry.last_seen < cutoff
                    ]
                    for h in stale_hashes:
                        entry = self.ioc_store[h]
                        del self.ioc_store[h]
                        self.type_index[entry.ioc_type].discard(h)
                        self.source_index[entry.source].discard(h)
                        del self.value_index[entry.value]
            except Exception:
                time.sleep(60)

    def _start_cleanup_thread(self):
        thread = threading.Thread(target=self._cleanup_stale_iocs, daemon=True)
        thread.start()

    def export_to_stix(self, filepath: str) -> bool:
        """Export IOCs to STIX 2.1 format"""
        try:
            iocs = self.get_unique_iocs()
            stix_objects = []
            
            for ioc in iocs:
                stix_obj = {
                    "type": "indicator",
                    "id": f"indicator--{ioc['content_hash']}",
                    "created": ioc["first_seen"],
                    "modified": ioc["last_seen"],
                    "name": f"{ioc['type']} IOC: {ioc['value']}",
                    "description": f"Confidence: {ioc['confidence']}, Source: {ioc['source']}",
                    "pattern": f"[file:hashes.{ioc['type'].upper()} = '{ioc['value']}']" if ioc['type'] in ['md5', 'sha1', 'sha256'] 
                              else f"[network-traffic:dst_{'ip' if 'ip' in ioc['type'] else 'domain'} = '{ioc['value']}']",
                    "pattern_type": "stix",
                    "valid_from": ioc["first_seen"],
                    "confidence": int(ioc["confidence"] * 100)
                }
                stix_objects.append(stix_obj)
            
            with open(filepath, 'w') as f:
                json.dump({
                    "type": "bundle",
                    "id": f"bundle--{hashlib.md5(str(time.time()).encode()).hexdigest()}",
                    "objects": stix_objects
                }, f, indent=2)
            
            return True
        except Exception:
            return False
