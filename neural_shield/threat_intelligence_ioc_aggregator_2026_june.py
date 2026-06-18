"""
NeuralShield-AI: Threat Intelligence IOC Aggregator
June 2026 - Real-Time Indicator of Compromise Matching Engine

This module provides:
1. Multi-source threat intelligence feed aggregation
2. IOC (Indicator of Compromise) extraction and normalization
3. Real-time matching against user inputs
4. Caching layer with TTL for performance
5. Confidence scoring for IOC matches
"""

import re
import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from datetime import datetime, timedelta
import urllib.request
import urllib.error


class IOType(Enum):
    """Types of Indicators of Compromise"""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    MD5_HASH = "md5_hash"
    SHA256_HASH = "sha256_hash"
    SHA1_HASH = "sha1_hash"
    EMAIL = "email"


class ThreatSeverity(Enum):
    """Threat severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class IOCEntry:
    """Single Indicator of Compromise entry"""
    value: str
    ioc_type: IOType
    source: str
    severity: ThreatSeverity
    first_seen: datetime
    last_seen: datetime
    confidence: float  # 0.0 - 1.0
    description: str = ""
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "value": self.value,
            "ioc_type": self.ioc_type.value,
            "source": self.source,
            "severity": self.severity.value,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "confidence": self.confidence,
            "description": self.description,
            "tags": self.tags
        }


@dataclass
class IOCMatchResult:
    """Result from IOC matching operation"""
    matched: bool
    matches: List[IOCEntry] = field(default_factory=list)
    scan_timestamp: datetime = field(default_factory=datetime.utcnow)
    total_iocs_scanned: int = 0
    highest_severity: Optional[ThreatSeverity] = None

    def get_highest_severity(self) -> Optional[ThreatSeverity]:
        if not self.matches:
            return None
        severity_order = [
            ThreatSeverity.CRITICAL,
            ThreatSeverity.HIGH,
            ThreatSeverity.MEDIUM,
            ThreatSeverity.LOW,
            ThreatSeverity.UNKNOWN
        ]
        for sev in severity_order:
            if any(m.severity == sev for m in self.matches):
                return sev
        return ThreatSeverity.UNKNOWN


class ThreatFeedSource:
    """Configuration for threat intelligence feed sources"""
    
    # Public threat intelligence feeds (free, publicly accessible)
    FEEDS = {
        "abuse.ch_malware": {
            "url": "https://bazaar.abuse.ch/export/txt/md5/recent/",
            "ioc_type": IOType.MD5_HASH,
            "severity": ThreatSeverity.HIGH,
            "parser": "simple_line"
        },
        "abuse.ch_urlhaus": {
            "url": "https://urlhaus.abuse.ch/downloads/text_online/",
            "ioc_type": IOType.URL,
            "severity": ThreatSeverity.HIGH,
            "parser": "simple_line"
        }
    }


class IOCExtractor:
    """Extracts potential IOCs from text content"""
    
    # Regex patterns for IOC extraction
    PATTERNS = {
        IOType.IP_ADDRESS: re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
            r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ),
        IOType.DOMAIN: re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}\b'
        ),
        IOType.URL: re.compile(
            r'https?://(?:[-\w.]|%[\da-fA-F]{2})+'
            r'(?:/(?:[-\w_.~!*\'();:@&=+$,/?%#[\]]|%[\da-fA-F]{2})*)?'
        ),
        IOType.MD5_HASH: re.compile(r'\b[a-fA-F0-9]{32}\b'),
        IOType.SHA1_HASH: re.compile(r'\b[a-fA-F0-9]{40}\b'),
        IOType.SHA256_HASH: re.compile(r'\b[a-fA-F0-9]{64}\b'),
        IOType.EMAIL: re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
    }

    @classmethod
    def extract_iocs(cls, text: str) -> Dict[IOType, Set[str]]:
        """
        Extract all potential IOCs from text content
        
        Args:
            text: Input text to scan
            
        Returns:
            Dictionary mapping IOC types to sets of found values
        """
        results = {}
        for ioc_type, pattern in cls.PATTERNS.items():
            matches = pattern.findall(text)
            if matches:
                results[ioc_type] = set(matches)
        return results

    @classmethod
    def extract_iocs_list(cls, text: str) -> List[Tuple[IOType, str]]:
        """Extract IOCs as flat list"""
        results = []
        extracted = cls.extract_iocs(text)
        for ioc_type, values in extracted.items():
            for value in values:
                results.append((ioc_type, value))
        return results


class ThreatIntelligenceAggregator:
    """
    Main Threat Intelligence IOC Aggregator
    
    Features:
    - Multi-feed aggregation
    - Automatic refresh with TTL
    - Thread-safe operations
    - Memory-efficient storage
    - Real-time matching
    """

    def __init__(
        self,
        cache_ttl_minutes: int = 60,
        auto_refresh: bool = True,
        max_iocs_per_type: int = 50000
    ):
        self.cache_ttl = timedelta(minutes=cache_ttl_minutes)
        self.auto_refresh = auto_refresh
        self.max_iocs = max_iocs_per_type
        
        # IOC storage: type -> value -> IOCEntry
        self._ioc_store: Dict[IOType, Dict[str, IOCEntry]] = {
            ioc_type: {} for ioc_type in IOType
        }
        
        self._last_refresh: Optional[datetime] = None
        self._refresh_lock = threading.Lock()
        self._initialized = False
        
        # Statistics
        self._stats = {
            "total_iocs": 0,
            "feeds_fetched": 0,
            "feeds_failed": 0,
            "matches_found": 0,
            "scans_performed": 0
        }

    def initialize(self) -> bool:
        """Initialize the aggregator and perform first feed fetch"""
        try:
            self.refresh_feeds()
            self._initialized = True
            return True
        except Exception as e:
            print(f"Initialization warning: {e}")
            # Even if feeds fail, mark as initialized to allow offline operation
            self._initialized = True
            return False

    def _fetch_feed(self, feed_name: str, feed_config: Dict) -> List[str]:
        """Fetch and parse a single threat feed"""
        try:
            url = feed_config["url"]
            req = urllib.request.Request(
                url,
                headers={'User-Agent': 'NeuralShield-AI/2026.6'}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                content = response.read().decode('utf-8', errors='ignore')
            
            if feed_config["parser"] == "simple_line":
                lines = [
                    line.strip() 
                    for line in content.split('\n')
                    if line.strip() and not line.startswith('#')
                ]
                return lines[:self.max_iocs]
            
            return []
            
        except urllib.error.URLError as e:
            self._stats["feeds_failed"] += 1
            return []
        except Exception as e:
            self._stats["feeds_failed"] += 1
            return []

    def refresh_feeds(self, force: bool = False) -> int:
        """
        Refresh all threat intelligence feeds
        
        Args:
            force: Force refresh even if TTL not expired
            
        Returns:
            Number of new IOCs added
        """
        with self._refresh_lock:
            # Check if refresh needed
            if not force and self._last_refresh:
                if datetime.utcnow() - self._last_refresh < self.cache_ttl:
                    return 0
            
            new_iocs_count = 0
            now = datetime.utcnow()
            
            for feed_name, feed_config in ThreatFeedSource.FEEDS.items():
                ioc_type = feed_config["ioc_type"]
                severity = feed_config["severity"]
                
                values = self._fetch_feed(feed_name, feed_config)
                self._stats["feeds_fetched"] += 1
                
                for value in values:
                    if value not in self._ioc_store[ioc_type]:
                        entry = IOCEntry(
                            value=value,
                            ioc_type=ioc_type,
                            source=feed_name,
                            severity=severity,
                            first_seen=now,
                            last_seen=now,
                            confidence=0.85,
                            description=f"From {feed_name} threat feed"
                        )
                        self._ioc_store[ioc_type][value] = entry
                        new_iocs_count += 1
            
            self._last_refresh = now
            self._stats["total_iocs"] = sum(
                len(store) for store in self._ioc_store.values()
            )
            
            return new_iocs_count

    def scan_text(self, text: str) -> IOCMatchResult:
        """
        Scan text content for malicious IOCs
        
        Args:
            text: Text content to scan
            
        Returns:
            IOCMatchResult with matches
        """
        if not self._initialized:
            self.initialize()
        
        if self.auto_refresh:
            self.refresh_feeds()
        
        self._stats["scans_performed"] += 1
        
        result = IOCMatchResult(
            matched=False,
            total_iocs_scanned=self._stats["total_iocs"]
        )
        
        # Extract potential IOCs from text
        potential_iocs = IOCExtractor.extract_iocs(text)
        
        # Check against our IOC store
        for ioc_type, values in potential_iocs.items():
            store = self._ioc_store.get(ioc_type, {})
            for value in values:
                if value in store:
                    result.matches.append(store[value])
                    result.matched = True
                    self._stats["matches_found"] += 1
        
        result.highest_severity = result.get_highest_severity()
        return result

    def scan_value(self, value: str, ioc_type: Optional[IOType] = None) -> Optional[IOCEntry]:
        """Scan a single value against IOC store"""
        if not self._initialized:
            self.initialize()
        
        if ioc_type:
            store = self._ioc_store.get(ioc_type, {})
            return store.get(value)
        else:
            # Check all types
            for store in self._ioc_store.values():
                if value in store:
                    return store[value]
        return None

    def get_statistics(self) -> Dict[str, Any]:
        """Get aggregator statistics"""
        return {
            **self._stats,
            "last_refresh": self._last_refresh.isoformat() if self._last_refresh else None,
            "iocs_by_type": {
                ioc_type.value: len(store)
                for ioc_type, store in self._ioc_store.items()
            },
            "cache_ttl_minutes": self.cache_ttl.total_seconds() / 60,
            "initialized": self._initialized
        }

    def export_iocs(self) -> Dict[str, List[Dict]]:
        """Export all IOCs as JSON-serializable dict"""
        result = {}
        for ioc_type, store in self._ioc_store.items():
            result[ioc_type.value] = [
                entry.to_dict() for entry in store.values()
            ]
        return result

    def add_custom_ioc(
        self,
        value: str,
        ioc_type: IOType,
        severity: ThreatSeverity,
        source: str = "custom",
        confidence: float = 0.9
    ) -> bool:
        """Add custom IOC entry"""
        try:
            entry = IOCEntry(
                value=value,
                ioc_type=ioc_type,
                source=source,
                severity=severity,
                first_seen=datetime.utcnow(),
                last_seen=datetime.utcnow(),
                confidence=confidence,
                description="Custom user-added IOC"
            )
            self._ioc_store[ioc_type][value] = entry
            self._stats["total_iocs"] += 1
            return True
        except Exception:
            return False
