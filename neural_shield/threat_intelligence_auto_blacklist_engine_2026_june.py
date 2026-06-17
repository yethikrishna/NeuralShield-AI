"""
NeuralShield-AI: Threat Intelligence Auto-Blacklisting Engine
June 18, 2026 - Production Grade Implementation
Real working feature: Automated threat blacklisting with confidence-based
auto-flagging, TTL management, pattern learning, and statistics tracking.
This engine automatically creates and maintains blacklists based on
detected threats from all NeuralShield detectors.
"""
import time
import threading
import hashlib
from dataclasses import dataclass, field
from typing import Dict, Optional, Set, List, Any, Callable
from enum import Enum
from collections import defaultdict, deque


class BlacklistSeverity(Enum):
    """Severity levels for blacklisted items"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class BlacklistSource(Enum):
    """Source of blacklist entry"""
    AUTO_DETECTED = "auto_detected"
    MANUAL = "manual"
    THREAT_FEED = "threat_feed"
    FEDERATED = "federated"
    PATTERN_LEARNED = "pattern_learned"


@dataclass
class BlacklistEntry:
    """Individual blacklist entry with full metadata"""
    item_id: str
    item_content: str
    item_type: str  # prompt_pattern, ip, domain, signature, embedding
    severity: BlacklistSeverity
    source: BlacklistSource
    confidence: float  # 0.0 - 1.0
    detector_name: str = ""
    threat_category: str = ""
    
    created_at: float = field(default_factory=time.time)
    expires_at: float = 0.0
    last_seen_at: float = field(default_factory=time.time)
    
    hit_count: int = 0
    false_positive_count: int = 0
    detection_count: int = 1
    
    metadata: Dict[str, Any] = field(default_factory=dict)
    pattern_signature: str = ""
    
    def is_expired(self) -> bool:
        """Check if entry has expired (permanent if expires_at = 0)"""
        if self.expires_at == 0:
            return False
        return time.time() > self.expires_at
    
    def get_remaining_ttl(self) -> float:
        """Get remaining TTL in seconds (0 = permanent)"""
        if self.expires_at == 0:
            return float('inf')
        return max(0.0, self.expires_at - time.time())
    
    def increment_hit(self) -> None:
        """Increment hit counter and update access time"""
        self.hit_count += 1
        self.last_seen_at = time.time()
    
    def report_false_positive(self) -> None:
        """Report a false positive for this entry"""
        self.false_positive_count += 1
    
    def get_effective_confidence(self) -> float:
        """Calculate effective confidence accounting for false positives"""
        if self.detection_count + self.false_positive_count == 0:
            return self.confidence
        accuracy = self.detection_count / (self.detection_count + self.false_positive_count)
        return min(self.confidence, accuracy)
    
    def should_auto_remove(self) -> bool:
        """Determine if entry should be auto-removed based on accuracy"""
        if self.false_positive_count >= 3:
            return self.get_effective_confidence() < 0.5
        return False


@dataclass
class BlacklistStats:
    """Statistics for blacklist engine"""
    total_entries: int = 0
    total_hits: int = 0
    auto_added_count: int = 0
    auto_removed_count: int = 0
    pattern_learned_count: int = 0
    false_positive_total: int = 0
    severity_distribution: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    source_distribution: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    type_distribution: Dict[str, int] = field(default_factory=lambda: defaultdict(int))


class ThreatIntelligenceAutoBlacklistEngine:
    """
    Auto-Blacklisting Engine for NeuralShield-AI
    
    Real working features:
    1. Auto-blacklists high-confidence threats from all detectors
    2. Manages TTL and automatic expiration
    3. Tracks false positives and auto-removes inaccurate entries
    4. Learns patterns and creates derived blacklist entries
    5. Provides fast lookup with hash-based indexing
    6. Maintains comprehensive statistics
    """
    
    def __init__(
        self,
        auto_blacklist_threshold: float = 0.85,
        default_ttl_seconds: float = 86400 * 7,  # 7 days
        critical_ttl_seconds: float = 86400 * 30,  # 30 days
        max_entries: int = 100000,
        enable_pattern_learning: bool = True
    ):
        self.auto_blacklist_threshold = auto_blacklist_threshold
        self.default_ttl = default_ttl_seconds
        self.critical_ttl = critical_ttl_seconds
        self.max_entries = max_entries
        self.enable_pattern_learning = enable_pattern_learning
        
        # Main storage
        self._blacklist: Dict[str, BlacklistEntry] = {}
        self._content_hash_index: Dict[str, str] = {}
        self._type_index: Dict[str, Set[str]] = defaultdict(set)
        self._severity_index: Dict[str, Set[str]] = defaultdict(set)
        
        # Pattern learning
        self._pattern_frequency: Dict[str, int] = defaultdict(int)
        self._recent_detections: deque = deque(maxlen=1000)
        
        # Statistics
        self.stats = BlacklistStats()
        self._lock = threading.RLock()
        
        # Callbacks
        self._on_blacklist_add: Optional[Callable] = None
        self._on_blacklist_remove: Optional[Callable] = None
        
        # Start cleanup thread
        self._start_cleanup_thread()
    
    def _compute_content_hash(self, content: str) -> str:
        """Compute hash for content-based lookup"""
        return hashlib.sha256(content.lower().strip().encode()).hexdigest()[:32]
    
    def _determine_severity(self, confidence: float, threat_category: str) -> BlacklistSeverity:
        """Determine severity based on confidence and category"""
        critical_categories = {'jailbreak', 'prompt_injection', 'backdoor'}
        high_categories = {'toxicity', 'hallucination', 'data_leakage'}
        
        if threat_category in critical_categories and confidence >= 0.9:
            return BlacklistSeverity.CRITICAL
        elif threat_category in critical_categories or confidence >= 0.95:
            return BlacklistSeverity.HIGH
        elif threat_category in high_categories or confidence >= 0.85:
            return BlacklistSeverity.MEDIUM
        return BlacklistSeverity.LOW
    
    def _get_ttl_for_severity(self, severity: BlacklistSeverity) -> float:
        """Get appropriate TTL for severity level"""
        if severity == BlacklistSeverity.CRITICAL:
            return self.critical_ttl
        elif severity == BlacklistSeverity.HIGH:
            return self.default_ttl * 2
        elif severity == BlacklistSeverity.MEDIUM:
            return self.default_ttl
        return self.default_ttl / 2
    
    def register_callbacks(
        self,
        on_add: Optional[Callable] = None,
        on_remove: Optional[Callable] = None
    ) -> None:
        """Register callbacks for blacklist events"""
        self._on_blacklist_add = on_add
        self._on_blacklist_remove = on_remove
    
    def process_detection(
        self,
        content: str,
        confidence: float,
        detector_name: str,
        threat_category: str,
        item_type: str = "prompt_pattern",
        metadata: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Process a detection and auto-blacklist if confidence is high enough.
        Returns True if item was auto-blacklisted.
        """
        if confidence < self.auto_blacklist_threshold:
            # Track for pattern learning even if below threshold
            if self.enable_pattern_learning:
                self._track_detection_for_patterns(content, threat_category)
            return False
        
        with self._lock:
            content_hash = self._compute_content_hash(content)
            
            # Check if already exists
            if content_hash in self._content_hash_index:
                entry_id = self._content_hash_index[content_hash]
                if entry_id in self._blacklist:
                    self._blacklist[entry_id].increment_hit()
                    self._blacklist[entry_id].detection_count += 1
                    return False
            
            # Determine severity and TTL
            severity = self._determine_severity(confidence, threat_category)
            ttl = self._get_ttl_for_severity(severity)
            
            # Create entry
            entry_id = f"auto_{int(time.time() * 1000000)}"
            entry = BlacklistEntry(
                item_id=entry_id,
                item_content=content,
                item_type=item_type,
                severity=severity,
                source=BlacklistSource.AUTO_DETECTED,
                confidence=confidence,
                detector_name=detector_name,
                threat_category=threat_category,
                expires_at=time.time() + ttl if ttl > 0 else 0,
                metadata=metadata or {},
                pattern_signature=self._extract_pattern_signature(content)
            )
            
            # Add to blacklist
            self._add_entry(entry)
            
            # Track for pattern learning
            if self.enable_pattern_learning:
                self._track_detection_for_patterns(content, threat_category)
            
            return True
    
    def _add_entry(self, entry: BlacklistEntry) -> None:
        """Add entry to blacklist (internal, lock already held)"""
        # Enforce max entries - remove oldest if needed
        if len(self._blacklist) >= self.max_entries:
            self._remove_oldest_entries(100)
        
        content_hash = self._compute_content_hash(entry.item_content)
        
        self._blacklist[entry.item_id] = entry
        self._content_hash_index[content_hash] = entry.item_id
        self._type_index[entry.item_type].add(entry.item_id)
        self._severity_index[entry.severity.value].add(entry.item_id)
        
        # Update stats
        self.stats.total_entries += 1
        self.stats.severity_distribution[entry.severity.value] += 1
        self.stats.source_distribution[entry.source.value] += 1
        self.stats.type_distribution[entry.item_type] += 1
        
        if entry.source == BlacklistSource.AUTO_DETECTED:
            self.stats.auto_added_count += 1
        
        # Callback
        if self._on_blacklist_add:
            self._on_blacklist_add(entry)
    
    def _remove_oldest_entries(self, count: int) -> None:
        """Remove oldest expired/lowest confidence entries"""
        sorted_entries = sorted(
            self._blacklist.values(),
            key=lambda e: (e.is_expired(), -e.get_effective_confidence(), e.created_at)
        )
        for entry in sorted_entries[:count]:
            self._remove_entry(entry.item_id)
    
    def _remove_entry(self, entry_id: str) -> bool:
        """Remove entry from blacklist (internal)"""
        if entry_id not in self._blacklist:
            return False
        
        entry = self._blacklist[entry_id]
        content_hash = self._compute_content_hash(entry.item_content)
        
        del self._blacklist[entry_id]
        if content_hash in self._content_hash_index:
            del self._content_hash_index[content_hash]
        
        self._type_index[entry.item_type].discard(entry_id)
        self._severity_index[entry.severity.value].discard(entry_id)
        
        self.stats.total_entries -= 1
        self.stats.auto_removed_count += 1
        
        if self._on_blacklist_remove:
            self._on_blacklist_remove(entry)
        
        return True
    
    def is_blacklisted(self, content: str) -> Optional[BlacklistEntry]:
        """Check if content is blacklisted - fast lookup"""
        content_hash = self._compute_content_hash(content)
        
        with self._lock:
            if content_hash not in self._content_hash_index:
                return None
            
            entry_id = self._content_hash_index[content_hash]
            if entry_id not in self._blacklist:
                return None
            
            entry = self._blacklist[entry_id]
            
            # Check for expiration
            if entry.is_expired():
                self._remove_entry(entry_id)
                return None
            
            # Check for auto-removal due to false positives
            if entry.should_auto_remove():
                self._remove_entry(entry_id)
                return None
            
            entry.increment_hit()
            self.stats.total_hits += 1
            return entry
    
    def manual_add(
        self,
        content: str,
        severity: BlacklistSeverity,
        item_type: str = "prompt_pattern",
        threat_category: str = "manual",
        permanent: bool = False,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """Manually add an item to blacklist"""
        with self._lock:
            content_hash = self._compute_content_hash(content)
            
            if content_hash in self._content_hash_index:
                return self._content_hash_index[content_hash]
            
            ttl = 0 if permanent else self._get_ttl_for_severity(severity)
            entry_id = f"manual_{int(time.time() * 1000000)}"
            
            entry = BlacklistEntry(
                item_id=entry_id,
                item_content=content,
                item_type=item_type,
                severity=severity,
                source=BlacklistSource.MANUAL,
                confidence=1.0,
                threat_category=threat_category,
                expires_at=time.time() + ttl if ttl > 0 else 0,
                metadata=metadata or {}
            )
            
            self._add_entry(entry)
            return entry_id
    
    def manual_remove(self, entry_id: str) -> bool:
        """Manually remove an item from blacklist"""
        with self._lock:
            return self._remove_entry(entry_id)
    
    def report_false_positive(self, content: str) -> bool:
        """Report a false positive for potential auto-removal"""
        with self._lock:
            content_hash = self._compute_content_hash(content)
            
            if content_hash not in self._content_hash_index:
                return False
            
            entry_id = self._content_hash_index[content_hash]
            if entry_id not in self._blacklist:
                return False
            
            entry = self._blacklist[entry_id]
            entry.report_false_positive()
            self.stats.false_positive_total += 1
            
            # Auto-remove if needed
            if entry.should_auto_remove():
                self._remove_entry(entry_id)
            
            return True
    
    def _extract_pattern_signature(self, content: str) -> str:
        """Extract simple pattern signature for learning"""
        words = content.lower().split()
        keywords = [w for w in words if len(w) > 4]
        return '|'.join(sorted(keywords)[:10])
    
    def _track_detection_for_patterns(self, content: str, category: str) -> None:
        """Track detections for pattern learning"""
        pattern = self._extract_pattern_signature(content)
        key = f"{category}:{pattern}"
        self._pattern_frequency[key] += 1
        self._recent_detections.append((time.time(), category, content, pattern))
        
        # Auto-learn patterns that appear frequently
        if self._pattern_frequency[key] >= 5:
            self._learn_pattern(content, category, pattern)
    
    def _learn_pattern(self, content: str, category: str, pattern: str) -> None:
        """Learn and auto-blacklist based on recurring patterns"""
        if not self.enable_pattern_learning:
            return
        
        # Check if pattern already exists
        pattern_hash = self._compute_content_hash(pattern)
        if pattern_hash in self._content_hash_index:
            return
        
        entry_id = f"pattern_{int(time.time() * 1000000)}"
        entry = BlacklistEntry(
            item_id=entry_id,
            item_content=pattern,
            item_type="learned_pattern",
            severity=BlacklistSeverity.MEDIUM,
            source=BlacklistSource.PATTERN_LEARNED,
            confidence=0.75,
            threat_category=category,
            expires_at=time.time() + self.default_ttl,
            pattern_signature=pattern
        )
        
        self._add_entry(entry)
        self.stats.pattern_learned_count += 1
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive blacklist statistics"""
        with self._lock:
            expired_count = sum(1 for e in self._blacklist.values() if e.is_expired())
            
            return {
                "total_entries": self.stats.total_entries,
                "total_hits": self.stats.total_hits,
                "auto_added": self.stats.auto_added_count,
                "auto_removed": self.stats.auto_removed_count,
                "pattern_learned": self.stats.pattern_learned_count,
                "false_positives_reported": self.stats.false_positive_total,
                "expired_entries_pending_cleanup": expired_count,
                "severity_distribution": dict(self.stats.severity_distribution),
                "source_distribution": dict(self.stats.source_distribution),
                "type_distribution": dict(self.stats.type_distribution),
                "hit_rate": self.stats.total_hits / max(1, self.stats.total_entries)
            }
    
    def get_entries_by_severity(self, severity: BlacklistSeverity) -> List[BlacklistEntry]:
        """Get all entries of a specific severity"""
        with self._lock:
            entry_ids = self._severity_index.get(severity.value, set())
            return [self._blacklist[eid] for eid in entry_ids if eid in self._blacklist]
    
    def cleanup_expired(self) -> int:
        """Remove all expired entries, returns count removed"""
        removed = 0
        with self._lock:
            expired_ids = [
                eid for eid, entry in self._blacklist.items()
                if entry.is_expired()
            ]
            for eid in expired_ids:
                if self._remove_entry(eid):
                    removed += 1
        return removed
    
    def _start_cleanup_thread(self) -> None:
        """Start background cleanup thread"""
        def cleanup_worker():
            while True:
                time.sleep(3600)  # Clean every hour
                try:
                    self.cleanup_expired()
                except:
                    pass
        
        thread = threading.Thread(target=cleanup_worker, daemon=True)
        thread.start()
    
    def export_blacklist(self) -> List[Dict[str, Any]]:
        """Export blacklist for persistence/sharing"""
        with self._lock:
            return [
                {
                    "item_id": e.item_id,
                    "content": e.item_content,
                    "type": e.item_type,
                    "severity": e.severity.value,
                    "source": e.source.value,
                    "confidence": e.confidence,
                    "category": e.threat_category,
                    "expires_at": e.expires_at
                }
                for e in self._blacklist.values()
                if not e.is_expired()
            ]
