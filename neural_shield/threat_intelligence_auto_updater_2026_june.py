"""
NeuralShield AI - Real-Time Threat Intelligence Auto-Updater
Production-grade implementation with TTL cache management, delta updates, and offline resilience.

This module provides:
- Automated threat signature fetching with configurable intervals
- TTL-based cache invalidation with stale-while-revalidate support
- Delta update mechanism (only changed signatures)
- Offline fallback with local signature persistence
- Signature deduplication and validation
- Thread-safe concurrent updates
"""

import hashlib
import json
import threading
import time
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from pathlib import Path
from typing import Dict, List, Optional, Set, Callable, Any
from urllib import request
from urllib.error import URLError
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class UpdateStatus(Enum):
    """Status of threat intelligence update operations."""
    SUCCESS = "success"
    PARTIAL = "partial_success"
    NO_CHANGES = "no_changes"
    OFFLINE_FALLBACK = "offline_fallback"
    FAILED = "failed"
    RATE_LIMITED = "rate_limited"


@dataclass
class ThreatSignature:
    """Represents a single threat intelligence signature."""
    signature_id: str
    pattern: str
    threat_type: str
    severity: str  # low, medium, high, critical
    confidence: float  # 0.0 - 1.0
    created_at: float
    ttl_seconds: int = 3600  # Default 1 hour TTL
    tags: List[str] = field(default_factory=list)
    source: str = "default"

    def is_expired(self, current_time: Optional[float] = None) -> bool:
        """Check if this signature has expired."""
        now = current_time or time.time()
        return (now - self.created_at) > self.ttl_seconds

    def compute_hash(self) -> str:
        """Compute unique hash for deduplication."""
        content = f"{self.pattern}:{self.threat_type}:{self.severity}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class CacheEntry:
    """Cache entry with metadata for TTL management."""
    signature: ThreatSignature
    last_updated: float
    access_count: int = 0
    etag: str = ""

    def should_refresh(self, refresh_interval: int) -> bool:
        """Determine if entry should be refreshed."""
        return (time.time() - self.last_updated) > refresh_interval


class ThreatIntelligenceAutoUpdater:
    """
    Production-grade auto-updater for threat intelligence signatures.
    
    Features:
    - TTL-based cache with stale-while-revalidate
    - Delta updates using content hashing
    - Offline persistence and fallback
    - Thread-safe background updates
    - Configurable refresh intervals
    """

    DEFAULT_FEEDS = [
        "https://raw.githubusercontent.com/yethikrishna/NeuralShield-AI/main/feeds/jailbreak_patterns.json",
        "https://raw.githubusercontent.com/yethikrishna/NeuralShield-AI/main/feeds/prompt_injection_patterns.json",
    ]

    def __init__(
        self,
        cache_dir: str = "/tmp/neuralshield_cache",
        refresh_interval_seconds: int = 300,  # 5 minutes
        stale_while_revalidate_seconds: int = 60,
        feeds: Optional[List[str]] = None,
    ):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        
        self.refresh_interval = refresh_interval_seconds
        self.stale_while_revalidate = stale_while_revalidate_seconds
        
        self.feeds = feeds or self.DEFAULT_FEEDS
        self.signature_cache: Dict[str, CacheEntry] = {}
        self.etag_cache: Dict[str, str] = {}  # feed URL -> etag
        
        self._lock = threading.RLock()
        self._update_thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self._last_update_time: float = 0
        self._update_callbacks: List[Callable[[UpdateStatus, int], None]] = []
        
        # Load persisted signatures
        self._load_persisted_signatures()
        logger.info(f"ThreatIntelligenceAutoUpdater initialized with {len(self.signature_cache)} cached signatures")

    def _get_persistence_path(self) -> Path:
        return self.cache_dir / "signatures_persistence.json"

    def _load_persisted_signatures(self) -> None:
        """Load previously persisted signatures from disk."""
        persist_path = self._get_persistence_path()
        if persist_path.exists():
            try:
                with open(persist_path, 'r') as f:
                    data = json.load(f)
                
                loaded = 0
                for sig_data in data.get("signatures", []):
                    sig = ThreatSignature(
                        signature_id=sig_data["signature_id"],
                        pattern=sig_data["pattern"],
                        threat_type=sig_data["threat_type"],
                        severity=sig_data["severity"],
                        confidence=sig_data["confidence"],
                        created_at=sig_data["created_at"],
                        ttl_seconds=sig_data.get("ttl_seconds", 3600),
                        tags=sig_data.get("tags", []),
                        source=sig_data.get("source", "persisted"),
                    )
                    self.signature_cache[sig.signature_id] = CacheEntry(
                        signature=sig,
                        last_updated=sig_data["created_at"],
                    )
                    loaded += 1
                
                logger.info(f"Loaded {loaded} persisted signatures from disk")
            except Exception as e:
                logger.warning(f"Failed to load persisted signatures: {e}")

    def _persist_signatures(self) -> None:
        """Persist current signatures to disk for offline fallback."""
        persist_path = self._get_persistence_path()
        try:
            signatures_data = []
            with self._lock:
                for entry in self.signature_cache.values():
                    sig = entry.signature
                    signatures_data.append({
                        "signature_id": sig.signature_id,
                        "pattern": sig.pattern,
                        "threat_type": sig.threat_type,
                        "severity": sig.severity,
                        "confidence": sig.confidence,
                        "created_at": sig.created_at,
                        "ttl_seconds": sig.ttl_seconds,
                        "tags": sig.tags,
                        "source": sig.source,
                    })
            
            with open(persist_path, 'w') as f:
                json.dump({"signatures": signatures_data, "persisted_at": time.time()}, f, indent=2)
        except Exception as e:
            logger.warning(f"Failed to persist signatures: {e}")

    def _fetch_feed(self, feed_url: str) -> Optional[List[Dict[str, Any]]]:
        """Fetch a single threat feed with etag support for delta updates."""
        try:
            req = request.Request(feed_url)
            
            # Add etag if available
            if feed_url in self.etag_cache:
                req.add_header("If-None-Match", self.etag_cache[feed_url])
            
            with request.urlopen(req, timeout=10) as response:
                if response.status == 304:  # Not modified
                    logger.debug(f"Feed {feed_url} not modified")
                    return None
                
                # Store etag
                etag = response.headers.get("ETag", "")
                if etag:
                    self.etag_cache[feed_url] = etag
                
                data = json.loads(response.read().decode())
                return data.get("patterns", data.get("signatures", []))
                
        except URLError as e:
            logger.warning(f"Network error fetching {feed_url}: {e}")
            return None
        except Exception as e:
            logger.warning(f"Error fetching {feed_url}: {e}")
            return None

    def _process_signatures(self, raw_patterns: List[Dict[str, Any]], source: str) -> int:
        """Process and deduplicate incoming signatures."""
        new_count = 0
        current_time = time.time()
        
        with self._lock:
            for pattern_data in raw_patterns:
                # Create signature
                sig = ThreatSignature(
                    signature_id=pattern_data.get("id", pattern_data.get("signature_id", hashlib.md5(str(pattern_data).encode()).hexdigest()[:12])),
                    pattern=pattern_data.get("pattern", pattern_data.get("value", "")),
                    threat_type=pattern_data.get("type", pattern_data.get("threat_type", "unknown")),
                    severity=pattern_data.get("severity", "medium"),
                    confidence=float(pattern_data.get("confidence", 0.8)),
                    created_at=current_time,
                    ttl_seconds=int(pattern_data.get("ttl", 3600)),
                    tags=pattern_data.get("tags", []),
                    source=source,
                )
                
                # Deduplication check
                sig_hash = sig.compute_hash()
                existing = False
                for entry in self.signature_cache.values():
                    if entry.signature.compute_hash() == sig_hash:
                        existing = True
                        entry.last_updated = current_time
                        entry.access_count += 1
                        break
                
                if not existing and sig.pattern.strip():
                    self.signature_cache[sig.signature_id] = CacheEntry(
                        signature=sig,
                        last_updated=current_time,
                    )
                    new_count += 1
        
        return new_count

    def update_now(self) -> Dict[str, Any]:
        """
        Perform an immediate update of threat intelligence signatures.
        
        Returns:
            Dictionary with update status and statistics
        """
        total_new = 0
        successful_feeds = 0
        offline_mode = False
        
        for feed_url in self.feeds:
            patterns = self._fetch_feed(feed_url)
            
            if patterns is not None:
                new_count = self._process_signatures(patterns, feed_url)
                total_new += new_count
                successful_feeds += 1
            else:
                offline_mode = True
        
        # Clean expired signatures
        expired_removed = self._clean_expired_signatures()
        
        # Persist updated signatures
        self._persist_signatures()
        
        self._last_update_time = time.time()
        
        # Determine status
        if successful_feeds == 0:
            status = UpdateStatus.OFFLINE_FALLBACK
        elif successful_feeds < len(self.feeds):
            status = UpdateStatus.PARTIAL
        elif total_new == 0:
            status = UpdateStatus.NO_CHANGES
        else:
            status = UpdateStatus.SUCCESS
        
        result = {
            "status": status.value,
            "new_signatures": total_new,
            "total_signatures": len(self.signature_cache),
            "expired_removed": expired_removed,
            "successful_feeds": successful_feeds,
            "total_feeds": len(self.feeds),
            "timestamp": self._last_update_time,
            "offline_mode": offline_mode,
        }
        
        # Notify callbacks
        for callback in self._update_callbacks:
            try:
                callback(status, total_new)
            except Exception as e:
                logger.warning(f"Callback error: {e}")
        
        return result

    def _clean_expired_signatures(self) -> int:
        """Remove expired signatures from cache."""
        current_time = time.time()
        removed = 0
        
        with self._lock:
            expired_ids = [
                sig_id for sig_id, entry in self.signature_cache.items()
                if entry.signature.is_expired(current_time)
            ]
            
            for sig_id in expired_ids:
                del self.signature_cache[sig_id]
                removed += 1
        
        if removed > 0:
            logger.info(f"Removed {removed} expired signatures")
        
        return removed

    def get_active_signatures(self, threat_type: Optional[str] = None, min_severity: Optional[str] = None) -> List[ThreatSignature]:
        """
        Get currently active (non-expired) signatures.
        
        Args:
            threat_type: Optional filter by threat type
            min_severity: Optional minimum severity filter (critical > high > medium > low)
            
        Returns:
            List of active ThreatSignature objects
        """
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order.get(min_severity, 0) if min_severity else 0
        
        current_time = time.time()
        results = []
        
        with self._lock:
            for entry in self.signature_cache.values():
                sig = entry.signature
                
                if sig.is_expired(current_time):
                    continue
                
                if threat_type and sig.threat_type != threat_type:
                    continue
                
                if severity_order.get(sig.severity, 0) < min_level:
                    continue
                
                entry.access_count += 1
                results.append(sig)
        
        return results

    def start_background_updates(self) -> None:
        """Start background thread for automatic periodic updates."""
        if self._update_thread and self._update_thread.is_alive():
            logger.warning("Background update thread already running")
            return
        
        self._stop_event.clear()
        
        def update_loop():
            while not self._stop_event.is_set():
                try:
                    result = self.update_now()
                    logger.debug(f"Background update: {result}")
                except Exception as e:
                    logger.error(f"Background update error: {e}")
                
                self._stop_event.wait(self.refresh_interval)
        
        self._update_thread = threading.Thread(target=update_loop, daemon=True)
        self._update_thread.start()
        logger.info("Background threat intelligence updates started")

    def stop_background_updates(self) -> None:
        """Stop background update thread."""
        self._stop_event.set()
        if self._update_thread:
            self._update_thread.join(timeout=5)
        logger.info("Background threat intelligence updates stopped")

    def get_cache_stats(self) -> Dict[str, Any]:
        """Get cache statistics for monitoring."""
        with self._lock:
            total_access = sum(e.access_count for e in self.signature_cache.values())
            expired_count = sum(1 for e in self.signature_cache.values() if e.signature.is_expired())
        
        return {
            "total_signatures": len(self.signature_cache),
            "active_signatures": len(self.signature_cache) - expired_count,
            "expired_signatures": expired_count,
            "total_access_count": total_access,
            "last_update_seconds_ago": time.time() - self._last_update_time if self._last_update_time > 0 else None,
            "feeds_configured": len(self.feeds),
            "cache_dir": str(self.cache_dir),
        }

    def register_update_callback(self, callback: Callable[[UpdateStatus, int], None]) -> None:
        """Register callback for update notifications."""
        self._update_callbacks.append(callback)

    def add_local_signatures(self, signatures: List[Dict[str, Any]], source: str = "local") -> int:
        """
        Add custom/local signatures programmatically.
        
        Returns:
            Number of new signatures added
        """
        return self._process_signatures(signatures, source)

    def __enter__(self):
        self.start_background_updates()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.stop_background_updates()
