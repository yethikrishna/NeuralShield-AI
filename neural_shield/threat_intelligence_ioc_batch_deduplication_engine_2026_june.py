"""
Threat Intelligence IOC Batch Deduplication & Normalization Engine - Production Grade
NeuralShield-AI Module
Provides enterprise-grade IOC deduplication, normalization, and enrichment
for threat intelligence feeds. Handles millions of IOCs efficiently with
configurable deduplication strategies and normalization rules.

Features:
- Multi-strategy deduplication (exact, fuzzy, semantic)
- IOC normalization and standardization
- Cross-feed conflict resolution
- IOC aging and TTL management
- Confidence scoring aggregation
- Batch processing with memory optimization
- Thread-safe operations
- Statistics and metrics tracking
"""
import hashlib
import re
import ipaddress
from urllib.parse import urlparse, urlunparse
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import threading
import json


class IOCType(Enum):
    """Types of Indicators of Compromise"""
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    HASH_MD5 = "HASH_MD5"
    HASH_SHA1 = "HASH_SHA1"
    HASH_SHA256 = "HASH_SHA256"
    EMAIL = "EMAIL"
    FILENAME = "FILENAME"
    UNKNOWN = "UNKNOWN"


class DeduplicationStrategy(Enum):
    """Deduplication strategies"""
    EXACT_MATCH = "exact_match"
    NORMALIZED_MATCH = "normalized_match"
    FUZZY_MATCH = "fuzzy_match"
    SEMANTIC_MATCH = "semantic_match"


class ConflictResolution(Enum):
    """Conflict resolution strategies"""
    FIRST_SEEN = "first_seen"
    LAST_SEEN = "last_seen"
    HIGHEST_CONFIDENCE = "highest_confidence"
    MOST_TRUSTED_SOURCE = "most_trusted_source"
    MERGE_ALL = "merge_all"


@dataclass
class IOCEntry:
    """Single IOC entry with metadata"""
    value: str
    ioc_type: IOCType
    normalized_value: str = ""
    source: str = "unknown"
    confidence: float = 0.5
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    ttl_days: int = 90
    threat_types: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    feed_ids: Set[str] = field(default_factory=set)
    raw_entries: List[Dict[str, Any]] = field(default_factory=list)
    
    def __post_init__(self):
        if not self.normalized_value:
            self.normalized_value = self.value
    
    @property
    def is_expired(self) -> bool:
        """Check if IOC is expired based on TTL"""
        expiry_date = self.last_seen + timedelta(days=self.ttl_days)
        return datetime.now() > expiry_date
    
    @property
    def age_days(self) -> int:
        """Age of IOC in days"""
        return (datetime.now() - self.first_seen).days
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization"""
        data = asdict(self)
        data["ioc_type"] = self.ioc_type.value
        data["first_seen"] = self.first_seen.isoformat()
        data["last_seen"] = self.last_seen.isoformat()
        data["feed_ids"] = list(self.feed_ids)
        data["is_expired"] = self.is_expired
        data["age_days"] = self.age_days
        return data


@dataclass
class DeduplicationResult:
    """Result of batch deduplication"""
    total_input: int
    unique_after_dedup: int
    duplicates_removed: int
    expired_removed: int
    normalized_count: int
    by_type: Dict[str, int]
    by_source: Dict[str, int]
    processing_time_ms: float
    deduplicated_iocs: List[IOCEntry] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_input": self.total_input,
            "unique_after_dedup": self.unique_after_dedup,
            "duplicates_removed": self.duplicates_removed,
            "expired_removed": self.expired_removed,
            "normalized_count": self.normalized_count,
            "by_type": self.by_type,
            "by_source": self.by_source,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "deduplication_rate": round((self.duplicates_removed / max(1, self.total_input)) * 100, 2)
        }


class IOCNormalizer:
    """IOC normalization utilities"""
    
    # Domain normalization patterns
    DOMAIN_RE = re.compile(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$')
    
    @staticmethod
    def normalize_ipv4(ip: str) -> str:
        """Normalize IPv4 address - handles leading zeros"""
        ip = ip.strip()
        try:
            # Remove leading zeros from each octet
            octets = []
            for octet in ip.split('.'):
                octets.append(str(int(octet)))
            cleaned = '.'.join(octets)
            return str(ipaddress.IPv4Address(cleaned))
        except (ipaddress.AddressValueError, ValueError):
            return ip.lower()
    
    @staticmethod
    def normalize_ipv6(ip: str) -> str:
        """Normalize IPv6 address"""
        try:
            return str(ipaddress.IPv6Address(ip.strip()))
        except (ipaddress.AddressValueError, ValueError):
            return ip.strip().lower()
    
    @staticmethod
    def normalize_domain(domain: str) -> str:
        """Normalize domain name"""
        domain = domain.strip().lower()
        # Remove trailing dots (FQDN format)
        domain = domain.rstrip('.')
        # Remove www. prefix for normalization
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain
    
    @staticmethod
    def normalize_url(url: str) -> str:
        """Normalize URL"""
        url = url.strip()
        try:
            parsed = urlparse(url)
            # Normalize scheme to lowercase
            scheme = parsed.scheme.lower()
            # Normalize netloc (domain)
            netloc = parsed.netloc.lower()
            # Remove default ports
            if scheme == 'http' and netloc.endswith(':80'):
                netloc = netloc[:-3]
            elif scheme == 'https' and netloc.endswith(':443'):
                netloc = netloc[:-4]
            # Remove trailing slash from path and normalize to lowercase
            path = parsed.path.rstrip('/').lower()
            # Reconstruct
            normalized = urlunparse((
                scheme,
                netloc,
                path,
                parsed.params,
                parsed.query,
                ''  # Remove fragment
            ))
            return normalized
        except Exception:
            return url.lower()
    
    @staticmethod
    def normalize_hash(hash_val: str) -> str:
        """Normalize hash value"""
        return hash_val.strip().lower()
    
    @staticmethod
    def normalize_email(email: str) -> str:
        """Normalize email address"""
        email = email.strip().lower()
        # Remove mailto: prefix
        if email.startswith('mailto:'):
            email = email[7:]
        return email
    
    @classmethod
    def detect_type(cls, value: str) -> IOCType:
        """Detect IOC type from value"""
        value = value.strip()
        value_lower = value.lower()
        
        # Hash detection
        hash_val = re.sub(r'[^a-fA-F0-9]', '', value_lower)
        if len(hash_val) == 32:
            return IOCType.HASH_MD5
        if len(hash_val) == 40:
            return IOCType.HASH_SHA1
        if len(hash_val) == 64:
            return IOCType.HASH_SHA256
        
        # IP detection
        try:
            ipaddress.IPv4Address(value)
            return IOCType.IPV4
        except (ipaddress.AddressValueError, ValueError):
            pass
        
        try:
            ipaddress.IPv6Address(value)
            return IOCType.IPV6
        except (ipaddress.AddressValueError, ValueError):
            pass
        
        # URL detection
        if value_lower.startswith(('http://', 'https://', 'ftp://')):
            return IOCType.URL
        
        # Email detection
        if '@' in value and '.' in value.split('@')[-1]:
            return IOCType.EMAIL
        
        # Domain detection - check before filename
        if '.' in value and cls.DOMAIN_RE.match(value_lower):
            # Check if this looks like a filename vs domain
            # Filenames typically have executable/document extensions, not TLDs
            common_file_exts = {'exe', 'dll', 'bin', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'zip', 'rar', 'js', 'vbs', 'ps1', 'bat', 'cmd', 'scr'}
            ext = value.split('.')[-1].lower()
            if ext in common_file_exts:
                return IOCType.FILENAME
            return IOCType.DOMAIN
        
        # Filename detection fallback
        if '.' in value:
            common_file_exts = {'exe', 'dll', 'bin', 'doc', 'docx', 'xls', 'xlsx', 'pdf', 'zip', 'rar', 'js', 'vbs', 'ps1', 'bat', 'cmd', 'scr'}
            ext = value.split('.')[-1].lower()
            if ext in common_file_exts:
                return IOCType.FILENAME
        
        return IOCType.UNKNOWN
    
    @classmethod
    def normalize(cls, value: str, ioc_type: Optional[IOCType] = None) -> Tuple[str, IOCType]:
        """Normalize IOC value and detect/verify type"""
        if ioc_type is None:
            ioc_type = cls.detect_type(value)
        
        normalizers = {
            IOCType.IPV4: cls.normalize_ipv4,
            IOCType.IPV6: cls.normalize_ipv6,
            IOCType.DOMAIN: cls.normalize_domain,
            IOCType.URL: cls.normalize_url,
            IOCType.HASH_MD5: cls.normalize_hash,
            IOCType.HASH_SHA1: cls.normalize_hash,
            IOCType.HASH_SHA256: cls.normalize_hash,
            IOCType.EMAIL: cls.normalize_email,
        }
        
        normalizer = normalizers.get(ioc_type, lambda x: x.strip().lower())
        normalized = normalizer(value)
        
        return normalized, ioc_type


class IOCBatchDeduplicationEngine:
    """
    Production-grade IOC Batch Deduplication Engine
    
    Features:
    - Batch processing of IOCs from multiple feeds
    - Multiple deduplication strategies
    - Smart conflict resolution
    - IOC normalization
    - TTL-based expiration
    - Confidence aggregation
    """
    
    def __init__(
        self,
        dedup_strategy: DeduplicationStrategy = DeduplicationStrategy.NORMALIZED_MATCH,
        conflict_resolution: ConflictResolution = ConflictResolution.MERGE_ALL,
        remove_expired: bool = True,
        default_ttl_days: int = 90,
        trusted_sources: Optional[List[str]] = None
    ):
        self.dedup_strategy = dedup_strategy
        self.conflict_resolution = conflict_resolution
        self.remove_expired = remove_expired
        self.default_ttl_days = default_ttl_days
        self.trusted_sources = set(trusted_sources or [])
        self._lock = threading.RLock()
        self._stats = {
            "total_processed": 0,
            "total_deduplicated": 0,
            "batches_processed": 0
        }
    
    def _get_dedup_key(self, ioc: Dict[str, Any]) -> str:
        """Generate deduplication key based on strategy"""
        value = str(ioc.get("value", "")).strip()
        
        if self.dedup_strategy == DeduplicationStrategy.EXACT_MATCH:
            return value.lower()
        
        elif self.dedup_strategy == DeduplicationStrategy.NORMALIZED_MATCH:
            normalized, _ = IOCNormalizer.normalize(value)
            return normalized
        
        elif self.dedup_strategy == DeduplicationStrategy.FUZZY_MATCH:
            normalized, ioc_type = IOCNormalizer.normalize(value)
            # Use hash of normalized value for fuzzy matching
            return hashlib.md5(normalized.encode()).hexdigest()[:16]
        
        elif self.dedup_strategy == DeduplicationStrategy.SEMANTIC_MATCH:
            normalized, ioc_type = IOCNormalizer.normalize(value)
            # Type + normalized value for semantic grouping
            return f"{ioc_type.value}:{normalized}"
        
        return value.lower()
    
    def _resolve_conflict(self, existing: IOCEntry, new_data: Dict[str, Any]) -> IOCEntry:
        """Resolve conflict between existing and new IOC"""
        if self.conflict_resolution == ConflictResolution.FIRST_SEEN:
            # Keep existing, add new source info
            existing.feed_ids.add(new_data.get("feed_id", "unknown"))
            existing.raw_entries.append(new_data)
            return existing
        
        elif self.conflict_resolution == ConflictResolution.LAST_SEEN:
            # Update last seen time
            new_last_seen = new_data.get("last_seen", datetime.now())
            if isinstance(new_last_seen, str):
                new_last_seen = datetime.fromisoformat(new_last_seen)
            if new_last_seen > existing.last_seen:
                existing.last_seen = new_last_seen
            existing.feed_ids.add(new_data.get("feed_id", "unknown"))
            existing.raw_entries.append(new_data)
            return existing
        
        elif self.conflict_resolution == ConflictResolution.HIGHEST_CONFIDENCE:
            new_confidence = new_data.get("confidence", 0.5)
            if new_confidence > existing.confidence:
                existing.confidence = new_confidence
                existing.value = new_data.get("value", existing.value)
            existing.feed_ids.add(new_data.get("feed_id", "unknown"))
            existing.raw_entries.append(new_data)
            return existing
        
        elif self.conflict_resolution == ConflictResolution.MOST_TRUSTED_SOURCE:
            new_source = new_data.get("source", "unknown")
            if new_source in self.trusted_sources and existing.source not in self.trusted_sources:
                existing.source = new_source
                existing.confidence = min(1.0, existing.confidence + 0.1)
            existing.feed_ids.add(new_data.get("feed_id", "unknown"))
            existing.raw_entries.append(new_data)
            return existing
        
        else:  # MERGE_ALL
            # Merge all metadata
            existing.feed_ids.add(new_data.get("feed_id", "unknown"))
            
            new_confidence = new_data.get("confidence", 0.5)
            existing.confidence = max(existing.confidence, new_confidence)
            
            new_last_seen = new_data.get("last_seen", datetime.now())
            if isinstance(new_last_seen, str):
                new_last_seen = datetime.fromisoformat(new_last_seen)
            existing.last_seen = max(existing.last_seen, new_last_seen)
            
            new_first_seen = new_data.get("first_seen", datetime.now())
            if isinstance(new_first_seen, str):
                new_first_seen = datetime.fromisoformat(new_first_seen)
            existing.first_seen = min(existing.first_seen, new_first_seen)
            
            threat_types = new_data.get("threat_types", [])
            for tt in threat_types:
                if tt not in existing.threat_types:
                    existing.threat_types.append(tt)
            
            tags = new_data.get("tags", [])
            for tag in tags:
                if tag not in existing.tags:
                    existing.tags.append(tag)
            
            existing.raw_entries.append(new_data)
            return existing
    
    def process_batch(
        self,
        iocs: List[Dict[str, Any]],
        feed_id: str = "default"
    ) -> DeduplicationResult:
        """
        Process a batch of IOCs for deduplication and normalization
        
        Args:
            iocs: List of IOC dictionaries with 'value' and optional metadata
            feed_id: Identifier for the source feed
            
        Returns:
            DeduplicationResult with statistics and deduplicated IOCs
        """
        start_time = datetime.now()
        dedup_map: Dict[str, IOCEntry] = {}
        normalized_count = 0
        expired_count = 0
        
        with self._lock:
            for ioc_data in iocs:
                self._stats["total_processed"] += 1
                
                value = str(ioc_data.get("value", "")).strip()
                if not value:
                    continue
                
                # Normalize and detect type
                normalized, ioc_type = IOCNormalizer.normalize(value)
                if normalized != value.lower():
                    normalized_count += 1
                
                # Get deduplication key
                dedup_key = self._get_dedup_key({"value": value})
                
                # Create IOC entry
                if dedup_key in dedup_map:
                    # Resolve conflict
                    dedup_map[dedup_key] = self._resolve_conflict(
                        dedup_map[dedup_key],
                        {**ioc_data, "feed_id": feed_id}
                    )
                else:
                    # Create new entry
                    first_seen = ioc_data.get("first_seen", datetime.now())
                    if isinstance(first_seen, str):
                        first_seen = datetime.fromisoformat(first_seen)
                    
                    last_seen = ioc_data.get("last_seen", datetime.now())
                    if isinstance(last_seen, str):
                        last_seen = datetime.fromisoformat(last_seen)
                    
                    entry = IOCEntry(
                        value=value,
                        ioc_type=ioc_type,
                        normalized_value=normalized,
                        source=ioc_data.get("source", "unknown"),
                        confidence=ioc_data.get("confidence", 0.5),
                        first_seen=first_seen,
                        last_seen=last_seen,
                        ttl_days=ioc_data.get("ttl_days", self.default_ttl_days),
                        threat_types=ioc_data.get("threat_types", []),
                        tags=ioc_data.get("tags", []),
                        feed_ids={feed_id},
                        raw_entries=[{**ioc_data, "feed_id": feed_id}]
                    )
                    dedup_map[dedup_key] = entry
            
            # Filter expired if enabled
            final_iocs = []
            for ioc in dedup_map.values():
                if self.remove_expired and ioc.is_expired:
                    expired_count += 1
                else:
                    final_iocs.append(ioc)
            
            # Calculate statistics
            by_type: Dict[str, int] = {}
            by_source: Dict[str, int] = {}
            for ioc in final_iocs:
                type_key = ioc.ioc_type.value
                by_type[type_key] = by_type.get(type_key, 0) + 1
                by_source[ioc.source] = by_source.get(ioc.source, 0) + 1
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            self._stats["total_deduplicated"] += len(iocs) - len(final_iocs)
            self._stats["batches_processed"] += 1
            
            return DeduplicationResult(
                total_input=len(iocs),
                unique_after_dedup=len(final_iocs),
                duplicates_removed=len(iocs) - len(final_iocs) + expired_count,
                expired_removed=expired_count,
                normalized_count=normalized_count,
                by_type=by_type,
                by_source=by_source,
                processing_time_ms=processing_time,
                deduplicated_iocs=final_iocs
            )
    
    def merge_batches(
        self,
        batches: List[List[Dict[str, Any]]],
        feed_ids: Optional[List[str]] = None
    ) -> DeduplicationResult:
        """
        Process and merge multiple batches from different feeds
        
        Args:
            batches: List of IOC batches
            feed_ids: Optional list of feed identifiers
            
        Returns:
            Combined deduplication result
        """
        all_iocs = []
        for i, batch in enumerate(batches):
            feed_id = feed_ids[i] if feed_ids and i < len(feed_ids) else f"feed_{i}"
            for ioc in batch:
                ioc["feed_id"] = feed_id
                all_iocs.append(ioc)
        
        return self.process_batch(all_iocs, "merged")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self._lock:
            return dict(self._stats)
    
    def export_json(self, result: DeduplicationResult, filepath: str) -> bool:
        """Export deduplication results to JSON file"""
        try:
            output = {
                "summary": result.to_dict(),
                "iocs": [ioc.to_dict() for ioc in result.deduplicated_iocs],
                "exported_at": datetime.now().isoformat(),
                "engine_config": {
                    "deduplication_strategy": self.dedup_strategy.value,
                    "conflict_resolution": self.conflict_resolution.value
                }
            }
            with open(filepath, 'w') as f:
                json.dump(output, f, indent=2)
            return True
        except Exception:
            return False
