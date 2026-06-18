"""
Threat Intelligence IOC Hash Validator - NeuralShield-AI
June 2026 - Production Grade

Validates, normalizes, and enriches hash-based Indicators of Compromise (IOCs)
Supports MD5, SHA1, SHA256, SHA512, SHA3-256 hash types
"""

import hashlib
import re
import json
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone
from enum import Enum


class HashType(Enum):
    """Supported hash types for IOC validation"""
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    SHA512 = "sha512"
    SHA3_256 = "sha3-256"
    UNKNOWN = "unknown"


class HashValidationStatus(Enum):
    """Validation status for hash IOCs"""
    VALID = "valid"
    INVALID_FORMAT = "invalid_format"
    INVALID_CHECKSUM = "invalid_checksum"
    DUPLICATE = "duplicate"
    WHITELISTED = "whitelisted"
    BLACKLISTED = "blacklisted"


@dataclass
class HashValidationResult:
    """Result of hash IOC validation"""
    hash_value: str
    hash_type: HashType
    status: HashValidationStatus
    normalized_hash: str
    is_valid: bool
    confidence_score: float = 0.0
    validation_details: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    enrichment_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary format"""
        return {
            "hash_value": self.hash_value,
            "hash_type": self.hash_type.value,
            "status": self.status.value,
            "normalized_hash": self.normalized_hash,
            "is_valid": self.is_valid,
            "confidence_score": self.confidence_score,
            "validation_details": self.validation_details,
            "timestamp": self.timestamp,
            "enrichment_data": self.enrichment_data
        }


class IOCHashValidator:
    """
    Production-grade IOC Hash Validator for Threat Intelligence
    
    Features:
    - Hash format validation and normalization
    - Hash type auto-detection
    - Duplicate detection
    - Whitelist/blacklist checking
    - Batch processing support
    - Confidence scoring
    """

    # Hash regex patterns
    HASH_PATTERNS = {
        HashType.MD5: re.compile(r'^[a-fA-F0-9]{32}$'),
        HashType.SHA1: re.compile(r'^[a-fA-F0-9]{40}$'),
        HashType.SHA256: re.compile(r'^[a-fA-F0-9]{64}$'),
        HashType.SHA512: re.compile(r'^[a-fA-F0-9]{128}$'),
        HashType.SHA3_256: re.compile(r'^[a-fA-F0-9]{64}$'),
    }

    def __init__(
        self,
        whitelist_hashes: Optional[List[str]] = None,
        blacklist_hashes: Optional[List[str]] = None,
        enable_duplicate_detection: bool = True,
        case_sensitive: bool = False
    ):
        """
        Initialize IOC Hash Validator
        
        Args:
            whitelist_hashes: List of known safe hashes
            blacklist_hashes: List of known malicious hashes
            enable_duplicate_detection: Track processed hashes
            case_sensitive: Whether hash comparison is case-sensitive
        """
        self.whitelist = set(h.lower() for h in (whitelist_hashes or []))
        self.blacklist = set(h.lower() for h in (blacklist_hashes or []))
        self.enable_duplicate_detection = enable_duplicate_detection
        self.case_sensitive = case_sensitive
        self.processed_hashes: Dict[str, datetime] = {}
        self.validation_stats: Dict[str, int] = {
            "total_processed": 0,
            "valid": 0,
            "invalid_format": 0,
            "whitelisted": 0,
            "blacklisted": 0,
            "duplicates": 0
        }

    def detect_hash_type(self, hash_value: str) -> HashType:
        """
        Auto-detect hash type based on length and format
        
        Args:
            hash_value: The hash string to analyze
            
        Returns:
            Detected HashType or UNKNOWN
        """
        normalized = hash_value.strip()
        
        for hash_type, pattern in self.HASH_PATTERNS.items():
            if pattern.match(normalized):
                # SHA256 and SHA3-256 have same length, default to SHA256
                if hash_type == HashType.SHA3_256 and len(normalized) == 64:
                    return HashType.SHA256
                return hash_type
        
        return HashType.UNKNOWN

    def normalize_hash(self, hash_value: str) -> str:
        """
        Normalize hash to standard format (lowercase, trimmed)
        
        Args:
            hash_value: Raw hash string
            
        Returns:
            Normalized hash string
        """
        normalized = hash_value.strip()
        if not self.case_sensitive:
            normalized = normalized.lower()
        return normalized

    def validate_hash_format(self, hash_value: str, hash_type: HashType) -> Tuple[bool, str]:
        """
        Validate hash format against expected pattern
        
        Args:
            hash_value: Hash to validate
            hash_type: Expected hash type
            
        Returns:
            Tuple of (is_valid, reason)
        """
        if hash_type == HashType.UNKNOWN:
            return False, "Unknown hash type"
        
        pattern = self.HASH_PATTERNS.get(hash_type)
        if not pattern:
            return False, f"No pattern defined for {hash_type.value}"
        
        if not pattern.match(hash_value.strip()):
            return False, f"Hash does not match {hash_type.value} format"
        
        return True, "Format validation passed"

    def validate_single_hash(
        self,
        hash_value: str,
        expected_type: Optional[HashType] = None
    ) -> HashValidationResult:
        """
        Validate a single hash IOC
        
        Args:
            hash_value: The hash to validate
            expected_type: Optional expected hash type
            
        Returns:
            HashValidationResult with full validation details
        """
        self.validation_stats["total_processed"] += 1
        
        normalized = self.normalize_hash(hash_value)
        detected_type = expected_type or self.detect_hash_type(hash_value)
        
        # Check whitelist first
        if normalized in self.whitelist:
            self.validation_stats["whitelisted"] += 1
            return HashValidationResult(
                hash_value=hash_value,
                hash_type=detected_type,
                status=HashValidationStatus.WHITELISTED,
                normalized_hash=normalized,
                is_valid=False,
                confidence_score=1.0,
                validation_details={"reason": "Hash found in whitelist"}
            )
        
        # Check blacklist
        if normalized in self.blacklist:
            self.validation_stats["blacklisted"] += 1
            return HashValidationResult(
                hash_value=hash_value,
                hash_type=detected_type,
                status=HashValidationStatus.BLACKLISTED,
                normalized_hash=normalized,
                is_valid=True,
                confidence_score=1.0,
                validation_details={"reason": "Hash found in blacklist - confirmed malicious"},
                enrichment_data={"threat_level": "high"}
            )
        
        # Check duplicates
        if self.enable_duplicate_detection and normalized in self.processed_hashes:
            self.validation_stats["duplicates"] += 1
            return HashValidationResult(
                hash_value=hash_value,
                hash_type=detected_type,
                status=HashValidationStatus.DUPLICATE,
                normalized_hash=normalized,
                is_valid=True,
                confidence_score=0.95,
                validation_details={
                    "reason": "Duplicate hash",
                    "first_seen": self.processed_hashes[normalized].isoformat()
                }
            )
        
        # Validate format
        format_valid, format_reason = self.validate_hash_format(hash_value, detected_type)
        
        if not format_valid:
            self.validation_stats["invalid_format"] += 1
            return HashValidationResult(
                hash_value=hash_value,
                hash_type=detected_type,
                status=HashValidationStatus.INVALID_FORMAT,
                normalized_hash=normalized,
                is_valid=False,
                confidence_score=0.0,
                validation_details={"reason": format_reason}
            )
        
        # Valid hash
        self.validation_stats["valid"] += 1
        self.processed_hashes[normalized] = datetime.now(timezone.utc)
        
        # Calculate confidence based on hash type and validation
        confidence = self._calculate_confidence(detected_type, normalized)
        
        return HashValidationResult(
            hash_value=hash_value,
            hash_type=detected_type,
            status=HashValidationStatus.VALID,
            normalized_hash=normalized,
            is_valid=True,
            confidence_score=confidence,
            validation_details={"reason": "All validations passed"},
            enrichment_data=self._generate_enrichment(detected_type, normalized)
        )

    def validate_batch(
        self,
        hash_list: List[str],
        expected_types: Optional[List[Optional[HashType]]] = None
    ) -> List[HashValidationResult]:
        """
        Validate a batch of hash IOCs
        
        Args:
            hash_list: List of hash strings to validate
            expected_types: Optional list of expected hash types
            
        Returns:
            List of HashValidationResult objects
        """
        results = []
        types = expected_types or [None] * len(hash_list)
        
        for hash_val, exp_type in zip(hash_list, types):
            results.append(self.validate_single_hash(hash_val, exp_type))
        
        return results

    def validate_file_content(self, file_content: bytes) -> Dict[str, HashValidationResult]:
        """
        Generate and validate hashes for file content
        
        Args:
            file_content: Raw file bytes
            
        Returns:
            Dictionary of hash_type -> HashValidationResult
        """
        results = {}
        
        # Calculate all hash types
        hash_functions = {
            HashType.MD5: hashlib.md5(),
            HashType.SHA1: hashlib.sha1(),
            HashType.SHA256: hashlib.sha256(),
            HashType.SHA512: hashlib.sha512(),
            HashType.SHA3_256: hashlib.sha3_256(),
        }
        
        for hash_type, hasher in hash_functions.items():
            hasher.update(file_content)
            hash_value = hasher.hexdigest()
            results[hash_type.value] = self.validate_single_hash(hash_value, hash_type)
        
        return results

    def _calculate_confidence(self, hash_type: HashType, normalized_hash: str) -> float:
        """Calculate confidence score for valid hash"""
        base_scores = {
            HashType.MD5: 0.7,      # MD5 is cryptographically broken
            HashType.SHA1: 0.8,     # SHA1 is weakened
            HashType.SHA256: 0.98,  # SHA256 is secure
            HashType.SHA512: 0.99,  # SHA512 is very secure
            HashType.SHA3_256: 1.0, # SHA3 is most secure
            HashType.UNKNOWN: 0.0
        }
        return base_scores.get(hash_type, 0.5)

    def _generate_enrichment(self, hash_type: HashType, normalized_hash: str) -> Dict[str, Any]:
        """Generate enrichment data for valid hash"""
        return {
            "hash_entropy": self._calculate_entropy(normalized_hash),
            "cryptographic_strength": hash_type.value in ["sha256", "sha512", "sha3-256"],
            "recommended_for_threat_intel": hash_type.value in ["sha256", "sha512"],
            "bit_length": {
                "md5": 128,
                "sha1": 160,
                "sha256": 256,
                "sha512": 512,
                "sha3-256": 256
            }.get(hash_type.value, 0)
        }

    def _calculate_entropy(self, hash_str: str) -> float:
        """Calculate Shannon entropy of hash string"""
        from collections import Counter
        import math
        
        if not hash_str:
            return 0.0
        
        counts = Counter(hash_str)
        entropy = 0.0
        length = len(hash_str)
        
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        
        return round(entropy, 4)

    def get_statistics(self) -> Dict[str, Any]:
        """Get validation statistics"""
        stats = self.validation_stats.copy()
        if stats["total_processed"] > 0:
            stats["valid_percentage"] = round(
                (stats["valid"] / stats["total_processed"]) * 100, 2
            )
        else:
            stats["valid_percentage"] = 0.0
        stats["unique_hashes_processed"] = len(self.processed_hashes)
        return stats

    def export_results(
        self,
        results: List[HashValidationResult],
        format_type: str = "json"
    ) -> str:
        """Export validation results to specified format"""
        if format_type.lower() == "json":
            return json.dumps([r.to_dict() for r in results], indent=2)
        elif format_type.lower() == "jsonl":
            return "\n".join(json.dumps(r.to_dict()) for r in results)
        else:
            raise ValueError(f"Unsupported format: {format_type}")

    def add_to_whitelist(self, hash_values: List[str]) -> None:
        """Add hashes to whitelist"""
        for h in hash_values:
            self.whitelist.add(self.normalize_hash(h))

    def add_to_blacklist(self, hash_values: List[str]) -> None:
        """Add hashes to blacklist"""
        for h in hash_values:
            self.blacklist.add(self.normalize_hash(h))

    def clear_processed_cache(self) -> None:
        """Clear processed hash cache for duplicate detection"""
        self.processed_hashes.clear()
