"""
Threat Intelligence Whitelist Validator
Production-grade whitelist validation for IPs, domains, and URLs

Features:
- IP whitelist validation with CIDR support
- Domain whitelist with subdomain matching
- URL whitelist with pattern matching
- Confidence scoring system
- TTL-based caching
- Bulk validation support
- Custom whitelist source loading
"""

import ipaddress
import re
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class WhitelistType(Enum):
    """Types of whitelist entries"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    CIDR = "cidr"


class ValidationResult(Enum):
    """Validation result status"""
    WHITELISTED = "whitelisted"
    NOT_WHITELISTED = "not_whitelisted"
    INVALID_INPUT = "invalid_input"
    PARTIAL_MATCH = "partial_match"


@dataclass
class WhitelistEntry:
    """Single whitelist entry"""
    value: str
    entry_type: WhitelistType
    source: str = "default"
    confidence: float = 1.0
    added_at: float = field(default_factory=time.time)
    description: str = ""


@dataclass
class ValidationReport:
    """Validation result report"""
    input_value: str
    result: ValidationResult
    matched_entry: Optional[WhitelistEntry] = None
    confidence: float = 0.0
    match_type: str = ""
    validation_time: float = field(default_factory=time.time)
    details: Dict = field(default_factory=dict)


class CacheEntry:
    """Cache entry with TTL"""
    def __init__(self, value: ValidationReport, ttl: int = 300):
        self.value = value
        self.expires_at = time.time() + ttl

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class ThreatIntelligenceWhitelistValidator:
    """
    Production-grade whitelist validator for threat intelligence
    
    Validates IPs, domains, and URLs against trusted whitelists
    with caching and confidence scoring.
    """

    def __init__(
        self,
        cache_ttl: int = 300,
        enable_caching: bool = True,
        strict_domain_matching: bool = False
    ):
        self.cache_ttl = cache_ttl
        self.enable_caching = enable_caching
        self.strict_domain_matching = strict_domain_matching
        
        # Whitelist storage
        self.ip_whitelist: Set[str] = set()
        self.cidr_whitelist: List[ipaddress.ip_network] = []
        self.domain_whitelist: Set[str] = set()
        self.url_whitelist: Set[str] = set()
        self.url_patterns: List[re.Pattern] = []
        
        # Entry metadata
        self.entries: Dict[str, WhitelistEntry] = {}
        
        # Cache
        self._cache: Dict[str, CacheEntry] = {}
        
        # Domain regex
        self._domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}$'
        )
        
        logger.info("ThreatIntelligenceWhitelistValidator initialized")

    def add_ip(self, ip: str, source: str = "custom", confidence: float = 1.0, description: str = "") -> bool:
        """Add an IP address to whitelist"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            normalized = str(ip_obj)
            self.ip_whitelist.add(normalized)
            self.entries[normalized] = WhitelistEntry(
                value=normalized,
                entry_type=WhitelistType.IP,
                source=source,
                confidence=confidence,
                description=description
            )
            logger.debug(f"Added IP to whitelist: {normalized}")
            return True
        except ValueError:
            logger.warning(f"Invalid IP address: {ip}")
            return False

    def add_cidr(self, cidr: str, source: str = "custom", confidence: float = 1.0, description: str = "") -> bool:
        """Add a CIDR range to whitelist"""
        try:
            network = ipaddress.ip_network(cidr, strict=False)
            self.cidr_whitelist.append(network)
            key = f"cidr:{cidr}"
            self.entries[key] = WhitelistEntry(
                value=str(network),
                entry_type=WhitelistType.CIDR,
                source=source,
                confidence=confidence,
                description=description
            )
            logger.debug(f"Added CIDR to whitelist: {network}")
            return True
        except ValueError:
            logger.warning(f"Invalid CIDR: {cidr}")
            return False

    def add_domain(self, domain: str, source: str = "custom", confidence: float = 1.0, description: str = "") -> bool:
        """Add a domain to whitelist"""
        if not self._domain_regex.match(domain):
            logger.warning(f"Invalid domain format: {domain}")
            return False
        
        normalized = domain.lower().strip()
        self.domain_whitelist.add(normalized)
        self.entries[f"domain:{normalized}"] = WhitelistEntry(
            value=normalized,
            entry_type=WhitelistType.DOMAIN,
            source=source,
            confidence=confidence,
            description=description
        )
        logger.debug(f"Added domain to whitelist: {normalized}")
        return True

    def add_url(self, url: str, source: str = "custom", confidence: float = 1.0, description: str = "") -> bool:
        """Add a URL to whitelist"""
        try:
            parsed = urlparse(url)
            if not parsed.scheme or not parsed.netloc:
                logger.warning(f"Invalid URL: {url}")
                return False
            
            normalized = url.lower().strip()
            self.url_whitelist.add(normalized)
            self.entries[f"url:{normalized}"] = WhitelistEntry(
                value=normalized,
                entry_type=WhitelistType.URL,
                source=source,
                confidence=confidence,
                description=description
            )
            logger.debug(f"Added URL to whitelist: {normalized}")
            return True
        except Exception:
            logger.warning(f"Error parsing URL: {url}")
            return False

    def add_url_pattern(self, pattern: str, source: str = "custom", confidence: float = 0.9) -> bool:
        """Add a regex pattern for URL matching"""
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
            self.url_patterns.append(compiled)
            logger.debug(f"Added URL pattern: {pattern}")
            return True
        except re.error:
            logger.warning(f"Invalid regex pattern: {pattern}")
            return False

    def load_default_whitelists(self) -> None:
        """Load default trusted whitelists"""
        # Cloudflare DNS
        self.add_ip("1.1.1.1", "cloudflare", 1.0, "Cloudflare DNS")
        self.add_ip("1.0.0.1", "cloudflare", 1.0, "Cloudflare DNS")
        
        # Google DNS
        self.add_ip("8.8.8.8", "google", 1.0, "Google DNS")
        self.add_ip("8.8.4.4", "google", 1.0, "Google DNS")
        
        # Cloudflare range
        self.add_cidr("104.16.0.0/12", "cloudflare", 0.95, "Cloudflare CDN")
        
        # Trusted domains
        self.add_domain("github.com", "trusted", 1.0, "GitHub")
        self.add_domain("gitlab.com", "trusted", 1.0, "GitLab")
        self.add_domain("python.org", "trusted", 1.0, "Python")
        self.add_domain("pypi.org", "trusted", 1.0, "PyPI")
        self.add_domain("npmjs.com", "trusted", 1.0, "npm")
        self.add_domain("docker.io", "trusted", 1.0, "Docker Hub")
        
        logger.info("Default whitelists loaded")

    def validate_ip(self, ip: str) -> ValidationReport:
        """Validate if an IP is whitelisted"""
        cache_key = f"ip:{ip}"
        
        if self.enable_caching and cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired():
                return entry.value
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            normalized = str(ip_obj)
            
            # Exact IP match
            if normalized in self.ip_whitelist:
                entry = self.entries.get(normalized)
                report = ValidationReport(
                    input_value=ip,
                    result=ValidationResult.WHITELISTED,
                    matched_entry=entry,
                    confidence=entry.confidence if entry else 1.0,
                    match_type="exact_ip",
                    details={"normalized": normalized}
                )
                self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
                return report
            
            # CIDR match
            for network in self.cidr_whitelist:
                if ip_obj in network:
                    entry_key = f"cidr:{network}"
                    entry = self.entries.get(entry_key)
                    report = ValidationReport(
                        input_value=ip,
                        result=ValidationResult.WHITELISTED,
                        matched_entry=entry,
                        confidence=entry.confidence if entry else 0.9,
                        match_type="cidr_match",
                        details={"network": str(network)}
                    )
                    self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
                    return report
            
            report = ValidationReport(
                input_value=ip,
                result=ValidationResult.NOT_WHITELISTED,
                confidence=0.0,
                match_type="none"
            )
            self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
            return report
            
        except ValueError:
            return ValidationReport(
                input_value=ip,
                result=ValidationResult.INVALID_INPUT,
                confidence=0.0,
                match_type="invalid",
                details={"error": "Invalid IP address"}
            )

    def validate_domain(self, domain: str) -> ValidationReport:
        """Validate if a domain is whitelisted"""
        cache_key = f"domain:{domain}"
        
        if self.enable_caching and cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired():
                return entry.value
        
        normalized = domain.lower().strip()
        
        if not self._domain_regex.match(normalized):
            return ValidationReport(
                input_value=domain,
                result=ValidationResult.INVALID_INPUT,
                confidence=0.0,
                match_type="invalid",
                details={"error": "Invalid domain format"}
            )
        
        # Exact match
        if normalized in self.domain_whitelist:
            entry = self.entries.get(f"domain:{normalized}")
            report = ValidationReport(
                input_value=domain,
                result=ValidationResult.WHITELISTED,
                matched_entry=entry,
                confidence=entry.confidence if entry else 1.0,
                match_type="exact_domain"
            )
            self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
            return report
        
        # Subdomain match (if not strict mode)
        if not self.strict_domain_matching:
            parts = normalized.split('.')
            for i in range(len(parts) - 1):
                parent_domain = '.'.join(parts[i:])
                if parent_domain in self.domain_whitelist:
                    entry = self.entries.get(f"domain:{parent_domain}")
                    report = ValidationReport(
                        input_value=domain,
                        result=ValidationResult.WHITELISTED,
                        matched_entry=entry,
                        confidence=(entry.confidence * 0.9) if entry else 0.9,
                        match_type="subdomain",
                        details={"parent_domain": parent_domain}
                    )
                    self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
                    return report
        
        report = ValidationReport(
            input_value=domain,
            result=ValidationResult.NOT_WHITELISTED,
            confidence=0.0,
            match_type="none"
        )
        self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
        return report

    def validate_url(self, url: str) -> ValidationReport:
        """Validate if a URL is whitelisted"""
        cache_key = f"url:{hashlib.md5(url.encode()).hexdigest()}"
        
        if self.enable_caching and cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired():
                return entry.value
        
        try:
            parsed = urlparse(url)
            normalized = url.lower().strip()
            
            # Exact URL match
            if normalized in self.url_whitelist:
                entry = self.entries.get(f"url:{normalized}")
                report = ValidationReport(
                    input_value=url,
                    result=ValidationResult.WHITELISTED,
                    matched_entry=entry,
                    confidence=entry.confidence if entry else 1.0,
                    match_type="exact_url"
                )
                self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
                return report
            
            # Pattern match
            for pattern in self.url_patterns:
                if pattern.search(url):
                    report = ValidationReport(
                        input_value=url,
                        result=ValidationResult.WHITELISTED,
                        confidence=0.85,
                        match_type="pattern",
                        details={"pattern": pattern.pattern}
                    )
                    self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
                    return report
            
            # Validate domain part
            if parsed.netloc:
                domain_report = self.validate_domain(parsed.netloc)
                if domain_report.result == ValidationResult.WHITELISTED:
                    report = ValidationReport(
                        input_value=url,
                        result=ValidationResult.PARTIAL_MATCH,
                        matched_entry=domain_report.matched_entry,
                        confidence=domain_report.confidence * 0.8,
                        match_type="domain_in_url",
                        details={"domain": parsed.netloc}
                    )
                    self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
                    return report
            
            report = ValidationReport(
                input_value=url,
                result=ValidationResult.NOT_WHITELISTED,
                confidence=0.0,
                match_type="none"
            )
            self._cache[cache_key] = CacheEntry(report, self.cache_ttl)
            return report
            
        except Exception as e:
            return ValidationReport(
                input_value=url,
                result=ValidationResult.INVALID_INPUT,
                confidence=0.0,
                match_type="invalid",
                details={"error": str(e)}
            )

    def validate_auto(self, value: str) -> ValidationReport:
        """Automatically detect type and validate"""
        # Try IP first
        try:
            ipaddress.ip_address(value)
            return self.validate_ip(value)
        except ValueError:
            pass
        
        # Try domain
        if self._domain_regex.match(value):
            return self.validate_domain(value)
        
        # Try URL
        if value.startswith(('http://', 'https://', 'ftp://')):
            return self.validate_url(value)
        
        # Default: try domain first, then URL
        domain_result = self.validate_domain(value)
        if domain_result.result != ValidationResult.INVALID_INPUT:
            return domain_result
        
        return self.validate_url(value)

    def bulk_validate(self, values: List[str]) -> List[ValidationReport]:
        """Bulk validate multiple values"""
        return [self.validate_auto(v) for v in values]

    def get_statistics(self) -> Dict:
        """Get whitelist statistics"""
        return {
            "total_entries": len(self.entries),
            "ip_count": len(self.ip_whitelist),
            "cidr_count": len(self.cidr_whitelist),
            "domain_count": len(self.domain_whitelist),
            "url_count": len(self.url_whitelist),
            "url_pattern_count": len(self.url_patterns),
            "cache_size": len(self._cache),
            "cache_hits": 0,  # Would need tracking
            "sources": list(set(e.source for e in self.entries.values()))
        }

    def clear_cache(self) -> None:
        """Clear validation cache"""
        self._cache.clear()
        logger.info("Cache cleared")

    def is_whitelisted(self, value: str, min_confidence: float = 0.5) -> bool:
        """Simple check if value is whitelisted with minimum confidence"""
        report = self.validate_auto(value)
        return (
            report.result in (ValidationResult.WHITELISTED, ValidationResult.PARTIAL_MATCH)
            and report.confidence >= min_confidence
        )
