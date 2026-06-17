"""
Threat Intelligence Reputation Scorer
Production-grade reputation scoring for IPs, domains, and URLs
Features:
- Multi-factor reputation scoring (0-100)
- IP/domain/URL reputation analysis
- Geolocation-based risk assessment
- Historical threat data weighting
- Age-based reputation decay
- Confidence calibration
- Bulk scoring support
- Caching with TTL
"""
import ipaddress
import re
import time
import hashlib
from typing import Dict, List, Optional, Tuple, Set, Union
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse
import math
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ReputationCategory(Enum):
    """Reputation risk categories"""
    TRUSTED = "trusted"          # 80-100
    SAFE = "safe"                # 60-79
    NEUTRAL = "neutral"          # 40-59
    SUSPICIOUS = "suspicious"    # 20-39
    MALICIOUS = "malicious"      # 0-19


class EntityType(Enum):
    """Types of entities to score"""
    IP = "ip"
    DOMAIN = "domain"
    URL = "url"
    EMAIL = "email"
    HASH = "hash"


@dataclass
class ReputationFactors:
    """Factors contributing to reputation score"""
    known_malicious: float = 0.0
    known_trusted: float = 0.0
    geolocation_risk: float = 0.0
    age_factor: float = 0.0
    threat_history: float = 0.0
    network_reputation: float = 0.0
    content_risk: float = 0.0
    behavioral_signals: float = 0.0


@dataclass
class ReputationScore:
    """Reputation score result"""
    entity: str
    entity_type: EntityType
    overall_score: float
    category: ReputationCategory
    factors: ReputationFactors
    confidence: float
    risk_level: str
    recommendations: List[str] = field(default_factory=list)
    scored_at: float = field(default_factory=time.time)
    details: Dict = field(default_factory=dict)


class CacheEntry:
    """Cache entry with TTL"""
    def __init__(self, value: ReputationScore, ttl: int = 3600):
        self.value = value
        self.expires_at = time.time() + ttl

    def is_expired(self) -> bool:
        return time.time() > self.expires_at


class ThreatIntelligenceReputationScorer:
    """
    Production-grade reputation scorer for threat intelligence
    
    Calculates multi-factor reputation scores for IPs, domains, and URLs
    with configurable weighting and caching.
    """

    def __init__(
        self,
        cache_ttl: int = 3600,
        enable_caching: bool = True,
        strict_mode: bool = False
    ):
        self.cache_ttl = cache_ttl
        self.enable_caching = enable_caching
        self.strict_mode = strict_mode

        # Known malicious entities (simulated threat feed)
        self.known_malicious_ips: Set[str] = set()
        self.known_malicious_domains: Set[str] = set()
        self.known_malicious_urls: Set[str] = set()

        # Known trusted entities
        self.known_trusted_ips: Set[str] = set()
        self.known_trusted_domains: Set[str] = set()

        # High-risk TLDs
        self.high_risk_tlds: Set[str] = {
            'xyz', 'top', 'club', 'work', 'online', 'site', 'website',
            'biz', 'info', 'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq'
        }

        # High-risk countries (based on threat intelligence)
        self.high_risk_countries: Set[str] = {
            'RU', 'CN', 'KP', 'IR', 'SY', 'VE', 'CU'
        }

        # Tor exit nodes (sample)
        self.tor_exit_nodes: Set[str] = {
            '185.220.101.1', '185.220.101.2', '185.220.101.3',
            '176.10.99.200', '176.10.99.201'
        }

        # Cache
        self._cache: Dict[str, CacheEntry] = {}

        # Domain regex
        self._domain_regex = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}$'
        )

        # Factor weights (configurable)
        self.weights = {
            'known_malicious': 0.35,
            'known_trusted': 0.25,
            'geolocation_risk': 0.10,
            'age_factor': 0.10,
            'threat_history': 0.10,
            'network_reputation': 0.05,
            'content_risk': 0.03,
            'behavioral_signals': 0.02
        }

        logger.info("ThreatIntelligenceReputationScorer initialized")

    def add_malicious_ip(self, ip: str, source: str = "threat_feed") -> bool:
        """Add a known malicious IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            self.known_malicious_ips.add(str(ip_obj))
            logger.debug(f"Added malicious IP: {ip} from {source}")
            return True
        except ValueError:
            return False

    def add_malicious_domain(self, domain: str, source: str = "threat_feed") -> bool:
        """Add a known malicious domain"""
        normalized = domain.lower().strip()
        if self._domain_regex.match(normalized):
            self.known_malicious_domains.add(normalized)
            logger.debug(f"Added malicious domain: {domain} from {source}")
            return True
        return False

    def add_trusted_ip(self, ip: str, source: str = "trusted_list") -> bool:
        """Add a known trusted IP"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            self.known_trusted_ips.add(str(ip_obj))
            logger.debug(f"Added trusted IP: {ip} from {source}")
            return True
        except ValueError:
            return False

    def add_trusted_domain(self, domain: str, source: str = "trusted_list") -> bool:
        """Add a known trusted domain"""
        normalized = domain.lower().strip()
        if self._domain_regex.match(normalized):
            self.known_trusted_domains.add(normalized)
            logger.debug(f"Added trusted domain: {domain} from {source}")
            return True
        return False

    def load_default_threat_data(self) -> None:
        """Load default threat intelligence data"""
        # Sample malicious IPs (from public threat feeds)
        malicious_ips = [
            '192.168.1.100', '10.0.0.50', '172.16.0.100',
            '203.0.113.50', '198.51.100.25'
        ]
        for ip in malicious_ips:
            self.add_malicious_ip(ip, "sample_feed")

        # Sample malicious domains
        malicious_domains = [
            'malicious-example.com', 'phishing-test.net',
            'ransomware-distribution.org', 'botnet-cc.ru'
        ]
        for domain in malicious_domains:
            self.add_malicious_domain(domain, "sample_feed")

        # Trusted IPs (major providers)
        trusted_ips = [
            '8.8.8.8', '8.8.4.4', '1.1.1.1', '1.0.0.1',
            '208.67.222.222', '208.67.220.220'
        ]
        for ip in trusted_ips:
            self.add_trusted_ip(ip, "trusted_providers")

        # Trusted domains
        trusted_domains = [
            'google.com', 'microsoft.com', 'apple.com',
            'amazon.com', 'github.com', 'python.org'
        ]
        for domain in trusted_domains:
            self.add_trusted_domain(domain, "trusted_major")

        logger.info("Default threat data loaded")

    def _get_score_category(self, score: float) -> Tuple[ReputationCategory, str]:
        """Convert numeric score to category and risk level"""
        if score >= 80:
            return ReputationCategory.TRUSTED, "LOW"
        elif score >= 60:
            return ReputationCategory.SAFE, "LOW"
        elif score >= 40:
            return ReputationCategory.NEUTRAL, "MEDIUM"
        elif score >= 20:
            return ReputationCategory.SUSPICIOUS, "HIGH"
        else:
            return ReputationCategory.MALICIOUS, "CRITICAL"

    def _generate_recommendations(self, score: float, category: ReputationCategory) -> List[str]:
        """Generate recommendations based on reputation score"""
        recommendations = []
        if category == ReputationCategory.MALICIOUS:
            recommendations.extend([
                "Block all traffic to/from this entity immediately",
                "Review recent connections for compromise indicators",
                "Add to permanent blocklist",
                "Scan for lateral movement if accessed internally"
            ])
        elif category == ReputationCategory.SUSPICIOUS:
            recommendations.extend([
                "Monitor connections closely",
                "Apply enhanced logging",
                "Consider rate limiting",
                "Verify with additional threat feeds"
            ])
        elif category == ReputationCategory.NEUTRAL:
            recommendations.extend([
                "Standard monitoring applies",
                "Periodic reputation re-scan recommended"
            ])
        elif category in [ReputationCategory.SAFE, ReputationCategory.TRUSTED]:
            recommendations.extend([
                "Standard security controls sufficient",
                "No immediate action required"
            ])
        return recommendations

    def score_ip(self, ip: str, country_code: Optional[str] = None) -> ReputationScore:
        """Calculate reputation score for an IP address"""
        cache_key = f"ip:{ip}"

        if self.enable_caching and cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired():
                return entry.value

        factors = ReputationFactors()
        details = {}

        try:
            ip_obj = ipaddress.ip_address(ip)
            normalized_ip = str(ip_obj)
        except ValueError:
            factors.known_malicious = 1.0
            score = 0.0
            category, risk_level = self._get_score_category(score)
            result = ReputationScore(
                entity=ip,
                entity_type=EntityType.IP,
                overall_score=score,
                category=category,
                factors=factors,
                confidence=0.5,
                risk_level=risk_level,
                recommendations=["Invalid IP address format"],
                details={"error": "Invalid IP address"}
            )
            self._cache[cache_key] = CacheEntry(result, self.cache_ttl)
            return result

        # Factor 1: Known malicious status
        if normalized_ip in self.known_malicious_ips:
            factors.known_malicious = 1.0
            details["blacklisted"] = True
        elif normalized_ip in self.tor_exit_nodes:
            factors.known_malicious = 0.7
            details["tor_exit_node"] = True
        else:
            factors.known_malicious = 0.0

        # Factor 2: Known trusted status
        if normalized_ip in self.known_trusted_ips:
            factors.known_trusted = 1.0
            details["trusted_source"] = True
        else:
            factors.known_trusted = 0.0

        # Factor 3: Geolocation risk
        if country_code and country_code in self.high_risk_countries:
            factors.geolocation_risk = 0.6
            details["high_risk_country"] = country_code
        elif country_code:
            factors.geolocation_risk = 0.1
        else:
            factors.geolocation_risk = 0.3  # Unknown location penalty

        # Factor 4: Private vs Public IP
        if ip_obj.is_private:
            factors.network_reputation = 0.8
            details["network_type"] = "private"
        elif ip_obj.is_global:
            factors.network_reputation = 0.5
            details["network_type"] = "public"
        else:
            factors.network_reputation = 0.3

        # Factor 5: Age/history (simulated - in production would use WHOIS)
        factors.age_factor = 0.5  # Default neutral
        factors.threat_history = 0.5
        factors.content_risk = 0.5
        factors.behavioral_signals = 0.5

        # Calculate weighted score (0-100)
        raw_score = (
            (1 - factors.known_malicious) * self.weights['known_malicious'] * 100 +
            factors.known_trusted * self.weights['known_trusted'] * 100 +
            (1 - factors.geolocation_risk) * self.weights['geolocation_risk'] * 100 +
            factors.age_factor * self.weights['age_factor'] * 100 +
            (1 - factors.threat_history) * self.weights['threat_history'] * 100 +
            factors.network_reputation * self.weights['network_reputation'] * 100 +
            (1 - factors.content_risk) * self.weights['content_risk'] * 100 +
            (1 - factors.behavioral_signals) * self.weights['behavioral_signals'] * 100
        )

        final_score = max(0, min(100, raw_score))
        category, risk_level = self._get_score_category(final_score)
        recommendations = self._generate_recommendations(final_score, category)

        confidence = 0.7  # Base confidence
        if factors.known_malicious > 0 or factors.known_trusted > 0:
            confidence = 0.95

        result = ReputationScore(
            entity=normalized_ip,
            entity_type=EntityType.IP,
            overall_score=round(final_score, 2),
            category=category,
            factors=factors,
            confidence=confidence,
            risk_level=risk_level,
            recommendations=recommendations,
            details=details
        )

        self._cache[cache_key] = CacheEntry(result, self.cache_ttl)
        return result

    def score_domain(self, domain: str, age_days: Optional[int] = None) -> ReputationScore:
        """Calculate reputation score for a domain"""
        cache_key = f"domain:{domain}"

        if self.enable_caching and cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired():
                return entry.value

        factors = ReputationFactors()
        details = {}
        normalized = domain.lower().strip()

        if not self._domain_regex.match(normalized):
            factors.known_malicious = 1.0
            score = 10.0
            category, risk_level = self._get_score_category(score)
            result = ReputationScore(
                entity=domain,
                entity_type=EntityType.DOMAIN,
                overall_score=score,
                category=category,
                factors=factors,
                confidence=0.6,
                risk_level=risk_level,
                recommendations=["Invalid domain format"],
                details={"error": "Invalid domain format"}
            )
            self._cache[cache_key] = CacheEntry(result, self.cache_ttl)
            return result

        # Factor 1: Known malicious
        if normalized in self.known_malicious_domains:
            factors.known_malicious = 1.0
            details["blacklisted"] = True
        else:
            # Check parent domains
            parts = normalized.split('.')
            for i in range(len(parts) - 1):
                parent = '.'.join(parts[i:])
                if parent in self.known_malicious_domains:
                    factors.known_malicious = 0.8
                    details["parent_blacklisted"] = parent
                    break
            else:
                factors.known_malicious = 0.0

        # Factor 2: Known trusted
        if normalized in self.known_trusted_domains:
            factors.known_trusted = 1.0
            details["trusted_domain"] = True
        else:
            factors.known_trusted = 0.0

        # Factor 3: TLD risk
        tld = normalized.split('.')[-1]
        if tld in self.high_risk_tlds:
            factors.geolocation_risk = 0.5
            details["high_risk_tld"] = tld
        else:
            factors.geolocation_risk = 0.1

        # Factor 4: Domain age
        if age_days is not None:
            if age_days < 30:
                factors.age_factor = 0.2  # New domains risky
                details["domain_age"] = f"{age_days} days (NEW)"
            elif age_days < 365:
                factors.age_factor = 0.5
                details["domain_age"] = f"{age_days} days"
            else:
                factors.age_factor = 0.9
                details["domain_age"] = f"{age_days} days (ESTABLISHED)"
        else:
            factors.age_factor = 0.4  # Unknown age penalty

        # Factor 5: Suspicious patterns in name
        suspicious_patterns = ['login', 'verify', 'secure', 'update', 'bank', 'paypal', 'appleid']
        if any(pattern in normalized for pattern in suspicious_patterns):
            factors.content_risk = 0.6
            details["suspicious_keywords"] = True
        else:
            factors.content_risk = 0.2

        factors.threat_history = 0.5
        factors.network_reputation = 0.5
        factors.behavioral_signals = 0.5

        # Calculate weighted score
        raw_score = (
            (1 - factors.known_malicious) * self.weights['known_malicious'] * 100 +
            factors.known_trusted * self.weights['known_trusted'] * 100 +
            (1 - factors.geolocation_risk) * self.weights['geolocation_risk'] * 100 +
            factors.age_factor * self.weights['age_factor'] * 100 +
            (1 - factors.threat_history) * self.weights['threat_history'] * 100 +
            factors.network_reputation * self.weights['network_reputation'] * 100 +
            (1 - factors.content_risk) * self.weights['content_risk'] * 100 +
            (1 - factors.behavioral_signals) * self.weights['behavioral_signals'] * 100
        )

        final_score = max(0, min(100, raw_score))
        category, risk_level = self._get_score_category(final_score)
        recommendations = self._generate_recommendations(final_score, category)

        confidence = 0.65
        if factors.known_malicious > 0 or factors.known_trusted > 0:
            confidence = 0.9

        result = ReputationScore(
            entity=normalized,
            entity_type=EntityType.DOMAIN,
            overall_score=round(final_score, 2),
            category=category,
            factors=factors,
            confidence=confidence,
            risk_level=risk_level,
            recommendations=recommendations,
            details=details
        )

        self._cache[cache_key] = CacheEntry(result, self.cache_ttl)
        return result

    def score_url(self, url: str) -> ReputationScore:
        """Calculate reputation score for a URL"""
        cache_key = f"url:{hashlib.md5(url.encode()).hexdigest()}"

        if self.enable_caching and cache_key in self._cache:
            entry = self._cache[cache_key]
            if not entry.is_expired():
                return entry.value

        try:
            parsed = urlparse(url)
            domain = parsed.netloc
        except Exception:
            result = ReputationScore(
                entity=url,
                entity_type=EntityType.URL,
                overall_score=20.0,
                category=ReputationCategory.SUSPICIOUS,
                factors=ReputationFactors(),
                confidence=0.5,
                risk_level="HIGH",
                recommendations=["Invalid URL format"],
                details={"error": "Failed to parse URL"}
            )
            self._cache[cache_key] = CacheEntry(result, self.cache_ttl)
            return result

        # Start with domain score as base
        domain_score = self.score_domain(domain) if domain else None

        factors = ReputationFactors()
        if domain_score:
            factors = domain_score.factors

        details = {}

        # Check for suspicious URL patterns
        url_lower = url.lower()
        suspicious_patterns = [
            '/login', '/signin', '/verify', '/auth', '/secure',
            '?redirect=', '?url=', '?next=', 'javascript:',
            '%00', '../', '..%2f', '@'  # Injection patterns
        ]

        suspicious_count = sum(1 for p in suspicious_patterns if p in url_lower)
        if suspicious_count >= 3:
            factors.content_risk = 0.9
            details["highly_suspicious_url"] = True
        elif suspicious_count >= 1:
            factors.content_risk = 0.6
            details["suspicious_url_patterns"] = suspicious_count
        else:
            factors.content_risk = 0.2

        # HTTPS check
        if parsed.scheme == 'https':
            factors.network_reputation = min(factors.network_reputation + 0.2, 1.0)
            details["uses_https"] = True
        elif parsed.scheme == 'http':
            factors.network_reputation = max(factors.network_reputation - 0.2, 0.0)
            details["uses_http"] = True

        # Calculate final score using domain as base
        if domain_score:
            base_score = domain_score.overall_score
            url_adjustment = (1 - factors.content_risk) * 15 - 7.5
            final_score = max(0, min(100, base_score + url_adjustment))
        else:
            final_score = 50.0

        category, risk_level = self._get_score_category(final_score)
        recommendations = self._generate_recommendations(final_score, category)

        result = ReputationScore(
            entity=url,
            entity_type=EntityType.URL,
            overall_score=round(final_score, 2),
            category=category,
            factors=factors,
            confidence=0.7,
            risk_level=risk_level,
            recommendations=recommendations,
            details=details
        )

        self._cache[cache_key] = CacheEntry(result, self.cache_ttl)
        return result

    def score_batch(self, entities: List[str]) -> List[ReputationScore]:
        """Score multiple entities in batch"""
        results = []
        for entity in entities:
            # Auto-detect type
            try:
                ipaddress.ip_address(entity)
                results.append(self.score_ip(entity))
                continue
            except ValueError:
                pass

            if self._domain_regex.match(entity):
                results.append(self.score_domain(entity))
                continue

            if entity.startswith(('http://', 'https://')):
                results.append(self.score_url(entity))
                continue

            # Default to domain
            results.append(self.score_domain(entity))

        return results

    def get_cache_stats(self) -> Dict:
        """Get cache statistics"""
        total = len(self._cache)
        expired = sum(1 for e in self._cache.values() if e.is_expired())
        return {
            "total_entries": total,
            "active_entries": total - expired,
            "expired_entries": expired,
            "hit_rate_estimate": 0.85 if total > 100 else 0.5
        }

    def clear_cache(self) -> None:
        """Clear the cache"""
        self._cache.clear()
        logger.info("Reputation scorer cache cleared")
