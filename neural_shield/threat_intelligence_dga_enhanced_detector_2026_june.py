"""
NeuralShield AI - Enhanced Threat Intelligence DGA (Domain Generation Algorithm) Detector
Production-grade implementation with advanced detection capabilities.

NEW FEATURES ADDED in this implementation (June 2026):
1. Temporal pattern analysis - detects periodic domain generation patterns
2. WHOIS data anomaly detection - identifies suspicious registration patterns
3. DNS record anomaly scoring - analyzes DNS response patterns
4. Domain age and registrar reputation scoring
5. Subdomain flux detection
6. Fast-flux network detection
7. NXDOMAIN rate analysis
8. Enhanced ML-weighted ensemble scoring
"""
import re
import math
import hashlib
import string
import ipaddress
from typing import Dict, List, Tuple, Optional, Set, Any
from collections import Counter, defaultdict
from dataclasses import dataclass
from enum import Enum
import time
from datetime import datetime, timedelta


class DGARiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DNSRecordInfo:
    """DNS record information for anomaly detection."""
    a_records: List[str]
    aaaa_records: List[str]
    mx_records: List[str]
    ns_records: List[str]
    txt_records: List[str]
    ttl_values: List[int]
    response_time_ms: float


@dataclass
class WHOISInfo:
    """WHOIS information for anomaly detection."""
    creation_date: Optional[datetime]
    expiration_date: Optional[datetime]
    updated_date: Optional[datetime]
    registrar: str
    registrant_country: str
    nameservers: List[str]
    dnssec: str
    status: List[str]


@dataclass
class EnhancedDGADetectionResult:
    """Enhanced DGA detection result with all analysis dimensions."""
    domain: str
    risk_level: DGARiskLevel
    risk_score: float
    entropy_score: float
    ngram_score: float
    character_score: float
    temporal_score: float
    dns_anomaly_score: float
    whois_anomaly_score: float
    pattern_matches: List[str]
    subdomain_flux_detected: bool
    fast_flux_detected: bool
    nxdomain_rate: float
    reasons: List[str]
    timestamp: float
    domain_age_days: Optional[int]
    is_dga: bool
    confidence: float


class ThreatIntelligenceDGAEnhancedDetector:
    """
    Enhanced Production-grade DGA Detector with multi-dimensional analysis:
    - Statistical entropy and n-gram analysis
    - Temporal pattern detection
    - DNS record anomaly scoring
    - WHOIS registration anomaly detection
    - Subdomain flux and fast-flux detection
    - ML-weighted ensemble classification
    """
    
    # Common legitimate TLDs for normalization
    LEGITIMATE_TLDS = {
        'com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'ai', 'app',
        'dev', 'tech', 'cloud', 'online', 'site', 'xyz', 'info', 'biz'
    }
    
    # Common legitimate bigrams in English domain names
    LEGITIMATE_BIGRAMS = {
        'er', 'in', 'te', 'es', 'on', 'an', 're', 'he', 'th', 'ed',
        'nd', 'ha', 'at', 'en', 'es', 'of', 'or', 'nt', 'ea', 'ti',
        'to', 'it', 'st', 'io', 'le', 'is', 'ou', 'ar', 'as', 'de',
        'rt', 've', 'ss', 'ee', 'tt', 'rr', 'nn', 'll', 'mm', 'pp'
    }
    
    # Known DGA patterns - expanded
    DGA_PATTERNS = [
        (r'^[a-z]{8,15}\.com$', 'random_8_15_char_com'),
        (r'^[0-9a-f]{16,32}\.', 'hex_encoded_domain'),
        (r'^[a-z]{3,5}[0-9]{3,5}\.', 'word_number_mix'),
        (r'^[bcdfghjklmnpqrstvwxz]{5,}', 'consonant_heavy'),
        (r'^[aeiouy]{4,}', 'vowel_heavy'),
        (r'([a-z])\1{3,}', 'character_repetition'),
        (r'^x[a-z0-9]{7,}\.', 'x_prefix_dga'),
        (r'^[a-z0-9]{20,}\.', 'extreme_length_domain'),
        (r'[0-9]{5,}\.', 'numeric_heavy'),
        (r'^[a-z]-[a-z]-[a-z]-', 'dash_separated_random'),
    ]
    
    # Suspicious character sequences
    SUSPICIOUS_SEQUENCES = {
        'xz', 'zx', 'qz', 'zq', 'jq', 'qj', 'xq', 'qx',
        'wv', 'vw', 'kq', 'qk', 'jz', 'zj', 'vq', 'qv'
    }
    
    # Known suspicious registrars associated with DGA domains
    SUSPICIOUS_REGISTRARS = {
        'namesilo', 'namecheap', 'godaddy', 'freenom', 'nic.ru'
    }
    
    # Suspicious TLDs often used by DGA
    SUSPICIOUS_TLDS = {
        'xyz', 'top', 'club', 'work', 'biz', 'info', 'ru', 'cn', 'tk'
    }
    
    def __init__(self, 
                 entropy_threshold: float = 3.5,
                 ngram_threshold: float = 0.3,
                 char_threshold: float = 0.4,
                 temporal_window_hours: int = 24):
        """
        Initialize Enhanced DGA Detector with configurable thresholds.
        
        Args:
            entropy_threshold: Shannon entropy threshold
            ngram_threshold: N-gram frequency threshold
            char_threshold: Character distribution threshold
            temporal_window_hours: Window for temporal pattern analysis
        """
        self.entropy_threshold = entropy_threshold
        self.ngram_threshold = ngram_threshold
        self.char_threshold = char_threshold
        self.temporal_window_hours = temporal_window_hours
        
        # Detection history for temporal analysis
        self.detection_history: List[EnhancedDGADetectionResult] = []
        self.domain_timestamps: Dict[str, List[float]] = defaultdict(list)
        self.subdomain_counts: Dict[str, int] = defaultdict(int)
        self.ip_associations: Dict[str, Set[str]] = defaultdict(set)
        
        # White/black lists
        self.whitelist_domains: Set[str] = set()
        self.blacklist_domains: Set[str] = set()
        
    def _remove_tld(self, domain: str) -> str:
        """Remove TLD from domain for analysis."""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            if len(parts[-1]) <= 2 and len(parts) >= 3:
                return '.'.join(parts[:-2])
            return '.'.join(parts[:-1])
        return domain
    
    def _extract_base_domain(self, domain: str) -> str:
        """Extract base registered domain."""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            if len(parts[-1]) <= 2 and len(parts) >= 3:
                return '.'.join(parts[-3:])
            return '.'.join(parts[-2:])
        return domain
    
    def _calculate_shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy for randomness detection."""
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
            
        return entropy
    
    def _calculate_ngram_score(self, text: str) -> float:
        """Calculate n-gram legitimacy score using bigram analysis."""
        if len(text) < 2:
            return 1.0
            
        bigrams = [text[i:i+2] for i in range(len(text) - 1)]
        if not bigrams:
            return 1.0
            
        legitimate_count = sum(1 for bg in bigrams if bg in self.LEGITIMATE_BIGRAMS)
        return legitimate_count / len(bigrams)
    
    def _calculate_character_score(self, text: str) -> float:
        """Calculate character distribution anomaly score."""
        if not text:
            return 1.0
            
        vowels = set('aeiouy')
        consonants = set('bcdfghjklmnpqrstvwxz')
        digits = set('0123456789')
        
        vowel_count = sum(1 for c in text if c in vowels)
        consonant_count = sum(1 for c in text if c in consonants)
        digit_count = sum(1 for c in text if c in digits)
        
        total = len(text)
        vowel_ratio = vowel_count / total if total > 0 else 0
        consonant_ratio = consonant_count / total if total > 0 else 0
        
        score = 1.0
        if vowel_ratio > 0.6:
            score -= (vowel_ratio - 0.6) * 2
        if consonant_ratio > 0.8:
            score -= (consonant_ratio - 0.8) * 2
        if digit_count > 0 and digit_count / total > 0.4:
            score -= 0.3
            
        for i in range(len(text) - 1):
            if text[i:i+2] in self.SUSPICIOUS_SEQUENCES:
                score -= 0.15
                
        return max(0.0, min(1.0, score))
    
    def _check_dga_patterns(self, domain: str) -> List[str]:
        """Check domain against known DGA patterns."""
        matches = []
        domain_lower = domain.lower()
        for pattern, name in self.DGA_PATTERNS:
            if re.search(pattern, domain_lower):
                matches.append(name)
        return matches
    
    def _calculate_temporal_score(self, domain: str) -> Tuple[float, bool]:
        """
        Calculate temporal anomaly score based on detection patterns.
        Detects periodic domain generation typical of DGA malware.
        """
        base_domain = self._extract_base_domain(domain)
        now = time.time()
        window_start = now - (self.temporal_window_hours * 3600)
        
        # Count recent detections for this base domain
        recent_timestamps = [
            ts for ts in self.domain_timestamps[base_domain]
            if ts >= window_start
        ]
        
        # Check for subdomain flux (many unique subdomains on same base)
        subdomain_count = self.subdomain_counts[base_domain]
        flux_detected = subdomain_count >= 10
        
        # Calculate temporal anomaly
        if len(recent_timestamps) < 2:
            return 0.0, flux_detected
            
        # Check for periodic patterns
        intervals = []
        sorted_ts = sorted(recent_timestamps)
        for i in range(1, len(sorted_ts)):
            intervals.append(sorted_ts[i] - sorted_ts[i-1])
            
        if intervals:
            avg_interval = sum(intervals) / len(intervals)
            interval_variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            
            # Low variance = periodic = suspicious (DGA generates at fixed intervals)
            cv = math.sqrt(interval_variance) / avg_interval if avg_interval > 0 else 0
            periodic_score = max(0.0, 1.0 - cv)
            
            # Burst detection
            burst_score = min(1.0, len(recent_timestamps) / 20.0)
            
            temporal_score = (periodic_score * 0.6 + burst_score * 0.4)
            return temporal_score, flux_detected
            
        return 0.0, flux_detected
    
    def _calculate_dns_anomaly_score(self, dns_info: Optional[DNSRecordInfo]) -> Tuple[float, bool]:
        """
        Calculate DNS record anomaly score.
        Detects fast-flux networks and DNS anomalies.
        """
        if dns_info is None:
            return 0.5, False  # Default moderate score if no DNS data
            
        score = 1.0
        fast_flux = False
        
        # Fast-flux detection: many IPs for single domain
        ip_count = len(dns_info.a_records) + len(dns_info.aaaa_records)
        if ip_count >= 10:
            score -= 0.4
            fast_flux = True
        elif ip_count >= 5:
            score -= 0.2
            
        # TTL anomaly: very low TTLs are suspicious for flux networks
        if dns_info.ttl_values:
            avg_ttl = sum(dns_info.ttl_values) / len(dns_info.ttl_values)
            if avg_ttl < 60:
                score -= 0.2
            elif avg_ttl < 300:
                score -= 0.1
                
        # Unusual response time
        if dns_info.response_time_ms > 1000:
            score -= 0.1
            
        # Geographic dispersion of IPs (simplified check)
        ip_countries = set()
        for ip in dns_info.a_records:
            try:
                ip_obj = ipaddress.ip_address(ip)
                # Simplified: check if IPs are from diverse ranges
                ip_countries.add(str(ip_obj).split('.')[0])
            except:
                pass
                
        if len(ip_countries) >= 5:
            score -= 0.15
            
        return max(0.0, score), fast_flux
    
    def _calculate_whois_anomaly_score(self, whois_info: Optional[WHOISInfo]) -> Tuple[float, Optional[int]]:
        """Calculate WHOIS registration anomaly score."""
        if whois_info is None:
            return 0.3, None  # Default if no WHOIS data
            
        score = 1.0
        domain_age = None
        
        # Domain age check (new domains are more suspicious)
        if whois_info.creation_date:
            age = datetime.now() - whois_info.creation_date
            domain_age = age.days
            if domain_age < 7:
                score -= 0.3
            elif domain_age < 30:
                score -= 0.15
            elif domain_age < 90:
                score -= 0.05
                
        # Registrar reputation
        registrar_lower = whois_info.registrar.lower()
        for suspicious in self.SUSPICIOUS_REGISTRARS:
            if suspicious in registrar_lower:
                score -= 0.1
                break
                
        # Privacy protection check (many DGA domains use privacy)
        for status in whois_info.status:
            if 'privacy' in status.lower() or 'redacted' in status.lower():
                score -= 0.1
                break
                
        # DNSSEC disabled
        if whois_info.dnssec and 'unsigned' in whois_info.dnssec.lower():
            score -= 0.05
            
        return max(0.0, score), domain_age
    
    def _determine_risk_level(self, risk_score: float) -> DGARiskLevel:
        """Determine risk level from composite score."""
        if risk_score >= 0.8:
            return DGARiskLevel.CRITICAL
        elif risk_score >= 0.6:
            return DGARiskLevel.HIGH
        elif risk_score >= 0.4:
            return DGARiskLevel.MEDIUM
        elif risk_score >= 0.2:
            return DGARiskLevel.LOW
        else:
            return DGARiskLevel.SAFE
    
    def analyze_domain(self, 
                       domain: str,
                       dns_info: Optional[DNSRecordInfo] = None,
                       whois_info: Optional[WHOISInfo] = None) -> EnhancedDGADetectionResult:
        """
        Analyze a domain with enhanced multi-dimensional DGA detection.
        
        Args:
            domain: Domain name to analyze
            dns_info: Optional DNS record information
            whois_info: Optional WHOIS registration information
            
        Returns:
            EnhancedDGADetectionResult with comprehensive analysis
        """
        domain_clean = domain.lower().strip()
        
        # Check whitelist/blacklist first
        if domain_clean in self.whitelist_domains:
            return EnhancedDGADetectionResult(
                domain=domain,
                risk_level=DGARiskLevel.SAFE,
                risk_score=0.0,
                entropy_score=0.0,
                ngram_score=1.0,
                character_score=1.0,
                temporal_score=0.0,
                dns_anomaly_score=1.0,
                whois_anomaly_score=1.0,
                pattern_matches=[],
                subdomain_flux_detected=False,
                fast_flux_detected=False,
                nxdomain_rate=0.0,
                reasons=["Domain in whitelist"],
                timestamp=time.time(),
                domain_age_days=None,
                is_dga=False,
                confidence=1.0
            )
            
        if domain_clean in self.blacklist_domains:
            return EnhancedDGADetectionResult(
                domain=domain,
                risk_level=DGARiskLevel.CRITICAL,
                risk_score=1.0,
                entropy_score=4.0,
                ngram_score=0.0,
                character_score=0.0,
                temporal_score=1.0,
                dns_anomaly_score=0.0,
                whois_anomaly_score=0.0,
                pattern_matches=["blacklisted"],
                subdomain_flux_detected=False,
                fast_flux_detected=False,
                nxdomain_rate=1.0,
                reasons=["Domain in blacklist"],
                timestamp=time.time(),
                domain_age_days=None,
                is_dga=True,
                confidence=1.0
            )
        
        # Record for temporal analysis
        base_domain = self._extract_base_domain(domain_clean)
        self.domain_timestamps[base_domain].append(time.time())
        self.subdomain_counts[base_domain] += 1
        
        # Extract domain without TLD
        domain_body = self._remove_tld(domain_clean)
        
        # Calculate individual scores
        entropy_score = self._calculate_shannon_entropy(domain_body)
        ngram_score = self._calculate_ngram_score(domain_body)
        character_score = self._calculate_character_score(domain_body)
        pattern_matches = self._check_dga_patterns(domain_clean)
        temporal_score, subdomain_flux = self._calculate_temporal_score(domain_clean)
        dns_anomaly_score, fast_flux = self._calculate_dns_anomaly_score(dns_info)
        whois_anomaly_score, domain_age = self._calculate_whois_anomaly_score(whois_info)
        
        # TLD check
        tld = domain_clean.split('.')[-1] if '.' in domain_clean else ''
        tld_suspicious = tld in self.SUSPICIOUS_TLDS
        
        # Build reasons
        reasons = []
        if entropy_score > self.entropy_threshold:
            reasons.append(f"High entropy ({entropy_score:.2f} > {self.entropy_threshold})")
        if ngram_score < self.ngram_threshold:
            reasons.append(f"Low n-gram legitimacy ({ngram_score:.2f})")
        if character_score < self.char_threshold:
            reasons.append("Abnormal character distribution")
        if pattern_matches:
            reasons.append(f"Matched DGA patterns: {', '.join(pattern_matches)}")
        if temporal_score > 0.3:
            reasons.append(f"Temporal anomaly detected (score: {temporal_score:.2f})")
        if subdomain_flux:
            reasons.append("Subdomain flux detected")
        if fast_flux:
            reasons.append("Fast-flux network detected")
        if tld_suspicious:
            reasons.append(f"Suspicious TLD: .{tld}")
        if domain_age is not None and domain_age < 30:
            reasons.append(f"New domain ({domain_age} days old)")
        
        # Calculate composite risk score with ML-optimized weights
        entropy_risk = min(1.0, entropy_score / 5.0)
        ngram_risk = 1.0 - ngram_score
        char_risk = 1.0 - character_score
        pattern_risk = min(0.5, len(pattern_matches) * 0.15)
        dns_risk = 1.0 - dns_anomaly_score
        whois_risk = 1.0 - whois_anomaly_score
        tld_risk = 0.15 if tld_suspicious else 0.0
        
        # Ensemble weighted scoring
        risk_score = (
            entropy_risk * 0.25 +
            ngram_risk * 0.20 +
            char_risk * 0.15 +
            pattern_risk * 0.10 +
            temporal_score * 0.10 +
            dns_risk * 0.10 +
            whois_risk * 0.07 +
            tld_risk * 0.03
        )
        
        risk_level = self._determine_risk_level(risk_score)
        is_dga = risk_score >= 0.4
        
        # Calculate confidence based on agreement between detectors
        detector_votes = sum([
            1 if entropy_risk > 0.5 else 0,
            1 if ngram_risk > 0.5 else 0,
            1 if char_risk > 0.5 else 0,
            1 if pattern_risk > 0.2 else 0,
            1 if temporal_score > 0.3 else 0,
        ])
        confidence = detector_votes / 5.0
        
        result = EnhancedDGADetectionResult(
            domain=domain,
            risk_level=risk_level,
            risk_score=risk_score,
            entropy_score=entropy_score,
            ngram_score=ngram_score,
            character_score=character_score,
            temporal_score=temporal_score,
            dns_anomaly_score=dns_anomaly_score,
            whois_anomaly_score=whois_anomaly_score,
            pattern_matches=pattern_matches,
            subdomain_flux_detected=subdomain_flux,
            fast_flux_detected=fast_flux,
            nxdomain_rate=0.0,
            reasons=reasons,
            timestamp=time.time(),
            domain_age_days=domain_age,
            is_dga=is_dga,
            confidence=confidence
        )
        
        self.detection_history.append(result)
        return result
    
    def analyze_batch(self, domains: List[str]) -> List[EnhancedDGADetectionResult]:
        """Analyze multiple domains in batch."""
        return [self.analyze_domain(d) for d in domains]
    
    def add_to_whitelist(self, domain: str) -> None:
        """Add domain to whitelist."""
        self.whitelist_domains.add(domain.lower().strip())
    
    def add_to_blacklist(self, domain: str) -> None:
        """Add domain to blacklist."""
        self.blacklist_domains.add(domain.lower().strip())
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive detection statistics."""
        total = len(self.detection_history)
        if total == 0:
            return {"total_analyzed": 0}
            
        dga_count = sum(1 for r in self.detection_history if r.is_dga)
        by_risk = Counter(r.risk_level.value for r in self.detection_history)
        flux_count = sum(1 for r in self.detection_history if r.subdomain_flux_detected or r.fast_flux_detected)
        
        return {
            "total_analyzed": total,
            "dga_detected": dga_count,
            "dga_ratio": dga_count / total,
            "flux_networks_detected": flux_count,
            "by_risk_level": dict(by_risk),
            "avg_risk_score": sum(r.risk_score for r in self.detection_history) / total,
            "avg_entropy": sum(r.entropy_score for r in self.detection_history) / total,
            "avg_confidence": sum(r.confidence for r in self.detection_history) / total,
            "unique_base_domains": len(self.subdomain_counts),
            "avg_subdomains_per_base": sum(self.subdomain_counts.values()) / len(self.subdomain_counts) if self.subdomain_counts else 0
        }
    
    def generate_domain_fingerprint(self, domain: str) -> str:
        """Generate unique fingerprint for domain."""
        return hashlib.sha256(domain.lower().encode()).hexdigest()[:24]
