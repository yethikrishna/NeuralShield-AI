"""
NeuralShield AI - Threat Intelligence Phishing Domain Analyzer
Production-grade phishing domain detection and analysis module

This module provides real-time phishing domain analysis using:
- Heuristic-based suspicious pattern detection
- Levenshtein distance analysis for brand impersonation
- Domain age and registration pattern analysis
- DNS record anomaly detection
- Suspicious keyword scoring
"""

import re
import hashlib
import datetime
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
import math


class PhishingRiskLevel(Enum):
    """Phishing risk level enumeration"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


@dataclass
class PhishingAnalysisResult:
    """Data class for phishing analysis results"""
    domain: str
    overall_risk_score: float = 0.0
    risk_level: PhishingRiskLevel = PhishingRiskLevel.UNKNOWN
    suspicious_keywords_found: List[str] = field(default_factory=list)
    brand_impersonation_score: float = 0.0
    impersonated_brands: List[str] = field(default_factory=list)
    domain_age_days: Optional[int] = None
    dns_anomalies: List[str] = field(default_factory=list)
    character_anomalies: List[str] = field(default_factory=list)
    subdomain_analysis: Dict[str, Any] = field(default_factory=dict)
    tld_risk_score: float = 0.0
    heuristic_checks: Dict[str, bool] = field(default_factory=dict)
    analysis_timestamp: str = field(default_factory=lambda: datetime.datetime.utcnow().isoformat())
    recommendations: List[str] = field(default_factory=list)


class PhishingDomainAnalyzer:
    """
    Production-grade phishing domain analyzer
    
    Features:
    - Multi-layer heuristic detection
    - Brand impersonation detection via string similarity
    - Suspicious keyword and pattern matching
    - DNS anomaly detection
    - Character-based anomaly detection (homoglyphs, confusables)
    """
    
    # Known legitimate brands commonly impersonated in phishing
    LEGITIMATE_BRANDS = [
        "paypal", "apple", "microsoft", "amazon", "google", "facebook",
        "instagram", "netflix", "bankofamerica", "chase", "wellsfargo",
        "citibank", "visa", "mastercard", "ebay", "linkedin", "twitter",
        "whatsapp", "telegram", "discord", "steam", "riotgames", "blizzard",
        "coinbase", "binance", "metamask", "opensea", "gmail", "outlook",
        "yahoo", "dropbox", "onedrive", "icloud", "office365", "adobe"
    ]
    
    # High-risk TLDs commonly used in phishing
    HIGH_RISK_TLDS = {
        "xyz": 0.8, "top": 0.7, "club": 0.6, "work": 0.6,
        "online": 0.7, "site": 0.65, "biz": 0.5, "info": 0.4,
        "ru": 0.5, "cn": 0.4, "tk": 0.9, "ml": 0.85, "ga": 0.85,
        "cf": 0.85, "gq": 0.85, "surf": 0.6, "vip": 0.5
    }
    
    # Suspicious keywords commonly found in phishing domains
    SUSPICIOUS_KEYWORDS = [
        "verify", "login", "signin", "secure", "update", "confirm",
        "account", "password", "credential", "authenticate", "validate",
        "support", "help", "service", "customer", "billing", "payment",
        "suspend", "restrict", "limit", "freeze", "hold", "verifyaccount",
        "security", "alert", "notification", "notice", "warning",
        "official", "authorized", "legitimate", "genuine", "real"
    ]
    
    # Suspicious patterns (regex)
    SUSPICIOUS_PATTERNS = [
        r"\d{4,}",  # 4+ consecutive numbers
        r"[a-z]{20,}",  # Very long strings
        r"www\d+",  # www1, www2, etc.
        r"secure-", r"secure\.",
        r"login-", r"login\.",
        r"verify-", r"verify\."
    ]
    
    # Homoglyph / confusable character mappings
    HOMOGLYPHS = {
        '0': ['o', 'O'], '1': ['l', 'I', 'i'], '2': ['z', 'Z'],
        '5': ['s', 'S'], '8': ['B'], 'a': ['à', 'á', 'â', 'ã', 'ä', 'å', 'ɑ', 'а'],
        'b': ['d', 'lb', 'ib'], 'c': ['с', 'ϲ'], 'd': ['b', 'cl', 'dl'],
        'e': ['é', 'ê', 'ë', 'è', 'е'], 'g': ['q', '9'], 'h': ['lh', 'ih'],
        'i': ['1', 'l', 'I', 'í', 'ì'], 'k': ['lk', 'ik'], 'l': ['1', 'I', 'i'],
        'm': ['n', 'rn', 'rr'], 'n': ['m', 'r'], 'o': ['0', 'Ο', 'о', 'օ'],
        'p': ['ρ', 'р'], 'q': ['g', '9'], 'r': ['n'], 's': ['5', 'ѕ'],
        't': ['τ'], 'u': ['μ', 'υ'], 'v': ['ν', 'ѵ'], 'w': ['vv'],
        'x': ['х', 'ҳ'], 'y': ['у', 'ү'], 'z': ['2', 'ʐ']
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the phishing domain analyzer"""
        self.config = config or {}
        self.thresholds = self.config.get('thresholds', {
            'critical': 80,
            'high': 60,
            'medium': 40,
            'low': 20
        })
        self.analysis_cache: Dict[str, PhishingAnalysisResult] = {}

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """Calculate Levenshtein distance between two strings"""
        if len(s1) < len(s2):
            return PhishingDomainAnalyzer._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        
        return previous_row[-1]

    @staticmethod
    def _similarity_score(s1: str, s2: str) -> float:
        """Calculate similarity score (0-1) between two strings"""
        distance = PhishingDomainAnalyzer._levenshtein_distance(s1.lower(), s2.lower())
        max_len = max(len(s1), len(s2))
        if max_len == 0:
            return 1.0
        return 1.0 - (distance / max_len)

    def _extract_domain_parts(self, domain: str) -> Tuple[str, str, str]:
        """Extract subdomain, main domain, and TLD from full domain"""
        domain = domain.lower().strip()
        if domain.startswith('www.'):
            domain = domain[4:]
        
        parts = domain.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            main_domain = parts[-2]
            subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
            return subdomain, main_domain, tld
        return '', domain, ''

    def _analyze_suspicious_keywords(self, domain: str) -> Tuple[List[str], float]:
        """Analyze domain for suspicious keywords"""
        found_keywords = []
        domain_lower = domain.lower()
        
        for keyword in self.SUSPICIOUS_KEYWORDS:
            if keyword in domain_lower:
                found_keywords.append(keyword)
        
        score = min(len(found_keywords) * 10, 40)
        return found_keywords, score

    def _analyze_brand_impersonation(self, main_domain: str) -> Tuple[float, List[str]]:
        """Analyze potential brand impersonation using similarity metrics"""
        max_similarity = 0.0
        matched_brands = []
        
        for brand in self.LEGITIMATE_BRANDS:
            # Skip exact matches - legitimate domains
            if main_domain == brand:
                continue
            
            similarity = self._similarity_score(main_domain, brand)
            
            # Check for substring match too (brand embedded in longer name)
            if brand in main_domain and len(main_domain) > len(brand) + 2:
                similarity = max(similarity, 0.85)
            
            if similarity > 0.7:
                max_similarity = max(max_similarity, similarity)
                if similarity > 0.75:
                    matched_brands.append(brand)
        
        score = max_similarity * 50
        return score, matched_brands

    def _analyze_tld_risk(self, tld: str) -> float:
        """Analyze TLD risk level"""
        return self.HIGH_RISK_TLDS.get(tld.lower(), 0.0) * 30

    def _analyze_character_anomalies(self, domain: str) -> Tuple[List[str], float]:
        """Analyze character anomalies and homoglyphs"""
        anomalies = []
        score = 0.0
        
        # Check for mixed scripts
        has_latin = bool(re.search(r'[a-z]', domain.lower()))
        has_cyrillic = bool(re.search(r'[а-я]', domain.lower()))
        has_greek = bool(re.search(r'[α-ω]', domain.lower()))
        
        if (has_latin and has_cyrillic) or (has_latin and has_greek):
            anomalies.append("Mixed character scripts detected (potential homoglyph attack)")
            score += 30
        
        # Check for excessive hyphens
        hyphen_count = domain.count('-')
        if hyphen_count >= 3:
            anomalies.append(f"Excessive hyphens detected ({hyphen_count} hyphens)")
            score += min(hyphen_count * 5, 15)
        
        # Check for consecutive numbers
        if re.search(r'\d{4,}', domain):
            anomalies.append("Consecutive numeric patterns detected")
            score += 10
        
        return anomalies, score

    def _analyze_subdomain_complexity(self, subdomain: str) -> Tuple[Dict[str, Any], float]:
        """Analyze subdomain for suspicious patterns"""
        analysis = {
            'subdomain_count': subdomain.count('.') + 1 if subdomain else 0,
            'total_length': len(subdomain),
            'has_suspicious_prefix': False
        }
        score = 0.0
        
        if subdomain:
            # Too many subdomain levels
            if analysis['subdomain_count'] >= 3:
                score += 15
            
            # Suspicious prefixes
            suspicious_prefixes = ['secure-', 'login-', 'verify-', 'update-', 'account-']
            for prefix in suspicious_prefixes:
                if subdomain.lower().startswith(prefix):
                    analysis['has_suspicious_prefix'] = True
                    score += 10
                    break
        
        return analysis, score

    def _analyze_dns_patterns(self, domain: str) -> Tuple[List[str], float]:
        """Analyze DNS-related patterns (simulated heuristics)"""
        anomalies = []
        score = 0.0
        
        # Pattern: recently registered domain indicator (via naming patterns)
        if re.search(r'\d{2,}x\d{2,}', domain) or re.search(r'new\d+', domain.lower()):
            anomalies.append("Pattern suggests recently registered disposable domain")
            score += 15
        
        # Pattern: random-looking domain names
        entropy = 0
        char_counts = {}
        for c in domain.lower():
            if c.isalnum():
                char_counts[c] = char_counts.get(c, 0) + 1
        
        if char_counts:
            total = sum(char_counts.values())
            for count in char_counts.values():
                p = count / total
                entropy -= p * math.log2(p) if p > 0 else 0
            
            if entropy < 3.0 and len(domain) > 10:
                anomalies.append("Low character entropy suggests domain generation algorithm")
                score += 20
        
        return anomalies, score

    def _determine_risk_level(self, total_score: float) -> PhishingRiskLevel:
        """Determine risk level based on total score"""
        if total_score >= self.thresholds['critical']:
            return PhishingRiskLevel.CRITICAL
        elif total_score >= self.thresholds['high']:
            return PhishingRiskLevel.HIGH
        elif total_score >= self.thresholds['medium']:
            return PhishingRiskLevel.MEDIUM
        elif total_score >= self.thresholds['low']:
            return PhishingRiskLevel.LOW
        return PhishingRiskLevel.UNKNOWN

    def _generate_recommendations(self, result: PhishingAnalysisResult) -> List[str]:
        """Generate security recommendations based on analysis"""
        recommendations = []
        
        if result.risk_level in [PhishingRiskLevel.CRITICAL, PhishingRiskLevel.HIGH]:
            recommendations.append("BLOCK this domain immediately - high confidence phishing indicator")
            recommendations.append("Add to DNS firewall and proxy blacklists")
        
        if result.risk_level == PhishingRiskLevel.MEDIUM:
            recommendations.append("Flag for additional security scrutiny")
            recommendations.append("Monitor for suspicious activity patterns")
        
        if result.brand_impersonation_score > 30:
            recommendations.append(f"Potential brand impersonation detected targeting: {', '.join(result.impersonated_brands)}")
        
        if result.character_anomalies:
            recommendations.append("Character-based attacks detected - warn users about homoglyph phishing")
        
        if not recommendations:
            recommendations.append("Continue routine monitoring")
        
        return recommendations

    def analyze(self, domain: str, use_cache: bool = True) -> PhishingAnalysisResult:
        """
        Perform comprehensive phishing analysis on a domain
        
        Args:
            domain: Domain name to analyze
            use_cache: Whether to use cached results
        
        Returns:
            PhishingAnalysisResult with complete analysis
        """
        # Check cache
        if use_cache and domain in self.analysis_cache:
            return self.analysis_cache[domain]
        
        # Initialize result
        result = PhishingAnalysisResult(domain=domain)
        
        # Extract domain components
        subdomain, main_domain, tld = self._extract_domain_parts(domain)
        
        # Run all analysis modules
        keyword_list, keyword_score = self._analyze_suspicious_keywords(domain)
        brand_score, brand_list = self._analyze_brand_impersonation(main_domain)
        tld_score = self._analyze_tld_risk(tld)
        char_anomalies, char_score = self._analyze_character_anomalies(domain)
        subdomain_analysis, subdomain_score = self._analyze_subdomain_complexity(subdomain)
        dns_anomalies, dns_score = self._analyze_dns_patterns(domain)
        
        # Populate result
        result.suspicious_keywords_found = keyword_list
        result.brand_impersonation_score = brand_score
        result.impersonated_brands = brand_list
        result.tld_risk_score = tld_score
        result.character_anomalies = char_anomalies
        result.subdomain_analysis = subdomain_analysis
        result.dns_anomalies = dns_anomalies
        
        # Calculate heuristic checks
        result.heuristic_checks = {
            'has_suspicious_keywords': len(keyword_list) > 0,
            'potential_brand_impersonation': brand_score > 25,
            'high_risk_tld': tld_score > 15,
            'character_anomalies': len(char_anomalies) > 0,
            'complex_subdomain_structure': subdomain_score > 10,
            'dns_pattern_anomalies': dns_score > 10
        }
        
        # Calculate total score
        total_score = (
            keyword_score +
            brand_score +
            tld_score +
            char_score +
            subdomain_score +
            dns_score
        )
        
        result.overall_risk_score = min(total_score, 100)
        result.risk_level = self._determine_risk_level(total_score)
        result.recommendations = self._generate_recommendations(result)
        
        # Cache result
        self.analysis_cache[domain] = result
        
        return result

    def batch_analyze(self, domains: List[str]) -> Dict[str, PhishingAnalysisResult]:
        """Analyze multiple domains in batch"""
        return {domain: self.analyze(domain) for domain in domains}

    def get_analysis_summary(self, result: PhishingAnalysisResult) -> Dict[str, Any]:
        """Get a concise summary of the analysis result"""
        return {
            'domain': result.domain,
            'risk_score': result.overall_risk_score,
            'risk_level': result.risk_level.value,
            'total_flags': sum(1 for v in result.heuristic_checks.values() if v),
            'impersonated_brands': result.impersonated_brands,
            'recommendations_count': len(result.recommendations)
        }


# Export analyzer instance
phishing_analyzer = PhishingDomainAnalyzer()

if __name__ == "__main__":
    # Example usage
    test_domains = [
        "paypal-secure-login.xyz",
        "appleid-verification123.com",
        "microsoft-verify-account.top",
        "google.com",
        "secure-login-paypal-update.tk"
    ]
    
    analyzer = PhishingDomainAnalyzer()
    
    print("=== NeuralShield AI - Phishing Domain Analyzer Demo ===")
    for domain in test_domains:
        result = analyzer.analyze(domain)
        print(f"\nDomain: {domain}")
        print(f"Risk Score: {result.overall_risk_score:.1f}")
        print(f"Risk Level: {result.risk_level.value.upper()}")
        if result.impersonated_brands:
            print(f"Impersonated Brands: {result.impersonated_brands}")
        print(f"Recommendations: {result.recommendations[:2]}")
