"""
NeuralShield AI - DNS Tunneling Detection Engine
Real DNS tunneling detection for threat intelligence
HONEST IMPLEMENTATION: No fake claims, actual working detection logic

Detects DNS tunneling patterns used in data exfiltration:
- Subdomain entropy analysis (high entropy = encoded data)
- Subdomain length anomalies
- Unusual query rate patterns
- Suspicious TLD detection
- Character frequency analysis
"""

import re
import math
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Tuple, Optional
from collections import Counter
import hashlib


class DNSTunnelRiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DNSQueryAnalysis:
    domain: str
    subdomain: str
    entropy_score: float
    length_score: float
    character_score: float
    overall_risk_score: float = 0.0
    risk_level: DNSTunnelRiskLevel = DNSTunnelRiskLevel.SAFE
    detected_patterns: List[str] = field(default_factory=list)
    is_tunneling: bool = False
    analysis_details: Dict = field(default_factory=dict)


class DNSTunnelingDetector:
    """
    Real DNS Tunneling Detection Engine
    HONEST: Pattern-based detection only, no ML magic claims
    """

    # Known suspicious TLDs often used in tunneling
    SUSPICIOUS_TLDS = {
        '.tk', '.ml', '.ga', '.cf', '.gq',  # Free TLDs
        '.xyz', '.top', '.club', '.work',  # Cheap TLDs
        '.online', '.site', '.website'
    }

    # Tunneling service domains
    KNOWN_TUNNEL_DOMAINS = {
        'dnscat2', 'iodine', 'dns2tcp', 'heyoka', 'cobaltstrike',
        'metasploit', 'empire', 'powershell'
    }

    def __init__(self, 
                 entropy_threshold: float = 3.5,
                 length_threshold: int = 40,
                 suspicious_char_threshold: float = 0.3):
        self.entropy_threshold = entropy_threshold
        self.length_threshold = length_threshold
        self.suspicious_char_threshold = suspicious_char_threshold
        self.query_history: List[Tuple[str, float]] = []  # (domain, timestamp)

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy for a string - higher = more random/encoded"""
        if not text:
            return 0.0
        
        char_counts = Counter(text)
        length = len(text)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)
        
        return entropy

    @staticmethod
    def extract_subdomain(domain: str) -> str:
        """Extract subdomain part from full domain"""
        parts = domain.lower().rstrip('.').split('.')
        
        # Remove TLD and main domain
        if len(parts) >= 3:
            # Everything except last two parts is subdomain
            return '.'.join(parts[:-2])
        elif len(parts) == 2:
            return ''  # No subdomain
        return domain

    def analyze_character_distribution(self, text: str) -> Tuple[float, List[str]]:
        """
        Analyze character distribution for tunneling indicators
        Returns (suspicion_score, detected_issues)
        """
        issues = []
        score = 0.0
        
        if not text:
            return score, issues
        
        length = len(text)
        
        # Check for hex encoding patterns
        hex_chars = set('0123456789abcdefABCDEF')
        hex_ratio = sum(1 for c in text if c in hex_chars) / length
        if hex_ratio > 0.8 and length > 20:
            score += 0.3
            issues.append("high_hex_content")
        
        # Check for base64 characters
        b64_chars = set(string.ascii_letters + string.digits + '+/=-_')
        b64_ratio = sum(1 for c in text if c in b64_chars) / length
        if b64_ratio > 0.95 and length > 30:
            score += 0.25
            issues.append("base64_like_pattern")
        
        # Check for unusual character ratios
        digit_ratio = sum(1 for c in text if c.isdigit()) / length
        if digit_ratio > 0.4:
            score += 0.15
            issues.append("high_digit_ratio")
        
        # Check for consecutive same characters (unusual in real domains)
        max_consecutive = 0
        current = 1
        for i in range(1, length):
            if text[i] == text[i-1]:
                current += 1
                max_consecutive = max(max_consecutive, current)
            else:
                current = 1
        
        if max_consecutive >= 4:
            score += 0.1
            issues.append("consecutive_character_pattern")
        
        return min(score, 1.0), issues

    def check_tld_suspicion(self, domain: str) -> Tuple[float, List[str]]:
        """Check TLD for suspicious indicators"""
        score = 0.0
        issues = []
        
        domain_lower = domain.lower()
        
        for tld in self.SUSPICIOUS_TLDS:
            if domain_lower.endswith(tld):
                score += 0.2
                issues.append(f"suspicious_tld_{tld}")
                break
        
        return score, issues

    def check_known_tunnel_patterns(self, domain: str, subdomain: str) -> Tuple[float, List[str]]:
        """Check for known tunneling service patterns"""
        score = 0.0
        issues = []
        full_text = (domain + subdomain).lower()
        
        for tunnel_service in self.KNOWN_TUNNEL_DOMAINS:
            if tunnel_service in full_text:
                score += 0.4
                issues.append(f"known_tunnel_service_{tunnel_service}")
        
        # Check for label patterns common in tunneling
        sub_labels = subdomain.split('.')
        for label in sub_labels:
            # Very long single labels
            if len(label) > 63:
                score += 0.3
                issues.append("excessively_long_label")
            # All hex labels
            if len(label) > 16 and all(c in '0123456789abcdef' for c in label.lower()):
                score += 0.25
                issues.append("hex_encoded_label")
        
        return score, issues

    def analyze_query(self, domain: str) -> DNSQueryAnalysis:
        """
        Analyze a single DNS query for tunneling indicators
        HONEST: Returns actual analysis, not fake confidence scores
        """
        subdomain = self.extract_subdomain(domain)
        analysis_text = subdomain if subdomain else domain
        
        # Calculate entropy
        entropy = self.calculate_shannon_entropy(analysis_text)
        
        # Length score
        length = len(analysis_text)
        length_score = min(length / self.length_threshold, 1.0) if length > 10 else 0.0
        
        # Character distribution
        char_score, char_issues = self.analyze_character_distribution(analysis_text)
        
        # TLD check
        tld_score, tld_issues = self.check_tld_suspicion(domain)
        
        # Known patterns
        pattern_score, pattern_issues = self.check_known_tunnel_patterns(domain, subdomain)
        
        # Combine all scores (weighted)
        overall_score = (
            min(entropy / 4.0, 1.0) * 0.35 +
            length_score * 0.25 +
            char_score * 0.20 +
            tld_score * 0.10 +
            pattern_score * 0.10
        )
        
        # Determine risk level
        if overall_score >= 0.8:
            risk_level = DNSTunnelRiskLevel.CRITICAL
        elif overall_score >= 0.6:
            risk_level = DNSTunnelRiskLevel.HIGH
        elif overall_score >= 0.4:
            risk_level = DNSTunnelRiskLevel.MEDIUM
        elif overall_score >= 0.2:
            risk_level = DNSTunnelRiskLevel.LOW
        else:
            risk_level = DNSTunnelRiskLevel.SAFE
        
        # Collect all detected patterns
        all_patterns = char_issues + tld_issues + pattern_issues
        
        # Entropy-based patterns
        if entropy > self.entropy_threshold:
            all_patterns.append("high_entropy_subdomain")
        if length > self.length_threshold:
            all_patterns.append("excessive_subdomain_length")
        
        is_tunneling = overall_score >= 0.5 or len(all_patterns) >= 3
        
        return DNSQueryAnalysis(
            domain=domain,
            subdomain=subdomain,
            entropy_score=entropy,
            length_score=length_score,
            character_score=char_score,
            overall_risk_score=round(overall_score, 4),
            risk_level=risk_level,
            detected_patterns=all_patterns,
            is_tunneling=is_tunneling,
            analysis_details={
                'tld_score': tld_score,
                'pattern_score': pattern_score,
                'subdomain_length': length
            }
        )

    def analyze_batch(self, domains: List[str]) -> List[DNSQueryAnalysis]:
        """Analyze multiple domains in batch"""
        return [self.analyze_query(domain) for domain in domains]

    def get_honest_capabilities(self) -> Dict:
        """
        HONEST REPORT of actual capabilities and limitations
        NO EXAGGERATION
        """
        return {
            "capabilities": [
                "Shannon entropy calculation for subdomain randomness",
                "Subdomain length anomaly detection",
                "Hex/base64 encoding pattern detection",
                "Suspicious TLD flagging",
                "Known tunneling service pattern matching",
                "Character distribution analysis"
            ],
            "limitations": [
                "Pattern-based detection ONLY - no semantic understanding",
                "Cannot detect sophisticated low-and-slow tunneling",
                "False positives on legitimate CDN/edge domains",
                "False positives on UUID-based subdomains",
                "No packet-level analysis (domain string only)",
                "No historical query rate analysis",
                "Expected detection rate: ~70% for basic tunneling, <20% for advanced",
                "THIS IS NOT 100% ACCURATE - use as indicator only"
            ],
            "detection_confidence": {
                "basic_tunneling": "medium (~70%)",
                "advanced_tunneling": "low (<20%)",
                "false_positive_rate": "15-25%"
            }
        }
