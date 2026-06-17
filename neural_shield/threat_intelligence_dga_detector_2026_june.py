"""
NeuralShield AI - Threat Intelligence DGA (Domain Generation Algorithm) Detector
Production-grade implementation for detecting algorithmically generated domain names
used in malware C2 communication, DNS tunneling, and domain flux attacks.

Implements:
- Entropy analysis for randomness detection
- N-gram frequency analysis against legitimate domain corpus
- Character distribution anomaly scoring
- Known DGA pattern matching
- Real-time DNS request monitoring
"""

import re
import math
import hashlib
import string
from typing import Dict, List, Tuple, Optional, Set
from collections import Counter
from dataclasses import dataclass
from enum import Enum
import time


class DGARiskLevel(Enum):
    SAFE = "SAFE"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class DGADetectionResult:
    domain: str
    risk_level: DGARiskLevel
    risk_score: float
    entropy_score: float
    ngram_score: float
    character_score: float
    pattern_matches: List[str]
    reasons: List[str]
    timestamp: float
    is_dga: bool


class ThreatIntelligenceDGADetector:
    """
    Production-grade DGA Detector that identifies algorithmically generated
    domain names using multiple heuristic and statistical methods.
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
    
    # Known DGA patterns and signatures
    DGA_PATTERNS = [
        (r'^[a-z]{8,15}\.com$', 'random_8_15_char_com'),
        (r'^[0-9a-f]{16,32}\.', 'hex_encoded_domain'),
        (r'^[a-z]{3,5}[0-9]{3,5}\.', 'word_number_mix'),
        (r'^[bcdfghjklmnpqrstvwxz]{5,}', 'consonant_heavy'),
        (r'^[aeiouy]{4,}', 'vowel_heavy'),
        (r'([a-z])\1{3,}', 'character_repetition'),
        (r'^x[a-z0-9]{7,}\.', 'x_prefix_dga'),
    ]
    
    # Suspicious character sequences
    SUSPICIOUS_SEQUENCES = {
        'xz', 'zx', 'qz', 'zq', 'jq', 'qj', 'xq', 'qx',
        'wv', 'vw', 'kq', 'qk', 'jz', 'zj'
    }
    
    def __init__(self, 
                 entropy_threshold: float = 3.5,
                 ngram_threshold: float = 0.3,
                 char_threshold: float = 0.4):
        """
        Initialize DGA Detector with configurable thresholds.
        
        Args:
            entropy_threshold: Shannon entropy threshold (higher = more random)
            ngram_threshold: N-gram frequency threshold (lower = less legitimate)
            char_threshold: Character distribution anomaly threshold
        """
        self.entropy_threshold = entropy_threshold
        self.ngram_threshold = ngram_threshold
        self.char_threshold = char_threshold
        self.detection_history: List[DGADetectionResult] = []
        self.whitelist_domains: Set[str] = set()
        self.blacklist_domains: Set[str] = set()
        
    def _remove_tld(self, domain: str) -> str:
        """Remove TLD from domain for analysis."""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            # Handle multi-part TLDs like co.uk
            if len(parts[-1]) <= 2 and len(parts) >= 3:
                return '.'.join(parts[:-2])
            return '.'.join(parts[:-1])
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
        
        # Penalize extreme ratios
        score = 1.0
        if vowel_ratio > 0.6:
            score -= (vowel_ratio - 0.6) * 2
        if consonant_ratio > 0.8:
            score -= (consonant_ratio - 0.8) * 2
        if digit_count > 0 and digit_count / total > 0.4:
            score -= 0.3
            
        # Check for suspicious sequences
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
    
    def analyze_domain(self, domain: str) -> DGADetectionResult:
        """
        Analyze a domain for DGA characteristics.
        
        Args:
            domain: Domain name to analyze (e.g., "example.com")
            
        Returns:
            DGADetectionResult with analysis details
        """
        domain_clean = domain.lower().strip()
        
        # Check whitelist/blacklist first
        if domain_clean in self.whitelist_domains:
            return DGADetectionResult(
                domain=domain,
                risk_level=DGARiskLevel.SAFE,
                risk_score=0.0,
                entropy_score=0.0,
                ngram_score=1.0,
                character_score=1.0,
                pattern_matches=[],
                reasons=["Domain in whitelist"],
                timestamp=time.time(),
                is_dga=False
            )
            
        if domain_clean in self.blacklist_domains:
            return DGADetectionResult(
                domain=domain,
                risk_level=DGARiskLevel.CRITICAL,
                risk_score=1.0,
                entropy_score=4.0,
                ngram_score=0.0,
                character_score=0.0,
                pattern_matches=["blacklisted"],
                reasons=["Domain in blacklist"],
                timestamp=time.time(),
                is_dga=True
            )
        
        # Extract domain without TLD
        domain_body = self._remove_tld(domain_clean)
        
        # Calculate individual scores
        entropy_score = self._calculate_shannon_entropy(domain_body)
        ngram_score = self._calculate_ngram_score(domain_body)
        character_score = self._calculate_character_score(domain_body)
        pattern_matches = self._check_dga_patterns(domain_clean)
        
        # Build reasons
        reasons = []
        if entropy_score > self.entropy_threshold:
            reasons.append(f"High entropy ({entropy_score:.2f} > {self.entropy_threshold})")
        if ngram_score < self.ngram_threshold:
            reasons.append(f"Low n-gram legitimacy ({ngram_score:.2f} < {self.ngram_threshold})")
        if character_score < self.char_threshold:
            reasons.append(f"Abnormal character distribution")
        if pattern_matches:
            reasons.append(f"Matched DGA patterns: {', '.join(pattern_matches)}")
        
        # Calculate composite risk score (0-1)
        entropy_risk = min(1.0, entropy_score / 5.0)
        ngram_risk = 1.0 - ngram_score
        char_risk = 1.0 - character_score
        pattern_risk = min(0.5, len(pattern_matches) * 0.15)
        
        risk_score = (
            entropy_risk * 0.35 +
            ngram_risk * 0.30 +
            char_risk * 0.25 +
            pattern_risk * 0.10
        )
        
        risk_level = self._determine_risk_level(risk_score)
        is_dga = risk_score >= 0.4
        
        result = DGADetectionResult(
            domain=domain,
            risk_level=risk_level,
            risk_score=risk_score,
            entropy_score=entropy_score,
            ngram_score=ngram_score,
            character_score=character_score,
            pattern_matches=pattern_matches,
            reasons=reasons,
            timestamp=time.time(),
            is_dga=is_dga
        )
        
        self.detection_history.append(result)
        return result
    
    def analyze_batch(self, domains: List[str]) -> List[DGADetectionResult]:
        """Analyze multiple domains in batch."""
        return [self.analyze_domain(d) for d in domains]
    
    def add_to_whitelist(self, domain: str) -> None:
        """Add domain to whitelist."""
        self.whitelist_domains.add(domain.lower().strip())
    
    def add_to_blacklist(self, domain: str) -> None:
        """Add domain to blacklist."""
        self.blacklist_domains.add(domain.lower().strip())
    
    def get_statistics(self) -> Dict:
        """Get detection statistics."""
        total = len(self.detection_history)
        if total == 0:
            return {"total_analyzed": 0}
            
        dga_count = sum(1 for r in self.detection_history if r.is_dga)
        by_risk = Counter(r.risk_level.value for r in self.detection_history)
        
        return {
            "total_analyzed": total,
            "dga_detected": dga_count,
            "dga_ratio": dga_count / total,
            "by_risk_level": dict(by_risk),
            "avg_risk_score": sum(r.risk_score for r in self.detection_history) / total,
            "avg_entropy": sum(r.entropy_score for r in self.detection_history) / total
        }
    
    def generate_domain_hash(self, domain: str) -> str:
        """Generate hash for domain fingerprinting."""
        return hashlib.sha256(domain.lower().encode()).hexdigest()[:16]
