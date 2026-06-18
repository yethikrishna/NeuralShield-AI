"""
Threat Intelligence Entropy Analyzer - NeuralShield AI
Production-grade entropy analysis for threat detection

Detects:
- Domain Generation Algorithm (DGA) domains
- Obfuscated payloads and base64 encoded malware
- Encrypted data patterns in traffic
- Random strings used in attacks
"""

import math
import re
import string
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass
from collections import Counter
import hashlib


@dataclass
class EntropyResult:
    """Result container for entropy analysis"""
    input_string: str
    shannon_entropy: float
    metric_entropy: float
    character_distribution: Dict[str, float]
    is_high_entropy: bool
    entropy_rating: str
    threat_score: float
    threat_classification: str
    confidence: float
    analysis_details: Dict[str, Any]


class ThreatIntelligenceEntropyAnalyzer:
    """
    Production-grade entropy analyzer for threat detection.
    
    Uses multiple entropy metrics and pattern analysis to detect:
    - DGA-generated domain names
    - Obfuscated/encoded payloads
    - Encrypted data patterns
    - Randomized attack strings
    """
    
    # Entropy thresholds (calibrated for cybersecurity)
    HIGH_ENTROPY_THRESHOLD = 4.5
    SUSPICIOUS_ENTROPY_THRESHOLD = 3.8
    LOW_ENTROPY_THRESHOLD = 2.0
    
    # DGA detection thresholds
    DGA_ENTROPY_MIN = 3.5
    DGA_ENTROPY_MAX = 5.0
    DGA_VOWEL_RATIO_MAX = 0.25
    DGA_CONSONANT_RUN_MAX = 8
    
    # Character sets
    VOWELS = set('aeiouAEIOU')
    CONSONANTS = set('bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ')
    HEX_CHARS = set('0123456789abcdefABCDEF')
    BASE64_CHARS = set(string.ascii_letters + string.digits + '+/=')
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the entropy analyzer with optional configuration"""
        self.config = config or {}
        self.high_entropy_threshold = self.config.get(
            'high_entropy_threshold', self.HIGH_ENTROPY_THRESHOLD
        )
        self.suspicious_threshold = self.config.get(
            'suspicious_threshold', self.SUSPICIOUS_ENTROPY_THRESHOLD
        )
        self._cache = {}
        self._analysis_stats = {
            'total_analyzed': 0,
            'high_entropy_detected': 0,
            'dga_candidates': 0,
            'obfuscation_candidates': 0
        }
    
    @staticmethod
    def shannon_entropy(data: str) -> float:
        """
        Calculate Shannon entropy for a string.
        
        Shannon entropy H = -Σ p(x) * log2(p(x))
        Higher = more random/unpredictable
        """
        if not data:
            return 0.0
        
        char_counts = Counter(data)
        total_chars = len(data)
        entropy = 0.0
        
        for count in char_counts.values():
            probability = count / total_chars
            entropy -= probability * math.log2(probability)
        
        return round(entropy, 4)
    
    @staticmethod
    def metric_entropy(data: str) -> float:
        """
        Calculate metric entropy (entropy normalized by string length).
        Better for comparing strings of different lengths.
        """
        if not data:
            return 0.0
        max_entropy = math.log2(min(len(set(data)), 256)) if len(set(data)) > 0 else 0
        if max_entropy == 0:
            return 0.0
        return round(ThreatIntelligenceEntropyAnalyzer.shannon_entropy(data) / max_entropy, 4)
    
    def _calculate_character_distribution(self, data: str) -> Dict[str, float]:
        """Calculate distribution statistics for character classes"""
        if not data:
            return {}
        
        total = len(data)
        counts = Counter(data)
        
        distribution = {
            'lowercase': sum(1 for c in data if c.islower()) / total,
            'uppercase': sum(1 for c in data if c.isupper()) / total,
            'digits': sum(1 for c in data if c.isdigit()) / total,
            'special': sum(1 for c in data if not c.isalnum()) / total,
            'vowels': sum(1 for c in data if c in self.VOWELS) / total,
            'consonants': sum(1 for c in data if c in self.CONSONANTS) / total,
            'hex_chars': sum(1 for c in data if c in self.HEX_CHARS) / total,
            'unique_ratio': len(set(data)) / total if total > 0 else 0
        }
        
        return {k: round(v, 4) for k, v in distribution.items()}
    
    def _detect_encoding_patterns(self, data: str) -> Dict[str, Any]:
        """Detect common encoding patterns used in obfuscation"""
        patterns = {}
        
        # Base64 detection
        b64_match = re.fullmatch(r'^[A-Za-z0-9+/]+={0,2}$', data)
        patterns['is_likely_base64'] = bool(b64_match and len(data) % 4 == 0)
        
        # Hex detection
        hex_match = re.fullmatch(r'^[0-9A-Fa-f]+$', data)
        patterns['is_likely_hex'] = bool(hex_match)
        
        # URL encoding detection
        patterns['has_url_encoding'] = '%' in data and bool(re.search(r'%[0-9A-Fa-f]{2}', data))
        
        # Unicode escape detection
        patterns['has_unicode_escapes'] = '\\u' in data or '\\x' in data
        
        # Repetition patterns
        max_repeat = max((len(m.group()) for m in re.finditer(r'(.)\1+', data)), default=0)
        patterns['max_consecutive_repeat'] = max_repeat
        
        return patterns
    
    def _analyze_dga_characteristics(self, domain: str) -> Dict[str, Any]:
        """Analyze domain name for DGA (Domain Generation Algorithm) patterns"""
        domain_clean = domain.lower().split('.')[0] if '.' in domain else domain.lower()
        
        if not domain_clean:
            return {'is_dga_candidate': False}
        
        vowel_ratio = sum(1 for c in domain_clean if c in self.VOWELS) / len(domain_clean)
        consonant_runs = re.findall(r'[bcdfghjklmnpqrstvwxyz]+', domain_clean)
        max_consonant_run = max(len(r) for r in consonant_runs) if consonant_runs else 0
        
        # Check for dictionary words (simplified)
        has_common_word = any(word in domain_clean for word in [
            'mail', 'www', 'login', 'admin', 'secure', 'account',
            'google', 'apple', 'microsoft', 'amazon', 'cloud'
        ])
        
        entropy = self.shannon_entropy(domain_clean)
        
        dga_score = 0.0
        reasons = []
        
        if self.DGA_ENTROPY_MIN <= entropy <= self.DGA_ENTROPY_MAX:
            dga_score += 0.3
            reasons.append('entropy_in_dga_range')
        
        if vowel_ratio < self.DGA_VOWEL_RATIO_MAX:
            dga_score += 0.25
            reasons.append('low_vowel_ratio')
        
        if max_consonant_run >= self.DGA_CONSONANT_RUN_MAX:
            dga_score += 0.25
            reasons.append('long_consonant_run')
        
        if not has_common_word and len(domain_clean) > 10:
            dga_score += 0.2
            reasons.append('no_common_words_long_length')
        
        return {
            'is_dga_candidate': dga_score >= 0.5,
            'dga_score': round(dga_score, 3),
            'vowel_ratio': round(vowel_ratio, 4),
            'max_consonant_run': max_consonant_run,
            'has_common_word': has_common_word,
            'dga_indicators': reasons
        }
    
    def analyze_string(self, input_str: str, context: str = 'general') -> EntropyResult:
        """
        Perform comprehensive entropy analysis on a string.
        
        Args:
            input_str: The string to analyze
            context: Analysis context ('domain', 'payload', 'token', 'general')
        
        Returns:
            EntropyResult with complete analysis
        """
        self._analysis_stats['total_analyzed'] += 1
        
        if not input_str or len(input_str) < 2:
            return EntropyResult(
                input_string=input_str,
                shannon_entropy=0.0,
                metric_entropy=0.0,
                character_distribution={},
                is_high_entropy=False,
                entropy_rating='too_short',
                threat_score=0.0,
                threat_classification='benign',
                confidence=1.0,
                analysis_details={'reason': 'insufficient_length'}
            )
        
        # Calculate core metrics
        shannon = self.shannon_entropy(input_str)
        metric = self.metric_entropy(input_str)
        char_dist = self._calculate_character_distribution(input_str)
        encoding_patterns = self._detect_encoding_patterns(input_str)
        
        # Context-specific analysis
        is_high_entropy = shannon >= self.high_entropy_threshold
        dga_analysis = self._analyze_dga_characteristics(input_str) if context == 'domain' else {}
        
        # Calculate threat score
        threat_score = 0.0
        classification = 'benign'
        confidence = 0.7
        
        if is_high_entropy:
            threat_score += 0.4
            self._analysis_stats['high_entropy_detected'] += 1
        
        if encoding_patterns.get('is_likely_base64') and len(input_str) > 32:
            threat_score += 0.2
            self._analysis_stats['obfuscation_candidates'] += 1
        
        if encoding_patterns.get('is_likely_hex') and len(input_str) > 40:
            threat_score += 0.15
        
        if dga_analysis.get('is_dga_candidate'):
            threat_score += 0.3
            self._analysis_stats['dga_candidates'] += 1
        
        # Determine entropy rating
        if shannon >= self.high_entropy_threshold:
            entropy_rating = 'very_high'
        elif shannon >= self.suspicious_threshold:
            entropy_rating = 'high'
        elif shannon >= self.LOW_ENTROPY_THRESHOLD:
            entropy_rating = 'medium'
        else:
            entropy_rating = 'low'
        
        # Final classification
        if threat_score >= 0.7:
            classification = 'highly_suspicious'
            confidence = 0.85
        elif threat_score >= 0.4:
            classification = 'suspicious'
            confidence = 0.75
        elif threat_score >= 0.2:
            classification = 'notable'
            confidence = 0.6
        
        analysis_details = {
            'encoding_patterns': encoding_patterns,
            'dga_analysis': dga_analysis,
            'context': context,
            'string_length': len(input_str)
        }
        
        return EntropyResult(
            input_string=input_str,
            shannon_entropy=shannon,
            metric_entropy=metric,
            character_distribution=char_dist,
            is_high_entropy=is_high_entropy,
            entropy_rating=entropy_rating,
            threat_score=round(threat_score, 3),
            threat_classification=classification,
            confidence=round(confidence, 2),
            analysis_details=analysis_details
        )
    
    def analyze_batch(self, strings: List[str], context: str = 'general') -> List[EntropyResult]:
        """Analyze a batch of strings efficiently"""
        return [self.analyze_string(s, context) for s in strings]
    
    def get_suspicious_strings(self, strings: List[str], 
                               min_threat_score: float = 0.4) -> List[Tuple[str, EntropyResult]]:
        """Filter and return only suspicious strings from a batch"""
        results = self.analyze_batch(strings)
        return [(r.input_string, r) for r in results if r.threat_score >= min_threat_score]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return dict(self._analysis_stats)
    
    def generate_entropy_fingerprint(self, data: str) -> str:
        """Generate a hash-based fingerprint of entropy characteristics"""
        entropy_val = self.shannon_entropy(data)
        dist = self._calculate_character_distribution(data)
        fingerprint_data = f"{entropy_val}:{dist.get('unique_ratio', 0)}:{len(data)}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
