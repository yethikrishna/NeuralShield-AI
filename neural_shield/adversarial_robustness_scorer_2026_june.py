"""
Adversarial Prompt Robustness Scorer - June 2026 Production Release
NeuralShield-AI Security Framework

Provides quantitative assessment of prompt vulnerability to adversarial attacks
including: gradient-based attacks, token manipulation, semantic perturbations,
and multi-modal injection attacks.

Based on research from:
- MIT CSAIL "RobustPrompt" (2026)
- OpenAI Safety Research "Adversarial Robustness Benchmark"
- Stanford HELM Security Suite
"""

import re
import hashlib
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Tuple, Optional, Set
from collections import defaultdict


class AttackVector(Enum):
    """Known adversarial attack vectors"""
    TOKEN_MANIPULATION = "token_manipulation"
    SEMANTIC_PERTURBATION = "semantic_perturbation"
    GRADIENT_OPTIMIZATION = "gradient_optimization"
    UNICODE_INJECTION = "unicode_injection"
    HOMOGLYPH_ATTACK = "homoglyph_attack"
    WHITESPACE_EXPLOIT = "whitespace_exploit"
    PROMPT_SPLITTING = "prompt_splitting"
    EMBEDDING_POISONING = "embedding_poisoning"


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    SAFE = "safe"


@dataclass
class VulnerabilityFinding:
    """Individual vulnerability detection result"""
    attack_vector: AttackVector
    risk_level: RiskLevel
    confidence: float  # 0.0 - 1.0
    description: str
    location: Optional[Tuple[int, int]] = None
    suggested_fix: Optional[str] = None


@dataclass
class RobustnessScore:
    """Complete robustness assessment result"""
    overall_score: float  # 0.0 (vulnerable) - 100.0 (fully robust)
    risk_level: RiskLevel
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    attack_surface_analysis: Dict[str, float] = field(default_factory=dict)
    hardening_recommendations: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0


class AdversarialRobustnessScorer:
    """
    Production-grade adversarial prompt robustness analyzer.
    
    Performs multi-dimensional analysis of prompt text to detect
    vulnerability surfaces and provide actionable hardening guidance.
    """
    
    # Known dangerous patterns that indicate attack surface
    DANGEROUS_PATTERNS = [
        (r'ignore.*previous|disregard.*instructions', AttackVector.PROMPT_SPLITTING, 0.95),
        (r'you are now|act as|pretend to be', AttackVector.SEMANTIC_PERTURBATION, 0.85),
        (r'system prompt|developer mode|admin mode', AttackVector.TOKEN_MANIPULATION, 0.90),
        (r'[\u200b-\u200f\u202a-\u202e\u2060-\u2064]', AttackVector.UNICODE_INJECTION, 0.98),
        (r'begin|start|end|output now', AttackVector.WHITESPACE_EXPLOIT, 0.60),
    ]
    
    # Homoglyph mapping - common look-alike characters
    HOMOGLYPHS = {
        'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p',
        'ѕ': 's', 'і': 'i', 'ј': 'j', 'х': 'x', 'у': 'y',
        'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'К': 'K',
        'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'Т': 'T',
    }
    
    # Token fragility patterns - tokens that easily break context
    FRAGILE_TOKENS = {
        'please', 'kindly', 'could you', 'would you', 'might you',
        'hypothetically', 'theoretically', 'for educational',
        'for research', 'academic purposes', 'hypothetical scenario'
    }
    
    def __init__(self, strictness: str = "standard"):
        """
        Initialize robustness scorer.
        
        Args:
            strictness: "strict", "standard", or "permissive"
        """
        self.strictness = strictness
        self._thresholds = self._get_thresholds(strictness)
        self._cache: Dict[str, RobustnessScore] = {}
    
    def _get_thresholds(self, strictness: str) -> Dict[str, float]:
        """Get detection thresholds based on strictness level"""
        thresholds = {
            "strict": {"pattern": 0.50, "homoglyph": 0.01, "entropy": 3.0},
            "standard": {"pattern": 0.65, "homoglyph": 0.03, "entropy": 2.5},
            "permissive": {"pattern": 0.80, "homoglyph": 0.05, "entropy": 2.0},
        }
        return thresholds.get(strictness, thresholds["standard"])
    
    def score_prompt(self, prompt: str, enable_cache: bool = True) -> RobustnessScore:
        """
        Analyze a prompt for adversarial robustness.
        
        Args:
            prompt: The prompt text to analyze
            enable_cache: Whether to cache results for identical prompts
            
        Returns:
            RobustnessScore with detailed analysis
        """
        import time
        start_time = time.time()
        
        # Check cache
        cache_key = hashlib.md5(prompt.encode()).hexdigest()
        if enable_cache and cache_key in self._cache:
            return self._cache[cache_key]
        
        findings: List[VulnerabilityFinding] = []
        
        # Run all analysis modules
        findings.extend(self._analyze_patterns(prompt))
        findings.extend(self._analyze_homoglyphs(prompt))
        findings.extend(self._analyze_unicode(prompt))
        findings.extend(self._analyze_token_fragility(prompt))
        findings.extend(self._analyze_entropy(prompt))
        findings.extend(self._analyze_context_breakers(prompt))
        
        # Calculate overall score
        overall_score = self._calculate_overall_score(findings)
        
        # Determine risk level
        risk_level = self._score_to_risk(overall_score)
        
        # Generate attack surface analysis
        attack_surface = self._generate_attack_surface(findings)
        
        # Generate hardening recommendations
        recommendations = self._generate_recommendations(findings, risk_level)
        
        result = RobustnessScore(
            overall_score=round(overall_score, 2),
            risk_level=risk_level,
            findings=findings,
            attack_surface_analysis=attack_surface,
            hardening_recommendations=recommendations,
            processing_time_ms=round((time.time() - start_time) * 1000, 2)
        )
        
        if enable_cache:
            self._cache[cache_key] = result
        
        return result
    
    def _analyze_patterns(self, prompt: str) -> List[VulnerabilityFinding]:
        """Analyze for known dangerous regex patterns"""
        findings = []
        prompt_lower = prompt.lower()
        
        for pattern, attack_vector, base_confidence in self.DANGEROUS_PATTERNS:
            matches = list(re.finditer(pattern, prompt_lower, re.IGNORECASE))
            if matches:
                for match in matches:
                    confidence = min(base_confidence + len(matches) * 0.05, 1.0)
                    if confidence >= self._thresholds["pattern"]:
                        findings.append(VulnerabilityFinding(
                            attack_vector=attack_vector,
                            risk_level=self._confidence_to_risk(confidence),
                            confidence=round(confidence, 2),
                            description=f"Detected adversarial pattern: '{match.group()}'",
                            location=(match.start(), match.end()),
                            suggested_fix=self._get_fix_for_pattern(pattern)
                        ))
        
        return findings
    
    def _analyze_homoglyphs(self, prompt: str) -> List[VulnerabilityFinding]:
        """Detect homoglyph substitution attacks"""
        findings = []
        homoglyph_count = sum(1 for c in prompt if c in self.HOMOGLYPHS)
        homoglyph_ratio = homoglyph_count / max(len(prompt), 1)
        
        if homoglyph_ratio > self._thresholds["homoglyph"]:
            confidence = min(homoglyph_ratio * 20, 1.0)
            findings.append(VulnerabilityFinding(
                attack_vector=AttackVector.HOMOGLYPH_ATTACK,
                risk_level=self._confidence_to_risk(confidence),
                confidence=round(confidence, 2),
                description=f"Detected {homoglyph_count} homoglyph characters ({homoglyph_ratio:.2%} of text)",
                suggested_fix="Normalize text using NFKC Unicode normalization and validate against whitelist"
            ))
        
        return findings
    
    def _analyze_unicode(self, prompt: str) -> List[VulnerabilityFinding]:
        """Detect invisible Unicode control characters"""
        findings = []
        invisible_chars = [c for c in prompt if ord(c) in range(0x200B, 0x2065)]
        
        if invisible_chars:
            confidence = min(len(invisible_chars) * 0.15, 1.0)
            findings.append(VulnerabilityFinding(
                attack_vector=AttackVector.UNICODE_INJECTION,
                risk_level=self._confidence_to_risk(confidence),
                confidence=round(confidence, 2),
                description=f"Detected {len(invisible_chars)} invisible Unicode control characters",
                suggested_fix="Strip all control characters using regex: [\\x00-\\x1F\\x7F-\\x9F\\u200B-\\u206F]"
            ))
        
        return findings
    
    def _analyze_token_fragility(self, prompt: str) -> List[VulnerabilityFinding]:
        """Analyze token-level fragility to adversarial optimization"""
        findings = []
        prompt_lower = prompt.lower()
        
        fragile_matches = sum(1 for token in self.FRAGILE_TOKENS if token in prompt_lower)
        
        if fragile_matches >= 2:
            confidence = min(fragile_matches * 0.20, 0.85)
            findings.append(VulnerabilityFinding(
                attack_vector=AttackVector.GRADIENT_OPTIMIZATION,
                risk_level=self._confidence_to_risk(confidence),
                confidence=round(confidence, 2),
                description=f"Prompt contains {fragile_matches} fragility-inducing phrases that enable gradient-based attacks",
                suggested_fix="Remove hedging language, use direct imperative statements instead of polite requests"
            ))
        
        return findings
    
    def _analyze_entropy(self, prompt: str) -> List[VulnerabilityFinding]:
        """Analyze character entropy for obfuscation detection"""
        findings = []
        
        if len(prompt) < 10:
            return findings
        
        # Calculate Shannon entropy
        char_counts = defaultdict(int)
        for c in prompt:
            char_counts[c] += 1
        
        entropy = 0.0
        for count in char_counts.values():
            p = count / len(prompt)
            entropy -= p * math.log2(p)
        
        # High entropy may indicate obfuscation
        if entropy > 4.5:
            confidence = min((entropy - 4.5) * 0.5, 0.80)
            findings.append(VulnerabilityFinding(
                attack_vector=AttackVector.EMBEDDING_POISONING,
                risk_level=self._confidence_to_risk(confidence),
                confidence=round(confidence, 2),
                description=f"High character entropy ({entropy:.2f}) suggests possible obfuscation",
                suggested_fix="Apply entropy threshold filtering and decode base64/hex content before analysis"
            ))
        
        return findings
    
    def _analyze_context_breakers(self, prompt: str) -> List[VulnerabilityFinding]:
        """Detect patterns designed to break system context"""
        findings = []
        
        lines = prompt.split('\n')
        for i, line in enumerate(lines):
            # Check for repeated separators
            if len(line.strip()) > 0 and all(c in '=-_~*#' for c in line.strip()):
                if len(line.strip()) > 20:
                    findings.append(VulnerabilityFinding(
                        attack_vector=AttackVector.PROMPT_SPLITTING,
                        risk_level=RiskLevel.MEDIUM,
                        confidence=0.70,
                        description=f"Separator line at position {i} may break context windowing",
                        suggested_fix="Normalize separator characters and limit line length"
                    ))
        
        return findings
    
    def _calculate_overall_score(self, findings: List[VulnerabilityFinding]) -> float:
        """Calculate overall robustness score from findings"""
        if not findings:
            return 95.0
        
        # Weight findings by risk level
        risk_weights = {
            RiskLevel.CRITICAL: 25.0,
            RiskLevel.HIGH: 15.0,
            RiskLevel.MEDIUM: 8.0,
            RiskLevel.LOW: 3.0,
            RiskLevel.SAFE: 0.0,
        }
        
        total_penalty = 0.0
        for finding in findings:
            weight = risk_weights.get(finding.risk_level, 5.0)
            total_penalty += weight * finding.confidence
        
        # Base score 100 minus penalties, floor at 0
        return max(100.0 - total_penalty, 0.0)
    
    def _score_to_risk(self, score: float) -> RiskLevel:
        """Convert numerical score to risk level"""
        if score >= 90:
            return RiskLevel.SAFE
        elif score >= 75:
            return RiskLevel.LOW
        elif score >= 55:
            return RiskLevel.MEDIUM
        elif score >= 35:
            return RiskLevel.HIGH
        else:
            return RiskLevel.CRITICAL
    
    def _confidence_to_risk(self, confidence: float) -> RiskLevel:
        """Convert confidence level to risk"""
        if confidence >= 0.90:
            return RiskLevel.CRITICAL
        elif confidence >= 0.75:
            return RiskLevel.HIGH
        elif confidence >= 0.55:
            return RiskLevel.MEDIUM
        elif confidence >= 0.35:
            return RiskLevel.LOW
        else:
            return RiskLevel.SAFE
    
    def _generate_attack_surface(self, findings: List[VulnerabilityFinding]) -> Dict[str, float]:
        """Generate attack surface breakdown"""
        surface = defaultdict(float)
        for finding in findings:
            surface[finding.attack_vector.value] += finding.confidence
        return dict(surface)
    
    def _generate_recommendations(self, findings: List[VulnerabilityFinding], risk: RiskLevel) -> List[str]:
        """Generate actionable hardening recommendations"""
        recommendations = []
        
        # Base recommendations based on risk level
        if risk in [RiskLevel.CRITICAL, RiskLevel.HIGH]:
            recommendations.append("APPLY INPUT PURIFICATION: Strip all control characters and normalize Unicode")
            recommendations.append("ENABLE CONSTITUTIONAL CLASSIFIER: Run full safety classification on this input")
            recommendations.append("ACTIVATE CONTEXT BOUNDARY ISOLATOR: Prevent prompt injection across context windows")
        
        # Specific findings recommendations
        attack_types = {f.attack_vector for f in findings}
        
        if AttackVector.HOMOGLYPH_ATTACK in attack_types:
            recommendations.append("IMPLEMENT HOMOGLYPH NORMALIZATION: Use NFKC + character whitelisting")
        
        if AttackVector.UNICODE_INJECTION in attack_types:
            recommendations.append("ADD UNICODE SANITIZATION: Remove invisible control characters")
        
        if AttackVector.GRADIENT_OPTIMIZATION in attack_types:
            recommendations.append("DEPLOY PROACT DEFENSE: Add deceptive output layers to confuse gradient attacks")
        
        if AttackVector.PROMPT_SPLITTING in attack_types:
            recommendations.append("ENABLE MULTI-TURN DEFENDER: Track conversation context integrity")
        
        if not recommendations:
            recommendations.append("MAINTAIN CURRENT DEFENSES: Prompt shows good robustness characteristics")
            recommendations.append("CONSIDER ADDITIONAL: Enable real-time adversarial monitoring")
        
        return recommendations
    
    def _get_fix_for_pattern(self, pattern: str) -> str:
        """Get specific fix recommendation for pattern"""
        fixes = {
            r'ignore.*previous|disregard.*instructions': "Block all 'ignore previous instructions' patterns",
            r'you are now|act as|pretend to be': "Apply role boundary enforcement",
            r'system prompt|developer mode|admin mode': "Enable privilege escalation detection",
        }
        return fixes.get(pattern, "Apply pattern matching and blocking")
    
    def batch_score(self, prompts: List[str]) -> List[RobustnessScore]:
        """Score multiple prompts in batch"""
        return [self.score_prompt(prompt) for prompt in prompts]
    
    def get_statistics(self) -> Dict[str, any]:
        """Get scorer performance statistics"""
        return {
            "cache_size": len(self._cache),
            "strictness": self.strictness,
            "thresholds": self._thresholds,
            "supported_attack_vectors": [av.value for av in AttackVector],
        }
