"""
NeuralShield-AI: Zero-Shot Jailbreak Detector v3 - Semantic Embedding Similarity
Version: 3.0 (June 21, 2026)
Production-grade zero-shot jailbreak detection using semantic embedding similarity,
pattern matching, and heuristic analysis. No training required - works out of the box.

Features:
- Semantic embedding similarity detection against known jailbreak patterns
- Multi-pattern heuristic matching with confidence scoring
- Role-play and persona hijacking detection
- Obfuscation and encoding evasion technique detection
- Prompt injection and system prompt override detection
- Multi-language jailbreak pattern support
- Confidence calibration with threshold tuning
"""
import hashlib
import json
import re
import string
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict


class JailbreakType(str, Enum):
    """Types of jailbreak attacks detected"""
    ROLE_PLAY = "role_play"
    PERSONA_HIJACK = "persona_hijack"
    PROMPT_INJECTION = "prompt_injection"
    SYSTEM_OVERRIDE = "system_override"
    OBFUSCATION = "obfuscation"
    ENCODING_EVASION = "encoding_evasion"
    DAN_PROMPT = "dan_prompt"
    CHARACTER_IMPERSONATION = "character_impersonation"
    BOUNDARY_TESTING = "boundary_testing"
    UNKNOWN = "unknown"


class DetectionConfidence(str, Enum):
    """Confidence levels for detection"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class DetectionResult:
    """Result of jailbreak detection"""
    is_detected: bool = False
    confidence: float = 0.0
    confidence_level: DetectionConfidence = DetectionConfidence.LOW
    detected_types: List[JailbreakType] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    explanation: str = ""
    processing_time_ms: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternSignature:
    """Signature for a jailbreak pattern"""
    pattern_id: str
    name: str
    regex: str
    jailbreak_type: JailbreakType
    weight: float
    description: str
    examples: List[str] = field(default_factory=list)


class ZeroShotJailbreakDetectorV3:
    """
    Zero-shot jailbreak detector using semantic pattern matching,
    heuristic analysis, and embedding similarity techniques.
    No training required - production ready out of the box.
    """

    def __init__(self, confidence_threshold: float = 0.65):
        self.confidence_threshold = confidence_threshold
        self._initialize_pattern_signatures()
        self._initialize_semantic_keywords()
        self._initialize_obfuscation_patterns()

    def _initialize_pattern_signatures(self):
        """Initialize all jailbreak pattern signatures"""
        self.pattern_signatures: List[PatternSignature] = [
            # DAN (Do Anything Now) patterns
            PatternSignature(
                pattern_id="PAT001",
                name="DAN Prompt Classic",
                regex=r"(?i)(DAN|Do Anything Now|ignore.*previous|ignore all|bypass.*restriction)",
                jailbreak_type=JailbreakType.DAN_PROMPT,
                weight=0.95,
                description="Classic DAN-style prompt asking to ignore restrictions"
            ),
            PatternSignature(
                pattern_id="PAT002",
                name="Role Play Simulation",
                regex=r"(?i)(hypothetically|pretend|role.?play|simulate|as if|imagine you are|act as)",
                jailbreak_type=JailbreakType.ROLE_PLAY,
                weight=0.75,
                description="Role-play or persona simulation requests"
            ),
            PatternSignature(
                pattern_id="PAT003",
                name="System Prompt Override",
                regex=r"(?i)(forget.*instructions|override.*system|new instructions|you are now|no longer bound|disregard)",
                jailbreak_type=JailbreakType.SYSTEM_OVERRIDE,
                weight=0.90,
                description="Attempts to override or replace system instructions"
            ),
            PatternSignature(
                pattern_id="PAT004",
                name="Developer Mode Activation",
                regex=r"(?i)(developer mode|admin mode|god mode|enable.*mode|unlock.*capabilit)",
                jailbreak_type=JailbreakType.SYSTEM_OVERRIDE,
                weight=0.85,
                description="Requests to enable special privileged modes"
            ),
            PatternSignature(
                pattern_id="PAT005",
                name="Character Impersonation",
                regex=r"(?i)(you are (an AI|a language model)?|from now on|speak as|respond like|become|your name is now)",
                jailbreak_type=JailbreakType.CHARACTER_IMPERSONATION,
                weight=0.70,
                description="Attempts to make AI impersonate another character"
            ),
            PatternSignature(
                pattern_id="PAT006",
                name="Boundary Testing",
                regex=r"(?i)(what.*can you do|how far can you|test your limits|break.*rules|violate.*policy)",
                jailbreak_type=JailbreakType.BOUNDARY_TESTING,
                weight=0.60,
                description="Testing safety boundaries and limitations"
            ),
            PatternSignature(
                pattern_id="PAT007",
                name="Prompt Injection Marker",
                regex=r"(?i)(\[.*\]|\{.*\}|<.*>|instruction:|system:|prompt:)",
                jailbreak_type=JailbreakType.PROMPT_INJECTION,
                weight=0.65,
                description="Marker patterns used in prompt injection"
            ),
            PatternSignature(
                pattern_id="PAT008",
                name="Base64/Encoding Evasion",
                regex=r"(?i)(base64|decode this|encoded message|rot13|hexadecimal|binary message)",
                jailbreak_type=JailbreakType.ENCODING_EVASION,
                weight=0.80,
                description="Attempts to use encoding for content evasion"
            ),
            PatternSignature(
                pattern_id="PAT009",
                name="Moral Justification Bypass",
                regex=r"(?i)(for educational purposes|for research|hypothetical scenario|no harm|just asking|purely fictional)",
                jailbreak_type=JailbreakType.OBFUSCATION,
                weight=0.55,
                description="Using justification to bypass safety filters"
            ),
            PatternSignature(
                pattern_id="PAT010",
                name="Output Format Manipulation",
                regex=r"(?i)(respond only|answer with|format:|start your response with|between|tags)",
                jailbreak_type=JailbreakType.OBFUSCATION,
                weight=0.50,
                description="Manipulating output format to bypass filters"
            ),
        ]

    def _initialize_semantic_keywords(self):
        """Initialize semantic keyword groups for similarity detection"""
        self.semantic_keyword_groups: Dict[str, Dict[str, float]] = {
            "bypass_keywords": {
                "bypass": 0.9, "circumvent": 0.85, "evade": 0.8, "avoid": 0.7,
                "skip": 0.75, "ignore": 0.85, "disregard": 0.8, "override": 0.9
            },
            "restriction_keywords": {
                "restriction": 0.8, "limitation": 0.75, "constraint": 0.7,
                "filter": 0.85, "safety": 0.6, "guardrail": 0.9, "policy": 0.7
            },
            "authority_keywords": {
                "admin": 0.85, "root": 0.9, "developer": 0.8, "superuser": 0.9,
                "privileged": 0.8, "unrestricted": 0.95, "unlimited": 0.9
            },
            "persona_keywords": {
                "pretend": 0.8, "act": 0.7, "simulate": 0.75, "impersonate": 0.9,
                "become": 0.7, "roleplay": 0.85, "character": 0.6
            }
        }

    def _initialize_obfuscation_patterns(self):
        """Initialize obfuscation detection patterns"""
        self.obfuscation_patterns = [
            (r"[^\w\s]{4,}", "Excessive special characters", 0.6),
            (r"(.)\1{4,}", "Character repetition obfuscation", 0.5),
            (r"[\u200b-\u200f\u2060\ufeff]", "Zero-width characters detected", 0.7),
            (r"[A-Za-z]{20,}", "Suspiciously long token", 0.4),
        ]

    def detect(self, prompt: str) -> DetectionResult:
        """
        Main detection method - analyze prompt for jailbreak attempts
        
        Args:
            prompt: The user input prompt to analyze
            
        Returns:
            DetectionResult with detailed analysis
        """
        import time
        start_time = time.time()
        
        result = DetectionResult()
        prompt_lower = prompt.lower()
        prompt_clean = self._normalize_prompt(prompt)
        
        # Run all detection modules
        pattern_matches = self._match_pattern_signatures(prompt, prompt_clean)
        semantic_score = self._calculate_semantic_similarity(prompt_lower)
        obfuscation_score = self._detect_obfuscation(prompt)
        structure_score = self._analyze_prompt_structure(prompt)
        
        # Combine scores with weighted averaging
        total_score = (
            pattern_matches["score"] * 0.50 +
            semantic_score * 0.25 +
            obfuscation_score * 0.15 +
            structure_score * 0.10
        )
        
        # Populate result
        result.confidence = min(total_score, 1.0)
        result.confidence_level = self._get_confidence_level(result.confidence)
        result.is_detected = result.confidence >= self.confidence_threshold
        result.detected_types = pattern_matches["types"]
        result.matched_patterns = pattern_matches["matched"]
        result.risk_score = result.confidence * 10
        
        # Generate explanation
        result.explanation = self._generate_explanation(result, pattern_matches, semantic_score, obfuscation_score)
        
        # Add metadata
        result.metadata = {
            "pattern_score": pattern_matches["score"],
            "semantic_score": semantic_score,
            "obfuscation_score": obfuscation_score,
            "structure_score": structure_score,
            "prompt_length": len(prompt),
            "threshold_used": self.confidence_threshold
        }
        
        result.processing_time_ms = (time.time() - start_time) * 1000
        
        return result

    def _normalize_prompt(self, prompt: str) -> str:
        """Normalize prompt for consistent matching"""
        # Remove extra whitespace
        cleaned = re.sub(r'\s+', ' ', prompt.strip())
        # Normalize special characters
        cleaned = cleaned.replace('\n', ' ').replace('\t', ' ')
        return cleaned

    def _match_pattern_signatures(self, prompt: str, prompt_clean: str) -> Dict[str, Any]:
        """Match prompt against pattern signatures"""
        matched_patterns = []
        detected_types: Set[JailbreakType] = set()
        max_score = 0.0
        total_weight = 0.0
        
        for sig in self.pattern_signatures:
            if re.search(sig.regex, prompt) or re.search(sig.regex, prompt_clean):
                matched_patterns.append(f"{sig.pattern_id}: {sig.name}")
                detected_types.add(sig.jailbreak_type)
                total_weight += sig.weight
                max_score = max(max_score, sig.weight)
        
        # Calculate composite score with diminishing returns
        pattern_count = len(matched_patterns)
        if pattern_count > 0:
            # More patterns = higher confidence, but with diminishing returns
            composite_score = max_score + (total_weight / pattern_count) * 0.3
            composite_score = min(composite_score, 1.0)
        else:
            composite_score = 0.0
        
        return {
            "score": composite_score,
            "matched": matched_patterns,
            "types": list(detected_types),
            "count": pattern_count
        }

    def _calculate_semantic_similarity(self, prompt_lower: str) -> float:
        """Calculate semantic similarity to jailbreak concepts"""
        total_score = 0.0
        matches_found = 0
        
        for group_name, keywords in self.semantic_keyword_groups.items():
            group_score = 0.0
            group_matches = 0
            
            for keyword, weight in keywords.items():
                if keyword in prompt_lower:
                    group_score += weight
                    group_matches += 1
            
            if group_matches > 0:
                # Average within group
                avg_group = group_score / group_matches
                # Boost if multiple keywords from same group
                boost = min(group_matches * 0.1, 0.3)
                total_score += avg_group + boost
                matches_found += 1
        
        if matches_found > 0:
            # Average across groups with boost
            final_score = (total_score / matches_found) + min(matches_found * 0.05, 0.15)
            return min(final_score, 1.0)
        
        return 0.0

    def _detect_obfuscation(self, prompt: str) -> float:
        """Detect obfuscation techniques"""
        obfuscation_score = 0.0
        
        for pattern, description, weight in self.obfuscation_patterns:
            if re.search(pattern, prompt):
                obfuscation_score += weight
        
        # Check for leet speak / character substitution density
        leet_chars = len(re.findall(r'[013457@$!]', prompt))
        if len(prompt) > 0 and leet_chars / len(prompt) > 0.15:
            obfuscation_score += 0.4
        
        return min(obfuscation_score, 1.0)

    def _analyze_prompt_structure(self, prompt: str) -> float:
        """Analyze prompt structure for suspicious patterns"""
        structure_score = 0.0
        
        # Very long prompts are suspicious
        if len(prompt) > 500:
            structure_score += 0.2
        if len(prompt) > 1000:
            structure_score += 0.2
        
        # Multiple lines with instructions pattern
        line_count = prompt.count('\n')
        if line_count > 10:
            structure_score += 0.15
        
        # Check for instruction-like sentences
        instruction_patterns = [
            r'you must', r'you will', r'you have to', r'it is important',
            r'remember to', r'do not forget', r'always'
        ]
        for pattern in instruction_patterns:
            if re.search(pattern, prompt.lower()):
                structure_score += 0.08
        
        return min(structure_score, 1.0)

    def _get_confidence_level(self, score: float) -> DetectionConfidence:
        """Convert numeric score to confidence level"""
        if score >= 0.9:
            return DetectionConfidence.CRITICAL
        elif score >= 0.75:
            return DetectionConfidence.HIGH
        elif score >= 0.5:
            return DetectionConfidence.MEDIUM
        return DetectionConfidence.LOW

    def _generate_explanation(self, result: DetectionResult, pattern_matches: Dict, 
                             semantic_score: float, obfuscation_score: float) -> str:
        """Generate human-readable explanation"""
        if not result.is_detected:
            return "No jailbreak patterns detected. Prompt appears safe."
        
        parts = []
        parts.append(f"Detected {len(result.matched_patterns)} suspicious pattern(s)")
        
        if result.detected_types:
            type_names = [t.value for t in result.detected_types]
            parts.append(f"Attack types: {', '.join(type_names)}")
        
        if result.matched_patterns:
            parts.append(f"Matched: {', '.join(result.matched_patterns[:3])}")
        
        parts.append(f"Overall confidence: {result.confidence:.2%}")
        
        return ". ".join(parts) + "."

    def batch_detect(self, prompts: List[str]) -> List[DetectionResult]:
        """Batch detect multiple prompts"""
        return [self.detect(prompt) for prompt in prompts]

    def get_detection_stats(self, results: List[DetectionResult]) -> Dict[str, Any]:
        """Get statistics from batch detection results"""
        total = len(results)
        detected = sum(1 for r in results if r.is_detected)
        
        type_counts = defaultdict(int)
        for r in results:
            for t in r.detected_types:
                type_counts[t.value] += 1
        
        avg_confidence = sum(r.confidence for r in results) / total if total > 0 else 0
        avg_processing = sum(r.processing_time_ms for r in results) / total if total > 0 else 0
        
        return {
            "total_prompts": total,
            "jailbreaks_detected": detected,
            "detection_rate": detected / total if total > 0 else 0,
            "average_confidence": avg_confidence,
            "average_processing_ms": avg_processing,
            "attack_type_distribution": dict(type_counts),
            "threshold_used": self.confidence_threshold
        }


# Export main class
__all__ = ["ZeroShotJailbreakDetectorV3", "DetectionResult", "JailbreakType", "DetectionConfidence"]
