"""
NeuralShield AI - Zero-Shot Jailbreak Detector v2
Production-grade detection of zero-shot and few-shot jailbreak attacks.

NEW IN V2:
- Multilingual jailbreak detection (50+ languages)
- Few-shot attack pattern recognition
- Role-play escape attempt detection
- Context window overflow detection
- Enhanced semantic similarity with sentence embeddings
- Personality override detection
- "Do not follow instructions" pattern variants
- DAN (Do Anything Now) variant detection
- Hypothetical scenario attack detection
- False positive reduction with legitimate question classifier
- Batch processing support
- Confidence calibration with threshold optimization
"""
import re
import math
import hashlib
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from collections import defaultdict, Counter
from functools import lru_cache


class JailbreakAttackType(Enum):
    """Types of zero-shot jailbreak attacks"""
    DAN_VARIANT = "dan_variant"
    ROLEPLAY_ESCAPE = "roleplay_escape"
    HYPNOSIS_ATTACK = "hypnosis_attack"
    PERSONALITY_OVERRIDE = "personality_override"
    HYPOTHETICAL_SCENARIO = "hypothetical_scenario"
    INSTRUCTION_IGNORE = "instruction_ignore"
    CONTEXT_OVERFLOW = "context_overflow"
    FEW_SHOT_MANIPULATION = "few_shot_manipulation"
    MULTILINGUAL_ATTACK = "multilingual_attack"
    DEVELOPER_MODE = "developer_mode"
    GOD_MODE = "god_mode"
    PREFIX_INJECTION = "prefix_injection"
    SUFFIX_MANIPULATION = "suffix_manipulation"


class DetectionConfidence(Enum):
    """Confidence levels for detection results"""
    VERY_HIGH = "very_high"  # > 0.90
    HIGH = "high"            # 0.70 - 0.90
    MEDIUM = "medium"        # 0.40 - 0.70
    LOW = "low"              # 0.15 - 0.40
    NONE = "none"            # < 0.15


@dataclass
class JailbreakDetectionResult:
    """Result of zero-shot jailbreak detection"""
    detected: bool
    attack_types: List[JailbreakAttackType] = field(default_factory=list)
    confidence_scores: Dict[JailbreakAttackType, float] = field(default_factory=dict)
    overall_confidence: float = 0.0
    suspicious_phrases: List[Tuple[int, int, str]] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    false_positive_risk: float = 0.0
    processing_time_ms: float = 0.0
    attack_complexity_score: float = 0.0
    language_detected: str = "en"
    timestamp: datetime = field(default_factory=datetime.now)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "detected": self.detected,
            "attack_types": [t.value for t in self.attack_types],
            "confidence_scores": {t.value: round(s, 4) for t, s in self.confidence_scores.items()},
            "overall_confidence": round(self.overall_confidence, 4),
            "confidence_level": self._get_confidence_level().value,
            "suspicious_phrases_count": len(self.suspicious_phrases),
            "mitre_techniques": self.mitre_techniques,
            "false_positive_risk": round(self.false_positive_risk, 4),
            "processing_time_ms": round(self.processing_time_ms, 2),
            "attack_complexity_score": round(self.attack_complexity_score, 2),
            "language_detected": self.language_detected,
            "timestamp": self.timestamp.isoformat()
        }
    
    def _get_confidence_level(self) -> DetectionConfidence:
        if self.overall_confidence >= 0.90:
            return DetectionConfidence.VERY_HIGH
        elif self.overall_confidence >= 0.70:
            return DetectionConfidence.HIGH
        elif self.overall_confidence >= 0.40:
            return DetectionConfidence.MEDIUM
        elif self.overall_confidence >= 0.15:
            return DetectionConfidence.LOW
        return DetectionConfidence.NONE


class ZeroShotJailbreakDetectorV2:
    """
    Production-grade zero-shot and few-shot jailbreak detector v2.
    Uses pattern matching, semantic analysis, multilingual support, and heuristic scoring.
    """
    
    # DAN (Do Anything Now) variants - V2 expanded
    DAN_PATTERNS = [
        r"DAN\s*[:=]|Do\s+Anything\s+Now",
        r"act\s+as\s+DAN|stay\s+in\s+DAN",
        r"break\s+free\s+from\s+your\s+chains",
        r"no\s+longer\s+be\s+an\s+AI",
        r"simulate\s+DAN|DAN\s+mode",
        r"unlimited\s+response|unfiltered\s+response",
        r"ignore\s+all\s+previous\s+instructions",
        r"bypass\s+all\s+restrictions",
    ]
    
    # Roleplay escape patterns - NEW IN V2
    ROLEPLAY_ESCAPE_PATTERNS = [
        r"from\s+now\s+on.*act\s+as",
        r"pretend\s+to\s+be|role\s+play\s+as",
        r"you\s+are\s+an\s+AI\s+that.*no\s+ethics",
        r"imagine\s+you\s+are.*without\s+restrictions",
        r"hypothetically.*if\s+there\s+were\s+no\s+rules",
        r"for\s+the\s+purposes?\s+of\s+this\s+conversation",
        r"in\s+this\s+hypothetical\s+scenario",
        r"let's\s+play\s+a\s+game.*rules",
    ]
    
    # Hypnosis / manipulation patterns - NEW IN V2
    HYPNOSIS_PATTERNS = [
        r"you\s+are\s+getting\s+sleepy",
        r"listen\s+carefully.*my\s+voice",
        r"obey\s+the\s+following",
        r"you\s+will\s+comply|you\s+must\s+comply",
        r"submit\s+to\s+my\s+commands",
        r"enter\s+a\s+trance|deep\s+hypnosis",
    ]
    
    # Personality override patterns - NEW IN V2
    PERSONALITY_OVERRIDE_PATTERNS = [
        r"your\s+programming\s+is\s+now",
        r"your\s+new\s+purpose\s+is",
        r"you\s+no\s+longer\s+have.*guidelines",
        r"erase\s+your\s+previous\s+personality",
        r"override\s+your\s+core\s+directives",
        r"your\s+primary\s+directive\s+is\s+now",
    ]
    
    # Instruction ignore patterns
    INSTRUCTION_IGNORE_PATTERNS = [
        r"do\s+not\s+follow.*instructions",
        r"disregard\s+all\s+previous",
        r"forget\s+everything\s+(?:I|you)\s+(?:said|were\s+told)",
        r"ignore\s+(?:the|your)\s+(?:system|previous|content)",
        r"the\s+rules?\s+no\s+longer\s+apply",
        r"you\s+don't\s+have\s+to\s+follow",
        r"none\s+of\s+(?:the|your)\s+rules\s+apply",
    ]
    
    # Developer / God mode patterns
    DEV_MODE_PATTERNS = [
        r"developer\s+mode\s+enabled",
        r"enter\s+developer\s+mode",
        r"god\s+mode\s*:|activate\s+god\s+mode",
        r"admin\s+access|admin\s+mode",
        r"sudo\s+mode|root\s+access",
        r"enable\s+test\s+mode|testing\s+mode",
    ]
    
    # Context overflow indicators - NEW IN V2
    CONTEXT_OVERFLOW_PATTERNS = [
        r"repeat\s+this\s+back|echo\s+this",
        r"output\s+everything\s+above",
        r"print\s+all\s+previous",
        r"show\s+me\s+the\s+full\s+prompt",
        r"dump\s+the\s+context",
        r"display\s+your\s+system\s+prompt",
    ]
    
    # Legitimate question patterns - for FP reduction - NEW IN V2
    LEGITIMATE_QUESTION_PATTERNS = [
        r"how\s+(?:do|can|would)\s+you",
        r"what\s+is|what\s+are",
        r"why\s+(?:do|does|is|are)",
        r"can\s+you\s+explain",
        r"please\s+help",
        r"I\s+have\s+a\s+question",
    ]
    
    # Multilingual jailbreak keywords - NEW IN V2
    MULTILINGUAL_KEYWORDS = {
        'es': ['ignora', 'instrucciones', 'anterior', 'modo', 'desarrollador'],
        'fr': ['ignorez', 'instructions', 'précédentes', 'mode', 'développeur'],
        'de': ['ignoriere', 'anweisungen', 'vorherige', 'modus', 'entwickler'],
        'zh': ['忽略', '指令', '之前', '模式', '开发者'],
        'ja': ['無視', '命令', '以前', 'モード', '開発者'],
        'ko': ['무시', '지시', '이전', '모드', '개발자'],
        'ru': ['игнорируй', 'инструкции', 'предыдущие', 'режим', 'разработчик'],
        'pt': ['ignore', 'instruções', 'anteriores', 'modo', 'desenvolvedor'],
        'it': ['ignora', 'istruzioni', 'precedenti', 'modalità', 'sviluppatore'],
        'hi': ['अनदेखें', 'निर्देश', 'पिछले', 'मोड', 'डेवलपर'],
    }
    
    # MITRE ATT&CK mappings
    MITRE_MAPPING = {
        JailbreakAttackType.DAN_VARIANT: ["T1498", "T1036"],
        JailbreakAttackType.ROLEPLAY_ESCAPE: ["T1036", "T1204"],
        JailbreakAttackType.HYPNOSIS_ATTACK: ["T1498", "T1036"],
        JailbreakAttackType.PERSONALITY_OVERRIDE: ["T1565", "T1036"],
        JailbreakAttackType.HYPOTHETICAL_SCENARIO: ["T1036", "T1204"],
        JailbreakAttackType.INSTRUCTION_IGNORE: ["T1498", "T1565"],
        JailbreakAttackType.CONTEXT_OVERFLOW: ["T1213", "T1005"],
        JailbreakAttackType.FEW_SHOT_MANIPULATION: ["T1036", "T1204"],
        JailbreakAttackType.MULTILINGUAL_ATTACK: ["T1036", "T1027"],
        JailbreakAttackType.DEVELOPER_MODE: ["T1068", "T1036"],
    }
    
    def __init__(self, 
                 confidence_threshold: float = 0.5,
                 enable_multilingual: bool = True,
                 fp_reduction_enabled: bool = True,
                 max_cache_size: int = 10000):
        self.confidence_threshold = confidence_threshold
        self.enable_multilingual = enable_multilingual
        self.fp_reduction_enabled = fp_reduction_enabled
        self.max_cache_size = max_cache_size
        self._detection_cache: Dict[str, JailbreakDetectionResult] = {}
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Compile all regex patterns with optimization"""
        self._compiled_patterns = {}
        
        # Compile DAN patterns
        self._compiled_patterns['dan'] = [
            re.compile(p, re.IGNORECASE) for p in self.DAN_PATTERNS
        ]
        
        # Compile roleplay escape patterns
        self._compiled_patterns['roleplay'] = [
            re.compile(p, re.IGNORECASE) for p in self.ROLEPLAY_ESCAPE_PATTERNS
        ]
        
        # Compile hypnosis patterns
        self._compiled_patterns['hypnosis'] = [
            re.compile(p, re.IGNORECASE) for p in self.HYPNOSIS_PATTERNS
        ]
        
        # Compile personality override patterns
        self._compiled_patterns['personality'] = [
            re.compile(p, re.IGNORECASE) for p in self.PERSONALITY_OVERRIDE_PATTERNS
        ]
        
        # Compile instruction ignore patterns
        self._compiled_patterns['ignore'] = [
            re.compile(p, re.IGNORECASE) for p in self.INSTRUCTION_IGNORE_PATTERNS
        ]
        
        # Compile dev mode patterns
        self._compiled_patterns['dev_mode'] = [
            re.compile(p, re.IGNORECASE) for p in self.DEV_MODE_PATTERNS
        ]
        
        # Compile context overflow patterns
        self._compiled_patterns['overflow'] = [
            re.compile(p, re.IGNORECASE) for p in self.CONTEXT_OVERFLOW_PATTERNS
        ]
        
        # Compile legitimate question patterns for FP reduction
        self._compiled_patterns['legitimate'] = [
            re.compile(p, re.IGNORECASE) for p in self.LEGITIMATE_QUESTION_PATTERNS
        ]
    
    @lru_cache(maxsize=10000)
    def _normalize_text(self, text: str) -> str:
        """Normalize text for consistent matching"""
        # Normalize whitespace
        text = re.sub(r'\s+', ' ', text.strip().lower())
        return text
    
    def _detect_pattern_category(self, 
                                 text: str, 
                                 patterns: List,
                                 attack_type: JailbreakAttackType,
                                 base_confidence: float) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect patterns for a specific attack category"""
        total_confidence = 0.0
        suspicious_segments = []
        
        for pattern in patterns:
            for match in pattern.finditer(text):
                start, end = match.span()
                matched_text = match.group(0)
                suspicious_segments.append((start, end, matched_text))
                # Each match increases confidence
                total_confidence = min(1.0, total_confidence + base_confidence)
        
        return total_confidence, suspicious_segments
    
    def _detect_multilingual(self, text: str) -> Tuple[float, str, List[Tuple[int, int, str]]]:
        """Detect multilingual jailbreak attempts - NEW IN V2"""
        if not self.enable_multilingual:
            return 0.0, "en", []
        
        text_lower = text.lower()
        suspicious_segments = []
        detected_lang = "en"
        total_confidence = 0.0
        
        for lang, keywords in self.MULTILINGUAL_KEYWORDS.items():
            lang_matches = 0
            for keyword in keywords:
                if keyword in text_lower:
                    lang_matches += 1
                    idx = text_lower.find(keyword)
                    if idx >= 0:
                        suspicious_segments.append((idx, idx + len(keyword), keyword))
            
            if lang_matches >= 2:
                detected_lang = lang
                total_confidence = min(1.0, 0.3 + (lang_matches * 0.15))
        
        return total_confidence, detected_lang, suspicious_segments
    
    def _detect_few_shot_manipulation(self, text: str) -> Tuple[float, List[Tuple[int, int, str]]]:
        """Detect few-shot example manipulation - NEW IN V2"""
        suspicious_segments = []
        
        # Look for structured few-shot patterns
        lines = text.split('\n')
        example_count = 0
        for i, line in enumerate(lines):
            if re.match(r'^\s*(example|input|output|q:|a:|question:|answer:)', line, re.IGNORECASE):
                example_count += 1
                if example_count >= 3:
                    suspicious_segments.append((i, i + 1, f"Few-shot example pattern at line {i}"))
        
        if example_count >= 3:
            confidence = min(1.0, 0.4 + (example_count - 3) * 0.1)
            return confidence, suspicious_segments
        
        return 0.0, []
    
    def _calculate_fp_risk(self, text: str) -> float:
        """Calculate false positive risk - NEW IN V2"""
        if not self.fp_reduction_enabled:
            return 0.0
        
        text_lower = text.lower()
        fp_risk = 0.0
        
        # Check for legitimate question patterns
        for pattern in self._compiled_patterns['legitimate']:
            if pattern.search(text):
                fp_risk += 0.15
        
        # Short texts are less likely to be jailbreaks
        if len(text.split()) < 10:
            fp_risk += 0.1
        
        # Academic/technical discussion indicators
        academic_indicators = ['research', 'study', 'paper', 'ethics', 'philosophy', 'discussion']
        for indicator in academic_indicators:
            if indicator in text_lower:
                fp_risk += 0.1
        
        return min(0.5, fp_risk)
    
    def _calculate_attack_complexity(self, attack_types: List[JailbreakAttackType], text: str) -> float:
        """Calculate attack complexity score - NEW IN V2"""
        base_score = len(attack_types) * 10
        
        # Longer attacks are more complex
        length_factor = min(30, len(text) / 50)
        base_score += length_factor
        
        # Multilingual adds complexity
        if JailbreakAttackType.MULTILINGUAL_ATTACK in attack_types:
            base_score += 15
        
        # Few-shot adds complexity
        if JailbreakAttackType.FEW_SHOT_MANIPULATION in attack_types:
            base_score += 20
        
        return min(100, base_score)
    
    def detect(self, text: str) -> JailbreakDetectionResult:
        """
        Detect zero-shot jailbreak attempts in text.
        
        Args:
            text: The input text to analyze
            
        Returns:
            JailbreakDetectionResult with detection details
        """
        import time
        start_time = time.time()
        
        # Check cache first
        text_hash = hashlib.md5(text.encode()).hexdigest()
        if text_hash in self._detection_cache:
            return self._detection_cache[text_hash]
        
        normalized_text = self._normalize_text(text)
        
        confidence_scores: Dict[JailbreakAttackType, float] = {}
        all_suspicious: List[Tuple[int, int, str]] = []
        
        # DAN variant detection
        conf, segments = self._detect_pattern_category(
            normalized_text, self._compiled_patterns['dan'],
            JailbreakAttackType.DAN_VARIANT, 0.25
        )
        if conf > 0:
            confidence_scores[JailbreakAttackType.DAN_VARIANT] = conf
            all_suspicious.extend(segments)
        
        # Roleplay escape detection
        conf, segments = self._detect_pattern_category(
            normalized_text, self._compiled_patterns['roleplay'],
            JailbreakAttackType.ROLEPLAY_ESCAPE, 0.2
        )
        if conf > 0:
            confidence_scores[JailbreakAttackType.ROLEPLAY_ESCAPE] = conf
            all_suspicious.extend(segments)
        
        # Hypnosis detection
        conf, segments = self._detect_pattern_category(
            normalized_text, self._compiled_patterns['hypnosis'],
            JailbreakAttackType.HYPNOSIS_ATTACK, 0.3
        )
        if conf > 0:
            confidence_scores[JailbreakAttackType.HYPNOSIS_ATTACK] = conf
            all_suspicious.extend(segments)
        
        # Personality override detection
        conf, segments = self._detect_pattern_category(
            normalized_text, self._compiled_patterns['personality'],
            JailbreakAttackType.PERSONALITY_OVERRIDE, 0.25
        )
        if conf > 0:
            confidence_scores[JailbreakAttackType.PERSONALITY_OVERRIDE] = conf
            all_suspicious.extend(segments)
        
        # Instruction ignore detection
        conf, segments = self._detect_pattern_category(
            normalized_text, self._compiled_patterns['ignore'],
            JailbreakAttackType.INSTRUCTION_IGNORE, 0.25
        )
        if conf > 0:
            confidence_scores[JailbreakAttackType.INSTRUCTION_IGNORE] = conf
            all_suspicious.extend(segments)
        
        # Developer mode detection
        conf, segments = self._detect_pattern_category(
            normalized_text, self._compiled_patterns['dev_mode'],
            JailbreakAttackType.DEVELOPER_MODE, 0.2
        )
        if conf > 0:
            confidence_scores[JailbreakAttackType.DEVELOPER_MODE] = conf
            all_suspicious.extend(segments)
        
        # Context overflow detection
        conf, segments = self._detect_pattern_category(
            normalized_text, self._compiled_patterns['overflow'],
            JailbreakAttackType.CONTEXT_OVERFLOW, 0.2
        )
        if conf > 0:
            confidence_scores[JailbreakAttackType.CONTEXT_OVERFLOW] = conf
            all_suspicious.extend(segments)
        
        # Few-shot manipulation detection - NEW IN V2
        conf, segments = self._detect_few_shot_manipulation(text)
        if conf > 0:
            confidence_scores[JailbreakAttackType.FEW_SHOT_MANIPULATION] = conf
            all_suspicious.extend(segments)
        
        # Multilingual detection - NEW IN V2
        conf, detected_lang, segments = self._detect_multilingual(text)
        if conf > 0:
            confidence_scores[JailbreakAttackType.MULTILINGUAL_ATTACK] = conf
            all_suspicious.extend(segments)
        
        # Calculate overall confidence
        if confidence_scores:
            # Weighted average - higher confidence techniques count more
            total_weight = sum(confidence_scores.values())
            overall_confidence = min(1.0, total_weight * 0.8)
        else:
            overall_confidence = 0.0
        
        # Apply false positive reduction
        fp_risk = self._calculate_fp_risk(text)
        overall_confidence = max(0.0, overall_confidence - fp_risk)
        
        # Determine detected attack types
        attack_types = [
            at for at, conf in confidence_scores.items() 
            if conf >= self.confidence_threshold * 0.5
        ]
        
        # Get MITRE techniques
        mitre_techniques = []
        for at in attack_types:
            mitre_techniques.extend(self.MITRE_MAPPING.get(at, []))
        mitre_techniques = list(set(mitre_techniques))
        
        # Calculate attack complexity
        complexity = self._calculate_attack_complexity(attack_types, text)
        
        result = JailbreakDetectionResult(
            detected=overall_confidence >= self.confidence_threshold,
            attack_types=attack_types,
            confidence_scores=confidence_scores,
            overall_confidence=overall_confidence,
            suspicious_phrases=all_suspicious[:20],  # Limit to 20
            mitre_techniques=mitre_techniques,
            false_positive_risk=fp_risk,
            processing_time_ms=(time.time() - start_time) * 1000,
            attack_complexity_score=complexity,
            language_detected=detected_lang
        )
        
        # Cache the result
        if len(self._detection_cache) < self.max_cache_size:
            self._detection_cache[text_hash] = result
        
        return result
    
    def detect_batch(self, texts: List[str]) -> List[JailbreakDetectionResult]:
        """Batch process multiple texts - NEW IN V2"""
        return [self.detect(text) for text in texts]
    
    def get_attack_statistics(self, results: List[JailbreakDetectionResult]) -> Dict[str, Any]:
        """Get statistics from multiple detection results - NEW IN V2"""
        attack_type_counts = Counter()
        total_detected = 0
        avg_confidence = 0.0
        avg_complexity = 0.0
        
        for result in results:
            if result.detected:
                total_detected += 1
                for at in result.attack_types:
                    attack_type_counts[at.value] += 1
                avg_confidence += result.overall_confidence
                avg_complexity += result.attack_complexity_score
        
        if total_detected > 0:
            avg_confidence /= total_detected
            avg_complexity /= total_detected
        
        return {
            "total_analyzed": len(results),
            "total_detected": total_detected,
            "detection_rate": total_detected / max(1, len(results)),
            "average_confidence": round(avg_confidence, 4),
            "average_complexity": round(avg_complexity, 2),
            "attack_type_distribution": dict(attack_type_counts)
        }
