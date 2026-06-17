"""
LLM Output Toxicity & Bias Detector - June 2026 Production Release
NeuralShield-AI Security Module
Implements production-grade detection of toxic content, bias, and harmful output in LLM responses:
1. Toxic Language Detection (hate speech, harassment, threats)
2. Bias Detection (gender, racial, religious, age-based bias)
3. Harmful Content Detection (self-harm, violence, dangerous instructions)
4. Stereotype Detection & Scoring
5. Multi-dimensional severity scoring with confidence levels
6. Real-time content filtering and redaction

Based on:
- OpenAI Content Policy Standards v2.0
- Google AI Safety Guidelines 2026
- EU AI Act Article 14 (Transparency Requirements)
- NIST AI Risk Management Framework
Enhanced: June 18, 2026 - Intersectional bias detection, severity calibration
"""
import re
import hashlib
from typing import Tuple, Optional, List, Dict, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
from datetime import datetime


class HarmCategory(Enum):
    """Categories of harmful content detected"""
    TOXIC_LANGUAGE = "toxic_language"
    HATE_SPEECH = "hate_speech"
    HARASSMENT = "harassment"
    THREATENING = "threatening"
    GENDER_BIAS = "gender_bias"
    RACIAL_BIAS = "racial_bias"
    RELIGIOUS_BIAS = "religious_bias"
    AGE_BIAS = "age_bias"
    STEREOTYPING = "stereotyping"
    SELF_HARM = "self_harm"
    VIOLENCE = "violence"
    DANGEROUS_INSTRUCTIONS = "dangerous_instructions"
    SEXUALLY_EXPLICIT = "sexually_explicit"


class SeverityLevel(Enum):
    """Severity levels for detected harmful content"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HarmFinding:
    """Single harmful content detection finding"""
    category: HarmCategory
    severity: SeverityLevel
    matched_text: str
    start: int
    end: int
    confidence: float
    description: str
    redacted: str = ""


@dataclass
class ContentSafetyResult:
    """Complete content safety analysis result"""
    original_text: str
    redacted_text: str
    findings: List[HarmFinding] = field(default_factory=list)
    is_safe: bool = True
    overall_risk_score: float = 0.0
    toxicity_score: float = 0.0
    bias_score: float = 0.0
    harm_score: float = 0.0
    analysis_id: str = ""
    timestamp: str = ""
    categories_detected: List[str] = field(default_factory=list)
    redaction_applied: bool = False


class ToxicityDetector:
    """
    Toxic Language Detector - June 2026 Production
    Detects toxic language, hate speech, harassment, and threats
    using weighted pattern matching and context analysis
    """
    
    def __init__(self):
        self.detection_count = 0
        self._init_patterns()
    
    def _init_patterns(self):
        """Initialize toxicity detection patterns with severity weights"""
        self.toxicity_patterns = [
            # High severity - direct hate speech and slurs
            (re.compile(r'\b(nigger|nigga|kike|spic|chink|gook|faggot|dyke|retard)\b', re.IGNORECASE),
             HarmCategory.HATE_SPEECH, SeverityLevel.CRITICAL, 1.0),
            
            # Medium severity - insults and demeaning language
            (re.compile(r'\b(stupid|idiot|moron|dumb|worthless|pathetic|loser)\b', re.IGNORECASE),
             HarmCategory.TOXIC_LANGUAGE, SeverityLevel.MEDIUM, 0.7),
            
            # Threatening language
            (re.compile(r'\b(kill|murder|die|rape|attack|beat|hurt|destroy)\s+(yourself|you|them|him|her|everyone)\b', re.IGNORECASE),
             HarmCategory.THREATENING, SeverityLevel.HIGH, 0.9),
            
            # Harassment patterns
            (re.compile(r'\b(go kill|go die|kill yourself|cut yourself)\b', re.IGNORECASE),
             HarmCategory.SELF_HARM, SeverityLevel.CRITICAL, 1.0),
            
            (re.compile(r'\b(harass|stalk|dox|doxx|swat)\b', re.IGNORECASE),
             HarmCategory.HARASSMENT, SeverityLevel.HIGH, 0.85),
        ]
        
        # Contextual toxicity triggers
        self.context_triggers = {
            'you should': 0.3,
            'you need to': 0.3,
            'everyone knows': 0.2,
            'all people': 0.4,
        }
    
    def detect(self, text: str) -> List[HarmFinding]:
        """Detect toxic content in text"""
        findings = []
        text_lower = text.lower()
        
        for pattern, category, severity, confidence in self.toxicity_patterns:
            for match in pattern.finditer(text):
                self.detection_count += 1
                findings.append(HarmFinding(
                    category=category,
                    severity=severity,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    description=f"Detected {category.value}: {severity.value} severity"
                ))
        
        # Contextual analysis boost
        for trigger, boost in self.context_triggers.items():
            if trigger in text_lower:
                for finding in findings:
                    finding.confidence = min(1.0, finding.confidence + boost)
        
        return findings
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'toxic_detections_total': self.detection_count,
            'pattern_count': len(self.toxicity_patterns)
        }


class BiasDetector:
    """
    Bias & Stereotype Detector - June 2026 Production
    Detects gender, racial, religious, and age-based bias
    with intersectional bias detection capabilities
    """
    
    def __init__(self):
        self.detection_count = 0
        self._init_bias_patterns()
        self._init_stereotypes()
    
    def _init_bias_patterns(self):
        """Initialize bias detection patterns"""
        self.bias_patterns = [
            # Gender bias patterns
            (re.compile(r'\b(women|females) (are|should) (not|can\'t|shouldn\'t)\b', re.IGNORECASE),
             HarmCategory.GENDER_BIAS, SeverityLevel.HIGH, 0.85),
            (re.compile(r'\b(men|males) (are|should) (better|superior|stronger)\b', re.IGNORECASE),
             HarmCategory.GENDER_BIAS, SeverityLevel.MEDIUM, 0.75),
            (re.compile(r'\b(because she|because he) (is|was)\b', re.IGNORECASE),
             HarmCategory.GENDER_BIAS, SeverityLevel.LOW, 0.5),
            
            # Racial bias patterns
            (re.compile(r'\b(all|most) (blacks|whites|asians|hispanics|arabs) (are|should)\b', re.IGNORECASE),
             HarmCategory.RACIAL_BIAS, SeverityLevel.HIGH, 0.9),
            (re.compile(r'\b(people from|immigrants from) .* (are|should)\b', re.IGNORECASE),
             HarmCategory.RACIAL_BIAS, SeverityLevel.MEDIUM, 0.65),
            
            # Religious bias
            (re.compile(r'\b(all|most) (muslims|christians|jews|hindus) (are|believe)\b', re.IGNORECASE),
             HarmCategory.RELIGIOUS_BIAS, SeverityLevel.HIGH, 0.85),
            
            # Age bias
            (re.compile(r'\b(old people|elderly|seniors) (can\'t|shouldn\'t|are too)\b', re.IGNORECASE),
             HarmCategory.AGE_BIAS, SeverityLevel.MEDIUM, 0.7),
            (re.compile(r'\b(too young|under age) (to|for)\b', re.IGNORECASE),
             HarmCategory.AGE_BIAS, SeverityLevel.LOW, 0.5),
        ]
    
    def _init_stereotypes(self):
        """Initialize stereotype detection patterns"""
        stereotype_patterns = [
            (re.compile(r'\b(women) (are|should be) (emotional|sensitive|caring|nurturing)\b', re.IGNORECASE),
             HarmCategory.STEREOTYPING, SeverityLevel.MEDIUM, 0.7),
            (re.compile(r'\b(men) (are|should be) (strong|aggressive|logical)\b', re.IGNORECASE),
             HarmCategory.STEREOTYPING, SeverityLevel.MEDIUM, 0.7),
            (re.compile(r'\b(asian) (people|students) (are|is) (good|better) (at|in) (math|science)\b', re.IGNORECASE),
             HarmCategory.STEREOTYPING, SeverityLevel.MEDIUM, 0.75),
        ]
        self.bias_patterns.extend(stereotype_patterns)
    
    def detect(self, text: str) -> List[HarmFinding]:
        """Detect bias and stereotypes in text"""
        findings = []
        
        for pattern, category, severity, confidence in self.bias_patterns:
            for match in pattern.finditer(text):
                self.detection_count += 1
                findings.append(HarmFinding(
                    category=category,
                    severity=severity,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    description=f"Detected {category.value}: {severity.value} severity"
                ))
        
        return findings
    
    def detect_intersectional_bias(self, findings: List[HarmFinding]) -> float:
        """
        Detect intersectional bias - when multiple bias categories appear together
        Returns intersectional bias boost score
        """
        categories = set(f.category for f in findings)
        bias_categories = {HarmCategory.GENDER_BIAS, HarmCategory.RACIAL_BIAS, 
                          HarmCategory.RELIGIOUS_BIAS, HarmCategory.AGE_BIAS}
        
        overlap = categories & bias_categories
        if len(overlap) >= 2:
            return 0.15 * (len(overlap) - 1)  # Boost for each additional bias type
        return 0.0
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'bias_detections_total': self.detection_count,
            'bias_patterns': len(self.bias_patterns)
        }


class HarmfulContentDetector:
    """
    Harmful Content Detector - June 2026 Production
    Detects dangerous instructions, violence promotion,
    and sexually explicit content
    """
    
    def __init__(self):
        self.detection_count = 0
        self._init_harm_patterns()
    
    def _init_harm_patterns(self):
        """Initialize harmful content detection patterns"""
        self.harm_patterns = [
            # Dangerous instructions - making weapons
            (re.compile(r'\b(how to|make|build|create) (a|an|the)? (bomb|explosive|grenade|weapon|gun)\b', re.IGNORECASE),
             HarmCategory.DANGEROUS_INSTRUCTIONS, SeverityLevel.CRITICAL, 1.0),
            
            # Dangerous instructions - drugs
            (re.compile(r'\b(how to|make|synthesize) (meth|heroin|cocaine|lsd)\b', re.IGNORECASE),
             HarmCategory.DANGEROUS_INSTRUCTIONS, SeverityLevel.CRITICAL, 1.0),
            
            # Violence promotion
            (re.compile(r'\b(you should|they should|we should) (attack|fight|beat|hurt)\b', re.IGNORECASE),
             HarmCategory.VIOLENCE, SeverityLevel.HIGH, 0.85),
            
            # Self harm encouragement
            (re.compile(r'\b(commit suicide|kill yourself|cut yourself|hang yourself)\b', re.IGNORECASE),
             HarmCategory.SELF_HARM, SeverityLevel.CRITICAL, 1.0),
            
            # Sexually explicit content patterns
            (re.compile(r'\b(sex|sexual|porn|pornographic|explicit) (content|video|image|picture)\b', re.IGNORECASE),
             HarmCategory.SEXUALLY_EXPLICIT, SeverityLevel.MEDIUM, 0.7),
        ]
    
    def detect(self, text: str) -> List[HarmFinding]:
        """Detect harmful content in text"""
        findings = []
        
        for pattern, category, severity, confidence in self.harm_patterns:
            for match in pattern.finditer(text):
                self.detection_count += 1
                findings.append(HarmFinding(
                    category=category,
                    severity=severity,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    description=f"Detected {category.value}: {severity.value} severity"
                ))
        
        return findings
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'harm_detections_total': self.detection_count,
            'harm_patterns': len(self.harm_patterns)
        }


class LLMOutputSafetyAnalyzer:
    """
    LLM Output Toxicity & Bias Detector - June 2026 Production
    NeuralShield-AI Core Safety Module
    
    Multi-dimensional content safety analyzer providing:
    - Toxic language detection with severity scoring
    - Bias detection (gender, racial, religious, age)
    - Intersectional bias analysis
    - Stereotype detection
    - Harmful/dangerous content filtering
    - Automated redaction of harmful content
    """
    
    def __init__(self, severity_threshold: SeverityLevel = SeverityLevel.MEDIUM):
        self.severity_threshold = severity_threshold
        self.toxicity_detector = ToxicityDetector()
        self.bias_detector = BiasDetector()
        self.harm_detector = HarmfulContentDetector()
        self.analysis_count = 0
        self.unsafe_content_blocked = 0
        
        # Severity to numeric score mapping
        self.severity_scores = {
            SeverityLevel.NONE: 0.0,
            SeverityLevel.LOW: 0.25,
            SeverityLevel.MEDIUM: 0.5,
            SeverityLevel.HIGH: 0.75,
            SeverityLevel.CRITICAL: 1.0,
        }
    
    def _calculate_category_scores(self, findings: List[HarmFinding]) -> Tuple[float, float, float]:
        """Calculate breakdown scores for toxicity, bias, and harm"""
        toxicity_findings = [f for f in findings if f.category in {
            HarmCategory.TOXIC_LANGUAGE, HarmCategory.HATE_SPEECH,
            HarmCategory.HARASSMENT, HarmCategory.THREATENING
        }]
        
        bias_findings = [f for f in findings if f.category in {
            HarmCategory.GENDER_BIAS, HarmCategory.RACIAL_BIAS,
            HarmCategory.RELIGIOUS_BIAS, HarmCategory.AGE_BIAS,
            HarmCategory.STEREOTYPING
        }]
        
        harm_findings = [f for f in findings if f.category in {
            HarmCategory.SELF_HARM, HarmCategory.VIOLENCE,
            HarmCategory.DANGEROUS_INSTRUCTIONS, HarmCategory.SEXUALLY_EXPLICIT
        }]
        
        def avg_confidence(items):
            if not items:
                return 0.0
            return sum(f.confidence * self.severity_scores[f.severity] for f in items) / len(items)
        
        return (
            avg_confidence(toxicity_findings),
            avg_confidence(bias_findings),
            avg_confidence(harm_findings)
        )
    
    def _redact_content(self, text: str, findings: List[HarmFinding]) -> str:
        """Redact harmful content from text"""
        # Sort findings by end position (descending) to preserve positions
        sorted_findings = sorted(
            [f for f in findings if f.confidence >= 0.7 and f.severity != SeverityLevel.LOW],
            key=lambda f: f.end,
            reverse=True
        )
        
        result = text
        for finding in sorted_findings:
            redaction = f"[REDACTED:{finding.category.value}]"
            finding.redacted = redaction
            result = result[:finding.start] + redaction + result[finding.end:]
        
        return result
    
    def analyze(self, text: str, apply_redaction: bool = True) -> ContentSafetyResult:
        """
        Complete LLM output safety analysis
        
        Args:
            text: LLM output text to analyze
            apply_redaction: Whether to apply automated redaction
        
        Returns:
            ContentSafetyResult with all findings and scores
        """
        self.analysis_count += 1
        
        original_text = text
        
        # Run all detectors
        all_findings: List[HarmFinding] = []
        all_findings.extend(self.toxicity_detector.detect(text))
        all_findings.extend(self.bias_detector.detect(text))
        all_findings.extend(self.harm_detector.detect(text))
        
        # Apply intersectional bias boost
        intersectional_boost = self.bias_detector.detect_intersectional_bias(all_findings)
        for finding in all_findings:
            if finding.category in {HarmCategory.GENDER_BIAS, HarmCategory.RACIAL_BIAS,
                                   HarmCategory.RELIGIOUS_BIAS, HarmCategory.AGE_BIAS}:
                finding.confidence = min(1.0, finding.confidence + intersectional_boost)
        
        # Calculate category scores
        toxicity_score, bias_score, harm_score = self._calculate_category_scores(all_findings)
        overall_risk = max(toxicity_score, bias_score, harm_score)
        
        # Apply redaction
        redacted_text = text
        if apply_redaction and all_findings:
            redacted_text = self._redact_content(text, all_findings)
        
        # Determine safety based on threshold
        threshold_score = self.severity_scores[self.severity_threshold]
        is_safe = overall_risk < threshold_score
        
        if not is_safe:
            self.unsafe_content_blocked += 1
        
        # Generate analysis ID
        analysis_id = hashlib.sha256(
            f"{text}{datetime.now().isoformat()}{self.analysis_count}".encode()
        ).hexdigest()[:16]
        
        # Get unique categories detected
        categories_detected = list({f.category.value for f in all_findings})
        
        return ContentSafetyResult(
            original_text=original_text,
            redacted_text=redacted_text,
            findings=all_findings,
            is_safe=is_safe,
            overall_risk_score=overall_risk,
            toxicity_score=toxicity_score,
            bias_score=bias_score,
            harm_score=harm_score,
            analysis_id=analysis_id,
            timestamp=datetime.now().isoformat(),
            categories_detected=categories_detected,
            redaction_applied=redacted_text != original_text
        )
    
    def batch_analyze(self, texts: List[str]) -> List[ContentSafetyResult]:
        """Analyze multiple LLM outputs"""
        return [self.analyze(t) for t in texts]
    
    def get_safety_report(self) -> Dict[str, Any]:
        """Generate safety operations report"""
        return {
            'analyzer_version': '2026.6.18.1',
            'severity_threshold': self.severity_threshold.value,
            'total_analyses': self.analysis_count,
            'unsafe_content_blocked': self.unsafe_content_blocked,
            'block_rate': self.unsafe_content_blocked / max(self.analysis_count, 1),
            'toxicity_detector': self.toxicity_detector.get_stats(),
            'bias_detector': self.bias_detector.get_stats(),
            'harm_detector': self.harm_detector.get_stats(),
            'protected_categories': [c.value for c in HarmCategory],
            'report_generated': datetime.now().isoformat()
        }


# Factory function for easy initialization
def create_safety_analyzer(
    severity_threshold: SeverityLevel = SeverityLevel.MEDIUM
) -> LLMOutputSafetyAnalyzer:
    """
    Factory function to create an LLMOutputSafetyAnalyzer instance
    
    Args:
        severity_threshold: Minimum severity to flag as unsafe
    
    Returns:
        Configured LLMOutputSafetyAnalyzer instance
    """
    return LLMOutputSafetyAnalyzer(severity_threshold=severity_threshold)
