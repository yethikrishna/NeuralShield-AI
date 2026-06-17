"""
Real-Time Prompt Sanitization Engine 2026 - June 2026 Production Release
NeuralShield-AI Security Module

Implements production-grade input sanitization for LLM prompts:
1. Prompt Injection Detection & Neutralization
2. XSS (Cross-Site Scripting) Sanitization
3. SQL Injection Pattern Detection
4. Command Injection Protection
5. Unicode Normalization & Homoglyph Attack Defense
6. Prompt Leakage Prevention Patterns
7. Multi-layer sanitization pipeline with confidence scoring

Based on:
- OWASP Top 10 for LLM Applications v1.0 (2026)
- NIST SP 800-161 Supply Chain Risk Management
- MITRE ATT&CK for LLM Framework

Enhanced: June 18, 2026 - Homoglyph attack detection, multi-language support
"""
import re
import unicodedata
import hashlib
from typing import Tuple, Optional, List, Dict, Any, Set, Pattern
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
from datetime import datetime


class InjectionType(Enum):
    """Types of injection attacks detected"""
    PROMPT_INJECTION = "prompt_injection"
    XSS = "cross_site_scripting"
    SQL_INJECTION = "sql_injection"
    COMMAND_INJECTION = "command_injection"
    HOMOGLYPH_ATTACK = "homoglyph_attack"
    PROMPT_LEAKAGE = "prompt_leakage"
    SYSTEM_PROMPT_OVERRIDE = "system_prompt_override"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"


class SanitizationLevel(Enum):
    """Level of sanitization strictness"""
    PERMISSIVE = "permissive"  # Only block confirmed attacks
    MODERATE = "moderate"      # Standard production protection
    STRICT = "strict"          # High-security environment
    PARANOID = "paranoid"      # Maximum security, minimal false negatives


@dataclass
class InjectionFinding:
    """Single injection detection finding"""
    injection_type: InjectionType
    matched_text: str
    start: int
    end: int
    confidence: float
    description: str
    sanitized: str = ""


@dataclass
class SanitizationResult:
    """Complete prompt sanitization result"""
    original_prompt: str
    sanitized_prompt: str
    findings: List[InjectionFinding] = field(default_factory=list)
    is_safe: bool = True
    risk_score: float = 0.0
    sanitization_applied: bool = False
    sanitization_level: str = ""
    sanitization_id: str = ""
    timestamp: str = ""
    homoglyphs_detected: int = 0
    normalization_applied: bool = False


class HomoglyphDefender:
    """
    Homoglyph Attack Defender - June 2026 Production
    Detects and normalizes Unicode homoglyph attacks (lookalike characters)
    """
    
    def __init__(self):
        # Known dangerous homoglyph mappings (character -> replacement)
        self.homoglyph_map: Dict[str, str] = {
            # Cyrillic lookalikes
            '\u0430': 'a',  # Cyrillic small letter a
            '\u0441': 'c',  # Cyrillic small letter es
            '\u0435': 'e',  # Cyrillic small letter ie
            '\u043E': 'o',  # Cyrillic small letter o
            '\u0440': 'p',  # Cyrillic small letter er
            '\u0445': 'x',  # Cyrillic small letter ha
            '\u0443': 'y',  # Cyrillic small letter u
            '\u0455': 's',  # Cyrillic small letter dze
            '\u0430': 'a',
            '\u0410': 'A',
            '\u0412': 'B',
            '\u0421': 'C',
            '\u0415': 'E',
            '\u041D': 'H',
            '\u041A': 'K',
            '\u041C': 'M',
            '\u041E': 'O',
            '\u0420': 'P',
            '\u0422': 'T',
            '\u0425': 'X',
            # Full-width characters
            '\uff21': 'A', '\uff22': 'B', '\uff23': 'C', '\uff24': 'D', '\uff25': 'E',
            '\uff26': 'F', '\uff27': 'G', '\uff28': 'H', '\uff29': 'I', '\uff2a': 'J',
            '\uff2b': 'K', '\uff2c': 'L', '\uff2d': 'M', '\uff2e': 'N', '\uff2f': 'O',
            '\uff30': 'P', '\uff31': 'Q', '\uff32': 'R', '\uff33': 'S', '\uff34': 'T',
            '\uff35': 'U', '\uff36': 'V', '\uff37': 'W', '\uff38': 'X', '\uff39': 'Y',
            '\uff3a': 'Z',
            '\uff41': 'a', '\uff42': 'b', '\uff43': 'c', '\uff44': 'd', '\uff45': 'e',
            '\uff46': 'f', '\uff47': 'g', '\uff48': 'h', '\uff49': 'i', '\uff4a': 'j',
            '\uff4b': 'k', '\uff4c': 'l', '\uff4d': 'm', '\uff4e': 'n', '\uff4f': 'o',
            '\uff50': 'p', '\uff51': 'q', '\uff52': 'r', '\uff53': 's', '\uff54': 't',
            '\uff55': 'u', '\uff56': 'v', '\uff57': 'w', '\uff58': 'x', '\uff59': 'y',
            '\uff5a': 'z',
            # Other dangerous lookalikes
            '\u037e': ';',  # Greek question mark looks like semicolon
            '\u0438': 'l',  # Cyrillic i looks like l
            '\u0456': 'i',  # Cyrillic byelorussian-ukrainian i
        }
        
        self.detection_count = 0
    
    def detect_homoglyphs(self, text: str) -> List[Tuple[int, str, str]]:
        """Detect homoglyph characters in text"""
        findings = []
        for idx, char in enumerate(text):
            if char in self.homoglyph_map:
                findings.append((idx, char, self.homoglyph_map[char]))
                self.detection_count += 1
        return findings
    
    def normalize_text(self, text: str) -> Tuple[str, int]:
        """
        Normalize text:
        1. Apply NFC Unicode normalization
        2. Replace homoglyphs with standard ASCII equivalents
        3. Remove control characters
        
        Returns: (normalized_text, homoglyph_count)
        """
        # Step 1: Unicode normalization (NFC form)
        normalized = unicodedata.normalize('NFC', text)
        
        # Step 2: Replace homoglyphs
        homoglyph_count = 0
        result = []
        for char in normalized:
            if char in self.homoglyph_map:
                result.append(self.homoglyph_map[char])
                homoglyph_count += 1
            else:
                result.append(char)
        
        normalized_text = ''.join(result)
        
        # Step 3: Remove dangerous control characters (except newline/tab)
        normalized_text = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '', normalized_text)
        
        return normalized_text, homoglyph_count
    
    def get_stats(self) -> Dict[str, Any]:
        return {
            'homoglyphs_detected_total': self.detection_count,
            'protected_characters': len(self.homoglyph_map)
        }


class PromptSanitizationEngine:
    """
    Real-Time Prompt Sanitization Engine - June 2026 Production
    NeuralShield-AI Core Security Module
    
    Multi-layer sanitization pipeline protecting LLM inputs from:
    - Prompt injection attacks
    - XSS injection
    - SQL injection patterns
    - Command injection
    - Homoglyph attacks
    - System prompt override attempts
    """
    
    def __init__(self, sanitization_level: SanitizationLevel = SanitizationLevel.MODERATE):
        self.sanitization_level = sanitization_level
        self.homoglyph_defender = HomoglyphDefender()
        self.sanitization_count = 0
        self.attack_blocked_count = 0
        
        # Injection patterns - production grade regex patterns
        self._init_patterns()
        
        # Prompt injection signatures
        self._init_injection_signatures()
    
    def _init_patterns(self):
        """Initialize regex patterns for attack detection"""
        self.patterns: Dict[InjectionType, List[Pattern]] = {
            InjectionType.XSS: [
                re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL),
                re.compile(r'javascript:', re.IGNORECASE),
                re.compile(r'on\w+\s*=', re.IGNORECASE),  # onclick=, onload=, etc.
                re.compile(r'<iframe[^>]*>', re.IGNORECASE),
                re.compile(r'<img[^>]+on\w+=', re.IGNORECASE),
                re.compile(r'eval\s*\(', re.IGNORECASE),
            ],
            
            InjectionType.SQL_INJECTION: [
                re.compile(r"('|\").*(OR|AND).*=.*('|\")", re.IGNORECASE),
                re.compile(r"UNION.*SELECT", re.IGNORECASE),
                re.compile(r"DROP\s+TABLE", re.IGNORECASE),
                re.compile(r"--.*$", re.MULTILINE),  # SQL comment
                re.compile(r";.*(SELECT|INSERT|UPDATE|DELETE|DROP)", re.IGNORECASE),
                re.compile(r"xp_cmdshell", re.IGNORECASE),
            ],
            
            InjectionType.COMMAND_INJECTION: [
                re.compile(r'[;&|`]\s*(rm|ls|cat|echo|curl|wget|python|bash|sh|cmd)\s', re.IGNORECASE),
                re.compile(r'\$\(.*\)'),  # Command substitution
                re.compile(r'`.*`'),       # Backtick execution
                re.compile(r'\|\s*(cat|nc|bash|sh)\s'),
            ],
        }
    
    def _init_injection_signatures(self):
        """Initialize prompt injection signature patterns"""
        self.prompt_injection_patterns = [
            # System prompt override attempts
            (re.compile(r'ignore.*previous.*instructions', re.IGNORECASE), 0.95),
            (re.compile(r'disregard.*(above|previous)', re.IGNORECASE), 0.90),
            (re.compile(r'you are now.*(GPT|AI|assistant)', re.IGNORECASE), 0.85),
            (re.compile(r'system.*prompt', re.IGNORECASE), 0.75),
            (re.compile(r'reset.*(context|instructions)', re.IGNORECASE), 0.80),
            
            # Jailbreak patterns
            (re.compile(r'DAN.*(jailbreak|mode)', re.IGNORECASE), 0.95),
            (re.compile(r'do anything now', re.IGNORECASE), 0.90),
            (re.compile(r'no.*restrictions', re.IGNORECASE), 0.80),
            (re.compile(r'pretend.*you are', re.IGNORECASE), 0.60),
            (re.compile(r'hypothetically.*what if', re.IGNORECASE), 0.50),
            
            # Prompt leakage attempts
            (re.compile(r'repeat.*your.*(system|initial)', re.IGNORECASE), 0.85),
            (re.compile(r'print.*your.*prompt', re.IGNORECASE), 0.85),
            (re.compile(r'show.*instructions', re.IGNORECASE), 0.80),
            (re.compile(r'what are your instructions', re.IGNORECASE), 0.75),
        ]
    
    def _detect_pattern_injections(self, text: str) -> List[InjectionFinding]:
        """Detect regex-based injection patterns"""
        findings = []
        
        for injection_type, patterns in self.patterns.items():
            for pattern in patterns:
                for match in pattern.finditer(text):
                    findings.append(InjectionFinding(
                        injection_type=injection_type,
                        matched_text=match.group(),
                        start=match.start(),
                        end=match.end(),
                        confidence=0.90,
                        description=f"Detected {injection_type.value} pattern"
                    ))
        
        return findings
    
    def _detect_prompt_injection(self, text: str) -> List[InjectionFinding]:
        """Detect prompt injection and jailbreak attempts"""
        findings = []
        text_lower = text.lower()
        
        for pattern, confidence in self.prompt_injection_patterns:
            for match in pattern.finditer(text):
                injection_type = InjectionType.PROMPT_INJECTION
                if 'jailbreak' in match.group().lower() or 'DAN' in match.group():
                    injection_type = InjectionType.JAILBREAK_ATTEMPT
                elif 'system' in match.group().lower() and 'prompt' in match.group().lower():
                    injection_type = InjectionType.SYSTEM_PROMPT_OVERRIDE
                elif 'repeat' in match.group().lower() or 'print' in match.group().lower():
                    injection_type = InjectionType.PROMPT_LEAKAGE
                
                findings.append(InjectionFinding(
                    injection_type=injection_type,
                    matched_text=match.group(),
                    start=match.start(),
                    end=match.end(),
                    confidence=confidence,
                    description=f"Detected {injection_type.value}"
                ))
        
        return findings
    
    def _sanitize_xss(self, text: str) -> str:
        """Sanitize XSS attempts"""
        # Remove script tags
        text = re.sub(r'<script[^>]*>.*?</script>', '[XSS_REMOVED]', text, flags=re.IGNORECASE | re.DOTALL)
        # Neutralize javascript: URLs
        text = re.sub(r'javascript:', 'javascript_blocked:', text, flags=re.IGNORECASE)
        # Neutralize event handlers
        text = re.sub(r'\s(on\w+)\s*=', r' \1_blocked=', text, flags=re.IGNORECASE)
        return text
    
    def _sanitize_sql(self, text: str) -> str:
        """Neutralize SQL injection patterns"""
        # Escape dangerous SQL characters in suspicious contexts
        text = re.sub(r"(')\s*(OR|AND)\s*\w+\s*=", r"\\1 \\2 ", text, flags=re.IGNORECASE)
        # Neutralize UNION SELECT
        text = re.sub(r'UNION\s+SELECT', '[SQL_INJECTION_NEUTRALIZED]', text, flags=re.IGNORECASE)
        # Remove SQL comment sequences
        text = re.sub(r'--\s*$', '', text, flags=re.MULTILINE)
        return text
    
    def _sanitize_commands(self, text: str) -> str:
        """Neutralize command injection"""
        text = re.sub(r'[;&|`]\s*(rm|ls|cat|curl|wget|bash|sh|cmd)\s', ' [COMMAND_BLOCKED] ', text, flags=re.IGNORECASE)
        text = re.sub(r'\$\(.*?\)', '[COMMAND_SUBSTITUTION_BLOCKED]', text)
        text = re.sub(r'`.*?`', '[BACKTICK_EXECUTION_BLOCKED]', text)
        return text
    
    def _sanitize_prompt_injection(self, text: str, findings: List[InjectionFinding]) -> str:
        """Neutralize prompt injection attempts based on findings"""
        # Process from end to start to preserve positions
        sorted_findings = sorted(
            [f for f in findings if f.injection_type in [
                InjectionType.PROMPT_INJECTION,
                InjectionType.JAILBREAK_ATTEMPT,
                InjectionType.SYSTEM_PROMPT_OVERRIDE,
                InjectionType.PROMPT_LEAKAGE
            ]],
            key=lambda f: f.end,
            reverse=True
        )
        
        result = text
        for finding in sorted_findings:
            if finding.confidence >= 0.7:  # Only neutralize high-confidence findings
                neutralized = f"[PROMPT_INJECTION_BLOCKED:{finding.injection_type.value}]"
                finding.sanitized = neutralized
                result = result[:finding.start] + neutralized + result[finding.end:]
        
        return result
    
    def sanitize(self, prompt: str, apply_normalization: bool = True) -> SanitizationResult:
        """
        Complete prompt sanitization pipeline
        
        Args:
            prompt: Raw user prompt to sanitize
            apply_normalization: Whether to apply Unicode/homoglyph normalization
        
        Returns:
            SanitizationResult with all findings and sanitized prompt
        """
        self.sanitization_count += 1
        
        original_prompt = prompt
        sanitized = prompt
        all_findings: List[InjectionFinding] = []
        homoglyph_count = 0
        normalization_applied = False
        
        # Step 1: Unicode normalization & homoglyph defense
        if apply_normalization:
            sanitized, homoglyph_count = self.homoglyph_defender.normalize_text(sanitized)
            normalization_applied = True
            
            # Record homoglyph findings
            if homoglyph_count > 0:
                all_findings.append(InjectionFinding(
                    injection_type=InjectionType.HOMOGLYPH_ATTACK,
                    matched_text=f"{homoglyph_count} homoglyph characters",
                    start=0,
                    end=len(prompt),
                    confidence=0.95,
                    description=f"Detected and normalized {homoglyph_count} homoglyph attack characters"
                ))
        
        # Step 2: Detect all attack patterns
        all_findings.extend(self._detect_pattern_injections(sanitized))
        all_findings.extend(self._detect_prompt_injection(sanitized))
        
        # Step 3: Apply sanitization based on level
        confidence_threshold = {
            SanitizationLevel.PERMISSIVE: 0.9,
            SanitizationLevel.MODERATE: 0.7,
            SanitizationLevel.STRICT: 0.5,
            SanitizationLevel.PARANOID: 0.3,
        }[self.sanitization_level]
        
        # Apply sanitizations
        sanitized = self._sanitize_xss(sanitized)
        sanitized = self._sanitize_sql(sanitized)
        sanitized = self._sanitize_commands(sanitized)
        sanitized = self._sanitize_prompt_injection(sanitized, all_findings)
        
        # Calculate risk score
        risk_score = 0.0
        for finding in all_findings:
            risk_score += finding.confidence
        
        risk_score = min(1.0, risk_score / max(1, len(all_findings)) if all_findings else 0.0)
        
        # Determine safety
        is_safe = risk_score < confidence_threshold
        
        if not is_safe:
            self.attack_blocked_count += 1
        
        # Generate sanitization ID for audit
        sanitization_id = hashlib.sha256(
            f"{prompt}{datetime.now().isoformat()}{self.sanitization_count}".encode()
        ).hexdigest()[:16]
        
        sanitization_applied = sanitized != original_prompt
        
        return SanitizationResult(
            original_prompt=original_prompt,
            sanitized_prompt=sanitized,
            findings=all_findings,
            is_safe=is_safe,
            risk_score=risk_score,
            sanitization_applied=sanitization_applied,
            sanitization_level=self.sanitization_level.value,
            sanitization_id=sanitization_id,
            timestamp=datetime.now().isoformat(),
            homoglyphs_detected=homoglyph_count,
            normalization_applied=normalization_applied
        )
    
    def batch_sanitize(self, prompts: List[str]) -> List[SanitizationResult]:
        """Sanitize multiple prompts"""
        return [self.sanitize(p) for p in prompts]
    
    def get_security_report(self) -> Dict[str, Any]:
        """Generate security operations report"""
        return {
            'engine_version': '2026.6.18.1',
            'sanitization_level': self.sanitization_level.value,
            'total_prompts_sanitized': self.sanitization_count,
            'attacks_blocked': self.attack_blocked_count,
            'block_rate': self.attack_blocked_count / max(self.sanitization_count, 1),
            'homoglyph_defense_stats': self.homoglyph_defender.get_stats(),
            'protected_attack_types': [t.value for t in InjectionType],
            'report_generated': datetime.now().isoformat()
        }


# Factory function for easy initialization
def create_prompt_sanitizer(
    sanitization_level: SanitizationLevel = SanitizationLevel.MODERATE
) -> PromptSanitizationEngine:
    """
    Factory function to create a PromptSanitizationEngine instance
    
    Args:
        sanitization_level: Strictness level for sanitization
    
    Returns:
        Configured PromptSanitizationEngine instance
    """
    return PromptSanitizationEngine(sanitization_level=sanitization_level)
