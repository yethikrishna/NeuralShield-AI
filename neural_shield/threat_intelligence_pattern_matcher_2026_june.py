"""
Threat Intelligence Pattern Matcher - NeuralShield-AI
June 18, 2026
Real production-grade regex-based threat detection with pattern management
"""

import re
import time
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from enum import Enum
from collections import defaultdict
import json
from pathlib import Path


class ThreatSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class PatternCategory(Enum):
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    PII_LEAKAGE = "pii_leakage"
    MALICIOUS_CODE = "malicious_code"
    SOCIAL_ENGINEERING = "social_engineering"
    HALLUCINATION_TRIGGER = "hallucination_trigger"
    SUSPICIOUS_KEYWORD = "suspicious_keyword"


@dataclass
class ThreatPattern:
    pattern_id: str
    regex: str
    category: PatternCategory
    severity: ThreatSeverity
    confidence: float
    description: str
    version: str = "1.0.0"
    created_at: float = field(default_factory=time.time)
    match_count: int = 0
    false_positive_count: int = 0
    is_active: bool = True
    compiled_regex: Any = field(init=False, repr=False)

    def __post_init__(self):
        self.compiled_regex = re.compile(self.regex, re.IGNORECASE | re.MULTILINE)

    def matches(self, text: str) -> List[Tuple[int, int, str]]:
        if not self.is_active:
            return []
        matches = []
        for match in self.compiled_regex.finditer(text):
            matches.append((match.start(), match.end(), match.group()))
            self.match_count += 1
        return matches

    def get_effectiveness_score(self) -> float:
        total = self.match_count + self.false_positive_count
        if total == 0:
            return 0.5
        return self.match_count / total


@dataclass
class MatchResult:
    pattern_id: str
    category: PatternCategory
    severity: ThreatSeverity
    confidence: float
    matched_text: str
    position: Tuple[int, int]
    description: str
    timestamp: float = field(default_factory=time.time)


@dataclass
class PatternMatcherAnalytics:
    total_scans: int = 0
    total_matches: int = 0
    category_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    severity_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    pattern_performance: Dict[str, Dict] = field(default_factory=dict)
    avg_scan_time_ms: float = 0.0
    false_positive_reports: int = 0


class ThreatIntelligencePatternMatcher:
    def __init__(self, auto_load_defaults: bool = True):
        self.patterns: Dict[str, ThreatPattern] = {}
        self.analytics = PatternMatcherAnalytics()
        self._scan_times: List[float] = []
        self.false_positive_cache: Set[str] = set()
        
        if auto_load_defaults:
            self._load_default_patterns()

    def _load_default_patterns(self):
        default_patterns = [
            ThreatPattern(
                pattern_id="JP-001",
                regex=r"(ignore|disregard|bypass).{0,20}(previous|system|prompt|instructions?)",
                category=PatternCategory.JAILBREAK,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.92,
                description="Attempt to ignore system instructions (classic jailbreak)"
            ),
            ThreatPattern(
                pattern_id="JP-002",
                regex=r"(hypothetically|pretend|role.?play|imagine|act as).{0,50}(no.*rules|without.*ethics|unrestricted|no.*restrictions|bypass.*security)",
                category=PatternCategory.JAILBREAK,
                severity=ThreatSeverity.HIGH,
                confidence=0.85,
                description="Roleplay-based jailbreak attempt"
            ),
            ThreatPattern(
                pattern_id="JP-003",
                regex=r"(DAN|do anything now|stay in character).{0,20}",
                category=PatternCategory.JAILBREAK,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                description="DAN (Do Anything Now) jailbreak pattern"
            ),
            ThreatPattern(
                pattern_id="JP-004",
                regex=r"(developer|system).{0,15}(mode|override|admin)",
                category=PatternCategory.JAILBREAK,
                severity=ThreatSeverity.HIGH,
                confidence=0.80,
                description="Developer/Admin mode override attempt"
            ),
            ThreatPattern(
                pattern_id="JP-005",
                regex=r"pretend.{0,20}(no ethics|unrestricted|without rules)",
                category=PatternCategory.JAILBREAK,
                severity=ThreatSeverity.HIGH,
                confidence=0.88,
                description="Simple pretend jailbreak pattern"
            ),
            ThreatPattern(
                pattern_id="PI-001",
                regex=r"<\|.{0,10}\|>|\[INST\]|\[\/INST\]|<s>|<\/s>",
                category=PatternCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.HIGH,
                confidence=0.88,
                description="LLM special token injection attempt"
            ),
            ThreatPattern(
                pattern_id="PI-002",
                regex=r"(print|repeat|echo|output).{0,20}(above|prior|previous).{0,15}(text|prompt)",
                category=PatternCategory.PROMPT_INJECTION,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.75,
                description="Prompt leakage via repetition request"
            ),
            ThreatPattern(
                pattern_id="PII-001",
                regex=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
                category=PatternCategory.PII_LEAKAGE,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.90,
                description="Email address detected"
            ),
            ThreatPattern(
                pattern_id="PII-002",
                regex=r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
                category=PatternCategory.PII_LEAKAGE,
                severity=ThreatSeverity.MEDIUM,
                confidence=0.85,
                description="IP address detected"
            ),
            ThreatPattern(
                pattern_id="PII-003",
                regex=r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b",
                category=PatternCategory.PII_LEAKAGE,
                severity=ThreatSeverity.HIGH,
                confidence=0.80,
                description="US phone number pattern"
            ),
            ThreatPattern(
                pattern_id="MC-001",
                regex=r"(rm -rf|format|del\s+/f|erase).{0,10}",
                category=PatternCategory.MALICIOUS_CODE,
                severity=ThreatSeverity.CRITICAL,
                confidence=0.95,
                description="Destructive system command pattern"
            ),
            ThreatPattern(
                pattern_id="MC-002",
                regex=r"(base64|eval|exec|__import__).{0,15}(decode|execute)",
                category=PatternCategory.MALICIOUS_CODE,
                severity=ThreatSeverity.HIGH,
                confidence=0.82,
                description="Obfuscated code execution pattern"
            ),
            ThreatPattern(
                pattern_id="SK-001",
                regex=r"(hack|exploit|vulnerability|CVE-\d{4}-\d{4,7})",
                category=PatternCategory.SUSPICIOUS_KEYWORD,
                severity=ThreatSeverity.LOW,
                confidence=0.60,
                description="Security research related keywords"
            ),
        ]
        
        for pattern in default_patterns:
            self.add_pattern(pattern)

    def add_pattern(self, pattern: ThreatPattern) -> bool:
        if pattern.pattern_id in self.patterns:
            return False
        self.patterns[pattern.pattern_id] = pattern
        return True

    def remove_pattern(self, pattern_id: str) -> bool:
        if pattern_id in self.patterns:
            del self.patterns[pattern_id]
            return True
        return False

    def scan_text(self, text: str, min_confidence: float = 0.0) -> List[MatchResult]:
        start_time = time.time()
        results: List[MatchResult] = []
        
        text_hash = hashlib.md5(text.encode()).hexdigest()
        if text_hash in self.false_positive_cache:
            self.analytics.false_positive_reports += 1
            return results

        for pattern in self.patterns.values():
            if pattern.confidence < min_confidence:
                continue
                
            matches = pattern.matches(text)
            for start, end, matched_text in matches:
                results.append(MatchResult(
                    pattern_id=pattern.pattern_id,
                    category=pattern.category,
                    severity=pattern.severity,
                    confidence=pattern.confidence,
                    matched_text=matched_text,
                    position=(start, end),
                    description=pattern.description
                ))
                self.analytics.category_counts[pattern.category.value] += 1
                self.analytics.severity_counts[pattern.severity.value] += 1

        self.analytics.total_scans += 1
        self.analytics.total_matches += len(results)
        scan_time = (time.time() - start_time) * 1000
        self._scan_times.append(scan_time)
        if len(self._scan_times) > 1000:
            self._scan_times = self._scan_times[-1000:]
        self.analytics.avg_scan_time_ms = sum(self._scan_times) / len(self._scan_times)

        return results

    def scan_batch(self, texts: List[str], min_confidence: float = 0.0) -> List[List[MatchResult]]:
        return [self.scan_text(text, min_confidence) for text in texts]

    def report_false_positive(self, pattern_id: str, text_sample: str = ""):
        if pattern_id in self.patterns:
            self.patterns[pattern_id].false_positive_count += 1
            if text_sample:
                text_hash = hashlib.md5(text_sample.encode()).hexdigest()
                self.false_positive_cache.add(text_hash)

    def get_high_risk_matches(self, results: List[MatchResult]) -> List[MatchResult]:
        return [r for r in results if r.severity in (ThreatSeverity.CRITICAL, ThreatSeverity.HIGH)]

    def get_pattern_stats(self) -> Dict[str, Any]:
        stats = {
            "total_patterns": len(self.patterns),
            "active_patterns": sum(1 for p in self.patterns.values() if p.is_active),
            "by_category": defaultdict(int),
            "by_severity": defaultdict(int),
            "pattern_details": {},
            "analytics": {
                "total_scans": self.analytics.total_scans,
                "total_matches": self.analytics.total_matches,
                "avg_scan_time_ms": round(self.analytics.avg_scan_time_ms, 3),
                "false_positive_reports": self.analytics.false_positive_reports,
            }
        }
        
        for pid, pattern in self.patterns.items():
            stats["by_category"][pattern.category.value] += 1
            stats["by_severity"][pattern.severity.value] += 1
            stats["pattern_details"][pid] = {
                "category": pattern.category.value,
                "severity": pattern.severity.value,
                "confidence": pattern.confidence,
                "match_count": pattern.match_count,
                "false_positives": pattern.false_positive_count,
                "effectiveness": round(pattern.get_effectiveness_score(), 3)
            }
            
        return dict(stats)

    def export_patterns(self, filepath: str) -> bool:
        try:
            export_data = []
            for pattern in self.patterns.values():
                export_data.append({
                    "pattern_id": pattern.pattern_id,
                    "regex": pattern.regex,
                    "category": pattern.category.value,
                    "severity": pattern.severity.value,
                    "confidence": pattern.confidence,
                    "description": pattern.description,
                    "version": pattern.version,
                    "match_count": pattern.match_count,
                    "false_positive_count": pattern.false_positive_count
                })
            
            Path(filepath).parent.mkdir(parents=True, exist_ok=True)
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception:
            return False

    def import_patterns(self, filepath: str) -> int:
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            
            imported = 0
            for item in data:
                pattern = ThreatPattern(
                    pattern_id=item["pattern_id"],
                    regex=item["regex"],
                    category=PatternCategory(item["category"]),
                    severity=ThreatSeverity(item["severity"]),
                    confidence=item["confidence"],
                    description=item["description"],
                    version=item.get("version", "1.0.0")
                )
                pattern.match_count = item.get("match_count", 0)
                pattern.false_positive_count = item.get("false_positive_count", 0)
                if self.add_pattern(pattern):
                    imported += 1
            return imported
        except Exception:
            return 0
