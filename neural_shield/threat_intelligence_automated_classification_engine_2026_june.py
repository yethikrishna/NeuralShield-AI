"""
Threat Intelligence Automated Classification Engine
Production-grade implementation for NeuralShield-AI

Classifies threat intelligence feeds into categories:
- MALWARE: Malicious software, ransomware, trojans, viruses
- PHISHING: Phishing domains, fake login pages, social engineering
- VULNERABILITY: CVEs, security advisories, patch information
- IOC: Indicators of Compromise (IPs, domains, hashes)
- THREAT_ACTOR: APT groups, hacker teams, campaign tracking
- NETWORK: Network attacks, DDoS, port scanning
- DATA_BREACH: Data leaks, credential stuffing, exfiltration
- ZERO_DAY: Unknown vulnerabilities, exploit development
- MISCELLANEOUS: Uncategorized threats
"""

import re
import hashlib
import json
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, Counter
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatCategory(Enum):
    """Standard threat classification categories"""
    MALWARE = "malware"
    PHISHING = "phishing"
    VULNERABILITY = "vulnerability"
    IOC = "ioc"
    THREAT_ACTOR = "threat_actor"
    NETWORK = "network"
    DATA_BREACH = "data_breach"
    ZERO_DAY = "zero_day"
    MISCELLANEOUS = "miscellaneous"


class SeverityLevel(Enum):
    """Severity classification levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ClassificationResult:
    """Result of threat classification"""
    threat_id: str
    category: ThreatCategory
    severity: SeverityLevel
    confidence: float
    matched_keywords: List[str]
    extracted_iocs: Dict[str, List[str]]
    classification_reason: str
    processing_time_ms: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreatIntelligenceClassifier:
    """
    Production-grade threat intelligence classification engine.
    Uses pattern matching, keyword analysis, and IOC extraction.
    """

    def __init__(self, min_confidence: float = 0.3):
        self.min_confidence = min_confidence
        self.classification_stats = Counter()
        self.processed_count = 0
        self._init_patterns()

    def _init_patterns(self):
        """Initialize classification patterns and keywords"""
        
        # Malware patterns
        self.malware_keywords = {
            'malware', 'ransomware', 'trojan', 'virus', 'worm', 'botnet',
            'spyware', 'adware', 'rootkit', 'keylogger', 'backdoor',
            'cryptolocker', 'wannacry', 'emotet', 'trickbot', 'zeus',
            'dridex', 'formbook', 'agenttesla', 'remcos', 'njrat',
            'exe', 'dll', 'payload', 'infection', 'infect', 'dropper'
        }

        # Phishing patterns
        self.phishing_keywords = {
            'phish', 'phishing', 'spoof', 'spoofing', 'fake login',
            'credential harvester', 'social engineering', 'spear phish',
            'whaling', 'vishing', 'smishing', 'lookalike', 'typosquat',
            'brand impersonation', 'login page', 'verify account',
            'suspicious email', 'malicious attachment'
        }

        # Vulnerability patterns
        self.vulnerability_keywords = {
            'cve', 'vulnerability', 'exploit', 'patch', 'security advisory',
            'buffer overflow', 'sql injection', 'xss', 'cross-site',
            'remote code execution', 'rce', 'privilege escalation',
            'authentication bypass', 'directory traversal', 'csrf',
            'ssrf', 'deserialization', 'use-after-free', 'nvd'
        }

        # IOC patterns
        self.ioc_keywords = {
            'ioc', 'indicator', 'ip address', 'domain', 'hash', 'md5',
            'sha1', 'sha256', 'url', 'malicious ip', 'malicious domain',
            'c2', 'command and control', 'callback'
        }

        # Threat actor patterns
        self.threat_actor_keywords = {
            'apt', 'threat actor', 'hacking group', 'campaign', 'ta',
            'nation state', 'financially motivated', 'espionage',
            'lazarus', 'apt28', 'apt29', 'cozy bear', 'fancy bear',
            'conti', 'lockbit', 'cl0p', 'ransomware gang', 'hackers'
        }

        # Network attack patterns
        self.network_keywords = {
            'ddos', 'denial of service', 'port scan', 'brute force',
            'network attack', 'syn flood', 'udp flood', 'dns amplification',
            'man-in-the-middle', 'mitm', 'arp spoofing', 'dns poisoning',
            'traffic anomaly', 'bandwidth', 'packet'
        }

        # Data breach patterns
        self.data_breach_keywords = {
            'data breach', 'leak', 'leaked', 'exfiltration', 'exfiltrate',
            'credential stuffing', 'password dump', 'database leak',
            'personal information', 'pii', 'data exposure', 'compromised',
            'hacked database', 'dark web'
        }

        # Zero-day patterns
        self.zero_day_keywords = {
            'zero day', 'zero-day', '0day', 'zeroday', 'unknown vulnerability',
            'unpatched', 'no patch', 'no patch available', 'actively exploited', 
            'in the wild', 'exploit development', 'proof of concept', 'poc'
        }

        # Regex patterns for IOC extraction
        self.ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
            r'[a-zA-Z]{2,}\b'
        )
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.]|%[\da-fA-F]{2})+'
        )
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from threat text"""
        iocs = {
            'ipv4': [],
            'domains': [],
            'md5': [],
            'sha1': [],
            'sha256': [],
            'urls': [],
            'cves': []
        }

        # Extract IPs
        ips = self.ipv4_pattern.findall(text)
        iocs['ipv4'] = list(set([ip for ip in ips if not ip.startswith('192.168.') 
                                and not ip.startswith('10.')
                                and not ip.startswith('127.')]))

        # Extract domains (basic filtering)
        domains = self.domain_pattern.findall(text)
        exclude_domains = {'example.com', 'localhost', 'test.com'}
        iocs['domains'] = list(set([d.lower() for d in domains 
                                   if d.lower() not in exclude_domains]))

        # Extract hashes
        iocs['md5'] = list(set(self.md5_pattern.findall(text)))
        iocs['sha1'] = list(set(self.sha1_pattern.findall(text)))
        iocs['sha256'] = list(set(self.sha256_pattern.findall(text)))

        # Extract URLs
        iocs['urls'] = list(set(self.url_pattern.findall(text)))

        # Extract CVEs
        iocs['cves'] = list(set([c.upper() for c in self.cve_pattern.findall(text)]))

        return iocs

    def _calculate_category_score(self, text: str, keywords: set) -> Tuple[float, List[str]]:
        """Calculate classification score for a category"""
        text_lower = text.lower()
        matched = []
        score = 0.0

        for keyword in keywords:
            if keyword in text_lower:
                matched.append(keyword)
                # Longer keywords get more weight
                score += len(keyword) / 10.0

        # Bonus for multiple matches
        if len(matched) >= 3:
            score *= 1.5
        elif len(matched) >= 5:
            score *= 2.0

        return min(score, 1.0), matched

    def _calculate_severity(self, text: str, category: ThreatCategory) -> SeverityLevel:
        """Calculate severity level based on content"""
        text_lower = text.lower()

        critical_keywords = {
            'critical', 'emergency', 'massive', 'widespread', 'actively exploited',
            'in the wild', 'zero day', 'ransomware', 'data breach', 'cve-202'
        }
        high_keywords = {
            'high', 'important', 'serious', 'exploit available', 'remote code',
            'privilege escalation', 'authentication bypass'
        }
        medium_keywords = {
            'medium', 'moderate', 'dos', 'denial of service', 'xss', 'csrf'
        }
        low_keywords = {
            'low', 'minor', 'information disclosure', 'best practice'
        }

        critical_count = sum(1 for k in critical_keywords if k in text_lower)
        high_count = sum(1 for k in high_keywords if k in text_lower)
        medium_count = sum(1 for k in medium_keywords if k in text_lower)
        low_count = sum(1 for k in low_keywords if k in text_lower)

        if critical_count > 0 or category in {ThreatCategory.ZERO_DAY, ThreatCategory.DATA_BREACH}:
            return SeverityLevel.CRITICAL
        elif high_count > 0 or category in {ThreatCategory.MALWARE, ThreatCategory.THREAT_ACTOR}:
            return SeverityLevel.HIGH
        elif medium_count > 0 or category in {ThreatCategory.VULNERABILITY}:
            return SeverityLevel.MEDIUM
        elif low_count > 0 or category in {ThreatCategory.IOC}:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO

    def classify(self, threat_text: str, 
                 threat_source: str = "unknown",
                 metadata: Optional[Dict[str, Any]] = None) -> ClassificationResult:
        """
        Classify a threat intelligence entry.
        
        Args:
            threat_text: The threat description to classify
            threat_source: Source of the threat intel
            metadata: Additional metadata
            
        Returns:
            ClassificationResult with category, severity, confidence
        """
        start_time = time.time()
        self.processed_count += 1

        # Generate threat ID
        threat_id = hashlib.sha256(
            f"{threat_text}{time.time()}".encode()
        ).hexdigest()[:16]

        # Extract IOCs
        extracted_iocs = self._extract_iocs(threat_text)

        # Calculate scores for each category
        scores = {}
        all_matched = {}

        scores[ThreatCategory.MALWARE], all_matched[ThreatCategory.MALWARE] = \
            self._calculate_category_score(threat_text, self.malware_keywords)
        scores[ThreatCategory.PHISHING], all_matched[ThreatCategory.PHISHING] = \
            self._calculate_category_score(threat_text, self.phishing_keywords)
        scores[ThreatCategory.VULNERABILITY], all_matched[ThreatCategory.VULNERABILITY] = \
            self._calculate_category_score(threat_text, self.vulnerability_keywords)
        scores[ThreatCategory.IOC], all_matched[ThreatCategory.IOC] = \
            self._calculate_category_score(threat_text, self.ioc_keywords)
        scores[ThreatCategory.THREAT_ACTOR], all_matched[ThreatCategory.THREAT_ACTOR] = \
            self._calculate_category_score(threat_text, self.threat_actor_keywords)
        scores[ThreatCategory.NETWORK], all_matched[ThreatCategory.NETWORK] = \
            self._calculate_category_score(threat_text, self.network_keywords)
        scores[ThreatCategory.DATA_BREACH], all_matched[ThreatCategory.DATA_BREACH] = \
            self._calculate_category_score(threat_text, self.data_breach_keywords)
        scores[ThreatCategory.ZERO_DAY], all_matched[ThreatCategory.ZERO_DAY] = \
            self._calculate_category_score(threat_text, self.zero_day_keywords)

        # Find best category
        best_category = ThreatCategory.MISCELLANEOUS
        best_score = self.min_confidence
        best_matched = []

        for category, score in scores.items():
            if score > best_score:
                best_score = score
                best_category = category
                best_matched = all_matched[category]

        # Calculate severity
        severity = self._calculate_severity(threat_text, best_category)

        # Build classification reason
        if best_matched:
            reason = f"Matched keywords: {', '.join(best_matched[:5])}"
        else:
            reason = "No strong classification signals, defaulting to miscellaneous"

        processing_time = (time.time() - start_time) * 1000

        # Update stats
        self.classification_stats[best_category.value] += 1

        result_metadata = metadata or {}
        result_metadata.update({
            'source': threat_source,
            'all_scores': {k.value: v for k, v in scores.items()},
            'ioc_count': sum(len(v) for v in extracted_iocs.values())
        })

        return ClassificationResult(
            threat_id=threat_id,
            category=best_category,
            severity=severity,
            confidence=round(best_score, 3),
            matched_keywords=best_matched,
            extracted_iocs=extracted_iocs,
            classification_reason=reason,
            processing_time_ms=round(processing_time, 2),
            metadata=result_metadata
        )

    def batch_classify(self, threats: List[Tuple[str, str]], 
                       metadata: Optional[Dict[str, Any]] = None) -> List[ClassificationResult]:
        """Classify multiple threats in batch"""
        results = []
        for threat_text, source in threats:
            result = self.classify(threat_text, source, metadata)
            results.append(result)
        return results

    def get_statistics(self) -> Dict[str, Any]:
        """Get classification statistics"""
        return {
            'total_processed': self.processed_count,
            'category_distribution': dict(self.classification_stats),
            'min_confidence_threshold': self.min_confidence
        }

    def export_results_json(self, results: List[ClassificationResult]) -> str:
        """Export classification results to JSON"""
        export_data = []
        for r in results:
            export_data.append({
                'threat_id': r.threat_id,
                'category': r.category.value,
                'severity': r.severity.value,
                'confidence': r.confidence,
                'matched_keywords': r.matched_keywords,
                'extracted_iocs': r.extracted_iocs,
                'reason': r.classification_reason,
                'processing_time_ms': r.processing_time_ms
            })
        return json.dumps(export_data, indent=2)


# Export main class
__all__ = [
    'ThreatIntelligenceClassifier',
    'ClassificationResult',
    'ThreatCategory',
    'SeverityLevel'
]
