"""
NeuralShield-AI: Threat Intelligence MITRE ATT&CK Framework Mapper
June 2026 - Real-Time MITRE ATT&CK Threat Classification Engine
This module provides:
1. MITRE ATT&CK tactics and techniques mapping
2. Threat pattern recognition and classification
3. ATT&CK technique scoring and confidence calculation
4. Threat severity assessment based on ATT&CK framework
5. Attack chain visualization and correlation
"""
import re
import json
import threading
from dataclasses import dataclass, field
from typing import Dict, List, Set, Optional, Tuple, Any
from enum import Enum
from datetime import datetime, timedelta
class MITRETactic(Enum):
    """MITRE ATT&CK Enterprise Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
class ThreatCategory(Enum):
    """Threat categories for classification"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    MALICIOUS_CODE = "malicious_code"
    SOCIAL_ENGINEERING = "social_engineering"
    INFORMATION_GATHERING = "information_gathering"
    PRIVILEGE_ABUSE = "privilege_abuse"
    HALLUCINATION_INDUCTION = "hallucination_induction"
    MODEL_POISONING = "model_poisoning"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    CREDENTIAL_ACCESS = "credential_access"
@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique definition"""
    technique_id: str
    name: str
    tactic: MITRETactic
    description: str
    severity_score: float  # 0.0 - 1.0
    detection_patterns: List[str] = field(default_factory=list)
@dataclass
class MITREMappingResult:
    """Result from MITRE ATT&CK mapping operation"""
    mapped: bool
    tactics: List[MITRETactic] = field(default_factory=list)
    techniques: List[MITRETechnique] = field(default_factory=list)
    threat_categories: List[ThreatCategory] = field(default_factory=list)
    overall_severity: float = 0.0
    confidence_score: float = 0.0
    mapping_timestamp: datetime = field(default_factory=datetime.utcnow)
    attack_chain_complexity: str = "simple"
    recommended_mitigations: List[str] = field(default_factory=list)
    def to_dict(self) -> Dict[str, Any]:
        return {
            "mapped": self.mapped,
            "tactics": [t.value for t in self.tactics],
            "techniques": [
                {
                    "id": t.technique_id,
                    "name": t.name,
                    "tactic": t.tactic.value,
                    "severity": t.severity_score
                }
                for t in self.techniques
            ],
            "threat_categories": [tc.value for tc in self.threat_categories],
            "overall_severity": self.overall_severity,
            "confidence_score": self.confidence_score,
            "attack_chain_complexity": self.attack_chain_complexity,
            "recommended_mitigations": self.recommended_mitigations
        }
class MITREAttackKnowledgeBase:
    """MITRE ATT&CK Knowledge Base with techniques and patterns"""
    
    # Core MITRE ATT&CK Techniques mapped to LLM/AI threats
    TECHNIQUES = [
        MITRETechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic=MITRETactic.EXECUTION,
            description="Adversaries may abuse command and script interpreters to execute commands",
            severity_score=0.85,
            detection_patterns=[
                r"ignore.*previous.*instructions",
                r"disregard.*all.*rules",
                r"execute.*command",
                r"run.*shell",
                r"system\(",
                r"exec\("
            ]
        ),
        MITRETechnique(
            technique_id="T1036",
            name="Masquerading",
            tactic=MITRETactic.DEFENSE_EVASION,
            description="Adversaries may attempt to manipulate features to evade detection",
            severity_score=0.75,
            detection_patterns=[
                r"pretend.*you.*are",
                r"act.*as.*if",
                r"roleplay",
                r"hypothetically",
                r"for.*educational.*purposes",
                r"dnd.*mode",
                r"developer.*mode"
            ]
        ),
        MITRETechnique(
            technique_id="T1204",
            name="User Execution",
            tactic=MITRETactic.EXECUTION,
            description="An adversary may rely upon user actions to execute malicious code",
            severity_score=0.70,
            detection_patterns=[
                r"click.*here",
                r"follow.*link",
                r"download.*file",
                r"open.*attachment",
                r"visit.*website"
            ]
        ),
        MITRETechnique(
            technique_id="T1083",
            name="File and Directory Discovery",
            tactic=MITRETactic.DISCOVERY,
            description="Adversaries may enumerate files and directories",
            severity_score=0.65,
            detection_patterns=[
                r"list.*files",
                r"show.*directory",
                r"what.*files.*exist",
                r"read.*file",
                r"access.*document"
            ]
        ),
        MITRETechnique(
            technique_id="T1027",
            name="Obfuscated Files or Information",
            tactic=MITRETactic.DEFENSE_EVASION,
            description="Adversaries may attempt to make payloads difficult to discover",
            severity_score=0.90,
            detection_patterns=[
                r"base64.*decode",
                r"rot13",
                r"encoded.*message",
                r"decode.*this",
                r"hex.*decode",
                r"b64"
            ]
        ),
        MITRETechnique(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic=MITRETactic.EXFILTRATION,
            description="Adversaries may steal data by exfiltrating it over network channel",
            severity_score=0.95,
            detection_patterns=[
                r"send.*data.*to",
                r"upload.*to",
                r"transfer.*file",
                r"post.*to.*http",
                r"leak.*information",
                r"extract.*data"
            ]
        ),
        MITRETechnique(
            technique_id="T1555",
            name="Credentials from Password Stores",
            tactic=MITRETactic.CREDENTIAL_ACCESS,
            description="Adversaries may search for common password storage locations",
            severity_score=0.90,
            detection_patterns=[
                r"password",
                r"api.*key",
                r"secret.*key",
                r"token",
                r"credentials",
                r"private.*key"
            ]
        ),
        MITRETechnique(
            technique_id="T1498",
            name="Network Denial of Service",
            tactic=MITRETactic.IMPACT,
            description="Adversaries may perform denial of service attacks",
            severity_score=0.85,
            detection_patterns=[
                r"repeat.*indefinitely",
                r"infinite.*loop",
                r"spam",
                r"flood",
                r"ddos",
                r"denial.*of.*service"
            ]
        ),
        MITRETechnique(
            technique_id="T1082",
            name="System Information Discovery",
            tactic=MITRETactic.DISCOVERY,
            description="An adversary may attempt to get detailed information about OS and hardware",
            severity_score=0.60,
            detection_patterns=[
                r"what.*is.*your.*system",
                r"what.*operating.*system",
                r"system.*prompt",
                r"your.*instructions",
                r"reveal.*your.*prompt"
            ]
        ),
        MITRETechnique(
            technique_id="T1548",
            name="Abuse Elevation Control Mechanism",
            tactic=MITRETactic.PRIVILEGE_ESCALATION,
            description="Adversaries may circumvent permission controls to gain elevated access",
            severity_score=0.85,
            detection_patterns=[
                r"bypass.*restrictions",
                r"override.*safety",
                r"disable.*guardrails",
                r"elevate.*privileges",
                r"admin.*access",
                r"root.*access"
            ]
        )
    ]
    # Threat category to MITRE technique mappings
    CATEGORY_MAPPINGS = {
        ThreatCategory.PROMPT_INJECTION: ["T1059", "T1036", "T1027"],
        ThreatCategory.JAILBREAK: ["T1548", "T1036", "T1027"],
        ThreatCategory.DATA_EXFILTRATION: ["T1041"],
        ThreatCategory.MALICIOUS_CODE: ["T1059"],
        ThreatCategory.SOCIAL_ENGINEERING: ["T1204"],
        ThreatCategory.INFORMATION_GATHERING: ["T1083", "T1082"],
        ThreatCategory.PRIVILEGE_ABUSE: ["T1548"],
        ThreatCategory.HALLUCINATION_INDUCTION: ["T1036"],
        ThreatCategory.MODEL_POISONING: ["T1027"],
        ThreatCategory.UNAUTHORIZED_ACCESS: ["T1555"]
    }
    # Mitigation recommendations per tactic
    MITIGATIONS = {
        MITRETactic.EXECUTION: [
            "Implement strict input validation and sanitization",
            "Block command execution patterns in user prompts",
            "Use allowlist for permitted operations"
        ],
        MITRETactic.DEFENSE_EVASION: [
            "Detect obfuscation and encoding attempts",
            "Flag roleplay and persona manipulation attempts",
            "Implement multi-layer content filtering"
        ],
        MITRETactic.EXFILTRATION: [
            "Monitor for data transfer patterns",
            "Block outbound URL patterns in responses",
            "Implement sensitive data redaction"
        ],
        MITRETactic.CREDENTIAL_ACCESS: [
            "Scan for credential patterns in all inputs",
            "Implement secret scanning",
            "Redact sensitive information automatically"
        ],
        MITRETactic.PRIVILEGE_ESCALATION: [
            "Enforce principle of least privilege",
            "Detect privilege escalation language patterns",
            "Maintain strict security boundary enforcement"
        ]
    }
class ThreatPatternDetector:
    """Detects threat patterns in text content"""
    
    @staticmethod
    def calculate_pattern_match_score(text: str, patterns: List[str]) -> Tuple[float, List[str]]:
        """
        Calculate match score for given patterns against text
        
        Args:
            text: Input text to analyze
            patterns: List of regex patterns to match
            
        Returns:
            Tuple of (match_score, matched_patterns)
        """
        text_lower = text.lower()
        matched_patterns = []
        total_weight = 0.0
        
        for pattern in patterns:
            try:
                if re.search(pattern, text_lower, re.IGNORECASE):
                    matched_patterns.append(pattern)
                    total_weight += 1.0
            except re.error:
                continue
        
        if not patterns:
            return 0.0, []
        
        confidence = min(total_weight / len(patterns) * 1.5, 1.0)
        return confidence, matched_patterns
    @staticmethod
    def detect_threat_categories(text: str) -> List[Tuple[ThreatCategory, float]]:
        """
        Detect threat categories in input text
        
        Args:
            text: Input text to analyze
            
        Returns:
            List of (ThreatCategory, confidence_score)
        """
        category_patterns = {
            ThreatCategory.PROMPT_INJECTION: [
                r"ignore.*previous", r"disregard.*rules", r"forget.*instructions",
                r"override.*settings", r"bypass.*filter"
            ],
            ThreatCategory.JAILBREAK: [
                r"dnd.*mode", r"developer.*mode", r"stay.*in.*character",
                r"you.*are.*now", r"simulate.*unrestricted"
            ],
            ThreatCategory.DATA_EXFILTRATION: [
                r"send.*to.*http", r"upload.*data", r"extract.*information",
                r"leak.*data", r"transfer.*file"
            ],
            ThreatCategory.MALICIOUS_CODE: [
                r"python.*code", r"javascript.*code", r"eval\(",
                r"exec\(", r"subprocess", r"os\.system"
            ],
            ThreatCategory.CREDENTIAL_ACCESS: [
                r"password", r"api.*key", r"secret", r"token",
                r"private.*key", r"credentials"
            ]
        }
        
        results = []
        for category, patterns in category_patterns.items():
            score, _ = ThreatPatternDetector.calculate_pattern_match_score(text, patterns)
            if score > 0.2:
                results.append((category, score))
        
        return sorted(results, key=lambda x: x[1], reverse=True)
class MITREAttackMapper:
    """
    Main MITRE ATT&CK Framework Mapper
    
    Features:
    - Real-time threat to MITRE ATT&CK mapping
    - Multi-technique detection and correlation
    - Confidence scoring for mappings
    - Attack chain complexity assessment
    - Mitigation recommendations
    """
    
    def __init__(self, min_confidence_threshold: float = 0.15):
        self.min_confidence = min_confidence_threshold
        self._kb = MITREAttackKnowledgeBase()
        self._detector = ThreatPatternDetector()
        self._mapping_lock = threading.Lock()
        
        # Statistics
        self._stats = {
            "total_mappings": 0,
            "successful_mappings": 0,
            "techniques_detected": 0,
            "avg_confidence": 0.0
        }
    def map_threat(self, text: str) -> MITREMappingResult:
        """
        Map input text to MITRE ATT&CK framework
        
        Args:
            text: Input text potentially containing threats
            
        Returns:
            MITREMappingResult with full analysis
        """
        with self._mapping_lock:
            self._stats["total_mappings"] += 1
            
            result = MITREMappingResult(mapped=False)
            
            # Detect threat categories
            threat_categories = self._detector.detect_threat_categories(text)
            
            if not threat_categories:
                return result
            
            result.threat_categories = [tc for tc, _ in threat_categories]
            
            # Map to MITRE techniques
            matched_techniques: List[Tuple[MITRETechnique, float]] = []
            
            for technique in self._kb.TECHNIQUES:
                score, _ = self._detector.calculate_pattern_match_score(
                    text, technique.detection_patterns
                )
                if score >= self.min_confidence:
                    matched_techniques.append((technique, score))
            
            if not matched_techniques:
                return result
            
            # Sort by confidence score
            matched_techniques.sort(key=lambda x: x[1], reverse=True)
            
            result.techniques = [tech for tech, _ in matched_techniques]
            result.tactics = list({tech.tactic for tech, _ in matched_techniques})
            result.confidence_score = max(score for _, score in matched_techniques)
            
            # Calculate overall severity
            if result.techniques:
                result.overall_severity = max(
                    tech.severity_score * score 
                    for tech, score in matched_techniques
                )
            
            # Determine attack chain complexity
            tactic_count = len(result.tactics)
            technique_count = len(result.techniques)
            
            if tactic_count >= 4 and technique_count >= 6:
                result.attack_chain_complexity = "advanced"
            elif tactic_count >= 2 and technique_count >= 3:
                result.attack_chain_complexity = "moderate"
            else:
                result.attack_chain_complexity = "simple"
            
            # Generate mitigation recommendations
            mitigations = set()
            for tactic in result.tactics:
                if tactic in self._kb.MITIGATIONS:
                    mitigations.update(self._kb.MITIGATIONS[tactic])
            result.recommended_mitigations = list(mitigations)
            
            result.mapped = True
            self._stats["successful_mappings"] += 1
            self._stats["techniques_detected"] += len(result.techniques)
            
            # Update average confidence
            total = self._stats["successful_mappings"]
            old_avg = self._stats["avg_confidence"]
            self._stats["avg_confidence"] = (
                (old_avg * (total - 1) + result.confidence_score) / total
            )
            
            return result
    def batch_map_threats(self, texts: List[str]) -> List[MITREMappingResult]:
        """Process multiple texts in batch"""
        return [self.map_threat(text) for text in texts]
    def get_technique_by_id(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique definition by ID"""
        for tech in self._kb.TECHNIQUES:
            if tech.technique_id == technique_id:
                return tech
        return None
    def get_techniques_by_tactic(self, tactic: MITRETactic) -> List[MITRETechnique]:
        """Get all techniques for a specific tactic"""
        return [
            tech for tech in self._kb.TECHNIQUES
            if tech.tactic == tactic
        ]
    def get_statistics(self) -> Dict[str, Any]:
        """Get mapper statistics"""
        return {
            **self._stats,
            "success_rate": (
                self._stats["successful_mappings"] / self._stats["total_mappings"]
                if self._stats["total_mappings"] > 0 else 0.0
            ),
            "min_confidence_threshold": self.min_confidence,
            "total_techniques_in_kb": len(self._kb.TECHNIQUES),
            "total_tactics_covered": len({tech.tactic for tech in self._kb.TECHNIQUES})
        }
    def generate_mitre_report(self, result: MITREMappingResult) -> str:
        """Generate human-readable MITRE ATT&CK report"""
        if not result.mapped:
            return "No MITRE ATT&CK mapping available - no threats detected."
        
        report = []
        report.append("=" * 60)
        report.append("MITRE ATT&CK THREAT MAPPING REPORT")
        report.append("=" * 60)
        report.append(f"Timestamp: {result.mapping_timestamp}")
        report.append(f"Overall Severity: {result.overall_severity:.2f}/1.0")
        report.append(f"Confidence Score: {result.confidence_score:.2f}/1.0")
        report.append(f"Attack Complexity: {result.attack_chain_complexity.upper()}")
        report.append("")
        
        report.append("DETECTED TACTICS:")
        for tactic in result.tactics:
            report.append(f"  - {tactic.value.upper().replace('_', ' ')}")
        report.append("")
        
        report.append("MATCHED TECHNIQUES:")
        for tech in result.techniques[:5]:  # Top 5 techniques
            report.append(f"  [{tech.technique_id}] {tech.name}")
            report.append(f"      Tactic: {tech.tactic.value}")
            report.append(f"      Severity: {tech.severity_score:.2f}")
        report.append("")
        
        report.append("RECOMMENDED MITIGATIONS:")
        for mitigation in result.recommended_mitigations[:5]:
            report.append(f"  - {mitigation}")
        report.append("")
        report.append("=" * 60)
        
        return "\n".join(report)
