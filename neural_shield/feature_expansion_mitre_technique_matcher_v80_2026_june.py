"""
MITRE ATT&CK Technique Matcher - NeuralShield AI Feature Expansion v80
Maps detected security threats to specific MITRE ATT&CK techniques with confidence scoring.

STABILITY: STABLE
BACKWARD COMPATIBLE: YES
DEPENDENCIES: None (standalone module)
"""

import re
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum


class MITREAttackTactic(Enum):
    """MITRE ATT&CK Enterprise Tactics"""
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    EXFILTRATION = "Exfiltration"
    COMMAND_AND_CONTROL = "Command and Control"
    IMPACT = "Impact"


@dataclass
class MITRETechnique:
    """Represents a MITRE ATT&CK technique"""
    technique_id: str
    name: str
    tactic: MITREAttackTactic
    description: str
    keywords: List[str] = field(default_factory=list)
    severity_score: float = 5.0


@dataclass
class TechniqueMatch:
    """Result of a technique matching operation"""
    technique: MITRETechnique
    confidence_score: float
    matched_keywords: List[str]
    threat_context: str


class MITREAttackTechniqueMatcher:
    """
    Matches detected threats to MITRE ATT&CK techniques.
    
    Features:
    - Keyword-based matching with weighted scoring
    - Context-aware confidence calculation
    - Tactic-based grouping
    - Severity assessment
    """
    
    def __init__(self):
        self._initialize_technique_database()
        self.match_history: List[TechniqueMatch] = []
        
    def _initialize_technique_database(self):
        """Initialize the MITRE ATT&CK technique database"""
        self.techniques: Dict[str, MITRETechnique] = {}
        
        # Initial Access Techniques
        self._add_technique(MITRETechnique(
            technique_id="T1566",
            name="Phishing",
            tactic=MITREAttackTactic.INITIAL_ACCESS,
            description="User receives spearphishing messages with malicious attachments or links",
            keywords=["phish", "spearphish", "email", "attachment", "malicious link", "spoof"],
            severity_score=7.5
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1190",
            name="Exploit Public-Facing Application",
            tactic=MITREAttackTactic.INITIAL_ACCESS,
            description="Exploit vulnerabilities in internet-facing systems",
            keywords=["exploit", "vulnerability", "cve", "public facing", "internet", "web app"],
            severity_score=8.5
        ))
        
        # Execution Techniques
        self._add_technique(MITRETechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic=MITREAttackTactic.EXECUTION,
            description="Execute commands and scripts through various interpreters",
            keywords=["powershell", "cmd", "bash", "script", "command", "shell", "python", "wscript"],
            severity_score=7.0
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1204",
            name="User Execution",
            tactic=MITREAttackTactic.EXECUTION,
            description="Trick user into executing malicious code",
            keywords=["user execute", "run", "open", "double click", "social engineering"],
            severity_score=6.5
        ))
        
        # Persistence Techniques
        self._add_technique(MITRETechnique(
            technique_id="T1547",
            name="Boot or Logon Autostart Execution",
            tactic=MITREAttackTactic.PERSISTENCE,
            description="Execute code on system boot or user logon",
            keywords=["registry", "run key", "startup", "boot", "logon", "autostart", "services"],
            severity_score=8.0
        ))
        
        # Privilege Escalation
        self._add_technique(MITRETechnique(
            technique_id="T1548",
            name="Abuse Elevation Control Mechanism",
            tactic=MITREAttackTactic.PRIVILEGE_ESCALATION,
            description="Bypass elevation control mechanisms to gain higher permissions",
            keywords=["uac", "elevate", "admin", "root", "sudo", "privilege", "permission"],
            severity_score=8.5
        ))
        
        # Defense Evasion
        self._add_technique(MITRETechnique(
            technique_id="T1027",
            name="Obfuscated Files or Information",
            tactic=MITREAttackTactic.DEFENSE_EVASION,
            description="Obfuscate files or information to avoid detection",
            keywords=["obfuscate", "encode", "base64", "encrypt", "pack", "xor", "shellcode"],
            severity_score=7.5
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1562",
            name="Impair Defenses",
            tactic=MITREAttackTactic.DEFENSE_EVASION,
            description="Disable or modify system defenses",
            keywords=["disable", "defender", "antivirus", "edr", "firewall", "whitelist", "bypass"],
            severity_score=9.0
        ))
        
        # Credential Access
        self._add_technique(MITRETechnique(
            technique_id="T1003",
            name="OS Credential Dumping",
            tactic=MITREAttackTactic.CREDENTIAL_ACCESS,
            description="Dump credentials from OS memory or files",
            keywords=["dump", "credential", "hash", "lsass", "sam", "ntds", "mimikatz", "password"],
            severity_score=9.5
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1110",
            name="Brute Force",
            tactic=MITREAttackTactic.CREDENTIAL_ACCESS,
            description="Guess credentials through brute force",
            keywords=["brute", "guess", "spray", "password attack", "login attempt"],
            severity_score=7.0
        ))
        
        # Discovery
        self._add_technique(MITRETechnique(
            technique_id="T1087",
            name="Account Discovery",
            tactic=MITREAttackTactic.DISCOVERY,
            description="Discover system and domain accounts",
            keywords=["user", "account", "group", "whoami", "net user", "domain"],
            severity_score=5.0
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1046",
            name="Network Service Scanning",
            tactic=MITREAttackTactic.DISCOVERY,
            description="Scan network for open services and ports",
            keywords=["scan", "port", "nmap", "service discovery", "network"],
            severity_score=5.5
        ))
        
        # Lateral Movement
        self._add_technique(MITRETechnique(
            technique_id="T1021",
            name="Remote Services",
            tactic=MITREAttackTactic.LATERAL_MOVEMENT,
            description="Use remote services to move laterally",
            keywords=["smb", "rdp", "ssh", "winrm", "wmi", "remote", "psexec"],
            severity_score=8.0
        ))
        
        # Collection
        self._add_technique(MITRETechnique(
            technique_id="T1005",
            name="Data from Local System",
            tactic=MITREAttackTactic.COLLECTION,
            description="Collect data from local system files",
            keywords=["collect", "steal", "document", "file", "data"],
            severity_score=6.0
        ))
        
        # Exfiltration
        self._add_technique(MITRETechnique(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic=MITREAttackTactic.EXFILTRATION,
            description="Exfiltrate data over existing C2 channel",
            keywords=["exfiltrate", "send", "transfer", "data leak", "upload"],
            severity_score=8.5
        ))
        
        # Command and Control
        self._add_technique(MITRETechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            tactic=MITREAttackTactic.COMMAND_AND_CONTROL,
            description="Use application layer protocols for C2",
            keywords=["http", "https", "dns", "ftp", "c2", "beacon", "callback"],
            severity_score=8.0
        ))
        
        # Impact
        self._add_technique(MITRETechnique(
            technique_id="T1486",
            name="Data Encrypted for Impact",
            tactic=MITREAttackTactic.IMPACT,
            description="Encrypt data to disrupt availability (ransomware)",
            keywords=["ransom", "encrypt", "bitcoin", "wallet", "decrypt", "lock"],
            severity_score=10.0
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1490",
            name="Inhibit System Recovery",
            tactic=MITREAttackTactic.IMPACT,
            description="Delete or disable system recovery mechanisms",
            keywords=["vss", "shadow copy", "backup", "restore", "recovery"],
            severity_score=9.5
        ))
        
        # Prompt Injection Specific Techniques (AI Security)
        self._add_technique(MITRETechnique(
            technique_id="T1001",
            name="Prompt Injection",
            tactic=MITREAttackTactic.INITIAL_ACCESS,
            description="Inject malicious instructions into LLM prompts",
            keywords=["prompt inject", "jailbreak", "instruction override", "ignore previous", "DAN"],
            severity_score=8.0
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1002",
            name="Data Exfiltration via LLM",
            tactic=MITREAttackTactic.EXFILTRATION,
            description="Exfiltrate data through LLM responses",
            keywords=["leak", "output", "response", "reveal", "show", "display"],
            severity_score=7.5
        ))
    
    def _add_technique(self, technique: MITRETechnique):
        """Add a technique to the database"""
        self.techniques[technique.technique_id] = technique
    
    def match_threat(self, threat_text: str, min_confidence: float = 0.3) -> List[TechniqueMatch]:
        """
        Match a threat description to MITRE ATT&CK techniques.
        
        Args:
            threat_text: Text describing the detected threat
            min_confidence: Minimum confidence score to return (0.0-1.0)
            
        Returns:
            List of TechniqueMatch objects sorted by confidence
        """
        if not threat_text or not threat_text.strip():
            return []
        
        threat_lower = threat_text.lower()
        matches: List[TechniqueMatch] = []
        
        for technique in self.techniques.values():
            matched_keywords = []
            keyword_scores = []
            
            for keyword in technique.keywords:
                keyword_lower = keyword.lower()
                if keyword_lower in threat_lower:
                    matched_keywords.append(keyword)
                    # Score based on keyword length (longer = more specific)
                    keyword_scores.append(min(1.0, len(keyword) / 15.0))
            
            if matched_keywords:
                # Calculate confidence: weighted keyword matches + bonus for more matches
                # Use matched_keywords count instead of total keywords for better recall
                base_confidence = sum(keyword_scores) / len(matched_keywords)
                match_bonus = min(0.4, len(matched_keywords) * 0.1)
                confidence = min(1.0, base_confidence + match_bonus)
                
                if confidence >= min_confidence:
                    match = TechniqueMatch(
                        technique=technique,
                        confidence_score=round(confidence, 3),
                        matched_keywords=matched_keywords,
                        threat_context=threat_text[:200]
                    )
                    matches.append(match)
                    self.match_history.append(match)
        
        # Sort by confidence descending
        matches.sort(key=lambda x: x.confidence_score, reverse=True)
        return matches
    
    def get_technique_by_id(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get technique details by ID"""
        return self.techniques.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: MITREAttackTactic) -> List[MITRETechnique]:
        """Get all techniques for a specific tactic"""
        return [t for t in self.techniques.values() if t.tactic == tactic]
    
    def get_match_summary(self) -> Dict[str, Any]:
        """Get summary of matching history"""
        if not self.match_history:
            return {"total_matches": 0, "tactic_distribution": {}}
        
        tactic_counts: Dict[str, int] = {}
        for match in self.match_history:
            tactic_name = match.technique.tactic.value
            tactic_counts[tactic_name] = tactic_counts.get(tactic_name, 0) + 1
        
        return {
            "total_matches": len(self.match_history),
            "unique_techniques_matched": len(set(m.technique.technique_id for m in self.match_history)),
            "tactic_distribution": dict(sorted(tactic_counts.items(), key=lambda x: x[1], reverse=True)),
            "average_confidence": round(sum(m.confidence_score for m in self.match_history) / len(self.match_history), 3)
        }
    
    def generate_threat_report(self, threat_text: str) -> Dict[str, Any]:
        """Generate a comprehensive threat analysis report"""
        matches = self.match_threat(threat_text)
        
        if not matches:
            return {
                "threat_analyzed": threat_text[:200],
                "techniques_matched": [],
                "overall_severity": 0,
                "primary_tactic": "Unknown",
                "recommendations": ["Insufficient information to classify threat"]
            }
        
        # Calculate overall severity (weighted by confidence)
        total_weight = sum(m.confidence_score for m in matches)
        weighted_severity = sum(
            m.technique.severity_score * m.confidence_score 
            for m in matches
        ) / total_weight if total_weight > 0 else 0
        
        # Find primary tactic
        tactic_scores: Dict[str, float] = {}
        for m in matches:
            tactic = m.technique.tactic.value
            tactic_scores[tactic] = tactic_scores.get(tactic, 0) + m.confidence_score
        
        primary_tactic = max(tactic_scores.items(), key=lambda x: x[1])[0] if tactic_scores else "Unknown"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(matches)
        
        return {
            "threat_analyzed": threat_text[:200],
            "techniques_matched": [
                {
                    "id": m.technique.technique_id,
                    "name": m.technique.name,
                    "tactic": m.technique.tactic.value,
                    "confidence": m.confidence_score,
                    "severity": m.technique.severity_score,
                    "matched_keywords": m.matched_keywords
                }
                for m in matches[:5]
            ],
            "overall_severity": round(weighted_severity, 2),
            "primary_tactic": primary_tactic,
            "tactic_distribution": tactic_scores,
            "recommendations": recommendations
        }
    
    def _generate_recommendations(self, matches: List[TechniqueMatch]) -> List[str]:
        """Generate security recommendations based on matched techniques"""
        recommendations = []
        tactics_seen = set()
        
        for match in matches[:3]:
            tactic = match.technique.tactic
            if tactic not in tactics_seen:
                tactics_seen.add(tactic)
                
                if tactic == MITREAttackTactic.INITIAL_ACCESS:
                    recommendations.append("Review email filtering and web application firewall rules")
                elif tactic == MITREAttackTactic.EXECUTION:
                    recommendations.append("Enable application whitelisting and script block logging")
                elif tactic == MITREAttackTactic.PERSISTENCE:
                    recommendations.append("Monitor registry run keys and startup folders for anomalies")
                elif tactic == MITREAttackTactic.PRIVILEGE_ESCALATION:
                    recommendations.append("Review UAC settings and administrator group membership")
                elif tactic == MITREAttackTactic.DEFENSE_EVASION:
                    recommendations.append("Verify EDR/AV integrity and enable tamper protection")
                elif tactic == MITREAttackTactic.CREDENTIAL_ACCESS:
                    recommendations.append("Enable LSA protection and monitor credential dumping attempts")
                elif tactic == MITREAttackTactic.LATERAL_MOVEMENT:
                    recommendations.append("Restrict SMB/RDP access and implement network segmentation")
                elif tactic == MITREAttackTactic.EXFILTRATION:
                    recommendations.append("Implement DLP controls and monitor unusual data transfers")
                elif tactic == MITREAttackTactic.COMMAND_AND_CONTROL:
                    recommendations.append("Review DNS queries and outbound connection patterns")
                elif tactic == MITREAttackTactic.IMPACT:
                    recommendations.append("Ensure offline backups exist and test recovery procedures")
        
        return recommendations


# Singleton instance for easy import
_mitre_matcher_instance: Optional[MITREAttackTechniqueMatcher] = None


def get_mitre_matcher() -> MITREAttackTechniqueMatcher:
    """Get or create the singleton MITRE matcher instance"""
    global _mitre_matcher_instance
    if _mitre_matcher_instance is None:
        _mitre_matcher_instance = MITREAttackTechniqueMatcher()
    return _mitre_matcher_instance


def match_threat_to_mitre(threat_text: str) -> Dict[str, Any]:
    """Convenience function to match threat and get report"""
    matcher = get_mitre_matcher()
    return matcher.generate_threat_report(threat_text)


__all__ = [
    "MITREAttackTechniqueMatcher",
    "MITREAttackTactic",
    "MITRETechnique",
    "TechniqueMatch",
    "get_mitre_matcher",
    "match_threat_to_mitre"
]
