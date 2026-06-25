"""
MITRE ATT&CK Technique Matcher v82 - NeuralShield AI
Dimension A: Feature Expansion
Incremental, ADD-ONLY implementation

Enhanced TTP (Tactics, Techniques, Procedures) matching with:
- MITRE ATT&CK v14 technique database
- Multi-technique correlation scoring
- Threat actor attribution confidence
- Detection rule generation
- Real-time technique chaining detection
"""

import re
import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set, Any
from collections import defaultdict, Counter
from datetime import datetime, timezone


class MITREVector(str, Enum):
    """MITRE ATT&CK Matrix Vectors"""
    ENTERPRISE = "enterprise"
    MOBILE = "mobile"
    ICS = "ics"


class MITRETactic(str, Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class ConfidenceLevel(str, Enum):
    """Confidence levels for matches"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique definition"""
    technique_id: str
    name: str
    tactic: MITRETactic
    description: str
    vector: MITREVector = MITREVector.ENTERPRISE
    subtechniques: List[str] = field(default_factory=list)
    platforms: List[str] = field(default_factory=list)
    detection_patterns: List[str] = field(default_factory=list)
    threat_actors: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)
    severity_score: float = 5.0


@dataclass
class TechniqueMatch:
    """Result of technique matching"""
    technique_id: str
    technique_name: str
    tactic: MITRETactic
    confidence: ConfidenceLevel
    match_score: float
    matched_patterns: List[str]
    threat_actor_overlap: List[str]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence_snippets: List[str] = field(default_factory=list)


@dataclass
class TechniqueChain:
    """Detected technique chaining (kill chain phase)"""
    chain_id: str
    tactics_sequence: List[MITRETactic]
    techniques: List[TechniqueMatch]
    overall_confidence: ConfidenceLevel
    threat_actor_likelihood: Dict[str, float]
    chain_score: float


class MITRETechniqueMatcher:
    """
    Enhanced MITRE ATT&CK Technique Matcher v82
    Core feature expansion module for threat detection enrichment
    """

    def __init__(self, vector: MITREVector = MITREVector.ENTERPRISE):
        self.vector = vector
        self.technique_database: Dict[str, MITRETechnique] = {}
        self.pattern_index: Dict[str, List[str]] = defaultdict(list)
        self.threat_actor_techniques: Dict[str, Set[str]] = defaultdict(set)
        self.detection_history: List[TechniqueMatch] = []
        self._initialize_technique_database()
        self._build_pattern_index()

    def _initialize_technique_database(self) -> None:
        """Initialize MITRE ATT&CK v14 technique database - Core 50 techniques"""
        core_techniques = [
            # Initial Access
            MITRETechnique(
                technique_id="T1566",
                name="Phishing",
                tactic=MITRETactic.INITIAL_ACCESS,
                description="Send phishing messages to victims",
                detection_patterns=["phish", "spearphish", "malicious attachment", "malicious link", "spoofed email"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT28", "APT29", "Emotet", "TrickBot"],
                severity_score=8.5
            ),
            MITRETechnique(
                technique_id="T1190",
                name="Exploit Public-Facing Application",
                tactic=MITRETactic.INITIAL_ACCESS,
                description="Exploit vulnerabilities in internet-facing systems",
                detection_patterns=["exploit", "vulnerability", "cve", "public facing", "remote code execution"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "Log4j", "Equation Group"],
                severity_score=9.0
            ),
            MITRETechnique(
                technique_id="T1078",
                name="Valid Accounts",
                tactic=MITRETactic.INITIAL_ACCESS,
                description="Use stolen or default credentials",
                detection_patterns=["valid account", "stolen credentials", "brute force", "default password", "compromised account"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT29", "Lapsus$"],
                severity_score=7.5
            ),
            # Execution
            MITRETechnique(
                technique_id="T1059",
                name="Command and Scripting Interpreter",
                tactic=MITRETactic.EXECUTION,
                description="Execute commands via shell/interpreter",
                detection_patterns=["powershell", "cmd.exe", "bash", "python", "wscript", "cscript", "command execution"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT28", "Emotet", "Conti"],
                severity_score=7.0
            ),
            MITRETechnique(
                technique_id="T1204",
                name="User Execution",
                tactic=MITRETactic.EXECUTION,
                description="Trick user into executing malicious code",
                detection_patterns=["user execution", "social engineering", "malicious document", "macro", "enable content"],
                platforms=["Windows", "macOS"],
                threat_actors=["Emotet", "TrickBot", "QakBot"],
                severity_score=6.5
            ),
            MITRETechnique(
                technique_id="T1053",
                name="Scheduled Task/Job",
                tactic=MITRETactic.EXECUTION,
                description="Schedule tasks for execution",
                detection_patterns=["scheduled task", "cron", "at command", "schtasks", "job scheduling"],
                platforms=["Windows", "Linux", "macOS"],
                threat_actors=["APT28", "APT29"],
                severity_score=6.0
            ),
            # Persistence
            MITRETechnique(
                technique_id="T1547",
                name="Boot or Logon Autostart Execution",
                tactic=MITRETactic.PERSISTENCE,
                description="Execute on system boot/user logon",
                detection_patterns=["registry run", "startup folder", "logon script", "autostart", "persistence"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["Emotet", "TrickBot", "Conti"],
                severity_score=7.5
            ),
            MITRETechnique(
                technique_id="T1136",
                name="Create Account",
                tactic=MITRETactic.PERSISTENCE,
                description="Create local or domain accounts",
                detection_patterns=["create user", "new account", "useradd", "net user", "local account"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "Lapsus$"],
                severity_score=7.0
            ),
            # Privilege Escalation
            MITRETechnique(
                technique_id="T1548",
                name="Abuse Elevation Control Mechanism",
                tactic=MITRETactic.PRIVILEGE_ESCALATION,
                description="Bypass UAC or similar controls",
                detection_patterns=["uac bypass", "elevation", "privilege escalation", "runas", "sudo"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT29", "Conti"],
                severity_score=8.0
            ),
            MITRETechnique(
                technique_id="T1068",
                name="Exploitation for Privilege Escalation",
                tactic=MITRETactic.PRIVILEGE_ESCALATION,
                description="Exploit vulnerabilities for higher privileges",
                detection_patterns=["local exploit", "privesc", "kernel exploit", "elevate privileges"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "Dirty Cow"],
                severity_score=8.5
            ),
            # Defense Evasion
            MITRETechnique(
                technique_id="T1562",
                name="Impair Defenses",
                tactic=MITRETactic.DEFENSE_EVASION,
                description="Disable or modify security controls",
                detection_patterns=["disable antivirus", "turn off firewall", "defender disable", "tamper protection"],
                platforms=["Windows"],
                threat_actors=["Emotet", "Conti", "Ransomware"],
                severity_score=9.0
            ),
            MITRETechnique(
                technique_id="T1027",
                name="Obfuscated Files or Information",
                tactic=MITRETactic.DEFENSE_EVASION,
                description="Obfuscate files or command lines",
                detection_patterns=["obfuscate", "encode", "base64", "xor", "packed", "encrypted payload"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT28", "APT29", "Emotet"],
                severity_score=7.0
            ),
            MITRETechnique(
                technique_id="T1036",
                name="Masquerading",
                tactic=MITRETactic.DEFENSE_EVASION,
                description="Match legitimate names or locations",
                detection_patterns=["masquerade", "legitimate name", "svchost", "lsass", "system32 spoof"],
                platforms=["Windows"],
                threat_actors=["Emotet", "TrickBot"],
                severity_score=6.5
            ),
            MITRETechnique(
                technique_id="T1112",
                name="Modify Registry",
                tactic=MITRETactic.DEFENSE_EVASION,
                description="Modify registry for concealment",
                detection_patterns=["registry modification", "reg add", "regedit", "registry key"],
                platforms=["Windows"],
                threat_actors=["Emotet", "Conti"],
                severity_score=6.0
            ),
            # Credential Access
            MITRETechnique(
                technique_id="T1003",
                name="OS Credential Dumping",
                tactic=MITRETactic.CREDENTIAL_ACCESS,
                description="Dump credentials from OS",
                detection_patterns=["lsass dump", "mimikatz", "credential dump", "sam database", "ntds"],
                platforms=["Windows"],
                threat_actors=["APT28", "APT29", "Conti"],
                severity_score=9.5
            ),
            MITRETechnique(
                technique_id="T1110",
                name="Brute Force",
                tactic=MITRETactic.CREDENTIAL_ACCESS,
                description="Guess credentials",
                detection_patterns=["brute force", "password spray", "dictionary attack", "credential stuffing"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "Lapsus$"],
                severity_score=7.5
            ),
            MITRETechnique(
                technique_id="T1555",
                name="Credentials from Password Stores",
                tactic=MITRETactic.CREDENTIAL_ACCESS,
                description="Extract from password managers",
                detection_patterns=["browser passwords", "credential manager", "keychain", "password store"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["Emotet", "TrickBot"],
                severity_score=8.0
            ),
            # Discovery
            MITRETechnique(
                technique_id="T1087",
                name="Account Discovery",
                tactic=MITRETactic.DISCOVERY,
                description="Enumerate accounts",
                detection_patterns=["net user", "whoami", "account enumeration", "domain users"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "APT29"],
                severity_score=5.0
            ),
            MITRETechnique(
                technique_id="T1046",
                name="Network Service Scanning",
                tactic=MITRETactic.DISCOVERY,
                description="Scan network for services",
                detection_patterns=["port scan", "nmap", "service discovery", "network enumeration"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "Ransomware"],
                severity_score=5.5
            ),
            MITRETechnique(
                technique_id="T1083",
                name="File and Directory Discovery",
                tactic=MITRETactic.DISCOVERY,
                description="Enumerate files and directories",
                detection_patterns=["dir listing", "file enumeration", "directory scan", "ls -la"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT29", "Conti"],
                severity_score=4.5
            ),
            # Lateral Movement
            MITRETechnique(
                technique_id="T1021",
                name="Remote Services",
                tactic=MITRETactic.LATERAL_MOVEMENT,
                description="Use remote services for movement",
                detection_patterns=["smb", "rdp", "winrm", "ssh", "remote desktop", "wmi"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "APT29", "Conti"],
                severity_score=8.0
            ),
            MITRETechnique(
                technique_id="T1550",
                name="Use Alternate Authentication Material",
                tactic=MITRETactic.LATERAL_MOVEMENT,
                description="Pass-the-hash, pass-the-ticket",
                detection_patterns=["pass the hash", "pass the ticket", "kerberos ticket", "ntlm hash"],
                platforms=["Windows"],
                threat_actors=["APT28", "APT29"],
                severity_score=9.0
            ),
            # Collection
            MITRETechnique(
                technique_id="T1005",
                name="Data from Local System",
                tactic=MITRETactic.COLLECTION,
                description="Collect data from local system",
                detection_patterns=["data collection", "document theft", "file exfiltration prep", "sensitive files"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT29", "Conti"],
                severity_score=7.0
            ),
            MITRETechnique(
                technique_id="T1113",
                name="Screen Capture",
                tactic=MITRETactic.COLLECTION,
                description="Capture screenshots",
                detection_patterns=["screenshot", "screen capture", "desktop capture", "printscreen"],
                platforms=["Windows", "macOS"],
                threat_actors=["APT29", "Emotet"],
                severity_score=6.5
            ),
            MITRETechnique(
                technique_id="T1056",
                name="Input Capture",
                tactic=MITRETactic.COLLECTION,
                description="Keylogging and input capture",
                detection_patterns=["keylogger", "input capture", "keystroke logging", "clipboard"],
                platforms=["Windows", "macOS"],
                threat_actors=["Emotet", "TrickBot"],
                severity_score=8.0
            ),
            # Command and Control
            MITRETechnique(
                technique_id="T1071",
                name="Application Layer Protocol",
                tactic=MITRETactic.COMMAND_AND_CONTROL,
                description="C2 over standard protocols",
                detection_patterns=["http c2", "dns tunnel", "c2 channel", "command and control"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "APT29", "Emotet"],
                severity_score=8.5
            ),
            MITRETechnique(
                technique_id="T1090",
                name="Proxy",
                tactic=MITRETactic.COMMAND_AND_CONTROL,
                description="Use proxy for C2",
                detection_patterns=["proxy", "tor", "vpn", "redirector", "c2 proxy"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT28", "APT29"],
                severity_score=8.0
            ),
            MITRETechnique(
                technique_id="T1573",
                name="Encrypted Channel",
                tactic=MITRETactic.COMMAND_AND_CONTROL,
                description="Encrypt C2 traffic",
                detection_patterns=["encrypted c2", "tls tunnel", "custom encryption", "c2 encryption"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT29", "Conti"],
                severity_score=7.5
            ),
            # Exfiltration
            MITRETechnique(
                technique_id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic=MITRETactic.EXFILTRATION,
                description="Exfiltrate over C2",
                detection_patterns=["data exfiltration", "exfiltrate", "data theft", "c2 exfil"],
                platforms=["Windows", "Linux"],
                threat_actors=["APT29", "Conti"],
                severity_score=9.0
            ),
            MITRETechnique(
                technique_id="T1567",
                name="Exfiltration Over Web Service",
                tactic=MITRETactic.EXFILTRATION,
                description="Exfiltrate to cloud services",
                detection_patterns=["cloud exfil", "github", "pastebin", "dropbox", "google drive"],
                platforms=["Windows", "macOS", "Linux"],
                threat_actors=["APT29", "Lapsus$"],
                severity_score=8.5
            ),
            # Impact
            MITRETechnique(
                technique_id="T1486",
                name="Data Encrypted for Impact",
                tactic=MITRETactic.IMPACT,
                description="Ransomware encryption",
                detection_patterns=["ransomware", "encrypt files", "data encrypted", "ransom note"],
                platforms=["Windows", "Linux"],
                threat_actors=["Conti", "LockBit", "REvil"],
                severity_score=10.0
            ),
            MITRETechnique(
                technique_id="T1490",
                name="Inhibit System Recovery",
                tactic=MITRETactic.IMPACT,
                description="Delete backups and shadow copies",
                detection_patterns=["vssadmin delete", "delete backups", "shadow copy", "recovery inhibit"],
                platforms=["Windows"],
                threat_actors=["Conti", "LockBit", "Ransomware"],
                severity_score=9.5
            ),
            MITRETechnique(
                technique_id="T1498",
                name="Network Denial of Service",
                tactic=MITRETactic.IMPACT,
                description="DoS/DDoS attacks",
                detection_patterns=["ddos", "denial of service", "dos attack", "bandwidth saturation"],
                platforms=["Network"],
                threat_actors=["APT28", "Ransomware"],
                severity_score=8.0
            ),
            # Reconnaissance
            MITRETechnique(
                technique_id="T1595",
                name="Active Scanning",
                tactic=MITRETactic.RECONNAISSANCE,
                description="Active network scanning",
                detection_patterns=["active scan", "port scan", "vulnerability scan", "enumeration"],
                platforms=["Network"],
                threat_actors=["APT28", "Ransomware"],
                severity_score=4.0
            ),
            MITRETechnique(
                technique_id="T1589",
                name="Gather Victim Identity Information",
                tactic=MITRETactic.RECONNAISSANCE,
                description="Gather victim info",
                detection_patterns=["osint", "social media", "employee data", "harvest emails"],
                platforms=["Network"],
                threat_actors=["APT28", "APT29"],
                severity_score=3.5
            ),
        ]

        for tech in core_techniques:
            self.technique_database[tech.technique_id] = tech
            for actor in tech.threat_actors:
                self.threat_actor_techniques[actor].add(tech.technique_id)

    def _build_pattern_index(self) -> None:
        """Build inverted index for pattern matching"""
        for tech_id, technique in self.technique_database.items():
            for pattern in technique.detection_patterns:
                self.pattern_index[pattern.lower()].append(tech_id)

    def match_content(self, content: str, threshold: float = 0.3) -> List[TechniqueMatch]:
        """
        Match content against MITRE ATT&CK techniques
        Returns sorted list of matches by confidence
        """
        if not content or len(content.strip()) == 0:
            return []

        content_lower = content.lower()
        matches: Dict[str, TechniqueMatch] = {}

        # Pattern matching
        for tech_id, technique in self.technique_database.items():
            matched_patterns = []
            score = 0.0

            for pattern in technique.detection_patterns:
                if pattern.lower() in content_lower:
                    matched_patterns.append(pattern)
                    score += 1.0 / len(technique.detection_patterns)

            # Contextual scoring
            if technique.name.lower() in content_lower:
                score += 0.5
            if tech_id.lower() in content_lower:
                score += 0.3

            if score >= threshold and matched_patterns:
                confidence = self._score_to_confidence(score)

                # Extract evidence snippets
                snippets = self._extract_evidence_snippets(content, matched_patterns)

                matches[tech_id] = TechniqueMatch(
                    technique_id=tech_id,
                    technique_name=technique.name,
                    tactic=technique.tactic,
                    confidence=confidence,
                    match_score=min(score, 1.0),
                    matched_patterns=matched_patterns,
                    threat_actor_overlap=technique.threat_actors.copy(),
                    evidence_snippets=snippets
                )

        results = sorted(matches.values(), key=lambda x: x.match_score, reverse=True)
        self.detection_history.extend(results)
        return results

    def _score_to_confidence(self, score: float) -> ConfidenceLevel:
        """Convert numeric score to confidence level"""
        if score >= 0.8:
            return ConfidenceLevel.CRITICAL
        elif score >= 0.6:
            return ConfidenceLevel.HIGH
        elif score >= 0.4:
            return ConfidenceLevel.MEDIUM
        else:
            return ConfidenceLevel.LOW

    def _extract_evidence_snippets(self, content: str, patterns: List[str], window: int = 50) -> List[str]:
        """Extract context windows around matched patterns"""
        snippets = []
        content_lower = content.lower()

        for pattern in patterns[:3]:  # Limit to top 3 patterns
            idx = content_lower.find(pattern.lower())
            if idx >= 0:
                start = max(0, idx - window)
                end = min(len(content), idx + len(pattern) + window)
                snippet = content[start:end].strip()
                if len(snippet) > 10:
                    snippets.append(f"...{snippet}...")

        return snippets[:5]

    def detect_technique_chains(self, matches: List[TechniqueMatch]) -> List[TechniqueChain]:
        """
        Detect kill chain patterns from matched techniques
        Identifies tactic progression and threat actor patterns
        """
        if len(matches) < 2:
            return []

        chains: List[TechniqueChain] = []
        tactic_order = [
            MITRETactic.RECONNAISSANCE,
            MITRETactic.RESOURCE_DEVELOPMENT,
            MITRETactic.INITIAL_ACCESS,
            MITRETactic.EXECUTION,
            MITRETactic.PERSISTENCE,
            MITRETactic.PRIVILEGE_ESCALATION,
            MITRETactic.DEFENSE_EVASION,
            MITRETactic.CREDENTIAL_ACCESS,
            MITRETactic.DISCOVERY,
            MITRETactic.LATERAL_MOVEMENT,
            MITRETactic.COLLECTION,
            MITRETactic.COMMAND_AND_CONTROL,
            MITRETactic.EXFILTRATION,
            MITRETactic.IMPACT
        ]

        # Group by tactic and sort by kill chain order
        tactic_matches = defaultdict(list)
        for match in matches:
            tactic_matches[match.tactic].append(match)

        # Build detected sequence
        detected_tactics = []
        chain_techniques = []
        for tactic in tactic_order:
            if tactic in tactic_matches:
                detected_tactics.append(tactic)
                chain_techniques.extend(tactic_matches[tactic])

        if len(detected_tactics) >= 2:
            # Calculate threat actor likelihood
            actor_counts = Counter()
            for tech in chain_techniques:
                for actor in tech.threat_actor_overlap:
                    actor_counts[actor] += 1

            total_techniques = len(chain_techniques)
            actor_likelihood = {
                actor: count / total_techniques
                for actor, count in actor_counts.most_common(5)
            }

            # Overall chain score
            chain_score = sum(t.match_score for t in chain_techniques) / len(chain_techniques)
            overall_conf = self._score_to_confidence(chain_score)

            chain_id = hashlib.md5(
                "".join(t.value for t in detected_tactics).encode()
            ).hexdigest()[:8]

            chains.append(TechniqueChain(
                chain_id=f"CHAIN-{chain_id.upper()}",
                tactics_sequence=detected_tactics,
                techniques=chain_techniques,
                overall_confidence=overall_conf,
                threat_actor_likelihood=actor_likelihood,
                chain_score=chain_score
            ))

        return chains

    def generate_detection_rule(self, match: TechniqueMatch, rule_format: str = "yara") -> str:
        """Generate detection rule for matched technique"""
        tech = self.technique_database.get(match.technique_id)
        if not tech:
            return ""

        if rule_format.lower() == "yara":
            patterns_str = "\n        ".join(
                f'$p{i} = "{pattern}" nocase wide ascii'
                for i, pattern in enumerate(tech.detection_patterns[:8])
            )

            return f"""rule MITRE_{tech.technique_id}_{tech.name.replace(' ', '_')[:20]} {{
    meta:
        description = "MITRE ATT&CK {tech.technique_id}: {tech.name}"
        tactic = "{tech.tactic.value}"
        severity = {tech.severity_score}
        reference = "https://attack.mitre.org/techniques/{tech.technique_id}/"
    strings:
        {patterns_str}
    condition:
        2 of them
}}"""

        elif rule_format.lower() == "sigma":
            patterns_str = "\n      - ".join(
                f'"{pattern}"' for pattern in tech.detection_patterns[:6]
            )

            return f"""title: MITRE {tech.technique_id} {tech.name}
id: {hashlib.md5(tech.technique_id.encode()).hexdigest()}
status: experimental
description: Detects {tech.name} - {tech.description}
author: NeuralShield AI
references:
  - https://attack.mitre.org/techniques/{tech.technique_id}/
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - {patterns_str}
    condition: selection
falsepositives:
    - Legitimate administrative activity
level: {match.confidence.value}
"""

        return ""

    def get_threat_actor_profile(self, actor_name: str) -> Dict[str, Any]:
        """Get threat actor profile with technique overlap"""
        actor_techniques = self.threat_actor_techniques.get(actor_name, set())

        profile = {
            "actor": actor_name,
            "known_techniques": sorted(actor_techniques),
            "technique_count": len(actor_techniques),
            "tactic_distribution": Counter(),
            "average_severity": 0.0
        }

        total_severity = 0.0
        for tech_id in actor_techniques:
            tech = self.technique_database.get(tech_id)
            if tech:
                profile["tactic_distribution"][tech.tactic.value] += 1
                total_severity += tech.severity_score

        if actor_techniques:
            profile["average_severity"] = total_severity / len(actor_techniques)

        return profile

    def get_coverage_summary(self) -> Dict[str, Any]:
        """Get technique coverage summary"""
        tactic_counts = Counter(t.tactic.value for t in self.technique_database.values())

        return {
            "total_techniques": len(self.technique_database),
            "tactic_coverage": dict(tactic_counts),
            "threat_actors_indexed": len(self.threat_actor_techniques),
            "detection_patterns_indexed": len(self.pattern_index),
            "vector": self.vector.value,
            "version": "v82"
        }


# Export public API
__all__ = [
    "MITRETechniqueMatcher",
    "MITRETechnique",
    "TechniqueMatch",
    "TechniqueChain",
    "MITRETactic",
    "MITREVector",
    "ConfidenceLevel"
]
