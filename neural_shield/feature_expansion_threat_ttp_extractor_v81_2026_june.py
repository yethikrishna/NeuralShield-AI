"""
NeuralShield Feature Expansion v81: Threat Intelligence TTP Extractor
DIMENSION A - Feature Expansion
ADD-ONLY implementation - no existing code modified

Automatically extracts MITRE ATT&CK Tactics, Techniques, and Procedures (TTPs)
from threat reports, security alerts, and raw log data using pattern matching
and heuristic analysis.
"""
import re
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict


class MITRETactic(str, Enum):
    """MITRE ATT&CK Tactics enumeration."""
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


class MITRETechnique(str, Enum):
    """Common MITRE ATT&CK Techniques with IDs."""
    T1059 = "T1059"  # Command and Scripting Interpreter
    T1053 = "T1053"  # Scheduled Task/Job
    T1027 = "T1027"  # Obfuscated Files or Information
    T1003 = "T1003"  # OS Credential Dumping
    T1055 = "T1055"  # Process Injection
    T1071 = "T1071"  # Application Layer Protocol
    T1046 = "T1046"  # Network Service Scanning
    T1082 = "T1082"  # System Information Discovery
    T1083 = "T1083"  # File and Directory Discovery
    T1090 = "T1090"  # Proxy
    T1041 = "T1041"  # Exfiltration Over C2 Channel
    T1486 = "T1486"  # Data Encrypted for Impact
    T1566 = "T1566"  # Phishing
    T1562 = "T1562"  # Impair Defenses
    T1547 = "T1547"  # Boot or Logon Autostart Execution
    T1548 = "T1548"  # Abuse Elevation Control Mechanism
    T1555 = "T1555"  # Credentials from Password Stores
    T1558 = "T1558"  # Steal or Forge Kerberos Tickets
    T1569 = "T1569"  # System Services
    T1574 = "T1574"  # Hijack Execution Flow


@dataclass
class ExtractedTTP:
    """Container for extracted TTP with confidence scoring."""
    technique_id: str
    technique_name: str
    tactic: MITRETactic
    confidence: float  # 0.0 - 1.0
    matched_pattern: str
    source_context: str
    occurrence_count: int = 1


@dataclass
class TTPExtractionResult:
    """Result container for TTP extraction analysis."""
    input_id: str
    total_techniques_found: int
    unique_techniques: List[ExtractedTTP]
    tactics_distribution: Dict[str, int]
    extraction_summary: str
    processing_time_ms: float
    confidence_score: float


class TTPPatternMatcher:
    """Pattern definitions for TTP extraction."""
    
    # Technique patterns: regex patterns -> (technique_id, technique_name, tactic)
    TECHNIQUE_PATTERNS: List[Tuple[str, str, str, MITRETactic]] = [
        # Execution (T1059)
        (r'(?i)powershell\.exe|powershell|invoke-|iex |iwr |irm ', 'T1059', 'Command and Scripting Interpreter', MITRETactic.EXECUTION),
        (r'(?i)cmd\.exe|cmd /c|cmd /k', 'T1059', 'Command and Scripting Interpreter', MITRETactic.EXECUTION),
        (r'(?i)python |python3 |perl |ruby |bash |sh ', 'T1059', 'Command and Scripting Interpreter', MITRETactic.EXECUTION),
        (r'(?i)wscript\.exe|cscript\.exe|cscript |wscript ', 'T1059', 'Command and Scripting Interpreter', MITRETactic.EXECUTION),
        
        # Persistence (T1053)
        (r'(?i)schtasks|at |crontab|cron job|scheduled task', 'T1053', 'Scheduled Task/Job', MITRETactic.PERSISTENCE),
        (r'(?i)reg add.*CurrentVersion\\\\Run|runonce|startup', 'T1547', 'Boot or Logon Autostart Execution', MITRETactic.PERSISTENCE),
        (r'(?i)service create|sc create|systemctl enable', 'T1569', 'System Services', MITRETactic.PERSISTENCE),
        
        # Defense Evasion (T1027)
        (r'(?i)base64|b64|decode|encod|obfuscat', 'T1027', 'Obfuscated Files or Information', MITRETactic.DEFENSE_EVASION),
        (r'(?i)xor |encrypt|aes|rc4|rot13', 'T1027', 'Obfuscated Files or Information', MITRETactic.DEFENSE_EVASION),
        (r'(?i)disable.*defender|disable.*antivirus|stop.*service.*defend', 'T1562', 'Impair Defenses', MITRETactic.DEFENSE_EVASION),
        (r'(?i)add.*exclusion|exclusion path|whitelist', 'T1562', 'Impair Defenses', MITRETactic.DEFENSE_EVASION),
        
        # Credential Access (T1003)
        (r'(?i)mimikatz|sekurlsa|lsadump|dcsync', 'T1003', 'OS Credential Dumping', MITRETactic.CREDENTIAL_ACCESS),
        (r'(?i)pwdump|hashdump|sam dump|lsass dump', 'T1003', 'OS Credential Dumping', MITRETactic.CREDENTIAL_ACCESS),
        (r'(?i)kerberos|golden ticket|silver ticket|krbtgt', 'T1558', 'Steal or Forge Kerberos Tickets', MITRETactic.CREDENTIAL_ACCESS),
        (r'(?i)keychain|credential manager|vaultcred', 'T1555', 'Credentials from Password Stores', MITRETactic.CREDENTIAL_ACCESS),
        
        # Privilege Escalation
        (r'(?i)uac bypass|runas |sudo |elevate|token.*privilege', 'T1548', 'Abuse Elevation Control Mechanism', MITRETactic.PRIVILEGE_ESCALATION),
        (r'(?i)dll hijack|dll side-loading|path hijack', 'T1574', 'Hijack Execution Flow', MITRETactic.PRIVILEGE_ESCALATION),
        
        # Discovery
        (r'(?i)whoami|hostname|ipconfig|ifconfig|netstat', 'T1082', 'System Information Discovery', MITRETactic.DISCOVERY),
        (r'(?i)dir |ls |get-childitem|list.*files', 'T1083', 'File and Directory Discovery', MITRETactic.DISCOVERY),
        (r'(?i)nmap|port scan|portscan|network scan', 'T1046', 'Network Service Scanning', MITRETactic.DISCOVERY),
        (r'(?i)net user|net group|net localgroup', 'T1087', 'Account Discovery', MITRETactic.DISCOVERY),
        
        # Lateral Movement
        (r'(?i)psexec|wmi |winrs|smbexec|dcom', 'T1021', 'Remote Services', MITRETactic.LATERAL_MOVEMENT),
        (r'(?i)pass the hash|pass-the-hash|overpass the hash', 'T1550', 'Use Alternate Authentication Material', MITRETactic.LATERAL_MOVEMENT),
        
        # C2
        (r'(?i)socks|proxy|reverse shell|bind shell', 'T1090', 'Proxy', MITRETactic.COMMAND_AND_CONTROL),
        (r'(?i)http.*c2|https.*c2|dns tunnel|icmp tunnel', 'T1071', 'Application Layer Protocol', MITRETactic.COMMAND_AND_CONTROL),
        (r'(?i)useragent|user-agent|curl |wget ', 'T1071', 'Application Layer Protocol', MITRETactic.COMMAND_AND_CONTROL),
        
        # Exfiltration
        (r'(?i)upload|ftp |sftp |scp |exfiltr', 'T1041', 'Exfiltration Over C2 Channel', MITRETactic.EXFILTRATION),
        (r'(?i)data.*leak|send.*data|post.*data', 'T1041', 'Exfiltration Over C2 Channel', MITRETactic.EXFILTRATION),
        
        # Impact
        (r'(?i)ransom|encrypt.*file|bitcoin|wallet address', 'T1486', 'Data Encrypted for Impact', MITRETactic.IMPACT),
        (r'(?i)wipe|delete.*backup|format |diskpart', 'T1485', 'Data Destruction', MITRETactic.IMPACT),
        
        # Initial Access
        (r'(?i)phish|spearphish|malicious.*attach|macro.*doc', 'T1566', 'Phishing', MITRETactic.INITIAL_ACCESS),
        (r'(?i)exploit|cve-|vulnerab|remote code', 'T1203', 'Exploitation for Client Execution', MITRETactic.INITIAL_ACCESS),
    ]
    
    # High confidence indicators that boost scores
    HIGH_CONFIDENCE_INDICATORS = [
        r'(?i)mimikatz',
        r'(?i)cobalt\s*strike|beacon',
        r'(?i)metasploit|meterpreter',
        r'(?i)empire.*agent',
        r'(?i)bloodhound|sharphound',
    ]


class ThreatTTPExtractor:
    """
    Main TTP extraction engine.
    Extracts MITRE ATT&CK TTPs from threat intelligence data.
    ADD-ONLY implementation - wraps existing threat intel modules.
    """
    
    def __init__(self, min_confidence: float = 0.3, case_sensitive: bool = False):
        self.min_confidence = min_confidence
        self.case_sensitive = case_sensitive
        self._pattern_cache: Dict[str, re.Pattern] = {}
        self._stats: Dict[str, Any] = defaultdict(int)
        self._compile_patterns()
    
    def _compile_patterns(self) -> None:
        """Pre-compile regex patterns for performance."""
        for pattern, _, _, _ in TTPPatternMatcher.TECHNIQUE_PATTERNS:
            flags = 0 if self.case_sensitive else re.IGNORECASE
            self._pattern_cache[pattern] = re.compile(pattern, flags)
    
    def extract_from_text(self, text: str, source_context: str = "unknown") -> TTPExtractionResult:
        """
        Extract TTPs from raw text content.
        
        Args:
            text: Raw text to analyze (threat report, alert, log, etc.)
            source_context: Source identifier for tracking
            
        Returns:
            TTPExtractionResult with all extracted techniques
        """
        import time
        start_time = time.time()
        
        matches: Dict[str, ExtractedTTP] = {}
        tactics_count: Dict[str, int] = defaultdict(int)
        
        # Check each pattern
        for pattern, tech_id, tech_name, tactic in TTPPatternMatcher.TECHNIQUE_PATTERNS:
            compiled = self._pattern_cache[pattern]
            found_matches = list(compiled.finditer(text))
            
            if found_matches:
                # Calculate confidence based on number of matches and pattern strength
                base_confidence = min(0.3 + (len(found_matches) * 0.1), 0.9)
                
                # Boost confidence for high-value indicators
                for indicator in TTPPatternMatcher.HIGH_CONFIDENCE_INDICATORS:
                    if re.search(indicator, text, re.IGNORECASE):
                        base_confidence = min(base_confidence + 0.2, 1.0)
                        break
                
                if base_confidence >= self.min_confidence:
                    key = f"{tech_id}_{tactic.value}"
                    context_snippet = self._get_context_snippet(text, found_matches[0].start())
                    
                    if key in matches:
                        matches[key].occurrence_count += len(found_matches)
                        matches[key].confidence = max(matches[key].confidence, base_confidence)
                    else:
                        matches[key] = ExtractedTTP(
                            technique_id=tech_id,
                            technique_name=tech_name,
                            tactic=tactic,
                            confidence=round(base_confidence, 3),
                            matched_pattern=pattern,
                            source_context=context_snippet,
                            occurrence_count=len(found_matches)
                        )
                    
                    tactics_count[tactic.value] += len(found_matches)
                    self._stats[f"extracted_{tech_id}"] += len(found_matches)
        
        # Sort by confidence
        sorted_techniques = sorted(
            matches.values(),
            key=lambda x: x.confidence,
            reverse=True
        )
        
        # Generate input ID
        input_id = hashlib.md5(text.encode('utf-8')).hexdigest()[:12]
        
        # Calculate overall confidence
        overall_confidence = 0.0
        if sorted_techniques:
            overall_confidence = sum(t.confidence for t in sorted_techniques) / len(sorted_techniques)
        
        processing_time = (time.time() - start_time) * 1000
        
        # Generate summary
        summary = self._generate_summary(sorted_techniques, tactics_count)
        
        self._stats["total_extractions"] += 1
        
        return TTPExtractionResult(
            input_id=input_id,
            total_techniques_found=sum(t.occurrence_count for t in sorted_techniques),
            unique_techniques=sorted_techniques,
            tactics_distribution=dict(tactics_count),
            extraction_summary=summary,
            processing_time_ms=round(processing_time, 2),
            confidence_score=round(overall_confidence, 3)
        )
    
    def _get_context_snippet(self, text: str, position: int, window: int = 50) -> str:
        """Extract context window around match position."""
        start = max(0, position - window)
        end = min(len(text), position + window)
        snippet = text[start:end].strip()
        return snippet.replace('\n', ' ')[:150]
    
    def _generate_summary(self, techniques: List[ExtractedTTP], tactics: Dict[str, int]) -> str:
        """Generate human-readable summary."""
        if not techniques:
            return "No TTPs detected in input."
        
        top_techniques = techniques[:3]
        top_tactics = sorted(tactics.items(), key=lambda x: x[1], reverse=True)[:3]
        
        summary_parts = []
        summary_parts.append(f"Detected {len(techniques)} unique MITRE ATT&CK techniques")
        
        if top_techniques:
            names = [f"{t.technique_id} ({t.technique_name})" for t in top_techniques]
            summary_parts.append(f"Top techniques: {', '.join(names)}")
        
        if top_tactics:
            tactic_names = [f"{t[0]} ({t[1]} matches)" for t in top_tactics]
            summary_parts.append(f"Primary tactics: {', '.join(tactic_names)}")
        
        return ". ".join(summary_parts) + "."
    
    def extract_from_logs(self, logs: List[str]) -> TTPExtractionResult:
        """Extract TTPs from a list of log entries."""
        combined = "\n".join(logs)
        return self.extract_from_text(combined, source_context="log_batch")
    
    def batch_extract(self, documents: List[Tuple[str, str]]) -> List[TTPExtractionResult]:
        """Process multiple documents in batch."""
        results = []
        for text, context in documents:
            results.append(self.extract_from_text(text, source_context=context))
        return results
    
    def get_extraction_stats(self) -> Dict[str, Any]:
        """Get extraction statistics."""
        return {
            "total_documents_processed": self._stats["total_extractions"],
            "technique_distribution": {
                k: v for k, v in self._stats.items()
                if k.startswith("extracted_")
            },
            "min_confidence_threshold": self.min_confidence,
        }
    
    def get_mitre_mapping(self) -> Dict[str, List[str]]:
        """Get technique -> tactic mapping."""
        mapping: Dict[str, List[str]] = defaultdict(list)
        for _, tech_id, _, tactic in TTPPatternMatcher.TECHNIQUE_PATTERNS:
            if tactic.value not in mapping[tech_id]:
                mapping[tech_id].append(tactic.value)
        return dict(mapping)


# Convenience functions
def extract_ttps(text: str, min_confidence: float = 0.3) -> TTPExtractionResult:
    """Convenience function for quick TTP extraction."""
    extractor = ThreatTTPExtractor(min_confidence=min_confidence)
    return extractor.extract_from_text(text)


def get_supported_techniques() -> List[Dict[str, str]]:
    """Get list of all supported MITRE techniques."""
    seen = set()
    techniques = []
    for _, tech_id, tech_name, tactic in TTPPatternMatcher.TECHNIQUE_PATTERNS:
        key = (tech_id, tactic.value)
        if key not in seen:
            seen.add(key)
            techniques.append({
                "id": tech_id,
                "name": tech_name,
                "tactic": tactic.value
            })
    return techniques


# API Stability markers
__all__ = [
    'MITRETactic',
    'MITRETechnique',
    'ExtractedTTP',
    'TTPExtractionResult',
    'ThreatTTPExtractor',
    'extract_ttps',
    'get_supported_techniques',
]

__api_stability__ = {
    'MITRETactic': 'STABLE',
    'MITRETechnique': 'STABLE',
    'ExtractedTTP': 'STABLE',
    'TTPExtractionResult': 'STABLE',
    'ThreatTTPExtractor': 'STABLE',
    'extract_ttps': 'STABLE',
    'get_supported_techniques': 'STABLE',
}

__version__ = '1.0.0'
__dimension__ = 'A'
__description__ = 'Feature Expansion - Threat Intelligence TTP Extractor v81'
