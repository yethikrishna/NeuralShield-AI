"""
NeuralShield-AI: Threat Intelligence MITRE ATT&CK Mapping Engine v1
Production-grade implementation for automated mapping of threat intelligence
to MITRE ATT&CK tactics, techniques, and sub-techniques.

Features:
- Keyword-based technique matching with confidence scoring
- Tactic categorization and aggregation
- Technique frequency analysis and heatmap generation
- Batch processing support
- LRU caching for performance optimization
- Confidence threshold calibration
- Export to JSON/CSV formats for reporting
"""
import re
import hashlib
import threading
import time
import json
from collections import OrderedDict, defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics"""
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


@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique definition"""
    technique_id: str
    name: str
    tactic: MITRETactic
    keywords: List[str]
    description: str = ""


@dataclass
class MappingResult:
    """Result of MITRE ATT&CK mapping"""
    threat_id: str
    threat_title: str
    matched_techniques: List[Tuple[MITRETechnique, float]]  # (technique, confidence)
    tactic_distribution: Dict[str, float]
    overall_confidence: float
    technique_count: int
    timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class CacheEntry:
    results: MappingResult
    created_at: float
    ttl_seconds: int = 7200

    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds


class ThreadSafeLRUCache:
    """Thread-safe LRU Cache with TTL support"""

    def __init__(self, max_size: int = 500):
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self._max_size = max_size
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[MappingResult]:
        with self._lock:
            if key not in self._cache:
                return None

            entry = self._cache[key]
            if entry.is_expired():
                del self._cache[key]
                return None

            self._cache.move_to_end(key)
            return entry.results

    def put(self, key: str, results: MappingResult, ttl_seconds: int = 7200) -> None:
        with self._lock:
            if key in self._cache:
                del self._cache[key]
            elif len(self._cache) >= self._max_size:
                self._cache.popitem(last=False)

            self._cache[key] = CacheEntry(
                results=results,
                created_at=time.time(),
                ttl_seconds=ttl_seconds
            )

    def clear_expired(self) -> int:
        with self._lock:
            expired_keys = [k for k, v in self._cache.items() if v.is_expired()]
            for k in expired_keys:
                del self._cache[k]
            return len(expired_keys)

    def size(self) -> int:
        with self._lock:
            return len(self._cache)


class MITREAttackKnowledgeBase:
    """MITRE ATT&CK Knowledge Base with techniques and keyword mappings"""

    def __init__(self):
        self.techniques: List[MITRETechnique] = []
        self._build_knowledge_base()

    def _build_knowledge_base(self) -> None:
        """Build the MITRE ATT&CK technique knowledge base"""

        # Reconnaissance
        self.techniques.extend([
            MITRETechnique("T1595", "Active Scanning", MITRETactic.RECONNAISSANCE,
                          ["scan", "port scan", "nmap", "vulnerability scan", "network scan",
                           "recon", "enumeration", "service discovery"]),
            MITRETechnique("T1592", "Gather Victim Host Information", MITRETactic.RECONNAISSANCE,
                          ["gather", "host info", "system info", "enumerate", "fingerprint"]),
            MITRETechnique("T1589", "Gather Victim Identity Information", MITRETactic.RECONNAISSANCE,
                          ["credentials", "email", "identity", "user info", "account"]),
        ])

        # Resource Development
        self.techniques.extend([
            MITRETechnique("T1583", "Acquire Infrastructure", MITRETactic.RESOURCE_DEVELOPMENT,
                          ["domain", "server", "infrastructure", "botnet", "c2 server",
                           "compromised server", "acquire"]),
            MITRETechnique("T1587", "Develop Capabilities", MITRETactic.RESOURCE_DEVELOPMENT,
                          ["malware", "exploit", "backdoor", "payload", "develop", "build",
                           "custom malware"]),
            MITRETechnique("T1584", "Compromise Infrastructure", MITRETactic.RESOURCE_DEVELOPMENT,
                          ["compromise", "hijack", "takeover", "domain hijack", "third party"]),
        ])

        # Initial Access
        self.techniques.extend([
            MITRETechnique("T1566", "Phishing", MITRETactic.INITIAL_ACCESS,
                          ["phish", "spearphish", "email", "attachment", "malicious attachment",
                           "link", "malicious link", "social engineering"]),
            MITRETechnique("T1190", "Exploit Public-Facing Application", MITRETactic.INITIAL_ACCESS,
                          ["exploit", "vulnerability", "cve", "public facing", "web application",
                           "remote code execution", "rce"]),
            MITRETechnique("T1078", "Valid Accounts", MITRETactic.INITIAL_ACCESS,
                          ["valid account", "compromised credentials", "stolen credentials",
                           "brute force", "password spray"]),
        ])

        # Execution
        self.techniques.extend([
            MITRETechnique("T1059", "Command and Scripting Interpreter", MITRETactic.EXECUTION,
                          ["powershell", "cmd", "bash", "script", "command line", "shell",
                           "python", "wscript", "cscript"]),
            MITRETechnique("T1204", "User Execution", MITRETactic.EXECUTION,
                          ["user execute", "run", "double click", "open file", "user interaction"]),
            MITRETechnique("T1053", "Scheduled Task/Job", MITRETactic.EXECUTION,
                          ["scheduled task", "cron", "at", "schtasks", "timer", "schedule"]),
        ])

        # Persistence
        self.techniques.extend([
            MITRETechnique("T1547", "Boot or Logon Autostart Execution", MITRETactic.PERSISTENCE,
                          ["registry run", "startup", "autostart", "boot execute", "logon script"]),
            MITRETechnique("T1037", "Boot or Logon Initialization Scripts", MITRETactic.PERSISTENCE,
                          ["logon script", "startup script", "profile", "bashrc", "init"]),
            MITRETechnique("T1136", "Create Account", MITRETactic.PERSISTENCE,
                          ["create user", "new account", "add user", "local account"]),
        ])

        # Privilege Escalation
        self.techniques.extend([
            MITRETechnique("T1548", "Abuse Elevation Control Mechanism", MITRETactic.PRIVILEGE_ESCALATION,
                          ["uac bypass", "elevate", "admin", "root", "sudo", "privilege"]),
            MITRETechnique("T1068", "Exploitation for Privilege Escalation", MITRETactic.PRIVILEGE_ESCALATION,
                          ["exploit", "local privilege", "escalate", "elevation", "kernel exploit"]),
            MITRETechnique("T1574", "Hijack Execution Flow", MITRETactic.PRIVILEGE_ESCALATION,
                          ["dll hijack", "path hijack", "side loading", "dll preload"]),
        ])

        # Defense Evasion
        self.techniques.extend([
            MITRETechnique("T1562", "Impair Defenses", MITRETactic.DEFENSE_EVASION,
                          ["disable antivirus", "turn off", "defender", "edr", "disable firewall",
                           "tamper", "bypass av"]),
            MITRETechnique("T1027", "Obfuscated Files or Information", MITRETactic.DEFENSE_EVASION,
                          ["obfuscate", "encode", "base64", "encrypt", "packed", "xor", "shellcode"]),
            MITRETechnique("T1036", "Masquerading", MITRETactic.DEFENSE_EVASION,
                          ["masquerade", "fake name", "impersonate", "rename", "legitimate name"]),
            MITRETechnique("T1497", "Virtualization/Sandbox Evasion", MITRETactic.DEFENSE_EVASION,
                          ["sandbox detect", "vm detect", "virtualbox", "vmware", "debugger"]),
        ])

        # Credential Access
        self.techniques.extend([
            MITRETechnique("T1003", "OS Credential Dumping", MITRETactic.CREDENTIAL_ACCESS,
                          ["dump", "lsass", "sam", "ntds", "mimikatz", "password hash", "credentials"]),
            MITRETechnique("T1110", "Brute Force", MITRETactic.CREDENTIAL_ACCESS,
                          ["brute force", "password crack", "spray", "guess password"]),
            MITRETechnique("T1555", "Credentials from Password Stores", MITRETactic.CREDENTIAL_ACCESS,
                          ["credential manager", "vault", "keychain", "browser password", "stored credentials"]),
        ])

        # Discovery
        self.techniques.extend([
            MITRETechnique("T1087", "Account Discovery", MITRETactic.DISCOVERY,
                          ["user list", "enumerate users", "whoami", "net user", "local users"]),
            MITRETechnique("T1082", "System Information Discovery", MITRETactic.DISCOVERY,
                          ["system info", "os version", "hostname", "architecture", "env"]),
            MITRETechnique("T1049", "System Network Connections Discovery", MITRETactic.DISCOVERY,
                          ["netstat", "network connections", "tcp", "udp", "ports", "connections"]),
            MITRETechnique("T1083", "File and Directory Discovery", MITRETactic.DISCOVERY,
                          ["dir", "ls", "list files", "directory listing", "explore"]),
        ])

        # Lateral Movement
        self.techniques.extend([
            MITRETechnique("T1021", "Remote Services", MITRETactic.LATERAL_MOVEMENT,
                          ["rdp", "ssh", "wmi", "smb", "remote desktop", "winrm", "psexec"]),
            MITRETechnique("T1550", "Use Alternate Authentication Material", MITRETactic.LATERAL_MOVEMENT,
                          ["pass the hash", "pass the ticket", "kerberos", "ptt", "pth", "golden ticket"]),
            MITRETechnique("T1072", "Software Deployment Tools", MITRETactic.LATERAL_MOVEMENT,
                          ["sccm", "gpo", "group policy", "deploy", "push install"]),
        ])

        # Collection
        self.techniques.extend([
            MITRETechnique("T1005", "Data from Local System", MITRETactic.COLLECTION,
                          ["steal data", "copy files", "collect documents", "exfiltrate files"]),
            MITRETechnique("T1113", "Screen Capture", MITRETactic.COLLECTION,
                          ["screenshot", "screen capture", "desktop", "record screen"]),
            MITRETechnique("T1056", "Input Capture", MITRETactic.COLLECTION,
                          ["keylogger", "keystroke", "capture input", "hook keyboard"]),
            MITRETechnique("T1114", "Email Collection", MITRETactic.COLLECTION,
                          ["email", "outlook", "mailbox", "pst", "email dump"]),
        ])

        # Command and Control
        self.techniques.extend([
            MITRETechnique("T1071", "Application Layer Protocol", MITRETactic.COMMAND_AND_CONTROL,
                          ["http", "https", "dns", "ftp", "c2", "callback", "beacon"]),
            MITRETechnique("T1090", "Proxy", MITRETactic.COMMAND_AND_CONTROL,
                          ["proxy", "tor", "socks", "redirector", "relay"]),
            MITRETechnique("T1573", "Encrypted Channel", MITRETactic.COMMAND_AND_CONTROL,
                          ["encrypt", "tls", "ssl", "encrypted c2", "aes"]),
            MITRETechnique("T1008", "Fallback Channels", MITRETactic.COMMAND_AND_CONTROL,
                          ["backup c2", "fallback", "domain generation", "dga"]),
        ])

        # Exfiltration
        self.techniques.extend([
            MITRETechnique("T1041", "Exfiltration Over C2 Channel", MITRETactic.EXFILTRATION,
                          ["exfiltrate", "data leak", "send data", "upload"]),
            MITRETechnique("T1567", "Exfiltration Over Web Service", MITRETactic.EXFILTRATION,
                          ["cloud", "dropbox", "google drive", "pastebin", "github", "web exfil"]),
            MITRETechnique("T1030", "Data Transfer Size Limits", MITRETactic.EXFILTRATION,
                          ["chunked", "split", "small packets", "data size"]),
        ])

        # Impact
        self.techniques.extend([
            MITRETechnique("T1486", "Data Encrypted for Impact", MITRETactic.IMPACT,
                          ["ransomware", "encrypt files", "bitcoin", "decrypt", "ransom", "encrypted"]),
            MITRETechnique("T1490", "Inhibit System Recovery", MITRETactic.IMPACT,
                          ["delete backup", "vssadmin", "shadow copy", "restore point", "recovery"]),
            MITRETechnique("T1498", "Network Denial of Service", MITRETactic.IMPACT,
                          ["ddos", "dos", "denial of service", "flood", "bandwidth"]),
            MITRETechnique("T1565", "Data Manipulation", MITRETactic.IMPACT,
                          ["alter data", "modify", "corrupt", "tamper data"]),
            MITRETechnique("T1485", "Data Destruction", MITRETactic.IMPACT,
                          ["wipe", "delete", "shred", "destroy data", "format"]),
        ])

    def get_all_techniques(self) -> List[MITRETechnique]:
        return self.techniques

    def get_techniques_by_tactic(self, tactic: MITRETactic) -> List[MITRETechnique]:
        return [t for t in self.techniques if t.tactic == tactic]


class MITREAttackMappingEngine:
    """
    Production-grade MITRE ATT&CK Mapping Engine
    Maps threat intelligence to MITRE ATT&CK tactics and techniques
    """

    def __init__(self, cache_size: int = 500, confidence_threshold: float = 0.15):
        self.kb = MITREAttackKnowledgeBase()
        self.cache = ThreadSafeLRUCache(max_size=cache_size)
        self.confidence_threshold = confidence_threshold
        self._lock = threading.Lock()
        self._stats = {
            'total_mappings': 0,
            'cache_hits': 0,
            'cache_misses': 0,
            'avg_response_time_ms': 0.0,
            'avg_techniques_per_mapping': 0.0
        }

    def _generate_cache_key(self, threat_id: str, text: str) -> str:
        key_data = f"{threat_id}:{text}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _tokenize(self, text: str) -> List[str]:
        """Tokenize text for keyword matching"""
        text = re.sub(r'[^\w\s]', ' ', text.lower())
        return [t.strip() for t in text.split() if len(t.strip()) > 2]

    def _calculate_match_confidence(self, text: str, technique: MITRETechnique) -> float:
        """Calculate confidence score for technique match"""
        text_lower = text.lower()
        tokens = set(self._tokenize(text))
        
        max_confidence = 0.0
        
        # Check each keyword individually
        for kw in technique.keywords:
            kw_lower = kw.lower()
            
            # Exact phrase match (highest weight)
            if kw_lower in text_lower:
                max_confidence = max(max_confidence, 0.8)
            
            # Individual token matches
            kw_tokens = set(self._tokenize(kw))
            if kw_tokens and tokens:
                match_ratio = len(tokens & kw_tokens) / len(kw_tokens)
                max_confidence = max(max_confidence, match_ratio * 0.6)
        
        return min(max_confidence, 1.0)

    def map_threat(self, threat_id: str, threat_title: str, 
                   threat_description: str = "", use_cache: bool = True) -> MappingResult:
        """
        Map a single threat intelligence entry to MITRE ATT&CK

        Args:
            threat_id: Unique threat identifier
            threat_title: Threat title
            threat_description: Threat description text
            use_cache: Whether to use caching

        Returns:
            MappingResult with matched techniques
        """
        start_time = time.time()
        full_text = f"{threat_title} {threat_description}"

        # Check cache
        if use_cache:
            cache_key = self._generate_cache_key(threat_id, full_text)
            cached_result = self.cache.get(cache_key)

            with self._lock:
                self._stats['total_mappings'] += 1

            if cached_result is not None:
                with self._lock:
                    self._stats['cache_hits'] += 1
                return cached_result

            with self._lock:
                self._stats['cache_misses'] += 1

        # Find matching techniques
        matched_techniques: List[Tuple[MITRETechnique, float]] = []

        for technique in self.kb.get_all_techniques():
            confidence = self._calculate_match_confidence(full_text, technique)
            if confidence >= self.confidence_threshold:
                matched_techniques.append((technique, round(confidence, 4)))

        # Sort by confidence descending
        matched_techniques.sort(key=lambda x: x[1], reverse=True)

        # Calculate tactic distribution
        tactic_counts: Dict[str, int] = defaultdict(int)
        tactic_confidence: Dict[str, float] = defaultdict(float)

        for technique, conf in matched_techniques:
            tactic_name = technique.tactic.value
            tactic_counts[tactic_name] += 1
            tactic_confidence[tactic_name] += conf

        tactic_distribution: Dict[str, float] = {}
        total_matched = len(matched_techniques)

        if total_matched > 0:
            for tactic in tactic_counts:
                avg_conf = tactic_confidence[tactic] / tactic_counts[tactic]
                tactic_distribution[tactic] = round(avg_conf, 4)
        else:
            for tactic in MITRETactic:
                tactic_distribution[tactic.value] = 0.0

        # Calculate overall confidence
        if matched_techniques:
            overall_confidence = round(
                sum(conf for _, conf in matched_techniques) / len(matched_techniques), 4
            )
        else:
            overall_confidence = 0.0

        result = MappingResult(
            threat_id=threat_id,
            threat_title=threat_title,
            matched_techniques=matched_techniques,
            tactic_distribution=tactic_distribution,
            overall_confidence=overall_confidence,
            technique_count=total_matched
        )

        # Cache result
        if use_cache:
            self.cache.put(cache_key, result)

        # Update stats
        elapsed_ms = (time.time() - start_time) * 1000
        with self._lock:
            total = self._stats['total_mappings']
            self._stats['avg_response_time_ms'] = (
                self._stats['avg_response_time_ms'] * (total - 1) + elapsed_ms
            ) / total
            self._stats['avg_techniques_per_mapping'] = (
                self._stats['avg_techniques_per_mapping'] * (total - 1) + total_matched
            ) / total

        return result

    def batch_map(self, threats: List[Dict[str, str]], **kwargs) -> List[MappingResult]:
        """Batch map multiple threats"""
        results = []
        for threat in threats:
            results.append(self.map_threat(
                threat.get('id', ''),
                threat.get('title', ''),
                threat.get('description', ''),
                **kwargs
            ))
        return results

    def generate_heatmap_data(self, results: List[MappingResult]) -> Dict[str, Any]:
        """Generate heatmap data from multiple mapping results"""
        tactic_scores: Dict[str, List[float]] = defaultdict(list)
        technique_frequency: Counter = Counter()

        for result in results:
            for tactic, score in result.tactic_distribution.items():
                tactic_scores[tactic].append(score)
            for technique, _ in result.matched_techniques:
                technique_frequency[technique.technique_id] += 1

        heatmap = {
            'tactic_average_scores': {
                tactic: round(sum(scores) / max(len(scores), 1), 4)
                for tactic, scores in tactic_scores.items()
            },
            'technique_frequency': dict(technique_frequency.most_common(20)),
            'total_threats_analyzed': len(results),
            'total_technique_matches': sum(technique_frequency.values())
        }

        return heatmap

    def export_to_json(self, results: List[MappingResult], filepath: str) -> bool:
        """Export mapping results to JSON"""
        try:
            export_data = []
            for result in results:
                export_data.append({
                    'threat_id': result.threat_id,
                    'threat_title': result.threat_title,
                    'overall_confidence': result.overall_confidence,
                    'technique_count': result.technique_count,
                    'matched_techniques': [
                        {
                            'technique_id': t.technique_id,
                            'name': t.name,
                            'tactic': t.tactic.value,
                            'confidence': conf
                        }
                        for t, conf in result.matched_techniques
                    ],
                    'tactic_distribution': result.tactic_distribution,
                    'timestamp': result.timestamp
                })

            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
            return True
        except Exception:
            return False

    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self._lock:
            stats = dict(self._stats)

        stats.update({
            'cache_size': self.cache.size(),
            'kb_technique_count': len(self.kb.get_all_techniques()),
            'confidence_threshold': self.confidence_threshold
        })

        if stats['total_mappings'] > 0:
            stats['cache_hit_rate'] = round(
                stats['cache_hits'] / stats['total_mappings'], 4
            )
        else:
            stats['cache_hit_rate'] = 0.0

        return stats

    def clear_cache(self) -> int:
        """Clear expired cache entries"""
        return self.cache.clear_expired()


__all__ = [
    'MITREAttackMappingEngine',
    'MappingResult',
    'MITRETechnique',
    'MITRETactic',
    'MITREAttackKnowledgeBase',
]
