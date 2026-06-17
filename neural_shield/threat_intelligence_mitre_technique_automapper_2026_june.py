"""
Threat Intelligence MITRE Technique Auto-Mapper
NeuralShield-AI Feature - June 2026

Real working implementation:
- Auto-maps IOCs to MITRE ATT&CK techniques
- Confidence scoring based on pattern matching
- TTP (Tactics, Techniques, Procedures) extraction
- Caching layer for performance
- Batch processing support
"""

import re
import hashlib
import json
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from collections import defaultdict


@dataclass
class IOC:
    """Indicator of Compromise data structure"""
    value: str
    ioc_type: str  # ip, domain, hash, url, email
    source: str = "unknown"
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class MITREMapping:
    """MITRE ATT&CK mapping result"""
    technique_id: str
    technique_name: str
    tactic: str
    confidence: float
    evidence: List[str]
    mapped_at: datetime


@dataclass
class AutoMapperResult:
    """Complete auto-mapping result"""
    ioc: IOC
    mappings: List[MITREMapping]
    primary_technique: Optional[MITREMapping]
    processing_time_ms: float
    cache_hit: bool = False


class LRUCache:
    """Simple LRU Cache implementation"""
    def __init__(self, max_size: int = 1000, ttl_seconds: int = 3600):
        self.max_size = max_size
        self.ttl = timedelta(seconds=ttl_seconds)
        self.cache: Dict[str, Tuple[Any, datetime]] = {}
        self.access_order: List[str] = []
    
    def get(self, key: str) -> Optional[Any]:
        if key in self.cache:
            value, timestamp = self.cache[key]
            if datetime.now() - timestamp < self.ttl:
                # Move to end (most recently used)
                self.access_order.remove(key)
                self.access_order.append(key)
                return value
            else:
                del self.cache[key]
                self.access_order.remove(key)
        return None
    
    def put(self, key: str, value: Any) -> None:
        if key in self.cache:
            self.access_order.remove(key)
        elif len(self.cache) >= self.max_size:
            # Evict least recently used
            lru_key = self.access_order.pop(0)
            del self.cache[lru_key]
        
        self.cache[key] = (value, datetime.now())
        self.access_order.append(key)
    
    def size(self) -> int:
        return len(self.cache)


class ThreatIntelMITREAutoMapper:
    """
    Real working MITRE ATT&CK Auto-Mapper for Threat Intelligence
    
    Maps IOCs to MITRE ATT&CK techniques using:
    1. Pattern-based heuristic matching
    2. Known IOC-to-technique associations
    3. Confidence scoring
    4. Tactic classification
    """
    
    # MITRE ATT&CK Technique Database (real subset)
    MITRE_TECHNIQUES = {
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution",
                  "patterns": ["powershell", "cmd.exe", "bash", "python", "script", "shell"]},
        "T1027": {"name": "Obfuscated Files or Information", "tactic": "Defense Evasion",
                  "patterns": ["base64", "encode", "encrypt", "obfuscat", "packed"]},
        "T1055": {"name": "Process Injection", "tactic": "Privilege Escalation",
                  "patterns": ["inject", "dll", "shellcode", "reflective"]},
        "T1071": {"name": "Application Layer Protocol", "tactic": "Command and Control",
                  "patterns": ["http", "https", "dns", "ftp", "c2", "callback"]},
        "T1046": {"name": "Network Service Scanning", "tactic": "Discovery",
                  "patterns": ["scan", "portscan", "nmap", "enumerate"]},
        "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access",
                  "patterns": ["mimikatz", "hashdump", "credential", "lsass"]},
        "T1566": {"name": "Phishing", "tactic": "Initial Access",
                  "patterns": ["phish", "spearphish", "email", "attachment"]},
        "T1083": {"name": "File and Directory Discovery", "tactic": "Discovery",
                  "patterns": ["dir", "ls", "enumerate", "file listing"]},
        "T1047": {"name": "Windows Management Instrumentation", "tactic": "Execution",
                  "patterns": ["wmi", "winmgmt", "wmic"]},
        "T1053": {"name": "Scheduled Task/Job", "tactic": "Execution",
                  "patterns": ["schtasks", "cron", "at", "scheduled"]},
        "T1021": {"name": "Remote Services", "tactic": "Lateral Movement",
                  "patterns": ["rdp", "ssh", "smb", "winrm", "psexec"]},
        "T1074": {"name": "Data Staged", "tactic": "Collection",
                  "patterns": ["archive", "zip", "rar", "stage", "collect"]},
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": "Exfiltration",
                  "patterns": ["exfiltr", "upload", "send", "transfer"]},
        "T1486": {"name": "Data Encrypted for Impact", "tactic": "Impact",
                  "patterns": ["ransom", "encrypt", "bitcoin", "decrypt"]},
        "T1090": {"name": "Proxy", "tactic": "Command and Control",
                  "patterns": ["proxy", "tor", "vpn", "redirector"]},
        "T1555": {"name": "Credentials from Password Stores", "tactic": "Credential Access",
                  "patterns": ["browser", "password", "keychain", "vault"]},
    }
    
    # IOC Type patterns
    IOC_PATTERNS = {
        "ip": re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'),
        "domain": re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$'),
        "hash_md5": re.compile(r'^[a-fA-F0-9]{32}$'),
        "hash_sha1": re.compile(r'^[a-fA-F0-9]{40}$'),
        "hash_sha256": re.compile(r'^[a-fA-F0-9]{64}$'),
        "url": re.compile(r'^https?://'),
        "email": re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'),
    }
    
    def __init__(self, cache_size: int = 1000, cache_ttl: int = 3600):
        self.cache = LRUCache(max_size=cache_size, ttl_seconds=cache_ttl)
        self.stats = {
            "total_processed": 0,
            "cache_hits": 0,
            "successful_mappings": 0,
            "failed_mappings": 0,
        }
    
    def detect_ioc_type(self, value: str) -> str:
        """Detect the type of IOC"""
        value_lower = value.lower().strip()
        
        for ioc_type, pattern in self.IOC_PATTERNS.items():
            if pattern.match(value_lower):
                if ioc_type.startswith("hash_"):
                    return "hash"
                return ioc_type
        
        return "unknown"
    
    def _generate_cache_key(self, ioc: IOC) -> str:
        """Generate cache key for IOC"""
        key_data = f"{ioc.value}:{ioc.ioc_type}"
        return hashlib.md5(key_data.encode()).hexdigest()
    
    def _calculate_confidence(self, match_count: int, pattern_count: int, 
                              ioc_context: Optional[str] = None) -> float:
        """Calculate confidence score 0.0 - 1.0"""
        base_score = min(match_count / max(pattern_count, 1), 1.0)
        
        # Boost if context matches
        context_boost = 0.0
        if ioc_context:
            context_boost = 0.1 if any(t in ioc_context.lower() for t in ["malware", "attack", "compromise"]) else 0.0
        
        final_score = min(base_score + context_boost, 1.0)
        return round(final_score, 3)
    
    def map_ioc_to_mitre(self, ioc: IOC, context: Optional[str] = None) -> AutoMapperResult:
        """
        Map a single IOC to MITRE ATT&CK techniques
        Real working implementation with actual pattern matching
        """
        import time
        start_time = time.time()
        
        # Check cache first
        cache_key = self._generate_cache_key(ioc)
        cached_result = self.cache.get(cache_key)
        
        if cached_result:
            self.stats["cache_hits"] += 1
            self.stats["total_processed"] += 1
            cached_result.cache_hit = True
            return cached_result
        
        mappings: List[MITREMapping] = []
        ioc_value_lower = ioc.value.lower()
        
        # Check each MITRE technique for pattern matches
        for tech_id, tech_data in self.MITRE_TECHNIQUES.items():
            matches = []
            patterns = tech_data["patterns"]
            
            for pattern in patterns:
                # Check pattern in IOC value or context
                if pattern in ioc_value_lower:
                    matches.append(f"IOC value contains: '{pattern}'")
                if context and pattern in context.lower():
                    matches.append(f"Context contains: '{pattern}'")
            
            if matches:
                confidence = self._calculate_confidence(
                    len(matches), len(patterns), context
                )
                
                mapping = MITREMapping(
                    technique_id=tech_id,
                    technique_name=tech_data["name"],
                    tactic=tech_data["tactic"],
                    confidence=confidence,
                    evidence=matches,
                    mapped_at=datetime.now()
                )
                mappings.append(mapping)
        
        # Sort by confidence descending
        mappings.sort(key=lambda x: x.confidence, reverse=True)
        
        # Determine primary technique
        primary = mappings[0] if mappings else None
        
        processing_time = (time.time() - start_time) * 1000
        
        result = AutoMapperResult(
            ioc=ioc,
            mappings=mappings,
            primary_technique=primary,
            processing_time_ms=round(processing_time, 2)
        )
        
        # Cache the result
        self.cache.put(cache_key, result)
        
        # Update stats
        self.stats["total_processed"] += 1
        if mappings:
            self.stats["successful_mappings"] += 1
        else:
            self.stats["failed_mappings"] += 1
        
        return result
    
    def batch_map_iocs(self, iocs: List[IOC], context: Optional[str] = None) -> List[AutoMapperResult]:
        """Process multiple IOCs in batch"""
        return [self.map_ioc_to_mitre(ioc, context) for ioc in iocs]
    
    def get_mitre_tactic_summary(self, results: List[AutoMapperResult]) -> Dict[str, int]:
        """Get summary count by MITRE tactic"""
        summary = defaultdict(int)
        for result in results:
            if result.primary_technique:
                summary[result.primary_technique.tactic] += 1
        return dict(summary)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get mapper statistics"""
        stats = self.stats.copy()
        stats["cache_size"] = self.cache.size()
        if stats["total_processed"] > 0:
            stats["cache_hit_rate"] = round(stats["cache_hits"] / stats["total_processed"], 3)
            stats["success_rate"] = round(stats["successful_mappings"] / stats["total_processed"], 3)
        return stats
    
    def export_results_json(self, results: List[AutoMapperResult]) -> str:
        """Export results to JSON format"""
        export_data = []
        for result in results:
            data = {
                "ioc": asdict(result.ioc),
                "mappings": [asdict(m) for m in result.mappings],
                "processing_time_ms": result.processing_time_ms,
                "cache_hit": result.cache_hit
            }
            if result.primary_technique:
                data["primary_technique"] = asdict(result.primary_technique)
            export_data.append(data)
        
        return json.dumps(export_data, indent=2, default=str)


# Export the class
__all__ = ["ThreatIntelMITREAutoMapper", "IOC", "MITREMapping", "AutoMapperResult", "LRUCache"]
