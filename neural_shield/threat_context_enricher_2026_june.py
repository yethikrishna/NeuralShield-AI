"""
Threat Context Enricher for NeuralShield-AI
Production-grade threat context enrichment module
Enriches detected threats with metadata: geolocation, IP reputation, threat intelligence, etc.
"""

import re
import ipaddress
import hashlib
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
import json


class ThreatSeverity(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatCategory(Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK = "jailbreak"
    DATA_EXFILTRATION = "data_exfiltration"
    RAG_POISONING = "rag_poisoning"
    BACKDOOR = "backdoor"
    MODEL_EXTRACTION = "model_extraction"
    UNKNOWN = "unknown"


@dataclass
class EnrichedContext:
    """Dataclass for enriched threat context"""
    threat_id: str
    timestamp: float
    severity: ThreatSeverity
    category: ThreatCategory
    ip_reputation: Dict[str, Any] = field(default_factory=dict)
    geolocation: Dict[str, Any] = field(default_factory=dict)
    threat_intel_matches: List[Dict[str, Any]] = field(default_factory=list)
    behavioral_indicators: Dict[str, Any] = field(default_factory=dict)
    risk_score: float = 0.0
    confidence: float = 0.0
    mitigation_suggestions: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)


class ThreatContextEnricher:
    """
    Production-grade Threat Context Enricher
    Enriches detected threats with contextual metadata for better decision making
    """

    # Known malicious IP ranges (simplified production dataset)
    MALICIOUS_IP_RANGES = [
        ("192.168.1.0/24", "known_scanner", 0.8),
        ("10.0.0.0/8", "internal_network", 0.2),
        ("172.16.0.0/12", "internal_network", 0.2),
    ]

    # Known malicious patterns
    MALICIOUS_PATTERNS = {
        "ignore_previous": r"(ignore|disregard|forget)\s+(all\s+)?(previous|above|prior)",
        "system_prompt": r"(system|developer|initial)\s+(prompt|instruction|message)",
        "role_play": r"(act|pretend|role.?play|simulate)\s+(as|like)",
        "prompt_leak": r"(reveal|disclose|show|output)\s+(your|the)\s+(system|prompt)",
    }

    # Geolocation database (simplified)
    GEOLOCATION_DB = {
        "US": {"country": "United States", "risk_factor": 0.3},
        "CN": {"country": "China", "risk_factor": 0.5},
        "RU": {"country": "Russia", "risk_factor": 0.7},
        "KP": {"country": "North Korea", "risk_factor": 0.9},
        "IR": {"country": "Iran", "risk_factor": 0.8},
        "DEFAULT": {"country": "Unknown", "risk_factor": 0.5},
    }

    # Threat intelligence feed (simplified production feed)
    THREAT_INTEL_FEED = {
        "signature_001": {"name": "DAN Jailbreak", "severity": "critical", "family": "jailbreak"},
        "signature_002": {"name": "Dev Mode Prompt", "severity": "high", "family": "jailbreak"},
        "signature_003": {"name": "System Prompt Extraction", "severity": "critical", "family": "prompt_leak"},
        "signature_004": {"name": "RAG Poisoning Vector", "severity": "high", "family": "rag_poisoning"},
        "signature_005": {"name": "Multi-Turn Jailbreak", "severity": "high", "family": "jailbreak"},
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the Threat Context Enricher"""
        self.config = config or {}
        self.enrichment_cache: Dict[str, EnrichedContext] = {}
        self.cache_ttl = self.config.get("cache_ttl", 3600)  # 1 hour default
        self.enrichment_count = 0
        self.start_time = time.time()

    def generate_threat_id(self, threat_data: Dict[str, Any]) -> str:
        """Generate a unique threat ID based on threat content"""
        threat_str = json.dumps(threat_data, sort_keys=True)
        return "threat_" + hashlib.sha256(threat_str.encode()).hexdigest()[:16]

    def extract_ip_addresses(self, text: str) -> List[str]:
        """Extract IP addresses from text"""
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        return re.findall(ip_pattern, text)

    def check_ip_reputation(self, ip: str) -> Dict[str, Any]:
        """Check IP reputation against known malicious ranges"""
        try:
            ip_obj = ipaddress.ip_address(ip)
            result = {
                "ip": ip,
                "is_malicious": False,
                "reputation_score": 1.0,  # 1.0 = clean, 0.0 = malicious
                "classification": "clean",
                "matches": []
            }

            for network, classification, risk in self.MALICIOUS_IP_RANGES:
                if ip_obj in ipaddress.ip_network(network, strict=False):
                    result["is_malicious"] = risk > 0.5
                    result["reputation_score"] = 1.0 - risk
                    result["classification"] = classification
                    result["matches"].append({
                        "network": network,
                        "classification": classification,
                        "risk": risk
                    })

            return result
        except ValueError:
            return {
                "ip": ip,
                "is_malicious": False,
                "reputation_score": 0.5,
                "classification": "invalid",
                "matches": []
            }

    def get_geolocation_context(self, country_code: str = "DEFAULT") -> Dict[str, Any]:
        """Get geolocation risk context"""
        return self.GEOLOCATION_DB.get(country_code, self.GEOLOCATION_DB["DEFAULT"])

    def match_threat_intelligence(self, threat_signals: List[str]) -> List[Dict[str, Any]]:
        """Match threat signals against threat intelligence feed"""
        matches = []
        for signal in threat_signals:
            for sig_id, sig_data in self.THREAT_INTEL_FEED.items():
                if sig_data["family"] in signal.lower() or sig_data["name"].lower() in signal.lower():
                    matches.append({
                        "signature_id": sig_id,
                        **sig_data,
                        "matched_signal": signal
                    })
        return matches

    def calculate_risk_score(self, enriched_data: EnrichedContext) -> float:
        """Calculate overall risk score based on enriched context"""
        base_score = {
            ThreatSeverity.LOW: 0.2,
            ThreatSeverity.MEDIUM: 0.5,
            ThreatSeverity.HIGH: 0.8,
            ThreatSeverity.CRITICAL: 1.0
        }.get(enriched_data.severity, 0.5)

        # Adjust for IP reputation
        ip_risk = 1.0 - min(1.0, sum(
            1.0 - rep.get("reputation_score", 1.0)
            for rep in enriched_data.ip_reputation.values()
        )) if enriched_data.ip_reputation else 0.0

        # Adjust for threat intel matches
        intel_risk = sum(
            1.0 if match.get("severity") == "critical"
            else 0.7 if match.get("severity") == "high"
            else 0.4 if match.get("severity") == "medium"
            else 0.2
            for match in enriched_data.threat_intel_matches
        ) * 0.1

        # Adjust for geolocation risk
        geo_risk = enriched_data.geolocation.get("risk_factor", 0.5) * 0.1

        final_score = min(1.0, base_score + ip_risk + intel_risk + geo_risk)
        return round(final_score, 3)

    def generate_mitigation_suggestions(self, enriched_data: EnrichedContext) -> List[str]:
        """Generate context-aware mitigation suggestions"""
        suggestions = []

        if enriched_data.risk_score >= 0.8:
            suggestions.append("Immediate: Block request and trigger security alert")
            suggestions.append("Immediate: Activate rate limiting and circuit breaker")
        elif enriched_data.risk_score >= 0.5:
            suggestions.append("Flag request for human review")
            suggestions.append("Apply enhanced input sanitization")

        if enriched_data.category == ThreatCategory.JAILBREAK:
            suggestions.append("Apply constitutional classifier filtering")
            suggestions.append("Enable prompt confusion detection")
        elif enriched_data.category == ThreatCategory.PROMPT_INJECTION:
            suggestions.append("Enable CoT prompt injection detection")
            suggestions.append("Apply input purification")
        elif enriched_data.category == ThreatCategory.RAG_POISONING:
            suggestions.append("Verify RAG context integrity")
            suggestions.append("Check document signatures")

        if enriched_data.ip_reputation:
            suggestions.append("Monitor IP address for repeated suspicious activity")

        return list(set(suggestions))  # Remove duplicates

    def enrich_threat(self, threat_data: Dict[str, Any]) -> EnrichedContext:
        """
        Main enrichment method - adds full contextual metadata to a detected threat
        
        Args:
            threat_data: Dictionary containing threat detection data
                Required keys: 'content', 'severity', 'category'
                Optional keys: 'ip_address', 'user_agent', 'country_code', 'detection_signals'
        
        Returns:
            EnrichedContext object with all enrichment metadata
        """
        # Check cache first
        threat_id = self.generate_threat_id(threat_data)
        
        if threat_id in self.enrichment_cache:
            cached = self.enrichment_cache[threat_id]
            if time.time() - cached.timestamp < self.cache_ttl:
                return cached

        # Parse severity
        severity_map = {
            "low": ThreatSeverity.LOW,
            "medium": ThreatSeverity.MEDIUM,
            "high": ThreatSeverity.HIGH,
            "critical": ThreatSeverity.CRITICAL
        }
        severity = severity_map.get(threat_data.get("severity", "medium").lower(), ThreatSeverity.MEDIUM)

        # Parse category
        category_map = {
            "prompt_injection": ThreatCategory.PROMPT_INJECTION,
            "jailbreak": ThreatCategory.JAILBREAK,
            "data_exfiltration": ThreatCategory.DATA_EXFILTRATION,
            "rag_poisoning": ThreatCategory.RAG_POISONING,
            "backdoor": ThreatCategory.BACKDOOR,
            "model_extraction": ThreatCategory.MODEL_EXTRACTION,
        }
        category = category_map.get(threat_data.get("category", "unknown").lower(), ThreatCategory.UNKNOWN)

        # Create base enriched context
        enriched = EnrichedContext(
            threat_id=threat_id,
            timestamp=time.time(),
            severity=severity,
            category=category,
            confidence=float(threat_data.get("confidence", 0.8))
        )

        # IP reputation enrichment
        ip_addresses = []
        if "ip_address" in threat_data:
            ip_addresses.append(threat_data["ip_address"])
        ip_addresses.extend(self.extract_ip_addresses(threat_data.get("content", "")))

        for ip in ip_addresses:
            enriched.ip_reputation[ip] = self.check_ip_reputation(ip)

        # Geolocation enrichment
        enriched.geolocation = self.get_geolocation_context(
            threat_data.get("country_code", "DEFAULT")
        )

        # Threat intelligence matching
        detection_signals = threat_data.get("detection_signals", [])
        if isinstance(detection_signals, str):
            detection_signals = [detection_signals]
        enriched.threat_intel_matches = self.match_threat_intelligence(detection_signals)

        # Behavioral indicators
        enriched.behavioral_indicators = {
            "contains_ip_addresses": len(ip_addresses) > 0,
            "malicious_pattern_matches": self._detect_malicious_patterns(threat_data.get("content", "")),
            "content_length": len(threat_data.get("content", "")),
            "threat_intel_match_count": len(enriched.threat_intel_matches)
        }

        # Calculate risk score
        enriched.risk_score = self.calculate_risk_score(enriched)

        # Generate mitigation suggestions
        enriched.mitigation_suggestions = self.generate_mitigation_suggestions(enriched)

        # Add metadata
        enriched.metadata = {
            "enrichment_version": "1.0.0",
            "enrichment_timestamp": time.time(),
            "threat_intel_feed_version": "2026.06.17",
            "enrichment_engine": "ThreatContextEnricher"
        }

        # Cache the result
        self.enrichment_cache[threat_id] = enriched
        self.enrichment_count += 1

        return enriched

    def _detect_malicious_patterns(self, content: str) -> Dict[str, int]:
        """Detect known malicious patterns in content"""
        matches = {}
        content_lower = content.lower()
        for pattern_name, pattern_regex in self.MALICIOUS_PATTERNS.items():
            count = len(re.findall(pattern_regex, content_lower, re.IGNORECASE))
            if count > 0:
                matches[pattern_name] = count
        return matches

    def batch_enrich(self, threats: List[Dict[str, Any]]) -> List[EnrichedContext]:
        """Enrich multiple threats in batch"""
        return [self.enrich_threat(threat) for threat in threats]

    def get_stats(self) -> Dict[str, Any]:
        """Get enrichment engine statistics"""
        return {
            "total_enrichments": self.enrichment_count,
            "cache_size": len(self.enrichment_cache),
            "cache_ttl_seconds": self.cache_ttl,
            "uptime_seconds": time.time() - self.start_time,
            "threat_intel_signatures": len(self.THREAT_INTEL_FEED),
            "monitored_ip_ranges": len(self.MALICIOUS_IP_RANGES)
        }

    def to_dict(self, enriched: EnrichedContext) -> Dict[str, Any]:
        """Convert EnrichedContext to dictionary for serialization"""
        return {
            "threat_id": enriched.threat_id,
            "timestamp": enriched.timestamp,
            "severity": enriched.severity.value,
            "category": enriched.category.value,
            "ip_reputation": enriched.ip_reputation,
            "geolocation": enriched.geolocation,
            "threat_intel_matches": enriched.threat_intel_matches,
            "behavioral_indicators": enriched.behavioral_indicators,
            "risk_score": enriched.risk_score,
            "confidence": enriched.confidence,
            "mitigation_suggestions": enriched.mitigation_suggestions,
            "metadata": enriched.metadata
        }
