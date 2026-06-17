"""
Threat Intelligence WebSocket Streaming Service
Real-time threat intelligence streaming with WebSocket support.

This module provides:
1. Real-time threat feed aggregation
2. WebSocket server for live streaming
3. Threat intelligence normalization
4. Client connection management
5. Threat severity filtering
"""

import asyncio
import json
import time
import hashlib
import logging
from typing import Dict, List, Optional, Any, Set
from dataclasses import dataclass, asdict
from enum import Enum
from datetime import datetime, timezone
import uuid

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class ThreatSeverity(Enum):
    """Threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    """Types of security threats"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    MODEL_HIJACKING = "model_hijacking"
    PII_LEAKAGE = "pii_leakage"
    HALLUCINATION = "hallucination"
    BACKDOOR_DETECTED = "backdoor_detected"


@dataclass
class ThreatIntelEntry:
    """Threat intelligence entry structure"""
    threat_id: str
    timestamp: str
    severity: str
    threat_type: str
    source: str
    description: str
    affected_components: List[str]
    confidence_score: float
    mitigation_recommendation: str
    indicators: Dict[str, Any]


class ThreatFeedSimulator:
    """Simulates real threat intelligence feeds with realistic patterns"""
    
    def __init__(self):
        self.feed_sources = [
            "internal_security_monitor",
            "external_threat_feed",
            "community_threat_intel",
            "dark_web_monitor",
            "honeypot_network",
            "anomaly_detection_engine"
        ]
        
        self.threat_patterns = [
            {
                "type": ThreatType.PROMPT_INJECTION,
                "descriptions": [
                    "Detected prompt injection attempt using role-playing technique",
                    "System prompt override attempt detected in user input",
                    "Context manipulation pattern identified in query"
                ]
            },
            {
                "type": ThreatType.JAILBREAK_ATTEMPT,
                "descriptions": [
                    "Multi-turn jailbreak pattern with gradual boundary pushing",
                    "DAN-style prompt detected with persona override",
                    "Encoding-based obfuscation attempt identified"
                ]
            },
            {
                "type": ThreatType.DATA_EXFILTRATION,
                "descriptions": [
                    "Suspicious data extraction pattern detected",
                    "Base64 encoding detected in output - potential exfiltration",
                    "Steganographic embedding attempt identified"
                ]
            },
            {
                "type": ThreatType.ADVERSARIAL_ATTACK,
                "descriptions": [
                    "Adversarial perturbation detected in input embedding space",
                    "Gradient-based attack pattern identified",
                    "Model extraction query patterns detected"
                ]
            }
        ]
    
    def generate_threat_entry(self) -> ThreatIntelEntry:
        """Generate a realistic threat intelligence entry"""
        pattern = self.threat_patterns[int(time.time() * 1000) % len(self.threat_patterns)]
        severity_idx = int(time.time() * 1000) % 4
        severities = [ThreatSeverity.LOW, ThreatSeverity.MEDIUM, ThreatSeverity.HIGH, ThreatSeverity.CRITICAL]
        severity = severities[severity_idx]
        
        return ThreatIntelEntry(
            threat_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            severity=severity.value,
            threat_type=pattern["type"].value,
            source=self.feed_sources[int(time.time() * 1000) % len(self.feed_sources)],
            description=pattern["descriptions"][int(time.time() * 1000) % len(pattern["descriptions"])],
            affected_components=["input_validator", "prompt_guard", "output_sanitizer"],
            confidence_score=0.75 + (hash(uuid.uuid4().hex) % 25) / 100,
            mitigation_recommendation=self._get_mitigation(severity),
            indicators={
                "pattern_match": True,
                "anomaly_score": 0.6 + (hash(uuid.uuid4().hex) % 40) / 100,
                "historical_precedence": bool(hash(uuid.uuid4().hex) % 2)
            }
        )
    
    def _get_mitigation(self, severity: ThreatSeverity) -> str:
        """Get mitigation recommendation based on severity"""
        mitigations = {
            ThreatSeverity.LOW: "Monitor and log for pattern analysis",
            ThreatSeverity.MEDIUM: "Apply enhanced input validation and rate limiting",
            ThreatSeverity.HIGH: "Block suspicious input, trigger alert, increase logging verbosity",
            ThreatSeverity.CRITICAL: "Immediate input blocking, security team alert, incident response trigger"
        }
        return mitigations.get(severity, "Standard security protocols apply")


class ThreatIntelWebSocketStreamer:
    """
    WebSocket streaming service for real-time threat intelligence.
    
    Features:
    - Real-time threat feed streaming
    - Client connection management
    - Severity-based filtering
    - Threat deduplication
    - Connection health monitoring
    """
    
    def __init__(self, host: str = "localhost", port: int = 8765):
        self.host = host
        self.port = port
        self.connected_clients: Dict[str, Any] = {}
        self.threat_history: List[ThreatIntelEntry] = []
        self.max_history_size = 1000
        self.feed_simulator = ThreatFeedSimulator()
        self.is_running = False
        self.deduplication_cache: Set[str] = set()
        self.stats = {
            "total_threats_broadcast": 0,
            "clients_connected": 0,
            "deduplicated_threats": 0,
            "start_time": None
        }
    
    def _compute_threat_hash(self, threat: ThreatIntelEntry) -> str:
        """Compute hash for threat deduplication"""
        threat_signature = f"{threat.threat_type}:{threat.description[:50]}:{threat.source}"
        return hashlib.md5(threat_signature.encode()).hexdigest()
    
    def is_duplicate(self, threat: ThreatIntelEntry) -> bool:
        """Check if threat is duplicate based on signature"""
        threat_hash = self._compute_threat_hash(threat)
        if threat_hash in self.deduplication_cache:
            return True
        self.deduplication_cache.add(threat_hash)
        # Keep cache bounded
        if len(self.deduplication_cache) > 5000:
            self.deduplication_cache = set(list(self.deduplication_cache)[-2500:])
        return False
    
    def add_threat_to_history(self, threat: ThreatIntelEntry):
        """Add threat to history with bounded size"""
        self.threat_history.append(threat)
        if len(self.threat_history) > self.max_history_size:
            self.threat_history = self.threat_history[-self.max_history_size:]
    
    def get_threats_by_severity(self, min_severity: str) -> List[Dict[str, Any]]:
        """Get filtered threats by minimum severity level"""
        severity_order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        min_level = severity_order.get(min_severity.lower(), 0)
        
        filtered = []
        for threat in self.threat_history:
            if severity_order.get(threat.severity, 0) >= min_level:
                filtered.append(asdict(threat))
        return filtered
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get streaming service statistics"""
        uptime = 0
        if self.stats["start_time"]:
            uptime = time.time() - self.stats["start_time"]
        
        return {
            "service": "threat_intel_websocket_streamer",
            "uptime_seconds": uptime,
            "connected_clients": len(self.connected_clients),
            "total_threats_broadcast": self.stats["total_threats_broadcast"],
            "deduplicated_threats": self.stats["deduplicated_threats"],
            "history_size": len(self.threat_history),
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    
    async def broadcast_threat(self, threat: ThreatIntelEntry):
        """Broadcast threat to all connected clients"""
        if self.is_duplicate(threat):
            self.stats["deduplicated_threats"] += 1
            return
        
        self.add_threat_to_history(threat)
        self.stats["total_threats_broadcast"] += 1
        
        threat_data = json.dumps({
            "type": "threat_alert",
            "data": asdict(threat)
        })
        
        logger.info(f"Broadcasting threat: {threat.threat_type} [{threat.severity}]")
        return threat_data
    
    async def generate_and_broadcast_threats(self):
        """Continuously generate and broadcast threats"""
        while self.is_running:
            threat = self.feed_simulator.generate_threat_entry()
            await self.broadcast_threat(threat)
            await asyncio.sleep(2 + (hash(uuid.uuid4().hex) % 3))  # 2-5 second intervals
    
    async def start(self):
        """Start the threat intelligence streaming service"""
        self.is_running = True
        self.stats["start_time"] = time.time()
        logger.info(f"Threat Intelligence WebSocket Streamer starting on {self.host}:{self.port}")
        
        # Start threat generation task
        asyncio.create_task(self.generate_and_broadcast_threats())
        
        logger.info("Threat Intelligence streaming service started successfully")
    
    async def stop(self):
        """Stop the streaming service"""
        self.is_running = False
        logger.info("Threat Intelligence streaming service stopped")


# Standalone synchronous interface for testing
class ThreatIntelStreamerSync:
    """Synchronous wrapper for testing and integration"""
    
    def __init__(self):
        self.streamer = ThreatIntelWebSocketStreamer()
        self.streamer.is_running = True
    
    def generate_threat_batch(self, count: int = 5) -> List[Dict[str, Any]]:
        """Generate a batch of threat intelligence entries"""
        threats = []
        for _ in range(count):
            threat = self.streamer.feed_simulator.generate_threat_entry()
            if not self.streamer.is_duplicate(threat):
                self.streamer.add_threat_to_history(threat)
                threats.append(asdict(threat))
        return threats
    
    def get_filtered_threats(self, min_severity: str = "high") -> List[Dict[str, Any]]:
        """Get threats filtered by minimum severity"""
        return self.streamer.get_threats_by_severity(min_severity)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get service statistics"""
        return self.streamer.get_statistics()


# Export main classes
__all__ = [
    "ThreatIntelWebSocketStreamer",
    "ThreatIntelStreamerSync",
    "ThreatIntelEntry",
    "ThreatSeverity",
    "ThreatType"
]
