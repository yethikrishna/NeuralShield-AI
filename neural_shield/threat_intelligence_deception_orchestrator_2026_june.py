"""
NeuralShield AI - Threat Intelligence Deception Technology Orchestrator
Production-grade implementation for honeypot and deception technology management
This module provides:
1. Honeypot deployment and lifecycle management
2. Decoy asset creation and monitoring
3. Deception campaign orchestration
4. Attacker behavior tracking and analysis
5. Deception event correlation and alerting
6. Breadcrumb and honeytoken generation
7. Deception metrics and effectiveness reporting
8. Integration with threat intelligence feeds
"""
import json
import hmac
import hashlib
import logging
import asyncio
import ipaddress
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Any, Optional, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class HoneypotType(Enum):
    LOW_INTERACTION = "low_interaction"
    MEDIUM_INTERACTION = "medium_interaction"
    HIGH_INTERACTION = "high_interaction"
    RESEARCH = "research"


class HoneypotStatus(Enum):
    CREATED = "created"
    DEPLOYING = "deploying"
    ACTIVE = "active"
    MAINTENANCE = "maintenance"
    DISABLED = "disabled"
    DECOMMISSIONED = "decommissioned"


class DecoyType(Enum):
    FILE = "file"
    DATABASE_RECORD = "database_record"
    USER_ACCOUNT = "user_account"
    SERVICE = "service"
    NETWORK_ENDPOINT = "network_endpoint"
    DOCUMENT = "document"
    CREDENTIAL = "credential"
    API_KEY = "api_key"
    REGISTRY_KEY = "registry_key"
    CONFIG_ENTRY = "config_entry"


class DecoyStatus(Enum):
    PLACED = "placed"
    ACTIVE = "active"
    ACCESSED = "accessed"
    TRIGGERED = "triggered"
    REMOVED = "removed"
    EXPIRED = "expired"


class AttackPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    ENUMERATION = "enumeration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE = "persistence"
    C2_COMMUNICATION = "c2_communication"


class DeceptionEventType(Enum):
    HONEYPOT_PROBE = "honeypot_probe"
    HONEYPOT_CONNECTION = "honeypot_connection"
    DECOY_ACCESS = "decoy_access"
    HONEYTOKEN_TRIGGER = "honeytoken_trigger"
    CREDENTIAL_USE = "credential_use"
    FILE_ACCESS = "file_access"
    LATERAL_MOVEMENT_ATTEMPT = "lateral_movement_attempt"
    BRUTE_FORCE_ATTEMPT = "brute_force_attempt"
    EXPLOIT_ATTEMPT = "exploit_attempt"


class SeverityLevel(Enum):
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HoneypotInstance:
    honeypot_id: str
    name: str
    honeypot_type: HoneypotType
    ip_address: str
    port: int
    service: str
    status: HoneypotStatus
    created_at: datetime
    deployed_at: Optional[datetime] = None
    last_activity: Optional[datetime] = None
    location: str = "internal"
    tags: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    interaction_count: int = 0
    unique_attackers: Set[str] = field(default_factory=set)
    alerts_generated: int = 0


@dataclass
class DecoyAsset:
    decoy_id: str
    name: str
    decoy_type: DecoyType
    location: str
    status: DecoyStatus
    created_at: datetime
    placed_at: Optional[datetime] = None
    last_accessed: Optional[datetime] = None
    access_count: int = 0
    value: Optional[str] = None
    honeytoken: Optional[str] = None
    tags: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    access_log: List[Dict[str, Any]] = field(default_factory=list)
    expected_accessors: List[str] = field(default_factory=list)


@dataclass
class DeceptionEvent:
    event_id: str
    event_type: DeceptionEventType
    timestamp: datetime
    source_ip: str
    honeypot_id: Optional[str] = None
    decoy_id: Optional[str] = None
    attack_phase: Optional[AttackPhase] = None
    severity: SeverityLevel = SeverityLevel.MEDIUM
    raw_data: Dict[str, Any] = field(default_factory=dict)
    attacker_profile: Dict[str, Any] = field(default_factory=dict)
    indicators: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    correlated: bool = False
    alert_generated: bool = False


@dataclass
class AttackerProfile:
    attacker_id: str
    ip_address: str
    first_seen: datetime
    last_seen: datetime
    total_interactions: int = 0
    tactics_observed: List[str] = field(default_factory=list)
    techniques_observed: List[str] = field(default_factory=list)
    deception_targets: List[str] = field(default_factory=list)
    tools_observed: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    geolocation: Optional[Dict[str, str]] = None
    asn_info: Optional[Dict[str, Any]] = None
    reputation: Optional[str] = None
    tags: List[str] = field(default_factory=list)


@dataclass
class DeceptionCampaign:
    campaign_id: str
    name: str
    description: str
    start_date: datetime
    end_date: Optional[datetime] = None
    active: bool = True
    honeypots: List[str] = field(default_factory=list)
    decoys: List[str] = field(default_factory=list)
    objectives: List[str] = field(default_factory=list)
    metrics: Dict[str, Any] = field(default_factory=dict)
    created_by: str = "system"


class HoneypotBackend(ABC):
    """Abstract base class for honeypot deployment backends."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.initialized = False
    
    @abstractmethod
    def initialize(self) -> bool:
        """Initialize the backend."""
        pass
    
    @abstractmethod
    def deploy_honeypot(self, honeypot: HoneypotInstance) -> bool:
        """Deploy a honeypot instance."""
        pass
    
    @abstractmethod
    def stop_honeypot(self, honeypot_id: str) -> bool:
        """Stop a honeypot instance."""
        pass
    
    @abstractmethod
    def get_honeypot_logs(self, honeypot_id: str) -> List[Dict[str, Any]]:
        """Get interaction logs from honeypot."""
        pass


class MockHoneypotBackend(HoneypotBackend):
    """Mock honeypot backend for testing."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.honeypots: Dict[str, HoneypotInstance] = {}
        self.interaction_logs: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    
    def initialize(self) -> bool:
        self.initialized = True
        logger.info("Mock honeypot backend initialized")
        return True
    
    def deploy_honeypot(self, honeypot: HoneypotInstance) -> bool:
        if not self.initialized:
            return False
        self.honeypots[honeypot.honeypot_id] = honeypot
        # Generate some mock interaction logs
        self._generate_mock_interactions(honeypot.honeypot_id)
        return True
    
    def stop_honeypot(self, honeypot_id: str) -> bool:
        if honeypot_id in self.honeypots:
            self.honeypots[honeypot_id].status = HoneypotStatus.DISABLED
            return True
        return False
    
    def _generate_mock_interactions(self, honeypot_id: str) -> None:
        """Generate mock interaction data."""
        base_time = datetime.now(timezone.utc)
        attacker_ips = [
            f"192.168.100.{10 + i}" for i in range(5)
        ] + [
            f"10.255.255.{i}" for i in range(3)
        ]
        
        for i in range(20):
            interaction = {
                "timestamp": (base_time - timedelta(minutes=i * 15)).isoformat(),
                "source_ip": attacker_ips[i % len(attacker_ips)],
                "source_port": 10000 + i * 100,
                "protocol": ["TCP", "UDP"][i % 2],
                "payload_size": 64 + i * 32,
                "interaction_type": ["probe", "connection_attempt", "credential_attempt"][i % 3],
                "user_agent": f"Malicious-Scanner/{i}.0" if i % 3 == 0 else None,
            }
            self.interaction_logs[honeypot_id].append(interaction)
    
    def get_honeypot_logs(self, honeypot_id: str) -> List[Dict[str, Any]]:
        return self.interaction_logs.get(honeypot_id, [])


class DeceptionOrchestrator:
    """
    Production-grade Deception Technology Orchestrator.
    Manages honeypots, decoys, deception campaigns, and attacker profiling.
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.honeypots: Dict[str, HoneypotInstance] = {}
        self.decoys: Dict[str, DecoyAsset] = {}
        self.events: Dict[str, DeceptionEvent] = {}
        self.attackers: Dict[str, AttackerProfile] = {}
        self.campaigns: Dict[str, DeceptionCampaign] = {}
        self.backends: Dict[str, HoneypotBackend] = {}
        self.event_callbacks: List[Callable] = []
        self._initialize_backends()
        logger.info("Deception Technology Orchestrator initialized")
    
    def _initialize_backends(self) -> None:
        """Initialize honeypot deployment backends."""
        mock_backend = MockHoneypotBackend({})
        mock_backend.initialize()
        self.backends["mock"] = mock_backend
    
    def create_honeypot(
        self,
        name: str,
        honeypot_type: HoneypotType,
        ip_address: str,
        port: int,
        service: str,
        location: str = "internal",
        tags: Optional[List[str]] = None,
        config: Optional[Dict[str, Any]] = None,
    ) -> HoneypotInstance:
        """
        Create a new honeypot instance.
        
        Args:
            name: Honeypot display name
            honeypot_type: Level of interaction
            ip_address: Listening IP address
            port: Listening port
            service: Emulated service name
            location: Network location
            tags: Classification tags
            config: Additional configuration
            
        Returns:
            Created HoneypotInstance
        """
        honeypot_id = f"hp_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        
        honeypot = HoneypotInstance(
            honeypot_id=honeypot_id,
            name=name,
            honeypot_type=honeypot_type,
            ip_address=ip_address,
            port=port,
            service=service,
            status=HoneypotStatus.CREATED,
            created_at=now,
            location=location,
            tags=tags or [],
            config=config or {},
        )
        
        self.honeypots[honeypot_id] = honeypot
        logger.info(f"Created honeypot: {honeypot_id} - {name} ({service}:{port})")
        return honeypot
    
    def deploy_honeypot(self, honeypot_id: str, backend_id: str = "mock") -> bool:
        """
        Deploy a honeypot instance using specified backend.
        
        Args:
            honeypot_id: Honeypot to deploy
            backend_id: Deployment backend
            
        Returns:
            True if deployment successful
        """
        if honeypot_id not in self.honeypots:
            logger.error(f"Honeypot not found: {honeypot_id}")
            return False
        
        if backend_id not in self.backends:
            logger.error(f"Backend not found: {backend_id}")
            return False
        
        honeypot = self.honeypots[honeypot_id]
        honeypot.status = HoneypotStatus.DEPLOYING
        
        backend = self.backends[backend_id]
        if backend.deploy_honeypot(honeypot):
            honeypot.status = HoneypotStatus.ACTIVE
            honeypot.deployed_at = datetime.now(timezone.utc)
            logger.info(f"Deployed honeypot: {honeypot_id}")
            return True
        
        honeypot.status = HoneypotStatus.CREATED
        logger.error(f"Failed to deploy honeypot: {honeypot_id}")
        return False
    
    def disable_honeypot(self, honeypot_id: str) -> bool:
        """Disable an active honeypot."""
        if honeypot_id not in self.honeypots:
            return False
        
        honeypot = self.honeypots[honeypot_id]
        honeypot.status = HoneypotStatus.DISABLED
        logger.info(f"Disabled honeypot: {honeypot_id}")
        return True
    
    def create_decoy(
        self,
        name: str,
        decoy_type: DecoyType,
        location: str,
        value: Optional[str] = None,
        tags: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        expected_accessors: Optional[List[str]] = None,
    ) -> DecoyAsset:
        """
        Create a decoy asset.
        
        Args:
            name: Decoy name
            decoy_type: Type of decoy
            location: Placement location
            value: Decoy content/value
            tags: Classification tags
            metadata: Additional metadata
            expected_accessors: List of allowed/expected accessors
            
        Returns:
            Created DecoyAsset
        """
        decoy_id = f"decoy_{uuid.uuid4().hex[:12]}"
        now = datetime.now(timezone.utc)
        
        # Generate honeytoken
        honeytoken = self._generate_honeytoken(decoy_id, decoy_type)
        
        decoy = DecoyAsset(
            decoy_id=decoy_id,
            name=name,
            decoy_type=decoy_type,
            location=location,
            status=DecoyStatus.PLACED,
            created_at=now,
            placed_at=now,
            value=value,
            honeytoken=honeytoken,
            tags=tags or [],
            metadata=metadata or {},
            expected_accessors=expected_accessors or [],
        )
        
        self.decoys[decoy_id] = decoy
        logger.info(f"Created decoy: {decoy_id} - {name} ({decoy_type.value})")
        return decoy
    
    def _generate_honeytoken(self, decoy_id: str, decoy_type: DecoyType) -> str:
        """Generate a unique honeytoken for tracking."""
        token_data = f"{decoy_id}:{decoy_type.value}:{datetime.now(timezone.utc).isoformat()}"
        return hashlib.sha256(token_data.encode()).hexdigest()[:16]
    
    def trigger_decoy_access(
        self,
        decoy_id: str,
        accessor: str,
        source_ip: str,
        access_details: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """
        Record decoy access and generate deception event.
        
        Args:
            decoy_id: Accessed decoy ID
            accessor: Accessor identifier
            source_ip: Source IP address
            access_details: Additional access details
            
        Returns:
            event_id or None
        """
        if decoy_id not in self.decoys:
            logger.error(f"Decoy not found: {decoy_id}")
            return None
        
        decoy = self.decoys[decoy_id]
        decoy.status = DecoyStatus.ACCESSED
        decoy.last_accessed = datetime.now(timezone.utc)
        decoy.access_count += 1
        
        # Record access
        access_log = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "accessor": accessor,
            "source_ip": source_ip,
            "details": access_details or {},
        }
        decoy.access_log.append(access_log)
        
        # Check if unexpected accessor
        is_unexpected = accessor not in decoy.expected_accessors and decoy.expected_accessors
        
        # Create deception event
        event = self._create_deception_event(
            event_type=DeceptionEventType.DECOY_ACCESS,
            source_ip=source_ip,
            decoy_id=decoy_id,
            severity=SeverityLevel.HIGH if is_unexpected else SeverityLevel.MEDIUM,
            raw_data={
                "decoy_name": decoy.name,
                "decoy_type": decoy.decoy_type.value,
                "accessor": accessor,
                "is_unexpected": is_unexpected,
                **(access_details or {}),
            },
        )
        
        logger.info(
            f"Decoy access recorded: {decoy_id} by {accessor} from {source_ip}"
            f"{' (UNEXPECTED)' if is_unexpected else ''}"
        )
        
        return event.event_id
    
    def _create_deception_event(
        self,
        event_type: DeceptionEventType,
        source_ip: str,
        honeypot_id: Optional[str] = None,
        decoy_id: Optional[str] = None,
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        raw_data: Optional[Dict[str, Any]] = None,
    ) -> DeceptionEvent:
        """Create and store a deception event."""
        event_id = f"evt_{uuid.uuid4().hex[:12]}"
        
        event = DeceptionEvent(
            event_id=event_id,
            event_type=event_type,
            timestamp=datetime.now(timezone.utc),
            source_ip=source_ip,
            honeypot_id=honeypot_id,
            decoy_id=decoy_id,
            severity=severity,
            raw_data=raw_data or {},
        )
        
        self.events[event_id] = event
        
        # Update attacker profile
        self._update_attacker_profile(source_ip, event)
        
        # Update honeypot stats
        if honeypot_id and honeypot_id in self.honeypots:
            hp = self.honeypots[honeypot_id]
            hp.interaction_count += 1
            hp.unique_attackers.add(source_ip)
            hp.last_activity = event.timestamp
            hp.alerts_generated += 1
        
        # Trigger callbacks
        for callback in self.event_callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error(f"Event callback error: {e}")
        
        return event
    
    def _update_attacker_profile(self, ip_address: str, event: DeceptionEvent) -> None:
        """Update or create attacker profile based on event."""
        if ip_address not in self.attackers:
            self.attackers[ip_address] = AttackerProfile(
                attacker_id=f"attacker_{uuid.uuid4().hex[:12]}",
                ip_address=ip_address,
                first_seen=event.timestamp,
                last_seen=event.timestamp,
            )
        
        attacker = self.attackers[ip_address]
        attacker.last_seen = event.timestamp
        attacker.total_interactions += 1
        
        if event.honeypot_id and event.honeypot_id not in attacker.deception_targets:
            attacker.deception_targets.append(event.honeypot_id)
        
        if event.decoy_id and event.decoy_id not in attacker.deception_targets:
            attacker.deception_targets.append(event.decoy_id)
        
        # Calculate threat score based on activity
        attacker.threat_score = min(10.0, 1.0 + (attacker.total_interactions * 0.1))
    
    def poll_honeypot_events(self, honeypot_id: Optional[str] = None) -> int:
        """
        Poll honeypots for new interaction events.
        
        Args:
            honeypot_id: Specific honeypot to poll (all if None)
            
        Returns:
            Number of new events created
        """
        target_ids = [honeypot_id] if honeypot_id else list(self.honeypots.keys())
        new_events = 0
        
        for hp_id in target_ids:
            if hp_id not in self.honeypots:
                continue
            
            honeypot = self.honeypots[hp_id]
            if honeypot.status != HoneypotStatus.ACTIVE:
                continue
            
            # Get logs from backend
            for backend in self.backends.values():
                logs = backend.get_honeypot_logs(hp_id)
                for log in logs[-5:]:  # Process recent logs
                    event_type = self._map_log_to_event_type(log.get("interaction_type", "probe"))
                    self._create_deception_event(
                        event_type=event_type,
                        source_ip=log.get("source_ip", "unknown"),
                        honeypot_id=hp_id,
                        severity=self._determine_event_severity(event_type),
                        raw_data=log,
                    )
                    new_events += 1
        
        logger.info(f"Polled honeypots, created {new_events} new events")
        return new_events
    
    def _map_log_to_event_type(self, interaction_type: str) -> DeceptionEventType:
        """Map log interaction type to deception event type."""
        mapping = {
            "probe": DeceptionEventType.HONEYPOT_PROBE,
            "connection_attempt": DeceptionEventType.HONEYPOT_CONNECTION,
            "credential_attempt": DeceptionEventType.BRUTE_FORCE_ATTEMPT,
        }
        return mapping.get(interaction_type, DeceptionEventType.HONEYPOT_PROBE)
    
    def _determine_event_severity(self, event_type: DeceptionEventType) -> SeverityLevel:
        """Determine severity level based on event type."""
        severity_mapping = {
            DeceptionEventType.HONEYPOT_PROBE: SeverityLevel.LOW,
            DeceptionEventType.HONEYPOT_CONNECTION: SeverityLevel.MEDIUM,
            DeceptionEventType.DECOY_ACCESS: SeverityLevel.HIGH,
            DeceptionEventType.HONEYTOKEN_TRIGGER: SeverityLevel.HIGH,
            DeceptionEventType.CREDENTIAL_USE: SeverityLevel.CRITICAL,
            DeceptionEventType.LATERAL_MOVEMENT_ATTEMPT: SeverityLevel.CRITICAL,
            DeceptionEventType.BRUTE_FORCE_ATTEMPT: SeverityLevel.HIGH,
            DeceptionEventType.EXPLOIT_ATTEMPT: SeverityLevel.CRITICAL,
        }
        return severity_mapping.get(event_type, SeverityLevel.MEDIUM)
    
    def create_campaign(
        self,
        name: str,
        description: str,
        objectives: Optional[List[str]] = None,
        honeypot_ids: Optional[List[str]] = None,
        decoy_ids: Optional[List[str]] = None,
    ) -> DeceptionCampaign:
        """
        Create a deception campaign.
        
        Args:
            name: Campaign name
            description: Detailed description
            objectives: List of campaign objectives
            honeypot_ids: Honeypots to include
            decoy_ids: Decoys to include
            
        Returns:
            Created DeceptionCampaign
        """
        campaign_id = f"camp_{uuid.uuid4().hex[:12]}"
        
        campaign = DeceptionCampaign(
            campaign_id=campaign_id,
            name=name,
            description=description,
            start_date=datetime.now(timezone.utc),
            honeypots=honeypot_ids or [],
            decoys=decoy_ids or [],
            objectives=objectives or [],
        )
        
        self.campaigns[campaign_id] = campaign
        logger.info(f"Created deception campaign: {campaign_id} - {name}")
        return campaign
    
    def get_attacker_profile(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get detailed attacker profile."""
        if ip_address not in self.attackers:
            return None
        
        attacker = self.attackers[ip_address]
        return {
            "attacker_id": attacker.attacker_id,
            "ip_address": attacker.ip_address,
            "first_seen": attacker.first_seen.isoformat(),
            "last_seen": attacker.last_seen.isoformat(),
            "total_interactions": attacker.total_interactions,
            "threat_score": round(attacker.threat_score, 2),
            "deception_targets_hit": len(attacker.deception_targets),
            "tactics_observed": attacker.tactics_observed,
            "techniques_observed": attacker.techniques_observed,
        }
    
    def get_deception_metrics(self) -> Dict[str, Any]:
        """Get comprehensive deception technology metrics."""
        active_honeypots = sum(
            1 for hp in self.honeypots.values()
            if hp.status == HoneypotStatus.ACTIVE
        )
        active_decoys = sum(
            1 for d in self.decoys.values()
            if d.status in [DecoyStatus.PLACED, DecoyStatus.ACTIVE, DecoyStatus.ACCESSED]
        )
        decoys_triggered = sum(
            1 for d in self.decoys.values()
            if d.status == DecoyStatus.TRIGGERED or d.access_count > 0
        )
        total_interactions = sum(hp.interaction_count for hp in self.honeypots.values())
        unique_attackers = len(self.attackers)
        
        high_risk_attackers = sum(
            1 for a in self.attackers.values()
            if a.threat_score >= 7.0
        )
        
        return {
            "overview": {
                "active_honeypots": active_honeypots,
                "total_honeypots": len(self.honeypots),
                "active_decoys": active_decoys,
                "total_decoys": len(self.decoys),
                "decoys_triggered": decoys_triggered,
                "active_campaigns": sum(1 for c in self.campaigns.values() if c.active),
            },
            "activity": {
                "total_deception_events": len(self.events),
                "honeypot_interactions": total_interactions,
                "unique_attackers_tracked": unique_attackers,
                "high_risk_attackers": high_risk_attackers,
            },
            "by_type": {
                "honeypot_types": self._count_by_type(
                    list(self.honeypots.values()), "honeypot_type"
                ),
                "decoy_types": self._count_by_type(
                    list(self.decoys.values()), "decoy_type"
                ),
                "event_types": self._count_by_type(
                    list(self.events.values()), "event_type"
                ),
            },
            "effectiveness": {
                "decoy_trigger_rate": (
                    round(decoys_triggered / active_decoys * 100, 1)
                    if active_decoys > 0 else 0
                ),
                "average_attacker_threat_score": (
                    round(sum(a.threat_score for a in self.attackers.values()) / len(self.attackers), 2)
                    if self.attackers else 0
                ),
            },
        }
    
    def _count_by_type(self, items: List[Any], type_attr: str) -> Dict[str, int]:
        """Count items by enum type."""
        counts: Dict[str, int] = defaultdict(int)
        for item in items:
            type_val = getattr(item, type_attr)
            counts[type_val.value] += 1
        return dict(counts)
    
    def list_honeypots(self) -> List[Dict[str, Any]]:
        """List all honeypots with summary info."""
        return [
            {
                "honeypot_id": hp.honeypot_id,
                "name": hp.name,
                "type": hp.honeypot_type.value,
                "ip_address": hp.ip_address,
                "port": hp.port,
                "service": hp.service,
                "status": hp.status.value,
                "interactions": hp.interaction_count,
                "unique_attackers": len(hp.unique_attackers),
            }
            for hp in self.honeypots.values()
        ]
    
    def list_decoys(self) -> List[Dict[str, Any]]:
        return [
            {
                "decoy_id": d.decoy_id,
                "name": d.name,
                "type": d.decoy_type.value,
                "location": d.location,
                "status": d.status.value,
                "access_count": d.access_count,
                "last_accessed": d.last_accessed.isoformat() if d.last_accessed else None,
            }
            for d in self.decoys.values()
        ]
    
    def list_events(
        self,
        limit: int = 100,
        min_severity: Optional[SeverityLevel] = None,
    ) -> List[Dict[str, Any]]:
        """List deception events."""
        events_list = list(self.events.values())
        events_list.sort(key=lambda e: e.timestamp, reverse=True)
        
        if min_severity:
            severity_order = [
                SeverityLevel.INFORMATIONAL,
                SeverityLevel.LOW,
                SeverityLevel.MEDIUM,
                SeverityLevel.HIGH,
                SeverityLevel.CRITICAL,
            ]
            min_idx = severity_order.index(min_severity)
            events_list = [
                e for e in events_list
                if severity_order.index(e.severity) >= min_idx
            ]
        
        return [
            {
                "event_id": e.event_id,
                "event_type": e.event_type.value,
                "timestamp": e.timestamp.isoformat(),
                "source_ip": e.source_ip,
                "severity": e.severity.value,
                "honeypot_id": e.honeypot_id,
                "decoy_id": e.decoy_id,
            }
            for e in events_list[:limit]
        ]
