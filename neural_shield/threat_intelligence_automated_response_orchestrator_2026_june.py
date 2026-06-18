"""
Threat Intelligence Automated Response Orchestrator
June 18, 2026 - Production Release

Automated security incident response orchestration:
- Threat detection correlation and prioritization
- Automated response playbook execution
- Response action templating
- Incident severity assessment
- Mitigation workflow management
- Response effectiveness tracking
"""

import time
import uuid
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Set
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading


class IncidentSeverity(str, Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class ResponseStatus(str, Enum):
    """Response execution status"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial_success"
    CANCELLED = "cancelled"


class ResponseActionType(str, Enum):
    """Types of automated response actions"""
    BLOCK_IP = "block_ip_address"
    BLOCK_DOMAIN = "block_domain"
    ISOLATE_HOST = "isolate_host"
    QUARANTINE_FILE = "quarantine_file"
    RESET_PASSWORD = "reset_user_password"
    REVOKE_TOKEN = "revoke_access_token"
    ENABLE_MFA = "force_enable_mfa"
    NETWORK_ISOLATION = "enable_network_isolation"
    ALERT_ADMIN = "alert_administrators"
    LOG_COLLECTION = "collect_forensic_logs"
    SNAPSHOT_VM = "create_vm_snapshot"
    DISABLE_USER = "disable_user_account"


class PlaybookTrigger(str, Enum):
    """Conditions that trigger response playbooks"""
    MALWARE_DETECTED = "malware_detected"
    PHISHING_ATTACK = "phishing_attack"
    BRUTE_FORCE = "brute_force_attack"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    RANSOMWARE = "ransomware_activity"
    IOC_MATCH = "ioc_reputation_match"
    ANOMALY_DETECTED = "anomaly_detected"


@dataclass
class ThreatIndicator:
    """Single threat indicator from detection"""
    indicator_type: str
    value: str
    confidence: float  # 0.0 - 1.0
    source: str
    first_seen: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseAction:
    """Single response action to execute"""
    action_id: str
    action_type: ResponseActionType
    target: str
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: ResponseStatus = ResponseStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    result: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    duration_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type.value,
            "target": self.target,
            "status": self.status.value,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_seconds": round(self.duration_seconds, 3),
            "error": self.error_message
        }


@dataclass
class SecurityIncident:
    """Security incident with associated response"""
    incident_id: str
    title: str
    description: str
    severity: IncidentSeverity
    indicators: List[ThreatIndicator] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    response_actions: List[ResponseAction] = field(default_factory=list)
    playbook_triggered: Optional[PlaybookTrigger] = None
    created_at: datetime = field(default_factory=datetime.now)
    resolved_at: Optional[datetime] = None
    mitigated: bool = False
    notes: List[str] = field(default_factory=list)

    def summary(self) -> Dict[str, Any]:
        status_counts = defaultdict(int)
        for action in self.response_actions:
            status_counts[action.status.value] += 1

        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value,
            "indicators_count": len(self.indicators),
            "affected_assets_count": len(self.affected_assets),
            "response_actions": dict(status_counts),
            "mitigated": self.mitigated,
            "created_at": self.created_at.isoformat()
        }


@dataclass
class ResponsePlaybook:
    """Automated response playbook definition"""
    playbook_id: str
    name: str
    description: str
    trigger: PlaybookTrigger
    min_severity: IncidentSeverity
    actions: List[ResponseActionType]
    auto_execute: bool = False
    require_approval: bool = True
    cooldown_minutes: int = 60

    def should_trigger(self, severity: IncidentSeverity) -> bool:
        """Check if playbook should trigger for given severity"""
        severity_order = {
            IncidentSeverity.INFORMATIONAL: 0,
            IncidentSeverity.LOW: 1,
            IncidentSeverity.MEDIUM: 2,
            IncidentSeverity.HIGH: 3,
            IncidentSeverity.CRITICAL: 4
        }
        return severity_order[severity] >= severity_order[self.min_severity]


class AutomatedResponseOrchestrator:
    """
    Production-grade automated security response orchestrator.
    
    Features:
    - Threat correlation and incident creation
    - Playbook-based response automation
    - Action execution and tracking
    - Cooldown and rate limiting
    - Incident lifecycle management
    - Response effectiveness metrics
    - Thread-safe operation
    """

    # Default response playbooks
    DEFAULT_PLAYBOOKS = [
        ResponsePlaybook(
            playbook_id="playbook_ransomware",
            name="Ransomware Containment",
            description="Immediate isolation and snapshot for ransomware",
            trigger=PlaybookTrigger.RANSOMWARE,
            min_severity=IncidentSeverity.HIGH,
            actions=[
                ResponseActionType.SNAPSHOT_VM,
                ResponseActionType.NETWORK_ISOLATION,
                ResponseActionType.QUARANTINE_FILE,
                ResponseActionType.ALERT_ADMIN
            ],
            auto_execute=True,
            require_approval=False,
            cooldown_minutes=30
        ),
        ResponsePlaybook(
            playbook_id="playbook_bruteforce",
            name="Brute Force Mitigation",
            description="Block sources and alert on brute force attacks",
            trigger=PlaybookTrigger.BRUTE_FORCE,
            min_severity=IncidentSeverity.MEDIUM,
            actions=[
                ResponseActionType.BLOCK_IP,
                ResponseActionType.ALERT_ADMIN
            ],
            auto_execute=True,
            require_approval=False,
            cooldown_minutes=15
        ),
        ResponsePlaybook(
            playbook_id="playbook_phishing",
            name="Phishing Response",
            description="Block domains and notify users",
            trigger=PlaybookTrigger.PHISHING_ATTACK,
            min_severity=IncidentSeverity.MEDIUM,
            actions=[
                ResponseActionType.BLOCK_DOMAIN,
                ResponseActionType.ALERT_ADMIN
            ],
            auto_execute=True,
            require_approval=False,
            cooldown_minutes=10
        ),
        ResponsePlaybook(
            playbook_id="playbook_ioc_match",
            name="IOC Match Response",
            description="Standard response for known IOC matches",
            trigger=PlaybookTrigger.IOC_MATCH,
            min_severity=IncidentSeverity.LOW,
            actions=[
                ResponseActionType.LOG_COLLECTION,
                ResponseActionType.ALERT_ADMIN
            ],
            auto_execute=False,
            require_approval=True,
            cooldown_minutes=60
        )
    ]

    def __init__(self,
                 enable_auto_response: bool = True,
                 max_actions_per_minute: int = 10,
                 enable_playbook_cooldown: bool = True):
        self.enable_auto_response = enable_auto_response
        self.max_actions_per_minute = max_actions_per_minute
        self.enable_playbook_cooldown = enable_playbook_cooldown
        
        # Incident tracking
        self._incidents: Dict[str, SecurityIncident] = {}
        self._playbooks: Dict[str, ResponsePlaybook] = {p.playbook_id: p for p in self.DEFAULT_PLAYBOOKS}
        
        # Execution tracking
        self._action_history: deque = deque(maxlen=1000)
        self._playbook_cooldowns: Dict[str, datetime] = {}
        self._rate_limit_window: deque = deque(maxlen=max_actions_per_minute)
        
        # Statistics
        self._stats = {
            "incidents_created": 0,
            "actions_executed": 0,
            "playbooks_triggered": 0,
            "incidents_mitigated": 0,
            "actions_failed": 0
        }
        
        # Thread safety
        self._lock = threading.Lock()

    def _generate_id(self, prefix: str = "id") -> str:
        """Generate unique identifier"""
        return f"{prefix}_{uuid.uuid4().hex[:12]}"

    def _calculate_severity(self, indicators: List[ThreatIndicator]) -> IncidentSeverity:
        """Calculate overall incident severity from indicators"""
        if not indicators:
            return IncidentSeverity.INFORMATIONAL

        avg_confidence = sum(i.confidence for i in indicators) / len(indicators)
        max_confidence = max(i.confidence for i in indicators)

        # Weighted severity calculation
        if max_confidence >= 0.95 and len(indicators) >= 3:
            return IncidentSeverity.CRITICAL
        elif max_confidence >= 0.85 and len(indicators) >= 2:
            return IncidentSeverity.HIGH
        elif avg_confidence >= 0.7:
            return IncidentSeverity.MEDIUM
        elif avg_confidence >= 0.4:
            return IncidentSeverity.LOW
        else:
            return IncidentSeverity.INFORMATIONAL

    def _check_rate_limit(self) -> bool:
        """Check if we're within rate limits"""
        now = time.time()
        one_minute_ago = now - 60
        
        # Remove old entries
        while self._rate_limit_window and self._rate_limit_window[0] < one_minute_ago:
            self._rate_limit_window.popleft()
        
        if len(self._rate_limit_window) >= self.max_actions_per_minute:
            return False
        
        self._rate_limit_window.append(now)
        return True

    def _check_playbook_cooldown(self, playbook_id: str) -> bool:
        """Check if playbook is in cooldown"""
        if not self.enable_playbook_cooldown:
            return True
        
        if playbook_id not in self._playbook_cooldowns:
            return True
        
        cooldown_end = self._playbook_cooldowns[playbook_id]
        return datetime.now() >= cooldown_end

    def _simulate_action_execution(self, action: ResponseAction) -> ResponseAction:
        """
        Simulate response action execution (production would call real APIs).
        Returns action with execution results.
        """
        action.started_at = datetime.now()
        action.status = ResponseStatus.IN_PROGRESS
        
        # Simulate execution time
        execution_time = 0.05 + (hash(action.action_id) % 50) / 100
        time.sleep(execution_time)
        
        # Deterministic success/failure based on hash
        success_hash = int(hashlib.md5(action.action_id.encode()).hexdigest(), 16)
        success_rate = 0.92  # 92% success rate
        
        if success_hash % 100 < success_rate * 100:
            action.status = ResponseStatus.COMPLETED
            action.result = {
                "success": True,
                "execution_node": f"responder_{success_hash % 8:03d}",
                "details": f"Action {action.action_type.value} applied to {action.target}"
            }
        else:
            action.status = ResponseStatus.FAILED
            action.error_message = f"Simulated execution failure for testing"
            with self._lock:
                self._stats["actions_failed"] += 1
        
        action.completed_at = datetime.now()
        action.duration_seconds = execution_time
        
        return action

    def create_incident(self,
                        title: str,
                        description: str,
                        indicators: List[Dict[str, Any]],
                        affected_assets: List[str] = None,
                        trigger_type: PlaybookTrigger = None) -> SecurityIncident:
        """
        Create a new security incident from threat indicators.
        
        Args:
            title: Incident title
            description: Incident description
            indicators: List of threat indicator dicts
            affected_assets: List of affected asset identifiers
            trigger_type: Optional playbook trigger
            
        Returns:
            Created SecurityIncident
        """
        # Parse indicators
        threat_indicators = [
            ThreatIndicator(
                indicator_type=i.get("type", "unknown"),
                value=i.get("value", ""),
                confidence=i.get("confidence", 0.5),
                source=i.get("source", "manual")
            )
            for i in indicators
        ]

        # Calculate severity
        severity = self._calculate_severity(threat_indicators)

        incident = SecurityIncident(
            incident_id=self._generate_id("incident"),
            title=title,
            description=description,
            severity=severity,
            indicators=threat_indicators,
            affected_assets=affected_assets or [],
            playbook_triggered=trigger_type
        )

        with self._lock:
            self._incidents[incident.incident_id] = incident
            self._stats["incidents_created"] += 1

        # Auto-trigger playbooks if enabled
        if self.enable_auto_response and trigger_type:
            self.trigger_playbooks(incident.incident_id, trigger_type)

        return incident

    def trigger_playbooks(self, incident_id: str, trigger: PlaybookTrigger) -> List[ResponseAction]:
        """
        Trigger matching response playbooks for an incident.
        
        Args:
            incident_id: Target incident ID
            trigger: Trigger condition
            
        Returns:
            List of created response actions
        """
        if incident_id not in self._incidents:
            return []

        incident = self._incidents[incident_id]
        created_actions = []

        for playbook in self._playbooks.values():
            if playbook.trigger != trigger:
                continue

            if not playbook.should_trigger(incident.severity):
                continue

            if not self._check_playbook_cooldown(playbook.playbook_id):
                continue

            # Create actions from playbook
            for action_type in playbook.actions:
                if not self._check_rate_limit():
                    break

                target = incident.affected_assets[0] if incident.affected_assets else "unknown"
                
                action = ResponseAction(
                    action_id=self._generate_id("action"),
                    action_type=action_type,
                    target=target
                )

                if playbook.auto_execute and not playbook.require_approval:
                    action = self._simulate_action_execution(action)
                    with self._lock:
                        self._stats["actions_executed"] += 1

                incident.response_actions.append(action)
                created_actions.append(action)
                self._action_history.append(action)

            # Set cooldown
            if self.enable_playbook_cooldown:
                self._playbook_cooldowns[playbook.playbook_id] = (
                    datetime.now() + timedelta(minutes=playbook.cooldown_minutes)
                )

            with self._lock:
                self._stats["playbooks_triggered"] += 1

        return created_actions

    def execute_action(self, incident_id: str, action_id: str) -> Optional[ResponseAction]:
        """Execute a specific pending response action"""
        if incident_id not in self._incidents:
            return None

        incident = self._incidents[incident_id]
        
        for action in incident.response_actions:
            if action.action_id == action_id and action.status == ResponseStatus.PENDING:
                if not self._check_rate_limit():
                    action.status = ResponseStatus.FAILED
                    action.error_message = "Rate limit exceeded"
                    return action

                executed = self._simulate_action_execution(action)
                with self._lock:
                    self._stats["actions_executed"] += 1
                return executed

        return None

    def mark_incident_mitigated(self, incident_id: str, notes: str = None) -> bool:
        """Mark an incident as successfully mitigated"""
        if incident_id not in self._incidents:
            return False

        incident = self._incidents[incident_id]
        incident.mitigated = True
        incident.resolved_at = datetime.now()
        if notes:
            incident.notes.append(notes)

        with self._lock:
            self._stats["incidents_mitigated"] += 1

        return True

    def get_incident(self, incident_id: str) -> Optional[SecurityIncident]:
        """Get incident by ID"""
        return self._incidents.get(incident_id)

    def get_active_incidents(self, min_severity: IncidentSeverity = None) -> List[SecurityIncident]:
        """Get all unresolved incidents"""
        incidents = [
            i for i in self._incidents.values()
            if not i.mitigated
        ]
        
        if min_severity:
            severity_order = {
                IncidentSeverity.INFORMATIONAL: 0,
                IncidentSeverity.LOW: 1,
                IncidentSeverity.MEDIUM: 2,
                IncidentSeverity.HIGH: 3,
                IncidentSeverity.CRITICAL: 4
            }
            incidents = [
                i for i in incidents
                if severity_order[i.severity] >= severity_order[min_severity]
            ]

        return sorted(incidents, key=lambda i: i.created_at, reverse=True)

    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics"""
        with self._lock:
            return {
                **self._stats,
                "active_incidents": len(self.get_active_incidents()),
                "total_incidents": len(self._incidents),
                "mitigation_rate": (
                    self._stats["incidents_mitigated"] / self._stats["incidents_created"]
                    if self._stats["incidents_created"] > 0 else 0.0
                ),
                "action_success_rate": (
                    (self._stats["actions_executed"] - self._stats["actions_failed"]) / self._stats["actions_executed"]
                    if self._stats["actions_executed"] > 0 else 1.0
                ),
                "playbooks_available": len(self._playbooks)
            }

    def register_custom_playbook(self, playbook: ResponsePlaybook) -> None:
        """Register a custom response playbook"""
        with self._lock:
            self._playbooks[playbook.playbook_id] = playbook


def create_response_orchestrator(**kwargs) -> AutomatedResponseOrchestrator:
    """Factory function to create Automated Response Orchestrator"""
    return AutomatedResponseOrchestrator(**kwargs)


if __name__ == "__main__":
    # Demo usage
    orchestrator = create_response_orchestrator()
    
    print("=" * 60)
    print("THREAT INTELLIGENCE AUTOMATED RESPONSE ORCHESTRATOR - DEMO")
    print("=" * 60)

    # Create test incident
    test_indicators = [
        {"type": "ipv4", "value": "192.168.1.100", "confidence": 0.95, "source": "ids"},
        {"type": "domain", "value": "malicious-domain.xyz", "confidence": 0.88, "source": "dns"},
        {"type": "sha256", "value": "e3b0c44298fc1c149afbf4c8996fb924", "confidence": 0.92, "source": "edr"}
    ]

    incident = orchestrator.create_incident(
        title="Potential Ransomware Infection Detected",
        description="Multiple IOCs matching known ransomware signatures",
        indicators=test_indicators,
        affected_assets=["workstation-42", "fileserver-01"],
        trigger_type=PlaybookTrigger.RANSOMWARE
    )

    print(f"\nINCIDENT CREATED: {incident.incident_id}")
    print(f"SEVERITY: {incident.severity.value.upper()}")
    print(f"INDICATORS: {len(incident.indicators)}")
    print(f"AFFECTED ASSETS: {len(incident.affected_assets)}")

    print("\n--- RESPONSE ACTIONS ---")
    for action in incident.response_actions:
        print(f"  [{action.status.value.upper()}] {action.action_type.value} -> {action.target}")
        if action.duration_seconds > 0:
            print(f"       Executed in {action.duration_seconds:.3f}s")

    # Mark as mitigated
    orchestrator.mark_incident_mitigated(
        incident.incident_id,
        notes="Ransomware successfully contained via automated response"
    )

    print(f"\n{'-' * 60}")
    print("STATISTICS:")
    stats = orchestrator.get_statistics()
    for key, value in stats.items():
        if isinstance(value, float):
            print(f"  {key}: {value:.2%}")
        else:
            print(f"  {key}: {value}")
