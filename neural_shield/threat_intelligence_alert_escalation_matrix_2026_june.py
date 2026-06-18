"""
Threat Intelligence Alert Escalation Matrix Manager
Production-grade alert severity classification, SLA tracking, and escalation path management

This module provides:
1. Multi-level severity classification (CRITICAL, HIGH, MEDIUM, LOW, INFO)
2. SLA (Service Level Agreement) tracking with timeout monitoring
3. Configurable escalation paths based on severity, time, and responder availability
4. Alert aging and auto-escalation policies
5. On-call rotation integration
6. Escalation history audit logging
"""

import asyncio
import logging
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict
import uuid

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class AlertSeverity(Enum):
    """Standardized alert severity levels following NIST SP 800-61"""
    CRITICAL = "CRITICAL"    # Immediate business impact, active breach
    HIGH = "HIGH"           # Significant risk, requires urgent attention
    MEDIUM = "MEDIUM"       # Moderate risk, requires timely response
    LOW = "LOW"            # Minor risk, routine handling
    INFO = "INFO"          # Informational, no immediate action


class EscalationStatus(Enum):
    PENDING = "PENDING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    ESCALATED = "ESCALATED"
    RESOLVED = "RESOLVED"
    AUTO_ESCALATED = "AUTO_ESCALATED"


@dataclass
class SLAPolicy:
    """SLA Policy definition for each severity level"""
    severity: AlertSeverity
    acknowledge_timeout_minutes: int
    first_response_timeout_minutes: int
    resolution_timeout_minutes: int
    auto_escalate_after_minutes: int
    
    def get_timeout_seconds(self, phase: str) -> int:
        """Get timeout in seconds for a specific phase"""
        mapping = {
            "acknowledge": self.acknowledge_timeout_minutes * 60,
            "first_response": self.first_response_timeout_minutes * 60,
            "resolution": self.resolution_timeout_minutes * 60,
            "auto_escalate": self.auto_escalate_after_minutes * 60
        }
        return mapping.get(phase, 3600)


@dataclass
class Responder:
    """Security operations responder definition"""
    id: str
    name: str
    email: str
    phone: str
    role: str
    escalation_level: int  # 1 = L1, 2 = L2, 3 = L3/Manager, 4 = Executive
    is_on_call: bool = False
    notification_preferences: Dict[str, bool] = field(default_factory=dict)


@dataclass
class EscalationStep:
    """Single step in an escalation path"""
    level: int
    responder_ids: List[str]
    notification_channels: List[str]  # email, slack, sms, phone
    delay_minutes: int = 0
    require_acknowledgement: bool = True


@dataclass
class AlertEscalationRecord:
    """Record of an alert's escalation history"""
    escalation_id: str
    alert_id: str
    timestamp: datetime
    from_level: int
    to_level: int
    reason: str
    escalated_by: str  # "system" or responder ID
    status: EscalationStatus
    sla_breached: bool = False


class EscalationMatrix:
    """Defines escalation paths based on severity and organizational structure"""
    
    DEFAULT_SLA_POLICIES = {
        AlertSeverity.CRITICAL: SLAPolicy(
            severity=AlertSeverity.CRITICAL,
            acknowledge_timeout_minutes=5,
            first_response_timeout_minutes=15,
            resolution_timeout_minutes=240,
            auto_escalate_after_minutes=10
        ),
        AlertSeverity.HIGH: SLAPolicy(
            severity=AlertSeverity.HIGH,
            acknowledge_timeout_minutes=15,
            first_response_timeout_minutes=30,
            resolution_timeout_minutes=480,
            auto_escalate_after_minutes=30
        ),
        AlertSeverity.MEDIUM: SLAPolicy(
            severity=AlertSeverity.MEDIUM,
            acknowledge_timeout_minutes=60,
            first_response_timeout_minutes=120,
            resolution_timeout_minutes=1440,
            auto_escalate_after_minutes=120
        ),
        AlertSeverity.LOW: SLAPolicy(
            severity=AlertSeverity.LOW,
            acknowledge_timeout_minutes=240,
            first_response_timeout_minutes=480,
            resolution_timeout_minutes=4320,
            auto_escalate_after_minutes=480
        ),
        AlertSeverity.INFO: SLAPolicy(
            severity=AlertSeverity.INFO,
            acknowledge_timeout_minutes=1440,
            first_response_timeout_minutes=2880,
            resolution_timeout_minutes=10080,
            auto_escalate_after_minutes=2880
        )
    }
    
    def __init__(self):
        self.sla_policies: Dict[AlertSeverity, SLAPolicy] = self.DEFAULT_SLA_POLICIES.copy()
        self.responders: Dict[str, Responder] = {}
        self.escalation_paths: Dict[AlertSeverity, List[EscalationStep]] = {}
        self._setup_default_escalation_paths()
        self.on_call_rotation: Dict[int, List[str]] = defaultdict(list)  # level -> responder_ids
    
    def _setup_default_escalation_paths(self) -> None:
        """Setup default escalation paths based on standard SOC structure"""
        # Critical: L1 -> L2 -> L3 -> Executive
        self.escalation_paths[AlertSeverity.CRITICAL] = [
            EscalationStep(level=1, responder_ids=[], notification_channels=["slack", "sms"], delay_minutes=0),
            EscalationStep(level=2, responder_ids=[], notification_channels=["slack", "sms", "phone"], delay_minutes=10),
            EscalationStep(level=3, responder_ids=[], notification_channels=["slack", "sms", "phone", "email"], delay_minutes=30),
            EscalationStep(level=4, responder_ids=[], notification_channels=["email", "phone"], delay_minutes=60)
        ]
        
        # High: L1 -> L2 -> L3
        self.escalation_paths[AlertSeverity.HIGH] = [
            EscalationStep(level=1, responder_ids=[], notification_channels=["slack", "email"], delay_minutes=0),
            EscalationStep(level=2, responder_ids=[], notification_channels=["slack", "sms"], delay_minutes=30),
            EscalationStep(level=3, responder_ids=[], notification_channels=["slack", "sms", "email"], delay_minutes=90)
        ]
        
        # Medium: L1 -> L2
        self.escalation_paths[AlertSeverity.MEDIUM] = [
            EscalationStep(level=1, responder_ids=[], notification_channels=["slack", "email"], delay_minutes=0),
            EscalationStep(level=2, responder_ids=[], notification_channels=["slack", "email"], delay_minutes=120)
        ]
        
        # Low: L1 only
        self.escalation_paths[AlertSeverity.LOW] = [
            EscalationStep(level=1, responder_ids=[], notification_channels=["email"], delay_minutes=0)
        ]
        
        # Info: No escalation
        self.escalation_paths[AlertSeverity.INFO] = [
            EscalationStep(level=1, responder_ids=[], notification_channels=["email"], delay_minutes=0)
        ]
    
    def add_responder(self, responder: Responder) -> None:
        """Add a responder to the matrix"""
        self.responders[responder.id] = responder
        self.on_call_rotation[responder.escalation_level].append(responder.id)
    
    def get_on_call_responders(self, level: int) -> List[Responder]:
        """Get currently on-call responders for a level"""
        responder_ids = self.on_call_rotation.get(level, [])
        return [
            self.responders[rid] for rid in responder_ids
            if rid in self.responders and self.responders[rid].is_on_call
        ]
    
    def get_escalation_path(self, severity: AlertSeverity) -> List[EscalationStep]:
        """Get the escalation path for a given severity"""
        return self.escalation_paths.get(severity, self.escalation_paths[AlertSeverity.MEDIUM])
    
    def get_sla_policy(self, severity: AlertSeverity) -> SLAPolicy:
        """Get SLA policy for a given severity"""
        return self.sla_policies.get(severity, self.DEFAULT_SLA_POLICIES[AlertSeverity.MEDIUM])


class AlertEscalationManager:
    """
    Main manager class for alert escalation handling
    
    Features:
    - Track alert lifecycle with timestamps
    - Monitor SLA compliance
    - Auto-escalate on SLA breach
    - Maintain escalation history
    - Notification dispatch
    """
    
    def __init__(self, matrix: Optional[EscalationMatrix] = None):
        self.matrix = matrix or EscalationMatrix()
        self.active_alerts: Dict[str, Dict[str, Any]] = {}
        self.escalation_history: List[AlertEscalationRecord] = []
        self.notification_callbacks: List[Callable] = []
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
    
    def register_notification_callback(self, callback: Callable) -> None:
        """Register a callback for notification dispatch"""
        self.notification_callbacks.append(callback)
    
    def register_alert(self, alert_id: str, severity: AlertSeverity, 
                      title: str, description: str, source: str) -> Dict[str, Any]:
        """
        Register a new alert and start escalation process
        
        Returns: Alert tracking data
        """
        now = datetime.utcnow()
        sla_policy = self.matrix.get_sla_policy(severity)
        
        alert_data = {
            "alert_id": alert_id,
            "severity": severity,
            "title": title,
            "description": description,
            "source": source,
            "created_at": now,
            "current_level": 1,
            "status": EscalationStatus.PENDING,
            "acknowledged_at": None,
            "acknowledged_by": None,
            "first_response_at": None,
            "resolved_at": None,
            "last_escalated_at": now,
            "escalation_count": 0,
            "sla_policy": sla_policy,
            "sla_breaches": [],
            "assigned_responders": []
        }
        
        self.active_alerts[alert_id] = alert_data
        
        # Initial notification
        self._dispatch_notification(alert_data, "initial")
        
        logger.info(f"Alert {alert_id} registered with severity {severity.value}")
        return alert_data
    
    def acknowledge_alert(self, alert_id: str, responder_id: str) -> bool:
        """Acknowledge an alert, stopping the acknowledgement timer"""
        if alert_id not in self.active_alerts:
            logger.warning(f"Alert {alert_id} not found for acknowledgement")
            return False
        
        alert = self.active_alerts[alert_id]
        now = datetime.utcnow()
        
        alert["acknowledged_at"] = now
        alert["acknowledged_by"] = responder_id
        alert["status"] = EscalationStatus.ACKNOWLEDGED
        
        # Check if acknowledgement was within SLA
        sla_policy = alert["sla_policy"]
        ack_time = (now - alert["created_at"]).total_seconds()
        if ack_time > sla_policy.get_timeout_seconds("acknowledge"):
            alert["sla_breaches"].append({
                "phase": "acknowledge",
                "breach_time": now,
                "actual_seconds": ack_time,
                "allowed_seconds": sla_policy.get_timeout_seconds("acknowledge")
            })
            logger.warning(f"Alert {alert_id} acknowledgement SLA breached")
        
        logger.info(f"Alert {alert_id} acknowledged by {responder_id}")
        return True
    
    def resolve_alert(self, alert_id: str, responder_id: str, resolution_notes: str) -> bool:
        """Mark an alert as resolved"""
        if alert_id not in self.active_alerts:
            logger.warning(f"Alert {alert_id} not found for resolution")
            return False
        
        alert = self.active_alerts[alert_id]
        now = datetime.utcnow()
        
        alert["resolved_at"] = now
        alert["status"] = EscalationStatus.RESOLVED
        alert["resolution_notes"] = resolution_notes
        
        # Check resolution SLA
        sla_policy = alert["sla_policy"]
        resolution_time = (now - alert["created_at"]).total_seconds()
        if resolution_time > sla_policy.get_timeout_seconds("resolution"):
            alert["sla_breaches"].append({
                "phase": "resolution",
                "breach_time": now,
                "actual_seconds": resolution_time,
                "allowed_seconds": sla_policy.get_timeout_seconds("resolution")
            })
        
        logger.info(f"Alert {alert_id} resolved by {responder_id}")
        return True
    
    def escalate_alert(self, alert_id: str, reason: str, escalated_by: str = "system") -> bool:
        """Manually or automatically escalate an alert to next level"""
        if alert_id not in self.active_alerts:
            logger.warning(f"Alert {alert_id} not found for escalation")
            return False
        
        alert = self.active_alerts[alert_id]
        current_level = alert["current_level"]
        escalation_path = self.matrix.get_escalation_path(alert["severity"])
        
        if current_level >= len(escalation_path):
            logger.info(f"Alert {alert_id} already at maximum escalation level")
            return False
        
        next_level = current_level + 1
        now = datetime.utcnow()
        
        # Record escalation
        record = AlertEscalationRecord(
            escalation_id=str(uuid.uuid4()),
            alert_id=alert_id,
            timestamp=now,
            from_level=current_level,
            to_level=next_level,
            reason=reason,
            escalated_by=escalated_by,
            status=EscalationStatus.ESCALATED if escalated_by != "system" else EscalationStatus.AUTO_ESCALATED
        )
        self.escalation_history.append(record)
        
        # Update alert
        alert["current_level"] = next_level
        alert["last_escalated_at"] = now
        alert["escalation_count"] += 1
        alert["status"] = EscalationStatus.ESCALATED
        
        # Dispatch escalation notification
        self._dispatch_notification(alert, "escalation")
        
        logger.info(f"Alert {alert_id} escalated from L{current_level} to L{next_level}: {reason}")
        return True
    
    def _dispatch_notification(self, alert: Dict[str, Any], notification_type: str) -> None:
        """Dispatch notification through registered callbacks"""
        for callback in self.notification_callbacks:
            try:
                callback(alert, notification_type)
            except Exception as e:
                logger.error(f"Notification callback failed: {e}")
    
    async def monitor_sla_compliance(self) -> None:
        """Background task to monitor SLA compliance and auto-escalate"""
        self._running = True
        logger.info("SLA compliance monitor started")
        
        while self._running:
            try:
                now = datetime.utcnow()
                
                for alert_id, alert in list(self.active_alerts.items()):
                    if alert["status"] == EscalationStatus.RESOLVED:
                        continue
                    
                    elapsed = (now - alert["created_at"]).total_seconds()
                    sla_policy = alert["sla_policy"]
                    
                    # Check for auto-escalation
                    auto_escalate_timeout = sla_policy.get_timeout_seconds("auto_escalate")
                    time_since_escalation = (now - alert["last_escalated_at"]).total_seconds()
                    
                    if time_since_escalation >= auto_escalate_timeout:
                        if alert["status"] != EscalationStatus.ACKNOWLEDGED:
                            self.escalate_alert(
                                alert_id, 
                                f"SLA breach: No acknowledgement after {auto_escalate_timeout//60} minutes",
                                "system"
                            )
                
                await asyncio.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"SLA monitor error: {e}")
                await asyncio.sleep(5)
    
    def start_monitor(self) -> None:
        """Start the SLA monitoring background task"""
        if not self._monitor_task:
            self._monitor_task = asyncio.create_task(self.monitor_sla_compliance())
    
    def stop_monitor(self) -> None:
        """Stop the SLA monitoring"""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
    
    def get_alert_status(self, alert_id: str) -> Optional[Dict[str, Any]]:
        """Get current status of an alert"""
        return self.active_alerts.get(alert_id)
    
    def get_sla_metrics(self) -> Dict[str, Any]:
        """Get SLA compliance metrics"""
        total_alerts = len(self.active_alerts)
        breached_alerts = sum(1 for a in self.active_alerts.values() if a["sla_breaches"])
        resolved_alerts = sum(1 for a in self.active_alerts.values() 
                            if a["status"] == EscalationStatus.RESOLVED)
        
        avg_ack_time = 0.0
        ack_count = 0
        for alert in self.active_alerts.values():
            if alert["acknowledged_at"]:
                ack_time = (alert["acknowledged_at"] - alert["created_at"]).total_seconds()
                avg_ack_time += ack_time
                ack_count += 1
        
        return {
            "total_alerts_tracked": total_alerts,
            "alerts_with_sla_breaches": breached_alerts,
            "resolved_alerts": resolved_alerts,
            "active_alerts": total_alerts - resolved_alerts,
            "sla_compliance_rate": ((total_alerts - breached_alerts) / total_alerts * 100) if total_alerts > 0 else 100.0,
            "average_acknowledgement_time_seconds": avg_ack_time / ack_count if ack_count > 0 else 0.0,
            "total_escalations": len(self.escalation_history),
            "auto_escalations": sum(1 for r in self.escalation_history if r.escalated_by == "system")
        }
    
    def export_escalation_report(self) -> Dict[str, Any]:
        """Export full escalation report"""
        return {
            "generated_at": datetime.utcnow().isoformat(),
            "metrics": self.get_sla_metrics(),
            "escalation_history": [
                {
                    "escalation_id": r.escalation_id,
                    "alert_id": r.alert_id,
                    "timestamp": r.timestamp.isoformat(),
                    "from_level": r.from_level,
                    "to_level": r.to_level,
                    "reason": r.reason,
                    "escalated_by": r.escalated_by,
                    "status": r.status.value
                }
                for r in self.escalation_history
            ]
        }
