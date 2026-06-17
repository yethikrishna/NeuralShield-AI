"""
Threat Response Orchestrator - NeuralShield AI Security Module
Coordinates automated response actions across multiple security detectors.

This module provides:
- Threat severity classification and prioritization
- Automated response policy enforcement
- Response action orchestration
- Incident logging and metrics
"""

import time
import hashlib
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable
from datetime import datetime, timezone


class ThreatSeverity(Enum):
    """Threat severity levels for response prioritization."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseAction(Enum):
    """Available automated response actions."""
    LOG_ONLY = "log_only"
    FLAG_FOR_REVIEW = "flag_for_review"
    BLOCK_INPUT = "block_input"
    SANITIZE_OUTPUT = "sanitize_output"
    TERMINATE_SESSION = "terminate_session"
    ALERT_ADMIN = "alert_admin"
    QUARANTINE = "quarantine"


@dataclass
class ThreatIncident:
    """Represents a single security threat incident."""
    incident_id: str
    detector: str
    threat_type: str
    severity: ThreatSeverity
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    source: str = "unknown"
    user_context: Optional[Dict[str, Any]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert incident to dictionary format."""
        return {
            "incident_id": self.incident_id,
            "detector": self.detector,
            "threat_type": self.threat_type,
            "severity": self.severity.value,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "user_context": self.user_context
        }


@dataclass
class ResponseResult:
    """Result of an orchestrated response action."""
    incident_id: str
    action_taken: ResponseAction
    success: bool
    response_time_ms: float
    details: Dict[str, Any]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ResponsePolicy:
    """Defines response rules based on threat severity and type."""
    
    DEFAULT_POLICY = {
        ThreatSeverity.LOW: [ResponseAction.LOG_ONLY],
        ThreatSeverity.MEDIUM: [ResponseAction.LOG_ONLY, ResponseAction.FLAG_FOR_REVIEW],
        ThreatSeverity.HIGH: [ResponseAction.BLOCK_INPUT, ResponseAction.FLAG_FOR_REVIEW, ResponseAction.ALERT_ADMIN],
        ThreatSeverity.CRITICAL: [ResponseAction.BLOCK_INPUT, ResponseAction.TERMINATE_SESSION, 
                                 ResponseAction.ALERT_ADMIN, ResponseAction.QUARANTINE]
    }
    
    def __init__(self, custom_policy: Optional[Dict[ThreatSeverity, List[ResponseAction]]] = None):
        self.policy = custom_policy if custom_policy else self.DEFAULT_POLICY.copy()
    
    def get_actions(self, severity: ThreatSeverity) -> List[ResponseAction]:
        """Get response actions for a given severity level."""
        return self.policy.get(severity, [ResponseAction.LOG_ONLY])
    
    def update_policy(self, severity: ThreatSeverity, actions: List[ResponseAction]) -> None:
        """Update policy for specific severity level."""
        self.policy[severity] = actions


class ThreatResponseOrchestrator:
    """
    Orchestrates automated responses to security threats detected by NeuralShield.
    
    Features:
    - Receives detections from multiple detectors
    - Applies configurable response policies
    - Executes appropriate mitigation actions
    - Tracks response metrics
    - Maintains incident audit log
    """
    
    def __init__(self, policy: Optional[ResponsePolicy] = None):
        self.policy = policy if policy else ResponsePolicy()
        self.incident_log: List[ThreatIncident] = []
        self.response_log: List[ResponseResult] = []
        self.response_handlers: Dict[ResponseAction, Callable] = {}
        self.metrics = {
            "total_incidents": 0,
            "incidents_by_severity": {s.value: 0 for s in ThreatSeverity},
            "responses_by_action": {a.value: 0 for a in ResponseAction},
            "avg_response_time_ms": 0.0,
            "total_response_time_ms": 0.0
        }
        self._setup_default_handlers()
        self._setup_logger()
    
    def _setup_logger(self) -> None:
        """Configure logging for response orchestration."""
        self.logger = logging.getLogger("neural_shield.response_orchestrator")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
    
    def _setup_default_handlers(self) -> None:
        """Register default response action handlers."""
        self.response_handlers[ResponseAction.LOG_ONLY] = self._handle_log_only
        self.response_handlers[ResponseAction.FLAG_FOR_REVIEW] = self._handle_flag_review
        self.response_handlers[ResponseAction.BLOCK_INPUT] = self._handle_block_input
        self.response_handlers[ResponseAction.SANITIZE_OUTPUT] = self._handle_sanitize_output
        self.response_handlers[ResponseAction.TERMINATE_SESSION] = self._handle_terminate_session
        self.response_handlers[ResponseAction.ALERT_ADMIN] = self._handle_alert_admin
        self.response_handlers[ResponseAction.QUARANTINE] = self._handle_quarantine
    
    def _generate_incident_id(self, detector: str, threat_type: str, timestamp: float) -> str:
        """Generate unique incident ID."""
        raw = f"{detector}:{threat_type}:{timestamp}:{time.time_ns()}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]
    
    def _handle_log_only(self, incident: ThreatIncident) -> Dict[str, Any]:
        """Handle: Log incident only."""
        self.logger.info(f"Incident logged: {incident.incident_id} - {incident.threat_type}")
        return {"logged": True, "log_level": "INFO"}
    
    def _handle_flag_review(self, incident: ThreatIncident) -> Dict[str, Any]:
        """Handle: Flag for human review."""
        self.logger.warning(f"Flagged for review: {incident.incident_id}")
        return {"flagged": True, "review_queue": "security_review", "priority": incident.severity.value}
    
    def _handle_block_input(self, incident: ThreatIncident) -> Dict[str, Any]:
        """Handle: Block malicious input."""
        self.logger.error(f"Input blocked: {incident.incident_id}")
        return {"blocked": True, "block_reason": incident.threat_type}
    
    def _handle_sanitize_output(self, incident: ThreatIncident) -> Dict[str, Any]:
        """Handle: Sanitize model output."""
        self.logger.warning(f"Output sanitization triggered: {incident.incident_id}")
        return {"sanitized": True, "sanitization_rules": ["pii_removal", "toxicity_filter"]}
    
    def _handle_terminate_session(self, incident: ThreatIncident) -> Dict[str, Any]:
        """Handle: Terminate user session."""
        self.logger.critical(f"Session termination: {incident.incident_id}")
        return {"session_terminated": True, "termination_reason": incident.threat_type}
    
    def _handle_alert_admin(self, incident: ThreatIncident) -> Dict[str, Any]:
        """Handle: Alert security administrators."""
        self.logger.critical(f"Admin alert triggered: {incident.incident_id}")
        return {"alert_sent": True, "alert_channels": ["email", "slack", "dashboard"]}
    
    def _handle_quarantine(self, incident: ThreatIncident) -> Dict[str, Any]:
        """Handle: Quarantine suspicious content."""
        self.logger.critical(f"Content quarantined: {incident.incident_id}")
        return {"quarantined": True, "quarantine_id": hashlib.md5(str(time.time()).encode()).hexdigest()[:8]}
    
    def register_detector(self, detector_name: str, callback: Optional[Callable] = None) -> None:
        """Register a security detector with the orchestrator."""
        self.logger.info(f"Detector registered: {detector_name}")
        if callback:
            self.logger.info(f"Callback registered for {detector_name}")
    
    def process_threat(self, 
                      detector: str, 
                      threat_type: str, 
                      severity: ThreatSeverity,
                      details: Dict[str, Any],
                      source: str = "unknown",
                      user_context: Optional[Dict[str, Any]] = None) -> ResponseResult:
        """
        Process a detected threat and orchestrate response.
        
        Args:
            detector: Name of the detecting module
            threat_type: Type of threat detected
            severity: Threat severity level
            details: Additional threat details
            source: Source of the input
            user_context: Optional user context
            
        Returns:
            ResponseResult with action details
        """
        start_time = time.time()
        
        # Create incident record
        incident_id = self._generate_incident_id(detector, threat_type, start_time)
        incident = ThreatIncident(
            incident_id=incident_id,
            detector=detector,
            threat_type=threat_type,
            severity=severity,
            details=details,
            source=source,
            user_context=user_context
        )
        
        # Log incident
        self.incident_log.append(incident)
        self.metrics["total_incidents"] += 1
        self.metrics["incidents_by_severity"][severity.value] += 1
        
        # Get and execute response actions
        actions = self.policy.get_actions(severity)
        response_details = {}
        
        for action in actions:
            handler = self.response_handlers.get(action)
            if handler:
                try:
                    result = handler(incident)
                    response_details[action.value] = result
                    self.metrics["responses_by_action"][action.value] += 1
                except Exception as e:
                    response_details[action.value] = {"error": str(e)}
                    self.logger.error(f"Handler error for {action.value}: {e}")
        
        # Calculate response time
        response_time_ms = (time.time() - start_time) * 1000
        self.metrics["total_response_time_ms"] += response_time_ms
        self.metrics["avg_response_time_ms"] = (
            self.metrics["total_response_time_ms"] / self.metrics["total_incidents"]
        )
        
        # Create response result
        result = ResponseResult(
            incident_id=incident_id,
            action_taken=actions[-1] if actions else ResponseAction.LOG_ONLY,
            success=True,
            response_time_ms=response_time_ms,
            details=response_details
        )
        
        self.response_log.append(result)
        return result
    
    def batch_process(self, threats: List[Dict[str, Any]]) -> List[ResponseResult]:
        """Process multiple threats in batch."""
        results = []
        for threat in threats:
            result = self.process_threat(
                detector=threat.get("detector", "unknown"),
                threat_type=threat.get("threat_type", "unknown"),
                severity=threat.get("severity", ThreatSeverity.MEDIUM),
                details=threat.get("details", {}),
                source=threat.get("source", "unknown"),
                user_context=threat.get("user_context")
            )
            results.append(result)
        return results
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get current response orchestration metrics."""
        return {
            "orchestrator_metrics": self.metrics.copy(),
            "incident_count": len(self.incident_log),
            "response_count": len(self.response_log),
            "policy_config": {k.value: [a.value for a in v] for k, v in self.policy.policy.items()}
        }
    
    def get_recent_incidents(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Get most recent incidents."""
        recent = sorted(self.incident_log, key=lambda x: x.timestamp, reverse=True)[:limit]
        return [incident.to_dict() for incident in recent]
    
    def clear_logs(self) -> None:
        """Clear incident and response logs (for testing)."""
        self.incident_log.clear()
        self.response_log.clear()
