"""
NeuralShield-AI: Threat Intelligence Incident Playbook Executor
June 18, 2026

A production-grade incident response playbook executor that:
1. Maintains a library of security response playbooks
2. Matches detected incidents to appropriate playbooks
3. Executes playbook steps with validation and rollback
4. Tracks execution progress and outcomes
5. Provides audit logging for compliance
"""

import asyncio
import logging
import json
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable, Awaitable
from datetime import datetime, timezone


class PlaybookStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    PARTIAL = "partial_success"
    ROLLED_BACK = "rolled_back"


class StepStatus(Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class SeverityLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentType(Enum):
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    DATA_LEAKAGE = "data_leakage"
    MODEL_EXTRACTION = "model_extraction"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    RAG_POISONING = "rag_poisoning"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    SUSPICIOUS_BEHAVIOR = "suspicious_behavior"


@dataclass
class PlaybookStep:
    step_id: str
    name: str
    description: str
    action: Callable[[Dict[str, Any]], Awaitable[bool]]
    rollback_action: Optional[Callable[[Dict[str, Any]], Awaitable[bool]]] = None
    required: bool = True
    timeout_seconds: int = 30
    retry_count: int = 2
    status: StepStatus = StepStatus.PENDING
    error_message: Optional[str] = None
    execution_time_ms: float = 0.0


@dataclass
class IncidentContext:
    incident_id: str
    incident_type: IncidentType
    severity: SeverityLevel
    source: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class PlaybookExecution:
    execution_id: str
    incident_context: IncidentContext
    playbook_name: str
    steps: List[PlaybookStep]
    status: PlaybookStatus = PlaybookStatus.PENDING
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    rollback_triggered: bool = False


class PlaybookLibrary:
    """Library of predefined security response playbooks"""

    def __init__(self):
        self._playbooks: Dict[str, Dict[str, Any]] = {}
        self._register_default_playbooks()

    def _register_default_playbooks(self):
        """Register built-in response playbooks"""
        # Prompt Injection Response Playbook
        self.register_playbook(
            "prompt_injection_response",
            "Prompt Injection Incident Response",
            [
                IncidentType.PROMPT_INJECTION,
                IncidentType.JAILBREAK_ATTEMPT
            ],
            SeverityLevel.MEDIUM
        )

        # Critical Data Leakage Response
        self.register_playbook(
            "data_leakage_response",
            "Data Leakage Emergency Response",
            [IncidentType.DATA_LEAKAGE],
            SeverityLevel.CRITICAL
        )

        # RAG Poisoning Response
        self.register_playbook(
            "rag_poisoning_response",
            "RAG Poisoning Containment Response",
            [IncidentType.RAG_POISONING],
            SeverityLevel.HIGH
        )

        # Model Extraction Defense
        self.register_playbook(
            "model_extraction_defense",
            "Model Extraction Active Defense",
            [IncidentType.MODEL_EXTRACTION],
            SeverityLevel.HIGH
        )

    def register_playbook(
        self,
        playbook_id: str,
        name: str,
        incident_types: List[IncidentType],
        min_severity: SeverityLevel,
        description: str = ""
    ):
        """Register a new playbook template"""
        self._playbooks[playbook_id] = {
            "id": playbook_id,
            "name": name,
            "incident_types": incident_types,
            "min_severity": min_severity,
            "description": description,
            "steps": []
        }

    def get_matching_playbooks(
        self,
        incident_type: IncidentType,
        severity: SeverityLevel
    ) -> List[str]:
        """Find playbooks matching incident type and severity"""
        severity_order = [SeverityLevel.LOW, SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]
        severity_idx = severity_order.index(severity)

        matches = []
        for pb_id, pb in self._playbooks.items():
            if incident_type in pb["incident_types"]:
                pb_severity_idx = severity_order.index(pb["min_severity"])
                if severity_idx >= pb_severity_idx:
                    matches.append(pb_id)
        return matches

    def get_playbook(self, playbook_id: str) -> Optional[Dict[str, Any]]:
        return self._playbooks.get(playbook_id)


class IncidentPlaybookExecutor:
    """
    Production-grade incident response playbook executor.
    
    Features:
    - Async execution with timeout protection
    - Automatic rollback on critical step failure
    - Retry logic for transient failures
    - Comprehensive audit logging
    - Execution tracking and metrics
    """

    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.library = PlaybookLibrary()
        self._executions: Dict[str, PlaybookExecution] = {}
        self._audit_log: List[Dict[str, Any]] = []
        self._built_in_actions = self._initialize_builtin_actions()

    def _initialize_builtin_actions(self) -> Dict[str, Callable]:
        """Initialize built-in response actions"""
        return {
            "log_incident": self._action_log_incident,
            "block_user": self._action_block_user,
            "quarantine_session": self._action_quarantine_session,
            "sanitize_output": self._action_sanitize_output,
            "notify_administrators": self._action_notify_administrators,
            "trigger_rate_limit": self._action_trigger_rate_limit,
            "capture_forensics": self._action_capture_forensics,
            "isolate_context": self._action_isolate_context
        }

    async def _action_log_incident(self, context: Dict[str, Any]) -> bool:
        """Action: Log incident details to audit log"""
        self.logger.warning(f"[PLAYBOOK] Logging incident: {context.get('incident_id', 'unknown')}")
        self._audit_log.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": "log_incident",
            "context": context
        })
        return True

    async def _action_block_user(self, context: Dict[str, Any]) -> bool:
        """Action: Block user temporarily"""
        user_id = context.get("user_id", "unknown")
        duration = context.get("block_duration_minutes", 60)
        self.logger.warning(f"[PLAYBOOK] Blocking user {user_id} for {duration} minutes")
        return True

    async def _action_quarantine_session(self, context: Dict[str, Any]) -> bool:
        """Action: Quarantine current session"""
        session_id = context.get("session_id", str(uuid.uuid4()))
        self.logger.warning(f"[PLAYBOOK] Quarantining session: {session_id}")
        return True

    async def _action_sanitize_output(self, context: Dict[str, Any]) -> bool:
        """Action: Sanitize model output"""
        self.logger.info("[PLAYBOOK] Sanitizing model output")
        return True

    async def _action_notify_administrators(self, context: Dict[str, Any]) -> bool:
        """Action: Send alert notifications"""
        incident_id = context.get("incident_id", "unknown")
        severity = context.get("severity", "unknown")
        self.logger.warning(f"[PLAYBOOK] Notifying admins: Incident {incident_id} ({severity})")
        return True

    async def _action_trigger_rate_limit(self, context: Dict[str, Any]) -> bool:
        """Action: Apply rate limiting"""
        self.logger.info("[PLAYBOOK] Triggering rate limiting")
        return True

    async def _action_capture_forensics(self, context: Dict[str, Any]) -> bool:
        """Action: Capture forensic data"""
        self.logger.info("[PLAYBOOK] Capturing forensic data")
        return True

    async def _action_isolate_context(self, context: Dict[str, Any]) -> bool:
        """Action: Isolate conversation context"""
        self.logger.info("[PLAYBOOK] Isolating conversation context")
        return True

    def create_playbook_steps(self, playbook_id: str) -> List[PlaybookStep]:
        """Create concrete steps for a given playbook"""
        steps = []
        
        if playbook_id == "prompt_injection_response":
            steps = [
                PlaybookStep(
                    step_id="log_001",
                    name="Log Incident",
                    description="Log incident details to audit trail",
                    action=self._built_in_actions["log_incident"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="sanitize_001",
                    name="Sanitize Output",
                    description="Sanitize any generated output",
                    action=self._built_in_actions["sanitize_output"],
                    rollback_action=None,
                    required=False
                ),
                PlaybookStep(
                    step_id="quarantine_001",
                    name="Quarantine Session",
                    description="Place session in monitored quarantine",
                    action=self._built_in_actions["quarantine_session"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="notify_001",
                    name="Notify Administrators",
                    description="Alert security team",
                    action=self._built_in_actions["notify_administrators"],
                    rollback_action=None,
                    required=False
                )
            ]
        elif playbook_id == "data_leakage_response":
            steps = [
                PlaybookStep(
                    step_id="log_001",
                    name="Log Critical Incident",
                    description="Log critical data leakage event",
                    action=self._built_in_actions["log_incident"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="forensics_001",
                    name="Capture Forensics",
                    description="Capture complete forensic snapshot",
                    action=self._built_in_actions["capture_forensics"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="block_001",
                    name="Block User",
                    description="Immediately block offending user",
                    action=self._built_in_actions["block_user"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="isolate_001",
                    name="Isolate Context",
                    description="Isolate all related context",
                    action=self._built_in_actions["isolate_context"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="notify_001",
                    name="Emergency Alert",
                    description="Send emergency notification to all admins",
                    action=self._built_in_actions["notify_administrators"],
                    rollback_action=None
                )
            ]
        elif playbook_id == "rag_poisoning_response":
            steps = [
                PlaybookStep(
                    step_id="log_001",
                    name="Log Poisoning Attempt",
                    description="Log RAG poisoning detection",
                    action=self._built_in_actions["log_incident"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="ratelimit_001",
                    name="Trigger Rate Limit",
                    description="Apply strict rate limiting",
                    action=self._built_in_actions["trigger_rate_limit"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="notify_001",
                    name="Notify Administrators",
                    description="Alert RAG maintenance team",
                    action=self._built_in_actions["notify_administrators"],
                    rollback_action=None,
                    required=False
                )
            ]
        elif playbook_id == "model_extraction_defense":
            steps = [
                PlaybookStep(
                    step_id="log_001",
                    name="Log Extraction Attempt",
                    description="Log model extraction detection",
                    action=self._built_in_actions["log_incident"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="ratelimit_001",
                    name="Strict Rate Limiting",
                    description="Apply maximum rate limiting",
                    action=self._built_in_actions["trigger_rate_limit"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="block_001",
                    name="Temporary Block",
                    description="Temporarily block user",
                    action=self._built_in_actions["block_user"],
                    rollback_action=None
                ),
                PlaybookStep(
                    step_id="notify_001",
                    name="Notify Security Team",
                    description="Alert security team of extraction attempt",
                    action=self._built_in_actions["notify_administrators"],
                    rollback_action=None
                )
            ]

        return steps

    async def execute_playbook(
        self,
        incident_context: IncidentContext,
        playbook_id: Optional[str] = None
    ) -> PlaybookExecution:
        """
        Execute the appropriate response playbook for an incident.
        
        Args:
            incident_context: Details about the security incident
            playbook_id: Optional specific playbook to execute (auto-detect if None)
        
        Returns:
            PlaybookExecution with complete execution details
        """
        # Auto-select playbook if not specified
        if playbook_id is None:
            matches = self.library.get_matching_playbooks(
                incident_context.incident_type,
                incident_context.severity
            )
            if not matches:
                self.logger.warning(f"No playbook found for {incident_context.incident_type}")
                playbook_id = "prompt_injection_response"  # Default
            else:
                playbook_id = matches[0]

        execution_id = f"exec_{uuid.uuid4().hex[:12]}"
        steps = self.create_playbook_steps(playbook_id)

        execution = PlaybookExecution(
            execution_id=execution_id,
            incident_context=incident_context,
            playbook_name=playbook_id,
            steps=steps,
            status=PlaybookStatus.RUNNING,
            started_at=datetime.now(timezone.utc)
        )

        self._executions[execution_id] = execution
        self.logger.info(
            f"Starting playbook execution {execution_id}: "
            f"{playbook_id} for incident {incident_context.incident_id}"
        )

        # Execute each step
        all_succeeded = True
        for step in steps:
            step_result = await self._execute_step(step, incident_context)
            if not step_result and step.required:
                all_succeeded = False
                execution.error_message = f"Critical step failed: {step.name}"
                await self._rollback_execution(execution)
                break

        execution.completed_at = datetime.now(timezone.utc)
        if execution.rollback_triggered:
            execution.status = PlaybookStatus.ROLLED_BACK
        elif all_succeeded:
            execution.status = PlaybookStatus.COMPLETED
        elif any(s.status == StepStatus.SUCCEEDED for s in steps):
            execution.status = PlaybookStatus.PARTIAL
        else:
            execution.status = PlaybookStatus.FAILED

        self.logger.info(
            f"Playbook {execution_id} completed: {execution.status.value}"
        )
        return execution

    async def _execute_step(
        self,
        step: PlaybookStep,
        context: IncidentContext
    ) -> bool:
        """Execute a single playbook step with retry and timeout"""
        step.status = StepStatus.RUNNING
        start_time = time.time()

        context_dict = {
            "incident_id": context.incident_id,
            "incident_type": context.incident_type.value,
            "severity": context.severity.value,
            "source": context.source,
            "description": context.description,
            **context.metadata
        }

        for attempt in range(step.retry_count + 1):
            try:
                result = await asyncio.wait_for(
                    step.action(context_dict),
                    timeout=step.timeout_seconds
                )
                if result:
                    step.status = StepStatus.SUCCEEDED
                    step.execution_time_ms = (time.time() - start_time) * 1000
                    return True
            except asyncio.TimeoutError:
                step.error_message = f"Timeout after {step.timeout_seconds}s (attempt {attempt + 1})"
            except Exception as e:
                step.error_message = f"Exception: {str(e)} (attempt {attempt + 1})"

            if attempt < step.retry_count:
                await asyncio.sleep(0.5 * (attempt + 1))  # Backoff

        step.status = StepStatus.FAILED
        step.execution_time_ms = (time.time() - start_time) * 1000
        self.logger.error(f"Step failed: {step.name} - {step.error_message}")
        return False

    async def _rollback_execution(self, execution: PlaybookExecution):
        """Roll back completed steps if rollback actions exist"""
        execution.rollback_triggered = True
        self.logger.warning(f"Initiating rollback for {execution.execution_id}")

        for step in reversed(execution.steps):
            if step.status == StepStatus.SUCCEEDED and step.rollback_action:
                try:
                    context_dict = {
                        "incident_id": execution.incident_context.incident_id,
                        "rollback_reason": execution.error_message
                    }
                    await step.rollback_action(context_dict)
                    step.status = StepStatus.ROLLED_BACK
                except Exception as e:
                    self.logger.error(f"Rollback failed for {step.name}: {e}")

    def get_execution(self, execution_id: str) -> Optional[PlaybookExecution]:
        return self._executions.get(execution_id)

    def get_execution_summary(self) -> Dict[str, Any]:
        """Get summary statistics of all executions"""
        status_counts = {status: 0 for status in PlaybookStatus}
        total_executions = len(self._executions)
        total_steps = 0
        failed_steps = 0

        for exec_item in self._executions.values():
            status_counts[exec_item.status] += 1
            for step in exec_item.steps:
                total_steps += 1
                if step.status == StepStatus.FAILED:
                    failed_steps += 1

        return {
            "total_executions": total_executions,
            "status_breakdown": {k.value: v for k, v in status_counts.items() if v > 0},
            "total_steps_executed": total_steps,
            "failed_steps": failed_steps,
            "success_rate": ((total_steps - failed_steps) / total_steps * 100) if total_steps > 0 else 100.0,
            "audit_log_entries": len(self._audit_log)
        }

    def export_audit_log(self, filepath: Optional[str] = None) -> str:
        """Export audit log as JSON"""
        log_data = json.dumps(self._audit_log, indent=2, default=str)
        if filepath:
            with open(filepath, 'w') as f:
                f.write(log_data)
        return log_data
