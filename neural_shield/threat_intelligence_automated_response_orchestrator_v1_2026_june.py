"""
NeuralShield AI - Threat Intelligence Automated Response Orchestrator v1.0.0
Dimension A - Feature Expansion (2026 June)

ADD-ONLY IMPLEMENTATION: No existing code modified
This module provides automated response orchestration for detected threats.
It enables configuration of response policies and automated execution of
security actions based on threat severity and type.

API Stability: STABLE
"""

from __future__ import annotations

import enum
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from collections import deque


class ThreatSeverity(enum.IntEnum):
    """Threat severity levels for response policy matching."""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ResponseActionType(enum.Enum):
    """Types of automated response actions that can be executed."""
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    BLOCK_USER = "block_user"
    ALERT_ADMIN = "alert_admin"
    ALERT_SECURITY_TEAM = "alert_security_team"
    QUARANTINE_RESOURCE = "quarantine_resource"
    RATE_LIMIT = "rate_limit"
    REVOKE_TOKEN = "revoke_token"
    LOG_EVENT = "log_event"
    TRIGGER_WEBHOOK = "trigger_webhook"
    ISOLATE_NETWORK = "isolate_network"
    FORCE_PASSWORD_RESET = "force_password_reset"
    ENABLE_MFA = "enable_mfa"
    TERMINATE_SESSION = "terminate_session"
    NO_ACTION = "no_action"


class ActionStatus(enum.Enum):
    """Execution status of response actions."""
    PENDING = "pending"
    EXECUTING = "executing"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"
    ROLLED_BACK = "rolled_back"


class PolicyMatchMode(enum.Enum):
    """How policies are matched against threats."""
    EXACT = "exact"
    SEVERITY_AT_LEAST = "severity_at_least"
    SEVERITY_AT_MOST = "severity_at_most"
    ANY = "any"


@dataclass
class ThreatContext:
    """Context information about a detected threat."""
    threat_id: str
    threat_type: str
    severity: ThreatSeverity
    source_ip: Optional[str] = None
    source_domain: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    resource_id: Optional[str] = None
    confidence: float = 0.0
    detection_time: datetime = field(default_factory=datetime.now)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponseAction:
    """A single response action to be executed."""
    action_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    action_type: ResponseActionType = ResponseActionType.NO_ACTION
    target: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    status: ActionStatus = ActionStatus.PENDING
    created_at: datetime = field(default_factory=datetime.now)
    executed_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    rollback_supported: bool = False
    execution_result: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ResponsePolicy:
    """Policy defining what actions to take for matching threats."""
    policy_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    name: str = "default_policy"
    description: str = "Default response policy"
    enabled: bool = True
    match_mode: PolicyMatchMode = PolicyMatchMode.SEVERITY_AT_LEAST
    match_severity: ThreatSeverity = ThreatSeverity.HIGH
    match_threat_types: Set[str] = field(default_factory=set)
    actions: List[ResponseActionType] = field(default_factory=list)
    action_parameters: Dict[ResponseActionType, Dict[str, Any]] = field(default_factory=dict)
    cooldown_seconds: int = 300
    priority: int = 0
    require_approval: bool = False
    auto_rollback_on_failure: bool = True
    created_at: datetime = field(default_factory=datetime.now)


@dataclass
class ActionExecutionRecord:
    """Record of an action execution for audit trail."""
    record_id: str
    threat_context: ThreatContext
    policy: ResponsePolicy
    action: ResponseAction
    executed_by: str = "automated"
    timestamp: datetime = field(default_factory=datetime.now)


class ActionExecutor:
    """
    Executes response actions with proper error handling and rollback support.
    This is a framework - actual integration with infrastructure requires
    registering custom action handlers.
    """

    def __init__(self) -> None:
        self._handlers: Dict[ResponseActionType, Callable] = {}
        self._rollback_handlers: Dict[ResponseActionType, Callable] = {}
        self._lock = threading.Lock()
        self._register_default_handlers()

    def _register_default_handlers(self) -> None:
        """Register default no-op handlers for all action types."""
        for action_type in ResponseActionType:
            self._handlers[action_type] = self._default_handler
            self._rollback_handlers[action_type] = self._default_rollback_handler

    def _default_handler(self, target: Optional[str], params: Dict[str, Any]) -> Tuple[bool, Dict[str, Any], Optional[str]]:
        """Default handler - logs action but doesn't modify actual infrastructure."""
        return True, {"handled": "default", "timestamp": time.time()}, None

    def _default_rollback_handler(self, target: Optional[str], params: Dict[str, Any], result: Dict[str, Any]) -> bool:
        """Default rollback handler."""
        return True

    def register_handler(
        self,
        action_type: ResponseActionType,
        handler: Callable,
        rollback_handler: Optional[Callable] = None
    ) -> None:
        """Register a custom handler for an action type."""
        with self._lock:
            self._handlers[action_type] = handler
            if rollback_handler:
                self._rollback_handlers[action_type] = rollback_handler

    def execute(self, action: ResponseAction) -> ResponseAction:
        """Execute a single response action."""
        action.status = ActionStatus.EXECUTING
        action.executed_at = datetime.now()

        try:
            handler = self._handlers.get(action.action_type, self._default_handler)
            success, result, error = handler(action.target, action.parameters)

            if success:
                action.status = ActionStatus.SUCCESS
                action.execution_result = result
            else:
                action.status = ActionStatus.FAILED
                action.error_message = error or "Unknown execution error"

        except Exception as e:
            action.status = ActionStatus.FAILED
            action.error_message = str(e)

        action.completed_at = datetime.now()
        return action

    def rollback(self, action: ResponseAction) -> bool:
        """Attempt to rollback an executed action."""
        if not action.rollback_supported:
            return False

        try:
            handler = self._rollback_handlers.get(action.action_type, self._default_rollback_handler)
            success = handler(action.target, action.parameters, action.execution_result)
            if success:
                action.status = ActionStatus.ROLLED_BACK
            return success
        except Exception:
            return False


class PolicyEngine:
    """Matches threats against policies and generates appropriate response actions."""

    def __init__(self) -> None:
        self._policies: Dict[str, ResponsePolicy] = {}
        self._lock = threading.Lock()
        self._last_match: Dict[str, datetime] = {}
        self._add_default_policies()

    def _add_default_policies(self) -> None:
        """Add default response policies."""
        # Critical threat policy - aggressive response
        self.add_policy(ResponsePolicy(
            name="critical_threat_response",
            description="Aggressive response for critical threats",
            match_mode=PolicyMatchMode.EXACT,
            match_severity=ThreatSeverity.CRITICAL,
            actions=[
                ResponseActionType.BLOCK_IP,
                ResponseActionType.TERMINATE_SESSION,
                ResponseActionType.ALERT_SECURITY_TEAM,
                ResponseActionType.LOG_EVENT
            ],
            priority=100,
            cooldown_seconds=60
        ))

        # High threat policy
        self.add_policy(ResponsePolicy(
            name="high_threat_response",
            description="Standard response for high severity threats",
            match_mode=PolicyMatchMode.EXACT,
            match_severity=ThreatSeverity.HIGH,
            actions=[
                ResponseActionType.RATE_LIMIT,
                ResponseActionType.ALERT_ADMIN,
                ResponseActionType.LOG_EVENT
            ],
            priority=50,
            cooldown_seconds=120
        ))

        # Medium threat policy
        self.add_policy(ResponsePolicy(
            name="medium_threat_response",
            description="Monitoring response for medium threats",
            match_mode=PolicyMatchMode.EXACT,
            match_severity=ThreatSeverity.MEDIUM,
            actions=[
                ResponseActionType.LOG_EVENT,
                ResponseActionType.TRIGGER_WEBHOOK
            ],
            priority=10,
            cooldown_seconds=300
        ))

    def add_policy(self, policy: ResponsePolicy) -> str:
        """Add a new response policy."""
        with self._lock:
            self._policies[policy.policy_id] = policy
            return policy.policy_id

    def remove_policy(self, policy_id: str) -> bool:
        """Remove a policy by ID."""
        with self._lock:
            return self._policies.pop(policy_id, None) is not None

    def get_policy(self, policy_id: str) -> Optional[ResponsePolicy]:
        """Get a policy by ID."""
        return self._policies.get(policy_id)

    def get_all_policies(self) -> List[ResponsePolicy]:
        """Get all policies sorted by priority."""
        policies = list(self._policies.values())
        policies.sort(key=lambda p: -p.priority)
        return policies

    def match_threat(self, threat: ThreatContext) -> List[Tuple[ResponsePolicy, float]]:
        """Match a threat against all policies, returning (policy, match_score)."""
        matches: List[Tuple[ResponsePolicy, float]] = []

        with self._lock:
            for policy in self._policies.values():
                if not policy.enabled:
                    continue

                score = self._calculate_match_score(threat, policy)
                if score > 0:
                    matches.append((policy, score))

        matches.sort(key=lambda x: (-x[1], -x[0].priority))
        return matches

    def _calculate_match_score(self, threat: ThreatContext, policy: ResponsePolicy) -> float:
        """Calculate how well a threat matches a policy."""
        score = 0.0

        # Severity matching
        if policy.match_mode == PolicyMatchMode.EXACT:
            if threat.severity == policy.match_severity:
                score += 50.0
        elif policy.match_mode == PolicyMatchMode.SEVERITY_AT_LEAST:
            if threat.severity >= policy.match_severity:
                score += 50.0
        elif policy.match_mode == PolicyMatchMode.SEVERITY_AT_MOST:
            if threat.severity <= policy.match_severity:
                score += 50.0
        elif policy.match_mode == PolicyMatchMode.ANY:
            score += 50.0

        # Threat type matching
        if policy.match_threat_types:
            if threat.threat_type in policy.match_threat_types:
                score += 50.0
            else:
                score = 0  # Must match threat type if specified
        else:
            score += 25.0  # No threat type filter

        return score

    def generate_actions(self, threat: ThreatContext, policy: ResponsePolicy) -> List[ResponseAction]:
        """Generate response actions for a threat based on policy."""
        actions: List[ResponseAction] = []

        for action_type in policy.actions:
            params = policy.action_parameters.get(action_type, {})
            target = self._infer_target(threat, action_type)

            action = ResponseAction(
                action_type=action_type,
                target=target,
                parameters=params.copy(),
                rollback_supported=self._is_rollback_supported(action_type)
            )
            actions.append(action)

        return actions

    def _infer_target(self, threat: ThreatContext, action_type: ResponseActionType) -> Optional[str]:
        """Infer the appropriate target for an action based on threat context."""
        if action_type == ResponseActionType.BLOCK_IP:
            return threat.source_ip
        elif action_type == ResponseActionType.BLOCK_DOMAIN:
            return threat.source_domain
        elif action_type == ResponseActionType.BLOCK_USER:
            return threat.user_id
        elif action_type == ResponseActionType.TERMINATE_SESSION:
            return threat.session_id
        elif action_type == ResponseActionType.QUARANTINE_RESOURCE:
            return threat.resource_id
        return None

    def _is_rollback_supported(self, action_type: ResponseActionType) -> bool:
        """Determine if rollback is conceptually supported for an action type."""
        rollback_supported = {
            ResponseActionType.BLOCK_IP,
            ResponseActionType.BLOCK_DOMAIN,
            ResponseActionType.BLOCK_USER,
            ResponseActionType.RATE_LIMIT,
            ResponseActionType.ISOLATE_NETWORK,
            ResponseActionType.QUARANTINE_RESOURCE
        }
        return action_type in rollback_supported

    def check_cooldown(self, policy: ResponsePolicy, threat: ThreatContext) -> bool:
        """Check if policy is in cooldown for this threat pattern."""
        key = f"{policy.policy_id}:{threat.threat_type}"
        last = self._last_match.get(key)

        if last and datetime.now() - last < timedelta(seconds=policy.cooldown_seconds):
            return False  # Still in cooldown

        self._last_match[key] = datetime.now()
        return True


class ResponseOrchestrator:
    """
    Main orchestrator class that coordinates threat response.
    
    This is the primary public API for automated response orchestration.
    """

    def __init__(self) -> None:
        self._policy_engine = PolicyEngine()
        self._action_executor = ActionExecutor()
        self._audit_log: deque[ActionExecutionRecord] = deque(maxlen=10000)
        self._lock = threading.Lock()
        self._enabled = True
        self._dry_run = False

    @property
    def policy_engine(self) -> PolicyEngine:
        """Access the policy engine for policy management."""
        return self._policy_engine

    @property
    def action_executor(self) -> ActionExecutor:
        """Access the action executor for handler registration."""
        return self._action_executor

    def set_dry_run(self, enabled: bool) -> None:
        """Enable/disable dry run mode (no actual actions executed)."""
        self._dry_run = enabled

    def set_enabled(self, enabled: bool) -> None:
        """Enable/disable the orchestrator."""
        self._enabled = enabled

    def process_threat(self, threat: ThreatContext) -> Dict[str, Any]:
        """
        Process a detected threat and execute appropriate responses.
        
        Returns execution summary.
        """
        if not self._enabled:
            return {"status": "disabled", "actions_executed": 0}

        # Match policies
        matches = self._policy_engine.match_threat(threat)
        if not matches:
            return {"status": "no_policy_match", "actions_executed": 0}

        policy, score = matches[0]  # Use highest scoring policy

        # Check cooldown
        if not self._policy_engine.check_cooldown(policy, threat):
            return {"status": "in_cooldown", "policy": policy.name, "actions_executed": 0}

        # Generate actions
        actions = self._policy_engine.generate_actions(threat, policy)

        if self._dry_run:
            return {
                "status": "dry_run",
                "policy": policy.name,
                "match_score": score,
                "actions_would_execute": [a.action_type.value for a in actions],
                "actions_executed": 0
            }

        # Execute actions
        results = []
        for action in actions:
            executed = self._action_executor.execute(action)
            results.append(executed)

            # Audit log
            record = ActionExecutionRecord(
                record_id=str(uuid.uuid4()),
                threat_context=threat,
                policy=policy,
                action=executed
            )
            with self._lock:
                self._audit_log.append(record)

            # Rollback on failure if configured
            if policy.auto_rollback_on_failure and executed.status == ActionStatus.FAILED:
                self._rollback_previous_actions(results[:-1])

        success_count = sum(1 for r in results if r.status == ActionStatus.SUCCESS)

        return {
            "status": "completed",
            "policy": policy.name,
            "match_score": score,
            "total_actions": len(actions),
            "successful_actions": success_count,
            "failed_actions": len(actions) - success_count,
            "action_results": [
                {"type": r.action_type.value, "status": r.status.value, "error": r.error_message}
                for r in results
            ]
        }

    def _rollback_previous_actions(self, actions: List[ResponseAction]) -> None:
        """Rollback previously executed actions."""
        for action in reversed(actions):
            if action.status == ActionStatus.SUCCESS:
                self._action_executor.rollback(action)

    def get_audit_log(self, limit: int = 100) -> List[ActionExecutionRecord]:
        """Get recent audit log entries."""
        with self._lock:
            return list(self._audit_log)[-limit:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        with self._lock:
            total = len(self._audit_log)
            by_status: Dict[str, int] = {}
            by_action: Dict[str, int] = {}

            for record in self._audit_log:
                status = record.action.status.value
                by_status[status] = by_status.get(status, 0) + 1

                action_type = record.action.action_type.value
                by_action[action_type] = by_action.get(action_type, 0) + 1

        return {
            "total_actions_executed": total,
            "by_status": by_status,
            "by_action_type": by_action,
            "policies_configured": len(self._policy_engine.get_all_policies()),
            "dry_run_mode": self._dry_run,
            "enabled": self._enabled
        }


# Global singleton instance for easy import
_global_orchestrator: Optional[ResponseOrchestrator] = None
_global_lock = threading.Lock()


def get_orchestrator() -> ResponseOrchestrator:
    """Get the global response orchestrator instance."""
    global _global_orchestrator
    if _global_orchestrator is None:
        with _global_lock:
            if _global_orchestrator is None:
                _global_orchestrator = ResponseOrchestrator()
    return _global_orchestrator
