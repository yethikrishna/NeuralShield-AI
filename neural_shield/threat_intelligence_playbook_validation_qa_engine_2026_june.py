"""
Threat Intelligence Playbook Validation & QA Engine
Production-grade security playbook validation, quality assurance, and compliance checking

This module provides:
1. Playbook structure validation
2. Step completeness and correctness checking  
3. MITRE ATT&CK mapping validation
4. Security control effectiveness validation
5. Response automation readiness scoring
6. QA compliance reporting
"""

import json
import hashlib
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class PlaybookStatus(Enum):
    DRAFT = "draft"
    REVIEW_REQUIRED = "review_required"
    VALID = "valid"
    INVALID = "invalid"
    DEPRECATED = "deprecated"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class ValidationIssue:
    issue_id: str
    severity: SeverityLevel
    category: str
    message: str
    location: str
    recommendation: str
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


@dataclass
class ValidationResult:
    playbook_id: str
    playbook_name: str
    status: PlaybookStatus
    overall_score: float
    issues: List[ValidationIssue]
    passed_checks: List[str]
    validation_timestamp: str
    qa_summary: Dict[str, Any]


class PlaybookValidationQaEngine:
    """
    Production-grade playbook validation and QA engine
    Validates security incident response playbooks for completeness, correctness, and compliance
    """

    REQUIRED_FIELDS = [
        "playbook_id", "name", "description", "severity", "mitre_techniques",
        "detection_steps", "response_steps", "escalation_points", "roles",
        "communication_templates", "metrics"
    ]

    VALID_MITRE_TACTICS = {
        "initial-access", "execution", "persistence", "privilege-escalation",
        "defense-evasion", "credential-access", "discovery", "lateral-movement",
        "collection", "command-and-control", "exfiltration", "impact"
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.validation_rules = self._load_validation_rules()
        self.validation_history: List[ValidationResult] = []

    def _load_validation_rules(self) -> Dict[str, Any]:
        """Load validation rules from config or defaults"""
        return {
            "min_detection_steps": 2,
            "min_response_steps": 3,
            "min_escalation_points": 1,
            "required_roles": ["incident_commander", "technical_lead"],
            "max_step_duration_minutes": 120,
            "min_sla_response_minutes": 15
        }

    def validate_playbook(self, playbook: Dict[str, Any]) -> ValidationResult:
        """
        Validate a complete security playbook with all QA checks
        
        Args:
            playbook: The playbook dictionary to validate
            
        Returns:
            ValidationResult with all findings and scores
        """
        issues: List[ValidationIssue] = []
        passed_checks: List[str] = []
        playbook_id = playbook.get("playbook_id", "unknown")
        playbook_name = playbook.get("name", "Unnamed Playbook")

        # Run all validation checks
        issues.extend(self._validate_required_fields(playbook))
        issues.extend(self._validate_structure(playbook))
        issues.extend(self._validate_mitre_mapping(playbook))
        issues.extend(self._validate_detection_steps(playbook))
        issues.extend(self._validate_response_steps(playbook))
        issues.extend(self._validate_escalation_procedures(playbook))
        issues.extend(self._validate_roles_and_responsibilities(playbook))
        issues.extend(self._validate_communication_templates(playbook))
        issues.extend(self._validate_metrics_and_sla(playbook))
        issues.extend(self._validate_automation_readiness(playbook))

        # Calculate passed checks
        if not any(i.severity == SeverityLevel.CRITICAL for i in issues):
            passed_checks.append("No critical validation failures")
        if len([i for i in issues if i.severity == SeverityLevel.HIGH]) < 3:
            passed_checks.append("High severity issues within acceptable limits")
        if playbook.get("detection_steps") and len(playbook["detection_steps"]) >= self.validation_rules["min_detection_steps"]:
            passed_checks.append("Detection steps completeness check passed")
        if playbook.get("response_steps") and len(playbook["response_steps"]) >= self.validation_rules["min_response_steps"]:
            passed_checks.append("Response steps completeness check passed")

        # Calculate overall score
        overall_score = self._calculate_overall_score(issues, playbook)

        # Determine status
        status = self._determine_status(issues, overall_score)

        # Generate QA summary
        qa_summary = self._generate_qa_summary(issues, passed_checks, overall_score)

        result = ValidationResult(
            playbook_id=playbook_id,
            playbook_name=playbook_name,
            status=status,
            overall_score=overall_score,
            issues=issues,
            passed_checks=passed_checks,
            validation_timestamp=datetime.now(timezone.utc).isoformat(),
            qa_summary=qa_summary
        )

        self.validation_history.append(result)
        return result

    def _validate_required_fields(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate all required fields exist"""
        issues = []
        for field in self.REQUIRED_FIELDS:
            if field not in playbook:
                issues.append(ValidationIssue(
                    issue_id=f"REQ-{field.upper()}",
                    severity=SeverityLevel.CRITICAL,
                    category="required_fields",
                    message=f"Missing required field: {field}",
                    location=f"root.{field}",
                    recommendation=f"Add the '{field}' field with appropriate content"
                ))
            elif playbook[field] in [None, "", [], {}]:
                issues.append(ValidationIssue(
                    issue_id=f"EMPTY-{field.upper()}",
                    severity=SeverityLevel.HIGH,
                    category="empty_fields",
                    message=f"Required field is empty: {field}",
                    location=f"root.{field}",
                    recommendation=f"Populate the '{field}' field with meaningful content"
                ))
        return issues

    def _validate_structure(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate overall playbook structure"""
        issues = []
        
        # Validate versioning
        if "version" not in playbook:
            issues.append(ValidationIssue(
                issue_id="STRUCT-VERSION",
                severity=SeverityLevel.MEDIUM,
                category="structure",
                message="Playbook missing version information",
                location="root.version",
                recommendation="Add semantic versioning (e.g., '1.0.0')"
            ))
        
        # Validate last updated
        if "last_updated" not in playbook:
            issues.append(ValidationIssue(
                issue_id="STRUCT-TIMESTAMP",
                severity=SeverityLevel.MEDIUM,
                category="structure",
                message="Playbook missing last updated timestamp",
                location="root.last_updated",
                recommendation="Add ISO 8601 timestamp for last modification"
            ))
        
        # Validate author information
        if "author" not in playbook:
            issues.append(ValidationIssue(
                issue_id="STRUCT-AUTHOR",
                severity=SeverityLevel.LOW,
                category="structure",
                message="Playbook missing author information",
                location="root.author",
                recommendation="Add author/owner information for accountability"
            ))
        
        return issues

    def _validate_mitre_mapping(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate MITRE ATT&CK technique mappings"""
        issues = []
        
        techniques = playbook.get("mitre_techniques", [])
        if not techniques:
            issues.append(ValidationIssue(
                issue_id="MITRE-EMPTY",
                severity=SeverityLevel.HIGH,
                category="mitre_mapping",
                message="No MITRE ATT&CK techniques mapped",
                location="root.mitre_techniques",
                recommendation="Map relevant MITRE ATT&CK techniques for threat intelligence correlation"
            ))
            return issues
        
        for idx, technique in enumerate(techniques):
            # Validate technique ID format (TXXXX)
            technique_id = technique.get("id", "")
            if not re.match(r'^T\d{4}(\.\d{3})?$', technique_id):
                issues.append(ValidationIssue(
                    issue_id=f"MITRE-FORMAT-{idx}",
                    severity=SeverityLevel.MEDIUM,
                    category="mitre_mapping",
                    message=f"Invalid MITRE technique ID format: {technique_id}",
                    location=f"mitre_techniques[{idx}].id",
                    recommendation="Use standard MITRE format: TXXXX or TXXXX.XXX"
                ))
            
            # Validate tactic
            tactic = technique.get("tactic", "")
            if tactic and tactic not in self.VALID_MITRE_TACTICS:
                issues.append(ValidationIssue(
                    issue_id=f"MITRE-TACTIC-{idx}",
                    severity=SeverityLevel.MEDIUM,
                    category="mitre_mapping",
                    message=f"Invalid MITRE tactic: {tactic}",
                    location=f"mitre_techniques[{idx}].tactic",
                    recommendation=f"Use valid MITRE tactic from: {', '.join(sorted(self.VALID_MITRE_TACTICS))}"
                ))
        
        return issues

    def _validate_detection_steps(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate detection steps completeness and quality"""
        issues = []
        
        steps = playbook.get("detection_steps", [])
        min_steps = self.validation_rules["min_detection_steps"]
        
        if len(steps) < min_steps:
            issues.append(ValidationIssue(
                issue_id="DETECT-COUNT",
                severity=SeverityLevel.HIGH,
                category="detection_steps",
                message=f"Insufficient detection steps: {len(steps)} (minimum {min_steps})",
                location="root.detection_steps",
                recommendation="Add more detection steps covering different detection vectors"
            ))
        
        for idx, step in enumerate(steps):
            if not step.get("description"):
                issues.append(ValidationIssue(
                    issue_id=f"DETECT-DESC-{idx}",
                    severity=SeverityLevel.MEDIUM,
                    category="detection_steps",
                    message=f"Detection step {idx+1} missing description",
                    location=f"detection_steps[{idx}].description",
                    recommendation="Add clear description for each detection step"
                ))
            
            if not step.get("tools"):
                issues.append(ValidationIssue(
                    issue_id=f"DETECT-TOOLS-{idx}",
                    severity=SeverityLevel.LOW,
                    category="detection_steps",
                    message=f"Detection step {idx+1} missing tool references",
                    location=f"detection_steps[{idx}].tools",
                    recommendation="Specify tools used for this detection step"
                ))
            
            if "expected_outcome" not in step:
                issues.append(ValidationIssue(
                    issue_id=f"DETECT-OUTCOME-{idx}",
                    severity=SeverityLevel.MEDIUM,
                    category="detection_steps",
                    message=f"Detection step {idx+1} missing expected outcome",
                    location=f"detection_steps[{idx}].expected_outcome",
                    recommendation="Define clear success criteria for each detection step"
                ))
        
        return issues

    def _validate_response_steps(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate response steps completeness and quality"""
        issues = []
        
        steps = playbook.get("response_steps", [])
        min_steps = self.validation_rules["min_response_steps"]
        
        if len(steps) < min_steps:
            issues.append(ValidationIssue(
                issue_id="RESPONSE-COUNT",
                severity=SeverityLevel.HIGH,
                category="response_steps",
                message=f"Insufficient response steps: {len(steps)} (minimum {min_steps})",
                location="root.response_steps",
                recommendation="Add comprehensive response steps covering containment, eradication, recovery"
            ))
        
        # Check for containment step
        has_containment = any("contain" in step.get("action", "").lower() or "isolat" in step.get("action", "").lower() 
                              for step in steps)
        if not has_containment:
            issues.append(ValidationIssue(
                issue_id="RESPONSE-CONTAINMENT",
                severity=SeverityLevel.HIGH,
                category="response_steps",
                message="No containment/isolation steps found in response",
                location="root.response_steps",
                recommendation="Add explicit containment steps to limit incident spread"
            ))
        
        # Check for eradication step
        has_eradication = any("eradicate" in step.get("action", "").lower() or "remov" in step.get("action", "").lower()
                               for step in steps)
        if not has_eradication:
            issues.append(ValidationIssue(
                issue_id="RESPONSE-ERADICATION",
                severity=SeverityLevel.MEDIUM,
                category="response_steps",
                message="No eradication/removal steps found",
                location="root.response_steps",
                recommendation="Add steps to remove the threat from the environment"
            ))
        
        # Check for recovery step
        has_recovery = any("recover" in step.get("action", "").lower() or "restor" in step.get("action", "").lower()
                           for step in steps)
        if not has_recovery:
            issues.append(ValidationIssue(
                issue_id="RESPONSE-RECOVERY",
                severity=SeverityLevel.MEDIUM,
                category="response_steps",
                message="No recovery/restoration steps found",
                location="root.response_steps",
                recommendation="Add steps to restore systems to normal operation"
            ))
        
        for idx, step in enumerate(steps):
            if "duration_minutes" in step:
                duration = step["duration_minutes"]
                if duration > self.validation_rules["max_step_duration_minutes"]:
                    issues.append(ValidationIssue(
                        issue_id=f"RESPONSE-TIME-{idx}",
                        severity=SeverityLevel.LOW,
                        category="response_steps",
                        message=f"Response step {idx+1} duration exceeds recommended maximum",
                        location=f"response_steps[{idx}].duration_minutes",
                        recommendation="Consider breaking long steps into smaller, manageable tasks"
                    ))
        
        return issues

    def _validate_escalation_procedures(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate escalation procedures"""
        issues = []
        
        escalations = playbook.get("escalation_points", [])
        min_escalations = self.validation_rules["min_escalation_points"]
        
        if len(escalations) < min_escalations:
            issues.append(ValidationIssue(
                issue_id="ESC-COUNT",
                severity=SeverityLevel.HIGH,
                category="escalation",
                message=f"Insufficient escalation points: {len(escalations)} (minimum {min_escalations})",
                location="root.escalation_points",
                recommendation="Define clear escalation triggers and procedures"
            ))
        
        for idx, point in enumerate(escalations):
            if not point.get("trigger_condition"):
                issues.append(ValidationIssue(
                    issue_id=f"ESC-TRIGGER-{idx}",
                    severity=SeverityLevel.MEDIUM,
                    category="escalation",
                    message=f"Escalation point {idx+1} missing trigger condition",
                    location=f"escalation_points[{idx}].trigger_condition",
                    recommendation="Define clear condition when this escalation should occur"
                ))
            
            if not point.get("escalate_to"):
                issues.append(ValidationIssue(
                    issue_id=f"ESC-TO-{idx}",
                    severity=SeverityLevel.MEDIUM,
                    category="escalation",
                    message=f"Escalation point {idx+1} missing target",
                    location=f"escalation_points[{idx}].escalate_to",
                    recommendation="Specify role/team to escalate to"
                ))
        
        return issues

    def _validate_roles_and_responsibilities(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate roles and responsibilities"""
        issues = []
        
        roles = playbook.get("roles", {})
        
        for required_role in self.validation_rules["required_roles"]:
            if required_role not in roles:
                issues.append(ValidationIssue(
                    issue_id=f"ROLE-{required_role.upper()}",
                    severity=SeverityLevel.MEDIUM,
                    category="roles",
                    message=f"Missing required role definition: {required_role}",
                    location=f"roles.{required_role}",
                    recommendation=f"Define responsibilities for role: {required_role}"
                ))
        
        return issues

    def _validate_communication_templates(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate communication templates"""
        issues = []
        
        templates = playbook.get("communication_templates", {})
        
        if "stakeholder_update" not in templates:
            issues.append(ValidationIssue(
                issue_id="COMM-STAKEHOLDER",
                severity=SeverityLevel.MEDIUM,
                category="communication",
                message="Missing stakeholder update template",
                location="communication_templates.stakeholder_update",
                recommendation="Add template for regular stakeholder communications"
            ))
        
        if "executive_brief" not in templates:
            issues.append(ValidationIssue(
                issue_id="COMM-EXECUTIVE",
                severity=SeverityLevel.LOW,
                category="communication",
                message="Missing executive brief template",
                location="communication_templates.executive_brief",
                recommendation="Add template for executive-level communications"
            ))
        
        return issues

    def _validate_metrics_and_sla(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate metrics and SLA definitions"""
        issues = []
        
        metrics = playbook.get("metrics", {})
        
        if "mttd" not in metrics:  # Mean Time to Detect
            issues.append(ValidationIssue(
                issue_id="METRICS-MTTD",
                severity=SeverityLevel.MEDIUM,
                category="metrics",
                message="Missing MTTD (Mean Time to Detect) target",
                location="metrics.mttd",
                recommendation="Define MTTD target in minutes"
            ))
        
        if "mttr" not in metrics:  # Mean Time to Respond
            issues.append(ValidationIssue(
                issue_id="METRICS-MTTR",
                severity=SeverityLevel.MEDIUM,
                category="metrics",
                message="Missing MTTR (Mean Time to Respond) target",
                location="metrics.mttr",
                recommendation="Define MTTR target in minutes"
            ))
        
        if "mttr" in metrics:
            mttr = metrics["mttr"]
            if mttr < self.validation_rules["min_sla_response_minutes"]:
                issues.append(ValidationIssue(
                    issue_id="METRICS-SLA",
                    severity=SeverityLevel.LOW,
                    category="metrics",
                    message=f"MTTR target may be unrealistically aggressive: {mttr} minutes",
                    location="metrics.mttr",
                    recommendation="Review SLA targets for practical achievability"
                ))
        
        return issues

    def _validate_automation_readiness(self, playbook: Dict[str, Any]) -> List[ValidationIssue]:
        """Validate automation readiness of playbook steps"""
        issues = []
        
        steps = playbook.get("response_steps", [])
        automated_count = sum(1 for step in steps if step.get("automated", False))
        
        if len(steps) > 0 and automated_count == 0:
            issues.append(ValidationIssue(
                issue_id="AUTO-NONE",
                severity=SeverityLevel.INFO,
                category="automation",
                message="No automated steps identified in playbook",
                location="root.response_steps",
                recommendation="Consider automating repetitive response steps"
            ))
        
        return issues

    def _calculate_overall_score(self, issues: List[ValidationIssue], playbook: Dict[str, Any]) -> float:
        """Calculate overall playbook quality score 0-100"""
        base_score = 100
        
        # Severity-based deductions
        severity_weights = {
            SeverityLevel.CRITICAL: 15,
            SeverityLevel.HIGH: 8,
            SeverityLevel.MEDIUM: 4,
            SeverityLevel.LOW: 1,
            SeverityLevel.INFO: 0
        }
        
        for issue in issues:
            base_score -= severity_weights.get(issue.severity, 0)
        
        # Bonus points for completeness
        if len(playbook.get("detection_steps", [])) >= 4:
            base_score += 5
        if len(playbook.get("response_steps", [])) >= 6:
            base_score += 5
        if len(playbook.get("mitre_techniques", [])) >= 3:
            base_score += 3
        
        # Clamp to 0-100 range
        return max(0, min(100, base_score))

    def _determine_status(self, issues: List[ValidationIssue], score: float) -> PlaybookStatus:
        """Determine overall playbook status based on validation"""
        critical_count = sum(1 for i in issues if i.severity == SeverityLevel.CRITICAL)
        high_count = sum(1 for i in issues if i.severity == SeverityLevel.HIGH)
        
        if critical_count > 0:
            return PlaybookStatus.INVALID
        elif high_count > 3:
            return PlaybookStatus.REVIEW_REQUIRED
        elif score >= 80:
            return PlaybookStatus.VALID
        else:
            return PlaybookStatus.REVIEW_REQUIRED

    def _generate_qa_summary(self, issues: List[ValidationIssue], passed: List[str], score: float) -> Dict[str, Any]:
        """Generate QA summary statistics"""
        severity_counts = {
            level.value: sum(1 for i in issues if i.severity == level)
            for level in SeverityLevel
        }
        
        category_counts: Dict[str, int] = {}
        for issue in issues:
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
        
        return {
            "severity_breakdown": severity_counts,
            "category_breakdown": category_counts,
            "total_issues": len(issues),
            "checks_passed": len(passed),
            "overall_score": score,
            "quality_grade": self._get_grade(score),
            "recommended_actions": self._get_recommendations(issues)
        }

    def _get_grade(self, score: float) -> str:
        """Convert numeric score to letter grade"""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"

    def _get_recommendations(self, issues: List[ValidationIssue]) -> List[str]:
        """Get prioritized recommendations"""
        recommendations = []
        
        # Critical first
        for issue in sorted(issues, key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}[x.severity.value]):
            if issue.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]:
                recommendations.append(f"[{issue.severity.value.upper()}] {issue.recommendation}")
        
        return recommendations[:10]  # Top 10 recommendations

    def batch_validate(self, playbooks: List[Dict[str, Any]]) -> List[ValidationResult]:
        """Validate multiple playbooks in batch"""
        return [self.validate_playbook(pb) for pb in playbooks]

    def generate_validation_report(self, result: ValidationResult, format: str = "json") -> str:
        """Generate human-readable validation report"""
        report_data = {
            "playbook_id": result.playbook_id,
            "playbook_name": result.playbook_name,
            "status": result.status.value,
            "overall_score": result.overall_score,
            "quality_grade": result.qa_summary["quality_grade"],
            "validation_timestamp": result.validation_timestamp,
            "issues": [
                {
                    "issue_id": i.issue_id,
                    "severity": i.severity.value,
                    "category": i.category,
                    "message": i.message,
                    "location": i.location,
                    "recommendation": i.recommendation
                }
                for i in result.issues
            ],
            "passed_checks": result.passed_checks,
            "qa_summary": result.qa_summary
        }
        
        if format == "json":
            return json.dumps(report_data, indent=2)
        elif format == "markdown":
            return self._generate_markdown_report(report_data)
        else:
            return json.dumps(report_data)

    def _generate_markdown_report(self, data: Dict[str, Any]) -> str:
        """Generate markdown format report"""
        md = f"""# Playbook Validation Report: {data['playbook_name']}

**Playbook ID:** {data['playbook_id']}  
**Status:** {data['status'].upper()}  
**Overall Score:** {data['overall_score']}/100 ({data['quality_grade']})  
**Validated:** {data['validation_timestamp']}

## Issues Found ({len(data['issues'])})

"""
        for issue in data['issues']:
            md += f"### [{issue['severity'].upper()}] {issue['issue_id']}\n"
            md += f"- **Category:** {issue['category']}\n"
            md += f"- **Location:** `{issue['location']}`\n"
            md += f"- **Message:** {issue['message']}\n"
            md += f"- **Recommendation:** {issue['recommendation']}\n\n"
        
        md += "## Checks Passed\n\n"
        for check in data['passed_checks']:
            md += f"- ✅ {check}\n"
        
        return md

    def get_validation_history(self) -> List[ValidationResult]:
        """Get all validation results from this session"""
        return self.validation_history
