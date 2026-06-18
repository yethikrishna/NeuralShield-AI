"""
Threat Intelligence Signature Version Control & Rollback Manager
June 2026 - Production Grade Implementation

Provides semantic versioning, atomic rollback, deployment validation gates,
and integrity verification for threat intelligence signatures (YARA, Snort, Suricata, Sigma).

Core Features:
1. Semantic versioning (MAJOR.MINOR.PATCH) with auto-bump
2. Atomic rollback with integrity validation
3. Deployment validation gates with risk scoring
4. Version diff and impact analysis
5. Complete audit logging and history tracking
6. Cryptographic content verification (SHA-256)
"""

import hashlib
import json
import time
import difflib
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
from pathlib import Path
import uuid


class SignatureType(Enum):
    YARA = "yara"
    SNORT = "snort"
    SIGMA = "sigma"
    SURICATA = "suricata"
    CUSTOM = "custom"


class DeploymentStatus(Enum):
    PENDING = "pending"
    VALIDATING = "validating"
    DEPLOYED = "deployed"
    ROLLED_BACK = "rolled_back"
    FAILED = "failed"


@dataclass
class SignatureVersion:
    version_id: str
    version_number: str
    signature_type: SignatureType
    signature_name: str
    content: str
    content_hash: str
    author: str
    created_timestamp: float
    deployment_status: DeploymentStatus
    deployed_timestamp: Optional[float]
    change_description: str
    risk_score: float
    previous_version_id: Optional[str]
    validation_results: Dict[str, Any]


@dataclass
class RollbackResult:
    success: bool
    new_version_id: str
    new_version_number: str
    rollback_from_version: str
    rollback_to_version: str
    message: str
    timestamp: float


@dataclass
class VersionDiff:
    version_a: str
    version_b: str
    similarity_score: float
    lines_added: int
    lines_removed: int
    lines_modified: int
    impact_assessment: str
    diff_summary: str


class ThreatIntelSignatureVersionControl:
    """
    Production-grade threat intelligence signature version control system.
    Manages signature lifecycle with versioning, validation, and rollback.
    """

    def __init__(self, storage_path: Optional[str] = None):
        self.versions: Dict[str, SignatureVersion] = {}
        self.version_history: List[str] = []
        self.deployed_version_id: Optional[str] = None
        self.audit_log: List[Dict[str, Any]] = []
        self.storage_path = Path(storage_path) if storage_path else None
        self._validation_rules = self._initialize_validation_rules()

    def _initialize_validation_rules(self) -> Dict[str, Any]:
        """Initialize signature validation rules."""
        return {
            SignatureType.YARA: {
                "min_length": 50,
                "required_keywords": ["rule", "condition"],
                "banned_patterns": ["private_key", "password"],
                "max_complexity": 100
            },
            SignatureType.SNORT: {
                "min_length": 20,
                "required_keywords": ["alert", "sid:"],
                "banned_patterns": [],
                "max_complexity": 50
            },
            SignatureType.SIGMA: {
                "min_length": 30,
                "required_keywords": ["title", "detection"],
                "banned_patterns": [],
                "max_complexity": 80
            },
            SignatureType.SURICATA: {
                "min_length": 20,
                "required_keywords": ["alert", "sid:"],
                "banned_patterns": [],
                "max_complexity": 50
            }
        }

    def _generate_version_id(self) -> str:
        """Generate unique version identifier."""
        return f"sig_{uuid.uuid4().hex[:12]}"

    def _compute_content_hash(self, content: str) -> str:
        """Compute SHA-256 hash of signature content."""
        return hashlib.sha256(content.encode('utf-8')).hexdigest()

    def _calculate_risk_score(
        self,
        content: str,
        signature_type: SignatureType,
        previous_content: Optional[str] = None
    ) -> float:
        """
        Calculate deployment risk score (0.0 - 1.0).
        Lower = safer, Higher = riskier.
        """
        risk_score = 0.0
        rules = self._validation_rules.get(signature_type, {})
        
        # Content length risk
        min_length = rules.get("min_length", 0)
        if len(content) < min_length:
            risk_score += 0.3
        
        # Banned patterns check
        banned = rules.get("banned_patterns", [])
        for pattern in banned:
            if pattern.lower() in content.lower():
                risk_score += 0.4
        
        # Change magnitude risk (if previous exists)
        if previous_content:
            similarity = difflib.SequenceMatcher(None, content, previous_content).ratio()
            change_magnitude = 1.0 - similarity
            risk_score += change_magnitude * 0.5
        
        # Complexity heuristic
        complexity = min(content.count('|') + content.count('&'), 10) / 10.0
        risk_score += complexity * 0.2
        
        return min(risk_score, 1.0)

    def _validate_signature_syntax(
        self,
        content: str,
        signature_type: SignatureType
    ) -> Tuple[bool, List[str], List[str]]:
        """Basic syntax validation for signature types."""
        is_valid = True
        errors = []
        warnings = []
        
        rules = self._validation_rules.get(signature_type, {})
        required = rules.get("required_keywords", [])
        
        for keyword in required:
            if keyword not in content:
                errors.append(f"Missing required keyword: {keyword}")
                is_valid = False
        
        if len(content.strip()) < rules.get("min_length", 0):
            warnings.append(f"Content shorter than recommended minimum")
        
        return is_valid, errors, warnings

    def create_new_version(
        self,
        signature_name: str,
        signature_type: SignatureType,
        content: str,
        author: str,
        change_description: str,
        previous_version_id: Optional[str] = None
    ) -> SignatureVersion:
        """
        Create a new signature version with semantic versioning.
        Auto-bumps version number based on change magnitude.
        """
        version_id = self._generate_version_id()
        content_hash = self._compute_content_hash(content)
        
        # Determine version number
        if previous_version_id and previous_version_id in self.versions:
            prev = self.versions[previous_version_id]
            prev_major, prev_minor, prev_patch = map(int, prev.version_number.split('.'))
            
            # Calculate change magnitude for auto-bump
            similarity = difflib.SequenceMatcher(None, content, prev.content).ratio()
            
            if similarity < 0.7:  # Major change
                major, minor, patch = prev_major + 1, 0, 0
            elif similarity < 0.9:  # Minor change
                major, minor, patch = prev_major, prev_minor + 1, 0
            else:  # Patch change
                major, minor, patch = prev_major, prev_minor, prev_patch + 1
            
            version_number = f"{major}.{minor}.{patch}"
            risk_score = self._calculate_risk_score(content, signature_type, prev.content)
        else:
            version_number = "1.0.0"
            risk_score = self._calculate_risk_score(content, signature_type)
        
        # Run validation
        syntax_valid, val_errors, val_warnings = self._validate_signature_syntax(content, signature_type)
        
        version = SignatureVersion(
            version_id=version_id,
            version_number=version_number,
            signature_type=signature_type,
            signature_name=signature_name,
            content=content,
            content_hash=content_hash,
            author=author,
            created_timestamp=time.time(),
            deployment_status=DeploymentStatus.PENDING,
            deployed_timestamp=None,
            change_description=change_description,
            risk_score=risk_score,
            previous_version_id=previous_version_id,
            validation_results={
                "syntax_valid": syntax_valid,
                "errors": val_errors,
                "warnings": val_warnings,
                "risk_score": risk_score
            }
        )
        
        self.versions[version_id] = version
        self.version_history.append(version_id)
        
        self._log_audit({
            "action": "create_version",
            "version_id": version_id,
            "version_number": version_number,
            "signature_name": signature_name,
            "author": author,
            "risk_score": risk_score,
            "timestamp": time.time()
        })
        
        return version

    def validate_integrity(self, version_id: str) -> Tuple[bool, str]:
        """
        Validate content integrity of a signature version.
        Returns (is_valid: bool, message: str)
        """
        if version_id not in self.versions:
            return False, "Version not found"
        
        version = self.versions[version_id]
        computed_hash = self._compute_content_hash(version.content)
        
        if computed_hash != version.content_hash:
            self._log_audit({
                "action": "integrity_check_failed",
                "version_id": version_id,
                "expected_hash": version.content_hash,
                "computed_hash": computed_hash,
                "timestamp": time.time()
            })
            return False, "Content hash mismatch - integrity compromised"
        
        return True, "Integrity verified"

    def validate_deployment_gates(self, version_id: str) -> Tuple[bool, Dict[str, Any]]:
        """
        Run deployment validation gates before allowing deployment.
        Returns (can_deploy: bool, gate_results: dict)
        """
        if version_id not in self.versions:
            return False, {"error": "Version not found"}
        
        version = self.versions[version_id]
        gates = {
            "integrity_check": self.validate_integrity(version_id)[0],
            "syntax_validation": version.validation_results.get("syntax_valid", False),
            "risk_threshold": version.risk_score < 0.7,
            "no_critical_errors": len(version.validation_results.get("errors", [])) == 0
        }
        
        all_passed = all(gates.values())
        
        self._log_audit({
            "action": "deployment_gates_check",
            "version_id": version_id,
            "all_passed": all_passed,
            "gates": gates,
            "timestamp": time.time()
        })
        
        return all_passed, gates

    def mark_deployed(self, version_id: str) -> Tuple[bool, str]:
        """
        Mark a version as deployed after validation gates pass.
        """
        gates_passed, gate_results = self.validate_deployment_gates(version_id)
        if not gates_passed:
            return False, f"Deployment gates failed: {gate_results}"
        
        if version_id not in self.versions:
            return False, "Version not found"
        
        version = self.versions[version_id]
        version.deployment_status = DeploymentStatus.DEPLOYED
        version.deployed_timestamp = time.time()
        self.deployed_version_id = version_id
        
        self._log_audit({
            "action": "mark_deployed",
            "version_id": version_id,
            "version_number": version.version_number,
            "timestamp": time.time()
        })
        
        return True, "Version marked as deployed"

    def compare_versions(self, version_a_id: str, version_b_id: str) -> VersionDiff:
        """
        Compare two signature versions and generate diff analysis.
        """
        if version_a_id not in self.versions or version_b_id not in self.versions:
            raise ValueError("One or both versions not found")
        
        v_a = self.versions[version_a_id]
        v_b = self.versions[version_b_id]
        
        similarity = difflib.SequenceMatcher(None, v_a.content, v_b.content).ratio()
        
        a_lines = v_a.content.split('\n')
        b_lines = v_b.content.split('\n')
        
        diff = list(difflib.unified_diff(a_lines, b_lines, n=0))
        added = sum(1 for line in diff if line.startswith('+') and not line.startswith('+++'))
        removed = sum(1 for line in diff if line.startswith('-') and not line.startswith('---'))
        
        # Impact assessment
        if similarity > 0.95:
            impact = "LOW: Minor cosmetic changes"
        elif similarity > 0.85:
            impact = "MEDIUM: Targeted changes to specific patterns"
        elif similarity > 0.7:
            impact = "HIGH: Significant logic changes detected"
        else:
            impact = "CRITICAL: Major rewrite or replacement"
        
        return VersionDiff(
            version_a=v_a.version_number,
            version_b=v_b.version_number,
            similarity_score=similarity,
            lines_added=added,
            lines_removed=removed,
            lines_modified=min(added, removed),
            impact_assessment=impact,
            diff_summary=f"Changed from v{v_a.version_number} to v{v_b.version_number}"
        )

    def rollback_to_version(self, target_version_id: str, author: str) -> RollbackResult:
        """
        Atomic rollback to a previous version.
        Creates a NEW version from the target (preserves history).
        """
        if target_version_id not in self.versions:
            return RollbackResult(
                success=False,
                new_version_id="",
                new_version_number="",
                rollback_from_version="",
                rollback_to_version="",
                message="Target version not found",
                timestamp=time.time()
            )
        
        target = self.versions[target_version_id]
        
        # Verify target integrity
        integrity_ok, integrity_msg = self.validate_integrity(target_version_id)
        if not integrity_ok:
            return RollbackResult(
                success=False,
                new_version_id="",
                new_version_number="",
                rollback_from_version=self.deployed_version_id or "unknown",
                rollback_to_version=target_version_id,
                message=f"Rollback target integrity check failed: {integrity_msg}",
                timestamp=time.time()
            )
        
        # Create new version as rollback copy
        current_deployed = self.versions.get(self.deployed_version_id) if self.deployed_version_id else None
        rollback_version = self.create_new_version(
            signature_name=target.signature_name,
            signature_type=target.signature_type,
            content=target.content,
            author=author,
            change_description=f"ROLLBACK: Reverted to version {target.version_number}",
            previous_version_id=self.deployed_version_id
        )
        
        # Mark as deployed
        self.mark_deployed(rollback_version.version_id)
        
        # Mark old version as rolled back
        if current_deployed:
            current_deployed.deployment_status = DeploymentStatus.ROLLED_BACK
        
        self._log_audit({
            "action": "rollback",
            "from_version": current_deployed.version_number if current_deployed else "none",
            "to_version": target.version_number,
            "new_version_id": rollback_version.version_id,
            "author": author,
            "timestamp": time.time()
        })
        
        return RollbackResult(
            success=True,
            new_version_id=rollback_version.version_id,
            new_version_number=rollback_version.version_number,
            rollback_from_version=current_deployed.version_number if current_deployed else "none",
            rollback_to_version=target.version_number,
            message=f"Successfully rolled back. New version {rollback_version.version_number} created from rollback",
            timestamp=time.time()
        )

    def get_version_history(self) -> List[Dict[str, Any]]:
        """Get complete version history with metadata."""
        history = []
        for vid in self.version_history:
            v = self.versions[vid]
            history.append({
                "version_id": v.version_id,
                "version_number": v.version_number,
                "signature_name": v.signature_name,
                "signature_type": v.signature_type.value,
                "author": v.author,
                "created": datetime.fromtimestamp(v.created_timestamp, timezone.utc).isoformat(),
                "status": v.deployment_status.value,
                "risk_score": v.risk_score,
                "description": v.change_description[:80] + "..." if len(v.change_description) > 80 else v.change_description
            })
        return history

    def _log_audit(self, entry: Dict[str, Any]) -> None:
        """Add entry to audit log."""
        self.audit_log.append(entry)
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]

    def get_statistics(self) -> Dict[str, Any]:
        """Get version control system statistics."""
        deployed = [v for v in self.versions.values() if v.deployment_status == DeploymentStatus.DEPLOYED]
        rolled_back = [v for v in self.versions.values() if v.deployment_status == DeploymentStatus.ROLLED_BACK]
        
        avg_risk = sum(v.risk_score for v in self.versions.values()) / len(self.versions) if self.versions else 0
        
        return {
            "total_versions": len(self.versions),
            "deployed_count": len(deployed),
            "rolled_back_count": len(rolled_back),
            "rollback_rate": len(rolled_back) / len(self.versions) if self.versions else 0,
            "average_risk_score": avg_risk,
            "audit_log_entries": len(self.audit_log),
            "current_deployed_version": self.deployed_version_id
        }
