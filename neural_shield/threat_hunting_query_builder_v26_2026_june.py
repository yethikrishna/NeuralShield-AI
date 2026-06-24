"""
Threat Hunting Query Builder v26 - NeuralShield AI Security Module
ADD-ONLY Feature Expansion - Dimension A
June 2026 - 100% Backward Compatible

Real working feature: Threat hunting query construction, validation, and execution engine
with MITRE ATT&CK mapping, template library, and query optimization.
"""

import re
import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from enum import Enum
from datetime import datetime, timedelta


class QueryOperator(Enum):
    EQUALS = "=="
    NOT_EQUALS = "!="
    GREATER_THAN = ">"
    LESS_THAN = "<"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"
    IN = "in"
    NOT_IN = "not_in"
    STARTS_WITH = "starts_with"
    ENDS_WITH = "ends_with"


class DataSource(Enum):
    PROCESS_CREATION = "process_creation"
    NETWORK_CONNECTION = "network_connection"
    FILE_CREATION = "file_creation"
    REGISTRY_MODIFICATION = "registry_modification"
    DNS_QUERY = "dns_query"
    AUTHENTICATION = "authentication"
    POWERSHELL = "powershell"
    CMD_LINE = "command_line"
    MEMORY_INJECTION = "memory_injection"


class SeverityLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class QueryCondition:
    field: str
    operator: QueryOperator
    value: Any
    case_sensitive: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "field": self.field,
            "operator": self.operator.value,
            "value": self.value,
            "case_sensitive": self.case_sensitive
        }


@dataclass
class HuntingQuery:
    name: str
    description: str
    data_source: DataSource
    conditions: List[QueryCondition] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    severity: SeverityLevel = SeverityLevel.MEDIUM
    tags: List[str] = field(default_factory=list)
    created_at: datetime = field(default_factory=datetime.now)
    query_id: str = field(init=False)

    def __post_init__(self):
        self.query_id = hashlib.sha256(
            f"{self.name}{self.created_at.isoformat()}".encode()
        ).hexdigest()[:16]

    def add_condition(self, condition: QueryCondition) -> None:
        """Add a condition to the query."""
        self.conditions.append(condition)

    def add_mitre_technique(self, technique_id: str) -> bool:
        """Add a MITRE ATT&CK technique with validation."""
        if re.match(r'^T\d{4}(\.\d{3})?$', technique_id):
            self.mitre_techniques.append(technique_id)
            return True
        return False

    def validate(self) -> Dict[str, Any]:
        """Validate the query structure and return validation report."""
        errors = []
        warnings = []

        if not self.name:
            errors.append("Query name is required")
        
        if len(self.conditions) == 0:
            warnings.append("Query has no conditions - will match all events")

        for cond in self.conditions:
            if not cond.field:
                errors.append(f"Condition has empty field name")
            if cond.operator in [QueryOperator.IN, QueryOperator.NOT_IN]:
                if not isinstance(cond.value, (list, tuple)):
                    errors.append(f"IN/NOT_IN operator requires list value")

        valid_fields = self._get_valid_fields()
        for cond in self.conditions:
            if cond.field not in valid_fields.get(self.data_source.value, []):
                warnings.append(f"Field '{cond.field}' may not be standard for {self.data_source.value}")

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
            "condition_count": len(self.conditions),
            "mitre_count": len(self.mitre_techniques)
        }

    def _get_valid_fields(self) -> Dict[str, List[str]]:
        return {
            "process_creation": ["process_name", "command_line", "parent_process", "user", "pid", "path"],
            "network_connection": ["src_ip", "dst_ip", "src_port", "dst_port", "protocol", "direction"],
            "file_creation": ["file_path", "file_name", "file_size", "extension", "sha256", "md5"],
            "registry_modification": ["key_path", "value_name", "value_data", "hive"],
            "dns_query": ["query_name", "query_type", "response", "rcode"],
            "authentication": ["username", "auth_type", "success", "source_ip", "logon_type"],
            "powershell": ["script_block", "command", "encoded", "script_id"],
            "command_line": ["command", "arguments", "parent", "user"],
            "memory_injection": ["target_pid", "technique", "allocation_size", "protection"]
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "query_id": self.query_id,
            "name": self.name,
            "description": self.description,
            "data_source": self.data_source.value,
            "conditions": [c.to_dict() for c in self.conditions],
            "mitre_techniques": self.mitre_techniques,
            "severity": self.severity.value,
            "tags": self.tags,
            "created_at": self.created_at.isoformat()
        }

    def to_json(self, pretty: bool = True) -> str:
        indent = 2 if pretty else None
        return json.dumps(self.to_dict(), indent=indent)


class QueryTemplateLibrary:
    """Pre-built threat hunting query templates."""

    _TEMPLATES = {
        "suspicious_powershell": {
            "name": "Suspicious PowerShell Execution",
            "description": "Detects obfuscated or encoded PowerShell commands",
            "data_source": DataSource.POWERSHELL,
            "severity": SeverityLevel.HIGH,
            "mitre_techniques": ["T1059.001", "T1027"],
            "conditions": [
                ("command_line", QueryOperator.CONTAINS, "-enc"),
                ("command_line", QueryOperator.CONTAINS, "-encodedcommand"),
                ("command_line", QueryOperator.CONTAINS, "base64"),
            ]
        },
        "lateral_movement_smb": {
            "name": "SMB Lateral Movement Detection",
            "description": "Detects SMB connections indicative of lateral movement",
            "data_source": DataSource.NETWORK_CONNECTION,
            "severity": SeverityLevel.HIGH,
            "mitre_techniques": ["T1021.002", "T1075"],
            "conditions": [
                ("dst_port", QueryOperator.EQUALS, 445),
                ("direction", QueryOperator.EQUALS, "outbound"),
            ]
        },
        "rundll32_suspicious": {
            "name": "Suspicious Rundll32 Execution",
            "description": "Detects suspicious rundll32 usage often used in malware",
            "data_source": DataSource.PROCESS_CREATION,
            "severity": SeverityLevel.HIGH,
            "mitre_techniques": ["T1218.011"],
            "conditions": [
                ("process_name", QueryOperator.EQUALS, "rundll32.exe"),
                ("command_line", QueryOperator.MATCHES, r"shell32\.dll.*Control_RunDLL"),
            ]
        },
        "credential_dumping": {
            "name": "Credential Dumping Detection",
            "description": "Detects processes commonly used for credential dumping",
            "data_source": DataSource.PROCESS_CREATION,
            "severity": SeverityLevel.CRITICAL,
            "mitre_techniques": ["T1003"],
            "conditions": [
                ("process_name", QueryOperator.IN, ["lsass.exe", "samdump.exe", "mimikatz.exe", "procdump.exe"]),
            ]
        },
        "dns_tunneling": {
            "name": "DNS Tunneling Detection",
            "description": "Detects unusual DNS queries indicative of tunneling",
            "data_source": DataSource.DNS_QUERY,
            "severity": SeverityLevel.MEDIUM,
            "mitre_techniques": ["T1048.003", "T1071.004"],
            "conditions": [
                ("query_name", QueryOperator.MATCHES, r"[a-f0-9]{32,}\."),
                ("query_type", QueryOperator.EQUALS, "TXT"),
            ]
        },
        "registry_persistence": {
            "name": "Registry Run Key Persistence",
            "description": "Detects modifications to registry run keys",
            "data_source": DataSource.REGISTRY_MODIFICATION,
            "severity": SeverityLevel.MEDIUM,
            "mitre_techniques": ["T1547.001"],
            "conditions": [
                ("key_path", QueryOperator.CONTAINS, r"Software\Microsoft\Windows\CurrentVersion\Run"),
            ]
        }
    }

    @classmethod
    def get_template_names(cls) -> List[str]:
        return list(cls._TEMPLATES.keys())

    @classmethod
    def get_template(cls, template_name: str) -> Optional[HuntingQuery]:
        """Create a HuntingQuery from template."""
        if template_name not in cls._TEMPLATES:
            return None
        
        tpl = cls._TEMPLATES[template_name]
        query = HuntingQuery(
            name=tpl["name"],
            description=tpl["description"],
            data_source=tpl["data_source"],
            severity=tpl["severity"],
            mitre_techniques=tpl["mitre_techniques"].copy()
        )
        
        for field, op, value in tpl["conditions"]:
            query.add_condition(QueryCondition(field=field, operator=op, value=value))
        
        return query

    @classmethod
    def list_templates(cls) -> List[Dict[str, str]]:
        return [
            {
                "id": tid,
                "name": t["name"],
                "severity": t["severity"].value,
                "mitre_count": len(t["mitre_techniques"])
            }
            for tid, t in cls._TEMPLATES.items()
        ]


class ThreatHuntingEngine:
    """Main threat hunting query execution engine."""

    def __init__(self):
        self.saved_queries: Dict[str, HuntingQuery] = {}
        self.query_history: List[Dict[str, Any]] = []
        self.execution_callbacks: List[Callable] = []

    def create_query(self, name: str, description: str, 
                     data_source: DataSource) -> HuntingQuery:
        """Create a new hunting query."""
        return HuntingQuery(
            name=name,
            description=description,
            data_source=data_source
        )

    def save_query(self, query: HuntingQuery) -> str:
        """Save a query to the library."""
        self.saved_queries[query.query_id] = query
        return query.query_id

    def get_saved_query(self, query_id: str) -> Optional[HuntingQuery]:
        return self.saved_queries.get(query_id)

    def list_saved_queries(self) -> List[Dict[str, Any]]:
        return [
            {
                "query_id": q.query_id,
                "name": q.name,
                "data_source": q.data_source.value,
                "severity": q.severity.value,
                "condition_count": len(q.conditions)
            }
            for q in self.saved_queries.values()
        ]

    def execute_query(self, query: HuntingQuery, 
                      event_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Execute a hunting query against event data."""
        start_time = datetime.now()
        matches = []

        validation = query.validate()
        if not validation["valid"]:
            return {
                "success": False,
                "error": "Query validation failed",
                "errors": validation["errors"]
            }

        for event in event_data:
            if self._match_conditions(query.conditions, event):
                matches.append(event)

        execution_time = (datetime.now() - start_time).total_seconds()
        
        result = {
            "success": True,
            "query_id": query.query_id,
            "query_name": query.name,
            "total_events": len(event_data),
            "matching_events": len(matches),
            "matches": matches,
            "execution_time_seconds": execution_time,
            "executed_at": datetime.now().isoformat(),
            "severity": query.severity.value,
            "mitre_techniques": query.mitre_techniques
        }

        self.query_history.append({
            "query_id": query.query_id,
            "matches": len(matches),
            "timestamp": datetime.now().isoformat()
        })

        return result

    def _match_conditions(self, conditions: List[QueryCondition], 
                          event: Dict[str, Any]) -> bool:
        """Match all conditions against an event (AND logic)."""
        for cond in conditions:
            if not self._match_single_condition(cond, event):
                return False
        return True

    def _match_single_condition(self, condition: QueryCondition, 
                                event: Dict[str, Any]) -> bool:
        """Match a single condition."""
        field_value = event.get(condition.field)
        if field_value is None:
            return False

        op = condition.operator
        target = condition.value

        if not condition.case_sensitive and isinstance(field_value, str):
            field_value = field_value.lower()
            if isinstance(target, str):
                target = target.lower()

        if op == QueryOperator.EQUALS:
            return field_value == target
        elif op == QueryOperator.NOT_EQUALS:
            return field_value != target
        elif op == QueryOperator.GREATER_THAN:
            return field_value > target
        elif op == QueryOperator.LESS_THAN:
            return field_value < target
        elif op == QueryOperator.CONTAINS:
            return isinstance(field_value, str) and target in field_value
        elif op == QueryOperator.NOT_CONTAINS:
            return isinstance(field_value, str) and target not in field_value
        elif op == QueryOperator.MATCHES:
            return isinstance(field_value, str) and bool(re.search(str(target), field_value))
        elif op == QueryOperator.IN:
            return field_value in target
        elif op == QueryOperator.NOT_IN:
            return field_value not in target
        elif op == QueryOperator.STARTS_WITH:
            return isinstance(field_value, str) and field_value.startswith(str(target))
        elif op == QueryOperator.ENDS_WITH:
            return isinstance(field_value, str) and field_value.endswith(str(target))
        
        return False

    def get_query_statistics(self, lookback_hours: int = 24) -> Dict[str, Any]:
        """Get query execution statistics."""
        cutoff = datetime.now() - timedelta(hours=lookback_hours)
        recent = [
            h for h in self.query_history 
            if datetime.fromisoformat(h["timestamp"]) > cutoff
        ]

        return {
            "total_queries_executed": len(self.query_history),
            "queries_last_24h": len(recent),
            "total_matches": sum(h["matches"] for h in recent),
            "saved_queries_count": len(self.saved_queries),
            "available_templates": len(QueryTemplateLibrary.get_template_names())
        }


# Export public API
__all__ = [
    "ThreatHuntingEngine",
    "HuntingQuery",
    "QueryCondition",
    "QueryTemplateLibrary",
    "QueryOperator",
    "DataSource",
    "SeverityLevel"
]
