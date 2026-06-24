"""
Threat Hunting Query Builder - NeuralShield AI Security Module
Stable API - Production Grade

Provides structured threat hunting query construction with:
- MITRE ATT&CK technique mapping
- IOC (Indicator of Compromise) pattern matching
- Time range filtering
- Severity-based query optimization
- Multi-platform query generation (SIEM, EDR, Log)
- Query validation and sanitization

This is an ADD-ONLY module - wraps existing functionality without modification.
"""

import re
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum, auto
from typing import Dict, List, Optional, Set, Tuple, Any, Union
from abc import ABC, abstractmethod


class QueryPlatform(Enum):
    """Supported query platforms for threat hunting."""
    SPLUNK = "splunk"
    ELASTICSEARCH = "elasticsearch"
    KIBANA = "kibana"
    MICROSOFT_DEFENDER = "microsoft_defender"
    CROWDSTRIKE = "crowdstrike"
    GENERIC_SIEM = "generic_siem"
    SQL = "sql"


class IOCType(Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    FILE_HASH = "file_hash"
    PROCESS_NAME = "process_name"
    REGISTRY_KEY = "registry_key"
    USER_AGENT = "user_agent"
    EMAIL = "email"


class SeverityLevel(Enum):
    """Severity levels for threat prioritization."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique representation."""
    technique_id: str
    tactic: str
    name: str
    description: str = ""
    data_sources: List[str] = field(default_factory=list)


@dataclass
class IOC:
    """Indicator of Compromise representation."""
    value: str
    ioc_type: IOCType
    description: str = ""
    source: str = ""
    confidence: float = 1.0
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None


@dataclass
class TimeRange:
    """Time range for query filtering."""
    start_time: datetime
    end_time: datetime

    @classmethod
    def last_hours(cls, hours: int) -> 'TimeRange':
        """Create time range for last N hours."""
        end = datetime.utcnow()
        start = end - timedelta(hours=hours)
        return cls(start_time=start, end_time=end)

    @classmethod
    def last_days(cls, days: int) -> 'TimeRange':
        """Create time range for last N days."""
        end = datetime.utcnow()
        start = end - timedelta(days=days)
        return cls(start_time=start, end_time=end)

    def to_iso_format(self) -> Tuple[str, str]:
        """Convert to ISO 8601 format strings."""
        return (
            self.start_time.isoformat() + "Z",
            self.end_time.isoformat() + "Z"
        )


class QueryTemplate(ABC):
    """Abstract base class for query templates."""

    @abstractmethod
    def generate(self, **kwargs) -> str:
        """Generate the query string."""
        pass

    @abstractmethod
    def validate(self, query: str) -> bool:
        """Validate the generated query."""
        pass


class SplunkQueryTemplate(QueryTemplate):
    """Splunk SPL query template generator."""

    def generate(self, **kwargs) -> str:
        """Generate Splunk SPL query."""
        index = kwargs.get('index', '*')
        sourcetype = kwargs.get('sourcetype', '*')
        conditions = kwargs.get('conditions', [])
        fields = kwargs.get('fields', ['*'])
        time_range = kwargs.get('time_range', None)
        stats = kwargs.get('stats', None)

        query_parts = [f"index={index} sourcetype={sourcetype}"]

        if conditions:
            query_parts.extend(conditions)

        if fields != ['*']:
            query_parts.append(f"| fields {', '.join(fields)}")

        if stats:
            query_parts.append(f"| {stats}")

        return " ".join(query_parts)

    def validate(self, query: str) -> bool:
        """Basic Splunk query validation."""
        if not query or len(query.strip()) == 0:
            return False
        # Check for common injection patterns
        dangerous_patterns = ['| delete', '| outputlookup', 'script']
        for pattern in dangerous_patterns:
            if pattern in query.lower():
                return False
        return True


class ElasticsearchQueryTemplate(QueryTemplate):
    """Elasticsearch DSL query template generator."""

    def generate(self, **kwargs) -> str:
        """Generate Elasticsearch DSL query."""
        must_conditions = kwargs.get('must_conditions', [])
        filter_conditions = kwargs.get('filter_conditions', [])
        time_range = kwargs.get('time_range', None)

        query = {
            "query": {
                "bool": {
                    "must": must_conditions,
                    "filter": filter_conditions
                }
            }
        }

        if time_range:
            start_iso, end_iso = time_range.to_iso_format()
            query["query"]["bool"]["filter"].append({
                "range": {
                    "@timestamp": {
                        "gte": start_iso,
                        "lte": end_iso
                    }
                }
            })

        return json.dumps(query, indent=2)

    def validate(self, query: str) -> bool:
        """Validate Elasticsearch query JSON."""
        try:
            parsed = json.loads(query)
            return "query" in parsed
        except json.JSONDecodeError:
            return False


class ThreatHuntingQueryBuilder:
    """
    Main threat hunting query builder class.

    Features:
    - MITRE ATT&CK technique-based query generation
    - IOC matching query construction
    - Multi-platform output
    - Query validation and sanitization
    - Query history tracking
    """

    # MITRE ATT&CK technique mappings (core subset)
    _MITRE_TECHNIQUES: Dict[str, MITRETechnique] = {
        "T1059": MITRETechnique(
            technique_id="T1059",
            tactic="Execution",
            name="Command and Scripting Interpreter",
            data_sources=["process_creation", "command_line"]
        ),
        "T1027": MITRETechnique(
            technique_id="T1027",
            tactic="Defense Evasion",
            name="Obfuscated Files or Information",
            data_sources=["file", "process_creation"]
        ),
        "T1003": MITRETechnique(
            technique_id="T1003",
            tactic="Credential Access",
            name="OS Credential Dumping",
            data_sources=["process_access", "file"]
        ),
        "T1055": MITRETechnique(
            technique_id="T1055",
            tactic="Privilege Escalation",
            name="Process Injection",
            data_sources=["process_access", "process_creation"]
        ),
        "T1071": MITRETechnique(
            technique_id="T1071",
            tactic="Command and Control",
            name="Application Layer Protocol",
            data_sources=["network_traffic", "dns"]
        ),
        "T1046": MITRETechnique(
            technique_id="T1046",
            tactic="Discovery",
            name="Network Service Scanning",
            data_sources=["network_traffic", "connection"]
        ),
        "T1083": MITRETechnique(
            technique_id="T1083",
            tactic="Discovery",
            name="File and Directory Discovery",
            data_sources=["process_creation", "file"]
        ),
        "T1021": MITRETechnique(
            technique_id="T1021",
            tactic="Lateral Movement",
            name="Remote Services",
            data_sources=["authentication", "network_traffic"]
        ),
        "T1041": MITRETechnique(
            technique_id="T1041",
            tactic="Exfiltration",
            name="Exfiltration Over C2 Channel",
            data_sources=["network_traffic", "file"]
        ),
        "T1486": MITRETechnique(
            technique_id="T1486",
            tactic="Impact",
            name="Data Encrypted for Impact",
            data_sources=["file", "process_creation"]
        ),
    }

    def __init__(self, default_platform: QueryPlatform = QueryPlatform.SPLUNK):
        """Initialize query builder with default platform."""
        self.default_platform = default_platform
        self._query_history: List[Dict[str, Any]] = []
        self._templates: Dict[QueryPlatform, QueryTemplate] = {
            QueryPlatform.SPLUNK: SplunkQueryTemplate(),
            QueryPlatform.ELASTICSEARCH: ElasticsearchQueryTemplate(),
            QueryPlatform.KIBANA: ElasticsearchQueryTemplate(),
        }
        self._ioc_patterns = self._compile_ioc_patterns()

    def _compile_ioc_patterns(self) -> Dict[IOCType, re.Pattern]:
        """Compile regex patterns for IOC validation."""
        return {
            IOCType.IP_ADDRESS: re.compile(
                r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}'
                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
            ),
            IOCType.DOMAIN: re.compile(
                r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+'
                r'[a-zA-Z]{2,}$'
            ),
            IOCType.FILE_HASH: re.compile(
                r'^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$'
            ),
        }

    def get_supported_techniques(self) -> List[MITRETechnique]:
        """Get list of supported MITRE ATT&CK techniques."""
        return list(self._MITRE_TECHNIQUES.values())

    def get_technique_by_id(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get MITRE technique by ID."""
        return self._MITRE_TECHNIQUES.get(technique_id)

    def validate_ioc(self, ioc: IOC) -> Tuple[bool, List[str]]:
        """
        Validate IOC value against expected pattern.

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        if not ioc.value or len(ioc.value.strip()) == 0:
            errors.append("IOC value cannot be empty")
            return False, errors

        if ioc.ioc_type in self._ioc_patterns:
            pattern = self._ioc_patterns[ioc.ioc_type]
            if not pattern.match(ioc.value):
                errors.append(
                    f"IOC value '{ioc.value}' does not match "
                    f"expected pattern for {ioc.ioc_type.value}"
                )

        if ioc.confidence < 0 or ioc.confidence > 1:
            errors.append("Confidence must be between 0 and 1")

        return len(errors) == 0, errors

    def build_ioc_search_query(
        self,
        iocs: List[IOC],
        platform: Optional[QueryPlatform] = None,
        time_range: Optional[TimeRange] = None,
        severity: SeverityLevel = SeverityLevel.HIGH
    ) -> Dict[str, Any]:
        """
        Build query to search for IOCs.

        Args:
            iocs: List of IOCs to search for
            platform: Target query platform
            time_range: Optional time range filter
            severity: Query severity level

        Returns:
            Dictionary containing query, metadata, and validation info
        """
        target_platform = platform or self.default_platform

        # Validate all IOCs
        validation_results = []
        valid_iocs = []
        for ioc in iocs:
            is_valid, errors = self.validate_ioc(ioc)
            validation_results.append({
                "ioc": ioc.value,
                "type": ioc.ioc_type.value,
                "is_valid": is_valid,
                "errors": errors
            })
            if is_valid:
                valid_iocs.append(ioc)

        if not valid_iocs:
            return {
                "query": "",
                "platform": target_platform.value,
                "valid_iocs_count": 0,
                "validation": validation_results,
                "error": "No valid IOCs provided"
            }

        # Group IOCs by type
        iocs_by_type: Dict[IOCType, List[str]] = {}
        for ioc in valid_iocs:
            if ioc.ioc_type not in iocs_by_type:
                iocs_by_type[ioc.ioc_type] = []
            iocs_by_type[ioc.ioc_type].append(ioc.value)

        # Generate platform-specific query
        query = self._generate_ioc_query(
            target_platform, iocs_by_type, time_range, severity
        )

        result = {
            "query": query,
            "platform": target_platform.value,
            "valid_iocs_count": len(valid_iocs),
            "iocs_by_type": {k.value: v for k, v in iocs_by_type.items()},
            "severity": severity.value,
            "time_range": time_range.to_iso_format() if time_range else None,
            "validation": validation_results,
            "generated_at": datetime.utcnow().isoformat() + "Z"
        }

        self._query_history.append(result)
        return result

    def _generate_ioc_query(
        self,
        platform: QueryPlatform,
        iocs_by_type: Dict[IOCType, List[str]],
        time_range: Optional[TimeRange],
        severity: SeverityLevel
    ) -> str:
        """Generate platform-specific IOC search query."""
        if platform == QueryPlatform.SPLUNK:
            return self._generate_splunk_ioc_query(iocs_by_type, time_range)
        elif platform == QueryPlatform.ELASTICSEARCH:
            return self._generate_es_ioc_query(iocs_by_type, time_range)
        else:
            return self._generate_generic_ioc_query(iocs_by_type, time_range)

    def _generate_splunk_ioc_query(
        self,
        iocs_by_type: Dict[IOCType, List[str]],
        time_range: Optional[TimeRange]
    ) -> str:
        """Generate Splunk SPL query for IOC search."""
        conditions = []

        for ioc_type, values in iocs_by_type.items():
            if ioc_type == IOCType.IP_ADDRESS:
                ip_list = ", ".join(f'"{v}"' for v in values)
                conditions.append(f'(src_ip IN ({ip_list}) OR dest_ip IN ({ip_list}))')
            elif ioc_type == IOCType.DOMAIN:
                domain_list = ", ".join(f'"{v}"' for v in values)
                conditions.append(f'(query IN ({domain_list}) OR dest IN ({domain_list}))')
            elif ioc_type == IOCType.FILE_HASH:
                hash_list = ", ".join(f'"{v}"' for v in values)
                conditions.append(f'(md5 IN ({hash_list}) OR sha1 IN ({hash_list}) OR sha256 IN ({hash_list}))')

        template = SplunkQueryTemplate()
        return template.generate(
            index="*",
            sourcetype="*",
            conditions=conditions,
            time_range=time_range
        )

    def _generate_es_ioc_query(
        self,
        iocs_by_type: Dict[IOCType, List[str]],
        time_range: Optional[TimeRange]
    ) -> str:
        """Generate Elasticsearch DSL query for IOC search."""
        must_conditions = []

        for ioc_type, values in iocs_by_type.items():
            if ioc_type == IOCType.IP_ADDRESS:
                must_conditions.append({
                    "terms": {
                        "source.ip": values
                    }
                })
            elif ioc_type == IOCType.DOMAIN:
                must_conditions.append({
                    "terms": {
                        "dns.question.name": values
                    }
                })
            elif ioc_type == IOCType.FILE_HASH:
                must_conditions.append({
                    "terms": {
                        "hash.sha256": values
                    }
                })

        template = ElasticsearchQueryTemplate()
        return template.generate(
            must_conditions=must_conditions,
            filter_conditions=[],
            time_range=time_range
        )

    def _generate_generic_ioc_query(
        self,
        iocs_by_type: Dict[IOCType, List[str]],
        time_range: Optional[TimeRange]
    ) -> str:
        """Generate generic query string."""
        parts = []
        for ioc_type, values in iocs_by_type.items():
            parts.append(f"{ioc_type.value}: ({' OR '.join(values)})")

        if time_range:
            start, end = time_range.to_iso_format()
            parts.append(f"time: [{start} TO {end}]")

        return " AND ".join(parts)

    def build_mitre_technique_query(
        self,
        technique_id: str,
        platform: Optional[QueryPlatform] = None,
        time_range: Optional[TimeRange] = None,
        additional_filters: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Build query for a specific MITRE ATT&CK technique.

        Args:
            technique_id: MITRE technique ID (e.g., T1059)
            platform: Target query platform
            time_range: Optional time range filter
            additional_filters: Optional key-value filters

        Returns:
            Dictionary containing query, technique info, and metadata
        """
        technique = self.get_technique_by_id(technique_id)
        if not technique:
            return {
                "query": "",
                "error": f"Unknown technique ID: {technique_id}",
                "supported_techniques": list(self._MITRE_TECHNIQUES.keys())
            }

        target_platform = platform or self.default_platform

        query = self._generate_mitre_query(
            target_platform, technique, time_range, additional_filters or {}
        )

        result = {
            "query": query,
            "technique": {
                "id": technique.technique_id,
                "name": technique.name,
                "tactic": technique.tactic,
                "data_sources": technique.data_sources
            },
            "platform": target_platform.value,
            "time_range": time_range.to_iso_format() if time_range else None,
            "additional_filters": additional_filters,
            "generated_at": datetime.utcnow().isoformat() + "Z"
        }

        self._query_history.append(result)
        return result

    def _generate_mitre_query(
        self,
        platform: QueryPlatform,
        technique: MITRETechnique,
        time_range: Optional[TimeRange],
        filters: Dict[str, Any]
    ) -> str:
        """Generate MITRE technique-specific query."""
        if platform == QueryPlatform.SPLUNK:
            conditions = [f"mitre_technique_id={technique.technique_id}"]
            for k, v in filters.items():
                conditions.append(f"{k}={v}")

            template = SplunkQueryTemplate()
            return template.generate(
                index="*",
                sourcetype="*",
                conditions=conditions,
                time_range=time_range
            )
        else:
            must_conditions = [
                {"match": {"mitre.technique.id": technique.technique_id}}
            ]
            for k, v in filters.items():
                must_conditions.append({"match": {k: v}})

            template = ElasticsearchQueryTemplate()
            return template.generate(
                must_conditions=must_conditions,
                filter_conditions=[],
                time_range=time_range
            )

    def get_query_history(self, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """Get query generation history."""
        history = list(reversed(self._query_history))
        if limit:
            return history[:limit]
        return history

    def get_query_statistics(self) -> Dict[str, Any]:
        """Get statistics about generated queries."""
        platform_counts: Dict[str, int] = {}
        technique_counts: Dict[str, int] = {}

        for query in self._query_history:
            platform = query.get("platform", "unknown")
            platform_counts[platform] = platform_counts.get(platform, 0) + 1

            if "technique" in query:
                tech_id = query["technique"].get("id", "unknown")
                technique_counts[tech_id] = technique_counts.get(tech_id, 0) + 1

        return {
            "total_queries_generated": len(self._query_history),
            "queries_by_platform": platform_counts,
            "queries_by_technique": technique_counts,
            "first_query_at": self._query_history[0]["generated_at"] if self._query_history else None,
            "last_query_at": self._query_history[-1]["generated_at"] if self._query_history else None
        }

    def sanitize_query(self, query: str) -> str:
        """
        Sanitize query to prevent injection attacks.
        Removes dangerous commands and patterns.
        """
        dangerous_patterns = [
            (r'\|\s*delete\b', ''),
            (r'\|\s*outputlookup\b', ''),
            (r'exec\s*\(', ''),
            (r'system\s*\(', ''),
        ]

        sanitized = query
        for pattern, replacement in dangerous_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        return sanitized

    def export_query_package(
        self,
        queries: List[Dict[str, Any]],
        name: str,
        description: str = ""
    ) -> str:
        """
        Export a package of queries as JSON.

        Returns:
            JSON string of query package
        """
        package = {
            "name": name,
            "description": description,
            "version": "1.0.0",
            "created_at": datetime.utcnow().isoformat() + "Z",
            "queries": queries,
            "checksum": hashlib.sha256(json.dumps(queries, sort_keys=True).encode()).hexdigest()
        }
        return json.dumps(package, indent=2)


# Singleton instance for easy import
_default_builder: Optional[ThreatHuntingQueryBuilder] = None


def get_query_builder(platform: QueryPlatform = QueryPlatform.SPLUNK) -> ThreatHuntingQueryBuilder:
    """Get or create default query builder instance."""
    global _default_builder
    if _default_builder is None:
        _default_builder = ThreatHuntingQueryBuilder(platform)
    return _default_builder
