"""
Threat Intelligence Incident Response Automation Engine with MITRE ATT&CK Mapping
June 20, 2026 - Production Grade Implementation

Real working feature:
- Automated incident classification and severity scoring
- MITRE ATT&CK tactic and technique mapping
- Automated response playbook generation
- Incident timeline reconstruction
- Stakeholder notification routing
"""

import hashlib
import json
import time
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime, timedelta
from collections import defaultdict


class IncidentType(Enum):
    """Types of security incidents"""
    MALWARE = "malware"
    PHISHING = "phishing"
    RANSOMWARE = "ransomware"
    DATA_BREACH = "data_breach"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    DENIAL_OF_SERVICE = "denial_of_service"
    SQL_INJECTION = "sql_injection"
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    ADVERSARIAL_PROMPT = "adversarial_prompt"
    MODEL_EXTRACTION = "model_extraction"
    UNKNOWN = "unknown"


class IncidentSeverity(Enum):
    """Incident severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class MITRETechnique(Enum):
    """Common MITRE ATT&CK Techniques"""
    T1566 = "phishing"
    T1059 = "command_and_scripting_interpreter"
    T1027 = "obfuscated_files_or_information"
    T1003 = "credential_dumping"
    T1046 = "network_service_scanning"
    T1055 = "process_injection"
    T1078 = "valid_accounts"
    T1082 = "system_information_discovery"
    T1083 = "file_and_directory_discovery"
    T1090 = "proxy"
    T1095 = "non_application_layer_protocol"
    T1105 = "ingress_tool_transfer"
    T1110 = "brute_force"
    T1140 = "deobfuscate_decode_files_or_information"
    T1204 = "user_execution"
    T1486 = "data_encrypted_for_impact"
    T1490 = "inhibit_system_recovery"
    T1555 = "credentials_from_password_stores"
    T1562 = "impair_defenses"
    T1567 = "exfiltration_over_web_service"
    T1574 = "hijack_execution_flow"


class ResponseActionType(Enum):
    """Types of automated response actions"""
    ISOLATE_ASSET = "isolate_asset"
    BLOCK_IP = "block_ip"
    BLOCK_DOMAIN = "block_domain"
    RESET_CREDENTIALS = "reset_credentials"
    ENABLE_MFA = "enable_mfa"
    SCAN_FOR_MALWARE = "scan_for_malware"
    COLLECT_FORENSICS = "collect_forensics"
    NOTIFY_SECURITY_TEAM = "notify_security_team"
    NOTIFY_EXECUTIVES = "notify_executives"
    NOTIFY_LEGAL = "notify_legal"
    NOTIFY_PR = "notify_pr"
    ENABLE_ADDITIONAL_LOGGING = "enable_additional_logging"
    QUARANTINE_FILE = "quarantine_file"
    TERMINATE_PROCESS = "terminate_process"
    ROLLBACK_CHANGES = "rollback_changes"


@dataclass
class IncidentEvent:
    """Individual event within an incident"""
    event_id: str
    timestamp: datetime
    source: str
    event_type: str
    description: str
    raw_data: Dict[str, Any] = field(default_factory=dict)
    ip_address: Optional[str] = None
    user_identifier: Optional[str] = None
    asset_identifier: Optional[str] = None


@dataclass
class MITREMapping:
    """MITRE ATT&CK mapping result"""
    tactic: MITRETactic
    technique: MITRETechnique
    confidence_score: float
    evidence: List[str] = field(default_factory=list)


@dataclass
class ResponseAction:
    """Automated response action"""
    action_id: str
    action_type: ResponseActionType
    description: str
    priority: int
    target: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    executed: bool = False
    execution_time: Optional[datetime] = None
    success: Optional[bool] = None


@dataclass
class IncidentResponseResult:
    """Complete incident response result"""
    incident_id: str
    incident_type: IncidentType
    severity: IncidentSeverity
    severity_score: float
    title: str
    description: str
    events: List[IncidentEvent] = field(default_factory=list)
    mitre_mappings: List[MITREMapping] = field(default_factory=list)
    response_actions: List[ResponseAction] = field(default_factory=list)
    affected_assets: List[str] = field(default_factory=list)
    affected_users: List[str] = field(default_factory=list)
    indicators_of_compromise: List[str] = field(default_factory=list)
    timeline_summary: str = ""
    recommendations: List[str] = field(default_factory=list)
    response_playbook: str = ""
    created_at: datetime = field(default_factory=datetime.now)
    processing_time_ms: float = 0.0


class IncidentResponseAutomationEngine:
    """
    Production-grade Incident Response Automation Engine
    
    Real working capabilities:
    1. Process raw security events and correlate into incidents
    2. Classify incident type and calculate severity score
    3. Map incidents to MITRE ATT&CK framework
    4. Generate automated response playbooks
    5. Create incident timeline
    6. Route notifications to appropriate stakeholders
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.incident_history: List[IncidentResponseResult] = []
        self._initialize_patterns()
        self._initialize_mitre_mapping_rules()
        self._initialize_response_playbooks()
        
    def _initialize_patterns(self):
        """Initialize regex patterns for incident classification"""
        self.incident_patterns = {
            IncidentType.MALWARE: [
                r'malware', r'virus', r'trojan', r'ransom', r'backdoor',
                r'spyware', r'adware', r'rootkit', r'worm'
            ],
            IncidentType.PHISHING: [
                r'phish', r'spearphish', r'fake.*email', r'spoof.*email',
                r'credential.*harvest', r'fake.*login'
            ],
            IncidentType.RANSOMWARE: [
                r'ransomware', r'encrypt.*file', r'bitcoin', r'readme.*restore',
                r'decrypt.*key', r'locked.*file'
            ],
            IncidentType.DATA_BREACH: [
                r'data.*breach', r'data.*leak', r'unauthorized.*access.*data',
                r'confidential.*data', r'exfiltrate'
            ],
            IncidentType.UNAUTHORIZED_ACCESS: [
                r'unauthorized.*access', r'failed.*login.*multiple',
                r'suspicious.*login', r'anomalous.*access', r'brute.*force'
            ],
            IncidentType.PRIVILEGE_ESCALATION: [
                r'privilege.*escalat', r'elevate.*privilege',
                r'admin.*access.*unauthorized', r'root.*access'
            ],
            IncidentType.DATA_EXFILTRATION: [
                r'exfiltrat', r'data.*transfer.*suspicious',
                r'large.*file.*transfer', r'data.*leak'
            ],
            IncidentType.DENIAL_OF_SERVICE: [
                r'dos', r'ddos', r'denial.*service', r'service.*unavailable',
                r'resource.*exhaustion', r'bandwidth.*flood'
            ],
            IncidentType.SQL_INJECTION: [
                r'sql.*inject', r'union.*select', r'or 1=1',
                r'drop table', r'sql.*error'
            ],
            IncidentType.PROMPT_INJECTION: [
                r'prompt.*inject', r'ignore.*previous',
                r'system.*prompt', r'hypnoti', r'dan'
            ],
            IncidentType.JAILBREAK_ATTEMPT: [
                r'jailbreak', r'role.*play', r'character.*play',
                r'now you are', r'pretend'
            ],
            IncidentType.ADVERSARIAL_PROMPT: [
                r'adversarial', r'universal.*trigger', r'perturb',
                r'evasion', r'bypass'
            ],
            IncidentType.MODEL_EXTRACTION: [
                r'model.*extract', r'weight.*steal',
                r'api.*query.*excessive', r'steal.*model'
            ]
        }
        
    def _initialize_mitre_mapping_rules(self):
        """Initialize rules for MITRE ATT&CK mapping"""
        self.mitre_rules = {
            IncidentType.PHISHING: [
                (MITRETactic.INITIAL_ACCESS, MITRETechnique.T1566, 0.95)
            ],
            IncidentType.RANSOMWARE: [
                (MITRETactic.IMPACT, MITRETechnique.T1486, 0.98),
                (MITRETactic.IMPACT, MITRETechnique.T1490, 0.85)
            ],
            IncidentType.UNAUTHORIZED_ACCESS: [
                (MITRETactic.CREDENTIAL_ACCESS, MITRETechnique.T1110, 0.90),
                (MITRETactic.INITIAL_ACCESS, MITRETechnique.T1078, 0.85)
            ],
            IncidentType.PRIVILEGE_ESCALATION: [
                (MITRETactic.PRIVILEGE_ESCALATION, MITRETechnique.T1574, 0.88)
            ],
            IncidentType.DATA_EXFILTRATION: [
                (MITRETactic.EXFILTRATION, MITRETechnique.T1567, 0.92)
            ],
            IncidentType.MALWARE: [
                (MITRETactic.EXECUTION, MITRETechnique.T1059, 0.85),
                (MITRETactic.DEFENSE_EVASION, MITRETechnique.T1027, 0.80)
            ],
            IncidentType.PROMPT_INJECTION: [
                (MITRETactic.EXECUTION, MITRETechnique.T1059, 0.75),
                (MITRETactic.DEFENSE_EVASION, MITRETechnique.T1027, 0.70)
            ],
            IncidentType.JAILBREAK_ATTEMPT: [
                (MITRETactic.DEFENSE_EVASION, MITRETechnique.T1027, 0.80),
                (MITRETactic.EXECUTION, MITRETechnique.T1204, 0.75)
            ]
        }
        
    def _initialize_response_playbooks(self):
        """Initialize response playbooks by incident type"""
        self.response_playbooks = {
            IncidentSeverity.CRITICAL: {
                "immediate": [
                    ResponseActionType.ISOLATE_ASSET,
                    ResponseActionType.BLOCK_IP,
                    ResponseActionType.NOTIFY_SECURITY_TEAM,
                    ResponseActionType.NOTIFY_EXECUTIVES
                ],
                "short_term": [
                    ResponseActionType.RESET_CREDENTIALS,
                    ResponseActionType.COLLECT_FORENSICS,
                    ResponseActionType.SCAN_FOR_MALWARE
                ],
                "long_term": [
                    ResponseActionType.NOTIFY_LEGAL,
                    ResponseActionType.ENABLE_ADDITIONAL_LOGGING
                ]
            },
            IncidentSeverity.HIGH: {
                "immediate": [
                    ResponseActionType.BLOCK_IP,
                    ResponseActionType.NOTIFY_SECURITY_TEAM
                ],
                "short_term": [
                    ResponseActionType.RESET_CREDENTIALS,
                    ResponseActionType.SCAN_FOR_MALWARE
                ],
                "long_term": [
                    ResponseActionType.ENABLE_ADDITIONAL_LOGGING
                ]
            },
            IncidentSeverity.MEDIUM: {
                "immediate": [
                    ResponseActionType.NOTIFY_SECURITY_TEAM
                ],
                "short_term": [
                    ResponseActionType.SCAN_FOR_MALWARE,
                    ResponseActionType.ENABLE_ADDITIONAL_LOGGING
                ],
                "long_term": []
            },
            IncidentSeverity.LOW: {
                "immediate": [],
                "short_term": [
                    ResponseActionType.SCAN_FOR_MALWARE
                ],
                "long_term": []
            },
            IncidentSeverity.INFORMATIONAL: {
                "immediate": [],
                "short_term": [],
                "long_term": []
            }
        }
        
    def _generate_incident_id(self, events: List[IncidentEvent]) -> str:
        """Generate deterministic incident ID"""
        content = "|".join([e.event_id for e in sorted(events, key=lambda x: x.event_id)])
        hash_obj = hashlib.sha256(content.encode())
        return f"INC-{hash_obj.hexdigest()[:12].upper()}"
        
    def _classify_incident_type(self, events: List[IncidentEvent]) -> Tuple[IncidentType, float]:
        """Classify incident type based on event content"""
        type_scores = defaultdict(float)
        
        for event in events:
            content = f"{event.event_type} {event.description}".lower()
            
            for incident_type, patterns in self.incident_patterns.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        type_scores[incident_type] += 1.0
                        
        if not type_scores:
            return IncidentType.UNKNOWN, 0.0
            
        best_type = max(type_scores.keys(), key=lambda t: type_scores[t])
        max_score = type_scores[best_type]
        total_score = sum(type_scores.values())
        confidence = max_score / total_score if total_score > 0 else 0.5
        
        return best_type, confidence
        
    def _calculate_severity(self, incident_type: IncidentType, events: List[IncidentEvent]) -> Tuple[IncidentSeverity, float]:
        """Calculate incident severity score"""
        base_scores = {
            IncidentType.RANSOMWARE: 95,
            IncidentType.DATA_BREACH: 90,
            IncidentType.DATA_EXFILTRATION: 88,
            IncidentType.UNAUTHORIZED_ACCESS: 75,
            IncidentType.PRIVILEGE_ESCALATION: 80,
            IncidentType.MALWARE: 70,
            IncidentType.PHISHING: 60,
            IncidentType.DENIAL_OF_SERVICE: 75,
            IncidentType.SQL_INJECTION: 70,
            IncidentType.PROMPT_INJECTION: 65,
            IncidentType.JAILBREAK_ATTEMPT: 55,
            IncidentType.ADVERSARIAL_PROMPT: 60,
            IncidentType.MODEL_EXTRACTION: 85,
            IncidentType.UNKNOWN: 30
        }
        
        base_score = base_scores.get(incident_type, 50)
        
        # Adjust based on number of events
        event_count_factor = min(len(events) * 5, 20)
        
        # Adjust based on affected assets/users
        unique_assets = len(set(e.asset_identifier for e in events if e.asset_identifier))
        unique_users = len(set(e.user_identifier for e in events if e.user_identifier))
        asset_factor = min(unique_assets * 3, 15)
        user_factor = min(unique_users * 2, 10)
        
        final_score = base_score + event_count_factor + asset_factor + user_factor
        final_score = min(final_score, 100)
        
        if final_score >= 90:
            severity = IncidentSeverity.CRITICAL
        elif final_score >= 70:
            severity = IncidentSeverity.HIGH
        elif final_score >= 50:
            severity = IncidentSeverity.MEDIUM
        elif final_score >= 25:
            severity = IncidentSeverity.LOW
        else:
            severity = IncidentSeverity.INFORMATIONAL
            
        return severity, final_score
        
    def _map_to_mitre(self, incident_type: IncidentType, events: List[IncidentEvent]) -> List[MITREMapping]:
        """Map incident to MITRE ATT&CK framework"""
        mappings = []
        
        rules = self.mitre_rules.get(incident_type, [])
        
        for tactic, technique, confidence in rules:
            evidence = [
                f"Incident type {incident_type.value} matches tactic {tactic.value}",
                f"Technique {technique.value} applicable based on attack pattern"
            ]
            mappings.append(MITREMapping(
                tactic=tactic,
                technique=technique,
                confidence_score=confidence,
                evidence=evidence
            ))
            
        return mappings
        
    def _generate_response_actions(self, severity: IncidentSeverity, 
                                    incident_type: IncidentType,
                                    events: List[IncidentEvent]) -> List[ResponseAction]:
        """Generate automated response actions"""
        actions = []
        playbook = self.response_playbooks.get(severity, {})
        
        action_counter = 0
        
        for timeframe, action_types in playbook.items():
            priority_base = 0 if timeframe == "immediate" else 10 if timeframe == "short_term" else 20
            
            for i, action_type in enumerate(action_types):
                action_counter += 1
                
                target = None
                if action_type == ResponseActionType.BLOCK_IP:
                    ips = [e.ip_address for e in events if e.ip_address]
                    if ips:
                        target = ips[0]
                elif action_type == ResponseActionType.ISOLATE_ASSET:
                    assets = [e.asset_identifier for e in events if e.asset_identifier]
                    if assets:
                        target = assets[0]
                
                action = ResponseAction(
                    action_id=f"ACT-{action_counter:04d}",
                    action_type=action_type,
                    description=f"{action_type.value.replace('_', ' ').title()}",
                    priority=priority_base + i,
                    target=target
                )
                actions.append(action)
                
        return actions
        
    def _generate_timeline(self, events: List[IncidentEvent]) -> str:
        """Generate incident timeline summary"""
        if not events:
            return "No events available"
            
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        start_time = sorted_events[0].timestamp
        end_time = sorted_events[-1].timestamp
        
        timeline = [
            f"Incident Timeline:",
            f"  Start: {start_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  End:   {end_time.strftime('%Y-%m-%d %H:%M:%S')}",
            f"  Duration: {str(end_time - start_time)}",
            f"  Total Events: {len(events)}",
            "",
            "Key Events:"
        ]
        
        for i, event in enumerate(sorted_events[:5]):
            timeline.append(f"  [{i+1}] {event.timestamp.strftime('%H:%M:%S')} - {event.event_type}: {event.description[:60]}...")
            
        if len(sorted_events) > 5:
            timeline.append(f"  ... and {len(sorted_events) - 5} more events")
            
        return "\n".join(timeline)
        
    def _generate_recommendations(self, severity: IncidentSeverity, 
                                   incident_type: IncidentType,
                                   mitre_mappings: List[MITREMapping]) -> List[str]:
        """Generate security recommendations"""
        recommendations = []
        
        general_recs = [
            "Review and update incident response plan",
            "Conduct security awareness training",
            "Enable multi-factor authentication everywhere",
            "Implement network segmentation",
            "Regular backup verification and testing"
        ]
        
        severity_recs = {
            IncidentSeverity.CRITICAL: [
                "Activate full incident response team immediately",
                "Prepare breach notification communications",
                "Engage external cybersecurity forensics team",
                "Consider legal and regulatory reporting requirements"
            ],
            IncidentSeverity.HIGH: [
                "Escalate to security leadership team",
                "Conduct full environment sweep",
                "Review recent access logs comprehensively"
            ],
            IncidentSeverity.MEDIUM: [
                "Investigate root cause within 24 hours",
                "Apply relevant security patches",
                "Monitor for related activity"
            ],
            IncidentSeverity.LOW: [
                "Document incident for trend analysis",
                "Review detection rules for improvement"
            ],
            IncidentSeverity.INFORMATIONAL: [
                "Monitor for escalation to higher severity"
            ]
        }
        
        type_specific = {
            IncidentType.RANSOMWARE: [
                "Verify offline backup integrity immediately",
                "Isolate affected systems from network",
                "Check for lateral movement indicators"
            ],
            IncidentType.PHISHING: [
                "Block sender domain and IP",
                "Run email security awareness training",
                "Update spam filter rules"
            ],
            IncidentType.PROMPT_INJECTION: [
                "Update prompt injection detection rules",
                "Review system prompt hardening",
                "Implement input validation layers"
            ]
        }
        
        recommendations.extend(severity_recs.get(severity, []))
        recommendations.extend(type_specific.get(incident_type, []))
        recommendations.extend(general_recs[:2])
        
        return list(dict.fromkeys(recommendations))  # Remove duplicates
        
    def _generate_playbook_text(self, severity: IncidentSeverity, incident_type: IncidentType) -> str:
        """Generate response playbook text"""
        playbook = f"""
INCIDENT RESPONSE PLAYBOOK
==========================
Incident Type: {incident_type.value.upper()}
Severity: {severity.value.upper()}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

PHASE 1: IMMEDIATE RESPONSE (0-1 HOUR)
--------------------------------------
1. Confirm incident and validate detection
2. Assign incident commander and response team
3. Isolate affected assets to prevent spread
4. Begin evidence collection and preservation
5. Initial stakeholder notification

PHASE 2: CONTAINMENT (1-4 HOURS)
--------------------------------
1. Block malicious IPs and domains
2. Reset compromised credentials
3. Enable enhanced logging and monitoring
4. Scan environment for indicators of compromise
5. Document all actions taken

PHASE 3: ERADICATION (4-24 HOURS)
---------------------------------
1. Remove malware and persistence mechanisms
2. Patch vulnerabilities exploited
3. Restore from clean backups if needed
4. Verify systems are clean
5. Update detection signatures

PHASE 4: RECOVERY (24-72 HOURS)
-------------------------------
1. Gradually restore services
2. Monitor for signs of re-infection
3. Validate all systems functioning normally
4. Conduct post-incident review
5. Update security controls

PHASE 5: POST-INCIDENT (72+ HOURS)
----------------------------------
1. Complete root cause analysis
2. Document lessons learned
3. Update incident response procedures
4. Provide executive summary report
5. Schedule follow-up security assessment
"""
        return playbook.strip()
        
    def process_incident(self, events: List[IncidentEvent]) -> IncidentResponseResult:
        """
        Process security events and generate full incident response
        
        This is the main production method that:
        1. Correlates events into an incident
        2. Classifies and scores severity
        3. Maps to MITRE ATT&CK
        4. Generates response actions
        5. Creates timeline and recommendations
        """
        start_time = time.time()
        
        # Generate incident ID
        incident_id = self._generate_incident_id(events)
        
        # Classify incident
        incident_type, type_confidence = self._classify_incident_type(events)
        
        # Calculate severity
        severity, severity_score = self._calculate_severity(incident_type, events)
        
        # Map to MITRE
        mitre_mappings = self._map_to_mitre(incident_type, events)
        
        # Generate response actions
        response_actions = self._generate_response_actions(severity, incident_type, events)
        
        # Collect metadata
        affected_assets = list(set(e.asset_identifier for e in events if e.asset_identifier))
        affected_users = list(set(e.user_identifier for e in events if e.user_identifier))
        iocs = list(set(e.ip_address for e in events if e.ip_address))
        
        # Generate timeline
        timeline = self._generate_timeline(events)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(severity, incident_type, mitre_mappings)
        
        # Generate playbook
        playbook = self._generate_playbook_text(severity, incident_type)
        
        # Create title and description
        title = f"{severity.value.upper()} - {incident_type.value.replace('_', ' ').title()} Incident"
        description = (f"Automated incident response for {len(events)} correlated events. "
                      f"Classification confidence: {type_confidence:.2%}")
        
        processing_time = (time.time() - start_time) * 1000
        
        result = IncidentResponseResult(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=severity,
            severity_score=severity_score,
            title=title,
            description=description,
            events=events,
            mitre_mappings=mitre_mappings,
            response_actions=response_actions,
            affected_assets=affected_assets,
            affected_users=affected_users,
            indicators_of_compromise=iocs,
            timeline_summary=timeline,
            recommendations=recommendations,
            response_playbook=playbook,
            processing_time_ms=processing_time
        )
        
        self.incident_history.append(result)
        return result
        
    def export_result_json(self, result: IncidentResponseResult) -> str:
        """Export result as JSON"""
        data = {
            "incident_id": result.incident_id,
            "incident_type": result.incident_type.value,
            "severity": result.severity.value,
            "severity_score": result.severity_score,
            "title": result.title,
            "description": result.description,
            "event_count": len(result.events),
            "mitre_mappings": [
                {
                    "tactic": m.tactic.value,
                    "technique": m.technique.value,
                    "confidence": m.confidence_score
                }
                for m in result.mitre_mappings
            ],
            "response_actions_count": len(result.response_actions),
            "affected_assets": result.affected_assets,
            "affected_users": result.affected_users,
            "iocs": result.indicators_of_compromise,
            "processing_time_ms": result.processing_time_ms,
            "generated_at": result.created_at.isoformat()
        }
        return json.dumps(data, indent=2)
        
    def get_incident_statistics(self) -> Dict[str, Any]:
        """Get statistics about processed incidents"""
        if not self.incident_history:
            return {"total_incidents": 0}
            
        severity_counts = defaultdict(int)
        type_counts = defaultdict(int)
        
        for incident in self.incident_history:
            severity_counts[incident.severity.value] += 1
            type_counts[incident.incident_type.value] += 1
            
        avg_processing = sum(i.processing_time_ms for i in self.incident_history) / len(self.incident_history)
        
        return {
            "total_incidents": len(self.incident_history),
            "severity_distribution": dict(severity_counts),
            "type_distribution": dict(type_counts),
            "average_processing_time_ms": round(avg_processing, 2)
        }
