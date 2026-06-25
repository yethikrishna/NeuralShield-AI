"""
Threat Hunting Playbook Generator v83 - NeuralShield AI
Dimension A: Feature Expansion
Incremental, ADD-ONLY implementation
Automated threat hunting playbook generation with:
- MITRE ATT&CK technique-specific hunting procedures
- Data source mapping and collection guidance
- Detection logic and query templates
- False positive reduction strategies
- Investigation workflow checklists
- Remediation and containment playbooks
"""
import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime


class PlaybookType(Enum):
    """Types of threat hunting playbooks"""
    TACTICAL = "tactical"
    OPERATIONAL = "operational"
    STRATEGIC = "strategic"
    INCIDENT_RESPONSE = "incident_response"
    THREAT_HUNTING = "threat_hunting"


class SeverityLevel(Enum):
    """Severity levels for playbook steps"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class HuntingStep:
    """Individual step in a threat hunting playbook"""
    step_id: str
    description: str
    data_sources: List[str]
    query_template: str
    tools: List[str]
    expected_outcome: str
    severity: SeverityLevel
    estimated_time_minutes: int
    false_positive_guidance: str = ""


@dataclass
class HuntingPlaybook:
    """Complete threat hunting playbook"""
    playbook_id: str
    title: str
    description: str
    mitre_techniques: List[str]
    playbook_type: PlaybookType
    steps: List[HuntingStep]
    prerequisites: List[str]
    success_criteria: List[str]
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    version: str = "1.0.0"


class ThreatHuntingPlaybookGenerator:
    """
    Generates comprehensive threat hunting playbooks
    Dimension A: Feature Expansion - ADD-ONLY implementation
    """
    
    def __init__(self):
        self.playbook_templates = self._initialize_playbook_templates()
        self.data_source_mappings = self._initialize_data_source_mappings()
        self.tool_mappings = self._initialize_tool_mappings()
    
    def _initialize_playbook_templates(self) -> Dict[str, Dict]:
        """Initialize MITRE technique to playbook template mappings"""
        return {
            "T1059": {
                "title": "Command and Scripting Interpreter Hunting",
                "description": "Detect and investigate abuse of command and scripting interpreters",
                "techniques": ["T1059.001", "T1059.003", "T1059.005", "T1059.007"],
                "playbook_type": PlaybookType.THREAT_HUNTING,
                "prerequisites": [
                    "Endpoint detection and response (EDR) logging enabled",
                    "PowerShell transcription enabled",
                    "Command line process auditing configured",
                    "Network proxy logs available"
                ],
                "success_criteria": [
                    "Identify all suspicious interpreter usage",
                    "Distinguish malicious from legitimate activity",
                    "Document evidence chain for findings",
                    "Provide actionable remediation steps"
                ]
            },
            "T1027": {
                "title": "Obfuscated Files or Information Hunting",
                "description": "Detect obfuscation techniques used to evade detection",
                "techniques": ["T1027.001", "T1027.002", "T1027.004", "T1027.010"],
                "playbook_type": PlaybookType.THREAT_HUNTING,
                "prerequisites": [
                    "File scanning capabilities",
                    "Memory forensics tools available",
                    "Network traffic analysis enabled",
                    "Script block logging configured"
                ],
                "success_criteria": [
                    "Detect encoded and encrypted payloads",
                    "Identify suspicious string obfuscation",
                    "Unpack packed executables when possible",
                    "Correlate obfuscation with known threats"
                ]
            },
            "T1053": {
                "title": "Scheduled Task/Job Hunting",
                "description": "Detect persistence via scheduled tasks and jobs",
                "techniques": ["T1053.002", "T1053.003", "T1053.005", "T1053.007"],
                "playbook_type": PlaybookType.THREAT_HUNTING,
                "prerequisites": [
                    "Windows Event Logs collected",
                    "Scheduled task enumeration tools",
                    "Cron job monitoring (Linux)",
                    "System configuration auditing"
                ],
                "success_criteria": [
                    "Enumerate all persistence mechanisms",
                    "Identify suspicious scheduled tasks",
                    "Correlate with threat actor TTPs",
                    "Document removal procedures"
                ]
            },
            "T1003": {
                "title": "Credential Dumping Hunting",
                "description": "Detect credential dumping and credential access attempts",
                "techniques": ["T1003.001", "T1003.002", "T1003.003", "T1003.006"],
                "playbook_type": PlaybookType.INCIDENT_RESPONSE,
                "prerequisites": [
                    "LSASS process monitoring",
                    "Memory dump detection",
                    "SAM/SYSTEM file access auditing",
                    "Domain controller monitoring"
                ],
                "success_criteria": [
                    "Detect credential dumping tools",
                    "Identify suspicious process injection",
                    "Alert on NTDS.dit access",
                    "Provide credential rotation procedures"
                ]
            },
            "T1046": {
                "title": "Network Service Scanning Hunting",
                "description": "Detect network reconnaissance and service scanning",
                "techniques": ["T1046"],
                "playbook_type": PlaybookType.TACTICAL,
                "prerequisites": [
                    "Network flow logs available",
                    "Firewall logs collected",
                    "IDS/IPS alerts configured",
                    "Port scanning detection enabled"
                ],
                "success_criteria": [
                    "Identify port scanning activity",
                    "Distinguish scanning types (TCP, UDP, SYN)",
                    "Correlate with threat intelligence",
                    "Block malicious sources"
                ]
            }
        }
    
    def _initialize_data_source_mappings(self) -> Dict[str, List[str]]:
        """Initialize technique to data source mappings"""
        return {
            "process": [
                "Windows Security Event Logs (Event ID 4688)",
                "Sysmon Process Creation (Event ID 1)",
                "EDR Process Telemetry",
                "PowerShell Operational Logs"
            ],
            "network": [
                "NetFlow/IPFIX Data",
                "Proxy Server Logs",
                "DNS Query Logs",
                "Firewall Connection Logs",
                "Zeek/Bro Network Logs"
            ],
            "file": [
                "File Creation/Modification Events",
                "NTFS Change Journal",
                "FIM (File Integrity Monitoring)",
                "Prefetch Files Analysis"
            ],
            "registry": [
                "Registry Modification Events",
                "Sysmon Registry Events (Event ID 12,13,14)",
                "Reg.exe Command Line Logging"
            ],
            "memory": [
                "Process Memory Dumps",
                "LSASS Memory Access Events",
                "Handle Operation Auditing"
            ]
        }
    
    def _initialize_tool_mappings(self) -> Dict[str, List[str]]:
        """Initialize hunting tool mappings"""
        return {
            "endpoint": [
                "Microsoft Defender for Endpoint",
                "CrowdStrike Falcon",
                "SentinelOne",
                "Carbon Black",
                "Velociraptor"
            ],
            "network": [
                "Suricata",
                "Zeek",
                "Wireshark",
                "tcpdump",
                "BruteShark"
            ],
            "forensics": [
                "Volatility 3",
                "FTK Imager",
                "Autopsy",
                "REMnux",
                "Process Hacker"
            ],
            "siem": [
                "Splunk",
                "Microsoft Sentinel",
                "Elastic Security",
                "QRadar",
                "Chronicle"
            ]
        }
    
    def generate_playbook(self, mitre_technique_id: str, 
                          playbook_type: Optional[PlaybookType] = None) -> HuntingPlaybook:
        """
        Generate a threat hunting playbook for a specific MITRE technique
        
        Args:
            mitre_technique_id: MITRE ATT&CK technique ID
            playbook_type: Optional playbook type override
            
        Returns:
            HuntingPlaybook object with complete hunting procedures
        """
        base_id = mitre_technique_id.split('.')[0] if '.' in mitre_technique_id else mitre_technique_id
        
        if base_id not in self.playbook_templates:
            return self._generate_generic_playbook(mitre_technique_id)
        
        template = self.playbook_templates[base_id]
        
        steps = self._generate_hunting_steps(base_id, mitre_technique_id)
        
        playbook = HuntingPlaybook(
            playbook_id=f"PB-{base_id}-{hashlib.md5(mitre_technique_id.encode()).hexdigest()[:8]}",
            title=template["title"],
            description=template["description"],
            mitre_techniques=template["techniques"],
            playbook_type=playbook_type or template["playbook_type"],
            steps=steps,
            prerequisites=template["prerequisites"],
            success_criteria=template["success_criteria"]
        )
        
        return playbook
    
    def _generate_hunting_steps(self, base_id: str, full_id: str) -> List[HuntingStep]:
        """Generate detailed hunting steps for a technique"""
        steps = []
        
        # Step 1: Initial Data Collection
        steps.append(HuntingStep(
            step_id=f"{base_id}-S01",
            description=f"Collect and review initial telemetry for {full_id} technique indicators",
            data_sources=self.data_source_mappings["process"] + self.data_source_mappings["network"],
            query_template=f"""
            // Initial hunting query for {full_id}
            index=* sourcetype IN (windows_security, sysmon, proxy) 
            | search EventCode IN (4688, 1, 3) 
            | where match(process_name, ".*(powershell|cmd|wscript|cscript|mshta).*", "i")
            | stats count by process_name, parent_process_name, dest_ip
            | where count > 5
            """,
            tools=self.tool_mappings["siem"],
            expected_outcome="Identify suspicious process activity matching technique patterns",
            severity=SeverityLevel.MEDIUM,
            estimated_time_minutes=15,
            false_positive_guidance="Filter out known administrative activity and approved scripts"
        ))
        
        # Step 2: Deep Dive Analysis
        steps.append(HuntingStep(
            step_id=f"{base_id}-S02",
            description="Perform deep dive analysis on identified suspicious entities",
            data_sources=self.data_source_mappings["file"] + self.data_source_mappings["registry"],
            query_template=f"""
            // Deep dive analysis
            | from endpoints 
            | where device_id IN (suspicious_devices)
            | join kind=inner (file_events) on device_id
            | summarize FilesAccessed = make_list(file_name) by device_id
            | extend SuspiciousScore = array_length(FilesAccessed)
            """,
            tools=self.tool_mappings["endpoint"] + self.tool_mappings["forensics"],
            expected_outcome="Correlate suspicious activity across multiple data sources",
            severity=SeverityLevel.HIGH,
            estimated_time_minutes=30,
            false_positive_guidance="Verify against application whitelists and approved software"
        ))
        
        # Step 3: Threat Intelligence Correlation
        steps.append(HuntingStep(
            step_id=f"{base_id}-S03",
            description="Correlate findings with threat intelligence sources",
            data_sources=["Threat Intelligence Feeds", "MISP Events", "MITRE ATT&CK Database"],
            query_template="""
            // Threat intel correlation
            | lookup threat_intel.csv indicator AS sha256 OUTPUT description, actor, confidence
            | where confidence >= 70
            | summarize ThreatMatches = count() by actor
            """,
            tools=["MISP", "ThreatConnect", "MITRE ATT&CK Navigator"],
            expected_outcome="Map findings to known threat actors and campaigns",
            severity=SeverityLevel.HIGH,
            estimated_time_minutes=20,
            false_positive_guidance="Consider indicator age and confidence levels"
        ))
        
        # Step 4: Evidence Documentation
        steps.append(HuntingStep(
            step_id=f"{base_id}-S04",
            description="Document all findings and preserve evidence chain",
            data_sources=["Case Management System", "Evidence Repository"],
            query_template="N/A - Manual documentation step",
            tools=["TheHive", "RTIR", "DFIR Tools"],
            expected_outcome="Complete evidence chain with timestamps and hashes",
            severity=SeverityLevel.CRITICAL,
            estimated_time_minutes=25,
            false_positive_guidance="Maintain chain of custody for all artifacts"
        ))
        
        # Step 5: Remediation and Containment
        steps.append(HuntingStep(
            step_id=f"{base_id}-S05",
            description="Execute remediation and containment procedures",
            data_sources=["EDR Response Actions", "Network Controls"],
            query_template="N/A - Response execution",
            tools=self.tool_mappings["endpoint"] + ["Firewall Management"],
            expected_outcome="Threat contained and eradicated from environment",
            severity=SeverityLevel.CRITICAL,
            estimated_time_minutes=45,
            false_positive_guidance="Test containment in isolation before full deployment"
        ))
        
        return steps
    
    def _generate_generic_playbook(self, mitre_technique_id: str) -> HuntingPlaybook:
        """Generate a generic playbook for techniques without specific templates"""
        steps = [
            HuntingStep(
                step_id="GEN-S01",
                description=f"Initial reconnaissance for {mitre_technique_id} indicators",
                data_sources=self.data_source_mappings["process"] + self.data_source_mappings["network"],
                query_template="// Generic hunting query\n| search * | where technique matches pattern",
                tools=self.tool_mappings["siem"],
                expected_outcome="Identify potential matches",
                severity=SeverityLevel.MEDIUM,
                estimated_time_minutes=20
            ),
            HuntingStep(
                step_id="GEN-S02",
                description="Validate and triage identified indicators",
                data_sources=self.data_source_mappings["file"],
                query_template="// Validation query",
                tools=self.tool_mappings["endpoint"],
                expected_outcome="Confirm or dismiss potential findings",
                severity=SeverityLevel.HIGH,
                estimated_time_minutes=30
            )
        ]
        
        return HuntingPlaybook(
            playbook_id=f"PB-GEN-{hashlib.md5(mitre_technique_id.encode()).hexdigest()[:8]}",
            title=f"Generic Hunting Playbook - {mitre_technique_id}",
            description=f"Automatically generated playbook for technique {mitre_technique_id}",
            mitre_techniques=[mitre_technique_id],
            playbook_type=PlaybookType.THREAT_HUNTING,
            steps=steps,
            prerequisites=["Basic security monitoring enabled", "Log collection configured"],
            success_criteria=["Identify potential threats", "Validate findings", "Document results"]
        )
    
    def export_playbook_markdown(self, playbook: HuntingPlaybook) -> str:
        """Export playbook as markdown documentation"""
        md = [
            f"# {playbook.title}",
            "",
            f"**Playbook ID:** {playbook.playbook_id}",
            f"**Version:** {playbook.version}",
            f"**Type:** {playbook.playbook_type.value}",
            f"**Created:** {playbook.created_at}",
            "",
            "## Description",
            playbook.description,
            "",
            "## MITRE ATT&CK Techniques",
            ""
        ]
        
        for technique in playbook.mitre_techniques:
            md.append(f"- [{technique}](https://attack.mitre.org/techniques/{technique.replace('.', '/')}/)")
        
        md.extend([
            "",
            "## Prerequisites",
            ""
        ])
        
        for prereq in playbook.prerequisites:
            md.append(f"- [ ] {prereq}")
        
        md.extend([
            "",
            "## Hunting Procedures",
            ""
        ])
        
        for i, step in enumerate(playbook.steps, 1):
            md.extend([
                f"### Step {i}: {step.description}",
                "",
                f"**Severity:** {step.severity.value}",
                f"**Estimated Time:** {step.estimated_time_minutes} minutes",
                "",
                "**Data Sources:**",
                ""
            ])
            for ds in step.data_sources:
                md.append(f"- {ds}")
            
            md.extend([
                "",
                "**Tools:**",
                ""
            ])
            for tool in step.tools:
                md.append(f"- {tool}")
            
            if step.query_template.strip():
                md.extend([
                    "",
                    "**Query Template:**",
                    "```spl",
                    step.query_template.strip(),
                    "```"
                ])
            
            md.extend([
                "",
                f"**Expected Outcome:** {step.expected_outcome}",
                ""
            ])
            
            if step.false_positive_guidance:
                md.extend([
                    "**False Positive Guidance:**",
                    step.false_positive_guidance,
                    ""
                ])
        
        md.extend([
            "## Success Criteria",
            ""
        ])
        
        for criteria in playbook.success_criteria:
            md.append(f"- [ ] {criteria}")
        
        return "\n".join(md)
    
    def export_playbook_json(self, playbook: HuntingPlaybook) -> str:
        """Export playbook as JSON"""
        return json.dumps({
            "playbook_id": playbook.playbook_id,
            "title": playbook.title,
            "description": playbook.description,
            "mitre_techniques": playbook.mitre_techniques,
            "playbook_type": playbook.playbook_type.value,
            "version": playbook.version,
            "created_at": playbook.created_at,
            "prerequisites": playbook.prerequisites,
            "success_criteria": playbook.success_criteria,
            "steps": [
                {
                    "step_id": step.step_id,
                    "description": step.description,
                    "data_sources": step.data_sources,
                    "query_template": step.query_template,
                    "tools": step.tools,
                    "expected_outcome": step.expected_outcome,
                    "severity": step.severity.value,
                    "estimated_time_minutes": step.estimated_time_minutes,
                    "false_positive_guidance": step.false_positive_guidance
                }
                for step in playbook.steps
            ]
        }, indent=2)
    
    def get_available_techniques(self) -> List[str]:
        """Get list of techniques with playbook templates"""
        return list(self.playbook_templates.keys())


# Singleton instance for module-level access
playbook_generator = ThreatHuntingPlaybookGenerator()


def generate_threat_hunting_playbook(mitre_technique_id: str, 
                                     output_format: str = "object") -> Any:
    """
    Convenience function to generate threat hunting playbooks
    
    Args:
        mitre_technique_id: MITRE ATT&CK technique ID (e.g., "T1059", "T1059.001")
        output_format: "object", "markdown", or "json"
        
    Returns:
        Playbook in requested format
    """
    playbook = playbook_generator.generate_playbook(mitre_technique_id)
    
    if output_format == "markdown":
        return playbook_generator.export_playbook_markdown(playbook)
    elif output_format == "json":
        return playbook_generator.export_playbook_json(playbook)
    else:
        return playbook


def get_supported_techniques() -> List[str]:
    """Get list of techniques with dedicated playbook templates"""
    return playbook_generator.get_available_techniques()


if __name__ == "__main__":
    # Example usage
    print("Threat Hunting Playbook Generator v83")
    print("=" * 50)
    
    techniques = get_supported_techniques()
    print(f"\nSupported Techniques: {techniques}")
    
    # Generate example playbook
    playbook = generate_threat_hunting_playbook("T1059")
    print(f"\nGenerated Playbook: {playbook.title}")
    print(f"Techniques Covered: {playbook.mitre_techniques}")
    print(f"Number of Steps: {len(playbook.steps)}")
    print(f"Playbook Type: {playbook.playbook_type.value}")
    
    # Show markdown export
    md_output = generate_threat_hunting_playbook("T1059", output_format="markdown")
    print("\nMarkdown Preview (first 500 chars):")
    print(md_output[:500] + "...")
