"""
MITRE ATT&CK Coverage Gap Analyzer v78 - NeuralShield-AI
Dimension A: Feature Expansion
Incremental Build - June 24, 2026

Adds coverage gap analysis to the existing MITRE ATT&CK framework.
Identifies uncovered techniques, sub-techniques, and tactics.
Provides prioritized recommendations for coverage expansion.

API Stability: STABLE
Backward Compatible: YES - wraps existing MITRE modules, no breaking changes
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional, Any, Tuple
from datetime import datetime
import json
from collections import defaultdict


class CoveragePriority(Enum):
    """Priority levels for coverage gap remediation."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


class CoverageStatus(Enum):
    """Coverage status for MITRE ATT&CK entities."""
    FULLY_COVERED = "fully_covered"
    PARTIALLY_COVERED = "partially_covered"
    NOT_COVERED = "not_covered"
    EXPERIMENTAL = "experimental"
    DEPRECATED = "deprecated"


@dataclass
class CoverageGap:
    """Represents a single coverage gap in MITRE ATT&CK coverage."""
    technique_id: str
    technique_name: str
    tactic: str
    coverage_status: CoverageStatus
    priority: CoveragePriority
    gap_description: str
    detection_complexity: str
    false_positive_risk: str
    recommended_approach: str
    estimated_effort_hours: int
    related_covered_techniques: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)


@dataclass
class TacticCoverageSummary:
    """Summary of coverage for a specific tactic."""
    tactic_name: str
    total_techniques: int
    covered_techniques: int
    partially_covered: int
    not_covered: int
    coverage_percentage: float
    gaps: List[CoverageGap] = field(default_factory=list)


@dataclass
class CoverageAnalysisReport:
    """Comprehensive coverage analysis report."""
    report_id: str
    generated_at: datetime
    mitre_version: str
    total_techniques: int
    total_covered: int
    total_partially_covered: int
    total_not_covered: int
    overall_coverage_percentage: float
    tactic_summaries: Dict[str, TacticCoverageSummary]
    critical_gaps: List[CoverageGap]
    high_priority_gaps: List[CoverageGap]
    recommendations: List[str]
    coverage_trend: Optional[Dict[str, Any]] = None


class MITREAttackCoverageGapAnalyzer:
    """
    Analyzes coverage gaps in MITRE ATT&CK technique coverage.
    Builds on existing MITRE framework to identify and prioritize coverage gaps.
    
    This is an ADD-ONLY feature - wraps existing MITRE modules without modification.
    """
    
    VERSION = "1.0.0"
    API_STABILITY = "STABLE"
    
    # MITRE ATT&CK Tactics (v14)
    _MITRE_TACTICS = [
        "Reconnaissance",
        "Resource Development",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact"
    ]
    
    # Currently covered techniques in NeuralShield
    _COVERED_TECHNIQUES = {
        "T1059": "Command and Scripting Interpreter",
        "T1059.001": "PowerShell",
        "T1059.003": "Windows Command Shell",
        "T1059.004": "Unix Shell",
        "T1059.006": "Python",
        "T1027": "Obfuscated Files or Information",
        "T1027.001": "Binary Padding",
        "T1027.002": "Software Packing",
        "T1027.003": "Steganography",
        "T1027.004": "Compile After Delivery",
        "T1027.005": "Indicator Removal from Tools",
        "T1036": "Masquerading",
        "T1036.001": "Invalid Code Signature",
        "T1036.002": "Right-to-Left Override",
        "T1036.003": "Rename System Utilities",
        "T1036.004": "Masquerade Task or Service",
        "T1036.005": "Match Legitimate Name or Location",
        "T1055": "Process Injection",
        "T1055.001": "Dynamic-link Library Injection",
        "T1055.002": "Portable Executable Injection",
        "T1055.003": "Thread Execution Hijacking",
        "T1055.004": "Asynchronous Procedure Call",
        "T1055.005": "Thread Local Storage",
        "T1055.011": "Extra Window Memory Injection",
        "T1055.012": "Process Hollowing",
        "T1055.013": "Process Doppelgänging",
        "T1008": "Fallback Channels",
        "T1008.001": "DNS Tunneling",
        "T1008.002": "Domain Fronting",
        "T1041": "Exfiltration Over C2 Channel",
        "T1041.001": "Exfiltration Over Web Service",
        "T1048": "Exfiltration Over Alternative Protocol",
        "T1048.001": "Exfiltration Over FTP",
        "T1048.002": "Exfiltration Over SSH",
        "T1048.003": "Exfiltration Over DNS",
        "T1555": "Credentials from Password Stores",
        "T1555.001": "Credentials from Web Browsers",
        "T1555.003": "Credentials from Credential Managers",
        "T1555.004": "Windows Credential Manager",
        "T1083": "File and Directory Discovery",
        "T1087": "Account Discovery",
        "T1087.001": "Local Account",
        "T1087.002": "Domain Account",
        "T1087.003": "Email Account",
        "T1016": "System Network Configuration Discovery",
        "T1018": "Remote System Discovery",
        "T1049": "System Network Connections Discovery",
        "T1033": "System Owner/User Discovery",
        "T1069": "Permission Groups Discovery",
        "T1069.001": "Local Groups",
        "T1069.002": "Domain Groups",
        "T1057": "Process Discovery",
        "T1012": "Query Registry",
        "T1518": "Software Discovery",
        "T1518.001": "Security Software Discovery",
        "T1082": "System Information Discovery",
        "T1120": "Peripheral Device Discovery",
        "T1056": "Input Capture",
        "T1056.001": "Keylogging",
        "T1056.002": "GUI Input Capture",
        "T1056.003": "Web Portal Capture",
        "T1056.004": "Credential API Hooking",
        "T1114": "Email Collection",
        "T1114.001": "Local Email Collection",
        "T1114.002": "Remote Email Collection",
        "T1114.003": "Email Forwarding Rule",
        "T1005": "Data from Local System",
        "T1025": "Data from Removable Media",
        "T1039": "Data from Network Shared Drive",
        "T1074": "Data Staged",
        "T1074.001": "Local Data Staging",
        "T1074.002": "Remote Data Staging",
        "T1560": "Archive Collected Data",
        "T1560.001": "Archive via Utility",
        "T1560.002": "Archive via Library",
        "T1560.003": "Archive via Custom Method",
        "T1071": "Application Layer Protocol",
        "T1071.001": "Web Protocols",
        "T1071.002": "File Transfer Protocols",
        "T1071.003": "Mail Protocols",
        "T1071.004": "DNS",
        "T1092": "Communication Through Removable Media",
        "T1090": "Proxy",
        "T1090.001": "Internal Proxy",
        "T1090.002": "External Proxy",
        "T1090.003": "Multi-hop Proxy",
        "T1090.004": "Domain Fronting",
        "T1095": "Non-Application Layer Protocol",
        "T1205": "Traffic Signaling",
        "T1205.001": "Port Knocking",
        "T1205.002": "Socket Filters",
        "T1219": "Remote Access Software",
        "T1572": "Protocol Tunneling",
        "T1571": "Non-Standard Port",
        "T1091": "Replication Through Removable Media",
        "T1021": "Remote Services",
        "T1021.001": "Remote Desktop Protocol",
        "T1021.002": "SMB/Windows Admin Shares",
        "T1021.003": "Distributed Component Object Model",
        "T1021.004": "SSH",
        "T1021.005": "VNC",
        "T1021.006": "Windows Remote Management",
        "T1550": "Use Alternate Authentication Material",
        "T1550.001": "Application Access Token",
        "T1550.002": "Pass the Hash",
        "T1550.003": "Pass the Ticket",
        "T1550.004": "Web Session Cookie",
        "T1563": "Remote Service Session Hijacking",
        "T1563.001": "SSH Hijacking",
        "T1563.002": "RDP Hijacking",
        "T1543": "Create or Modify System Process",
        "T1543.001": "Launch Agent",
        "T1543.002": "Systemd Service",
        "T1543.003": "Windows Service",
        "T1543.004": "Launch Daemon",
        "T1546": "Event Triggered Execution",
        "T1546.001": "Change Default File Association",
        "T1546.002": "Screensaver",
        "T1546.003": "Windows Management Instrumentation Event Subscription",
        "T1546.004": "Unix Shell Configuration Modification",
        "T1546.005": "Trap",
        "T1546.006": "LC_LOAD_DYLIB Addition",
        "T1546.007": "Netsh Helper DLL",
        "T1546.008": "Accessibility Features",
        "T1546.009": "AppCert DLLs",
        "T1546.010": "AppInit DLLs",
        "T1546.011": "Application Shimming",
        "T1546.012": "Image File Execution Options Injection",
        "T1546.013": "PowerShell Profile",
        "T1546.014": "Active Setup",
        "T1546.015": "Component Object Model Hijacking",
        "T1547": "Boot or Logon Autostart Execution",
        "T1547.001": "Registry Run Keys / Startup Folder",
        "T1547.002": "Authentication Package",
        "T1547.003": "Time Providers",
        "T1547.004": "Winlogon Helper DLL",
        "T1547.005": "Security Support Provider",
        "T1547.006": "Kernel Modules and Extensions",
        "T1547.007": "Re-opened Applications",
        "T1547.008": "LSASS Driver",
        "T1547.009": "Shortcut Modification",
        "T1547.010": "Port Monitors",
        "T1547.011": "Plist Modification",
        "T1547.012": "Print Processors",
        "T1547.013": "XDG Autostart Entries",
        "T1547.014": "Active Setup",
        "T1547.015": "Login Items",
        "T1548": "Abuse Elevation Control Mechanism",
        "T1548.001": "Setuid and Setgid",
        "T1548.002": "Bypass User Account Control",
        "T1548.003": "Sudo and Sudo Caching",
        "T1548.004": "Elevated Execution with Prompt",
        "T1548.005": "Tainted Shared-Code Segment",
        "T1068": "Exploitation for Privilege Escalation",
        "T1078": "Valid Accounts",
        "T1078.001": "Default Accounts",
        "T1078.002": "Domain Accounts",
        "T1078.003": "Local Accounts",
        "T1078.004": "Cloud Accounts",
        "T1574": "Hijack Execution Flow",
        "T1574.001": "DLL Search Order Hijacking",
        "T1574.002": "DLL Side-Loading",
        "T1574.004": "DLL Search Order Hijacking",
        "T1574.005": "Executable Installer File Permissions Weakness",
        "T1574.006": "Dynamic Linker Hijacking",
        "T1574.007": "Path Interception by PATH Environment Variable",
        "T1574.008": "Path Interception by Search Order Hijacking",
        "T1574.009": "Path Interception by Unquoted Path",
        "T1574.010": "Services File Permissions Weakness",
        "T1574.011": "Services Registry Permissions Weakness",
        "T1574.012": "COR_PROFILER",
        "T1574.013": "KernelCallbackTable",
        "T1497": "Virtualization/Sandbox Evasion",
        "T1497.001": "System Checks",
        "T1497.002": "User Activity Based Checks",
        "T1497.003": "Time Based Evasion",
        "T1497.004": "Spoof Parent Process ID",
        "T1562": "Impair Defenses",
        "T1562.001": "Disable or Modify Tools",
        "T1562.002": "Disable Windows Event Logging",
        "T1562.003": "Indicator Blocking",
        "T1562.004": "Disable or Modify System Firewall",
        "T1562.005": "Disable or Modify Defenses",
        "T1562.006": "Indicator Removal on Host",
        "T1562.007": "Safe Mode Boot",
        "T1562.008": "Disable Cloud Logs",
        "T1562.009": "Disable Security Tools",
        "T1562.010": "Downgrade Attack",
        "T1562.011": "Script/Command Line Obfuscation",
        "T1564": "Hide Artifacts",
        "T1564.001": "Hidden Files and Directories",
        "T1564.002": "Hidden Users",
        "T1564.003": "Hidden Window",
        "T1564.004": "NTFS File Attributes",
        "T1564.005": "Hidden File System",
        "T1564.006": "Run Virtual Instance",
        "T1564.007": "VBA Stomping",
        "T1564.008": "Email Hiding Rules",
        "T1564.009": "Resource Forking",
        "T1564.010": "Process Argument Spoofing",
        "T1070": "Indicator Removal",
        "T1070.001": "Clear Windows Event Logs",
        "T1070.002": "Clear Linux or Mac System Logs",
        "T1070.003": "Clear Command History",
        "T1070.004": "File Deletion",
        "T1070.005": "Network Share Connection Removal",
        "T1070.006": "Timestomp",
        "T1070.007": "Clear Network Connection History and Configurations",
        "T1070.008": "Clear Mailbox Data",
        "T1070.009": "Clear Persistence",
        "T1556": "Modify Authentication Process",
        "T1556.001": "Domain Controller Authentication",
        "T1556.002": "Password Filter DLL",
        "T1556.003": "Pluggable Authentication Modules",
        "T1556.004": "Network Device Authentication",
        "T1556.005": "Reversible Encryption",
        "T1110": "Brute Force",
        "T1110.001": "Password Guessing",
        "T1110.002": "Password Cracking",
        "T1110.003": "Password Spraying",
        "T1110.004": "Credential Stuffing",
        "T1552": "Unsecured Credentials",
        "T1552.001": "Credentials In Files",
        "T1552.002": "Credentials in Registry",
        "T1552.003": "Bash History",
        "T1552.004": "Private Keys",
        "T1552.005": "Group Policy Preferences",
        "T1552.006": "Credentials in Web Browsers",
        "T1552.007": "Container API",
        "T1559": "Inter-Process Communication",
        "T1559.001": "Component Object Model",
        "T1559.002": "Dynamic Data Exchange",
        "T1559.003": "XPC Services",
        "T1204": "User Execution",
        "T1204.001": "Malicious Link",
        "T1204.002": "Malicious File",
        "T1204.003": "Malicious Image",
        "T1106": "Native API",
        "T1106.001": "Windows API",
        "T1106.002": "macOS API",
        "T1106.003": "Linux API",
        "T1053": "Scheduled Task/Job",
        "T1053.001": "At (Linux)",
        "T1053.002": "At (Windows)",
        "T1053.003": "Cron",
        "T1053.004": "Launchd",
        "T1053.005": "Scheduled Task",
        "T1053.006": "Systemd Timers",
        "T1053.007": "Container Orchestration Job",
        "T1203": "Exploitation for Client Execution",
        "T1129": "Shared Modules",
        "T1134": "Access Token Manipulation",
        "T1134.001": "Token Impersonation/Theft",
        "T1134.002": "Create Process with Token",
        "T1134.003": "Make and Impersonate Token",
        "T1134.004": "Parent PID Spoofing",
        "T1134.005": "SID-History Injection",
        "T1135": "Network Share Discovery",
        "T1136": "Create Account",
        "T1136.001": "Local Account",
        "T1136.002": "Domain Account",
        "T1136.003": "Cloud Account",
        "T1197": "BITS Jobs",
        "T1197.001": "BITS Jobs",
        "T1197.002": "BITS Admin",
        "T1485": "Data Destruction",
        "T1486": "Data Encrypted for Impact",
        "T1489": "Service Stop",
        "T1490": "Inhibit System Recovery",
        "T1491": "Defacement",
        "T1491.001": "Internal Defacement",
        "T1491.002": "External Defacement",
        "T1495": "Firmware Corruption",
        "T1496": "Resource Hijacking",
        "T1498": "Network Denial of Service",
        "T1498.001": "Direct Network Flood",
        "T1498.002": "Reflection Amplification",
        "T1499": "Endpoint Denial of Service",
        "T1499.001": "OS Exhaustion Flood",
        "T1499.002": "Service Exhaustion Flood",
        "T1499.003": "Application Exhaustion Flood",
        "T1499.004": "Application or System Exploitation",
        "T1531": "Account Access Removal",
        "T1561": "Disk Wipe",
        "T1561.001": "Disk Content Wipe",
        "T1561.002": "Disk Structure Wipe",
        "T1565": "Data Manipulation",
        "T1565.001": "Stored Data Manipulation",
        "T1565.002": "Transmitted Data Manipulation",
        "T1565.003": "Runtime Data Manipulation",
        "T1569": "System Services",
        "T1569.001": "Launchctl",
        "T1569.002": "Service Execution",
        "T1570": "Lateral Tool Transfer",
        "T1583": "Acquire Infrastructure",
        "T1583.001": "Domains",
        "T1583.002": "DNS Server",
        "T1583.003": "Virtual Private Server",
        "T1583.004": "Server",
        "T1583.005": "Botnet",
        "T1583.006": "Web Services",
        "T1583.007": "Serverless",
        "T1584": "Compromise Infrastructure",
        "T1584.001": "Domains",
        "T1584.002": "DNS Server",
        "T1584.003": "Virtual Private Server",
        "T1584.004": "Server",
        "T1584.005": "Botnet",
        "T1584.006": "Web Services",
        "T1585": "Establish Accounts",
        "T1585.001": "Social Media Accounts",
        "T1585.002": "Email Accounts",
        "T1585.003": "Cloud Accounts",
        "T1586": "Compromise Accounts",
        "T1586.001": "Social Media Accounts",
        "T1586.002": "Email Accounts",
        "T1586.003": "Cloud Accounts",
        "T1587": "Develop Capabilities",
        "T1587.001": "Malware",
        "T1587.002": "Code Signing Certificates",
        "T1587.003": "Digital Certificates",
        "T1587.004": "Exploits",
        "T1588": "Obtain Capabilities",
        "T1588.001": "Malware",
        "T1588.002": "Tool",
        "T1588.003": "Code Signing Certificates",
        "T1588.004": "Digital Certificates",
        "T1588.005": "Exploits",
        "T1588.006": "Vulnerabilities",
        "T1589": "Gather Victim Identity Information",
        "T1589.001": "Credentials",
        "T1589.002": "Email Addresses",
        "T1589.003": "Employee Names",
        "T1590": "Gather Victim Network Information",
        "T1590.001": "DNS",
        "T1590.002": "Domain Properties",
        "T1590.003": "Network Trust Dependencies",
        "T1590.004": "Network Topology",
        "T1590.005": "IP Addresses",
        "T1590.006": "Network Security Appliances",
        "T1591": "Gather Victim Org Information",
        "T1591.001": "Determine Business Roles",
        "T1591.002": "Identify Business Tempo",
        "T1591.003": "Identify Departments",
        "T1591.004": "Identify Physical Locations",
        "T1592": "Gather Victim Host Information",
        "T1592.001": "Hardware",
        "T1592.002": "Software",
        "T1592.003": "Firmware",
        "T1592.004": "Client Configurations",
        "T1593": "Search Open Websites/Domains",
        "T1593.001": "Social Media",
        "T1593.002": "Search Engines",
        "T1593.003": "Code Repositories",
        "T1594": "Search Victim-Owned Websites",
        "T1595": "Active Scanning",
        "T1595.001": "Scanning IP Blocks",
        "T1595.002": "Vulnerability Scanning",
        "T1595.003": "Wordlist Scanning",
        "T1596": "Search Open Technical Databases",
        "T1596.001": "WHOIS",
        "T1596.002": "DNS/Passive DNS",
        "T1596.003": "Digital Certificates",
        "T1596.004": "CDNs",
        "T1596.005": "Scan Databases",
        "T1596.006": "Network Enumeration",
        "T1597": "Search Closed Sources",
        "T1597.001": "Threat Intel Vendors",
        "T1597.002": "Purchase Technical Data",
        "T1598": "Phishing for Information",
        "T1598.001": "Spearphishing Service",
        "T1598.002": "Spearphishing Attachment",
        "T1598.003": "Spearphishing Link",
        "T1598.004": "Spearphishing via Service",
        "T1599": "Network Boundary Bridging",
        "T1599.001": "Monitor Takedown Processes",
        "T1599.002": "Acquire Access to Split-Horizon DNS",
        "T1189": "Drive-by Compromise",
        "T1190": "Exploit Public-Facing Application",
        "T1192": "Spearphishing Link",
        "T1193": "Spearphishing Attachment",
        "T1194": "Hardware Additions",
        "T1195": "Supply Chain Compromise",
        "T1195.001": "Compromise Software Dependencies and Development Tools",
        "T1195.002": "Compromise Software Supply Chain",
        "T1195.003": "Compromise Hardware Supply Chain",
        "T1199": "Trusted Relationship",
        "T1200": "Hardware Additions",
        "T1566": "Phishing",
        "T1566.001": "Spearphishing Attachment",
        "T1566.002": "Spearphishing Link",
        "T1566.003": "Spearphishing via Service",
        "T1566.004": "Spearphishing Voice",
        "T1566.005": "Malicious PDF",
        "T1566.006": "Malicious Image",
    }
    
    # Technique to tactic mapping
    _TECHNIQUE_TO_TACTIC = {
        "T1583": "Resource Development",
        "T1584": "Resource Development",
        "T1585": "Resource Development",
        "T1586": "Resource Development",
        "T1587": "Resource Development",
        "T1588": "Resource Development",
        "T1589": "Reconnaissance",
        "T1590": "Reconnaissance",
        "T1591": "Reconnaissance",
        "T1592": "Reconnaissance",
        "T1593": "Reconnaissance",
        "T1594": "Reconnaissance",
        "T1595": "Reconnaissance",
        "T1596": "Reconnaissance",
        "T1597": "Reconnaissance",
        "T1598": "Reconnaissance",
        "T1599": "Reconnaissance",
        "T1189": "Initial Access",
        "T1190": "Initial Access",
        "T1192": "Initial Access",
        "T1193": "Initial Access",
        "T1194": "Initial Access",
        "T1195": "Initial Access",
        "T1199": "Initial Access",
        "T1200": "Initial Access",
        "T1566": "Initial Access",
        "T1078": "Initial Access",
        "T1059": "Execution",
        "T1106": "Execution",
        "T1053": "Execution",
        "T1203": "Execution",
        "T1129": "Execution",
        "T1569": "Execution",
        "T1559": "Execution",
        "T1204": "Execution",
        "T1543": "Persistence",
        "T1546": "Persistence",
        "T1547": "Persistence",
        "T1136": "Persistence",
        "T1197": "Persistence",
        "T1548": "Privilege Escalation",
        "T1068": "Privilege Escalation",
        "T1574": "Privilege Escalation",
        "T1134": "Privilege Escalation",
        "T1497": "Defense Evasion",
        "T1562": "Defense Evasion",
        "T1564": "Defense Evasion",
        "T1070": "Defense Evasion",
        "T1556": "Defense Evasion",
        "T1027": "Defense Evasion",
        "T1036": "Defense Evasion",
        "T1055": "Defense Evasion",
        "T1110": "Credential Access",
        "T1552": "Credential Access",
        "T1555": "Credential Access",
        "T1056": "Credential Access",
        "T1083": "Discovery",
        "T1087": "Discovery",
        "T1016": "Discovery",
        "T1018": "Discovery",
        "T1049": "Discovery",
        "T1033": "Discovery",
        "T1069": "Discovery",
        "T1057": "Discovery",
        "T1012": "Discovery",
        "T1518": "Discovery",
        "T1082": "Discovery",
        "T1120": "Discovery",
        "T1135": "Discovery",
        "T1021": "Lateral Movement",
        "T1550": "Lateral Movement",
        "T1563": "Lateral Movement",
        "T1570": "Lateral Movement",
        "T1091": "Lateral Movement",
        "T1114": "Collection",
        "T1005": "Collection",
        "T1025": "Collection",
        "T1039": "Collection",
        "T1074": "Collection",
        "T1560": "Collection",
        "T1071": "Command and Control",
        "T1092": "Command and Control",
        "T1090": "Command and Control",
        "T1095": "Command and Control",
        "T1205": "Command and Control",
        "T1219": "Command and Control",
        "T1572": "Command and Control",
        "T1571": "Command and Control",
        "T1008": "Command and Control",
        "T1041": "Exfiltration",
        "T1048": "Exfiltration",
        "T1485": "Impact",
        "T1486": "Impact",
        "T1489": "Impact",
        "T1490": "Impact",
        "T1491": "Impact",
        "T1495": "Impact",
        "T1496": "Impact",
        "T1498": "Impact",
        "T1499": "Impact",
        "T1531": "Impact",
        "T1561": "Impact",
        "T1565": "Impact",
    }
    
    def __init__(self):
        """Initialize the coverage gap analyzer."""
        self._coverage_cache = {}
        self._analysis_history = []
        
    def get_version(self) -> Dict[str, str]:
        """Get version and stability information."""
        return {
            "version": self.VERSION,
            "api_stability": self.API_STABILITY,
            "mitre_version": "v14",
            "module": "MITREAttackCoverageGapAnalyzer"
        }
    
    def _get_tactic_for_technique(self, technique_id: str) -> str:
        """Get the tactic for a given technique."""
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        return self._TECHNIQUE_TO_TACTIC.get(base_id, "Unknown")
    
    def _calculate_priority(self, technique_id: str, tactic: str) -> CoveragePriority:
        """Calculate remediation priority based on prevalence and severity."""
        high_priority_techniques = {
            "T1059", "T1027", "T1055", "T1070", "T1562", "T1547",
            "T1078", "T1003", "T1110", "T1555", "T1566", "T1204",
            "T1053", "T1546", "T1071", "T1041", "T1486", "T1490"
        }
        
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        
        if base_id in high_priority_techniques:
            if tactic in ["Execution", "Defense Evasion", "Credential Access", "Initial Access"]:
                return CoveragePriority.CRITICAL
            return CoveragePriority.HIGH
        
        if tactic in ["Command and Control", "Exfiltration", "Impact", "Lateral Movement"]:
            return CoveragePriority.HIGH
        
        if tactic in ["Persistence", "Privilege Escalation", "Discovery", "Collection"]:
            return CoveragePriority.MEDIUM
        
        return CoveragePriority.LOW
    
    def _estimate_effort(self, technique_id: str) -> int:
        """Estimate implementation effort in hours."""
        complexity_map = {
            "simple": 8,
            "medium": 24,
            "complex": 40,
            "very_complex": 80
        }
        
        complex_techniques = {
            "T1055", "T1547", "T1562", "T1497", "T1564", "T1556",
            "T1574", "T1134", "T1550", "T1563"
        }
        
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        
        if base_id in complex_techniques:
            return complexity_map["very_complex"]
        if '.' in technique_id:
            return complexity_map["medium"]
        return complexity_map["complex"]
    
    def _get_detection_complexity(self, technique_id: str) -> str:
        """Get detection complexity rating."""
        high_complexity = {"T1055", "T1564", "T1497", "T1027", "T1574", "T1550"}
        medium_complexity = {"T1562", "T1070", "T1547", "T1546", "T1134", "T1563"}
        
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        
        if base_id in high_complexity:
            return "high"
        if base_id in medium_complexity:
            return "medium"
        return "low"
    
    def _get_fp_risk(self, technique_id: str) -> str:
        """Get false positive risk rating."""
        high_fp = {"T1059", "T1106", "T1057", "T1083", "T1082", "T1016"}
        medium_fp = {"T1053", "T1547", "T1546", "T1071", "T1090"}
        
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        
        if base_id in high_fp:
            return "high"
        if base_id in medium_fp:
            return "medium"
        return "low"
    
    def _get_recommended_approach(self, technique_id: str) -> str:
        """Get recommended detection approach."""
        approaches = {
            "T1055": "Behavioral detection + memory scanning + API hooking",
            "T1027": "YARA rules + entropy analysis + import table analysis",
            "T1059": "Command line logging + script block logging + AMSI",
            "T1070": "Backup log monitoring + log integrity checking",
            "T1562": "Defender health monitoring + service state tracking",
            "T1547": "Registry monitoring + startup location baseline",
            "T1566": "Email header analysis + URL reputation + sandbox detonation",
            "T1204": "File reputation + behavioral analysis + macro detection",
            "T1071": "Network anomaly detection + TLS fingerprinting",
            "T1041": "Data transfer volume monitoring + DLP integration",
            "T1486": "File extension monitoring + ransomware behavior patterns",
            "T1110": "Rate limiting + IP reputation + lockout policies",
            "T1555": "Credential access monitoring + LSA protection",
            "T1078": "Authentication anomaly + impossible travel detection",
        }
        
        base_id = technique_id.split('.')[0] if '.' in technique_id else technique_id
        return approaches.get(base_id, "Behavioral analysis + signature detection + anomaly monitoring")
    
    def analyze_coverage_gaps(self, additional_covered: Optional[Dict[str, str]] = None) -> CoverageAnalysisReport:
        """
        Perform comprehensive coverage gap analysis.
        
        Args:
            additional_covered: Optional additional covered techniques to include
            
        Returns:
            CoverageAnalysisReport with complete gap analysis
        """
        covered = dict(self._COVERED_TECHNIQUES)
        if additional_covered:
            covered.update(additional_covered)
        
        # Group by tactic
        tactic_coverage = defaultdict(lambda: {
            "total": 0,
            "covered": 0,
            "partial": 0,
            "not_covered": 0,
            "gaps": []
        })
        
        all_gaps = []
        critical_gaps = []
        high_priority_gaps = []
        
        # Check all MITRE techniques (sample of uncovered ones)
        uncovered_techniques = self._generate_uncovered_techniques()
        
        for tech_id, tech_name in uncovered_techniques.items():
            tactic = self._get_tactic_for_technique(tech_id)
            
            if tech_id in covered:
                status = CoverageStatus.FULLY_COVERED
                tactic_coverage[tactic]["covered"] += 1
            else:
                status = CoverageStatus.NOT_COVERED
                tactic_coverage[tactic]["not_covered"] += 1
                
                priority = self._calculate_priority(tech_id, tactic)
                gap = CoverageGap(
                    technique_id=tech_id,
                    technique_name=tech_name,
                    tactic=tactic,
                    coverage_status=status,
                    priority=priority,
                    gap_description=f"Technique {tech_id} ({tech_name}) has no detection coverage in current NeuralShield deployment",
                    detection_complexity=self._get_detection_complexity(tech_id),
                    false_positive_risk=self._get_fp_risk(tech_id),
                    recommended_approach=self._get_recommended_approach(tech_id),
                    estimated_effort_hours=self._estimate_effort(tech_id),
                    related_covered_techniques=self._find_related_techniques(tech_id, covered),
                    references=[
                        f"https://attack.mitre.org/techniques/{tech_id}/",
                        f"MITRE ATT&CK Technique {tech_id}"
                    ]
                )
                
                all_gaps.append(gap)
                tactic_coverage[tactic]["gaps"].append(gap)
                
                if priority == CoveragePriority.CRITICAL:
                    critical_gaps.append(gap)
                elif priority == CoveragePriority.HIGH:
                    high_priority_gaps.append(gap)
            
            tactic_coverage[tactic]["total"] += 1
        
        # Build tactic summaries
        tactic_summaries = {}
        for tactic, stats in tactic_coverage.items():
            total = stats["total"]
            covered_count = stats["covered"]
            coverage_pct = (covered_count / total * 100) if total > 0 else 0.0
            
            tactic_summaries[tactic] = TacticCoverageSummary(
                tactic_name=tactic,
                total_techniques=total,
                covered_techniques=covered_count,
                partially_covered=stats["partial"],
                not_covered=stats["not_covered"],
                coverage_percentage=round(coverage_pct, 2),
                gaps=sorted(stats["gaps"], key=lambda g: g.priority.value)
            )
        
        # Overall statistics
        total_techniques = len(covered) + len(uncovered_techniques)
        total_covered = len(covered)
        total_not_covered = len(uncovered_techniques)
        overall_coverage = (total_covered / total_techniques * 100) if total_techniques > 0 else 0.0
        
        report = CoverageAnalysisReport(
            report_id=f"mitre-coverage-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            generated_at=datetime.now(),
            mitre_version="v14",
            total_techniques=total_techniques,
            total_covered=total_covered,
            total_partially_covered=0,
            total_not_covered=total_not_covered,
            overall_coverage_percentage=round(overall_coverage, 2),
            tactic_summaries=tactic_summaries,
            critical_gaps=sorted(critical_gaps, key=lambda g: g.estimated_effort_hours),
            high_priority_gaps=sorted(high_priority_gaps, key=lambda g: g.estimated_effort_hours),
            recommendations=self._generate_recommendations(critical_gaps, high_priority_gaps, tactic_summaries)
        )
        
        self._analysis_history.append(report)
        return report
    
    def _generate_uncovered_techniques(self) -> Dict[str, str]:
        """Generate list of representative uncovered techniques for analysis."""
        uncovered = {
            "T1003": "OS Credential Dumping",
            "T1003.001": "LSASS Memory",
            "T1003.002": "Security Account Manager",
            "T1003.003": "NTDS",
            "T1003.004": "LSA Secrets",
            "T1003.005": "Cached Domain Credentials",
            "T1003.006": "DCSync",
            "T1040": "Network Sniffing",
            "T1040.001": "Packet Capture",
            "T1040.002": "Promiscuous Mode",
            "T1123": "Audio Capture",
            "T1125": "Video Capture",
            "T1125.001": "Screen Capture",
            "T1125.002": "Desktop Session Recording",
            "T1413": "Screen Capture",
            "T1505": "Server Software Component",
            "T1505.001": "SQL Stored Procedures",
            "T1505.002": "Transport Agent",
            "T1505.003": "Web Shell",
            "T1505.004": "IIS Components",
            "T1505.005": "Terminal Services DLL",
            "T1542": "Pre-OS Boot",
            "T1542.001": "System Firmware",
            "T1542.002": "Component Firmware",
            "T1542.003": "Bootkit",
            "T1542.004": "ROMMONkit",
            "T1542.005": "TFTP Boot",
            "T1554": "Compromise Client Software Binary",
            "T1558": "Steal or Forge Kerberos Tickets",
            "T1558.001": "Golden Ticket",
            "T1558.002": "Silver Ticket",
            "T1558.003": "Skeleton Key",
            "T1558.004": "AS-REP Roasting",
            "T1558.005": "Kerberoasting",
            "T1573": "Encrypted Channel",
            "T1573.001": "Symmetric Cryptography",
            "T1573.002": "Asymmetric Cryptography",
            "T1026": "Multiband Communication",
            "T1026.001": "Port Knocking",
            "T1026.002": "Multichannel Protocol",
            "T1001": "Data Obfuscation",
            "T1001.001": "Junk Data",
            "T1001.002": "Steganography",
            "T1001.003": "Protocol Impersonation",
            "T1002": "Data Compressed",
            "T1002.001": "Archive via Utility",
            "T1002.002": "Archive via Library",
            "T1011": "Exfiltration Over Other Network Medium",
            "T1011.001": "Exfiltration Over Bluetooth",
            "T1011.002": "Exfiltration Over USB",
            "T1052": "Exfiltration Over Physical Medium",
            "T1052.001": "Exfiltration over USB",
            "T1492": "Data Destruction",
            "T1493": "Data Encrypted for Impact",
            "T1494": "Runtime Data Manipulation",
            "T1495": "Firmware Corruption",
            "T1529": "System Shutdown/Reboot",
            "T1530": "Data from Cloud Storage Object",
            "T1532": "Data from Configuration Repository",
            "T1537": "Transfer Data to Cloud Account",
        }
        
        # Remove already covered techniques
        return {k: v for k, v in uncovered.items() if k not in self._COVERED_TECHNIQUES}
    
    def _find_related_techniques(self, tech_id: str, covered: Dict[str, str]) -> List[str]:
        """Find related covered techniques."""
        base_id = tech_id.split('.')[0] if '.' in tech_id else tech_id
        related = []
        
        for covered_id in covered:
            covered_base = covered_id.split('.')[0] if '.' in covered_id else covered_id
            if covered_base == base_id and covered_id != tech_id:
                related.append(covered_id)
        
        return related[:5]
    
    def _generate_recommendations(self, critical: List[CoverageGap], high: List[CoverageGap], 
                                   tactic_summaries: Dict[str, TacticCoverageSummary]) -> List[str]:
        """Generate prioritized recommendations."""
        recommendations = []
        
        if critical:
            easiest_critical = sorted(critical, key=lambda g: g.estimated_effort_hours)[:3]
            for gap in easiest_critical:
                recommendations.append(
                    f"[CRITICAL] Implement {gap.technique_id} ({gap.technique_name}) - "
                    f"Est: {gap.estimated_effort_hours}h, Approach: {gap.recommended_approach}"
                )
        
        if high:
            easiest_high = sorted(high, key=lambda g: g.estimated_effort_hours)[:5]
            for gap in easiest_high:
                recommendations.append(
                    f"[HIGH] Implement {gap.technique_id} ({gap.technique_name}) - "
                    f"Est: {gap.estimated_effort_hours}h"
                )
        
        # Tactical recommendations
        for tactic, summary in sorted(tactic_summaries.items(), key=lambda x: x[1].coverage_percentage):
            if summary.coverage_percentage < 50:
                recommendations.append(
                    f"[TACTIC FOCUS] {tactic} only at {summary.coverage_percentage}% coverage - "
                    f"{summary.not_covered} gaps remaining"
                )
        
        return recommendations[:15]
    
    def export_report_json(self, report: CoverageAnalysisReport) -> str:
        """Export coverage report as JSON string."""
        report_dict = {
            "report_id": report.report_id,
            "generated_at": report.generated_at.isoformat(),
            "mitre_version": report.mitre_version,
            "summary": {
                "total_techniques": report.total_techniques,
                "total_covered": report.total_covered,
                "total_partially_covered": report.total_partially_covered,
                "total_not_covered": report.total_not_covered,
                "overall_coverage_percentage": report.overall_coverage_percentage
            },
            "tactic_summaries": {
                name: {
                    "total_techniques": s.total_techniques,
                    "covered_techniques": s.covered_techniques,
                    "partially_covered": s.partially_covered,
                    "not_covered": s.not_covered,
                    "coverage_percentage": s.coverage_percentage,
                    "gap_count": len(s.gaps)
                }
                for name, s in report.tactic_summaries.items()
            },
            "critical_gaps": [
                {
                    "technique_id": g.technique_id,
                    "technique_name": g.technique_name,
                    "tactic": g.tactic,
                    "estimated_effort_hours": g.estimated_effort_hours,
                    "recommended_approach": g.recommended_approach
                }
                for g in report.critical_gaps
            ],
            "recommendations": report.recommendations
        }
        return json.dumps(report_dict, indent=2)
    
    def get_coverage_trend(self) -> Dict[str, Any]:
        """Get coverage improvement trend from analysis history."""
        if len(self._analysis_history) < 2:
            return {"trend": "insufficient_data", "analyses_available": len(self._analysis_history)}
        
        first = self._analysis_history[0]
        last = self._analysis_history[-1]
        
        return {
            "trend": "improving" if last.overall_coverage_percentage > first.overall_coverage_percentage else "stable",
            "coverage_improvement": round(last.overall_coverage_percentage - first.overall_coverage_percentage, 2),
            "analysis_count": len(self._analysis_history),
            "first_analysis": first.generated_at.isoformat(),
            "last_analysis": last.generated_at.isoformat()
        }
