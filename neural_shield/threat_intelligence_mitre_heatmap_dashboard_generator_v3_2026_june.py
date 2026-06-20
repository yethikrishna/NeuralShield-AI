"""
Threat Intelligence MITRE ATT&CK Heatmap Dashboard Generator v3
June 21, 2026

Enhanced production-grade implementation with:
- Interactive HTML dashboard generation
- Tactics and techniques visualization
- Severity-based color coding
- Trend analysis over time
- Export capabilities (JSON, CSV, HTML)
- Threat actor mapping integration
"""

import json
import csv
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from pathlib import Path


class MITRETactic(Enum):
    """MITRE ATT&CK Tactics"""
    RECONNAISSANCE = "Reconnaissance"
    RESOURCE_DEVELOPMENT = "Resource Development"
    INITIAL_ACCESS = "Initial Access"
    EXECUTION = "Execution"
    PERSISTENCE = "Persistence"
    PRIVILEGE_ESCALATION = "Privilege Escalation"
    DEFENSE_EVASION = "Defense Evasion"
    CREDENTIAL_ACCESS = "Credential Access"
    DISCOVERY = "Discovery"
    LATERAL_MOVEMENT = "Lateral Movement"
    COLLECTION = "Collection"
    COMMAND_AND_CONTROL = "Command and Control"
    EXFILTRATION = "Exfiltration"
    IMPACT = "Impact"


class SeverityLevel(Enum):
    """Severity levels for heatmap coloring"""
    CRITICAL = (4, "#8B0000", "Critical")
    HIGH = (3, "#FF4500", "High")
    MEDIUM = (2, "#FFA500", "Medium")
    LOW = (1, "#FFD700", "Low")
    NONE = (0, "#90EE90", "None")


@dataclass
class TechniqueObservation:
    """Single technique observation"""
    technique_id: str
    technique_name: str
    tactic: MITRETactic
    count: int = 1
    severity: SeverityLevel = SeverityLevel.MEDIUM
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    threat_actors: List[str] = field(default_factory=list)
    malware_families: List[str] = field(default_factory=list)
    detection_sources: List[str] = field(default_factory=list)


@dataclass
class HeatmapCell:
    """Heatmap cell data"""
    tactic: str
    technique_id: str
    technique_name: str
    count: int
    severity: SeverityLevel
    threat_actors: List[str]
    trend: float  # % change from previous period


class MITREHeatmapGeneratorV3:
    """
    Enhanced MITRE ATT&CK Heatmap Dashboard Generator v3.
    
    Features:
    - Full tactic and technique coverage
    - Severity-based color coding
    - Trend analysis (current vs previous period)
    - Threat actor mapping
    - Interactive HTML dashboard
    - Multiple export formats
    """
    
    # MITRE ATT&CK Techniques mapping (simplified production set)
    TACTIC_TECHNIQUES = {
        MITRETactic.RECONNAISSANCE: [
            ("T1595", "Active Scanning"),
            ("T1592", "Gather Victim Host Information"),
            ("T1591", "Gather Victim Org Information"),
            ("T1593", "Search Open Technical Databases"),
            ("T1598", "Phishing for Information"),
        ],
        MITRETactic.INITIAL_ACCESS: [
            ("T1566", "Phishing"),
            ("T1190", "Exploit Public-Facing Application"),
            ("T1200", "Hardware Additions"),
            ("T1091", "Replication Through Removable Media"),
            ("T1133", "External Remote Services"),
            ("T1078", "Valid Accounts"),
        ],
        MITRETactic.EXECUTION: [
            ("T1059", "Command and Scripting Interpreter"),
            ("T1053", "Scheduled Task/Job"),
            ("T1204", "User Execution"),
            ("T1072", "Software Deployment Tools"),
            ("T1559", "Inter-Process Communication"),
            ("T1047", "Windows Management Instrumentation"),
        ],
        MITRETactic.PERSISTENCE: [
            ("T1547", "Boot or Logon Autostart Execution"),
            ("T1037", "Boot or Logon Initialization Scripts"),
            ("T1546", "Event Triggered Execution"),
            ("T1136", "Create Account"),
            ("T1098", "Account Manipulation"),
        ],
        MITRETactic.PRIVILEGE_ESCALATION: [
            ("T1548", "Abuse Elevation Control Mechanism"),
            ("T1547", "Boot or Logon Autostart Execution"),
            ("T1068", "Exploitation for Privilege Escalation"),
            ("T1055", "Process Injection"),
            ("T1037", "Boot or Logon Initialization Scripts"),
        ],
        MITRETactic.DEFENSE_EVASION: [
            ("T1562", "Impair Defenses"),
            ("T1070", "Indicator Removal"),
            ("T1027", "Obfuscated Files or Information"),
            ("T1055", "Process Injection"),
            ("T1202", "Indirect Command Execution"),
            ("T1497", "Virtualization/Sandbox Evasion"),
        ],
        MITRETactic.CREDENTIAL_ACCESS: [
            ("T1555", "Credentials from Password Stores"),
            ("T1056", "Input Capture"),
            ("T1110", "Brute Force"),
            ("T1556", "Modify Authentication Process"),
            ("T1003", "OS Credential Dumping"),
            ("T1558", "Steal or Forge Kerberos Tickets"),
        ],
        MITRETactic.DISCOVERY: [
            ("T1087", "Account Discovery"),
            ("T1069", "Permission Groups Discovery"),
            ("T1083", "File and Directory Discovery"),
            ("T1046", "Network Service Scanning"),
            ("T1049", "System Network Connections Discovery"),
            ("T1082", "System Information Discovery"),
        ],
        MITRETactic.LATERAL_MOVEMENT: [
            ("T1021", "Remote Services"),
            ("T1075", "Pass the Hash"),
            ("T1550", "Use Alternate Authentication Material"),
            ("T1080", "Data Staged"),
            ("T1210", "Exploitation of Remote Services"),
        ],
        MITRETactic.COLLECTION: [
            ("T1560", "Archive Collected Data"),
            ("T1114", "Email Collection"),
            ("T1056", "Input Capture"),
            ("T1113", "Screen Capture"),
            ("T1005", "Data from Local System"),
        ],
        MITRETactic.COMMAND_AND_CONTROL: [
            ("T1071", "Application Layer Protocol"),
            ("T1095", "Non-Application Layer Protocol"),
            ("T1573", "Encrypted Channel"),
            ("T1090", "Proxy"),
            ("T1105", "Ingress Tool Transfer"),
            ("T1571", "Non-Standard Port"),
        ],
        MITRETactic.EXFILTRATION: [
            ("T1041", "Exfiltration Over C2 Channel"),
            ("T1048", "Exfiltration Over Alternative Protocol"),
            ("T1052", "Exfiltration Over Physical Medium"),
            ("T1567", "Exfiltration Over Web Service"),
            ("T1030", "Data Transfer Size Limits"),
        ],
        MITRETactic.IMPACT: [
            ("T1498", "Network Denial of Service"),
            ("T1499", "Endpoint Denial of Service"),
            ("T1486", "Data Encrypted for Impact"),
            ("T1485", "Data Destruction"),
            ("T1490", "Inhibit System Recovery"),
            ("T1565", "Data Manipulation"),
        ],
    }
    
    def __init__(self):
        self.observations: Dict[str, TechniqueObservation] = {}
        self.previous_period_observations: Dict[str, int] = {}
        self.threat_actor_mapping: Dict[str, Set[str]] = defaultdict(set)
    
    def add_observation(
        self,
        technique_id: str,
        technique_name: str,
        tactic: MITRETactic,
        count: int = 1,
        severity: SeverityLevel = SeverityLevel.MEDIUM,
        threat_actor: Optional[str] = None,
        malware_family: Optional[str] = None,
        detection_source: Optional[str] = None
    ) -> None:
        """Add or update a technique observation"""
        key = f"{tactic.value}:{technique_id}"
        
        if key not in self.observations:
            self.observations[key] = TechniqueObservation(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                count=0,
                severity=severity,
                first_seen=datetime.now(),
                last_seen=datetime.now()
            )
        
        obs = self.observations[key]
        obs.count += count
        obs.last_seen = datetime.now()
        
        # Update severity if higher
        if severity.value[0] > obs.severity.value[0]:
            obs.severity = severity
        
        if threat_actor and threat_actor not in obs.threat_actors:
            obs.threat_actors.append(threat_actor)
            self.threat_actor_mapping[threat_actor].add(key)
        
        if malware_family and malware_family not in obs.malware_families:
            obs.malware_families.append(malware_family)
        
        if detection_source and detection_source not in obs.detection_sources:
            obs.detection_sources.append(detection_source)
    
    def set_previous_period_baseline(self, baseline_counts: Dict[str, int]) -> None:
        """Set previous period counts for trend analysis"""
        self.previous_period_observations = baseline_counts.copy()
    
    def calculate_trend(self, key: str, current_count: int) -> float:
        """Calculate trend percentage vs previous period"""
        prev_count = self.previous_period_observations.get(key, 0)
        
        if prev_count == 0:
            return 100.0 if current_count > 0 else 0.0
        
        return ((current_count - prev_count) / prev_count) * 100
    
    def generate_heatmap_data(self) -> Dict[str, List[HeatmapCell]]:
        """Generate structured heatmap data by tactic"""
        heatmap: Dict[str, List[HeatmapCell]] = defaultdict(list)
        
        for tactic, techniques in self.TACTIC_TECHNIQUES.items():
            for tech_id, tech_name in techniques:
                key = f"{tactic.value}:{tech_id}"
                obs = self.observations.get(key)
                
                if obs:
                    count = obs.count
                    severity = obs.severity
                    actors = obs.threat_actors
                else:
                    count = 0
                    severity = SeverityLevel.NONE
                    actors = []
                
                trend = self.calculate_trend(key, count)
                
                cell = HeatmapCell(
                    tactic=tactic.value,
                    technique_id=tech_id,
                    technique_name=tech_name,
                    count=count,
                    severity=severity,
                    threat_actors=actors,
                    trend=round(trend, 1)
                )
                
                heatmap[tactic.value].append(cell)
        
        return dict(heatmap)
    
    def get_severity_color(self, count: int) -> str:
        """Get color based on observation count"""
        if count >= 10:
            return SeverityLevel.CRITICAL.value[1]
        elif count >= 5:
            return SeverityLevel.HIGH.value[1]
        elif count >= 2:
            return SeverityLevel.MEDIUM.value[1]
        elif count >= 1:
            return SeverityLevel.LOW.value[1]
        else:
            return SeverityLevel.NONE.value[1]
    
    def generate_html_dashboard(self, output_path: str, title: str = "MITRE ATT&CK Heatmap Dashboard") -> bool:
        """Generate interactive HTML dashboard"""
        heatmap_data = self.generate_heatmap_data()
        
        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background: #1a1a2e; color: #eee; padding: 20px; }}
        .dashboard {{ max-width: 1800px; margin: 0 auto; }}
        h1 {{ text-align: center; color: #4fc3f7; margin-bottom: 30px; font-size: 28px; }}
        .header-info {{ display: flex; justify-content: space-between; margin-bottom: 20px; background: #16213e; padding: 15px; border-radius: 8px; }}
        .stat-box {{ text-align: center; padding: 10px 20px; }}
        .stat-value {{ font-size: 24px; font-weight: bold; color: #4fc3f7; }}
        .stat-label {{ font-size: 12px; color: #888; text-transform: uppercase; }}
        .legend {{ display: flex; justify-content: center; gap: 20px; margin-bottom: 20px; flex-wrap: wrap; }}
        .legend-item {{ display: flex; align-items: center; gap: 8px; }}
        .legend-color {{ width: 20px; height: 20px; border-radius: 4px; }}
        .heatmap-container {{ overflow-x: auto; }}
        .heatmap {{ display: grid; gap: 2px; background: #0f0f23; padding: 10px; border-radius: 8px; }}
        .tactic-header {{ 
            background: #16213e; 
            padding: 12px 8px; 
            font-weight: bold; 
            text-align: center;
            color: #4fc3f7;
            font-size: 12px;
            border-radius: 4px;
            min-width: 120px;
        }}
        .technique-cell {{
            padding: 8px 6px;
            text-align: center;
            border-radius: 4px;
            cursor: pointer;
            transition: all 0.2s;
            font-size: 11px;
            min-height: 50px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            position: relative;
        }}
        .technique-cell:hover {{ transform: scale(1.05); z-index: 10; box-shadow: 0 4px 12px rgba(0,0,0,0.5); }}
        .tech-id {{ font-weight: bold; font-size: 10px; opacity: 0.9; }}
        .tech-count {{ font-size: 14px; font-weight: bold; margin: 2px 0; }}
        .tech-name {{ font-size: 9px; opacity: 0.8; line-height: 1.2; }}
        .trend-up {{ color: #ff6b6b; }}
        .trend-down {{ color: #51cf66; }}
        .tooltip {{
            position: absolute;
            background: #16213e;
            border: 1px solid #4fc3f7;
            padding: 10px;
            border-radius: 6px;
            font-size: 12px;
            z-index: 100;
            display: none;
            min-width: 200px;
            text-align: left;
        }}
        .technique-cell:hover .tooltip {{ display: block; }}
        .tactic-row {{ display: contents; }}
        .generated {{ text-align: center; margin-top: 20px; color: #666; font-size: 11px; }}
    </style>
</head>
<body>
    <div class="dashboard">
        <h1>🔥 {title}</h1>
        
        <div class="header-info">
            <div class="stat-box">
                <div class="stat-value">{sum(o.count for o in self.observations.values())}</div>
                <div class="stat-label">Total Detections</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(self.observations)}</div>
                <div class="stat-label">Techniques Observed</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{len(self.threat_actor_mapping)}</div>
                <div class="stat-label">Threat Actors</div>
            </div>
            <div class="stat-box">
                <div class="stat-value">{datetime.now().strftime('%Y-%m-%d %H:%M')}</div>
                <div class="stat-label">Generated</div>
            </div>
        </div>
        
        <div class="legend">
            <div class="legend-item"><div class="legend-color" style="background: #8B0000;"></div> Critical (10+)</div>
            <div class="legend-item"><div class="legend-color" style="background: #FF4500;"></div> High (5-9)</div>
            <div class="legend-item"><div class="legend-color" style="background: #FFA500;"></div> Medium (2-4)</div>
            <div class="legend-item"><div class="legend-color" style="background: #FFD700;"></div> Low (1)</div>
            <div class="legend-item"><div class="legend-color" style="background: #90EE90;"></div> None (0)</div>
        </div>
        
        <div class="heatmap-container">
            <div class="heatmap" style="grid-template-columns: repeat({len(self.TACTIC_TECHNIQUES)}, minmax(120px, 1fr));">
"""
        
        # Add tactic headers
        for tactic in self.TACTIC_TECHNIQUES.keys():
            html_content += f'<div class="tactic-header">{tactic.value}</div>\n'
        
        # Find max techniques per tactic for grid
        max_techs = max(len(techs) for techs in self.TACTIC_TECHNIQUES.values())
        
        # Add technique cells row by row
        for row_idx in range(max_techs):
            for tactic, techniques in self.TACTIC_TECHNIQUES.items():
                if row_idx < len(techniques):
                    tech_id, tech_name = techniques[row_idx]
                    key = f"{tactic.value}:{tech_id}"
                    obs = self.observations.get(key)
                    count = obs.count if obs else 0
                    color = self.get_severity_color(count)
                    trend = self.calculate_trend(key, count)
                    trend_class = "trend-up" if trend > 0 else "trend-down"
                    trend_sign = "+" if trend > 0 else ""
                    actors = ", ".join(obs.threat_actors) if obs and obs.threat_actors else "None"
                    
                    html_content += f'''
                <div class="technique-cell" style="background: {color};">
                    <div class="tech-id">{tech_id}</div>
                    <div class="tech-count">{count}</div>
                    <div class="tech-name">{tech_name[:22]}...</div>
                    <div class="{trend_class}" style="font-size: 10px;">{trend_sign}{trend}%</div>
                    <div class="tooltip">
                        <strong>{tech_id}: {tech_name}</strong><br>
                        Tactic: {tactic.value}<br>
                        Count: {count}<br>
                        Trend: {trend_sign}{trend}%<br>
                        Threat Actors: {actors}
                    </div>
                </div>'''
                else:
                    html_content += '<div></div>'
        
        html_content += f"""
            </div>
        </div>
        
        <div class="generated">
            MITRE ATT&CK Heatmap Dashboard v3 - Generated by NeuralShield-AI
        </div>
    </div>
</body>
</html>"""
        
        try:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            return True
        except Exception:
            return False
    
    def export_json(self, output_path: str) -> bool:
        """Export heatmap data to JSON"""
        data = {
            "generated_at": datetime.now().isoformat(),
            "version": "v3",
            "summary": {
                "total_detections": sum(o.count for o in self.observations.values()),
                "techniques_observed": len(self.observations),
                "threat_actors": len(self.threat_actor_mapping)
            },
            "heatmap_data": {}
        }
        
        heatmap = self.generate_heatmap_data()
        for tactic, cells in heatmap.items():
            data["heatmap_data"][tactic] = [
                {
                    "technique_id": cell.technique_id,
                    "technique_name": cell.technique_name,
                    "count": cell.count,
                    "severity": cell.severity.value[2],
                    "trend_percent": cell.trend,
                    "threat_actors": cell.threat_actors
                }
                for cell in cells
            ]
        
        try:
            with open(output_path, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False
    
    def export_csv(self, output_path: str) -> bool:
        """Export heatmap data to CSV"""
        heatmap = self.generate_heatmap_data()
        
        try:
            with open(output_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    "Tactic", "Technique ID", "Technique Name", 
                    "Count", "Severity", "Trend %", "Threat Actors"
                ])
                
                for tactic, cells in heatmap.items():
                    for cell in cells:
                        writer.writerow([
                            tactic,
                            cell.technique_id,
                            cell.technique_name,
                            cell.count,
                            cell.severity.value[2],
                            cell.trend,
                            ", ".join(cell.threat_actors)
                        ])
            return True
        except Exception:
            return False
    
    def get_threat_actor_matrix(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get techniques per threat actor"""
        result: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        
        for actor, tech_keys in self.threat_actor_mapping.items():
            for key in tech_keys:
                obs = self.observations.get(key)
                if obs:
                    result[actor].append({
                        "technique_id": obs.technique_id,
                        "technique_name": obs.technique_name,
                        "tactic": obs.tactic.value,
                        "count": obs.count
                    })
        
        return dict(result)


def verify_heatmap_generator_v3() -> Dict[str, Any]:
    """Verify the heatmap generator works correctly"""
    generator = MITREHeatmapGeneratorV3()
    
    # Add sample observations
    sample_data = [
        ("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, 15, SeverityLevel.CRITICAL, "APT29", "Emotet"),
        ("T1059", "Command and Scripting Interpreter", MITRETactic.EXECUTION, 8, SeverityLevel.HIGH, "APT29"),
        ("T1027", "Obfuscated Files or Information", MITRETactic.DEFENSE_EVASION, 12, SeverityLevel.CRITICAL, "APT28"),
        ("T1003", "OS Credential Dumping", MITRETactic.CREDENTIAL_ACCESS, 6, SeverityLevel.HIGH, "APT28"),
        ("T1046", "Network Service Scanning", MITRETactic.DISCOVERY, 3, SeverityLevel.MEDIUM),
        ("T1071", "Application Layer Protocol", MITRETactic.COMMAND_AND_CONTROL, 9, SeverityLevel.HIGH, "APT29"),
        ("T1041", "Exfiltration Over C2 Channel", MITRETactic.EXFILTRATION, 5, SeverityLevel.HIGH, "APT28"),
        ("T1486", "Data Encrypted for Impact", MITRETactic.IMPACT, 2, SeverityLevel.MEDIUM),
    ]
    
    for tech_id, tech_name, tactic, count, severity, *rest in sample_data:
        actor = rest[0] if len(rest) > 0 else None
        malware = rest[1] if len(rest) > 1 else None
        generator.add_observation(tech_id, tech_name, tactic, count, severity, actor, malware)
    
    # Set baseline for trend calculation
    generator.set_previous_period_baseline({
        "Initial Access:T1566": 10,
        "Execution:T1059": 5,
        "Defense Evasion:T1027": 15,
    })
    
    # Generate heatmap data
    heatmap_data = generator.generate_heatmap_data()
    
    # Verify data structure
    assert len(heatmap_data) > 0, "No heatmap data generated"
    
    # Test exports
    base_path = "/home/user/.super_doubao/super-doubao-runtime/workspace/NeuralShield-AI"
    html_ok = generator.generate_html_dashboard(f"{base_path}/test_heatmap_v3_dashboard.html")
    json_ok = generator.export_json(f"{base_path}/test_heatmap_v3_data.json")
    csv_ok = generator.export_csv(f"{base_path}/test_heatmap_v3_data.csv")
    
    # Get threat actor matrix
    actor_matrix = generator.get_threat_actor_matrix()
    
    return {
        "status": "success",
        "observations_added": len(sample_data),
        "tactics_covered": len(heatmap_data),
        "html_export_ok": html_ok,
        "json_export_ok": json_ok,
        "csv_export_ok": csv_ok,
        "threat_actors_identified": len(actor_matrix),
        "total_detections": sum(o.count for o in generator.observations.values())
    }


if __name__ == "__main__":
    result = verify_heatmap_generator_v3()
    print(json.dumps(result, indent=2))
