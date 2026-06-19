"""
NeuralShield-AI: Threat Intelligence MITRE ATT&CK Heatmap Visualizer
June 2026 - Production Grade Implementation

This module generates MITRE ATT&CK heatmap data for security visualization dashboards.
It processes threat intelligence data and creates weighted heatmaps showing attack
technique frequency, severity, and risk distribution across MITRE tactics.

Production Features:
- Tactic and technique frequency counting
- Severity-weighted scoring
- Risk-based heatmap generation
- JSON and CSV export formats
- Dashboard-ready data structures
- Time-window filtering
- Top N technique identification
"""

import json
import csv
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, Counter


class MITRETactic(str, Enum):
    """MITRE ATT&CK Enterprise Tactics"""
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


class SeverityLevel(str, Enum):
    """Severity levels for threat scoring"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


SEVERITY_WEIGHTS = {
    SeverityLevel.CRITICAL: 10.0,
    SeverityLevel.HIGH: 7.0,
    SeverityLevel.MEDIUM: 4.0,
    SeverityLevel.LOW: 2.0,
    SeverityLevel.INFORMATIONAL: 1.0,
}


@dataclass
class HeatmapCell:
    """Single cell in the MITRE heatmap"""
    tactic: str
    technique_id: str
    technique_name: str
    count: int
    severity_score: float
    risk_score: float
    normalized_score: float
    last_seen: Optional[str] = None


@dataclass
class HeatmapResult:
    """Complete heatmap analysis result"""
    generated_at: str
    time_window_hours: int
    total_alerts: int
    unique_techniques: int
    cells: List[HeatmapCell]
    top_techniques: List[Dict[str, Any]]
    tactic_summary: Dict[str, Dict[str, Any]]
    overall_risk_score: float


class MITREHeatmapVisualizer:
    """
    Production-grade MITRE ATT&CK Heatmap Visualizer
    
    Processes threat intelligence alerts and generates visualization-ready heatmap data.
    """
    
    def __init__(self):
        self.tactic_order = list(MITRETactic)
        self.technique_mapping = self._build_technique_mapping()
        
    def _build_technique_mapping(self) -> Dict[str, Dict[str, str]]:
        """Build MITRE technique to tactic mapping (production subset)"""
        return {
            "T1595": {"name": "Active Scanning", "tactic": MITRETactic.RECONNAISSANCE},
            "T1592": {"name": "Gather Victim Host Information", "tactic": MITRETactic.RECONNAISSANCE},
            "T1589": {"name": "Gather Victim Identity Information", "tactic": MITRETactic.RECONNAISSANCE},
            "T1583": {"name": "Acquire Infrastructure", "tactic": MITRETactic.RESOURCE_DEVELOPMENT},
            "T1587": {"name": "Develop Capabilities", "tactic": MITRETactic.RESOURCE_DEVELOPMENT},
            "T1566": {"name": "Phishing", "tactic": MITRETactic.INITIAL_ACCESS},
            "T1190": {"name": "Exploit Public-Facing Application", "tactic": MITRETactic.INITIAL_ACCESS},
            "T1078": {"name": "Valid Accounts", "tactic": MITRETactic.INITIAL_ACCESS},
            "T1059": {"name": "Command and Scripting Interpreter", "tactic": MITRETactic.EXECUTION},
            "T1204": {"name": "User Execution", "tactic": MITRETactic.EXECUTION},
            "T1053": {"name": "Scheduled Task/Job", "tactic": MITRETactic.EXECUTION},
            "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": MITRETactic.PERSISTENCE},
            "T1136": {"name": "Create Account", "tactic": MITRETactic.PERSISTENCE},
            "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": MITRETactic.PRIVILEGE_ESCALATION},
            "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": MITRETactic.PRIVILEGE_ESCALATION},
            "T1036": {"name": "Masquerading", "tactic": MITRETactic.DEFENSE_EVASION},
            "T1562": {"name": "Impair Defenses", "tactic": MITRETactic.DEFENSE_EVASION},
            "T1027": {"name": "Obfuscated Files or Information", "tactic": MITRETactic.DEFENSE_EVASION},
            "T1555": {"name": "Credentials from Password Stores", "tactic": MITRETactic.CREDENTIAL_ACCESS},
            "T1110": {"name": "Brute Force", "tactic": MITRETactic.CREDENTIAL_ACCESS},
            "T1087": {"name": "Account Discovery", "tactic": MITRETactic.DISCOVERY},
            "T1046": {"name": "Network Service Scanning", "tactic": MITRETactic.DISCOVERY},
            "T1083": {"name": "File and Directory Discovery", "tactic": MITRETactic.DISCOVERY},
            "T1021": {"name": "Remote Services", "tactic": MITRETactic.LATERAL_MOVEMENT},
            "T1550": {"name": "Use Alternate Authentication Material", "tactic": MITRETactic.LATERAL_MOVEMENT},
            "T1005": {"name": "Data from Local System", "tactic": MITRETactic.COLLECTION},
            "T1114": {"name": "Email Collection", "tactic": MITRETactic.COLLECTION},
            "T1071": {"name": "Application Layer Protocol", "tactic": MITRETactic.COMMAND_AND_CONTROL},
            "T1090": {"name": "Proxy", "tactic": MITRETactic.COMMAND_AND_CONTROL},
            "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": MITRETactic.EXFILTRATION},
            "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": MITRETactic.EXFILTRATION},
            "T1486": {"name": "Data Encrypted for Impact", "tactic": MITRETactic.IMPACT},
            "T1490": {"name": "Inhibit System Recovery", "tactic": MITRETactic.IMPACT},
            "T1498": {"name": "Network Denial of Service", "tactic": MITRETactic.IMPACT},
        }
    
    def process_alerts(
        self,
        alerts: List[Dict[str, Any]],
        time_window_hours: int = 24
    ) -> HeatmapResult:
        """
        Process threat alerts and generate heatmap data.
        
        Args:
            alerts: List of alert dictionaries with technique_id, severity, timestamp
            time_window_hours: Time window for analysis
            
        Returns:
            HeatmapResult with complete visualization data
        """
        cutoff_time = datetime.utcnow() - timedelta(hours=time_window_hours)
        
        # Filter alerts by time window and valid technique IDs
        filtered_alerts = []
        for alert in alerts:
            try:
                ts_value = alert.get("timestamp", datetime.utcnow().isoformat())
                if isinstance(ts_value, (int, float)) or (isinstance(ts_value, str) and ts_value.isdigit()):
                    # Unix timestamp
                    alert_time = datetime.fromtimestamp(int(ts_value))
                else:
                    # ISO format
                    alert_time = datetime.fromisoformat(
                        str(ts_value).replace("Z", "+00:00")
                    )
                if alert_time >= cutoff_time:
                    filtered_alerts.append(alert)
            except (ValueError, TypeError):
                continue
        
        # Aggregate technique statistics
        technique_stats = defaultdict(lambda: {
            "count": 0,
            "severity_sum": 0.0,
            "last_seen": None,
            "tactic": None,
            "name": "Unknown Technique"
        })
        
        tactic_totals = defaultdict(lambda: {"count": 0, "risk_score": 0.0})
        
        for alert in filtered_alerts:
            tech_id = alert.get("technique_id", "T0000")
            severity = SeverityLevel(alert.get("severity", SeverityLevel.MEDIUM))
            weight = SEVERITY_WEIGHTS[severity]
            
            tech_info = self.technique_mapping.get(tech_id, {
                "name": f"Unknown ({tech_id})",
                "tactic": MITRETactic.DISCOVERY
            })
            
            stats = technique_stats[tech_id]
            stats["count"] += 1
            stats["severity_sum"] += weight
            stats["tactic"] = tech_info["tactic"]
            stats["name"] = tech_info["name"]
            stats["last_seen"] = alert.get("timestamp", stats["last_seen"])
            
            tactic_totals[tech_info["tactic"]]["count"] += 1
            tactic_totals[tech_info["tactic"]]["risk_score"] += weight
        
        # Calculate max scores for normalization
        all_scores = [s["severity_sum"] for s in technique_stats.values()]
        max_score = max(all_scores) if all_scores else 1.0
        
        # Build heatmap cells
        cells = []
        for tech_id, stats in technique_stats.items():
            normalized = stats["severity_sum"] / max_score if max_score > 0 else 0.0
            cells.append(HeatmapCell(
                tactic=stats["tactic"].value,
                technique_id=tech_id,
                technique_name=stats["name"],
                count=stats["count"],
                severity_score=stats["severity_sum"],
                risk_score=stats["severity_sum"],
                normalized_score=round(normalized, 3),
                last_seen=stats["last_seen"]
            ))
        
        # Get top techniques by risk score
        sorted_techniques = sorted(
            technique_stats.items(),
            key=lambda x: x[1]["severity_sum"],
            reverse=True
        )[:10]
        
        top_techniques = [
            {
                "technique_id": tid,
                "technique_name": stats["name"],
                "tactic": stats["tactic"].value,
                "count": stats["count"],
                "risk_score": round(stats["severity_sum"], 2)
            }
            for tid, stats in sorted_techniques
        ]
        
        # Build tactic summary
        tactic_summary = {}
        for tactic in MITRETactic:
            totals = tactic_totals[tactic]
            tactic_summary[tactic.value] = {
                "alert_count": totals["count"],
                "total_risk_score": round(totals["risk_score"], 2),
                "coverage_percent": round(
                    (totals["count"] / len(filtered_alerts) * 100) 
                    if filtered_alerts else 0, 1
                )
            }
        
        # Calculate overall risk score (0-100)
        total_risk = sum(s["severity_sum"] for s in technique_stats.values())
        overall_risk = min(100.0, round(total_risk * 2, 1))
        
        return HeatmapResult(
            generated_at=datetime.utcnow().isoformat() + "Z",
            time_window_hours=time_window_hours,
            total_alerts=len(filtered_alerts),
            unique_techniques=len(technique_stats),
            cells=cells,
            top_techniques=top_techniques,
            tactic_summary=tactic_summary,
            overall_risk_score=overall_risk
        )
    
    def export_to_json(self, result: HeatmapResult, filepath: Optional[str] = None) -> str:
        """Export heatmap result to JSON format"""
        output = {
            "metadata": {
                "generated_at": result.generated_at,
                "time_window_hours": result.time_window_hours,
                "total_alerts": result.total_alerts,
                "unique_techniques": result.unique_techniques,
                "overall_risk_score": result.overall_risk_score
            },
            "tactic_summary": result.tactic_summary,
            "top_techniques": result.top_techniques,
            "heatmap_cells": [asdict(cell) for cell in result.cells]
        }
        
        json_str = json.dumps(output, indent=2)
        
        if filepath:
            with open(filepath, "w") as f:
                f.write(json_str)
        
        return json_str
    
    def export_to_csv(self, result: HeatmapResult, filepath: str) -> None:
        """Export heatmap cells to CSV format for spreadsheet analysis"""
        with open(filepath, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "Tactic", "Technique ID", "Technique Name", "Alert Count",
                "Severity Score", "Risk Score", "Normalized Score", "Last Seen"
            ])
            for cell in result.cells:
                writer.writerow([
                    cell.tactic, cell.technique_id, cell.technique_name,
                    cell.count, cell.severity_score, cell.risk_score,
                    cell.normalized_score, cell.last_seen or ""
                ])
    
    def generate_dashboard_data(self, result: HeatmapResult) -> Dict[str, Any]:
        """Generate dashboard-ready data structure for visualization libraries"""
        # Build matrix-style heatmap data
        matrix_data = {}
        for tactic in MITRETactic:
            matrix_data[tactic.value] = []
        
        for cell in result.cells:
            matrix_data[cell.tactic].append({
                "id": cell.technique_id,
                "name": cell.technique_name,
                "value": cell.normalized_score,
                "count": cell.count,
                "risk": cell.risk_score
            })
        
        return {
            "matrix_heatmap": matrix_data,
            "risk_gauge": {
                "value": result.overall_risk_score,
                "level": "critical" if result.overall_risk_score >= 70 
                        else "high" if result.overall_risk_score >= 40
                        else "medium" if result.overall_risk_score >= 20
                        else "low"
            },
            "top_threats_barchart": result.top_techniques,
            "tactic_distribution": result.tactic_summary,
            "summary_stats": {
                "total_alerts": result.total_alerts,
                "techniques_detected": result.unique_techniques,
                "tactics_observed": sum(
                    1 for t in result.tactic_summary.values() 
                    if t["alert_count"] > 0
                )
            }
        }
    
    def generate_sample_alerts(self, count: int = 50) -> List[Dict[str, Any]]:
        """Generate sample alert data for testing and demonstration"""
        import random
        
        techniques = list(self.technique_mapping.keys())
        severities = list(SeverityLevel)
        alerts = []
        
        base_time = datetime.utcnow()
        
        for i in range(count):
            hours_ago = random.randint(0, 23)
            alert_time = base_time - timedelta(hours=hours_ago, minutes=random.randint(0, 59))
            
            alerts.append({
                "alert_id": f"ALERT-{i:06d}",
                "technique_id": random.choice(techniques),
                "severity": random.choice(severities).value,
                "timestamp": alert_time.isoformat() + "Z",
                "source_ip": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}",
                "confidence": round(random.uniform(0.5, 1.0), 2)
            })
        
        return alerts
