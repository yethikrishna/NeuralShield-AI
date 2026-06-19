"""
NeuralShield AI - Threat Intelligence MITRE ATT&CK Heatmap Executive Dashboard Generator
Production-Grade Implementation

This module provides executive-level threat visibility by:
1. Mapping security alerts to MITRE ATT&CK tactics and techniques
2. Generating heatmap data for dashboard visualization
3. Calculating risk scores per tactic/technique
4. Producing executive summary reports
5. Exporting data for SIEM and SOAR integration

Author: NeuralShield AI Team
Version: 1.0.0
Date: June 2026
"""

import json
import hashlib
import datetime
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from enum import Enum


class MITRETactic(str, Enum):
    """MITRE ATT&CK Enterprise Tactics"""
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


class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class HeatmapCell:
    """Represents a single cell in the MITRE heatmap"""
    tactic: str
    technique: str
    technique_id: str
    alert_count: int
    risk_score: float
    severity: str
    trend: str  # increasing, decreasing, stable
    last_detected: str


@dataclass
class ExecutiveSummary:
    """Executive-level summary of threat posture"""
    report_generated: str
    total_alerts_analyzed: int
    critical_tactics: List[str]
    highest_risk_technique: str
    overall_threat_level: str
    risk_score: float
    top_attack_vectors: List[Dict[str, Any]]
    recommendations: List[str]
    trend_analysis: Dict[str, Any]


class MITREHeatmapDashboard:
    """
    Production-grade MITRE ATT&CK Heatmap Dashboard Generator
    
    Features:
    - Alert-to-MITRE mapping with confidence scoring
    - Risk calculation based on severity and frequency
    - Trend analysis over time windows
    - Executive report generation
    - JSON export for dashboard integration
    """
    
    # MITRE Technique mapping (simplified production version)
    TECHNIQUE_MAPPING = {
        "T1595": {"name": "Active Scanning", "tactic": MITRETactic.RECONNAISSANCE},
        "T1589": {"name": "Gather Victim Identity Information", "tactic": MITRETactic.RECONNAISSANCE},
        "T1566": {"name": "Phishing", "tactic": MITRETactic.INITIAL_ACCESS},
        "T1190": {"name": "Exploit Public-Facing Application", "tactic": MITRETactic.INITIAL_ACCESS},
        "T1059": {"name": "Command and Scripting Interpreter", "tactic": MITRETactic.EXECUTION},
        "T1053": {"name": "Scheduled Task/Job", "tactic": MITRETactic.EXECUTION},
        "T1547": {"name": "Boot or Logon Autostart Execution", "tactic": MITRETactic.PERSISTENCE},
        "T1136": {"name": "Create Account", "tactic": MITRETactic.PERSISTENCE},
        "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": MITRETactic.PRIVILEGE_ESCALATION},
        "T1068": {"name": "Exploitation for Privilege Escalation", "tactic": MITRETactic.PRIVILEGE_ESCALATION},
        "T1027": {"name": "Obfuscated Files or Information", "tactic": MITRETactic.DEFENSE_EVASION},
        "T1562": {"name": "Impair Defenses", "tactic": MITRETactic.DEFENSE_EVASION},
        "T1110": {"name": "Brute Force", "tactic": MITRETactic.CREDENTIAL_ACCESS},
        "T1555": {"name": "Credentials from Password Stores", "tactic": MITRETactic.CREDENTIAL_ACCESS},
        "T1087": {"name": "Account Discovery", "tactic": MITRETactic.DISCOVERY},
        "T1046": {"name": "Network Service Scanning", "tactic": MITRETactic.DISCOVERY},
        "T1021": {"name": "Remote Services", "tactic": MITRETactic.LATERAL_MOVEMENT},
        "T1550": {"name": "Use Alternate Authentication Material", "tactic": MITRETactic.LATERAL_MOVEMENT},
        "T1005": {"name": "Data from Local System", "tactic": MITRETactic.COLLECTION},
        "T1114": {"name": "Email Collection", "tactic": MITRETactic.COLLECTION},
        "T1071": {"name": "Application Layer Protocol", "tactic": MITRETactic.COMMAND_AND_CONTROL},
        "T1090": {"name": "Proxy", "tactic": MITRETactic.COMMAND_AND_CONTROL},
        "T1041": {"name": "Exfiltration Over C2 Channel", "tactic": MITRETactic.EXFILTRATION},
        "T1048": {"name": "Exfiltration Over Alternative Protocol", "tactic": MITRETactic.EXFILTRATION},
        "T1490": {"name": "Inhibit System Recovery", "tactic": MITRETactic.IMPACT},
        "T1486": {"name": "Data Encrypted for Impact", "tactic": MITRETactic.IMPACT},
    }
    
    SEVERITY_WEIGHTS = {
        SeverityLevel.CRITICAL: 10.0,
        SeverityLevel.HIGH: 7.0,
        SeverityLevel.MEDIUM: 4.0,
        SeverityLevel.LOW: 1.0,
        SeverityLevel.INFORMATIONAL: 0.5,
    }
    
    def __init__(self):
        self.alert_cache: Dict[str, Dict[str, Any]] = {}
        self.technique_counts: Counter = Counter()
        self.tactic_counts: Counter = Counter()
        self.severity_distribution: Counter = Counter()
        self.historical_data: List[Dict[str, Any]] = []
        
    def ingest_alert(self, alert: Dict[str, Any]) -> bool:
        """
        Ingest and process a single security alert
        
        Args:
            alert: Security alert dictionary with required fields
            
        Returns:
            bool: Success status
        """
        try:
            # Validate required fields
            required_fields = ["alert_id", "technique_id", "severity", "timestamp"]
            if not all(field in alert for field in required_fields):
                return False
                
            alert_id = alert["alert_id"]
            technique_id = alert["technique_id"].upper()
            
            # Deduplication using hash
            alert_hash = hashlib.sha256(
                json.dumps(alert, sort_keys=True).encode()
            ).hexdigest()[:16]
            
            if alert_hash in self.alert_cache:
                return False  # Duplicate
                
            # Map to MITRE
            if technique_id in self.TECHNIQUE_MAPPING:
                mapping = self.TECHNIQUE_MAPPING[technique_id]
                tactic = mapping["tactic"]
                
                self.technique_counts[technique_id] += 1
                self.tactic_counts[tactic] += 1
                self.severity_distribution[alert["severity"]] += 1
                
                self.alert_cache[alert_hash] = {
                    "alert_id": alert_id,
                    "technique_id": technique_id,
                    "technique_name": mapping["name"],
                    "tactic": tactic,
                    "severity": alert["severity"],
                    "timestamp": alert["timestamp"],
                    "source": alert.get("source", "unknown"),
                }
                return True
            return False
            
        except Exception:
            return False
            
    def ingest_alerts_batch(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """
        Batch process multiple alerts
        
        Returns:
            Dict with processing statistics
        """
        success = 0
        failed = 0
        duplicates = 0
        
        for alert in alerts:
            result = self.ingest_alert(alert)
            if result:
                success += 1
            else:
                if alert.get("alert_id") in [a["alert_id"] for a in self.alert_cache.values()]:
                    duplicates += 1
                else:
                    failed += 1
                    
        return {
            "total": len(alerts),
            "success": success,
            "failed": failed,
            "duplicates": duplicates,
        }
        
    def calculate_risk_score(self, technique_id: str, count: int) -> Tuple[float, str]:
        """
        Calculate weighted risk score for a technique
        
        Returns:
            (risk_score, severity_level)
        """
        # Get alerts for this technique
        technique_alerts = [
            a for a in self.alert_cache.values() 
            if a["technique_id"] == technique_id
        ]
        
        if not technique_alerts:
            return 0.0, SeverityLevel.LOW
            
        # Calculate weighted score
        total_weight = sum(
            self.SEVERITY_WEIGHTS.get(a["severity"], 1.0) 
            for a in technique_alerts
        )
        avg_severity = total_weight / len(technique_alerts)
        frequency_factor = min(count * 0.5, 5.0)  # Cap frequency impact
        
        risk_score = round((avg_severity * 0.7) + (frequency_factor * 0.3), 2)
        
        # Determine level
        if risk_score >= 8.0:
            level = SeverityLevel.CRITICAL
        elif risk_score >= 5.0:
            level = SeverityLevel.HIGH
        elif risk_score >= 3.0:
            level = SeverityLevel.MEDIUM
        else:
            level = SeverityLevel.LOW
            
        return risk_score, level
        
    def determine_trend(self, technique_id: str) -> str:
        """Determine trend based on timing analysis"""
        technique_alerts = [
            a for a in self.alert_cache.values() 
            if a["technique_id"] == technique_id
        ]
        
        if len(technique_alerts) < 3:
            return "stable"
            
        # Simple trend: compare first half vs second half
        mid = len(technique_alerts) // 2
        first_half = technique_alerts[:mid]
        second_half = technique_alerts[mid:]
        
        if len(second_half) > len(first_half) * 1.2:
            return "increasing"
        elif len(first_half) > len(second_half) * 1.2:
            return "decreasing"
        return "stable"
        
    def generate_heatmap(self) -> Dict[str, Any]:
        """Generate complete heatmap data structure"""
        heatmap_cells = []
        tactic_summary = {}
        
        for technique_id, count in self.technique_counts.items():
            if technique_id in self.TECHNIQUE_MAPPING:
                mapping = self.TECHNIQUE_MAPPING[technique_id]
                risk_score, severity = self.calculate_risk_score(technique_id, count)
                trend = self.determine_trend(technique_id)
                
                # Get last detected
                technique_alerts = [
                    a for a in self.alert_cache.values() 
                    if a["technique_id"] == technique_id
                ]
                last_detected = max(a["timestamp"] for a in technique_alerts) if technique_alerts else ""
                
                cell = HeatmapCell(
                    tactic=mapping["tactic"],
                    technique=mapping["name"],
                    technique_id=technique_id,
                    alert_count=count,
                    risk_score=risk_score,
                    severity=severity,
                    trend=trend,
                    last_detected=last_detected,
                )
                heatmap_cells.append(asdict(cell))
                
        # Build tactic summary
        for tactic, count in self.tactic_counts.items():
            tactic_alerts = [
                a for a in self.alert_cache.values() 
                if a["tactic"] == tactic
            ]
            avg_risk = sum(
                self.SEVERITY_WEIGHTS.get(a["severity"], 1.0) 
                for a in tactic_alerts
            ) / len(tactic_alerts) if tactic_alerts else 0
            
            tactic_summary[tactic] = {
                "count": count,
                "avg_risk": round(avg_risk, 2),
                "techniques_used": len(set(a["technique_id"] for a in tactic_alerts)),
            }
            
        return {
            "metadata": {
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "total_alerts": len(self.alert_cache),
                "techniques_detected": len(self.technique_counts),
                "tactics_observed": len(self.tactic_counts),
            },
            "heatmap_cells": heatmap_cells,
            "tactic_summary": tactic_summary,
            "severity_distribution": dict(self.severity_distribution),
        }
        
    def generate_executive_summary(self) -> ExecutiveSummary:
        """Generate executive-level threat summary"""
        heatmap = self.generate_heatmap()
        
        # Find critical tactics (avg risk >= 5.0)
        critical_tactics = [
            tactic for tactic, data in heatmap["tactic_summary"].items()
            if data["avg_risk"] >= 5.0
        ]
        
        # Find highest risk technique
        highest_risk = max(
            heatmap["heatmap_cells"],
            key=lambda x: x["risk_score"],
            default={"technique": "None", "risk_score": 0}
        )
        
        # Overall risk calculation
        total_risk = sum(cell["risk_score"] for cell in heatmap["heatmap_cells"])
        overall_score = round(total_risk / max(len(heatmap["heatmap_cells"]), 1), 2)
        
        if overall_score >= 7.0:
            overall_level = "CRITICAL"
        elif overall_score >= 5.0:
            overall_level = "HIGH"
        elif overall_score >= 3.0:
            overall_level = "MEDIUM"
        else:
            overall_level = "LOW"
            
        # Top attack vectors
        top_techniques = sorted(
            heatmap["heatmap_cells"],
            key=lambda x: x["risk_score"],
            reverse=True
        )[:5]
        
        top_vectors = [
            {
                "technique": t["technique"],
                "technique_id": t["technique_id"],
                "tactic": t["tactic"],
                "risk_score": t["risk_score"],
                "alert_count": t["alert_count"],
            }
            for t in top_techniques
        ]
        
        # Generate recommendations
        recommendations = self._generate_recommendations(heatmap)
        
        # Trend analysis
        trends = [cell["trend"] for cell in heatmap["heatmap_cells"]]
        trend_analysis = {
            "increasing": trends.count("increasing"),
            "decreasing": trends.count("decreasing"),
            "stable": trends.count("stable"),
            "dominant_trend": max(set(trends), key=trends.count) if trends else "stable",
        }
        
        return ExecutiveSummary(
            report_generated=datetime.datetime.utcnow().isoformat() + "Z",
            total_alerts_analyzed=len(self.alert_cache),
            critical_tactics=critical_tactics,
            highest_risk_technique=f"{highest_risk['technique']} ({highest_risk['risk_score']})",
            overall_threat_level=overall_level,
            risk_score=overall_score,
            top_attack_vectors=top_vectors,
            recommendations=recommendations,
            trend_analysis=trend_analysis,
        )
        
    def _generate_recommendations(self, heatmap: Dict[str, Any]) -> List[str]:
        """Generate actionable security recommendations"""
        recommendations = []
        
        # Check for critical issues
        high_risk_cells = [
            c for c in heatmap["heatmap_cells"] 
            if c["severity"] in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        ]
        
        if any(c["tactic"] == MITRETactic.INITIAL_ACCESS for c in high_risk_cells):
            recommendations.append("IMMEDIATE: Review and harden perimeter security controls")
            
        if any(c["tactic"] == MITRETactic.CREDENTIAL_ACCESS for c in high_risk_cells):
            recommendations.append("URGENT: Enforce MFA and rotate compromised credentials")
            
        if any(c["tactic"] == MITRETactic.COMMAND_AND_CONTROL for c in high_risk_cells):
            recommendations.append("CRITICAL: Investigate and block C2 communication channels")
            
        if any(c["trend"] == "increasing" for c in high_risk_cells):
            recommendations.append("Escalating threats detected - increase monitoring frequency")
            
        if not recommendations:
            recommendations.append("Maintain current security posture - no critical threats detected")
            
        recommendations.extend([
            "Conduct weekly MITRE ATT&CK coverage reviews",
            "Update detection rules for observed techniques",
            "Schedule tabletop exercises for critical attack paths",
        ])
        
        return recommendations
        
    def export_dashboard_json(self, filepath: str) -> bool:
        """Export complete dashboard data to JSON file"""
        try:
            dashboard_data = {
                "heatmap": self.generate_heatmap(),
                "executive_summary": asdict(self.generate_executive_summary()),
                "export_metadata": {
                    "version": "1.0.0",
                    "export_time": datetime.datetime.utcnow().isoformat() + "Z",
                    "module": "MITREHeatmapDashboard",
                },
            }
            
            with open(filepath, "w") as f:
                json.dump(dashboard_data, f, indent=2)
            return True
        except Exception:
            return False
            
    def get_statistics(self) -> Dict[str, Any]:
        """Get processing statistics"""
        return {
            "total_alerts_processed": len(self.alert_cache),
            "unique_techniques": len(self.technique_counts),
            "tactics_observed": len(self.tactic_counts),
            "severity_breakdown": dict(self.severity_distribution),
            "top_techniques": self.technique_counts.most_common(5),
        }


# Production entry point
def create_sample_dashboard() -> Dict[str, Any]:
    """Create and populate a sample dashboard for testing"""
    dashboard = MITREHeatmapDashboard()
    
    # Sample alerts for testing/demo
    sample_alerts = [
        {"alert_id": f"ALT-{i:04d}", "technique_id": tid, 
         "severity": sev, "timestamp": f"2026-06-19T{10+i:02d}:00:00Z",
         "source": "endpoint_edr"}
        for i, (tid, sev) in enumerate([
            ("T1566", "HIGH"), ("T1566", "HIGH"), ("T1566", "MEDIUM"),
            ("T1059", "CRITICAL"), ("T1059", "HIGH"),
            ("T1027", "HIGH"), ("T1027", "MEDIUM"),
            ("T1071", "HIGH"), ("T1071", "HIGH"), ("T1071", "MEDIUM"),
            ("T1110", "CRITICAL"),
            ("T1046", "MEDIUM"), ("T1046", "LOW"),
            ("T1486", "CRITICAL"),
            ("T1041", "HIGH"),
        ])
    ]
    
    stats = dashboard.ingest_alerts_batch(sample_alerts)
    heatmap = dashboard.generate_heatmap()
    summary = dashboard.generate_executive_summary()
    
    return {
        "processing_stats": stats,
        "heatmap": heatmap,
        "executive_summary": asdict(summary),
        "dashboard_stats": dashboard.get_statistics(),
    }


if __name__ == "__main__":
    result = create_sample_dashboard()
    print(json.dumps(result, indent=2))
