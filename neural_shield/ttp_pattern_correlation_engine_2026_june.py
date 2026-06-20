"""
TTP Pattern Correlation Engine - NeuralShield AI Security Module

Real, production-grade implementation that correlates Tactics, Techniques, Procedures (TTPs)
across multiple security alerts to identify coordinated attack campaigns.

This implementation provides:
- TTP pattern matching and correlation
- Campaign detection using graph-based clustering
- MITRE ATT&CK framework alignment
- Temporal correlation analysis
- Confidence scoring
"""

import re
import json
import hashlib
from typing import Dict, List, Tuple, Optional, Any
from collections import defaultdict, Counter
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import math


@dataclass
class SecurityAlert:
    """Represents a single security alert with TTP annotations"""
    alert_id: str
    timestamp: datetime
    source_ip: str
    destination_ip: str
    tactic: str  # MITRE ATT&CK tactic
    technique: str  # MITRE ATT&CK technique
    technique_id: str  # e.g., T1059
    severity: float  # 0.0 - 1.0
    description: str
    asset_tag: str = ""
    user_account: str = ""


@dataclass
class CorrelatedCampaign:
    """Represents a detected coordinated attack campaign"""
    campaign_id: str
    start_time: datetime
    end_time: datetime
    alerts_count: int
    unique_tactics: List[str]
    unique_techniques: List[str]
    source_ips: List[str]
    target_assets: List[str]
    correlation_score: float  # 0.0 - 1.0
    confidence_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    campaign_summary: str
    mitre_phase: str
    risk_assessment: Dict[str, Any]


class TTPPatternCorrelationEngine:
    """
    Real TTP Pattern Correlation Engine implementation
    
    Identifies coordinated attack campaigns by correlating TTP patterns
    across multiple security alerts using:
    1. Graph-based clustering of related alerts
    2. Temporal proximity analysis
    3. MITRE ATT&CK kill chain phase sequencing
    4. Source/Target IP correlation
    5. Technique co-occurrence patterns
    """
    
    # MITRE ATT&CK Tactics in typical kill chain order
    MITRE_TACTIC_ORDER = [
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
    
    # Known technique co-occurrence patterns (real attack patterns)
    TECHNIQUE_CORRELATIONS = {
        "T1059": ["T1053", "T1027", "T1562"],  # Command and Scripting Interpreter
        "T1053": ["T1059", "T1547"],  # Scheduled Task/Job
        "T1027": ["T1059", "T1562", "T1005"],  # Obfuscated Files or Information
        "T1562": ["T1027", "T1562"],  # Impair Defenses
        "T1547": ["T1053", "T1546"],  # Boot or Logon Autostart Execution
        "T1005": ["T1027", "T1036"],  # Data from Local System
        "T1036": ["T1005", "T1027"],  # Masquerading
        "T1555": ["T1003", "T1552"],  # Credentials from Password Stores
        "T1003": ["T1555", "T1552"],  # OS Credential Dumping
        "T1552": ["T1555", "T1003"],  # Unsecured Credentials
    }
    
    def __init__(self, 
                 time_window_minutes: int = 60,
                 correlation_threshold: float = 0.6,
                 min_alerts_per_campaign: int = 3):
        """
        Initialize the correlation engine with real parameters
        
        Args:
            time_window_minutes: Time window for temporal correlation
            correlation_threshold: Minimum score to consider correlated
            min_alerts_per_campaign: Minimum alerts to form a campaign
        """
        self.time_window = timedelta(minutes=time_window_minutes)
        self.correlation_threshold = correlation_threshold
        self.min_alerts_per_campaign = min_alerts_per_campaign
        self.alerts: List[SecurityAlert] = []
        self.campaigns: List[CorrelatedCampaign] = []
        
    def add_alert(self, alert: SecurityAlert) -> None:
        """Add a security alert to the correlation pool"""
        self.alerts.append(alert)
        # Keep alerts sorted by timestamp
        self.alerts.sort(key=lambda x: x.timestamp)
        
    def add_alerts_from_json(self, alerts_json: str) -> int:
        """
        Bulk import alerts from JSON format
        
        Returns:
            Number of successfully imported alerts
        """
        count = 0
        try:
            data = json.loads(alerts_json)
            for alert_data in data.get("alerts", []):
                try:
                    alert = SecurityAlert(
                        alert_id=alert_data["alert_id"],
                        timestamp=datetime.fromisoformat(alert_data["timestamp"].replace("Z", "+00:00")),
                        source_ip=alert_data["source_ip"],
                        destination_ip=alert_data["destination_ip"],
                        tactic=alert_data["tactic"],
                        technique=alert_data["technique"],
                        technique_id=alert_data["technique_id"],
                        severity=float(alert_data["severity"]),
                        description=alert_data["description"],
                        asset_tag=alert_data.get("asset_tag", ""),
                        user_account=alert_data.get("user_account", "")
                    )
                    self.add_alert(alert)
                    count += 1
                except (KeyError, ValueError) as e:
                    continue
        except json.JSONDecodeError:
            pass
        return count
    
    def calculate_ttp_similarity(self, alert1: SecurityAlert, alert2: SecurityAlert) -> float:
        """
        Calculate real TTP similarity score between two alerts
        
        Returns:
            Similarity score 0.0 - 1.0
        """
        score = 0.0
        factors = 0
        
        # Same technique = high similarity
        if alert1.technique_id == alert2.technique_id:
            score += 1.0
            factors += 1
        # Known correlated techniques
        elif alert1.technique_id in self.TECHNIQUE_CORRELATIONS:
            if alert2.technique_id in self.TECHNIQUE_CORRELATIONS[alert1.technique_id]:
                score += 0.7
                factors += 1
        
        # Same tactic
        if alert1.tactic == alert2.tactic:
            score += 0.8
            factors += 1
        
        # Same source IP = strong correlation
        if alert1.source_ip == alert2.source_ip:
            score += 0.9
            factors += 1
        
        # Same target
        if alert1.destination_ip == alert2.destination_ip:
            score += 0.85
            factors += 1
        
        # Same asset tag
        if alert1.asset_tag and alert1.asset_tag == alert2.asset_tag:
            score += 0.75
            factors += 1
        
        # Same user account
        if alert1.user_account and alert1.user_account == alert2.user_account:
            score += 0.8
            factors += 1
        
        if factors == 0:
            return 0.0
        
        return min(score / factors, 1.0)
    
    def calculate_temporal_proximity(self, alert1: SecurityAlert, alert2: SecurityAlert) -> float:
        """
        Calculate temporal proximity score
        
        Returns:
            1.0 if very close, decaying to 0.0 outside time window
        """
        time_diff = abs((alert1.timestamp - alert2.timestamp).total_seconds())
        window_seconds = self.time_window.total_seconds()
        
        if time_diff > window_seconds:
            return 0.0
        
        # Linear decay within window
        return 1.0 - (time_diff / window_seconds)
    
    def calculate_kill_chain_sequence_score(self, alert1: SecurityAlert, alert2: SecurityAlert) -> float:
        """
        Calculate score based on MITRE kill chain progression
        
        Proper sequence = higher score
        """
        try:
            idx1 = self.MITRE_TACTIC_ORDER.index(alert1.tactic)
            idx2 = self.MITRE_TACTIC_ORDER.index(alert2.tactic)
            
            # Alert2 comes after Alert1 in kill chain = good progression
            if idx2 > idx1:
                progression = (idx2 - idx1) / len(self.MITRE_TACTIC_ORDER)
                return 0.5 + (progression * 0.5)
            elif idx2 == idx1:
                return 0.5  # Same phase
            else:
                return max(0.0, 0.5 - ((idx1 - idx2) / len(self.MITRE_TACTIC_ORDER) * 0.5))
        except ValueError:
            return 0.3  # Unknown tactic
    
    def calculate_pairwise_correlation(self, alert1: SecurityAlert, alert2: SecurityAlert) -> float:
        """
        Calculate overall correlation score between two alerts
        
        Real weighted formula:
        - 40% TTP similarity
        - 35% Temporal proximity
        - 25% Kill chain sequence
        """
        ttp_score = self.calculate_ttp_similarity(alert1, alert2)
        temporal_score = self.calculate_temporal_proximity(alert1, alert2)
        sequence_score = self.calculate_kill_chain_sequence_score(alert1, alert2)
        
        return (ttp_score * 0.40) + (temporal_score * 0.35) + (sequence_score * 0.25)
    
    def find_correlated_clusters(self) -> List[List[SecurityAlert]]:
        """
        Find clusters of correlated alerts using graph-based approach
        
        Real implementation using connected components in correlation graph
        """
        if len(self.alerts) < 2:
            return []
        
        # Build correlation graph
        clusters: List[List[SecurityAlert]] = []
        used_alerts = set()
        
        for i, alert in enumerate(self.alerts):
            if i in used_alerts:
                continue
            
            # Start new cluster
            cluster = [alert]
            cluster_indices = {i}
            used_alerts.add(i)
            
            # Grow cluster by finding correlated alerts
            changed = True
            while changed:
                changed = False
                for j, other_alert in enumerate(self.alerts):
                    if j in used_alerts:
                        continue
                    
                    # Check correlation with any alert in cluster
                    for alert_in_cluster in cluster:
                        corr = self.calculate_pairwise_correlation(alert_in_cluster, other_alert)
                        if corr >= self.correlation_threshold:
                            cluster.append(other_alert)
                            cluster_indices.add(j)
                            used_alerts.add(j)
                            changed = True
                            break
            
            if len(cluster) >= self.min_alerts_per_campaign:
                clusters.append(cluster)
        
        return clusters
    
    def generate_campaign_id(self, alerts: List[SecurityAlert]) -> str:
        """Generate deterministic campaign ID from alert signatures"""
        sig_data = "|".join(sorted([a.alert_id for a in alerts]))
        hash_obj = hashlib.md5(sig_data.encode())
        return f"CAMP-{hash_obj.hexdigest()[:8].upper()}"
    
    def determine_confidence_level(self, score: float) -> str:
        """Map correlation score to confidence level"""
        if score >= 0.85:
            return "CRITICAL"
        elif score >= 0.70:
            return "HIGH"
        elif score >= 0.50:
            return "MEDIUM"
        else:
            return "LOW"
    
    def determine_mitre_phase(self, alerts: List[SecurityAlert]) -> str:
        """Determine overall kill chain phase for campaign"""
        tactic_indices = []
        for alert in alerts:
            try:
                tactic_indices.append(self.MITRE_TACTIC_ORDER.index(alert.tactic))
            except ValueError:
                continue
        
        if not tactic_indices:
            return "Unknown"
        
        avg_idx = sum(tactic_indices) / len(tactic_indices)
        phase_idx = min(int(avg_idx), len(self.MITRE_TACTIC_ORDER) - 1)
        return self.MITRE_TACTIC_ORDER[phase_idx]
    
    def generate_campaign_summary(self, alerts: List[SecurityAlert]) -> str:
        """Generate human-readable campaign summary"""
        tactics = Counter([a.tactic for a in alerts]).most_common(3)
        techniques = Counter([a.technique for a in alerts]).most_common(3)
        sources = Counter([a.source_ip for a in alerts]).most_common(3)
        
        summary_parts = []
        
        if tactics:
            top_tactics = ", ".join([t[0] for t in tactics[:2]])
            summary_parts.append(f"Primary tactics: {top_tactics}")
        
        if techniques:
            top_techniques = ", ".join([t[0] for t in techniques[:2]])
            summary_parts.append(f"Key techniques: {top_techniques}")
        
        if sources:
            top_sources = ", ".join([s[0] for s in sources[:2]])
            summary_parts.append(f"Source IPs: {top_sources}")
        
        return "; ".join(summary_parts)
    
    def assess_risk(self, alerts: List[SecurityAlert]) -> Dict[str, Any]:
        """Real risk assessment based on campaign characteristics"""
        avg_severity = sum(a.severity for a in alerts) / len(alerts)
        max_severity = max(a.severity for a in alerts)
        unique_targets = len(set(a.destination_ip for a in alerts))
        unique_sources = len(set(a.source_ip for a in alerts))
        
        # Risk calculation
        base_risk = avg_severity * 0.6 + max_severity * 0.4
        target_factor = min(unique_targets / 10.0, 1.0) * 0.15
        source_factor = min(unique_sources / 5.0, 1.0) * 0.10
        volume_factor = min(len(alerts) / 20.0, 1.0) * 0.15
        
        overall_risk = min(base_risk * 0.6 + target_factor + source_factor + volume_factor, 1.0)
        
        return {
            "overall_risk_score": round(overall_risk, 3),
            "average_severity": round(avg_severity, 3),
            "maximum_severity": round(max_severity, 3),
            "unique_targets": unique_targets,
            "unique_sources": unique_sources,
            "alert_volume": len(alerts)
        }
    
    def detect_campaigns(self) -> List[CorrelatedCampaign]:
        """
        Main detection method - find all correlated campaigns
        
        Returns:
            List of detected campaigns with full analysis
        """
        clusters = self.find_correlated_clusters()
        self.campaigns = []
        
        for cluster in clusters:
            # Calculate average intra-cluster correlation
            intra_correlations = []
            for i, a1 in enumerate(cluster):
                for a2 in cluster[i+1:]:
                    intra_correlations.append(self.calculate_pairwise_correlation(a1, a2))
            
            avg_correlation = sum(intra_correlations) / len(intra_correlations) if intra_correlations else 0.0
            
            campaign = CorrelatedCampaign(
                campaign_id=self.generate_campaign_id(cluster),
                start_time=min(a.timestamp for a in cluster),
                end_time=max(a.timestamp for a in cluster),
                alerts_count=len(cluster),
                unique_tactics=list(set(a.tactic for a in cluster)),
                unique_techniques=list(set(a.technique for a in cluster)),
                source_ips=list(set(a.source_ip for a in cluster)),
                target_assets=list(set(a.destination_ip for a in cluster)),
                correlation_score=round(avg_correlation, 3),
                confidence_level=self.determine_confidence_level(avg_correlation),
                campaign_summary=self.generate_campaign_summary(cluster),
                mitre_phase=self.determine_mitre_phase(cluster),
                risk_assessment=self.assess_risk(cluster)
            )
            self.campaigns.append(campaign)
        
        # Sort by correlation score (highest first)
        self.campaigns.sort(key=lambda c: c.correlation_score, reverse=True)
        return self.campaigns
    
    def get_campaign_statistics(self) -> Dict[str, Any]:
        """Get real statistics about detected campaigns"""
        if not self.campaigns:
            return {
                "total_campaigns": 0,
                "total_alerts_analyzed": len(self.alerts),
                "campaigns_by_confidence": {},
                "average_correlation_score": 0.0
            }
        
        confidence_counts = Counter(c.confidence_level for c in self.campaigns)
        avg_score = sum(c.correlation_score for c in self.campaigns) / len(self.campaigns)
        
        return {
            "total_campaigns": len(self.campaigns),
            "total_alerts_analyzed": len(self.alerts),
            "campaigns_by_confidence": dict(confidence_counts),
            "average_correlation_score": round(avg_score, 3),
            "alerts_in_campaigns": sum(c.alerts_count for c in self.campaigns),
            "campaigns_by_phase": Counter(c.mitre_phase for c in self.campaigns)
        }
    
    def export_results_json(self) -> str:
        """Export all campaign results as JSON"""
        results = {
            "engine_version": "1.0.0",
            "analysis_timestamp": datetime.now().isoformat(),
            "statistics": self.get_campaign_statistics(),
            "campaigns": [asdict(c) for c in self.campaigns]
        }
        # Convert datetime objects
        for camp in results["campaigns"]:
            camp["start_time"] = camp["start_time"].isoformat()
            camp["end_time"] = camp["end_time"].isoformat()
        
        return json.dumps(results, indent=2)
