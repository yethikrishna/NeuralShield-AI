"""
Threat Intelligence Asset Risk Assessment Engine
June 19, 2026 - Production Grade Implementation

Calculates comprehensive risk scores for assets based on:
- CVE vulnerability severity and exploitability
- Threat intelligence feed matches
- Business impact weighting
- Network exposure level
- Historical incident data
- MITRE ATT&CK technique mapping

Provides prioritized risk assessment for asset inventory management
and vulnerability remediation planning.
"""

import re
import math
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict


class RiskLevel(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class AssetType(Enum):
    WEB_SERVER = "web_server"
    DATABASE = "database"
    APPLICATION_SERVER = "application_server"
    ENDPOINT = "endpoint"
    NETWORK_DEVICE = "network_device"
    CLOUD_INSTANCE = "cloud_instance"
    CONTAINER = "container"


@dataclass
class Vulnerability:
    """Represents a vulnerability on an asset."""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    exploit_available: bool = False
    exploit_maturity: str = "unproven"  # unproven, proof-of-concept, weaponized
    cvss_vector: Optional[str] = None
    published_date: Optional[str] = None
    threat_feed_match: Optional[str] = None


@dataclass
class Asset:
    """Represents an asset to be assessed."""
    asset_id: str
    asset_name: str
    asset_type: AssetType
    ip_address: str
    operating_system: str
    business_impact: int  # 1-10, 10 = highest
    network_exposure: str  # internet, internal, restricted
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    department: Optional[str] = None
    last_scan_date: Optional[str] = None
    metadata: Dict[str, any] = field(default_factory=dict)


@dataclass
class RiskAssessmentResult:
    """Result of asset risk assessment."""
    asset_id: str
    asset_name: str
    overall_risk_score: float  # 0.0 - 10.0
    risk_level: RiskLevel
    vulnerability_risk_score: float
    threat_intelligence_score: float
    business_impact_score: float
    exposure_risk_score: float
    prioritized_vulnerabilities: List[Dict[str, any]]
    remediation_priority: str
    estimated_remediation_effort_hours: float
    key_risk_factors: List[str]
    mitre_techniques_involved: List[str]
    assessment_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())


class CVSSRiskCalculator:
    """Calculates risk based on CVSS scores with contextual adjustments."""
    
    def __init__(self):
        # Exploit maturity multipliers
        self.exploit_maturity_multipliers = {
            "unproven": 0.5,
            "proof-of-concept": 0.75,
            "weaponized": 1.0
        }
        
        # Age-based decay for vulnerabilities (older = slightly lower priority unless actively exploited)
        self.age_decay_rate = 0.01  # 1% per month
        
    def calculate_adjusted_cvss(self, vulnerability: Vulnerability) -> float:
        """Calculate CVSS score adjusted for exploitability and age."""
        base_score = vulnerability.cvss_score
        
        # Apply exploit maturity multiplier
        maturity_mult = self.exploit_maturity_multipliers.get(
            vulnerability.exploit_maturity, 0.5
        )
        
        # Apply age adjustment
        age_multiplier = 1.0
        if vulnerability.published_date:
            try:
                published = datetime.fromisoformat(vulnerability.published_date.replace('Z', '+00:00'))
                age_months = (datetime.utcnow() - published).days / 30
                if not vulnerability.exploit_available and age_months > 6:
                    age_multiplier = max(0.7, 1.0 - (age_months * self.age_decay_rate))
            except:
                pass
        
        # Threat feed match boost (indicates active exploitation)
        threat_boost = 1.15 if vulnerability.threat_feed_match else 1.0
        
        adjusted_score = base_score * maturity_mult * age_multiplier * threat_boost
        return min(adjusted_score, 10.0)
    
    def calculate_vulnerability_aggregate_score(
        self, 
        vulnerabilities: List[Vulnerability]
    ) -> Tuple[float, List[Dict[str, any]]]:
        """Calculate aggregate vulnerability risk score for an asset."""
        if not vulnerabilities:
            return 0.0, []
        
        adjusted_scores = []
        prioritized = []
        
        for vuln in vulnerabilities:
            adjusted = self.calculate_adjusted_cvss(vuln)
            adjusted_scores.append(adjusted)
            prioritized.append({
                "cve_id": vuln.cve_id,
                "base_cvss": vuln.cvss_score,
                "adjusted_score": round(adjusted, 2),
                "severity": vuln.severity,
                "exploit_available": vuln.exploit_available,
                "exploit_maturity": vuln.exploit_maturity
            })
        
        # Sort by adjusted score descending
        prioritized.sort(key=lambda x: x["adjusted_score"], reverse=True)
        
        # Weighted aggregate: top 3 vulnerabilities have most impact
        sorted_scores = sorted(adjusted_scores, reverse=True)
        weights = [0.5, 0.3, 0.2]  # Top 3 get 50%, 30%, 20% weight
        weighted_sum = 0.0
        
        for i, score in enumerate(sorted_scores[:3]):
            weighted_sum += score * weights[i]
        
        # Add remaining with small weight
        if len(sorted_scores) > 3:
            remaining_avg = sum(sorted_scores[3:]) / len(sorted_scores[3:])
            weighted_sum += remaining_avg * 0.1
        
        return min(weighted_sum, 10.0), prioritized


class ThreatIntelligenceScorer:
    """Scores assets based on threat intelligence context."""
    
    def __init__(self):
        self.technique_risk_weights = {
            "T1190": 0.9,   # Exploit Public-Facing Application
            "T1210": 0.85,  # Exploitation of Remote Services
            "T1566": 0.8,   # Phishing
            "T1059": 0.75,  # Command and Scripting Interpreter
            "T1027": 0.7,   # Obfuscated Files or Information
            "T1046": 0.65,  # Network Service Scanning
            "T1082": 0.6,   # System Information Discovery
            "T1003": 0.9,   # OS Credential Dumping
            "T1055": 0.85,  # Process Injection
            "T1071": 0.7    # Application Layer Protocol
        }
        
    def calculate_threat_score(self, asset: Asset) -> Tuple[float, List[str]]:
        """Calculate threat intelligence score based on asset context."""
        threat_score = 0.0
        matched_techniques = []
        
        # Asset type to MITRE technique mapping
        asset_type_techniques = {
            AssetType.WEB_SERVER: ["T1190", "T1210", "T1071"],
            AssetType.DATABASE: ["T1210", "T1003"],
            AssetType.APPLICATION_SERVER: ["T1210", "T1059", "T1055"],
            AssetType.ENDPOINT: ["T1566", "T1059", "T1027", "T1003"],
            AssetType.NETWORK_DEVICE: ["T1046", "T1210"],
            AssetType.CLOUD_INSTANCE: ["T1190", "T1082", "T1071"],
            AssetType.CONTAINER: ["T1210", "T1055", "T1082"]
        }
        
        techniques = asset_type_techniques.get(asset.asset_type, [])
        matched_techniques.extend(techniques)
        
        # Calculate technique-based score
        for technique in techniques:
            threat_score += self.technique_risk_weights.get(technique, 0.5)
        
        if techniques:
            threat_score = (threat_score / len(techniques)) * 10
        else:
            threat_score = 5.0
        
        # Check vulnerabilities for threat feed matches
        threat_matches = sum(1 for v in asset.vulnerabilities if v.threat_feed_match)
        if threat_matches > 0:
            threat_score = min(threat_score * (1.0 + (threat_matches * 0.1)), 10.0)
        
        return round(threat_score, 2), matched_techniques


class AssetRiskAssessmentEngine:
    """Main engine for comprehensive asset risk assessment."""
    
    def __init__(self):
        self.cvss_calculator = CVSSRiskCalculator()
        self.threat_scorer = ThreatIntelligenceScorer()
        
        # Risk component weights
        self.component_weights = {
            "vulnerability": 0.40,
            "threat_intelligence": 0.25,
            "business_impact": 0.20,
            "exposure": 0.15
        }
        
        # Exposure level multipliers
        self.exposure_multipliers = {
            "internet": 1.0,
            "internal": 0.6,
            "restricted": 0.3
        }
        
        self.assessment_history: List[RiskAssessmentResult] = []
        
    def _calculate_business_impact_score(self, asset: Asset) -> float:
        """Normalize business impact to 0-10 scale."""
        return float(asset.business_impact)
    
    def _calculate_exposure_score(self, asset: Asset) -> float:
        """Calculate exposure risk score."""
        multiplier = self.exposure_multipliers.get(asset.network_exposure.lower(), 0.5)
        return multiplier * 10.0
    
    def _determine_risk_level(self, score: float) -> RiskLevel:
        """Map numerical score to risk level enum."""
        if score >= 8.5:
            return RiskLevel.CRITICAL
        elif score >= 7.0:
            return RiskLevel.HIGH
        elif score >= 5.0:
            return RiskLevel.MEDIUM
        elif score >= 2.5:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFO
    
    def _calculate_remediation_effort(self, vulnerabilities: List[Vulnerability]) -> float:
        """Estimate remediation effort in hours."""
        if not vulnerabilities:
            return 0.0
        
        effort_per_severity = {
            "critical": 8.0,
            "high": 4.0,
            "medium": 2.0,
            "low": 0.5,
            "info": 0.25
        }
        
        total_effort = 0.0
        for vuln in vulnerabilities:
            effort = effort_per_severity.get(vuln.severity.lower(), 1.0)
            # Complexity adjustment
            if vuln.exploit_available:
                effort *= 1.5
            total_effort += effort
        
        return round(total_effort, 1)
    
    def _generate_risk_factors(
        self, 
        asset: Asset, 
        vuln_score: float,
        threat_score: float
    ) -> List[str]:
        """Generate list of key risk factors."""
        factors = []
        
        if vuln_score >= 8.0:
            factors.append("Multiple critical-severity vulnerabilities present")
        elif vuln_score >= 6.0:
            factors.append("High-severity vulnerabilities detected")
        
        if asset.network_exposure.lower() == "internet":
            factors.append("Asset is directly exposed to the Internet")
        
        if asset.business_impact >= 8:
            factors.append("High business impact - critical system")
        
        if threat_score >= 7.0:
            factors.append("High threat intelligence risk for this asset type")
        
        exploit_count = sum(1 for v in asset.vulnerabilities if v.exploit_available)
        if exploit_count > 0:
            factors.append(f"{exploit_count} vulnerability(ies) with known exploits")
        
        if not factors:
            factors.append("No significant risk factors identified")
        
        return factors
    
    def assess_asset_risk(self, asset: Asset) -> RiskAssessmentResult:
        """Perform comprehensive risk assessment on a single asset."""
        # Calculate component scores
        vuln_score, prioritized_vulns = self.cvss_calculator.calculate_vulnerability_aggregate_score(
            asset.vulnerabilities
        )
        threat_score, mitre_techniques = self.threat_scorer.calculate_threat_score(asset)
        business_score = self._calculate_business_impact_score(asset)
        exposure_score = self._calculate_exposure_score(asset)
        
        # Calculate weighted overall score
        overall_score = (
            vuln_score * self.component_weights["vulnerability"] +
            threat_score * self.component_weights["threat_intelligence"] +
            business_score * self.component_weights["business_impact"] +
            exposure_score * self.component_weights["exposure"]
        )
        
        overall_score = round(overall_score, 2)
        risk_level = self._determine_risk_level(overall_score)
        
        # Determine remediation priority
        if risk_level == RiskLevel.CRITICAL:
            remediation_priority = "IMMEDIATE - within 24 hours"
        elif risk_level == RiskLevel.HIGH:
            remediation_priority = "URGENT - within 72 hours"
        elif risk_level == RiskLevel.MEDIUM:
            remediation_priority = "SCHEDULED - within 30 days"
        else:
            remediation_priority = "MAINTENANCE - next patch cycle"
        
        # Generate risk factors
        risk_factors = self._generate_risk_factors(asset, vuln_score, threat_score)
        
        # Calculate remediation effort
        remediation_effort = self._calculate_remediation_effort(asset.vulnerabilities)
        
        result = RiskAssessmentResult(
            asset_id=asset.asset_id,
            asset_name=asset.asset_name,
            overall_risk_score=overall_score,
            risk_level=risk_level,
            vulnerability_risk_score=round(vuln_score, 2),
            threat_intelligence_score=threat_score,
            business_impact_score=business_score,
            exposure_risk_score=exposure_score,
            prioritized_vulnerabilities=prioritized_vulns[:5],  # Top 5
            remediation_priority=remediation_priority,
            estimated_remediation_effort_hours=remediation_effort,
            key_risk_factors=risk_factors,
            mitre_techniques_involved=mitre_techniques
        )
        
        self.assessment_history.append(result)
        return result
    
    def batch_assess(self, assets: List[Asset]) -> List[RiskAssessmentResult]:
        """Assess risk for multiple assets and return sorted by risk."""
        results = [self.assess_asset_risk(asset) for asset in assets]
        results.sort(key=lambda x: x.overall_risk_score, reverse=True)
        return results
    
    def get_risk_summary(self) -> Dict[str, any]:
        """Get summary statistics of all assessments."""
        if not self.assessment_history:
            return {"message": "No assessments performed yet"}
        
        risk_counts = defaultdict(int)
        total_score = 0.0
        
        for result in self.assessment_history:
            risk_counts[result.risk_level.value] += 1
            total_score += result.overall_risk_score
        
        return {
            "total_assets_assessed": len(self.assessment_history),
            "average_risk_score": round(total_score / len(self.assessment_history), 2),
            "risk_distribution": dict(risk_counts),
            "component_weights_used": self.component_weights,
            "highest_risk_asset": max(
                self.assessment_history, 
                key=lambda x: x.overall_risk_score
            ).asset_name if self.assessment_history else None
        }
