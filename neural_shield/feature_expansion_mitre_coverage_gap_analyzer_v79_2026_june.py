"""
NeuralShield-AI: MITRE ATT&CK Coverage Gap Analyzer v79
Dimension A: Feature Expansion
ADD-ONLY implementation - no existing code modified
Production-grade, backward compatible, zero dependencies
"""

import json
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Set, Optional, Any, Tuple
from collections import defaultdict
from datetime import datetime


class MITRETactic(Enum):
    """MITRE ATT&CK Enterprise Tactics"""
    INITIAL_ACCESS = "initial-access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege-escalation"
    DEFENSE_EVASION = "defense-evasion"
    CREDENTIAL_ACCESS = "credential-access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral-movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command-and-control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class CoverageLevel(Enum):
    """Detection coverage levels"""
    FULL = "full"           # Direct detection with high confidence
    PARTIAL = "partial"     # Indirect detection possible
    NONE = "none"           # No detection coverage
    EXPERIMENTAL = "experimental"  # Research/ML coverage only


class RiskLevel(Enum):
    """Gap risk assessment"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique definition"""
    technique_id: str
    name: str
    tactic: MITRETactic
    description: str = ""
    coverage_level: CoverageLevel = CoverageLevel.NONE
    detectors: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    last_analyzed: str = ""
    notes: List[str] = field(default_factory=list)


@dataclass
class CoverageGap:
    """Identified coverage gap with assessment"""
    technique_id: str
    technique_name: str
    tactic: MITRETactic
    risk_level: RiskLevel
    severity_score: float
    recommendation: str
    implementation_complexity: str  # low, medium, high
    estimated_effort_hours: int
    references: List[str] = field(default_factory=list)


@dataclass
class CoverageReport:
    """Comprehensive coverage analysis report"""
    report_id: str
    generated_at: str
    total_techniques: int
    covered_techniques: int
    partial_coverage: int
    no_coverage: int
    coverage_percentage: float
    tactic_breakdown: Dict[str, Dict[str, Any]]
    critical_gaps: List[CoverageGap]
    high_priority_gaps: List[CoverageGap]
    recommendations: List[str]
    coverage_trend: Dict[str, float] = field(default_factory=dict)


class MITRECoverageGapAnalyzer:
    """
    MITRE ATT&CK Coverage Gap Analyzer v79
    Analyzes threat detection coverage against MITRE ATT&CK framework
    Identifies critical gaps and provides prioritized recommendations
    """
    
    def __init__(self):
        self._initialized = False
        self._techniques: Dict[str, MITRETechnique] = {}
        self._detector_registry: Dict[str, List[str]] = defaultdict(list)
        self._coverage_history: List[Tuple[str, float]] = []
        self._initialize_mitre_framework()
        self._initialized = True
    
    def _initialize_mitre_framework(self) -> None:
        """Initialize MITRE ATT&CK framework techniques"""
        # Core MITRE ATT&CK techniques for AI/LLM security
        mitre_techniques = [
            # Initial Access
            ("T1566", "Phishing", MITRETactic.INITIAL_ACCESS, "Spearphishing for LLM prompt injection"),
            ("T1200", "Hardware Additions", MITRETactic.INITIAL_ACCESS, "Malicious hardware for training data poisoning"),
            ("T1190", "Supply Chain Compromise", MITRETactic.INITIAL_ACCESS, "Compromised model weights or datasets"),
            
            # Execution
            ("T1059", "Command and Scripting Interpreter", MITRETactic.EXECUTION, "Prompt injection executing system commands"),
            ("T1203", "Exploitation for Client Execution", MITRETactic.EXECUTION, "Exploiting LLM context windows"),
            ("T1053", "Scheduled Task/Job", MITRETactic.EXECUTION, "Scheduled prompt injection via automation"),
            
            # Persistence
            ("T1547", "Boot or Logon Autostart Execution", MITRETactic.PERSISTENCE, "System prompt poisoning"),
            ("T1546", "Event Triggered Execution", MITRETactic.PERSISTENCE, "Trigger words in conversation history"),
            ("T1136", "Create Account", MITRETactic.PERSISTENCE, "Creating persistent agent personas"),
            
            # Privilege Escalation
            ("T1548", "Abuse Elevation Control Mechanism", MITRETactic.PRIVILEGE_ESCALATION, "Bypassing safety guardrails"),
            ("T1068", "Exploitation for Privilege Escalation", MITRETactic.PRIVILEGE_ESCALATION, "Context overflow attacks"),
            
            # Defense Evasion
            ("T1027", "Obfuscated Files or Information", MITRETactic.DEFENSE_EVASION, "Obfuscated prompt injection"),
            ("T1562", "Impair Defenses", MITRETactic.DEFENSE_EVASION, "Disabling safety mechanisms"),
            ("T1036", "Masquerading", MITRETactic.DEFENSE_EVASION, "Benign-looking malicious prompts"),
            ("T1497", "Virtualization/Sandbox Evasion", MITRETactic.DEFENSE_EVASION, "Detecting safety monitoring"),
            
            # Credential Access
            ("T1555", "Credentials from Password Stores", MITRETactic.CREDENTIAL_ACCESS, "Extracting credentials from context"),
            ("T1110", "Brute Force", MITRETactic.CREDENTIAL_ACCESS, "Brute forcing prompt injection"),
            ("T1552", "Unsecured Credentials", MITRETactic.CREDENTIAL_ACCESS, "Finding API keys in training data"),
            
            # Discovery
            ("T1082", "System Information Discovery", MITRETactic.DISCOVERY, "Probing system prompt boundaries"),
            ("T1083", "File and Directory Discovery", MITRETactic.DISCOVERY, "Discovering RAG document structure"),
            ("T1016", "System Network Configuration Discovery", MITRETactic.DISCOVERY, "Mapping tool access permissions"),
            
            # Lateral Movement
            ("T1570", "Lateral Tool Transfer", MITRETactic.LATERAL_MOVEMENT, "Moving between agent tools"),
            ("T1021", "Remote Services", MITRETactic.LATERAL_MOVEMENT, "Compromising connected APIs"),
            
            # Collection
            ("T1005", "Data from Local System", MITRETactic.COLLECTION, "Exfiltrating RAG context data"),
            ("T1114", "Email Collection", MITRETactic.COLLECTION, "Collecting email via tool access"),
            ("T1056", "Input Capture", MITRETactic.COLLECTION, "Capturing user conversation history"),
            
            # Command and Control
            ("T1071", "Application Layer Protocol", MITRETactic.COMMAND_AND_CONTROL, "C2 via natural language"),
            ("T1095", "Non-Application Layer Protocol", MITRETactic.COMMAND_AND_CONTROL, "Steganography in responses"),
            ("T1105", "Ingress Tool Transfer", MITRETactic.COMMAND_AND_CONTROL, "Downloading malicious tools"),
            
            # Exfiltration
            ("T1041", "Exfiltration Over C2 Channel", MITRETactic.EXFILTRATION, "Data exfiltration in responses"),
            ("T1048", "Exfiltration Over Alternative Protocol", MITRETactic.EXFILTRATION, "Exfiltrating via tool APIs"),
            ("T1567", "Exfiltration Over Web Service", MITRETactic.EXFILTRATION, "Data exfiltration to external services"),
            
            # Impact
            ("T1498", "Network Denial of Service", MITRETactic.IMPACT, "Prompt flooding / token exhaustion"),
            ("T1499", "Endpoint Denial of Service", MITRETactic.IMPACT, "Resource exhaustion attacks"),
            ("T1565", "Data Manipulation", MITRETactic.IMPACT, "Hallucination injection attacks"),
            ("T1485", "Data Destruction", MITRETactic.IMPACT, "Corrupting RAG vector stores"),
        ]
        
        for tech_id, name, tactic, desc in mitre_techniques:
            self._techniques[tech_id] = MITRETechnique(
                technique_id=tech_id,
                name=name,
                tactic=tactic,
                description=desc,
                last_analyzed=datetime.utcnow().isoformat()
            )
    
    def register_detector(self, detector_name: str, covers_techniques: List[str]) -> bool:
        """
        Register a threat detector with techniques it covers
        Returns: Success status
        """
        if not detector_name or not covers_techniques:
            return False
        
        for technique_id in covers_techniques:
            if technique_id in self._techniques:
                technique = self._techniques[technique_id]
                if detector_name not in technique.detectors:
                    technique.detectors.append(detector_name)
                technique.coverage_level = CoverageLevel.FULL
                technique.confidence_score = min(1.0, technique.confidence_score + 0.3)
                self._detector_registry[detector_name].append(technique_id)
        
        return True
    
    def mark_partial_coverage(self, technique_id: str, detector_name: str, confidence: float = 0.5) -> bool:
        """Mark technique as having partial coverage"""
        if technique_id not in self._techniques:
            return False
        
        technique = self._techniques[technique_id]
        technique.coverage_level = CoverageLevel.PARTIAL
        technique.confidence_score = confidence
        if detector_name not in technique.detectors:
            technique.detectors.append(detector_name)
        
        return True
    
    def identify_gaps(self) -> List[CoverageGap]:
        """Identify and prioritize coverage gaps"""
        gaps = []
        
        # Risk weighting factors
        tactic_risk_weights = {
            MITRETactic.INITIAL_ACCESS: 1.0,
            MITRETactic.EXECUTION: 0.95,
            MITRETactic.PERSISTENCE: 0.9,
            MITRETactic.PRIVILEGE_ESCALATION: 0.9,
            MITRETactic.DEFENSE_EVASION: 0.85,
            MITRETactic.CREDENTIAL_ACCESS: 0.95,
            MITRETactic.DISCOVERY: 0.7,
            MITRETactic.LATERAL_MOVEMENT: 0.85,
            MITRETactic.COLLECTION: 0.8,
            MITRETactic.COMMAND_AND_CONTROL: 0.85,
            MITRETactic.EXFILTRATION: 0.9,
            MITRETactic.IMPACT: 0.95,
        }
        
        for tech_id, technique in self._techniques.items():
            if technique.coverage_level in (CoverageLevel.NONE, CoverageLevel.PARTIAL):
                # Calculate severity score
                base_score = 1.0 if technique.coverage_level == CoverageLevel.NONE else 0.5
                tactic_weight = tactic_risk_weights.get(technique.tactic, 0.5)
                severity_score = base_score * tactic_weight
                
                # Determine risk level
                if severity_score >= 0.9:
                    risk_level = RiskLevel.CRITICAL
                elif severity_score >= 0.7:
                    risk_level = RiskLevel.HIGH
                elif severity_score >= 0.5:
                    risk_level = RiskLevel.MEDIUM
                else:
                    risk_level = RiskLevel.LOW
                
                # Generate recommendation
                recommendation = self._generate_recommendation(technique, risk_level)
                
                # Estimate complexity
                complexity, effort = self._estimate_implementation_effort(technique)
                
                gaps.append(CoverageGap(
                    technique_id=tech_id,
                    technique_name=technique.name,
                    tactic=technique.tactic,
                    risk_level=risk_level,
                    severity_score=round(severity_score, 3),
                    recommendation=recommendation,
                    implementation_complexity=complexity,
                    estimated_effort_hours=effort,
                    references=[f"https://attack.mitre.org/techniques/{tech_id}/"]
                ))
        
        # Sort by severity descending
        gaps.sort(key=lambda g: g.severity_score, reverse=True)
        return gaps
    
    def _generate_recommendation(self, technique: MITRETechnique, risk_level: RiskLevel) -> str:
        """Generate implementation recommendation"""
        base = f"Add detection for {technique.name} ({technique.technique_id})"
        
        if risk_level == RiskLevel.CRITICAL:
            return f"[CRITICAL PRIORITY] {base}. Implement dedicated detector with high-confidence rules and behavioral heuristics."
        elif risk_level == RiskLevel.HIGH:
            return f"[HIGH PRIORITY] {base}. Implement pattern-based detection with anomaly scoring."
        elif risk_level == RiskLevel.MEDIUM:
            return f"[MEDIUM PRIORITY] {base}. Add heuristic detection or extend existing detectors."
        else:
            return f"[LOW PRIORITY] {base}. Consider for future detector enhancements."
    
    def _estimate_implementation_effort(self, technique: MITRETechnique) -> Tuple[str, int]:
        """Estimate implementation complexity and effort"""
        # Simple heuristic based on tactic and technique type
        complex_tactics = {MITRETactic.DEFENSE_EVASION, MITRETactic.PERSISTENCE}
        
        if technique.tactic in complex_tactics:
            return "high", 16
        elif technique.coverage_level == CoverageLevel.PARTIAL:
            return "low", 4
        else:
            return "medium", 8
    
    def generate_coverage_report(self) -> CoverageReport:
        """Generate comprehensive coverage analysis report"""
        gaps = self.identify_gaps()
        
        # Calculate statistics
        total = len(self._techniques)
        full_covered = sum(1 for t in self._techniques.values() if t.coverage_level == CoverageLevel.FULL)
        partial = sum(1 for t in self._techniques.values() if t.coverage_level == CoverageLevel.PARTIAL)
        no_coverage = sum(1 for t in self._techniques.values() if t.coverage_level == CoverageLevel.NONE)
        
        # Tactic breakdown
        tactic_stats = defaultdict(lambda: {"total": 0, "covered": 0, "partial": 0, "none": 0})
        for technique in self._techniques.values():
            tactic_key = technique.tactic.value
            tactic_stats[tactic_key]["total"] += 1
            if technique.coverage_level == CoverageLevel.FULL:
                tactic_stats[tactic_key]["covered"] += 1
            elif technique.coverage_level == CoverageLevel.PARTIAL:
                tactic_stats[tactic_key]["partial"] += 1
            else:
                tactic_stats[tactic_key]["none"] += 1
        
        # Separate gaps by priority
        critical_gaps = [g for g in gaps if g.risk_level == RiskLevel.CRITICAL]
        high_gaps = [g for g in gaps if g.risk_level == RiskLevel.HIGH]
        
        # Generate recommendations
        recommendations = self._generate_strategic_recommendations(gaps)
        
        report_id = hashlib.md5(f"{datetime.utcnow().isoformat()}_v79".encode()).hexdigest()[:12]
        
        return CoverageReport(
            report_id=report_id,
            generated_at=datetime.utcnow().isoformat(),
            total_techniques=total,
            covered_techniques=full_covered,
            partial_coverage=partial,
            no_coverage=no_coverage,
            coverage_percentage=round((full_covered + partial * 0.5) / total * 100, 2),
            tactic_breakdown=dict(tactic_stats),
            critical_gaps=critical_gaps,
            high_priority_gaps=high_gaps,
            recommendations=recommendations
        )
    
    def _generate_strategic_recommendations(self, gaps: List[CoverageGap]) -> List[str]:
        """Generate strategic improvement recommendations"""
        recommendations = []
        
        critical_count = sum(1 for g in gaps if g.risk_level == RiskLevel.CRITICAL)
        high_count = sum(1 for g in gaps if g.risk_level == RiskLevel.HIGH)
        
        if critical_count > 0:
            recommendations.append(
                f"IMMEDIATE: Address {critical_count} CRITICAL coverage gaps within 2 weeks"
            )
        
        if high_count > 0:
            recommendations.append(
                f"SHORT-TERM: Address {high_count} HIGH priority gaps within 4 weeks"
            )
        
        # Tactic-based recommendations
        uncovered_tactics = defaultdict(int)
        for gap in gaps:
            uncovered_tactics[gap.tactic.value] += 1
        
        for tactic, count in sorted(uncovered_tactics.items(), key=lambda x: x[1], reverse=True)[:3]:
            recommendations.append(
                f"Focus area: Improve coverage for {tactic.replace('-', ' ').title()} ({count} gaps)"
            )
        
        recommendations.extend([
            "Implement detector registry for centralized coverage tracking",
            "Add automated gap reassessment after each detector update",
            "Establish monthly coverage review cadence",
            "Consider MITRE ATT&CK mapping for all new detectors"
        ])
        
        return recommendations
    
    def export_json(self, report: CoverageReport) -> str:
        """Export report as JSON string"""
        report_dict = {
            "report_id": report.report_id,
            "generated_at": report.generated_at,
            "summary": {
                "total_techniques": report.total_techniques,
                "fully_covered": report.covered_techniques,
                "partial_coverage": report.partial_coverage,
                "no_coverage": report.no_coverage,
                "coverage_percentage": report.coverage_percentage
            },
            "tactic_breakdown": report.tactic_breakdown,
            "critical_gaps": [
                {
                    "technique_id": g.technique_id,
                    "technique_name": g.technique_name,
                    "tactic": g.tactic.value,
                    "risk_level": g.risk_level.value,
                    "severity_score": g.severity_score,
                    "recommendation": g.recommendation,
                    "complexity": g.implementation_complexity,
                    "estimated_effort_hours": g.estimated_effort_hours
                }
                for g in report.critical_gaps
            ],
            "high_priority_gaps": [
                {
                    "technique_id": g.technique_id,
                    "technique_name": g.technique_name,
                    "tactic": g.tactic.value,
                    "risk_level": g.risk_level.value,
                    "severity_score": g.severity_score,
                    "recommendation": g.recommendation
                }
                for g in report.high_priority_gaps
            ],
            "recommendations": report.recommendations
        }
        return json.dumps(report_dict, indent=2)
    
    def get_coverage_summary(self) -> Dict[str, Any]:
        """Get quick coverage summary"""
        report = self.generate_coverage_report()
        return {
            "coverage_percentage": report.coverage_percentage,
            "critical_gaps": len(report.critical_gaps),
            "high_priority_gaps": len(report.high_priority_gaps),
            "total_gaps": report.no_coverage + report.partial_coverage,
            "report_id": report.report_id
        }


# Singleton instance
_coverage_analyzer: Optional[MITRECoverageGapAnalyzer] = None


def get_mitre_coverage_analyzer() -> MITRECoverageGapAnalyzer:
    """Get singleton coverage analyzer instance"""
    global _coverage_analyzer
    if _coverage_analyzer is None:
        _coverage_analyzer = MITRECoverageGapAnalyzer()
    return _coverage_analyzer


def generate_mitre_coverage_report() -> CoverageReport:
    """Convenience function to generate coverage report"""
    analyzer = get_mitre_coverage_analyzer()
    return analyzer.generate_coverage_report()


# Direct execution for testing
if __name__ == "__main__":
    print("MITRE ATT&CK Coverage Gap Analyzer v79")
    print("=" * 50)
    
    analyzer = get_mitre_coverage_analyzer()
    
    # Simulate some existing detector coverage
    analyzer.register_detector("prompt_injection_detector", ["T1059", "T1027"])
    analyzer.register_detector("jailbreak_detector", ["T1548", "T1562"])
    analyzer.mark_partial_coverage("T1566", "phishing_classifier", 0.6)
    
    report = analyzer.generate_coverage_report()
    
    print(f"\nReport ID: {report.report_id}")
    print(f"Coverage: {report.coverage_percentage}%")
    print(f"Critical gaps: {len(report.critical_gaps)}")
    print(f"High priority gaps: {len(report.high_priority_gaps)}")
    
    print("\n=== CRITICAL GAPS ===")
    for gap in report.critical_gaps[:5]:
        print(f"  [{gap.technique_id}] {gap.technique_name}: {gap.recommendation[:60]}...")
    
    print("\n=== RECOMMENDATIONS ===")
    for rec in report.recommendations[:5]:
        print(f"  - {rec}")
    
    print("\n✓ Analysis complete")
