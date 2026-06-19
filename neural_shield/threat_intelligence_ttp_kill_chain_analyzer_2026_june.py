"""
NeuralShield AI - TTP Kill Chain Analyzer
Production-grade threat intelligence module for analyzing attack sequences
and mapping TTPs to MITRE ATT&CK Kill Chain phases.

This module provides:
- Kill chain phase detection and sequencing
- TTP correlation across attack phases
- Attack progression prediction
- Early warning for attack chain completion
"""

import re
import json
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from enum import Enum


class KillChainPhase(str, Enum):
    """MITRE ATT&CK Kill Chain Phases"""
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_AND_CONTROL = "command_and_control"
    ACTIONS_ON_OBJECTIVES = "actions_on_objectives"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    COLLECTION = "collection"
    IMPACT = "impact"


@dataclass
class TTPAttackStep:
    """Represents a single TTP observation in the kill chain"""
    ttp_id: str
    ttp_name: str
    phase: KillChainPhase
    timestamp: datetime
    source_ip: str = ""
    target_asset: str = ""
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class KillChainAnalysis:
    """Result of kill chain analysis"""
    chain_id: str
    detected_phases: List[KillChainPhase]
    missing_phases: List[KillChainPhase]
    completion_percentage: float
    attack_progression_score: float
    predicted_next_phases: List[KillChainPhase]
    critical_assets: List[str]
    risk_level: str
    recommended_actions: List[str]
    ttp_sequence: List[TTPAttackStep]
    analysis_timestamp: datetime = field(default_factory=datetime.now)


class TTPKillChainAnalyzer:
    """
    Production-grade TTP Kill Chain Analyzer
    
    Analyzes sequences of TTPs to:
    1. Identify active kill chain phases
    2. Calculate attack progression
    3. Predict next likely attack steps
    4. Generate risk assessments
    """
    
    # Standard kill chain progression order
    STANDARD_PROGRESSION = [
        KillChainPhase.RECONNAISSANCE,
        KillChainPhase.WEAPONIZATION,
        KillChainPhase.DELIVERY,
        KillChainPhase.EXPLOITATION,
        KillChainPhase.INSTALLATION,
        KillChainPhase.COMMAND_AND_CONTROL,
        KillChainPhase.DISCOVERY,
        KillChainPhase.PRIVILEGE_ESCALATION,
        KillChainPhase.CREDENTIAL_ACCESS,
        KillChainPhase.LATERAL_MOVEMENT,
        KillChainPhase.COLLECTION,
        KillChainPhase.EXFILTRATION,
        KillChainPhase.ACTIONS_ON_OBJECTIVES,
        KillChainPhase.IMPACT
    ]
    
    # Phase transition probabilities (from -> to probability)
    TRANSITION_MATRIX = {
        KillChainPhase.RECONNAISSANCE: {
            KillChainPhase.WEAPONIZATION: 0.85,
            KillChainPhase.DELIVERY: 0.10,
            KillChainPhase.EXPLOITATION: 0.05
        },
        KillChainPhase.DELIVERY: {
            KillChainPhase.EXPLOITATION: 0.90,
            KillChainPhase.INSTALLATION: 0.10
        },
        KillChainPhase.EXPLOITATION: {
            KillChainPhase.INSTALLATION: 0.80,
            KillChainPhase.COMMAND_AND_CONTROL: 0.15,
            KillChainPhase.PRIVILEGE_ESCALATION: 0.05
        },
        KillChainPhase.INSTALLATION: {
            KillChainPhase.COMMAND_AND_CONTROL: 0.95,
            KillChainPhase.PERSISTENCE: 0.05
        },
        KillChainPhase.COMMAND_AND_CONTROL: {
            KillChainPhase.DISCOVERY: 0.60,
            KillChainPhase.PRIVILEGE_ESCALATION: 0.25,
            KillChainPhase.DEFENSE_EVASION: 0.15
        },
        KillChainPhase.DISCOVERY: {
            KillChainPhase.CREDENTIAL_ACCESS: 0.50,
            KillChainPhase.LATERAL_MOVEMENT: 0.30,
            KillChainPhase.COLLECTION: 0.20
        },
        KillChainPhase.CREDENTIAL_ACCESS: {
            KillChainPhase.LATERAL_MOVEMENT: 0.70,
            KillChainPhase.PRIVILEGE_ESCALATION: 0.30
        },
        KillChainPhase.LATERAL_MOVEMENT: {
            KillChainPhase.COLLECTION: 0.50,
            KillChainPhase.PERSISTENCE: 0.30,
            KillChainPhase.EXFILTRATION: 0.20
        },
        KillChainPhase.COLLECTION: {
            KillChainPhase.EXFILTRATION: 0.85,
            KillChainPhase.ACTIONS_ON_OBJECTIVES: 0.15
        },
        KillChainPhase.EXFILTRATION: {
            KillChainPhase.ACTIONS_ON_OBJECTIVES: 0.60,
            KillChainPhase.IMPACT: 0.40
        }
    }
    
    def __init__(self, time_window_hours: int = 24):
        self.time_window = timedelta(hours=time_window_hours)
        self.ttp_database: Dict[str, TTPAttackStep] = {}
        self.attack_chains: Dict[str, List[TTPAttackStep]] = defaultdict(list)
        self.phase_patterns = self._build_phase_patterns()
        
    def _build_phase_patterns(self) -> Dict[KillChainPhase, List[str]]:
        """Build regex patterns for each kill chain phase"""
        return {
            KillChainPhase.RECONNAISSANCE: [
                r"port.?scan", r"nmap", r"recon", r"footprint",
                r"whois", r"dns.?enumeration", r"subdomain",
                r"directory.?brute", r"dirb", r"gobuster"
            ],
            KillChainPhase.DELIVERY: [
                r"phish", r"spearphish", r"malicious.?attachment",
                r"drive.?by", r"exploit.?kit", r"watering.?hole"
            ],
            KillChainPhase.EXPLOITATION: [
                r"exploit", r"cve-\d{4}-\d+", r"buffer.?overflow",
                r"sql.?injection", r"rce", r"remote.?code",
                r"vulnerability", r"payload"
            ],
            KillChainPhase.INSTALLATION: [
                r"backdoor", r"trojan", r"implant", r"dropper",
                r"persistence", r"registry", r"startup", r"service"
            ],
            KillChainPhase.COMMAND_AND_CONTROL: [
                r"c2", r"command.?control", r"beacon", r"callback",
                r"reverse.?shell", r"bind.?shell", r"meterpreter"
            ],
            KillChainPhase.LATERAL_MOVEMENT: [
                r"pass.?the.?hash", r"psexec", r"wmi", r"smb",
                r"winrm", r"rdp", r"remote.?desktop", r"lateral"
            ],
            KillChainPhase.EXFILTRATION: [
                r"exfiltr", r"data.?leak", r"data.?theft",
                r"upload", r"ftp", r"dns.?tunnel", r"steganography"
            ],
            KillChainPhase.ACTIONS_ON_OBJECTIVES: [
                r"ransom", r"encrypt", r"destroy", r"deface",
                r"data.?destruct", r"wipe", r"breach"
            ]
        }
    
    def add_ttp_observation(
        self,
        ttp_id: str,
        ttp_name: str,
        phase: str,
        timestamp: Optional[datetime] = None,
        source_ip: str = "",
        target_asset: str = "",
        confidence: float = 0.0,
        metadata: Optional[Dict] = None
    ) -> str:
        """
        Add a TTP observation to the analyzer
        
        Returns: observation_id
        """
        if timestamp is None:
            timestamp = datetime.now()
        
        try:
            phase_enum = KillChainPhase(phase.lower())
        except (ValueError, KeyError):
            # Try to detect phase from name
            phase_enum = self._detect_phase_from_name(ttp_name)
        
        step = TTPAttackStep(
            ttp_id=ttp_id,
            ttp_name=ttp_name,
            phase=phase_enum,
            timestamp=timestamp,
            source_ip=source_ip,
            target_asset=target_asset,
            confidence=confidence,
            metadata=metadata or {}
        )
        
        obs_id = hashlib.md5(f"{ttp_id}{timestamp.isoformat()}".encode()).hexdigest()[:16]
        self.ttp_database[obs_id] = step
        
        # Group by attack chain (using source IP as chain identifier)
        chain_key = source_ip or "unknown_chain"
        self.attack_chains[chain_key].append(step)
        
        return obs_id
    
    def _detect_phase_from_name(self, ttp_name: str) -> KillChainPhase:
        """Detect kill chain phase from TTP name using patterns"""
        ttp_lower = ttp_name.lower()
        
        for phase, patterns in self.phase_patterns.items():
            for pattern in patterns:
                if re.search(pattern, ttp_lower, re.IGNORECASE):
                    return phase
        
        return KillChainPhase.DISCOVERY  # Default
    
    def analyze_kill_chain(self, chain_key: str = "unknown_chain") -> KillChainAnalysis:
        """
        Analyze a specific attack chain and return comprehensive analysis
        """
        chain_steps = self.attack_chains.get(chain_key, [])
        
        # Filter by time window
        cutoff = datetime.now() - self.time_window
        recent_steps = [s for s in chain_steps if s.timestamp >= cutoff]
        recent_steps.sort(key=lambda x: x.timestamp)
        
        if not recent_steps:
            return KillChainAnalysis(
                chain_id=chain_key,
                detected_phases=[],
                missing_phases=list(KillChainPhase),
                completion_percentage=0.0,
                attack_progression_score=0.0,
                predicted_next_phases=[],
                critical_assets=[],
                risk_level="LOW",
                recommended_actions=["No active attack detected"],
                ttp_sequence=[]
            )
        
        # Extract detected phases
        detected_phases = list({s.phase for s in recent_steps})
        detected_phases.sort(key=lambda p: self.STANDARD_PROGRESSION.index(p) 
                           if p in self.STANDARD_PROGRESSION else 999)
        
        # Calculate completion
        total_phases = len(self.STANDARD_PROGRESSION)
        detected_count = len(detected_phases)
        completion = (detected_count / total_phases) * 100
        
        # Calculate progression score based on furthest phase reached
        max_phase_idx = max(
            self.STANDARD_PROGRESSION.index(p) 
            for p in detected_phases 
            if p in self.STANDARD_PROGRESSION
        )
        progression_score = (max_phase_idx / (len(self.STANDARD_PROGRESSION) - 1)) * 100
        
        # Predict next phases
        predicted = self._predict_next_phases(detected_phases)
        
        # Identify critical assets
        asset_counts = Counter(s.target_asset for s in recent_steps if s.target_asset)
        critical_assets = [asset for asset, count in asset_counts.most_common(5)]
        
        # Determine risk level
        if progression_score >= 70:
            risk_level = "CRITICAL"
        elif progression_score >= 40:
            risk_level = "HIGH"
        elif progression_score >= 20:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        # Generate recommendations
        recommendations = self._generate_recommendations(
            detected_phases, predicted, risk_level
        )
        
        return KillChainAnalysis(
            chain_id=chain_key,
            detected_phases=detected_phases,
            missing_phases=[p for p in self.STANDARD_PROGRESSION if p not in detected_phases],
            completion_percentage=round(completion, 2),
            attack_progression_score=round(progression_score, 2),
            predicted_next_phases=predicted,
            critical_assets=critical_assets,
            risk_level=risk_level,
            recommended_actions=recommendations,
            ttp_sequence=recent_steps
        )
    
    def _predict_next_phases(
        self, 
        detected_phases: List[KillChainPhase]
    ) -> List[KillChainPhase]:
        """Predict next likely phases based on transition probabilities"""
        if not detected_phases:
            return []
        
        latest_phase = detected_phases[-1]
        predictions = []
        
        if latest_phase in self.TRANSITION_MATRIX:
            transitions = self.TRANSITION_MATRIX[latest_phase]
            sorted_transitions = sorted(
                transitions.items(),
                key=lambda x: x[1],
                reverse=True
            )
            predictions = [phase for phase, prob in sorted_transitions 
                         if prob >= 0.15 and phase not in detected_phases][:3]
        
        # Fallback: use standard progression
        if not predictions:
            try:
                current_idx = self.STANDARD_PROGRESSION.index(latest_phase)
                for i in range(current_idx + 1, len(self.STANDARD_PROGRESSION)):
                    next_phase = self.STANDARD_PROGRESSION[i]
                    if next_phase not in detected_phases:
                        predictions.append(next_phase)
                        if len(predictions) >= 3:
                            break
            except ValueError:
                pass
        
        return predictions
    
    def _generate_recommendations(
        self,
        detected_phases: List[KillChainPhase],
        predicted_phases: List[KillChainPhase],
        risk_level: str
    ) -> List[str]:
        """Generate actionable recommendations based on analysis"""
        recommendations = []
        
        if KillChainPhase.RECONNAISSANCE in detected_phases:
            recommendations.append("Implement network segmentation to limit reconnaissance")
            recommendations.append("Enable rate limiting on external-facing services")
        
        if KillChainPhase.DELIVERY in detected_phases:
            recommendations.append("Enhance email filtering and attachment scanning")
            recommendations.append("Deploy endpoint protection with behavioral analysis")
        
        if KillChainPhase.EXPLOITATION in detected_phases:
            recommendations.append("Immediately patch identified vulnerabilities")
            recommendations.append("Enable intrusion detection/prevention systems")
        
        if KillChainPhase.COMMAND_AND_CONTROL in detected_phases:
            recommendations.append("Block known C2 IPs and domains")
            recommendations.append("Isolate compromised endpoints")
        
        if KillChainPhase.LATERAL_MOVEMENT in detected_phases:
            recommendations.append("Reset credentials for compromised accounts")
            recommendations.append("Enable Privileged Access Management (PAM)")
        
        if KillChainPhase.EXFILTRATION in detected_phases or KillChainPhase.EXFILTRATION in predicted_phases:
            recommendations.append("Implement Data Loss Prevention (DLP) controls")
            recommendations.append("Monitor for unusual outbound data transfers")
        
        if risk_level == "CRITICAL":
            recommendations.insert(0, "ACTIVATE INCIDENT RESPONSE TEAM IMMEDIATELY")
            recommendations.append("Initiate forensic investigation on all affected systems")
        elif risk_level == "HIGH":
            recommendations.insert(0, "Escalate to security operations team")
        
        return list(dict.fromkeys(recommendations))  # Remove duplicates
    
    def get_all_chain_summaries(self) -> List[Dict]:
        """Get summary of all detected attack chains"""
        summaries = []
        for chain_key in self.attack_chains:
            analysis = self.analyze_kill_chain(chain_key)
            summaries.append({
                "chain_id": analysis.chain_id,
                "risk_level": analysis.risk_level,
                "completion_percentage": analysis.completion_percentage,
                "progression_score": analysis.attack_progression_score,
                "detected_phases_count": len(analysis.detected_phases),
                "ttp_count": len(analysis.ttp_sequence),
                "critical_assets": analysis.critical_assets
            })
        return summaries
    
    def export_analysis_json(self, chain_key: str = "unknown_chain") -> str:
        """Export analysis as JSON string"""
        analysis = self.analyze_kill_chain(chain_key)
        
        result = {
            "chain_id": analysis.chain_id,
            "analysis_timestamp": analysis.analysis_timestamp.isoformat(),
            "detected_phases": [p.value for p in analysis.detected_phases],
            "missing_phases": [p.value for p in analysis.missing_phases],
            "completion_percentage": analysis.completion_percentage,
            "attack_progression_score": analysis.attack_progression_score,
            "predicted_next_phases": [p.value for p in analysis.predicted_next_phases],
            "critical_assets": analysis.critical_assets,
            "risk_level": analysis.risk_level,
            "recommended_actions": analysis.recommended_actions,
            "ttp_sequence": [
                {
                    "ttp_id": step.ttp_id,
                    "ttp_name": step.ttp_name,
                    "phase": step.phase.value,
                    "timestamp": step.timestamp.isoformat(),
                    "confidence": step.confidence
                }
                for step in analysis.ttp_sequence
            ]
        }
        
        return json.dumps(result, indent=2)
