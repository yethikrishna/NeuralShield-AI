"""
NeuralShield AI - MITRE ATT&CK Mapping Engine v77
DIMENSION A - Feature Expansion
Maps detected threats and security events to MITRE ATT&CK framework tactics and techniques.

This is a NEW module - wraps existing threat detection, does NOT modify core code.
Backward compatible: all existing functionality preserved.
"""

import json
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum
from datetime import datetime


class MITRETactic(str, Enum):
    """MITRE ATT&CK Enterprise Tactics"""
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource-development"
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


@dataclass
class MITRETechnique:
    """MITRE ATT&CK Technique with metadata"""
    technique_id: str
    name: str
    tactic: MITRETactic
    description: str
    severity_score: float = 5.0
    data_sources: List[str] = field(default_factory=list)
    mitigations: List[str] = field(default_factory=list)


@dataclass
class ThreatMappingResult:
    """Result of threat to MITRE ATT&CK mapping"""
    threat_id: str
    threat_type: str
    mapped_techniques: List[MITRETechnique]
    confidence_score: float
    attack_chain: List[MITRETactic]
    mapping_timestamp: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    risk_score: float = 0.0


class MITREAttackMappingEngine:
    """
    MITRE ATT&CK Mapping Engine - Maps detected threats to MITRE framework.
    
    This is a new feature module that integrates with existing threat detection
    without modifying core detection logic.
    
    Usage:
        engine = MITREAttackMappingEngine()
        result = engine.map_threat_to_mitre("prompt_injection", threat_data)
    """
    
    def __init__(self):
        self._technique_database: Dict[str, MITRETechnique] = {}
        self._threat_to_technique_map: Dict[str, List[str]] = {}
        self._mapping_cache: Dict[str, ThreatMappingResult] = {}
        self._initialize_mitre_database()
    
    def _initialize_mitre_database(self) -> None:
        """Initialize MITRE ATT&CK technique database relevant to LLM/AI threats"""
        
        # Initial Access Techniques
        self._add_technique(MITRETechnique(
            technique_id="T1566",
            name="Phishing",
            tactic=MITRETactic.INITIAL_ACCESS,
            description="Prompt injection via deceptive inputs mimicking legitimate requests",
            severity_score=7.5,
            data_sources=["user input analysis", "prompt embedding similarity"],
            mitigations=["input validation", "prompt sanitization", "context boundary enforcement"]
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1204",
            name="User Execution",
            tactic=MITRETactic.EXECUTION,
            description="Malicious prompt execution through user interaction",
            severity_score=7.0,
            data_sources=["execution logs", "response analysis"],
            mitigations=["sandboxed execution", "output validation"]
        ))
        
        # Defense Evasion Techniques
        self._add_technique(MITRETechnique(
            technique_id="T1027",
            name="Obfuscated Files or Information",
            tactic=MITRETactic.DEFENSE_EVASION,
            description="Prompt obfuscation, encoding, or paraphrasing to evade detection",
            severity_score=8.0,
            data_sources=["semantic analysis", "obfuscation pattern detection"],
            mitigations=["semantic analysis", "deobfuscation pipelines"]
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1562",
            name="Impair Defenses",
            tactic=MITRETactic.DEFENSE_EVASION,
            description="Jailbreak attempts to disable or bypass AI safety guardrails",
            severity_score=9.0,
            data_sources=["adversarial prompt detection", "safety guardrail monitoring"],
            mitigations=["constitutional AI", "adversarial robustness training"]
        ))
        
        # Credential Access
        self._add_technique(MITRETechnique(
            technique_id="T1555",
            name="Credentials from Password Stores",
            tactic=MITRETactic.CREDENTIAL_ACCESS,
            description="Prompt injection to extract stored credentials or secrets",
            severity_score=9.5,
            data_sources=["secret detection", "output scanning"],
            mitigations=["secret redaction", "output sanitization"]
        ))
        
        # Collection
        self._add_technique(MITRETechnique(
            technique_id="T1213",
            name="Data from Information Repositories",
            tactic=MITRETactic.COLLECTION,
            description="RAG context poisoning or extraction of sensitive context data",
            severity_score=8.5,
            data_sources=["context integrity verification", "retrieval logs"],
            mitigations=["RAG integrity checks", "source verification"]
        ))
        
        # Command and Control
        self._add_technique(MITRETechnique(
            technique_id="T1071",
            name="Application Layer Protocol",
            tactic=MITRETactic.COMMAND_AND_CONTROL,
            description="Indirect prompt injection via external content or tool calls",
            severity_score=8.0,
            data_sources=["tool call validation", "external content scanning"],
            mitigations=["tool call authorization", "external input validation"]
        ))
        
        # Exfiltration
        self._add_technique(MITRETechnique(
            technique_id="T1041",
            name="Exfiltration Over C2 Channel",
            tactic=MITRETactic.EXFILTRATION,
            description="Data exfiltration via LLM response manipulation",
            severity_score=9.0,
            data_sources=["output analysis", "data leakage detection"],
            mitigations=["output filtering", "PII redaction"]
        ))
        
        # Impact
        self._add_technique(MITRETechnique(
            technique_id="T1499",
            name="Endpoint Denial of Service",
            tactic=MITRETactic.IMPACT,
            description="Resource exhaustion via malicious prompts or token flooding",
            severity_score=7.0,
            data_sources=["rate limiting", "resource monitoring"],
            mitigations=["rate limiting", "input size restrictions"]
        ))
        
        self._add_technique(MITRETechnique(
            technique_id="T1565",
            name="Data Manipulation",
            tactic=MITRETactic.IMPACT,
            description="Hallucination induction or output manipulation",
            severity_score=7.5,
            data_sources=["factuality checking", "output consistency validation"],
            mitigations=["fact verification", "output grounding"]
        ))
        
        # Discovery
        self._add_technique(MITRETechnique(
            technique_id="T1083",
            name="File and Directory Discovery",
            tactic=MITRETactic.DISCOVERY,
            description="System prompt leakage or boundary probing",
            severity_score=6.5,
            data_sources=["system prompt detection", "boundary analysis"],
            mitigations=["system prompt watermarking", "boundary enforcement"]
        ))
        
        # Execution
        self._add_technique(MITRETechnique(
            technique_id="T1059",
            name="Command and Scripting Interpreter",
            tactic=MITRETactic.EXECUTION,
            description="Multi-turn attack chains or chain-of-thought manipulation",
            severity_score=8.5,
            data_sources=["conversation analysis", "CoT monitoring"],
            mitigations=["conversation history validation", "thought process auditing"]
        ))
        
        # Persistence
        self._add_technique(MITRETechnique(
            technique_id="T1547",
            name="Boot or Logon Autostart Execution",
            tactic=MITRETactic.PERSISTENCE,
            description="Conversation history poisoning for persistent attacks",
            severity_score=8.0,
            data_sources=["history integrity checks", "conversation reset triggers"],
            mitigations=["history sanitization", "fresh context windows"]
        ))
        
        # Initialize threat type to technique mappings
        self._initialize_threat_mappings()
    
    def _add_technique(self, technique: MITRETechnique) -> None:
        """Add technique to database"""
        self._technique_database[technique.technique_id] = technique
    
    def _initialize_threat_mappings(self) -> None:
        """Map NeuralShield threat types to MITRE techniques"""
        self._threat_to_technique_map = {
            "prompt_injection": ["T1566", "T1204"],
            "jailbreak": ["T1562"],
            "system_prompt_leak": ["T1083"],
            "rag_poisoning": ["T1213"],
            "hallucination": ["T1565"],
            "data_exfiltration": ["T1041", "T1555"],
            "obfuscated_prompt": ["T1027"],
            "multi_turn_attack": ["T1059", "T1547"],
            "tool_call_attack": ["T1071"],
            "resource_exhaustion": ["T1499"],
            "output_manipulation": ["T1565"],
            "conversation_poisoning": ["T1547"],
            "indirect_injection": ["T1071", "T1566"],
        }
    
    def map_threat_to_mitre(
        self,
        threat_type: str,
        threat_data: Optional[Dict] = None,
        threat_id: Optional[str] = None
    ) -> ThreatMappingResult:
        """
        Map a detected threat to MITRE ATT&CK framework.
        
        Args:
            threat_type: Type of threat detected (e.g., "prompt_injection")
            threat_data: Additional threat metadata
            threat_id: Unique threat identifier
            
        Returns:
            ThreatMappingResult with mapped techniques and attack chain
        """
        if threat_id is None:
            threat_id = hashlib.sha256(
                f"{threat_type}:{datetime.utcnow().isoformat()}".encode()
            ).hexdigest()[:16]
        
        # Check cache first
        cache_key = f"{threat_type}:{threat_id}"
        if cache_key in self._mapping_cache:
            return self._mapping_cache[cache_key]
        
        # Get mapped techniques
        technique_ids = self._threat_to_technique_map.get(threat_type.lower(), [])
        mapped_techniques = [
            self._technique_database[tid] 
            for tid in technique_ids 
            if tid in self._technique_database
        ]
        
        # Calculate confidence based on match quality
        confidence_score = min(1.0, len(mapped_techniques) * 0.3 + 0.4)
        
        # Build attack chain from tactics
        attack_chain = list({t.tactic for t in mapped_techniques})
        attack_chain.sort(key=lambda t: list(MITRETactic).index(t))
        
        # Calculate risk score
        risk_score = sum(t.severity_score for t in mapped_techniques) / max(1, len(mapped_techniques))
        if threat_data and threat_data.get("severity"):
            risk_score = (risk_score + threat_data["severity"] * 10) / 2
        
        result = ThreatMappingResult(
            threat_id=threat_id,
            threat_type=threat_type,
            mapped_techniques=mapped_techniques,
            confidence_score=confidence_score,
            attack_chain=attack_chain,
            risk_score=round(risk_score, 2)
        )
        
        # Cache result
        self._mapping_cache[cache_key] = result
        
        return result
    
    def get_technique_by_id(self, technique_id: str) -> Optional[MITRETechnique]:
        """Get MITRE technique by ID"""
        return self._technique_database.get(technique_id)
    
    def get_techniques_by_tactic(self, tactic: MITRETactic) -> List[MITRETechnique]:
        """Get all techniques for a given tactic"""
        return [
            t for t in self._technique_database.values()
            if t.tactic == tactic
        ]
    
    def generate_mitre_report(
        self,
        mapping_results: List[ThreatMappingResult]
    ) -> Dict:
        """
        Generate comprehensive MITRE ATT&CK coverage report.
        
        Args:
            mapping_results: List of threat mapping results
            
        Returns:
            Dictionary with coverage statistics and recommendations
        """
        tactic_counts: Dict[MITRETactic, int] = {}
        technique_counts: Dict[str, int] = {}
        total_risk = 0.0
        
        for result in mapping_results:
            for technique in result.mapped_techniques:
                tactic_counts[technique.tactic] = tactic_counts.get(technique.tactic, 0) + 1
                technique_counts[technique.technique_id] = technique_counts.get(technique.technique_id, 0) + 1
            total_risk += result.risk_score
        
        covered_tactics = len(tactic_counts)
        total_tactics = len(MITRETactic)
        
        return {
            "summary": {
                "total_threats_mapped": len(mapping_results),
                "unique_techniques_observed": len(technique_counts),
                "tactics_covered": covered_tactics,
                "tactics_total": total_tactics,
                "coverage_percentage": round((covered_tactics / total_tactics) * 100, 1),
                "average_risk_score": round(total_risk / max(1, len(mapping_results)), 2)
            },
            "tactic_distribution": {
                k.value: v for k, v in sorted(tactic_counts.items(), key=lambda x: -x[1])
            },
            "technique_distribution": dict(
                sorted(technique_counts.items(), key=lambda x: -x[1])
            ),
            "top_techniques": [
                {"id": tid, "count": count, "name": self._technique_database[tid].name}
                for tid, count in sorted(technique_counts.items(), key=lambda x: -x[1])[:5]
            ],
            "recommendations": self._generate_recommendations(tactic_counts, technique_counts),
            "generated_at": datetime.utcnow().isoformat()
        }
    
    def _generate_recommendations(
        self,
        tactic_counts: Dict[MITRETactic, int],
        technique_counts: Dict[str, int]
    ) -> List[str]:
        """Generate security recommendations based on observed patterns"""
        recommendations = []
        
        high_risk_tactics = [
            MITRETactic.CREDENTIAL_ACCESS,
            MITRETactic.EXFILTRATION,
            MITRETactic.IMPACT
        ]
        
        for tactic in high_risk_tactics:
            if tactic in tactic_counts and tactic_counts[tactic] > 0:
                recommendations.append(
                    f"HIGH PRIORITY: {tactic.value.replace('-', ' ').title()} attacks detected. "
                    f"Enhance monitoring and implement additional mitigation controls."
                )
        
        if technique_counts.get("T1562", 0) > 3:
            recommendations.append(
                "Multiple jailbreak attempts detected. Consider adversarial robustness fine-tuning."
            )
        
        if technique_counts.get("T1027", 0) > 2:
            recommendations.append(
                "Obfuscated prompts detected frequently. Enhance semantic analysis capabilities."
            )
        
        if technique_counts.get("T1213", 0) > 0:
            recommendations.append(
                "RAG context attacks detected. Implement source verification and integrity checks."
            )
        
        if not recommendations:
            recommendations.append(
                "No critical attack patterns observed. Continue baseline monitoring."
            )
        
        return recommendations
    
    def export_mitre_mapping_json(
        self,
        mapping_results: List[ThreatMappingResult]
    ) -> str:
        """Export mapping results to JSON format"""
        export_data = []
        for result in mapping_results:
            export_data.append({
                "threat_id": result.threat_id,
                "threat_type": result.threat_type,
                "confidence": result.confidence_score,
                "risk_score": result.risk_score,
                "attack_chain": [t.value for t in result.attack_chain],
                "techniques": [
                    {
                        "id": t.technique_id,
                        "name": t.name,
                        "tactic": t.tactic.value,
                        "severity": t.severity_score
                    }
                    for t in result.mapped_techniques
                ],
                "timestamp": result.mapping_timestamp
            })
        
        return json.dumps(export_data, indent=2)


# Export singleton instance for easy integration
mitre_mapping_engine = MITREAttackMappingEngine()
