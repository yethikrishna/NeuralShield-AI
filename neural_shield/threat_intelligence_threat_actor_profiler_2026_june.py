"""
NeuralShield AI - Threat Intelligence Threat Actor Profiler
Production-grade threat actor profiling and attribution system.

This module provides comprehensive threat actor profiling capabilities:
- Actor identification and categorization
- TTP (Tactics, Techniques, Procedures) matching
- MITRE ATT&CK mapping
- Sophistication and risk scoring
- Attribution confidence calculation
- Historical pattern analysis
"""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter


class ThreatActorType(Enum):
    """Types of threat actors"""
    NATION_STATE = "nation_state"
    CRIMINAL_ORGANIZATION = "criminal_organization"
    HACKTIVIST = "hacktivist"
    SCRIPT_KIDDIE = "script_kiddie"
    INSIDER_THREAT = "insider_threat"
    UNKNOWN = "unknown"


class ThreatActorSophistication(Enum):
    """Threat actor sophistication levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    ADVANCED = "advanced"
    ELITE = "elite"


class ThreatMotivation(Enum):
    """Threat actor motivations"""
    ESPIONAGE = "espionage"
    FINANCIAL = "financial"
    DESTRUCTION = "destruction"
    IDEOLOGICAL = "ideological"
    COMPETITIVE = "competitive"
    UNKNOWN = "unknown"


@dataclass
class ThreatActorProfile:
    """Threat actor profile data structure"""
    actor_id: str
    actor_name: str
    actor_type: ThreatActorType
    sophistication: ThreatActorSophistication
    motivations: List[ThreatMotivation]
    associated_groups: List[str]
    known_ttps: Set[str]
    mitre_techniques: Set[str]
    ioc_signatures: Dict[str, List[str]]
    first_seen: datetime
    last_seen: datetime
    risk_score: float
    attribution_confidence: float
    geographical_origins: List[str]
    target_sectors: List[str]
    tools_used: List[str]
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AttributionResult:
    """Result of threat actor attribution"""
    matched_actors: List[Tuple[ThreatActorProfile, float]]
    primary_actor: Optional[ThreatActorProfile]
    confidence_score: float
    matched_ttps: List[str]
    matched_techniques: List[str]
    risk_assessment: Dict[str, Any]
    attribution_reasoning: List[str]
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class ThreatActorProfiler:
    """
    Production-grade threat actor profiling and attribution engine.
    
    Features:
    - Threat actor database with known actor profiles
    - TTP-based matching and attribution
    - MITRE ATT&CK technique correlation
    - Sophistication and risk scoring
    - Confidence-based attribution
    - Pattern analysis and clustering
    """

    def __init__(self):
        self._actor_database: Dict[str, ThreatActorProfile] = {}
        self._ttp_patterns: Dict[str, Set[str]] = defaultdict(set)
        self._technique_to_actors: Dict[str, Set[str]] = defaultdict(set)
        self._ioc_to_actors: Dict[str, Set[str]] = defaultdict(set)
        self._initialize_known_actors()

    def _initialize_known_actors(self) -> None:
        """Initialize database with known threat actor profiles"""
        known_actors = [
            {
                "actor_id": "APT29",
                "actor_name": "Cozy Bear",
                "actor_type": ThreatActorType.NATION_STATE,
                "sophistication": ThreatActorSophistication.ELITE,
                "motivations": [ThreatMotivation.ESPIONAGE],
                "associated_groups": ["The Dukes", "CozyDuke"],
                "known_ttps": {"spear_phishing", "credential_stuffing", "lateral_movement", "persistence"},
                "mitre_techniques": {"T1566", "T1110", "T1021", "T1053", "T1003", "T1027"},
                "ioc_signatures": {"ip": ["192.168.1.100"], "domain": ["malicious-domain.ru"], "hash": []},
                "geographical_origins": ["Russia"],
                "target_sectors": ["Government", "Defense", "Technology", "Healthcare"],
                "tools_used": ["CozyDuke", "MiniDuke", "SeaDuke"],
                "description": "Russian state-sponsored APT group known for sophisticated espionage"
            },
            {
                "actor_id": "APT28",
                "actor_name": "Fancy Bear",
                "actor_type": ThreatActorType.NATION_STATE,
                "sophistication": ThreatActorSophistication.ELITE,
                "motivations": [ThreatMotivation.ESPIONAGE],
                "associated_groups": ["Sofacy Group", "Sednit"],
                "known_ttps": {"spear_phishing", "watering_hole", "exploit_kit", "credential_dumping"},
                "mitre_techniques": {"T1566", "T1189", "T1203", "T1003", "T1027", "T1071"},
                "ioc_signatures": {"ip": [], "domain": ["apt28-malicious.net"], "hash": []},
                "geographical_origins": ["Russia"],
                "target_sectors": ["Government", "Military", "NGO", "Political"],
                "tools_used": ["X-Agent", "Seduploader", "Zebrocy"],
                "description": "Russian military intelligence APT group active since mid-2000s"
            },
            {
                "actor_id": "LAPSUS$",
                "actor_name": "LAPSUS$",
                "actor_type": ThreatActorType.CRIMINAL_ORGANIZATION,
                "sophistication": ThreatActorSophistication.ADVANCED,
                "motivations": [ThreatMotivation.FINANCIAL, ThreatMotivation.DESTRUCTION],
                "associated_groups": [],
                "known_ttps": {"social_engineering", "initial_access", "data_exfiltration", "ransomware"},
                "mitre_techniques": {"T1589", "T1078", "T1048", "T1486", "T1490"},
                "ioc_signatures": {"ip": [], "domain": [], "hash": []},
                "geographical_origins": ["South America", "Europe"],
                "target_sectors": ["Technology", "Telecommunications", "Healthcare"],
                "tools_used": ["Mimikatz", "RDP", "VPN"],
                "description": "Extortion-focused group known for high-profile attacks"
            },
            {
                "actor_id": "CONTI",
                "actor_name": "Conti",
                "actor_type": ThreatActorType.CRIMINAL_ORGANIZATION,
                "sophistication": ThreatActorSophistication.ADVANCED,
                "motivations": [ThreatMotivation.FINANCIAL],
                "associated_groups": ["Ryuk"],
                "known_ttps": {"ransomware", "double_extortion", "lateral_movement", "data_leak"},
                "mitre_techniques": {"T1486", "T1021", "T1003", "T1048", "T1490"},
                "ioc_signatures": {"ip": [], "domain": [], "hash": []},
                "geographical_origins": ["Russia"],
                "target_sectors": ["Healthcare", "Government", "Education", "Finance"],
                "tools_used": ["Cobalt Strike", "TrickBot", "BazarLoader"],
                "description": "RaaS operation known for double extortion tactics"
            },
            {
                "actor_id": "ANONYMOUS",
                "actor_name": "Anonymous",
                "actor_type": ThreatActorType.HACKTIVIST,
                "sophistication": ThreatActorSophistication.MEDIUM,
                "motivations": [ThreatMotivation.IDEOLOGICAL],
                "associated_groups": [],
                "known_ttps": {"ddos", "defacement", "data_leak", "social_media"},
                "mitre_techniques": {"T1498", "T1491", "T1048", "T1566"},
                "ioc_signatures": {"ip": [], "domain": [], "hash": []},
                "geographical_origins": ["Global"],
                "target_sectors": ["Government", "Corporate", "Religious"],
                "tools_used": ["LOIC", "HOIC", "Social Engineering"],
                "description": "Decentralized hacktivist collective"
            }
        ]

        for actor_data in known_actors:
            profile = ThreatActorProfile(
                actor_id=actor_data["actor_id"],
                actor_name=actor_data["actor_name"],
                actor_type=actor_data["actor_type"],
                sophistication=actor_data["sophistication"],
                motivations=actor_data["motivations"],
                associated_groups=actor_data["associated_groups"],
                known_ttps=actor_data["known_ttps"],
                mitre_techniques=actor_data["mitre_techniques"],
                ioc_signatures=actor_data["ioc_signatures"],
                first_seen=datetime(2015, 1, 1, tzinfo=timezone.utc),
                last_seen=datetime.now(timezone.utc),
                risk_score=self._calculate_base_risk_score(actor_data["sophistication"]),
                attribution_confidence=0.95,
                geographical_origins=actor_data["geographical_origins"],
                target_sectors=actor_data["target_sectors"],
                tools_used=actor_data["tools_used"],
                description=actor_data["description"]
            )
            self.add_actor_profile(profile)

    def _calculate_base_risk_score(self, sophistication: ThreatActorSophistication) -> float:
        """Calculate base risk score based on sophistication level"""
        risk_map = {
            ThreatActorSophistication.LOW: 0.2,
            ThreatActorSophistication.MEDIUM: 0.4,
            ThreatActorSophistication.HIGH: 0.6,
            ThreatActorSophistication.ADVANCED: 0.8,
            ThreatActorSophistication.ELITE: 0.95
        }
        return risk_map.get(sophistication, 0.3)

    def add_actor_profile(self, profile: ThreatActorProfile) -> None:
        """Add or update a threat actor profile in the database"""
        self._actor_database[profile.actor_id] = profile
        
        # Index TTPs
        for ttp in profile.known_ttps:
            self._ttp_patterns[ttp].add(profile.actor_id)
        
        # Index MITRE techniques
        for technique in profile.mitre_techniques:
            self._technique_to_actors[technique].add(profile.actor_id)
        
        # Index IOCs
        for ioc_type, ioc_list in profile.ioc_signatures.items():
            for ioc in ioc_list:
                self._ioc_to_actors[ioc].add(profile.actor_id)

    def get_actor_profile(self, actor_id: str) -> Optional[ThreatActorProfile]:
        """Get a threat actor profile by ID"""
        return self._actor_database.get(actor_id)

    def list_all_actors(self) -> List[ThreatActorProfile]:
        """List all threat actor profiles"""
        return list(self._actor_database.values())

    def attribute_by_ttps(self, observed_ttps: List[str], 
                         observed_techniques: Optional[List[str]] = None,
                         observed_iocs: Optional[Dict[str, List[str]]] = None) -> AttributionResult:
        """
        Attribute observed activity to known threat actors based on TTPs.
        
        Args:
            observed_ttps: List of observed tactics, techniques, procedures
            observed_techniques: Optional list of observed MITRE ATT&CK technique IDs
            observed_iocs: Optional dictionary of observed IOCs by type
            
        Returns:
            AttributionResult with matched actors and confidence scores
        """
        if observed_techniques is None:
            observed_techniques = []
        if observed_iocs is None:
            observed_iocs = {}

        actor_scores: Dict[str, float] = defaultdict(float)
        matched_ttp_list: List[str] = []
        matched_technique_list: List[str] = []
        reasoning: List[str] = []

        # Score by TTP matching
        for ttp in observed_ttps:
            matching_actors = self._ttp_patterns.get(ttp, set())
            if matching_actors:
                matched_ttp_list.append(ttp)
                for actor_id in matching_actors:
                    actor_scores[actor_id] += 0.15
                reasoning.append(f"TTP '{ttp}' matched {len(matching_actors)} actor(s)")

        # Score by MITRE technique matching
        for technique in observed_techniques:
            matching_actors = self._technique_to_actors.get(technique, set())
            if matching_actors:
                matched_technique_list.append(technique)
                for actor_id in matching_actors:
                    actor_scores[actor_id] += 0.20
                reasoning.append(f"MITRE technique '{technique}' matched {len(matching_actors)} actor(s)")

        # Score by IOC matching
        for ioc_type, ioc_values in observed_iocs.items():
            for ioc in ioc_values:
                matching_actors = self._ioc_to_actors.get(ioc, set())
                if matching_actors:
                    for actor_id in matching_actors:
                        actor_scores[actor_id] += 0.30
                    reasoning.append(f"IOC '{ioc}' matched {len(matching_actors)} actor(s)")

        # Normalize scores and calculate final confidence
        max_score = max(actor_scores.values()) if actor_scores else 0
        normalized_scores: Dict[str, float] = {}
        for actor_id, score in actor_scores.items():
            normalized_scores[actor_id] = min(score / max(1.0, max_score), 1.0)

        # Sort actors by score
        sorted_actors = sorted(
            [(self._actor_database[aid], score) for aid, score in normalized_scores.items()],
            key=lambda x: x[1],
            reverse=True
        )

        primary_actor = sorted_actors[0][0] if sorted_actors else None
        overall_confidence = sorted_actors[0][1] if sorted_actors else 0.0

        # Calculate risk assessment
        risk_assessment = self._calculate_risk_assessment(sorted_actors)

        if not sorted_actors:
            reasoning.append("No matching threat actors found in database")
        else:
            reasoning.append(f"Primary attribution: {primary_actor.actor_name} with {overall_confidence:.2%} confidence")

        return AttributionResult(
            matched_actors=sorted_actors,
            primary_actor=primary_actor,
            confidence_score=overall_confidence,
            matched_ttps=matched_ttp_list,
            matched_techniques=matched_technique_list,
            risk_assessment=risk_assessment,
            attribution_reasoning=reasoning
        )

    def _calculate_risk_assessment(self, matched_actors: List[Tuple[ThreatActorProfile, float]]) -> Dict[str, Any]:
        """Calculate comprehensive risk assessment based on matched actors"""
        if not matched_actors:
            return {
                "overall_risk": 0.0,
                "risk_level": "LOW",
                "sophistication_level": "UNKNOWN",
                "primary_motivation": "UNKNOWN",
                "recommended_actions": ["monitor", "log", "analyze"]
            }

        weighted_risk = 0.0
        total_weight = 0.0
        motivation_counter: Counter = Counter()
        sophistication_counter: Counter = Counter()

        for actor, confidence in matched_actors:
            weighted_risk += actor.risk_score * confidence
            total_weight += confidence
            for motivation in actor.motivations:
                motivation_counter[motivation.value] += confidence
            sophistication_counter[actor.sophistication.value] += confidence

        avg_risk = weighted_risk / total_weight if total_weight > 0 else 0.0
        
        if avg_risk >= 0.8:
            risk_level = "CRITICAL"
        elif avg_risk >= 0.6:
            risk_level = "HIGH"
        elif avg_risk >= 0.4:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"

        primary_motivation = motivation_counter.most_common(1)[0][0] if motivation_counter else "unknown"
        primary_sophistication = sophistication_counter.most_common(1)[0][0] if sophistication_counter else "unknown"

        recommendations = self._generate_recommendations(risk_level, primary_motivation)

        return {
            "overall_risk": round(avg_risk, 3),
            "risk_level": risk_level,
            "sophistication_level": primary_sophistication,
            "primary_motivation": primary_motivation,
            "matched_actor_count": len(matched_actors),
            "recommended_actions": recommendations
        }

    def _generate_recommendations(self, risk_level: str, motivation: str) -> List[str]:
        """Generate security recommendations based on risk and motivation"""
        recommendations = ["enhance_logging", "review_access_controls"]
        
        if risk_level in ["HIGH", "CRITICAL"]:
            recommendations.extend([
                "isolate_affected_systems",
                "initiate_incident_response",
                "conduct_forensic_analysis",
                "notify_stakeholders"
            ])
        
        if motivation == "financial":
            recommendations.extend(["audit_financial_systems", "review_payment_systems"])
        elif motivation == "espionage":
            recommendations.extend(["review_sensitive_data", "enhance_counterintelligence"])
        elif motivation == "destruction":
            recommendations.extend(["verify_backups", "enhance_data_protection"])

        return list(set(recommendations))

    def search_actors(self, query: str) -> List[ThreatActorProfile]:
        """Search threat actors by name, ID, or description"""
        query_lower = query.lower()
        results = []
        
        for actor in self._actor_database.values():
            if (query_lower in actor.actor_id.lower() or
                query_lower in actor.actor_name.lower() or
                query_lower in actor.description.lower()):
                results.append(actor)
        
        return results

    def get_actors_by_sector(self, sector: str) -> List[ThreatActorProfile]:
        """Get threat actors known to target specific sectors"""
        sector_lower = sector.lower()
        return [
            actor for actor in self._actor_database.values()
            if any(sector_lower in s.lower() for s in actor.target_sectors)
        ]

    def get_actors_by_type(self, actor_type: ThreatActorType) -> List[ThreatActorProfile]:
        """Get threat actors by type"""
        return [
            actor for actor in self._actor_database.values()
            if actor.actor_type == actor_type
        ]

    def export_profiles_json(self) -> str:
        """Export all actor profiles as JSON"""
        profiles_data = []
        for actor in self._actor_database.values():
            profiles_data.append({
                "actor_id": actor.actor_id,
                "actor_name": actor.actor_name,
                "actor_type": actor.actor_type.value,
                "sophistication": actor.sophistication.value,
                "motivations": [m.value for m in actor.motivations],
                "risk_score": actor.risk_score,
                "target_sectors": actor.target_sectors,
                "description": actor.description
            })
        return json.dumps(profiles_data, indent=2)

    def generate_profile_hash(self, actor_id: str) -> str:
        """Generate a unique hash for actor profile verification"""
        actor = self.get_actor_profile(actor_id)
        if not actor:
            return ""
        
        profile_data = json.dumps({
            "actor_id": actor.actor_id,
            "known_ttps": sorted(actor.known_ttps),
            "mitre_techniques": sorted(actor.mitre_techniques),
            "risk_score": actor.risk_score
        }, sort_keys=True)
        
        return hashlib.sha256(profile_data.encode()).hexdigest()[:16]


# Export main class
__all__ = [
    "ThreatActorProfiler",
    "ThreatActorProfile",
    "AttributionResult",
    "ThreatActorType",
    "ThreatActorSophistication",
    "ThreatMotivation"
]
