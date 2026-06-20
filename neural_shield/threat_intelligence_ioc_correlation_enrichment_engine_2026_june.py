"""
Threat Intelligence IOC Correlation & Context Enrichment Engine - Production Grade
NeuralShield-AI Module
Provides enterprise-grade IOC correlation, threat actor attribution,
campaign tracking, and MITRE ATT&CK technique mapping for enriched
threat intelligence context.

Features:
- IOC to threat actor correlation
- Campaign detection and tracking
- MITRE ATT&CK technique auto-mapping
- TTP pattern recognition
- Relationship graph building
- Confidence-weighted attribution
- Batch enrichment processing
- Thread-safe operations
- Statistics and metrics tracking
"""
import hashlib
import re
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta
from enum import Enum
import threading
import json
from collections import defaultdict, Counter

class AttributionConfidence(Enum):
    """Attribution confidence levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CONFIRMED = "confirmed"

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

@dataclass
class ThreatActorProfile:
    """Threat actor profile with known TTPs and IOCs"""
    actor_id: str
    actor_name: str
    aliases: List[str] = field(default_factory=list)
    associated_groups: List[str] = field(default_factory=list)
    known_iocs: Set[str] = field(default_factory=set)
    known_ttps: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    campaign_ids: Set[str] = field(default_factory=set)
    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)
    sector_targets: List[str] = field(default_factory=list)
    geo_targets: List[str] = field(default_factory=list)
    confidence_score: float = 0.0
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "actor_id": self.actor_id,
            "actor_name": self.actor_name,
            "aliases": self.aliases,
            "associated_groups": self.associated_groups,
            "known_iocs_count": len(self.known_iocs),
            "known_ttps_count": len(self.known_ttps),
            "mitre_techniques_count": len(self.mitre_techniques),
            "campaigns": list(self.campaign_ids),
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "sector_targets": self.sector_targets,
            "geo_targets": self.geo_targets,
            "confidence_score": round(self.confidence_score, 3)
        }

@dataclass
class CampaignProfile:
    """Campaign profile with timeline and associated IOCs"""
    campaign_id: str
    campaign_name: str
    description: str = ""
    associated_actors: Set[str] = field(default_factory=set)
    associated_iocs: Set[str] = field(default_factory=set)
    mitre_techniques: Set[str] = field(default_factory=set)
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    status: str = "active"
    severity: str = "medium"
    target_sectors: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "campaign_id": self.campaign_id,
            "campaign_name": self.campaign_name,
            "description": self.description,
            "associated_actors": list(self.associated_actors),
            "iocs_count": len(self.associated_iocs),
            "mitre_techniques": list(self.mitre_techniques),
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "status": self.status,
            "severity": self.severity,
            "target_sectors": self.target_sectors
        }

@dataclass
class EnrichedIOC:
    """IOC with full enrichment context"""
    ioc_value: str
    ioc_type: str
    normalized_value: str
    threat_actors: List[Dict[str, Any]] = field(default_factory=list)
    campaigns: List[Dict[str, Any]] = field(default_factory=list)
    mitre_techniques: List[Dict[str, Any]] = field(default_factory=list)
    related_iocs: List[str] = field(default_factory=list)
    attribution_confidence: AttributionConfidence = AttributionConfidence.LOW
    enrichment_score: float = 0.0
    enrichment_timestamp: datetime = field(default_factory=datetime.now)
    raw_metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "ioc_value": self.ioc_value,
            "ioc_type": self.ioc_type,
            "normalized_value": self.normalized_value,
            "threat_actors": self.threat_actors,
            "campaigns": self.campaigns,
            "mitre_techniques": self.mitre_techniques,
            "related_iocs_count": len(self.related_iocs),
            "related_iocs_sample": self.related_iocs[:10],
            "attribution_confidence": self.attribution_confidence.value,
            "enrichment_score": round(self.enrichment_score, 3),
            "enrichment_timestamp": self.enrichment_timestamp.isoformat(),
            "metadata": self.raw_metadata
        }

@dataclass
class EnrichmentResult:
    """Result of batch enrichment"""
    total_input: int
    enriched_count: int
    partially_enriched: int
    no_enrichment: int
    threat_actors_matched: int
    campaigns_matched: int
    mitre_techniques_matched: int
    processing_time_ms: float
    enriched_iocs: List[EnrichedIOC] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            "total_input": self.total_input,
            "enriched_count": self.enriched_count,
            "partially_enriched": self.partially_enriched,
            "no_enrichment": self.no_enrichment,
            "threat_actors_matched": self.threat_actors_matched,
            "campaigns_matched": self.campaigns_matched,
            "mitre_techniques_matched": self.mitre_techniques_matched,
            "processing_time_ms": round(self.processing_time_ms, 2),
            "enrichment_rate": round((self.enriched_count / max(1, self.total_input)) * 100, 2),
            "enrichment_coverage": round(((self.enriched_count + self.partially_enriched) / max(1, self.total_input)) * 100, 2)
        }

class IOCRelationshipGraph:
    """IOC relationship graph for correlation analysis"""
    
    def __init__(self):
        self.relationships: Dict[str, Set[str]] = defaultdict(set)
        self.ioc_to_actors: Dict[str, Set[str]] = defaultdict(set)
        self.ioc_to_campaigns: Dict[str, Set[str]] = defaultdict(set)
        self.actor_to_iocs: Dict[str, Set[str]] = defaultdict(set)
        self.campaign_to_iocs: Dict[str, Set[str]] = defaultdict(set)
        self._lock = threading.RLock()
    
    def add_relationship(self, ioc1: str, ioc2: str):
        """Add relationship between two IOCs"""
        with self._lock:
            self.relationships[ioc1].add(ioc2)
            self.relationships[ioc2].add(ioc1)
    
    def add_actor_association(self, ioc: str, actor_id: str):
        """Associate IOC with threat actor"""
        with self._lock:
            self.ioc_to_actors[ioc].add(actor_id)
            self.actor_to_iocs[actor_id].add(ioc)
    
    def add_campaign_association(self, ioc: str, campaign_id: str):
        """Associate IOC with campaign"""
        with self._lock:
            self.ioc_to_campaigns[ioc].add(campaign_id)
            self.campaign_to_iocs[campaign_id].add(ioc)
    
    def get_related_iocs(self, ioc: str, depth: int = 1) -> List[str]:
        """Get related IOCs up to specified depth"""
        with self._lock:
            visited = set()
            queue = [(ioc, 0)]
            related = []
            
            while queue:
                current, current_depth = queue.pop(0)
                if current in visited or current_depth > depth:
                    continue
                visited.add(current)
                if current != ioc:
                    related.append(current)
                if current_depth < depth:
                    for neighbor in self.relationships.get(current, set()):
                        queue.append((neighbor, current_depth + 1))
            
            return related
    
    def get_common_actors(self, iocs: List[str]) -> List[Tuple[str, int]]:
        """Get threat actors common to multiple IOCs"""
        with self._lock:
            actor_counts = Counter()
            for ioc in iocs:
                for actor in self.ioc_to_actors.get(ioc, set()):
                    actor_counts[actor] += 1
            return actor_counts.most_common()
    
    def get_common_campaigns(self, iocs: List[str]) -> List[Tuple[str, int]]:
        """Get campaigns common to multiple IOCs"""
        with self._lock:
            campaign_counts = Counter()
            for ioc in iocs:
                for campaign in self.ioc_to_campaigns.get(ioc, set()):
                    campaign_counts[campaign] += 1
            return campaign_counts.most_common()

class MITRETechniqueMapper:
    """MITRE ATT&CK technique mapping based on IOC characteristics"""
    
    # IOC type to MITRE technique mapping rules
    TECHNIQUE_RULES = {
        "IPV4": [
            {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": MITRETactic.COMMAND_AND_CONTROL},
            {"technique_id": "T1090", "technique_name": "Proxy", "tactic": MITRETactic.COMMAND_AND_CONTROL},
        ],
        "DOMAIN": [
            {"technique_id": "T1568", "technique_name": "Dynamic Resolution", "tactic": MITRETactic.COMMAND_AND_CONTROL},
            {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": MITRETactic.COMMAND_AND_CONTROL},
        ],
        "URL": [
            {"technique_id": "T1071", "technique_name": "Application Layer Protocol", "tactic": MITRETactic.COMMAND_AND_CONTROL},
            {"technique_id": "T1041", "technique_name": "Exfiltration Over C2 Channel", "tactic": MITRETactic.EXFILTRATION},
        ],
        "HASH_MD5": [
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "tactic": MITRETactic.DEFENSE_EVASION},
            {"technique_id": "T1059", "technique_name": "Command and Scripting Interpreter", "tactic": MITRETactic.EXECUTION},
        ],
        "HASH_SHA256": [
            {"technique_id": "T1027", "technique_name": "Obfuscated Files or Information", "tactic": MITRETactic.DEFENSE_EVASION},
            {"technique_id": "T1204", "technique_name": "User Execution", "tactic": MITRETactic.EXECUTION},
        ],
        "EMAIL": [
            {"technique_id": "T1566", "technique_name": "Phishing", "tactic": MITRETactic.INITIAL_ACCESS},
            {"technique_id": "T1534", "technique_name": "Internal Spearphishing", "tactic": MITRETactic.INITIAL_ACCESS},
        ],
    }
    
    # Pattern-based technique detection
    PATTERN_RULES = [
        {
            "pattern": r"pastebin|github\.io|gitlab\.io",
            "technique_id": "T1567",
            "technique_name": "Exfiltration Over Web Service",
            "tactic": MITRETactic.EXFILTRATION
        },
        {
            "pattern": r"onion|tor2web|darkweb",
            "technique_id": "T1090",
            "technique_name": "Proxy",
            "tactic": MITRETactic.COMMAND_AND_CONTROL
        },
        {
            "pattern": r"powershell|ps1|invoke-",
            "technique_id": "T1059.001",
            "technique_name": "PowerShell",
            "tactic": MITRETactic.EXECUTION
        },
        {
            "pattern": r"rundll32|regsvr32|mshta",
            "technique_id": "T1218",
            "technique_name": "Signed Binary Proxy Execution",
            "tactic": MITRETactic.DEFENSE_EVASION
        },
    ]
    
    @classmethod
    def map_ioc_to_techniques(cls, ioc_value: str, ioc_type: str) -> List[Dict[str, Any]]:
        """Map IOC to relevant MITRE ATT&CK techniques"""
        techniques = []
        ioc_value_lower = ioc_value.lower()
        
        # Type-based mapping
        if ioc_type in cls.TECHNIQUE_RULES:
            for rule in cls.TECHNIQUE_RULES[ioc_type]:
                techniques.append({
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "tactic": rule["tactic"].value,
                    "confidence": 0.7,
                    "source": "ioc_type_mapping"
                })
        
        # Pattern-based mapping
        for rule in cls.PATTERN_RULES:
            if re.search(rule["pattern"], ioc_value_lower, re.IGNORECASE):
                techniques.append({
                    "technique_id": rule["technique_id"],
                    "technique_name": rule["technique_name"],
                    "tactic": rule["tactic"].value,
                    "confidence": 0.85,
                    "source": "pattern_matching"
                })
        
        return techniques

class IOCCorrelationEnrichmentEngine:
    """
    Production-grade IOC Correlation & Context Enrichment Engine
    
    Features:
    - Threat actor attribution based on IOC matching
    - Campaign detection and association
    - MITRE ATT&CK technique mapping
    - IOC relationship graph building
    - Confidence-weighted enrichment scoring
    - Batch processing optimization
    """
    
    def __init__(
        self,
        min_confidence_threshold: float = 0.3,
        auto_build_relationships: bool = True,
        enrichment_depth: int = 2
    ):
        self.min_confidence_threshold = min_confidence_threshold
        self.auto_build_relationships = auto_build_relationships
        self.enrichment_depth = enrichment_depth
        
        # Knowledge bases
        self.threat_actors: Dict[str, ThreatActorProfile] = {}
        self.campaigns: Dict[str, CampaignProfile] = {}
        self.ioc_knowledge_base: Dict[str, Dict[str, Any]] = {}
        
        # Relationship graph
        self.relationship_graph = IOCRelationshipGraph()
        
        # Thread safety
        self._lock = threading.RLock()
        self._stats = {
            "total_iocs_processed": 0,
            "total_enriched": 0,
            "actors_identified": 0,
            "campaigns_identified": 0,
            "enrichment_batches": 0
        }
        
        # Initialize with sample threat actor knowledge
        self._initialize_sample_knowledge()
    
    def _initialize_sample_knowledge(self):
        """Initialize with sample threat intelligence knowledge"""
        sample_actors = [
            ThreatActorProfile(
                actor_id="APT-28",
                actor_name="Fancy Bear",
                aliases=["Sednit", "Pawn Storm", "Sofacy Group"],
                sector_targets=["Government", "Defense", "Aerospace"],
                geo_targets=["Europe", "North America", "Ukraine"],
                confidence_score=0.95
            ),
            ThreatActorProfile(
                actor_id="APT-29",
                actor_name="Cozy Bear",
                aliases=["The Dukes", "Office Monkeys"],
                sector_targets=["Government", "Think Tanks", "Diplomatic"],
                geo_targets=["Global"],
                confidence_score=0.92
            ),
            ThreatActorProfile(
                actor_id="LAPSUS$",
                actor_name="Lapsus$",
                aliases=["DEV-0537"],
                sector_targets=["Technology", "Telecommunications"],
                geo_targets=["Global"],
                confidence_score=0.88
            ),
            ThreatActorProfile(
                actor_id="CONTI",
                actor_name="Conti",
                aliases=[" Wizard Spider"],
                sector_targets=["Healthcare", "Education", "Government"],
                geo_targets=["Global"],
                confidence_score=0.90
            ),
            ThreatActorProfile(
                actor_id="EMISSARY-PANDA",
                actor_name="Emissary Panda",
                aliases=["APT-27", "Iron Tiger"],
                sector_targets=["Government", "Technology", "Defense"],
                geo_targets=["Asia", "Europe"],
                confidence_score=0.85
            )
        ]
        
        sample_campaigns = [
            CampaignProfile(
                campaign_id="CAMP-001",
                campaign_name="SolarStorm Supply Chain",
                description="Supply chain attack targeting software vendors",
                status="completed",
                severity="critical",
                target_sectors=["Technology", "Government", "Defense"]
            ),
            CampaignProfile(
                campaign_id="CAMP-002",
                campaign_name="Log4Shell Exploitation",
                description="Mass exploitation of Log4j vulnerability",
                status="active",
                severity="high",
                target_sectors=["All sectors"]
            ),
            CampaignProfile(
                campaign_id="CAMP-003",
                campaign_name="Ransomware-as-a-Service",
                description="RaaS operations targeting critical infrastructure",
                status="active",
                severity="critical",
                target_sectors=["Healthcare", "Education", "Government"]
            )
        ]
        
        with self._lock:
            for actor in sample_actors:
                self.threat_actors[actor.actor_id] = actor
            
            for campaign in sample_campaigns:
                self.campaigns[campaign.campaign_id] = campaign
    
    def register_threat_actor(self, actor: ThreatActorProfile):
        """Register a threat actor profile"""
        with self._lock:
            self.threat_actors[actor.actor_id] = actor
            self._stats["actors_identified"] = len(self.threat_actors)
    
    def register_campaign(self, campaign: CampaignProfile):
        """Register a campaign profile"""
        with self._lock:
            self.campaigns[campaign.campaign_id] = campaign
            self._stats["campaigns_identified"] = len(self.campaigns)
    
    def register_ioc_knowledge(self, ioc_value: str, knowledge: Dict[str, Any]):
        """Register known intelligence for an IOC"""
        with self._lock:
            normalized = ioc_value.lower().strip()
            self.ioc_knowledge_base[normalized] = knowledge
    
    def _calculate_attribution_confidence(self, match_count: int, total_patterns: int) -> AttributionConfidence:
        """Calculate attribution confidence level"""
        ratio = match_count / max(1, total_patterns)
        if ratio >= 0.8:
            return AttributionConfidence.CONFIRMED
        elif ratio >= 0.5:
            return AttributionConfidence.HIGH
        elif ratio >= 0.25:
            return AttributionConfidence.MEDIUM
        return AttributionConfidence.LOW
    
    def _enrich_single_ioc(self, ioc_data: Dict[str, Any]) -> EnrichedIOC:
        """Enrich a single IOC with threat intelligence context"""
        ioc_value = ioc_data.get("value", "").strip()
        ioc_type = ioc_data.get("type", "UNKNOWN")
        normalized = ioc_value.lower().strip()
        
        enriched = EnrichedIOC(
            ioc_value=ioc_value,
            ioc_type=ioc_type,
            normalized_value=normalized
        )
        
        enrichment_signals = 0
        
        # Check knowledge base
        if normalized in self.ioc_knowledge_base:
            kb_data = self.ioc_knowledge_base[normalized]
            enriched.raw_metadata.update(kb_data)
            enrichment_signals += 1
            
            if "threat_actors" in kb_data:
                for actor_id in kb_data["threat_actors"]:
                    if actor_id in self.threat_actors:
                        enriched.threat_actors.append(self.threat_actors[actor_id].to_dict())
            
            if "campaigns" in kb_data:
                for camp_id in kb_data["campaigns"]:
                    if camp_id in self.campaigns:
                        enriched.campaigns.append(self.campaigns[camp_id].to_dict())
        
        # Pattern-based threat actor matching
        actor_matches = []
        ioc_lower = ioc_value.lower()
        for actor_id, actor in self.threat_actors.items():
            match_score = 0
            # Check for actor name/alias mentions
            all_names = [actor.actor_name.lower()] + [a.lower() for a in actor.aliases]
            for name in all_names:
                if name in ioc_lower or name.replace(" ", "") in ioc_lower:
                    match_score += 1
            
            # Check sector/geo hints
            for sector in actor.sector_targets:
                if sector.lower() in ioc_lower:
                    match_score += 0.5
            
            if match_score > 0:
                actor_matches.append((actor, match_score))
        
        # Add matched actors
        for actor, score in sorted(actor_matches, key=lambda x: x[1], reverse=True)[:3]:
            enriched.threat_actors.append({
                **actor.to_dict(),
                "match_score": round(score, 2)
            })
            enrichment_signals += 1
        
        # Campaign pattern matching
        campaign_matches = []
        for camp_id, campaign in self.campaigns.items():
            match_score = 0
            camp_lower = campaign.campaign_name.lower()
            desc_lower = campaign.description.lower()
            
            if camp_lower in ioc_lower or camp_lower.replace(" ", "") in ioc_lower:
                match_score += 2
            if any(kw in ioc_lower for kw in desc_lower.split()):
                match_score += 0.5
            
            if match_score > 0:
                campaign_matches.append((campaign, match_score))
        
        for campaign, score in sorted(campaign_matches, key=lambda x: x[1], reverse=True)[:2]:
            enriched.campaigns.append({
                **campaign.to_dict(),
                "match_score": round(score, 2)
            })
            enrichment_signals += 1
        
        # MITRE ATT&CK mapping
        enriched.mitre_techniques = MITRETechniqueMapper.map_ioc_to_techniques(ioc_value, ioc_type)
        if enriched.mitre_techniques:
            enrichment_signals += len(enriched.mitre_techniques)
        
        # Get related IOCs from graph
        if self.auto_build_relationships:
            enriched.related_iocs = self.relationship_graph.get_related_iocs(
                normalized, depth=self.enrichment_depth
            )
            if enriched.related_iocs:
                enrichment_signals += 1
        
        # Calculate final enrichment score and confidence
        max_possible_signals = 10  # Actors + Campaigns + MITRE + Relationships
        enriched.enrichment_score = min(1.0, enrichment_signals / max_possible_signals)
        enriched.attribution_confidence = self._calculate_attribution_confidence(
            enrichment_signals, max_possible_signals
        )
        
        return enriched
    
    def enrich_batch(
        self,
        iocs: List[Dict[str, Any]],
        build_relationships: bool = True
    ) -> EnrichmentResult:
        """
        Enrich a batch of IOCs with threat intelligence context
        
        Args:
            iocs: List of IOC dictionaries
            build_relationships: Whether to build IOC relationship graph
            
        Returns:
            EnrichmentResult with statistics and enriched IOCs
        """
        start_time = datetime.now()
        enriched_iocs = []
        fully_enriched = 0
        partially_enriched = 0
        no_enrichment = 0
        
        with self._lock:
            self._stats["enrichment_batches"] += 1
            
            for ioc_data in iocs:
                enriched = self._enrich_single_ioc(ioc_data)
                enriched_iocs.append(enriched)
                
                self._stats["total_iocs_processed"] += 1
                
                if enriched.enrichment_score >= 0.7:
                    fully_enriched += 1
                    self._stats["total_enriched"] += 1
                elif enriched.enrichment_score >= 0.2:
                    partially_enriched += 1
                else:
                    no_enrichment += 1
                
                # Build relationships if enabled
                if build_relationships and self.auto_build_relationships:
                    normalized = enriched.normalized_value
                    # Relate IOCs that share actors
                    for actor_data in enriched.threat_actors:
                        actor_id = actor_data.get("actor_id")
                        if actor_id:
                            self.relationship_graph.add_actor_association(normalized, actor_id)
                    # Relate IOCs that share campaigns
                    for camp_data in enriched.campaigns:
                        camp_id = camp_data.get("campaign_id")
                        if camp_id:
                            self.relationship_graph.add_campaign_association(normalized, camp_id)
            
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            
            return EnrichmentResult(
                total_input=len(iocs),
                enriched_count=fully_enriched,
                partially_enriched=partially_enriched,
                no_enrichment=no_enrichment,
                threat_actors_matched=sum(1 for e in enriched_iocs if e.threat_actors),
                campaigns_matched=sum(1 for e in enriched_iocs if e.campaigns),
                mitre_techniques_matched=sum(1 for e in enriched_iocs if e.mitre_techniques),
                processing_time_ms=processing_time,
                enriched_iocs=enriched_iocs
            )
    
    def get_correlation_insights(self, iocs: List[str]) -> Dict[str, Any]:
        """Get correlation insights for a list of IOCs"""
        normalized_iocs = [ioc.lower().strip() for ioc in iocs]
        
        with self._lock:
            common_actors = self.relationship_graph.get_common_actors(normalized_iocs)
            common_campaigns = self.relationship_graph.get_common_campaigns(normalized_iocs)
            
            # Get all related IOCs
            all_related = set()
            for ioc in normalized_iocs:
                all_related.update(self.relationship_graph.get_related_iocs(ioc, depth=2))
            
            return {
                "query_iocs_count": len(iocs),
                "unique_related_iocs": len(all_related),
                "common_threat_actors": [
                    {"actor_id": aid, "match_count": count, "actor_name": self.threat_actors.get(aid, {}).actor_name if aid in self.threat_actors else aid}
                    for aid, count in common_actors
                ],
                "common_campaigns": [
                    {"campaign_id": cid, "match_count": count, "campaign_name": self.campaigns.get(cid, {}).campaign_name if cid in self.campaigns else cid}
                    for cid, count in common_campaigns
                ],
                "related_iocs_sample": list(all_related)[:20]
            }
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self._lock:
            return {
                **self._stats,
                "knowledge_base_size": len(self.ioc_knowledge_base),
                "threat_actors_registered": len(self.threat_actors),
                "campaigns_registered": len(self.campaigns)
            }
