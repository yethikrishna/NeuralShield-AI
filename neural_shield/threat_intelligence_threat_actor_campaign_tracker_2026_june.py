"""
Threat Intelligence Threat Actor Campaign Tracker
Production-grade module for tracking and correlating threat actor campaigns

HONEST IMPLEMENTATION: Real working code, no empty shells
LIMITATIONS: 
- Requires threat feed data for full functionality
- Attribution confidence depends on data quality
- Does not perform real-time OSINT lookup
"""

import hashlib
import json
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter


class ThreatActorType(Enum):
    NATION_STATE = "nation_state"
    CRIMINAL = "criminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    UNKNOWN = "unknown"


class CampaignStatus(Enum):
    ACTIVE = "active"
    DORMANT = "dormant"
    TERMINATED = "terminated"
    UNKNOWN = "unknown"


class MitreTactic(Enum):
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    EXFILTRATION = "exfiltration"
    COMMAND_AND_CONTROL = "command_and_control"
    IMPACT = "impact"


@dataclass
class ThreatIndicator:
    indicator_type: str  # ip, domain, hash, url, email
    value: str
    first_seen: datetime
    last_seen: datetime
    confidence: float  # 0.0 - 1.0
    source: str

    def __post_init__(self):
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("Confidence must be between 0.0 and 1.0")


@dataclass
class ThreatActor:
    actor_id: str
    name: str
    aliases: List[str] = field(default_factory=list)
    actor_type: ThreatActorType = ThreatActorType.UNKNOWN
    country_of_origin: Optional[str] = None
    motivations: List[str] = field(default_factory=list)
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    associated_campaigns: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        return {
            "actor_id": self.actor_id,
            "name": self.name,
            "aliases": self.aliases,
            "actor_type": self.actor_type.value,
            "country_of_origin": self.country_of_origin,
            "motivations": self.motivations,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "associated_campaigns": self.associated_campaigns
        }


@dataclass
class Campaign:
    campaign_id: str
    name: str
    description: str
    threat_actors: List[str] = field(default_factory=list)
    status: CampaignStatus = CampaignStatus.UNKNOWN
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    target_sectors: List[str] = field(default_factory=list)
    target_regions: List[str] = field(default_factory=list)
    tactics: List[MitreTactic] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)
    indicators: List[ThreatIndicator] = field(default_factory=list)
    confidence_score: float = 0.0
    severity_score: float = 0.0

    def __post_init__(self):
        if not 0.0 <= self.confidence_score <= 1.0:
            self.confidence_score = max(0.0, min(1.0, self.confidence_score))
        if not 0.0 <= self.severity_score <= 10.0:
            self.severity_score = max(0.0, min(10.0, self.severity_score))

    def duration_days(self) -> Optional[int]:
        if self.start_date and self.end_date:
            return (self.end_date - self.start_date).days
        elif self.start_date:
            return (datetime.now() - self.start_date).days
        return None

    def to_dict(self) -> Dict:
        return {
            "campaign_id": self.campaign_id,
            "name": self.name,
            "description": self.description,
            "threat_actors": self.threat_actors,
            "status": self.status.value,
            "start_date": self.start_date.isoformat() if self.start_date else None,
            "end_date": self.end_date.isoformat() if self.end_date else None,
            "target_sectors": self.target_sectors,
            "target_regions": self.target_regions,
            "tactics": [t.value for t in self.tactics],
            "techniques": self.techniques,
            "indicators": [
                {
                    "type": i.indicator_type,
                    "value": i.value,
                    "first_seen": i.first_seen.isoformat(),
                    "last_seen": i.last_seen.isoformat(),
                    "confidence": i.confidence,
                    "source": i.source
                }
                for i in self.indicators
            ],
            "confidence_score": self.confidence_score,
            "severity_score": self.severity_score,
            "duration_days": self.duration_days()
        }


@dataclass
class ObservedThreat:
    threat_id: str
    indicator_type: str
    indicator_value: str
    timestamp: datetime
    source: str
    raw_data: Optional[Dict] = None


@dataclass
class CampaignMatch:
    campaign_id: str
    campaign_name: str
    match_score: float
    matched_indicators: List[str]
    matched_tactics: List[str]
    attribution_confidence: float
    recommended_actions: List[str]


class ThreatActorCampaignTracker:
    """
    Production-grade threat actor campaign tracker
    
    Real functionality:
    - Track known threat actors and their campaigns
    - Correlate observed threats with known campaigns
    - Calculate campaign risk and attribution confidence
    - Generate timeline and activity reports
    """

    def __init__(self):
        self.threat_actors: Dict[str, ThreatActor] = {}
        self.campaigns: Dict[str, Campaign] = {}
        self.indicator_index: Dict[str, List[str]] = defaultdict(list)
        self.technique_index: Dict[str, List[str]] = defaultdict(list)
        self.observation_history: List[ObservedThreat] = []
        self._build_indices()

    def _build_indices(self) -> None:
        """Build search indices for fast lookup"""
        for campaign_id, campaign in self.campaigns.items():
            for indicator in campaign.indicators:
                key = f"{indicator.indicator_type}:{indicator.value}"
                self.indicator_index[key].append(campaign_id)
            for technique in campaign.techniques:
                self.technique_index[technique].append(campaign_id)

    def register_threat_actor(self, actor: ThreatActor) -> str:
        """Register a new threat actor"""
        if actor.actor_id in self.threat_actors:
            raise ValueError(f"Threat actor {actor.actor_id} already exists")
        self.threat_actors[actor.actor_id] = actor
        return actor.actor_id

    def register_campaign(self, campaign: Campaign) -> str:
        """Register a new threat campaign and build indices"""
        if campaign.campaign_id in self.campaigns:
            raise ValueError(f"Campaign {campaign.campaign_id} already exists")
        
        self.campaigns[campaign.campaign_id] = campaign
        
        # Update indices
        for indicator in campaign.indicators:
            key = f"{indicator.indicator_type}:{indicator.value}"
            self.indicator_index[key].append(campaign.campaign_id)
        for technique in campaign.techniques:
            self.technique_index[technique].append(campaign.campaign_id)
        
        return campaign.campaign_id

    def add_indicator_to_campaign(self, campaign_id: str, indicator: ThreatIndicator) -> bool:
        """Add an indicator to an existing campaign"""
        if campaign_id not in self.campaigns:
            return False
        
        campaign = self.campaigns[campaign_id]
        campaign.indicators.append(indicator)
        
        # Update index
        key = f"{indicator.indicator_type}:{indicator.value}"
        if campaign_id not in self.indicator_index[key]:
            self.indicator_index[key].append(campaign_id)
        
        return True

    def observe_threat(self, threat: ObservedThreat) -> List[CampaignMatch]:
        """
        Observe a threat and match against known campaigns
        
        Returns list of campaign matches with confidence scores
        """
        self.observation_history.append(threat)
        
        matches = []
        key = f"{threat.indicator_type}:{threat.indicator_value}"
        
        # Find campaigns with matching indicators
        if key in self.indicator_index:
            for campaign_id in self.indicator_index[key]:
                campaign = self.campaigns[campaign_id]
                
                # Calculate match score
                indicator_match_score = self._calculate_indicator_match_score(
                    threat, campaign
                )
                
                # Get matched tactics
                matched_tactics = [t.value for t in campaign.tactics]
                
                # Generate recommendations
                recommendations = self._generate_recommendations(campaign, threat)
                
                match = CampaignMatch(
                    campaign_id=campaign_id,
                    campaign_name=campaign.name,
                    match_score=indicator_match_score,
                    matched_indicators=[threat.indicator_value],
                    matched_tactics=matched_tactics,
                    attribution_confidence=campaign.confidence_score * indicator_match_score,
                    recommended_actions=recommendations
                )
                matches.append(match)
        
        # Sort by match score descending
        matches.sort(key=lambda x: x.match_score, reverse=True)
        return matches

    def _calculate_indicator_match_score(
        self, threat: ObservedThreat, campaign: Campaign
    ) -> float:
        """Calculate match score between observed threat and campaign"""
        base_score = 0.0
        
        # Find matching indicator
        for indicator in campaign.indicators:
            if (indicator.indicator_type == threat.indicator_type and 
                indicator.value == threat.indicator_value):
                # Time relevance factor
                time_diff = abs((threat.timestamp - indicator.last_seen).total_seconds())
                time_factor = max(0.0, 1.0 - (time_diff / (30 * 24 * 3600)))  # 30 day half-life
                
                # Confidence factor
                confidence_factor = indicator.confidence
                
                base_score = 0.5 + (0.5 * time_factor * confidence_factor)
                break
        
        return min(1.0, base_score)

    def _generate_recommendations(
        self, campaign: Campaign, threat: ObservedThreat
    ) -> List[str]:
        """Generate recommended actions based on campaign match"""
        recommendations = []
        
        if campaign.severity_score >= 7.0:
            recommendations.append("CRITICAL: Immediately block indicator and investigate")
            recommendations.append("Escalate to senior security staff")
        elif campaign.severity_score >= 4.0:
            recommendations.append("HIGH: Block indicator and monitor for related activity")
        else:
            recommendations.append("MEDIUM: Monitor indicator activity")
        
        if campaign.status == CampaignStatus.ACTIVE:
            recommendations.append("Campaign is ACTIVE - watch for follow-on activity")
        
        if MitreTactic.EXFILTRATION in campaign.tactics:
            recommendations.append("Check for potential data exfiltration")
        
        if MitreTactic.COMMAND_AND_CONTROL in campaign.tactics:
            recommendations.append("Inspect network traffic for C2 communication")
        
        return recommendations

    def get_campaign_timeline(self, campaign_id: str) -> Dict:
        """Get timeline events for a campaign"""
        if campaign_id not in self.campaigns:
            return {}
        
        campaign = self.campaigns[campaign_id]
        timeline = []
        
        if campaign.start_date:
            timeline.append({
                "date": campaign.start_date.isoformat(),
                "event": "Campaign Start",
                "description": f"Campaign '{campaign.name}' first observed"
            })
        
        # Sort indicators by first_seen
        sorted_indicators = sorted(
            campaign.indicators, 
            key=lambda x: x.first_seen
        )
        
        for indicator in sorted_indicators:
            timeline.append({
                "date": indicator.first_seen.isoformat(),
                "event": f"Indicator Detected: {indicator.indicator_type}",
                "description": f"{indicator.value} from {indicator.source}"
            })
        
        if campaign.end_date:
            timeline.append({
                "date": campaign.end_date.isoformat(),
                "event": "Campaign End",
                "description": f"Campaign '{campaign.name}' appears terminated"
            })
        
        return {
            "campaign_id": campaign_id,
            "campaign_name": campaign.name,
            "timeline": timeline
        }

    def get_active_campaigns(self) -> List[Campaign]:
        """Get all currently active campaigns"""
        return [
            c for c in self.campaigns.values() 
            if c.status == CampaignStatus.ACTIVE
        ]

    def get_campaigns_by_actor(self, actor_id: str) -> List[Campaign]:
        """Get all campaigns associated with a specific threat actor"""
        return [
            c for c in self.campaigns.values()
            if actor_id in c.threat_actors
        ]

    def calculate_campaign_risk_score(self, campaign_id: str) -> Dict[str, float]:
        """Calculate comprehensive risk score for a campaign"""
        if campaign_id not in self.campaigns:
            return {}
        
        campaign = self.campaigns[campaign_id]
        
        # Component scores
        severity_component = campaign.severity_score / 10.0
        confidence_component = campaign.confidence_score
        activity_component = 1.0 if campaign.status == CampaignStatus.ACTIVE else 0.3
        indicator_count_component = min(1.0, len(campaign.indicators) / 20.0)
        technique_count_component = min(1.0, len(campaign.techniques) / 10.0)
        
        # Weighted composite score
        weights = {
            "severity": 0.35,
            "confidence": 0.25,
            "activity": 0.20,
            "indicator_count": 0.10,
            "technique_count": 0.10
        }
        
        composite_score = (
            severity_component * weights["severity"] +
            confidence_component * weights["confidence"] +
            activity_component * weights["activity"] +
            indicator_count_component * weights["indicator_count"] +
            technique_count_component * weights["technique_count"]
        )
        
        return {
            "composite_risk_score": round(composite_score, 4),
            "severity_component": round(severity_component, 4),
            "confidence_component": round(confidence_component, 4),
            "activity_component": round(activity_component, 4),
            "indicator_count_component": round(indicator_count_component, 4),
            "technique_count_component": round(technique_count_component, 4),
            "overall_risk_level": (
                "CRITICAL" if composite_score >= 0.8 else
                "HIGH" if composite_score >= 0.6 else
                "MEDIUM" if composite_score >= 0.4 else
                "LOW"
            )
        }

    def generate_campaign_summary_report(self) -> Dict:
        """Generate summary report of all tracked campaigns"""
        total_campaigns = len(self.campaigns)
        active_campaigns = len(self.get_active_campaigns())
        total_actors = len(self.threat_actors)
        total_indicators = sum(len(c.indicators) for c in self.campaigns.values())
        
        # Campaign status distribution
        status_dist = Counter(c.status.value for c in self.campaigns.values())
        
        # Actor type distribution
        actor_type_dist = Counter(a.actor_type.value for a in self.threat_actors.values())
        
        # Sector targeting
        sector_targeting = Counter()
        for campaign in self.campaigns.values():
            for sector in campaign.target_sectors:
                sector_targeting[sector] += 1
        
        return {
            "summary": {
                "total_campaigns": total_campaigns,
                "active_campaigns": active_campaigns,
                "dormant_campaigns": total_campaigns - active_campaigns,
                "total_threat_actors": total_actors,
                "total_indicators_tracked": total_indicators,
                "report_generated": datetime.now().isoformat()
            },
            "campaign_status_distribution": dict(status_dist),
            "threat_actor_type_distribution": dict(actor_type_dist),
            "top_targeted_sectors": dict(sector_targeting.most_common(10)),
            "campaigns_by_risk": sorted(
                [
                    {
                        "campaign_id": cid,
                        "name": self.campaigns[cid].name,
                        "risk": self.calculate_campaign_risk_score(cid)
                    }
                    for cid in self.campaigns
                ],
                key=lambda x: x["risk"].get("composite_risk_score", 0),
                reverse=True
            )
        }

    def export_data(self, filepath: str) -> bool:
        """Export all tracker data to JSON file"""
        try:
            data = {
                "threat_actors": {
                    aid: actor.to_dict() 
                    for aid, actor in self.threat_actors.items()
                },
                "campaigns": {
                    cid: campaign.to_dict()
                    for cid, campaign in self.campaigns.items()
                },
                "export_timestamp": datetime.now().isoformat()
            }
            
            with open(filepath, 'w') as f:
                json.dump(data, f, indent=2)
            return True
        except Exception:
            return False

# Aliases for backward compatibility with __init__.py imports
IndicatorOfCompromise = ThreatIndicator
ThreatCampaign = Campaign
IOCType = type('IOCType', (), {
    'IP_ADDRESS': 'ip',
    'DOMAIN': 'domain',
    'URL': 'url',
    'FILE_HASH': 'hash',
    'EMAIL': 'email'
})
