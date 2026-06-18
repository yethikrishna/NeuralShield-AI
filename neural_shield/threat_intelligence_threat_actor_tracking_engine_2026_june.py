"""
NeuralShield AI - Threat Intelligence Threat Actor Tracking Engine
Production-grade threat actor activity tracking and monitoring system.
This module provides comprehensive threat actor tracking capabilities:
- Activity timeline construction and analysis
- Temporal pattern detection and anomaly detection
- Campaign correlation and association
- Actor activity velocity and intensity scoring
- Geographical and infrastructure tracking
- Tool/technique evolution monitoring
- Predictive activity forecasting
"""
import hashlib
import json
import math
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict, Counter, deque


class ActivityType(Enum):
    """Types of threat actor activities"""
    PHISHING = "phishing"
    MALWARE_DEPLOYMENT = "malware_deployment"
    RANSOMWARE_ATTACK = "ransomware_attack"
    DATA_BREACH = "data_breach"
    DDOS_ATTACK = "ddos_attack"
    SUPPLY_CHAIN = "supply_chain"
    RECONNAISSANCE = "reconnaissance"
    INITIAL_ACCESS = "initial_access"
    LATERAL_MOVEMENT = "lateral_movement"
    DATA_EXFILTRATION = "data_exfiltration"
    COMMAND_CONTROL = "command_control"
    TOOL_DEVELOPMENT = "tool_development"
    INFRASTRUCTURE_SETUP = "infrastructure_setup"
    UNKNOWN = "unknown"


class ActivitySeverity(Enum):
    """Severity levels for activities"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TrackedActivity:
    """Data structure for a tracked threat actor activity"""
    activity_id: str
    actor_id: str
    activity_type: ActivityType
    severity: ActivitySeverity
    timestamp: datetime
    description: str
    source: str
    confidence: float
    indicators: List[str] = field(default_factory=list)
    targets: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary format"""
        return {
            "activity_id": self.activity_id,
            "actor_id": self.actor_id,
            "activity_type": self.activity_type.value,
            "severity": self.severity.value,
            "timestamp": self.timestamp.isoformat(),
            "description": self.description,
            "source": self.source,
            "confidence": self.confidence,
            "indicators": self.indicators,
            "targets": self.targets,
            "mitre_techniques": self.mitre_techniques,
            "metadata": self.metadata
        }


@dataclass
class ActorProfile:
    """Threat actor profile with tracking data"""
    actor_id: str
    actor_name: str
    first_seen: datetime
    last_seen: datetime
    activity_count: int = 0
    total_severity_score: float = 0.0
    activity_types: Counter = field(default_factory=Counter)
    targets: Set[str] = field(default_factory=set)
    techniques: Set[str] = field(default_factory=set)
    infrastructure: Set[str] = field(default_factory=set)
    activity_timeline: List[TrackedActivity] = field(default_factory=list)
    
    def calculate_activity_velocity(self, window_days: int = 30) -> float:
        """Calculate activity velocity (activities per day) over the specified window"""
        if not self.activity_timeline:
            return 0.0
        
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        window_activities = [a for a in self.activity_timeline if a.timestamp >= cutoff]
        
        if not window_activities:
            return 0.0
        
        return len(window_activities) / window_days
    
    def calculate_severity_trend(self, window_days: int = 30) -> Dict[str, float]:
        """Calculate severity trend analysis"""
        severity_weights = {
            ActivitySeverity.LOW: 1,
            ActivitySeverity.MEDIUM: 3,
            ActivitySeverity.HIGH: 7,
            ActivitySeverity.CRITICAL: 15
        }
        
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        window_activities = [a for a in self.activity_timeline if a.timestamp >= cutoff]
        
        if not window_activities:
            return {"current_score": 0, "trend": 0, "peak_severity": 0}
        
        weighted_scores = [severity_weights[a.severity] * a.confidence for a in window_activities]
        current_score = sum(weighted_scores) / len(window_activities)
        
        # Calculate trend by comparing first and second halves
        mid = len(window_activities) // 2
        if mid > 0:
            first_half_avg = sum(weighted_scores[:mid]) / mid
            second_half_avg = sum(weighted_scores[mid:]) / (len(window_activities) - mid)
            trend = second_half_avg - first_half_avg
        else:
            trend = 0
        
        peak_severity = max(weighted_scores) if weighted_scores else 0
        
        return {
            "current_score": round(current_score, 3),
            "trend": round(trend, 3),
            "peak_severity": round(peak_severity, 3),
            "activities_analyzed": len(window_activities)
        }


class ThreatActorTrackingEngine:
    """
    Production-grade threat actor tracking engine.
    Tracks threat actor activities over time, detects patterns,
    and provides predictive analytics.
    """
    
    def __init__(self, max_timeline_size: int = 10000):
        self.max_timeline_size = max_timeline_size
        self.actors: Dict[str, ActorProfile] = {}
        self.activity_index: Dict[str, TrackedActivity] = {}
        self.campaign_clusters: Dict[str, Set[str]] = defaultdict(set)
        self.correlation_cache: Dict[str, List[Tuple[str, float]]] = {}
        
    def _generate_activity_id(self, activity_data: Dict[str, Any]) -> str:
        """Generate deterministic activity ID"""
        content = json.dumps(activity_data, sort_keys=True)
        return f"act_{hashlib.sha256(content.encode()).hexdigest()[:16]}"
    
    def _generate_actor_id(self, actor_name: str) -> str:
        """Generate deterministic actor ID"""
        return f"actor_{hashlib.sha256(actor_name.lower().encode()).hexdigest()[:12]}"
    
    def track_activity(
        self,
        actor_name: str,
        activity_type: str,
        severity: str,
        timestamp: str,
        description: str,
        source: str,
        confidence: float = 0.8,
        indicators: Optional[List[str]] = None,
        targets: Optional[List[str]] = None,
        mitre_techniques: Optional[List[str]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Tuple[str, bool]:
        """
        Track a new threat actor activity.
        Returns (activity_id, is_new_activity)
        """
        # Parse and validate inputs
        try:
            activity_type_enum = ActivityType(activity_type.lower())
        except (ValueError, KeyError):
            activity_type_enum = ActivityType.UNKNOWN
        
        try:
            severity_enum = ActivitySeverity(severity.lower())
        except (ValueError, KeyError):
            severity_enum = ActivitySeverity.MEDIUM
        
        try:
            activity_ts = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
            if activity_ts.tzinfo is None:
                activity_ts = activity_ts.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            activity_ts = datetime.now(timezone.utc)
        
        confidence = max(0.0, min(1.0, confidence))
        
        # Generate IDs
        actor_id = self._generate_actor_id(actor_name)
        activity_data = {
            "actor_id": actor_id,
            "activity_type": activity_type_enum.value,
            "timestamp": activity_ts.isoformat(),
            "description": description,
            "source": source
        }
        activity_id = self._generate_activity_id(activity_data)
        
        # Check for duplicate
        if activity_id in self.activity_index:
            return activity_id, False
        
        # Create tracked activity
        activity = TrackedActivity(
            activity_id=activity_id,
            actor_id=actor_id,
            activity_type=activity_type_enum,
            severity=severity_enum,
            timestamp=activity_ts,
            description=description,
            source=source,
            confidence=confidence,
            indicators=indicators or [],
            targets=targets or [],
            mitre_techniques=mitre_techniques or [],
            metadata=metadata or {}
        )
        
        # Store activity
        self.activity_index[activity_id] = activity
        
        # Update or create actor profile
        if actor_id not in self.actors:
            self.actors[actor_id] = ActorProfile(
                actor_id=actor_id,
                actor_name=actor_name,
                first_seen=activity_ts,
                last_seen=activity_ts
            )
        
        profile = self.actors[actor_id]
        profile.last_seen = max(profile.last_seen, activity_ts)
        profile.first_seen = min(profile.first_seen, activity_ts)
        profile.activity_count += 1
        profile.activity_types[activity_type_enum.value] += 1
        profile.targets.update(targets or [])
        profile.techniques.update(mitre_techniques or [])
        profile.infrastructure.update(indicators or [])
        profile.activity_timeline.append(activity)
        
        # Maintain timeline size
        if len(profile.activity_timeline) > self.max_timeline_size:
            profile.activity_timeline = profile.activity_timeline[-self.max_timeline_size:]
        
        return activity_id, True
    
    def get_actor_profile(self, actor_name: str) -> Optional[Dict[str, Any]]:
        """Get comprehensive profile for a threat actor"""
        actor_id = self._generate_actor_id(actor_name)
        
        if actor_id not in self.actors:
            return None
        
        profile = self.actors[actor_id]
        
        return {
            "actor_id": profile.actor_id,
            "actor_name": profile.actor_name,
            "first_seen": profile.first_seen.isoformat(),
            "last_seen": profile.last_seen.isoformat(),
            "days_active": (profile.last_seen - profile.first_seen).days,
            "total_activities": profile.activity_count,
            "activity_velocity_30d": round(profile.calculate_activity_velocity(30), 3),
            "activity_velocity_7d": round(profile.calculate_activity_velocity(7), 3),
            "severity_analysis": profile.calculate_severity_trend(30),
            "activity_distribution": dict(profile.activity_types),
            "unique_targets": len(profile.targets),
            "unique_techniques": len(profile.techniques),
            "infrastructure_count": len(profile.infrastructure),
            "dominant_activity_type": profile.activity_types.most_common(1)[0][0] if profile.activity_types else None,
            "recent_activities": [a.to_dict() for a in profile.activity_timeline[-10:]]
        }
    
    def detect_activity_anomalies(self, actor_name: str, window_days: int = 90) -> Dict[str, Any]:
        """
        Detect anomalous activity patterns for a threat actor.
        Identifies spikes in activity, unusual targets, or new techniques.
        """
        actor_id = self._generate_actor_id(actor_name)
        
        if actor_id not in self.actors:
            return {"anomalies_detected": False, "message": "Actor not found"}
        
        profile = self.actors[actor_id]
        anomalies = []
        
        if len(profile.activity_timeline) < 5:
            return {"anomalies_detected": False, "message": "Insufficient data for anomaly detection"}
        
        # Check for activity spikes
        velocity_7d = profile.calculate_activity_velocity(7)
        velocity_30d = profile.calculate_activity_velocity(30)
        
        if velocity_30d > 0 and velocity_7d > velocity_30d * 2.5:
            anomalies.append({
                "type": "ACTIVITY_SPIKE",
                "severity": "HIGH",
                "description": f"Activity spike detected: 7-day velocity {velocity_7d:.2f} is {velocity_7d/velocity_30d:.1f}x above 30-day baseline",
                "baseline_30d": round(velocity_30d, 3),
                "current_7d": round(velocity_7d, 3)
            })
        
        # Check for new techniques
        cutoff_new = datetime.now(timezone.utc) - timedelta(days=14)
        cutoff_historical = datetime.now(timezone.utc) - timedelta(days=90)
        
        recent_techniques = set()
        historical_techniques = set()
        
        for activity in profile.activity_timeline:
            if activity.timestamp >= cutoff_new:
                recent_techniques.update(activity.mitre_techniques)
            elif activity.timestamp >= cutoff_historical:
                historical_techniques.update(activity.mitre_techniques)
        
        new_techniques = recent_techniques - historical_techniques
        if new_techniques:
            anomalies.append({
                "type": "NEW_TECHNIQUES",
                "severity": "MEDIUM",
                "description": f"New techniques detected: {len(new_techniques)} previously unseen techniques in last 14 days",
                "new_techniques": list(new_techniques)
            })
        
        # Check for new targets
        recent_targets = set()
        historical_targets = set()
        
        for activity in profile.activity_timeline:
            if activity.timestamp >= cutoff_new:
                recent_targets.update(activity.targets)
            elif activity.timestamp >= cutoff_historical:
                historical_targets.update(activity.targets)
        
        new_targets = recent_targets - historical_targets
        if new_targets:
            anomalies.append({
                "type": "NEW_TARGETS",
                "severity": "MEDIUM",
                "description": f"New targets detected: {len(new_targets)} new target sectors/organizations in last 14 days",
                "new_targets_count": len(new_targets)
            })
        
        return {
            "anomalies_detected": len(anomalies) > 0,
            "anomaly_count": len(anomalies),
            "anomalies": anomalies,
            "analyzed_activities": len(profile.activity_timeline)
        }
    
    def get_top_active_actors(self, limit: int = 10, window_days: int = 30) -> List[Dict[str, Any]]:
        """Get most active threat actors within the specified window"""
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
        actor_scores = []
        
        for actor_id, profile in self.actors.items():
            window_activities = [a for a in profile.activity_timeline if a.timestamp >= cutoff]
            
            if not window_activities:
                continue
            
            severity_score = profile.calculate_severity_trend(window_days)["current_score"]
            velocity = len(window_activities) / window_days
            
            actor_scores.append({
                "actor_id": actor_id,
                "actor_name": profile.actor_name,
                "activities_in_window": len(window_activities),
                "activity_velocity": round(velocity, 3),
                "severity_score": severity_score,
                "combined_score": round(velocity * severity_score, 3)
            })
        
        # Sort by combined score
        actor_scores.sort(key=lambda x: x["combined_score"], reverse=True)
        
        return actor_scores[:limit]
    
    def export_tracking_data(self, format_type: str = "json") -> Any:
        """Export all tracking data in specified format"""
        data = {
            "export_timestamp": datetime.now(timezone.utc).isoformat(),
            "total_actors_tracked": len(self.actors),
            "total_activities_tracked": len(self.activity_index),
            "actors": [self.get_actor_profile(name) for name in [a.actor_name for a in self.actors.values()]]
        }
        
        if format_type.lower() == "json":
            return json.dumps(data, indent=2)
        return data
