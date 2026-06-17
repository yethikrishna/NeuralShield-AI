"""
NeuralShield-AI: Behavioral Biometrics Anomaly Detector
June 2026 Production Release

Detects anomalous behavioral patterns in user interactions that may indicate:
- Account takeover (ATO) attacks
- Adversarial human operators
- Automated bot activity
- Credential stuffing aftermath
- Insider threat indicators

Production-grade implementation with statistical anomaly detection,
typing biometrics analysis, and interaction pattern fingerprinting.
"""

import re
import time
import hashlib
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict, deque
import math


class AnomalyType(Enum):
    """Types of behavioral anomalies detected."""
    TYPING_PATTERN_SHIFT = "typing_pattern_shift"
    INTERACTION_SPEED_ANOMALY = "interaction_speed_anomaly"
    QUERY_VOLUME_SPIKE = "query_volume_spike"
    SESSION_DEVIATION = "session_deviation"
    IP_GEOLOCATION_JUMP = "ip_geolocation_jump"
    USER_AGENT_SHIFT = "user_agent_shift"
    ACCESS_PATTERN_ANOMALY = "access_pattern_anomaly"
    TIME_OF_DAY_DEVIATION = "time_of_day_deviation"
    BOT_LIKE_BEHAVIOR = "bot_like_behavior"
    INSIDER_THREAT_PATTERN = "insider_threat_pattern"


class RiskLevel(Enum):
    """Risk assessment levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class BehavioralFinding:
    """Single behavioral anomaly finding."""
    anomaly_type: AnomalyType
    risk_level: RiskLevel
    confidence: float  # 0.0 - 1.0
    description: str
    baseline_deviation: float  # Standard deviations from baseline
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class BehavioralDetectionResult:
    """Complete behavioral analysis result."""
    user_id: str
    session_id: str
    is_anomalous: bool
    overall_risk_level: RiskLevel
    overall_anomaly_score: float  # 0.0 - 1.0
    findings: List[BehavioralFinding]
    baseline_profile_hash: str
    analysis_timestamp: float
    recommendations: List[str] = field(default_factory=list)


@dataclass
class InteractionEvent:
    """Single user interaction event."""
    timestamp: float
    event_type: str  # keystroke, mouse_click, submission, navigation
    duration_ms: Optional[float] = None
    key_code: Optional[int] = None
    position: Optional[Tuple[int, int]] = None


@dataclass
class UserBehavioralBaseline:
    """Baseline behavioral profile for a user."""
    user_id: str
    profile_created: float
    profile_updated: float
    sample_count: int
    
    # Typing biometrics
    avg_keystroke_interval_ms: float
    std_keystroke_interval_ms: float
    avg_word_delay_ms: float
    avg_backspace_rate: float
    
    # Interaction patterns
    avg_session_duration_sec: float
    avg_queries_per_session: float
    avg_time_between_queries_sec: float
    typical_active_hours: List[int]  # Hours of day (0-23)
    
    # Environmental patterns
    typical_user_agents: List[str]
    typical_ip_ranges: List[str]
    
    # Access patterns
    common_feature_access: Dict[str, float]  # feature -> access frequency


class BehavioralBiometricsAnomalyDetector:
    """
    Production-grade behavioral biometrics anomaly detector.
    
    Analyzes user interaction patterns against established baselines
    to detect account takeover, bot activity, and adversarial behavior.
    
    Features:
    - Statistical typing pattern analysis (keystroke dynamics)
    - Session behavior deviation detection
    - Temporal pattern analysis
    - Environmental fingerprint verification
    - Bot vs human classification
    """
    
    def __init__(self, sensitivity: float = 0.7):
        """
        Initialize detector with configurable sensitivity.
        
        Args:
            sensitivity: Detection threshold (0.0 = permissive, 1.0 = strict)
        """
        self.sensitivity = max(0.1, min(1.0, sensitivity))
        self.user_baselines: Dict[str, UserBehavioralBaseline] = {}
        self.session_events: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=1000)
        )
        self.anomaly_threshold = 2.0 + (1.0 - sensitivity) * 2.0
        
    def create_baseline_from_events(
        self,
        user_id: str,
        events: List[InteractionEvent],
        metadata: Optional[Dict[str, Any]] = None
    ) -> UserBehavioralBaseline:
        """
        Create behavioral baseline from historical interaction events.
        
        Args:
            user_id: Unique user identifier
            events: List of historical interaction events
            metadata: Optional environmental metadata
            
        Returns:
            UserBehavioralBaseline profile
        """
        metadata = metadata or {}
        
        # Calculate typing metrics
        keystroke_intervals = []
        backspace_count = 0
        total_keystrokes = 0
        prev_timestamp = None
        
        for event in sorted(events, key=lambda e: e.timestamp):
            if event.event_type == "keystroke":
                total_keystrokes += 1
                if event.key_code == 8:  # Backspace
                    backspace_count += 1
                if prev_timestamp is not None:
                    interval = (event.timestamp - prev_timestamp) * 1000
                    if 0 < interval < 5000:  # Filter outliers
                        keystroke_intervals.append(interval)
                prev_timestamp = event.timestamp
        
        # Session metrics
        session_starts = sorted([e.timestamp for e in events if e.event_type == "session_start"])
        session_ends = sorted([e.timestamp for e in events if e.event_type == "session_end"])
        session_durations = []
        for start, end in zip(session_starts, session_ends):
            session_durations.append(end - start)
        
        # Time of day patterns
        active_hours = defaultdict(int)
        for event in events:
            hour = time.localtime(event.timestamp).tm_hour
            active_hours[hour] += 1
        
        typical_hours = [
            hour for hour, count in active_hours.items()
            if count > len(events) * 0.05
        ]
        
        baseline = UserBehavioralBaseline(
            user_id=user_id,
            profile_created=time.time(),
            profile_updated=time.time(),
            sample_count=len(events),
            
            avg_keystroke_interval_ms=(
                sum(keystroke_intervals) / len(keystroke_intervals)
                if keystroke_intervals else 150.0
            ),
            std_keystroke_interval_ms=(
                self._calculate_std(keystroke_intervals)
                if keystroke_intervals else 50.0
            ),
            avg_word_delay_ms=200.0,  # Default, refined with more data
            avg_backspace_rate=(
                backspace_count / total_keystrokes
                if total_keystrokes > 0 else 0.05
            ),
            
            avg_session_duration_sec=(
                sum(session_durations) / len(session_durations)
                if session_durations else 600.0
            ),
            avg_queries_per_session=metadata.get("avg_queries", 15.0),
            avg_time_between_queries_sec=metadata.get("avg_query_gap", 30.0),
            typical_active_hours=sorted(typical_hours) if typical_hours else list(range(9, 18)),
            
            typical_user_agents=metadata.get("user_agents", []),
            typical_ip_ranges=metadata.get("ip_ranges", []),
            common_feature_access=metadata.get("feature_access", {})
        )
        
        self.user_baselines[user_id] = baseline
        return baseline
    
    def analyze_session(
        self,
        user_id: str,
        session_id: str,
        current_events: List[InteractionEvent],
        environmental_data: Optional[Dict[str, Any]] = None
    ) -> BehavioralDetectionResult:
        """
        Analyze current session against user baseline for anomalies.
        
        Args:
            user_id: User identifier
            session_id: Session identifier
            current_events: Events from current session
            environmental_data: IP, user agent, location data
            
        Returns:
            BehavioralDetectionResult with findings
        """
        environmental_data = environmental_data or {}
        findings: List[BehavioralFinding] = []
        
        # Get or create baseline
        if user_id not in self.user_baselines:
            # Create initial baseline from this session
            baseline = self.create_baseline_from_events(
                user_id, current_events, environmental_data
            )
            is_anomalous = False
            overall_score = 0.0
            risk_level = RiskLevel.LOW
        else:
            baseline = self.user_baselines[user_id]
            
            # Run all detection checks
            findings.extend(self._check_typing_patterns(baseline, current_events))
            findings.extend(self._check_timing_patterns(baseline, current_events))
            findings.extend(self._check_environmental_factors(baseline, environmental_data))
            findings.extend(self._check_bot_indicators(current_events))
            
            # Calculate overall score
            overall_score = self._calculate_overall_anomaly_score(findings)
            is_anomalous = overall_score > self.sensitivity * 0.5
            
            # Determine risk level
            if overall_score > 0.8:
                risk_level = RiskLevel.CRITICAL
            elif overall_score > 0.6:
                risk_level = RiskLevel.HIGH
            elif overall_score > 0.3:
                risk_level = RiskLevel.MEDIUM
            else:
                risk_level = RiskLevel.LOW
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings, risk_level)
        
        return BehavioralDetectionResult(
            user_id=user_id,
            session_id=session_id,
            is_anomalous=is_anomalous,
            overall_risk_level=risk_level,
            overall_anomaly_score=overall_score,
            findings=findings,
            baseline_profile_hash=self._hash_baseline(baseline),
            analysis_timestamp=time.time(),
            recommendations=recommendations
        )
    
    def _check_typing_patterns(
        self,
        baseline: UserBehavioralBaseline,
        events: List[InteractionEvent]
    ) -> List[BehavioralFinding]:
        """Check for typing pattern deviations."""
        findings = []
        
        keystroke_events = [e for e in events if e.event_type == "keystroke"]
        if len(keystroke_events) < 10:
            return findings  # Not enough data
        
        intervals = []
        backspaces = 0
        prev_ts = None
        
        for e in keystroke_events:
            if prev_ts is not None:
                interval = (e.timestamp - prev_ts) * 1000
                if 0 < interval < 5000:
                    intervals.append(interval)
            if e.key_code == 8:
                backspaces += 1
            prev_ts = e.timestamp
        
        if intervals:
            current_avg = sum(intervals) / len(intervals)
            deviation = abs(current_avg - baseline.avg_keystroke_interval_ms)
            std_devs = deviation / max(baseline.std_keystroke_interval_ms, 1)
            
            if std_devs > self.anomaly_threshold * 0.7:  # Lowered threshold for better detection
                findings.append(BehavioralFinding(
                    anomaly_type=AnomalyType.TYPING_PATTERN_SHIFT,
                    risk_level=RiskLevel.HIGH if std_devs > 3 else RiskLevel.MEDIUM,
                    confidence=min(0.95, 0.5 + std_devs * 0.15),
                    description=f"Typing speed deviates {std_devs:.1f}σ from baseline",
                    baseline_deviation=std_devs,
                    evidence={
                        "baseline_avg_ms": baseline.avg_keystroke_interval_ms,
                        "current_avg_ms": current_avg,
                        "sample_size": len(intervals)
                    }
                ))
        
        current_backspace_rate = backspaces / len(keystroke_events)
        if abs(current_backspace_rate - baseline.avg_backspace_rate) > 0.15:
            findings.append(BehavioralFinding(
                anomaly_type=AnomalyType.TYPING_PATTERN_SHIFT,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7,
                description="Backspace usage pattern differs significantly from baseline",
                baseline_deviation=2.0,
                evidence={
                    "baseline_rate": baseline.avg_backspace_rate,
                    "current_rate": current_backspace_rate
                }
            ))
        
        return findings
    
    def _check_timing_patterns(
        self,
        baseline: UserBehavioralBaseline,
        events: List[InteractionEvent]
    ) -> List[BehavioralFinding]:
        """Check timing and session pattern anomalies."""
        findings = []
        
        # Check query submission speed
        submission_events = [e for e in events if e.event_type == "submission"]
        if len(submission_events) >= 3:
            gaps = []
            for i in range(1, len(submission_events)):
                gaps.append(submission_events[i].timestamp - submission_events[i-1].timestamp)
            
            avg_gap = sum(gaps) / len(gaps)
            if avg_gap < 2.0:  # Less than 2 seconds between complex queries
                findings.append(BehavioralFinding(
                    anomaly_type=AnomalyType.INTERACTION_SPEED_ANOMALY,
                    risk_level=RiskLevel.HIGH,
                    confidence=0.85,
                    description="Query submission speed indicates automated behavior",
                    baseline_deviation=3.5,
                    evidence={"avg_seconds_between_queries": avg_gap}
                ))
        
        # Check time of day
        current_hour = time.localtime(time.time()).tm_hour
        if current_hour not in baseline.typical_active_hours:
            findings.append(BehavioralFinding(
                anomaly_type=AnomalyType.TIME_OF_DAY_DEVIATION,
                risk_level=RiskLevel.MEDIUM,
                confidence=0.6,
                description=f"Activity at {current_hour}:00 outside typical hours",
                baseline_deviation=2.0,
                evidence={
                    "current_hour": current_hour,
                    "typical_hours": baseline.typical_active_hours
                }
            ))
        
        return findings
    
    def _check_environmental_factors(
        self,
        baseline: UserBehavioralBaseline,
        env_data: Dict[str, Any]
    ) -> List[BehavioralFinding]:
        """Check environmental fingerprint changes."""
        findings = []
        
        user_agent = env_data.get("user_agent", "")
        if user_agent and baseline.typical_user_agents:
            if user_agent not in baseline.typical_user_agents:
                findings.append(BehavioralFinding(
                    anomaly_type=AnomalyType.USER_AGENT_SHIFT,
                    risk_level=RiskLevel.LOW,
                    confidence=0.5,
                    description="Unfamiliar browser/device fingerprint",
                    baseline_deviation=1.5,
                    evidence={"user_agent": user_agent[:50]}
                ))
        
        ip_address = env_data.get("ip_address", "")
        if ip_address and baseline.typical_ip_ranges:
            ip_match = any(
                ip_address.startswith(prefix)
                for prefix in baseline.typical_ip_ranges
            )
            if not ip_match:
                findings.append(BehavioralFinding(
                    anomaly_type=AnomalyType.IP_GEOLOCATION_JUMP,
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.65,
                    description="Access from unrecognized IP address range",
                    baseline_deviation=2.0,
                    evidence={"ip_address": ip_address}
                ))
        
        return findings
    
    def _check_bot_indicators(self, events: List[InteractionEvent]) -> List[BehavioralFinding]:
        """Detect bot-like behavioral patterns."""
        findings = []
        
        if len(events) < 5:
            return findings
        
        # Check for perfectly regular timing (bot signature)
        timestamps = sorted([e.timestamp for e in events])
        intervals = [timestamps[i] - timestamps[i-1] for i in range(1, len(timestamps))]
        
        if intervals:
            interval_std = self._calculate_std(intervals)
            if interval_std < 0.05:  # Almost perfectly regular timing
                findings.append(BehavioralFinding(
                    anomaly_type=AnomalyType.BOT_LIKE_BEHAVIOR,
                    risk_level=RiskLevel.HIGH,
                    confidence=0.9,
                    description="Nearly perfect timing regularity indicates automation",
                    baseline_deviation=4.0,
                    evidence={"interval_std_seconds": interval_std}
                ))
        
        # Check for no hesitation patterns
        keystrokes = [e for e in events if e.event_type == "keystroke"]
        if len(keystrokes) >= 20:
            long_pauses = sum(1 for i in intervals if i > 2.0)
            if long_pauses == 0:
                findings.append(BehavioralFinding(
                    anomaly_type=AnomalyType.BOT_LIKE_BEHAVIOR,
                    risk_level=RiskLevel.MEDIUM,
                    confidence=0.75,
                    description="No thinking pauses detected in input stream",
                    baseline_deviation=2.5,
                    evidence={"sample_size": len(keystrokes)}
                ))
        
        return findings
    
    def _calculate_overall_anomaly_score(self, findings: List[BehavioralFinding]) -> float:
        """Calculate weighted overall anomaly score."""
        if not findings:
            return 0.0
        
        risk_weights = {
            RiskLevel.LOW: 0.2,
            RiskLevel.MEDIUM: 0.5,
            RiskLevel.HIGH: 0.8,
            RiskLevel.CRITICAL: 1.0
        }
        
        weighted_sum = sum(
            risk_weights[f.risk_level] * f.confidence
            for f in findings
        )
        
        return min(1.0, weighted_sum / max(1, len(findings)))
    
    def _generate_recommendations(
        self,
        findings: List[BehavioralFinding],
        risk_level: RiskLevel
    ) -> List[str]:
        """Generate security recommendations based on findings."""
        recommendations = []
        
        if risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            recommendations.append("Trigger step-up authentication (MFA)")
            recommendations.append("Flag session for security review")
            recommendations.append("Limit sensitive operations for this session")
        
        if risk_level == RiskLevel.MEDIUM:
            recommendations.append("Monitor session for escalating anomalies")
            recommendations.append("Log session details for audit trail")
        
        if any(f.anomaly_type == AnomalyType.BOT_LIKE_BEHAVIOR for f in findings):
            recommendations.append("Apply CAPTCHA challenge")
            recommendations.append("Implement rate limiting")
        
        if not recommendations:
            recommendations.append("Continue normal monitoring")
        
        return recommendations
    
    @staticmethod
    def _calculate_std(values: List[float]) -> float:
        """Calculate standard deviation."""
        if len(values) < 2:
            return 0.0
        mean = sum(values) / len(values)
        variance = sum((x - mean) ** 2 for x in values) / len(values)
        return math.sqrt(variance)
    
    @staticmethod
    def _hash_baseline(baseline: UserBehavioralBaseline) -> str:
        """Generate hash of baseline for integrity verification."""
        profile_str = (
            f"{baseline.user_id}:{baseline.avg_keystroke_interval_ms}:"
            f"{baseline.sample_count}:{baseline.profile_created}"
        )
        return hashlib.sha256(profile_str.encode()).hexdigest()[:16]


# Export public API
__all__ = [
    "BehavioralBiometricsAnomalyDetector",
    "AnomalyType",
    "RiskLevel",
    "BehavioralFinding",
    "BehavioralDetectionResult",
    "InteractionEvent",
    "UserBehavioralBaseline",
]
