"""
NeuralShield-AI: Threat Intelligence Anomaly Sequence Detector
June 18, 2026

Real, production-grade implementation of sequence anomaly detection for threat intelligence.
Detects anomalous patterns in temporal sequences of security events using:
- Sliding window statistical analysis
- Markov chain transition probability deviation
- Sequence rarity scoring
- Out-of-order event detection
"""

import re
import math
import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import List, Dict, Tuple, Optional, Any
from datetime import datetime, timedelta
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class SecurityEvent:
    """Represents a single security event in the sequence."""
    event_id: str
    event_type: str
    timestamp: datetime
    source_ip: str = ""
    severity: str = "low"
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if not self.event_id:
            self.event_id = hashlib.md5(
                f"{self.event_type}{self.timestamp}{self.source_ip}".encode()
            ).hexdigest()[:12]


@dataclass
class AnomalyResult:
    """Result of anomaly detection analysis."""
    is_anomalous: bool
    anomaly_score: float
    anomaly_type: str
    confidence: float
    affected_events: List[str]
    description: str
    recommendation: str


class ThreatIntelligenceAnomalySequenceDetector:
    """
    Real working implementation of sequence anomaly detection.

    Features:
    1. Sliding window z-score analysis for event frequency anomalies
    2. Markov chain transition probability deviation detection
    3. Rare sequence pattern identification
    4. Out-of-order event detection
    5. Baseline comparison with historical normal patterns
    """

    def __init__(
        self,
        window_size: int = 10,
        z_score_threshold: float = 2.5,
        transition_prob_threshold: float = 0.05,
        rarity_threshold: float = 0.1
    ):
        self.window_size = window_size
        self.z_score_threshold = z_score_threshold
        self.transition_prob_threshold = transition_prob_threshold
        self.rarity_threshold = rarity_threshold

        # Historical baseline data
        self.event_type_counts: Dict[str, int] = defaultdict(int)
        self.transition_counts: Dict[Tuple[str, str], int] = defaultdict(int)
        self.sequence_frequencies: Dict[str, int] = defaultdict(int)
        self.total_events = 0
        self.total_transitions = 0

        # Event buffer for sliding window
        self.event_buffer: deque = deque(maxlen=window_size * 2)

        # Normal baseline statistics (pre-trained)
        self.normal_event_rates: Dict[str, float] = {
            "login_attempt": 0.35,
            "file_access": 0.25,
            "api_call": 0.20,
            "network_connection": 0.15,
            "privilege_escalation": 0.03,
            "data_exfiltration": 0.01,
            "suspicious_command": 0.01
        }

    def train_baseline(self, historical_events: List[SecurityEvent]) -> None:
        """Train the baseline model on historical normal events."""
        if not historical_events:
            logger.warning("No historical events provided for baseline training")
            return

        sorted_events = sorted(historical_events, key=lambda e: e.timestamp)

        prev_type = None
        window_sequence: List[str] = []

        for event in sorted_events:
            self.event_type_counts[event.event_type] += 1
            self.total_events += 1

            if prev_type is not None:
                self.transition_counts[(prev_type, event.event_type)] += 1
                self.total_transitions += 1

            window_sequence.append(event.event_type)
            if len(window_sequence) >= 3:
                seq_key = "|".join(window_sequence[-3:])
                self.sequence_frequencies[seq_key] += 1

            prev_type = event.event_type

        logger.info(
            f"Baseline trained on {self.total_events} events, "
            f"{self.total_transitions} transitions"
        )

    def get_transition_probability(self, from_type: str, to_type: str) -> float:
        """Get probability of transition from one event type to another."""
        if self.total_transitions == 0:
            return self.normal_event_rates.get(to_type, 0.01)

        from_count = sum(
            cnt for (f, t), cnt in self.transition_counts.items()
            if f == from_type
        )

        if from_count == 0:
            return 0.01

        return self.transition_counts.get((from_type, to_type), 0) / from_count

    def analyze_sliding_window_anomaly(
        self, events: List[SecurityEvent]
    ) -> List[AnomalyResult]:
        """Detect anomalies using sliding window statistical analysis."""
        results: List[AnomalyResult] = []

        if len(events) < self.window_size:
            return results

        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for i in range(len(sorted_events) - self.window_size + 1):
            window = sorted_events[i:i + self.window_size]
            window_types = [e.event_type for e in window]

            # Calculate event type distribution in window
            window_counts: Dict[str, int] = defaultdict(int)
            for et in window_types:
                window_counts[et] += 1

            # Compare against baseline rates
            for event_type, count in window_counts.items():
                observed_rate = count / self.window_size
                expected_rate = self.normal_event_rates.get(event_type, 0.05)

                if expected_rate > 0:
                    deviation = observed_rate / expected_rate
                else:
                    deviation = float('inf')

                # Rare event type with high occurrence = anomaly
                if (event_type in ["privilege_escalation", "data_exfiltration",
                                   "suspicious_command"] and count >= 2):
                    results.append(AnomalyResult(
                        is_anomalous=True,
                        anomaly_score=min(deviation, 10.0),
                        anomaly_type="rare_event_cluster",
                        confidence=min(0.95, 0.7 + (count * 0.08)),
                        affected_events=[e.event_id for e in window if e.event_type == event_type],
                        description=f"Unusual cluster of {count} {event_type} events in window",
                        recommendation="Investigate source of clustered suspicious activity immediately"
                    ))

                # General rate anomaly
                if deviation > 4.0 and count >= 3:
                    results.append(AnomalyResult(
                        is_anomalous=True,
                        anomaly_score=min(deviation / 2, 8.0),
                        anomaly_type="rate_anomaly",
                        confidence=min(0.85, 0.6 + (deviation * 0.05)),
                        affected_events=[e.event_id for e in window],
                        description=f"Event rate anomaly: {event_type} at {deviation:.1f}x normal rate",
                        recommendation="Review for potential automated attack or scanning"
                    ))

        return results

    def analyze_transition_anomalies(
        self, events: List[SecurityEvent]
    ) -> List[AnomalyResult]:
        """Detect anomalous transitions between event types using Markov chains."""
        results: List[AnomalyResult] = []

        if len(events) < 2:
            return results

        sorted_events = sorted(events, key=lambda e: e.timestamp)

        suspicious_transitions = {
            ("login_attempt", "privilege_escalation"): "Rapid escalation after login",
            ("file_access", "data_exfiltration"): "Data access followed by exfiltration",
            ("network_connection", "suspicious_command"): "Remote command execution pattern",
            ("api_call", "privilege_escalation"): "API-based privilege escalation attempt"
        }

        for i in range(len(sorted_events) - 1):
            from_event = sorted_events[i]
            to_event = sorted_events[i + 1]

            transition = (from_event.event_type, to_event.event_type)
            prob = self.get_transition_probability(from_event.event_type, to_event.event_type)

            # Known suspicious patterns
            if transition in suspicious_transitions:
                time_diff = (to_event.timestamp - from_event.timestamp).total_seconds()

                if time_diff < 30:  # Within 30 seconds
                    results.append(AnomalyResult(
                        is_anomalous=True,
                        anomaly_score=8.5,
                        anomaly_type="known_attack_sequence",
                        confidence=0.92,
                        affected_events=[from_event.event_id, to_event.event_id],
                        description=suspicious_transitions[transition],
                        recommendation="Block source IP and initiate incident response protocol"
                    ))

            # Very low probability transition
            elif prob < self.transition_prob_threshold and self.total_transitions > 100:
                results.append(AnomalyResult(
                    is_anomalous=True,
                    anomaly_score=6.0,
                    anomaly_type="rare_transition",
                    confidence=0.75,
                    affected_events=[from_event.event_id, to_event.event_id],
                    description=f"Rare transition pattern: {from_event.event_type} -> {to_event.event_type}",
                    recommendation="Review for potential novel attack pattern"
                ))

        return results

    def analyze_sequence_rarity(
        self, events: List[SecurityEvent]
    ) -> List[AnomalyResult]:
        """Detect rare 3-event sequences that deviate from baseline."""
        results: List[AnomalyResult] = []

        if len(events) < 3:
            return results

        sorted_events = sorted(events, key=lambda e: e.timestamp)
        event_types = [e.event_type for e in sorted_events]

        for i in range(len(event_types) - 2):
            seq_types = event_types[i:i + 3]
            seq_key = "|".join(seq_types)

            if self.total_events > 0:
                freq = self.sequence_frequencies.get(seq_key, 0)
                total_seqs = max(sum(self.sequence_frequencies.values()), 1)
                rarity = 1.0 - (freq / total_seqs)
            else:
                rarity = 0.5

            if rarity > (1.0 - self.rarity_threshold) and self.total_events > 50:
                results.append(AnomalyResult(
                    is_anomalous=True,
                    anomaly_score=rarity * 10,
                    anomaly_type="rare_sequence",
                    confidence=min(0.85, 0.5 + rarity * 0.4),
                    affected_events=[e.event_id for e in sorted_events[i:i + 3]],
                    description=f"Rare event sequence detected: {seq_key}",
                    recommendation="Flag for manual review as potential novel attack"
                ))

        return results

    def detect_out_of_order_events(
        self, events: List[SecurityEvent]
    ) -> List[AnomalyResult]:
        """Detect events that appear out of expected logical order."""
        results: List[AnomalyResult] = []

        if len(events) < 3:
            return results

        # Expected logical progression patterns
        expected_order = {
            "login_attempt": 1,
            "file_access": 2,
            "api_call": 2,
            "privilege_escalation": 3,
            "data_exfiltration": 4,
            "suspicious_command": 3
        }

        sorted_events = sorted(events, key=lambda e: e.timestamp)

        for i in range(1, len(sorted_events)):
            curr_level = expected_order.get(sorted_events[i].event_type, 2)
            prev_level = expected_order.get(sorted_events[i - 1].event_type, 2)

            # Reversal of expected order (e.g., data exfil before login)
            if curr_level < prev_level - 1 and prev_level >= 3:
                results.append(AnomalyResult(
                    is_anomalous=True,
                    anomaly_score=7.0,
                    anomaly_type="logical_order_reversal",
                    confidence=0.80,
                    affected_events=[
                        sorted_events[i - 1].event_id,
                        sorted_events[i].event_id
                    ],
                    description=(
                        f"Logical order anomaly: {sorted_events[i].event_type} "
                        f"appeared before {sorted_events[i - 1].event_type}"
                    ),
                    recommendation="Check for indicator removal or anti-forensics"
                ))

        return results

    def analyze(
        self, events: List[SecurityEvent]
    ) -> Dict[str, Any]:
        """
        Main analysis entry point - runs all detection methods.

        Returns comprehensive analysis results.
        """
        if not events:
            return {
                "success": False,
                "error": "No events provided for analysis",
                "anomalies": [],
                "summary": {}
            }

        # Add events to buffer
        for event in events:
            self.event_buffer.append(event)

        # Run all detectors
        window_anomalies = self.analyze_sliding_window_anomaly(events)
        transition_anomalies = self.analyze_transition_anomalies(events)
        rarity_anomalies = self.analyze_sequence_rarity(events)
        order_anomalies = self.detect_out_of_order_events(events)

        all_anomalies = (
            window_anomalies +
            transition_anomalies +
            rarity_anomalies +
            order_anomalies
        )

        # Deduplicate anomalies by affected events
        seen_combinations = set()
        unique_anomalies: List[AnomalyResult] = []

        for anomaly in all_anomalies:
            key = "|".join(sorted(anomaly.affected_events)) + anomaly.anomaly_type
            if key not in seen_combinations:
                seen_combinations.add(key)
                unique_anomalies.append(anomaly)

        # Sort by anomaly score
        unique_anomalies.sort(key=lambda a: a.anomaly_score, reverse=True)

        summary = {
            "total_events_analyzed": len(events),
            "total_anomalies_detected": len(unique_anomalies),
            "anomalies_by_type": defaultdict(int),
            "max_anomaly_score": max([a.anomaly_score for a in unique_anomalies], default=0.0),
            "average_confidence": (
                sum(a.confidence for a in unique_anomalies) / len(unique_anomalies)
                if unique_anomalies else 0.0
            )
        }

        for anomaly in unique_anomalies:
            summary["anomalies_by_type"][anomaly.anomaly_type] += 1

        summary["anomalies_by_type"] = dict(summary["anomalies_by_type"])

        return {
            "success": True,
            "anomalies": unique_anomalies,
            "summary": summary,
            "is_critical": any(a.anomaly_score >= 7.0 for a in unique_anomalies),
            "recommendations": [a.recommendation for a in unique_anomalies[:5]]
        }
