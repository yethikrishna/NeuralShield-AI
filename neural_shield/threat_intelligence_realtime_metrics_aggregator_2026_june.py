"""
NeuralShield AI - Threat Intelligence Real-Time Metrics Aggregator
Production-grade module for aggregating threat intelligence metrics in real-time

This module provides:
- Real-time threat metrics aggregation
- Rolling window statistics (1min, 5min, 15min, 1hr)
- Threat severity distribution tracking
- Alert rate monitoring
- Dashboard-ready JSON output
- Thread-safe operations
"""

import time
import threading
import json
from collections import deque, defaultdict
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
import math


@dataclass
class ThreatEvent:
    """Single threat event data structure"""
    event_id: str
    timestamp: float
    threat_type: str
    severity: str  # critical, high, medium, low, info
    source: str
    confidence: float  # 0.0 - 1.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class WindowMetrics:
    """Metrics for a specific time window"""
    window_name: str
    window_seconds: int
    total_events: int = 0
    events_per_second: float = 0.0
    severity_distribution: Dict[str, int] = field(default_factory=lambda: {
        "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0
    })
    threat_type_distribution: Dict[str, int] = field(default_factory=dict)
    avg_confidence: float = 0.0
    max_confidence: float = 0.0
    min_confidence: float = 1.0
    unique_sources: int = 0
    critical_alerts_rate: float = 0.0


class RealtimeMetricsAggregator:
    """
    Production-grade real-time threat metrics aggregator
    
    Features:
    - Multiple rolling time windows
    - Thread-safe event ingestion
    - Automatic window rotation
    - Memory-efficient event storage
    - Dashboard-ready metrics output
    """
    
    SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    
    def __init__(self, max_events_per_window: int = 10000):
        self.max_events_per_window = max_events_per_window
        
        # Define time windows (name: seconds)
        self.windows = {
            "1min": 60,
            "5min": 300,
            "15min": 900,
            "1hr": 3600,
            "total": float('inf')
        }
        
        # Event storage - deque for efficient FIFO operations
        self._events: deque = deque(maxlen=max_events_per_window)
        
        # Thread safety
        self._lock = threading.RLock()
        
        # Statistics tracking
        self._total_events_processed = 0
        self._start_time = time.time()
        
    def add_event(self, event: ThreatEvent) -> bool:
        """
        Add a threat event to the aggregator (thread-safe)
        
        Returns:
            bool: True if event was added successfully
        """
        if not self._validate_event(event):
            return False
            
        with self._lock:
            self._events.append(event)
            self._total_events_processed += 1
            return True
    
    def add_event_simple(
        self,
        threat_type: str,
        severity: str = "medium",
        source: str = "unknown",
        confidence: float = 0.5,
        metadata: Optional[Dict[str, Any]] = None
    ) -> str:
        """
        Simplified interface to add an event without creating ThreatEvent object
        
        Returns:
            str: Generated event ID
        """
        event_id = f"evt_{int(time.time() * 1000000)}"
        event = ThreatEvent(
            event_id=event_id,
            timestamp=time.time(),
            threat_type=threat_type,
            severity=severity.lower(),
            source=source,
            confidence=max(0.0, min(1.0, confidence)),
            metadata=metadata or {}
        )
        self.add_event(event)
        return event_id
    
    def _validate_event(self, event: ThreatEvent) -> bool:
        """Validate event data"""
        if not event.event_id:
            return False
        if event.severity not in self.SEVERITY_ORDER:
            return False
        if not 0.0 <= event.confidence <= 1.0:
            return False
        if event.timestamp <= 0:
            return False
        return True
    
    def _get_window_events(self, window_seconds: float) -> List[ThreatEvent]:
        """Get events within the specified time window"""
        now = time.time()
        cutoff = now - window_seconds if window_seconds != float('inf') else 0
        
        events = []
        for event in reversed(self._events):
            if event.timestamp >= cutoff:
                events.append(event)
            else:
                break  # Events are ordered, can break early
        return events
    
    def _calculate_window_metrics(
        self,
        window_name: str,
        window_seconds: float,
        events: List[ThreatEvent]
    ) -> WindowMetrics:
        """Calculate metrics for a window of events"""
        metrics = WindowMetrics(
            window_name=window_name,
            window_seconds=window_seconds if window_seconds != float('inf') else 0
        )
        
        if not events:
            return metrics
            
        metrics.total_events = len(events)
        actual_window = time.time() - events[-1].timestamp if events else window_seconds
        metrics.events_per_second = metrics.total_events / max(actual_window, 1)
        
        # Severity distribution
        confidences = []
        sources = set()
        threat_types = defaultdict(int)
        
        for event in events:
            metrics.severity_distribution[event.severity] += 1
            threat_types[event.threat_type] += 1
            confidences.append(event.confidence)
            sources.add(event.source)
        
        metrics.threat_type_distribution = dict(threat_types)
        metrics.unique_sources = len(sources)
        
        # Confidence stats
        if confidences:
            metrics.avg_confidence = sum(confidences) / len(confidences)
            metrics.max_confidence = max(confidences)
            metrics.min_confidence = min(confidences)
        
        # Critical alerts rate
        total_critical = metrics.severity_distribution["critical"] + metrics.severity_distribution["high"]
        metrics.critical_alerts_rate = total_critical / metrics.total_events if metrics.total_events > 0 else 0.0
        
        return metrics
    
    def get_metrics(self) -> Dict[str, Any]:
        """
        Get aggregated metrics for all time windows
        
        Returns:
            Dashboard-ready metrics dictionary
        """
        with self._lock:
            result = {
                "aggregator_info": {
                    "total_events_processed": self._total_events_processed,
                    "events_in_buffer": len(self._events),
                    "uptime_seconds": time.time() - self._start_time,
                    "timestamp": datetime.utcnow().isoformat() + "Z",
                    "max_buffer_size": self.max_events_per_window
                },
                "windows": {}
            }
            
            for window_name, window_seconds in self.windows.items():
                events = self._get_window_events(window_seconds)
                metrics = self._calculate_window_metrics(window_name, window_seconds, events)
                result["windows"][window_name] = asdict(metrics)
            
            # Calculate overall threat score
            result["overall_threat_score"] = self._calculate_threat_score(result)
            
            return result
    
    def _calculate_threat_score(self, metrics: Dict[str, Any]) -> Dict[str, float]:
        """Calculate composite threat score (0-100)"""
        window_1min = metrics["windows"].get("1min", {})
        severity = window_1min.get("severity_distribution", {})
        
        # Weighted severity score
        weighted_score = (
            severity.get("critical", 0) * 25 +
            severity.get("high", 0) * 10 +
            severity.get("medium", 0) * 3 +
            severity.get("low", 0) * 1
        )
        
        # Normalize to 0-100
        threat_score = min(100, weighted_score)
        
        # Risk level classification
        if threat_score >= 70:
            risk_level = "CRITICAL"
        elif threat_score >= 40:
            risk_level = "HIGH"
        elif threat_score >= 20:
            risk_level = "MEDIUM"
        elif threat_score >= 5:
            risk_level = "LOW"
        else:
            risk_level = "NORMAL"
        
        return {
            "score": round(threat_score, 2),
            "risk_level": risk_level,
            "weighted_events": weighted_score
        }
    
    def get_metrics_json(self, pretty: bool = True) -> str:
        """Get metrics as JSON string for dashboards"""
        metrics = self.get_metrics()
        indent = 2 if pretty else None
        return json.dumps(metrics, indent=indent)
    
    def get_threat_summary(self) -> Dict[str, Any]:
        """Get concise threat summary for quick monitoring"""
        metrics = self.get_metrics()
        window_1min = metrics["windows"]["1min"]
        window_5min = metrics["windows"]["5min"]
        
        return {
            "timestamp": metrics["aggregator_info"]["timestamp"],
            "threat_score": metrics["overall_threat_score"],
            "events_last_minute": window_1min["total_events"],
            "events_last_5minutes": window_5min["total_events"],
            "critical_alerts": window_5min["severity_distribution"]["critical"],
            "high_alerts": window_5min["severity_distribution"]["high"],
            "eps": round(window_1min["events_per_second"], 2),
            "top_threats": dict(sorted(
                window_5min["threat_type_distribution"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5])
        }
    
    def clear(self) -> None:
        """Clear all events (thread-safe)"""
        with self._lock:
            self._events.clear()


# Singleton instance for global usage
_global_aggregator: Optional[RealtimeMetricsAggregator] = None
_global_lock = threading.Lock()


def get_global_aggregator() -> RealtimeMetricsAggregator:
    """Get or create the global aggregator singleton"""
    global _global_aggregator
    with _global_lock:
        if _global_aggregator is None:
            _global_aggregator = RealtimeMetricsAggregator()
        return _global_aggregator


if __name__ == "__main__":
    # Demo usage
    aggregator = RealtimeMetricsAggregator()
    
    # Simulate some threat events
    print("=== NeuralShield Real-Time Metrics Aggregator Demo ===")
    print()
    
    # Add sample events
    for i in range(50):
        severity = ["critical", "high", "medium", "low", "info"][i % 5]
        threat_type = ["prompt_injection", "jailbreak", "data_leakage", "hallucination", "backdoor"][i % 5]
        aggregator.add_event_simple(
            threat_type=threat_type,
            severity=severity,
            source=f"sensor_{i % 3}",
            confidence=0.5 + (i % 5) * 0.1
        )
        if i % 10 == 0:
            time.sleep(0.01)
    
    # Get and display metrics
    summary = aggregator.get_threat_summary()
    print("Threat Summary:")
    print(json.dumps(summary, indent=2))
    print()
    
    metrics = aggregator.get_metrics()
    print(f"Total Events Processed: {metrics['aggregator_info']['total_events_processed']}")
    print(f"Threat Score: {metrics['overall_threat_score']['score']} ({metrics['overall_threat_score']['risk_level']})")
    print()
    
    print("1-Minute Window Stats:")
    win = metrics["windows"]["1min"]
    print(f"  Events: {win['total_events']}")
    print(f"  EPS: {win['events_per_second']:.2f}")
    print(f"  Critical: {win['severity_distribution']['critical']}")
    print(f"  High: {win['severity_distribution']['high']}")
    print(f"  Avg Confidence: {win['avg_confidence']:.2f}")
