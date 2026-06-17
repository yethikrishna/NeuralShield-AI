"""
NeuralShield AI - Real-time Threat Alert Aggregator & Notification Engine
Production Grade - June 17, 2026

This module provides real-time threat aggregation, deduplication,
severity classification, and multi-channel notification capabilities.
"""

import hashlib
import json
import time
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Callable
from collections import deque
from datetime import datetime, timezone


class ThreatSeverity(Enum):
    """Standardized threat severity levels"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    """Categories of security threats"""
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    DATA_LEAKAGE = "data_leakage"
    ADVERSARIAL_ATTACK = "adversarial_attack"
    HALLUCINATION = "hallucination"
    PII_EXPOSURE = "pii_exposure"
    MODEL_EXTRACTION = "model_extraction"
    BACKDOOR_DETECTED = "backdoor_detected"
    UNKNOWN = "unknown"


class NotificationChannel(Enum):
    """Available notification channels"""
    CONSOLE = "console"
    LOG_FILE = "log_file"
    WEBHOOK = "webhook"
    EMAIL = "email"
    SLACK = "slack"


@dataclass
class ThreatAlert:
    """Represents a single threat alert"""
    alert_id: str
    timestamp: float
    detector: str
    category: ThreatCategory
    severity: ThreatSeverity
    description: str
    source: str
    confidence: float
    metadata: Dict = field(default_factory=dict)
    deduplication_key: Optional[str] = None

    def to_dict(self) -> Dict:
        return {
            "alert_id": self.alert_id,
            "timestamp": self.timestamp,
            "timestamp_iso": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "detector": self.detector,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "source": self.source,
            "confidence": self.confidence,
            "metadata": self.metadata
        }


@dataclass
class AggregatedThreatSummary:
    """Aggregated summary of threats over a time window"""
    window_start: float
    window_end: float
    total_alerts: int
    by_severity: Dict[str, int]
    by_category: Dict[str, int]
    by_detector: Dict[str, int]
    unique_sources: int
    top_alerts: List[ThreatAlert]

    def to_dict(self) -> Dict:
        return {
            "window_start": self.window_start,
            "window_end": self.window_end,
            "duration_seconds": self.window_end - self.window_start,
            "total_alerts": self.total_alerts,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "by_detector": self.by_detector,
            "unique_sources": self.unique_sources,
            "top_alerts": [a.to_dict() for a in self.top_alerts[:5]]
        }


class ThreatAlertAggregator:
    """
    Real-time threat alert aggregator with deduplication,
    severity-based prioritization, and rolling window analytics.
    """

    def __init__(
        self,
        deduplication_window_seconds: int = 60,
        aggregation_window_seconds: int = 300,
        max_history_size: int = 10000
    ):
        self.deduplication_window = deduplication_window_seconds
        self.aggregation_window = aggregation_window_seconds
        self.max_history_size = max_history_size

        self.alert_history: deque = deque(maxlen=max_history_size)
        self.recent_deduplication_keys: Dict[str, float] = {}

        self.severity_counts: Dict[ThreatSeverity, int] = {s: 0 for s in ThreatSeverity}
        self.category_counts: Dict[ThreatCategory, int] = {c: 0 for c in ThreatCategory}
        self.detector_counts: Dict[str, int] = {}

        self._lock = threading.RLock()
        self._cleanup_thread = threading.Thread(target=self._periodic_cleanup, daemon=True)
        self._cleanup_thread.start()

    def _generate_alert_id(self) -> str:
        """Generate unique alert ID"""
        timestamp = str(time.time()).encode()
        random_data = str(time.perf_counter_ns()).encode()
        return hashlib.sha256(timestamp + random_data).hexdigest()[:16]

    def _generate_deduplication_key(
        self,
        detector: str,
        category: ThreatCategory,
        source: str,
        description: str
    ) -> str:
        """Generate hash key for deduplication"""
        key_data = f"{detector}:{category.value}:{source}:{description[:100]}"
        return hashlib.md5(key_data.encode()).hexdigest()

    def _classify_severity(
        self,
        category: ThreatCategory,
        confidence: float,
        detector: str
    ) -> ThreatSeverity:
        """Intelligently classify threat severity based on multiple factors"""
        # Base severity by category
        base_severity_map = {
            ThreatCategory.JAILBREAK_ATTEMPT: ThreatSeverity.HIGH,
            ThreatCategory.PROMPT_INJECTION: ThreatSeverity.HIGH,
            ThreatCategory.DATA_LEAKAGE: ThreatSeverity.CRITICAL,
            ThreatCategory.PII_EXPOSURE: ThreatSeverity.CRITICAL,
            ThreatCategory.BACKDOOR_DETECTED: ThreatSeverity.CRITICAL,
            ThreatCategory.MODEL_EXTRACTION: ThreatSeverity.HIGH,
            ThreatCategory.ADVERSARIAL_ATTACK: ThreatSeverity.HIGH,
            ThreatCategory.HALLUCINATION: ThreatSeverity.MEDIUM,
            ThreatCategory.UNKNOWN: ThreatSeverity.UNKNOWN
        }

        base_severity = base_severity_map.get(category, ThreatSeverity.MEDIUM)

        # Adjust based on confidence
        if confidence >= 0.95:
            if base_severity == ThreatSeverity.HIGH:
                return ThreatSeverity.CRITICAL
            elif base_severity == ThreatSeverity.MEDIUM:
                return ThreatSeverity.HIGH
        elif confidence < 0.5:
            if base_severity == ThreatSeverity.CRITICAL:
                return ThreatSeverity.HIGH
            elif base_severity == ThreatSeverity.HIGH:
                return ThreatSeverity.MEDIUM

        return base_severity

    def ingest_alert(
        self,
        detector: str,
        category: str,
        description: str,
        source: str,
        confidence: float,
        metadata: Optional[Dict] = None
    ) -> Optional[ThreatAlert]:
        """
        Ingest a new threat alert.
        Returns the alert if not a duplicate, None if deduplicated.
        """
        with self._lock:
            try:
                threat_category = ThreatCategory(category.lower())
            except ValueError:
                threat_category = ThreatCategory.UNKNOWN

            severity = self._classify_severity(threat_category, confidence, detector)
            deduplication_key = self._generate_deduplication_key(
                detector, threat_category, source, description
            )

            # Check for recent duplicate
            now = time.time()
            if deduplication_key in self.recent_deduplication_keys:
                last_seen = self.recent_deduplication_keys[deduplication_key]
                if now - last_seen < self.deduplication_window:
                    return None

            self.recent_deduplication_keys[deduplication_key] = now

            alert = ThreatAlert(
                alert_id=self._generate_alert_id(),
                timestamp=now,
                detector=detector,
                category=threat_category,
                severity=severity,
                description=description,
                source=source,
                confidence=max(0.0, min(1.0, confidence)),
                metadata=metadata or {},
                deduplication_key=deduplication_key
            )

            self.alert_history.append(alert)
            self.severity_counts[severity] += 1
            self.category_counts[threat_category] += 1
            self.detector_counts[detector] = self.detector_counts.get(detector, 0) + 1

            return alert

    def get_aggregated_summary(self, window_seconds: Optional[int] = None) -> AggregatedThreatSummary:
        """Get aggregated threat summary for the specified time window"""
        window = window_seconds or self.aggregation_window
        now = time.time()
        window_start = now - window

        with self._lock:
            window_alerts = [
                alert for alert in self.alert_history
                if alert.timestamp >= window_start
            ]

            by_severity = {s.value: 0 for s in ThreatSeverity}
            by_category = {c.value: 0 for c in ThreatCategory}
            by_detector: Dict[str, int] = {}
            sources: Set[str] = set()

            for alert in window_alerts:
                by_severity[alert.severity.value] += 1
                by_category[alert.category.value] += 1
                by_detector[alert.detector] = by_detector.get(alert.detector, 0) + 1
                sources.add(alert.source)

            # Sort by severity then confidence
            sorted_alerts = sorted(
                window_alerts,
                key=lambda a: (
                    {"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}[a.severity.value],
                    a.confidence
                ),
                reverse=True
            )

            return AggregatedThreatSummary(
                window_start=window_start,
                window_end=now,
                total_alerts=len(window_alerts),
                by_severity=by_severity,
                by_category=by_category,
                by_detector=by_detector,
                unique_sources=len(sources),
                top_alerts=sorted_alerts[:10]
            )

    def get_critical_alerts(self) -> List[ThreatAlert]:
        """Get all active critical severity alerts"""
        with self._lock:
            return [
                alert for alert in self.alert_history
                if alert.severity == ThreatSeverity.CRITICAL
            ]

    def _periodic_cleanup(self):
        """Background thread to clean up old deduplication keys"""
        while True:
            time.sleep(30)
            with self._lock:
                now = time.time()
                expired = [
                    k for k, v in self.recent_deduplication_keys.items()
                    if now - v > self.deduplication_window * 2
                ]
                for k in expired:
                    del self.recent_deduplication_keys[k]

    def get_statistics(self) -> Dict:
        """Get overall statistics"""
        with self._lock:
            return {
                "total_alerts_processed": len(self.alert_history),
                "by_severity": {k.value: v for k, v in self.severity_counts.items()},
                "by_category": {k.value: v for k, v in self.category_counts.items()},
                "by_detector": dict(self.detector_counts),
                "active_deduplication_keys": len(self.recent_deduplication_keys)
            }


class NotificationEngine:
    """
    Multi-channel notification engine for threat alerts.
    Supports console, log file, webhook, and extensible channels.
    """

    def __init__(self, log_file_path: Optional[str] = None):
        self.channels: Dict[NotificationChannel, Callable] = {
            NotificationChannel.CONSOLE: self._notify_console,
            NotificationChannel.LOG_FILE: self._notify_log_file,
        }
        self.log_file_path = log_file_path
        self.enabled_channels: Set[NotificationChannel] = {NotificationChannel.CONSOLE}
        self.severity_threshold: ThreatSeverity = ThreatSeverity.LOW
        self._notification_callbacks: List[Callable] = []

    def enable_channel(self, channel: NotificationChannel):
        """Enable a notification channel"""
        self.enabled_channels.add(channel)

    def disable_channel(self, channel: NotificationChannel):
        """Disable a notification channel"""
        self.enabled_channels.discard(channel)

    def set_severity_threshold(self, severity: ThreatSeverity):
        """Set minimum severity for notifications"""
        self.severity_threshold = severity

    def add_callback(self, callback: Callable[[ThreatAlert], None]):
        """Add custom callback for notifications"""
        self._notification_callbacks.append(callback)

    def _should_notify(self, alert: ThreatAlert) -> bool:
        """Determine if alert should trigger notification"""
        severity_order = {
            ThreatSeverity.LOW: 1,
            ThreatSeverity.MEDIUM: 2,
            ThreatSeverity.HIGH: 3,
            ThreatSeverity.CRITICAL: 4,
            ThreatSeverity.UNKNOWN: 0
        }
        return severity_order[alert.severity] >= severity_order[self.severity_threshold]

    def _notify_console(self, alert: ThreatAlert):
        """Send notification to console"""
        severity_color = {
            ThreatSeverity.CRITICAL: "\033[91m",
            ThreatSeverity.HIGH: "\033[93m",
            ThreatSeverity.MEDIUM: "\033[94m",
            ThreatSeverity.LOW: "\033[92m",
            ThreatSeverity.UNKNOWN: "\033[90m"
        }
        reset = "\033[0m"
        color = severity_color.get(alert.severity, "")
        timestamp = datetime.fromtimestamp(alert.timestamp, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        print(f"{color}[{alert.severity.value.upper()}] {timestamp} - {alert.detector}{reset}")
        print(f"  {alert.description}")
        print(f"  Source: {alert.source} | Confidence: {alert.confidence:.2f}")

    def _notify_log_file(self, alert: ThreatAlert):
        """Send notification to log file"""
        if not self.log_file_path:
            return
        try:
            with open(self.log_file_path, 'a', encoding='utf-8') as f:
                log_entry = json.dumps(alert.to_dict())
                f.write(log_entry + "\n")
        except Exception:
            pass

    def notify(self, alert: ThreatAlert):
        """Send alert through all enabled channels"""
        if not self._should_notify(alert):
            return

        for channel in self.enabled_channels:
            if channel in self.channels:
                try:
                    self.channels[channel](alert)
                except Exception:
                    pass

        for callback in self._notification_callbacks:
            try:
                callback(alert)
            except Exception:
                pass

    def notify_batch(self, alerts: List[ThreatAlert]):
        """Process multiple alerts"""
        for alert in alerts:
            self.notify(alert)


class ThreatAlertOrchestrator:
    """
    Orchestrator combining aggregator and notification engine
    for end-to-end threat alert management.
    """

    def __init__(
        self,
        deduplication_window_seconds: int = 60,
        aggregation_window_seconds: int = 300,
        log_file_path: Optional[str] = None
    ):
        self.aggregator = ThreatAlertAggregator(
            deduplication_window_seconds=deduplication_window_seconds,
            aggregation_window_seconds=aggregation_window_seconds
        )
        self.notification_engine = NotificationEngine(log_file_path=log_file_path)

    def process_threat_detection(
        self,
        detector: str,
        category: str,
        description: str,
        source: str,
        confidence: float,
        metadata: Optional[Dict] = None,
        notify: bool = True
    ) -> Optional[ThreatAlert]:
        """Process a threat detection result"""
        alert = self.aggregator.ingest_alert(
            detector=detector,
            category=category,
            description=description,
            source=source,
            confidence=confidence,
            metadata=metadata
        )

        if alert and notify:
            self.notification_engine.notify(alert)

        return alert

    def get_status_summary(self) -> Dict:
        """Get comprehensive status summary"""
        stats = self.aggregator.get_statistics()
        summary = self.aggregator.get_aggregated_summary()
        critical = self.aggregator.get_critical_alerts()

        return {
            "statistics": stats,
            "recent_summary": summary.to_dict(),
            "critical_alerts_count": len(critical),
            "enabled_channels": [c.value for c in self.notification_engine.enabled_channels]
        }
