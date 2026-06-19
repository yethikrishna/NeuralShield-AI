"""
Threat Intelligence Threat Feed Health Monitor
Production-grade health monitoring for threat intelligence feeds

Monitors:
- Feed latency and response time
- Data freshness and staleness detection
- Data quality and schema validation
- Feed availability and uptime
- Error rate tracking
- Automatic alerting on degradation
"""

import time
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import json
import threading
from collections import deque, defaultdict

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeedHealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    STALE = "stale"


class FeedQualityIssue(Enum):
    MISSING_FIELDS = "missing_required_fields"
    INVALID_FORMAT = "invalid_data_format"
    DUPLICATE_ENTRIES = "duplicate_entries"
    LOW_ENTROPY = "low_data_entropy"
    SCHEMA_MISMATCH = "schema_mismatch"
    EMPTY_FEED = "empty_feed"


@dataclass
class FeedHealthMetrics:
    feed_name: str
    status: FeedHealthStatus = FeedHealthStatus.HEALTHY
    last_check_time: datetime = field(default_factory=datetime.utcnow)
    last_successful_pull: Optional[datetime] = None
    average_latency_ms: float = 0.0
    latency_history: deque = field(default_factory=lambda: deque(maxlen=100))
    success_rate: float = 100.0
    consecutive_failures: int = 0
    total_requests: int = 0
    failed_requests: int = 0
    data_freshness_minutes: float = 0.0
    entry_count: int = 0
    duplicate_count: int = 0
    quality_issues: List[FeedQualityIssue] = field(default_factory=list)
    error_messages: List[str] = field(default_factory=list)
    uptime_percentage: float = 100.0


@dataclass
class FeedConfiguration:
    feed_name: str
    feed_url: str
    expected_update_interval_minutes: int = 60
    timeout_seconds: int = 30
    latency_threshold_warning_ms: int = 1000
    latency_threshold_critical_ms: int = 5000
    freshness_threshold_warning_minutes: int = 120
    freshness_threshold_critical_minutes: int = 360
    required_fields: List[str] = field(default_factory=lambda: ["ioc", "type", "timestamp"])
    min_entry_count: int = 1


class ThreatFeedHealthMonitor:
    """
    Production-grade threat feed health monitoring system.
    
    Provides real-time monitoring of threat intelligence feed health
    with automatic degradation detection and alerting.
    """

    def __init__(self):
        self.feeds: Dict[str, FeedConfiguration] = {}
        self.metrics: Dict[str, FeedHealthMetrics] = {}
        self.alert_callbacks: List[callable] = []
        self._lock = threading.Lock()
        self._start_time = datetime.utcnow()

    def register_feed(self, config: FeedConfiguration) -> None:
        """Register a new threat feed for monitoring."""
        with self._lock:
            self.feeds[config.feed_name] = config
            self.metrics[config.feed_name] = FeedHealthMetrics(
                feed_name=config.feed_name
            )
            logger.info(f"Registered feed for monitoring: {config.feed_name}")

    def unregister_feed(self, feed_name: str) -> None:
        """Remove a feed from monitoring."""
        with self._lock:
            self.feeds.pop(feed_name, None)
            self.metrics.pop(feed_name, None)
            logger.info(f"Unregistered feed: {feed_name}")

    def check_feed_health(
        self, 
        feed_name: str, 
        feed_data: Optional[List[Dict]] = None,
        response_time_ms: Optional[float] = None,
        pull_successful: bool = True,
        error_message: Optional[str] = None
    ) -> FeedHealthMetrics:
        """
        Perform health check on a threat feed with actual data.
        
        Args:
            feed_name: Name of the feed to check
            feed_data: Actual feed entries received
            response_time_ms: Time taken to fetch feed
            pull_successful: Whether the feed pull succeeded
            error_message: Error details if pull failed
            
        Returns:
            Updated health metrics
        """
        if feed_name not in self.feeds:
            raise ValueError(f"Feed not registered: {feed_name}")

        config = self.feeds[feed_name]
        
        with self._lock:
            metrics = self.metrics[feed_name]
            metrics.last_check_time = datetime.utcnow()
            metrics.total_requests += 1

            # Update latency metrics
            if response_time_ms is not None:
                metrics.latency_history.append(response_time_ms)
                metrics.average_latency_ms = sum(metrics.latency_history) / len(metrics.latency_history)

            # Update success/failure metrics
            if pull_successful:
                metrics.last_successful_pull = datetime.utcnow()
                metrics.consecutive_failures = 0
            else:
                metrics.failed_requests += 1
                metrics.consecutive_failures += 1
                if error_message:
                    metrics.error_messages.append(f"{datetime.utcnow()}: {error_message}")
                    if len(metrics.error_messages) > 50:
                        metrics.error_messages = metrics.error_messages[-50:]

            # Calculate success rate
            if metrics.total_requests > 0:
                metrics.success_rate = ((metrics.total_requests - metrics.failed_requests) / 
                                       metrics.total_requests) * 100

            # Calculate uptime (simplified based on check window)
            metrics.uptime_percentage = metrics.success_rate

            # Analyze feed data if provided
            metrics.quality_issues = []
            if feed_data is not None and pull_successful:
                self._analyze_feed_data(metrics, config, feed_data)
            elif pull_successful and feed_data is None:
                # Successful pull but no data provided
                metrics.quality_issues.append(FeedQualityIssue.EMPTY_FEED)

            # Determine overall health status
            metrics.status = self._determine_health_status(metrics, config)

            # Trigger alerts if status degraded
            if metrics.status in (FeedHealthStatus.UNHEALTHY, FeedHealthStatus.OFFLINE, FeedHealthStatus.STALE):
                self._trigger_alerts(feed_name, metrics)

            return metrics

    def _analyze_feed_data(
        self, 
        metrics: FeedHealthMetrics, 
        config: FeedConfiguration, 
        feed_data: List[Dict]
    ) -> None:
        """Analyze feed data for quality issues."""
        metrics.entry_count = len(feed_data)

        if len(feed_data) < config.min_entry_count:
            metrics.quality_issues.append(FeedQualityIssue.EMPTY_FEED)

        # Check for required fields
        seen_hashes = set()
        metrics.duplicate_count = 0

        for entry in feed_data:
            # Check required fields
            missing_fields = [f for f in config.required_fields if f not in entry]
            if missing_fields and FeedQualityIssue.MISSING_FIELDS not in metrics.quality_issues:
                metrics.quality_issues.append(FeedQualityIssue.MISSING_FIELDS)

            # Check for duplicates using content hash
            entry_hash = hashlib.md5(json.dumps(entry, sort_keys=True).encode()).hexdigest()
            if entry_hash in seen_hashes:
                metrics.duplicate_count += 1
            else:
                seen_hashes.add(entry_hash)

        if metrics.duplicate_count > 0:
            metrics.quality_issues.append(FeedQualityIssue.DUPLICATE_ENTRIES)

        # Calculate data freshness based on most recent entry
        timestamps = []
        for entry in feed_data:
            if "timestamp" in entry:
                try:
                    if isinstance(entry["timestamp"], (int, float)):
                        ts = datetime.fromtimestamp(entry["timestamp"])
                    elif isinstance(entry["timestamp"], str):
                        ts = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
                    else:
                        continue
                    timestamps.append(ts)
                except (ValueError, TypeError):
                    continue

        if timestamps:
            latest_entry = max(timestamps)
            metrics.data_freshness_minutes = (datetime.utcnow() - latest_entry).total_seconds() / 60
        else:
            metrics.data_freshness_minutes = float('inf')

    def _determine_health_status(
        self, 
        metrics: FeedHealthMetrics, 
        config: FeedConfiguration
    ) -> FeedHealthStatus:
        """Determine overall health status based on metrics."""
        # Check for offline condition
        if metrics.consecutive_failures >= 3:
            return FeedHealthStatus.OFFLINE

        # Check for stale data
        if metrics.data_freshness_minutes > config.freshness_threshold_critical_minutes:
            return FeedHealthStatus.STALE

        # Check for unhealthy conditions
        unhealthy_conditions = [
            metrics.success_rate < 70,
            metrics.average_latency_ms > config.latency_threshold_critical_ms,
            len(metrics.quality_issues) >= 3,
            metrics.consecutive_failures >= 2
        ]
        if any(unhealthy_conditions):
            return FeedHealthStatus.UNHEALTHY

        # Check for degraded conditions
        degraded_conditions = [
            metrics.success_rate < 90,
            metrics.average_latency_ms > config.latency_threshold_warning_ms,
            metrics.data_freshness_minutes > config.freshness_threshold_warning_minutes,
            len(metrics.quality_issues) >= 1,
            metrics.consecutive_failures >= 1
        ]
        if any(degraded_conditions):
            return FeedHealthStatus.DEGRADED

        return FeedHealthStatus.HEALTHY

    def _trigger_alerts(self, feed_name: str, metrics: FeedHealthMetrics) -> None:
        """Trigger alert callbacks for unhealthy feeds."""
        alert_data = {
            "feed_name": feed_name,
            "status": metrics.status.value,
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                "success_rate": metrics.success_rate,
                "average_latency_ms": metrics.average_latency_ms,
                "consecutive_failures": metrics.consecutive_failures,
                "data_freshness_minutes": metrics.data_freshness_minutes,
                "quality_issues": [q.value for q in metrics.quality_issues]
            }
        }
        for callback in self.alert_callbacks:
            try:
                callback(alert_data)
            except Exception as e:
                logger.error(f"Alert callback failed: {e}")

    def register_alert_callback(self, callback: callable) -> None:
        """Register callback for health alerts."""
        self.alert_callbacks.append(callback)

    def get_feed_health(self, feed_name: str) -> Optional[FeedHealthMetrics]:
        """Get current health metrics for a feed."""
        with self._lock:
            return self.metrics.get(feed_name)

    def get_all_feeds_health(self) -> Dict[str, FeedHealthMetrics]:
        """Get health metrics for all monitored feeds."""
        with self._lock:
            return dict(self.metrics)

    def get_health_summary(self) -> Dict[str, Any]:
        """Get summary health report across all feeds."""
        with self._lock:
            status_counts = defaultdict(int)
            total_latency = 0.0
            total_success_rate = 0.0
            count = len(self.metrics)

            for metrics in self.metrics.values():
                status_counts[metrics.status.value] += 1
                total_latency += metrics.average_latency_ms
                total_success_rate += metrics.success_rate

            return {
                "summary_timestamp": datetime.utcnow().isoformat(),
                "monitoring_since": self._start_time.isoformat(),
                "total_feeds_monitored": count,
                "status_breakdown": dict(status_counts),
                "average_latency_all_feeds_ms": total_latency / count if count > 0 else 0,
                "average_success_rate": total_success_rate / count if count > 0 else 0,
                "unhealthy_feeds": [
                    name for name, m in self.metrics.items() 
                    if m.status in (FeedHealthStatus.UNHEALTHY, FeedHealthStatus.OFFLINE, FeedHealthStatus.STALE)
                ]
            }

    def generate_health_report(self) -> str:
        """Generate human-readable health report."""
        summary = self.get_health_summary()
        lines = [
            "=" * 60,
            "THREAT FEED HEALTH MONITOR - STATUS REPORT",
            "=" * 60,
            f"Generated: {summary['summary_timestamp']}",
            f"Monitoring Since: {summary['monitoring_since']}",
            f"Total Feeds Monitored: {summary['total_feeds_monitored']}",
            "",
            "Status Breakdown:",
        ]
        
        for status, count in summary['status_breakdown'].items():
            lines.append(f"  - {status.upper()}: {count}")
        
        lines.extend([
            "",
            f"Average Latency: {summary['average_latency_all_feeds_ms']:.2f}ms",
            f"Average Success Rate: {summary['average_success_rate']:.2f}%",
            "",
            "Individual Feed Status:",
            "-" * 60,
        ])

        for feed_name, metrics in self.metrics.items():
            lines.extend([
                f"\nFeed: {feed_name}",
                f"  Status: {metrics.status.value.upper()}",
                f"  Success Rate: {metrics.success_rate:.2f}%",
                f"  Avg Latency: {metrics.average_latency_ms:.2f}ms",
                f"  Data Freshness: {metrics.data_freshness_minutes:.1f} minutes",
                f"  Entries: {metrics.entry_count}",
                f"  Duplicates: {metrics.duplicate_count}",
                f"  Quality Issues: {[q.value for q in metrics.quality_issues]}"
            ])

        if summary['unhealthy_feeds']:
            lines.extend([
                "",
                "⚠️  UNHEALTHY FEEDS REQUIRING ATTENTION:",
                *[f"  - {name}" for name in summary['unhealthy_feeds']]
            ])

        return "\n".join(lines)
