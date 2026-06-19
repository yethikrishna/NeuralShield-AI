"""
Threat Intelligence Threat Feed Health Monitor
Production-grade threat feed health monitoring system

Monitors:
- Feed availability and uptime
- Data freshness and latency
- Data quality and completeness
- Error rates and anomalies
- Performance metrics
"""

import time
import json
import hashlib
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from enum import Enum
import threading
from collections import deque


class FeedStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"
    MAINTENANCE = "maintenance"


class HealthIssueType(Enum):
    LATENCY_HIGH = "high_latency"
    DATA_STALE = "stale_data"
    DATA_INCOMPLETE = "incomplete_data"
    ERROR_RATE_HIGH = "high_error_rate"
    CONNECTION_FAILURE = "connection_failure"
    AUTH_FAILURE = "authentication_failure"
    RATE_LIMITED = "rate_limited"
    DATA_CORRUPTED = "corrupted_data"


@dataclass
class FeedHealthMetrics:
    feed_id: str
    feed_name: str
    status: FeedStatus
    uptime_percent: float
    avg_latency_ms: float
    p95_latency_ms: float
    p99_latency_ms: float
    error_rate: float
    data_freshness_seconds: float
    last_successful_pull: datetime
    last_failed_pull: Optional[datetime]
    consecutive_failures: int
    data_completeness_score: float
    record_count: int
    duplicate_rate: float
    issues: List[HealthIssueType]

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["status"] = self.status.value
        data["issues"] = [issue.value for issue in self.issues]
        data["last_successful_pull"] = self.last_successful_pull.isoformat()
        if self.last_failed_pull:
            data["last_failed_pull"] = self.last_failed_pull.isoformat()
        return data


@dataclass
class FeedPullResult:
    success: bool
    latency_ms: float
    record_count: int
    error_message: Optional[str] = None
    data_hash: Optional[str] = None
    timestamp: datetime = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class ThreatFeedHealthMonitor:
    """
    Production-grade threat feed health monitoring system.
    
    Provides real-time monitoring, anomaly detection, and health scoring
    for threat intelligence feeds.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or self._default_config()
        self.feeds: Dict[str, Dict] = {}
        self.pull_history: Dict[str, deque] = {}
        self.health_metrics: Dict[str, FeedHealthMetrics] = {}
        self.alert_callbacks: List = []
        self.lock = threading.Lock()
        self.logger = self._setup_logger()
        self._initialize_default_feeds()

    def _default_config(self) -> Dict:
        return {
            "history_window_size": 100,
            "latency_warning_threshold_ms": 5000,
            "latency_critical_threshold_ms": 15000,
            "stale_data_threshold_seconds": 3600,
            "error_rate_warning_threshold": 0.1,
            "error_rate_critical_threshold": 0.3,
            "completeness_warning_threshold": 0.8,
            "uptime_warning_threshold": 0.95,
            "max_consecutive_failures": 5,
            "evaluation_window_minutes": 60
        }

    def _setup_logger(self) -> logging.Logger:
        logger = logging.getLogger("ThreatFeedHealthMonitor")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _initialize_default_feeds(self):
        """Initialize default threat feed configurations."""
        default_feeds = [
            {
                "feed_id": "abuse_ch_feodo",
                "feed_name": "Abuse.ch Feodo Tracker",
                "feed_url": "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
                "expected_interval_seconds": 300,
                "minimum_records": 100
            },
            {
                "feed_id": "abuse_ch_urlhaus",
                "feed_name": "Abuse.ch URLhaus",
                "feed_url": "https://urlhaus.abuse.ch/downloads/csv/",
                "expected_interval_seconds": 300,
                "minimum_records": 500
            },
            {
                "feed_id": "emerging_threats",
                "feed_name": "Emerging Threats Rules",
                "feed_url": "https://rules.emergingthreats.net/open/suricata/rules/",
                "expected_interval_seconds": 3600,
                "minimum_records": 1000
            },
            {
                "feed_id": "spamhaus_drop",
                "feed_name": "Spamhaus DROP List",
                "feed_url": "https://www.spamhaus.org/drop/drop.txt",
                "expected_interval_seconds": 86400,
                "minimum_records": 50
            },
            {
                "feed_id": "alien_otx",
                "feed_name": "AlienVault OTX",
                "feed_url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                "expected_interval_seconds": 600,
                "minimum_records": 10
            }
        ]
        
        for feed in default_feeds:
            self.register_feed(**feed)

    def register_feed(
        self,
        feed_id: str,
        feed_name: str,
        feed_url: str,
        expected_interval_seconds: int = 3600,
        minimum_records: int = 1,
        enabled: bool = True
    ) -> None:
        """Register a new threat feed for monitoring."""
        with self.lock:
            self.feeds[feed_id] = {
                "feed_id": feed_id,
                "feed_name": feed_name,
                "feed_url": feed_url,
                "expected_interval_seconds": expected_interval_seconds,
                "minimum_records": minimum_records,
                "enabled": enabled,
                "registered_at": datetime.utcnow()
            }
            self.pull_history[feed_id] = deque(
                maxlen=self.config["history_window_size"]
            )
            # Initialize with default health metrics
            self.health_metrics[feed_id] = FeedHealthMetrics(
                feed_id=feed_id,
                feed_name=feed_name,
                status=FeedStatus.MAINTENANCE,
                uptime_percent=100.0,
                avg_latency_ms=0.0,
                p95_latency_ms=0.0,
                p99_latency_ms=0.0,
                error_rate=0.0,
                data_freshness_seconds=0.0,
                last_successful_pull=datetime.utcnow(),
                last_failed_pull=None,
                consecutive_failures=0,
                data_completeness_score=1.0,
                record_count=0,
                duplicate_rate=0.0,
                issues=[]
            )
            self.logger.info(f"Registered feed: {feed_name} ({feed_id})")

    def record_pull_result(self, feed_id: str, result: FeedPullResult) -> None:
        """Record the result of a feed pull operation."""
        if feed_id not in self.feeds:
            self.logger.warning(f"Unknown feed: {feed_id}")
            return

        with self.lock:
            self.pull_history[feed_id].append(result)
            self._update_health_metrics(feed_id)
            
            if not result.success:
                self.logger.warning(
                    f"Feed pull failed: {feed_id} - {result.error_message}"
                )

    def _calculate_uptime(self, feed_id: str, window_minutes: int = 60) -> float:
        """Calculate uptime percentage for a feed."""
        if feed_id not in self.pull_history:
            return 100.0
            
        cutoff = datetime.utcnow() - timedelta(minutes=window_minutes)
        history = [
            r for r in self.pull_history[feed_id]
            if r.timestamp >= cutoff
        ]
        
        if not history:
            return 100.0
            
        successful = sum(1 for r in history if r.success)
        return (successful / len(history)) * 100

    def _calculate_latency_percentiles(
        self, feed_id: str
    ) -> Tuple[float, float, float]:
        """Calculate average, p95, and p99 latency."""
        if feed_id not in self.pull_history:
            return 0.0, 0.0, 0.0
            
        latencies = [
            r.latency_ms for r in self.pull_history[feed_id]
            if r.success and r.latency_ms > 0
        ]
        
        if not latencies:
            return 0.0, 0.0, 0.0
            
        latencies_sorted = sorted(latencies)
        n = len(latencies_sorted)
        
        avg = sum(latencies) / n
        p95 = latencies_sorted[int(n * 0.95)] if n > 0 else 0
        p99 = latencies_sorted[int(n * 0.99)] if n > 0 else 0
        
        return avg, p95, p99

    def _calculate_error_rate(self, feed_id: str) -> float:
        """Calculate error rate."""
        if feed_id not in self.pull_history:
            return 0.0
            
        history = list(self.pull_history[feed_id])
        if not history:
            return 0.0
            
        errors = sum(1 for r in history if not r.success)
        return errors / len(history)

    def _calculate_data_freshness(self, feed_id: str) -> float:
        """Calculate data freshness in seconds."""
        if feed_id not in self.pull_history:
            return float('inf')
            
        successful_pulls = [
            r for r in self.pull_history[feed_id] if r.success
        ]
        
        if not successful_pulls:
            return float('inf')
            
        last_pull = max(r.timestamp for r in successful_pulls)
        return (datetime.utcnow() - last_pull).total_seconds()

    def _calculate_completeness_score(
        self, feed_id: str, record_count: int
    ) -> float:
        """Calculate data completeness score (0-1)."""
        if feed_id not in self.feeds:
            return 1.0
            
        min_records = self.feeds[feed_id]["minimum_records"]
        return min(1.0, record_count / max(1, min_records))

    def _calculate_duplicate_rate(self, feed_id: str) -> float:
        """Calculate duplicate record rate."""
        if feed_id not in self.pull_history:
            return 0.0
            
        hashes = [
            r.data_hash for r in self.pull_history[feed_id]
            if r.success and r.data_hash
        ]
        
        if len(hashes) < 2:
            return 0.0
            
        unique_hashes = len(set(hashes))
        return 1.0 - (unique_hashes / len(hashes))

    def _count_consecutive_failures(self, feed_id: str) -> int:
        """Count consecutive failures."""
        if feed_id not in self.pull_history:
            return 0
            
        count = 0
        for result in reversed(list(self.pull_history[feed_id])):
            if result.success:
                break
            count += 1
        return count

    def _update_health_metrics(self, feed_id: str) -> None:
        """Update health metrics for a feed."""
        feed = self.feeds[feed_id]
        
        uptime = self._calculate_uptime(feed_id)
        avg_latency, p95_latency, p99_latency = self._calculate_latency_percentiles(feed_id)
        error_rate = self._calculate_error_rate(feed_id)
        freshness = self._calculate_data_freshness(feed_id)
        
        successful_pulls = [
            r for r in self.pull_history[feed_id] if r.success
        ]
        last_success = (
            max(r.timestamp for r in successful_pulls)
            if successful_pulls else datetime.utcfromtimestamp(0)
        )
        
        failed_pulls = [
            r for r in self.pull_history[feed_id] if not r.success
        ]
        last_failed = (
            max(r.timestamp for r in failed_pulls)
            if failed_pulls else None
        )
        
        latest_records = (
            successful_pulls[-1].record_count
            if successful_pulls else 0
        )
        
        completeness = self._calculate_completeness_score(feed_id, latest_records)
        duplicate_rate = self._calculate_duplicate_rate(feed_id)
        consecutive_failures = self._count_consecutive_failures(feed_id)
        
        issues = self._detect_health_issues(
            feed_id, uptime, avg_latency, error_rate,
            freshness, completeness, consecutive_failures
        )
        
        status = self._determine_overall_status(issues, consecutive_failures)
        
        metrics = FeedHealthMetrics(
            feed_id=feed_id,
            feed_name=feed["feed_name"],
            status=status,
            uptime_percent=uptime,
            avg_latency_ms=avg_latency,
            p95_latency_ms=p95_latency,
            p99_latency_ms=p99_latency,
            error_rate=error_rate,
            data_freshness_seconds=freshness,
            last_successful_pull=last_success,
            last_failed_pull=last_failed,
            consecutive_failures=consecutive_failures,
            data_completeness_score=completeness,
            record_count=latest_records,
            duplicate_rate=duplicate_rate,
            issues=issues
        )
        
        self.health_metrics[feed_id] = metrics

    def _detect_health_issues(
        self,
        feed_id: str,
        uptime: float,
        latency: float,
        error_rate: float,
        freshness: float,
        completeness: float,
        consecutive_failures: int
    ) -> List[HealthIssueType]:
        """Detect health issues based on metrics."""
        issues = []
        
        if latency > self.config["latency_critical_threshold_ms"]:
            issues.append(HealthIssueType.LATENCY_HIGH)
            
        if freshness > self.config["stale_data_threshold_seconds"]:
            issues.append(HealthIssueType.DATA_STALE)
            
        if completeness < self.config["completeness_warning_threshold"]:
            issues.append(HealthIssueType.DATA_INCOMPLETE)
            
        if error_rate > self.config["error_rate_warning_threshold"]:
            issues.append(HealthIssueType.ERROR_RATE_HIGH)
            
        if consecutive_failures >= self.config["max_consecutive_failures"]:
            issues.append(HealthIssueType.CONNECTION_FAILURE)
            
        return issues

    def _determine_overall_status(
        self, issues: List[HealthIssueType], consecutive_failures: int
    ) -> FeedStatus:
        """Determine overall feed status."""
        if consecutive_failures >= self.config["max_consecutive_failures"]:
            return FeedStatus.OFFLINE
            
        if not issues:
            return FeedStatus.HEALTHY
            
        critical_issues = {
            HealthIssueType.CONNECTION_FAILURE,
            HealthIssueType.DATA_CORRUPTED
        }
        
        if any(issue in critical_issues for issue in issues):
            return FeedStatus.UNHEALTHY
            
        return FeedStatus.DEGRADED

    def get_feed_health(self, feed_id: str) -> Optional[FeedHealthMetrics]:
        """Get health metrics for a specific feed."""
        with self.lock:
            return self.health_metrics.get(feed_id)

    def get_all_feeds_health(self) -> Dict[str, FeedHealthMetrics]:
        """Get health metrics for all feeds."""
        with self.lock:
            return dict(self.health_metrics)

    def get_overall_health_score(self) -> float:
        """Calculate overall health score (0-100)."""
        if not self.health_metrics:
            return 100.0
            
        scores = []
        for metrics in self.health_metrics.values():
            score = 100.0
            
            if metrics.status == FeedStatus.HEALTHY:
                score = 100.0
            elif metrics.status == FeedStatus.DEGRADED:
                score = 70.0
            elif metrics.status == FeedStatus.UNHEALTHY:
                score = 30.0
            else:
                score = 0.0
                
            scores.append(score)
            
        return sum(scores) / len(scores)

    def generate_health_report(self) -> Dict[str, Any]:
        """Generate comprehensive health report."""
        report = {
            "report_timestamp": datetime.utcnow().isoformat(),
            "overall_health_score": self.get_overall_health_score(),
            "total_feeds_monitored": len(self.feeds),
            "feeds_by_status": {},
            "feeds": []
        }
        
        for feed_id, metrics in self.health_metrics.items():
            status = metrics.status.value
            if status not in report["feeds_by_status"]:
                report["feeds_by_status"][status] = 0
            report["feeds_by_status"][status] += 1
            report["feeds"].append(metrics.to_dict())
            
        return report

    def simulate_feed_pull(
        self,
        feed_id: str,
        success: bool = True,
        latency_ms: float = 1000,
        record_count: int = 100,
        error_message: Optional[str] = None
    ) -> None:
        """Simulate a feed pull for testing."""
        data_hash = hashlib.md5(
            f"{feed_id}{datetime.utcnow().isoformat()}".encode()
        ).hexdigest() if success else None
        
        result = FeedPullResult(
            success=success,
            latency_ms=latency_ms,
            record_count=record_count,
            error_message=error_message,
            data_hash=data_hash
        )
        self.record_pull_result(feed_id, result)
