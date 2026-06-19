"""
Threat Intelligence Feed Health & Quality Monitor
June 19, 2026 - Production Grade Implementation

Monitors and evaluates the health, quality, and reliability of threat intelligence feeds.
Core capabilities:
- Feed freshness monitoring (data age, update frequency)
- Feed availability tracking (uptime, latency, error rates)
- Feed quality scoring (duplicate rate, false positive rate, signal-to-noise)
- Feed coverage analysis (IOC types, threat categories, MITRE mapping)
- Feed performance metrics (processing time, throughput)
- Health alerting and degradation detection

Provides actionable insights for feed selection, optimization, and
threat intelligence operations management.
"""
import re
import math
import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set, Any
from datetime import datetime, timedelta
from enum import Enum
from collections import defaultdict, Counter
from statistics import mean, median, stdev


class FeedHealthStatus(Enum):
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    OFFLINE = "offline"


class FeedQualityTier(Enum):
    PREMIUM = "premium"
    STANDARD = "standard"
    BASIC = "basic"
    LOW_QUALITY = "low_quality"


@dataclass
class FeedMetrics:
    feed_name: str
    feed_url: str
    last_poll_time: datetime
    next_scheduled_poll: datetime
    total_records: int = 0
    new_records_since_last: int = 0
    duplicate_records: int = 0
    error_count: int = 0
    success_count: int = 0
    average_latency_ms: float = 0.0
    data_age_minutes: float = 0.0
    false_positive_indicators: int = 0
    ioc_type_distribution: Dict[str, int] = field(default_factory=dict)
    threat_category_distribution: Dict[str, int] = field(default_factory=dict)
    mitre_technique_coverage: Set[str] = field(default_factory=set)


@dataclass
class HealthAssessment:
    feed_name: str
    overall_score: float
    freshness_score: float
    availability_score: float
    quality_score: float
    coverage_score: float
    performance_score: float
    health_status: FeedHealthStatus
    quality_tier: FeedQualityTier
    recommendations: List[str]
    assessment_timestamp: datetime


class ThreatFeedHealthMonitor:
    """
    Production-grade threat intelligence feed health and quality monitor.
    Provides real-time monitoring, scoring, and alerting for feed operations.
    """

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.feed_metrics_store: Dict[str, FeedMetrics] = {}
        self.historical_data: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.alert_thresholds = {
            'freshness_minutes_warning': 120,
            'freshness_minutes_critical': 360,
            'availability_error_rate_warning': 0.1,
            'availability_error_rate_critical': 0.3,
            'duplicate_rate_warning': 0.3,
            'duplicate_rate_critical': 0.6,
            'latency_ms_warning': 5000,
            'latency_ms_critical': 15000
        }
        self.valid_ioc_types = {
            'ipv4', 'ipv6', 'domain', 'url', 'md5', 'sha1', 'sha256',
            'email', 'filename', 'filepath', 'mutex', 'registry'
        }
        self.valid_threat_categories = {
            'malware', 'phishing', 'botnet', 'ransomware', 'apt',
            'exploit', 'c2', 'scanner', 'spam', 'ddos'
        }

    def register_feed(self, feed_name: str, feed_url: str) -> bool:
        """
        Register a new threat feed for monitoring.
        Returns True if successfully registered.
        """
        if feed_name in self.feed_metrics_store:
            return False
        
        self.feed_metrics_store[feed_name] = FeedMetrics(
            feed_name=feed_name,
            feed_url=feed_url,
            last_poll_time=datetime.now(),
            next_scheduled_poll=datetime.now() + timedelta(minutes=30)
        )
        return True

    def record_poll_result(
        self,
        feed_name: str,
        records: List[Dict[str, Any]],
        latency_ms: float,
        success: bool,
        error_message: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Record the results of a feed poll operation.
        Calculates duplicates, freshness, and updates metrics.
        """
        if feed_name not in self.feed_metrics_store:
            raise ValueError(f"Feed {feed_name} not registered")

        metrics = self.feed_metrics_store[feed_name]
        poll_time = datetime.now()

        if success:
            metrics.success_count += 1
            
            # Calculate duplicates using content hashing
            record_hashes = set()
            duplicate_count = 0
            
            for record in records:
                record_str = str(sorted(record.items())).encode('utf-8')
                record_hash = hashlib.md5(record_str).hexdigest()
                if record_hash in record_hashes:
                    duplicate_count += 1
                record_hashes.add(record_hash)

            # Update metrics
            metrics.total_records += len(records)
            metrics.new_records_since_last = len(records) - duplicate_count
            metrics.duplicate_records += duplicate_count
            
            # Update latency with EWMA
            if metrics.average_latency_ms == 0:
                metrics.average_latency_ms = latency_ms
            else:
                metrics.average_latency_ms = (
                    0.7 * metrics.average_latency_ms + 0.3 * latency_ms
                )

            # Analyze IOC types and categories
            type_counts: Dict[str, int] = defaultdict(int)
            category_counts: Dict[str, int] = defaultdict(int)
            mitre_techniques = set()

            for record in records:
                ioc_type = record.get('ioc_type', 'unknown').lower()
                if ioc_type in self.valid_ioc_types:
                    type_counts[ioc_type] += 1
                
                category = record.get('threat_category', 'unknown').lower()
                if category in self.valid_threat_categories:
                    category_counts[category] += 1
                
                mitre = record.get('mitre_technique')
                if mitre:
                    mitre_techniques.add(str(mitre))

            metrics.ioc_type_distribution = dict(type_counts)
            metrics.threat_category_distribution = dict(category_counts)
            metrics.mitre_technique_coverage = mitre_techniques

            # Calculate data age
            if records:
                timestamps = []
                for record in records:
                    ts = record.get('timestamp') or record.get('last_seen')
                    if isinstance(ts, datetime):
                        timestamps.append(ts)
                    elif isinstance(ts, str):
                        try:
                            parsed = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                            timestamps.append(parsed)
                        except (ValueError, TypeError):
                            pass
                
                if timestamps:
                    avg_record_time = mean([t.timestamp() for t in timestamps])
                    avg_datetime = datetime.fromtimestamp(avg_record_time)
                    metrics.data_age_minutes = (
                        poll_time - avg_datetime
                    ).total_seconds() / 60

            metrics.last_poll_time = poll_time
            metrics.next_scheduled_poll = poll_time + timedelta(minutes=30)

        else:
            metrics.error_count += 1

        # Store historical data point
        self.historical_data[feed_name].append({
            'timestamp': poll_time.isoformat(),
            'record_count': len(records) if success else 0,
            'latency_ms': latency_ms,
            'success': success,
            'error': error_message
        })

        # Keep only last 100 data points per feed
        if len(self.historical_data[feed_name]) > 100:
            self.historical_data[feed_name] = self.historical_data[feed_name][-100:]

        return {
            'feed_name': feed_name,
            'poll_time': poll_time.isoformat(),
            'records_processed': len(records) if success else 0,
            'duplicates_found': duplicate_count if success else 0,
            'latency_ms': latency_ms,
            'success': success
        }

    def calculate_freshness_score(self, feed_name: str) -> Tuple[float, List[str]]:
        """
        Calculate freshness score (0-100) based on data age and update regularity.
        Lower data age = higher score.
        """
        metrics = self.feed_metrics_store.get(feed_name)
        if not metrics:
            return 0.0, ["Feed not found"]

        issues = []
        score = 100.0

        # Penalty for data age
        data_age = metrics.data_age_minutes
        if data_age > self.alert_thresholds['freshness_minutes_critical']:
            score -= 60
            issues.append(f"CRITICAL: Data age {data_age:.1f}min exceeds 6hr threshold")
        elif data_age > self.alert_thresholds['freshness_minutes_warning']:
            score -= 25
            issues.append(f"WARNING: Data age {data_age:.1f}min exceeds 2hr threshold")
        elif data_age > 60:
            score -= 10
            issues.append(f"Data age {data_age:.1f}min exceeds 1hr")

        # Penalty for no new records
        if metrics.new_records_since_last == 0 and metrics.total_records > 0:
            score -= 20
            issues.append("No new records since last poll")

        return max(0.0, score), issues

    def calculate_availability_score(self, feed_name: str) -> Tuple[float, List[str]]:
        """
        Calculate availability score (0-100) based on success rate and latency.
        """
        metrics = self.feed_metrics_store.get(feed_name)
        if not metrics:
            return 0.0, ["Feed not found"]

        issues = []
        score = 100.0

        total_polls = metrics.success_count + metrics.error_count
        if total_polls > 0:
            error_rate = metrics.error_count / total_polls
            
            if error_rate > self.alert_thresholds['availability_error_rate_critical']:
                score -= 70
                issues.append(f"CRITICAL: Error rate {error_rate:.1%} exceeds 30% threshold")
            elif error_rate > self.alert_thresholds['availability_error_rate_warning']:
                score -= 30
                issues.append(f"WARNING: Error rate {error_rate:.1%} exceeds 10% threshold")
            elif error_rate > 0.02:
                score -= 10
                issues.append(f"Error rate {error_rate:.1%} observed")

        # Latency penalty
        latency = metrics.average_latency_ms
        if latency > self.alert_thresholds['latency_ms_critical']:
            score -= 40
            issues.append(f"CRITICAL: Average latency {latency:.0f}ms exceeds 15s threshold")
        elif latency > self.alert_thresholds['latency_ms_warning']:
            score -= 15
            issues.append(f"WARNING: Average latency {latency:.0f}ms exceeds 5s threshold")

        return max(0.0, score), issues

    def calculate_quality_score(self, feed_name: str) -> Tuple[float, List[str]]:
        """
        Calculate quality score (0-100) based on duplicate rate and signal quality.
        """
        metrics = self.feed_metrics_store.get(feed_name)
        if not metrics:
            return 0.0, ["Feed not found"]

        issues = []
        score = 100.0

        # Duplicate rate penalty
        if metrics.total_records > 0:
            duplicate_rate = metrics.duplicate_records / metrics.total_records
            
            if duplicate_rate > self.alert_thresholds['duplicate_rate_critical']:
                score -= 50
                issues.append(f"CRITICAL: Duplicate rate {duplicate_rate:.1%} exceeds 60% threshold")
            elif duplicate_rate > self.alert_thresholds['duplicate_rate_warning']:
                score -= 20
                issues.append(f"WARNING: Duplicate rate {duplicate_rate:.1%} exceeds 30% threshold")
            elif duplicate_rate > 0.1:
                score -= 10
                issues.append(f"Duplicate rate {duplicate_rate:.1%} observed")

        # False positive indicators penalty
        if metrics.false_positive_indicators > 0:
            fp_ratio = metrics.false_positive_indicators / max(1, metrics.total_records)
            score -= min(30, fp_ratio * 100)
            if fp_ratio > 0.05:
                issues.append(f"High false positive indicators: {fp_ratio:.1%}")

        return max(0.0, score), issues

    def calculate_coverage_score(self, feed_name: str) -> Tuple[float, List[str]]:
        """
        Calculate coverage score (0-100) based on IOC types and categories covered.
        """
        metrics = self.feed_metrics_store.get(feed_name)
        if not metrics:
            return 0.0, ["Feed not found"]

        issues = []
        score = 100.0

        # IOC type coverage
        ioc_types_covered = len([
            t for t in metrics.ioc_type_distribution.keys()
            if t in self.valid_ioc_types
        ])
        ioc_coverage_ratio = ioc_types_covered / len(self.valid_ioc_types)
        
        if ioc_coverage_ratio < 0.1:
            score -= 40
            issues.append("Very limited IOC type coverage")
        elif ioc_coverage_ratio < 0.3:
            score -= 15
            issues.append("Limited IOC type diversity")

        # Threat category coverage
        categories_covered = len([
            c for c in metrics.threat_category_distribution.keys()
            if c in self.valid_threat_categories
        ])
        category_coverage_ratio = categories_covered / len(self.valid_threat_categories)
        
        if category_coverage_ratio < 0.1:
            score -= 30
            issues.append("Very limited threat category coverage")
        elif category_coverage_ratio < 0.2:
            score -= 10
            issues.append("Limited threat category diversity")

        # MITRE coverage bonus
        if len(metrics.mitre_technique_coverage) >= 5:
            score = min(100, score + 10)

        return max(0.0, score), issues

    def calculate_performance_score(self, feed_name: str) -> Tuple[float, List[str]]:
        """
        Calculate performance score based on throughput and consistency.
        """
        metrics = self.feed_metrics_store.get(feed_name)
        if not metrics:
            return 0.0, ["Feed not found"]

        issues = []
        score = 100.0

        # Consistency check using historical data
        history = self.historical_data.get(feed_name, [])
        if len(history) >= 5:
            record_counts = [h['record_count'] for h in history if h['success']]
            if len(record_counts) >= 3:
                try:
                    cv = stdev(record_counts) / mean(record_counts) if mean(record_counts) > 0 else 0
                    if cv > 2.0:
                        score -= 25
                        issues.append("High variance in record counts indicates instability")
                    elif cv > 1.0:
                        score -= 10
                except (ZeroDivisionError, StatisticsError):
                    pass

        return max(0.0, score), issues

    def assess_feed_health(self, feed_name: str) -> HealthAssessment:
        """
        Perform comprehensive health assessment for a feed.
        Returns complete assessment with scores and recommendations.
        """
        freshness_score, freshness_issues = self.calculate_freshness_score(feed_name)
        availability_score, availability_issues = self.calculate_availability_score(feed_name)
        quality_score, quality_issues = self.calculate_quality_score(feed_name)
        coverage_score, coverage_issues = self.calculate_coverage_score(feed_name)
        performance_score, performance_issues = self.calculate_performance_score(feed_name)

        # Weighted overall score
        weights = {
            'freshness': 0.25,
            'availability': 0.30,
            'quality': 0.25,
            'coverage': 0.10,
            'performance': 0.10
        }

        overall_score = (
            freshness_score * weights['freshness'] +
            availability_score * weights['availability'] +
            quality_score * weights['quality'] +
            coverage_score * weights['coverage'] +
            performance_score * weights['performance']
        )

        # Determine health status
        if overall_score >= 80:
            health_status = FeedHealthStatus.HEALTHY
        elif overall_score >= 60:
            health_status = FeedHealthStatus.DEGRADED
        elif overall_score >= 40:
            health_status = FeedHealthStatus.UNHEALTHY
        else:
            health_status = FeedHealthStatus.OFFLINE

        # Determine quality tier
        if overall_score >= 90:
            quality_tier = FeedQualityTier.PREMIUM
        elif overall_score >= 75:
            quality_tier = FeedQualityTier.STANDARD
        elif overall_score >= 55:
            quality_tier = FeedQualityTier.BASIC
        else:
            quality_tier = FeedQualityTier.LOW_QUALITY

        # Compile recommendations
        all_issues = (
            freshness_issues + availability_issues + 
            quality_issues + coverage_issues + performance_issues
        )
        
        recommendations = []
        for issue in all_issues:
            if 'CRITICAL' in issue:
                recommendations.append(f"IMMEDIATE ACTION: {issue}")
            elif 'WARNING' in issue:
                recommendations.append(f"INVESTIGATE: {issue}")
            else:
                recommendations.append(f"MONITOR: {issue}")

        if not recommendations:
            recommendations.append("Feed operating within normal parameters")

        return HealthAssessment(
            feed_name=feed_name,
            overall_score=round(overall_score, 2),
            freshness_score=round(freshness_score, 2),
            availability_score=round(availability_score, 2),
            quality_score=round(quality_score, 2),
            coverage_score=round(coverage_score, 2),
            performance_score=round(performance_score, 2),
            health_status=health_status,
            quality_tier=quality_tier,
            recommendations=recommendations,
            assessment_timestamp=datetime.now()
        )

    def get_all_feeds_summary(self) -> Dict[str, Any]:
        """
        Get summary dashboard of all monitored feeds.
        """
        assessments = {}
        for feed_name in self.feed_metrics_store.keys():
            assessments[feed_name] = self.assess_feed_health(feed_name)

        status_counts = Counter(a.health_status.value for a in assessments.values())
        tier_counts = Counter(a.quality_tier.value for a in assessments.values())

        return {
            'total_feeds_monitored': len(self.feed_metrics_store),
            'health_status_distribution': dict(status_counts),
            'quality_tier_distribution': dict(tier_counts),
            'average_overall_score': mean([a.overall_score for a in assessments.values()]) if assessments else 0,
            'feed_assessments': {
                name: {
                    'overall_score': a.overall_score,
                    'health_status': a.health_status.value,
                    'quality_tier': a.quality_tier.value,
                    'recommendations_count': len(a.recommendations)
                }
                for name, a in assessments.items()
            },
            'summary_timestamp': datetime.now().isoformat()
        }
