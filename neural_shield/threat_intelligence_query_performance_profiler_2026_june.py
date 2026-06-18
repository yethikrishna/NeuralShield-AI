"""
Threat Intelligence Query Performance Profiler - NeuralShield-AI
June 2026 Production Implementation

Real, working performance profiling and optimization engine for threat intelligence queries.
Provides execution timing, bottleneck detection, and actionable optimization recommendations.
"""

import time
import threading
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Callable
from collections import defaultdict, deque
from enum import Enum
import statistics


class QueryPhase(Enum):
    """Query execution phases for fine-grained profiling."""
    INITIALIZATION = "initialization"
    DATA_FETCH = "data_fetch"
    PARSING = "parsing"
    ANALYSIS = "analysis"
    CORRELATION = "correlation"
    ENRICHMENT = "enrichment"
    SCORING = "scoring"
    AGGREGATION = "aggregation"
    SERIALIZATION = "serialization"
    TOTAL = "total"


@dataclass
class QueryProfile:
    """Complete profile of a single query execution."""
    query_id: str
    query_type: str
    start_time: float
    end_time: float = 0.0
    phase_timings: Dict[QueryPhase, float] = field(default_factory=dict)
    phase_start_times: Dict[QueryPhase, float] = field(default_factory=dict)
    memory_usage_mb: float = 0.0
    row_count: int = 0
    cache_hit: bool = False
    error_occurred: bool = False
    error_message: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def total_duration_ms(self) -> float:
        """Total query duration in milliseconds."""
        return (self.end_time - self.start_time) * 1000 if self.end_time > self.start_time else 0.0


@dataclass
class OptimizationRecommendation:
    """Actionable optimization recommendation."""
    recommendation_id: str
    severity: str  # low, medium, high, critical
    category: str
    message: str
    suggested_action: str
    expected_improvement_pct: float
    supporting_metrics: Dict[str, Any]


class ThreatIntelligenceQueryPerformanceProfiler:
    """
    Production-grade query performance profiler for threat intelligence operations.
    
    Features:
    - Real-time phase-level timing measurement
    - Historical performance baseline tracking
    - Automatic bottleneck detection
    - Data-driven optimization recommendations
    - Thread-safe concurrent query profiling
    - Performance anomaly detection
    """

    def __init__(self, 
                 baseline_window_size: int = 100,
                 anomaly_threshold_std: float = 2.0,
                 enable_memory_tracking: bool = True):
        """
        Initialize the performance profiler.
        
        Args:
            baseline_window_size: Number of queries to keep for baseline statistics
            anomaly_threshold_std: Standard deviations for anomaly detection
            enable_memory_tracking: Whether to track memory usage
        """
        self.baseline_window_size = baseline_window_size
        self.anomaly_threshold_std = anomaly_threshold_std
        self.enable_memory_tracking = enable_memory_tracking
        
        # Active query tracking
        self._active_queries: Dict[str, QueryProfile] = {}
        self._lock = threading.RLock()
        
        # Historical performance data
        self._query_history: Dict[str, deque] = defaultdict(
            lambda: deque(maxlen=baseline_window_size)
        )
        self._phase_history: Dict[QueryPhase, deque] = defaultdict(
            lambda: deque(maxlen=baseline_window_size)
        )
        
        # Performance statistics cache
        self._stats_cache: Dict[str, Any] = {}
        self._cache_timestamp = 0.0
        
        # Counters
        self.total_queries_profiled = 0
        self.slow_queries_detected = 0
        self.anomalies_detected = 0

    def start_query(self, query_type: str, **metadata) -> str:
        """
        Start profiling a new query.
        
        Args:
            query_type: Type of query being executed
            **metadata: Additional metadata about the query
            
        Returns:
            query_id: Unique identifier for the query
        """
        query_id = str(uuid.uuid4())
        
        with self._lock:
            profile = QueryProfile(
                query_id=query_id,
                query_type=query_type,
                start_time=time.time(),
                metadata=metadata
            )
            self._active_queries[query_id] = profile
            
        return query_id

    def start_phase(self, query_id: str, phase: QueryPhase) -> bool:
        """
        Mark the start of a specific execution phase.
        
        Args:
            query_id: The query identifier
            phase: The phase starting
            
        Returns:
            success: True if phase was started successfully
        """
        with self._lock:
            if query_id not in self._active_queries:
                return False
            
            profile = self._active_queries[query_id]
            profile.phase_start_times[phase] = time.time()
            
        return True

    def end_phase(self, query_id: str, phase: QueryPhase) -> Optional[float]:
        """
        Mark the end of a specific execution phase.
        
        Args:
            query_id: The query identifier
            phase: The phase ending
            
        Returns:
            duration_ms: Phase duration in milliseconds or None if not found
        """
        with self._lock:
            if query_id not in self._active_queries:
                return None
            
            profile = self._active_queries[query_id]
            
            if phase not in profile.phase_start_times:
                return None
            
            end_time = time.time()
            start_time = profile.phase_start_times[phase]
            duration_ms = (end_time - start_time) * 1000
            
            profile.phase_timings[phase] = duration_ms
            
            # Record in phase history
            self._phase_history[phase].append(duration_ms)
            
        return duration_ms

    def end_query(self, query_id: str, 
                  row_count: int = 0,
                  cache_hit: bool = False,
                  error: Optional[str] = None,
                  **kwargs) -> Optional[QueryProfile]:
        """
        Complete query profiling and store results.
        
        Args:
            query_id: The query identifier
            row_count: Number of rows/results returned
            cache_hit: Whether result came from cache
            error: Error message if query failed
            **kwargs: Additional fields
            
        Returns:
            Complete query profile or None if not found
        """
        with self._lock:
            if query_id not in self._active_queries:
                return None
            
            profile = self._active_queries.pop(query_id)
            profile.end_time = time.time()
            profile.row_count = row_count
            profile.cache_hit = cache_hit
            
            if error:
                profile.error_occurred = True
                profile.error_message = error
            
            # Update metadata
            profile.metadata.update(kwargs)
            
            # Store in history
            self._query_history[profile.query_type].append(profile.total_duration_ms)
            
            # Update counters
            self.total_queries_profiled += 1
            
            # Check for slow query
            if profile.total_duration_ms > 1000:  # > 1 second
                self.slow_queries_detected += 1
            
            # Check for anomaly
            if self._is_performance_anomaly(profile):
                self.anomalies_detected += 1
            
        return profile

    def profile_function(self, query_type: str) -> Callable:
        """
        Decorator to automatically profile a function.
        
        Args:
            query_type: Type identifier for the query
            
        Returns:
            Decorated function with automatic profiling
        """
        def decorator(func: Callable) -> Callable:
            def wrapper(*args, **kwargs):
                query_id = self.start_query(
                    query_type=query_type,
                    function_name=func.__name__
                )
                
                try:
                    self.start_phase(query_id, QueryPhase.TOTAL)
                    result = func(*args, **kwargs)
                    self.end_phase(query_id, QueryPhase.TOTAL)
                    self.end_query(query_id, row_count=len(result) if hasattr(result, '__len__') else 0)
                    return result
                except Exception as e:
                    self.end_query(query_id, error=str(e))
                    raise
                    
            return wrapper
        return decorator

    def get_query_statistics(self, query_type: Optional[str] = None) -> Dict[str, Any]:
        """
        Get performance statistics for queries.
        
        Args:
            query_type: Optional filter for specific query type
            
        Returns:
            Dictionary of performance statistics
        """
        with self._lock:
            if query_type:
                durations = list(self._query_history.get(query_type, []))
            else:
                durations = []
                for qt_durations in self._query_history.values():
                    durations.extend(list(qt_durations))
            
            if not durations:
                return {
                    "count": 0,
                    "message": "No profiling data available"
                }
            
            return {
                "count": len(durations),
                "min_ms": round(min(durations), 2),
                "max_ms": round(max(durations), 2),
                "mean_ms": round(statistics.mean(durations), 2),
                "median_ms": round(statistics.median(durations), 2),
                "p50_ms": round(self._percentile(durations, 50), 2),
                "p95_ms": round(self._percentile(durations, 95), 2),
                "p99_ms": round(self._percentile(durations, 99), 2),
                "std_dev_ms": round(statistics.stdev(durations) if len(durations) > 1 else 0, 2)
            }

    def get_phase_statistics(self) -> Dict[str, Any]:
        """Get performance breakdown by execution phase."""
        results = {}
        
        with self._lock:
            for phase in QueryPhase:
                if phase == QueryPhase.TOTAL:
                    continue
                    
                timings = list(self._phase_history.get(phase, []))
                
                if timings:
                    results[phase.value] = {
                        "count": len(timings),
                        "avg_ms": round(statistics.mean(timings), 2),
                        "p95_ms": round(self._percentile(timings, 95), 2),
                        "total_contribution_pct": 0.0  # Calculated below
                    }
        
        # Calculate contribution percentages
        total_avg = sum(r["avg_ms"] for r in results.values())
        if total_avg > 0:
            for phase_data in results.values():
                phase_data["total_contribution_pct"] = round(
                    (phase_data["avg_ms"] / total_avg) * 100, 1
                )
        
        return results

    def detect_bottlenecks(self) -> List[Dict[str, Any]]:
        """
        Automatically detect performance bottlenecks based on phase data.
        
        Returns:
            List of detected bottlenecks with severity and details
        """
        phase_stats = self.get_phase_statistics()
        bottlenecks = []
        
        for phase_name, stats in phase_stats.items():
            severity = "low"
            
            # High contribution to total time (>30%)
            if stats["total_contribution_pct"] > 50:
                severity = "critical"
            elif stats["total_contribution_pct"] > 30:
                severity = "high"
            elif stats["total_contribution_pct"] > 20:
                severity = "medium"
            
            # High p95 latency
            if stats["p95_ms"] > 500:
                severity = "critical" if severity == "critical" else "high"
            
            if severity != "low" or stats["total_contribution_pct"] > 15:
                bottlenecks.append({
                    "phase": phase_name,
                    "severity": severity,
                    "avg_duration_ms": stats["avg_ms"],
                    "p95_duration_ms": stats["p95_ms"],
                    "contribution_pct": stats["total_contribution_pct"],
                    "sample_count": stats["count"]
                })
        
        return sorted(bottlenecks, key=lambda x: x["contribution_pct"], reverse=True)

    def generate_optimization_recommendations(self) -> List[OptimizationRecommendation]:
        """
        Generate actionable optimization recommendations based on profiling data.
        
        Returns:
            List of optimization recommendations
        """
        recommendations = []
        bottlenecks = self.detect_bottlenecks()
        query_stats = self.get_query_statistics()
        
        # Recommendation 1: Data fetch optimization
        for bottleneck in bottlenecks:
            if bottleneck["phase"] == "data_fetch" and bottleneck["severity"] in ["high", "critical"]:
                recommendations.append(OptimizationRecommendation(
                    recommendation_id=f"OPT-FETCH-{uuid.uuid4().hex[:8]}",
                    severity=bottleneck["severity"],
                    category="data_access",
                    message=f"Data fetch phase is contributing {bottleneck['contribution_pct']}% of total query time",
                    suggested_action="Implement query result caching, add database indexes, or consider data pre-aggregation",
                    expected_improvement_pct=min(40.0, bottleneck["contribution_pct"] * 0.6),
                    supporting_metrics=bottleneck
                ))
        
        # Recommendation 2: Correlation optimization
        for bottleneck in bottlenecks:
            if bottleneck["phase"] == "correlation" and bottleneck["severity"] in ["high", "critical"]:
                recommendations.append(OptimizationRecommendation(
                    recommendation_id=f"OPT-CORR-{uuid.uuid4().hex[:8]}",
                    severity=bottleneck["severity"],
                    category="algorithm",
                    message=f"Correlation phase taking {bottleneck['avg_duration_ms']}ms average",
                    suggested_action="Implement early termination, use bloom filters, or reduce correlation window size",
                    expected_improvement_pct=35.0,
                    supporting_metrics=bottleneck
                ))
        
        # Recommendation 3: Enrichment optimization
        for bottleneck in bottlenecks:
            if bottleneck["phase"] == "enrichment" and bottleneck["severity"] in ["medium", "high", "critical"]:
                recommendations.append(OptimizationRecommendation(
                    recommendation_id=f"OPT-ENRICH-{uuid.uuid4().hex[:8]}",
                    severity=bottleneck["severity"],
                    category="external_api",
                    message=f"Enrichment phase showing high latency at p95: {bottleneck['p95_duration_ms']}ms",
                    suggested_action="Implement enrichment caching, add circuit breakers, or batch enrichment requests",
                    expected_improvement_pct=25.0,
                    supporting_metrics=bottleneck
                ))
        
        # Recommendation 4: General caching recommendation
        if query_stats.get("count", 0) > 10 and not any(b["phase"] == "cache_hit" for b in bottlenecks):
            recommendations.append(OptimizationRecommendation(
                recommendation_id=f"OPT-CACHE-{uuid.uuid4().hex[:8]}",
                severity="medium",
                category="caching",
                message=f"Processed {query_stats['count']} queries with mean latency {query_stats.get('mean_ms', 0)}ms",
                suggested_action="Implement multi-level caching strategy (L1 memory, L2 Redis)",
                expected_improvement_pct=50.0,
                supporting_metrics=query_stats
            ))
        
        return recommendations

    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        return {
            "summary": {
                "total_queries_profiled": self.total_queries_profiled,
                "active_queries": len(self._active_queries),
                "slow_queries_detected": self.slow_queries_detected,
                "anomalies_detected": self.anomalies_detected,
                "query_types_tracked": len(self._query_history)
            },
            "query_statistics": self.get_query_statistics(),
            "phase_breakdown": self.get_phase_statistics(),
            "detected_bottlenecks": self.detect_bottlenecks(),
            "recommendations_count": len(self.generate_optimization_recommendations())
        }

    def _is_performance_anomaly(self, profile: QueryProfile) -> bool:
        """Check if query performance is anomalous compared to baseline."""
        history = list(self._query_history.get(profile.query_type, []))
        
        if len(history) < 10:
            return False
            
        baseline_mean = statistics.mean(history)
        baseline_std = statistics.stdev(history) if len(history) > 1 else 0
        
        if baseline_std == 0:
            return profile.total_duration_ms > baseline_mean * 2
            
        z_score = (profile.total_duration_ms - baseline_mean) / baseline_std
        return z_score > self.anomaly_threshold_std

    @staticmethod
    def _percentile(data: List[float], percentile: int) -> float:
        """Calculate percentile value from sorted data."""
        if not data:
            return 0.0
            
        sorted_data = sorted(data)
        k = (len(sorted_data) - 1) * (percentile / 100.0)
        f = int(k)
        c = f + 1 if f + 1 < len(sorted_data) else f
        
        if f == c:
            return sorted_data[f]
            
        return sorted_data[f] + (k - f) * (sorted_data[c] - sorted_data[f])
