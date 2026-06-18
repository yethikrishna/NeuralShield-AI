"""
Threat Intelligence Threat Hunting Query Optimizer
Production-Grade Implementation - June 19, 2026

This module provides intelligent threat hunting query optimization:
- Query parsing, validation, and syntax checking
- Performance optimization (index suggestions, query rewriting)
- Resource usage estimation and cost modeling
- Query caching strategies and TTL management
- Result set optimization (pagination, filtering, projection)
- Query history and performance analytics
"""
import re
import hashlib
import time
import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict, Counter


class QueryType(Enum):
    """Supported threat hunting query types."""
    IOC_SEARCH = "IOC_SEARCH"
    THREAT_ACTOR_PROFILE = "THREAT_ACTOR_PROFILE"
    NETWORK_TRAFFIC = "NETWORK_TRAFFIC"
    PROCESS_ANALYSIS = "PROCESS_ANALYSIS"
    LOG_CORRELATION = "LOG_CORRELATION"
    BEHAVIORAL_ANALYSIS = "BEHAVIORAL_ANALYSIS"
    INDICATOR_EXPANSION = "INDICATOR_EXPANSION"
    HISTORICAL_TREND = "HISTORICAL_TREND"


class OptimizationLevel(Enum):
    """Optimization aggressiveness levels."""
    CONSERVATIVE = "CONSERVATIVE"  # Only safe optimizations
    MODERATE = "MODERATE"        # Balanced optimizations
    AGGRESSIVE = "AGGRESSIVE"    # Maximum performance, riskier


class QueryStatus(Enum):
    """Query execution status."""
    PENDING = "PENDING"
    OPTIMIZING = "OPTIMIZING"
    EXECUTING = "EXECUTING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CACHED = "CACHED"


@dataclass
class QueryCostEstimate:
    """Estimated resource costs for query execution."""
    estimated_rows_scanned: int
    estimated_execution_time_ms: int
    estimated_memory_mb: int
    estimated_cpu_percent: float
    io_cost: float  # 0.0 - 1.0
    network_cost: float  # 0.0 - 1.0
    overall_cost_score: float  # 0.0 - 100.0
    cost_category: str  # LOW, MEDIUM, HIGH, CRITICAL


@dataclass
class OptimizationSuggestion:
    """Single optimization recommendation."""
    suggestion_type: str  # INDEX, REWRITE, FILTER, PROJECTION, CACHE
    description: str
    impact: str  # LOW, MEDIUM, HIGH
    implementation: str
    expected_improvement_pct: float
    applied: bool = False


@dataclass
class OptimizedQuery:
    """Fully optimized query result."""
    original_query: str
    optimized_query: str
    query_type: QueryType
    query_hash: str
    cost_estimate: QueryCostEstimate
    suggestions: List[OptimizationSuggestion]
    applied_optimizations: List[str]
    recommended_indexes: List[str]
    cache_strategy: Dict[str, Any]
    pagination_strategy: Dict[str, Any]
    validation_errors: List[str]
    optimization_timestamp: datetime
    execution_plan: Dict[str, Any] = field(default_factory=dict)


@dataclass
class QueryPerformanceMetrics:
    """Performance metrics for executed queries."""
    query_hash: str
    execution_count: int
    avg_execution_time_ms: float
    min_execution_time_ms: float
    max_execution_time_ms: float
    total_rows_returned: int
    cache_hit_count: int
    last_executed: datetime
    performance_trend: str  # IMPROVING, STABLE, DEGRADING


class ThreatHuntingQueryOptimizer:
    """
    Production-Grade Threat Hunting Query Optimizer
    
    Optimizes threat hunting queries for:
    - Maximum performance and minimal resource usage
    - Correctness and result accuracy
    - Cache efficiency
    - Scalability for large datasets
    """
    
    # Query patterns for different data sources
    QUERY_PATTERNS = {
        QueryType.IOC_SEARCH: [
            r"(ip|domain|hash|url)\s*[=:~]",
            r"indicator.*value",
            r"ioc.*search",
        ],
        QueryType.NETWORK_TRAFFIC: [
            r"src_ip|dst_ip|src_port|dst_port",
            r"network.*traffic",
            r"connection.*event",
        ],
        QueryType.PROCESS_ANALYSIS: [
            r"process.*name|command.*line",
            r"parent.*process|child.*process",
            r"process.*create",
        ],
        QueryType.LOG_CORRELATION: [
            r"join|correlate|union",
            r"log.*source",
            r"event.*id",
        ],
    }
    
    # Common expensive patterns to optimize
    EXPENSIVE_PATTERNS = [
        (r"\.+\*", "Unbounded wildcard search", 80),
        (r"NOT.*CONTAINS", "Negative contains search", 60),
        (r"regex|regexp", "Regular expression matching", 50),
        (r"ORDER BY.*DESC", "Unindexed sorting", 40),
        (r"DISTINCT", "Distinct aggregation", 45),
    ]
    
    # Recommended indexes for common queries
    RECOMMENDED_INDEXES = {
        "timestamp": ["@timestamp", "event_time", "timestamp"],
        "ip_address": ["src_ip", "dst_ip", "ip_address"],
        "indicator": ["indicator_value", "ioc_value", "hash_value"],
        "process": ["process_name", "command_line", "parent_process"],
        "network": ["src_port", "dst_port", "protocol"],
    }
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or self._default_config()
        self.query_cache: Dict[str, Dict[str, Any]] = {}
        self.query_history: List[Dict[str, Any]] = []
        self.performance_metrics: Dict[str, QueryPerformanceMetrics] = {}
        self.optimization_level = OptimizationLevel.MODERATE
        self.validation_rules = self._build_validation_rules()
        
    def _default_config(self) -> Dict[str, Any]:
        return {
            "max_query_length": 10000,
            "max_result_rows": 100000,
            "default_page_size": 1000,
            "cache_ttl_seconds": 3600,  # 1 hour
            "max_cache_entries": 1000,
            "cost_thresholds": {
                "LOW": 20.0,
                "MEDIUM": 40.0,
                "HIGH": 70.0,
                "CRITICAL": 90.0,
            },
            "optimization_weights": {
                "execution_time": 0.35,
                "memory_usage": 0.25,
                "io_cost": 0.25,
                "network_cost": 0.15,
            },
            "enable_auto_apply": True,
            "enable_query_caching": True,
            "enable_pagination": True,
        }
    
    def _build_validation_rules(self) -> Dict[str, Any]:
        """Build query validation rules."""
        return {
            "syntax": [
                (r"['\"].*['\"]", "Check for unclosed quotes"),
                (r"\(|\)", "Check for balanced parentheses"),
                (r"\[|\]", "Check for balanced brackets"),
            ],
            "security": [
                (r";.*--|;.*#", "Potential SQL injection pattern"),
                (r"DROP|DELETE|ALTER", "Destructive operations not allowed"),
                (r"EXEC|SYSTEM|SHELL", "Command execution patterns"),
            ],
            "performance": [
                (r"SELECT \*", "Avoid SELECT *, specify fields explicitly"),
                (r"WHERE 1=1", "Tautology condition detected"),
            ],
        }
    
    def generate_query_hash(self, query: str) -> str:
        """Generate deterministic hash for query caching."""
        normalized = self._normalize_query(query)
        return hashlib.sha256(normalized.encode()).hexdigest()[:16]
    
    def _normalize_query(self, query: str) -> str:
        """Normalize query for consistent hashing."""
        # Remove extra whitespace
        normalized = re.sub(r'\s+', ' ', query.strip())
        # Standardize case for keywords
        keywords = ['AND', 'OR', 'NOT', 'SELECT', 'FROM', 'WHERE', 'ORDER', 'BY', 'LIMIT']
        for kw in keywords:
            normalized = re.sub(rf'\b{kw.lower()}\b', kw, normalized)
        return normalized
    
    def detect_query_type(self, query: str) -> QueryType:
        """Detect the type of threat hunting query."""
        query_lower = query.lower()
        
        for query_type, patterns in self.QUERY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, query_lower, re.IGNORECASE):
                    return query_type
        
        return QueryType.BEHAVIORAL_ANALYSIS  # Default
    
    def validate_query(self, query: str) -> Tuple[bool, List[str]]:
        """
        Validate query for syntax, security, and performance issues.
        
        Returns: (is_valid, list_of_errors_and_warnings)
        """
        issues = []
        
        # Check length
        if len(query) > self.config["max_query_length"]:
            issues.append(f"Query exceeds maximum length ({self.config['max_query_length']} chars)")
        
        # Syntax validation
        if query.count("(") != query.count(")"):
            issues.append("Unbalanced parentheses detected")
        if query.count("[") != query.count("]"):
            issues.append("Unbalanced brackets detected")
        
        # Security checks
        for pattern, desc, _ in self.EXPENSIVE_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                issues.append(f"Security warning: {desc}")
        
        # Performance anti-patterns
        if "SELECT *" in query.upper():
            issues.append("Performance: Use explicit field projection instead of SELECT *")
        
        # Check for very broad queries
        if "WHERE 1=1" in query or "WHERE true" in query.lower():
            issues.append("Performance: Tautology condition may cause full table scan")
        
        return len(issues) == 0, issues
    
    def estimate_query_cost(self, query: str, query_type: QueryType) -> QueryCostEstimate:
        """
        Estimate resource costs for query execution.
        
        Uses heuristic modeling based on:
        - Query complexity and patterns
        - Data source size estimates
        - Index availability
        - Result set size
        """
        base_rows = 10000  # Base estimate
        
        # Adjust based on expensive patterns
        complexity_multiplier = 1.0
        for pattern, _, impact in self.EXPENSIVE_PATTERNS:
            if re.search(pattern, query, re.IGNORECASE):
                complexity_multiplier *= (1 + impact / 100)
        
        # Adjust based on query type
        type_multipliers = {
            QueryType.IOC_SEARCH: 0.5,
            QueryType.NETWORK_TRAFFIC: 1.2,
            QueryType.PROCESS_ANALYSIS: 0.8,
            QueryType.LOG_CORRELATION: 2.0,
            QueryType.BEHAVIORAL_ANALYSIS: 1.5,
            QueryType.THREAT_ACTOR_PROFILE: 0.6,
            QueryType.INDICATOR_EXPANSION: 1.0,
            QueryType.HISTORICAL_TREND: 1.8,
        }
        complexity_multiplier *= type_multipliers.get(query_type, 1.0)
        
        # Time range impact
        time_range_hours = self._extract_time_range(query)
        if time_range_hours > 168:  # > 1 week
            complexity_multiplier *= 2.0
        elif time_range_hours > 24:
            complexity_multiplier *= 1.3
        
        estimated_rows = int(base_rows * complexity_multiplier)
        
        # Calculate individual costs
        execution_time = int(estimated_rows * 0.05)  # ms
        memory_mb = int(estimated_rows * 0.001)
        io_cost = min(1.0, complexity_multiplier / 5.0)
        network_cost = min(1.0, estimated_rows / 100000)
        
        # Overall cost score (weighted)
        weights = self.config["optimization_weights"]
        time_score = min(100, execution_time / 10)
        memory_score = min(100, memory_mb / 10)
        
        overall_score = (
            (time_score * weights["execution_time"]) +
            (memory_score * weights["memory_usage"]) +
            (io_cost * 100 * weights["io_cost"]) +
            (network_cost * 100 * weights["network_cost"])
        )
        
        # Determine cost category
        thresholds = self.config["cost_thresholds"]
        if overall_score >= thresholds["CRITICAL"]:
            category = "CRITICAL"
        elif overall_score >= thresholds["HIGH"]:
            category = "HIGH"
        elif overall_score >= thresholds["MEDIUM"]:
            category = "MEDIUM"
        else:
            category = "LOW"
        
        return QueryCostEstimate(
            estimated_rows_scanned=estimated_rows,
            estimated_execution_time_ms=execution_time,
            estimated_memory_mb=memory_mb,
            estimated_cpu_percent=min(100.0, complexity_multiplier * 10),
            io_cost=io_cost,
            network_cost=network_cost,
            overall_cost_score=overall_score,
            cost_category=category,
        )
    
    def _extract_time_range(self, query: str) -> int:
        """Extract estimated time range from query in hours."""
        query_lower = query.lower()
        
        if "last 24h" in query_lower or "last 24 hours" in query_lower:
            return 24
        elif "last 7d" in query_lower or "last week" in query_lower:
            return 168
        elif "last 30d" in query_lower or "last month" in query_lower:
            return 720
        elif "last 1h" in query_lower:
            return 1
        else:
            return 24  # Default assumption
    
    def generate_optimization_suggestions(
        self, 
        query: str, 
        query_type: QueryType,
        cost_estimate: QueryCostEstimate
    ) -> List[OptimizationSuggestion]:
        """Generate optimization suggestions based on query analysis."""
        suggestions = []
        
        # 1. Index suggestions based on query type
        index_fields = self.RECOMMENDED_INDEXES.get(query_type.value.lower().split('_')[0], [])
        if index_fields and cost_estimate.overall_cost_score > 30:
            suggestions.append(OptimizationSuggestion(
                suggestion_type="INDEX",
                description=f"Add composite indexes for frequently filtered fields",
                impact="HIGH",
                implementation=f"Create indexes on: {', '.join(index_fields[:3])}",
                expected_improvement_pct=40.0,
            ))
        
        # 2. Query rewriting suggestions
        if "SELECT *" in query.upper():
            suggestions.append(OptimizationSuggestion(
                suggestion_type="PROJECTION",
                description="Replace SELECT * with explicit field list",
                impact="MEDIUM",
                implementation="Specify only needed fields to reduce data transfer",
                expected_improvement_pct=25.0,
            ))
        
        # 3. Pagination suggestion for large result sets
        if cost_estimate.estimated_rows_scanned > 10000:
            suggestions.append(OptimizationSuggestion(
                suggestion_type="PAGINATION",
                description="Implement result pagination",
                impact="HIGH",
                implementation=f"Use LIMIT {self.config['default_page_size']} OFFSET pattern",
                expected_improvement_pct=50.0,
            ))
        
        # 4. Caching suggestion
        if self.config["enable_query_caching"]:
            suggestions.append(OptimizationSuggestion(
                suggestion_type="CACHE",
                description="Enable query result caching",
                impact="MEDIUM",
                implementation=f"Cache results for {self.config['cache_ttl_seconds']//60} minutes",
                expected_improvement_pct=80.0,
            ))
        
        # 5. Filter optimization
        if cost_estimate.overall_cost_score > 50:
            suggestions.append(OptimizationSuggestion(
                suggestion_type="FILTER",
                description="Add more selective filters early in query",
                impact="HIGH",
                implementation="Apply timestamp and high-cardinality filters first",
                expected_improvement_pct=35.0,
            ))
        
        return suggestions
    
    def apply_optimizations(
        self, 
        query: str, 
        suggestions: List[OptimizationSuggestion]
    ) -> Tuple[str, List[str]]:
        """Apply safe optimizations automatically to query."""
        optimized = query
        applied = []
        
        if not self.config["enable_auto_apply"]:
            return optimized, applied
        
        # Apply pagination if not present
        if self.config["enable_pagination"] and "LIMIT" not in query.upper():
            page_size = self.config["default_page_size"]
            optimized = f"{optimized.rstrip(';')} LIMIT {page_size}"
            applied.append(f"Added LIMIT {page_size} pagination")
        
        # Normalize whitespace
        optimized = re.sub(r'\s+', ' ', optimized).strip()
        
        return optimized, applied
    
    def optimize_query(self, query: str) -> OptimizedQuery:
        """
        Main optimization pipeline.
        
        Performs full query analysis, validation, cost estimation,
        optimization suggestion generation, and automatic optimization application.
        """
        query_hash = self.generate_query_hash(query)
        query_type = self.detect_query_type(query)
        
        # Validate
        is_valid, validation_issues = self.validate_query(query)
        
        # Estimate cost
        cost_estimate = self.estimate_query_cost(query, query_type)
        
        # Generate suggestions
        suggestions = self.generate_optimization_suggestions(query, query_type, cost_estimate)
        
        # Apply optimizations
        optimized_query, applied = self.apply_optimizations(query, suggestions)
        
        # Build cache strategy
        cache_strategy = {
            "enabled": self.config["enable_query_caching"],
            "ttl_seconds": self.config["cache_ttl_seconds"],
            "cache_key": query_hash,
            "cacheable": cost_estimate.cost_category in ["HIGH", "CRITICAL"],
        }
        
        # Build pagination strategy
        pagination_strategy = {
            "enabled": self.config["enable_pagination"],
            "page_size": self.config["default_page_size"],
            "recommended": cost_estimate.estimated_rows_scanned > 5000,
        }
        
        # Extract recommended indexes
        recommended_indexes = []
        for s in suggestions:
            if s.suggestion_type == "INDEX":
                recommended_indexes.append(s.implementation)
        
        # Record in history
        self.query_history.append({
            "query_hash": query_hash,
            "timestamp": datetime.now().isoformat(),
            "query_type": query_type.value,
            "cost_score": cost_estimate.overall_cost_score,
        })
        
        return OptimizedQuery(
            original_query=query,
            optimized_query=optimized_query,
            query_type=query_type,
            query_hash=query_hash,
            cost_estimate=cost_estimate,
            suggestions=suggestions,
            applied_optimizations=applied,
            recommended_indexes=recommended_indexes,
            cache_strategy=cache_strategy,
            pagination_strategy=pagination_strategy,
            validation_errors=validation_issues,
            optimization_timestamp=datetime.now(),
        )
    
    def check_cache(self, query_hash: str) -> Optional[Dict[str, Any]]:
        """Check if query results are in cache and valid."""
        if query_hash not in self.query_cache:
            return None
        
        cached = self.query_cache[query_hash]
        cache_age = time.time() - cached["timestamp"]
        
        if cache_age > self.config["cache_ttl_seconds"]:
            del self.query_cache[query_hash]
            return None
        
        return cached
    
    def cache_results(self, query_hash: str, results: Any, metadata: Dict[str, Any] = None) -> None:
        """Cache query results."""
        if not self.config["enable_query_caching"]:
            return
        
        # Evict oldest if at capacity
        if len(self.query_cache) >= self.config["max_cache_entries"]:
            oldest_key = min(
                self.query_cache.keys(),
                key=lambda k: self.query_cache[k]["timestamp"]
            )
            del self.query_cache[oldest_key]
        
        self.query_cache[query_hash] = {
            "results": results,
            "timestamp": time.time(),
            "metadata": metadata or {},
        }
    
    def get_performance_report(self) -> Dict[str, Any]:
        """Generate performance analytics report."""
        if not self.query_history:
            return {"message": "No query history available"}
        
        cost_scores = [h["cost_score"] for h in self.query_history]
        query_types = Counter(h["query_type"] for h in self.query_history)
        
        return {
            "total_queries_optimized": len(self.query_history),
            "avg_cost_score": sum(cost_scores) / len(cost_scores),
            "min_cost_score": min(cost_scores),
            "max_cost_score": max(cost_scores),
            "query_type_distribution": dict(query_types),
            "cache_size": len(self.query_cache),
            "cache_hit_rate": 0.0,  # Would track with actual execution
        }
