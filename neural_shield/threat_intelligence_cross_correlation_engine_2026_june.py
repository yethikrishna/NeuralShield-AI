"""
Threat Intelligence Cross-Correlation Engine - NeuralShield-AI
Production-Grade Implementation
June 2026
Real working cross-correlation engine that identifies relationships between IOCs
across multiple threat feeds and detects connected attack infrastructure.
"""
import hashlib
import time
import threading
from typing import Dict, List, Set, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, deque
from enum import Enum
class IOCTYPE(Enum):
    """Types of Indicators of Compromise."""
    IP_ADDRESS = "ip_address"
    DOMAIN = "domain"
    URL = "url"
    HASH_SHA256 = "hash_sha256"
    HASH_MD5 = "hash_md5"
    EMAIL = "email"
    CERTIFICATE = "certificate"
    ASN = "asn"
@dataclass
class IOCNode:
    """Represents a single IOC node in the correlation graph."""
    ioc_value: str
    ioc_type: IOCTYPE
    first_seen: float
    last_seen: float
    source_feeds: Set[str] = field(default_factory=set)
    threat_labels: Set[str] = field(default_factory=set)
    confidence: float = 0.0
    observation_count: int = 0
    
    def __post_init__(self):
        self.node_id = hashlib.sha256(
            f"{self.ioc_type.value}:{self.ioc_value}".encode()
        ).hexdigest()[:16]
@dataclass
class CorrelationEdge:
    """Represents a correlation relationship between two IOCs."""
    source_node_id: str
    target_node_id: str
    relationship_type: str
    strength: float  # 0.0 to 1.0
    first_observed: float
    last_observed: float
    evidence_count: int = 1
@dataclass
class CorrelationResult:
    """Result of a cross-correlation query."""
    root_ioc: str
    root_type: IOCTYPE
    connected_iocs: List[Dict[str, Any]]
    correlation_path: List[Tuple[str, str, str]]  # (from, to, relationship)
    threat_cluster_score: float
    affected_feeds: List[str]
    execution_time_ms: float
class ThreatIntelligenceCrossCorrelator:
    """
    Production-grade Cross-Correlation Engine for Threat Intelligence.
    
    Real implementation with:
    - Graph-based IOC relationship tracking
    - Multi-hop correlation discovery (BFS)
    - Threat cluster detection
    - Confidence-weighted edge scoring
    - Thread-safe operations
    - Performance statistics
    """
    
    def __init__(self, max_hops: int = 3, min_correlation_strength: float = 0.3):
        """
        Initialize cross-correlation engine.
        
        Args:
            max_hops: Maximum number of correlation hops to traverse
            min_correlation_strength: Minimum edge strength to consider valid
        """
        self.max_hops = max_hops
        self.min_correlation_strength = min_correlation_strength
        
        # Graph storage
        self.nodes: Dict[str, IOCNode] = {}  # node_id -> IOCNode
        self.edges: Dict[str, List[CorrelationEdge]] = defaultdict(list)  # node_id -> edges
        
        # Reverse lookup: ioc_value -> node_id
        self.ioc_to_node: Dict[Tuple[IOCTYPE, str], str] = {}
        
        # Statistics
        self.total_correlations = 0
        self.total_queries = 0
        self.avg_query_time = 0.0
        
        self._lock = threading.RLock()
    
    def add_ioc(
        self,
        ioc_value: str,
        ioc_type: IOCTYPE,
        source_feed: str,
        threat_label: Optional[str] = None,
        confidence: float = 0.5
    ) -> str:
        """
        Add or update an IOC node.
        
        Returns:
            node_id of the added/updated IOC
        """
        with self._lock:
            lookup_key = (ioc_type, ioc_value)
            
            if lookup_key in self.ioc_to_node:
                # Update existing node
                node_id = self.ioc_to_node[lookup_key]
                node = self.nodes[node_id]
                node.last_seen = time.time()
                node.source_feeds.add(source_feed)
                node.observation_count += 1
                if threat_label:
                    node.threat_labels.add(threat_label)
                node.confidence = max(node.confidence, confidence)
                return node_id
            
            # Create new node
            now = time.time()
            node = IOCNode(
                ioc_value=ioc_value,
                ioc_type=ioc_type,
                first_seen=now,
                last_seen=now,
                confidence=confidence,
                observation_count=1
            )
            node.source_feeds.add(source_feed)
            if threat_label:
                node.threat_labels.add(threat_label)
            
            self.nodes[node.node_id] = node
            self.ioc_to_node[lookup_key] = node.node_id
            
            return node.node_id
    
    def add_correlation(
        self,
        source_ioc: str,
        source_type: IOCTYPE,
        target_ioc: str,
        target_type: IOCTYPE,
        relationship_type: str,
        strength: float = 0.5
    ) -> bool:
        """
        Add a correlation edge between two IOCs.
        
        Returns:
            True if correlation was added successfully
        """
        with self._lock:
            # Ensure both nodes exist
            source_id = self.add_ioc(source_ioc, source_type, "correlation_engine")
            target_id = self.add_ioc(target_ioc, target_type, "correlation_engine")
            
            now = time.time()
            
            # Check if edge already exists
            existing_edge = None
            for edge in self.edges[source_id]:
                if edge.target_node_id == target_id and edge.relationship_type == relationship_type:
                    existing_edge = edge
                    break
            
            if existing_edge:
                # Update existing edge
                existing_edge.last_observed = now
                existing_edge.evidence_count += 1
                existing_edge.strength = min(1.0, existing_edge.strength + 0.1)
            else:
                # Create new edge
                edge = CorrelationEdge(
                    source_node_id=source_id,
                    target_node_id=target_id,
                    relationship_type=relationship_type,
                    strength=strength,
                    first_observed=now,
                    last_observed=now
                )
                self.edges[source_id].append(edge)
                
                # Add reverse edge for undirected correlation
                reverse_edge = CorrelationEdge(
                    source_node_id=target_id,
                    target_node_id=source_id,
                    relationship_type=relationship_type,
                    strength=strength,
                    first_observed=now,
                    last_observed=now
                )
                self.edges[target_id].append(reverse_edge)
                
                self.total_correlations += 1
            
            return True
    
    def correlate(
        self,
        ioc_value: str,
        ioc_type: IOCTYPE,
        max_hops: Optional[int] = None
    ) -> Optional[CorrelationResult]:
        """
        Perform BFS-based cross-correlation starting from an IOC.
        
        Returns:
            CorrelationResult with all connected IOCs and paths
        """
        start_time = time.time()
        max_hops = max_hops or self.max_hops
        
        with self._lock:
            self.total_queries += 1
            
            lookup_key = (ioc_type, ioc_value)
            if lookup_key not in self.ioc_to_node:
                return None
            
            root_node_id = self.ioc_to_node[lookup_key]
            root_node = self.nodes[root_node_id]
            
            # BFS traversal
            visited: Set[str] = set()
            queue: deque[Tuple[str, int, List[Tuple[str, str, str]]]] = deque()
            queue.append((root_node_id, 0, []))
            
            connected_iocs = []
            all_paths = []
            affected_feeds = set(root_node.source_feeds)
            
            while queue:
                current_id, current_hop, path_so_far = queue.popleft()
                
                if current_id in visited or current_hop > max_hops:
                    continue
                
                visited.add(current_id)
                current_node = self.nodes[current_id]
                
                if current_id != root_node_id:
                    connected_iocs.append({
                        "ioc_value": current_node.ioc_value,
                        "ioc_type": current_node.ioc_type.value,
                        "hops": current_hop,
                        "threat_labels": list(current_node.threat_labels),
                        "confidence": current_node.confidence,
                        "source_feeds": list(current_node.source_feeds)
                    })
                    affected_feeds.update(current_node.source_feeds)
                    all_paths.extend(path_so_far)
                
                # Explore neighbors
                for edge in self.edges[current_id]:
                    if edge.strength >= self.min_correlation_strength and edge.target_node_id not in visited:
                        new_path = path_so_far + [(
                            root_node.ioc_value if current_id == root_node_id else self.nodes[current_id].ioc_value,
                            self.nodes[edge.target_node_id].ioc_value,
                            edge.relationship_type
                        )]
                        queue.append((edge.target_node_id, current_hop + 1, new_path))
            
            # Calculate threat cluster score
            threat_count = sum(1 for ioc in connected_iocs if ioc["threat_labels"])
            cluster_score = (
                (len(connected_iocs) / max(1, max_hops * 10)) *
                (threat_count / max(1, len(connected_iocs))) *
                min(1.0, len(affected_feeds) / 5)
            ) if connected_iocs else 0.0
            
            execution_time = (time.time() - start_time) * 1000
            self.avg_query_time = (
                (self.avg_query_time * (self.total_queries - 1) + execution_time) / self.total_queries
            )
            
            return CorrelationResult(
                root_ioc=ioc_value,
                root_type=ioc_type,
                connected_iocs=connected_iocs,
                correlation_path=all_paths,
                threat_cluster_score=cluster_score,
                affected_feeds=list(affected_feeds),
                execution_time_ms=execution_time
            )
    
    def find_threat_clusters(self, min_cluster_size: int = 3) -> List[Dict[str, Any]]:
        """
        Find connected threat clusters in the correlation graph.
        
        Returns:
            List of detected threat clusters with metadata
        """
        with self._lock:
            visited: Set[str] = set()
            clusters = []
            
            for node_id in self.nodes:
                if node_id in visited:
                    continue
                
                # BFS to find connected component
                component: Set[str] = set()
                queue = deque([node_id])
                
                while queue:
                    current = queue.popleft()
                    if current in visited:
                        continue
                    visited.add(current)
                    component.add(current)
                    
                    for edge in self.edges[current]:
                        if edge.strength >= self.min_correlation_strength:
                            queue.append(edge.target_node_id)
                
                if len(component) >= min_cluster_size:
                    # Calculate cluster metrics
                    all_threats = set()
                    all_feeds = set()
                    avg_confidence = 0.0
                    
                    for nid in component:
                        node = self.nodes[nid]
                        all_threats.update(node.threat_labels)
                        all_feeds.update(node.source_feeds)
                        avg_confidence += node.confidence
                    
                    avg_confidence /= len(component)
                    
                    clusters.append({
                        "cluster_id": hashlib.md5(str(sorted(component)).encode()).hexdigest()[:8],
                        "size": len(component),
                        "threat_labels": list(all_threats),
                        "source_feeds": list(all_feeds),
                        "avg_confidence": avg_confidence,
                        "node_samples": [
                            self.nodes[nid].ioc_value for nid in list(component)[:5]
                        ]
                    })
            
            return clusters
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine performance statistics."""
        with self._lock:
            total_edges = sum(len(edges) for edges in self.edges.values()) // 2  # undirected
            
            return {
                "total_ioc_nodes": len(self.nodes),
                "total_correlation_edges": total_edges,
                "unique_ioc_types": len(set(node.ioc_type for node in self.nodes.values())),
                "unique_source_feeds": len(set(
                    feed for node in self.nodes.values() for feed in node.source_feeds
                )),
                "total_correlations_recorded": self.total_correlations,
                "total_correlation_queries": self.total_queries,
                "average_query_time_ms": self.avg_query_time,
                "max_hops_configured": self.max_hops,
                "min_correlation_strength": self.min_correlation_strength
            }
    
    def batch_add_from_feed(self, feed_data: List[Dict[str, Any]], feed_name: str) -> int:
        """
        Batch add IOCs from a threat feed.
        
        Args:
            feed_data: List of IOC dicts with 'value', 'type', 'label' keys
            feed_name: Name of the threat feed
            
        Returns:
            Number of IOCs successfully added
        """
        count = 0
        for item in feed_data:
            try:
                ioc_type = IOCTYPE(item.get("type", "ip_address"))
                self.add_ioc(
                    ioc_value=item["value"],
                    ioc_type=ioc_type,
                    source_feed=feed_name,
                    threat_label=item.get("label"),
                    confidence=item.get("confidence", 0.5)
                )
                count += 1
            except (ValueError, KeyError):
                continue
        return count
class AutoCorrelationDetector:
    """
    Automatic correlation detector that identifies implicit relationships
    between IOCs based on co-occurrence patterns.
    """
    
    def __init__(self, correlator: ThreatIntelligenceCrossCorrelator):
        self.correlator = correlator
        self.cooccurrence_window: Dict[str, List[Tuple[str, IOCTYPE, float]]] = defaultdict(list)
        self.window_seconds = 300  # 5 minute co-occurrence window
    
    def observe_ioc(self, ioc_value: str, ioc_type: IOCTYPE, source_context: str) -> None:
        """
        Observe an IOC and automatically detect correlations based on co-occurrence.
        """
        now = time.time()
        
        # Clean old observations
        self.cooccurrence_window[source_context] = [
            (v, t, ts) for v, t, ts in self.cooccurrence_window[source_context]
            if now - ts < self.window_seconds
        ]
        
        # Add correlations with all IOCs in same context window
        for existing_value, existing_type, _ in self.cooccurrence_window[source_context]:
            if existing_value != ioc_value:
                self.correlator.add_correlation(
                    source_ioc=existing_value,
                    source_type=existing_type,
                    target_ioc=ioc_value,
                    target_type=ioc_type,
                    relationship_type="cooccurrence",
                    strength=0.4
                )
        
        self.cooccurrence_window[source_context].append((ioc_value, ioc_type, now))
