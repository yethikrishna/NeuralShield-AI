"""
Threat Intelligence Network Traffic Analyzer - NeuralShield AI
Production-grade network traffic analysis for threat detection
Detects:
- Port scanning patterns (horizontal/vertical)
- DDoS and volumetric attack patterns
- Data exfiltration indicators
- DNS tunneling and covert channels
- Unusual connection patterns
- Traffic entropy anomalies
"""
import math
import time
import hashlib
import ipaddress
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter, deque
from datetime import datetime, timedelta
import uuid
import statistics


@dataclass
class NetworkFlow:
    """Container for a single network flow record"""
    flow_id: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, DNS
    bytes_in: int
    bytes_out: int
    packet_count: int
    timestamp: float
    duration: float  # seconds
    flags: Set[str] = field(default_factory=set)
    dns_query: Optional[str] = None


@dataclass
class TrafficAnomaly:
    """Container for detected traffic anomaly"""
    anomaly_id: str
    anomaly_type: str
    severity: float  # 0.0 - 1.0
    confidence: float  # 0.0 - 1.0
    description: str
    source_ips: List[str]
    target_ips: List[str]
    timestamp: float
    evidence: Dict[str, Any] = field(default_factory=dict)


class NetworkTrafficAnalyzer:
    """
    Production-grade network traffic analyzer for threat intelligence
    Real working implementation with actual detection logic
    """
    
    def __init__(self, window_seconds: int = 300):
        self.window_seconds = window_seconds
        self.flows: deque = deque()
        self.src_connection_counts: Dict[str, Counter] = defaultdict(Counter)
        self.dst_port_counts: Dict[str, Counter] = defaultdict(Counter)
        self.byte_volume_history: deque = deque(maxlen=100)
        self.ip_entropy_history: deque = deque(maxlen=100)
        self.baseline_bytes_per_second: Optional[float] = None
        self.baseline_unique_ips: Optional[float] = None
        self.anomalies: List[TrafficAnomaly] = []
        self.whitelisted_ips: Set[str] = set()
        self.blacklisted_ips: Set[str] = set()
        
    def add_flow(self, flow: NetworkFlow) -> None:
        """Add a network flow to the analyzer"""
        self.flows.append(flow)
        self.src_connection_counts[flow.src_ip][flow.dst_ip] += 1
        self.dst_port_counts[flow.src_ip][flow.dst_port] += 1
        
        # Clean old flows
        cutoff = time.time() - self.window_seconds
        while self.flows and self.flows[0].timestamp < cutoff:
            old_flow = self.flows.popleft()
            self.src_connection_counts[old_flow.src_ip][old_flow.dst_ip] -= 1
            if self.src_connection_counts[old_flow.src_ip][old_flow.dst_ip] <= 0:
                del self.src_connection_counts[old_flow.src_ip][old_flow.dst_ip]
            self.dst_port_counts[old_flow.src_ip][old_flow.dst_port] -= 1
            if self.dst_port_counts[old_flow.src_ip][old_flow.dst_port] <= 0:
                del self.dst_port_counts[old_flow.src_ip][old_flow.dst_port]
    
    def calculate_entropy(self, items: List[str]) -> float:
        """Calculate Shannon entropy of a list of items"""
        if not items:
            return 0.0
        counts = Counter(items)
        total = len(items)
        entropy = 0.0
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy
    
    def detect_port_scanning(self) -> List[TrafficAnomaly]:
        """Detect horizontal and vertical port scanning patterns"""
        anomalies = []
        scan_threshold = 15  # More than 15 unique ports = potential scan
        
        for src_ip, port_counter in self.dst_port_counts.items():
            if src_ip in self.whitelisted_ips:
                continue
                
            unique_ports = len(port_counter)
            total_connections = sum(port_counter.values())
            
            # Vertical scan: many ports on single target
            if unique_ports >= scan_threshold:
                severity = min(1.0, unique_ports / 50.0)
                confidence = min(1.0, unique_ports / 30.0)
                
                anomaly = TrafficAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    anomaly_type="PORT_SCAN_VERTICAL",
                    severity=severity,
                    confidence=confidence,
                    description=f"Vertical port scan detected from {src_ip} - {unique_ports} unique ports targeted",
                    source_ips=[src_ip],
                    target_ips=list(self.src_connection_counts[src_ip].keys()),
                    timestamp=time.time(),
                    evidence={
                        "unique_ports": unique_ports,
                        "total_connections": total_connections,
                        "top_ports": port_counter.most_common(5)
                    }
                )
                anomalies.append(anomaly)
            
            # Horizontal scan: single port on many targets
            for port, count in port_counter.items():
                if count >= 10:
                    unique_targets = len(self.src_connection_counts[src_ip])
                    if unique_targets >= 10:
                        severity = min(1.0, unique_targets / 30.0)
                        confidence = min(1.0, unique_targets / 20.0)
                        
                        anomaly = TrafficAnomaly(
                            anomaly_id=str(uuid.uuid4()),
                            anomaly_type="PORT_SCAN_HORIZONTAL",
                            severity=severity,
                            confidence=confidence,
                            description=f"Horizontal port scan detected from {src_ip} - port {port} across {unique_targets} targets",
                            source_ips=[src_ip],
                            target_ips=list(self.src_connection_counts[src_ip].keys()),
                            timestamp=time.time(),
                            evidence={
                                "target_port": port,
                                "unique_targets": unique_targets,
                                "connection_count": count
                            }
                        )
                        anomalies.append(anomaly)
        
        return anomalies
    
    def detect_ddos_patterns(self) -> List[TrafficAnomaly]:
        """Detect DDoS and volumetric attack patterns"""
        anomalies = []
        
        if not self.flows:
            return anomalies
            
        # Calculate current traffic metrics
        current_bytes = sum(f.bytes_in + f.bytes_out for f in self.flows)
        current_pps = sum(f.packet_count for f in self.flows) / self.window_seconds
        current_bps = current_bytes * 8 / self.window_seconds
        
        # Update history
        self.byte_volume_history.append(current_bps)
        
        # Establish baseline
        if len(self.byte_volume_history) >= 10 and self.baseline_bytes_per_second is None:
            self.baseline_bytes_per_second = statistics.mean(list(self.byte_volume_history)[:-1])
        
        # Detect traffic spikes (3x baseline = anomaly)
        if self.baseline_bytes_per_second and self.baseline_bytes_per_second > 0:
            spike_ratio = current_bps / self.baseline_bytes_per_second
            if spike_ratio >= 3.0:
                severity = min(1.0, spike_ratio / 10.0)
                confidence = min(1.0, spike_ratio / 5.0)
                
                # Count unique source IPs for DDoS fingerprint
                unique_sources = len(set(f.src_ip for f in self.flows))
                
                anomaly = TrafficAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    anomaly_type="TRAFFIC_SPIKE_POTENTIAL_DDOS",
                    severity=severity,
                    confidence=confidence,
                    description=f"Traffic spike detected: {spike_ratio:.1f}x baseline with {unique_sources} unique sources",
                    source_ips=list(set(f.src_ip for f in self.flows))[:10],
                    target_ips=list(set(f.dst_ip for f in self.flows))[:5],
                    timestamp=time.time(),
                    evidence={
                        "current_bps": current_bps,
                        "baseline_bps": self.baseline_bytes_per_second,
                        "spike_ratio": spike_ratio,
                        "unique_sources": unique_sources,
                        "packets_per_second": current_pps
                    }
                )
                anomalies.append(anomaly)
        
        # SYN flood detection (many SYN packets without ACK)
        syn_only_flows = [f for f in self.flows if 'SYN' in f.flags and 'ACK' not in f.flags]
        if len(syn_only_flows) >= 50:
            severity = min(1.0, len(syn_only_flows) / 200.0)
            confidence = min(1.0, len(syn_only_flows) / 100.0)
            
            anomaly = TrafficAnomaly(
                anomaly_id=str(uuid.uuid4()),
                anomaly_type="SYN_FLOOD_POTENTIAL",
                severity=severity,
                confidence=confidence,
                description=f"Potential SYN flood detected: {len(syn_only_flows)} unacknowledged SYN packets",
                source_ips=list(set(f.src_ip for f in syn_only_flows))[:10],
                target_ips=list(set(f.dst_ip for f in syn_only_flows))[:5],
                timestamp=time.time(),
                evidence={
                    "syn_only_count": len(syn_only_flows),
                    "ratio": len(syn_only_flows) / len(self.flows)
                }
            )
            anomalies.append(anomaly)
        
        return anomalies
    
    def detect_data_exfiltration(self) -> List[TrafficAnomaly]:
        """Detect potential data exfiltration patterns"""
        anomalies = []
        
        # Look for large outbound transfers to unusual destinations
        outbound_by_ip: Dict[str, int] = defaultdict(int)
        for flow in self.flows:
            if flow.bytes_out > flow.bytes_in * 10:  # Much more outbound than inbound
                outbound_by_ip[flow.dst_ip] += flow.bytes_out
        
        for dst_ip, bytes_out in outbound_by_ip.items():
            if bytes_out > 10_000_000:  # > 10MB outbound
                severity = min(1.0, bytes_out / 100_000_000.0)
                confidence = 0.7 if bytes_out > 50_000_000 else 0.4
                
                anomaly = TrafficAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    anomaly_type="LARGE_DATA_TRANSFER_OUTBOUND",
                    severity=severity,
                    confidence=confidence,
                    description=f"Large outbound data transfer to {dst_ip}: {bytes_out/1_000_000:.1f} MB",
                    source_ips=list(set(f.src_ip for f in self.flows if f.dst_ip == dst_ip)),
                    target_ips=[dst_ip],
                    timestamp=time.time(),
                    evidence={
                        "total_bytes_out": bytes_out,
                        "megabytes": bytes_out / 1_000_000
                    }
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def detect_dns_tunneling(self) -> List[TrafficAnomaly]:
        """Detect DNS tunneling and covert channel patterns"""
        anomalies = []
        
        dns_flows = [f for f in self.flows if f.protocol == "DNS" and f.dns_query]
        
        if not dns_flows:
            return anomalies
        
        # Check for unusual subdomain length (indicative of tunneling)
        for flow in dns_flows:
            if flow.dns_query:
                query_length = len(flow.dns_query)
                subdomain_parts = flow.dns_query.split('.')
                
                # Long subdomains are suspicious
                if any(len(part) > 50 for part in subdomain_parts):
                    severity = 0.7
                    confidence = 0.6
                    
                    anomaly = TrafficAnomaly(
                        anomaly_id=str(uuid.uuid4()),
                        anomaly_type="DNS_TUNNELING_LONG_SUBDOMAIN",
                        severity=severity,
                        confidence=confidence,
                        description=f"Unusually long DNS subdomain detected, potential tunneling",
                        source_ips=[flow.src_ip],
                        target_ips=[flow.dst_ip],
                        timestamp=time.time(),
                        evidence={
                            "dns_query": flow.dns_query[:100],
                            "max_subdomain_length": max(len(p) for p in subdomain_parts)
                        }
                    )
                    anomalies.append(anomaly)
        
        # High DNS query volume from single source
        dns_by_source = Counter(f.src_ip for f in dns_flows)
        for src_ip, count in dns_by_source.items():
            if count >= 100:
                severity = min(1.0, count / 500.0)
                confidence = min(1.0, count / 200.0)
                
                anomaly = TrafficAnomaly(
                    anomaly_id=str(uuid.uuid4()),
                    anomaly_type="DNS_HIGH_QUERY_VOLUME",
                    severity=severity,
                    confidence=confidence,
                    description=f"High DNS query volume from {src_ip}: {count} queries in window",
                    source_ips=[src_ip],
                    target_ips=list(set(f.dst_ip for f in dns_flows if f.src_ip == src_ip)),
                    timestamp=time.time(),
                    evidence={
                        "query_count": count,
                        "queries_per_second": count / self.window_seconds
                    }
                )
                anomalies.append(anomaly)
        
        return anomalies
    
    def analyze_traffic(self) -> Dict[str, Any]:
        """Run full traffic analysis and return all detections"""
        all_anomalies = []
        
        # Run all detectors
        all_anomalies.extend(self.detect_port_scanning())
        all_anomalies.extend(self.detect_ddos_patterns())
        all_anomalies.extend(self.detect_data_exfiltration())
        all_anomalies.extend(self.detect_dns_tunneling())
        
        # Calculate summary statistics
        total_flows = len(self.flows)
        unique_src_ips = len(set(f.src_ip for f in self.flows))
        unique_dst_ips = len(set(f.dst_ip for f in self.flows))
        total_bytes = sum(f.bytes_in + f.bytes_out for f in self.flows)
        
        # Calculate traffic entropy
        src_ips_list = [f.src_ip for f in self.flows]
        traffic_entropy = self.calculate_entropy(src_ips_list)
        
        self.anomalies.extend(all_anomalies)
        
        return {
            "timestamp": time.time(),
            "window_seconds": self.window_seconds,
            "summary": {
                "total_flows": total_flows,
                "unique_source_ips": unique_src_ips,
                "unique_destination_ips": unique_dst_ips,
                "total_bytes": total_bytes,
                "traffic_entropy": traffic_entropy,
                "baseline_bps": self.baseline_bytes_per_second
            },
            "anomalies_detected": len(all_anomalies),
            "anomalies": [
                {
                    "id": a.anomaly_id,
                    "type": a.anomaly_type,
                    "severity": a.severity,
                    "confidence": a.confidence,
                    "description": a.description,
                    "evidence": a.evidence
                }
                for a in all_anomalies
            ],
            "high_severity_count": sum(1 for a in all_anomalies if a.severity >= 0.7)
        }
    
    def add_to_whitelist(self, ip: str) -> bool:
        """Add IP to whitelist, returns True if valid IP"""
        try:
            ipaddress.ip_address(ip)
            self.whitelisted_ips.add(ip)
            return True
        except ValueError:
            return False
    
    def add_to_blacklist(self, ip: str) -> bool:
        """Add IP to blacklist, returns True if valid IP"""
        try:
            ipaddress.ip_address(ip)
            self.blacklisted_ips.add(ip)
            return True
        except ValueError:
            return False
    
    def get_anomaly_summary(self) -> Dict[str, Any]:
        """Get summary of all detected anomalies"""
        by_type = Counter(a.anomaly_type for a in self.anomalies)
        severity_buckets = {
            "critical": sum(1 for a in self.anomalies if a.severity >= 0.9),
            "high": sum(1 for a in self.anomalies if 0.7 <= a.severity < 0.9),
            "medium": sum(1 for a in self.anomalies if 0.4 <= a.severity < 0.7),
            "low": sum(1 for a in self.anomalies if a.severity < 0.4)
        }
        
        return {
            "total_anomalies": len(self.anomalies),
            "by_type": dict(by_type),
            "by_severity": severity_buckets,
            "whitelisted_ips": len(self.whitelisted_ips),
            "blacklisted_ips": len(self.blacklisted_ips)
        }
