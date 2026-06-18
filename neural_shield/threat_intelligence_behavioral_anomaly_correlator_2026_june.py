"""
Threat Intelligence Behavioral Anomaly Correlator - NeuralShield AI
Production-grade behavioral anomaly correlation across multiple threat intelligence sources

Correlates:
- Temporal anomaly patterns across feeds
- Behavioral sequence matching
- Cross-feed anomaly correlation
- Threat actor behavioral fingerprinting
"""
import math
import time
import hashlib
from typing import Dict, List, Tuple, Optional, Any, Set
from dataclasses import dataclass, field
from collections import defaultdict, Counter
from datetime import datetime, timedelta
import uuid


@dataclass
class AnomalyEvent:
    """Container for a single anomaly event from any feed"""
    event_id: str
    source_feed: str
    timestamp: float
    anomaly_type: str
    severity: float  # 0.0 - 1.0
    entity_id: str  # IP, domain, hash, user, etc.
    entity_type: str  # 'ip', 'domain', 'hash', 'user', 'process'
    attributes: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.7
    raw_data: Optional[Dict[str, Any]] = None


@dataclass
class CorrelatedAnomaly:
    """Result container for correlated anomalies"""
    correlation_id: str
    primary_anomaly: AnomalyEvent
    correlated_events: List[AnomalyEvent]
    correlation_score: float
    correlation_type: str  # 'temporal', 'behavioral', 'entity_based', 'pattern'
    threat_actor_fingerprint: Optional[str]
    attack_phase: str  # 'reconnaissance', 'initial_access', 'execution', 'persistence', etc.
    overall_severity: float
    confidence: float
    supporting_evidence: List[Dict[str, Any]]
    recommended_actions: List[str]
    mitre_techniques: List[str]


@dataclass
class BehavioralSequence:
    """Represents a sequence of behavioral events"""
    sequence_id: str
    events: List[AnomalyEvent]
    sequence_pattern: List[str]  # Ordered anomaly types
    time_window_seconds: float
    rarity_score: float
    known_attack_pattern: Optional[str]


class ThreatIntelligenceBehavioralAnomalyCorrelator:
    """
    Production-grade behavioral anomaly correlator for threat intelligence.
    
    Correlates anomalies across multiple threat feeds to detect:
    - Multi-stage attack patterns
    - Threat actor behavioral fingerprints
    - Temporal attack sequences
    - Cross-feed anomaly relationships
    - Emerging threat patterns
    """
    
    # MITRE ATT&CK phase mapping
    ATTACK_PHASES = {
        'reconnaissance': ['port_scan', 'osint', 'dns_enum', 'service_discovery'],
        'initial_access': ['phishing', 'exploit_attempt', 'brute_force', 'credential_stuffing'],
        'execution': ['malware_execution', 'script_execution', 'command_injection', 'lateral_movement'],
        'persistence': ['registry_modification', 'scheduled_task', 'service_install', 'startup_item'],
        'privilege_escalation': ['privesc_attempt', 'token_theft', 'uac_bypass'],
        'defense_evasion': ['obfuscation', 'anti_analysis', 'fileless', 'living_off_land'],
        'credential_access': ['credential_dumping', 'keylogging', 'password_cracking'],
        'discovery': ['network_scan', 'system_discovery', 'file_discovery'],
        'lateral_movement': ['smb_lateral', 'rdp_lateral', 'winrm_lateral', 'ssh_lateral'],
        'collection': ['data_collection', 'screen_capture', 'clipboard_capture'],
        'command_control': ['c2_traffic', 'dns_tunnel', 'domain_generation', 'beaconing'],
        'exfiltration': ['data_exfil', 'cloud_exfil', 'ftp_exfil'],
        'impact': ['ransomware', 'data_destruction', 'dos', 'defacement']
    }
    
    # Correlation weights
    TEMPORAL_CORRELATION_WEIGHT = 0.3
    ENTITY_CORRELATION_WEIGHT = 0.4
    BEHAVIORAL_SEQUENCE_WEIGHT = 0.5
    PATTERN_MATCH_WEIGHT = 0.35
    
    # Time windows (seconds)
    SHORT_TERM_WINDOW = 300  # 5 minutes
    MEDIUM_TERM_WINDOW = 3600  # 1 hour
    LONG_TERM_WINDOW = 86400  # 24 hours
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """Initialize the behavioral anomaly correlator"""
        self.config = config or {}
        self.anomaly_buffer: List[AnomalyEvent] = []
        self.entity_anomaly_map: Dict[str, List[AnomalyEvent]] = defaultdict(list)
        self.source_feed_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {'count': 0, 'severity_sum': 0.0}
        )
        self.known_patterns: Dict[str, List[str]] = self._initialize_known_patterns()
        self.correlation_history: List[CorrelatedAnomaly] = []
        
        # Statistics
        self._stats = {
            'total_anomalies_processed': 0,
            'correlations_found': 0,
            'multi_feed_correlations': 0,
            'high_severity_correlations': 0,
            'attack_chains_detected': 0
        }
    
    def _initialize_known_patterns(self) -> Dict[str, List[str]]:
        """Initialize known attack behavioral patterns"""
        return {
            'ransomware_chain': [
                'initial_access', 'execution', 'defense_evasion', 
                'credential_access', 'discovery', 'lateral_movement',
                'collection', 'impact'
            ],
            'phishing_breach': [
                'phishing', 'malware_execution', 'c2_traffic', 
                'credential_dumping', 'data_exfil'
            ],
            'brute_force_attack': [
                'service_discovery', 'brute_force', 'successful_login',
                'privesc_attempt', 'lateral_movement'
            ],
            'apt_attack_chain': [
                'reconnaissance', 'initial_access', 'persistence',
                'discovery', 'lateral_movement', 'collection', 'exfiltration'
            ]
        }
    
    def add_anomaly(self, anomaly: AnomalyEvent) -> None:
        """
        Add a single anomaly event to the correlator.
        
        Args:
            anomaly: AnomalyEvent to add
        """
        self.anomaly_buffer.append(anomaly)
        self.entity_anomaly_map[anomaly.entity_id].append(anomaly)
        self.source_feed_stats[anomaly.source_feed]['count'] += 1
        self.source_feed_stats[anomaly.source_feed]['severity_sum'] += anomaly.severity
        self._stats['total_anomalies_processed'] += 1
        
        # Maintain buffer size (keep last 10000 events)
        if len(self.anomaly_buffer) > 10000:
            self.anomaly_buffer = self.anomaly_buffer[-10000:]
    
    def add_anomalies_batch(self, anomalies: List[AnomalyEvent]) -> None:
        """Add a batch of anomalies efficiently"""
        for anomaly in anomalies:
            self.add_anomaly(anomaly)
    
    def _calculate_temporal_correlation(
        self, 
        event1: AnomalyEvent, 
        event2: AnomalyEvent,
        window_seconds: float
    ) -> float:
        """Calculate temporal correlation score between two events"""
        time_diff = abs(event1.timestamp - event2.timestamp)
        if time_diff > window_seconds:
            return 0.0
        
        # Exponential decay based on time difference
        decay_factor = math.exp(-time_diff / (window_seconds / 3))
        base_score = decay_factor * self.TEMPORAL_CORRELATION_WEIGHT
        
        # Bonus for same severity level
        severity_similarity = 1.0 - abs(event1.severity - event2.severity)
        return base_score * (0.7 + 0.3 * severity_similarity)
    
    def _calculate_entity_correlation(self, event1: AnomalyEvent, event2: AnomalyEvent) -> float:
        """Calculate correlation based on shared entities"""
        score = 0.0
        
        # Same entity
        if event1.entity_id == event2.entity_id:
            score += self.ENTITY_CORRELATION_WEIGHT
        
        # Same entity type
        if event1.entity_type == event2.entity_type:
            score += 0.1
        
        # Check for related entities in attributes
        event1_related = set(event1.attributes.get('related_entities', []))
        event2_related = set(event2.attributes.get('related_entities', []))
        if event1_related & event2_related:
            score += 0.15
        
        return min(score, self.ENTITY_CORRELATION_WEIGHT + 0.25)
    
    def _detect_behavioral_sequence(
        self, 
        events: List[AnomalyEvent],
        max_time_window: float = 3600
    ) -> List[BehavioralSequence]:
        """Detect meaningful behavioral sequences from event list"""
        if len(events) < 3:
            return []
        
        sequences = []
        sorted_events = sorted(events, key=lambda e: e.timestamp)
        
        # Sliding window analysis
        for start_idx in range(len(sorted_events) - 2):
            window_events = []
            window_start = sorted_events[start_idx].timestamp
            
            for event in sorted_events[start_idx:]:
                if event.timestamp - window_start <= max_time_window:
                    window_events.append(event)
                else:
                    break
            
            if len(window_events) >= 3:
                sequence_pattern = [e.anomaly_type for e in window_events]
                time_span = window_events[-1].timestamp - window_events[0].timestamp
                
                # Calculate rarity (based on pattern frequency)
                pattern_key = '|'.join(sequence_pattern)
                pattern_hash = hashlib.md5(pattern_key.encode()).hexdigest()[:8]
                
                # Check against known attack patterns
                matched_pattern = None
                for pattern_name, expected_types in self.known_patterns.items():
                    overlap = len(set(sequence_pattern) & set(expected_types))
                    if overlap / len(expected_types) >= 0.6:
                        matched_pattern = pattern_name
                        break
                
                rarity_score = 1.0 - (1.0 / (1.0 + len(window_events) * 0.5))
                
                sequences.append(BehavioralSequence(
                    sequence_id=f"seq_{pattern_hash}_{int(time.time())}",
                    events=window_events,
                    sequence_pattern=sequence_pattern,
                    time_window_seconds=time_span,
                    rarity_score=round(rarity_score, 3),
                    known_attack_pattern=matched_pattern
                ))
        
        return sequences
    
    def _determine_attack_phase(self, anomaly_types: List[str]) -> str:
        """Determine the most likely MITRE attack phase"""
        phase_scores = defaultdict(float)
        
        for anomaly_type in anomaly_types:
            for phase, indicators in self.ATTACK_PHASES.items():
                if anomaly_type in indicators:
                    phase_scores[phase] += 1.0
        
        if not phase_scores:
            return 'unknown'
        
        return max(phase_scores.items(), key=lambda x: x[1])[0]
    
    def _generate_mitre_techniques(self, correlated_events: List[AnomalyEvent]) -> List[str]:
        """Map anomaly types to MITRE ATT&CK techniques"""
        technique_mapping = {
            'port_scan': 'T1046',
            'phishing': 'T1566',
            'brute_force': 'T1110',
            'malware_execution': 'T1204',
            'command_injection': 'T1059',
            'registry_modification': 'T1112',
            'scheduled_task': 'T1053',
            'credential_dumping': 'T1003',
            'c2_traffic': 'T1071',
            'dns_tunnel': 'T1048',
            'data_exfil': 'T1041',
            'ransomware': 'T1486',
            'lateral_movement': 'T1021',
            'privesc_attempt': 'T1068'
        }
        
        techniques = set()
        for event in correlated_events:
            if event.anomaly_type in technique_mapping:
                techniques.add(technique_mapping[event.anomaly_type])
        
        return sorted(list(techniques))
    
    def _generate_recommendations(self, severity: float, attack_phase: str) -> List[str]:
        """Generate context-aware recommended actions"""
        recommendations = []
        
        if severity >= 0.8:
            recommendations.append("Immediate incident response activation")
            recommendations.append("Isolate affected systems from network")
        elif severity >= 0.6:
            recommendations.append("Escalate to security operations team")
            recommendations.append("Begin forensic data collection")
        
        # Phase-specific recommendations
        phase_actions = {
            'reconnaissance': ["Block suspicious source IP addresses", "Increase logging verbosity"],
            'initial_access': ["Reset compromised credentials", "Scan for malware on affected hosts"],
            'execution': ["Terminate suspicious processes", "Review and restore from clean backups"],
            'persistence': ["Review autorun locations and scheduled tasks", "Remove persistence mechanisms"],
            'credential_access': ["Force password resets for affected accounts", "Review privileged account activity"],
            'lateral_movement': ["Isolate compromised systems", "Review lateral movement paths"],
            'command_control': ["Block C2 communication channels", "Sinkhole malicious domains"],
            'exfiltration': ["Implement data loss prevention rules", "Review recent data transfers"],
            'impact': ["Activate disaster recovery plan", "Begin ransomware response procedures"]
        }
        
        if attack_phase in phase_actions:
            recommendations.extend(phase_actions[attack_phase])
        
        recommendations.append("Update threat intelligence signatures")
        recommendations.append("Document incident for lessons learned")
        
        return recommendations
    
    def find_correlations(
        self,
        time_window_seconds: Optional[float] = None,
        min_correlation_score: float = 0.3,
        entity_filter: Optional[str] = None
    ) -> List[CorrelatedAnomaly]:
        """
        Find correlated anomalies across all feeds.
        
        Args:
            time_window_seconds: Time window for temporal correlation (default: 1 hour)
            min_correlation_score: Minimum score to report
            entity_filter: Optional entity ID to filter correlations
        
        Returns:
            List of CorrelatedAnomaly results
        """
        window = time_window_seconds or self.MEDIUM_TERM_WINDOW
        correlations = []
        
        # Filter events if entity specified
        target_events = self.anomaly_buffer
        if entity_filter:
            target_events = [e for e in target_events if e.entity_id == entity_filter]
        
        if len(target_events) < 2:
            return []
        
        # Sort by timestamp
        sorted_events = sorted(target_events, key=lambda e: e.timestamp)
        
        # Process event pairs
        processed_pairs = set()
        
        for i, primary_event in enumerate(sorted_events):
            correlated = []
            total_score = 0.0
            
            for j, other_event in enumerate(sorted_events):
                if i == j:
                    continue
                
                pair_key = tuple(sorted([i, j]))
                if pair_key in processed_pairs:
                    continue
                
                # Calculate correlation scores
                temporal_score = self._calculate_temporal_correlation(
                    primary_event, other_event, window
                )
                entity_score = self._calculate_entity_correlation(
                    primary_event, other_event
                )
                
                combined_score = temporal_score + entity_score
                
                if combined_score >= min_correlation_score * 0.5:
                    correlated.append(other_event)
                    total_score += combined_score
                    processed_pairs.add(pair_key)
            
            if correlated:
                # Normalize score
                normalized_score = min(total_score / (len(correlated) + 1), 1.0)
                
                all_events = [primary_event] + correlated
                anomaly_types = [e.anomaly_type for e in all_events]
                
                # Detect sequences
                sequences = self._detect_behavioral_sequence(all_events, window)
                has_attack_pattern = any(s.known_attack_pattern for s in sequences)
                
                if has_attack_pattern:
                    normalized_score = min(normalized_score + 0.15, 1.0)
                    self._stats['attack_chains_detected'] += 1
                
                # Calculate overall severity (weighted average)
                total_severity = sum(e.severity * e.confidence for e in all_events)
                total_confidence = sum(e.confidence for e in all_events)
                overall_severity = total_severity / total_confidence if total_confidence > 0 else 0
                
                attack_phase = self._determine_attack_phase(anomaly_types)
                mitre_techniques = self._generate_mitre_techniques(all_events)
                
                # Generate threat actor fingerprint
                fingerprint_data = '|'.join(sorted(set(
                    f"{e.entity_type}:{e.anomaly_type}" for e in all_events
                )))
                threat_fingerprint = hashlib.sha256(fingerprint_data.encode()).hexdigest()[:16]
                
                # Determine correlation type
                corr_type = 'entity_based'
                if has_attack_pattern:
                    corr_type = 'behavioral'
                elif normalized_score > 0.6:
                    corr_type = 'pattern'
                
                correlation = CorrelatedAnomaly(
                    correlation_id=f"corr_{uuid.uuid4().hex[:12]}",
                    primary_anomaly=primary_event,
                    correlated_events=correlated,
                    correlation_score=round(normalized_score, 3),
                    correlation_type=corr_type,
                    threat_actor_fingerprint=threat_fingerprint,
                    attack_phase=attack_phase,
                    overall_severity=round(overall_severity, 3),
                    confidence=round(min(total_confidence / len(all_events), 1.0), 2),
                    supporting_evidence=[
                        {
                            'type': 'temporal_correlation',
                            'value': round(normalized_score * 0.4, 3),
                            'description': f'Events occurred within {window}s window'
                        },
                        {
                            'type': 'entity_correlation',
                            'value': round(normalized_score * 0.3, 3),
                            'description': 'Shared entities or attributes'
                        },
                        {
                            'type': 'behavioral_pattern',
                            'value': 0.15 if has_attack_pattern else 0.0,
                            'description': 'Matches known attack pattern' if has_attack_pattern else 'No known pattern match'
                        }
                    ],
                    recommended_actions=self._generate_recommendations(overall_severity, attack_phase),
                    mitre_techniques=mitre_techniques
                )
                
                correlations.append(correlation)
                self._stats['correlations_found'] += 1
                
                if len(set(e.source_feed for e in all_events)) > 1:
                    self._stats['multi_feed_correlations'] += 1
                
                if overall_severity >= 0.7:
                    self._stats['high_severity_correlations'] += 1
                
                self.correlation_history.append(correlation)
        
        # Sort by correlation score descending
        return sorted(correlations, key=lambda c: c.correlation_score, reverse=True)
    
    def get_entity_anomaly_history(self, entity_id: str) -> List[AnomalyEvent]:
        """Get all anomalies for a specific entity"""
        return sorted(
            self.entity_anomaly_map.get(entity_id, []),
            key=lambda e: e.timestamp,
            reverse=True
        )
    
    def get_correlation_statistics(self) -> Dict[str, Any]:
        """Get comprehensive correlation statistics"""
        feed_stats = {}
        for feed, stats in self.source_feed_stats.items():
            count = stats['count']
            feed_stats[feed] = {
                'anomaly_count': count,
                'average_severity': round(stats['severity_sum'] / count, 3) if count > 0 else 0
            }
        
        return {
            'processing_stats': self._stats,
            'feed_statistics': feed_stats,
            'unique_entities_tracked': len(self.entity_anomaly_map),
            'active_anomalies_in_buffer': len(self.anomaly_buffer),
            'correlation_types': Counter(c.correlation_type for c in self.correlation_history),
            'attack_phases_detected': Counter(c.attack_phase for c in self.correlation_history)
        }
    
    def generate_threat_summary(self) -> Dict[str, Any]:
        """Generate a concise threat summary report"""
        stats = self.get_correlation_statistics()
        high_severity = [c for c in self.correlation_history if c.overall_severity >= 0.7]
        
        return {
            'summary_timestamp': datetime.utcnow().isoformat(),
            'overall_threat_level': 'CRITICAL' if len(high_severity) > 3 else 
                                   'HIGH' if len(high_severity) > 0 else
                                   'MEDIUM' if stats['processing_stats']['correlations_found'] > 10 else 'LOW',
            'active_correlations': stats['processing_stats']['correlations_found'],
            'high_severity_incidents': len(high_severity),
            'attack_chains_detected': stats['processing_stats']['attack_chains_detected'],
            'entities_under_investigation': stats['unique_entities_tracked'],
            'top_attack_phases': dict(stats['attack_phases_detected'].most_common(3)),
            'recommended_priority_actions': [
                "Review all high-severity correlated anomalies",
                "Investigate detected attack chains for containment",
                "Update threat intelligence feeds with new IOCs"
            ]
        }
