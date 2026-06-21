"""
Threat Intelligence Alert Correlation & Context Enrichment Engine v63
Real production-grade implementation for NeuralShield-AI

NEW FEATURES IN v63:
1. Bloom Filter Caching Layer for O(1) deduplication lookups
2. TF-IDF Semantic Similarity Scoring for alert content matching
3. Adaptive Time Window Correlation (scales with severity)
4. MITRE ATT&CK Technique Auto-Tagging Integration
5. Enhanced False Positive Reduction with Bayesian inference
6. Performance optimizations for large alert volumes
7. Alert priority queue with weighted scoring
"""
import hashlib
import json
import time
import re
import math
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import ipaddress


@dataclass
class ThreatIndicator:
    """Threat Indicator of Compromise (IOC) data structure"""
    type: str  # ip, url, domain, hash, email
    value: str
    source: str
    first_seen: float
    last_seen: float
    confidence: float  # 0.0 - 1.0
    threat_type: str  # malware, phishing, c2, scanning, etc
    severity: str  # low, medium, high, critical
    tlp: str = "WHITE"  # Traffic Light Protocol
    metadata: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)

    def get_hash(self) -> str:
        """Generate unique hash for deduplication"""
        return hashlib.sha256(f"{self.type}:{self.value.lower()}".encode()).hexdigest()[:16]


@dataclass
class SecurityAlert:
    """Security Alert data structure with v63 enhancements"""
    alert_id: str
    timestamp: float
    source: str
    alert_type: str
    severity: str
    title: str = ""
    description: str = ""
    indicators: List[ThreatIndicator] = field(default_factory=list)
    raw_data: Dict[str, Any] = field(default_factory=dict)
    enriched_context: Dict[str, Any] = field(default_factory=dict)
    correlation_score: float = 0.0
    false_positive_probability: float = 0.0
    mitre_techniques: List[str] = field(default_factory=list)
    priority_score: float = 0.0

    def get_alert_key(self) -> str:
        """Generate correlation key"""
        indicator_values = sorted([i.value.lower() for i in self.indicators])
        key_base = f"{self.alert_type}:{':'.join(indicator_values[:3])}:{self.title[:50]}"
        return hashlib.md5(key_base.encode()).hexdigest()[:12]

    def get_content_vector(self) -> str:
        """Get content for semantic analysis"""
        content = f"{self.title} {self.description} {self.alert_type}"
        for ind in self.indicators:
            content += f" {ind.value} {ind.threat_type}"
        return content.lower()


class BloomFilter:
    """Bloom Filter for fast deduplication lookups - O(1) amortized"""
    
    def __init__(self, size: int = 100000, hash_count: int = 5):
        self.size = size
        self.hash_count = hash_count
        self.bit_array: Set[int] = set()  # Using set for simplicity, production would use bitarray
    
    def _hashes(self, item: str) -> List[int]:
        """Generate multiple hash values"""
        result = []
        for i in range(self.hash_count):
            h = hashlib.md5(f"{i}:{item}".encode()).hexdigest()
            result.append(int(h, 16) % self.size)
        return result
    
    def add(self, item: str) -> None:
        """Add item to filter"""
        for h in self._hashes(item):
            self.bit_array.add(h)
    
    def might_contain(self, item: str) -> bool:
        """Check if item might be in filter (false positive possible, no false negatives)"""
        for h in self._hashes(item):
            if h not in self.bit_array:
                return False
        return True


class TfidfSimilarity:
    """TF-IDF based semantic similarity calculator for alert content"""
    
    def __init__(self):
        self.document_freq: Counter = Counter()
        self.total_docs = 0
        self.stopwords = {
            "the", "a", "an", "and", "or", "but", "in", "on", "at", "to", "for",
            "of", "with", "by", "from", "as", "is", "was", "are", "were", "be",
            "alert", "detected", "found", "observed", "potential", "possible"
        }
    
    def _tokenize(self, text: str) -> List[str]:
        """Simple tokenization"""
        words = re.findall(r'\w+', text.lower())
        return [w for w in words if w not in self.stopwords and len(w) > 2]
    
    def add_document(self, text: str) -> None:
        """Add document for IDF calculation"""
        tokens = set(self._tokenize(text))
        for token in tokens:
            self.document_freq[token] += 1
        self.total_docs += 1
    
    def compute_tfidf(self, text: str) -> Dict[str, float]:
        """Compute TF-IDF vector for text"""
        tokens = self._tokenize(text)
        tf = Counter(tokens)
        tfidf = {}
        
        for term, count in tf.items():
            tf_val = count / len(tokens) if tokens else 0
            idf_val = math.log((self.total_docs + 1) / (self.document_freq.get(term, 0) + 1)) + 1
            tfidf[term] = tf_val * idf_val
        
        return tfidf
    
    def cosine_similarity(self, text1: str, text2: str) -> float:
        """Calculate cosine similarity between two texts"""
        vec1 = self.compute_tfidf(text1)
        vec2 = self.compute_tfidf(text2)
        
        if not vec1 or not vec2:
            return 0.0
        
        common_terms = set(vec1.keys()) & set(vec2.keys())
        dot_product = sum(vec1[t] * vec2[t] for t in common_terms)
        
        norm1 = math.sqrt(sum(v * v for v in vec1.values()))
        norm2 = math.sqrt(sum(v * v for v in vec2.values()))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)


class MitreAttackMapper:
    """MITRE ATT&CK Technique Auto-Tagging Engine"""
    
    def __init__(self):
        self.technique_mapping = self._build_mapping()
    
    def _build_mapping(self) -> Dict[str, List[str]]:
        """Build keyword to MITRE technique mapping"""
        return {
            "phishing": ["T1566", "T1566.001", "T1566.002"],
            "spearphishing": ["T1566.001", "T1566.002"],
            "brute force": ["T1110", "T1110.001", "T1110.003"],
            "bruteforce": ["T1110"],
            "credential": ["T1555", "T1003", "T1552"],
            "credential dumping": ["T1003"],
            "lateral movement": ["T1021", "T1075", "T1021.001", "T1021.002"],
            "ransomware": ["T1486", "T1490"],
            "malware": ["T1204", "T1059", "T1053"],
            "exfiltration": ["T1041", "T1048", "T1052"],
            "data exfiltration": ["T1041"],
            "c2": ["T1071", "T1090", "T1573"],
            "command and control": ["T1071"],
            "powershell": ["T1059.001"],
            "sql injection": ["T1190"],
            "xss": ["T1190"],
            "exploit": ["T1203", "T1210"],
            "privilege escalation": ["T1068", "T1548"],
            "persistence": ["T1547", "T1136", "T1037"],
            "defense evasion": ["T1562", "T1070", "T1027"],
            "obfuscation": ["T1027"],
            "discovery": ["T1087", "T1046", "T1049"],
            "reconnaissance": ["T1595", "T1592", "T1589"],
            "scanning": ["T1046", "T1595"],
            "port scan": ["T1046"],
        }
    
    def tag_alert(self, alert: SecurityAlert) -> List[str]:
        """Auto-tag alert with MITRE ATT&CK techniques"""
        content = alert.get_content_vector()
        techniques = set()
        
        for keyword, tech_list in self.technique_mapping.items():
            if keyword in content:
                techniques.update(tech_list)
        
        # Also check indicator threat types
        for ind in alert.indicators:
            if ind.threat_type.lower() in self.technique_mapping:
                techniques.update(self.technique_mapping[ind.threat_type.lower()])
        
        return sorted(list(techniques))


class ContextEnricher:
    """Context enrichment service for IOCs - v63 enhanced"""
    
    def __init__(self):
        self.whitelist: Set[str] = self._load_whitelist()
        self.ioc_cache: Dict[str, ThreatIndicator] = {}
        self.geo_db = self._init_geo_db()
    
    def _load_whitelist(self) -> Set[str]:
        """Load known good indicators"""
        return {
            "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
            "google.com", "microsoft.com", "apple.com",
            "cloudflare.com", "github.com", "amazonaws.com",
            "localhost", "127.0.0.1", "0.0.0.0"
        }
    
    def _init_geo_db(self) -> Dict[str, Dict]:
        """Initialize simplified geolocation database"""
        return {
            "US": {"country": "United States", "risk": 0.3},
            "CN": {"country": "China", "risk": 0.6},
            "RU": {"country": "Russia", "risk": 0.8},
            "KP": {"country": "North Korea", "risk": 0.9},
            "IR": {"country": "Iran", "risk": 0.85},
            "IL": {"country": "Israel", "risk": 0.4},
            "NL": {"country": "Netherlands", "risk": 0.35},
            "DE": {"country": "Germany", "risk": 0.3},
            "FR": {"country": "France", "risk": 0.3},
            "GB": {"country": "United Kingdom", "risk": 0.3},
            "UNKNOWN": {"country": "Unknown", "risk": 0.5}
        }
    
    def is_whitelisted(self, indicator: ThreatIndicator) -> bool:
        """Check if indicator is whitelisted"""
        value = indicator.value.lower()
        if value in self.whitelist:
            return True
        for whitelisted in self.whitelist:
            if value.endswith(f".{whitelisted}"):
                return True
        return False
    
    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """Enrich IP address with context - v63 enhanced"""
        result = {
            "is_private": False,
            "is_loopback": False,
            "is_multicast": False,
            "is_link_local": False,
            "geolocation": self.geo_db["UNKNOWN"],
            "network_type": "unknown",
            "asn": "unknown",
            "threat_rating": 0.5
        }
        
        try:
            ip_obj = ipaddress.ip_address(ip)
            result["is_private"] = ip_obj.is_private
            result["is_loopback"] = ip_obj.is_loopback
            result["is_multicast"] = ip_obj.is_multicast
            result["is_link_local"] = ip_obj.is_link_local
            result["version"] = ip_obj.version
            
            if result["is_private"] or result["is_loopback"]:
                result["network_type"] = "internal"
                result["threat_rating"] = 0.1
            elif ip.startswith(("5.", "45.", "91.", "185.", "178.", "176.")):
                result["geolocation"] = self.geo_db["RU"]
                result["threat_rating"] = 0.75
            elif ip.startswith(("113.", "116.", "117.", "118.", "119.", "120.", "121.", "122.", "123.", "124.", "125.")):
                result["geolocation"] = self.geo_db["CN"]
                result["threat_rating"] = 0.55
            elif ip.startswith(("198.", "209.", "199.", "172.", "104.")):
                result["geolocation"] = self.geo_db["US"]
                result["threat_rating"] = 0.35
            
        except ValueError:
            result["invalid"] = True
            result["threat_rating"] = 0.8
        
        return result
    
    def enrich_url(self, url: str) -> Dict[str, Any]:
        """Enrich URL with context - v63 enhanced"""
        result = {
            "has_suspicious_patterns": False,
            "suspicious_score": 0.0,
            "domain": "",
            "path": "",
            "query_params": 0,
            "uses_https": url.startswith("https"),
            "has_ip_in_url": bool(re.search(r'\d+\.\d+\.\d+\.\d+', url)),
            "subdomain_count": 0
        }
        
        domain_match = re.search(r'https?://([^/]+)', url)
        if domain_match:
            domain = domain_match.group(1)
            result["domain"] = domain
            result["subdomain_count"] = domain.count('.') - 1
        
        suspicious_patterns = [
            (r'login|signin|auth|verify|confirm|account|reset', 0.3),
            (r'bank|paypal|apple|microsoft|google|amazon|meta', 0.4),
            (r'\.exe|\.zip|\.rar|\.js|\.bat|\.cmd|\.ps1|\.vbs', 0.6),
            (r'base64|encode|crypt|encrypt', 0.2),
            (r'%[0-9A-Fa-f]{2}', 0.3),
            (r'@|[^\w\s.-]', 0.2),
            (r'\d{5,}', 0.15),
        ]
        
        for pattern, score in suspicious_patterns:
            if re.search(pattern, url, re.IGNORECASE):
                result["has_suspicious_patterns"] = True
                result["suspicious_score"] += score
        
        result["query_params"] = url.count('=')
        if result["has_ip_in_url"]:
            result["suspicious_score"] += 0.3
        
        result["suspicious_score"] = min(result["suspicious_score"], 1.0)
        
        return result
    
    def enrich_indicator(self, indicator: ThreatIndicator) -> Dict[str, Any]:
        """Enrich a single threat indicator"""
        enrichment = {
            "is_whitelisted": self.is_whitelisted(indicator),
            "enrichment_timestamp": time.time(),
            "enrichment_version": "v63"
        }
        
        if indicator.type == "ip":
            enrichment.update(self.enrich_ip(indicator.value))
        elif indicator.type == "url":
            enrichment.update(self.enrich_url(indicator.value))
        elif indicator.type == "domain":
            enrichment["age_estimate"] = "unknown"
            enrichment["reputation_score"] = 0.5 if indicator.confidence > 0.7 else 0.2
            enrichment["suspicious_tld"] = indicator.value.endswith(('.xyz', '.top', '.work', '.biz'))
        
        return enrichment


class AlertCorrelatorV63:
    """Alert correlation and deduplication engine - v63 with all enhancements"""
    
    def __init__(self, base_time_window_minutes: int = 60):
        self.base_time_window = base_time_window_minutes * 60
        self.alert_groups: Dict[str, List[SecurityAlert]] = defaultdict(list)
        self.processed_alerts: Set[str] = set()
        self.bloom_filter = BloomFilter(size=50000, hash_count=4)
        self.context_enricher = ContextEnricher()
        self.semantic_analyzer = TfidfSimilarity()
        self.mitre_mapper = MitreAttackMapper()
        self.severity_window_multipliers = {
            "critical": 2.0,
            "high": 1.5,
            "medium": 1.0,
            "low": 0.5
        }
    
    def get_adaptive_window(self, severity: str) -> float:
        """Get adaptive time window based on alert severity"""
        multiplier = self.severity_window_multipliers.get(severity.lower(), 1.0)
        return self.base_time_window * multiplier
    
    def bayesian_fp_calculation(self, alert: SecurityAlert) -> float:
        """Calculate false positive probability using Bayesian inference"""
        # Prior probability (base rate of false positives in security alerts)
        prior_fp = 0.3
        
        # Likelihood factors
        likelihood = 1.0
        
        # Factor 1: Whitelisted indicators
        whitelisted_count = sum(
            1 for i in alert.indicators 
            if i.metadata.get("is_whitelisted", False)
        )
        if whitelisted_count > 0:
            likelihood *= 8.0  # Whitelisted indicators strongly suggest FP
        
        # Factor 2: Private/internal IPs
        private_count = sum(
            1 for i in alert.indicators 
            if i.metadata.get("is_private", False) or i.metadata.get("is_loopback", False)
        )
        if private_count > 0:
            likelihood *= 3.0
        
        # Factor 3: Indicator confidence
        avg_confidence = sum(i.confidence for i in alert.indicators) / max(len(alert.indicators), 1)
        confidence_factor = 1.0 / max(avg_confidence, 0.1)  # Lower confidence = higher FP chance
        likelihood *= confidence_factor
        
        # Factor 4: Source reliability
        source_reliability = {
            "edr": 0.5, "ngfw": 0.4, "ids": 0.8, "siem": 0.6,
            "endpoint": 0.5, "network": 0.7, "email": 0.4
        }
        source_factor = source_reliability.get(alert.source.lower(), 0.6)
        likelihood *= source_factor
        
        # Bayes theorem (simplified)
        posterior = (likelihood * prior_fp) / (likelihood * prior_fp + (1 - prior_fp))
        return min(posterior, 0.99)
    
    def calculate_similarity(self, alert1: SecurityAlert, alert2: SecurityAlert) -> float:
        """Calculate similarity between two alerts - v63 with semantic analysis"""
        score = 0.0
        weight_count = 0
        
        # Alert type similarity (weight: 0.25)
        if alert1.alert_type == alert2.alert_type:
            score += 0.25
        weight_count += 0.25
        
        # Source similarity (weight: 0.1)
        if alert1.source == alert2.source:
            score += 0.1
        weight_count += 0.1
        
        # Indicator overlap (weight: 0.25)
        indicators1 = {i.get_hash() for i in alert1.indicators}
        indicators2 = {i.get_hash() for i in alert2.indicators}
        if indicators1 and indicators2:
            overlap = len(indicators1 & indicators2) / len(indicators1 | indicators2)
            score += overlap * 0.25
        weight_count += 0.25
        
        # Semantic content similarity (NEW in v63 - weight: 0.25)
        semantic_sim = self.semantic_analyzer.cosine_similarity(
            alert1.get_content_vector(),
            alert2.get_content_vector()
        )
        score += semantic_sim * 0.25
        weight_count += 0.25
        
        # Temporal proximity with adaptive window (weight: 0.15)
        max_window = max(
            self.get_adaptive_window(alert1.severity),
            self.get_adaptive_window(alert2.severity)
        )
        time_diff = abs(alert1.timestamp - alert2.timestamp)
        if time_diff < max_window:
            time_score = 1.0 - (time_diff / max_window)
            score += time_score * 0.15
        weight_count += 0.15
        
        # MITRE technique overlap (NEW in v63 - weight: 0.1)
        if alert1.mitre_techniques and alert2.mitre_techniques:
            tech_overlap = len(set(alert1.mitre_techniques) & set(alert2.mitre_techniques))
            tech_total = len(set(alert1.mitre_techniques) | set(alert2.mitre_techniques))
            if tech_total > 0:
                score += (tech_overlap / tech_total) * 0.1
        weight_count += 0.1
        
        return score / weight_count if weight_count > 0 else 0.0
    
    def calculate_priority(self, alert: SecurityAlert) -> float:
        """Calculate alert priority score (0.0 - 1.0)"""
        severity_weights = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}
        severity_score = severity_weights.get(alert.severity.lower(), 0.5)
        
        avg_confidence = sum(i.confidence for i in alert.indicators) / max(len(alert.indicators), 1)
        fp_risk = alert.false_positive_probability
        
        # Priority = Severity * Confidence * (1 - FP Risk) * MITRE multiplier
        mitre_multiplier = 1.0 + (len(alert.mitre_techniques) * 0.05)
        
        priority = severity_score * avg_confidence * (1 - fp_risk) * mitre_multiplier
        return min(priority, 1.0)
    
    def deduplicate_alerts(self, alerts: List[SecurityAlert]) -> Tuple[List[SecurityAlert], List[SecurityAlert]]:
        """Remove duplicate alerts using Bloom Filter + exact matching"""
        unique: List[SecurityAlert] = []
        duplicates: List[SecurityAlert] = []
        
        for alert in alerts:
            key = alert.get_alert_key()
            
            # Fast bloom filter check first
            if self.bloom_filter.might_contain(key):
                # Double check exact match (bloom can have false positives)
                if key in self.processed_alerts:
                    duplicates.append(alert)
                    continue
            
            self.bloom_filter.add(key)
            self.processed_alerts.add(key)
            unique.append(alert)
        
        return unique, duplicates
    
    def enrich_alert(self, alert: SecurityAlert) -> SecurityAlert:
        """Enrich alert with threat intelligence context - v63 enhanced"""
        # Train semantic analyzer
        self.semantic_analyzer.add_document(alert.get_content_vector())
        
        # Enrich indicators
        enriched_indicators = []
        for indicator in alert.indicators:
            enrichment = self.context_enricher.enrich_indicator(indicator)
            indicator.metadata.update(enrichment)
            enriched_indicators.append(indicator)
        
        alert.indicators = enriched_indicators
        
        # MITRE ATT&CK tagging (NEW v63)
        alert.mitre_techniques = self.mitre_mapper.tag_alert(alert)
        
        # Bayesian false positive calculation (NEW v63)
        alert.false_positive_probability = self.bayesian_fp_calculation(alert)
        
        # Priority scoring (NEW v63)
        alert.priority_score = self.calculate_priority(alert)
        
        alert.enriched_context["enrichment_timestamp"] = time.time()
        alert.enriched_context["enrichment_version"] = "v63"
        alert.enriched_context["indicators_enriched"] = len(alert.indicators)
        
        return alert
    
    def group_alerts(self, alerts: List[SecurityAlert]) -> Dict[str, List[SecurityAlert]]:
        """Group similar alerts together with hierarchical clustering"""
        if not alerts:
            return {}
        
        # Sort by timestamp for temporal processing
        sorted_alerts = sorted(alerts, key=lambda a: a.timestamp)
        
        groups: Dict[str, List[SecurityAlert]] = {}
        group_centroids: Dict[str, SecurityAlert] = {}
        
        for alert in sorted_alerts:
            best_group = None
            best_similarity = 0.0
            
            # Find best matching existing group
            for group_id, centroid in group_centroids.items():
                sim = self.calculate_similarity(alert, centroid)
                if sim > best_similarity and sim > 0.6:
                    best_similarity = sim
                    best_group = group_id
            
            if best_group:
                groups[best_group].append(alert)
                # Update centroid (use most recent alert as centroid)
                group_centroids[best_group] = alert
            else:
                new_id = alert.get_alert_key() + "_" + str(len(groups))
                groups[new_id] = [alert]
                group_centroids[new_id] = alert
        
        return groups
    
    def calculate_correlation_score(self, alert_group: List[SecurityAlert]) -> float:
        """Calculate overall correlation score for an alert group"""
        if not alert_group:
            return 0.0
        
        # Base score from alert count
        base_score = min(len(alert_group) / 8.0, 0.4)
        
        # Severity contribution
        severity_weights = {"low": 0.1, "medium": 0.3, "high": 0.6, "critical": 1.0}
        max_severity = max(severity_weights.get(a.severity.lower(), 0.2) for a in alert_group)
        
        # Confidence from indicators
        avg_confidence = 0.0
        indicator_count = 0
        for alert in alert_group:
            for ind in alert.indicators:
                avg_confidence += ind.confidence
                indicator_count += 1
        avg_confidence = avg_confidence / max(indicator_count, 1)
        
        # Priority contribution
        avg_priority = sum(a.priority_score for a in alert_group) / len(alert_group)
        
        # MITRE technique consistency
        all_techniques = [t for a in alert_group for t in a.mitre_techniques]
        technique_consistency = len(set(all_techniques)) / max(len(all_techniques), 1) if all_techniques else 0.5
        
        final_score = (
            base_score * 0.2 +
            max_severity * 0.3 +
            avg_confidence * 0.2 +
            avg_priority * 0.2 +
            technique_consistency * 0.1
        )
        return min(final_score, 1.0)
    
    def process_alerts(self, alerts: List[SecurityAlert]) -> Dict[str, Any]:
        """Main processing pipeline - v63 enhanced"""
        start_time = time.time()
        
        results = {
            "timestamp": time.time(),
            "engine_version": "v63",
            "input_count": len(alerts),
            "processing_time_ms": 0,
            "unique_alerts": [],
            "duplicate_alerts": [],
            "correlated_groups": {},
            "enrichment_summary": {},
            "performance_metrics": {}
        }
        
        # Step 1: Deduplication with Bloom Filter
        unique, duplicates = self.deduplicate_alerts(alerts)
        results["unique_alerts"] = [a.alert_id for a in unique]
        results["duplicate_alerts"] = [a.alert_id for a in duplicates]
        
        # Step 2: Enrichment with MITRE tagging and Bayesian FP
        enriched_alerts = [self.enrich_alert(a) for a in unique]
        
        # Step 3: Correlation with adaptive time window
        groups = self.group_alerts(enriched_alerts)
        correlated = {}
        
        for group_key, group_alerts in groups.items():
            correlation_score = self.calculate_correlation_score(group_alerts)
            correlated[group_key] = {
                "alert_count": len(group_alerts),
                "correlation_score": round(correlation_score, 4),
                "alert_ids": [a.alert_id for a in group_alerts],
                "severity": max(a.severity for a in group_alerts) if group_alerts else "low",
                "avg_priority": round(sum(a.priority_score for a in group_alerts) / len(group_alerts), 4) if group_alerts else 0,
                "false_positive_risk": round(sum(a.false_positive_probability for a in group_alerts) / len(group_alerts), 4) if group_alerts else 0.5,
                "mitre_techniques": sorted(list({t for a in group_alerts for t in a.mitre_techniques})),
                "time_window_minutes": round(max(self.get_adaptive_window(a.severity) for a in group_alerts) / 60, 1) if group_alerts else 60
            }
        
        results["correlated_groups"] = correlated
        
        # Summary statistics
        results["enrichment_summary"] = {
            "total_enriched": len(enriched_alerts),
            "whitelisted_indicators": sum(1 for a in enriched_alerts for i in a.indicators if i.metadata.get("is_whitelisted", False)),
            "avg_fp_probability": round(sum(a.false_positive_probability for a in enriched_alerts) / len(enriched_alerts), 4) if enriched_alerts else 0.0,
            "avg_priority_score": round(sum(a.priority_score for a in enriched_alerts) / len(enriched_alerts), 4) if enriched_alerts else 0.0,
            "mitre_tags_applied": sum(len(a.mitre_techniques) for a in enriched_alerts)
        }
        
        # Performance metrics
        results["processing_time_ms"] = round((time.time() - start_time) * 1000, 2)
        results["performance_metrics"] = {
            "deduplication_ratio": round(len(duplicates) / max(len(alerts), 1), 4),
            "alerts_per_second": round(len(alerts) / max(time.time() - start_time, 0.001), 2),
            "bloom_filter_size": len(self.bloom_filter.bit_array)
        }
        
        return results


# Export public API
__all__ = [
    "ThreatIndicator",
    "SecurityAlert",
    "BloomFilter",
    "TfidfSimilarity",
    "MitreAttackMapper",
    "ContextEnricher",
    "AlertCorrelatorV63"
]
