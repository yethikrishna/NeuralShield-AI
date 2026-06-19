"""
NeuralShield AI - Threat Intelligence Geolocation Tracker
Production-grade module for IP geolocation tracking and threat analysis.
This module provides:
- IPv4/IPv6 geolocation lookup with country/city/ASN data
- Threat reputation scoring based on geographic location
- Anonymization network detection (TOR, VPN, proxy)
- Distance calculation from trusted network zones
- Bulk geolocation processing with caching
- Geofencing and alerting capabilities
"""
import ipaddress
import hashlib
import json
from typing import Dict, List, Set, Tuple, Optional, Any, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timedelta
import math
import threading


class IPVersion(Enum):
    """IP address versions"""
    IPV4 = "ipv4"
    IPV6 = "ipv6"


class ThreatReputation(Enum):
    """Threat reputation levels"""
    TRUSTED = "trusted"
    LOW_RISK = "low_risk"
    MEDIUM_RISK = "medium_risk"
    HIGH_RISK = "high_risk"
    CRITICAL = "critical"
    ANONYMIZED = "anonymized"


class NetworkType(Enum):
    """Network type classification"""
    RESIDENTIAL = "residential"
    BUSINESS = "business"
    HOSTING = "hosting"
    EDUCATION = "education"
    GOVERNMENT = "government"
    TOR_EXIT = "tor_exit"
    VPN = "vpn"
    PROXY = "proxy"
    DATACENTER = "datacenter"
    UNKNOWN = "unknown"


@dataclass
class Coordinates:
    """Geographic coordinates"""
    latitude: float
    longitude: float
    
    def distance_to(self, other: 'Coordinates') -> float:
        """Calculate Haversine distance in kilometers between two coordinates"""
        R = 6371.0  # Earth radius in km
        
        lat1_rad = math.radians(self.latitude)
        lon1_rad = math.radians(self.longitude)
        lat2_rad = math.radians(other.latitude)
        lon2_rad = math.radians(other.longitude)
        
        dlat = lat2_rad - lat1_rad
        dlon = lon2_rad - lon1_rad
        
        a = math.sin(dlat / 2)**2 + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(dlon / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        
        return R * c


@dataclass
class GeolocationResult:
    """Result of geolocation lookup"""
    ip_address: str
    ip_version: IPVersion
    is_public: bool
    country_code: str = "ZZ"
    country_name: str = "Unknown"
    city: str = "Unknown"
    region: str = "Unknown"
    postal_code: str = ""
    timezone: str = "UTC"
    coordinates: Coordinates = field(default_factory=lambda: Coordinates(0.0, 0.0))
    asn: int = 0
    asn_organization: str = "Unknown"
    network_type: NetworkType = NetworkType.UNKNOWN
    threat_reputation: ThreatReputation = ThreatReputation.LOW_RISK
    threat_score: float = 0.0
    is_anonymized: bool = False
    is_malicious: bool = False
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


class GeolocationCache:
    """Thread-safe LRU cache for geolocation results"""
    
    def __init__(self, max_size: int = 10000, ttl_hours: int = 24):
        self.max_size = max_size
        self.ttl = timedelta(hours=ttl_hours)
        self._cache: Dict[str, Tuple[GeolocationResult, datetime]] = {}
        self._lock = threading.Lock()
    
    def get(self, ip: str) -> Optional[GeolocationResult]:
        """Get cached result if valid"""
        with self._lock:
            if ip in self._cache:
                result, timestamp = self._cache[ip]
                if datetime.now() - timestamp < self.ttl:
                    return result
                else:
                    del self._cache[ip]
            return None
    
    def put(self, ip: str, result: GeolocationResult) -> None:
        """Cache a geolocation result"""
        with self._lock:
            if len(self._cache) >= self.max_size:
                oldest_ip = min(self._cache.keys(), key=lambda k: self._cache[k][1])
                del self._cache[oldest_ip]
            self._cache[ip] = (result, datetime.now())
    
    def clear(self) -> None:
        """Clear all cached entries"""
        with self._lock:
            self._cache.clear()
    
    def size(self) -> int:
        """Get current cache size"""
        with self._lock:
            return len(self._cache)


class ThreatIntelligenceGeolocationTracker:
    """
    Production-grade IP geolocation tracker with threat intelligence.
    Provides real-time geolocation analysis with threat scoring.
    """
    
    # High-risk country codes (based on historical threat data)
    HIGH_RISK_COUNTRIES = {
        "CN", "RU", "IR", "KP", "SY", "VE", "CU"
    }
    
    # Medium-risk country codes
    MEDIUM_RISK_COUNTRIES = {
        "BR", "IN", "ID", "VN", "TH", "PH", "ZA", "NG"
    }
    
    # Trusted country codes
    TRUSTED_COUNTRIES = {
        "US", "CA", "GB", "DE", "FR", "JP", "AU", "NZ", "CH", "SE", "NO", "DK", "FI", "NL"
    }
    
    # Known TOR exit node ASNs (sample)
    TOR_ASNS = {12876, 16276, 16509, 20473, 24940, 32590, 36351, 393406}
    
    # Known VPN provider ASNs (sample)
    VPN_ASNS = {9009, 20473, 32244, 55286, 60068, 206224, 209400}
    
    def __init__(self, cache_size: int = 10000, cache_ttl_hours: int = 24):
        self.cache = GeolocationCache(max_size=cache_size, ttl_hours=cache_ttl_hours)
        self.trusted_zones: List[Tuple[Coordinates, float]] = []  # (center, radius_km)
        self._stats = {
            "total_lookups": 0,
            "cache_hits": 0,
            "anonymized_detected": 0,
            "malicious_detected": 0
        }
    
    def _classify_ip_version(self, ip_str: str) -> Tuple[IPVersion, bool]:
        """Classify IP version and check if it's public"""
        try:
            ip = ipaddress.ip_address(ip_str)
            version = IPVersion.IPV4 if ip.version == 4 else IPVersion.IPV6
            is_public = not (ip.is_private or ip.is_reserved or ip.is_loopback or ip.is_link_local)
            return version, is_public
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip_str}")
    
    def _get_mock_geolocation_data(self, ip_str: str) -> Dict[str, Any]:
        """
        Generate realistic mock geolocation data based on IP address.
        In production, this would call real geolocation APIs.
        """
        ip_hash = int(hashlib.md5(ip_str.encode()).hexdigest(), 16)
        
        # Determine country based on IP hash
        all_countries = list(self.TRUSTED_COUNTRIES | self.MEDIUM_RISK_COUNTRIES | self.HIGH_RISK_COUNTRIES)
        country_idx = ip_hash % len(all_countries)
        country_code = all_countries[country_idx]
        
        country_names = {
            "US": "United States", "CA": "Canada", "GB": "United Kingdom",
            "DE": "Germany", "FR": "France", "JP": "Japan", "AU": "Australia",
            "CN": "China", "RU": "Russian Federation", "IR": "Iran",
            "BR": "Brazil", "IN": "India", "ID": "Indonesia", "VN": "Vietnam"
        }
        
        # Generate realistic coordinates
        lat = ((ip_hash >> 8) % 18000) / 100 - 90
        lon = ((ip_hash >> 16) % 36000) / 100 - 180
        
        # Generate ASN
        asn = 1000 + (ip_hash % 500000)
        
        # Determine network type
        network_types = list(NetworkType)
        network_type_idx = (ip_hash >> 24) % len(network_types)
        network_type = network_types[network_type_idx]
        
        # Force some anonymized networks
        if asn in self.TOR_ASNS:
            network_type = NetworkType.TOR_EXIT
        elif asn in self.VPN_ASNS:
            network_type = NetworkType.VPN
        
        return {
            "country_code": country_code,
            "country_name": country_names.get(country_code, "Unknown"),
            "city": ["New York", "London", "Tokyo", "Berlin", "Singapore", "Amsterdam"][ip_hash % 6],
            "coordinates": Coordinates(lat, lon),
            "asn": asn,
            "asn_organization": f"AS{asn} Network Provider",
            "network_type": network_type,
            "timezone": ["America/New_York", "Europe/London", "Asia/Tokyo", "UTC"][ip_hash % 4]
        }
    
    def _calculate_threat_score(self, geo_data: Dict[str, Any]) -> Tuple[ThreatReputation, float, bool, bool]:
        """Calculate threat score and reputation based on geolocation data"""
        score = 0.0
        is_anonymized = False
        is_malicious = False
        
        country_code = geo_data["country_code"]
        network_type = geo_data["network_type"]
        
        # Country-based scoring
        if country_code in self.HIGH_RISK_COUNTRIES:
            score += 70.0
        elif country_code in self.MEDIUM_RISK_COUNTRIES:
            score += 30.0
        elif country_code in self.TRUSTED_COUNTRIES:
            score -= 20.0
        
        # Network type scoring
        if network_type == NetworkType.TOR_EXIT:
            score += 80.0
            is_anonymized = True
        elif network_type == NetworkType.VPN:
            score += 50.0
            is_anonymized = True
        elif network_type == NetworkType.PROXY:
            score += 60.0
            is_anonymized = True
        elif network_type == NetworkType.DATACENTER:
            score += 25.0
        elif network_type == NetworkType.HOSTING:
            score += 15.0
        
        # Normalize score to 0-100
        score = max(0.0, min(100.0, score))
        
        # Determine reputation
        if score >= 80:
            reputation = ThreatReputation.CRITICAL
            is_malicious = True
        elif score >= 55:
            reputation = ThreatReputation.HIGH_RISK
        elif score >= 30:
            reputation = ThreatReputation.MEDIUM_RISK
        elif score >= 10:
            reputation = ThreatReputation.LOW_RISK
        else:
            reputation = ThreatReputation.TRUSTED
        
        if is_anonymized:
            reputation = ThreatReputation.ANONYMIZED
        
        return reputation, score, is_anonymized, is_malicious
    
    def lookup(self, ip_address: str, use_cache: bool = True) -> GeolocationResult:
        """
        Perform geolocation lookup for an IP address.
        
        Args:
            ip_address: IP address to lookup
            use_cache: Whether to use cached results
            
        Returns:
            GeolocationResult with full geolocation and threat data
        """
        self._stats["total_lookups"] += 1
        
        # Check cache first
        if use_cache:
            cached = self.cache.get(ip_address)
            if cached:
                self._stats["cache_hits"] += 1
                return cached
        
        # Classify IP
        ip_version, is_public = self._classify_ip_version(ip_address)
        
        # Handle private IPs
        if not is_public:
            result = GeolocationResult(
                ip_address=ip_address,
                ip_version=ip_version,
                is_public=False,
                threat_reputation=ThreatReputation.TRUSTED,
                threat_score=0.0,
                network_type=NetworkType.BUSINESS
            )
            if use_cache:
                self.cache.put(ip_address, result)
            return result
        
        # Get geolocation data
        geo_data = self._get_mock_geolocation_data(ip_address)
        
        # Calculate threat metrics
        reputation, score, is_anonymized, is_malicious = self._calculate_threat_score(geo_data)
        
        if is_anonymized:
            self._stats["anonymized_detected"] += 1
        if is_malicious:
            self._stats["malicious_detected"] += 1
        
        result = GeolocationResult(
            ip_address=ip_address,
            ip_version=ip_version,
            is_public=True,
            country_code=geo_data["country_code"],
            country_name=geo_data["country_name"],
            city=geo_data["city"],
            coordinates=geo_data["coordinates"],
            asn=geo_data["asn"],
            asn_organization=geo_data["asn_organization"],
            network_type=geo_data["network_type"],
            timezone=geo_data["timezone"],
            threat_reputation=reputation,
            threat_score=score,
            is_anonymized=is_anonymized,
            is_malicious=is_malicious,
            first_seen=datetime.now(),
            last_seen=datetime.now()
        )
        
        if use_cache:
            self.cache.put(ip_address, result)
        
        return result
    
    def bulk_lookup(self, ip_addresses: List[str], use_cache: bool = True) -> List[GeolocationResult]:
        """Perform bulk geolocation lookup"""
        return [self.lookup(ip, use_cache) for ip in ip_addresses]
    
    def add_trusted_zone(self, center: Coordinates, radius_km: float) -> None:
        """Add a trusted geographic zone"""
        self.trusted_zones.append((center, radius_km))
    
    def is_in_trusted_zone(self, coordinates: Coordinates) -> bool:
        """Check if coordinates are within any trusted zone"""
        for center, radius in self.trusted_zones:
            if coordinates.distance_to(center) <= radius:
                return True
        return False
    
    def check_geofence_alert(self, result: GeolocationResult) -> bool:
        """Check if geolocation triggers a geofence alert"""
        if not result.is_public:
            return False
        
        # Alert if in high-risk country and anonymized
        if result.country_code in self.HIGH_RISK_COUNTRIES and result.is_anonymized:
            return True
        
        # Alert if critical threat score
        if result.threat_score >= 80:
            return True
        
        # Alert if outside all trusted zones (if zones are defined)
        if self.trusted_zones and not self.is_in_trusted_zone(result.coordinates):
            return True
        
        return False
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get tracker statistics"""
        return {
            **self._stats,
            "cache_size": self.cache.size(),
            "cache_hit_rate": (
                self._stats["cache_hits"] / self._stats["total_lookups"] * 100
                if self._stats["total_lookups"] > 0 else 0.0
            ),
            "trusted_zones_count": len(self.trusted_zones)
        }
    
    def export_report(self, results: List[GeolocationResult], format: str = "json") -> str:
        """Export geolocation results as report"""
        report_data = {
            "generated_at": datetime.now().isoformat(),
            "total_ips": len(results),
            "summary": {
                "trusted": sum(1 for r in results if r.threat_reputation == ThreatReputation.TRUSTED),
                "low_risk": sum(1 for r in results if r.threat_reputation == ThreatReputation.LOW_RISK),
                "medium_risk": sum(1 for r in results if r.threat_reputation == ThreatReputation.MEDIUM_RISK),
                "high_risk": sum(1 for r in results if r.threat_reputation == ThreatReputation.HIGH_RISK),
                "critical": sum(1 for r in results if r.threat_reputation == ThreatReputation.CRITICAL),
                "anonymized": sum(1 for r in results if r.is_anonymized),
                "malicious": sum(1 for r in results if r.is_malicious)
            },
            "results": [
                {
                    "ip": r.ip_address,
                    "country": r.country_code,
                    "city": r.city,
                    "threat_score": r.threat_score,
                    "reputation": r.threat_reputation.value,
                    "is_anonymized": r.is_anonymized,
                    "network_type": r.network_type.value
                }
                for r in results
            ]
        }
        
        if format == "json":
            return json.dumps(report_data, indent=2)
        return str(report_data)
