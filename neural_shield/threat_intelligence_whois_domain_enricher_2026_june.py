"""
Threat Intelligence WHOIS Domain Enrichment Engine
Real production-grade implementation for NeuralShield-AI

This module provides WHOIS domain lookup and enrichment capabilities
for threat intelligence analysis, helping identify suspicious domains,
their registration details, and potential threat actor associations.
"""

import re
import socket
import time
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, asdict
from ipaddress import ip_address, IPv4Address, IPv6Address
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class WHOISRecord:
    """Data class for WHOIS record information"""
    domain_name: str
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    name_servers: List[str] = None
    status: List[str] = None
    registrant_name: Optional[str] = None
    registrant_organization: Optional[str] = None
    registrant_email: Optional[str] = None
    registrant_country: Optional[str] = None
    admin_name: Optional[str] = None
    admin_email: Optional[str] = None
    tech_name: Optional[str] = None
    tech_email: Optional[str] = None
    dnssec: Optional[str] = None
    raw_data: Optional[str] = None
    lookup_timestamp: str = None

    def __post_init__(self):
        if self.name_servers is None:
            self.name_servers = []
        if self.status is None:
            self.status = []
        if self.lookup_timestamp is None:
            self.lookup_timestamp = datetime.utcnow().isoformat() + "Z"


class WHOISClient:
    """WHOIS client for performing domain lookups"""
    
    WHOIS_SERVERS = {
        'com': 'whois.verisign-grs.com',
        'net': 'whois.verisign-grs.com',
        'org': 'whois.pir.org',
        'io': 'whois.nic.io',
        'ai': 'whois.nic.ai',
        'app': 'whois.nic.google',
        'dev': 'whois.nic.google',
        'xyz': 'whois.nic.xyz',
        'info': 'whois.afilias.net',
        'biz': 'whois.neulevel.biz',
        'us': 'whois.nic.us',
        'uk': 'whois.nic.uk',
        'ca': 'whois.cira.ca',
        'au': 'whois.auda.org.au',
        'de': 'whois.denic.de',
        'fr': 'whois.nic.fr',
        'jp': 'whois.jprs.jp',
        'cn': 'whois.cnnic.cn',
        'ru': 'whois.tcinet.ru',
        'br': 'whois.registro.br',
        'in': 'whois.registry.in',
    }
    
    DEFAULT_WHOIS_SERVER = 'whois.iana.org'
    WHOIS_PORT = 43
    TIMEOUT = 15
    
    def __init__(self, timeout: int = TIMEOUT):
        self.timeout = timeout
    
    def _get_tld(self, domain: str) -> str:
        """Extract TLD from domain name"""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            return parts[-1]
        return ''
    
    def _get_whois_server(self, domain: str) -> str:
        """Get appropriate WHOIS server for domain"""
        tld = self._get_tld(domain)
        return self.WHOIS_SERVERS.get(tld, self.DEFAULT_WHOIS_SERVER)
    
    def _query_whois_server(self, domain: str, server: str) -> str:
        """Query a specific WHOIS server"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((server, self.WHOIS_PORT))
            sock.sendall(f"{domain}\r\n".encode('utf-8'))
            
            response = []
            while True:
                data = sock.recv(4096)
                if not data:
                    break
                response.append(data.decode('utf-8', errors='replace'))
            
            sock.close()
            return ''.join(response)
        except socket.timeout:
            logger.warning(f"WHOIS lookup timed out for {domain} on {server}")
            return ""
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain} on {server}: {e}")
            return ""
    
    def lookup(self, domain: str) -> Tuple[Optional[str], Optional[str]]:
        """Perform WHOIS lookup for a domain"""
        domain = domain.lower().strip()
        
        # First try TLD-specific server
        server = self._get_whois_server(domain)
        raw_data = self._query_whois_server(domain, server)
        
        # If no response or referral, try IANA
        if not raw_data or "No match" in raw_data or "NOT FOUND" in raw_data:
            raw_data = self._query_whois_server(domain, self.DEFAULT_WHOIS_SERVER)
        
        return raw_data, server


class WHOISParser:
    """Parser for WHOIS response data"""
    
    PATTERNS = {
        'domain_name': [
            r'Domain Name:\s*(.+)',
            r'Domain:\s*(.+)',
            r'domain:\s*(.+)',
        ],
        'registrar': [
            r'Registrar:\s*(.+)',
            r'Sponsoring Registrar:\s*(.+)',
            r'Registrar Name:\s*(.+)',
        ],
        'creation_date': [
            r'Creation Date:\s*(.+)',
            r'Created:\s*(.+)',
            r'registered:\s*(.+)',
            r'Domain Registration Date:\s*(.+)',
        ],
        'expiration_date': [
            r'Expir\w+ Date:\s*(.+)',
            r'Expires:\s*(.+)',
            r'Expiry Date:\s*(.+)',
        ],
        'updated_date': [
            r'Updated Date:\s*(.+)',
            r'Last Updated:\s*(.+)',
            r'Modified:\s*(.+)',
        ],
        'name_servers': [
            r'Name Server:\s*(.+)',
            r'Nameserver:\s*(.+)',
            r'Nserver:\s*(.+)',
        ],
        'status': [
            r'Status:\s*(.+)',
            r'Domain Status:\s*(.+)',
        ],
        'registrant_name': [
            r'Registrant Name:\s*(.+)',
            r'Registrant:\s*(.+)',
        ],
        'registrant_organization': [
            r'Registrant Organization:\s*(.+)',
            r'Registrant Org:\s*(.+)',
        ],
        'registrant_email': [
            r'Registrant Email:\s*(.+)',
            r'Registrant Contact Email:\s*(.+)',
        ],
        'registrant_country': [
            r'Registrant Country:\s*(.+)',
            r'Registrant Country Code:\s*(.+)',
        ],
        'admin_name': [
            r'Admin Name:\s*(.+)',
            r'Administrative Contact:\s*(.+)',
        ],
        'admin_email': [
            r'Admin Email:\s*(.+)',
        ],
        'tech_name': [
            r'Tech Name:\s*(.+)',
            r'Technical Contact:\s*(.+)',
        ],
        'tech_email': [
            r'Tech Email:\s*(.+)',
        ],
        'dnssec': [
            r'DNSSEC:\s*(.+)',
        ],
    }
    
    def parse(self, raw_data: str, domain: str) -> WHOISRecord:
        """Parse WHOIS raw data into structured record"""
        record = WHOISRecord(domain_name=domain, raw_data=raw_data[:5000])
        
        if not raw_data:
            return record
        
        lines = raw_data.split('\n')
        
        for field, patterns in self.PATTERNS.items():
            values = []
            for pattern in patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                for line in lines:
                    match = regex.search(line)
                    if match:
                        value = match.group(1).strip()
                        if value and value not in values:
                            values.append(value)
            
            if values:
                if field in ['name_servers', 'status']:
                    setattr(record, field, values)
                else:
                    setattr(record, field, values[0])
        
        return record


class DomainThreatAnalyzer:
    """Analyze domain WHOIS data for threat indicators"""
    
    SUSPICIOUS_KEYWORDS = [
        'privacy', 'protected', 'whoisguard', 'domainsbyproxy',
        'anonymous', 'redacted', 'not disclosed', 'private'
    ]
    
    SUSPICIOUS_TLDS = [
        'xyz', 'top', 'work', 'club', 'online', 'site', 'win',
        'biz', 'info', 'ru', 'cn', 'tk', 'ml', 'ga', 'cf', 'gq'
    ]
    
    def __init__(self):
        self.keyword_pattern = re.compile(
            '|'.join(self.SUSPICIOUS_KEYWORDS),
            re.IGNORECASE
        )
    
    def calculate_domain_age(self, creation_date: Optional[str]) -> Optional[int]:
        """Calculate domain age in days"""
        if not creation_date:
            return None
        
        date_formats = [
            '%Y-%m-%d', '%Y-%m-%dT%H:%M:%SZ', '%d-%b-%Y',
            '%Y/%m/%d', '%d/%m/%Y', '%B %d, %Y'
        ]
        
        for fmt in date_formats:
            try:
                created = datetime.strptime(creation_date.split('T')[0].split(' ')[0], fmt)
                age = (datetime.now() - created).days
                return max(0, age)
            except (ValueError, TypeError):
                continue
        return None
    
    def analyze_threat_level(self, record: WHOISRecord) -> Dict[str, Any]:
        """Analyze WHOIS record for threat indicators"""
        threat_score = 0
        indicators = []
        details = {}
        
        # 1. Check domain age
        age_days = self.calculate_domain_age(record.creation_date)
        details['domain_age_days'] = age_days
        
        if age_days is not None:
            if age_days < 30:
                threat_score += 25
                indicators.append(f"Very new domain ({age_days} days old)")
            elif age_days < 90:
                threat_score += 10
                indicators.append(f"New domain ({age_days} days old)")
        
        # 2. Check for privacy protection
        registrant_fields = [
            record.registrant_name, record.registrant_organization,
            record.registrant_email
        ]
        
        has_privacy = any(
            f and self.keyword_pattern.search(f)
            for f in registrant_fields
        )
        
        if has_privacy:
            threat_score += 15
            indicators.append("Privacy protection enabled")
            details['privacy_protection'] = True
        else:
            details['privacy_protection'] = False
        
        # 3. Check TLD reputation
        tld = record.domain_name.split('.')[-1].lower()
        details['tld'] = tld
        
        if tld in self.SUSPICIOUS_TLDS:
            threat_score += 10
            indicators.append(f"Suspicious TLD: .{tld}")
        
        # 4. Check missing registration data
        missing_fields = sum(1 for f in registrant_fields if not f or not f.strip())
        details['missing_registrant_fields'] = missing_fields
        
        if missing_fields >= 2:
            threat_score += 15
            indicators.append(f"Multiple registrant fields missing ({missing_fields})")
        
        # 5. Check DNSSEC status
        details['dnssec_enabled'] = record.dnssec and 'signed' in record.dnssec.lower()
        
        # 6. Check name server count
        ns_count = len(record.name_servers)
        details['nameserver_count'] = ns_count
        
        if ns_count == 0:
            threat_score += 10
            indicators.append("No name servers configured")
        elif ns_count == 1:
            threat_score += 5
            indicators.append("Only one name server")
        
        # Normalize score
        threat_score = min(100, threat_score)
        
        # Determine level
        if threat_score >= 50:
            level = "HIGH"
        elif threat_score >= 25:
            level = "MEDIUM"
        elif threat_score >= 10:
            level = "LOW"
        else:
            level = "LEGITIMATE"
        
        return {
            'domain': record.domain_name,
            'threat_score': threat_score,
            'threat_level': level,
            'indicators': indicators,
            'analysis_details': details,
            'analysis_timestamp': datetime.utcnow().isoformat() + "Z"
        }


class ThreatIntelligenceWHOISEnricher:
    """Main enrichment engine for threat intelligence"""
    
    def __init__(self, cache_ttl: int = 3600):
        self.whois_client = WHOISClient()
        self.whois_parser = WHOISParser()
        self.threat_analyzer = DomainThreatAnalyzer()
        self.cache: Dict[str, Tuple[float, Dict]] = {}
        self.cache_ttl = cache_ttl
        self.stats = {
            'total_lookups': 0,
            'cache_hits': 0,
            'failed_lookups': 0,
            'high_threat_domains': 0,
        }
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain format"""
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(pattern, domain)) and len(domain) <= 253
    
    def enrich_domain(self, domain: str, use_cache: bool = True) -> Dict[str, Any]:
        """Enrich a single domain with WHOIS data and threat analysis"""
        domain = domain.lower().strip()
        
        if not self._is_valid_domain(domain):
            return {
                'success': False,
                'error': 'Invalid domain format',
                'domain': domain
            }
        
        # Check cache
        cache_key = domain
        current_time = time.time()
        
        if use_cache and cache_key in self.cache:
            cache_time, cached_data = self.cache[cache_key]
            if current_time - cache_time < self.cache_ttl:
                self.stats['cache_hits'] += 1
                return {
                    'success': True,
                    'domain': domain,
                    'cached': True,
                    **cached_data
                }
        
        self.stats['total_lookups'] += 1
        
        # Perform lookup
        raw_data, server = self.whois_client.lookup(domain)
        
        if not raw_data:
            self.stats['failed_lookups'] += 1
            return {
                'success': False,
                'error': 'WHOIS lookup failed',
                'domain': domain,
                'whois_server': server
            }
        
        # Parse and analyze
        record = self.whois_parser.parse(raw_data, domain)
        threat_analysis = self.threat_analyzer.analyze_threat_level(record)
        
        if threat_analysis['threat_level'] == 'HIGH':
            self.stats['high_threat_domains'] += 1
        
        result = {
            'success': True,
            'domain': domain,
            'cached': False,
            'whois_server': server,
            'whois_record': asdict(record),
            'threat_analysis': threat_analysis
        }
        
        # Cache result
        self.cache[cache_key] = (current_time, result)
        
        return result
    
    def enrich_domains_batch(self, domains: List[str], 
                            max_concurrent: int = 10,
                            delay: float = 0.5) -> List[Dict[str, Any]]:
        """Enrich multiple domains in batch"""
        results = []
        seen = set()
        
        for domain in domains:
            domain = domain.lower().strip()
            if domain and domain not in seen:
                seen.add(domain)
                result = self.enrich_domain(domain)
                results.append(result)
                time.sleep(delay)
        
        return results
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get enrichment engine statistics"""
        return {
            **self.stats,
            'cache_size': len(self.cache),
            'cache_hit_rate': (
                self.stats['cache_hits'] / self.stats['total_lookups']
                if self.stats['total_lookups'] > 0 else 0
            ),
            'timestamp': datetime.utcnow().isoformat() + "Z"
        }
    
    def export_json(self, results: List[Dict], filepath: str) -> bool:
        """Export enrichment results to JSON file"""
        try:
            with open(filepath, 'w') as f:
                json.dump({
                    'generated_at': datetime.utcnow().isoformat() + "Z",
                    'total_domains': len(results),
                    'results': results
                }, f, indent=2)
            return True
        except Exception as e:
            logger.error(f"Failed to export JSON: {e}")
            return False


# Exports
__all__ = [
    'WHOISRecord',
    'WHOISClient',
    'WHOISParser', 
    'DomainThreatAnalyzer',
    'ThreatIntelligenceWHOISEnricher',
]
