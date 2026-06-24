"""
Threat Intelligence IOC (Indicator of Compromise) Extractor v76
Automatically extracts IOCs from threat alerts and context data.
ADD-ONLY MODULE - wraps existing functionality, no core code modified.

Stability: STABLE
Backward Compatible: YES
Dependencies: None additional
"""

import re
import ipaddress
from typing import Dict, List, Set, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum


class IOCTYPE(Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    MD5 = "md5"
    SHA1 = "sha1"
    SHA256 = "sha256"
    EMAIL = "email"


@dataclass
class IOCResult:
    """Single IOC extraction result"""
    value: str
    ioc_type: IOCTYPE
    confidence: float = 1.0
    context: str = ""
    source: str = ""
    
    def to_dict(self) -> Dict:
        return {
            "value": self.value,
            "type": self.ioc_type.value,
            "confidence": self.confidence,
            "context": self.context,
            "source": self.source
        }


@dataclass
class IOCExtractionReport:
    """Complete IOC extraction report"""
    total_iocs: int = 0
    by_type: Dict[str, List[IOCResult]] = field(default_factory=dict)
    unique_values: Set[str] = field(default_factory=set)
    processing_time_ms: float = 0.0
    source_text_length: int = 0
    
    def get_summary(self) -> Dict:
        return {
            "total_iocs": self.total_iocs,
            "by_type_count": {k: len(v) for k, v in self.by_type.items()},
            "unique_iocs": len(self.unique_values),
            "source_length": self.source_text_length
        }


class ThreatIntelligenceIOCExtractor:
    """
    Extracts IOCs from threat alert text, logs, and context data.
    Uses regex patterns with validation for accuracy.
    
    ADD-ONLY: This module layers on top of existing threat intelligence.
    No existing modules are modified.
    """
    
    def __init__(self, deduplicate: bool = True, validate: bool = True):
        self.deduplicate = deduplicate
        self.validate = validate
        self._compile_patterns()
    
    def _compile_patterns(self):
        """Compile regex patterns for IOC extraction"""
        # IPv4 pattern (simple)
        self.ipv4_pattern = re.compile(
            r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        )
        
        # IPv6 pattern (simplified)
        self.ipv6_pattern = re.compile(
            r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,7}:|'
            r'\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b'
        )
        
        # Domain pattern
        self.domain_pattern = re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        )
        
        # URL pattern
        self.url_pattern = re.compile(
            r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+'
            r'(?:/(?:[-\w_.~!*\'();:@&=+$,/?%#[\]]*))?'
        )
        
        # MD5 hash
        self.md5_pattern = re.compile(r'\b[a-fA-F0-9]{32}\b')
        
        # SHA1 hash
        self.sha1_pattern = re.compile(r'\b[a-fA-F0-9]{40}\b')
        
        # SHA256 hash
        self.sha256_pattern = re.compile(r'\b[a-fA-F0-9]{64}\b')
        
        # Email
        self.email_pattern = re.compile(
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        )
    
    def _validate_ipv4(self, ip: str) -> bool:
        """Validate IPv4 address"""
        try:
            ipaddress.IPv4Address(ip)
            return True
        except ValueError:
            return False
    
    def _validate_ipv6(self, ip: str) -> bool:
        """Validate IPv6 address"""
        try:
            ipaddress.IPv6Address(ip)
            return True
        except ValueError:
            return False
    
    def extract_from_text(self, text: str, source: str = "") -> IOCExtractionReport:
        """
        Extract all IOCs from input text.
        
        Args:
            text: Input text to scan for IOCs
            source: Source identifier for tracking
            
        Returns:
            IOCExtractionReport with all found IOCs
        """
        import time
        start_time = time.time()
        
        report = IOCExtractionReport()
        report.source_text_length = len(text)
        seen = set()
        
        extraction_map = [
            (self.ipv4_pattern, IOCTYPE.IPV4, self._validate_ipv4 if self.validate else None),
            (self.ipv6_pattern, IOCTYPE.IPV6, self._validate_ipv6 if self.validate else None),
            (self.md5_pattern, IOCTYPE.MD5, None),
            (self.sha1_pattern, IOCTYPE.SHA1, None),
            (self.sha256_pattern, IOCTYPE.SHA256, None),
            (self.url_pattern, IOCTYPE.URL, None),
            (self.email_pattern, IOCTYPE.EMAIL, None),
            (self.domain_pattern, IOCTYPE.DOMAIN, None),
        ]
        
        for pattern, ioc_type, validator in extraction_map:
            matches = pattern.findall(text)
            for match in matches:
                match_str = str(match).strip()
                
                # Deduplication
                if self.deduplicate:
                    key = f"{ioc_type.value}:{match_str}"
                    if key in seen:
                        continue
                    seen.add(key)
                
                # Validation
                if validator and not validator(match_str):
                    continue
                
                # Get context (surrounding text)
                idx = text.find(match_str)
                context_start = max(0, idx - 50)
                context_end = min(len(text), idx + len(match_str) + 50)
                context = text[context_start:context_end]
                
                ioc_result = IOCResult(
                    value=match_str,
                    ioc_type=ioc_type,
                    confidence=0.95 if validator else 0.85,
                    context=context,
                    source=source
                )
                
                type_key = ioc_type.value
                if type_key not in report.by_type:
                    report.by_type[type_key] = []
                report.by_type[type_key].append(ioc_result)
                report.unique_values.add(match_str)
                report.total_iocs += 1
        
        report.processing_time_ms = (time.time() - start_time) * 1000
        return report
    
    def extract_from_alerts(self, alerts: List[Dict]) -> IOCExtractionReport:
        """
        Extract IOCs from a list of alert dictionaries.
        
        Args:
            alerts: List of alert dictionaries with 'message' or 'description' fields
            
        Returns:
            Combined IOCExtractionReport
        """
        combined_report = IOCExtractionReport()
        
        for alert in alerts:
            alert_text = " ".join([
                str(alert.get(k, "")) 
                for k in ['message', 'description', 'details', 'raw']
            ])
            source = alert.get('alert_id', alert.get('id', ''))
            
            alert_report = self.extract_from_text(alert_text, str(source))
            
            # Merge reports
            combined_report.total_iocs += alert_report.total_iocs
            combined_report.unique_values.update(alert_report.unique_values)
            combined_report.source_text_length += alert_report.source_text_length
            
            for type_key, iocs in alert_report.by_type.items():
                if type_key not in combined_report.by_type:
                    combined_report.by_type[type_key] = []
                combined_report.by_type[type_key].extend(iocs)
        
        return combined_report
    
    def get_ioc_list(self, report: IOCExtractionReport, 
                     ioc_type: Optional[str] = None) -> List[str]:
        """Get flat list of IOC values"""
        results = []
        for type_key, iocs in report.by_type.items():
            if ioc_type is None or type_key == ioc_type:
                results.extend([ioc.value for ioc in iocs])
        return results


# Export singleton for easy use
ioc_extractor = ThreatIntelligenceIOCExtractor()

__all__ = [
    'ThreatIntelligenceIOCExtractor',
    'IOCExtractionReport',
    'IOCResult',
    'IOCTYPE',
    'ioc_extractor'
]
