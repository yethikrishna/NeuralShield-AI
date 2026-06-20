"""
Threat Intelligence Signature Auto-Generator Engine - NeuralShield-AI
Production-Grade Implementation
June 2026
Real working signature generation engine for YARA, Snort, and Suricata rules.
Automatically generates detection signatures from threat patterns, IOCs, and malware analysis.
"""
import hashlib
import re
import string
from typing import List, Dict, Set, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict
import datetime
import threading
@dataclass
class SignatureMetadata:
    """Metadata for generated signatures."""
    signature_id: str = ""
    signature_type: str = ""  # yara, snort, suricata
    threat_category: str = ""
    confidence_score: float = 0.0
    created_at: float = 0.0
    pattern_count: int = 0
    false_positive_risk: str = "medium"  # low, medium, high
    references: List[str] = field(default_factory=list)
@dataclass
class GeneratedSignature:
    """Container for generated signature output."""
    metadata: SignatureMetadata
    content: str
    patterns: List[str]
    validation_score: float = 0.0
class ThreatSignatureGenerator:
    """
    Production-grade Threat Intelligence Signature Auto-Generator.
    
    Real implementation with:
    - YARA rule generation with string patterns, hex patterns, and conditions
    - Snort/Suricata rule generation with content matching
    - Automatic pattern extraction and deduplication
    - Confidence scoring and false positive risk assessment
    - Pattern validation and optimization
    - Metadata enrichment
    - Thread-safe operations
    """
    
    # Common malware patterns for automatic extraction
    MALWARE_KEYWORDS = {
        "ransomware": ["encrypt", "decrypt", "ransom", "bitcoin", "wallet", "AES-256", "RSA-2048"],
        "backdoor": ["backdoor", "reverse_shell", "connect_back", "cmd.exe", "/bin/bash"],
        "trojan": ["trojan", "payload", "inject", "process hollowing"],
        "phishing": ["phish", "credential", "login", "password", "verify"],
        "exploit": ["exploit", "buffer overflow", "heap spray", "shellcode"]
    }
    
    def __init__(self, enable_optimization: bool = True):
        """
        Initialize the signature generator.
        
        Args:
            enable_optimization: Enable pattern optimization and deduplication
        """
        self.enable_optimization = enable_optimization
        self._lock = threading.RLock()
        self._generated_signatures: Dict[str, GeneratedSignature] = {}
        self._pattern_cache: Set[str] = set()
        
    def _generate_signature_id(self, prefix: str = "NS") -> str:
        """Generate unique signature ID."""
        timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        random_hash = hashlib.md5(f"{timestamp}{id(self)}".encode()).hexdigest()[:8]
        return f"{prefix}-SIG-{timestamp}-{random_hash.upper()}"
    
    def _extract_patterns_from_text(self, text: str, min_length: int = 6) -> List[str]:
        """Extract meaningful patterns from threat text."""
        patterns = []
        
        # Extract strings with special characters (potential magic bytes/headers)
        special_patterns = re.findall(r'[A-Fa-f0-9]{8,}', text)
        patterns.extend([p.upper() for p in special_patterns if len(p) >= min_length])
        
        # Extract meaningful strings
        words = re.findall(r'[A-Za-z0-9_./\\-]{6,}', text)
        for word in words:
            if len(word) >= min_length and not word.isdigit():
                patterns.append(word)
        
        # Deduplicate while preserving order
        seen = set()
        unique_patterns = []
        for p in patterns:
            if p not in seen:
                seen.add(p)
                unique_patterns.append(p)
        
        return unique_patterns[:20]  # Limit to top 20 patterns
    
    def _calculate_pattern_quality(self, pattern: str) -> float:
        """Calculate pattern quality score (0-1). Higher = better for detection."""
        score = 0.0
        
        # Length penalty/bonus
        if len(pattern) < 4:
            score -= 0.3
        elif len(pattern) > 12:
            score += 0.2
            
        # Entropy calculation (simplified)
        unique_chars = len(set(pattern))
        entropy_ratio = unique_chars / len(pattern) if pattern else 0
        score += entropy_ratio * 0.3
        
        # Special character bonus for hex patterns
        if all(c in string.hexdigits for c in pattern) and len(pattern) >= 8:
            score += 0.3
            
        # Printable string bonus
        if pattern.isprintable() and not pattern.isspace():
            score += 0.2
            
        return max(0.0, min(1.0, score))
    
    def _assess_false_positive_risk(self, patterns: List[str]) -> str:
        """Assess false positive risk based on patterns."""
        risky_patterns = ["http", "www", "html", "json", "api", "get", "post"]
        
        risk_score = 0
        for pattern in patterns:
            if any(risky in pattern.lower() for risky in risky_patterns):
                risk_score += 1
        
        if risk_score == 0:
            return "low"
        elif risk_score <= 2:
            return "medium"
        else:
            return "high"
    
    def generate_yara_rule(
        self,
        rule_name: str,
        threat_description: str,
        patterns: Optional[List[str]] = None,
        hex_patterns: Optional[List[str]] = None,
        threat_category: str = "malware",
        author: str = "NeuralShield-AI",
        reference: str = ""
    ) -> GeneratedSignature:
        """
        Generate a production-grade YARA rule.
        
        Args:
            rule_name: Name of the YARA rule
            threat_description: Description of the threat
            patterns: List of string patterns to match
            hex_patterns: List of hex patterns (without spaces)
            threat_category: Category of threat
            author: Rule author
            reference: Reference URL or source
            
        Returns:
            GeneratedSignature object with complete YARA rule
        """
        with self._lock:
            sig_id = self._generate_signature_id("YARA")
            
            # Auto-extract patterns if not provided
            if patterns is None:
                patterns = self._extract_patterns_from_text(threat_description)
            
            all_patterns = patterns.copy()
            if hex_patterns:
                all_patterns.extend(hex_patterns)
            
            # Calculate confidence
            pattern_scores = [self._calculate_pattern_quality(p) for p in all_patterns]
            confidence = sum(pattern_scores) / len(pattern_scores) if pattern_scores else 0.5
            
            # Build YARA rule
            yara_lines = []
            
            # Rule header
            clean_rule_name = re.sub(r'[^a-zA-Z0-9_]', '_', rule_name)
            yara_lines.append(f"rule {clean_rule_name} {{")
            
            # Metadata section
            yara_lines.append("    meta:")
            yara_lines.append(f'        description = "{threat_description[:200]}"')
            yara_lines.append(f'        author = "{author}"')
            yara_lines.append(f'        category = "{threat_category}"')
            yara_lines.append(f'        signature_id = "{sig_id}"')
            yara_lines.append(f'        confidence = {confidence:.2f}')
            yara_lines.append(f'        date = "{datetime.datetime.now().strftime("%Y-%m-%d")}"')
            if reference:
                yara_lines.append(f'        reference = "{reference}"')
            
            # Strings section
            yara_lines.append("    strings:")
            
            pattern_idx = 0
            
            # Add string patterns
            for i, pattern in enumerate(patterns[:10]):
                if '"' in pattern:
                    pattern = pattern.replace('"', '\\"')
                yara_lines.append(f'        $str{i} = "{pattern}" ascii wide')
                pattern_idx += 1
            
            # Add hex patterns
            if hex_patterns:
                for i, hex_pat in enumerate(hex_patterns[:5]):
                    # Format hex with spaces every 2 chars
                    formatted_hex = " ".join([hex_pat[j:j+2] for j in range(0, len(hex_pat), 2)])
                    yara_lines.append(f'        $hex{i} = {{ {formatted_hex} }}')
                    pattern_idx += 1
            
            # Condition section
            yara_lines.append("    condition:")
            if pattern_idx == 1:
                yara_lines.append("        any of them")
            elif pattern_idx <= 3:
                yara_lines.append("        all of them")
            else:
                yara_lines.append(f"        {max(2, pattern_idx // 2)} of them")
            
            yara_lines.append("}")
            
            signature_content = "\n".join(yara_lines)
            
            metadata = SignatureMetadata(
                signature_id=sig_id,
                signature_type="yara",
                threat_category=threat_category,
                confidence_score=confidence,
                created_at=datetime.datetime.now().timestamp(),
                pattern_count=pattern_idx,
                false_positive_risk=self._assess_false_positive_risk(all_patterns),
                references=[reference] if reference else []
            )
            
            signature = GeneratedSignature(
                metadata=metadata,
                content=signature_content,
                patterns=all_patterns,
                validation_score=confidence
            )
            
            self._generated_signatures[sig_id] = signature
            return signature
    
    def generate_snort_rule(
        self,
        action: str = "alert",
        protocol: str = "tcp",
        source_net: str = "any",
        source_port: str = "any",
        direction: str = "->",
        dest_net: str = "any",
        dest_port: str = "any",
        msg: str = "NeuralShield Threat Detection",
        content_patterns: Optional[List[str]] = None,
        sid: Optional[int] = None,
        rev: int = 1,
        priority: int = 2,
        classtype: str = "trojan-activity"
    ) -> GeneratedSignature:
        """
        Generate a production-grade Snort/Suricata rule.
        
        Args:
            action: Rule action (alert, log, pass, drop, reject, sdrop)
            protocol: IP protocol (tcp, udp, icmp, ip)
            source_net: Source network
            source_port: Source port
            direction: Traffic direction
            dest_net: Destination network
            dest_port: Destination port
            msg: Rule message
            content_patterns: List of content patterns to match
            sid: Signature ID
            rev: Revision number
            priority: Rule priority (1-3, 1=highest)
            classtype: Classification type
            
        Returns:
            GeneratedSignature object with complete Snort rule
        """
        with self._lock:
            sig_id = self._generate_signature_id("SNORT")
            
            if content_patterns is None:
                content_patterns = ["malicious_pattern"]
            
            # Build rule components
            rule_parts = [
                action,
                protocol,
                source_net,
                source_port,
                direction,
                dest_net,
                dest_port,
                "("
            ]
            
            # Add message
            rule_parts.append(f'msg:"{msg}";')
            
            # Add content patterns
            for pattern in content_patterns[:5]:
                if '"' in pattern:
                    pattern = pattern.replace('"', '\\"')
                rule_parts.append(f'content:"{pattern}";')
                rule_parts.append('nocase;')
            
            # Add metadata
            rule_parts.append(f'priority:{priority};')
            rule_parts.append(f'classtype:{classtype};')
            
            if sid:
                rule_parts.append(f'sid:{sid};')
            else:
                # Generate SID from hash
                sid_hash = int(hashlib.md5(sig_id.encode()).hexdigest()[:7], 16) % 9000000 + 1000000
                rule_parts.append(f'sid:{sid_hash};')
            
            rule_parts.append(f'rev:{rev};')
            rule_parts.append(f'tag:session,exclusive;')
            rule_parts.append(")")
            
            signature_content = " ".join(rule_parts)
            
            # Calculate confidence
            pattern_scores = [self._calculate_pattern_quality(p) for p in content_patterns]
            confidence = sum(pattern_scores) / len(pattern_scores) if pattern_scores else 0.5
            
            metadata = SignatureMetadata(
                signature_id=sig_id,
                signature_type="snort",
                threat_category=classtype,
                confidence_score=confidence,
                created_at=datetime.datetime.now().timestamp(),
                pattern_count=len(content_patterns),
                false_positive_risk=self._assess_false_positive_risk(content_patterns)
            )
            
            signature = GeneratedSignature(
                metadata=metadata,
                content=signature_content,
                patterns=content_patterns,
                validation_score=confidence
            )
            
            self._generated_signatures[sig_id] = signature
            return signature
    
    def generate_suricata_http_rule(
        self,
        msg: str,
        uri_patterns: Optional[List[str]] = None,
        user_agent_patterns: Optional[List[str]] = None,
        host_patterns: Optional[List[str]] = None,
        priority: int = 2
    ) -> GeneratedSignature:
        """
        Generate Suricata-specific HTTP inspection rule.
        
        Args:
            msg: Rule message
            uri_patterns: URI patterns to match
            user_agent_patterns: User-Agent patterns
            host_patterns: Host header patterns
            priority: Rule priority
            
        Returns:
            GeneratedSignature with Suricata HTTP rule
        """
        with self._lock:
            sig_id = self._generate_signature_id("SURI")
            
            all_patterns = []
            rule_parts = [
                "alert", "tcp", "any", "any", "->", "any", "$HTTP_PORTS",
                f'(msg:"{msg}";'
            ]
            
            rule_parts.append('flow:to_server,established;')
            rule_parts.append('http_method; content:"GET";')
            
            if uri_patterns:
                for pattern in uri_patterns[:3]:
                    rule_parts.append(f'http_uri; content:"{pattern}"; nocase;')
                    all_patterns.append(pattern)
            
            if user_agent_patterns:
                for pattern in user_agent_patterns[:2]:
                    rule_parts.append(f'http_user_agent; content:"{pattern}"; nocase;')
                    all_patterns.append(pattern)
            
            if host_patterns:
                for pattern in host_patterns[:2]:
                    rule_parts.append(f'http_host; content:"{pattern}"; nocase;')
                    all_patterns.append(pattern)
            
            sid_hash = int(hashlib.md5(sig_id.encode()).hexdigest()[:7], 16) % 9000000 + 1000000
            rule_parts.append(f'priority:{priority};')
            rule_parts.append('classtype:web-application-attack;')
            rule_parts.append(f'sid:{sid_hash}; rev:1;)')
            
            signature_content = " ".join(rule_parts)
            
            pattern_scores = [self._calculate_pattern_quality(p) for p in all_patterns]
            confidence = sum(pattern_scores) / len(pattern_scores) if pattern_scores else 0.5
            
            metadata = SignatureMetadata(
                signature_id=sig_id,
                signature_type="suricata",
                threat_category="web-attack",
                confidence_score=confidence,
                created_at=datetime.datetime.now().timestamp(),
                pattern_count=len(all_patterns),
                false_positive_risk=self._assess_false_positive_risk(all_patterns)
            )
            
            signature = GeneratedSignature(
                metadata=metadata,
                content=signature_content,
                patterns=all_patterns,
                validation_score=confidence
            )
            
            self._generated_signatures[sig_id] = signature
            return signature
    
    def batch_generate_from_iocs(
        self,
        iocs: Dict[str, List[str]],
        output_format: str = "yara"
    ) -> List[GeneratedSignature]:
        """
        Batch generate signatures from IOC dictionary.
        
        Args:
            iocs: Dictionary of {ioc_type: [values]} e.g., {"sha256": [...], "domains": [...]}
            output_format: "yara", "snort", or "all"
            
        Returns:
            List of GeneratedSignature objects
        """
        results = []
        
        for ioc_type, values in iocs.items():
            for i, value in enumerate(values[:20]):  # Limit batch size
                if output_format in ["yara", "all"]:
                    sig = self.generate_yara_rule(
                        rule_name=f"IOC_{ioc_type}_{i}",
                        threat_description=f"Indicator of Compromise: {ioc_type}",
                        patterns=[value],
                        threat_category=ioc_type
                    )
                    results.append(sig)
                
                if output_format in ["snort", "all"] and ioc_type in ["domain", "ip", "url"]:
                    sig = self.generate_snort_rule(
                        msg=f"NeuralShield IOC Detection: {value}",
                        content_patterns=[value],
                        classtype="bad-unknown"
                    )
                    results.append(sig)
        
        return results
    
    def get_signature_statistics(self) -> Dict[str, Any]:
        """Get generation statistics."""
        with self._lock:
            by_type = defaultdict(int)
            by_category = defaultdict(int)
            confidences = []
            
            for sig in self._generated_signatures.values():
                by_type[sig.metadata.signature_type] += 1
                by_category[sig.metadata.threat_category] += 1
                confidences.append(sig.metadata.confidence_score)
            
            return {
                "total_generated": len(self._generated_signatures),
                "by_type": dict(by_type),
                "by_category": dict(by_category),
                "average_confidence": sum(confidences) / len(confidences) if confidences else 0.0,
                "min_confidence": min(confidences) if confidences else 0.0,
                "max_confidence": max(confidences) if confidences else 0.0
            }
    
    def export_all_signatures(self, filepath: str) -> bool:
        """Export all signatures to a file."""
        try:
            with self._lock:
                with open(filepath, 'w') as f:
                    for sig in self._generated_signatures.values():
                        f.write(f"// Signature ID: {sig.metadata.signature_id}\n")
                        f.write(f"// Type: {sig.metadata.signature_type}\n")
                        f.write(f"// Confidence: {sig.metadata.confidence_score:.2f}\n")
                        f.write(sig.content)
                        f.write("\n\n")
            return True
        except Exception:
            return False
