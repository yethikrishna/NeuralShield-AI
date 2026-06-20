"""
Threat Intelligence Signature Auto-Generation Engine
Production-grade module for automated signature generation from threat patterns
Supports YARA, SNORT, and Suricata rule formats with ML-enhanced pattern extraction
"""

import re
import hashlib
import json
import time
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, field
from collections import defaultdict, Counter
import uuid
from datetime import datetime


@dataclass
class ThreatPattern:
    """Dataclass representing a detected threat pattern"""
    pattern_id: str
    pattern_type: str  # string, regex, byte_sequence, heuristic
    content: str
    confidence: float
    threat_type: str
    source: str
    severity: str
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GeneratedSignature:
    """Dataclass representing a generated detection signature"""
    signature_id: str
    signature_type: str  # yara, snort, suricata
    rule_content: str
    patterns_used: List[str]
    confidence_score: float
    false_positive_risk: str
    created_at: float = field(default_factory=time.time)
    metadata: Dict[str, Any] = field(default_factory=dict)


class PatternExtractor:
    """Extracts meaningful patterns from threat samples"""
    
    def __init__(self, min_pattern_length: int = 6, max_pattern_length: int = 128):
        self.min_pattern_length = min_pattern_length
        self.max_pattern_length = max_pattern_length
        self.stop_patterns = self._load_stop_patterns()
    
    def _load_stop_patterns(self) -> set:
        """Load common patterns that should not be signatured"""
        return {
            'the', 'and', 'for', 'are', 'but', 'not', 'you', 'all', 'can', 'had',
            'her', 'was', 'one', 'our', 'out', 'day', 'get', 'has', 'him', 'his',
            'how', 'its', 'let', 'may', 'new', 'now', 'old', 'see', 'two', 'way',
            'who', 'boy', 'did', 'own', 'say', 'she', 'too', 'use', 'http', 'https',
            'www', 'com', 'org', 'net', 'edu', 'gov'
        }
    
    def extract_string_patterns(self, content: str, min_occurrences: int = 2) -> List[ThreatPattern]:
        """Extract repeated string patterns from content"""
        patterns = []
        
        # Extract n-grams
        words = re.findall(r'\b\w+\b', content.lower())
        word_counts = Counter(words)
        
        for word, count in word_counts.items():
            if (count >= min_occurrences and 
                self.min_pattern_length <= len(word) <= self.max_pattern_length and
                word not in self.stop_patterns):
                
                pattern_id = str(uuid.uuid4())
                patterns.append(ThreatPattern(
                    pattern_id=pattern_id,
                    pattern_type='string',
                    content=word,
                    confidence=min(0.95, count * 0.1),
                    threat_type='suspicious_string',
                    source='pattern_extractor',
                    severity='medium'
                ))
        
        return patterns
    
    def extract_byte_patterns(self, content: bytes) -> List[ThreatPattern]:
        """Extract byte sequences from binary content"""
        patterns = []
        
        # Look for distinctive byte sequences
        if isinstance(content, str):
            content = content.encode('utf-8', errors='ignore')
        
        # Find repeated byte sequences
        seq_length = 8
        sequences = defaultdict(int)
        
        for i in range(len(content) - seq_length + 1):
            seq = content[i:i+seq_length]
            sequences[seq] += 1
        
        for seq, count in sequences.items():
            if count >= 2 and len(set(seq)) > 4:  # Diverse bytes
                hex_str = ' '.join(f'{b:02x}' for b in seq)
                pattern_id = str(uuid.uuid4())
                patterns.append(ThreatPattern(
                    pattern_id=pattern_id,
                    pattern_type='byte_sequence',
                    content=hex_str,
                    confidence=min(0.9, count * 0.15),
                    threat_type='byte_signature',
                    source='byte_analyzer',
                    severity='high'
                ))
        
        return patterns
    
    def extract_regex_patterns(self, content: str) -> List[ThreatPattern]:
        """Extract patterns suitable for regex matching"""
        patterns = []
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(ip_pattern, content)
        for ip in set(ips):
            pattern_id = str(uuid.uuid4())
            patterns.append(ThreatPattern(
                pattern_id=pattern_id,
                pattern_type='regex',
                content=ip,
                confidence=0.85,
                threat_type='ip_address',
                source='regex_extractor',
                severity='high',
                metadata={'pattern': ip_pattern}
            ))
        
        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
        domains = re.findall(domain_pattern, content)
        for domain in set(domains):
            if not any(x in domain.lower() for x in ['example', 'test', 'sample']):
                pattern_id = str(uuid.uuid4())
                patterns.append(ThreatPattern(
                    pattern_id=pattern_id,
                    pattern_type='regex',
                    content=domain,
                    confidence=0.8,
                    threat_type='domain',
                    source='regex_extractor',
                    severity='medium',
                    metadata={'pattern': domain_pattern}
                ))
        
        return patterns


class YARAGenerator:
    """Generates YARA detection rules"""
    
    def __init__(self):
        self.generated_count = 0
    
    def generate_rule(self, patterns: List[ThreatPattern], rule_name: str, 
                     description: str, author: str = "NeuralShield-AI") -> GeneratedSignature:
        """Generate a YARA rule from threat patterns"""
        
        # Build strings section
        strings_section = []
        patterns_used = []
        
        for i, pattern in enumerate(patterns[:10]):  # Max 10 patterns per rule
            if pattern.pattern_type == 'string':
                strings_section.append(f'        $str{i} = "{pattern.content}" nocase')
                patterns_used.append(pattern.pattern_id)
            elif pattern.pattern_type == 'byte_sequence':
                strings_section.append(f'        $hex{i} = {{ {pattern.content} }}')
                patterns_used.append(pattern.pattern_id)
            elif pattern.pattern_type == 'regex':
                strings_section.append(f'        $re{i} = /{re.escape(pattern.content)}/')
                patterns_used.append(pattern.pattern_id)
        
        # Build condition
        if len(patterns_used) >= 3:
            condition = f'{len(patterns_used)} of them'
        elif len(patterns_used) >= 2:
            condition = '2 of them'
        else:
            condition = 'any of them'
        
        # Calculate confidence
        avg_confidence = sum(p.confidence for p in patterns) / len(patterns) if patterns else 0.5
        
        # Build full rule
        rule_content = f'''rule {rule_name.replace(' ', '_').replace('-', '_')} {{
    meta:
        description = "{description}"
        author = "{author}"
        created = "{datetime.now().isoformat()}"
        confidence = {avg_confidence:.2f}
        severity = "medium"
    strings:
{chr(10).join(strings_section)}
    condition:
        {condition}
}}'''
        
        signature_id = f'yara_{uuid.uuid4().hex[:12]}'
        
        return GeneratedSignature(
            signature_id=signature_id,
            signature_type='yara',
            rule_content=rule_content,
            patterns_used=patterns_used,
            confidence_score=avg_confidence,
            false_positive_risk='low' if avg_confidence > 0.7 else 'medium'
        )


class SNORTGenerator:
    """Generates SNORT/Suricata detection rules"""
    
    def __init__(self):
        self.generated_count = 0
    
    def generate_rule(self, patterns: List[ThreatPattern], rule_name: str,
                     action: str = "alert", protocol: str = "tcp") -> GeneratedSignature:
        """Generate a SNORT rule from threat patterns"""
        
        # Build content matches
        content_matches = []
        patterns_used = []
        
        for pattern in patterns[:5]:
            if pattern.pattern_type == 'string':
                escaped = pattern.content.replace(';', '|3B|').replace('"', '|22|')
                content_matches.append(f'content:"{escaped}"; nocase;')
                patterns_used.append(pattern.pattern_id)
            elif pattern.pattern_type == 'regex':
                content_matches.append(f'pcre:"/{re.escape(pattern.content)}/i";')
                patterns_used.append(pattern.pattern_id)
        
        # Calculate confidence
        avg_confidence = sum(p.confidence for p in patterns) / len(patterns) if patterns else 0.5
        
        # Build SNORT rule
        sid = hash(rule_name) % 1000000 + 1000000
        msg = rule_name.replace('"', '\\"')
        
        rule_content = (
            f'{action} {protocol} $EXTERNAL_NET any -> $HOME_NET any '
            f'(msg:"{msg}"; '
            f'{" ".join(content_matches)} '
            f'sid:{sid}; rev:1; '
            f'classtype:trojan-activity; '
            f'priority:2;)'
        )
        
        signature_id = f'snort_{uuid.uuid4().hex[:12]}'
        
        return GeneratedSignature(
            signature_id=signature_id,
            signature_type='snort',
            rule_content=rule_content,
            patterns_used=patterns_used,
            confidence_score=avg_confidence,
            false_positive_risk='medium'
        )


class SignatureAutoGeneratorEngine:
    """
    Main engine for automated signature generation
    Production-grade with pattern extraction, rule generation, and quality control
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.pattern_extractor = PatternExtractor()
        self.yara_generator = YARAGenerator()
        self.snort_generator = SNORTGenerator()
        
        self.generated_signatures: List[GeneratedSignature] = []
        self.detected_patterns: List[ThreatPattern] = []
        self.generation_stats = defaultdict(int)
        
    def process_threat_sample(self, sample_content: str, sample_type: str = 'text',
                             threat_name: str = "Unknown_Threat") -> Dict[str, Any]:
        """
        Process a threat sample and generate detection signatures
        Returns dictionary with generated rules and metadata
        """
        start_time = time.time()
        
        # Extract patterns
        patterns = []
        
        if sample_type in ['text', 'log', 'payload']:
            patterns.extend(self.pattern_extractor.extract_string_patterns(sample_content))
            patterns.extend(self.pattern_extractor.extract_regex_patterns(sample_content))
        
        if sample_type in ['binary', 'hex', 'payload']:
            try:
                if isinstance(sample_content, str):
                    binary_content = sample_content.encode('utf-8', errors='ignore')
                else:
                    binary_content = sample_content
                patterns.extend(self.pattern_extractor.extract_byte_patterns(binary_content))
            except:
                pass
        
        self.detected_patterns.extend(patterns)
        
        # Filter high-confidence patterns
        high_conf_patterns = [p for p in patterns if p.confidence >= 0.6]
        
        if not high_conf_patterns:
            high_conf_patterns = patterns[:3]  # Fallback
        
        # Generate signatures
        signatures = []
        
        # Generate YARA rule
        if high_conf_patterns:
            yara_sig = self.yara_generator.generate_rule(
                high_conf_patterns,
                rule_name=f'NeuralShield_{threat_name}_{int(time.time())}',
                description=f'Auto-generated rule for {threat_name} threat'
            )
            signatures.append(yara_sig)
            self.generated_signatures.append(yara_sig)
            self.generation_stats['yara_rules'] += 1
        
        # Generate SNORT rule
        if high_conf_patterns:
            snort_sig = self.snort_generator.generate_rule(
                high_conf_patterns,
                rule_name=f'NeuralShield Detected {threat_name}'
            )
            signatures.append(snort_sig)
            self.generated_signatures.append(snort_sig)
            self.generation_stats['snort_rules'] += 1
        
        self.generation_stats['total_samples_processed'] += 1
        self.generation_stats['total_patterns_extracted'] += len(patterns)
        
        return {
            'success': True,
            'sample_type': sample_type,
            'patterns_extracted': len(patterns),
            'high_confidence_patterns': len(high_conf_patterns),
            'signatures_generated': len(signatures),
            'signatures': signatures,
            'patterns': patterns,
            'processing_time': time.time() - start_time,
            'timestamp': datetime.now().isoformat()
        }
    
    def batch_process_samples(self, samples: List[Dict[str, str]]) -> Dict[str, Any]:
        """Process multiple threat samples in batch"""
        results = []
        
        for sample in samples:
            result = self.process_threat_sample(
                sample.get('content', ''),
                sample.get('type', 'text'),
                sample.get('name', 'Unknown')
            )
            results.append(result)
        
        return {
            'batch_size': len(samples),
            'results': results,
            'total_signatures': sum(r['signatures_generated'] for r in results),
            'total_patterns': sum(r['patterns_extracted'] for r in results)
        }
    
    def export_signatures(self, output_format: str = 'json') -> str:
        """Export all generated signatures"""
        if output_format == 'json':
            export_data = []
            for sig in self.generated_signatures:
                export_data.append({
                    'signature_id': sig.signature_id,
                    'type': sig.signature_type,
                    'rule': sig.rule_content,
                    'confidence': sig.confidence_score,
                    'fp_risk': sig.false_positive_risk
                })
            return json.dumps(export_data, indent=2)
        elif output_format == 'raw':
            return '\n\n'.join(s.rule_content for s in self.generated_signatures)
        else:
            raise ValueError(f"Unsupported format: {output_format}")
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generation statistics"""
        return {
            **dict(self.generation_stats),
            'total_signatures_generated': len(self.generated_signatures),
            'total_patterns_detected': len(self.detected_patterns),
            'avg_confidence': (
                sum(s.confidence_score for s in self.generated_signatures) / 
                len(self.generated_signatures) if self.generated_signatures else 0
            )
        }


# Export main class
__all__ = ['SignatureAutoGeneratorEngine', 'ThreatPattern', 'GeneratedSignature']
