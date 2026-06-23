"""
NeuralShield AI - Threat Intelligence Automated Signature Generator v17
Dimension A - Feature Expansion (Incremental Build)

Add-only feature: Automated threat signature generation with pattern learning,
auto-update mechanisms, and signature effectiveness scoring.
Does NOT modify any existing code - completely new module.

API Stability: STABLE
Backward Compatible: YES
"""

import hashlib
import re
import json
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict, deque
from datetime import datetime, timedelta
import threading


@dataclass
class ThreatSignature:
    """Data class representing a generated threat signature."""
    signature_id: str
    pattern: str
    pattern_type: str  # regex, substring, heuristic, embedding
    threat_category: str
    confidence: float
    severity: str
    created_at: float
    last_updated: float
    hit_count: int = 0
    false_positive_count: int = 0
    effectiveness_score: float = 0.0
    is_active: bool = True
    version: str = "1.0.0"
    tags: List[str] = field(default_factory=list)
    source_samples: List[str] = field(default_factory=list)


@dataclass
class SignatureGenerationResult:
    """Result of signature generation attempt."""
    success: bool
    signature: Optional[ThreatSignature] = None
    generated_patterns: List[str] = field(default_factory=list)
    confidence_scores: Dict[str, float] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)
    processing_time_ms: float = 0.0


class ThreatPatternExtractor:
    """Extracts common patterns from threat samples."""
    
    def __init__(self, min_pattern_length: int = 4, max_pattern_length: int = 64):
        self.min_pattern_length = min_pattern_length
        self.max_pattern_length = max_pattern_length
        self._pattern_cache: Dict[str, float] = {}
        
    def extract_common_substrings(self, samples: List[str], min_occurrence: int = 2) -> List[Tuple[str, int]]:
        """Extract frequently occurring substrings across samples."""
        substring_counts: Dict[str, int] = defaultdict(int)
        
        for sample in samples:
            seen_in_sample: Set[str] = set()
            for length in range(self.min_pattern_length, min(self.max_pattern_length, len(sample)) + 1):
                for i in range(len(sample) - length + 1):
                    substr = sample[i:i+length]
                    if substr not in seen_in_sample:
                        substring_counts[substr] += 1
                        seen_in_sample.add(substr)
        
        results = [(pattern, count) for pattern, count in substring_counts.items() 
                  if count >= min_occurrence]
        return sorted(results, key=lambda x: (-x[1], -len(x[0])))
    
    def generate_regex_pattern(self, samples: List[str]) -> Tuple[str, float]:
        """Generate a regex pattern from threat samples with confidence score."""
        if not samples:
            return "", 0.0
        
        # Extract common tokens
        tokens: List[str] = []
        for sample in samples:
            # Split by common delimiters
            sample_tokens = re.split(r'[\s_\-\.\[\]{}()<>/\\]+', sample.lower())
            tokens.extend([t for t in sample_tokens if len(t) >= 3])
        
        # Count token frequency
        token_counts: Dict[str, int] = defaultdict(int)
        for token in tokens:
            token_counts[token] += 1
        
        common_tokens = [t for t, c in token_counts.items() if c >= len(samples) * 0.5]
        
        if not common_tokens:
            return "", 0.3
        
        # Build regex pattern
        pattern_parts = []
        for token in common_tokens[:5]:  # Top 5 common tokens
            pattern_parts.append(re.escape(token))
        
        regex_pattern = ".*" + ".*".join(pattern_parts) + ".*"
        confidence = min(0.95, 0.4 + (len(common_tokens) * 0.1))
        
        return regex_pattern, confidence
    
    def calculate_similarity_hash(self, sample: str) -> str:
        """Calculate a similarity hash for threat clustering."""
        # Simple rolling hash for similarity
        words = sample.lower().split()
        hash_input = "|".join(sorted(set(words))[:20])
        return hashlib.sha256(hash_input.encode()).hexdigest()[:16]


class ThreatIntelligenceSignatureGenerator:
    """
    Main signature generator class.
    NEW ADD-ONLY FEATURE - Does not modify any existing modules.
    """
    
    def __init__(self, auto_update_interval: int = 3600, max_signatures: int = 10000):
        self.signatures: Dict[str, ThreatSignature] = {}
        self.signature_index: Dict[str, List[str]] = defaultdict(list)
        self.pattern_extractor = ThreatPatternExtractor()
        self.auto_update_interval = auto_update_interval
        self.max_signatures = max_signatures
        self.generation_stats: Dict[str, Any] = {
            "total_generated": 0,
            "total_activated": 0,
            "total_hits": 0,
            "false_positives": 0
        }
        self._lock = threading.RLock()
        self._last_update = time.time()
        
    def generate_signature_from_samples(
        self,
        threat_samples: List[str],
        threat_category: str,
        severity: str = "medium",
        tags: Optional[List[str]] = None
    ) -> SignatureGenerationResult:
        """
        Generate a new threat signature from a list of threat samples.
        
        Args:
            threat_samples: List of threat sample strings to analyze
            threat_category: Category of threat (e.g., "prompt_injection", "jailbreak")
            severity: Threat severity level
            tags: Optional tags for classification
            
        Returns:
            SignatureGenerationResult with generated signature
        """
        start_time = time.time()
        result = SignatureGenerationResult(success=False)
        result.warnings = []
        
        if len(threat_samples) < 2:
            result.warnings.append("At least 2 threat samples recommended for reliable signature generation")
        
        if len(threat_samples) == 0:
            result.warnings.append("No threat samples provided")
            result.processing_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Generate patterns
        regex_pattern, regex_confidence = self.pattern_extractor.generate_regex_pattern(threat_samples)
        common_substrings = self.pattern_extractor.extract_common_substrings(threat_samples)
        
        result.generated_patterns = [p for p, _ in common_substrings[:10]]
        result.confidence_scores = {"regex": regex_confidence}
        
        # Determine best pattern
        best_pattern = regex_pattern if regex_pattern and regex_confidence > 0.5 else ""
        if not best_pattern and common_substrings:
            best_pattern = common_substrings[0][0]
        
        if not best_pattern:
            result.warnings.append("Could not extract reliable pattern from samples")
            result.processing_time_ms = (time.time() - start_time) * 1000
            return result
        
        # Calculate overall confidence
        overall_confidence = min(0.98, regex_confidence + (len(threat_samples) * 0.02))
        
        # Create signature ID
        sig_id = hashlib.sha256(f"{best_pattern}|{threat_category}|{time.time()}".encode()).hexdigest()[:16]
        
        signature = ThreatSignature(
            signature_id=f"NS-SIG-{sig_id.upper()}",
            pattern=best_pattern,
            pattern_type="regex" if regex_confidence > 0.5 else "substring",
            threat_category=threat_category,
            confidence=overall_confidence,
            severity=severity,
            created_at=time.time(),
            last_updated=time.time(),
            tags=tags or [],
            source_samples=threat_samples[:5]  # Store first 5 samples
        )
        
        with self._lock:
            self.signatures[signature.signature_id] = signature
            self.signature_index[threat_category].append(signature.signature_id)
            self.generation_stats["total_generated"] += 1
            self.generation_stats["total_activated"] += 1
        
        result.success = True
        result.signature = signature
        result.processing_time_ms = (time.time() - start_time) * 1000
        
        return result
    
    def match_threat(self, input_text: str, categories: Optional[List[str]] = None) -> List[Tuple[ThreatSignature, float]]:
        """
        Match input text against active signatures.
        
        Args:
            input_text: Text to scan for threats
            categories: Optional list of categories to limit matching
            
        Returns:
            List of (signature, match_score) tuples
        """
        matches: List[Tuple[ThreatSignature, float]] = []
        input_lower = input_text.lower()
        
        with self._lock:
            sig_ids_to_check: List[str] = []
            if categories:
                for cat in categories:
                    sig_ids_to_check.extend(self.signature_index.get(cat, []))
            else:
                sig_ids_to_check = list(self.signatures.keys())
            
            for sig_id in sig_ids_to_check:
                sig = self.signatures.get(sig_id)
                if not sig or not sig.is_active:
                    continue
                
                match_score = 0.0
                try:
                    if sig.pattern_type == "regex":
                        if re.search(sig.pattern, input_lower, re.IGNORECASE):
                            match_score = sig.confidence
                    else:  # substring
                        if sig.pattern.lower() in input_lower:
                            match_score = sig.confidence
                except re.error:
                    continue
                
                if match_score > 0.5:
                    sig.hit_count += 1
                    self.generation_stats["total_hits"] += 1
                    matches.append((sig, match_score))
        
        return sorted(matches, key=lambda x: -x[1])
    
    def report_false_positive(self, signature_id: str) -> bool:
        """Report a false positive hit for a signature."""
        with self._lock:
            sig = self.signatures.get(signature_id)
            if sig:
                sig.false_positive_count += 1
                self.generation_stats["false_positives"] += 1
                
                # Update effectiveness score
                total = sig.hit_count + sig.false_positive_count
                if total > 0:
                    sig.effectiveness_score = sig.hit_count / total
                
                # Auto-deactivate if effectiveness drops too low
                if sig.effectiveness_score < 0.3 and total > 10:
                    sig.is_active = False
                return True
        return False
    
    def update_signature_effectiveness(self) -> Dict[str, Any]:
        """Update effectiveness scores for all signatures."""
        update_stats = {
            "updated": 0,
            "deactivated": 0,
            "avg_effectiveness": 0.0
        }
        
        with self._lock:
            total_effectiveness = 0.0
            active_count = 0
            
            for sig in self.signatures.values():
                total = sig.hit_count + sig.false_positive_count
                if total > 0:
                    sig.effectiveness_score = sig.hit_count / total
                    update_stats["updated"] += 1
                    
                    if sig.effectiveness_score < 0.25 and total > 20:
                        sig.is_active = False
                        update_stats["deactivated"] += 1
                
                if sig.is_active:
                    total_effectiveness += sig.effectiveness_score
                    active_count += 1
            
            if active_count > 0:
                update_stats["avg_effectiveness"] = total_effectiveness / active_count
            
            self._last_update = time.time()
        
        return update_stats
    
    def export_signatures(self, filepath: Optional[str] = None) -> Dict[str, Any]:
        """Export all signatures to JSON format."""
        export_data = {
            "export_version": "1.0.0",
            "export_timestamp": datetime.utcnow().isoformat(),
            "generator_version": "v17",
            "total_signatures": len(self.signatures),
            "signatures": []
        }
        
        with self._lock:
            for sig in self.signatures.values():
                export_data["signatures"].append({
                    "signature_id": sig.signature_id,
                    "pattern": sig.pattern,
                    "pattern_type": sig.pattern_type,
                    "threat_category": sig.threat_category,
                    "confidence": sig.confidence,
                    "severity": sig.severity,
                    "created_at": sig.created_at,
                    "hit_count": sig.hit_count,
                    "false_positive_count": sig.false_positive_count,
                    "effectiveness_score": sig.effectiveness_score,
                    "is_active": sig.is_active,
                    "tags": sig.tags
                })
        
        if filepath:
            with open(filepath, 'w') as f:
                json.dump(export_data, f, indent=2)
        
        return export_data
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get generator statistics."""
        with self._lock:
            stats = dict(self.generation_stats)
            stats.update({
                "active_signatures": sum(1 for s in self.signatures.values() if s.is_active),
                "total_signatures": len(self.signatures),
                "categories_covered": len(self.signature_index),
                "last_update_time": self._last_update
            })
        return stats


# Singleton instance for global use
_signature_generator_instance: Optional[ThreatIntelligenceSignatureGenerator] = None

def get_signature_generator() -> ThreatIntelligenceSignatureGenerator:
    """Get or create the global signature generator instance."""
    global _signature_generator_instance
    if _signature_generator_instance is None:
        _signature_generator_instance = ThreatIntelligenceSignatureGenerator()
    return _signature_generator_instance
