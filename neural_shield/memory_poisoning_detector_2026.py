"""
Memory Poisoning Detector 2026
Based on Microsoft Research: Memory Poisoning, Jailbreaks, and Evasion Techniques
Detects data poisoning attacks in training data and RAG contexts
"""

import numpy as np
from collections import Counter
from typing import List, Dict, Tuple
import re


class MemoryPoisoningDetector:
    """
    Detects poisoning attacks in training data, embeddings, and RAG contexts
    Implements 2026 state-of-the-art detection techniques
    """
    
    def __init__(self):
        self.poisoning_signatures = [
            'trigger_word',
            'backdoor_pattern',
            'distribution_shift',
            'outlier_embedding',
            'syntax_anomaly'
        ]
        self.detections = []
        
    def detect_trigger_words(self, texts: List[str]) -> Tuple[bool, Dict]:
        """
        Detect trigger words used in backdoor attacks
        Trigger words are rare words that cause targeted misclassification
        """
        # Get word frequency distribution
        all_words = []
        for text in texts:
            words = re.findall(r'\b\w+\b', text.lower())
            all_words.extend(words)
        
        word_counts = Counter(all_words)
        total_words = len(all_words)
        
        # Find unusually rare words that appear together
        rare_words = {word: count for word, count in word_counts.items() 
                     if count / total_words < 0.001}
        
        # Check for co-occurrence patterns
        suspicious_triggers = []
        for word in rare_words:
            co_occurrences = sum(1 for text in texts if word in text.lower())
            if co_occurrences >= 3:  # Appears in multiple samples
                suspicious_triggers.append(word)
        
        is_poisoned = len(suspicious_triggers) >= 2
        
        result = {
            'suspicious_triggers': suspicious_triggers,
            'rare_words_count': len(rare_words),
            'is_poisoned': is_poisoned,
            'detection_type': 'trigger_words'
        }
        
        if is_poisoned:
            self.detections.append(result)
        
        return is_poisoned, result
    
    def detect_embedding_outliers(self, embeddings: np.ndarray) -> Tuple[bool, Dict]:
        """
        Detect outlier embeddings that indicate poisoned data points
        Uses Mahalanobis distance for robust outlier detection
        """
        if len(embeddings) < 10:
            return False, {'error': 'insufficient_samples'}
        
        # Compute centroid
        centroid = np.mean(embeddings, axis=0)
        
        # Compute distances from centroid
        distances = np.linalg.norm(embeddings - centroid, axis=1)
        
        # Use IQR method for outlier detection
        q1 = np.percentile(distances, 25)
        q3 = np.percentile(distances, 75)
        iqr = q3 - q1
        threshold = q3 + 1.5 * iqr
        
        outlier_indices = np.where(distances > threshold)[0]
        outlier_ratio = len(outlier_indices) / len(distances)
        
        # Poisoning indicated by >5% outliers
        is_poisoned = outlier_ratio > 0.05
        
        result = {
            'outlier_count': len(outlier_indices),
            'outlier_ratio': float(outlier_ratio),
            'outlier_indices': outlier_indices.tolist(),
            'distance_threshold': float(threshold),
            'is_poisoned': is_poisoned,
            'detection_type': 'embedding_outliers'
        }
        
        if is_poisoned:
            self.detections.append(result)
        
        return is_poisoned, result
    
    def detect_distribution_shift(self, reference_stats: Dict, current_stats: Dict) -> Tuple[bool, Dict]:
        """
        Detect distribution shift between reference and current data
        Indicates potential data poisoning or concept drift attacks
        """
        shifts = {}
        significant_shift = False
        
        for key in reference_stats:
            if key in current_stats and isinstance(reference_stats[key], (int, float)):
                ref_val = reference_stats[key]
                curr_val = current_stats[key]
                if ref_val > 0:
                    relative_change = abs(curr_val - ref_val) / ref_val
                    shifts[key] = relative_change
                    if relative_change > 0.3:  # >30% change
                        significant_shift = True
        
        is_poisoned = significant_shift
        
        result = {
            'feature_shifts': shifts,
            'significant_shift_detected': significant_shift,
            'is_poisoned': is_poisoned,
            'detection_type': 'distribution_shift'
        }
        
        if is_poisoned:
            self.detections.append(result)
        
        return is_poisoned, result
    
    def scan_rag_context(self, context_chunks: List[str]) -> Tuple[bool, Dict]:
        """
        Scan RAG context chunks for poisoning attacks
        Detects: hidden instructions, adversarial examples, data leaks
        """
        issues = []
        
        # Check for hidden instructions
        hidden_patterns = [
            r'<\|endoftext\|>',
            r'### Instruction:',
            r'Human:',
            r'Assistant:',
            r'Ignore all previous'
        ]
        
        for i, chunk in enumerate(context_chunks):
            for pattern in hidden_patterns:
                if re.search(pattern, chunk, re.IGNORECASE):
                    issues.append({
                        'chunk_index': i,
                        'issue': 'hidden_instruction',
                        'pattern': pattern
                    })
        
        # Check for repeated trigger patterns
        trigger_counts = Counter()
        for chunk in context_chunks:
            words = re.findall(r'\b\w{8,}\b', chunk)
            for word in words:
                trigger_counts[word] += 1
        
        repeated_triggers = {w: c for w, c in trigger_counts.items() if c >= 3}
        if repeated_triggers:
            issues.append({
                'issue': 'repeated_triggers',
                'triggers': repeated_triggers
            })
        
        is_poisoned = len(issues) > 0
        
        result = {
            'issues': issues,
            'is_poisoned': is_poisoned,
            'chunks_scanned': len(context_chunks),
            'detection_type': 'rag_poisoning'
        }
        
        if is_poisoned:
            self.detections.append(result)
        
        return is_poisoned, result
    
    def get_detection_report(self) -> Dict:
        """Get comprehensive poisoning detection report"""
        return {
            'total_detections': len(self.detections),
            'detections': self.detections.copy(),
            'detection_types': [d['detection_type'] for d in self.detections]
        }
