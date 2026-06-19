"""
Threat Intelligence Alert Context Similarity Scoring Engine
Production-grade implementation for NeuralShield-AI

This module provides:
1. TF-IDF based vectorization of alert context
2. Cosine similarity scoring between alerts
3. Duplicate/similar alert detection
4. Context-aware false positive reduction
5. Real-time similarity lookup with caching
"""

import re
import json
import hashlib
import time
import math
from collections import defaultdict, Counter
from typing import Dict, List, Tuple, Optional, Any
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
import threading


@dataclass
class AlertContext:
    """Structured alert context data"""
    alert_id: str
    source: str
    title: str
    description: str
    severity: str
    ip_address: Optional[str] = None
    domain: Optional[str] = None
    mitre_technique: Optional[str] = None
    timestamp: float = 0.0
    raw_context: str = ""
    
    def to_vector_text(self) -> str:
        """Convert alert to text for vectorization"""
        parts = [
            self.title.lower(),
            self.description.lower(),
            self.source.lower(),
            self.severity.lower()
        ]
        if self.ip_address:
            parts.append(self.ip_address)
        if self.domain:
            parts.append(self.domain)
        if self.mitre_technique:
            parts.append(self.mitre_technique)
        return " ".join(parts)


class TFIDFVectorizer:
    """Lightweight TF-IDF vectorizer optimized for security alerts"""
    
    def __init__(self, max_features: int = 1000):
        self.max_features = max_features
        self.vocabulary: Dict[str, int] = {}
        self.idf: Dict[str, float] = {}
        self.document_count = 0
        self.word_document_counts: Dict[str, int] = defaultdict(int)
        self._stopwords = self._load_security_stopwords()
    
    def _load_security_stopwords(self) -> set:
        """Security-specific stopwords"""
        return {
            'a', 'an', 'the', 'and', 'or', 'but', 'is', 'are', 'was', 'were',
            'be', 'been', 'being', 'in', 'on', 'at', 'to', 'for', 'of', 'with',
            'by', 'from', 'as', 'into', 'through', 'during', 'before', 'after',
            'above', 'below', 'between', 'under', 'again', 'further', 'then',
            'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all',
            'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor',
            'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very', 'can',
            'will', 'just', 'should', 'now', 'alert', 'detected', 'found',
            'potential', 'possible', 'suspected', 'identified'
        }
    
    def _tokenize(self, text: str) -> List[str]:
        """Tokenize and clean text"""
        # Remove special characters but keep IP/domain patterns
        text = re.sub(r'[^\w\s\.\-]', ' ', text.lower())
        tokens = text.split()
        return [t for t in tokens if t not in self._stopwords and len(t) > 2]
    
    def fit(self, documents: List[str]) -> None:
        """Fit vectorizer on corpus"""
        self.document_count = len(documents)
        self.word_document_counts.clear()
        
        # Count document frequencies
        for doc in documents:
            tokens = set(self._tokenize(doc))
            for token in tokens:
                self.word_document_counts[token] += 1
        
        # Build vocabulary (top N words)
        sorted_words = sorted(
            self.word_document_counts.items(),
            key=lambda x: x[1],
            reverse=True
        )[:self.max_features]
        
        self.vocabulary = {word: idx for idx, (word, _) in enumerate(sorted_words)}
        
        # Calculate IDF
        for word, doc_count in self.word_document_counts.items():
            if word in self.vocabulary:
                self.idf[word] = math.log(
                    (self.document_count + 1) / (doc_count + 1)
                ) + 1
    
    def transform(self, text: str) -> Dict[int, float]:
        """Transform text to TF-IDF vector (sparse representation)"""
        tokens = self._tokenize(text)
        tf = Counter(tokens)
        total_terms = len(tokens)
        
        vector: Dict[int, float] = {}
        if total_terms == 0:
            return vector
        
        for token, count in tf.items():
            if token in self.vocabulary:
                tf_val = count / total_terms
                tfidf_val = tf_val * self.idf.get(token, 1.0)
                vector[self.vocabulary[token]] = tfidf_val
        
        return vector


def cosine_similarity(vec1: Dict[int, float], vec2: Dict[int, float]) -> float:
    """Calculate cosine similarity between two sparse vectors"""
    if not vec1 or not vec2:
        return 0.0
    
    # Dot product
    dot_product = 0.0
    for idx, val in vec1.items():
        if idx in vec2:
            dot_product += val * vec2[idx]
    
    # Norms
    norm1 = math.sqrt(sum(v * v for v in vec1.values()))
    norm2 = math.sqrt(sum(v * v for v in vec2.values()))
    
    if norm1 == 0 or norm2 == 0:
        return 0.0
    
    return dot_product / (norm1 * norm2)


class ContextSimilarityEngine:
    """
    Production-grade context similarity engine for threat intelligence alerts
    
    Features:
    - Real-time similarity scoring
    - Duplicate alert detection
    - Caching for performance
    - Threshold-based grouping
    - Historical context comparison
    """
    
    def __init__(
        self,
        similarity_threshold: float = 0.75,
        max_cached_alerts: int = 10000,
        cache_ttl_seconds: int = 3600
    ):
        self.similarity_threshold = similarity_threshold
        self.max_cached_alerts = max_cached_alerts
        self.cache_ttl_seconds = cache_ttl_seconds
        
        self.vectorizer = TFIDFVectorizer(max_features=2000)
        self.alert_vectors: Dict[str, Dict[int, float]] = {}
        self.alert_cache: Dict[str, Tuple[AlertContext, float]] = {}
        self.alert_timestamps: Dict[str, float] = {}
        
        self._lock = threading.RLock()
        self._is_trained = False
        self._training_corpus: List[str] = []
    
    def add_to_training_corpus(self, alert: AlertContext) -> None:
        """Add alert to training corpus for vectorizer"""
        with self._lock:
            self._training_corpus.append(alert.to_vector_text())
            self._is_trained = False
    
    def train(self, force: bool = False) -> bool:
        """Train the TF-IDF vectorizer"""
        with self._lock:
            if self._is_trained and not force:
                return True
            
            if len(self._training_corpus) < 10:
                return False  # Not enough data
            
            self.vectorizer.fit(self._training_corpus)
            self._is_trained = True
            return True
    
    def _clean_expired_cache(self) -> None:
        """Remove expired entries from cache"""
        now = time.time()
        expired = [
            aid for aid, ts in self.alert_timestamps.items()
            if now - ts > self.cache_ttl_seconds
        ]
        for aid in expired:
            del self.alert_cache[aid]
            del self.alert_vectors[aid]
            del self.alert_timestamps[aid]
    
    def _enforce_cache_size(self) -> None:
        """Enforce maximum cache size"""
        if len(self.alert_cache) > self.max_cached_alerts:
            # Remove oldest entries
            sorted_alerts = sorted(
                self.alert_timestamps.items(),
                key=lambda x: x[1]
            )
            to_remove = len(self.alert_cache) - self.max_cached_alerts
            for aid, _ in sorted_alerts[:to_remove]:
                del self.alert_cache[aid]
                del self.alert_vectors[aid]
                del self.alert_timestamps[aid]
    
    def index_alert(self, alert: AlertContext) -> str:
        """Index an alert for similarity lookup"""
        with self._lock:
            # Ensure vectorizer is trained
            if not self._is_trained:
                self.add_to_training_corpus(alert)
                self.train()
            
            # Generate alert ID if not provided
            if not alert.alert_id:
                alert.alert_id = hashlib.md5(
                    f"{alert.title}{alert.description}{time.time()}".encode()
                ).hexdigest()[:16]
            
            # Vectorize
            vector = self.vectorizer.transform(alert.to_vector_text())
            
            # Cache
            self.alert_vectors[alert.alert_id] = vector
            self.alert_cache[alert.alert_id] = (alert, time.time())
            self.alert_timestamps[alert.alert_id] = time.time()
            
            # Cleanup
            self._clean_expired_cache()
            self._enforce_cache_size()
            
            return alert.alert_id
    
    def find_similar_alerts(
        self,
        alert: AlertContext,
        top_k: int = 10
    ) -> List[Tuple[str, float, AlertContext]]:
        """Find alerts similar to the given alert"""
        with self._lock:
            if not self._is_trained:
                return []
            
            query_vector = self.vectorizer.transform(alert.to_vector_text())
            
            results = []
            for alert_id, cached_vector in self.alert_vectors.items():
                sim = cosine_similarity(query_vector, cached_vector)
                if sim >= self.similarity_threshold:
                    cached_alert, _ = self.alert_cache[alert_id]
                    results.append((alert_id, sim, cached_alert))
            
            # Sort by similarity descending
            results.sort(key=lambda x: x[1], reverse=True)
            return results[:top_k]
    
    def calculate_similarity_score(
        self,
        alert1: AlertContext,
        alert2: AlertContext
    ) -> float:
        """Calculate similarity score between two alerts"""
        if not self._is_trained:
            # Fallback: simple string similarity
            text1 = alert1.to_vector_text()
            text2 = alert2.to_vector_text()
            words1 = set(text1.split())
            words2 = set(text2.split())
            if not words1 or not words2:
                return 0.0
            return len(words1 & words2) / len(words1 | words2)
        
        vec1 = self.vectorizer.transform(alert1.to_vector_text())
        vec2 = self.vectorizer.transform(alert2.to_vector_text())
        return cosine_similarity(vec1, vec2)
    
    def is_potential_duplicate(
        self,
        alert: AlertContext,
        window_minutes: int = 60
    ) -> Tuple[bool, List[Dict[str, Any]]]:
        """
        Check if alert is potentially a duplicate within time window
        
        Returns: (is_duplicate, list of similar alerts with scores)
        """
        similar = self.find_similar_alerts(alert, top_k=5)
        window_start = time.time() - (window_minutes * 60)
        
        duplicates = []
        for alert_id, score, similar_alert in similar:
            if similar_alert.timestamp >= window_start:
                duplicates.append({
                    'alert_id': alert_id,
                    'similarity_score': round(score, 4),
                    'title': similar_alert.title,
                    'source': similar_alert.source,
                    'severity': similar_alert.severity
                })
        
        return len(duplicates) > 0, duplicates
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics"""
        with self._lock:
            return {
                'indexed_alerts': len(self.alert_cache),
                'vocabulary_size': len(self.vectorizer.vocabulary),
                'is_trained': self._is_trained,
                'training_documents': len(self._training_corpus),
                'similarity_threshold': self.similarity_threshold,
                'cache_ttl_seconds': self.cache_ttl_seconds
            }
    
    def export_state(self) -> str:
        """Export engine state for persistence"""
        with self._lock:
            state = {
                'vectorizer_vocabulary': self.vectorizer.vocabulary,
                'vectorizer_idf': self.vectorizer.idf,
                'stats': self.get_stats(),
                'exported_at': datetime.utcnow().isoformat()
            }
            return json.dumps(state, indent=2)
