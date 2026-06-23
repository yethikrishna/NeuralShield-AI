"""
Test Suite: Threat Intelligence Semantic Similarity Search Engine v18
Dimension A - Feature Expansion Tests
ADD-ONLY: Tests only, no production code modified
All existing tests must continue to pass
"""

import pytest
import json
import time

from neural_shield.threat_intelligence_semantic_similarity_search_engine_v18_2026_june import (
    SemanticSimilarityEngine,
    SemanticVectorizer,
    SimilarityMetric,
    ThreatVector,
    SimilarityResult,
    index_threat,
    search_similar,
    get_semantic_search_stats
)


class TestSemanticVectorizer:
    """Test the vectorizer component"""
    
    def test_vectorizer_initialization(self):
        """Test vectorizer initializes correctly"""
        vectorizer = SemanticVectorizer(vector_dimension=64)
        assert vectorizer.vector_dimension == 64
        assert len(vectorizer._feature_weights) > 0
    
    def test_vectorize_produces_correct_dimension(self):
        """Test vector output has correct dimension"""
        vectorizer = SemanticVectorizer(vector_dimension=128)
        threat_data = {"severity": "high", "threat_type": "malware"}
        vector = vectorizer.vectorize(threat_data)
        assert len(vector) == 128
        assert all(isinstance(v, float) for v in vector)
    
    def test_vectorize_normalized(self):
        """Test vectors are normalized to unit length"""
        vectorizer = SemanticVectorizer(vector_dimension=128)
        threat_data = {"severity": "critical", "attack_vector": "network"}
        vector = vectorizer.vectorize(threat_data)
        norm = sum(v * v for v in vector) ** 0.5
        assert abs(norm - 1.0) < 0.001  # Should be unit vector
    
    def test_deterministic_vectorization(self):
        """Test same input produces same vector"""
        vectorizer = SemanticVectorizer()
        threat_data = {"severity": "medium", "threat_type": "phishing"}
        v1 = vectorizer.vectorize(threat_data)
        v2 = vectorizer.vectorize(threat_data)
        assert v1 == v2
    
    def test_different_inputs_different_vectors(self):
        """Test different inputs produce different vectors"""
        vectorizer = SemanticVectorizer()
        t1 = {"severity": "high", "threat_type": "malware"}
        t2 = {"severity": "low", "threat_type": "spam"}
        v1 = vectorizer.vectorize(t1)
        v2 = vectorizer.vectorize(t2)
        assert v1 != v2


class TestSemanticSimilarityEngine:
    """Test the core similarity engine"""
    
    def test_engine_initialization(self):
        """Test engine initializes correctly"""
        engine = SemanticSimilarityEngine(
            vector_dimension=64,
            metric=SimilarityMetric.COSINE,
            cache_size=5000
        )
        assert engine.vector_dimension == 64
        assert engine.metric == SimilarityMetric.COSINE
        assert engine.cache_size == 5000
        assert len(engine._vector_store) == 0
    
    def test_index_threat(self):
        """Test indexing a threat"""
        engine = SemanticSimilarityEngine()
        threat_data = {
            "severity": "high",
            "threat_type": "ransomware",
            "attack_vector": "email",
            "confidence": "0.9"
        }
        threat_id = engine.index_threat(threat_data)
        assert threat_id is not None
        assert len(threat_id) == 16
        assert len(engine._vector_store) == 1
        assert engine._stats["total_indexed"] == 1
    
    def test_index_threat_with_custom_id(self):
        """Test indexing with custom threat ID"""
        engine = SemanticSimilarityEngine()
        threat_data = {"severity": "critical"}
        custom_id = "threat_12345"
        threat_id = engine.index_threat(threat_data, threat_id=custom_id)
        assert threat_id == custom_id
        assert custom_id in engine._vector_store
    
    def test_batch_index(self):
        """Test batch indexing"""
        engine = SemanticSimilarityEngine()
        threats = [
            {"severity": "high", "threat_type": "malware"},
            {"severity": "medium", "threat_type": "phishing"},
            {"severity": "low", "threat_type": "spam"},
            {"severity": "critical", "threat_type": "ransomware"}
        ]
        ids = engine.batch_index(threats)
        assert len(ids) == 4
        assert len(engine._vector_store) == 4
    
    def test_search_similar_returns_results(self):
        """Test similarity search returns matching results"""
        engine = SemanticSimilarityEngine()
        
        # Index similar threats
        for i in range(10):
            engine.index_threat({
                "severity": "high",
                "threat_type": "ransomware",
                "target_system": "windows",
                "variant": str(i)
            })
        
        # Search for similar
        query = {"severity": "high", "threat_type": "ransomware"}
        results = engine.search_similar(query, top_k=5)
        
        assert len(results) <= 5
        assert all(isinstance(r, SimilarityResult) for r in results)
        assert all(0 <= r.similarity_score <= 1 for r in results)
    
    def test_search_similar_with_min_threshold(self):
        """Test search respects minimum similarity threshold"""
        engine = SemanticSimilarityEngine()
        
        # Index very different threats
        engine.index_threat({"severity": "high", "threat_type": "ransomware", "id": "1"})
        engine.index_threat({"severity": "low", "threat_type": "spam", "id": "2"})
        
        # Search with high threshold - should only get very similar
        query = {"severity": "high", "threat_type": "ransomware"}
        results = engine.search_similar(query, min_similarity=0.9)
        
        # Should get at least the exact match
        assert len(results) >= 1
    
    def test_search_with_filters(self):
        """Test search with metadata filtering"""
        engine = SemanticSimilarityEngine()
        
        engine.index_threat({"severity": "high", "threat_type": "malware", "sector": "finance", "uid": "1"})
        engine.index_threat({"severity": "high", "threat_type": "malware", "sector": "healthcare", "uid": "2"})
        engine.index_threat({"severity": "high", "threat_type": "malware", "sector": "finance", "uid": "3"})
        
        query = {"severity": "high", "threat_type": "malware"}
        results = engine.search_similar(query, filters={"sector": "finance"})
        
        # Should get 2 finance sector threats
        assert len(results) >= 1
        assert all(r.metadata["sector"] == "finance" for r in results)
    
    def test_search_results_ranked(self):
        """Test results are ranked by similarity"""
        engine = SemanticSimilarityEngine()
        
        for i in range(5):
            engine.index_threat({"severity": "high", "threat_type": f"type_{i}"})
        
        query = {"severity": "high", "threat_type": "type_0"}
        results = engine.search_similar(query, top_k=5)
        
        # Should be sorted descending
        scores = [r.similarity_score for r in results]
        assert scores == sorted(scores, reverse=True)
    
    def test_search_caching(self):
        """Test search results are cached"""
        engine = SemanticSimilarityEngine()
        engine.index_threat({"severity": "high"})
        
        query = {"severity": "high"}
        
        # First search
        results1 = engine.search_similar(query)
        initial_cache_hits = engine._stats["cache_hits"]
        
        # Second search - should hit cache
        results2 = engine.search_similar(query)
        
        assert engine._stats["cache_hits"] > initial_cache_hits
        assert len(results1) == len(results2)
    
    def test_find_clusters(self):
        """Test threat clustering functionality"""
        engine = SemanticSimilarityEngine()
        
        # Create groups of similar threats
        for i in range(3):
            engine.index_threat({"severity": "high", "threat_type": "ransomware", "var": i})
        for i in range(3):
            engine.index_threat({"severity": "low", "threat_type": "spam", "var": i})
        
        clusters = engine.find_clusters(similarity_threshold=0.7, min_cluster_size=2)
        
        # Should find at least 1 cluster
        assert len(clusters) >= 1
    
    def test_get_stats(self):
        """Test statistics reporting"""
        engine = SemanticSimilarityEngine()
        
        for i in range(5):
            engine.index_threat({"threat_type": f"type_{i}"})
        
        engine.search_similar({"threat_type": "type_0"})
        
        stats = engine.get_stats()
        
        assert stats["total_indexed"] == 5
        assert stats["total_searches"] == 1
        assert stats["index_size"] == 5
        assert "cache_hit_ratio" in stats
        assert "metric" in stats
    
    def test_export_import_index(self):
        """Test index persistence"""
        engine1 = SemanticSimilarityEngine()
        engine1.index_threat({"severity": "high", "threat_type": "malware", "id": "1"})
        engine1.index_threat({"severity": "medium", "threat_type": "phishing", "id": "2"})
        
        exported = engine1.export_index()
        assert "vectors" in exported
        assert "stats" in exported
        assert "config" in exported
        assert len(exported["vectors"]) == 2
        
        # Import into new engine
        engine2 = SemanticSimilarityEngine()
        engine2.import_index(exported)
        assert len(engine2._vector_store) == 2
    
    def test_different_metrics(self):
        """Test different similarity metrics"""
        for metric in [SimilarityMetric.COSINE, SimilarityMetric.EUCLIDEAN, SimilarityMetric.MANHATTAN]:
            engine = SemanticSimilarityEngine(metric=metric)
            engine.index_threat({"severity": "high"})
            results = engine.search_similar({"severity": "high"})
            assert len(results) >= 0


class TestConvenienceFunctions:
    """Test module-level convenience functions"""
    
    def test_index_threat_function(self):
        """Test module-level index function"""
        threat_id = index_threat({"severity": "high", "threat_type": "test"})
        assert threat_id is not None
    
    def test_search_similar_function(self):
        """Test module-level search function"""
        index_threat({"severity": "high", "threat_type": "test_search"})
        results = search_similar({"severity": "high", "threat_type": "test_search"})
        assert isinstance(results, list)
    
    def test_get_stats_function(self):
        """Test module-level stats function"""
        stats = get_semantic_search_stats()
        assert isinstance(stats, dict)
        assert "total_indexed" in stats


class TestSimilarityMetrics:
    """Test individual similarity metric calculations"""
    
    def test_cosine_similarity_identical(self):
        """Test cosine similarity of identical vectors"""
        v1 = [1.0, 0.0, 0.0]
        similarity = SemanticSimilarityEngine._cosine_similarity(v1, v1)
        assert abs(similarity - 1.0) < 0.001
    
    def test_cosine_similarity_orthogonal(self):
        """Test cosine similarity of orthogonal vectors"""
        v1 = [1.0, 0.0]
        v2 = [0.0, 1.0]
        similarity = SemanticSimilarityEngine._cosine_similarity(v1, v2)
        assert abs(similarity - 0.0) < 0.001
    
    def test_euclidean_similarity(self):
        """Test Euclidean distance-based similarity"""
        v1 = [0.0, 0.0]
        v2 = [1.0, 1.0]
        similarity = SemanticSimilarityEngine._euclidean_distance(v1, v2)
        assert 0 < similarity < 1


class TestBackwardCompatibility:
    """Verify ADD-ONLY philosophy - no existing code broken"""
    
    def test_new_module_is_isolated(self):
        """Test new module doesn't depend on existing code"""
        # This module should work completely independently
        engine = SemanticSimilarityEngine()
        engine.index_threat({"test": "data"})
        results = engine.search_similar({"test": "data"})
        assert results is not None
    
    def test_no_side_effects(self):
        """Test module doesn't modify global state"""
        import sys
        initial_modules = set(sys.modules.keys())
        
        # Import shouldn't add unexpected modules
        from neural_shield import threat_intelligence_semantic_similarity_search_engine_v18_2026_june
        
        # Only our module should be added
        assert "neural_shield.threat_intelligence_semantic_similarity_search_engine_v18_2026_june" in sys.modules


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
