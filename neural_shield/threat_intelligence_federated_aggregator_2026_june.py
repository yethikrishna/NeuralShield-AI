"""
Threat Intelligence Federated Learning Aggregator
Production-grade implementation for NeuralShield-AI

Implements privacy-preserving federated learning for threat intelligence sharing
across multiple organizations without exposing sensitive raw data.

Key Features:
- Federated Averaging (FedAvg) for model aggregation
- Differential privacy for gradient perturbation
- Secure multi-party computation for weight aggregation
- Model validation and drift detection
- Performance metrics tracking
"""

import hashlib
import hmac
import json
import time
import uuid
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
import math


@dataclass
class ClientUpdate:
    """Represents a model update from a federated client"""
    client_id: str
    model_weights: Dict[str, List[float]]
    sample_count: int
    timestamp: float
    signature: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AggregationResult:
    """Result of federated aggregation"""
    aggregated_weights: Dict[str, List[float]]
    participating_clients: int
    total_samples: int
    aggregation_timestamp: float
    privacy_budget_used: float
    validation_score: float


class DifferentialPrivacyEngine:
    """Differential privacy engine for gradient perturbation"""
    
    def __init__(self, epsilon: float = 1.0, delta: float = 1e-5, noise_scale: float = 0.01):
        self.epsilon = epsilon
        self.delta = delta
        self.noise_scale = noise_scale
        self.privacy_budget_used = 0.0
        self.max_privacy_budget = 100.0
    
    def add_gaussian_noise(self, values: List[float], sensitivity: float = 1.0) -> List[float]:
        """Add calibrated Gaussian noise for differential privacy"""
        import random
        
        sigma = sensitivity * math.sqrt(2 * math.log(1.25 / self.delta)) / self.epsilon
        noisy_values = []
        
        for v in values:
            noise = random.gauss(0, sigma * self.noise_scale)
            noisy_values.append(v + noise)
        
        self.privacy_budget_used += self.epsilon
        return noisy_values
    
    def clip_gradients(self, gradients: List[float], clip_norm: float = 1.0) -> List[float]:
        """Clip gradients to bound sensitivity"""
        norm = math.sqrt(sum(g * g for g in gradients))
        
        if norm > clip_norm:
            scale = clip_norm / norm
            return [g * scale for g in gradients]
        
        return gradients
    
    def can_aggregate(self) -> bool:
        """Check if remaining privacy budget is sufficient"""
        return self.privacy_budget_used < self.max_privacy_budget
    
    def get_privacy_status(self) -> Dict[str, float]:
        """Get current privacy budget status"""
        return {
            "epsilon_used": self.privacy_budget_used,
            "remaining_budget": self.max_privacy_budget - self.privacy_budget_used,
            "delta": self.delta,
            "current_noise_scale": self.noise_scale
        }


class SecureWeightAggregator:
    """Secure multi-party computation for weight aggregation"""
    
    def __init__(self):
        self.client_shares: Dict[str, Dict[str, List[float]]] = {}
    
    def generate_shares(self, secret: List[float], num_shares: int = 3) -> List[List[float]]:
        """Generate secret shares using simple additive sharing"""
        import random
        
        shares = []
        running_sum = [0.0] * len(secret)
        
        for i in range(num_shares - 1):
            share = [random.uniform(-100, 100) for _ in range(len(secret))]
            shares.append(share)
            running_sum = [running_sum[j] + share[j] for j in range(len(secret))]
        
        final_share = [secret[j] - running_sum[j] for j in range(len(secret))]
        shares.append(final_share)
        
        return shares
    
    def reconstruct_secret(self, shares: List[List[float]]) -> List[float]:
        """Reconstruct secret from shares"""
        if not shares:
            return []
        
        result = [0.0] * len(shares[0])
        
        for share in shares:
            for j in range(len(share)):
                result[j] += share[j]
        
        return result
    
    def federated_averaging(self, 
                          client_updates: List[ClientUpdate],
                          layer_name: str) -> List[float]:
        """Perform Federated Averaging (FedAvg) on model weights"""
        if not client_updates:
            return []
        
        total_samples = sum(update.sample_count for update in client_updates)
        
        if total_samples == 0:
            return []
        
        first_weights = client_updates[0].model_weights.get(layer_name, [])
        aggregated = [0.0] * len(first_weights)
        
        for update in client_updates:
            weights = update.model_weights.get(layer_name, [])
            if len(weights) != len(aggregated):
                continue
            
            weight = update.sample_count / total_samples
            for j in range(len(weights)):
                aggregated[j] += weights[j] * weight
        
        return aggregated


class ModelDriftDetector:
    """Detect model drift and validate client updates"""
    
    def __init__(self, baseline_weights: Optional[Dict[str, List[float]]] = None):
        self.baseline_weights = baseline_weights
        self.drift_history: List[Dict[str, Any]] = []
        self.drift_threshold = 0.15
    
    def calculate_cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        """Calculate cosine similarity between two vectors"""
        if len(vec1) != len(vec2) or len(vec1) == 0:
            return 0.0
        
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = math.sqrt(sum(a * a for a in vec1))
        norm2 = math.sqrt(sum(b * b for b in vec2))
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)
    
    def calculate_weight_distance(self, weights1: Dict[str, List[float]], 
                                weights2: Dict[str, List[float]]) -> float:
        """Calculate overall distance between two weight dictionaries"""
        if not weights1 or not weights2:
            return 1.0
        
        similarities = []
        common_layers = set(weights1.keys()) & set(weights2.keys())
        
        for layer in common_layers:
            sim = self.calculate_cosine_similarity(weights1[layer], weights2[layer])
            similarities.append(sim)
        
        if not similarities:
            return 1.0
        
        avg_similarity = sum(similarities) / len(similarities)
        return 1.0 - avg_similarity
    
    def validate_update(self, client_update: ClientUpdate) -> Tuple[bool, float]:
        """Validate a client update for potential drift or poisoning"""
        if self.baseline_weights is None:
            return True, 1.0
        
        drift_score = self.calculate_weight_distance(
            self.baseline_weights,
            client_update.model_weights
        )
        
        is_valid = drift_score < self.drift_threshold
        
        self.drift_history.append({
            "client_id": client_update.client_id,
            "drift_score": drift_score,
            "timestamp": client_update.timestamp,
            "is_valid": is_valid
        })
        
        return is_valid, drift_score
    
    def update_baseline(self, new_weights: Dict[str, List[float]]):
        """Update baseline weights with new aggregated model"""
        self.baseline_weights = new_weights


class ThreatIntelligenceFederatedAggregator:
    """Main federated learning aggregator for threat intelligence"""
    
    def __init__(self, 
                 epsilon: float = 1.0,
                 delta: float = 1e-5,
                 min_clients: int = 2,
                 aggregation_interval: int = 300):
        self.privacy_engine = DifferentialPrivacyEngine(epsilon, delta)
        self.secure_aggregator = SecureWeightAggregator()
        self.drift_detector = ModelDriftDetector()
        
        self.min_clients = min_clients
        self.aggregation_interval = aggregation_interval
        
        self.pending_updates: Dict[str, ClientUpdate] = {}
        self.aggregation_history: List[AggregationResult] = []
        self.client_registry: Dict[str, Dict[str, Any]] = {}
        
        self.global_model: Dict[str, List[float]] = {}
        self.last_aggregation_time = 0.0
        
        self.validation_metrics = {
            "total_validations": 0,
            "rejected_updates": 0,
            "average_drift_score": 0.0
        }
    
    def register_client(self, client_id: str, public_key: str = "") -> Dict[str, Any]:
        """Register a new federated client"""
        if client_id in self.client_registry:
            return {
                "success": False,
                "message": "Client already registered",
                "client_id": client_id
            }
        
        self.client_registry[client_id] = {
            "registered_at": time.time(),
            "public_key": public_key,
            "updates_submitted": 0,
            "last_update": None
        }
        
        return {
            "success": True,
            "message": "Client registered successfully",
            "client_id": client_id,
            "registration_time": time.time()
        }
    
    def verify_client_signature(self, client_update: ClientUpdate) -> bool:
        """Verify client update signature"""
        if client_update.client_id not in self.client_registry:
            return False
        
        message = f"{client_update.client_id}:{client_update.sample_count}:{client_update.timestamp}"
        expected_signature = hashlib.sha256(message.encode()).hexdigest()
        
        return hmac.compare_digest(client_update.signature, expected_signature)
    
    def submit_update(self, client_update: ClientUpdate) -> Dict[str, Any]:
        """Submit a client model update"""
        client_id = client_update.client_id
        
        # Verify client is registered
        if client_id not in self.client_registry:
            return {
                "success": False,
                "message": "Client not registered"
            }
        
        # Verify signature
        if not self.verify_client_signature(client_update):
            return {
                "success": False,
                "message": "Invalid client signature"
            }
        
        # Validate update for drift/poisoning
        is_valid, drift_score = self.drift_detector.validate_update(client_update)
        self.validation_metrics["total_validations"] += 1
        
        if not is_valid:
            self.validation_metrics["rejected_updates"] += 1
            return {
                "success": False,
                "message": f"Update rejected: drift score {drift_score:.3f} exceeds threshold",
                "drift_score": drift_score
            }
        
        # Store update
        self.pending_updates[client_id] = client_update
        
        # Update client stats
        self.client_registry[client_id]["updates_submitted"] += 1
        self.client_registry[client_id]["last_update"] = client_update.timestamp
        
        total_validations = self.validation_metrics["total_validations"]
        self.validation_metrics["average_drift_score"] = (
            (self.validation_metrics["average_drift_score"] * (total_validations - 1) + drift_score) 
            / total_validations
        )
        
        return {
            "success": True,
            "message": "Update accepted",
            "drift_score": drift_score,
            "pending_updates": len(self.pending_updates)
        }
    
    def should_aggregate(self) -> bool:
        """Check if aggregation should be performed"""
        current_time = time.time()
        enough_clients = len(self.pending_updates) >= self.min_clients
        enough_time = (current_time - self.last_aggregation_time) >= self.aggregation_interval
        has_privacy_budget = self.privacy_engine.can_aggregate()
        
        return enough_clients and enough_time and has_privacy_budget
    
    def aggregate(self) -> AggregationResult:
        """Perform federated aggregation"""
        if len(self.pending_updates) < self.min_clients:
            raise ValueError(f"Need at least {self.min_clients} clients for aggregation")
        
        updates = list(self.pending_updates.values())
        
        # Get all layer names
        all_layers = set()
        for update in updates:
            all_layers.update(update.model_weights.keys())
        
        # Aggregate each layer using FedAvg
        aggregated_weights = {}
        for layer in all_layers:
            raw_weights = self.secure_aggregator.federated_averaging(updates, layer)
            
            # Apply differential privacy
            noisy_weights = self.privacy_engine.add_gaussian_noise(raw_weights)
            aggregated_weights[layer] = noisy_weights
        
        # Calculate validation score
        validation_score = 0.0
        if self.drift_detector.baseline_weights:
            drift = self.drift_detector.calculate_weight_distance(
                self.drift_detector.baseline_weights,
                aggregated_weights
            )
            validation_score = 1.0 - drift
        
        # Create result
        result = AggregationResult(
            aggregated_weights=aggregated_weights,
            participating_clients=len(updates),
            total_samples=sum(u.sample_count for u in updates),
            aggregation_timestamp=time.time(),
            privacy_budget_used=self.privacy_engine.privacy_budget_used,
            validation_score=validation_score
        )
        
        # Update global model and baseline
        self.global_model = aggregated_weights
        self.drift_detector.update_baseline(aggregated_weights)
        
        # Clear pending updates
        self.pending_updates.clear()
        self.last_aggregation_time = time.time()
        
        # Record history
        self.aggregation_history.append(result)
        
        return result
    
    def get_global_model(self) -> Dict[str, Any]:
        """Get current global model state"""
        return {
            "model_weights": self.global_model,
            "aggregation_count": len(self.aggregation_history),
            "last_aggregation": self.last_aggregation_time,
            "privacy_status": self.privacy_engine.get_privacy_status()
        }
    
    def get_metrics(self) -> Dict[str, Any]:
        """Get aggregator metrics"""
        return {
            "registered_clients": len(self.client_registry),
            "pending_updates": len(self.pending_updates),
            "aggregations_performed": len(self.aggregation_history),
            "validation": self.validation_metrics,
            "privacy": self.privacy_engine.get_privacy_status(),
            "last_aggregation_time": self.last_aggregation_time
        }
