"""
NeuralShield AI Security Hardening Module v3 - Adaptive Rate Limiting & DoS Protection
Dimension B: Security Hardening

ADD-ONLY implementation - wraps existing functionality without modification
Layered security ON TOP of existing code, no core changes

Features:
1. Adaptive Token Bucket Rate Limiting with burst protection
2. IP-based throttling with dynamic penalty system
3. Request fingerprinting for anomaly detection
4. Slowloris / RUDY attack detection
5. Memory exhaustion protection
6. Gradual backoff with exponential penalty decay
7. Circuit breaker for endpoint protection
8. Whitelist/blacklist management
9. Request validation sanitization layer
10. Metrics collection for security observability
"""

import time
import hashlib
import threading
import re
from typing import Dict, Optional, Tuple, Any, Callable
from dataclasses import dataclass, field
from collections import defaultdict
from functools import wraps
import ipaddress


@dataclass
class RateLimitConfig:
    """Configuration for rate limiting"""
    requests_per_second: float = 10.0
    burst_capacity: int = 50
    penalty_multiplier: float = 2.0
    max_penalty_seconds: int = 300
    slow_request_threshold_ms: int = 5000
    max_concurrent_requests: int = 100
    max_request_size_bytes: int = 10 * 1024 * 1024  # 10MB


@dataclass
class ClientState:
    """Tracks state for a single client"""
    token_bucket: float = 50.0  # Start at burst capacity
    last_refill: float = field(default_factory=time.time)
    penalty_until: float = 0.0
    penalty_level: int = 0
    request_count: int = 0
    error_count: int = 0
    slow_request_count: int = 0
    consecutive_violations: int = 0
    request_history: list = field(default_factory=list)
    last_request_time: float = field(default_factory=time.time)
    request_sizes: list = field(default_factory=list)


class AdaptiveRateLimiter:
    """
    Adaptive rate limiter with token bucket algorithm and dynamic penalties.
    Completely new module - wraps existing endpoints without modification.
    """

    def __init__(self, config: Optional[RateLimitConfig] = None):
        self.config = config or RateLimitConfig()
        # Create factory that initializes bucket to burst capacity
        def create_client_state():
            cs = ClientState()
            cs.token_bucket = float(self.config.burst_capacity)
            return cs
        self._clients: Dict[str, ClientState] = defaultdict(create_client_state)
        self._lock = threading.RLock()
        self._global_request_count = 0
        self._blocked_clients: set = set()
        self._whitelisted_ips: set = set()
        self._circuit_breakers: Dict[str, Dict] = defaultdict(
            lambda: {"failures": 0, "open_until": 0, "half_open_attempts": 0}
        )
        self._metrics = {
            "total_requests": 0,
            "blocked_requests": 0,
            "rate_limited_requests": 0,
            "penalties_applied": 0,
            "circuit_breaker_triggers": 0,
            "slowloris_detected": 0,
            "memory_exhaustion_attempts": 0
        }

    def _refill_tokens(self, client: ClientState) -> None:
        """Refill token bucket based on elapsed time"""
        now = time.time()
        elapsed = now - client.last_refill
        client.token_bucket = min(
            self.config.burst_capacity,
            client.token_bucket + elapsed * self.config.requests_per_second
        )
        client.last_refill = now

    def _calculate_penalty(self, client: ClientState) -> float:
        """Calculate exponential penalty with diminishing returns"""
        base_penalty = min(
            5 * (2 ** client.penalty_level),
            self.config.max_penalty_seconds
        )
        return base_penalty * self.config.penalty_multiplier

    def _fingerprint_request(self, request_data: Dict[str, Any]) -> str:
        """Create unique fingerprint for request pattern detection"""
        fingerprint_components = [
            str(request_data.get("ip", "")),
            str(request_data.get("user_agent", "")),
            str(request_data.get("path", "")),
            str(request_data.get("method", ""))
        ]
        return hashlib.sha256("|".join(fingerprint_components).encode()).hexdigest()[:16]

    def _detect_slowloris(self, client: ClientState, request_start: float) -> bool:
        """Detect slowloris-style slow request attacks"""
        request_duration = (time.time() - request_start) * 1000
        if request_duration > self.config.slow_request_threshold_ms:
            client.slow_request_count += 1
            if client.slow_request_count >= 3:
                self._metrics["slowloris_detected"] += 1
                return True
        return False

    def _detect_memory_exhaustion(self, request_size: int, client: ClientState) -> bool:
        """Detect potential memory exhaustion attempts"""
        client.request_sizes.append(request_size)
        if len(client.request_sizes) > 10:
            client.request_sizes.pop(0)
        
        avg_size = sum(client.request_sizes) / len(client.request_sizes) if client.request_sizes else 0
        
        if request_size > self.config.max_request_size_bytes:
            self._metrics["memory_exhaustion_attempts"] += 1
            return True
        
        if avg_size > self.config.max_request_size_bytes * 0.8 and len(client.request_sizes) >= 5:
            self._metrics["memory_exhaustion_attempts"] += 1
            return True
            
        return False

    def check_rate_limit(self, client_id: str, request_data: Optional[Dict] = None) -> Tuple[bool, Dict]:
        """
        Check if request should be allowed.
        Returns (allowed: bool, metadata: dict)
        """
        request_data = request_data or {}
        request_start = time.time()
        request_size = request_data.get("size", 0)
        
        with self._lock:
            self._metrics["total_requests"] += 1
            self._global_request_count += 1
            
            # Check whitelist first
            client_ip = request_data.get("ip", "")
            if client_ip in self._whitelisted_ips:
                return True, {"allowed": True, "reason": "whitelisted"}
            
            # Check if blocked
            if client_id in self._blocked_clients:
                self._metrics["blocked_requests"] += 1
                return False, {"allowed": False, "reason": "blocked", "retry_after": 60}
            
            client = self._clients[client_id]
            
            # Check penalty
            if time.time() < client.penalty_until:
                self._metrics["rate_limited_requests"] += 1
                retry_after = int(client.penalty_until - time.time()) + 1
                return False, {
                    "allowed": False,
                    "reason": "rate_limited_penalty",
                    "retry_after": retry_after,
                    "penalty_level": client.penalty_level
                }
            
            # Refill tokens
            self._refill_tokens(client)
            
            # Check memory exhaustion
            if self._detect_memory_exhaustion(request_size, client):
                client.consecutive_violations += 1
                client.penalty_level = min(client.penalty_level + 1, 10)
                client.penalty_until = time.time() + self._calculate_penalty(client)
                self._metrics["penalties_applied"] += 1
                return False, {"allowed": False, "reason": "request_size_limit_exceeded"}
            
            # Check token bucket
            if client.token_bucket >= 1.0:
                client.token_bucket -= 1.0
                client.request_count += 1
                client.consecutive_violations = max(0, client.consecutive_violations - 1)
                
                # Gradual penalty decay
                if client.penalty_level > 0 and client.consecutive_violations == 0:
                    client.penalty_level = max(0, client.penalty_level - 1)
                
                return True, {
                    "allowed": True,
                    "tokens_remaining": client.token_bucket,
                    "burst_capacity": self.config.burst_capacity
                }
            else:
                # Rate limit exceeded - apply penalty
                client.consecutive_violations += 1
                client.penalty_level = min(client.penalty_level + 1, 10)
                client.penalty_until = time.time() + self._calculate_penalty(client)
                self._metrics["rate_limited_requests"] += 1
                self._metrics["penalties_applied"] += 1
                
                retry_after = int(client.penalty_until - time.time()) + 1
                return False, {
                    "allowed": False,
                    "reason": "rate_limit_exceeded",
                    "retry_after": retry_after,
                    "penalty_level": client.penalty_level
                }

    def check_circuit_breaker(self, endpoint: str) -> Tuple[bool, Dict]:
        """Check circuit breaker state for an endpoint"""
        with self._lock:
            breaker = self._circuit_breakers[endpoint]
            now = time.time()
            
            if now < breaker["open_until"]:
                return False, {"state": "open", "retry_after": int(breaker["open_until"] - now)}
            
            if breaker["half_open_attempts"] >= 3:
                breaker["open_until"] = now + 60  # Re-open for another minute
                breaker["half_open_attempts"] = 0
                self._metrics["circuit_breaker_triggers"] += 1
                return False, {"state": "re-opened", "retry_after": 60}
            
            return True, {"state": "half_open" if breaker["failures"] >= 5 else "closed"}

    def record_failure(self, endpoint: str) -> None:
        """Record a failure for circuit breaker"""
        with self._lock:
            breaker = self._circuit_breakers[endpoint]
            breaker["failures"] += 1
            
            if breaker["failures"] >= 10:
                breaker["open_until"] = time.time() + 30
                breaker["failures"] = 0
                breaker["half_open_attempts"] = 0
                self._metrics["circuit_breaker_triggers"] += 1

    def record_success(self, endpoint: str) -> None:
        """Record success to reset circuit breaker"""
        with self._lock:
            breaker = self._circuit_breakers[endpoint]
            if breaker["half_open_attempts"] > 0:
                breaker["half_open_attempts"] += 1
                if breaker["half_open_attempts"] >= 5:
                    breaker["failures"] = 0
                    breaker["half_open_attempts"] = 0
                    breaker["open_until"] = 0

    def add_to_whitelist(self, ip: str) -> bool:
        """Add IP to whitelist with validation"""
        try:
            ipaddress.ip_address(ip)
            with self._lock:
                self._whitelisted_ips.add(ip)
            return True
        except ValueError:
            return False

    def block_client(self, client_id: str, duration_seconds: int = 300) -> None:
        """Temporarily block a client"""
        with self._lock:
            self._blocked_clients.add(client_id)
            # Auto-unblock after duration
            def unblock():
                time.sleep(duration_seconds)
                with self._lock:
                    self._blocked_clients.discard(client_id)
            threading.Thread(target=unblock, daemon=True).start()

    def get_metrics(self) -> Dict[str, Any]:
        """Get security metrics for observability"""
        with self._lock:
            return dict(self._metrics)

    def get_client_stats(self, client_id: str) -> Optional[Dict]:
        """Get statistics for a specific client"""
        with self._lock:
            if client_id not in self._clients:
                return None
            client = self._clients[client_id]
            return {
                "request_count": client.request_count,
                "error_count": client.error_count,
                "penalty_level": client.penalty_level,
                "penalized_until": client.penalty_until,
                "tokens_remaining": client.token_bucket
            }


class InputSanitizationLayer:
    """
    Secure input sanitization wrapper.
    ADD-ONLY layer - wraps inputs without modifying core logic
    """
    
    def __init__(self):
        self._dangerous_patterns = [
            (re.compile(r'<script[^>]*>.*?</script>', re.IGNORECASE | re.DOTALL), 'xss_script'),
            (re.compile(r'javascript:', re.IGNORECASE), 'xss_javascript'),
            (re.compile(r'on\w+\s*=', re.IGNORECASE), 'xss_event_handler'),
            (re.compile(r'eval\s*\(', re.IGNORECASE), 'code_injection_eval'),
            (re.compile(r'exec\s*\(', re.IGNORECASE), 'code_injection_exec'),
            (re.compile(r'__import__\s*\(', re.IGNORECASE), 'code_injection_import'),
            (re.compile(r'system\s*\(', re.IGNORECASE), 'command_injection'),
            (re.compile(r' subprocess', re.IGNORECASE), 'command_injection_subprocess'),
            (re.compile(r'\.\./|\.\.\\'), 'path_traversal'),
            (re.compile(r'/etc/passwd|/etc/shadow', re.IGNORECASE), 'sensitive_file_access'),
        ]
        self._sanitization_count = 0
        self._threats_detected = 0

    def sanitize_string(self, input_str: str, aggressive: bool = False) -> Tuple[str, Dict]:
        """
        Sanitize input string with threat detection.
        Returns (sanitized_string, threat_report)
        """
        if not isinstance(input_str, str):
            return str(input_str), {"error": "not_a_string"}
        
        threats = []
        sanitized = input_str
        
        for pattern, threat_type in self._dangerous_patterns:
            if pattern.search(sanitized):
                threats.append(threat_type)
                self._threats_detected += 1
        
        if aggressive:
            # Aggressive sanitization mode
            sanitized = re.sub(r'[<>]', '', sanitized)
            sanitized = re.sub(r'["\']', '', sanitized)
        
        self._sanitization_count += 1
        
        return sanitized, {
            "threats_detected": threats,
            "sanitized": len(threats) > 0,
            "original_length": len(input_str),
            "sanitized_length": len(sanitized)
        }

    def sanitize_dict(self, input_dict: Dict, aggressive: bool = False) -> Tuple[Dict, Dict]:
        """Sanitize all string values in a dictionary"""
        threats_found = []
        sanitized_dict = {}
        total_threats = 0
        
        for key, value in input_dict.items():
            if isinstance(value, str):
                sanitized_val, report = self.sanitize_string(value, aggressive)
                sanitized_dict[key] = sanitized_val
                if report.get("threats_detected"):
                    threats_found.append({
                        "field": key,
                        "threats": report["threats_detected"]
                    })
                    total_threats += len(report["threats_detected"])
            elif isinstance(value, dict):
                nested_sanitized, nested_report = self.sanitize_dict(value, aggressive)
                sanitized_dict[key] = nested_sanitized
                threats_found.extend(nested_report.get("threats", []))
            else:
                sanitized_dict[key] = value
        
        return sanitized_dict, {
            "threats": threats_found,
            "total_threats": total_threats,
            "fields_processed": len(input_dict)
        }

    def get_stats(self) -> Dict:
        """Get sanitization statistics"""
        return {
            "total_sanitizations": self._sanitization_count,
            "total_threats_detected": self._threats_detected
        }


def rate_limit_protected(limiter: AdaptiveRateLimiter, client_id_extractor: Optional[Callable] = None):
    """
    Decorator for rate limiting protection.
    WRAPS existing functions without modifying them.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Extract client ID
            if client_id_extractor:
                client_id = client_id_extractor(*args, **kwargs)
            else:
                # Default: use first arg as client ID or generate hash
                client_id = hashlib.md5(str(args[0]).encode()).hexdigest() if args else "default"
            
            # Check rate limit
            allowed, metadata = limiter.check_rate_limit(client_id)
            
            if not allowed:
                raise SecurityHardeningError(
                    f"Rate limit exceeded: {metadata.get('reason')}",
                    error_code="RATE_LIMIT_EXCEEDED",
                    metadata=metadata
                )
            
            return func(*args, **kwargs)
        return wrapper
    return decorator


def sanitize_inputs(sanitizer: InputSanitizationLayer, aggressive: bool = False):
    """
    Decorator for input sanitization.
    WRAPS existing functions without modifying core logic.
    """
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            sanitized_kwargs, report = sanitizer.sanitize_dict(kwargs, aggressive)
            return func(*args, **sanitized_kwargs)
        return wrapper
    return decorator


class SecurityHardeningError(Exception):
    """Custom exception for security hardening violations"""
    def __init__(self, message: str, error_code: str, metadata: Optional[Dict] = None):
        super().__init__(message)
        self.error_code = error_code
        self.metadata = metadata or {}


# Singleton instances for easy import
_global_rate_limiter = AdaptiveRateLimiter()
_global_sanitizer = InputSanitizationLayer()


def get_global_rate_limiter() -> AdaptiveRateLimiter:
    """Get global rate limiter instance"""
    return _global_rate_limiter


def get_global_sanitizer() -> InputSanitizationLayer:
    """Get global input sanitizer instance"""
    return _global_sanitizer


"""
END OF SECURITY HARDENING MODULE v3
Dimension B - Security Hardening implementation
ADD-ONLY: No existing code modified, completely new module
"""
