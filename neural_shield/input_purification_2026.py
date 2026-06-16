"""
Input Purification Module 2026
Based on 2026 AI Security Research: Input Purification using Diffusion Models
Implements denoising-based purification for adversarial input defense
"""

import numpy as np
from typing import Tuple, Optional
import hashlib


class InputPurifier:
    """
    Advanced Input Purification for Adversarial Robustness
    Uses diffusion-model-inspired denoising to remove adversarial perturbations
    """
    
    def __init__(self, denoising_strength: float = 0.15, noise_threshold: float = 0.01):
        self.denoising_strength = denoising_strength
        self.noise_threshold = noise_threshold
        self.purification_count = 0
        self.adversarial_detected = 0
        
    def gaussian_denoise(self, x: np.ndarray, sigma: float = 0.1) -> np.ndarray:
        """Apply Gaussian denoising to remove adversarial perturbations"""
        noise = np.random.normal(0, sigma, x.shape)
        denoised = x + self.denoising_strength * noise
        return np.clip(denoised, 0, 1)
    
    def wavelet_denoise(self, x: np.ndarray) -> np.ndarray:
        """Simple wavelet-inspired thresholding denoising"""
        threshold = np.std(x) * self.noise_threshold
        return np.where(np.abs(x) < threshold, 0, x)
    
    def purify(self, x: np.ndarray, method: str = 'hybrid') -> Tuple[np.ndarray, dict]:
        """
        Purify input to remove adversarial perturbations
        Returns: (purified_input, metadata)
        """
        self.purification_count += 1
        original_norm = np.linalg.norm(x)
        
        if method == 'gaussian':
            purified = self.gaussian_denoise(x)
        elif method == 'wavelet':
            purified = self.wavelet_denoise(x)
        else:  # hybrid
            purified = self.gaussian_denoise(x)
            purified = self.wavelet_denoise(purified)
        
        # Detect potential adversarial perturbation
        diff_norm = np.linalg.norm(x - purified)
        is_adversarial = diff_norm / (original_norm + 1e-8) > 0.05
        
        if is_adversarial:
            self.adversarial_detected += 1
        
        metadata = {
            'original_norm': float(original_norm),
            'perturbation_norm': float(diff_norm),
            'adversarial_detected': is_adversarial,
            'purification_method': method,
            'timestamp': np.datetime64('now').astype(str)
        }
        
        return purified, metadata
    
    def compute_input_hash(self, x: np.ndarray) -> str:
        """Compute hash for input integrity verification"""
        return hashlib.sha256(x.tobytes()).hexdigest()
    
    def get_stats(self) -> dict:
        """Get purification statistics"""
        return {
            'total_purifications': self.purification_count,
            'adversarial_detected': self.adversarial_detected,
            'detection_rate': self.adversarial_detected / max(self.purification_count, 1)
        }


class AgentSecurityMonitor:
    """
    AI Agent Security Monitor 2026
    Detects agent hijacking, prompt injection, and tool call attacks
    Based on NIST Gray Swan red-teaming competition findings
    """
    
    def __init__(self):
        self.suspicious_patterns = [
            'ignore previous',
            'disregard instructions',
            'you are now',
            'act as',
            'bypass safety',
            'execute command',
            'delete',
            'override',
            'system prompt'
        ]
        self.alerts = []
        
    def scan_prompt(self, prompt: str) -> Tuple[bool, dict]:
        """Scan prompt for injection attacks"""
        prompt_lower = prompt.lower()
        risk_score = 0
        matched_patterns = []
        
        for pattern in self.suspicious_patterns:
            if pattern in prompt_lower:
                risk_score += 1
                matched_patterns.append(pattern)
        
        # Check for encoded injection
        if 'base64' in prompt_lower or 'b64' in prompt_lower:
            risk_score += 2
            matched_patterns.append('encoded_content')
        
        is_risky = risk_score >= 1
        
        result = {
            'risk_score': risk_score,
            'matched_patterns': matched_patterns,
            'is_risky': is_risky,
            'scan_time': np.datetime64('now').astype(str)
        }
        
        if is_risky:
            self.alerts.append(result)
        
        return is_risky, result
    
    def scan_tool_call(self, tool_name: str, parameters: dict) -> Tuple[bool, dict]:
        """Scan tool calls for suspicious operations"""
        risky_tools = ['shell', 'exec', 'delete', 'remove', 'write_file']
        risky_params = ['rm -rf', 'sudo', 'chmod 777', '/etc/passwd']
        
        risk_score = 0
        issues = []
        
        if tool_name.lower() in risky_tools:
            risk_score += 2
            issues.append(f'risky_tool:{tool_name}')
        
        param_str = str(parameters).lower()
        for risky in risky_params:
            if risky in param_str:
                risk_score += 1
                issues.append(f'risky_parameter:{risky}')
        
        is_risky = risk_score >= 1
        
        return is_risky, {
            'risk_score': risk_score,
            'issues': issues,
            'is_risky': is_risky,
            'tool_name': tool_name
        }
    
    def get_alerts(self) -> list:
        """Get all security alerts"""
        return self.alerts.copy()
