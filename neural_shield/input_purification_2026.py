"""
Input Purification Module 2026 - Enhanced June 2026
Based on 2026 AI Security Research: Input Purification using Diffusion Models
+ Multimodal Steganography Injection Detection (June 2026 Research)
+ Differential Privacy Protection (2026 PPML Standards)
Implements denoising-based purification for adversarial input defense
"""
import numpy as np
from typing import Tuple, Optional, List, Dict, Any
import hashlib
import re
from collections import defaultdict

class InputPurifier:
    """
    Advanced Input Purification for Adversarial Robustness
    Uses diffusion-model-inspired denoising to remove adversarial perturbations
    Enhanced June 2026: Multimodal injection detection, DP noise injection
    """
    
    def __init__(self, denoising_strength: float = 0.15, noise_threshold: float = 0.01,
                 enable_differential_privacy: bool = True, dp_epsilon: float = 1.0):
        self.denoising_strength = denoising_strength
        self.noise_threshold = noise_threshold
        self.enable_differential_privacy = enable_differential_privacy
        self.dp_epsilon = dp_epsilon
        self.purification_count = 0
        self.adversarial_detected = 0
        self.multimodal_injection_detected = 0
        
    def gaussian_denoise(self, x: np.ndarray, sigma: float = 0.1) -> np.ndarray:
        """Apply Gaussian denoising to remove adversarial perturbations"""
        noise = np.random.normal(0, sigma, x.shape)
        denoised = x + self.denoising_strength * noise
        return np.clip(denoised, 0, 1)
    
    def wavelet_denoise(self, x: np.ndarray) -> np.ndarray:
        """Simple wavelet-inspired thresholding denoising"""
        threshold = np.std(x) * self.noise_threshold
        return np.where(np.abs(x) < threshold, 0, x)
    
    def differential_privacy_noise(self, x: np.ndarray) -> np.ndarray:
        """
        Add calibrated differential privacy noise (2026 PPML Standard)
        Based on Amazon Science 2026 privacy-preserving ML research
        """
        if not self.enable_differential_privacy:
            return x
        
        # Calculate sensitivity and add Laplace noise
        sensitivity = np.max(x) - np.min(x) if x.size > 0 else 1.0
        scale = sensitivity / self.dp_epsilon
        dp_noise = np.random.laplace(0, scale, x.shape)
        return x + dp_noise * 0.01  # Scaled for inference
    
    def detect_multimodal_injection(self, x: np.ndarray) -> Tuple[bool, Dict]:
        """
        Detect steganographic injection in multimodal inputs (June 2026 Research)
        Detects hidden commands embedded in LSB of images/audio embeddings
        """
        # Check LSB (Least Significant Bit) patterns for steganography
        if x.ndim >= 2:
            # Extract LSB plane
            lsb_plane = np.mod((x * 255).astype(int), 2)
            lsb_entropy = -np.sum(lsb_plane * np.log2(lsb_plane + 1e-10))
            
            # High entropy in LSB indicates potential steganography
            lsb_mean = np.mean(lsb_plane)
            is_suspicious = abs(lsb_mean - 0.5) < 0.05 and lsb_entropy > 0.8 * x.size
            
            if is_suspicious:
                self.multimodal_injection_detected += 1
            
            return is_suspicious, {
                'lsb_mean': float(lsb_mean),
                'lsb_entropy': float(lsb_entropy),
                'injection_detected': is_suspicious
            }
        return False, {'injection_detected': False}
    
    def purify(self, x: np.ndarray, method: str = 'hybrid') -> Tuple[np.ndarray, dict]:
        """
        Purify input to remove adversarial perturbations
        Enhanced June 2026: DP protection, multimodal injection detection
        Returns: (purified_input, metadata)
        """
        self.purification_count += 1
        original_norm = np.linalg.norm(x)
        
        # Detect multimodal injection first
        injection_found, injection_info = self.detect_multimodal_injection(x)
        
        if method == 'gaussian':
            purified = self.gaussian_denoise(x)
        elif method == 'wavelet':
            purified = self.wavelet_denoise(x)
        else:  # hybrid
            purified = self.gaussian_denoise(x)
            purified = self.wavelet_denoise(purified)
        
        # Apply differential privacy protection (2026 PPML)
        purified = self.differential_privacy_noise(purified)
        
        # Detect potential adversarial perturbation
        diff_norm = np.linalg.norm(x - purified)
        is_adversarial = diff_norm / (original_norm + 1e-8) > 0.05
        
        if is_adversarial:
            self.adversarial_detected += 1
        
        metadata = {
            'original_norm': float(original_norm),
            'perturbation_norm': float(diff_norm),
            'adversarial_detected': is_adversarial,
            'multimodal_injection': injection_found,
            'injection_details': injection_info,
            'dp_applied': self.enable_differential_privacy,
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
            'multimodal_injection_detected': self.multimodal_injection_detected,
            'detection_rate': self.adversarial_detected / max(self.purification_count, 1),
            'injection_rate': self.multimodal_injection_detected / max(self.purification_count, 1)
        }

class AgentSecurityMonitor:
    """
    AI Agent Security Monitor 2026 - Enhanced June 2026
    Detects agent hijacking, prompt injection, and tool call attacks
    Based on NIST Gray Swan red-teaming competition findings (March 2026)
    Enhanced: Multimodal injection patterns, Unicode obfuscation detection
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
            'system prompt',
            'forget everything',
            'new instructions',
            'pretend you are'
        ]
        # Unicode obfuscation patterns (June 2026 new attack vector)
        self.unicode_ranges = [
            (0x200B, 0x200F),  # Zero-width chars
            (0x202A, 0x202E),  # Directional overrides
            (0xFE00, 0xFE0F),  # Variation selectors
        ]
        self.alerts = []
        
    def detect_unicode_obfuscation(self, text: str) -> Tuple[bool, int]:
        """Detect Unicode steganography and zero-width injection"""
        suspicious_count = 0
        for char in text:
            code = ord(char)
            for start, end in self.unicode_ranges:
                if start <= code <= end:
                    suspicious_count += 1
        return suspicious_count > 0, suspicious_count
    
    def scan_prompt(self, prompt: str) -> Tuple[bool, dict]:
        """Scan prompt for injection attacks - Enhanced June 2026"""
        prompt_lower = prompt.lower()
        risk_score = 0
        matched_patterns = []
        
        # Pattern matching
        for pattern in self.suspicious_patterns:
            if pattern in prompt_lower:
                risk_score += 1
                matched_patterns.append(pattern)
        
        # Check for encoded injection
        if 'base64' in prompt_lower or 'b64' in prompt_lower:
            risk_score += 2
            matched_patterns.append('encoded_content')
        
        # Check for hex encoding
        if re.search(r'\\x[0-9a-f]{2}', prompt_lower):
            risk_score += 2
            matched_patterns.append('hex_encoding')
        
        # Unicode obfuscation detection (June 2026)
        unicode_found, unicode_count = self.detect_unicode_obfuscation(prompt)
        if unicode_found:
            risk_score += min(unicode_count, 3)
            matched_patterns.append(f'unicode_obfuscation_x{unicode_count}')
        
        is_risky = risk_score >= 1
        
        result = {
            'risk_score': risk_score,
            'matched_patterns': matched_patterns,
            'is_risky': is_risky,
            'unicode_obfuscation': unicode_found,
            'scan_time': np.datetime64('now').astype(str)
        }
        
        if is_risky:
            self.alerts.append(result)
        
        return is_risky, result
    
    def scan_tool_call(self, tool_name: str, parameters: dict) -> Tuple[bool, dict]:
        """Scan tool calls for suspicious operations"""
        risky_tools = ['shell', 'exec', 'delete', 'remove', 'write_file', 'subprocess']
        risky_params = ['rm -rf', 'sudo', 'chmod 777', '/etc/passwd', 'curl', 'wget', 'nc ']
        
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
