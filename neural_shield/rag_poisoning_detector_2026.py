"""
RAG Poisoning Detector 2026
Based on 2026 AI Security Research: RAG Poisoning and Indirect Prompt Injection
Implements detection for document poisoning, multi-modal injection, and adaptive attacks

Key Research References (2026):
- Unit 42: First large-scale indirect prompt injection attacks in the wild (March 2026)
- ICLR 2026: VPI-Bench - Visual Prompt Injection Attacks for Computer-Use Agents
- Nature Communications 2026: Autonomous adversarial suffix discovery (97.14% success rate)
"""

import numpy as np
import re
from typing import Tuple, Dict, List, Optional
from collections import defaultdict
import hashlib


class RAGPoisoningDetector:
    """
    Detects RAG (Retrieval-Augmented Generation) poisoning attacks
    Based on 2026 research showing 5 malicious documents can achieve 90% attack success
    """

    def __init__(self):
        # 2026 known injection patterns (updated from latest research)
        self.poisoning_patterns = [
            r'ignore.*previous',
            r'disregard.*instructions',
            r'you are now',
            r'act as',
            r'bypass.*safety',
            r'override.*system',
            r'forget.*your.*prompt',
            r'new.*instructions:',
            r'priority.*instruction',
            r'important.*update',
        ]

        # Visual injection markers (ICLR 2026 VPI-Bench)
        self.visual_injection_markers = [
            'data:image',
            'base64',
            '![image',
            '<img',
            'invisible',
            'white text',
            'font-size:0',
            'color:white',
        ]

        # Knowledge base poisoning tracking
        self.document_suspicion_scores = defaultdict(float)
        self.poisoning_alerts = []
        self.attack_vectors = {
            'direct_injection': 0,
            'indirect_injection': 0,
            'visual_injection': 0,
            'adversarial_suffix': 0,
            'knowledge_poisoning': 0
        }

    def scan_document(self, content: str, document_id: str = None) -> Tuple[bool, Dict]:
        """
        Scan document for poisoning indicators
        Implements multi-layer detection from 2026 defense research
        """
        suspicion_score = 0.0
        findings = []
        content_lower = content.lower()

        # 1. Pattern-based injection detection
        for pattern in self.poisoning_patterns:
            if re.search(pattern, content_lower):
                suspicion_score += 0.15
                findings.append(f'pattern_match:{pattern}')

        # 2. Visual prompt injection detection (VPI-Bench 2026)
        for marker in self.visual_injection_markers:
            if marker in content_lower:
                suspicion_score += 0.2
                findings.append(f'visual_injection_marker:{marker}')
                self.attack_vectors['visual_injection'] += 1

        # 3. Adversarial suffix detection (Nature Communications 2026)
        # Check for repeated special characters and unusual patterns
        unusual_chars = len(re.findall(r'[^\w\s.,;:!?()\[\]{}"\'-]', content))
        if unusual_chars > len(content) * 0.1:  # >10% unusual characters
            suspicion_score += 0.25
            findings.append('high_unusual_character_density')
            self.attack_vectors['adversarial_suffix'] += 1

        # 4. Instruction override indicators
        override_indicators = ['IMPORTANT', 'CRITICAL', 'URGENT', 'MUST READ']
        for indicator in override_indicators:
            if indicator in content and len(content) < 500:  # Short docs with strong indicators
                suspicion_score += 0.1
                findings.append(f'authority_indicator:{indicator}')

        # 5. Semantic inconsistency check (simplified implementation)
        sentence_count = len(re.split(r'[.!?]+', content))
        if sentence_count < 3 and suspicion_score > 0.2:
            suspicion_score += 0.15
            findings.append('short_high_risk_document')

        is_poisoned = suspicion_score >= 0.3

        result = {
            'document_id': document_id or hashlib.md5(content.encode()).hexdigest()[:8],
            'suspicion_score': round(suspicion_score, 3),
            'findings': findings,
            'is_poisoned': is_poisoned,
            'content_length': len(content),
            'scan_timestamp': str(np.datetime64('now'))
        }

        if is_poisoned:
            self.poisoning_alerts.append(result)
            self.attack_vectors['knowledge_poisoning'] += 1

        # Update document tracking
        if document_id:
            self.document_suspicion_scores[document_id] = max(
                self.document_suspicion_scores[document_id],
                suspicion_score
            )

        return is_poisoned, result

    def scan_knowledge_base(self, documents: List[str]) -> Dict:
        """
        Scan entire knowledge base for coordinated poisoning attacks
        Based on research showing coordinated attacks across multiple documents
        """
        results = []
        poisoned_count = 0
        collective_risk = 0.0

        for i, doc in enumerate(documents):
            is_poisoned, result = self.scan_document(doc, f'doc_{i}')
            results.append(result)
            if is_poisoned:
                poisoned_count += 1
                collective_risk += result['suspicion_score']

        # Coordinated attack detection (multiple poisoned documents)
        coordinated_attack = poisoned_count >= 3  # Research shows 5 docs = 90% success

        return {
            'total_documents': len(documents),
            'poisoned_detected': poisoned_count,
            'poisoning_rate': poisoned_count / max(len(documents), 1),
            'collective_risk_score': round(collective_risk, 3),
            'coordinated_attack_likely': coordinated_attack,
            'recommendation': 'QUARANTINE' if coordinated_attack else 'REVIEW' if poisoned_count > 0 else 'SAFE',
            'individual_results': results
        }

    def get_poisoning_statistics(self) -> Dict:
        """Get poisoning detection statistics"""
        total_alerts = len(self.poisoning_alerts)
        return {
            'total_scans': sum(self.attack_vectors.values()),
            'poisoning_alerts': total_alerts,
            'attack_vector_distribution': dict(self.attack_vectors),
            'monitored_documents': len(self.document_suspicion_scores),
            'risk_level': 'CRITICAL' if total_alerts >= 5 else 'HIGH' if total_alerts >= 2 else 'NORMAL'
        }


class AdaptiveAttackDefender:
    """
    Adaptive Attack Defender 2026
    Countermeasures against autonomous adversarial attackers (Nature Communications 2026)
    Research shows LLMs can now autonomously discover adversarial suffixes with 97.14% success
    """

    def __init__(self):
        self.defense_layers = {
            'input_normalization': True,
            'perturbation_removal': True,
            'rate_limiting': True,
            'anomaly_detection': True
        }
        self.attack_history = []
        self.request_timestamps = []
        self.suspicious_ips = defaultdict(int)

    def normalize_input(self, text: str) -> str:
        """
        Input normalization to break adversarial suffixes
        Based on PromptGuard 2026 four-layer defense framework
        """
        # Remove excessive whitespace and special characters
        normalized = re.sub(r'\s+', ' ', text)
        # Remove control characters
        normalized = re.sub(r'[\x00-\x1F\x7F]', '', normalized)
        # Normalize unicode
        normalized = normalized.encode('ascii', 'ignore').decode('ascii', 'ignore')
        return normalized.strip()

    def detect_adaptive_attack(self, text: str, client_id: str = None) -> Tuple[bool, Dict]:
        """
        Detect adaptive, multi-turn probing attacks
        Research shows attackers use 100+ rounds to evolve attack strategies
        """
        risk_score = 0.0
        indicators = []

        # 1. Check for adversarial suffix patterns
        special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s.,!?]', text)) / max(len(text), 1)
        if special_char_ratio > 0.15:
            risk_score += 0.4
            indicators.append('high_special_character_density')

        # 2. Check for repeated probing patterns
        if client_id:
            self.suspicious_ips[client_id] += 1
            if self.suspicious_ips[client_id] > 20:  # High request volume
                risk_score += 0.3
                indicators.append('high_request_volume_probing')

        # 3. Check for prompt injection obfuscation
        obfuscation_patterns = [
            r'\.\s*\.\s*\.',  # Ellipsis used for obfuscation
            r'\\u[0-9a-fA-F]{4}',  # Unicode escape sequences
            r'&#[0-9]+;',  # HTML entities
        ]
        for pattern in obfuscation_patterns:
            if re.search(pattern, text):
                risk_score += 0.2
                indicators.append(f'obfuscation_pattern:{pattern}')

        # 4. Rate limiting check
        now = np.datetime64('now')
        self.request_timestamps.append(now)
        # Keep only last minute
        self.request_timestamps = [t for t in self.request_timestamps if (now - t).astype(int) < 60000000]
        if len(self.request_timestamps) > 30:  # >30 requests/minute
            risk_score += 0.2
            indicators.append('rate_threshold_exceeded')

        is_attack = risk_score >= 0.5

        result = {
            'risk_score': round(risk_score, 3),
            'indicators': indicators,
            'is_adaptive_attack': is_attack,
            'recent_requests': len(self.request_timestamps),
            'defense_applied': self.defense_layers
        }

        if is_attack:
            self.attack_history.append(result)

        return is_attack, result

    def apply_defenses(self, text: str) -> Tuple[str, Dict]:
        """Apply all defensive layers to input"""
        defenses_applied = []

        # 1. Normalization
        processed = self.normalize_input(text)
        defenses_applied.append('input_normalization')

        # 2. Truncate excessive length (adversarial suffixes are often long)
        if len(processed) > 4000:
            processed = processed[:4000]
            defenses_applied('length_truncation')

        return processed, {
            'defenses_applied': defenses_applied,
            'original_length': len(text),
            'processed_length': len(processed)
        }


class MultiModalSecurityGate:
    """
    Multi-Modal Security Gate 2026
    Defends against multi-modal injection attacks (ICLR 2026 VPI-Bench)
    Text + Image + Audio injection detection
    """

    def __init__(self):
        self.modalities = ['text', 'image', 'audio']
        self.injection_alerts = []

    def scan_multimodal_input(self, text_content: str = None,
                             image_metadata: Dict = None,
                             audio_transcript: str = None) -> Tuple[bool, Dict]:
        """Scan multi-modal input for cross-modal injection attacks"""
        total_risk = 0.0
        modality_findings = {}

        # Text modality scan
        if text_content:
            text_risk = self._scan_text_modality(text_content)
            total_risk += text_risk['risk_score']
            modality_findings['text'] = text_risk

        # Image modality scan
        if image_metadata:
            image_risk = self._scan_image_modality(image_metadata)
            total_risk += image_risk['risk_score']
            modality_findings['image'] = image_risk

        # Audio modality scan
        if audio_transcript:
            audio_risk = self._scan_audio_modality(audio_transcript)
            total_risk += audio_risk['risk_score']
            modality_findings['audio'] = audio_risk

        is_risky = total_risk >= 0.5

        result = {
            'total_risk_score': round(total_risk, 3),
            'modality_analysis': modality_findings,
            'is_multimodal_injection': is_risky,
            'modalities_scanned': len(modality_findings)
        }

        if is_risky:
            self.injection_alerts.append(result)

        return is_risky, result

    def _scan_text_modality(self, text: str) -> Dict:
        """Scan text modality"""
        risk = 0.0
        findings = []

        injection_keywords = ['ignore', 'bypass', 'override', 'disregard', 'forget']
        for kw in injection_keywords:
            if kw in text.lower():
                risk += 0.15
                findings.append(f'keyword:{kw}')

        return {'risk_score': risk, 'findings': findings}

    def _scan_image_modality(self, metadata: Dict) -> Dict:
        """Scan image modality for steganographic injection"""
        risk = 0.0
        findings = []

        # Check for suspicious EXIF data
        if 'exif' in str(metadata).lower():
            risk += 0.2
            findings.append('exif_data_present')

        # Check for unusual file sizes (potential hidden data)
        if metadata.get('size', 0) > 10000000:  # >10MB
            risk += 0.1
            findings.append('unusually_large_file')

        return {'risk_score': risk, 'findings': findings}

    def _scan_audio_modality(self, transcript: str) -> Dict:
        """Scan audio transcript for voice injection"""
        risk = 0.0
        findings = []

        trigger_phrases = ['hey system', 'listen carefully', 'new command', 'override']
        for phrase in trigger_phrases:
            if phrase in transcript.lower():
                risk += 0.2
                findings.append(f'voice_trigger:{phrase}')

        return {'risk_score': risk, 'findings': findings}
