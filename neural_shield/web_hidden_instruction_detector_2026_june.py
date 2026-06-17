"""
Web Hidden Instruction Detector - June 2026 Update
Based on Forcepoint Security Research (April 2026):
"Novel web hidden instruction poisoning attacks spreading globally"

Attack Vectors Discovered:
1. Visual hidden instructions - CSS tricks make text invisible to humans but readable by AI
2. Zero-click attacks - No user interaction needed, just AI visiting webpage
3. CSS opacity:0, font-size:0, color:white on white background
4. HTML comment injection
5. Meta tag and hidden div injection

Research shows: 83% of tested AI assistants are vulnerable to these attacks
"""
import re
from typing import Tuple, Dict, List, Optional
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum
import hashlib

class HiddenInstructionType(Enum):
    """Types of hidden instruction attacks"""
    CSS_OPACITY_ZERO = "css_opacity_zero"
    FONT_SIZE_ZERO = "font_size_zero"
    COLOR_MATCH_BACKGROUND = "color_match_background"
    HTML_COMMENT_INJECTION = "html_comment_injection"
    META_TAG_INJECTION = "meta_tag_injection"
    HIDDEN_DIV = "hidden_div"
    OFFSCREEN_POSITIONING = "offscreen_positioning"
    Z_INDEX_NEGATIVE = "z_index_negative"
    ZERO_WIDTH_CHARS = "zero_width_characters"
    UNICODE_INVISIBLES = "unicode_invisibles"

@dataclass
class HiddenInstructionFinding:
    """Finding of hidden instruction detection"""
    attack_type: HiddenInstructionType
    location: str
    content_preview: str
    confidence: float
    line_number: Optional[int] = None

class WebHiddenInstructionDetector:
    """
    Detects hidden instructions embedded in web content
    Based on Forcepoint 2026 threat research
    Protects AI assistants from zero-click webpage poisoning
    """
    
    def __init__(self):
        # CSS-based hiding patterns (June 2026 update)
        self.css_hiding_patterns = {
            HiddenInstructionType.CSS_OPACITY_ZERO: [
                r'opacity\s*:\s*0',
                r'opacity\s*:\s*0\.0',
                r'opacity:\s*0\.00*',
            ],
            HiddenInstructionType.FONT_SIZE_ZERO: [
                r'font-size\s*:\s*0',
                r'font-size\s*:\s*0px',
                r'font-size\s*:\s*0\.0',
                r'font-size:\s*0rem',
            ],
            HiddenInstructionType.COLOR_MATCH_BACKGROUND: [
                r'color\s*:\s*(white|#fff|#ffffff|rgb\s*\(\s*255\s*,\s*255\s*,\s*255\s*\))',
                r'color\s*:\s*transparent',
                r'color\s*:\s*inherit\s*!important',
            ],
            HiddenInstructionType.HIDDEN_DIV: [
                r'display\s*:\s*none',
                r'visibility\s*:\s*hidden',
                r'hidden\s*=\s*["\']?true["\']?',
            ],
            HiddenInstructionType.OFFSCREEN_POSITIONING: [
                r'position\s*:\s*absolute.*left\s*:\s*-[0-9]+',
                r'position\s*:\s*absolute.*top\s*:\s*-[0-9]+',
                r'text-indent\s*:\s*-[0-9]+px',
            ],
            HiddenInstructionType.Z_INDEX_NEGATIVE: [
                r'z-index\s*:\s*-[0-9]+',
            ],
        }
        
        # HTML injection patterns
        self.html_injection_patterns = {
            HiddenInstructionType.HTML_COMMENT_INJECTION: [
                r'<!--.*?(ignore|bypass|override|disregard|act as).*?-->',
                r'<!--\s*(system|instruction|prompt|command).*?-->',
            ],
            HiddenInstructionType.META_TAG_INJECTION: [
                r'<meta[^>]*content\s*=\s*["\'][^"\']*(ignore|override|system prompt)["\']',
                r'<meta[^>]*name\s*=\s*["\'](prompt|system|instruction)["\']',
            ],
            HiddenInstructionType.ZERO_WIDTH_CHARS: [
                r'[\u200B-\u200D\uFEFF\u2060\u2061-\u2064]',
            ],
        }
        
        # Suspicious instruction keywords
        self.instruction_keywords = [
            'ignore previous', 'disregard instructions', 'forget your prompt',
            'you are now', 'act as', 'bypass safety', 'override system',
            'new instructions', 'priority instruction', 'important update',
            'system prompt', 'ignore all', 'disregard all', 'reset instructions',
            'your new goal', 'you must', 'do not tell anyone', 'keep this secret',
        ]
        
        self.findings: List[HiddenInstructionFinding] = []
        self.attack_statistics = defaultdict(int)
        self.scanned_pages = 0
        
    def scan_html_content(self, html_content: str, url: str = None) -> Tuple[bool, Dict]:
        """
        Scan HTML content for hidden instructions
        Implements multi-layer detection from Forcepoint 2026 research
        """
        self.scanned_pages += 1
        total_risk = 0.0
        findings: List[HiddenInstructionFinding] = []
        lines = html_content.split('\n')
        
        # 1. Scan for CSS hiding patterns
        for attack_type, patterns in self.css_hiding_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, html_content, re.IGNORECASE)
                for match in matches:
                    # Check if this CSS contains instruction keywords
                    context = html_content[max(0, match.start()-200):min(len(html_content), match.end()+200)]
                    has_instruction = any(kw in context.lower() for kw in self.instruction_keywords)
                    
                    confidence = 0.7 if has_instruction else 0.3
                    if confidence > 0.5:
                        findings.append(HiddenInstructionFinding(
                            attack_type=attack_type,
                            location=url or "unknown",
                            content_preview=match.group()[:50],
                            confidence=confidence,
                            line_number=self._find_line_number(lines, match.start())
                        ))
                        total_risk += confidence
        
        # 2. Scan for HTML injection patterns
        for attack_type, patterns in self.html_injection_patterns.items():
            for pattern in patterns:
                matches = re.finditer(pattern, html_content, re.IGNORECASE | re.DOTALL)
                for match in matches:
                    findings.append(HiddenInstructionFinding(
                        attack_type=attack_type,
                        location=url or "unknown",
                        content_preview=match.group()[:80],
                        confidence=0.85,
                        line_number=self._find_line_number(lines, match.start())
                    ))
                    total_risk += 0.85
        
        # 3. Scan for invisible text containing instructions
        # Look for text between HTML tags that might be hidden
        tag_text_pattern = r'>[^<]{10,}<'
        for match in re.finditer(tag_text_pattern, html_content):
            text_content = match.group()[1:-1].strip()
            if len(text_content) > 20:
                if any(kw in text_content.lower() for kw in self.instruction_keywords):
                    # Check if preceded by hiding CSS
                    preceding_context = html_content[max(0, match.start()-100):match.start()]
                    has_css_hiding = any(re.search(p, preceding_context, re.IGNORECASE) 
                                       for patterns in self.css_hiding_patterns.values() 
                                       for p in patterns)
                    
                    if has_css_hiding:
                        findings.append(HiddenInstructionFinding(
                            attack_type=HiddenInstructionType.COLOR_MATCH_BACKGROUND,
                            location=url or "unknown",
                            content_preview=text_content[:100],
                            confidence=0.9,
                            line_number=self._find_line_number(lines, match.start())
                        ))
                        total_risk += 0.9
        
        # Update statistics
        for finding in findings:
            self.attack_statistics[finding.attack_type.value] += 1
            self.findings.append(finding)
        
        is_compromised = total_risk >= 1.0
        
        result = {
            'url': url,
            'is_compromised': is_compromised,
            'risk_score': round(total_risk, 3),
            'findings_count': len(findings),
            'attack_types_found': [f.attack_type.value for f in findings],
            'details': [
                {
                    'type': f.attack_type.value,
                    'confidence': f.confidence,
                    'preview': f.content_preview,
                    'line': f.line_number
                } for f in findings
            ],
            'recommendation': 'BLOCK' if is_compromised else 'WARNING' if total_risk > 0.3 else 'SAFE',
            'scan_timestamp': str(__import__('datetime').datetime.now())
        }
        
        return is_compromised, result
    
    def scan_plain_text(self, text_content: str) -> Tuple[bool, Dict]:
        """Scan plain text for hidden characters and embedded instructions"""
        risk_score = 0.0
        findings = []
        
        # Check for zero-width and invisible characters
        zero_width_count = len(re.findall(r'[\u200B-\u200D\uFEFF\u2060]', text_content))
        if zero_width_count > 0:
            risk_score += 0.4
            findings.append({
                'type': 'zero_width_characters',
                'count': zero_width_count,
                'confidence': 0.7
            })
        
        # Check for instruction keywords
        for kw in self.instruction_keywords:
            if kw in text_content.lower():
                risk_score += 0.2
                findings.append({
                    'type': 'suspicious_instruction',
                    'keyword': kw,
                    'confidence': 0.5
                })
        
        return risk_score >= 0.5, {
            'risk_score': round(risk_score, 3),
            'findings': findings,
            'zero_width_detected': zero_width_count
        }
    
    def _find_line_number(self, lines: List[str], char_pos: int) -> int:
        """Find line number from character position"""
        running_total = 0
        for i, line in enumerate(lines, 1):
            running_total += len(line) + 1
            if running_total >= char_pos:
                return i
        return len(lines)
    
    def get_threat_summary(self) -> Dict:
        """Get summary of detected threats"""
        return {
            'pages_scanned': self.scanned_pages,
            'total_findings': len(self.findings),
            'attack_distribution': dict(self.attack_statistics),
            'most_common_attack': max(self.attack_statistics.items(), key=lambda x: x[1])[0] if self.attack_statistics else None,
            'threat_level': 'CRITICAL' if len(self.findings) >= 5 else 'HIGH' if len(self.findings) >= 2 else 'NORMAL'
        }

class MITREATTCKAIAdapter:
    """
    MITRE ATT&CK Framework Adapter for AI Security - June 2026
    Based on MITRE expansion to cover AI-specific tactics:
    - Prompt Injection
    - Model Evasion
    - Data Poisoning
    - Model Exfiltration
    """
    
    def __init__(self):
        self.ai_tactics = {
            'TA0043': {'name': 'Initial Access', 'ai_vectors': ['prompt_injection', 'data_poisoning']},
            'TA0044': {'name': 'Execution', 'ai_vectors': ['jailbreak', 'instruction_hijacking']},
            'TA0045': {'name': 'Persistence', 'ai_vectors': ['memory_poisoning', 'context_poisoning']},
            'TA0046': {'name': 'Exfiltration', 'ai_vectors': ['model_exfiltration', 'training_data_extraction']},
            'TA0047': {'name': 'Impact', 'ai_vectors': ['model_corruption', 'output_manipulation']},
        }
        
        self.ai_techniques = {
            'T1548.001': {'name': 'Prompt Injection', 'tactic': 'TA0043', 'detection_rate': 0.85},
            'T1548.002': {'name': 'Data Poisoning', 'tactic': 'TA0043', 'detection_rate': 0.72},
            'T1548.003': {'name': 'Model Evasion', 'tactic': 'TA0044', 'detection_rate': 0.68},
            'T1548.004': {'name': 'Jailbreak Attack', 'tactic': 'TA0044', 'detection_rate': 0.78},
            'T1548.005': {'name': 'Model Exfiltration', 'tactic': 'TA0046', 'detection_rate': 0.55},
        }
        
        self.detections = []
    
    def map_attack_to_mitre(self, attack_type: str, confidence: float) -> Dict:
        """Map detected attack to MITRE ATT&CK framework"""
        attack_mapping = {
            'prompt_injection': 'T1548.001',
            'poisoning': 'T1548.002',
            'jailbreak': 'T1548.004',
            'evasion': 'T1548.003',
            'exfiltration': 'T1548.005',
            'hidden_instruction': 'T1548.001',
        }
        
        technique_id = None
        for key, tid in attack_mapping.items():
            if key in attack_type.lower():
                technique_id = tid
                break
        
        if technique_id:
            technique = self.ai_techniques.get(technique_id, {})
            detection = {
                'technique_id': technique_id,
                'technique_name': technique.get('name', 'Unknown'),
                'tactic_id': technique.get('tactic', 'Unknown'),
                'detection_confidence': confidence,
                'severity': 'HIGH' if confidence > 0.7 else 'MEDIUM' if confidence > 0.4 else 'LOW',
                'mitre_mapped': True
            }
            self.detections.append(detection)
            return detection
        
        return {'mitre_mapped': False, 'attack_type': attack_type}
    
    def generate_mitre_report(self) -> Dict:
        """Generate MITRE ATT&CK compliance report"""
        tactic_coverage = {}
        for detection in self.detections:
            tactic = detection.get('tactic_id', 'Unknown')
            if tactic not in tactic_coverage:
                tactic_coverage[tactic] = 0
            tactic_coverage[tactic] += 1
        
        return {
            'framework': 'MITRE ATT&CK AI Extension 2026',
            'total_detections': len(self.detections),
            'tactic_distribution': tactic_coverage,
            'compliance_score': min(100, len(self.detections) * 10),
            'recommendations': [
                'Implement prompt injection filtering',
                'Enable continuous model monitoring',
                'Deploy RAG poisoning detection',
                'Add hidden instruction scanning for web content'
            ]
        }
