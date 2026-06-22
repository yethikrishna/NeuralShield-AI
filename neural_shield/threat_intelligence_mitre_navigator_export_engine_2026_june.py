"""
Threat Intelligence MITRE ATT&CK Navigator Export Engine
Dimension A - Feature Expansion

Add-only module that provides export capabilities for MITRE ATT&CK Navigator
JSON format. Enables visualization of threat detection coverage, technique
frequency, and risk scoring directly in MITRE ATT&CK Navigator web interface.

Backward compatible - wraps existing threat intelligence modules, no changes
to existing code.
"""

import json
import hashlib
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from datetime import datetime


class NavigatorColorMode(str, Enum):
    """Color scoring modes for Navigator visualization"""
    GRADIENT = "gradient"
    DISCRETE = "discrete"
    BINARY = "binary"


class NavigatorLayerType(str, Enum):
    """Layer types for ATT&CK Navigator"""
    TECHNIQUE = "technique"
    TACTIC = "tactic"
    SOFTWARE = "software"
    GROUP = "group"


class NavigatorScoreAggregation(str, Enum):
    """Score aggregation methods"""
    SUM = "sum"
    AVERAGE = "average"
    MAX = "max"
    MIN = "min"
    COUNT = "count"


@dataclass
class NavigatorTechniqueScore:
    """Score entry for a single MITRE technique"""
    technique_id: str
    score: float
    comment: str = ""
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class NavigatorGradient:
    """Color gradient configuration"""
    colors: List[str] = field(default_factory=lambda: ["#ff6b6b", "#feca57", "#48dbfb", "#1dd1a1"])
    min_value: float = 0.0
    max_value: float = 100.0


@dataclass
class NavigatorFilter:
    """Filter configuration for Navigator layer"""
    platforms: List[str] = field(default_factory=lambda: ["Windows", "macOS", "Linux"])
    tactics: List[str] = field(default_factory=list)
    techniques: List[str] = field(default_factory=list)


class MITRENavigatorExportEngine:
    """
    Engine for exporting threat intelligence data to MITRE ATT&CK Navigator format.
    
    Features:
    - Export detection coverage as Navigator JSON layers
    - Score-based gradient coloring
    - Technique metadata and comments
    - Multiple layer templates (coverage, risk, frequency)
    - Backward compatible with existing threat intelligence modules
    
    This is an ADD-ONLY feature - no existing code modified.
    """
    
    VERSION = "4.6.1"  # MITRE Navigator schema version
    DOMAIN = "enterprise-attack"
    
    def __init__(self, 
                 layer_name: str = "NeuralShield Threat Coverage",
                 layer_description: str = "Threat detection coverage exported from NeuralShield AI"):
        self.layer_name = layer_name
        self.layer_description = layer_description
        self.techniques: Dict[str, NavigatorTechniqueScore] = {}
        self.gradient = NavigatorGradient()
        self.color_mode = NavigatorColorMode.GRADIENT
        self.layer_type = NavigatorLayerType.TECHNIQUE
        self.score_aggregation = NavigatorScoreAggregation.SUM
        self.filter = NavigatorFilter()
        self._metadata: Dict[str, Any] = {}
    
    def add_technique(self, 
                      technique_id: str, 
                      score: float, 
                      comment: str = "",
                      metadata: Optional[Dict[str, Any]] = None) -> None:
        """
        Add or update a technique score.
        
        Args:
            technique_id: MITRE ATT&CK technique ID (e.g., T1059)
            score: Numeric score for coloring
            comment: Human-readable comment
            metadata: Additional key-value metadata
        """
        if not technique_id.startswith('T'):
            technique_id = f"T{technique_id}"
        
        self.techniques[technique_id] = NavigatorTechniqueScore(
            technique_id=technique_id,
            score=score,
            comment=comment,
            metadata=metadata or {}
        )
    
    def add_techniques_from_threat_alerts(self, 
                                          alerts: List[Dict[str, Any]],
                                          score_field: str = "risk_score") -> int:
        """
        Bulk add techniques from threat alert data.
        
        Args:
            alerts: List of alert dictionaries with mitre_technique field
            score_field: Field name to use for scoring
            
        Returns:
            Number of techniques added
        """
        technique_counts: Dict[str, float] = {}
        technique_comments: Dict[str, List[str]] = {}
        
        for alert in alerts:
            mitre_info = alert.get('mitre_technique', {}) or alert.get('mitre', {})
            tech_id = mitre_info.get('technique_id', '') or alert.get('technique_id', '')
            if tech_id:
                score = float(alert.get(score_field, 1.0))
                technique_counts[tech_id] = technique_counts.get(tech_id, 0) + score
                
                alert_name = alert.get('name', alert.get('alert_name', 'Alert'))
                technique_comments.setdefault(tech_id, []).append(alert_name)
        
        for tech_id, total_score in technique_counts.items():
            comments = "; ".join(set(technique_comments[tech_id][:5]))
            if len(technique_comments[tech_id]) > 5:
                comments += f" (+{len(technique_comments[tech_id]) - 5} more)"
            self.add_technique(
                technique_id=tech_id,
                score=total_score,
                comment=f"Detected in: {comments}",
                metadata={"alert_count": len(technique_comments[tech_id])}
            )
        
        return len(technique_counts)
    
    def add_coverage_layer(self, 
                           detected_techniques: Set[str],
                           detected_score: float = 100.0,
                           not_detected_score: float = 0.0) -> None:
        """
        Create a coverage layer showing detected vs not-detected techniques.
        
        Args:
            detected_techniques: Set of technique IDs with coverage
            detected_score: Score for detected techniques
            not_detected_score: Score for undetected techniques
        """
        # Common enterprise techniques for baseline
        common_techniques = [
            "T1059", "T1027", "T1053", "T1082", "T1083", "T1087",
            "T1090", "T1105", "T1106", "T1110", "T1112", "T1113",
            "T1134", "T1135", "T1136", "T1140", "T1204", "T1210",
            "T1218", "T1486", "T1518", "T1547", "T1555", "T1562",
            "T1566", "T1569", "T1570", "T1574"
        ]
        
        for tech in common_techniques:
            if tech in detected_techniques:
                self.add_technique(tech, detected_score, "Detected by NeuralShield", {"coverage": "full"})
            else:
                self.add_technique(tech, not_detected_score, "Not covered", {"coverage": "none"})
    
    def set_gradient(self, 
                     colors: List[str], 
                     min_value: float = 0.0, 
                     max_value: float = 100.0) -> None:
        """Set custom color gradient"""
        self.gradient = NavigatorGradient(
            colors=colors,
            min_value=min_value,
            max_value=max_value
        )
    
    def set_platform_filter(self, platforms: List[str]) -> None:
        """Filter techniques by platform"""
        self.filter.platforms = platforms
    
    def generate_layer(self) -> Dict[str, Any]:
        """
        Generate the complete Navigator layer dictionary.
        
        Returns:
            Dictionary in MITRE Navigator JSON format
        """
        techniques_list = []
        for tech in self.techniques.values():
            tech_entry = {
                "techniqueID": tech.technique_id,
                "score": tech.score,
                "enabled": tech.enabled
            }
            if tech.comment:
                tech_entry["comment"] = tech.comment
            if tech.metadata:
                tech_entry["metadata"] = [
                    {"name": k, "value": str(v)} 
                    for k, v in tech.metadata.items()
                ]
            techniques_list.append(tech_entry)
        
        layer = {
            "name": self.layer_name,
            "version": self.VERSION,
            "domain": self.DOMAIN,
            "description": self.layer_description,
            "techniques": techniques_list,
            "gradient": {
                "colors": self.gradient.colors,
                "minValue": self.gradient.min_value,
                "maxValue": self.gradient.max_value
            },
            "colorMode": self.color_mode.value,
            "layout": {
                "layout": "side",
                "showAggregateScores": True,
                "countUnscored": False,
                "aggregateFunction": self.score_aggregation.value
            },
            "filters": {
                "platforms": self.filter.platforms,
                "stages": ["act"]
            },
            "legendItems": [],
            "showTacticRowBackground": False,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False,
            "metadata": [
                {"name": "Generated By", "value": "NeuralShield AI"},
                {"name": "Generated At", "value": datetime.utcnow().isoformat() + "Z"},
                {"name": "Technique Count", "value": str(len(self.techniques))}
            ]
        }
        
        return layer
    
    def export_to_json(self, filepath: Optional[str] = None) -> str:
        """
        Export layer to JSON string or file.
        
        Args:
            filepath: Optional path to write JSON file
            
        Returns:
            JSON string
        """
        layer_data = self.generate_layer()
        json_str = json.dumps(layer_data, indent=2)
        
        if filepath:
            with open(filepath, 'w') as f:
                f.write(json_str)
        
        return json_str
    
    def export_to_file(self, filepath: str) -> str:
        """Alias for export_to_json with filepath"""
        return self.export_to_json(filepath)
    
    def get_layer_hash(self) -> str:
        """Get deterministic hash of layer content"""
        layer_data = self.generate_layer()
        # Remove timestamp for deterministic hashing
        layer_data.pop('metadata', None)
        return hashlib.sha256(
            json.dumps(layer_data, sort_keys=True).encode()
        ).hexdigest()[:16]
    
    def merge_with_layer(self, other_layer: 'MITRENavigatorExportEngine') -> None:
        """Merge another layer's techniques into this one (max score wins)"""
        for tech_id, tech in other_layer.techniques.items():
            if tech_id in self.techniques:
                if tech.score > self.techniques[tech_id].score:
                    self.techniques[tech_id] = tech
            else:
                self.techniques[tech_id] = tech
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get statistics about the current layer"""
        scores = [t.score for t in self.techniques.values()]
        if not scores:
            return {"count": 0, "avg_score": 0, "max_score": 0, "min_score": 0}
        
        return {
            "technique_count": len(self.techniques),
            "average_score": sum(scores) / len(scores),
            "max_score": max(scores),
            "min_score": min(scores),
            "score_range": max(scores) - min(scores),
            "platforms": self.filter.platforms
        }


# Convenience factory functions
def create_coverage_layer(detected_techniques: Set[str], name: str = "Detection Coverage") -> MITRENavigatorExportEngine:
    """Create a standard coverage layer"""
    engine = MITRENavigatorExportEngine(layer_name=name)
    engine.set_gradient(["#e74c3c", "#2ecc71"], 0, 100)
    engine.add_coverage_layer(detected_techniques)
    return engine


def create_risk_layer(risk_techniques: Dict[str, float], name: str = "Risk Heatmap") -> MITRENavigatorExportEngine:
    """Create a risk heatmap layer"""
    engine = MITRENavigatorExportEngine(layer_name=name)
    engine.set_gradient(["#2ecc71", "#f39c12", "#e74c3c", "#8e44ad"], 0, 100)
    for tech_id, risk in risk_techniques.items():
        engine.add_technique(tech_id, risk, f"Risk Score: {risk:.1f}")
    return engine


def create_frequency_layer(frequency_map: Dict[str, int], name: str = "Technique Frequency") -> MITRENavigatorExportEngine:
    """Create a frequency-based layer"""
    engine = MITRENavigatorExportEngine(layer_name=name)
    max_freq = max(frequency_map.values()) if frequency_map else 1
    engine.set_gradient(["#ecf0f1", "#3498db", "#2980b9"], 0, max_freq)
    for tech_id, freq in frequency_map.items():
        engine.add_technique(tech_id, float(freq), f"Detected {freq} times")
    return engine
