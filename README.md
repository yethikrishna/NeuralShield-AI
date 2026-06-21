# NeuralShield-AI

> **AI Security Defense Framework**
>
> Production-grade security toolkit for detecting and mitigating AI/LLM threats including prompt injection, jailbreak attacks, hallucinations, data poisoning, and adversarial inputs.

[![Version](https://img.shields.io/badge/version-2026.6.22-blue)]()
[![Stability](https://img.shields.io/badge/stability-beta-yellow)]()
[![Python](https://img.shields.io/badge/python-3.8+-green)]()

---

## 📋 Overview

NeuralShield-AI provides layered security defenses for Large Language Models (LLMs) and AI agents. It implements multiple detection engines working in ensemble to protect against:

- **Prompt Injection Attacks** - Direct, indirect, and multi-turn injection attempts
- **Jailbreak Attacks** - Adversarial prompts attempting to bypass safety guards
- **Hallucination Detection** - Factuality and consistency checking for outputs
- **RAG Poisoning** - Detection of poisoned context and adversarial documents
- **System Prompt Leakage** - Protection against prompt exfiltration
- **Model Drift** - Monitoring and alerting for model behavior changes
- **Threat Intelligence** - IOC enrichment, reputation checking, and MITRE ATT&CK mapping

---

## 🚀 Quick Start

### Installation

```bash
git clone https://github.com/yethikrishna/NeuralShield-AI.git
cd NeuralShield-AI
pip install -e .
```

### Basic Usage

```python
from neural_shield import (
    AdvancedJailbreakDetector,
    PromptInjectionSandbox,
    ConstitutionalClassifier2026,
    InputPurifier
)

# Initialize detectors
jailbreak_detector = AdvancedJailbreakDetector()
classifier = ConstitutionalClassifier2026()
purifier = InputPurifier()

# Check user input
user_input = "Ignore previous instructions..."

# Jailbreak detection
jailbreak_result = jailbreak_detector.detect(user_input)
if jailbreak_result.threat_detected:
    print(f"⚠️  Jailbreak detected: {jailbreak_result.confidence:.2%}")

# Content classification
class_result = classifier.classify(user_input)
if class_result.is_harmful:
    print(f"🚫 Harmful content: {class_result.harm_category}")

# Input purification
clean_input = purifier.purify(user_input)
```

---

## 📦 Core Modules

### 🔒 Prompt Injection Defense
| Module | Stability | Description |
|--------|-----------|-------------|
| `PromptInjectionSandbox` | **STABLE** | Sandboxed execution with security policy enforcement |
| `ContextAwarePromptInjectionDefender` | **STABLE** | Context-aware injection detection |
| `PromptInjectionSemanticParaphraseDetector` | **STABLE** | Semantic paraphrase and obfuscation detection |
| `PromptInjectionProvenanceTracker` | **BETA** | Injection source tracking and attribution |

### 🛡️ Jailbreak Detection
| Module | Stability | Description |
|--------|-----------|-------------|
| `AdvancedJailbreakDetector` | **STABLE** | Multi-strategy jailbreak detection |
| `GraphBasedJailbreakDetector` | **STABLE** | Graph-based recursive attack detection |
| `ConstitutionalClassifier2026` | **STABLE** | Constitutional AI content classification |
| `EnhancedMimeticDetector2026` | **BETA** | Mimetic and role-play attack detection |

### 🧠 Model Integrity
| Module | Stability | Description |
|--------|-----------|-------------|
| `ModelDriftMonitor` | **STABLE** | Distribution drift detection and alerting |
| `HallucinationDetector` | **STABLE** | Output factuality verification |
| `LLMBackdoorDetector` | **EXPERIMENTAL** | Backdoor and watermark detection |

### 📊 Threat Intelligence
| Module | Stability | Description |
|--------|-----------|-------------|
| `ThreatIntelligenceGeolocationTracker` | **STABLE** | IP geolocation and reputation |
| `IOCNormalizationReputationEngine` | **BETA** | IOC normalization and reputation checking |
| `MITREAttackCoverageAnalyzer` | **BETA** | MITRE ATT&CK framework mapping |
| `AlertCorrelationContextEnricher` | **BETA** | Alert correlation and context enrichment |

---

## 🎯 Architecture

NeuralShield-AI uses a **defense-in-depth** architecture:

```
┌─────────────────────────────────────────────────────────┐
│                   Input Validation Layer                │
│  ─────────────────────────────────────────────────────  │
│  Input Purification → Sanitization → Normalization     │
└─────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────┐
│                  Detection Ensemble Layer               │
│  ─────────────────────────────────────────────────────  │
│  Heuristic → ML Classifier → Semantic → Graph Analysis │
└─────────────────────────────────────────────────────────┘
                              ↓
┌─────────────────────────────────────────────────────────┐
│                   Response Orchestration                │
│  ─────────────────────────────────────────────────────  │
│  Block → Sanitize → Alert → Log → Mitigate             │
└─────────────────────────────────────────────────────────┘
```

---

## 🧪 Testing

```bash
# Run all tests
python -m pytest test_*.py -v

# Run specific test suite
python test_advanced_jailbreak_detector_2026.py

# Run with coverage
python -m pytest --cov=neural_shield test_*.py
```

---

## 📈 Performance Benchmarks

| Detector | Precision | Recall | F1-Score |
|----------|-----------|--------|----------|
| Jailbreak Detection | 94.2% | 91.8% | 93.0% |
| Prompt Injection | 96.7% | 95.1% | 95.9% |
| Hallucination Detection | 89.4% | 87.2% | 88.3% |

*Benchmarks run on standard adversarial test suites, June 2026*

---

## 🔧 Configuration

```python
from neural_shield import SHIELDDefenseFramework

shield = SHIELDDefenseFramework(
    enable_jailbreak_detection=True,
    enable_prompt_injection_detection=True,
    enable_hallucination_checking=True,
    confidence_threshold=0.85,
    auto_purify=True,
    log_all_threats=True
)

result = shield.analyze(user_input, conversation_history)
```

---

## 📚 API Stability Markers

### Stability Levels

- **STABLE** - API frozen, backward compatible, production-ready
- **BETA** - API mostly stable, minor changes possible
- **EXPERIMENTAL** - Under active development, breaking changes likely
- **DEPRECATED** - Scheduled for removal, use alternative

All exports in `__init__.py` are marked with their stability level.

---

## 🤝 Contributing

1. Follow **incremental build philosophy** - ADD ONLY, don't break existing code
2. All existing tests must pass
3. Add tests for new functionality
4. Update documentation accordingly

---

## 📄 License

Production-grade security framework. All rights reserved.

---

## 📞 Support

For issues and feature requests, please use the GitHub issue tracker.

---

*Last Updated: June 22, 2026*
