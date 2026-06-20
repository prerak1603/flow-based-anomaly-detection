      # 🛡️ Aegis AI — Network Intrusion Detection Platform

<div align="center">

![Java](https://img.shields.io/badge/Java-Spring_Boot-green?style=for-the-badge&logo=spring)
![Python](https://img.shields.io/badge/Python-ML_Pipeline-blue?style=for-the-badge&logo=python)
![XGBoost](https://img.shields.io/badge/XGBoost-Ensemble-orange?style=for-the-badge)
![HuggingFace](https://img.shields.io/badge/HuggingFace-DistilBERT-yellow?style=for-the-badge)
![Status](https://img.shields.io/badge/Status-LIVE-brightgreen?style=for-the-badge)

**A production-grade, end-to-end network security platform that detects cyber attacks in real time with 99.98% confidence.**

[Live API](#live-api) · [Architecture](#architecture) · [Results](#results) · [Setup](#setup)

</div>

---

## What Is Aegis AI?

Most network intrusion detection research stays inside Jupyter notebooks. Great accuracy numbers, published, forgotten.

Aegis AI is different. It's a **complete, working system** — from raw network traffic all the way to a deployed REST API that any security tool can call in real time.

Send it a network connection. It tells you in milliseconds:
- Is this an attack or normal traffic?
- What type of attack — DoS, Probe, R2L, U2R?
- How severe — NONE / MEDIUM / HIGH / CRITICAL?
- How confident — 0 to 100%?

---

## Live API

```bash
# Health check — is the system alive?
curl https://aegis-ai-api.onrender.com/api/health

# Predict — is this network flow an attack?
curl -X POST https://aegis-ai-api.onrender.com/api/predict \
  -H "Content-Type: application/json" \
  -d '{
    "duration": 0,
    "protocolType": "tcp" ,
    "service": "http",
    "flag": "SF",
    "srcBytes": 232,
    "dstBytes": 8153
  }'

# Response:
# {
#   "threat_class": "Normal",
#   "severity": "NONE",
#   "confidence": 0.9986,
#   "message": "No threat detected."
# }
```

---

## Results

| Metric | Score |
|--------|-------|
| Overall Accuracy | **96%** |
| Macro ROC-AUC | **0.98** |
| DoS Detection Confidence | **99.98%** |
| Normal Traffic Confidence | **99.86%** |
| Training Records | **125,000+** |
| Attack Types Covered | **23** |

---

## Architecture

```
ANY NETWORK SOURCE
(Security system / IoT sensor / Router logs)
          │
          ▼
┌─────────────────────────────────────┐
│  PHASE 1: Feature Engineering       │
│  Universal Schema Adapter           │
│  Zeek / CIC-IDS / NSL-KDD → 41     │
│  standardized features              │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  PHASE 2: Stacking Ensemble         │
│                                     │
│  Random Forest  ──┐                 │
│  XGBoost        ──┼→ Logistic      │
│  LightGBM       ──┘   Regression   │
│                       (meta-learner)│
│                                     │
│  + SMOTE (class imbalance)          │
│  + Platt Scaling (calibration)      │
│  + Optuna (90-trial HPO)            │
│  + 5-fold Stratified CV             │
│                                     │
│  Result: 96% accuracy, 0.98 AUC    │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  PHASE 3: WGAN-GP                   │
│  Synthetic Attack Generation        │
│                                     │
│  Generator → fake attack samples    │
│  Discriminator → real vs fake       │
│  Gradient Penalty → stable training │
│                                     │
│  500 synthetic R2L/U2R samples      │
│  generated to fix rare class recall │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  PHASE 4: NLP Threat Intelligence   │
│  HuggingFace Transformers           │
│                                     │
│  Zero-shot: bart-large-mnli         │
│  Similarity: all-MiniLM-L6-v2       │
│  Fine-tuned: DistilBERT             │
│                                     │
│  Classifies raw alert TEXT          │
│  CVEs, threat reports, IDS alerts   │
└─────────────────┬───────────────────┘
                  │
                  ▼
┌─────────────────────────────────────┐
│  SPRING BOOT REST API (Java)        │
│                                     │
│  POST   /api/predict                │
│  GET    /api/history                │
│  GET    /api/stats                  │
│  DELETE /api/history                │
│  GET    /api/health                 │
│                                     │
│  Java → Python bridge (ProcessBuilder)
│  Thread-safe ConcurrentLinkedDeque  │
│  Jakarta Bean Validation            │
│  4-level severity classification    │
└─────────────────────────────────────┘
```

---

## The Java-Python Bridge

The most critical engineering piece — connecting a Java Spring Boot API to a Python ML model:

```
Java receives request
      │
      │ converts to CSV: "0,1,1,232,8153,10"
      │
      ▼
ProcessBuilder runs:
python3 predict.py "0,1,1,232,8153,10"
      │
      ▼
Python loads stacking ensemble
runs prediction
prints JSON to stdout
      │
      ▼
Java reads stdout
parses JSON
returns to caller
```

Graceful fallback to rule-based heuristics if Python model unavailable — API never goes down.

---

## Tech Stack

**ML Pipeline (Python)**
- Scikit-learn, XGBoost, LightGBM
- PyTorch (WGAN-GP)
- HuggingFace Transformers (DistilBERT, BART)
- Sentence Transformers
- Optuna, SMOTE, Joblib

**Backend API (Java)**
- Spring Boot, Spring MVC
- Maven, Jakarta Bean Validation
- REST, OOP, Multithreading
- ConcurrentLinkedDeque

**Dataset**
- NSL-KDD (125,000+ network flow records)
- 23 attack types across 5 categories

---

## Project Structure

```
cic_ids_project/
│
├── notebooks/
│   ├── 1_prepare_nslkdd.py
│   ├── 2_ensemble_classification.ipynb    ← Phase 2
│   ├── 2b_ensemble_classifier.ipynb
│   ├── 3_gan_synthetic_attack_generation.ipynb  ← Phase 3
│   └── 4_huggingface_nlp_threat_intelligence.ipynb  ← Phase 4
│
├── src/
│   ├── models/          ← trained model files (.pkl)
│   ├── results/         ← charts, confusion matrices
│   └── preprocessing/
│
└── aegis-api/           ← Spring Boot REST API
    └── src/main/java/com/aegis/api/
        ├── controller/AegisController.java
        ├── service/ThreatDetectionService.java
        ├── model/NetworkFlow.java
        ├── model/PredictionResult.java
        └── resources/predict.py    ← Java-Python bridge
```

---

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/predict` | Classify a network flow |
| GET | `/api/history` | Get last N predictions |
| GET | `/api/stats` | Threat distribution stats |
| DELETE | `/api/history` | Clear prediction history |
| GET | `/api/health` | System health check |

### Sample Request

```json
POST /api/predict
{
  "duration": 0,
  "protocolType": "tcp",
  "service": "http",
  "flag": "SF",
  "srcBytes": 232,
  "dstBytes": 8153
}
```

### Sample Response — Normal Traffic

```json
{
  "threat_class": "Normal",
  "severity": "NONE",
  "confidence": 0.998633,
  "probabilities": {
    "DoS": 0.000228,
    "Normal": 0.998633,
    "Probe": 0.000676,
    "R2L": 0.000277,
    "U2R": 0.000186
  },
  "message": "No threat detected."
}
```

### Sample Response — Real DoS Attack

```json
{
  "threat_class": "DoS",
  "severity": "HIGH",
  "confidence": 0.999822,
  "probabilities": {
    "DoS": 0.999822,
    "Normal": 0.000150,
    "Probe": 0.000008,
    "R2L": 0.000012,
    "U2R": 0.000008
  },
  "message": "Threat detected: DoS (100.0%). Immediate review recommended."
}
```

---

## Roadmap

- [x] Phase 1 — Feature Engineering & Schema Normalization
- [x] Phase 2 — Stacking Ensemble (96% accuracy, 0.98 ROC-AUC)
- [x] Phase 3 — WGAN-GP Synthetic Attack Generation
- [x] Phase 4 — HuggingFace NLP Threat Intelligence
- [x] Spring Boot REST API — 5 endpoints, Java-Python bridge
- [ ] Phase 5 — Attack Attribution (source IP, geolocation, threat actor mapping)
- [ ] Phase 6 — LLM Agent (automated response recommendations)
- [ ] Phase 7 — Real-time React Dashboard
-  [x] Docker — multi-stage build, deployed on Render

---

## About

Built by **Prerak Nain** — final year CS undergrad at Bennett University.

[![Portfolio](https://img.shields.io/badge/Portfolio-prerak1603.github.io-d4af6a?style=flat-square)](https://prerak1603.github.io)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-prerak--nain-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/prerak-nain-5a19a6362/)
[![GitHub](https://img.shields.io/badge/GitHub-prerak1603-181717?style=flat-square&logo=github)](https://github.com/prerak1603)
