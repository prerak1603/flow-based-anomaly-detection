# 🛡️ Aegis AI — Network Intrusion Detection Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-FastAPI-blue?style=for-the-badge&logo=python)
![XGBoost](https://img.shields.io/badge/Ensemble-RF_XGB_LGB-orange?style=for-the-badge)
![LangGraph](https://img.shields.io/badge/Agent-LangGraph-purple?style=for-the-badge)
![Docker](https://img.shields.io/badge/Docker-Deployed-2496ED?style=for-the-badge&logo=docker)
![Status](https://img.shields.io/badge/Status-LIVE-brightgreen?style=for-the-badge)

**A production-grade network security platform: an ML ensemble that detects attacks, a sliding-window module that attributes them, a RAG knowledge base that grounds explanations, and a LangGraph agent that reasons about severity and response — all wired into a live API and dashboard.**

[Live Dashboard](#live-deployments) · [Architecture](#architecture) · [Results](#results) · [Setup](#setup)

</div>

---

## What Is Aegis AI?

Most network intrusion detection projects stop at "trained a model, got X% accuracy." Aegis AI goes further — from raw network flow data all the way to a deployed system that classifies traffic, attributes attacks to their source, retrieves relevant context, and generates a structured WHAT / WHERE / HOW / WHY / RECOMMENDATION report.

Upload a network log. It tells you:
- Is this an attack, and what type — DDoS, PortScan, brute force, Heartbleed, and 9 more classes?
- Where did it come from — source IP when available, or the targeted service/port when it isn't?
- What behavioral pattern gave it away — automated timing, failed-connection ratio, port diversity?
- Why does it matter — grounded in a knowledge base of attack intent and historical model performance?
- What should happen next — a rule-based, auditable recommendation (not an LLM free-deciding to block an IP).

---

## Live Deployments

| Component | URL |
|---|---|
| **Landing Page** | [prerak1603.github.io/flow-based-anomaly-detection](https://prerak1603.github.io/flow-based-anomaly-detection/) |
| **Dashboard** | [flow-based-anomaly-detection.streamlit.app](https://flow-based-anomaly-detection-hqnj5ccn9xcz4ojug47sen.streamlit.app) |
| **API** | [aegis-ai-v2.onrender.com](https://aegis-ai-v2.onrender.com) |

```bash
# Health check
curl https://aegis-ai-v2.onrender.com/health

# Analyze a network log — auto-detects format, runs full pipeline
curl -X POST https://aegis-ai-v2.onrender.com/analyze \
  -F "file=@network_flows.csv"
```

> Free-tier hosting sleeps after inactivity — first request after idle time may take 30-50s to wake up.

---

## Results

| Metric | v2.0.0 (baseline) | v2.3.0 (current) |
|---|---|---|
| Macro F1-Score | 90.69% | **98.43%** |
| Overall Accuracy | 99.87% | **99.88%** |
| Heartbleed Recall | 0% | **100%** |
| LightGBM Training Accuracy | 52% | **99.96%** |
| Confidence Calibration Gap | 32.7pp | **0.6pp** |

Each improvement is a real, verified fix — SMOTE + WGAN-GP for the Heartbleed rare-class failure, 30-trial Optuna tuning for the LightGBM misconfiguration, Platt Scaling for confidence calibration.

- **Training data:** 2.8M+ real network flows (CIC-IDS-2017)
- **Attack classes:** 13 (DDoS, DoS Hulk/GoldenEye/slowloris/Slowhttptest, PortScan, FTP/SSH-Patator, Web Attack, Bot, Infiltration, Heartbleed, BENIGN)

---

## Architecture

```
CLIENT UPLOADS RAW NETWORK LOG (CICFlowMeter CSV / Zeek conn.log)
                    │
                    ▼
┌───────────────────────────────────────────────────┐
│  UNIVERSAL PARSER                                   │
│  Auto-detects format, extracts 78 features           │
└─────────────────┬─────────────────────────────────┘
                   │
       ┌───────────┴────────────┐
       ▼                        ▼
┌─────────────────┐   ┌──────────────────────────┐
│  ENSEMBLE MODEL   │   │  SLIDING-WINDOW           │
│  RF + XGB + LGB    │   │  ATTRIBUTION               │
│  → Meta-learner    │   │  Adaptive: full host-      │
│  "DDoS, 94%"       │   │  centric (IP available) or │
│                    │   │  degraded port-level       │
└─────────┬─────────┘   └────────────┬───────────────┘
          │                          │
          └────────────┬─────────────┘
                        ▼
        ┌───────────────────────────────┐
        │  LANGGRAPH AGENT                │
        │                                 │
        │  retrieve_context (RAG)          │
        │        ↓                        │
        │  assess_severity (rule-based)    │
        │        ↓                        │
        │  [HIGH/CRITICAL?] → enrich       │
        │        ↓                        │
        │  generate_narrative (LLM)        │
        │        ↓                        │
        │  determine_recommendation        │
        │  (rule-based action + LLM        │
        │   justification)                 │
        │        ↓                        │
        │  compile_report                  │
        └───────────────┬─────────────────┘
                        ▼
        WHAT / WHERE / HOW / WHY / RECOMMENDATION
```

**Design principle:** the LLM explains, it doesn't decide. Severity assessment and recommended actions are deterministic rule-based logic — auditable and predictable. The LLM (Claude Haiku) only writes the narrative explanation and a one-sentence justification, grounded in RAG-retrieved context.

Full agent analysis is capped to the top 8 highest-confidence detections per upload, keeping cost and latency predictable regardless of file size.

---

## The Attribution Problem

CIC-IDS-2017, like most published security benchmarks, strips source/destination IP columns before public release (standard anonymization practice). This means:

- **Zeek conn.log or an unmodified CICFlowMeter export** (real client traffic) → full host-centric attribution: source IP, connection timing regularity, failed-connection ratio, port-scan signature.
- **CIC-IDS-2017 style CSVs** (the public benchmark) → degraded to port-level attribution: destination port and likely targeted service, honestly disclosed as limited.

The system detects which mode applies automatically and never fabricates attribution data that isn't in the source file.

---

## Tech Stack

**ML Pipeline**
- scikit-learn, XGBoost, LightGBM (stacking ensemble)
- imbalanced-learn (SMOTE), PyTorch (WGAN-GP)
- Optuna (Bayesian hyperparameter tuning)

**Agent / RAG**
- LangGraph (multi-node agent orchestration)
- LangChain + Chroma (vector store)
- sentence-transformers (local embeddings)
- Anthropic Claude Haiku (narrative generation)

**Backend / Deployment**
- FastAPI, Uvicorn, Docker
- Render (API hosting)

**Frontend**
- Streamlit (client-facing dashboard, PDF report generation via ReportLab)
- GSAP + vanilla JS (animated landing page)
- GitHub Pages (landing page hosting)

---

## Project Structure

```
cic_ids_project/
├── v1/                          ← original NSL-KDD / Java Spring Boot iteration
│
├── v2/
│   ├── api/
│   │   ├── app/
│   │   │   ├── main.py           ← FastAPI app, /predict + /analyze
│   │   │   ├── inference.py       ← ensemble model wrapper
│   │   │   ├── parsers/           ← universal format detection
│   │   │   └── context/
│   │   │       ├── sliding_window.py  ← multi-scale window feature extraction
│   │   │       ├── attribution.py     ← adaptive IP/port attribution
│   │   │       ├── rag.py             ← knowledge base + retrieval
│   │   │       └── agent.py           ← LangGraph agent
│   │   ├── new_models/            ← trained ensemble (.pkl)
│   │   ├── results/                ← RAG source documents
│   │   └── Dockerfile
│   │
│   ├── dashboard/
│   │   └── aegis_dashboard.py     ← Streamlit client dashboard
│   │
│   ├── notebooks/                 ← training pipeline (01-13, SMOTE → Platt Scaling)
│   └── results/                    ← evaluation reports, attack reference doc
│
└── docs/
    └── index.html                 ← animated landing page (GitHub Pages)
```

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| GET | `/health` | System + model health check |
| POST | `/predict` | Classify a single 78-feature vector |
| POST | `/analyze` | Upload a log file — full pipeline: parse → classify → attribute → agent analysis |

### Sample `/analyze` Response (abridged)

```json
{
  "total_flows_analyzed": 50,
  "total_attacks_detected": 50,
  "attack_breakdown": {"DDoS": 50},
  "ai_analysis": {
    "flows_analyzed": 8,
    "flows_available": 50,
    "reports": [
      {
        "row": 36,
        "report": {
          "classification": {"attack_type": "DDoS", "confidence": 0.9998},
          "severity": {
            "level": "CRITICAL",
            "reasons": [
              "High model confidence (100.0%)",
              "Behavioral corroboration: automated timing pattern (CV < 0.1)",
              "Behavioral corroboration: >90% failed connections"
            ]
          },
          "attribution": {"mode": "full", "host_ip": "203.0.113.45"},
          "recommendation": {
            "recommended_action": "BLOCK source immediately + escalate to security team",
            "ip_action": "Block 203.0.113.45 at firewall/WAF level"
          }
        }
      }
    ]
  }
}
```

---

## Roadmap

- [x] Stacking ensemble (RF + XGBoost + LightGBM + meta-learner)
- [x] SMOTE + WGAN-GP for rare-class recall
- [x] Optuna hyperparameter tuning
- [x] Platt Scaling confidence calibration
- [x] FastAPI backend, Dockerized, deployed live
- [x] Universal log parser (CICFlowMeter + Zeek auto-detection)
- [x] End-to-end file upload → prediction pipeline
- [x] Streamlit client dashboard with PDF report generation
- [x] Animated landing page, deployed to GitHub Pages
- [x] Sliding-window host-centric attribution (adaptive full-IP / degraded-port)
- [x] RAG knowledge base (13-class attack reference + evaluation reports)
- [x] LangGraph agent — severity assessment, narrative generation, recommendations
- [ ] Live threat-intel IP reputation lookup (AbuseIPDB / AlienVault OTX)
- [ ] Rate limiting + API authentication (required before real client onboarding)
- [ ] Automated test suite + CI/CD

---

## About

Built by **Prerak Nain** — B.Tech CS, Bennett University (graduating May 2027).

[![Portfolio](https://img.shields.io/badge/Portfolio-prerak1603.github.io-d4af6a?style=flat-square)](https://prerak1603.github.io)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-prerak--nain-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/prerak-nain-5a19a6362/)
[![GitHub](https://img.shields.io/badge/GitHub-prerak1603-181717?style=flat-square&logo=github)](https://github.com/prerak1603)