# 🛡️ Aegis AI — Network Intrusion Detection Platform

<div align="center">

![Python](https://img.shields.io/badge/Python-FastAPI-blue?style=for-the-badge&logo=python)
![Next.js](https://img.shields.io/badge/Frontend-Next.js_16-black?style=for-the-badge&logo=next.js)
![XGBoost](https://img.shields.io/badge/Ensemble-RF_XGB_LGB-orange?style=for-the-badge)
![LangGraph](https://img.shields.io/badge/Agent-LangGraph-purple?style=for-the-badge)
![Postgres](https://img.shields.io/badge/DB-Neon_Postgres-00E599?style=for-the-badge&logo=postgresql&logoColor=black)
![Status](https://img.shields.io/badge/Status-LIVE-brightgreen?style=for-the-badge)

**A production-grade, multi-tenant network security platform: an ML ensemble that detects attacks, a sliding-window module that attributes them, a RAG knowledge base that grounds explanations, and a LangGraph agent that reasons about severity and response — all behind per-customer API keys, wired into a live Next.js frontend and FastAPI backend.**

[Live App](#live-deployments) · [Architecture](#architecture) · [Results](#results) · [Setup](#setup)

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

| Component | Platform | URL |
|---|---|---|
| **Frontend** (landing page + `/audit` + `/history`) | Vercel | [aegis-ai-frontend-tau.vercel.app](https://aegis-ai-frontend-tau.vercel.app) |
| **API** | Render | [aegis-ai-v2.onrender.com](https://aegis-ai-v2.onrender.com) |
| **Database** | Neon (Postgres) | — |

Sign-up is handled by Clerk on the frontend; a webhook auto-provisions a real backend `Customer` + API key the moment someone signs up, so every user gets their own isolated account (see [Architecture](#architecture)).

```bash
# Health check
curl https://aegis-ai-v2.onrender.com/health

# Analyze a network log — auto-detects format, runs full pipeline (requires an API key)
curl -X POST https://aegis-ai-v2.onrender.com/analyze \
  -H "X-API-Key: aegis_xxxxxxxxxxxx" \
  -F "file=@network_flows.csv"
```

> Free-tier hosting sleeps after inactivity — first request after idle time may take 30-50s to wake up.

> **Superseded:** the original GitHub Pages landing page and Streamlit dashboard have been replaced by the Next.js frontend above (full feature parity reached, including PDF export and upload history) and are no longer maintained.

> **Note:** Clerk is currently running in test/dev mode on the live deployment, not production keys — fine for demos, but flag it before treating this as fully production-ready for real signups.

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
BROWSER
   │
   │  signs in via Clerk
   ▼
┌────────────────────────────────────────────────────────────┐
│  NEXT.JS FRONTEND (Vercel)                                    │
│  Landing page · /audit (upload + live results) · /history     │
│                                                                │
│  Server-side route handlers (/api/analyze, /api/health)       │
│  look up the signed-in user's Aegis API key server-side        │
│  (Clerk private metadata) and forward it to the backend —       │
│  the browser never sees it, and CORS never comes into play.    │
└──────────────────────────┬────────────────────────────────────┘
                            │  X-API-Key: aegis_xxxxx
                            ▼
┌────────────────────────────────────────────────────────────┐
│  FASTAPI BACKEND (Render)                                      │
│  Auth (per-customer API key) → rate limiting → CORS lockdown   │
└──────────────────────────┬────────────────────────────────────┘
                            │
       ┌────────────────────┴────────────────────┐
       │  RAW NETWORK LOG (CICFlowMeter CSV / Zeek conn.log)
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
                        │
                        ▼
        ┌───────────────────────────────┐
        │  NEON POSTGRES                  │
        │  Customer / Upload / Detection   │
        │  — every row scoped to           │
        │    customer_id (tenant isolation) │
        └───────────────────────────────┘
```

**Design principle:** the LLM explains, it doesn't decide. Severity assessment and recommended actions are deterministic rule-based logic — auditable and predictable. The LLM (Claude Haiku) only writes the narrative explanation and a one-sentence justification, grounded in RAG-retrieved context.

Full agent analysis is capped to the top 8 highest-confidence detections per upload, keeping cost and latency predictable regardless of file size.

**Multi-tenancy:** every signup on the frontend fires a Clerk `user.created` webhook (`/webhooks/clerk`, signature-verified via Svix) that provisions a real `Customer` row and a unique API key, written back into Clerk's private user metadata. Every table downstream (`Upload`, `Detection`) carries a `customer_id`, and every query filters on it — so one tenant can never read another's data, on shared infrastructure, by construction rather than convention.

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
- SQLAlchemy ORM over Neon (managed Postgres) — SQLite fallback for local dev
- Per-customer API key auth, `slowapi` rate limiting, locked-down CORS, structured logging
- Svix (webhook signature verification)
- Render (API hosting)

**Frontend**
- Next.js 16 (App Router, TypeScript) on Vercel
- Clerk (auth, sign-up/sign-in, backs the per-customer provisioning webhook)
- Tailwind CSS v4, Framer Motion (animation), Recharts (attack breakdown chart)
- React Three Fiber + drei (3D flow visualization on the landing page)
- jsPDF (client-side PDF report export)

**Retired**
- Streamlit dashboard and the GitHub Pages landing page — both superseded by the Next.js frontend above once it reached feature parity (PDF export, upload history).

---

## Project Structure

This backend/ML repo (`cic_ids_project`) and the frontend live in separate repos.

```
cic_ids_project/                  (this repo — backend + ML)
├── v1/                          ← original NSL-KDD / Java Spring Boot iteration
│
├── v2/
│   ├── api/
│   │   ├── app/
│   │   │   ├── main.py           ← FastAPI app: /predict, /analyze, /history/*, rate limiting, CORS
│   │   │   ├── auth.py            ← per-customer API key auth (get_current_customer dependency)
│   │   │   ├── db.py              ← SQLAlchemy models (Customer/Upload/Detection), Neon/SQLite engine
│   │   │   ├── webhooks.py        ← Clerk user.created webhook → provisions Customer + API key
│   │   │   ├── config.py          ← model paths, upload size/row limits
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
│   │   └── aegis_dashboard.py     ← Streamlit dashboard (retired, superseded by aegis-frontend)
│   │
│   ├── notebooks/                 ← training pipeline (01-13, SMOTE → Platt Scaling)
│   └── results/                    ← evaluation reports, attack reference doc
│
└── docs/
    └── index.html                 ← original animated landing page (GitHub Pages, retired)

aegis-frontend/                   (separate repo — deployed to Vercel)
├── app/
│   ├── page.tsx                   ← landing page (3D flow viz, pipeline explainer, model stats)
│   ├── audit/page.tsx             ← upload → live analysis → threat cards (Clerk-protected)
│   ├── history/page.tsx           ← past uploads/detections (Clerk-protected)
│   ├── sign-in/, sign-up/         ← Clerk auth pages
│   └── api/
│       ├── analyze/route.ts       ← server-side proxy to Render /analyze, attaches API key
│       ├── health/route.ts        ← server-side proxy to Render /health
│       └── history/               ← server-side proxy to Render /history/*
├── components/                    ← Hero3D, UploadZone, ThreatCard, AttackChart, MetricCard, Nav
├── lib/
│   ├── getUserApiKey.ts           ← resolves the signed-in user's Aegis API key via Clerk metadata
│   └── generatePdf.ts             ← client-side PDF report export (jsPDF)
└── middleware.ts                  ← Clerk route protection for /audit and /history
```

---

## API Endpoints

All endpoints except `/health` require an `X-API-Key` header (a customer's Aegis API key) and are rate-limited.

| Method | Endpoint | Auth | Rate limit | Description |
|---|---|---|---|---|
| GET | `/health` | none | none | System + model health check |
| POST | `/predict` | API key | 30/min | Classify a single 78-feature vector |
| POST | `/analyze` | API key | 5/min | Upload a log file — full pipeline: parse → classify → attribute → agent analysis → persisted to Postgres |
| GET | `/history/uploads` | API key | 60/min | List the authenticated customer's past uploads |
| GET | `/history/detections` | API key | 60/min | List the authenticated customer's past detections (optionally filtered by `upload_id`) |
| POST | `/webhooks/clerk` | Svix signature | — | Clerk `user.created` webhook — provisions a `Customer` + API key on signup |

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
- [x] Sliding-window host-centric attribution (adaptive full-IP / degraded-port)
- [x] RAG knowledge base (13-class attack reference + evaluation reports)
- [x] LangGraph agent — severity assessment, narrative generation, recommendations
- [x] Rate limiting + per-customer API key authentication
- [x] Multi-tenant Postgres persistence (Neon), locked-down CORS, structured logging
- [x] Clerk-based sign-up with automatic backend account provisioning (webhook)
- [x] Next.js frontend on Vercel (landing page, live audit, history) — replaces the Streamlit dashboard and GitHub Pages landing page
- [x] Client-side PDF report export
- [ ] Switch Clerk from test/dev keys to production keys
- [ ] Live threat-intel IP reputation lookup (AbuseIPDB / AlienVault OTX)
- [ ] Automated test suite + CI/CD

---

## About

Built by **Prerak Nain** — B.Tech CS, Bennett University (graduating May 2027).

[![Portfolio](https://img.shields.io/badge/Portfolio-prerak1603.github.io-d4af6a?style=flat-square)](https://prerak1603.github.io)
[![LinkedIn](https://img.shields.io/badge/LinkedIn-prerak--nain-0077B5?style=flat-square&logo=linkedin)](https://www.linkedin.com/in/prerak-nain-5a19a6362/)
[![GitHub](https://img.shields.io/badge/GitHub-prerak1603-181717?style=flat-square&logo=github)](https://github.com/prerak1603)