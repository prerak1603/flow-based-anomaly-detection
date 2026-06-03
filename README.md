# Aegis AI — Network Intrusion Detection System 🛡️

A production-grade, 5-phase AI security platform that detects network intrusions using ensemble machine learning and exposes predictions via a Java Spring Boot REST API.

![Python](https://img.shields.io/badge/Python-3.10-blue) ![Java](https://img.shields.io/badge/Java-Spring%20Boot-green) ![Accuracy](https://img.shields.io/badge/Accuracy-96%25-brightgreen) ![ROC--AUC](https://img.shields.io/badge/ROC--AUC-0.98-brightgreen)

---

## 🎯 What It Does

Traditional IDS rely on static signatures that miss stealthy, low-and-slow attacks. Aegis AI solves this by:
- Training a stacking ensemble on 125,000+ real network flow records (NSL-KDD)
- Generating synthetic attack traffic with GANs to handle extreme class imbalance
- Classifying threat intelligence from text using NLP
- Serving real-time predictions via a Spring Boot REST API with severity classification

---

## 📊 Final Model Performance

| Metric | Score |
|--------|-------|
| Accuracy | **96%** |
| Macro ROC-AUC | **0.98** |
| Training Records | 125,000+ (NSL-KDD) |
| Attack Classes | DoS, Probe, R2L, U2R, Normal |

---

## 🏗️ Architecture — 5 Phases

### ✅ Phase 1 — Feature Engineering Engine
- Universal schema adapter for Zeek, CIC-IDS, NSL-KDD formats
- Dual-Lens architecture: Macro-Lens (global traffic) + Micro-Lens (per-IP behaviour)
- Sliding window feature builder for temporal patterns

### ✅ Phase 2 — Supervised Baseline
- Random Forest baseline: 94.18% accuracy
- Identified class imbalance (47,000:5 ratio for rare attacks) as critical bottleneck

### ✅ Phase 3 — Synthetic Data Generation (WGAN-GP)
- Wasserstein GAN with Gradient Penalty to synthesise rare attack traffic
- Resolved extreme class imbalance enabling rare-class (R2L/U2R) detection

### ✅ Phase 4 — NLP Threat Intelligence Pipeline
- HuggingFace DistilBERT fine-tuned for threat intelligence text classification
- Classifies CVE descriptions and security reports into attack categories

### ✅ Phase 5 — Java Spring Boot REST API
- Spring Boot backend exposing 5 REST endpoints
- Thread-safe prediction store using `ConcurrentLinkedDeque`
- Java ↔ Python integration via `ProcessBuilder` calling trained `joblib` ensemble
- 4-level severity output: `NONE / MEDIUM / HIGH / CRITICAL`

---

## 🔌 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/predict` | Submit network flow, get threat prediction |
| `GET` | `/api/history` | Retrieve last 100 predictions |
| `GET` | `/api/stats` | Aggregated stats by severity class |
| `DELETE` | `/api/history` | Clear prediction history |
| `GET` | `/api/health` | Service health check |

---

## 🧠 ML Pipeline Details

**Model:** Stacking Ensemble
- Base learners: Random Forest + XGBoost + LightGBM
- Meta-learner: Logistic Regression
- Hyperparameter tuning: 90-trial Optuna search
- Validation: 5-fold stratified cross-validation (SMOTE inside each fold to prevent data leakage)
- Calibration: Platt scaling + per-class threshold optimisation

---

## 📂 Project Structure

```
flow-based-anomaly-detection/
├── notebooks/          # Phase 1-2: Feature engineering & baseline
├── src/
│   ├── models/         # Ensemble training scripts
│   ├── gan/            # WGAN-GP synthetic data generation
│   ├── nlp/            # DistilBERT threat intelligence pipeline
│   └── results/        # Performance reports & confusion matrices
├── aegis-api/          # Java Spring Boot REST API
│   └── src/main/java/
│       ├── controller/
│       ├── service/
│       └── model/
└── README.md
```

---

## ▶️ Running the ML Pipeline

```bash
pip install -r requirements.txt
python3 notebooks/1_prepare_nslkdd.py
python3 src/models/train_ensemble.py
cat src/results/ensemble_report.txt
```

## ▶️ Running the Spring Boot API

```bash
cd aegis-api
mvn spring-boot:run
# API at http://localhost:8080
```

**Sample request:**
```json
POST /api/predict
{
  "duration": 0,
  "protocol_type": "tcp",
  "service": "http",
  "src_bytes": 232,
  "dst_bytes": 8153
}
```

---

## 🛠️ Tech Stack

| Layer | Technology |
|-------|-----------|
| ML Pipeline | Python, XGBoost, LightGBM, Scikit-learn, PyTorch |
| Data Augmentation | WGAN-GP (PyTorch) |
| NLP | HuggingFace Transformers, DistilBERT |
| Hyperparameter Tuning | Optuna |
| REST API | Java 17, Spring Boot, Maven |

---

## 👤 Author

**Prerak Nain** — B.Tech CS, Bennett University (2023–2027)  
[LinkedIn](https://linkedin.com/in/preraknain) · [GitHub](https://github.com/prerak1603)