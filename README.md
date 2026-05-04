# 🛡️ AegisAI — Flow-Based Network Anomaly Detection

A **dataset-agnostic AI-based Intrusion Detection System (IDS)** combining classical machine learning, generative AI, and transformer-based NLP for comprehensive threat detection across heterogeneous network telemetry.

---

## 🎯 Overview

AegisAI tackles the limitations of traditional IDS solutions through four integrated phases:

- **Universal schema adaptation** — works across Zeek, NSL-KDD, CIC-IDS-2017
- **Hierarchical sliding-window analysis** — captures bursty, distributed, and low-and-slow attack patterns (10s – 60min)
- **Multi-model ensemble classification** — Random Forest + XGBoost + LightGBM with stacking
- **Generative AI augmentation** — WGAN-GP synthesizes rare attack samples to fix class imbalance
- **NLP threat intelligence** — DistilBERT and Sentence-Transformers extend detection to unstructured threat text

---

## 🚀 Project Phases

### ✅ Phase 1 — Feature Engineering Engine
- Universal Schema Adapter for heterogeneous telemetry (Zeek, NSL-KDD, CIC-IDS)
- Dual-Lens analysis: Macro (60s windows) + Micro (10s bursts)
- Stealth Detector module for low-and-slow APT patterns
- Hierarchical sliding-window feature aggregation

### ✅ Phase 2 — Multi-Model Stacked Ensemble
- **Base learners:** Random Forest, XGBoost, LightGBM
- **Meta-learner:** Logistic Regression with 5-fold cross-validation
- **Test accuracy: 99.5%** with strong rare-class recall
  - DoS: 99.99% • Normal: 99.96% • Probe: 99.61%
  - **R2L: 99%** • **U2R: 90%**
- Cross-model feature importance validation

### ✅ Phase 3 — GAN-Based Synthetic Attack Generation
- **WGAN-GP** (Wasserstein GAN with Gradient Penalty) for stable training
- Generates synthetic samples of rare attack classes (R2L, U2R)
- Augmented training data improves minority-class recall in the Phase 2 ensemble
- PCA visualization confirms synthetic samples align with real distribution

### ✅ Phase 4 — NLP Threat Intelligence with Hugging Face
- **DistilBERT fine-tuning** for 5-class threat categorization (DoS / Probe / R2L / U2R / APT)
- **Zero-shot classification** with `facebook/bart-large-mnli`
- **Semantic similarity search** using Sentence-Transformers (SBERT)
- CVE / IP / port / protocol entity extraction for structured threat intelligence

---

## 🛠️ Tech Stack

**Machine Learning & Deep Learning:**
Python · PyTorch · TensorFlow · scikit-learn · XGBoost · LightGBM

**Generative AI & NLP:**
Hugging Face Transformers · Sentence-Transformers · DistilBERT · BART-MNLI · LangChain

**Data Processing:**
Pandas · NumPy · Zeek · NSL-KDD · CIC-IDS-2017

**Visualization & Tools:**
Matplotlib · Seaborn · Jupyter · Git · GitHub

---

## 📁 Repository Structure

```
cic_ids_project/
├── notebooks/
│   ├── 2b_ensemble_classifier.ipynb              # Phase 2: stacked ensemble
│   ├── 3_gan_synthetic_attack_generation.ipynb   # Phase 3: WGAN-GP
│   └── 4_huggingface_nlp_threat_intelligence.ipynb  # Phase 4: NLP pipeline
├── src/
│   ├── models/                                   # Trained classifiers
│   │   ├── train_baseline.py                     # Random Forest baseline
│   │   ├── phase2_stacking_ensemble.pkl          # Stacked ensemble
│   │   ├── phase2_feature_scaler.pkl
│   │   └── phase2_label_encoder.pkl
│   ├── results/                                  # Charts & reports
│   │   ├── ensemble_comparison.png
│   │   ├── stacking_confusion_matrix.png
│   │   ├── feature_importance_ensemble.png
│   │   ├── gan_training_curves.png
│   │   ├── gan_pca_comparison.png
│   │   ├── gan_augmented_confusion_matrix.png
│   │   └── threat_similarity_matrix.png
│   └── preprocessing/
├── csv_files/                                    # NSL-KDD dataset
├── pcap_files/                                   # Raw packet captures
└── tools/
```

---

## 📊 Key Results

| Model | Test Accuracy | Macro-F1 |
|---|---|---|
| Random Forest (baseline) | 94.18% | 0.62 |
| XGBoost | 95.40% | 0.71 |
| LightGBM | 95.10% | 0.70 |
| Voting Ensemble | 95.80% | 0.73 |
| **Stacking Ensemble (final)** | **99.50%** | **0.92** |

**GAN-Augmented Ensemble** further improves rare-class recall on R2L and U2R — full results in `src/results/`.

---

## ⚙️ Setup & Run

```bash
# Clone the repo
git clone https://github.com/prerak1603/flow-based-anomaly-detection.git
cd flow-based-anomaly-detection

# Install dependencies
pip install scikit-learn xgboost lightgbm torch transformers sentence-transformers pandas numpy matplotlib seaborn

# Run notebooks in order
jupyter notebook notebooks/2b_ensemble_classifier.ipynb
jupyter notebook notebooks/3_gan_synthetic_attack_generation.ipynb
jupyter notebook notebooks/4_huggingface_nlp_threat_intelligence.ipynb
```

---

## 👤 Author

**Prerak Nain**
B.Tech Computer Science · Bennett University, Greater Noida
GitHub: [@prerak1603](https://github.com/prerak1603)