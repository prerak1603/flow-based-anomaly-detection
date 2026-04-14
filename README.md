# Aegis AI: Flow-Based Network Anomaly Detection 🛡️

Aegis AI is a machine learning-based cybersecurity pipeline designed to detect both loud, volumetric network attacks (like DDoS and Port Scans) and stealthy, low-and-slow Advanced Persistent Threats (APTs).

## 🚀 Project Overview
Traditional Intrusion Detection Systems (IDS) often rely on static signatures, which fails to catch data exfiltration hidden in background noise. Aegis AI solves this by utilizing a **Dual-Lens Architecture**, processing raw network logs into dynamic mathematical baselines.

---

## ✅ Phase 1: Feature Engineering Engine (Completed)
The current pipeline successfully ingests raw network traffic and engineers highly contextual features.
- **Universal Schema Adapter:** Automatically detects and normalizes data from diverse sensors (Zeek, CIC-IDS, NSL-KDD).
- **Stealth Detector:** Calculates the *Anomaly Differential* to expose beacons hiding in heavy background traffic.
- **Dual-Lens Logic:** - *Macro-Lens:* Tracks global traffic states (bytes, port diversity).
  - *Micro-Lens:* Profiles individual Source IP behavior (IAT, fan-out volume).

---

## ⚖️ Phase 2: Supervised Baseline & Evaluation (Current)
We have implemented a supervised **Random Forest** baseline to validate the engineered features.

- **Current Accuracy:** 94.18%
- **Top Feature:** `orig_bytes` (contributing 57.7% to the decision logic).
- **Key Finding:** The model perfectly identifies volumetric DoS (Neptune) but highlights a critical need for synthetic oversampling (GANs) for rare attack classes like R2L/U2R.

### 📊 Performance Artifacts
Check `src/results/` for the latest visual evidence:
- **Feature Importance:** Visualizing the "Macro-Lens" decision weights.
- **Confusion Matrix:** Map of successful detections vs. false negatives.

---

## 📂 Project Structure
- `/notebooks/` - Research scripts for sliding window analysis and data prep.
- `/src/models/` - Production-ready training scripts (Random Forest).
- `/src/results/` - Model performance reports and visualization exports.
- `/data/` - (Local only) Raw and processed datasets (NSL-KDD).

---

## ▶️ Running the Pipeline
1. **Prepare Data:** `python3 notebooks/1_prepare_nslkdd.py`
2. **Train Baseline:** `python3 src/models/train_baseline.py`
3. **View Results:** Check `src/results/baseline_model_report.txt`

---

## 🚧 Phase 3: The Roadmap
- **Generative Adversarial Networks (GANs):** Implementing a generator to synthesize rare attack samples for improved minority class recall.
- **Behavioral Bridging:** Connecting the Phase 1 Sliding-Window builder with the Phase 2 classifier for real-time inference.