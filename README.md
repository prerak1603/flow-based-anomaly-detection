# Network Anomaly Detection Project
# Aegis AI: Flow-Based Network Anomaly Detection 🛡️

Aegis AI is a machine learning-based cybersecurity pipeline designed to detect both loud, volumetric network attacks (like DDoS and Port Scans) and stealthy, low-and-slow Advanced Persistent Threats (APTs).

## 🚀 Project Overview
Traditional Intrusion Detection Systems (IDS) often rely on static signatures or purely volumetric aggregation, which fails to catch data exfiltration hidden in background noise. Aegis AI solves this by utilizing a **Dual-Lens Sliding Window Architecture**, processing raw network logs into dynamic mathematical baselines.

## 🛠️ Phase 1: Feature Engineering Engine (Completed)
The current pipeline successfully ingests raw network traffic and engineers highly contextual time-series features.

### Core Capabilities:
* **Universal Schema Adapter:** Automatically detects and normalizes data from diverse sensors (Zeek `.log`, CIC-IDS `.csv`, NetFlow).
* **Timestamp Standardization:** Converts disparate time formats (Unix epoch floats, formatted strings) into standard continuous Pandas datetime objects for exact Inter-Arrival Time (IAT) calculations.

* **Dual-Lens Architecture:** * **Macro-Lens (Network-Centric):** Aggregates global traffic state (total bytes, active connections, port diversity) to catch massive anomalies like DDoS.
  * **Micro-Lens (Host-Centric):** Simultaneously profiles every individual Source IP (calculating host-specific IAT, fan-out, and byte volume).
* **The Stealth Detector:** Calculates the *Anomaly Differential* (the ratio of a single host's traffic against the global network volume) to expose stealth beacons hiding in heavy network traffic.

## 📂 Project Structure
* `/csv_files/` - Cleaned dataset inputs (CIC-IDS, NSL-KDD, etc.)
* `/pcap_files/` - Raw packet captures (e.g., Friday-WorkingHours.pcap)
* `/zeek_output/` - Parsed Zeek logs (conn.log, dns.log, etc.)
* `/notebooks/sliding_window_features.py` - The core Phase 1 feature extraction engine.
* `/notebooks/1_prepare_nslkdd.py` - Converts NSL-KDD into the universal conn.log-style schema.
* `/notebooks/2_train_baseline_ids.py` - Trains a baseline Isolation Forest on engineered windows and saves reports/artifacts.

## ▶️ Current Run Path
1. Prepare the NSL-KDD training file:
   `python3 notebooks/1_prepare_nslkdd.py`
2. Train the baseline IDS model:
   `python3 notebooks/2_train_baseline_ids.py`

Artifacts are saved to:
* `/data/models/baseline_isolation_forest.joblib`
* `/data/reports/baseline_metrics.json`
* `/data/reports/baseline_window_predictions.csv`

By default, the training step uses network-centric windows at `1min`, `5min`, and `15min` scales for a practical baseline runtime. You can opt into heavier runs by setting:
* `AEGIS_WINDOW_SIZES=10s,1min,5min,15min,1hr`
* `AEGIS_ANALYSIS_TYPES=network,host`

## 🚧 Next Steps
* Improve window labeling so mixed windows preserve attack evidence instead of only taking the mode label.
* Train supervised classifiers alongside anomaly detection for better recall on labeled datasets like NSL-KDD.
* Revisit host-centric training after optimizing the sliding-window builder for per-host performance.
