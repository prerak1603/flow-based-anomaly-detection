"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 09_evaluate_augmented.py
Description : Evaluate augmented model on SAME held-out test set,
              compare against original model
Author      : Prerak Nain
================================================================================
"""

import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from sklearn.metrics import precision_recall_fscore_support, accuracy_score

warnings.filterwarnings('ignore')


class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    RESULTS_DIR  = PROJECT_ROOT / "v2" / "results"
    
    TEST_FILE = RESULTS_DIR / "test_data.parquet"  # SAME test set, untouched
    
    ORIGINAL_MODEL  = PROJECT_ROOT / "v2" / "api" / "new_models" / "aegis_v2_ensemble.pkl"
    AUGMENTED_MODEL = PROJECT_ROOT / "v2" / "models_augmented" / "aegis_v2_1_ensemble_augmented.pkl"
    
    LABEL_COLUMN = "Label"


def load_test_data():
    df = pd.read_parquet(Config.TEST_FILE, engine='fastparquet')
    y = df[Config.LABEL_COLUMN]
    X = df.drop(columns=[Config.LABEL_COLUMN])
    return X, y


def evaluate_model(ensemble_path, X_test, y_test, model_label):
    ensemble = joblib.load(ensemble_path)
    
    scaler = ensemble['scaler']
    label_encoder = ensemble['label_encoder']
    
    X_scaled = scaler.transform(X_test)
    y_encoded = label_encoder.transform(y_test)
    
    rf_probs = ensemble['random_forest'].predict_proba(X_scaled)
    xgb_probs = ensemble['xgboost'].predict_proba(X_scaled)
    lgb_probs = ensemble['lightgbm'].predict_proba(X_scaled)
    
    meta_features = np.hstack([rf_probs, xgb_probs, lgb_probs])
    predictions = ensemble['meta_learner'].predict(meta_features)
    
    accuracy = accuracy_score(y_encoded, predictions)
    precision, recall, f1, support = precision_recall_fscore_support(
        y_encoded, predictions, average=None, zero_division=0
    )
    
    print(f"\n{'='*80}\n {model_label}\n{'='*80}")
    print(f"Overall Accuracy: {accuracy:.4f}\n")
    print(f"{'Class':<20} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print("-" * 62)
    
    results = {}
    for idx, label in enumerate(label_encoder.classes_):
        print(f"{label:<20} {precision[idx]:>10.4f} {recall[idx]:>10.4f} {f1[idx]:>10.4f} {int(support[idx]):>10}")
        results[label] = {'precision': precision[idx], 'recall': recall[idx], 'f1': f1[idx]}
    
    return results


def main():
    print("Loading test data...")
    X_test, y_test = load_test_data()
    print(f"Test records: {len(X_test):,}\n")
    
    original_results = evaluate_model(Config.ORIGINAL_MODEL, X_test, y_test, "ORIGINAL MODEL (v2.0.0)")
    augmented_results = evaluate_model(Config.AUGMENTED_MODEL, X_test, y_test, "AUGMENTED MODEL (v2.1.0 - SMOTE+WGAN-GP)")
    
    print(f"\n{'='*80}\n DIRECT COMPARISON — TARGET CLASSES\n{'='*80}")
    print(f"{'Class':<15} {'Metric':<10} {'Original':>12} {'Augmented':>12} {'Change':>12}")
    print("-" * 65)
    
    for cls in ["Heartbleed", "Infiltration"]:
        for metric in ["precision", "recall", "f1"]:
            orig = original_results.get(cls, {}).get(metric, 0)
            aug = augmented_results.get(cls, {}).get(metric, 0)
            change = aug - orig
            arrow = "↑" if change > 0 else ("↓" if change < 0 else "=")
            print(f"{cls:<15} {metric:<10} {orig:>12.4f} {aug:>12.4f} {change:>+11.4f} {arrow}")


if __name__ == "__main__":
    main()