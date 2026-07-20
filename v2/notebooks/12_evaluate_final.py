"""
================================================================================
AEGIS AI v2 - Final Three-Way Comparison
================================================================================

Module      : 12_evaluate_final.py
Description : Compare v2.0.0 (original) vs v2.1.0 (augmented) vs 
              v2.2.0 (augmented + tuned) on the SAME held-out test set
================================================================================
"""

import sys
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
import joblib

from sklearn.metrics import precision_recall_fscore_support, accuracy_score, f1_score

warnings.filterwarnings('ignore')


class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    RESULTS_DIR  = PROJECT_ROOT / "v2" / "results"
    
    TEST_FILE = RESULTS_DIR / "test_data.parquet"
    
    MODEL_V2_0 = PROJECT_ROOT / "v2" / "api" / "new_models" / "aegis_v2_ensemble.pkl"
    MODEL_V2_1 = PROJECT_ROOT / "v2" / "models_augmented" / "aegis_v2_1_ensemble_augmented.pkl"
    MODEL_V2_2 = PROJECT_ROOT / "v2" / "models_tuned" / "aegis_v2_2_ensemble_tuned.pkl"
    
    LABEL_COLUMN = "Label"


def load_test_data():
    df = pd.read_parquet(Config.TEST_FILE, engine='fastparquet')
    y = df[Config.LABEL_COLUMN]
    X = df.drop(columns=[Config.LABEL_COLUMN])
    return X, y


def evaluate(ensemble_path, X_test, y_test, label):
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
    weighted_f1 = f1_score(y_encoded, predictions, average='weighted')
    macro_f1 = f1_score(y_encoded, predictions, average='macro')
    
    precision, recall, f1, support = precision_recall_fscore_support(
        y_encoded, predictions, average=None, zero_division=0
    )
    
    results = {
        'accuracy': accuracy, 'weighted_f1': weighted_f1, 'macro_f1': macro_f1,
        'per_class': {}
    }
    for idx, cls in enumerate(label_encoder.classes_):
        results['per_class'][cls] = {
            'precision': precision[idx], 'recall': recall[idx], 'f1': f1[idx]
        }
    
    return results


def main():
    print("Loading test data...")
    X_test, y_test = load_test_data()
    print(f"Test records: {len(X_test):,}\n")
    
    results_v0 = evaluate(Config.MODEL_V2_0, X_test, y_test, "v2.0.0")
    results_v1 = evaluate(Config.MODEL_V2_1, X_test, y_test, "v2.1.0")
    results_v2 = evaluate(Config.MODEL_V2_2, X_test, y_test, "v2.2.0")
    
    print(f"{'='*90}")
    print(f" OVERALL METRICS COMPARISON")
    print(f"{'='*90}")
    print(f"{'Version':<12} {'Accuracy':>12} {'Weighted F1':>14} {'Macro F1':>12}")
    print(f"{'-'*52}")
    for label, r in [("v2.0.0 (orig)", results_v0), ("v2.1.0 (aug)", results_v1), ("v2.2.0 (tuned)", results_v2)]:
        print(f"{label:<12} {r['accuracy']:>12.4f} {r['weighted_f1']:>14.4f} {r['macro_f1']:>12.4f}")
    
    print(f"\n{'='*90}")
    print(f" PER-CLASS COMPARISON — ALL 13 CLASSES")
    print(f"{'='*90}")
    print(f"{'Class':<18} {'v2.0 Recall':>12} {'v2.1 Recall':>12} {'v2.2 Recall':>12}")
    print(f"{'-'*60}")
    
    for cls in results_v0['per_class'].keys():
        r0 = results_v0['per_class'][cls]['recall']
        r1 = results_v1['per_class'][cls]['recall']
        r2 = results_v2['per_class'][cls]['recall']
        print(f"{cls:<18} {r0:>12.4f} {r1:>12.4f} {r2:>12.4f}")


if __name__ == "__main__":
    main()