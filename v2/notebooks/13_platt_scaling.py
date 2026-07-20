"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 13_platt_scaling.py
Description : Calibrate meta-learner's confidence scores using Platt Scaling
              (CalibratedClassifierCV), verify calibration quality before/after
Author      : Prerak Nain
================================================================================
"""

import sys
import warnings
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

from sklearn.calibration import CalibratedClassifierCV, calibration_curve
from sklearn.metrics import brier_score_loss

warnings.filterwarnings('ignore')


class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    RESULTS_DIR  = PROJECT_ROOT / "v2" / "results"
    MODELS_DIR   = PROJECT_ROOT / "v2" / "models_calibrated"
    
    BEST_MODEL_FILE = PROJECT_ROOT / "v2" / "models_tuned" / "aegis_v2_2_ensemble_tuned.pkl"
    TRAIN_FILE       = RESULTS_DIR / "train_data_gan_augmented.parquet"
    TEST_FILE        = RESULTS_DIR / "test_data.parquet"
    
    CALIBRATED_MODEL_FILE = MODELS_DIR / "aegis_v2_3_ensemble_calibrated.pkl"
    
    LABEL_COLUMN = "Label"
    LINE_WIDTH = 80


def print_header(t): print(f"\n{'='*Config.LINE_WIDTH}\n {t}\n{'='*Config.LINE_WIDTH}")
def print_subheader(t): print(f"\n{'-'*Config.LINE_WIDTH}\n {t}\n{'-'*Config.LINE_WIDTH}")


def get_meta_features(ensemble, X):
    """Run X through the 3 base models to get the 39-feature meta input."""
    X_scaled = ensemble['scaler'].transform(X)
    rf_probs = ensemble['random_forest'].predict_proba(X_scaled)
    xgb_probs = ensemble['xgboost'].predict_proba(X_scaled)
    lgb_probs = ensemble['lightgbm'].predict_proba(X_scaled)
    return np.hstack([rf_probs, xgb_probs, lgb_probs])


def load_data():
    print_subheader("STAGE 1/5: LOADING DATA")
    
    train_df = pd.read_parquet(Config.TRAIN_FILE, engine='fastparquet')
    test_df = pd.read_parquet(Config.TEST_FILE, engine='fastparquet')
    
    y_train = train_df[Config.LABEL_COLUMN]
    X_train = train_df.drop(columns=[Config.LABEL_COLUMN])
    
    y_test = test_df[Config.LABEL_COLUMN]
    X_test = test_df.drop(columns=[Config.LABEL_COLUMN])
    
    print(f"\n  Train: {len(X_train):,}  |  Test: {len(X_test):,}")
    return X_train, y_train, X_test, y_test


def measure_calibration(y_true_binary, y_prob, label):
    """
    Reliability check: bucket predictions by confidence,
    compare CLAIMED confidence vs ACTUAL accuracy in each bucket.
    """
    prob_true, prob_pred = calibration_curve(y_true_binary, y_prob, n_bins=10, strategy='uniform')
    brier = brier_score_loss(y_true_binary, y_prob)
    
    print(f"\n  {label}")
    print(f"  Brier Score (lower = better calibrated): {brier:.4f}")
    print(f"  {'Predicted Conf.':>18} {'Actual Accuracy':>18} {'Gap':>10}")
    for pt, pp in zip(prob_true, prob_pred):
        gap = abs(pt - pp)
        print(f"  {pp:>18.3f} {pt:>18.3f} {gap:>10.3f}")
    
    return brier


def main():
    start = datetime.now()
    print_header("AEGIS AI v2.3 - PLATT SCALING CALIBRATION")
    
    try:
        X_train, y_train, X_test, y_test = load_data()
        
        print_subheader("STAGE 2/5: LOADING BEST MODEL (v2.2.0)")
        ensemble = joblib.load(Config.BEST_MODEL_FILE)
        label_encoder = ensemble['label_encoder']
        
        y_train_enc = label_encoder.transform(y_train)
        y_test_enc = label_encoder.transform(y_test)
        
        print_subheader("STAGE 3/5: BUILDING META-FEATURES")
        meta_train = get_meta_features(ensemble, X_train)
        meta_test = get_meta_features(ensemble, X_test)
        print(f"\n  Meta-feature shape (train): {meta_train.shape}")
        
        print_subheader("STAGE 4/5: CALIBRATING META-LEARNER (Platt Scaling)")
        
        # Wrap the ALREADY-TRAINED meta-learner with calibration
        # method='sigmoid' = Platt Scaling specifically
        calibrated_meta = CalibratedClassifierCV(
            ensemble['meta_learner'],
            method='sigmoid',
            cv='prefit'  # meta_learner already trained, just calibrate on top
        )
        calibrated_meta.fit(meta_train, y_train_enc)
        
        print("\n  Calibration fitted.")
        
        # ---- MEASURE CALIBRATION QUALITY: BEFORE vs AFTER ----
        # Use DDoS (class with lots of test samples) as example for reliability check
        print_subheader("STAGE 5/5: CALIBRATION QUALITY CHECK (DDoS class)")
        
        ddos_class_idx = list(label_encoder.classes_).index("DDoS")
        y_test_binary = (y_test_enc == ddos_class_idx).astype(int)
        
        # BEFORE: raw meta-learner probabilities
        probs_before = ensemble['meta_learner'].predict_proba(meta_test)[:, ddos_class_idx]
        brier_before = measure_calibration(y_test_binary, probs_before, "BEFORE CALIBRATION (raw)")
        
        # AFTER: calibrated probabilities
        probs_after = calibrated_meta.predict_proba(meta_test)[:, ddos_class_idx]
        brier_after = measure_calibration(y_test_binary, probs_after, "AFTER CALIBRATION (Platt Scaled)")
        
        print(f"\n  Brier Score improvement: {brier_before:.4f} -> {brier_after:.4f}")
        
        # ---- SAVE ----
        Config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
        calibrated_ensemble = dict(ensemble)  # copy base ensemble
        calibrated_ensemble['meta_learner'] = calibrated_meta  # swap in calibrated version
        calibrated_ensemble['version'] = '2.3.0-calibrated'
        calibrated_ensemble['trained_at'] = datetime.now().isoformat()
        calibrated_ensemble['notes'] = 'v2.2.0 + Platt Scaling calibration on meta-learner'
        
        joblib.dump(calibrated_ensemble, Config.CALIBRATED_MODEL_FILE)
        print(f"\n  Saved: {Config.CALIBRATED_MODEL_FILE.name}")
        
        elapsed = (datetime.now() - start).total_seconds()
        print_header("PLATT SCALING COMPLETE")
        print(f" Time: {elapsed:.1f}s")
        print(f"{'='*Config.LINE_WIDTH}\n")
        return 0
    
    except Exception as e:
        print(f"FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())