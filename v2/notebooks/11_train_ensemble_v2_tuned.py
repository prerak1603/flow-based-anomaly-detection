"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 11_train_ensemble_v2_tuned.py
Description : Retrain ensemble with Optuna-tuned LightGBM params, on top
              of SMOTE + WGAN-GP augmented data
Author      : Prerak Nain
Version     : 2.2.0
================================================================================
"""

import sys
import logging
import warnings
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import joblib

from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import cross_val_predict

import xgboost as xgb
import lightgbm as lgb

warnings.filterwarnings('ignore')


class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    RESULTS_DIR  = PROJECT_ROOT / "v2" / "results"
    MODELS_DIR   = PROJECT_ROOT / "v2" / "models_tuned"
    
    TRAIN_FILE    = RESULTS_DIR / "train_data_gan_augmented.parquet"
    ENSEMBLE_FILE = MODELS_DIR / "aegis_v2_2_ensemble_tuned.pkl"
    
    LABEL_COLUMN = "Label"
    RANDOM_STATE = 42
    N_JOBS       = -1
    
    RF_PARAMS = {
        'n_estimators': 100, 'max_depth': 20,
        'min_samples_split': 5, 'random_state': RANDOM_STATE,
        'n_jobs': N_JOBS, 'verbose': 0
    }
    XGB_PARAMS = {
        'n_estimators': 100, 'max_depth': 8,
        'learning_rate': 0.1, 'random_state': RANDOM_STATE,
        'n_jobs': N_JOBS, 'verbosity': 0, 'tree_method': 'hist'
    }
    
    # ===== OPTUNA-TUNED LIGHTGBM PARAMS =====
    LGB_PARAMS = {
        'n_estimators': 250,
        'max_depth': 10,
        'num_leaves': 10,
        'learning_rate': 0.04043011948520623,
        'min_data_in_leaf': 74,
        'feature_fraction': 0.8355693006993479,
        'bagging_fraction': 0.8533183479484784,
        'bagging_freq': 2,
        'lambda_l1': 2.024382544303047e-06,
        'lambda_l2': 0.0019460252387672884,
        'random_state': RANDOM_STATE,
        'n_jobs': N_JOBS,
        'verbose': -1
    }
    
    LINE_WIDTH = 80


def setup_logger():
    logger = logging.getLogger("AegisAI.TrainTuned")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S"))
        logger.addHandler(h)
    return logger

log = setup_logger()

def print_header(t): print(f"\n{'='*Config.LINE_WIDTH}\n {t}\n{'='*Config.LINE_WIDTH}")
def print_subheader(t): print(f"\n{'-'*Config.LINE_WIDTH}\n {t}\n{'-'*Config.LINE_WIDTH}")
def format_time(s): return f"{s:.1f}s" if s < 60 else f"{s/60:.1f}m"


def load_training_data():
    print_subheader("STAGE 1/7: LOADING DATA")
    df = pd.read_parquet(Config.TRAIN_FILE, engine='fastparquet')
    y = df[Config.LABEL_COLUMN]
    X = df.drop(columns=[Config.LABEL_COLUMN])
    print(f"\n  Records: {len(X):,}  |  Features: {X.shape[1]}")
    return X, y


def preprocess_data(X, y):
    print_subheader("STAGE 2/7: PREPROCESSING")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    return X_scaled, y_encoded, scaler, label_encoder


def train_random_forest(X, y):
    print_subheader("STAGE 3/7: TRAINING RANDOM FOREST")
    start = datetime.now()
    model = RandomForestClassifier(**Config.RF_PARAMS)
    model.fit(X, y)
    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n  Time: {format_time(elapsed)}  |  Train accuracy: {model.score(X, y):.4f}")
    return model


def train_xgboost(X, y):
    print_subheader("STAGE 4/7: TRAINING XGBOOST")
    start = datetime.now()
    model = xgb.XGBClassifier(**Config.XGB_PARAMS)
    model.fit(X, y)
    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n  Time: {format_time(elapsed)}  |  Train accuracy: {model.score(X, y):.4f}")
    return model


def train_lightgbm(X, y):
    print_subheader("STAGE 5/7: TRAINING LIGHTGBM (OPTUNA-TUNED)")
    start = datetime.now()
    model = lgb.LGBMClassifier(**Config.LGB_PARAMS)
    model.fit(X, y)
    elapsed = (datetime.now() - start).total_seconds()
    acc = model.score(X, y)
    print(f"\n  Time: {format_time(elapsed)}  |  Train accuracy: {acc:.4f}")
    print(f"  (Compare to original default params: 52-62%)")
    return model


def train_meta_learner(X, y, rf_model, xgb_model, lgb_model):
    print_subheader("STAGE 6/7: TRAINING META-LEARNER")
    start = datetime.now()
    
    log.info("  [1/3] RF out-of-fold predictions...")
    rf_preds = cross_val_predict(RandomForestClassifier(**Config.RF_PARAMS), X, y, cv=3, method='predict_proba', n_jobs=Config.N_JOBS)
    log.info("  [2/3] XGBoost out-of-fold predictions...")
    xgb_preds = cross_val_predict(xgb.XGBClassifier(**Config.XGB_PARAMS), X, y, cv=3, method='predict_proba', n_jobs=Config.N_JOBS)
    log.info("  [3/3] LightGBM (tuned) out-of-fold predictions...")
    lgb_preds = cross_val_predict(lgb.LGBMClassifier(**Config.LGB_PARAMS), X, y, cv=3, method='predict_proba', n_jobs=Config.N_JOBS)
    
    meta_features = np.hstack([rf_preds, xgb_preds, lgb_preds])
    meta_model = LogisticRegression(max_iter=1000, random_state=Config.RANDOM_STATE, n_jobs=Config.N_JOBS)
    meta_model.fit(meta_features, y)
    
    elapsed = (datetime.now() - start).total_seconds()
    print(f"\n  Time: {format_time(elapsed)}  |  Meta-learner accuracy: {meta_model.score(meta_features, y):.4f}")
    return meta_model


def save_all_models(rf_model, xgb_model, lgb_model, meta_model, scaler, label_encoder):
    print_subheader("STAGE 7/7: SAVING TUNED MODELS")
    Config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    ensemble = {
        'random_forest': rf_model, 'xgboost': xgb_model, 'lightgbm': lgb_model,
        'meta_learner': meta_model, 'scaler': scaler, 'label_encoder': label_encoder,
        'version': '2.2.0-tuned',
        'trained_at': datetime.now().isoformat(),
        'notes': 'SMOTE+WGAN-GP augmentation + Optuna-tuned LightGBM'
    }
    joblib.dump(ensemble, Config.ENSEMBLE_FILE)
    print(f"\n  Saved: {Config.ENSEMBLE_FILE.name}")


def main():
    start_time = datetime.now()
    print_header("AEGIS AI v2.2 - TRAINING WITH TUNED LIGHTGBM")
    
    try:
        X, y = load_training_data()
        X_scaled, y_encoded, scaler, label_encoder = preprocess_data(X, y)
        
        rf_model = train_random_forest(X_scaled, y_encoded)
        xgb_model = train_xgboost(X_scaled, y_encoded)
        lgb_model = train_lightgbm(X_scaled, y_encoded)
        meta_model = train_meta_learner(X_scaled, y_encoded, rf_model, xgb_model, lgb_model)
        
        save_all_models(rf_model, xgb_model, lgb_model, meta_model, scaler, label_encoder)
        
        elapsed = datetime.now() - start_time
        print_header("TRAINING COMPLETE")
        print(f" Total time: {format_time(elapsed.total_seconds())}")
        print(f" Next: Evaluate vs original AND augmented-only versions")
        print(f"{'='*Config.LINE_WIDTH}\n")
        return 0
    
    except Exception as e:
        log.error(f"Failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())