"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 04_train_ensemble.py
Description : Stacking ensemble training pipeline
Author      : Prerak Nain
Version     : 2.0.0

--------------------------------------------------------------------------------
PURPOSE
--------------------------------------------------------------------------------
Trains a stacking ensemble of three base models with a meta-learner:
    - Random Forest (bagging-based)
    - XGBoost (gradient boosting)
    - LightGBM (efficient gradient boosting)
    - Logistic Regression (meta-learner)

Each base model votes on the prediction.
The meta-learner combines their votes intelligently.

--------------------------------------------------------------------------------
PIPELINE
--------------------------------------------------------------------------------
    [1] Load training data
    [2] Preprocess (encode labels, scale features)
    [3] Train Random Forest
    [4] Train XGBoost
    [5] Train LightGBM
    [6] Train meta-learner (stacking)
    [7] Save all models
================================================================================
"""

import sys
import logging
import warnings
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict

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


# ==============================================================================
# CONFIGURATION
# ==============================================================================

class Config:
    """Training configuration."""
    
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    OUTPUT_DIR   = PROJECT_ROOT / "new_results"
    MODELS_DIR   = PROJECT_ROOT / "new_models"
    
    TRAIN_FILE   = OUTPUT_DIR / "train_data.parquet"
    TEST_FILE    = OUTPUT_DIR / "test_data.parquet"
    
    # Model artifact paths
    RF_MODEL_FILE     = MODELS_DIR / "random_forest.pkl"
    XGB_MODEL_FILE    = MODELS_DIR / "xgboost.pkl"
    LGB_MODEL_FILE    = MODELS_DIR / "lightgbm.pkl"
    META_MODEL_FILE   = MODELS_DIR / "meta_learner.pkl"
    ENSEMBLE_FILE     = MODELS_DIR / "aegis_v2_ensemble.pkl"
    SCALER_FILE       = MODELS_DIR / "scaler.pkl"
    ENCODER_FILE      = MODELS_DIR / "label_encoder.pkl"
    
    LABEL_COLUMN = "Label"
    RANDOM_STATE = 42
    N_JOBS       = -1  # Use all CPU cores
    
    # Random Forest params
    RF_PARAMS = {
        'n_estimators': 100,
        'max_depth': 20,
        'min_samples_split': 5,
        'random_state': RANDOM_STATE,
        'n_jobs': N_JOBS,
        'verbose': 0
    }
    
    # XGBoost params
    XGB_PARAMS = {
        'n_estimators': 100,
        'max_depth': 8,
        'learning_rate': 0.1,
        'random_state': RANDOM_STATE,
        'n_jobs': N_JOBS,
        'verbosity': 0,
        'tree_method': 'hist'  # Fast
    }
    
    # LightGBM params
    LGB_PARAMS = {
        'n_estimators': 100,
        'max_depth': 8,
        'learning_rate': 0.1,
        'random_state': RANDOM_STATE,
        'n_jobs': N_JOBS,
        'verbose': -1
    }
    
    LINE_WIDTH = 80


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("AegisAI.Training")
    logger.setLevel(logging.INFO)
    
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        formatter = logging.Formatter(
            fmt="[%(asctime)s] %(message)s",
            datefmt="%H:%M:%S"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    
    return logger


log = setup_logger()


# ==============================================================================
# UTILITIES
# ==============================================================================

def print_header(title: str) -> None:
    print(f"\n{'=' * Config.LINE_WIDTH}")
    print(f" {title}")
    print(f"{'=' * Config.LINE_WIDTH}")


def print_subheader(title: str) -> None:
    print(f"\n{'-' * Config.LINE_WIDTH}")
    print(f" {title}")
    print(f"{'-' * Config.LINE_WIDTH}")


def format_time(seconds: float) -> str:
    if seconds < 60:
        return f"{seconds:.1f}s"
    minutes = seconds / 60
    return f"{minutes:.1f}m"


# ==============================================================================
# PIPELINE STAGES
# ==============================================================================

def load_training_data() -> Tuple[pd.DataFrame, pd.Series]:
    """
    Load prepared training data.
    
    Returns:
        Tuple of (features DataFrame, labels Series)
    """
    print_subheader("STAGE 1/7: LOADING TRAINING DATA")
    
    if not Config.TRAIN_FILE.exists():
        raise FileNotFoundError(
            f"Training data not found: {Config.TRAIN_FILE}\n"
            "Please run 03_prepare_training.py first."
        )
    
    log.info(f"Loading: {Config.TRAIN_FILE}")
    df = pd.read_parquet(Config.TRAIN_FILE)
    
    y = df[Config.LABEL_COLUMN]
    X = df.drop(columns=[Config.LABEL_COLUMN])
    
    print(f"\n  Training records : {len(X):,}")
    print(f"  Features         : {X.shape[1]}")
    print(f"  Classes          : {y.nunique()}")
    
    print(f"\n  Class distribution:")
    for label, count in y.value_counts().head(5).items():
        pct = (count / len(y)) * 100
        print(f"    {label:<40} {count:>8,} ({pct:>5.2f}%)")
    if y.nunique() > 5:
        print(f"    ... and {y.nunique() - 5} more classes")
    
    return X, y


def preprocess_data(
    X: pd.DataFrame,
    y: pd.Series
) -> Tuple[np.ndarray, np.ndarray, StandardScaler, LabelEncoder]:
    """
    Preprocess features and labels.
    
    - Scale features to zero mean, unit variance
    - Encode string labels to integers
    
    Args:
        X: Feature DataFrame
        y: Label Series
    
    Returns:
        Tuple of (scaled features, encoded labels, scaler, encoder)
    """
    print_subheader("STAGE 2/7: PREPROCESSING")
    
    # Encode labels (string → integer)
    log.info("Encoding labels")
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    print(f"\n  Label encoding:")
    for idx, label in enumerate(label_encoder.classes_[:5]):
        print(f"    {label:<40} → {idx}")
    if len(label_encoder.classes_) > 5:
        print(f"    ... and {len(label_encoder.classes_) - 5} more mappings")
    
    # Scale features
    log.info("Scaling features")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"\n  Feature scaling: StandardScaler applied")
    print(f"  Shape: {X_scaled.shape}")
    
    return X_scaled, y_encoded, scaler, label_encoder


def train_random_forest(
    X: np.ndarray,
    y: np.ndarray
) -> RandomForestClassifier:
    """
    Train Random Forest classifier.
    
    Random Forest builds many decision trees and uses their
    majority vote for prediction (bagging).
    
    Args:
        X: Scaled features
        y: Encoded labels
    
    Returns:
        Trained RandomForestClassifier
    """
    print_subheader("STAGE 3/7: TRAINING RANDOM FOREST")
    
    log.info(f"Params: {Config.RF_PARAMS['n_estimators']} trees, "
             f"max_depth={Config.RF_PARAMS['max_depth']}")
    
    start = datetime.now()
    
    model = RandomForestClassifier(**Config.RF_PARAMS)
    model.fit(X, y)
    
    elapsed = (datetime.now() - start).total_seconds()
    
    # Training accuracy
    train_accuracy = model.score(X, y)
    
    print(f"\n  Training time    : {format_time(elapsed)}")
    print(f"  Training accuracy: {train_accuracy:.4f} ({train_accuracy * 100:.2f}%)")
    
    return model


def train_xgboost(
    X: np.ndarray,
    y: np.ndarray
) -> xgb.XGBClassifier:
    """
    Train XGBoost classifier.
    
    XGBoost builds trees sequentially, each fixing errors from previous.
    Very accurate but can overfit if not tuned.
    
    Args:
        X: Scaled features
        y: Encoded labels
    
    Returns:
        Trained XGBClassifier
    """
    print_subheader("STAGE 4/7: TRAINING XGBOOST")
    
    log.info(f"Params: {Config.XGB_PARAMS['n_estimators']} trees, "
             f"max_depth={Config.XGB_PARAMS['max_depth']}")
    
    start = datetime.now()
    
    model = xgb.XGBClassifier(**Config.XGB_PARAMS)
    model.fit(X, y)
    
    elapsed = (datetime.now() - start).total_seconds()
    
    train_accuracy = model.score(X, y)
    
    print(f"\n  Training time    : {format_time(elapsed)}")
    print(f"  Training accuracy: {train_accuracy:.4f} ({train_accuracy * 100:.2f}%)")
    
    return model


def train_lightgbm(
    X: np.ndarray,
    y: np.ndarray
) -> lgb.LGBMClassifier:
    """
    Train LightGBM classifier.
    
    LightGBM is like XGBoost but more memory efficient.
    Uses leaf-wise growth (faster).
    
    Args:
        X: Scaled features
        y: Encoded labels
    
    Returns:
        Trained LGBMClassifier
    """
    print_subheader("STAGE 5/7: TRAINING LIGHTGBM")
    
    log.info(f"Params: {Config.LGB_PARAMS['n_estimators']} trees, "
             f"max_depth={Config.LGB_PARAMS['max_depth']}")
    
    start = datetime.now()
    
    model = lgb.LGBMClassifier(**Config.LGB_PARAMS)
    model.fit(X, y)
    
    elapsed = (datetime.now() - start).total_seconds()
    
    train_accuracy = model.score(X, y)
    
    print(f"\n  Training time    : {format_time(elapsed)}")
    print(f"  Training accuracy: {train_accuracy:.4f} ({train_accuracy * 100:.2f}%)")
    
    return model


def train_meta_learner(
    X: np.ndarray,
    y: np.ndarray,
    rf_model: RandomForestClassifier,
    xgb_model: xgb.XGBClassifier,
    lgb_model: lgb.LGBMClassifier
) -> LogisticRegression:
    """
    Train the meta-learner using stacking.
    
    Uses out-of-fold predictions from base models as features
    for the meta-learner. This prevents data leakage.
    
    Args:
        X: Scaled features
        y: Encoded labels
        rf_model, xgb_model, lgb_model: Trained base models
    
    Returns:
        Trained LogisticRegression meta-learner
    """
    print_subheader("STAGE 6/7: TRAINING META-LEARNER (STACKING)")
    
    log.info("Generating out-of-fold predictions from base models")
    
    start = datetime.now()
    
    # Get probability predictions from each base model
    # Using cross_val_predict prevents data leakage
    log.info("  [1/3] Random Forest predictions...")
    rf_preds = cross_val_predict(
        RandomForestClassifier(**Config.RF_PARAMS),
        X, y, cv=3, method='predict_proba', n_jobs=Config.N_JOBS
    )
    
    log.info("  [2/3] XGBoost predictions...")
    xgb_preds = cross_val_predict(
        xgb.XGBClassifier(**Config.XGB_PARAMS),
        X, y, cv=3, method='predict_proba', n_jobs=Config.N_JOBS
    )
    
    log.info("  [3/3] LightGBM predictions...")
    lgb_preds = cross_val_predict(
        lgb.LGBMClassifier(**Config.LGB_PARAMS),
        X, y, cv=3, method='predict_proba', n_jobs=Config.N_JOBS
    )
    
    # Stack predictions horizontally
    meta_features = np.hstack([rf_preds, xgb_preds, lgb_preds])
    
    log.info(f"Meta features shape: {meta_features.shape}")
    
    # Train meta-learner
    log.info("Training Logistic Regression meta-learner")
    meta_model = LogisticRegression(
        max_iter=1000,
        random_state=Config.RANDOM_STATE,
        n_jobs=Config.N_JOBS
    )
    meta_model.fit(meta_features, y)
    
    elapsed = (datetime.now() - start).total_seconds()
    
    train_accuracy = meta_model.score(meta_features, y)
    
    print(f"\n  Total training time : {format_time(elapsed)}")
    print(f"  Meta-learner accuracy: {train_accuracy:.4f} ({train_accuracy * 100:.2f}%)")
    
    return meta_model


def save_all_models(
    rf_model: RandomForestClassifier,
    xgb_model: xgb.XGBClassifier,
    lgb_model: lgb.LGBMClassifier,
    meta_model: LogisticRegression,
    scaler: StandardScaler,
    label_encoder: LabelEncoder
) -> None:
    """
    Save all trained models and preprocessors.
    
    Args:
        All trained components
    """
    print_subheader("STAGE 7/7: SAVING MODELS")
    
    Config.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Save individual models
    log.info("Saving Random Forest")
    joblib.dump(rf_model, Config.RF_MODEL_FILE)
    
    log.info("Saving XGBoost")
    joblib.dump(xgb_model, Config.XGB_MODEL_FILE)
    
    log.info("Saving LightGBM")
    joblib.dump(lgb_model, Config.LGB_MODEL_FILE)
    
    log.info("Saving Meta-learner")
    joblib.dump(meta_model, Config.META_MODEL_FILE)
    
    log.info("Saving Scaler")
    joblib.dump(scaler, Config.SCALER_FILE)
    
    log.info("Saving Label Encoder")
    joblib.dump(label_encoder, Config.ENCODER_FILE)
    
    # Save complete ensemble as a single object
    log.info("Saving complete ensemble")
    ensemble = {
        'random_forest': rf_model,
        'xgboost': xgb_model,
        'lightgbm': lgb_model,
        'meta_learner': meta_model,
        'scaler': scaler,
        'label_encoder': label_encoder,
        'version': '2.0.0',
        'trained_at': datetime.now().isoformat()
    }
    joblib.dump(ensemble, Config.ENSEMBLE_FILE)
    
    # File sizes
    print(f"\n  Model files saved:")
    for name, path in [
        ('Random Forest', Config.RF_MODEL_FILE),
        ('XGBoost', Config.XGB_MODEL_FILE),
        ('LightGBM', Config.LGB_MODEL_FILE),
        ('Meta-learner', Config.META_MODEL_FILE),
        ('Scaler', Config.SCALER_FILE),
        ('Encoder', Config.ENCODER_FILE),
        ('Ensemble', Config.ENSEMBLE_FILE),
    ]:
        size_mb = path.stat().st_size / (1024 * 1024)
        print(f"    {name:<20} {size_mb:>6.2f} MB")


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main() -> int:
    """Execute the complete training pipeline."""
    start_time = datetime.now()
    
    print_header("AEGIS AI v2 - ENSEMBLE MODEL TRAINING")
    print(f" Started    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Input      : {Config.TRAIN_FILE}")
    print(f" Models dir : {Config.MODELS_DIR}")
    
    try:
        # Stage 1: Load
        X, y = load_training_data()
        
        # Stage 2: Preprocess
        X_scaled, y_encoded, scaler, label_encoder = preprocess_data(X, y)
        
        # Stage 3-5: Train base models
        rf_model = train_random_forest(X_scaled, y_encoded)
        xgb_model = train_xgboost(X_scaled, y_encoded)
        lgb_model = train_lightgbm(X_scaled, y_encoded)
        
        # Stage 6: Train meta-learner
        meta_model = train_meta_learner(
            X_scaled, y_encoded,
            rf_model, xgb_model, lgb_model
        )
        
        # Stage 7: Save everything
        save_all_models(
            rf_model, xgb_model, lgb_model, meta_model,
            scaler, label_encoder
        )
        
        # Summary
        elapsed = datetime.now() - start_time
        
        print_header("TRAINING COMPLETE")
        print(f" Total time  : {format_time(elapsed.total_seconds())}")
        print(f" Models      : 3 base + 1 meta-learner")
        print(f" Classes     : {len(label_encoder.classes_)}")
        print(f" Ready for   : Model evaluation (05_evaluate_v2.py)")
        print(f"{'=' * Config.LINE_WIDTH}\n")
        
        return 0
    
    except Exception as e:
        log.error(f"Training failed: {e}", exc_info=True)
        return 1


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    sys.exit(main())