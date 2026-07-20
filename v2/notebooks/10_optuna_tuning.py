"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 10_optuna_tuning.py
Description : Optuna hyperparameter tuning, focused on fixing LightGBM's
              underperformance (52-62% training accuracy vs RF/XGB's 99.95%)
Author      : Prerak Nain
================================================================================
"""

import sys
import logging
import warnings
from pathlib import Path
from datetime import datetime

import numpy as np
import pandas as pd
import optuna
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import StratifiedKFold, cross_val_score
import lightgbm as lgb

warnings.filterwarnings('ignore')
optuna.logging.set_verbosity(optuna.logging.WARNING)  # quiet Optuna's own logs


class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    RESULTS_DIR  = PROJECT_ROOT / "v2" / "results"
    
    TRAIN_FILE = RESULTS_DIR / "train_data_gan_augmented.parquet"
    BEST_PARAMS_FILE = RESULTS_DIR / "lightgbm_best_params.txt"
    
    LABEL_COLUMN = "Label"
    N_TRIALS = 30
    CV_FOLDS = 3
    RANDOM_STATE = 42
    LINE_WIDTH = 80


def setup_logger():
    logger = logging.getLogger("AegisAI.Optuna")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        h = logging.StreamHandler(sys.stdout)
        h.setFormatter(logging.Formatter("[%(asctime)s] %(message)s", "%H:%M:%S"))
        logger.addHandler(h)
    return logger

log = setup_logger()

def print_header(t): print(f"\n{'='*Config.LINE_WIDTH}\n {t}\n{'='*Config.LINE_WIDTH}")
def print_subheader(t): print(f"\n{'-'*Config.LINE_WIDTH}\n {t}\n{'-'*Config.LINE_WIDTH}")


def load_data():
    print_subheader("LOADING DATA FOR TUNING")
    df = pd.read_parquet(Config.TRAIN_FILE, engine='fastparquet')
    y = df[Config.LABEL_COLUMN]
    X = df.drop(columns=[Config.LABEL_COLUMN])
    
    label_encoder = LabelEncoder()
    y_encoded = label_encoder.fit_transform(y)
    
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    
    print(f"\n  Records: {len(X):,}  |  Features: {X.shape[1]}")
    return X_scaled, y_encoded


def objective(trial, X, y):
    """
    One Optuna trial: propose hyperparameters, train + cross-validate,
    return the score Optuna should try to MAXIMIZE.
    """
    params = {
        'objective': 'multiclass',
        'num_class': len(np.unique(y)),
        'n_estimators': trial.suggest_int('n_estimators', 50, 300),
        'max_depth': trial.suggest_int('max_depth', 3, 15),
        'num_leaves': trial.suggest_int('num_leaves', 10, 150),
        'learning_rate': trial.suggest_float('learning_rate', 0.01, 0.3, log=True),
        'min_data_in_leaf': trial.suggest_int('min_data_in_leaf', 5, 100),
        'feature_fraction': trial.suggest_float('feature_fraction', 0.5, 1.0),
        'bagging_fraction': trial.suggest_float('bagging_fraction', 0.5, 1.0),
        'bagging_freq': trial.suggest_int('bagging_freq', 1, 7),
        'lambda_l1': trial.suggest_float('lambda_l1', 1e-8, 10.0, log=True),
        'lambda_l2': trial.suggest_float('lambda_l2', 1e-8, 10.0, log=True),
        'random_state': Config.RANDOM_STATE,
        'verbose': -1,
        'n_jobs': -1
    }
    
    model = lgb.LGBMClassifier(**params)
    
    cv = StratifiedKFold(n_splits=Config.CV_FOLDS, shuffle=True, random_state=Config.RANDOM_STATE)
    
    # Use a SUBSET for speed during tuning (full 188K rows x 30 trials x 3 folds would be very slow)
    sample_size = min(30000, len(X))
    rng = np.random.RandomState(Config.RANDOM_STATE)
    idx = rng.choice(len(X), sample_size, replace=False)
    X_sample, y_sample = X[idx], y[idx]
    
    scores = cross_val_score(model, X_sample, y_sample, cv=cv, scoring='f1_weighted', n_jobs=1)
    
    return scores.mean()


def run_optuna_study(X, y):
    print_subheader(f"RUNNING OPTUNA — {Config.N_TRIALS} TRIALS")
    
    study = optuna.create_study(direction='maximize')
    
    def callback(study, trial):
        print(f"  Trial {trial.number+1}/{Config.N_TRIALS}: "
              f"F1={trial.value:.4f}  (best so far: {study.best_value:.4f})")
    
    study.optimize(
        lambda trial: objective(trial, X, y),
        n_trials=Config.N_TRIALS,
        callbacks=[callback]
    )
    
    print(f"\n  BEST TRIAL: F1={study.best_value:.4f}")
    print(f"  BEST PARAMS:")
    for k, v in study.best_params.items():
        print(f"    {k}: {v}")
    
    return study


def save_best_params(study):
    with open(Config.BEST_PARAMS_FILE, 'w') as f:
        f.write(f"Best F1 (weighted): {study.best_value:.4f}\n\n")
        f.write("Best hyperparameters:\n")
        for k, v in study.best_params.items():
            f.write(f"  {k}: {v}\n")
    log.info(f"Saved best params to {Config.BEST_PARAMS_FILE}")


def main():
    start = datetime.now()
    print_header("AEGIS AI v2 - OPTUNA TUNING (LightGBM)")
    
    try:
        X, y = load_data()
        study = run_optuna_study(X, y)
        save_best_params(study)
        
        elapsed = (datetime.now() - start).total_seconds()
        print_header("OPTUNA TUNING COMPLETE")
        print(f" Time: {elapsed/60:.1f} minutes")
        print(f" Next: Retrain ensemble using these tuned LightGBM params")
        print(f"{'='*Config.LINE_WIDTH}\n")
        return 0
    
    except Exception as e:
        log.error(f"Failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())