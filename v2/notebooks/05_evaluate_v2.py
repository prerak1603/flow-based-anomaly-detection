"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 05_evaluate_v2.py
Description : Comprehensive model evaluation on test data
Author      : Prerak Nain
Version     : 2.0.0

--------------------------------------------------------------------------------
PURPOSE
--------------------------------------------------------------------------------
Evaluates the trained ensemble on UNSEEN test data.
Generates:
    - Overall accuracy metrics
    - Per-class precision, recall, F1-score
    - Confusion matrix visualization
    - Feature importance analysis
    - Comprehensive evaluation report
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
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    classification_report,
    confusion_matrix
)

warnings.filterwarnings('ignore')


# ==============================================================================
# CONFIGURATION
# ==============================================================================

class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    OUTPUT_DIR   = PROJECT_ROOT / "new_results"
    MODELS_DIR   = PROJECT_ROOT / "new_models"
    
    TEST_FILE     = OUTPUT_DIR / "test_data.parquet"
    ENSEMBLE_FILE = MODELS_DIR / "aegis_v2_ensemble.pkl"
    
    REPORT_FILE     = OUTPUT_DIR / "day1_evaluation_report.txt"
    CM_PLOT_FILE    = OUTPUT_DIR / "confusion_matrix_v2.png"
    IMPORTANCE_FILE = OUTPUT_DIR / "feature_importance_v2.png"
    
    LABEL_COLUMN = "Label"
    LINE_WIDTH   = 80


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("AegisAI.Evaluation")
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


# ==============================================================================
# PIPELINE STAGES
# ==============================================================================

def load_test_data_and_models() -> Tuple[pd.DataFrame, pd.Series, Dict]:
    """
    Load test data and trained ensemble.
    
    Returns:
        Tuple of (features, labels, ensemble dict)
    """
    print_subheader("STAGE 1/6: LOADING TEST DATA AND MODELS")
    
    if not Config.TEST_FILE.exists():
        raise FileNotFoundError(f"Test data not found: {Config.TEST_FILE}")
    
    if not Config.ENSEMBLE_FILE.exists():
        raise FileNotFoundError(f"Ensemble not found: {Config.ENSEMBLE_FILE}")
    
    log.info(f"Loading test data: {Config.TEST_FILE}")
    df = pd.read_parquet(Config.TEST_FILE)
    
    y_test = df[Config.LABEL_COLUMN]
    X_test = df.drop(columns=[Config.LABEL_COLUMN])
    
    log.info(f"Loading ensemble: {Config.ENSEMBLE_FILE}")
    ensemble = joblib.load(Config.ENSEMBLE_FILE)
    
    print(f"\n  Test records : {len(X_test):,}")
    print(f"  Features     : {X_test.shape[1]}")
    print(f"  Classes      : {y_test.nunique()}")
    print(f"  Model version: {ensemble.get('version', 'unknown')}")
    
    return X_test, y_test, ensemble


def preprocess_test_data(
    X_test: pd.DataFrame,
    y_test: pd.Series,
    ensemble: Dict
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Apply the SAME preprocessing as training.
    
    Args:
        X_test: Test features
        y_test: Test labels
        ensemble: Loaded ensemble with scaler and encoder
    
    Returns:
        Tuple of (scaled features, encoded labels)
    """
    print_subheader("STAGE 2/6: PREPROCESSING TEST DATA")
    
    scaler = ensemble['scaler']
    label_encoder = ensemble['label_encoder']
    
    log.info("Applying scaler (using training statistics)")
    X_test_scaled = scaler.transform(X_test)
    
    log.info("Encoding labels")
    y_test_encoded = label_encoder.transform(y_test)
    
    print(f"\n  Scaled shape: {X_test_scaled.shape}")
    print(f"  Classes     : {len(label_encoder.classes_)}")
    
    return X_test_scaled, y_test_encoded


def make_ensemble_predictions(
    X_test: np.ndarray,
    ensemble: Dict
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Get predictions from all models and combine using meta-learner.
    
    Args:
        X_test: Scaled test features
        ensemble: Loaded ensemble
    
    Returns:
        Tuple of (predictions, probabilities)
    """
    print_subheader("STAGE 3/6: MAKING PREDICTIONS")
    
    rf_model = ensemble['random_forest']
    xgb_model = ensemble['xgboost']
    lgb_model = ensemble['lightgbm']
    meta_model = ensemble['meta_learner']
    
    log.info("[1/4] Random Forest predictions")
    rf_probs = rf_model.predict_proba(X_test)
    
    log.info("[2/4] XGBoost predictions")
    xgb_probs = xgb_model.predict_proba(X_test)
    
    log.info("[3/4] LightGBM predictions")
    lgb_probs = lgb_model.predict_proba(X_test)
    
    log.info("[4/4] Meta-learner combining predictions")
    meta_features = np.hstack([rf_probs, xgb_probs, lgb_probs])
    final_predictions = meta_model.predict(meta_features)
    final_probabilities = meta_model.predict_proba(meta_features)
    
    print(f"\n  Predictions shape: {final_predictions.shape}")
    print(f"  Probabilities shape: {final_probabilities.shape}")
    
    return final_predictions, final_probabilities


def calculate_metrics(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    label_encoder
) -> Dict:
    """
    Calculate comprehensive evaluation metrics.
    
    Args:
        y_true: True labels
        y_pred: Predicted labels
        label_encoder: For label names
    
    Returns:
        Dictionary of metrics
    """
    print_subheader("STAGE 4/6: CALCULATING METRICS")
    
    # Overall accuracy
    accuracy = accuracy_score(y_true, y_pred)
    
    # Per-class metrics
    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, average=None, zero_division=0
    )
    
    # Weighted averages (accounts for class imbalance)
    precision_w, recall_w, f1_w, _ = precision_recall_fscore_support(
        y_true, y_pred, average='weighted', zero_division=0
    )
    
    # Macro averages (unweighted mean)
    precision_m, recall_m, f1_m, _ = precision_recall_fscore_support(
        y_true, y_pred, average='macro', zero_division=0
    )
    
    print(f"\n  OVERALL PERFORMANCE:")
    print(f"    Accuracy         : {accuracy:.4f} ({accuracy * 100:.2f}%)")
    print(f"    Precision (wt.)  : {precision_w:.4f}")
    print(f"    Recall (wt.)     : {recall_w:.4f}")
    print(f"    F1-Score (wt.)   : {f1_w:.4f}")
    
    print(f"\n  PER-CLASS PERFORMANCE:")
    print(f"  {'Attack Type':<40} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}")
    print(f"  {'-' * 80}")
    
    for idx, label in enumerate(label_encoder.classes_):
        print(
            f"  {label:<40} "
            f"{precision[idx]:>10.4f} "
            f"{recall[idx]:>10.4f} "
            f"{f1[idx]:>10.4f} "
            f"{int(support[idx]):>10,}"
        )
    
    print(f"\n  {'MACRO AVERAGE':<40} "
          f"{precision_m:>10.4f} "
          f"{recall_m:>10.4f} "
          f"{f1_m:>10.4f}")
    print(f"  {'WEIGHTED AVERAGE':<40} "
          f"{precision_w:>10.4f} "
          f"{recall_w:>10.4f} "
          f"{f1_w:>10.4f}")
    
    return {
        'accuracy': accuracy,
        'precision_weighted': precision_w,
        'recall_weighted': recall_w,
        'f1_weighted': f1_w,
        'precision_macro': precision_m,
        'recall_macro': recall_m,
        'f1_macro': f1_m,
        'per_class': {
            label: {
                'precision': precision[idx],
                'recall': recall[idx],
                'f1': f1[idx],
                'support': int(support[idx])
            }
            for idx, label in enumerate(label_encoder.classes_)
        }
    }


def generate_confusion_matrix(
    y_true: np.ndarray,
    y_pred: np.ndarray,
    label_encoder
) -> None:
    """
    Generate and save confusion matrix visualization.
    """
    print_subheader("STAGE 5/6: GENERATING VISUALIZATIONS")
    
    log.info("Building confusion matrix")
    
    cm = confusion_matrix(y_true, y_pred)
    
    # Normalize for percentage view
    cm_normalized = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
    cm_normalized = np.nan_to_num(cm_normalized)
    
    class_names = label_encoder.classes_
    
    # Create figure
    fig, axes = plt.subplots(1, 2, figsize=(20, 8))
    
    # Absolute counts
    sns.heatmap(
        cm,
        annot=True,
        fmt='d',
        cmap='Blues',
        xticklabels=class_names,
        yticklabels=class_names,
        ax=axes[0]
    )
    axes[0].set_title('Confusion Matrix (Counts)', fontsize=14, fontweight='bold')
    axes[0].set_xlabel('Predicted Label')
    axes[0].set_ylabel('True Label')
    
    # Normalized (percentages)
    sns.heatmap(
        cm_normalized,
        annot=True,
        fmt='.2%',
        cmap='YlGnBu',
        xticklabels=class_names,
        yticklabels=class_names,
        ax=axes[1]
    )
    axes[1].set_title('Confusion Matrix (Normalized)', fontsize=14, fontweight='bold')
    axes[1].set_xlabel('Predicted Label')
    axes[1].set_ylabel('True Label')
    
    plt.tight_layout()
    plt.savefig(Config.CM_PLOT_FILE, dpi=100, bbox_inches='tight')
    plt.close()
    
    log.info(f"Saved: {Config.CM_PLOT_FILE}")
    print(f"\n  Confusion matrix saved: {Config.CM_PLOT_FILE.name}")


def generate_feature_importance(ensemble: Dict, feature_names: list) -> None:
    """
    Extract and visualize feature importance from Random Forest.
    """
    log.info("Extracting feature importance from Random Forest")
    
    rf_model = ensemble['random_forest']
    importances = rf_model.feature_importances_
    
    # Sort by importance
    indices = np.argsort(importances)[::-1][:20]  # Top 20
    top_features = [feature_names[i] for i in indices]
    top_importances = importances[indices]
    
    # Plot
    plt.figure(figsize=(12, 8))
    plt.barh(range(len(top_features)), top_importances, color='steelblue')
    plt.yticks(range(len(top_features)), top_features)
    plt.xlabel('Importance Score', fontsize=12)
    plt.title('Top 20 Most Important Features (Random Forest)', fontsize=14, fontweight='bold')
    plt.gca().invert_yaxis()
    plt.tight_layout()
    plt.savefig(Config.IMPORTANCE_FILE, dpi=100, bbox_inches='tight')
    plt.close()
    
    log.info(f"Saved: {Config.IMPORTANCE_FILE}")
    print(f"  Feature importance saved: {Config.IMPORTANCE_FILE.name}")
    
    # Print top 10
    print(f"\n  TOP 10 MOST IMPORTANT FEATURES:")
    for i, (feat, imp) in enumerate(zip(top_features[:10], top_importances[:10]), 1):
        print(f"    {i:2d}. {feat:<40} {imp:.4f}")


def generate_evaluation_report(
    metrics: Dict,
    ensemble: Dict,
    output_path: Path
) -> None:
    """
    Generate comprehensive text report.
    """
    print_subheader("STAGE 6/6: GENERATING REPORT")
    
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AEGIS AI v2 - EVALUATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Generated       : {datetime.now().isoformat()}\n")
        f.write(f"Model version   : {ensemble.get('version', 'unknown')}\n")
        f.write(f"Trained at      : {ensemble.get('trained_at', 'unknown')}\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("OVERALL PERFORMANCE\n")
        f.write("-" * 80 + "\n")
        f.write(f"Accuracy         : {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)\n")
        f.write(f"Precision (wtd)  : {metrics['precision_weighted']:.4f}\n")
        f.write(f"Recall (wtd)     : {metrics['recall_weighted']:.4f}\n")
        f.write(f"F1-Score (wtd)   : {metrics['f1_weighted']:.4f}\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("PER-CLASS METRICS\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Attack Type':<40} {'Precision':>10} {'Recall':>10} {'F1':>10} {'Support':>10}\n")
        f.write(f"{'-' * 80}\n")
        
        for label, m in metrics['per_class'].items():
            f.write(
                f"{label:<40} "
                f"{m['precision']:>10.4f} "
                f"{m['recall']:>10.4f} "
                f"{m['f1']:>10.4f} "
                f"{m['support']:>10,}\n"
            )
        
        f.write(f"\n{'MACRO AVERAGE':<40} "
                f"{metrics['precision_macro']:>10.4f} "
                f"{metrics['recall_macro']:>10.4f} "
                f"{metrics['f1_macro']:>10.4f}\n")
        f.write(f"{'WEIGHTED AVERAGE':<40} "
                f"{metrics['precision_weighted']:>10.4f} "
                f"{metrics['recall_weighted']:>10.4f} "
                f"{metrics['f1_weighted']:>10.4f}\n")
    
    log.info(f"Report saved: {output_path}")
    print(f"\n  Report saved: {output_path.name}")


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main() -> int:
    """Execute the complete evaluation pipeline."""
    start_time = datetime.now()
    
    print_header("AEGIS AI v2 - MODEL EVALUATION")
    print(f" Started    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Test file  : {Config.TEST_FILE}")
    print(f" Model      : {Config.ENSEMBLE_FILE}")
    
    try:
        # Stage 1: Load
        X_test, y_test, ensemble = load_test_data_and_models()
        feature_names = X_test.columns.tolist()
        
        # Stage 2: Preprocess
        X_test_scaled, y_test_encoded = preprocess_test_data(
            X_test, y_test, ensemble
        )
        
        # Stage 3: Predict
        predictions, probabilities = make_ensemble_predictions(
            X_test_scaled, ensemble
        )
        
        # Stage 4: Metrics
        metrics = calculate_metrics(
            y_test_encoded,
            predictions,
            ensemble['label_encoder']
        )
        
        # Stage 5: Visualizations
        generate_confusion_matrix(
            y_test_encoded,
            predictions,
            ensemble['label_encoder']
        )
        generate_feature_importance(ensemble, feature_names)
        
        # Stage 6: Report
        generate_evaluation_report(
            metrics=metrics,
            ensemble=ensemble,
            output_path=Config.REPORT_FILE
        )
        
        # Summary
        elapsed = datetime.now() - start_time
        
        print_header("EVALUATION COMPLETE")
        print(f" Execution time : {elapsed.total_seconds():.2f} seconds")
        print(f" Test accuracy  : {metrics['accuracy']:.4f} ({metrics['accuracy']*100:.2f}%)")
        print(f" F1-Score (wtd) : {metrics['f1_weighted']:.4f}")
        print(f"\n Generated files:")
        print(f"   - {Config.REPORT_FILE.name}")
        print(f"   - {Config.CM_PLOT_FILE.name}")
        print(f"   - {Config.IMPORTANCE_FILE.name}")
        print(f"\n DAY 1 COMPLETE! Your model is ready.")
        print(f"{'=' * Config.LINE_WIDTH}\n")
        
        return 0
    
    except Exception as e:
        log.error(f"Evaluation failed: {e}", exc_info=True)
        return 1


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    sys.exit(main())