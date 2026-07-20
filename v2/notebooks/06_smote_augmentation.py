"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 06_smote_augmentation.py
Description : SMOTE-based class balancing for rare attack classes
Author      : Prerak Nain
Version     : 2.0.0

--------------------------------------------------------------------------------
PURPOSE
--------------------------------------------------------------------------------
Addresses severe class imbalance for Heartbleed (9 samples) and Infiltration
(29 samples) using adaptive k-neighbor SMOTE — applied WITHIN a stratified
split to avoid data leakage.

--------------------------------------------------------------------------------
WHY ADAPTIVE K-NEIGHBORS
--------------------------------------------------------------------------------
Standard SMOTE defaults to k_neighbors=5, which FAILS if a class has fewer
than 6 samples (Heartbleed has 9 total, meaning only ~7 in the training
portion after split). We dynamically set k_neighbors = min(5, n_samples - 1)
per class to guarantee SMOTE can run.
================================================================================
"""

import sys
import logging
from pathlib import Path
from datetime import datetime
from collections import Counter

import numpy as np
import pandas as pd
from imblearn.over_sampling import SMOTE


# ==============================================================================
# CONFIGURATION
# ==============================================================================

class Config:
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    RESULTS_DIR  = PROJECT_ROOT / "v2" / "results"
    
    TRAIN_FILE       = RESULTS_DIR / "train_data.parquet"
    SMOTE_TRAIN_FILE = RESULTS_DIR / "train_data_smote.parquet"
    REPORT_FILE      = RESULTS_DIR / "day2_smote_report.txt"
    
    LABEL_COLUMN = "Label"
    
    # Classes we specifically want to boost
    TARGET_CLASSES = ["Heartbleed", "Infiltration"]
    
    # How many synthetic samples to aim for, per target class
    TARGET_SAMPLE_COUNT = 200
    
    RANDOM_STATE = 42
    LINE_WIDTH   = 80


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logger():
    logger = logging.getLogger("AegisAI.SMOTE")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(
            fmt="[%(asctime)s] %(message)s", datefmt="%H:%M:%S"
        ))
        logger.addHandler(handler)
    return logger

log = setup_logger()


def print_header(title):
    print(f"\n{'=' * Config.LINE_WIDTH}\n {title}\n{'=' * Config.LINE_WIDTH}")

def print_subheader(title):
    print(f"\n{'-' * Config.LINE_WIDTH}\n {title}\n{'-' * Config.LINE_WIDTH}")


# ==============================================================================
# PIPELINE
# ==============================================================================

def load_training_data():
    print_subheader("STAGE 1/4: LOADING TRAINING DATA")
    
    df = pd.read_parquet(Config.TRAIN_FILE, engine='fastparquet')
    
    print(f"\n  Records: {len(df):,}")
    print(f"  Current distribution:")
    counts = df[Config.LABEL_COLUMN].value_counts()
    for label, count in counts.items():
        print(f"    {label:<20} {count:>8,}")
    
    return df


def apply_adaptive_smote(df):
    print_subheader("STAGE 2/4: APPLYING ADAPTIVE SMOTE")
    
    X = df.drop(columns=[Config.LABEL_COLUMN])
    y = df[Config.LABEL_COLUMN]
    
    original_counts = Counter(y)
    
    # Build sampling_strategy dict — only boost our target rare classes
    sampling_strategy = {}
    for cls in Config.TARGET_CLASSES:
        current_count = original_counts.get(cls, 0)
        if current_count > 0:
            target = min(Config.TARGET_SAMPLE_COUNT, current_count * 20)
            sampling_strategy[cls] = target
            log.info(f"{cls}: {current_count} -> {target} (target)")
    
    if not sampling_strategy:
        raise ValueError("No target classes found in training data!")
    
    # Adaptive k_neighbors: smallest class determines the safe k
    min_class_size = min(
        original_counts[cls] for cls in Config.TARGET_CLASSES 
        if cls in original_counts
    )
    k_neighbors = max(1, min(5, min_class_size - 1))
    
    print(f"\n  Smallest target class size: {min_class_size}")
    print(f"  Adaptive k_neighbors: {k_neighbors}")
    print(f"  (Standard SMOTE default is 5 — would fail here)")
    
    smote = SMOTE(
        sampling_strategy=sampling_strategy,
        k_neighbors=k_neighbors,
        random_state=Config.RANDOM_STATE
    )
    
    log.info("Running SMOTE...")
    X_resampled, y_resampled = smote.fit_resample(X, y)
    
    new_counts = Counter(y_resampled)
    
    print(f"\n  RESULTS:")
    print(f"  {'Class':<20} {'Before':>10} {'After':>10} {'Added':>10}")
    print(f"  {'-' * 52}")
    for cls in Config.TARGET_CLASSES:
        before = original_counts.get(cls, 0)
        after = new_counts.get(cls, 0)
        print(f"  {cls:<20} {before:>10,} {after:>10,} {after-before:>10,}")
    
    print(f"\n  Total records: {len(y):,} -> {len(y_resampled):,}")
    
    # Reassemble into a DataFrame
    df_resampled = X_resampled.copy()
    df_resampled[Config.LABEL_COLUMN] = y_resampled
    
    return df_resampled, original_counts, new_counts


def persist_smote_data(df_resampled):
    print_subheader("STAGE 3/4: SAVING SMOTE-AUGMENTED DATA")
    
    Config.RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    df_resampled.to_parquet(
        Config.SMOTE_TRAIN_FILE,
        engine='fastparquet',
        index=False
    )
    
    size_mb = Config.SMOTE_TRAIN_FILE.stat().st_size / (1024*1024)
    print(f"\n  Saved: {Config.SMOTE_TRAIN_FILE.name}")
    print(f"  Size: {size_mb:.2f} MB")
    print(f"  Records: {len(df_resampled):,}")


def generate_report(original_counts, new_counts, output_path):
    print_subheader("STAGE 4/4: GENERATING REPORT")
    
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AEGIS AI v2 - SMOTE AUGMENTATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        f.write(f"Generated: {datetime.now().isoformat()}\n\n")
        f.write("BEFORE / AFTER (target classes)\n")
        f.write("-" * 80 + "\n")
        for cls in Config.TARGET_CLASSES:
            before = original_counts.get(cls, 0)
            after = new_counts.get(cls, 0)
            f.write(f"{cls:<20} {before:>10,} -> {after:>10,}\n")
    
    log.info(f"Report saved: {output_path}")


def main():
    start = datetime.now()
    print_header("AEGIS AI v2 - SMOTE AUGMENTATION")
    
    try:
        df = load_training_data()
        df_resampled, orig_counts, new_counts = apply_adaptive_smote(df)
        persist_smote_data(df_resampled)
        generate_report(orig_counts, new_counts, Config.REPORT_FILE)
        
        elapsed = (datetime.now() - start).total_seconds()
        print_header("SMOTE COMPLETE")
        print(f" Time: {elapsed:.2f}s")
        print(f" Next: Retrain ensemble on SMOTE data, compare results")
        print(f"{'=' * Config.LINE_WIDTH}\n")
        return 0
    
    except Exception as e:
        log.error(f"Failed: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())