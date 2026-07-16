"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 03_prepare_training.py
Description : Balanced sampling and train/test split
Author      : Prerak Nain
Version     : 2.0.0

--------------------------------------------------------------------------------
PURPOSE
--------------------------------------------------------------------------------
Takes cleaned dataset (imbalanced), creates balanced training data.
Splits into train (80%) and test (20%).

--------------------------------------------------------------------------------
PIPELINE
--------------------------------------------------------------------------------
    [1] Load cleaned dataset
    [2] Balance classes (sample per attack type)
    [3] Split features and labels
    [4] Train/test split (80/20)
    [5] Save training data
================================================================================
"""

import sys
import logging
from pathlib import Path
from datetime import datetime
from typing import Tuple, Dict

import numpy as np
import pandas as pd
from sklearn.model_selection import train_test_split


# ==============================================================================
# CONFIGURATION
# ==============================================================================

class Config:
    """Configuration for training data preparation."""
    
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    OUTPUT_DIR   = PROJECT_ROOT / "new_results"
    
    INPUT_FILE   = OUTPUT_DIR / "cleaned_dataset.parquet"
    TRAIN_FILE   = OUTPUT_DIR / "train_data.parquet"
    TEST_FILE    = OUTPUT_DIR / "test_data.parquet"
    REPORT_FILE  = OUTPUT_DIR / "day1_sampling_report.txt"
    
    LABEL_COLUMN = "Label"
    
    # Sampling strategy
    # For classes with MORE than this, sample down to this
    # For classes with LESS than this, keep all
    SAMPLES_PER_CLASS = 50000
    
    # Train/test split ratio
    TEST_SIZE    = 0.2  # 20% for testing
    RANDOM_STATE = 42   # For reproducibility
    
    LINE_WIDTH = 80


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logger() -> logging.Logger:
    logger = logging.getLogger("AegisAI.Sampling")
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


def format_size(bytes_val: float) -> str:
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"


# ==============================================================================
# PIPELINE STAGES
# ==============================================================================

def load_cleaned_dataset() -> pd.DataFrame:
    """
    Load the cleaned dataset from Parquet.
    
    Returns:
        Cleaned DataFrame ready for sampling
    """
    print_subheader("STAGE 1/5: LOADING CLEANED DATASET")
    
    if not Config.INPUT_FILE.exists():
        raise FileNotFoundError(
            f"Cleaned dataset not found: {Config.INPUT_FILE}\n"
            "Please run 02_clean_data.py first."
        )
    
    log.info(f"Loading: {Config.INPUT_FILE}")
    df = pd.read_parquet(Config.INPUT_FILE)
    
    print(f"\n  Records loaded : {len(df):,}")
    print(f"  Features       : {len(df.columns)}")
    print(f"  Attack types   : {df[Config.LABEL_COLUMN].nunique()}")
    print(f"  Memory         : {format_size(df.memory_usage(deep=True).sum())}")
    
    return df


def balance_classes(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict]:
    """
    Balance classes by sampling.
    
    Strategy:
        - For classes with MORE than SAMPLES_PER_CLASS: 
          random sample down to SAMPLES_PER_CLASS
        - For classes with LESS than SAMPLES_PER_CLASS:
          keep all samples
    
    Args:
        df: Cleaned DataFrame
    
    Returns:
        Tuple of (balanced DataFrame, sampling summary)
    """
    print_subheader("STAGE 2/5: CLASS BALANCING")
    
    # Get counts before sampling
    before_counts = df[Config.LABEL_COLUMN].value_counts()
    
    log.info(f"Balancing {len(before_counts)} classes")
    log.info(f"Target samples per class: {Config.SAMPLES_PER_CLASS:,}")
    
    balanced_dfs = []
    summary = {}
    
    print(f"\n  {'Attack Type':<40} {'Before':>10} {'After':>10} {'Kept':>8}")
    print(f"  {'-' * 68}")
    
    for label in before_counts.index:
        # Get all rows for this class
        class_df = df[df[Config.LABEL_COLUMN] == label]
        original_count = len(class_df)
        
        # Decide how many to keep
        if original_count > Config.SAMPLES_PER_CLASS:
            # Too many - random sample down
            sampled = class_df.sample(
                n=Config.SAMPLES_PER_CLASS,
                random_state=Config.RANDOM_STATE
            )
            action = "sampled"
        else:
            # Too few - keep all
            sampled = class_df
            action = "kept all"
        
        balanced_dfs.append(sampled)
        summary[label] = {
            'before': original_count,
            'after': len(sampled),
            'action': action
        }
        
        # Print row
        pct = (len(sampled) / original_count) * 100
        print(f"  {label:<40} {original_count:>10,} {len(sampled):>10,} {pct:>7.1f}%")
    
    # Combine all balanced samples
    balanced_df = pd.concat(balanced_dfs, ignore_index=True)
    
    # Shuffle the combined DataFrame
    balanced_df = balanced_df.sample(
        frac=1,
        random_state=Config.RANDOM_STATE
    ).reset_index(drop=True)
    
    print(f"\n  Total records after balancing: {len(balanced_df):,}")
    
    return balanced_df, summary


def separate_features_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """
    Separate features (X) from labels (y).
    
    Args:
        df: Balanced DataFrame
    
    Returns:
        Tuple of (features DataFrame, labels Series)
    """
    print_subheader("STAGE 3/5: SEPARATING FEATURES AND LABELS")
    
    # Drop columns that shouldn't be features
    cols_to_drop = [Config.LABEL_COLUMN, '__source_file']
    
    # Only drop columns that exist
    cols_to_drop = [c for c in cols_to_drop if c in df.columns]
    
    X = df.drop(columns=cols_to_drop)
    y = df[Config.LABEL_COLUMN]
    
    # Keep only numeric columns for features
    X = X.select_dtypes(include=[np.number])
    
    log.info(f"Features shape : {X.shape}")
    log.info(f"Labels shape   : {y.shape}")
    
    print(f"\n  Feature columns : {len(X.columns)}")
    print(f"  Sample features:")
    for col in list(X.columns)[:5]:
        print(f"    - {col}")
    print(f"    ... and {len(X.columns) - 5} more")
    
    return X, y


def split_train_test(
    X: pd.DataFrame,
    y: pd.Series
) -> Tuple[pd.DataFrame, pd.DataFrame, pd.Series, pd.Series]:
    """
    Split data into training and testing sets.
    
    Uses stratified splitting to preserve class distribution
    in both train and test sets.
    
    Args:
        X: Features
        y: Labels
    
    Returns:
        Tuple of (X_train, X_test, y_train, y_test)
    """
    print_subheader("STAGE 4/5: TRAIN/TEST SPLIT")
    
    log.info(f"Test size: {Config.TEST_SIZE * 100:.0f}%")
    log.info(f"Random state: {Config.RANDOM_STATE}")
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y,
        test_size=Config.TEST_SIZE,
        random_state=Config.RANDOM_STATE,
        stratify=y  # Preserve class distribution
    )
    
    print(f"\n  Training set   : {len(X_train):,} records")
    print(f"  Testing set    : {len(X_test):,} records")
    print(f"  Total          : {len(X_train) + len(X_test):,} records")
    
    print(f"\n  Training distribution:")
    train_dist = y_train.value_counts()
    for label, count in train_dist.head(5).items():
        pct = (count / len(y_train)) * 100
        print(f"    {label:<40} {count:>8,} ({pct:>5.2f}%)")
    if len(train_dist) > 5:
        print(f"    ... and {len(train_dist) - 5} more classes")
    
    return X_train, X_test, y_train, y_test


def persist_datasets(
    X_train: pd.DataFrame,
    X_test: pd.DataFrame,
    y_train: pd.Series,
    y_test: pd.Series
) -> None:
    """
    Save training and testing datasets to Parquet files.
    
    Args:
        X_train, X_test, y_train, y_test: Split datasets
    """
    print_subheader("STAGE 5/5: SAVING DATASETS")
    
    # Combine features and labels for saving
    train_df = X_train.copy()
    train_df[Config.LABEL_COLUMN] = y_train.values
    
    test_df = X_test.copy()
    test_df[Config.LABEL_COLUMN] = y_test.values
    
    # Save training data
    train_df.to_parquet(
        Config.TRAIN_FILE,
        engine='pyarrow',
        compression='snappy',
        index=False
    )
    
    # Save test data
    test_df.to_parquet(
        Config.TEST_FILE,
        engine='pyarrow',
        compression='snappy',
        index=False
    )
    
    train_size = Config.TRAIN_FILE.stat().st_size
    test_size = Config.TEST_FILE.stat().st_size
    
    print(f"\n  Training data saved:")
    print(f"    File: {Config.TRAIN_FILE.name}")
    print(f"    Size: {format_size(train_size)}")
    print(f"    Records: {len(train_df):,}")
    
    print(f"\n  Testing data saved:")
    print(f"    File: {Config.TEST_FILE.name}")
    print(f"    Size: {format_size(test_size)}")
    print(f"    Records: {len(test_df):,}")


def generate_sampling_report(
    original_stats: Dict,
    sampling_summary: Dict,
    train_size: int,
    test_size: int,
    output_path: Path
) -> None:
    """
    Generate audit report for sampling process.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AEGIS AI v2 - SAMPLING REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Generated       : {datetime.now().isoformat()}\n")
        f.write(f"Pipeline stage  : Day 1 - Hour 5 (Sampling)\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("SAMPLING STRATEGY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Samples per class  : {Config.SAMPLES_PER_CLASS:,}\n")
        f.write(f"Test size          : {Config.TEST_SIZE * 100:.0f}%\n")
        f.write(f"Random state       : {Config.RANDOM_STATE}\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("CLASS BALANCING RESULTS\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Attack Type':<40} {'Before':>10} {'After':>10} {'Action':>15}\n")
        f.write(f"{'-' * 76}\n")
        for label, stats in sampling_summary.items():
            f.write(
                f"{label:<40} "
                f"{stats['before']:>10,} "
                f"{stats['after']:>10,} "
                f"{stats['action']:>15}\n"
            )
        
        f.write("\n" + "-" * 80 + "\n")
        f.write("FINAL SPLIT\n")
        f.write("-" * 80 + "\n")
        f.write(f"Training set   : {train_size:,} records\n")
        f.write(f"Testing set    : {test_size:,} records\n")
        f.write(f"Total          : {train_size + test_size:,} records\n")
    
    log.info(f"Report saved: {output_path}")


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main() -> int:
    """
    Execute the complete sampling pipeline.
    """
    start_time = datetime.now()
    
    print_header("AEGIS AI v2 - TRAINING DATA PREPARATION")
    print(f" Started    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Input      : {Config.INPUT_FILE}")
    print(f" Output dir : {Config.OUTPUT_DIR}")
    
    try:
        # Stage 1: Load
        df = load_cleaned_dataset()
        original_stats = {
            'records': len(df),
            'features': len(df.columns),
            'labels': df[Config.LABEL_COLUMN].nunique()
        }
        
        # Stage 2: Balance
        df_balanced, sampling_summary = balance_classes(df)
        
        # Stage 3: Separate
        X, y = separate_features_labels(df_balanced)
        
        # Stage 4: Split
        X_train, X_test, y_train, y_test = split_train_test(X, y)
        
        # Stage 5: Save
        persist_datasets(X_train, X_test, y_train, y_test)
        
        # Report
        print_subheader("GENERATING SAMPLING REPORT")
        generate_sampling_report(
            original_stats=original_stats,
            sampling_summary=sampling_summary,
            train_size=len(X_train),
            test_size=len(X_test),
            output_path=Config.REPORT_FILE
        )
        
        # Summary
        elapsed = datetime.now() - start_time
        
        print_header("SAMPLING COMPLETE")
        print(f" Execution time : {elapsed.total_seconds():.2f} seconds")
        print(f" Training data  : {len(X_train):,} records")
        print(f" Testing data   : {len(X_test):,} records")
        print(f" Ready for      : Model training (04_train_ensemble.py)")
        print(f"{'=' * Config.LINE_WIDTH}\n")
        
        return 0
    
    except Exception as e:
        log.error(f"Pipeline failed: {e}", exc_info=True)
        return 1


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    sys.exit(main())