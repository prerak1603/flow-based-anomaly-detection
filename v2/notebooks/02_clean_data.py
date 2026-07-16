"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 02_clean_data.py
Description : Data cleaning pipeline for CIC-IDS-2017 dataset
Author      : Prerak Nain
Version     : 2.0.0
Created     : 2026
License     : MIT
Repository  : github.com/prerak1603/flow-based-anomaly-detection

--------------------------------------------------------------------------------
PURPOSE
--------------------------------------------------------------------------------
This module transforms raw exploration data into a production-ready dataset.
It handles infinity values, missing data, duplicates, encoding artifacts, and
consolidates related attack labels into unified categories.

--------------------------------------------------------------------------------
CLEANING PIPELINE
--------------------------------------------------------------------------------
    [1] Data Loading         -> Reload combined dataset
    [2] Label Normalization  -> Fix encoding + consolidate variants
    [3] Infinity Handling    -> Replace inf with column max
    [4] Null Handling        -> Impute missing values
    [5] Duplicate Removal    -> Drop identical rows
    [6] Type Optimization    -> Reduce memory footprint
    [7] Persistence          -> Save cleaned dataset (Parquet)

--------------------------------------------------------------------------------
INPUT
--------------------------------------------------------------------------------
    - csv_pcap/*.csv (8 files from CIC-IDS-2017)

--------------------------------------------------------------------------------
OUTPUT
--------------------------------------------------------------------------------
    - new_results/cleaned_dataset.parquet   (efficient columnar format)
    - new_results/day1_cleaning_report.txt  (audit trail)
================================================================================
"""

import os
import sys
import glob
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Tuple, Dict

import numpy as np
import pandas as pd


# ==============================================================================
# CONFIGURATION
# ==============================================================================

class Config:
    """Central configuration for the cleaning pipeline."""
    
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    DATA_DIR     = PROJECT_ROOT / "csv_pcap"
    OUTPUT_DIR   = PROJECT_ROOT / "new_results"
    
    CLEAN_DATA_FILE = OUTPUT_DIR / "cleaned_dataset.parquet"
    REPORT_FILE     = OUTPUT_DIR / "day1_cleaning_report.txt"
    
    LABEL_COLUMN = "Label"
    LINE_WIDTH   = 80
    
    # Label consolidation mapping
    # Merges attack variants into unified categories
    LABEL_MAPPING = {
        # Web attack variants (encoding issues + consolidation)
        "Web Attack \x96 Brute Force":  "Web Attack",
        "Web Attack \x96 XSS":          "Web Attack",
        "Web Attack \x96 Sql Injection":"Web Attack",
        "Web Attack � Brute Force":     "Web Attack",
        "Web Attack � XSS":             "Web Attack",
        "Web Attack � Sql Injection":   "Web Attack",
    }


# ==============================================================================
# LOGGING
# ==============================================================================

def setup_logger() -> logging.Logger:
    """Configure structured logging."""
    logger = logging.getLogger("AegisAI.Cleaning")
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
# UTILITY FUNCTIONS
# ==============================================================================

def print_header(title: str, char: str = "=") -> None:
    print(f"\n{char * Config.LINE_WIDTH}")
    print(f" {title}")
    print(f"{char * Config.LINE_WIDTH}")


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

def load_combined_dataset() -> pd.DataFrame:
    """
    Reload and combine all CSV files.
    
    Returns:
        Combined DataFrame with normalized column names
    """
    print_subheader("STAGE 1/7: LOADING DATASET")
    
    csv_files = sorted(Config.DATA_DIR.glob("*.csv"))
    
    if not csv_files:
        raise ValueError(f"No CSV files found in {Config.DATA_DIR}")
    
    log.info(f"Found {len(csv_files)} CSV files")
    
    dataframes = []
    for idx, filepath in enumerate(csv_files, 1):
        try:
            df = pd.read_csv(filepath, low_memory=False, encoding='utf-8')
        except UnicodeDecodeError:
            df = pd.read_csv(filepath, low_memory=False, encoding='latin-1')
        
        df['__source_file'] = filepath.name
        dataframes.append(df)
        print(f"  [{idx}/{len(csv_files)}] Loaded {filepath.name[:50]:<50} {len(df):>10,} rows")
    
    combined = pd.concat(dataframes, ignore_index=True)
    combined.columns = combined.columns.str.strip()
    
    print(f"\n  Combined shape: {combined.shape[0]:,} x {combined.shape[1]}")
    print(f"  Memory usage  : {format_size(combined.memory_usage(deep=True).sum())}")
    
    return combined


def normalize_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, Dict[str, int]]:
    """
    Normalize attack labels: fix encoding issues and consolidate variants.
    
    Args:
        df: Input DataFrame
    
    Returns:
        Tuple of (cleaned DataFrame, changes summary)
    """
    print_subheader("STAGE 2/7: LABEL NORMALIZATION")
    
    initial_labels = df[Config.LABEL_COLUMN].value_counts()
    log.info(f"Initial unique labels: {len(initial_labels)}")
    
    # Strip whitespace from labels
    df[Config.LABEL_COLUMN] = df[Config.LABEL_COLUMN].str.strip()
    
    # Apply label mapping to fix encoding + consolidate
    changes = {}
    for old_label, new_label in Config.LABEL_MAPPING.items():
        mask = df[Config.LABEL_COLUMN] == old_label
        count = mask.sum()
        if count > 0:
            df.loc[mask, Config.LABEL_COLUMN] = new_label
            changes[f"{old_label} -> {new_label}"] = count
    
    final_labels = df[Config.LABEL_COLUMN].value_counts()
    
    print(f"\n  Labels before : {len(initial_labels)}")
    print(f"  Labels after  : {len(final_labels)}")
    
    if changes:
        print(f"\n  Mappings applied:")
        for mapping, count in changes.items():
            print(f"    {mapping}: {count:,} rows")
    
    print(f"\n  Final distribution:")
    for label, count in final_labels.items():
        pct = (count / len(df)) * 100
        print(f"    {label:<40} {count:>10,} ({pct:>5.2f}%)")
    
    return df, changes


def handle_infinity_values(df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """
    Handle infinity values by replacing with column maximum.
    
    Rationale: Infinities occur from rate calculations (packets/second)
    when duration is zero. Setting to column max preserves signal that
    these are extreme values without breaking downstream ML models.
    
    Args:
        df: Input DataFrame
    
    Returns:
        Tuple of (cleaned DataFrame, count of values replaced)
    """
    print_subheader("STAGE 3/7: INFINITY HANDLING")
    
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    
    # Detect infinity values per column
    inf_counts = {}
    for col in numeric_cols:
        col_inf_count = np.isinf(df[col]).sum()
        if col_inf_count > 0:
            inf_counts[col] = col_inf_count
    
    total_inf = sum(inf_counts.values())
    log.info(f"Detected {total_inf:,} infinity values across {len(inf_counts)} columns")
    
    if inf_counts:
        print(f"\n  Affected columns:")
        for col, count in inf_counts.items():
            print(f"    - {col}: {count:,} infinity values")
        
        # Replace infinities with column max (excluding inf itself)
        for col in inf_counts.keys():
            # Get max of non-infinity values
            finite_max = df[col][np.isfinite(df[col])].max()
            
            # Replace inf with finite_max, -inf with -finite_max
            df[col] = df[col].replace([np.inf], finite_max)
            df[col] = df[col].replace([-np.inf], -finite_max if finite_max != 0 else 0)
        
        print(f"\n  Replaced {total_inf:,} infinity values with column extremes")
    else:
        print(f"\n  No infinity values found")
    
    return df, total_inf


def handle_missing_values(df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """
    Handle missing values through strategic imputation.
    
    Strategy: 
        - Numeric columns: fill with 0 (safe for count-based features)
        - Non-numeric: fill with 'Unknown'
    
    Args:
        df: Input DataFrame
    
    Returns:
        Tuple of (cleaned DataFrame, count of nulls filled)
    """
    print_subheader("STAGE 4/7: MISSING VALUE HANDLING")
    
    missing = df.isnull().sum()
    cols_with_missing = missing[missing > 0]
    total_missing = missing.sum()
    
    log.info(f"Detected {total_missing:,} missing values in {len(cols_with_missing)} columns")
    
    if total_missing > 0:
        print(f"\n  Affected columns:")
        for col, count in cols_with_missing.items():
            print(f"    - {col}: {count:,} nulls")
        
        # Fill numeric columns with 0
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)
        
        # Fill remaining (categorical) with 'Unknown'
        df = df.fillna('Unknown')
        
        print(f"\n  Imputed {total_missing:,} missing values")
    else:
        print(f"\n  No missing values found")
    
    return df, total_missing


def remove_duplicates(df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
    """
    Remove duplicate rows.
    
    Excludes __source_file from duplicate check as same flow can appear
    across files (edge cases at boundaries).
    
    Args:
        df: Input DataFrame
    
    Returns:
        Tuple of (deduplicated DataFrame, count removed)
    """
    print_subheader("STAGE 5/7: DUPLICATE REMOVAL")
    
    initial_count = len(df)
    
    # Check duplicates excluding metadata column
    cols_to_check = [c for c in df.columns if c != '__source_file']
    duplicates_mask = df.duplicated(subset=cols_to_check, keep='first')
    duplicate_count = duplicates_mask.sum()
    
    log.info(f"Detected {duplicate_count:,} duplicate rows ({duplicate_count/initial_count*100:.2f}%)")
    
    if duplicate_count > 0:
        df = df[~duplicates_mask].reset_index(drop=True)
        print(f"\n  Removed {duplicate_count:,} duplicates")
        print(f"  Records: {initial_count:,} -> {len(df):,}")
    else:
        print(f"\n  No duplicates found")
    
    return df, duplicate_count


def optimize_dtypes(df: pd.DataFrame) -> pd.DataFrame:
    """
    Downcast numeric types to reduce memory footprint.
    
    - int64 -> int32/int16 where safe
    - float64 -> float32 where precision allows
    
    Args:
        df: Input DataFrame
    
    Returns:
        Memory-optimized DataFrame
    """
    print_subheader("STAGE 6/7: MEMORY OPTIMIZATION")
    
    initial_memory = df.memory_usage(deep=True).sum()
    log.info(f"Initial memory: {format_size(initial_memory)}")
    
    # Downcast integers
    int_cols = df.select_dtypes(include=['int64']).columns
    for col in int_cols:
        df[col] = pd.to_numeric(df[col], downcast='integer')
    
    # Downcast floats
    float_cols = df.select_dtypes(include=['float64']).columns
    for col in float_cols:
        df[col] = pd.to_numeric(df[col], downcast='float')
    
    final_memory = df.memory_usage(deep=True).sum()
    reduction_pct = ((initial_memory - final_memory) / initial_memory) * 100
    
    print(f"\n  Before: {format_size(initial_memory)}")
    print(f"  After : {format_size(final_memory)}")
    print(f"  Saved : {format_size(initial_memory - final_memory)} ({reduction_pct:.1f}%)")
    
    return df


def persist_dataset(df: pd.DataFrame) -> None:
    """
    Save cleaned dataset in efficient Parquet format.
    
    Parquet advantages:
        - 5-10x smaller than CSV
        - 10-100x faster to read
        - Preserves data types
        - Column-based compression
    
    Args:
        df: Cleaned DataFrame to save
    """
    print_subheader("STAGE 7/7: PERSISTENCE")
    
    Config.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    log.info(f"Saving to: {Config.CLEAN_DATA_FILE}")
    
    df.to_parquet(
        Config.CLEAN_DATA_FILE,
        engine='pyarrow',
        compression='snappy',
        index=False
    )
    
    file_size = Config.CLEAN_DATA_FILE.stat().st_size
    print(f"\n  Format      : Parquet (snappy compression)")
    print(f"  File size   : {format_size(file_size)}")
    print(f"  Records     : {len(df):,}")
    print(f"  Features    : {len(df.columns)}")


def generate_cleaning_report(
    initial_stats: Dict,
    final_stats: Dict,
    label_changes: Dict[str, int],
    output_path: Path
) -> None:
    """
    Generate comprehensive cleaning audit report.
    
    Args:
        initial_stats: Metrics before cleaning
        final_stats: Metrics after cleaning
        label_changes: Label mapping changes applied
        output_path: Where to save the report
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AEGIS AI v2 - DATA CLEANING REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Generated       : {datetime.now().isoformat()}\n")
        f.write(f"Pipeline stage  : Day 1 - Hour 3-4 (Cleaning)\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("BEFORE VS AFTER\n")
        f.write("-" * 80 + "\n")
        f.write(f"{'Metric':<30} {'Before':>15} {'After':>15} {'Change':>15}\n")
        f.write(f"{'-' * 80}\n")
        f.write(f"{'Total records':<30} "
                f"{initial_stats['records']:>15,} "
                f"{final_stats['records']:>15,} "
                f"{final_stats['records'] - initial_stats['records']:>15,}\n")
        f.write(f"{'Total features':<30} "
                f"{initial_stats['features']:>15} "
                f"{final_stats['features']:>15} "
                f"{final_stats['features'] - initial_stats['features']:>15}\n")
        f.write(f"{'Attack categories':<30} "
                f"{initial_stats['labels']:>15} "
                f"{final_stats['labels']:>15} "
                f"{final_stats['labels'] - initial_stats['labels']:>15}\n")
        
        f.write("\n" + "-" * 80 + "\n")
        f.write("CLEANING ACTIONS\n")
        f.write("-" * 80 + "\n")
        f.write(f"Infinity values replaced : {final_stats.get('inf_replaced', 0):,}\n")
        f.write(f"Missing values imputed   : {final_stats.get('nulls_filled', 0):,}\n")
        f.write(f"Duplicates removed       : {final_stats.get('dups_removed', 0):,}\n")
        
        if label_changes:
            f.write("\n" + "-" * 80 + "\n")
            f.write("LABEL CONSOLIDATION\n")
            f.write("-" * 80 + "\n")
            for mapping, count in label_changes.items():
                f.write(f"  {mapping}: {count:,} rows\n")
        
        f.write("\n" + "-" * 80 + "\n")
        f.write("FINAL LABEL DISTRIBUTION\n")
        f.write("-" * 80 + "\n")
        for label, count in final_stats['label_distribution'].items():
            pct = (count / final_stats['records']) * 100
            f.write(f"  {label:<40} {count:>12,}  {pct:>6.2f}%\n")
    
    log.info(f"Report saved: {output_path}")


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main() -> int:
    """
    Execute the complete cleaning pipeline.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    start_time = datetime.now()
    
    print_header("AEGIS AI v2 - DATA CLEANING PIPELINE")
    print(f" Started    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Data dir   : {Config.DATA_DIR}")
    print(f" Output dir : {Config.OUTPUT_DIR}")
    
    try:
        # Stage 1: Load
        df = load_combined_dataset()
        initial_stats = {
            'records': len(df),
            'features': len(df.columns),
            'labels': df[Config.LABEL_COLUMN].nunique()
        }
        
        # Stage 2: Labels
        df, label_changes = normalize_labels(df)
        
        # Stage 3: Infinity
        df, inf_replaced = handle_infinity_values(df)
        
        # Stage 4: Nulls
        df, nulls_filled = handle_missing_values(df)
        
        # Stage 5: Duplicates
        df, dups_removed = remove_duplicates(df)
        
        # Stage 6: Memory
        df = optimize_dtypes(df)
        
        # Stage 7: Save
        persist_dataset(df)
        
        # Final stats
        final_stats = {
            'records': len(df),
            'features': len(df.columns),
            'labels': df[Config.LABEL_COLUMN].nunique(),
            'inf_replaced': inf_replaced,
            'nulls_filled': nulls_filled,
            'dups_removed': dups_removed,
            'label_distribution': df[Config.LABEL_COLUMN].value_counts().to_dict()
        }
        
        # Report
        print_subheader("GENERATING CLEANING REPORT")
        generate_cleaning_report(
            initial_stats=initial_stats,
            final_stats=final_stats,
            label_changes=label_changes,
            output_path=Config.REPORT_FILE
        )
        
        # Summary
        elapsed = datetime.now() - start_time
        
        print_header("CLEANING COMPLETE")
        print(f" Execution time : {elapsed.total_seconds():.2f} seconds")
        print(f" Records        : {initial_stats['records']:,} -> {final_stats['records']:,}")
        print(f" Attack types   : {initial_stats['labels']} -> {final_stats['labels']}")
        print(f" Data quality   : PRODUCTION-READY")
        print(f"\n Next step: Balanced sampling (03_prepare_training.py)")
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