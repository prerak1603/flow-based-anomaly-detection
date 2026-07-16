"""
================================================================================
AEGIS AI v2 - Network Intrusion Detection System
================================================================================

Module      : 01_explore_data.py
Description : Data exploration pipeline for CIC-IDS-2017 dataset
Author      : Prerak Nain
Version     : 2.0.0
Created     : 2026
License     : MIT
Repository  : github.com/prerak1603/flow-based-anomaly-detection

--------------------------------------------------------------------------------
PURPOSE
--------------------------------------------------------------------------------
This module performs comprehensive exploratory data analysis (EDA) on the
CIC-IDS-2017 dataset. It ingests raw CSV files, consolidates them into a
unified DataFrame, profiles the data distribution, identifies quality issues,
and generates a structured exploration report for downstream cleaning and
model training stages.

--------------------------------------------------------------------------------
PIPELINE OVERVIEW
--------------------------------------------------------------------------------
    [1] File Discovery       -> Locate all CSV files in data directory
    [2] Ingestion            -> Load CSVs with error handling
    [3] Consolidation        -> Merge into unified DataFrame
    [4] Schema Normalization -> Clean column names (strip whitespace)
    [5] Label Analysis       -> Attack type distribution
    [6] Quality Assessment   -> Missing values, infinities, duplicates
    [7] Report Generation    -> Persistent exploration artifact

--------------------------------------------------------------------------------
OUTPUTS
--------------------------------------------------------------------------------
    - Console: Real-time progress and statistics
    - File   : new_results/day1_exploration_report.txt
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
    """Central configuration for the exploration pipeline."""
    
    PROJECT_ROOT = Path.home() / "cic_ids_project"
    DATA_DIR     = PROJECT_ROOT / "csv_pcap"
    OUTPUT_DIR   = PROJECT_ROOT / "new_results"
    REPORT_FILE  = OUTPUT_DIR / "day1_exploration_report.txt"
    
    EXPECTED_FILES = 8
    LABEL_COLUMN   = "Label"
    
    # Display settings
    LINE_WIDTH   = 80
    SECTION_CHAR = "="
    DIVIDER_CHAR = "-"


# ==============================================================================
# LOGGING SETUP
# ==============================================================================

def setup_logger() -> logging.Logger:
    """Configure structured logging for the pipeline."""
    logger = logging.getLogger("AegisAI.EDA")
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
    """Print a formatted section header."""
    print(f"\n{char * Config.LINE_WIDTH}")
    print(f" {title}")
    print(f"{char * Config.LINE_WIDTH}")


def print_subheader(title: str) -> None:
    """Print a formatted subsection header."""
    print(f"\n{Config.DIVIDER_CHAR * Config.LINE_WIDTH}")
    print(f" {title}")
    print(f"{Config.DIVIDER_CHAR * Config.LINE_WIDTH}")


def format_size(bytes_val: float) -> str:
    """Convert bytes to human-readable format."""
    for unit in ['B', 'KB', 'MB', 'GB']:
        if bytes_val < 1024.0:
            return f"{bytes_val:.2f} {unit}"
        bytes_val /= 1024.0
    return f"{bytes_val:.2f} TB"


# ==============================================================================
# CORE PIPELINE FUNCTIONS
# ==============================================================================

def discover_csv_files(data_dir: Path) -> List[Path]:
    """
    Discover all CSV files in the data directory.
    
    Args:
        data_dir: Path to directory containing CSV files
    
    Returns:
        Sorted list of CSV file paths
    
    Raises:
        FileNotFoundError: If data directory doesn't exist
        ValueError: If no CSV files found
    """
    if not data_dir.exists():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")
    
    csv_files = sorted(data_dir.glob("*.csv"))
    
    if not csv_files:
        raise ValueError(f"No CSV files found in {data_dir}")
    
    return csv_files


def display_file_inventory(csv_files: List[Path]) -> None:
    """Display discovered files with size information."""
    print_subheader(f"STAGE 1/6: FILE DISCOVERY ({len(csv_files)} files)")
    
    total_size = 0
    for idx, filepath in enumerate(csv_files, start=1):
        size_bytes = filepath.stat().st_size
        total_size += size_bytes
        
        print(
            f"  [{idx}/{len(csv_files)}] "
            f"{filepath.name[:55]:<55} "
            f"{format_size(size_bytes):>10}"
        )
    
    print(f"\n  Total data size: {format_size(total_size)}")


def load_csv_files(csv_files: List[Path]) -> List[pd.DataFrame]:
    """
    Load CSV files with robust error handling.
    
    Args:
        csv_files: List of CSV file paths
    
    Returns:
        List of loaded DataFrames
    """
    print_subheader("STAGE 2/6: DATA INGESTION")
    
    dataframes = []
    failed_files = []
    
    for idx, filepath in enumerate(csv_files, start=1):
        try:
            df = pd.read_csv(filepath, low_memory=False, encoding='utf-8')
            df['__source_file'] = filepath.name
            dataframes.append(df)
            
            print(
                f"  [{idx}/{len(csv_files)}] "
                f"{filepath.name[:45]:<45} "
                f"[OK]  {len(df):>10,} rows"
            )
        
        except UnicodeDecodeError:
            try:
                df = pd.read_csv(filepath, low_memory=False, encoding='latin-1')
                df['__source_file'] = filepath.name
                dataframes.append(df)
                print(
                    f"  [{idx}/{len(csv_files)}] "
                    f"{filepath.name[:45]:<45} "
                    f"[OK]  {len(df):>10,} rows (latin-1)"
                )
            except Exception as e:
                failed_files.append((filepath.name, str(e)))
                print(f"  [{idx}/{len(csv_files)}] {filepath.name} [FAIL] {e}")
        
        except Exception as e:
            failed_files.append((filepath.name, str(e)))
            print(f"  [{idx}/{len(csv_files)}] {filepath.name} [FAIL] {e}")
    
    print(f"\n  Successfully loaded: {len(dataframes)}/{len(csv_files)} files")
    
    if failed_files:
        print(f"  Failed: {len(failed_files)} files")
        for name, error in failed_files:
            print(f"    - {name}: {error}")
    
    return dataframes


def consolidate_dataframes(dataframes: List[pd.DataFrame]) -> pd.DataFrame:
    """
    Consolidate multiple DataFrames into a single DataFrame.
    
    Args:
        dataframes: List of DataFrames to merge
    
    Returns:
        Combined DataFrame
    """
    print_subheader("STAGE 3/6: DATA CONSOLIDATION")
    
    combined = pd.concat(dataframes, ignore_index=True)
    
    print(f"  Combined dimensions : {combined.shape[0]:,} rows x {combined.shape[1]} cols")
    print(f"  Memory footprint    : {format_size(combined.memory_usage(deep=True).sum())}")
    
    return combined


def normalize_schema(df: pd.DataFrame) -> pd.DataFrame:
    """
    Normalize column names by stripping whitespace.
    
    CIC-IDS-2017 columns contain leading/trailing spaces which cause
    subtle bugs. This function standardizes the schema.
    
    Args:
        df: Input DataFrame
    
    Returns:
        DataFrame with normalized column names
    """
    print_subheader("STAGE 4/6: SCHEMA NORMALIZATION")
    
    original_cols = df.columns.tolist()
    df.columns = df.columns.str.strip()
    
    modified_count = sum(1 for o, n in zip(original_cols, df.columns) if o != n)
    
    print(f"  Total columns       : {len(df.columns)}")
    print(f"  Columns modified    : {modified_count}")
    print(f"\n  Sample columns:")
    for col in list(df.columns)[:8]:
        print(f"    - {col}")
    print(f"    ... and {len(df.columns) - 8} more")
    
    return df


def analyze_label_distribution(df: pd.DataFrame) -> pd.Series:
    """
    Analyze the distribution of attack labels.
    
    Args:
        df: DataFrame containing labeled data
    
    Returns:
        Series with label counts
    """
    print_subheader("STAGE 5/6: LABEL DISTRIBUTION ANALYSIS")
    
    if Config.LABEL_COLUMN not in df.columns:
        raise KeyError(f"Label column '{Config.LABEL_COLUMN}' not found")
    
    label_counts = df[Config.LABEL_COLUMN].value_counts()
    total = len(df)
    
    print(f"\n  Total attack categories: {len(label_counts)}\n")
    print(f"  {'Attack Category':<45} {'Count':>12} {'Percentage':>12}")
    print(f"  {Config.DIVIDER_CHAR * 71}")
    
    for label, count in label_counts.items():
        percentage = (count / total) * 100
        print(f"  {label:<45} {count:>12,} {percentage:>11.2f}%")
    
    return label_counts


def assess_data_quality(df: pd.DataFrame) -> Dict[str, any]:
    """
    Perform comprehensive data quality assessment.
    
    Args:
        df: DataFrame to assess
    
    Returns:
        Dictionary containing quality metrics
    """
    print_subheader("STAGE 6/6: DATA QUALITY ASSESSMENT")
    
    # Missing values analysis
    missing = df.isnull().sum()
    cols_with_missing = missing[missing > 0].sort_values(ascending=False)
    
    # Infinity values analysis
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    inf_mask = np.isinf(df[numeric_cols])
    inf_count = inf_mask.sum().sum()
    cols_with_inf = inf_mask.sum()
    cols_with_inf = cols_with_inf[cols_with_inf > 0].sort_values(ascending=False)
    
    # Duplicate analysis
    duplicate_count = df.duplicated().sum()
    duplicate_pct = (duplicate_count / len(df)) * 100
    
    # Memory analysis
    memory_bytes = df.memory_usage(deep=True).sum()
    
    # Report findings
    print(f"\n  MISSING VALUES:")
    print(f"    Affected columns  : {len(cols_with_missing)}")
    if len(cols_with_missing) > 0:
        print(f"    Top offenders     :")
        for col, count in cols_with_missing.head(5).items():
            print(f"      - {col}: {count:,}")
    
    print(f"\n  INFINITY VALUES:")
    print(f"    Total occurrences : {inf_count:,}")
    print(f"    Affected columns  : {len(cols_with_inf)}")
    if len(cols_with_inf) > 0:
        print(f"    Top offenders     :")
        for col, count in cols_with_inf.head(5).items():
            print(f"      - {col}: {count:,}")
    
    print(f"\n  DUPLICATES:")
    print(f"    Duplicate rows    : {duplicate_count:,} ({duplicate_pct:.2f}%)")
    
    print(f"\n  MEMORY:")
    print(f"    Total footprint   : {format_size(memory_bytes)}")
    
    return {
        'missing_columns': len(cols_with_missing),
        'infinity_values': inf_count,
        'infinity_columns': len(cols_with_inf),
        'duplicate_rows': duplicate_count,
        'duplicate_percentage': duplicate_pct,
        'memory_bytes': memory_bytes,
        'top_missing': cols_with_missing.head(10).to_dict(),
        'top_infinity': cols_with_inf.head(10).to_dict()
    }


def generate_report(
    df: pd.DataFrame,
    label_counts: pd.Series,
    quality_metrics: Dict,
    output_path: Path
) -> None:
    """
    Generate structured exploration report.
    
    Args:
        df: The DataFrame that was analyzed
        label_counts: Attack label distribution
        quality_metrics: Data quality assessment results
        output_path: Where to save the report
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_path, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("AEGIS AI v2 - EXPLORATION REPORT\n")
        f.write("=" * 80 + "\n\n")
        
        f.write(f"Generated       : {datetime.now().isoformat()}\n")
        f.write(f"Dataset         : CIC-IDS-2017\n")
        f.write(f"Purpose         : Data profiling for v2 model training\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("DATASET OVERVIEW\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total records   : {len(df):,}\n")
        f.write(f"Total features  : {len(df.columns)}\n")
        f.write(f"Attack types    : {len(label_counts)}\n")
        f.write(f"Memory size     : {format_size(quality_metrics['memory_bytes'])}\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("DATA QUALITY METRICS\n")
        f.write("-" * 80 + "\n")
        f.write(f"Columns with nulls    : {quality_metrics['missing_columns']}\n")
        f.write(f"Infinity values       : {quality_metrics['infinity_values']:,}\n")
        f.write(f"Columns with infinity : {quality_metrics['infinity_columns']}\n")
        f.write(f"Duplicate rows        : {quality_metrics['duplicate_rows']:,} "
                f"({quality_metrics['duplicate_percentage']:.2f}%)\n\n")
        
        f.write("-" * 80 + "\n")
        f.write("LABEL DISTRIBUTION\n")
        f.write("-" * 80 + "\n")
        for label, count in label_counts.items():
            pct = (count / len(df)) * 100
            f.write(f"{label:<45} {count:>12,}  {pct:>6.2f}%\n")
        
        f.write("\n" + "-" * 80 + "\n")
        f.write("FEATURE COLUMNS\n")
        f.write("-" * 80 + "\n")
        for idx, col in enumerate(df.columns, 1):
            f.write(f"  [{idx:3d}] {col}\n")
    
    log.info(f"Report saved to: {output_path}")


# ==============================================================================
# MAIN PIPELINE
# ==============================================================================

def main() -> int:
    """
    Execute the complete exploration pipeline.
    
    Returns:
        Exit code (0 for success, 1 for failure)
    """
    start_time = datetime.now()
    
    print_header("AEGIS AI v2 - DATA EXPLORATION PIPELINE")
    print(f" Started    : {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f" Data dir   : {Config.DATA_DIR}")
    print(f" Output dir : {Config.OUTPUT_DIR}")
    
    try:
        # Stage 1: Discovery
        csv_files = discover_csv_files(Config.DATA_DIR)
        display_file_inventory(csv_files)
        
        # Stage 2: Ingestion
        dataframes = load_csv_files(csv_files)
        
        if not dataframes:
            log.error("No data loaded. Aborting.")
            return 1
        
        # Stage 3: Consolidation
        combined_df = consolidate_dataframes(dataframes)
        
        # Stage 4: Schema normalization
        combined_df = normalize_schema(combined_df)
        
        # Stage 5: Label analysis
        label_counts = analyze_label_distribution(combined_df)
        
        # Stage 6: Quality assessment
        quality_metrics = assess_data_quality(combined_df)
        
        # Generate report
        print_subheader("REPORT GENERATION")
        generate_report(
            df=combined_df,
            label_counts=label_counts,
            quality_metrics=quality_metrics,
            output_path=Config.REPORT_FILE
        )
        
        # Final summary
        elapsed = datetime.now() - start_time
        
        print_header("EXPLORATION COMPLETE", char="=")
        print(f" Execution time    : {elapsed.total_seconds():.2f} seconds")
        print(f" Records processed : {len(combined_df):,}")
        print(f" Features analyzed : {len(combined_df.columns)}")
        print(f" Attack categories : {len(label_counts)}")
        print(f"\n Next step: Data cleaning pipeline (02_clean_data.py)")
        print(f"{Config.SECTION_CHAR * Config.LINE_WIDTH}\n")
        
        return 0
    
    except Exception as e:
        log.error(f"Pipeline failed: {e}", exc_info=True)
        return 1


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    sys.exit(main())