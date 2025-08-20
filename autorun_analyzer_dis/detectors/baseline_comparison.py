"""
Baseline comparison detector - moved from baseline.py
"""

import pandas as pd
from ..core.baseline import load_baseline, compare_against_baseline


def detect_baseline_deviations(df: pd.DataFrame, baseline_csv: str = None) -> pd.DataFrame:
    """
    Detect deviations from baseline using existing baseline comparison logic.
    
    Args:
        df: Input DataFrame
        baseline_csv: Path to baseline CSV file
        
    Returns:
        DataFrame with baseline deviation findings
    """
    if not baseline_csv:
        return pd.DataFrame()
    
    try:
        # Load baseline data
        baseline_paths, baseline_hash_by_path = load_baseline(baseline_csv)
        
        # Compare against baseline
        df_baseline = compare_against_baseline(df, baseline_paths, baseline_hash_by_path)
        
        if len(df_baseline) > 0:
            # Standardize the output format
            if "baseline_reason" in df_baseline.columns:
                df_baseline.rename(columns={"baseline_reason": "detection_reason"}, inplace=True)
            df_baseline.insert(len(df_baseline.columns), "detection_type", "Baseline Deviation")
        
        return df_baseline
        
    except Exception as e:
        print(f"[!] Baseline comparison failed: {e}")
        return pd.DataFrame()