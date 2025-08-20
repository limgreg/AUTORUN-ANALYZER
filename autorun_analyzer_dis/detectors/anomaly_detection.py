"""
Anomaly detection using PySAD - moved from pysad.py
"""

import pandas as pd
import numpy as np
import math
from ..core.pysad import build_features_for_pysad, pysad_scores


def detect_anomalies_pysad(df: pd.DataFrame, method: str = "hst", top_pct: float = 3.0) -> pd.DataFrame:
    """
    Detect statistical anomalies using PySAD.
    
    Args:
        df: Input DataFrame
        method: PySAD method ('hst' or 'loda')
        top_pct: Percentage of top scores to return
        
    Returns:
        DataFrame with anomaly findings (top percentile only)
    """
    try:
        # Build features and compute scores
        feats = build_features_for_pysad(df)
        pysad_scores_array = pysad_scores(feats, method=method)
        
        # Add scores to dataframe
        df_scored = df.copy()
        df_scored.insert(len(df_scored.columns), "pysad_score", np.round(pysad_scores_array, 3))
        
        # Get top percentile
        k = max(1, int(math.ceil(len(df_scored) * (top_pct / 100.0))))
        thresh = np.partition(pysad_scores_array, -k)[-k] if len(pysad_scores_array) else float("inf")
        
        # Filter to top scores only
        df_top = df_scored[pysad_scores_array >= thresh].copy()
        df_top = df_top.sort_values("pysad_score", ascending=False)
        
        if len(df_top) > 0:
            # Add detection details
            reasons = []
            for idx in df_top.index:
                score = df_top.at[idx, "pysad_score"]
                reasons.append(f"Statistical anomaly detected (score: {score}, method: {method})")
            
            df_top.insert(len(df_top.columns), "detection_reason", reasons)
            df_top.insert(len(df_top.columns), "detection_type", "Statistical Anomaly")
        
        return df_top
        
    except RuntimeError as e:
        print(f"[!] PySAD anomaly detection failed: {e}")
        return pd.DataFrame()