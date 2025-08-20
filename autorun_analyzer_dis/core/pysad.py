"""
PySAD integration for anomaly detection.
"""

import re
import numpy as np
import pandas as pd
from .utils import shannon_entropy
from .unsigned import unsigned_series
from .rules import ZERO_WIDTH, RLO, NBSP, ADS, DEVICE_PREFIX


def build_features_for_pysad(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build numeric feature matrix suitable for PySAD models.
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with numeric features for anomaly detection
    """
    # Find relevant columns
    col_img = next((c for c in df.columns if c.lower() in 
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    col_desc = next((c for c in df.columns if c.lower() in 
                    ['description', 'entry', 'entryname', 'entry name']), None)
    
    # Combine text fields
    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    desc = df[col_desc].astype(str) if col_desc else pd.Series([""] * len(df))
    combined = (text.fillna('') + " " + desc.fillna('')).str.strip()

    # Generate numeric features
    feat = pd.DataFrame({
        "len": combined.apply(len),
        "args": combined.apply(lambda s: len([t for t in re.split(r'\s+', s.strip()) if t])),
        "slashes": combined.str.count(r'[\\/]'),
        "dots": combined.str.count(r'\.'),
        "entropy": combined.apply(shannon_entropy),
        "zwsp": combined.apply(lambda s: 1 if ZERO_WIDTH.search(s) else 0),
        "rlo": combined.apply(lambda s: 1 if RLO.search(s) else 0),
        "nbsp": combined.apply(lambda s: 1 if NBSP.search(s) else 0),
        "ads": combined.apply(lambda s: 1 if ADS.search(s) else 0),
        "device": combined.apply(lambda s: 1 if DEVICE_PREFIX.search(s) else 0),
        "unsigned": unsigned_series(df.get("Signer"), len(df)).astype(int),
    })
    
    # Handle infinite values and NaNs
    return feat.replace([np.inf, -np.inf], np.nan).fillna(0)


def pysad_scores(features: pd.DataFrame, method: str = "hst") -> np.ndarray:
    """
    Generate anomaly scores using PySAD models.
    
    Args:
        features: Numeric feature matrix
        method: 'hst' (HalfSpaceTrees) or 'loda' (LODA)
        
    Returns:
        Array of normalized anomaly scores (0-1)
        
    Raises:
        RuntimeError: If PySAD is not available
    """
    try:
        if method == "loda":
            from pysad.models import LODA
        else:
            from pysad.models import HalfSpaceTrees
    except ImportError as e:
        raise RuntimeError("PySAD is not installed. Install with: pip install pysad") from e

    X = features.values.astype(np.float64)
    if X.shape[0] == 0:
        return np.zeros(0, dtype=np.float64)

    # Initialize model
    if method == "loda":
        model = LODA()
    else:
        # HalfSpaceTrees needs feature bounds
        fmins = X.min(axis=0) - 1e-6
        fmaxs = X.max(axis=0) + 1e-6
        model = HalfSpaceTrees(feature_mins=fmins, feature_maxes=fmaxs)

    # Compute scores with fallback for individual samples
    try:
        scores = model.fit_score(X)
    except Exception:
        # Fallback: process row by row
        scores = np.zeros(X.shape[0], dtype=np.float64)
        for i, xi in enumerate(X):
            s = 0.0
            try:
                s = float(model.score_partial(xi))
            except Exception:
                pass
            try:
                model.fit_partial(xi)
            except Exception:
                pass
            scores[i] = s

    # Normalize scores to 0-1 range
    if np.ptp(scores) > 0:
        scores = (scores - scores.min()) / (scores.max() - scores.min())
    else:
        scores = np.zeros_like(scores)
    
    return scores