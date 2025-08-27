"""
PySAD integration for anomaly detection.
Clean implementation with only essential functions.
"""

import re
import numpy as np
import pandas as pd
from .utils import shannon_entropy


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

    # Generate unsigned feature using detector
    unsigned_feature = _get_unsigned_feature(df)

    # Generate numeric features
    feat = pd.DataFrame({
        "len": combined.apply(len),           # String length
        "args": combined.apply(lambda s: len([t for t in re.split(r'\s+', s.strip()) if t])),  # Argument count  
        "slashes": combined.str.count(r'[\\/]'),  # Path depth
        "dots": combined.str.count(r'\.'),        # File extensions
        "entropy": combined.apply(shannon_entropy),  # Randomness
        "unsigned": unsigned_feature,  # Digital signatures
    })
    
    # Handle infinite values and NaNs
    return feat.replace([np.inf, -np.inf], np.nan).fillna(0)


def _get_unsigned_feature(df: pd.DataFrame) -> pd.Series:
    """
    Generate unsigned binary feature for PySAD analysis.
    Uses modular detector when available, fallback otherwise.
    """
    try:
        from ..detectors.unsigned_binaries import detect_unsigned_binaries
        unsigned_df = detect_unsigned_binaries(df)
        
        # Convert to binary mask (0/1 series)
        unsigned_mask = pd.Series(0, index=df.index, dtype=int)
        if len(unsigned_df) > 0:
            unsigned_mask.loc[unsigned_df.index] = 1
        
        return unsigned_mask
        
    except ImportError:
        # Simple fallback for unsigned detection
        if "Signer" not in df.columns:
            return pd.Series(1, index=df.index, dtype=int)
        
        signer_s = df["Signer"].astype("string")
        unsigned_mask = (
            signer_s.isna() |
            (signer_s == "") |
            (signer_s.str.strip() == "") |
            signer_s.str.contains(r"^\(not verified\)", case=False, regex=True, na=False) |
            (signer_s.str.lower() == "microsoft windows publisher") |
            (signer_s.str.lower() == "n/a") |
            (signer_s.str.lower() == "unknown") |
            (signer_s.str.lower() == "unsigned") |
            (signer_s.str.lower() == "not verified") |
            (signer_s.str.lower() == "unable to verify")
        )
        
        return unsigned_mask.fillna(True).astype(int)


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