"""
Updated core/pysad.py that works with the new modular system.
REMOVED: Combined scoring system - just use pure PySAD scores and flagged_by info
"""

import re
import numpy as np
import pandas as pd
from .utils import shannon_entropy


def get_unsigned_mask(df: pd.DataFrame) -> pd.Series:
    """
    Get unsigned mask using the new modular detector system.
    This replaces the old unsigned_series import.
    """
    try:
        # Try to use the new modular detector
        from ..detectors.unsigned_binaries import detect_unsigned_binaries
        unsigned_df = detect_unsigned_binaries(df)
        
        # Convert to binary mask (0/1 series)
        unsigned_mask = pd.Series(0, index=df.index, dtype=int)
        if len(unsigned_df) > 0:
            unsigned_mask.loc[unsigned_df.index] = 1
        
        return unsigned_mask
        
    except ImportError:
        # Fallback: inline unsigned detection logic
        print("[!] New detector not available, using fallback unsigned detection")
        return fallback_unsigned_detection(df)


def fallback_unsigned_detection(df: pd.DataFrame) -> pd.Series:
    """
    Fallback unsigned detection logic (copied from old unsigned.py).
    This ensures pysad.py works even during transition.
    """
    if "Signer" not in df.columns:
        return pd.Series(1, index=df.index, dtype=int)  # Assume unsigned if no Signer column
    
    signer_s = df["Signer"]
    s = signer_s.astype("string")

    # Only flag as unsigned if missing or explicitly unsigned
    unsigned_mask = (
        # Missing or empty values
        s.isna() |
        (s == "") |
        (s.str.strip() == "") |
        
        # Entries that start with "(Not verified)" - case insensitive
        s.str.contains(r"^\(not verified\)", case=False, regex=True, na=False) |
        
        # Exact matches for other known unsigned indicators (case insensitive)
        (s.str.lower() == "microsoft windows publisher") |
        (s.str.lower() == "n/a") |
        (s.str.lower() == "unknown") |
        (s.str.lower() == "unsigned") |
        (s.str.lower() == "not verified") |
        (s.str.lower() == "unable to verify")
    )
    
    return unsigned_mask.fillna(True).astype(int)


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
        "len": combined.apply(len),           # String length
        "args": combined.apply(lambda s: len([t for t in re.split(r'\s+', s.strip()) if t])),  # Argument count  
        "slashes": combined.str.count(r'[\\/]'),  # Path depth
        "dots": combined.str.count(r'\.'),        # File extensions
        "entropy": combined.apply(shannon_entropy),  # Randomness
        "unsigned": get_unsigned_mask(df),  # Digital signatures using new system
    })
    
    # Handle infinite values and NaNs
    return feat.replace([np.inf, -np.inf], np.nan).fillna(0)


def build_meta_features_for_pysad(df: pd.DataFrame, detection_results: dict = None) -> pd.DataFrame:
    """
    Build enhanced feature matrix that includes results from modular detectors.
    SIMPLIFIED: Just original features + binary detection flags (no complex scoring)
    
    Args:
        df: Input DataFrame
        detection_results: Dictionary of detection results from modular system
        
    Returns:
        DataFrame with original + detection features for meta-anomaly detection
    """
    # Start with original features
    original_features = build_features_for_pysad(df)
    
    # Add detection result features if available
    if detection_results:
        # Add binary features for each detector (0/1)
        for detector_name, result_df in detection_results.items():
            if isinstance(result_df, pd.DataFrame):
                feature_name = f"flagged_by_{detector_name}"
                original_features[feature_name] = 0
                if len(result_df) > 0:
                    original_features.loc[result_df.index, feature_name] = 1
        
        # Simple meta-features
        detection_columns = [col for col in original_features.columns if col.startswith('flagged_by_')]
        if detection_columns:
            # Total detection count
            original_features['total_detections'] = original_features[detection_columns].sum(axis=1)
    
    return original_features


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


def run_meta_pysad_analysis(df: pd.DataFrame, detection_results: dict, 
                           method: str = "hst", top_pct: float = 3.0) -> tuple:
    """
    Run meta-PySAD analysis using detection results as features.
    SIMPLIFIED: Removed complex combined scoring - just use pure PySAD + flagged_by info
    
    Args:
        df: Original DataFrame
        detection_results: Results from all individual detectors
        method: PySAD method ('hst' or 'loda')
        top_pct: Percentage of top scores to return
        
    Returns:
        Tuple of (top_meta_results_df, all_meta_results_df)
    """
    import math
    
    print(f"[+] Running meta-PySAD analysis (method: {method})...")
    
    # Build enhanced features including detection results
    meta_features = build_meta_features_for_pysad(df, detection_results)
    print(f"    Meta-features: {meta_features.shape[1]} features")
    
    # Run PySAD on meta-features
    meta_scores = pysad_scores(meta_features, method=method)
    
    # Create results DataFrame
    df_meta = df.copy()
    df_meta['meta_pysad_score'] = np.round(meta_scores, 4)
    
    # Add detection summary (simplified)
    flagged_by = []
    detection_counts = []
    
    for idx in df.index:
        detectors = []
        count = 0
        for detector_name, result_df in detection_results.items():
            if isinstance(result_df, pd.DataFrame) and idx in result_df.index:
                detectors.append(detector_name.replace('_', ' ').title())
                count += 1
        
        flagged_by.append(' + '.join(detectors) if detectors else 'None')
        detection_counts.append(count)
    
    df_meta['flagged_by_detectors'] = flagged_by
    df_meta['detection_count'] = detection_counts
    
    # SIMPLIFIED: Just use pure PySAD score for ranking (no complex combined scoring)
    # Users can see which detectors flagged items in the 'flagged_by_detectors' column
    
    # Get top percentile based on pure PySAD score
    k = max(1, int(math.ceil(len(df_meta) * (top_pct / 100.0))))
    thresh = np.partition(df_meta['meta_pysad_score'].values, -k)[-k]
    
    df_meta_top = df_meta[df_meta['meta_pysad_score'] >= thresh].copy()
    df_meta_top = df_meta_top.sort_values('meta_pysad_score', ascending=False)
    
    print(f"    Meta-analysis complete: {len(df_meta_top)} top anomalies (pure PySAD scoring)")
    
    return df_meta_top, df_meta


# For backwards compatibility during transition
def unsigned_series(signer_s, n):
    """
    DEPRECATED: Compatibility function for old code.
    Use get_unsigned_mask() or the new modular detector system instead.
    """
    import warnings
    warnings.warn(
        "unsigned_series() in pysad.py is deprecated. Use detectors.unsigned_binaries instead.",
        DeprecationWarning,
        stacklevel=2
    )
    
    df_temp = pd.DataFrame({'Signer': signer_s} if signer_s is not None else {'Signer': [pd.NA] * n})
    return get_unsigned_mask(df_temp)