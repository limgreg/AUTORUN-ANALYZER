"""
Core analysis modules for autoruns data processing.
"""

from .pysad import build_features_for_pysad, pysad_scores
from .baseline import load_baseline, compare_against_baseline
from .utils import AutorunsFileCompat, safe_lower, file_name, shannon_entropy, normalize_path

__all__ = [
    # PySAD functionality
    "build_features_for_pysad", 
    "pysad_scores",
    
    # Baseline functionality
    "load_baseline",
    "compare_against_baseline",
    
    # Shared utilities
    "AutorunsFileCompat",
    "safe_lower",
    "file_name", 
    "shannon_entropy",
    "normalize_path"
]