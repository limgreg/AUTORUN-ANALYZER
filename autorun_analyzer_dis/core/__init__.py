"""
Core analysis modules for autoruns data processing.
Updated for modular detection system.
"""

# Keep these - still needed by detector modules
from .pysad import build_features_for_pysad, pysad_scores
from .baseline import load_baseline, compare_against_baseline
from .utils import AutorunsFileCompat, safe_lower, file_name, shannon_entropy, normalize_path

# Remove these - moved to detector modules
# from .rules import rule_flags_with_reason  # REMOVED - now in detectors/visual_masquerading.py
# from .unsigned import unsigned_series      # REMOVED - now in detectors/unsigned_binaries.py

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