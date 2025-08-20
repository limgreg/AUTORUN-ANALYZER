"""
Core analysis modules for autoruns data processing.
"""

from .rules import rule_flags_with_reason
from .pysad import build_features_for_pysad, pysad_scores
from .baseline import load_baseline, compare_against_baseline
from .unsigned import unsigned_series
from .utils import AutorunsFileCompat, safe_lower, file_name, shannon_entropy

__all__ = [
    "rule_flags_with_reason",
    "build_features_for_pysad", 
    "pysad_scores",
    "load_baseline",
    "compare_against_baseline", 
    "unsigned_series",
    "AutorunsFileCompat",
    "safe_lower",
    "file_name", 
    "shannon_entropy"
]