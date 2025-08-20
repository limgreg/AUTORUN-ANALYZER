"""
Autoruns Analyzer Package

A comprehensive toolkit for analyzing Windows Autoruns data with:
- Rule-based detection of suspicious entries
- Machine learning anomaly detection via PySAD
- Baseline comparison capabilities
- Digital signature verification
- Excel report generation
"""

__version__ = "1.0.0"
__author__ = "Security Analysis Team"

from .main import main, autoruns_to_dataframe

__all__ = ["main", "autoruns_to_dataframe"]