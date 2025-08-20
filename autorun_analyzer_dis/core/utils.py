"""
Shared utility functions and classes.
"""

import re
import os
import csv
import io
import codecs
import numpy as np
import pandas as pd


def safe_lower(s):
    """Safely convert to lowercase string."""
    return str(s).lower() if pd.notna(s) else ""


def file_name(path):
    """Extract filename from path."""
    s = str(path) if pd.notna(path) else ""
    return os.path.basename(s.replace('"', '').strip())


def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    b = s.encode('utf-8', errors='ignore')
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p)).sum())


def normalize_path(p: str) -> str:
    """Normalize file path for comparison."""
    if not isinstance(p, str) or not p:
        return ""
    
    # Remove quotes and extra whitespace
    p = p.strip().strip('"').strip("'")
    
    # Handle different path separators
    p = p.replace("/", "\\")
    
    # Normalize case and handle environment variables
    p = p.lower()
    p = re.sub(r'%[^%]+%', lambda m: m.group(0).lower(), p)
    
    # Remove duplicate backslashes
    p = re.sub(r'\\+', r'\\', p)
    
    return p


class AutorunsFileCompat:
    """
    Robust reader for Sysinternals Autoruns CSV/TSV exports.
    Handles various encodings and formats automatically.
    """
    
    def __init__(self, path: str):
        self.path = path
        self.headers: list[str] = []
        self.rows: list[list[str]] = []
        self._read()

    @staticmethod
    def _detect_encoding(raw: bytes) -> str:
        """Detect file encoding from BOM or heuristics."""
        if raw.startswith(codecs.BOM_UTF16_LE):
            return "utf-16-le"
        if raw.startswith(codecs.BOM_UTF16_BE):
            return "utf-16-be"
        if raw.startswith(codecs.BOM_UTF8):
            return "utf-8-sig"
        
        # Heuristic: if many NUL bytes in even positions, assume UTF-16-LE
        if b'\x00' in raw[:200]:
            return "utf-16-le"
        return "utf-8"

    @staticmethod
    def _detect_delimiter(first_line: str) -> str:
        """Detect CSV delimiter (tab or comma)."""
        if "\t" in first_line and first_line.count("\t") >= first_line.count(","):
            return "\t"
        return ","

    def _read(self):
        """Read and parse the autoruns file."""
        with open(self.path, "rb") as f:
            raw = f.read()
        
        enc = self._detect_encoding(raw)
        text = raw.decode(enc, errors="replace")

        # Normalize newlines and strip empty lines
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = [ln for ln in text.split("\n") if ln.strip()]
        if not lines:
            raise RuntimeError("Empty file or unreadable content.")

        delimiter = self._detect_delimiter(lines[0])

        # Use csv module for proper parsing
        sio = io.StringIO("\n".join(lines))
        reader = csv.reader(sio, delimiter=delimiter, quotechar='"', skipinitialspace=False)

        rows = list(reader)
        if not rows:
            raise RuntimeError("No rows after CSV parse.")

        # Extract headers and data
        headers = [h.strip() for h in rows[0]]
        data = rows[1:]

        # Handle duplicate headers
        fixed_headers = []
        seen = {}
        for h in headers:
            key = h if h else "Unnamed"
            if key in seen:
                seen[key] += 1
                key = f"{key}.{seen[key]}"
            else:
                seen[key] = 1
            fixed_headers.append(key)
        self.headers = fixed_headers

        # Normalize row lengths to match headers
        width = len(self.headers)
        norm_rows = []
        for r in data:
            if len(r) < width:
                r = r + [""] * (width - len(r))
            elif len(r) > width:
                # Join overflow into last column
                r = r[:width-1] + [",".join(r[width-1:])]
            norm_rows.append(r)
        self.rows = norm_rows