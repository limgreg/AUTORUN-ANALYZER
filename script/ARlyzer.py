#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DFIR Autoruns Analyzer v2.0 - Production CIRT/DFIR Edition

Enhanced for incident response with:
- Comprehensive IOC detection rules
- Threat hunting capabilities  
- Performance optimizations
- Detailed analyst reporting
- Timeline analysis
- Hash lookups integration ready

Author: DFIR Team
Requires: pandas, numpy, xlsxwriter, requests (optional)
"""

import re
import os
import sys
import math
import csv
import io
import codecs
import datetime as dt
import hashlib
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Set
import numpy as np
import pandas as pd

# Configure logging for DFIR operations
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('autoruns_analysis.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================= Enhanced Constants =============================

# Comprehensive LOLBin list for DFIR
LOLBINS_COMPREHENSIVE = {
    # Core Windows utilities commonly abused
    'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'powershell.exe', 'pwsh.exe',
    'wscript.exe', 'cscript.exe', 'cmd.exe', 'wmic.exe', 'forfiles.exe',
    'schtasks.exe', 'installutil.exe', 'certutil.exe', 'bitsadmin.exe',
    
    # MSI and installer abuse
    'msiexec.exe', 'regasm.exe', 'regsvcs.exe', 'cmstp.exe', 'odbcconf.exe',
    
    # Process injection and DLL loading
    'mavinject.exe', 'dllhost.exe', 'verclsid.exe', 'rundll32.exe',
    
    # Help and documentation abuse
    'hh.exe', 'winhlp32.exe', 'infdefaultinstall.exe',
    
    # .NET and development tools
    'ieexec.exe', 'presentationhost.exe', 'msdt.exe', 'msbuild.exe',
    'csc.exe', 'vbc.exe', 'jsc.exe', 'cvtres.exe',
    
    # Remote access and management
    'winrm.exe', 'winrs.exe', 'psexec.exe', 'paexec.exe',
    
    # Subsystem abuse
    'wsl.exe', 'bash.exe', 'ubuntu.exe', 'kali.exe',
    
    # MMC and administrative tools
    'mmc.exe', 'eventvwr.exe', 'compmgmt.msc',
    
    # Antivirus bypass
    'mpcmdrun.exe', 'pcalua.exe', 'forfiles.exe',
    
    # Script execution
    'scriptrunner.exe', 'te.exe', 'syncappvpublishingserver.exe',
    
    # Without extensions for flexibility
    'rundll32', 'regsvr32', 'mshta', 'powershell', 'pwsh', 'wscript',
    'cscript', 'cmd', 'wmic', 'certutil', 'bitsadmin', 'msiexec'
}

# Suspicious paths for persistence and execution
SUSPICIOUS_PATHS = {
    # Startup locations
    r'\\startup\\',
    r'\\start menu\\programs\\startup\\',
    r'\\programdata\\microsoft\\windows\\start menu\\programs\\startup\\',
    
    # Scheduled tasks
    r'\\windows\\system32\\tasks\\',
    r'\\windows\\tasks\\',
    
    # Service binaries in unusual locations
    r'\\users\\.*\\appdata\\',
    r'\\programdata\\(?!microsoft)',
    r'\\windows\\temp\\',
    r'\\temp\\',
    
    # Web browser locations
    r'\\appdata\\local\\temp\\',
    r'\\appdata\\roaming\\',
    
    # System directory abuse
    r'\\windows\\system32\\(?!.*\.(exe|dll|sys)$)',
    r'\\windows\\syswow64\\(?!.*\.(exe|dll|sys)$)',
}

# Registry persistence locations (for reference in descriptions)
REGISTRY_PERSISTENCE = {
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce',
    'HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
    'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\Run',
    'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon',
    'HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options',
    'HKLM\\System\\CurrentControlSet\\Services'
}

# Unicode attack patterns
ZERO_WIDTH = re.compile(r'[\u200B-\u200D\u200E\u200F\uFEFF]')
RLO_LRO = re.compile(r'[\u202A-\u202E\u2066-\u2069]')
NBSP_VARIANTS = re.compile(r'[\u00A0\u202F\u2007\u2008\u2009\u200A]')

# Enhanced ADS detection (avoiding false positives)
ADS_PATTERN = re.compile(r'(?i)^[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*:[^\\/:*?"<>|\r\n]+$')
URL_PATTERN = re.compile(r'(?i)\b(?:https?|ftp|file)://')
ERROR_PATTERN = re.compile(r'(?i)(?:file not found|error|exception):')

# Device and volume path patterns  
DEVICE_VOLUME = re.compile(r'^(?:\\\\\?\\|\\\?\\|\\\\Device\\|\\\\\?\\GLOBALROOT\\|\\\\\?\\Volume\{)', re.I)

# Command injection patterns commonly seen in malware
INJECTION_PATTERNS = re.compile(r'[;&|`$(){}]|&&|\|\||>>|<<|powershell|cmd\.exe|wscript|cscript', re.I)

# High-risk file extensions
EXECUTABLE_EXTENSIONS = {'.exe', '.com', '.scr', '.pif', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar'}

# Network-related indicators
NETWORK_INDICATORS = re.compile(r'(?i)(?:http|ftp|tcp|udp|dns|proxy|tunnel|beacon|c2|command.{1,5}control)', re.I)

# ============================= Utilities =============================

def _ensure_xlsx(path: str) -> str:
    """Ensure output file has Excel extension"""
    lower = path.lower()
    if lower.endswith((".xlsx", ".xlsm")):
        return path
    base, _ = os.path.splitext(path)
    fixed = base + ".xlsx"
    logger.warning(f"Output file '{path}' is not Excel format; writing to '{fixed}'")
    return fixed

def _normalize_path_enhanced(p: str) -> str:
    """Enhanced path normalization for accurate comparison"""
    if not isinstance(p, str) or not p:
        return ""
    
    # Remove quotes, extra whitespace
    p = p.strip().strip('"').strip("'").strip()
    
    # Handle path separators
    p = p.replace("/", "\\")
    
    # Normalize case
    p = p.lower()
    
    # Expand common environment variables
    env_vars = {
        '%systemroot%': 'c:\\windows',
        '%windir%': 'c:\\windows', 
        '%programfiles%': 'c:\\program files',
        '%programfiles(x86)%': 'c:\\program files (x86)',
        '%programdata%': 'c:\\programdata',
        '%temp%': 'c:\\windows\\temp',
        '%tmp%': 'c:\\windows\\temp',
        '%appdata%': 'c:\\users\\[user]\\appdata\\roaming',
        '%localappdata%': 'c:\\users\\[user]\\appdata\\local'
    }
    
    for var, path in env_vars.items():
        p = p.replace(var, path)
    
    # Remove duplicate backslashes
    p = re.sub(r'\\+', '\\', p)
    
    # Remove trailing backslash unless it's root
    if p.endswith('\\') and len(p) > 3:
        p = p.rstrip('\\')
        
    return p

def safe_lower(s) -> str:
    """Safely convert to lowercase"""
    return str(s).lower() if pd.notna(s) else ""

def file_name(path) -> str:
    """Extract filename from path"""
    s = str(path) if pd.notna(path) else ""
    return os.path.basename(s.replace('"', '').strip())

def shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy for obfuscation detection"""
    if not s:
        return 0.0
    b = s.encode('utf-8', errors='ignore')
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p)).sum())

def calculate_file_hash(file_path: str, hash_type: str = 'sha256') -> Optional[str]:
    """Calculate file hash if file exists (for verification)"""
    try:
        if not os.path.exists(file_path):
            return None
        hash_obj = hashlib.new(hash_type)
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception:
        return None

# ============================= Enhanced File Reading =============================

class AutorunsFileCompat:
    """
    Production-ready Autoruns CSV/TSV reader with enhanced error handling
    """
    def __init__(self, path: str):
        self.path = path
        self.headers: List[str] = []
        self.rows: List[List[str]] = []
        self.metadata = {
            'encoding': None,
            'delimiter': None,
            'total_lines': 0,
            'data_rows': 0
        }
        self._read()

    @staticmethod
    def _detect_encoding(raw: bytes) -> str:
        """Enhanced encoding detection"""
        if raw.startswith(codecs.BOM_UTF16_LE):
            return "utf-16-le"
        if raw.startswith(codecs.BOM_UTF16_BE):
            return "utf-16-be"
        if raw.startswith(codecs.BOM_UTF8):
            return "utf-8-sig"
        
        # Heuristic for UTF-16 without BOM
        if b'\x00' in raw[:500]:
            null_positions = [i for i, b in enumerate(raw[:500]) if b == 0]
            if null_positions and most_common_modulo(null_positions) == 1:
                return "utf-16-le"
                
        return "utf-8"

    @staticmethod
    def _detect_delimiter(first_line: str) -> str:
        """Smart delimiter detection"""
        tab_count = first_line.count("\t")
        comma_count = first_line.count(",")
        semicolon_count = first_line.count(";")
        
        # Prefer delimiter with highest count
        counts = [
            (tab_count, "\t"),
            (comma_count, ","), 
            (semicolon_count, ";")
        ]
        counts.sort(reverse=True)
        
        if counts[0][0] > 0:
            return counts[0][1]
        return ","

    def _read(self):
        """Read and parse the autoruns file"""
        try:
            with open(self.path, "rb") as f:
                raw = f.read()
        except Exception as e:
            raise RuntimeError(f"Failed to read file {self.path}: {e}")
            
        if not raw:
            raise RuntimeError("File is empty")

        # Detect encoding and decode
        enc = self._detect_encoding(raw)
        self.metadata['encoding'] = enc
        
        try:
            text = raw.decode(enc, errors="replace")
        except Exception as e:
            logger.warning(f"Encoding detection failed, trying UTF-8: {e}")
            text = raw.decode('utf-8', errors='replace')

        # Normalize and clean
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
        
        if not lines:
            raise RuntimeError("No data lines found")
            
        self.metadata['total_lines'] = len(lines)

        # Detect delimiter
        delimiter = self._detect_delimiter(lines[0])
        self.metadata['delimiter'] = delimiter

        # Parse with CSV module for proper quote handling
        sio = io.StringIO("\n".join(lines))
        try:
            reader = csv.reader(sio, delimiter=delimiter, quotechar='"', skipinitialspace=False)
            rows = list(reader)
        except Exception as e:
            raise RuntimeError(f"CSV parsing failed: {e}")

        if not rows:
            raise RuntimeError("No rows after CSV parse")

        # Process headers
        headers = [h.strip() for h in rows[0]]
        self.headers = self._fix_duplicate_headers(headers)
        
        # Process data rows
        data_rows = rows[1:]
        width = len(self.headers)
        
        normalized_rows = []
        for i, row in enumerate(data_rows):
            if len(row) < width:
                row = row + [""] * (width - len(row))
            elif len(row) > width:
                # Join overflow into last column
                row = row[:width-1] + [",".join(row[width-1:])]
            normalized_rows.append(row)
            
        self.rows = normalized_rows
        self.metadata['data_rows'] = len(self.rows)
        
        logger.info(f"Loaded {len(self.rows)} rows with {len(self.headers)} columns")
        logger.debug(f"Encoding: {enc}, Delimiter: '{delimiter}'")

    def _fix_duplicate_headers(self, headers: List[str]) -> List[str]:
        """Fix duplicate or empty headers"""
        fixed = []
        seen = {}
        
        for h in headers:
            key = h if h else "Unnamed"
            if key in seen:
                seen[key] += 1
                key = f"{key}.{seen[key]}"
            else:
                seen[key] = 1
            fixed.append(key)
            
        return fixed

def most_common_modulo(positions: List[int]) -> int:
    """Helper for encoding detection"""
    if len(positions) < 2:
        return 0
    modulos = {}
    for i in range(len(positions) - 1):
        mod = positions[i] % 2
        modulos[mod] = modulos.get(mod, 0) + 1
    return max(modulos.items(), key=lambda x: x[1])[0] if modulos else 0

def autoruns_to_dataframe(path: str) -> pd.DataFrame:
    """Convert autoruns file to DataFrame with column normalization"""
    af = AutorunsFileCompat(path)
    df = pd.DataFrame(af.rows, columns=af.headers)

    # Normalize column names for consistency
    cols_lower = {c.lower(): c for c in df.columns}
    
    column_aliases = {
        'image path': ['image path', 'image', 'path', 'location', 'command', 'fullname', 'filepath'],
        'description': ['description', 'entry', 'entryname', 'entry name'],
        'publisher': ['publisher', 'company', 'signer'],
        'verified': ['verified', 'signature', 'signed']
    }
    
    # Apply column aliases
    mapping = {}
    for standard_name, aliases in column_aliases.items():
        for alias in aliases:
            if alias in cols_lower and cols_lower[alias] != standard_name:
                mapping[cols_lower[alias]] = standard_name.title()
                break
    
    if mapping:
        df.rename(columns=mapping, inplace=True)
        logger.info(f"Normalized columns: {mapping}")

    return df

# ============================= Enhanced Detection Rules =============================

def unsigned_series_enhanced(publisher_s: Optional[pd.Series], 
                           verified_s: Optional[pd.Series], 
                           n: int) -> pd.Series:
    """Enhanced unsigned binary detection"""
    if publisher_s is not None:
        p = publisher_s.astype("string").str.lower()
    else:
        p = pd.Series([pd.NA] * n, dtype="string")
        
    if verified_s is not None:
        v = verified_s.astype("string").str.lower()
    else:
        v = pd.Series([pd.NA] * n, dtype="string")

    # Comprehensive unsigned patterns
    unsigned_patterns = [
        # Publisher indicators
        r"\b(n/?a|unknown|unavailable|not available|none|\(null\))\b",
        r"\bmicrosoft windows publisher\b",  # Generic Windows
        r"\bunable to verify publisher\b",
        
        # Verification status
        r"(not verified|unsigned|invalid signature|no signature)",
        r"(unable to verify|verification failed|untrusted|revoked)",
        r"\b(no|false|0)\b"  # Boolean indicators
    ]
    
    unsigned_mask = (
        p.isna() | v.isna() |  # Missing data
        (p == "") | (v == "") |  # Empty strings
        p.str.contains("|".join(unsigned_patterns[:3]), regex=True, na=False, case=False) |
        v.str.contains("|".join(unsigned_patterns[3:]), regex=True, na=False, case=False)
    )
    
    return unsigned_mask.astype(int)

def improved_ads_detection(text_series: pd.Series) -> pd.Series:
    """Enhanced ADS detection avoiding false positives"""
    # Primary ADS pattern
    ads_mask = text_series.str.contains(ADS_PATTERN, na=False)
    
    # Exclude false positives
    false_positives = (
        text_series.str.contains(URL_PATTERN, na=False) |  # URLs
        text_series.str.contains(ERROR_PATTERN, na=False) |  # Error messages
        text_series.str.contains(r':\d+\s*$', na=False, regex=True)  # Port numbers
    )
    
    return ads_mask & ~false_positives

def detect_suspicious_patterns(df: pd.DataFrame) -> Dict[str, pd.Series]:
    """Comprehensive suspicious pattern detection for DFIR"""
    
    # Get primary path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    fname = text.apply(file_name)
    
    patterns = {}
    
    # 1. Path-based detections
    user_writable = text.str.contains(
        r'\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|%temp%|%appdata%',
        case=False, na=False, regex=True
    )
    
    suspicious_system_paths = text.str.contains(
        '|'.join(SUSPICIOUS_PATHS), case=False, na=False, regex=True
    )
    
    # 2. LOLBin detection
    lolbin_detection = fname.apply(lambda s: safe_lower(s) in LOLBINS_COMPREHENSIVE)
    
    # 3. Unicode attacks
    patterns['zero_width'] = text.str.contains(ZERO_WIDTH, na=False)
    patterns['unicode_override'] = text.str.contains(RLO_LRO, na=False)
    patterns['nbsp_variants'] = text.str.contains(NBSP_VARIANTS, na=False)
    
    # 4. File system abuse
    patterns['ads'] = improved_ads_detection(text)
    patterns['device_paths'] = text.str.contains(DEVICE_VOLUME, na=False)
    
    # 5. Obfuscation detection
    patterns['high_entropy'] = text.apply(lambda s: shannon_entropy(s) > 4.8)
    patterns['excessive_dots'] = text.str.count(r'\.') > 5
    patterns['long_paths'] = text.str.len() > 260  # Windows MAX_PATH
    
    # 6. Command injection patterns
    patterns['injection_chars'] = text.str.contains(INJECTION_PATTERNS, na=False)
    
    # 7. Network indicators in paths
    patterns['network_indicators'] = text.str.contains(NETWORK_INDICATORS, na=False)
    
    # 8. Executable masquerading
    patterns['double_extension'] = text.str.contains(
        r'\.(txt|pdf|doc|jpg|png)\.(exe|scr|com|pif|bat)$', 
        case=False, na=False, regex=True
    )
    
    # 9. Timestamp analysis (if available)
    time_cols = [c for c in df.columns if 'time' in c.lower() or 'date' in c.lower()]
    if time_cols:
        # Look for entries created/modified outside business hours
        try:
            time_col = time_cols[0]
            time_series = pd.to_datetime(df[time_col], errors='coerce')
            patterns['off_hours'] = (
                time_series.dt.hour.between(22, 6) | 
                time_series.dt.weekday.isin([5, 6])  # Weekend
            ).fillna(False)
        except Exception:
            patterns['off_hours'] = pd.Series([False] * len(df))
    
    # 10. Combined high-risk patterns
    patterns['lolbin_user_writable'] = user_writable & lolbin_detection
    patterns['lolbin_suspicious_path'] = suspicious_system_paths & lolbin_detection
    
    return patterns

def generate_risk_scores(patterns: Dict[str, pd.Series]) -> pd.Series:
    """Generate risk scores based on pattern combinations"""
    
    # Risk weights for different patterns
    risk_weights = {
        'lolbin_user_writable': 8,
        'lolbin_suspicious_path': 7,
        'ads': 6,
        'device_paths': 6,
        'injection_chars': 5,
        'unicode_override': 5,
        'zero_width': 4,
        'high_entropy': 3,
        'network_indicators': 3,
        'double_extension': 4,
        'nbsp_variants': 2,
        'excessive_dots': 2,
        'long_paths': 1,
        'off_hours': 2
    }
    
    risk_scores = pd.Series([0] * len(list(patterns.values())[0]))
    
    for pattern_name, pattern_series in patterns.items():
        weight = risk_weights.get(pattern_name, 1)
        risk_scores += pattern_series.astype(int) * weight
    
    # Normalize to 0-10 scale
    if risk_scores.max() > 0:
        risk_scores = (risk_scores / risk_scores.max() * 10).round(1)
    
    return risk_scores

def rule_flags_with_reason_enhanced(df: pd.DataFrame) -> Tuple[pd.Series, pd.Series, pd.Series]:
    """Enhanced rule-based detection with detailed reasons and risk scores"""
    
    patterns = detect_suspicious_patterns(df)
    risk_scores = generate_risk_scores(patterns)
    
    # Generate detailed reasons
    pattern_descriptions = {
        'lolbin_user_writable': 'LOLBin in user-writable location',
        'lolbin_suspicious_path': 'LOLBin in suspicious system path',
        'ads': 'Alternate Data Stream detected',
        'device_paths': 'Device/Volume/GLOBALROOT path',
        'injection_chars': 'Command injection characters',
        'unicode_override': 'Unicode RLO/LRO override',
        'zero_width': 'Zero-width Unicode characters',
        'high_entropy': 'High entropy (possible obfuscation)',
        'network_indicators': 'Network-related indicators',
        'double_extension': 'Double file extension (masquerading)',
        'nbsp_variants': 'Non-breaking space variants',
        'excessive_dots': 'Excessive dots in path',
        'long_paths': 'Unusually long path',
        'off_hours': 'Created/modified outside business hours'
    }
    
    reasons = []
    for i in range(len(df)):
        reason_list = []
        for pattern_name, pattern_series in patterns.items():
            if pattern_series.iloc[i]:
                desc = pattern_descriptions.get(pattern_name, pattern_name)
                reason_list.append(desc)
        reasons.append('; '.join(reason_list))
    
    # Flag entries with risk score >= 3 or specific high-risk patterns
    high_risk_patterns = ['lolbin_user_writable', 'lolbin_suspicious_path', 'ads', 'device_paths']
    high_risk_mask = pd.Series([False] * len(df))
    
    for pattern in high_risk_patterns:
        if pattern in patterns:
            high_risk_mask |= patterns[pattern]
    
    flag_mask = (risk_scores >= 3.0) | high_risk_mask
    
    return flag_mask, pd.Series(reasons), risk_scores

# ============================= PySAD Integration =============================

def build_features_for_pysad_enhanced(df: pd.DataFrame) -> pd.DataFrame:
    """Enhanced feature engineering for anomaly detection"""
    
    col_img = next((c for c in df.columns if c.lower() in 
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    col_desc = next((c for c in df.columns if c.lower() in 
                    ['description', 'entry', 'entryname', 'entry name']), None)
    col_publisher = next((c for c in df.columns if c.lower() in 
                         ['publisher', 'company']), None)
    col_verified = next((c for c in df.columns if c.lower() in 
                       ['verified', 'signature', 'signer']), None)

    # Combine text fields
    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    desc = df[col_desc].astype(str) if col_desc else pd.Series([""] * len(df))
    combined = (text.fillna('') + " " + desc.fillna('')).str.strip()

    # Enhanced feature set
    features = pd.DataFrame({
        # Basic text features
        "total_length": combined.apply(len),
        "word_count": combined.apply(lambda s: len(s.split())),
        "path_depth": combined.str.count(r'[\\/]'),
        "dot_count": combined.str.count(r'\.'),
        
        # Statistical features
        "entropy": combined.apply(shannon_entropy),
        "char_diversity": combined.apply(lambda s: len(set(s.lower())) / max(len(s), 1)),
        
        # Suspicious character features
        "special_chars": combined.str.count(r'[!@#$%^&*()+=\[\]{}|;:,.<>?]'),
        "numeric_chars": combined.str.count(r'\d'),
        "uppercase_ratio": combined.apply(lambda s: sum(c.isupper() for c in s) / max(len(s), 1)),
        
        # Unicode and encoding features
        "unicode_chars": combined.apply(lambda s: sum(ord(c) > 127 for c in s)),
        "zero_width": combined.apply(lambda s: 1 if ZERO_WIDTH.search(s) else 0),
        "unicode_override": combined.apply(lambda s: 1 if RLO_LRO.search(s) else 0),
        "nbsp_variants": combined.apply(lambda s: 1 if NBSP_VARIANTS.search(s) else 0),
        
        # File system features
        "ads_indicator": combined.apply(lambda s: 1 if ADS_PATTERN.search(s) and not URL_PATTERN.search(s) else 0),
        "device_path": combined.apply(lambda s: 1 if DEVICE_VOLUME.search(s) else 0),
        "long_path": combined.apply(lambda s: 1 if len(s) > 260 else 0),
        
        # Execution features
        "injection_chars": combined.apply(lambda s: 1 if INJECTION_PATTERNS.search(s) else 0),
        "lolbin_indicator": combined.apply(lambda s: 1 if file_name(s).lower() in LOLBINS_COMPREHENSIVE else 0),
        
        # Trust indicators
        "unsigned": unsigned_series_enhanced(
            df.get(col_publisher) if col_publisher else None,
            df.get(col_verified) if col_verified else None,
            len(df)
        ).astype(int),
        
        # Path location features
        "user_writable": combined.str.contains(
            r'\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\',
            case=False, na=False
        ).astype(int),
        
        "system_dir": combined.str.contains(
            r'\\Windows\\System32\\|\\Windows\\SysWOW64\\',
            case=False, na=False
        ).astype(int),
    })
    
    # Clean and normalize features
    features = features.replace([np.inf, -np.inf], np.nan).fillna(0)
    
    # Add feature interactions for better anomaly detection
    features['entropy_length_ratio'] = features['entropy'] / features['total_length'].clip(lower=1)
    features['suspicious_combo'] = (
        features['lolbin_indicator'] * features['user_writable'] * 2 +
        features['unicode_override'] * features['injection_chars'] * 3 +
        features['ads_indicator'] * features['unsigned'] * 2
    )
    
    return features

def pysad_scores_enhanced(features: pd.DataFrame, method: str = "hst") -> np.ndarray:
    """Enhanced PySAD scoring with better error handling and normalization"""
    try:
        if method == "loda":
            from pysad.models import LODA
        else:
            from pysad.models import HalfSpaceTrees
    except ImportError as e:
        logger.error(f"PySAD not available: {e}")
        raise RuntimeError("PySAD is not installed. Install with: pip install pysad")

    X = features.values.astype(np.float64)
    if X.shape[0] == 0:
        return np.zeros(0, dtype=np.float64)

    # Robust model initialization
    try:
        if method == "loda":
            model = LODA(n_bins=10, n_random_cuts=100)
        else:
            # Calculate feature bounds with safety margins
            fmins = X.min(axis=0) - 1e-6
            fmaxs = X.max(axis=0) + 1e-6
            # Handle constant features
            constant_features = (fmaxs - fmins) < 1e-10
            fmaxs[constant_features] = fmins[constant_features] + 1.0
            
            model = HalfSpaceTrees(
                num_trees=100,
                height=8, 
                feature_mins=fmins, 
                feature_maxes=fmaxs
            )
    except Exception as e:
        logger.error(f"PySAD model initialization failed: {e}")
        return np.zeros(X.shape[0], dtype=np.float64)

    # Robust scoring with fallback
    scores = np.zeros(X.shape[0], dtype=np.float64)
    
    try:
        # Batch processing for efficiency
        scores = model.fit_score(X)
        logger.info(f"PySAD {method.upper()} completed successfully")
    except Exception as e:
        logger.warning(f"Batch PySAD processing failed: {e}, falling back to incremental")
        # Incremental processing fallback
        for i, xi in enumerate(X):
            try:
                score = float(model.score_partial(xi.reshape(1, -1)))
                scores[i] = score
                model.fit_partial(xi.reshape(1, -1))
            except Exception:
                scores[i] = 0.0

    # Enhanced normalization with outlier handling
    if len(scores) > 0 and np.ptp(scores) > 1e-10:
        # Remove extreme outliers (>99.5th percentile) for better normalization
        q995 = np.percentile(scores, 99.5)
        scores_clipped = np.clip(scores, None, q995)
        
        if np.ptp(scores_clipped) > 0:
            scores = (scores_clipped - scores_clipped.min()) / np.ptp(scores_clipped)
        else:
            scores = np.zeros_like(scores)
    else:
        scores = np.zeros_like(scores)
    
    return scores

# ============================= Enhanced Baseline Analysis =============================

def load_baseline_enhanced(baseline_csv: str) -> Tuple[Set[str], Dict[str, Dict[str, str]]]:
    """Enhanced baseline loading with multi-hash support and validation"""
    if not baseline_csv or not os.path.exists(baseline_csv):
        logger.warning(f"Baseline file not found: {baseline_csv}")
        return set(), {}
    
    try:
        # Try different encodings
        for encoding in ['utf-8', 'utf-16', 'cp1252']:
            try:
                bdf = pd.read_csv(baseline_csv, encoding=encoding, engine="python")
                logger.info(f"Baseline loaded with encoding: {encoding}")
                break
            except UnicodeError:
                continue
        else:
            raise ValueError("Could not decode baseline file with any supported encoding")
            
    except Exception as e:
        logger.error(f"Failed to load baseline: {e}")
        raise

    if bdf.empty:
        logger.warning("Baseline file is empty")
        return set(), {}

    # Flexible column detection
    cols_lower = {c.lower(): c for c in bdf.columns}
    
    # Path column detection
    path_candidates = [
        "fullname", "path", "image path", "image", "full path", 
        "filepath", "location", "command", "file_path"
    ]
    path_col = next((cols_lower[name] for name in path_candidates if name in cols_lower), None)
    
    if not path_col:
        available_cols = list(bdf.columns)
        raise ValueError(f"No path column found in baseline. Available columns: {available_cols}")

    # Hash column detection
    hash_columns = {
        'sha256': cols_lower.get('sha256') or cols_lower.get('sha-256'),
        'sha1': cols_lower.get('sha1') or cols_lower.get('sha-1'),
        'md5': cols_lower.get('md5')
    }
    
    baseline_paths = set()
    baseline_hash_by_path = {}
    
    processed_count = 0
    hash_count = 0
    
    for _, row in bdf.iterrows():
        path_raw = row.get(path_col)
        if pd.isna(path_raw) or not str(path_raw).strip():
            continue
            
        normalized_path = _normalize_path_enhanced(str(path_raw))
        if not normalized_path:
            continue
            
        baseline_paths.add(normalized_path)
        processed_count += 1
        
        # Collect available hashes
        hashes = {}
        for hash_type, col_name in hash_columns.items():
            if col_name and pd.notna(row.get(col_name)):
                hash_value = str(row.get(col_name)).strip().lower()
                if hash_value and len(hash_value) > 10:  # Basic validation
                    hashes[hash_type] = hash_value
        
        if hashes:
            baseline_hash_by_path[normalized_path] = hashes
            hash_count += 1

    logger.info(f"Baseline processed: {processed_count} paths, {hash_count} with hashes")
    return baseline_paths, baseline_hash_by_path

def compare_against_baseline_enhanced(df: pd.DataFrame, 
                                    baseline_paths: Set[str], 
                                    baseline_hash_by_path: Dict[str, Dict[str, str]]) -> pd.DataFrame:
    """Enhanced baseline comparison with detailed analysis"""
    
    col_img = next((c for c in df.columns if c.lower() in
                   ["image path", "image", "path", "location", "command", "fullname"]), None)
    
    if not col_img:
        logger.warning("No image path column found for baseline comparison")
        return pd.DataFrame()
    
    text = df[col_img].astype(str)
    normalized_paths = text.apply(_normalize_path_enhanced)
    
    # Hash column detection in autoruns data
    cols_lower = {c.lower(): c for c in df.columns}
    hash_columns = {
        'sha256': cols_lower.get('sha-256') or cols_lower.get('sha256'),
        'sha1': cols_lower.get('sha-1') or cols_lower.get('sha1'),
        'md5': cols_lower.get('md5')
    }
    
    findings = []
    stats = {
        'total_checked': 0,
        'not_in_baseline': 0,
        'hash_mismatches': 0,
        'new_in_system_dirs': 0
    }
    
    for i in df.index:
        path_norm = normalized_paths.iloc[i]
        if not path_norm:
            continue
            
        stats['total_checked'] += 1
        row_data = df.loc[i].copy()
        reasons = []
        severity = 'Low'
        
        # Check if path exists in baseline
        if path_norm not in baseline_paths:
            reasons.append("Not present in baseline")
            stats['not_in_baseline'] += 1
            
            # Higher severity for new files in critical system directories
            critical_dirs = [
                'c:\\windows\\system32\\', 'c:\\windows\\syswow64\\',
                'c:\\program files\\', 'c:\\program files (x86)\\'
            ]
            
            if any(path_norm.startswith(cdir) for cdir in critical_dirs):
                reasons.append("New file in critical system directory")
                severity = 'High'
                stats['new_in_system_dirs'] += 1
            else:
                severity = 'Medium'
        else:
            # Path exists in baseline, check hashes
            baseline_hashes = baseline_hash_by_path.get(path_norm, {})
            if baseline_hashes:
                hash_mismatch = False
                mismatch_details = []
                
                for hash_type, baseline_hash in baseline_hashes.items():
                    col_name = hash_columns.get(hash_type)
                    if not col_name:
                        continue
                        
                    current_hash = row_data.get(col_name)
                    if pd.notna(current_hash):
                        current_hash_clean = str(current_hash).strip().lower()
                        if current_hash_clean and current_hash_clean != baseline_hash:
                            hash_mismatch = True
                            mismatch_details.append(f"{hash_type.upper()}: {current_hash_clean[:16]}... vs {baseline_hash[:16]}...")
                
                if hash_mismatch:
                    reasons.append("Hash mismatch with baseline")
                    reasons.extend(mismatch_details)
                    severity = 'High'
                    stats['hash_mismatches'] += 1
        
        # Add findings if any issues found
        if reasons:
            row_data['baseline_reasons'] = '; '.join(reasons)
            row_data['baseline_severity'] = severity
            row_data['baseline_path'] = path_norm
            findings.append(row_data)
    
    logger.info(f"Baseline analysis: {stats}")
    return pd.DataFrame(findings) if findings else pd.DataFrame()

# ============================= Advanced Excel Reporting =============================

def create_summary_statistics(df_src: pd.DataFrame, 
                             df_rules: pd.DataFrame,
                             df_pysad_top: Optional[pd.DataFrame],
                             df_baseline: Optional[pd.DataFrame],
                             risk_scores: pd.Series) -> pd.DataFrame:
    """Create comprehensive summary statistics for DFIR analysis"""
    
    stats_data = []
    
    # Basic statistics
    stats_data.extend([
        ("Dataset Overview", "", ""),
        ("Total entries scanned", len(df_src), ""),
        ("Columns in dataset", len(df_src.columns), ""),
        ("Data completeness", f"{(~df_src.isnull().all(axis=1)).sum()}/{len(df_src)}", "Good" if (~df_src.isnull().all(axis=1)).sum()/len(df_src) > 0.9 else "Review"),
        ("", "", ""),
    ])
    
    # Risk analysis
    high_risk_count = (risk_scores >= 7.0).sum()
    medium_risk_count = ((risk_scores >= 4.0) & (risk_scores < 7.0)).sum()
    low_risk_count = ((risk_scores > 0) & (risk_scores < 4.0)).sum()
    
    stats_data.extend([
        ("Risk Assessment", "", ""),
        ("High risk (7.0+)", high_risk_count, "Critical" if high_risk_count > 0 else "Good"),
        ("Medium risk (4.0-6.9)", medium_risk_count, "Review" if medium_risk_count > 10 else "Acceptable"),
        ("Low risk (0.1-3.9)", low_risk_count, "Monitor"),
        ("Clean entries", (risk_scores == 0).sum(), ""),
        ("", "", ""),
    ])
    
    # Rule-based detections
    stats_data.extend([
        ("Rule-Based Detection", "", ""),
        ("Total flagged by rules", len(df_rules), "Critical" if len(df_rules) > 0 else "Good"),
        ("Detection rate", f"{len(df_rules)/len(df_src)*100:.1f}%", ""),
        ("", "", ""),
    ])
    
    # PySAD analysis
    if df_pysad_top is not None:
        stats_data.extend([
            ("Anomaly Detection (PySAD)", "", ""),
            ("Anomalous entries detected", len(df_pysad_top), "Review" if len(df_pysad_top) > 0 else "Good"),
            ("Top anomaly score", f"{df_pysad_top['pysad_score'].max():.3f}" if len(df_pysad_top) > 0 else "N/A", ""),
            ("", "", ""),
        ])
    
    # Baseline comparison
    if df_baseline is not None and len(df_baseline) > 0:
        high_severity = (df_baseline.get('baseline_severity', pd.Series()) == 'High').sum()
        stats_data.extend([
            ("Baseline Analysis", "", ""),
            ("Total baseline deviations", len(df_baseline), "Critical" if len(df_baseline) > 0 else "Good"),
            ("High severity deviations", high_severity, "Critical" if high_severity > 0 else "Good"),
            ("", "", ""),
        ])
    
    # File system analysis
    if 'Image Path' in df_src.columns or any('path' in col.lower() for col in df_src.columns):
        path_col = next((col for col in df_src.columns if 'path' in col.lower()), None)
        if path_col:
            paths = df_src[path_col].dropna()
            user_writable_count = paths.str.contains(r'\\Users\\|\\AppData\\|\\Temp\\', case=False, na=False).sum()
            system_dir_count = paths.str.contains(r'\\Windows\\System32\\|\\Windows\\SysWOW64\\', case=False, na=False).sum()
            
            stats_data.extend([
                ("File System Analysis", "", ""),
                ("Files in user-writable locations", user_writable_count, "Review" if user_writable_count > len(df_src)*0.3 else "Normal"),
                ("Files in system directories", system_dir_count, ""),
                ("Unsigned binaries", (df_src.get('Publisher', pd.Series()).isna()).sum() if 'Publisher' in df_src.columns else "N/A", ""),
                ("", "", ""),
            ])
    
    # Recommendations
    recommendations = []
    if high_risk_count > 0:
        recommendations.append("Immediate investigation of high-risk entries required")
    if len(df_rules) > 0:
        recommendations.append("Review all rule-flagged entries for potential threats")
    if df_baseline is not None and len(df_baseline) > 0:
        high_sev_baseline = (df_baseline.get('baseline_severity') == 'High').sum()
        if high_sev_baseline > 0:
            recommendations.append("Critical: Hash mismatches detected - possible file replacement")
    
    stats_data.extend([
        ("DFIR Recommendations", "", ""),
    ])
    
    for i, rec in enumerate(recommendations[:5], 1):  # Limit to top 5
        stats_data.append((f"Priority {i}", rec, "Action Required"))
    
    # Metadata
    stats_data.extend([
        ("", "", ""),
        ("Analysis Metadata", "", ""),
        ("Analysis timestamp", dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), ""),
        ("Analyzer version", "DFIR v2.0", ""),
    ])
    
    return pd.DataFrame(stats_data, columns=["Metric", "Value", "Status"])

def _format_excel_enhanced(ws, df: pd.DataFrame, wb, sheet_type: str = "data"):
    """Enhanced Excel formatting for DFIR reports"""
    
    # Define formats
    header_fmt = wb.add_format({
        'bold': True,
        'bg_color': '#366092',
        'font_color': 'white',
        'align': 'center',
        'valign': 'vcenter',
        'border': 1
    })
    
    risk_high_fmt = wb.add_format({
        'bg_color': '#FF6B6B',
        'font_color': 'white',
        'bold': True,
        'valign': 'top'
    })
    
    risk_medium_fmt = wb.add_format({
        'bg_color': '#FFD93D',
        'font_color': 'black',
        'valign': 'top'
    })
    
    risk_low_fmt = wb.add_format({
        'bg_color': '#6BCF7F',
        'font_color': 'white',
        'valign': 'top'
    })
    
    wrap_fmt = wb.add_format({'text_wrap': True, 'valign': 'top'})
    num_fmt = wb.add_format({'num_format': '0.000', 'valign': 'top'})
    int_fmt = wb.add_format({'num_format': '0', 'valign': 'top'})
    
    # Apply header formatting
    for col_num, value in enumerate(df.columns):
        ws.write(0, col_num, value, header_fmt)
    
    # Calculate column widths
    max_width, min_width = 80, 10
    col_widths = []
    
    for j, col in enumerate(df.columns):
        width = len(str(col))
        sample_data = df[col].astype(str).head(100)  # Sample for performance
        
        for val in sample_data:
            if pd.notna(val):
                # Handle multi-line content
                val_str = str(val).replace('\r', '')
                line_lengths = [len(line) for line in val_str.split('\n')]
                width = max(width, max(line_lengths) if line_lengths else 0)
        
        width = max(min_width, min(max_width, width))
        col_widths.append(width)
    
    # Apply formatting by column type and content
    for j, col in enumerate(df.columns):
        col_name_lower = col.lower()
        
        # Risk score formatting
        if 'risk' in col_name_lower and 'score' in col_name_lower:
            for i, val in enumerate(df[col], start=1):
                if pd.notna(val) and isinstance(val, (int, float)):
                    if val >= 7.0:
                        ws.write(i, j, val, risk_high_fmt)
                    elif val >= 4.0:
                        ws.write(i, j, val, risk_medium_fmt)
                    elif val > 0:
                        ws.write(i, j, val, risk_low_fmt)
                    else:
                        ws.write(i, j, val, num_fmt)
            ws.set_column(j, j, max(12, min(18, col_widths[j])), num_fmt)
            
        # Numeric columns
        elif pd.api.types.is_numeric_dtype(df[col]):
            if pd.api.types.is_integer_dtype(df[col]):
                ws.set_column(j, j, max(12, min(18, col_widths[j])), int_fmt)
            else:
                ws.set_column(j, j, max(12, min(18, col_widths[j])), num_fmt)
        
        # Special handling for reason columns
        elif any(keyword in col_name_lower for keyword in ['reason', 'description', 'command', 'path']):
            ws.set_column(j, j, min(50, col_widths[j]), wrap_fmt)
        
        # Standard text columns
        else:
            ws.set_column(j, j, col_widths[j], wrap_fmt)
    
    # Add freeze panes and autofilter
    ws.freeze_panes(1, 0)
    if len(df) > 0:
        ws.autofilter(0, 0, len(df), len(df.columns) - 1)

def write_enhanced_report(out_path: str,
                         df_src: pd.DataFrame,
                         df_all: pd.DataFrame,
                         df_rules: pd.DataFrame,
                         df_pysad_all: Optional[pd.DataFrame],
                         df_pysad_top: Optional[pd.DataFrame],
                         df_baseline: Optional[pd.DataFrame],
                         risk_scores: pd.Series,
                         top_pct: float,
                         pysad_method: str):
    """Write comprehensive DFIR Excel report"""
    
    out_path = _ensure_xlsx(out_path)
    logger.info(f"Writing enhanced DFIR report to: {out_path}")
    
    with pd.ExcelWriter(out_path, engine="xlsxwriter") as writer:
        wb = writer.book
        
        # 1. Executive Summary
        summary_df = create_summary_statistics(df_src, df_rules, df_pysad_top, df_baseline, risk_scores)
        summary_df.to_excel(writer, sheet_name="Executive_Summary", index=False)
        _format_excel_enhanced(writer.sheets["Executive_Summary"], summary_df, wb, "summary")
        
        # 2. High-Risk Findings (Risk score >= 7)
        high_risk_df = df_all[risk_scores >= 7.0].copy()
        if len(high_risk_df) > 0:
            high_risk_df['risk_score'] = risk_scores[risk_scores >= 7.0].values
            high_risk_df.to_excel(writer, sheet_name="High_Risk_Findings", index=False)
            _format_excel_enhanced(writer.sheets["High_Risk_Findings"], high_risk_df, wb)
        
        # 3. All Rule-Based Detections
        if len(df_rules) > 0:
            df_rules.to_excel(writer, sheet_name="Rule_Detections", index=False)
            _format_excel_enhanced(writer.sheets["Rule_Detections"], df_rules, wb)
        
        # 4. PySAD Anomalies
        if df_pysad_top is not None and len(df_pysad_top) > 0:
            df_pysad_top.to_excel(writer, sheet_name="Anomaly_Detection", index=False)
            _format_excel_enhanced(writer.sheets["Anomaly_Detection"], df_pysad_top, wb)
        
        # 5. Baseline Deviations
        if df_baseline is not None and len(df_baseline) > 0:
            df_baseline.to_excel(writer, sheet_name="Baseline_Deviations", index=False)
            _format_excel_enhanced(writer.sheets["Baseline_Deviations"], df_baseline, wb)
        
        # 6. Complete Dataset with Risk Scores
        df_complete = df_all.copy()
        if 'risk_score' in df_complete.columns:
            df_complete = df_complete.drop('risk_score', axis=1)
        df_complete.insert(0, 'risk_score', risk_scores.values)
        df_complete = df_complete.sort_values('risk_score', ascending=False)
        df_complete.to_excel(writer, sheet_name="Complete_Dataset", index=False)
        _format_excel_enhanced(writer.sheets["Complete_Dataset"], df_complete, wb)
        
        # 7. All PySAD Scores (if available)
        if df_pysad_all is not None:
            df_pysad_all.to_excel(writer, sheet_name="All_PySAD_Scores", index=False)
            _format_excel_enhanced(writer.sheets["All_PySAD_Scores"], df_pysad_all, wb)

    logger.info("Enhanced DFIR report completed successfully")

# ============================= Main Analysis Function =============================

def main_dfir_enhanced(csv_path: str,
                      out_xlsx: str = "dfir_autoruns_report.xlsx",
                      top_pct: float = 3.0,
                      baseline_csv: Optional[str] = None,
                      pysad_method: str = "hst",
                      enable_pysad: bool = True) -> Dict[str, any]:
    """
    Enhanced main function for DFIR autoruns analysis
    
    Returns analysis results for potential integration with other DFIR tools
    """
    
    start_time = dt.datetime.now()
    logger.info("=" * 60)
    logger.info("DFIR AUTORUNS ANALYZER v2.0 - ANALYSIS STARTED")
    logger.info("=" * 60)
    
    try:
        # Input validation
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"Input file not found: {csv_path}")
        
        # Validate parameters
        if not 0.1 <= top_pct <= 50.0:
            logger.warning(f"Unusual top_pct value: {top_pct}, using 3.0")
            top_pct = 3.0
        
        if pysad_method not in ["hst", "loda"]:
            logger.warning(f"Unknown PySAD method: {pysad_method}, using 'hst'")
            pysad_method = "hst"
        
        # Load and validate autoruns data
        logger.info(f"Loading autoruns data from: {csv_path}")
        df = autoruns_to_dataframe(csv_path)
        
        if df.empty:
            raise ValueError("No data found in autoruns file")
        
        logger.info(f"Successfully loaded {len(df)} entries with {len(df.columns)} columns")
        
        # Enhanced rule-based analysis
        logger.info("Performing enhanced rule-based analysis...")
        rules_mask, rule_reasons, risk_scores = rule_flags_with_reason_enhanced(df)
        df_rules = df.loc[rules_mask].copy()
        
        if len(df_rules) > 0:
            df_rules.insert(len(df_rules.columns), "rule_reason", rule_reasons[rules_mask].values)
            df_rules.insert(len(df_rules.columns), "risk_score", risk_scores[rules_mask].values)
        
        logger.info(f"Rule-based analysis: {len(df_rules)} suspicious entries found")
        
        # PySAD anomaly detection
        df_pysad_all, df_pysad_top = None, None
        if enable_pysad:
            try:
                logger.info(f"Performing PySAD anomaly detection ({pysad_method.upper()})...")
                features = build_features_for_pysad_enhanced(df)
                pysad_scores = pysad_scores_enhanced(features, method=pysad_method)
                
                df_pysad_all = df.copy()
                df_pysad_all.insert(len(df_pysad_all.columns), "pysad_score", np.round(pysad_scores, 3))
                
                # Select top anomalies
                k = max(1, int(math.ceil(len(df) * (top_pct / 100.0))))
                if len(pysad_scores) > 0:
                    thresh = np.partition(pysad_scores, -k)[-k]
                    df_pysad_top = df_pysad_all[pysad_scores >= thresh].sort_values("pysad_score", ascending=False)
                    
                logger.info(f"PySAD analysis: {len(df_pysad_top)} anomalies detected (top {top_pct}%)")
                
            except Exception as e:
                logger.error(f"PySAD analysis failed: {e}")
                enable_pysad = False
        
        # Baseline comparison
        df_baseline = pd.DataFrame()
        if baseline_csv:
            try:
                logger.info(f"Loading baseline from: {baseline_csv}")
                baseline_paths, baseline_hashes = load_baseline_enhanced(baseline_csv)
                
                if baseline_paths:
                    logger.info("Comparing against baseline...")
                    df_baseline = compare_against_baseline_enhanced(df, baseline_paths, baseline_hashes)
                    logger.info(f"Baseline analysis: {len(df_baseline)} deviations found")
                else:
                    logger.warning("Baseline loaded but contains no valid entries")
                    
            except Exception as e:
                logger.error(f"Baseline analysis failed: {e}")
        
        # Prepare complete dataset
        df_all = df.copy()
        df_all.insert(len(df_all.columns), "rule_reason", rule_reasons.values)
        df_all.insert(len(df_all.columns), "risk_score", risk_scores.values)
        
        # Write comprehensive report
        logger.info("Generating comprehensive DFIR report...")
        write_enhanced_report(
            out_xlsx, df, df_all, df_rules, df_pysad_all, df_pysad_top, 
            df_baseline, risk_scores, top_pct, pysad_method
        )
        
        # Analysis summary
        analysis_time = dt.datetime.now() - start_time
        high_risk_count = (risk_scores >= 7.0).sum()
        
        logger.info("=" * 60)
        logger.info("ANALYSIS COMPLETED SUCCESSFULLY")
        logger.info("=" * 60)
        logger.info(f"Analysis time: {analysis_time.total_seconds():.1f} seconds")
        logger.info(f"Total entries analyzed: {len(df):,}")
        logger.info(f"High-risk findings: {high_risk_count}")
        logger.info(f"Rule-based detections: {len(df_rules)}")
        
        if enable_pysad and df_pysad_top is not None:
            logger.info(f"PySAD anomalies (top {top_pct}%): {len(df_pysad_top)}")
        
        if baseline_csv:
            logger.info(f"Baseline deviations: {len(df_baseline)}")
        
        logger.info(f"Report saved to: {out_xlsx}")
        
        # Return results for potential integration
        return {
            'success': True,
            'analysis_time': analysis_time.total_seconds(),
            'total_entries': len(df),
            'high_risk_count': high_risk_count,
            'rule_detections': len(df_rules),
            'anomaly_detections': len(df_pysad_top) if df_pysad_top is not None else 0,
            'baseline_deviations': len(df_baseline),
            'report_path': out_xlsx,
            'dataframes': {
                'all_data': df_all,
                'rules': df_rules,
                'high_risk': df_all[risk_scores >= 7.0],
                'pysad_top': df_pysad_top,
                'baseline_issues': df_baseline
            }
        }
        
    except Exception as e:
        logger.error(f"Analysis failed: {e}", exc_info=True)
        return {
            'success': False,
            'error': str(e),
            'analysis_time': (dt.datetime.now() - start_time).total_seconds()
        }

# ============================= DFIR Integration Helpers =============================

def export_iocs(df_flagged: pd.DataFrame, output_path: str = "autoruns_iocs.json") -> Dict[str, List[str]]:
    """Export IOCs in structured format for SIEM/threat hunting integration"""
    
    iocs = {
        'file_paths': [],
        'file_hashes': {'sha256': [], 'sha1': [], 'md5': []},
        'registry_keys': [],
        'suspicious_commands': [],
        'network_indicators': []
    }
    
    # Extract file paths
    path_cols = [col for col in df_flagged.columns if any(keyword in col.lower() 
                for keyword in ['path', 'image', 'location', 'command'])]
    
    for col in path_cols:
        paths = df_flagged[col].dropna().astype(str).unique()
        for path in paths:
            if path and len(path) > 3:
                iocs['file_paths'].append(path.strip('"'))
    
    # Extract hashes
    hash_cols = {
        'sha256': [col for col in df_flagged.columns if 'sha' in col.lower() and '256' in col.lower()],
        'sha1': [col for col in df_flagged.columns if 'sha' in col.lower() and '1' in col.lower()],
        'md5': [col for col in df_flagged.columns if 'md5' in col.lower()]
    }
    
    for hash_type, cols in hash_cols.items():
        for col in cols:
            if col in df_flagged.columns:
                hashes = df_flagged[col].dropna().astype(str).unique()
                for hash_val in hashes:
                    if hash_val and len(hash_val) > 10:
                        iocs['file_hashes'][hash_type].append(hash_val.lower())
    
    # Extract registry locations
    reg_cols = [col for col in df_flagged.columns if 'reg' in col.lower() or 'entry' in col.lower()]
    for col in reg_cols:
        reg_entries = df_flagged[col].dropna().astype(str).unique()
        for entry in reg_entries:
            if entry and ('HKLM' in entry or 'HKCU' in entry):
                iocs['registry_keys'].append(entry)
    
    # Save to JSON
    try:
        with open(output_path, 'w') as f:
            json.dump(iocs, f, indent=2)
        logger.info(f"IOCs exported to: {output_path}")
    except Exception as e:
        logger.error(f"Failed to export IOCs: {e}")
    
    return iocs

def generate_yara_rules(df_flagged: pd.DataFrame, output_path: str = "autoruns_detection.yar") -> str:
    """Generate basic YARA rules for detected suspicious patterns"""
    
    timestamp = dt.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    current_date = dt.datetime.now().strftime('%Y-%m-%d')
    
    yara_content = f'''/*
    YARA Rules Generated from Autoruns DFIR Analysis
    Generated: {timestamp}
    
    These rules detect patterns found in suspicious autoruns entries
*/

import "pe"

'''
    
    # Rule for suspicious file paths
    suspicious_paths = []
    path_cols = [col for col in df_flagged.columns if 'path' in col.lower()]
    
    for col in path_cols:
        paths = df_flagged[col].dropna().astype(str)
        for path in paths:
            if any(indicator in path.lower() for indicator in ['temp', 'appdata', 'programdata']):
                basename = os.path.basename(path.lower())
                if basename and basename not in suspicious_paths:
                    suspicious_paths.append(basename)
    
    if suspicious_paths:
        yara_content += f'''rule Suspicious_Autoruns_Paths
{{
    meta:
        description = "Detects files found in suspicious autoruns locations"
        author = "DFIR Autoruns Analyzer"
        date = "{current_date}"
        
    strings:
'''
        
        for i, path in enumerate(suspicious_paths[:20]):  # Limit to prevent overly long rules
            yara_content += f'        $path{i} = "{path}" nocase\n'
        
        yara_content += '''        
    condition:
        any of ($path*)
}}

'''
    
    # Rule for high entropy strings (obfuscation)
    yara_content += '''rule High_Entropy_Autoruns
{{
    meta:
        description = "Detects high entropy strings in autoruns entries (possible obfuscation)"
        author = "DFIR Autoruns Analyzer"
        
    condition:
        pe.is_pe and
        math.entropy(0, filesize) > 7.0
}}

'''
    
    # Save YARA rules
    try:
        with open(output_path, 'w') as f:
            f.write(yara_content)
        logger.info(f"YARA rules exported to: {output_path}")
    except Exception as e:
        logger.error(f"Failed to export YARA rules: {e}")
    
    return yara_content

def generate_sigma_rules(df_flagged: pd.DataFrame, output_path: str = "autoruns_sigma.yml") -> str:
    """Generate Sigma detection rules for SIEM integration"""
    
    sigma_content = '''title: Suspicious Autoruns Activity
id: {rule_id}
description: Detects suspicious autoruns entries identified by DFIR analysis
author: DFIR Team
date: {date}
tags:
    - attack.persistence
    - attack.t1547
    - autoruns
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 1  # Process Creation
        Image|contains:
'''.format(
    rule_id=hashlib.md5(f"autoruns_{dt.datetime.now()}".encode()).hexdigest()[:8],
    date=dt.datetime.now().strftime('%Y/%m/%d')
)
    
    # Extract suspicious executables
    suspicious_files = set()
    path_cols = [col for col in df_flagged.columns if 'path' in col.lower()]
    
    for col in path_cols:
        paths = df_flagged[col].dropna().astype(str)
        for path in paths:
            basename = os.path.basename(path.lower())
            if basename.endswith(('.exe', '.com', '.scr', '.pif')):
                suspicious_files.add(basename)
    
    for filename in list(suspicious_files)[:10]:  # Limit for readability
        sigma_content += f'            - "{filename}"\n'
    
    sigma_content += '''    condition: selection
falsepositives:
    - Legitimate software installations
    - Administrative activities
level: medium
'''
    
    # Save Sigma rules
    try:
        with open(output_path, 'w') as f:
            f.write(sigma_content)
        logger.info(f"Sigma rules exported to: {output_path}")
    except Exception as e:
        logger.error(f"Failed to export Sigma rules: {e}")
    
    return sigma_content

def create_timeline_analysis(df: pd.DataFrame) -> Optional[pd.DataFrame]:
    """Create timeline analysis from timestamp columns"""
    
    time_cols = [col for col in df.columns if any(keyword in col.lower() 
                for keyword in ['time', 'date', 'created', 'modified'])]
    
    if not time_cols:
        logger.warning("No timestamp columns found for timeline analysis")
        return None
    
    timeline_data = []
    
    for col in time_cols:
        try:
            timestamps = pd.to_datetime(df[col], errors='coerce').dropna()
            for idx, ts in timestamps.items():
                row_data = df.loc[idx]
                timeline_data.append({
                    'timestamp': ts,
                    'event_type': col,
                    'entry_name': row_data.get('Entry', 'Unknown'),
                    'image_path': row_data.get('Image Path', ''),
                    'description': row_data.get('Description', ''),
                    'risk_score': row_data.get('risk_score', 0)
                })
        except Exception as e:
            logger.debug(f"Failed to process timestamp column {col}: {e}")
            continue
    
    if not timeline_data:
        return None
    
    timeline_df = pd.DataFrame(timeline_data)
    timeline_df = timeline_df.sort_values('timestamp')
    
    logger.info(f"Timeline analysis created with {len(timeline_df)} events")
    return timeline_df

# ============================= CLI and Entry Point =============================

def parse_arguments():
    """Parse command line arguments for DFIR analysis"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="DFIR Autoruns Analyzer v2.0 - Production CIRT/DFIR Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  Basic analysis:
    python dfir_autoruns.py autoruns.csv
    
  Full analysis with baseline:
    python dfir_autoruns.py autoruns.csv -o incident_report.xlsx -b baseline.csv
    
  High sensitivity analysis:
    python dfir_autoruns.py autoruns.csv -t 1.0 --pysad-method loda
    
  Export IOCs for threat hunting:
    python dfir_autoruns.py autoruns.csv --export-iocs --export-yara --export-sigma
        """
    )
    
    parser.add_argument("input_file", help="Autoruns CSV/TSV export file")
    parser.add_argument("-o", "--output", default="dfir_autoruns_report.xlsx",
                       help="Output Excel report file (default: dfir_autoruns_report.xlsx)")
    parser.add_argument("-t", "--top-percent", type=float, default=3.0,
                       help="Top percentage for PySAD anomaly detection (default: 3.0)")
    parser.add_argument("-b", "--baseline", help="Baseline CSV file for comparison")
    parser.add_argument("--pysad-method", choices=["hst", "loda"], default="hst",
                       help="PySAD anomaly detection method (default: hst)")
    parser.add_argument("--disable-pysad", action="store_true",
                       help="Disable PySAD anomaly detection")
    parser.add_argument("--export-iocs", action="store_true",
                       help="Export IOCs to JSON file")
    parser.add_argument("--export-yara", action="store_true",
                       help="Export YARA detection rules")
    parser.add_argument("--export-sigma", action="store_true",
                       help="Export Sigma detection rules")
    parser.add_argument("--timeline", action="store_true",
                       help="Generate timeline analysis")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose logging")
    
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_arguments()
    
    # Configure logging level
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    try:
        # Run main analysis
        results = main_dfir_enhanced(
            csv_path=args.input_file,
            out_xlsx=args.output,
            top_pct=args.top_percent,
            baseline_csv=args.baseline,
            pysad_method=args.pysad_method,
            enable_pysad=not args.disable_pysad
        )
        
        if not results['success']:
            logger.error(f"Analysis failed: {results['error']}")
            sys.exit(1)
        
        # Additional exports if requested
        dataframes = results.get('dataframes', {})
        
        if args.export_iocs and 'rules' in dataframes and len(dataframes['rules']) > 0:
            export_iocs(dataframes['rules'], "autoruns_iocs.json")
        
        if args.export_yara and 'rules' in dataframes and len(dataframes['rules']) > 0:
            generate_yara_rules(dataframes['rules'], "autoruns_detection.yar")
        
        if args.export_sigma and 'rules' in dataframes and len(dataframes['rules']) > 0:
            generate_sigma_rules(dataframes['rules'], "autoruns_sigma.yml")
        
        if args.timeline and 'all_data' in dataframes:
            timeline_df = create_timeline_analysis(dataframes['all_data'])
            if timeline_df is not None:
                timeline_path = args.output.replace('.xlsx', '_timeline.xlsx')
                with pd.ExcelWriter(timeline_path, engine="xlsxwriter") as writer:
                    timeline_df.to_excel(writer, sheet_name="Timeline", index=False)
                logger.info(f"Timeline analysis saved to: {timeline_path}")
        
        # Print summary
        print("\n" + "="*60)
        print("DFIR AUTORUNS ANALYSIS COMPLETE")
        print("="*60)
        print(f"Total entries analyzed: {results['total_entries']:,}")
        print(f"High-risk findings: {results['high_risk_count']}")
        print(f"Rule-based detections: {results['rule_detections']}")
        print(f"Anomaly detections: {results['anomaly_detections']}")
        print(f"Baseline deviations: {results['baseline_deviations']}")
        print(f"Analysis time: {results['analysis_time']:.1f} seconds")
        print(f"Report saved to: {results['report_path']}")
        print("="*60)
        
        # Exit with appropriate code
        critical_findings = results['high_risk_count'] + results['rule_detections']
        if critical_findings > 0:
            print(f"\n⚠️  CRITICAL: {critical_findings} suspicious findings detected!")
            print("   Immediate investigation recommended.")
            sys.exit(2)  # Exit code 2 for findings
        else:
            print("\n✅ No critical findings detected.")
            sys.exit(0)  # Clean exit
            
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=True)
        sys.exit(1)