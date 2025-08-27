"""
File integrity checking via baseline hash comparison.
"""

import pandas as pd
from ..core.baseline import load_baseline
from ..core.utils import normalize_path


def detect_baseline_deviations(df: pd.DataFrame, baseline_csv: str) -> pd.DataFrame:
    """
    Detect file integrity violations through hash comparison against baseline.
    
    Args:
        df: Input DataFrame
        baseline_csv: Path to baseline CSV (required for hash comparison)
        
    Returns:
        DataFrame with file integrity violations
    """
    if not baseline_csv:
        return pd.DataFrame()
    
    try:
        baseline_paths, baseline_hash_by_path = load_baseline(baseline_csv)
        print(f"[+] Loaded baseline: {len(baseline_hash_by_path)} files with hashes")
    except Exception as e:
        print(f"[!] Failed to load baseline: {e}")
        return pd.DataFrame()
    
    if not baseline_hash_by_path:
        return pd.DataFrame()
    
    findings = []
    
    # Find path and hash columns
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        return pd.DataFrame()
    
    cols_lower = {c.lower(): c for c in df.columns}
    sha256_col = cols_lower.get("sha-256") or cols_lower.get("sha256")
    sha1_col = cols_lower.get("sha-1") or cols_lower.get("sha1") 
    md5_col = cols_lower.get("md5")
    
    if not any([sha256_col, sha1_col, md5_col]):
        return pd.DataFrame()
    
    hash_checks_performed = 0
    
    for i in df.index:
        path = str(df.at[i, col_img]).strip()
        if not path or path == "nan":
            continue
            
        normalized_path = normalize_path(path)
        expected_hash = baseline_hash_by_path.get(normalized_path)
        if not expected_hash:
            continue
        
        # Get current file hash (prefer SHA256)
        current_hash = None
        hash_type = None
        
        if sha256_col and pd.notna(df.at[i, sha256_col]):
            current_hash = str(df.at[i, sha256_col]).strip().lower()
            hash_type = "SHA256"
        elif sha1_col and pd.notna(df.at[i, sha1_col]):
            current_hash = str(df.at[i, sha1_col]).strip().lower()
            hash_type = "SHA1"
        elif md5_col and pd.notna(df.at[i, md5_col]):
            current_hash = str(df.at[i, md5_col]).strip().lower()
            hash_type = "MD5"
        
        if not current_hash:
            continue
        
        hash_checks_performed += 1
        
        # Check for hash mismatch
        if current_hash != expected_hash:
            severity = _determine_integrity_severity(normalized_path)
            
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = f"File integrity violation ({hash_type} hash mismatch)"
            row_out["detection_type"] = "File Integrity Violation"
            row_out["violation_severity"] = severity
            row_out["hash_type"] = hash_type
            row_out["expected_hash"] = expected_hash
            row_out["actual_hash"] = current_hash
            findings.append(row_out)
    
    print(f"[+] Performed {hash_checks_performed} integrity checks, found {len(findings)} violations")
    return pd.DataFrame(findings)


def _determine_integrity_severity(file_path: str) -> str:
    """Determine severity based on file location."""
    path_lower = file_path.lower()
    
    # Critical: Core system files
    if any(critical_dir in path_lower for critical_dir in [
        'c:\\windows\\system32\\',
        'c:\\windows\\syswow64\\',
        'c:\\windows\\winsxs\\',
    ]):
        return "Critical"
    
    # High: Other Windows files
    if path_lower.startswith('c:\\windows\\'):
        return "High"
    
    # High: Microsoft program files
    if any(ms_dir in path_lower for ms_dir in [
        'c:\\program files\\microsoft\\',
        'c:\\program files\\common files\\microsoft\\',
        'c:\\program files (x86)\\microsoft\\',
    ]):
        return "High"
    
    # Medium: Other program files
    if (path_lower.startswith('c:\\program files\\') or 
        path_lower.startswith('c:\\program files (x86)\\')):
        return "Medium"
    
    return "Low"