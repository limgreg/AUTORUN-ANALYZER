"""
Baseline comparison functionality for detecting deviations.
"""

import pandas as pd
from .utils import normalize_path


def load_baseline(baseline_csv: str) -> tuple[set, dict]:
    """
    Load baseline data from CSV file.
    
    Args:
        baseline_csv: Path to baseline CSV file
        
    Returns:
        tuple: (set of normalized paths, dict of path->hash mappings)
        
    Raises:
        ValueError: If baseline file lacks required columns
    """
    if not baseline_csv:
        return set(), {}
    
    # Try different encodings
    try:
        bdf = pd.read_csv(baseline_csv, engine="python")
    except UnicodeError:
        try:
            bdf = pd.read_csv(baseline_csv, engine="python", encoding="utf-16")
        except Exception:
            bdf = pd.read_csv(baseline_csv, engine="python", encoding="utf-8", errors="ignore")

    # Find path column
    cols_lower = {c.lower(): c for c in bdf.columns}
    path_candidates = ["fullname", "path", "image path", "image", "full path", "filepath"]
    path_col = next((cols_lower[n] for n in path_candidates if n in cols_lower), None)
    
    if not path_col:
        raise ValueError("Baseline CSV missing a Path-like column (e.g., FullName/Path/Image).")
    
    bdf.rename(columns={path_col: "Path"}, inplace=True)

    # Find hash columns (prefer SHA256 > SHA1 > MD5)
    sha256_col = cols_lower.get("sha256") or cols_lower.get("sha-256")
    sha1_col = cols_lower.get("sha1") or cols_lower.get("sha-1")
    md5_col = cols_lower.get("md5")

    baseline_paths = set()
    baseline_hash_by_path = {}

    for _, row in bdf.iterrows():
        p = normalize_path(row.get("Path", ""))
        if not p:
            continue
        
        baseline_paths.add(p)

        # Extract hash (prefer SHA256)
        h = None
        if sha256_col and pd.notna(row.get(sha256_col)):
            h = str(row.get(sha256_col)).strip().lower()
        elif sha1_col and pd.notna(row.get(sha1_col)):
            h = str(row.get(sha1_col)).strip().lower()
        elif md5_col and pd.notna(row.get(md5_col)):
            h = str(row.get(md5_col)).strip().lower()

        if h:
            baseline_hash_by_path[p] = h

    return baseline_paths, baseline_hash_by_path


def compare_against_baseline(df: pd.DataFrame, baseline_paths: set, baseline_hash_by_path: dict) -> pd.DataFrame:
    """
    Compare DataFrame entries against baseline data.
    
    Args:
        df: Input DataFrame
        baseline_paths: Set of known good paths
        baseline_hash_by_path: Dictionary mapping paths to expected hashes
        
    Returns:
        DataFrame with baseline findings (deviations)
    """
    # Find path column
    col_img = next((c for c in df.columns if c.lower() in
                   ["image path", "image", "path", "location", "command", "fullname"]), None)
    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    norm_path = text.apply(normalize_path)

    # Find hash columns
    cols_lower = {c.lower(): c for c in df.columns}
    sha256_col = cols_lower.get("sha-256") or cols_lower.get("sha256")
    sha1_col = cols_lower.get("sha-1") or cols_lower.get("sha1")
    md5_col = cols_lower.get("md5")

    findings = []
    for i in df.index:
        p = norm_path.iat[i]
        if not p:
            continue

        reason = []
        
        # Check if path exists in baseline
        if p not in baseline_paths:
            reason.append("Not present in Vanilla baseline")
            # Extra suspicious if it's in system directories
            if p.startswith(r"c:\windows") or p.startswith(r"c:\program files") or p.startswith(r"c:\program files (x86)"):
                reason.append("Unexpected path under system/program dirs")
        else:
            # Path exists in baseline, check hash if available
            baseline_hash = baseline_hash_by_path.get(p)
            if baseline_hash:
                # Get current file hash
                row_hash = None
                if sha256_col and pd.notna(df.at[i, sha256_col]):
                    row_hash = str(df.at[i, sha256_col]).strip().lower()
                elif sha1_col and pd.notna(df.at[i, sha1_col]):
                    row_hash = str(df.at[i, sha1_col]).strip().lower()
                elif md5_col and pd.notna(df.at[i, md5_col]):
                    row_hash = str(df.at[i, md5_col]).strip().lower()
                
                if row_hash and row_hash != baseline_hash:
                    reason.append("Hash mismatch vs baseline")

        # Add to findings if any issues detected
        if reason:
            row_out = df.loc[i].copy()
            row_out["baseline_reason"] = "; ".join(reason)
            findings.append(row_out)

    return pd.DataFrame(findings)