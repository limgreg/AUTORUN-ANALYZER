"""
Pure File Integrity Module - baseline_comparison.py
ONLY compares file hashes for integrity verification. No path analysis.
"""

import pandas as pd
from ..core.baseline import load_baseline
from ..core.utils import normalize_path


def detect_baseline_deviations(df: pd.DataFrame, baseline_csv: str) -> pd.DataFrame:
    """
    PURE FILE INTEGRITY CHECKING - answers: "Has this file been modified/replaced?"
    
    This module ONLY cares about file integrity via hash comparison.
    Path analysis is handled by suspicious_paths.py module.
    
    Args:
        df: Input DataFrame
        baseline_csv: Path to baseline CSV (REQUIRED for hash comparison)
        
    Returns:
        DataFrame with file integrity violations only
    """
    if not baseline_csv:
        print("[!] No baseline CSV provided - integrity checking disabled")
        return pd.DataFrame()
    
    try:
        baseline_paths, baseline_hash_by_path = load_baseline(baseline_csv)
        print(f"[+] Loaded baseline: {len(baseline_hash_by_path)} files with hashes for integrity checking")
    except Exception as e:
        print(f"[!] Failed to load baseline for integrity checking: {e}")
        return pd.DataFrame()
    
    if not baseline_hash_by_path:
        print("[!] No hash data in baseline - integrity checking disabled")
        return pd.DataFrame()
    
    findings = []
    
    # Find path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        print("[!] No path column found - cannot perform integrity checking")
        return pd.DataFrame()
    
    # Find hash columns (prefer SHA256 > SHA1 > MD5)
    cols_lower = {c.lower(): c for c in df.columns}
    sha256_col = cols_lower.get("sha-256") or cols_lower.get("sha256")
    sha1_col = cols_lower.get("sha-1") or cols_lower.get("sha1") 
    md5_col = cols_lower.get("md5")
    
    if not any([sha256_col, sha1_col, md5_col]):
        print("[!] No hash columns found in data - cannot perform integrity checking")
        return pd.DataFrame()
    
    hash_checks_performed = 0
    
    for i in df.index:
        path = str(df.at[i, col_img]).strip()
        if not path or path == "nan":
            continue
            
        normalized_path = normalize_path(path)
        
        # CORE QUESTION: Do we have a baseline hash for this file?
        expected_hash = baseline_hash_by_path.get(normalized_path)
        if not expected_hash:
            continue  # No baseline hash = no integrity check possible
        
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
            continue  # No current hash = no integrity check possible
        
        hash_checks_performed += 1
        
        # INTEGRITY CHECK: Does current hash match baseline?
        if current_hash != expected_hash:
            severity = _determine_integrity_violation_severity(normalized_path)
            
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = f"[{severity}] File integrity violation ({hash_type} hash mismatch)"
            row_out["detection_type"] = "File Integrity Violation"
            row_out["violation_severity"] = severity
            row_out["hash_type"] = hash_type
            row_out["expected_hash"] = expected_hash
            row_out["actual_hash"] = current_hash
            row_out["integrity_status"] = "COMPROMISED"
            findings.append(row_out)
    
    print(f"[+] Performed {hash_checks_performed} integrity checks, found {len(findings)} violations")
    return pd.DataFrame(findings)


def _determine_integrity_violation_severity(file_path: str) -> str:
    """
    Determine severity of integrity violation based on file location.
    System files are more critical than user applications.
    """
    path_lower = file_path.lower()
    
    # CRITICAL: Core system files
    if any(critical_dir in path_lower for critical_dir in [
        'c:\\windows\\system32\\',
        'c:\\windows\\syswow64\\',
        'c:\\windows\\winsxs\\',
        'c:\\windows\\system\\',
    ]):
        return "CRITICAL"
    
    # HIGH: Other Windows files
    if path_lower.startswith('c:\\windows\\'):
        return "HIGH"
    
    # HIGH: Microsoft program files
    if any(ms_dir in path_lower for ms_dir in [
        'c:\\program files\\microsoft\\',
        'c:\\program files\\common files\\microsoft\\',
        'c:\\program files (x86)\\microsoft\\',
    ]):
        return "HIGH"
    
    # MEDIUM: Other program files
    if (path_lower.startswith('c:\\program files\\') or 
        path_lower.startswith('c:\\program files (x86)\\')):
        return "MEDIUM"
    
    # LOW: Other locations
    return "LOW"


def get_integrity_analysis_summary(baseline_csv: str = None) -> dict:
    """
    Get summary of file integrity checking capabilities.
    """
    if not baseline_csv:
        return {
            'status': 'Disabled',
            'reason': 'No baseline CSV provided',
            'capability': 'File integrity checking requires baseline with hashes'
        }
    
    try:
        baseline_paths, baseline_hash_by_path = load_baseline(baseline_csv)
        
        if not baseline_hash_by_path:
            return {
                'status': 'Limited',
                'reason': 'Baseline has no hash data',
                'capability': 'Cannot perform integrity verification'
            }
        
        # Analyze hash coverage by file type and location
        hash_coverage = {
            'total_files_with_hashes': len(baseline_hash_by_path),
            'total_baseline_files': len(baseline_paths),
            'coverage_percentage': round(len(baseline_hash_by_path) / len(baseline_paths) * 100, 1) if baseline_paths else 0
        }
        
        # Categorize by location for severity analysis
        location_coverage = {
            'system32_files': len([p for p in baseline_hash_by_path.keys() if 'system32' in p]),
            'windows_files': len([p for p in baseline_hash_by_path.keys() if 'c:\\windows\\' in p]),
            'program_files': len([p for p in baseline_hash_by_path.keys() if 'program files' in p]),
            'other_files': 0
        }
        
        # Calculate other
        categorized = sum(location_coverage.values()) - location_coverage['other_files']
        location_coverage['other_files'] = len(baseline_hash_by_path) - categorized
        
        return {
            'status': 'Active',
            'capability': 'Full file integrity verification',
            'baseline_file': baseline_csv,
            'hash_coverage': hash_coverage,
            'location_coverage': location_coverage,
            'severity_levels': ['CRITICAL (system32)', 'HIGH (windows)', 'MEDIUM (programs)', 'LOW (other)']
        }
        
    except Exception as e:
        return {
            'status': 'Failed',
            'reason': f'Cannot load baseline: {str(e)}',
            'capability': 'File integrity checking unavailable'
        }


def print_integrity_summary(summary: dict):
    """
    Print file integrity checking configuration.
    """
    print("\n" + "="*50)
    print("FILE INTEGRITY VERIFICATION")
    print("="*50)
    
    if summary['status'] == 'Active':
        print(f"✅ Status: {summary['status']}")
        print(f"📁 Baseline: {summary['baseline_file']}")
        
        coverage = summary['hash_coverage']
        print(f"🔒 Hash coverage: {coverage['total_files_with_hashes']:,}/{coverage['total_baseline_files']:,} ({coverage['coverage_percentage']:.1f}%)")
        
        location = summary['location_coverage']
        print(f"\n📊 Integrity monitoring by location:")
        print(f"   System32: {location['system32_files']:,} files")
        print(f"   Windows: {location['windows_files']:,} files") 
        print(f"   Program Files: {location['program_files']:,} files")
        print(f"   Other: {location['other_files']:,} files")
        
        print(f"\n🎯 Integrity violation severity:")
        for level in summary['severity_levels']:
            print(f"   {level}")
            
    else:
        print(f"❌ Status: {summary['status']}")
        print(f"❓ Reason: {summary['reason']}")
        print(f"💡 Note: {summary['capability']}")
    
    print("="*50)