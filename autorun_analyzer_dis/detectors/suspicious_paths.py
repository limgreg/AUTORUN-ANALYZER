"""
Baseline-focused suspicious paths detector.
Removed generic rule-based detection in favor of baseline-driven analysis.
"""

import pandas as pd
import os
from ..core.baseline import load_baseline
from ..core.utils import normalize_path


def detect_suspicious_paths(df: pd.DataFrame, baseline_csv: str = None) -> pd.DataFrame:
    """
    Detect suspicious file paths using baseline comparison as the primary method.
    Only includes minimal critical rules as fallback when no baseline is available.
    
    Args:
        df: Input DataFrame
        baseline_csv: Path to baseline CSV (REQUIRED for meaningful results)
        
    Returns:
        DataFrame with suspicious path findings
    """
    # Find path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        return pd.DataFrame()
    
    findings = []
    
    # PRIMARY METHOD: Baseline-driven detection
    if baseline_csv:
        findings.extend(_baseline_driven_detection(df, col_img, baseline_csv))
    else:
        # FALLBACK: Only most critical rules when no baseline available
        print("[!] No baseline provided for suspicious paths - using minimal fallback detection")
        findings.extend(_critical_fallback_detection(df, col_img))
    
    return pd.DataFrame(findings)


def _baseline_driven_detection(df: pd.DataFrame, col_img: str, baseline_csv: str) -> list:
    """
    Primary detection method using baseline comparison.
    Much more accurate than rule-based detection.
    """
    try:
        baseline_paths, baseline_hash_by_path = load_baseline(baseline_csv)
        print(f"[+] Loaded {len(baseline_paths)} baseline paths for suspicious path analysis")
    except Exception as e:
        print(f"[!] Failed to load baseline: {e}")
        return []
    
    findings = []
    
    for i in df.index:
        path = str(df.at[i, col_img]).strip()
        if not path or path == "nan":
            continue
            
        path_lower = path.lower()
        normalized_path = normalize_path(path)
        reasons = []
        suspicion_level = "Medium"
        
        # Check if path is NOT in baseline
        if normalized_path and normalized_path not in baseline_paths:
            
            # CRITICAL: Unknown paths in system directories (HIGH PRIORITY)
            if any(sys_path in path_lower for sys_path in [
                'c:\\windows\\system32\\',
                'c:\\windows\\syswow64\\',
                'c:\\windows\\',
                'c:\\program files\\microsoft\\',
                'c:\\program files\\windows'
            ]):
                reasons.append("Unknown file in critical system directory (not in baseline)")
                suspicion_level = "Critical"
            
            # HIGH: Unknown executables in program directories
            elif any(prog_path in path_lower for prog_path in [
                'c:\\program files\\',
                'c:\\program files (x86)\\'
            ]) and path_lower.endswith('.exe'):
                reasons.append("Unknown executable in program directory (not in baseline)")
                suspicion_level = "High"
            
            # MEDIUM-HIGH: Unknown paths in autorun locations
            elif any(autorun_path in path_lower for autorun_path in [
                '\\startup\\',
                '\\run\\',
                '\\runonce\\',
                'c:\\programdata\\microsoft\\windows\\start menu\\',
                'c:\\users\\all users\\'
            ]):
                reasons.append("Unknown autorun entry (not in baseline)")
                suspicion_level = "Medium-High"
            
            # MEDIUM: Unknown executables anywhere
            elif path_lower.endswith('.exe'):
                reasons.append("Unknown executable (not in baseline)")
                suspicion_level = "Medium"
            
            # LOW: Other unknown files (only flag if in somewhat suspicious locations)
            elif any(watch_path in path_lower for watch_path in [
                'c:\\programdata\\',
                'c:\\users\\public\\',
                '\\temp\\',
                '\\tmp\\'
            ]):
                reasons.append("Unknown file in watched location (not in baseline)")
                suspicion_level = "Low"
        
        else:
            # Path exists in baseline - check for hash mismatches
            expected_hash = baseline_hash_by_path.get(normalized_path)
            if expected_hash:
                current_hash = _get_file_hash(df, i)
                if current_hash and current_hash != expected_hash:
                    reasons.append("File hash mismatch vs baseline (potential replacement)")
                    suspicion_level = "Critical"
        
        # Add to findings if any issues detected
        if reasons:
            row_out = df.loc[i].copy()
            reason_text = "; ".join(reasons)
            row_out["detection_reason"] = f"[{suspicion_level}] {reason_text}"
            row_out["detection_type"] = "Suspicious Path (Baseline-Driven)"
            row_out["baseline_status"] = "NOT in Baseline" if normalized_path not in baseline_paths else "Hash Mismatch"
            row_out["suspicion_level"] = suspicion_level
            findings.append(row_out)
    
    return findings


def _critical_fallback_detection(df: pd.DataFrame, col_img: str) -> list:
    """
    Minimal fallback detection when no baseline is available.
    Only flags the most obviously suspicious patterns.
    """
    findings = []
    
    for i in df.index:
        path = str(df.at[i, col_img]).strip()
        if not path or path == "nan":
            continue
            
        path_lower = path.lower()
        reasons = []
        
        # ONLY the most critical patterns that are almost always suspicious
        
        # 1. System32 masquerading (fake system32 directories)
        if '\\system32\\' in path_lower and not path_lower.startswith('c:\\windows\\system32\\'):
            reasons.append("Fake system32 directory masquerading")
        
        # 2. Obviously malicious file extensions in system directories
        malicious_extensions = ['.bat', '.cmd', '.vbs', '.js', '.ps1', '.scr']
        if (any(sys_path in path_lower for sys_path in ['c:\\windows\\system32\\', 'c:\\windows\\']) and
            any(path_lower.endswith(ext) for ext in malicious_extensions)):
            reasons.append("Script file in system directory (unusual)")
        
        # 3. Executables with illegal characters (almost always malicious)
        try:
            filename = os.path.basename(path_lower)
            illegal_chars = ['<', '>', ':', '"', '|', '?', '*']
            found_illegal = [char for char in illegal_chars if char in filename]
            if found_illegal and path_lower.endswith('.exe'):
                reasons.append(f"Executable with illegal filename characters: {', '.join(found_illegal)}")
        except:
            pass
        
        # 4. Extremely long paths (buffer overflow attempts)
        if len(path) > 300:  # Even longer threshold for fallback
            reasons.append(f"Extremely long path ({len(path)} characters) - potential exploit")
        
        # Add to findings if any critical issues detected
        if reasons:
            row_out = df.loc[i].copy()
            reason_text = "; ".join(reasons)
            row_out["detection_reason"] = f"[Critical] {reason_text}"
            row_out["detection_type"] = "Suspicious Path (Critical Fallback)"
            row_out["baseline_status"] = "No Baseline Available"
            row_out["suspicion_level"] = "Critical"
            findings.append(row_out)
    
    return findings


def _get_file_hash(df: pd.DataFrame, index: int) -> str:
    """
    Extract file hash from DataFrame row (prefers SHA256 > SHA1 > MD5).
    """
    cols_lower = {c.lower(): c for c in df.columns}
    
    # Check for hash columns in order of preference
    hash_columns = [
        cols_lower.get("sha-256") or cols_lower.get("sha256"),
        cols_lower.get("sha-1") or cols_lower.get("sha1"),
        cols_lower.get("md5")
    ]
    
    for hash_col in hash_columns:
        if hash_col and pd.notna(df.at[index, hash_col]):
            return str(df.at[index, hash_col]).strip().lower()
    
    return None


def get_baseline_statistics(baseline_csv: str) -> dict:
    """
    Get statistics about the baseline for reporting purposes.
    """
    if not baseline_csv:
        return {"status": "No baseline provided"}
    
    try:
        baseline_paths, baseline_hash_by_path = load_baseline(baseline_csv)
        
        # Categorize paths by location
        categories = {
            'system_paths': len([p for p in baseline_paths if 'c:\\windows\\' in p]),
            'program_paths': len([p for p in baseline_paths if 'c:\\program files' in p]),
            'programdata_paths': len([p for p in baseline_paths if 'c:\\programdata\\' in p]),
            'user_paths': len([p for p in baseline_paths if 'c:\\users\\' in p]),
            'other_paths': 0
        }
        
        # Calculate 'other' paths
        categorized_count = sum(categories.values()) - categories['other_paths']
        categories['other_paths'] = len(baseline_paths) - categorized_count
        
        return {
            'status': 'Loaded successfully',
            'total_baseline_paths': len(baseline_paths),
            'paths_with_hashes': len(baseline_hash_by_path),
            'hash_coverage_pct': round(len(baseline_hash_by_path)/len(baseline_paths)*100, 1) if baseline_paths else 0,
            'categories': categories,
            'baseline_file': os.path.basename(baseline_csv)
        }
        
    except Exception as e:
        return {
            'status': 'Failed to load',
            'error': str(e),
            'baseline_file': os.path.basename(baseline_csv)
        }


def print_detection_summary(baseline_stats: dict):
    """
    Print a summary of what the baseline-driven detection will focus on.
    """
    print("\n" + "="*50)
    print("BASELINE-DRIVEN SUSPICIOUS PATH DETECTION")
    print("="*50)
    
    if baseline_stats.get('status') == 'Loaded successfully':
        print(f"✅ Baseline loaded: {baseline_stats['baseline_file']}")
        print(f"📊 {baseline_stats['total_baseline_paths']:,} baseline paths")
        print(f"🔒 {baseline_stats['hash_coverage_pct']:.1f}% have hashes for integrity checking")
        
        print(f"\n📂 Path categories in baseline:")
        cats = baseline_stats['categories']
        print(f"   System: {cats['system_paths']:,}")
        print(f"   Programs: {cats['program_paths']:,}")
        print(f"   ProgramData: {cats['programdata_paths']:,}")
        print(f"   Users: {cats['user_paths']:,}")
        print(f"   Other: {cats['other_paths']:,}")
        
        print(f"\n🎯 Detection focus:")
        print(f"   🔥 Critical: Unknown files in system directories")
        print(f"   ⚠️  High: Unknown executables in program directories")
        print(f"   📍 Medium: Unknown autorun entries")
        print(f"   🔍 Hash: File replacement detection")
        
    else:
        print(f"❌ Baseline not available: {baseline_stats.get('error', 'Unknown error')}")
        print(f"🔙 Using minimal fallback detection:")
        print(f"   - System32 masquerading")
        print(f"   - Scripts in system directories")
        print(f"   - Illegal filename characters")
        print(f"   - Extremely long paths")
    
    print("="*50)