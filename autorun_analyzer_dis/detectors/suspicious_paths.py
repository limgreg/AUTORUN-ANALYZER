"""
Pure Path Analysis Module - suspicious_paths.py
ONLY analyzes file paths and locations. No hash checking (that's baseline_comparison.py's job).
"""

import pandas as pd
import os
from ..core.baseline import load_baseline
from ..core.utils import normalize_path


def detect_suspicious_paths(df: pd.DataFrame, baseline_csv: str = None) -> pd.DataFrame:
    """
    PURE PATH LOCATION ANALYSIS - answers: "Is this path suspicious for this environment?"
    
    This module ONLY cares about WHERE files are located, not their integrity.
    Hash verification is handled by baseline_comparison.py module.
    
    Args:
        df: Input DataFrame
        baseline_csv: Path to baseline CSV (for known-good path whitelist)
        
    Returns:
        DataFrame with suspicious path findings (location-based only)
    """
    # Find path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        return pd.DataFrame()
    
    findings = []
    
    if baseline_csv:
        print(f"[+] Using baseline-driven path analysis")
        findings.extend(_baseline_path_intelligence(df, col_img, baseline_csv))
    else:
        print(f"[+] Using pattern-based path analysis (no baseline)")
        findings.extend(_pattern_based_path_analysis(df, col_img))
    
    return pd.DataFrame(findings)


def _baseline_path_intelligence(df: pd.DataFrame, col_img: str, baseline_csv: str) -> list:
    """
    Environment-aware path analysis using baseline as whitelist.
    Question: "Is this path known-good for THIS environment?"
    """
    try:
        baseline_paths, _ = load_baseline(baseline_csv)  # Only need paths, ignore hashes
        print(f"[+] Loaded {len(baseline_paths)} known-good paths for location analysis")
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
        
        # CORE QUESTION: Is this path in our environment's whitelist?
        if normalized_path and normalized_path not in baseline_paths:
            suspicion_reason = _analyze_unknown_path_location(path_lower)
            
            if suspicion_reason:
                row_out = df.loc[i].copy()
                row_out["detection_reason"] = suspicion_reason['reason']
                row_out["detection_type"] = "Suspicious Path Location"
                row_out["suspicion_level"] = suspicion_reason['level']
                row_out["location_category"] = suspicion_reason['category']
                row_out["baseline_status"] = "Unknown Path"
                findings.append(row_out)
    
    return findings


def _analyze_unknown_path_location(path_lower: str) -> dict:
    """
    Analyze WHY an unknown path is suspicious based on its LOCATION.
    Returns None if location is not particularly suspicious.
    """
    
    # CRITICAL: Core system directories
    if any(critical_dir in path_lower for critical_dir in [
        'c:\\windows\\system32\\',
        'c:\\windows\\syswow64\\',
        'c:\\windows\\winsxs\\',
    ]):
        return {
            'reason': f"[CRITICAL] Unknown file in core system directory (not in baseline)",
            'level': 'Critical',
            'category': 'Core System Directory'
        }
    
    # HIGH: Microsoft program directories
    if any(ms_dir in path_lower for ms_dir in [
        'c:\\program files\\microsoft\\',
        'c:\\program files\\windows nt\\',
        'c:\\program files\\common files\\microsoft\\',
        'c:\\program files (x86)\\microsoft\\',
    ]) and path_lower.endswith('.exe'):
        return {
            'reason': f"[HIGH] Unknown executable in Microsoft directory (not in baseline)",
            'level': 'High', 
            'category': 'Microsoft Program Directory'
        }
    
    # HIGH: Windows directory (non-system32)
    if path_lower.startswith('c:\\windows\\') and path_lower.endswith('.exe'):
        return {
            'reason': f"[HIGH] Unknown executable in Windows directory (not in baseline)",
            'level': 'High',
            'category': 'Windows Directory'
        }
    
    # MEDIUM-HIGH: Autorun/Startup locations
    if any(autorun_dir in path_lower for autorun_dir in [
        '\\startup\\',
        '\\start menu\\programs\\startup\\',
        'c:\\programdata\\microsoft\\windows\\start menu\\',
        'c:\\users\\all users\\microsoft\\windows\\start menu\\',
        '\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\'
    ]):
        return {
            'reason': f"[MEDIUM-HIGH] Unknown autorun/startup entry (not in baseline)",
            'level': 'Medium-High',
            'category': 'Autorun Location'
        }
    
    # MEDIUM: Program Files executables
    if (path_lower.startswith('c:\\program files\\') or 
        path_lower.startswith('c:\\program files (x86)\\')) and path_lower.endswith('.exe'):
        return {
            'reason': f"[MEDIUM] Unknown executable in Program Files (not in baseline)",
            'level': 'Medium',
            'category': 'Program Files'
        }
    
    # MEDIUM: Common persistence locations
    if any(persist_dir in path_lower for persist_dir in [
        'c:\\programdata\\',
        'c:\\users\\public\\',
    ]) and path_lower.endswith('.exe'):
        return {
            'reason': f"[MEDIUM] Unknown executable in common persistence location (not in baseline)",
            'level': 'Medium',
            'category': 'Persistence Location'
        }
    
    # LOW: Other monitored locations (registry run keys, etc.)
    if any(monitor_dir in path_lower for monitor_dir in [
        '\\temp\\',
        '\\tmp\\',
        'c:\\windows\\temp\\',
        '\\appdata\\local\\temp\\',
    ]) and path_lower.endswith('.exe'):
        return {
            'reason': f"[LOW] Unknown executable in temporary location (not in baseline)",
            'level': 'Low',
            'category': 'Temporary Location'
        }
    
    # Not in a particularly suspicious location
    return None


def _pattern_based_path_analysis(df: pd.DataFrame, col_img: str) -> list:
    """
    Fallback path analysis using universal suspicious patterns.
    Only flags obviously malicious path patterns when no baseline available.
    """
    findings = []
    
    for i in df.index:
        path = str(df.at[i, col_img]).strip()
        if not path or path == "nan":
            continue
            
        path_lower = path.lower()
        suspicious_patterns = []
        
        # Pattern 1: System32 masquerading
        if '\\system32\\' in path_lower and not path_lower.startswith('c:\\windows\\system32\\'):
            suspicious_patterns.append("Fake System32 directory masquerading")
        
        # Pattern 2: Hidden system naming outside Windows
        if ('\\$' in path_lower or path_lower.startswith('$')) and not path_lower.startswith('c:\\windows\\'):
            suspicious_patterns.append("Hidden/system naming pattern outside Windows")
        
        # Pattern 3: Script files in system directories  
        script_extensions = ['.bat', '.cmd', '.vbs', '.js', '.ps1', '.scr', '.com', '.pif']
        if (any(sys_path in path_lower for sys_path in ['c:\\windows\\system32\\', 'c:\\windows\\']) and
            any(path_lower.endswith(ext) for ext in script_extensions)):
            suspicious_patterns.append("Script file in system directory")
        
        # Pattern 4: Illegal filename characters
        try:
            filename = os.path.basename(path_lower)
            illegal_chars = ['<', '>', ':', '"', '|', '?', '*']
            found_illegal = [char for char in illegal_chars if char in filename]
            if found_illegal:
                suspicious_patterns.append(f"Illegal filename characters: {', '.join(found_illegal)}")
        except:
            pass
        
        # Pattern 5: Double extensions (masquerading)
        try:
            filename = os.path.basename(path_lower)
            if filename.count('.') >= 2 and any(path_lower.endswith(ext) for ext in ['.exe', '.scr', '.com', '.bat']):
                suspicious_patterns.append("Double extension pattern (potential masquerading)")
        except:
            pass
        
        # Pattern 6: Extremely long paths
        if len(path) > 300:
            suspicious_patterns.append(f"Extremely long path ({len(path)} chars)")
        
        if suspicious_patterns:
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = f"[CRITICAL] {'; '.join(suspicious_patterns)}"
            row_out["detection_type"] = "Suspicious Path Pattern"
            row_out["suspicion_level"] = "Critical"
            row_out["location_category"] = "Malicious Pattern"
            row_out["baseline_status"] = "Pattern-based Detection"
            findings.append(row_out)
    
    return findings


def get_path_analysis_summary(baseline_csv: str = None) -> dict:
    """
    Get summary of path analysis capabilities.
    """
    if not baseline_csv:
        return {
            'analysis_type': 'Pattern-based',
            'description': 'Universal suspicious path patterns only',
            'accuracy': 'Basic - high false negatives, low false positives'
        }
    
    try:
        baseline_paths, _ = load_baseline(baseline_csv)
        
        # Categorize baseline paths by location type
        location_categories = {
            'system_critical': len([p for p in baseline_paths if any(x in p for x in ['system32', 'syswow64', 'winsxs'])]),
            'windows_other': len([p for p in baseline_paths if 'c:\\windows\\' in p and not any(x in p for x in ['system32', 'syswow64', 'winsxs'])]),
            'program_files': len([p for p in baseline_paths if 'program files' in p]),
            'programdata': len([p for p in baseline_paths if 'programdata' in p]),
            'users': len([p for p in baseline_paths if 'c:\\users\\' in p]),
            'other': 0
        }
        
        # Calculate other
        categorized = sum(location_categories.values()) - location_categories['other']
        location_categories['other'] = len(baseline_paths) - categorized
        
        return {
            'analysis_type': 'Baseline-driven',
            'description': 'Environment-aware path intelligence',
            'accuracy': 'High - low false positives, high threat detection',
            'total_known_paths': len(baseline_paths),
            'location_categories': location_categories,
            'baseline_file': os.path.basename(baseline_csv)
        }
        
    except Exception as e:
        return {
            'analysis_type': 'Baseline-driven (failed)',
            'description': f'Failed to load baseline: {str(e)}',
            'accuracy': 'Degraded to pattern-based'
        }