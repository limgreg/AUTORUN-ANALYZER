"""
Suspicious path location analysis.
"""

import pandas as pd
import os
from ..core.baseline import load_baseline
from ..core.utils import normalize_path


def detect_suspicious_paths(df: pd.DataFrame, baseline_csv: str = None) -> pd.DataFrame:
    """
    Detect suspicious file paths and locations.
    
    Args:
        df: Input DataFrame
        baseline_csv: Optional baseline for enhanced path analysis
        
    Returns:
        DataFrame with suspicious path findings
    """
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        return pd.DataFrame()
    
    findings = []
    
    if baseline_csv:
        findings.extend(_baseline_path_analysis(df, col_img, baseline_csv))
    else:
        findings.extend(_pattern_based_analysis(df, col_img))
    
    return pd.DataFrame(findings)


def _baseline_path_analysis(df: pd.DataFrame, col_img: str, baseline_csv: str) -> list:
    """Environment-aware path analysis using baseline whitelist."""
    try:
        baseline_paths, _ = load_baseline(baseline_csv)
        print(f"[+] Loaded {len(baseline_paths)} known-good paths")
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
        
        if normalized_path and normalized_path not in baseline_paths:
            suspicion_reason = _analyze_unknown_path(path_lower)
            
            if suspicion_reason:
                row_out = df.loc[i].copy()
                row_out["detection_reason"] = suspicion_reason['reason']
                row_out["detection_type"] = "Suspicious Path Location"
                row_out["suspicion_level"] = suspicion_reason['level']
                row_out["location_category"] = suspicion_reason['category']
                row_out["baseline_status"] = "Unknown Path"
                findings.append(row_out)
    
    return findings


def _analyze_unknown_path(path_lower: str) -> dict:
    """Analyze why an unknown path is suspicious."""
    
    # Critical: Core system directories
    if any(critical_dir in path_lower for critical_dir in [
        'c:\\windows\\system32\\',
        'c:\\windows\\syswow64\\',
        'c:\\windows\\winsxs\\',
    ]):
        return {
            'reason': f"Unknown file in core system directory",
            'level': 'Critical',
            'category': 'Core System Directory'
        }
    
    # High: Microsoft program directories
    if any(ms_dir in path_lower for ms_dir in [
        'c:\\program files\\microsoft\\',
        'c:\\program files\\windows nt\\',
        'c:\\program files\\common files\\microsoft\\',
        'c:\\program files (x86)\\microsoft\\',
    ]) and path_lower.endswith('.exe'):
        return {
            'reason': f"Unknown executable in Microsoft directory",
            'level': 'High', 
            'category': 'Microsoft Program Directory'
        }
    
    # High: Windows directory executables
    if path_lower.startswith('c:\\windows\\') and path_lower.endswith('.exe'):
        return {
            'reason': f"Unknown executable in Windows directory",
            'level': 'High',
            'category': 'Windows Directory'
        }
    
    # Medium-High: Autorun locations
    if any(autorun_dir in path_lower for autorun_dir in [
        '\\startup\\',
        '\\start menu\\programs\\startup\\',
        'c:\\programdata\\microsoft\\windows\\start menu\\',
        '\\appdata\\roaming\\microsoft\\windows\\start menu\\programs\\startup\\'
    ]):
        return {
            'reason': f"Unknown autorun/startup entry",
            'level': 'Medium-High',
            'category': 'Autorun Location'
        }
    
    # Medium: Program Files executables
    if (path_lower.startswith('c:\\program files\\') or 
        path_lower.startswith('c:\\program files (x86)\\')) and path_lower.endswith('.exe'):
        return {
            'reason': f"Unknown executable in Program Files",
            'level': 'Medium',
            'category': 'Program Files'
        }
    
    # Medium: Common persistence locations
    if any(persist_dir in path_lower for persist_dir in [
        'c:\\programdata\\',
        'c:\\users\\public\\',
    ]) and path_lower.endswith('.exe'):
        return {
            'reason': f"Unknown executable in persistence location",
            'level': 'Medium',
            'category': 'Persistence Location'
        }
    
    # Low: Temporary locations
    if any(temp_dir in path_lower for temp_dir in [
        '\\temp\\',
        '\\tmp\\',
        'c:\\windows\\temp\\',
        '\\appdata\\local\\temp\\',
    ]) and path_lower.endswith('.exe'):
        return {
            'reason': f"Unknown executable in temporary location",
            'level': 'Low',
            'category': 'Temporary Location'
        }
    
    return None


def _pattern_based_analysis(df: pd.DataFrame, col_img: str) -> list:
    """Pattern-based analysis for obviously malicious paths."""
    findings = []
    
    for i in df.index:
        path = str(df.at[i, col_img]).strip()
        if not path or path == "nan":
            continue
            
        path_lower = path.lower()
        suspicious_patterns = []
        
        # System32 masquerading
        if '\\system32\\' in path_lower and not path_lower.startswith('c:\\windows\\system32\\'):
            suspicious_patterns.append("Fake System32 directory masquerading")
        
        # Hidden system naming outside Windows
        if ('\\$' in path_lower or path_lower.startswith('$')) and not path_lower.startswith('c:\\windows\\'):
            suspicious_patterns.append("Hidden/system naming pattern outside Windows")
        
        # Script files in system directories  
        script_extensions = ['.bat', '.cmd', '.vbs', '.js', '.ps1', '.scr', '.com', '.pif']
        if (any(sys_path in path_lower for sys_path in ['c:\\windows\\system32\\', 'c:\\windows\\']) and
            any(path_lower.endswith(ext) for ext in script_extensions)):
            suspicious_patterns.append("Script file in system directory")
        
        # Illegal filename characters
        try:
            filename = os.path.basename(path_lower)
            illegal_chars = ['<', '>', ':', '"', '|', '?', '*']
            found_illegal = [char for char in illegal_chars if char in filename]
            if found_illegal:
                suspicious_patterns.append(f"Illegal filename characters: {', '.join(found_illegal)}")
        except:
            pass
        
        # Double extensions
        try:
            filename = os.path.basename(path_lower)
            if filename.count('.') >= 2 and any(path_lower.endswith(ext) for ext in ['.exe', '.scr', '.com', '.bat']):
                suspicious_patterns.append("Double extension pattern (potential masquerading)")
        except:
            pass
        
        # Extremely long paths
        if len(path) > 300:
            suspicious_patterns.append(f"Extremely long path ({len(path)} chars)")
        
        if suspicious_patterns:
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = f"{'; '.join(suspicious_patterns)}"
            row_out["detection_type"] = "Suspicious Path Pattern"
            row_out["suspicion_level"] = "Critical"
            row_out["location_category"] = "Malicious Pattern"
            row_out["baseline_status"] = "Pattern-based Detection"
            findings.append(row_out)
    
    return findings