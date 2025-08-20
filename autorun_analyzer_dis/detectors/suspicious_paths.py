"""
Suspicious paths detector - new detector for suspicious file locations.
"""

import pandas as pd
import os


def detect_suspicious_paths(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect suspicious file paths and locations.
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with suspicious path findings
    """
    # Find path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        return pd.DataFrame()
    
    findings = []
    
    for i in df.index:
        path = str(df.at[i, col_img]).lower().strip()
        if not path or path == "nan":
            continue
            
        reasons = []
        
        # Suspicious temporary directories
        temp_paths = [
            '\\temp\\', '\\tmp\\', '%temp%', '%tmp%',
            '\\appdata\\local\\temp\\',
            '\\users\\public\\',
            '\\programdata\\',
            '\\windows\\temp\\',
            'c:\\temp\\',
            'c:\\tmp\\'
        ]
        
        if any(temp_path in path for temp_path in temp_paths):
            reasons.append("Located in suspicious temporary directory")
        
        # System32 masquerading (not in real system32)
        if '\\system32\\' in path and not path.startswith('c:\\windows\\system32\\'):
            reasons.append("Potential system32 directory masquerading")
        
        # Suspicious root locations
        suspicious_roots = [
            'c:\\users\\public\\',
            'c:\\programdata\\',
            'c:\\perflogs\\',
            'c:\\$recycle.bin\\'
        ]
        
        if any(path.startswith(root) for root in suspicious_roots):
            reasons.append("Located in suspicious root directory")
        
        # Check filename for illegal characters
        try:
            filename = os.path.basename(path)
            illegal_chars = ['<', '>', ':', '"', '|', '?', '*']
            found_illegal = [char for char in illegal_chars if char in filename]
            if found_illegal:
                reasons.append(f"Illegal filename characters: {', '.join(found_illegal)}")
        except:
            pass
        
        # Very long paths (potential buffer overflow attempts)
        if len(path) > 260:  # Windows MAX_PATH limit
            reasons.append(f"Extremely long path ({len(path)} characters)")
        
        # Suspicious executable locations outside program files
        if (path.endswith('.exe') and 
            not any(legit_path in path for legit_path in [
                'c:\\windows\\', 
                'c:\\program files\\', 
                'c:\\program files (x86)\\'
            ])):
            reasons.append("Executable outside standard program directories")
        
        # Hidden/system file indicators in suspicious locations
        if ('\\$' in path or path.startswith('$')) and not path.startswith('c:\\windows\\'):
            reasons.append("Hidden/system file naming pattern in non-system location")
        
        if reasons:
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = "; ".join(reasons)
            row_out["detection_type"] = "Suspicious Path"
            findings.append(row_out)
    
    return pd.DataFrame(findings)