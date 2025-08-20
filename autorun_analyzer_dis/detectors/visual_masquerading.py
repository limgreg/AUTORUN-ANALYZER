"""
Visual masquerading detector - moved from rules.py
Detects filenames using confusable characters.
"""

import pandas as pd
from ..core.utils import file_name


def detect_visual_masquerading(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect visual masquerading - filenames using confusable characters that look identical
    to legitimate names but use different Unicode characters (e.g., I vs l, O vs 0).
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with findings that have visual masquerading
    """
    # Find the main path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        return pd.DataFrame()
    
    text = df[col_img].astype(str)
    fname = text.apply(file_name)
    
    findings = []
    
    # Confusable character mappings: confusable → legitimate
    confusables = {
        # Cyrillic/Greek letters masquerading as Latin
        'а': 'a',  # Cyrillic a -> Latin a
        'е': 'e',  # Cyrillic e -> Latin e
        'о': 'o',  # Cyrillic o -> Latin o
        'р': 'p',  # Cyrillic p -> Latin p
        'с': 'c',  # Cyrillic c -> Latin c
        'х': 'x',  # Cyrillic x -> Latin x
        'у': 'y',  # Cyrillic y -> Latin y
        
        # Greek letters
        'Ο': 'O',  # Greek Omicron -> Latin O
        'ο': 'o',  # Greek omicron -> Latin o
        
        # Mathematical/Unicode variants
        'ｌ': 'l',  # Fullwidth l -> Latin l
        'Ｉ': 'I',  # Fullwidth I -> Latin I
        'ｏ': 'o',  # Fullwidth o -> Latin o
        'Ｏ': 'O',  # Fullwidth O -> Latin O
        'ａ': 'a',  # Fullwidth a -> Latin a
        'ｅ': 'e',  # Fullwidth e -> Latin e
        'ｒ': 'r',  # Fullwidth r -> Latin r
        'ｐ': 'p',  # Fullwidth p -> Latin p
        'ｃ': 'c',  # Fullwidth c -> Latin c
        'ｘ': 'x',  # Fullwidth x -> Latin x
        'ｙ': 'y',  # Fullwidth y -> Latin y
        '０': '0',  # Fullwidth zero -> Latin zero
        '１': '1',  # Fullwidth one -> Latin one
    }
    
    # Common legitimate executables to check for masquerading
    legitimate_names = {
        'svchost.exe', 'explorer.exe', 'winlogon.exe', 'csrss.exe', 'lsass.exe',
        'chrome.exe', 'firefox.exe', 'notepad.exe', 'cmd.exe', 'powershell.exe',
        'rundll32.exe', 'regsvr32.exe', 'msiexec.exe', 'services.exe',
        'dwm.exe', 'conhost.exe', 'audiodg.exe', 'spoolsv.exe'
    }
    
    for i in df.index:
        filename = fname.iat[i]
        reason_parts = []
        
        # Check if filename contains confusable characters
        has_confusables = False
        confusable_chars_found = []
        
        for char in filename:
            if char in confusables:
                has_confusables = True
                legitimate_char = confusables[char]
                confusable_chars_found.append(f"'{char}' (should be '{legitimate_char}')")
        
        # If we found confusables, check if it might be masquerading a legitimate name
        if has_confusables:
            # Create normalized version by replacing confusables with legitimate characters
            normalized = filename
            for confusable_char, legitimate_char in confusables.items():
                normalized = normalized.replace(confusable_char, legitimate_char)
            
            # ONLY flag if the filename actually changed during normalization
            if normalized != filename:
                # Check if normalized version matches a legitimate name
                if normalized.lower() in {name.lower() for name in legitimate_names}:
                    reason_parts.append(f"Visual masquerading: {filename} → {normalized} using {', '.join(confusable_chars_found)}")
                
                # Also flag executables with actual confusable character substitutions
                elif filename.endswith('.exe'):
                    reason_parts.append(f"Executable with confusable character substitutions: {filename} → {normalized}")
        
        if reason_parts:
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = "; ".join(reason_parts)
            row_out["detection_type"] = "Visual Masquerading"
            findings.append(row_out)
    
    return pd.DataFrame(findings)