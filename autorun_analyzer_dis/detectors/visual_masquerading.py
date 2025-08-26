"""
Visual masquerading detector - mixed scripts detection only.
Detects filenames mixing different Unicode scripts (Latin + Greek/Cyrillic/etc.).
"""

import pandas as pd
import unicodedata
from ..core.utils import file_name


def get_script(char: str) -> str:
    """Return the Unicode script family for a character."""
    try:
        name = unicodedata.name(char)
        if "LATIN" in name:
            return "Latin"
        elif "GREEK" in name:
            return "Greek"
        elif "CYRILLIC" in name:
            return "Cyrillic"
        elif "ARABIC" in name:
            return "Arabic"
        elif "HEBREW" in name:
            return "Hebrew"
        elif "DEVANAGARI" in name:
            return "Devanagari"
        elif "HIRAGANA" in name or "KATAKANA" in name or "CJK" in name or "HANGUL" in name:
            return "CJK"
        else:
            return "Other"
    except ValueError:
        return "Other"


def detect_mixed_scripts(text: str) -> dict:
    """Return a dict of scripts and the characters found for each script in a string."""
    scripts = {}
    for ch in text:
        if ch.isalpha():  # only consider letters
            script = get_script(ch)
            scripts.setdefault(script, []).append(ch)
    return scripts


def detect_visual_masquerading(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect visual masquerading using mixed scripts detection.
    
    Detects filenames mixing different Unicode scripts (Latin + others)
    which is commonly used in visual masquerading attacks.
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame: Findings with detection details (NOT mask/reasons tuple)
    """
    # Find the main path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        return pd.DataFrame()
    
    text = df[col_img].astype(str)
    fname = text.apply(file_name)
    
    findings = []
    
    for i in df.index:
        filename = fname.iat[i]
        
        # Analyze scripts in filename
        scripts_found = detect_mixed_scripts(filename)
        
        if len(scripts_found) > 1:
            # Format script information for the reason
            script_details = []
            for script, chars in scripts_found.items():
                unique_chars = list(dict.fromkeys(chars))  # Remove duplicates
                char_sample = ''.join(unique_chars[:5])    # Show first 5 chars
                if len(unique_chars) > 5:
                    char_sample += "..."
                script_details.append(f"{script}({char_sample})")
            
            reason = f"Mixed char detected: {', '.join(script_details)}"
            
            # Create finding row (copy original row + add detection info)
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = reason
            row_out["detection_type"] = "Visual Masquerading"
            
            # Add script analysis details
            row_out["scripts_found"] = str(scripts_found)
            row_out["script_count"] = len(scripts_found)
            
            findings.append(row_out)
    
    return pd.DataFrame(findings)