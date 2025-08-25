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


def detect_visual_masquerading(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """
    Detect visual masquerading using mixed scripts detection.
    
    Detects filenames mixing different Unicode scripts (Latin + others)
    which is commonly used in visual masquerading attacks.
    
    Args:
        df: Input DataFrame
        
    Returns:
        tuple: (mask of flagged rows, series of reasons)
    """
    # Find the main path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    
    if not col_img:
        # Return empty results if no path column found
        empty_mask = pd.Series([False] * len(df), index=df.index)
        empty_reasons = pd.Series([""] * len(df), index=df.index)
        return empty_mask, empty_reasons
    
    text = df[col_img].astype(str)
    fname = text.apply(file_name)
    
    # Vectorized processing using apply
    def analyze_filename(filename: str) -> tuple[bool, str]:
        """Analyze single filename for mixed scripts."""
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
            return True, reason
        
        return False, ""
    
    # Apply analysis to all filenames at once
    results = fname.apply(analyze_filename)
    
    # Split results into mask and reasons
    mask_list = []
    reason_list = []
    
    for is_flagged, reason in results:
        mask_list.append(is_flagged)
        reason_list.append(reason)
    
    # Create pandas Series with proper index alignment
    mask = pd.Series(mask_list, index=df.index)
    reasons = pd.Series(reason_list, index=df.index)
    
    return mask, reasons