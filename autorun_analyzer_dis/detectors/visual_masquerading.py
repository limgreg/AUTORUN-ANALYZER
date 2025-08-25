"""
Visual masquerading detector - moved from rules.py
Detects filenames using confusable characters.
Now also dynamically detects mixed scripts (Latin + Greek/Cyrillic/etc.).
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
    Detect visual masquerading - filenames using confusable characters that look identical
    to legitimate names but use different Unicode characters (e.g., I vs l, O vs 0).
    Also dynamically detects mixed scripts (Latin + others).
    
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
        
        # --- Existing hardcoded confusable detection ---
        has_confusables = False
        confusable_chars_found = []
        
        for char in filename:
            if char in confusables:
                has_confusables = True
                legitimate_char = confusables[char]
                confusable_chars_found.append(f"'{char}' (should be '{legitimate_char}')")
        
        if has_confusables:
            normalized = filename
            for confusable_char, legitimate_char in confusables.items():
                normalized = normalized.replace(confusable_char, legitimate_char)
            
            if normalized != filename:
                if normalized.lower() in {name.lower() for name in legitimate_names}:
                    reason_parts.append(f"Visual masquerading: {filename} → {normalized} using {', '.join(confusable_chars_found)}")
                elif filename.endswith('.exe'):
                    reason_parts.append(f"Executable with confusable character substitutions: {filename} → {normalized}")
        
        # --- New dynamic mixed-script detection ---
        scripts_found = detect_mixed_scripts(filename)
        if len(scripts_found) > 1:
            reason_parts.append(f"Mixed scripts detected: {scripts_found}")
            
            # Check if stripping non-Latin reveals a known legitimate executable
            normalized = "".join(
                ch for ch in filename if get_script(ch) == "Latin" or not ch.isalpha()
            )
            if normalized.lower() in {name.lower() for name in legitimate_names}:
                reason_parts.append(f"Possible masquerading of {normalized} using mixed scripts")
        
        # --- Collect result ---
        if reason_parts:
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = "; ".join(reason_parts)
            row_out["detection_type"] = "Visual Masquerading"
            findings.append(row_out)
    
    return pd.DataFrame(findings)
