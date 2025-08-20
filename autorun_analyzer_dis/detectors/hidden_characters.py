"""
Hidden characters detector - detects NBSP, zero-width chars, control chars.
"""

import pandas as pd
import re


def detect_hidden_characters(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect entries with hidden/non-printable characters including NBSP.
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with hidden character findings
    """
    findings = []
    
    # Check multiple text columns for hidden characters
    text_columns = []
    for col in df.columns:
        if col.lower() in ['image path', 'image', 'path', 'location', 'command', 'fullname', 
                          'description', 'entry', 'entryname', 'entry name', 'signer']:
            text_columns.append(col)
    
    if not text_columns:
        return pd.DataFrame()
    
    for i in df.index:
        reasons = []
        affected_columns = []
        
        for col in text_columns:
            if col not in df.columns:
                continue
                
            text = str(df.at[i, col])
            if not text or text == "nan":
                continue
            
            col_issues = []
            
            # Check for non-breaking space (NBSP) - U+00A0
            if '\u00a0' in text:
                col_issues.append("Non-breaking space (NBSP)")
            
            # Check for other Unicode spaces
            unicode_spaces = {
                '\u2000': 'En Quad',
                '\u2001': 'Em Quad', 
                '\u2002': 'En Space',
                '\u2003': 'Em Space',
                '\u2004': 'Three-Per-Em Space',
                '\u2005': 'Four-Per-Em Space',
                '\u2006': 'Six-Per-Em Space',
                '\u2007': 'Figure Space',
                '\u2008': 'Punctuation Space',
                '\u2009': 'Thin Space',
                '\u200A': 'Hair Space'
            }
            
            for char, name in unicode_spaces.items():
                if char in text:
                    col_issues.append(f"Unicode space ({name})")
            
            # Check for zero-width characters
            zero_width_chars = {
                '\u200b': 'Zero Width Space',
                '\u200c': 'Zero Width Non-Joiner', 
                '\u200d': 'Zero Width Joiner',
                '\ufeff': 'Zero Width No-Break Space (BOM)',
                '\u2060': 'Word Joiner'
            }
            
            for char, name in zero_width_chars.items():
                if char in text:
                    col_issues.append(f"{name}")
            
            # Check for control characters (0x00-0x1F, 0x7F-0x9F)
            if re.search(r'[\x00-\x1f\x7f-\x9f]', text):
                control_chars = re.findall(r'[\x00-\x1f\x7f-\x9f]', text)
                unique_controls = list(set(control_chars))
                col_issues.append(f"Control characters: {[f'0x{ord(c):02x}' for c in unique_controls]}")
            
            # Check for right-to-left override characters (used in malware)
            rtl_chars = {
                '\u202d': 'Left-to-Right Override',
                '\u202e': 'Right-to-Left Override',
                '\u061c': 'Arabic Letter Mark'
            }
            
            for char, name in rtl_chars.items():
                if char in text:
                    col_issues.append(f"{name} (potential text spoofing)")
            
            # Check for unusual combining characters
            if re.search(r'[\u0300-\u036f\u1ab0-\u1aff\u1dc0-\u1dff\u20d0-\u20ff]', text):
                col_issues.append("Combining diacritical marks")
            
            if col_issues:
                affected_columns.append(f"{col}: {', '.join(col_issues)}")
        
        if affected_columns:
            row_out = df.loc[i].copy()
            row_out["detection_reason"] = "; ".join(affected_columns)
            row_out["detection_type"] = "Hidden Characters"
            
            # Add a cleaned version for comparison
            cleaned_text = ""
            for col in text_columns:
                if col in df.columns:
                    original = str(df.at[i, col])
                    # Remove hidden characters for comparison
                    cleaned = re.sub(r'[\u00a0\u2000-\u200f\u202a-\u202f\u2060-\u206f\ufeff\x00-\x1f\x7f-\x9f]', '', original)
                    if original != cleaned:
                        cleaned_text = f"{col}: '{original}' → '{cleaned}'"
                        break
            
            if cleaned_text:
                row_out["cleaned_comparison"] = cleaned_text
            
            findings.append(row_out)
    
    return pd.DataFrame(findings)