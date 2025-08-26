"""
Enhanced hidden characters detector using unicodedata for comprehensive detection.
Much more robust than hardcoded character lists.
"""

import pandas as pd
import unicodedata
import re


def detect_hidden_characters(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect entries with hidden/non-printable characters using unicodedata categorization.
    
    This approach is much more comprehensive than hardcoded lists as it uses Unicode
    standard categories to identify suspicious characters automatically.
    
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
            
            col_issues = analyze_text_for_hidden_chars(text)
            
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
                    cleaned = clean_hidden_characters(original)
                    if original != cleaned:
                        cleaned_text = f"{col}: '{original}' → '{cleaned}'"
                        break
            
            if cleaned_text:
                row_out["cleaned_comparison"] = cleaned_text
            
            # Add severity based on character types found
            severity = determine_hidden_char_severity(text)
            row_out["suspicion_level"] = severity
            
            findings.append(row_out)
    
    return pd.DataFrame(findings)


def analyze_text_for_hidden_chars(text: str) -> list:
    """
    Analyze text for hidden/suspicious characters using unicodedata categories.
    
    Returns list of issues found.
    """
    issues = []
    
    # Track different types of suspicious characters
    suspicious_chars = {
        'format_chars': [],      # Format characters (Cf category)
        'other_control': [],     # Other control (Cc category) 
        'private_use': [],       # Private use characters (Co category)
        'surrogate': [],         # Surrogate characters (Cs category)
        'unassigned': [],        # Unassigned characters (Cn category)
        'unusual_spaces': [],    # Unusual spacing characters
        'rtl_override': [],      # Right-to-left override characters
        'combining': []          # Unusual combining characters
    }
    
    for char in text:
        category = unicodedata.category(char)
        code_point = ord(char)
        
        # Format characters (includes zero-width characters, BOM, etc.)
        if category == 'Cf':
            char_name = unicodedata.name(char, f'U+{code_point:04X}')
            suspicious_chars['format_chars'].append((char, char_name))
        
        # Control characters (excluding normal whitespace like \t, \n, \r)
        elif category == 'Cc' and char not in ['\t', '\n', '\r', ' ']:
            char_name = unicodedata.name(char, f'CONTROL-{code_point:02X}')
            suspicious_chars['other_control'].append((char, char_name))
        
        # Private use characters
        elif category == 'Co':
            suspicious_chars['private_use'].append((char, f'PRIVATE-USE-{code_point:04X}'))
        
        # Surrogate characters (shouldn't appear in valid UTF-8)
        elif category == 'Cs':
            suspicious_chars['surrogate'].append((char, f'SURROGATE-{code_point:04X}'))
        
        # Unassigned characters
        elif category == 'Cn':
            suspicious_chars['unassigned'].append((char, f'UNASSIGNED-{code_point:04X}'))
        
        # Unusual spacing characters (Unicode spaces beyond normal space)
        elif category in ['Zs', 'Zl', 'Zp'] and char != ' ':
            char_name = unicodedata.name(char, f'SPACE-{code_point:04X}')
            suspicious_chars['unusual_spaces'].append((char, char_name))
        
        # Combining marks in suspicious contexts (many combining chars on one base)
        elif category.startswith('M'):  # Mark categories (Mn, Mc, Me)
            char_name = unicodedata.name(char, f'COMBINING-{code_point:04X}')
            suspicious_chars['combining'].append((char, char_name))
    
    # Check for specific highly suspicious patterns
    
    # Right-to-left override characters (common in malware for filename spoofing)
    rtl_overrides = ['\u202D', '\u202E', '\u061C', '\u200E', '\u200F']
    for rtl_char in rtl_overrides:
        if rtl_char in text:
            char_name = unicodedata.name(rtl_char)
            suspicious_chars['rtl_override'].append((rtl_char, char_name))
    
    # Generate issue descriptions
    for char_type, char_list in suspicious_chars.items():
        if char_list:
            if char_type == 'format_chars':
                unique_chars = list(dict.fromkeys(char_list))  # Remove duplicates
                if len(unique_chars) == 1:
                    char, name = unique_chars[0]
                    issues.append(f"Format character: {name}")
                else:
                    count = len(unique_chars)
                    issues.append(f"{count} format characters (zero-width, BOM, etc.)")
            
            elif char_type == 'other_control':
                count = len(set(char_list))
                issues.append(f"{count} control characters")
            
            elif char_type == 'private_use':
                count = len(set(char_list))
                issues.append(f"{count} private-use characters")
            
            elif char_type == 'surrogate':
                issues.append("Invalid surrogate characters")
            
            elif char_type == 'unassigned':
                count = len(set(char_list))
                issues.append(f"{count} unassigned Unicode characters")
            
            elif char_type == 'unusual_spaces':
                unique_chars = list(dict.fromkeys(char_list))
                if len(unique_chars) == 1:
                    char, name = unique_chars[0]
                    issues.append(f"Unusual space: {name}")
                else:
                    issues.append(f"{len(unique_chars)} unusual spacing characters")
            
            elif char_type == 'rtl_override':
                issues.append("Right-to-left override (potential spoofing)")
            
            elif char_type == 'combining':
                count = len(char_list)
                if count > 3:  # Many combining chars might be suspicious
                    issues.append(f"Excessive combining marks ({count})")
    
    # Additional pattern-based checks
    
    # Check for sequences of the same hidden character (potential padding/obfuscation)
    for suspicious_list in suspicious_chars.values():
        if len(suspicious_list) > 2:  # More than 2 of same type
            char_counts = {}
            for char, name in suspicious_list:
                char_counts[char] = char_counts.get(char, 0) + 1
            
            for char, count in char_counts.items():
                if count > 2:
                    issues.append(f"Repeated hidden character ({count}x)")
                    break
    
    return issues


def clean_hidden_characters(text: str) -> str:
    """
    Remove hidden/suspicious characters from text for comparison.
    Uses unicodedata categories for comprehensive cleaning.
    """
    cleaned_chars = []
    
    for char in text:
        category = unicodedata.category(char)
        
        # Keep normal characters
        if category[0] in ['L', 'N', 'P', 'S']:  # Letters, Numbers, Punctuation, Symbols
            cleaned_chars.append(char)
        elif category == 'Zs' and char == ' ':  # Normal space
            cleaned_chars.append(char)
        elif char in ['\t', '\n', '\r']:  # Normal whitespace
            cleaned_chars.append(char)
        # Skip everything else (Cf, Cc, Co, Cs, Cn, unusual Zs/Zl/Zp, etc.)
    
    return ''.join(cleaned_chars)


def determine_hidden_char_severity(text: str) -> str:
    """
    Determine severity level based on types of hidden characters found.
    """
    high_risk_patterns = [
        '\u202D', '\u202E',  # RTL overrides (filename spoofing)
        '\u061C',            # Arabic letter mark
    ]
    
    medium_risk_categories = ['Co', 'Cs', 'Cn']  # Private use, surrogate, unassigned
    
    # Check for high-risk patterns
    for pattern in high_risk_patterns:
        if pattern in text:
            return "High"
    
    # Check for medium-risk categories
    for char in text:
        if unicodedata.category(char) in medium_risk_categories:
            return "Medium-High"
    
    # Check for format characters (zero-width, etc.)
    for char in text:
        if unicodedata.category(char) == 'Cf':
            return "Medium"
    
    # Other control characters
    return "Low"


def get_hidden_char_categories_summary() -> dict:
    """
    Get a summary of Unicode categories checked for hidden characters.
    Useful for documentation and debugging.
    """
    return {
        'format_chars': {
            'category': 'Cf',
            'description': 'Format characters (zero-width, BOM, etc.)',
            'examples': ['Zero Width Space', 'Zero Width Joiner', 'Byte Order Mark'],
            'severity': 'Medium'
        },
        'control_chars': {
            'category': 'Cc', 
            'description': 'Control characters (excluding normal whitespace)',
            'examples': ['NUL', 'Bell', 'Escape', 'Delete'],
            'severity': 'Low-Medium'
        },
        'private_use': {
            'category': 'Co',
            'description': 'Private use characters',
            'examples': ['Custom application symbols'],
            'severity': 'Medium-High'
        },
        'surrogates': {
            'category': 'Cs',
            'description': 'Surrogate characters (invalid in UTF-8)',
            'examples': ['UTF-16 surrogates'],
            'severity': 'Medium-High'
        },
        'unassigned': {
            'category': 'Cn',
            'description': 'Unassigned Unicode code points',
            'examples': ['Reserved/undefined characters'],
            'severity': 'Medium-High'
        },
        'unusual_spaces': {
            'category': 'Zs/Zl/Zp',
            'description': 'Unusual spacing characters',
            'examples': ['En Space', 'Em Space', 'Non-breaking Space'],
            'severity': 'Low-Medium'
        },
        'rtl_override': {
            'category': 'Special',
            'description': 'Right-to-left text direction override',
            'examples': ['Used in filename spoofing attacks'],
            'severity': 'High'
        }
    }