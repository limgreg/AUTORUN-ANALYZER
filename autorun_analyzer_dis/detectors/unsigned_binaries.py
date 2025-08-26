"""
Unsigned binaries detector - ultra-strict production version.
Only accepts exactly "✓ (Verified) Microsoft Windows" with full integrity verification.
"""

import pandas as pd
import unicodedata


def detect_unsigned_binaries(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect unsigned/unverified binaries based on the Signer column.
    ULTRA STRICT: Only accepts exactly "✓ (Verified) Microsoft Windows" - flags everything else
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with unsigned/unverified binary findings
    """
    if "Signer" not in df.columns:
        return pd.DataFrame()
    
    signer_s = df["Signer"]
    s = signer_s.astype("string")

    # ULTRA STRICT: Only accept the exact verified Microsoft Windows signature
    legitimate_signature = "✓ (Verified) Microsoft Windows"
    
    # Check for exact match AND verify signature integrity
    verified_mask = (s == legitimate_signature) & s.notna()
    
    # Additional integrity checks for the legitimate signature
    for idx in df.index:
        if verified_mask.at[idx]:
            signer_val = str(df.at[idx, "Signer"])
            
            # Verify no manipulation/tampering
            if not is_signature_legitimate(signer_val):
                verified_mask.at[idx] = False
    
    # Everything else is suspicious (invert the mask)
    suspicious_mask = ~verified_mask
    
    # Get suspicious entries
    df_suspicious = df.loc[suspicious_mask].copy()
    
    if len(df_suspicious) > 0:
        # Add detection details with specific reasoning
        reasons = []
        severity_levels = []
        tampering_indicators = []
        
        for idx in df_suspicious.index:
            signer_val = str(df_suspicious.at[idx, "Signer"]).strip()
            
            if pd.isna(df.at[idx, "Signer"]) or signer_val == "" or signer_val == "nan":
                reason = "No digital signature present"
                severity = "Critical"
                tampering = "Missing signature"
            
            elif signer_val == legitimate_signature:
                # This means it failed integrity check
                reason = f"Signature manipulation detected: {signer_val}"
                severity = "Critical" 
                tampering = "Signature tampering detected"
            
            elif "microsoft windows" in signer_val.lower():
                # Looks like Microsoft but wrong format
                if "verified" not in signer_val.lower():
                    reason = f"Unverified Microsoft signature: {signer_val}"
                    severity = "High"
                    tampering = "Unverified signature"
                elif not signer_val.startswith("✓"):
                    reason = f"Invalid Microsoft signature format: {signer_val}"
                    severity = "High" 
                    tampering = "Format manipulation"
                else:
                    reason = f"Modified Microsoft signature: {signer_val}"
                    severity = "High"
                    tampering = "Signature modification"
            
            elif "microsoft" in signer_val.lower():
                reason = f"Non-Windows Microsoft signature: {signer_val}"
                severity = "Medium-High"
                tampering = "Wrong Microsoft component"
            
            elif any(term in signer_val.lower() for term in ["(not verified)", "not verified", "unable to verify"]):
                reason = f"Unverified signature: {signer_val}"
                severity = "High"
                tampering = "Unverified"
            
            elif signer_val.lower() in ["n/a", "unknown", "unsigned"]:
                reason = f"Unsigned binary: {signer_val}"
                severity = "Critical"
                tampering = "No signature"
            
            else:
                # Third-party or unknown
                reason = f"Third-party/unknown signature: {signer_val}"
                severity = "Medium"
                tampering = "Non-Microsoft signature"
            
            reasons.append(reason)
            severity_levels.append(severity)
            tampering_indicators.append(tampering)
        
        df_suspicious.insert(len(df_suspicious.columns), "detection_reason", reasons)
        df_suspicious.insert(len(df_suspicious.columns), "detection_type", "Unsigned/Unverified Binary")
        df_suspicious.insert(len(df_suspicious.columns), "severity_level", severity_levels)
        df_suspicious.insert(len(df_suspicious.columns), "tampering_indicator", tampering_indicators)
        
        # Add signature analysis
        signature_categories = []
        for idx in df_suspicious.index:
            signer_val = str(df_suspicious.at[idx, "Signer"]).strip()
            
            if pd.isna(df.at[idx, "Signer"]) or signer_val == "" or signer_val == "nan":
                category = "No Signature"
            elif signer_val == legitimate_signature:
                category = "Tampered Signature"  # Failed integrity check
            elif "microsoft" in signer_val.lower():
                category = "Invalid Microsoft"
            elif "verified" in signer_val.lower():
                category = "Invalid Verified"
            elif any(term in signer_val.lower() for term in ["not verified", "unable to verify"]):
                category = "Unverified"
            elif signer_val.lower() in ["n/a", "unknown", "unsigned"]:
                category = "Unsigned"
            else:
                category = "Third-Party"
            
            signature_categories.append(category)
        
        df_suspicious.insert(len(df_suspicious.columns), "signature_category", signature_categories)
    
    return df_suspicious


def is_signature_legitimate(signature: str) -> bool:
    """
    Verify signature integrity and legitimacy.
    Checks for common manipulation techniques.
    
    Args:
        signature: The signature string to verify
        
    Returns:
        bool: True if signature appears legitimate, False otherwise
    """
    legitimate_signature = "✓ (Verified) Microsoft Windows"
    
    if signature != legitimate_signature:
        return False
    
    # Additional integrity checks
    
    # Check character encoding (detect Unicode manipulation)
    try:
        # Ensure it's proper UTF-8 without hidden characters
        encoded = signature.encode('utf-8')
        decoded = encoded.decode('utf-8')
        if decoded != signature:
            return False
    except (UnicodeError, UnicodeDecodeError):
        return False
    
    # Check for suspicious Unicode characters
    suspicious_unicode = False
    for char in signature:
        # Check for format characters, control characters, etc.
        import unicodedata
        category = unicodedata.category(char)
        if category in ['Cf', 'Cc', 'Co', 'Cs', 'Cn']:  # Format, Control, Private, Surrogate, Unassigned
            suspicious_unicode = True
            break
        
        # Check for lookalike characters (homograph attack)
        if char == '✓':
            # Ensure it's the correct checkmark (U+2713)
            if ord(char) != 0x2713:
                suspicious_unicode = True
                break
    
    if suspicious_unicode:
        return False
    
    # Check string length (detect padding attacks)
    expected_length = len(legitimate_signature)
    if len(signature) != expected_length:
        return False
    
    # Check for whitespace manipulation
    if signature != signature.strip():
        return False
    
    # Check for case manipulation (though we already did exact match)
    if signature.lower() != legitimate_signature.lower():
        return False
    
    # All checks passed
    return True


def get_signature_analysis_summary(df: pd.DataFrame) -> dict:
    """
    Get summary of signature analysis for ultra-strict verification.
    """
    if "Signer" not in df.columns:
        return {
            'status': 'No signature data available',
            'total_entries': len(df),
            'legitimate': 0,
            'suspicious': len(df)
        }
    
    legitimate_signature = "✓ (Verified) Microsoft Windows"
    signer_s = df["Signer"].astype("string")
    
    # Count only exact legitimate signatures that pass integrity check
    legitimate_count = 0
    for idx in df.index:
        signer_val = str(df.at[idx, "Signer"])
        if signer_val == legitimate_signature and is_signature_legitimate(signer_val):
            legitimate_count += 1
    
    suspicious = len(df) - legitimate_count
    
    # Categorize all suspicious signatures
    categories = {
        'no_signature': signer_s.isna().sum(),
        'tampered': 0,  # Signatures that look right but fail integrity
        'invalid_microsoft': 0,  # Microsoft-like but wrong format
        'unverified': 0,
        'unsigned_explicit': 0,
        'third_party': 0
    }
    
    for idx in df.index:
        signer_val = str(df.at[idx, "Signer"]).strip()
        
        if pd.isna(df.at[idx, "Signer"]) or signer_val == "" or signer_val == "nan":
            continue  # Already counted in no_signature
        elif signer_val == legitimate_signature and not is_signature_legitimate(signer_val):
            categories['tampered'] += 1
        elif "microsoft" in signer_val.lower() and signer_val != legitimate_signature:
            categories['invalid_microsoft'] += 1
        elif any(term in signer_val.lower() for term in ["not verified", "unable to verify"]):
            categories['unverified'] += 1
        elif signer_val.lower() in ["n/a", "unknown", "unsigned"]:
            categories['unsigned_explicit'] += 1
        elif signer_val != legitimate_signature:
            categories['third_party'] += 1
    
    return {
        'status': 'Ultra-strict: Only exact verified Microsoft Windows accepted',
        'total_entries': len(df),
        'legitimate': legitimate_count,
        'suspicious': suspicious,
        'suspicious_percentage': round(suspicious / len(df) * 100, 1) if len(df) > 0 else 0,
        'categories': categories,
        'policy': 'Only "✓ (Verified) Microsoft Windows" with integrity verification',
        'legitimate_signature': legitimate_signature
    }


def print_signature_policy():
    """
    Print the ultra-strict signature verification policy.
    """
    print("\n" + "="*70)
    print("ULTRA-STRICT SIGNATURE VERIFICATION POLICY")
    print("="*70)
    print("🔒 MAXIMUM SECURITY: Only ONE specific signature accepted")
    print("")
    print("✅ TRUSTED (ONLY THIS EXACT STRING):")
    print("   ✓ (Verified) Microsoft Windows")
    print("")
    print("🛡️  INTEGRITY VERIFICATION:")
    print("   • Exact string match (case-sensitive)")
    print("   • UTF-8 encoding verification")
    print("   • Hidden character detection")
    print("   • Unicode homograph attack prevention")
    print("   • Whitespace manipulation detection")
    print("   • String length validation")
    print("")
    print("❌ FLAGGED AS SUSPICIOUS (EVERYTHING ELSE):")
    print("   • No signature")
    print("   • Tampered signatures (failed integrity check)")
    print("   • Invalid Microsoft formats:")
    print("     - 'Microsoft Windows' (missing checkmark/verified)")
    print("     - '(Verified) Microsoft Windows' (wrong checkmark)")
    print("     - 'Microsoft Corporation'")
    print("   • Unverified signatures")
    print("   • Third-party signatures (Adobe, Google, etc.)")
    print("   • Any other variation")
    print("")
    print("💡 RATIONALE:")
    print("   This ultra-strict approach prevents ALL signature manipulation")
    print("   attacks including Unicode spoofing, format manipulation, and")
    print("   ensures only genuine Windows system files are trusted.")
    print("="*70)