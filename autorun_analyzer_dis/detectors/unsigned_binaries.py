"""
Unsigned binaries detector with strict verification.
"""

import pandas as pd
import unicodedata


def detect_unsigned_binaries(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect unsigned/unverified binaries based on digital signatures.
    Strict policy: Only accepts exact "✓ (Verified) Microsoft Windows".
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with unsigned/unverified binary findings
    """
    if "Signer" not in df.columns:
        return pd.DataFrame()
    
    signer_s = df["Signer"]
    s = signer_s.astype("string")

    # Only accept exact verified Microsoft Windows signature
    legitimate_signature = "✓ (Verified) Microsoft Windows"
    
    # Check for exact match and integrity
    verified_mask = (s == legitimate_signature) & s.notna()
    
    # Additional integrity checks
    for idx in df.index:
        if verified_mask.at[idx]:
            signer_val = str(df.at[idx, "Signer"])
            if not _is_signature_legitimate(signer_val):
                verified_mask.at[idx] = False
    
    # Everything else is suspicious
    suspicious_mask = ~verified_mask
    df_suspicious = df.loc[suspicious_mask].copy()
    
    if len(df_suspicious) > 0:
        reasons = []
        severity_levels = []
        signature_categories = []
        
        for idx in df_suspicious.index:
            signer_val = str(df_suspicious.at[idx, "Signer"]).strip()
            
            if pd.isna(df.at[idx, "Signer"]) or signer_val == "" or signer_val == "nan":
                reason = "No digital signature present"
                severity = "Critical"
                category = "No Signature"
            
            elif signer_val == legitimate_signature:
                reason = f"Signature tampering detected"
                severity = "Critical" 
                category = "Tampered Signature"
            
            elif "microsoft windows" in signer_val.lower():
                if "verified" not in signer_val.lower():
                    reason = f"Unverified Microsoft signature: {signer_val}"
                    severity = "High"
                    category = "Invalid Microsoft"
                elif not signer_val.startswith("✓"):
                    reason = f"Invalid Microsoft signature format: {signer_val}"
                    severity = "High" 
                    category = "Invalid Microsoft"
                else:
                    reason = f"Modified Microsoft signature: {signer_val}"
                    severity = "High"
                    category = "Invalid Microsoft"
            
            elif "microsoft" in signer_val.lower():
                reason = f"Non-Windows Microsoft signature: {signer_val}"
                severity = "Medium-High"
                category = "Third-Party"
            
            elif any(term in signer_val.lower() for term in ["(not verified)", "not verified", "unable to verify"]):
                reason = f"Unverified signature: {signer_val}"
                severity = "High"
                category = "Unverified"
            
            elif signer_val.lower() in ["n/a", "unknown", "unsigned"]:
                reason = f"Unsigned binary: {signer_val}"
                severity = "Critical"
                category = "Unsigned"
            
            else:
                reason = f"Third-party signature: {signer_val}"
                severity = "Medium"
                category = "Third-Party"
            
            reasons.append(reason)
            severity_levels.append(severity)
            signature_categories.append(category)
        
        df_suspicious.insert(len(df_suspicious.columns), "detection_reason", reasons)
        df_suspicious.insert(len(df_suspicious.columns), "detection_type", "Unsigned/Unverified Binary")
        df_suspicious.insert(len(df_suspicious.columns), "severity_level", severity_levels)
        df_suspicious.insert(len(df_suspicious.columns), "signature_category", signature_categories)
    
    return df_suspicious


def _is_signature_legitimate(signature: str) -> bool:
    """Verify signature integrity against manipulation."""
    legitimate_signature = "✓ (Verified) Microsoft Windows"
    
    if signature != legitimate_signature:
        return False
    
    # Check character encoding
    try:
        encoded = signature.encode('utf-8')
        decoded = encoded.decode('utf-8')
        if decoded != signature:
            return False
    except (UnicodeError, UnicodeDecodeError):
        return False
    
    # Check for suspicious Unicode characters
    for char in signature:
        category = unicodedata.category(char)
        if category in ['Cf', 'Cc', 'Co', 'Cs', 'Cn']:
            return False
        
        # Ensure correct checkmark
        if char == '✓' and ord(char) != 0x2713:
            return False
    
    # Check string length and whitespace
    if len(signature) != len(legitimate_signature) or signature != signature.strip():
        return False
    
    return True