"""
Unsigned binaries detector - moved from unsigned.py
Detects files without valid digital signatures.
"""

import pandas as pd


def detect_unsigned_binaries(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect unsigned binaries based on the Signer column.
    
    Args:
        df: Input DataFrame
        
    Returns:
        DataFrame with unsigned binary findings
    """
    if "Signer" not in df.columns:
        return pd.DataFrame()
    
    signer_s = df["Signer"]
    s = signer_s.astype("string")

    # Only flag as unsigned if missing or explicitly unsigned
    unsigned_mask = (
        # Missing or empty values
        s.isna() |
        (s == "") |
        (s.str.strip() == "") |
        
        # Entries that start with "(Not verified)" - case insensitive
        s.str.contains(r"^\(not verified\)", case=False, regex=True, na=False) |
        
        # Exact matches for other known unsigned indicators (case insensitive)
        (s.str.lower() == "microsoft windows publisher") |
        (s.str.lower() == "n/a") |
        (s.str.lower() == "unknown") |
        (s.str.lower() == "unsigned") |
        (s.str.lower() == "not verified") |
        (s.str.lower() == "unable to verify")
    )
    
    # Convert to boolean and get unsigned entries
    df_unsigned = df.loc[unsigned_mask].copy()
    
    if len(df_unsigned) > 0:
        # Add detection details
        reasons = []
        for idx in df_unsigned.index:
            signer_val = str(df_unsigned.at[idx, "Signer"])
            if pd.isna(df.at[idx, "Signer"]) or signer_val == "" or signer_val.strip() == "":
                reason = "Missing digital signature"
            elif signer_val.lower().startswith("(not verified)"):
                reason = f"Unverified signature: {signer_val}"
            else:
                reason = f"Unsigned/invalid signature: {signer_val}"
            reasons.append(reason)
        
        df_unsigned.insert(len(df_unsigned.columns), "detection_reason", reasons)
        df_unsigned.insert(len(df_unsigned.columns), "detection_type", "Unsigned Binary")
    
    return df_unsigned