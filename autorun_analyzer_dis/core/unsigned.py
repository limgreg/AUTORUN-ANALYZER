"""
Digital signature verification functionality.
"""

import pandas as pd


def unsigned_series(signer_s: pd.Series | None, n: int) -> pd.Series:
    """
    Identify unsigned binaries based on the Signer column.
    
    Updated to handle the 'Signer' column format:
    - "(Verified) Microsoft Windows" → Signed
    - "Microsoft Windows Publisher"  → Unsigned  
    - Missing/empty                 → Unsigned
    
    Args:
        signer_s: Series containing signature information (can be None)
        n: Number of rows (for creating empty series if signer_s is None)
        
    Returns:
        Series of boolean values (1=unsigned, 0=signed)
    """
    if signer_s is not None:
        s = signer_s.astype("string")
    else:
        s = pd.Series([pd.NA] * n, dtype="string")

    # Check for unsigned patterns
    unsigned_mask = (
        s.isna() |
        (s == "") |
        # Case: No "(Verified)" prefix
        ~s.str.startswith("(Verified)", na=False) |
        # Case: Common unsigned placeholders
        s.str.contains(
            r"(?i)microsoft windows publisher|n/?a|unknown|unavailable|not available|unsigned|not verified",
            regex=True, na=False
        )
    )
    
    return unsigned_mask.fillna(True).astype(int)


def get_unsigned_entries(df: pd.DataFrame) -> pd.DataFrame:
    """
    Get all unsigned entries from the DataFrame.
    
    Args:
        df: Input DataFrame with Signer column
        
    Returns:
        DataFrame containing only unsigned entries with reason
    """
    unsigned_mask = unsigned_series(df.get("Signer"), len(df))
    df_unsigned = df.loc[unsigned_mask.astype(bool)].copy()
    
    if len(df_unsigned) > 0:
        df_unsigned.insert(len(df_unsigned.columns), "unsigned_reason", 
                          "No valid digital signature detected")
    
    return df_unsigned