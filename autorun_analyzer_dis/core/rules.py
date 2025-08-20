"""
Rule-based detection of suspicious autoruns entries.
"""

import re
import pandas as pd
from .utils import safe_lower, file_name, shannon_entropy


# Living Off The Land Binaries (LOLBins)
LOL_BINS = {
    # Original ones
    'rundll32.exe', 'regsvr32.exe', 'mshta.exe', 'powershell.exe', 'pwsh.exe',
    'wscript.exe', 'cscript.exe', 'cmd.exe', 'wmic.exe', 'forfiles.exe', 'schtasks.exe',
    'installutil.exe', 'certutil.exe', 'bitsadmin.exe',
    # Additional important ones
    'msiexec.exe', 'regasm.exe', 'regsvcs.exe', 'cmstp.exe', 'odbcconf.exe',
    'mavinject.exe', 'dllhost.exe', 'verclsid.exe', 'infdefaultinstall.exe',
    'ieexec.exe', 'presentationhost.exe', 'msdt.exe', 'winrm.exe', 'winrs.exe',
    'wsl.exe', 'bash.exe', 'hh.exe', 'mmc.exe', 'mpcmdrun.exe', 'pcalua.exe',
    # Without .exe extension for flexibility
    'rundll32', 'regsvr32', 'mshta', 'powershell', 'pwsh', 'wscript', 'cscript',
    'cmd', 'wmic', 'forfiles', 'schtasks', 'installutil', 'certutil', 'bitsadmin',
    'msiexec', 'regasm', 'regsvcs', 'cmstp', 'odbcconf', 'mavinject', 'dllhost'
}

# Unicode attack patterns
ZERO_WIDTH = re.compile(r'[\u200B-\u200D\u200E\u200F\uFEFF]')
RLO = re.compile(r'[\u202A-\u202E\u2066-\u2069]')
NBSP = re.compile(r'[\u00A0\u202F]')

# Alternate Data Stream pattern
ADS = re.compile(r'(?i)^[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*:[^\\/:*?"<>|\r\n]+$')

# Device path pattern
DEVICE_PREFIX = re.compile(r'^(?:\\\\\?\\|\\\?\\|\\\\Device\\|\\\\\?\\GLOBALROOT\\|\\\\\?\\Volume\{)', re.I)


def improved_ads_detection(text_series: pd.Series) -> pd.Series:
    """Enhanced ADS detection that avoids false positives."""
    ads_mask = text_series.str.contains(ADS, na=False)
    # Exclude common false positives
    false_positives = text_series.str.contains(
        r'(?i)(?:file not found:|http:|https:|ftp:|\b\w+://)',
        na=False, regex=True
    )
    return ads_mask & ~false_positives


def rule_flags_with_reason(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    """
    Apply rule-based detection to identify suspicious entries.
    
    Returns:
        tuple: (mask of flagged rows, series of reasons)
    """
    # Find the main path column
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path', 'image', 'path', 'location', 'command', 'fullname']), None)
    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    fname = text.apply(file_name)

    # Path classifications
    user_writable = text.str.contains(
        r'\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|%temp%|%appdata%', 
        case=False, na=False
    )
    
    suspicious_paths = text.str.contains(
        r'\\Windows\\Tasks\\|\\Windows\\System32\\Tasks\\|\\Startup\\|\\Start Menu\\',
        case=False, na=False
    )
    
    # LOLBin detection
    lolbin = fname.apply(lambda s: safe_lower(s) in LOL_BINS)
    
    # Unicode attacks
    has_zwsp = text.str.contains(ZERO_WIDTH, na=False)
    has_rlo = text.str.contains(RLO, na=False)
    has_nbsp = text.str.contains(NBSP, na=False)
    
    # File system attacks
    has_ads = improved_ads_detection(text)
    has_dev = text.str.contains(DEVICE_PREFIX, na=False)
    
    # High entropy detection (potential obfuscation)
    high_entropy = text.apply(lambda s: shannon_entropy(s) > 4.5)
    
    # Command line injection patterns
    has_injection = text.str.contains(
        r'[;&|`$(){}]|powershell|cmd\.exe|wscript|cscript',
        case=False, na=False, regex=True
    )
    
    # Combined conditions
    lolbin_user = (user_writable & lolbin)
    lolbin_suspicious = (suspicious_paths & lolbin)
    
    # Overall suspicious mask
    mask = (lolbin_user | lolbin_suspicious | has_zwsp | has_rlo | 
            has_nbsp | has_ads | has_dev | high_entropy | has_injection)

    # Generate detailed reasons
    reasons = []
    for i in df.index:
        rset = []
        if lolbin_user.iat[i]: 
            rset.append("LOLBin in user-writable path")
        if lolbin_suspicious.iat[i]: 
            rset.append("LOLBin in suspicious system path")
        if has_zwsp.iat[i]: 
            rset.append("Hidden zero-width Unicode")
        if has_rlo.iat[i]: 
            rset.append("RLO/Unicode override")
        if has_nbsp.iat[i]: 
            rset.append("Non-breaking space")
        if has_ads.iat[i]: 
            rset.append("Alternate Data Stream")
        if has_dev.iat[i]: 
            rset.append("Device/Volume path")
        if high_entropy.iat[i]: 
            rset.append("High entropy (possible obfuscation)")
        if has_injection.iat[i]: 
            rset.append("Command injection pattern")
        
        reasons.append("; ".join(dict.fromkeys(rset)))
    
    return mask, pd.Series(reasons, index=df.index)