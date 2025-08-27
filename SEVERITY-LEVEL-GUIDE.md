# Severity Level Guide

This document explains how the Autoruns Analyzer assigns severity levels (Critical, High, Medium, Low) across all detection modules.

## Severity Level Philosophy

The severity system is designed to help security analysts prioritize investigation efforts based on:
- **Potential for system compromise**
- **Likelihood of malicious intent**
- **Impact on system security**
- **Ease of exploitation**

---

## Critical Severity

**Definition:** Immediate security threat requiring urgent investigation.

### Visual Masquerading (Character Analysis)
- **Not implemented** - All findings currently flagged as detection only

### Unsigned Binaries (Signature Analysis)  
**CRITICAL** findings include:
- **No digital signature present** - Completely unsigned executables
- **Signature tampering detected** - Signatures that appear legitimate but fail integrity checks

### Suspicious Paths (Location Analysis)
**CRITICAL** findings include:
- **Unknown files in core system directories:**
  - `C:\Windows\System32\`
  - `C:\Windows\SysWOW64\` 
  - `C:\Windows\WinSxS\`
- **Malicious path patterns:**
  - Fake System32 directory masquerading (`\system32\` outside Windows)
  - Script files in system directories (.bat, .cmd, .vbs, .js, .ps1, .scr, .com, .pif in Windows dirs)
  - Illegal filename characters in executables
  - Double extension patterns (potential masquerading)
  - Extremely long paths (>300 characters)

### Hidden Characters (Character Encoding)
- **Not implemented** - All findings currently flagged as detection only

### Baseline Comparison (Integrity Analysis)
**CRITICAL** findings include:
- **System32 file integrity violations** - Core system files with hash mismatches
- **WinSxS file integrity violations** - Side-by-side assembly tampering
- **Other core system directory violations**

---

##  High Severity

**Definition:** Significant security concern requiring prompt investigation.

### Visual Masquerading (Character Analysis)
- **Not implemented** - All findings currently flagged as detection only

### Unsigned Binaries (Signature Analysis)
**HIGH** severity findings include:
- **Unverified Microsoft signatures** - Contains "microsoft" but not properly verified
- **Invalid Microsoft signature formats** - Microsoft-like signatures with wrong format
- **Modified Microsoft signatures** - Signatures that appear to be Microsoft but are altered
- **Unverified signatures** - Explicitly marked as "(not verified)" or "unable to verify"

### Suspicious Paths (Location Analysis)
**HIGH** severity findings include:
- **Unknown executables in Microsoft directories:**
  - `C:\Program Files\Microsoft\`
  - `C:\Program Files\Windows NT\`
  - `C:\Program Files\Common Files\Microsoft\`
  - `C:\Program Files (x86)\Microsoft\`
- **Unknown executables in Windows directory** (non-system32)

### Hidden Characters (Character Encoding)
**HIGH** severity findings include:
- **Right-to-left override characters** - Used in filename spoofing attacks (U+202D, U+202E, U+061C)

### Baseline Comparison (Integrity Analysis)
**HIGH** severity findings include:
- **Windows directory file violations** - Non-system32 Windows files with hash mismatches
- **Microsoft Program Files violations** - Microsoft application integrity compromised

---

##  Medium-High Severity

**Definition:** Elevated concern warranting investigation.

### Visual Masquerading (Character Analysis)
- **Not implemented** - All findings currently flagged as detection only

### Unsigned Binaries (Signature Analysis)
**MEDIUM-HIGH** severity findings include:
- **Non-Windows Microsoft signatures** - Microsoft products other than Windows OS

### Suspicious Paths (Location Analysis)  
**MEDIUM-HIGH** severity findings include:
- **Unknown autorun/startup entries:**
  - `\Startup\` directories
  - `\Start Menu\Programs\Startup\`
  - `C:\ProgramData\Microsoft\Windows\Start Menu\`
  - `\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`

### Hidden Characters (Character Encoding)
**MEDIUM-HIGH** severity findings include:
- **Private use characters** - Unicode private use area (Co category)
- **Surrogate characters** - Invalid UTF-8 surrogate pairs (Cs category)  
- **Unassigned characters** - Undefined Unicode code points (Cn category)

### Baseline Comparison (Integrity Analysis)
- **Not implemented at this level**

---

## Medium Severity

**Definition:** Moderate concern requiring evaluation.

### Visual Masquerading (Character Analysis)
- **Not implemented** - All findings currently flagged as detection only

### Unsigned Binaries (Signature Analysis)
**MEDIUM** severity findings include:
- **Third-party signatures** - Legitimate third-party software (Adobe, Google, etc.)

### Suspicious Paths (Location Analysis)
**MEDIUM** severity findings include:
- **Unknown executables in Program Files** - Third-party software not in baseline
- **Unknown executables in persistence locations:**
  - `C:\ProgramData\`
  - `C:\Users\Public\`

### Hidden Characters (Character Encoding)
**MEDIUM** severity findings include:
- **Format characters** - Zero-width characters, BOM, etc. (Cf category)

### Baseline Comparison (Integrity Analysis)
**MEDIUM** severity findings include:
- **Program Files integrity violations** - Third-party application files with hash mismatches

---

##  Low Severity

**Definition:** Minor anomaly worth noting.

### Visual Masquerading (Character Analysis)
- **Not implemented** - All findings currently flagged as detection only

### Unsigned Binaries (Signature Analysis)
- **Not implemented at this level**

### Suspicious Paths (Location Analysis)
**LOW** severity findings include:
- **Unknown executables in temporary locations:**
  - `\Temp\` directories
  - `\Tmp\` directories  
  - `C:\Windows\Temp\`
  - `\AppData\Local\Temp\`

### Hidden Characters (Character Encoding)  
**LOW** severity findings include:
- **Other control characters** - Non-printable characters (Cc category, excluding normal whitespace)

### Baseline Comparison (Integrity Analysis)
**LOW** severity findings include:
- **Other location integrity violations** - Files outside critical system areas with hash mismatches

---

##  Anomaly Detection Severity

The **Statistical Anomaly Detection** module doesn't assign traditional severity levels but uses **percentile-based scoring**:

- **Top 3%** - Highest anomaly scores (most suspicious statistical outliers)
- **Scores 0.0-1.0** - Normalized anomaly scores where 1.0 is most anomalous
- **Feature-based** - Considers path length, entropy, argument count, file signatures, etc.

---

##  Multi-Detection Priority Scoring

When multiple detectors flag the same item, **priority scores** are calculated:

```
Priority Score = (Number of Detectors × 10) × Severity Multiplier

Severity Multipliers:
- Critical: 2.0×
- High: 1.5×  
- Medium: 1.0×
- Low: 0.8×
```

**Example:**
- Item flagged by 3 detectors with highest severity "High"
- Priority Score = (3 × 10) × 1.5 = **45 points**

