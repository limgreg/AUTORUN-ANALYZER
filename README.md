# SIT-DIS-VA
auturun csv scanner 
# Autoruns Analyzer - Advanced Windows Persistence Detection

A comprehensive toolkit for analyzing Windows Sysinternals Autoruns data with multiple detection techniques including visual masquerading, anomaly detection, and baseline comparison.

##  Architecture Overview

The package follows a **modular detection architecture** where each detection technique is implemented as an independent module, managed by a central registry system.

```
autorun_analyzer_dis/
├── core/                    # Core analysis components
├── detectors/              # Modular detection system
├── reports/                # Report generation
└── main.py                # Main orchestration

```

##  File Structure & Purpose

###  Package Root

| File | Purpose | Key Features |
| --- | --- | --- |
| `__init__.py` | Package initialization | Exports main functions, version info |
| `main.py` | **Main orchestration** | CLI interface, coordinates all detections, fallback handling |

###  Core Analysis (`core/`)

| File | Purpose | Techniques Used |
| --- | --- | --- |
| `utils.py` | **Shared utilities** | File encoding detection, path normalization, Shannon entropy calculation |
| `baseline.py` | **Baseline comparison** | Hash-based file integrity checking, path normalization |
| `pysad.py` | **Statistical analysis** | PySAD integration, feature engineering, meta-detection |

###  Detection Modules (`detectors/`)

| File | Detection Type | Techniques & Algorithms |
| --- | --- | --- |
| `__init__.py` | **Detection Registry** | Central detector management, overlap analysis, priority scoring |
| `visual_masquerading.py` | **Visual Masquerading** | Unicode confusable character detection, legitimate filename spoofing |
| `unsigned_binaries.py` | **Digital Signatures** | Certificate validation, unsigned binary identification |
| `suspicious_paths.py` | **Path Analysis** | Suspicious location detection, system directory masquerading |
| `hidden_characters.py` | **Hidden Characters** | NBSP, zero-width chars, control characters, RTL override detection |
| `baseline_comparison.py` | **Baseline Deviations** | Known-good baseline comparison, hash verification |
| `anomaly_detection.py` | **Statistical Anomalies** | PySAD-based outlier detection, feature engineering |

###  Reports (`reports/`)

| File | Purpose | Features |
| --- | --- | --- |
| `excel.py` | **Excel Report Generation** | Multi-sheet reports, auto-formatting, overlap analysis, executive summary |

##  Detection Techniques Explained

### 1. Visual Masquerading Detection

**File:** `detectors/visual_masquerading.py`

**Technique:** Detects malware using Unicode confusable characters that appear identical to legitimate filenames.

**How it works:**

- Maps confusable characters (e.g., Cyrillic 'а' vs Latin 'a')
- Normalizes filenames by replacing confusables
- Compares against known legitimate executables
- Flags executables with actual character substitutions

**Example Detection:**

```
svchost.exe → svсhost.exe (using Cyrillic 'с' instead of Latin 'c')

```

### 2. Unsigned Binary Detection

**File:** `detectors/unsigned_binaries.py`

**Technique:** Identifies files without valid digital signatures.

**Detection Logic:**

- Missing/empty Signer fields
- "(Not verified)" prefixes
- Known unsigned indicators (N/A, Unknown, etc.)
- Case-insensitive pattern matching

### 3. Hidden Character Detection

**File:** `detectors/hidden_characters.py`

**Technique:** Finds non-printable and hidden Unicode characters often used in evasion.

**Character Types Detected:**

- **NBSP (U+00A0):** Non-breaking spaces
- **Zero-width chars:** ZWSP, ZWNJ, ZWJ, BOM
- **Control chars:** 0x00-0x1F, 0x7F-0x9F ranges
- **RTL override:** Right-to-left text manipulation
- **Unicode spaces:** En/Em spaces, hair spaces
- **Combining marks:** Diacritical marks

### 4. Baseline-Driven Suspicious Path Analysis

**File:** `detectors/suspicious_paths.py`

**Technique:** Intelligent path analysis using baseline comparison as primary method.

**Detection Strategy:**

- **Primary:** Baseline comparison (unknown paths in critical locations)
- **Hash Verification:** File replacement detection via hash mismatches
- **Critical Fallback:** Minimal rules when no baseline available
- **Suspicion Levels:** Critical/High/Medium/Low priority classification

**Focus Areas:**

- Unknown files in System32/SysWOW64 (Critical)
- Unknown executables in Program Files (High)
- File integrity violations (Critical)
- Minimal false positives through environment-aware detection

### 5. Statistical Anomaly Detection

**File:** `detectors/anomaly_detection.py`

**Technique:** Uses PySAD (Python Streaming Anomaly Detection) for outlier identification.

**Feature Engineering:**

- String length analysis
- Argument counting
- Path depth (slash/backslash count)
- File extension analysis (dot count)
- Shannon entropy (randomness measure)
- Digital signature status

**Algorithms Available:**

- **HalfSpaceTrees (HST):** Fast, memory-efficient
- **LODA:** Lightweight Online Detector of Anomalies

### 6. Baseline Comparison

**File:** `detectors/baseline_comparison.py`

**Technique:** Compares against known-good baseline data.

**Verification Methods:**

- Path existence checking
- Hash verification (SHA256 > SHA1 > MD5 priority)
- System directory validation
- Encoding-robust CSV parsing

### 7. Meta-Detection System

**File:** `core/pysad.py` - `run_meta_pysad_analysis()`

**Technique:** Advanced meta-analysis using detection results as features.

**Meta-Features:**

- Binary flags for each detector (0/1)
- Total detection count per entry
- High/medium priority detection counts
- Combined risk scoring

**Risk Calculation:**

```python
combined_risk_score = meta_pysad_score * (1 + detection_count * 0.2)

```

##  Detection Registry System

**File:** `detectors/__init__.py`

The registry provides centralized management of all detection modules:

### Key Features:

- **Dynamic Registration:** Easy addition of new detectors
- **Enable/Disable:** Runtime control of detectors
- **Overlap Analysis:** Find items detected by multiple methods
- **Priority Scoring:** Weighted importance of different detection types
- **Combined Findings:** High-priority items flagged by multiple detectors

### Priority Weights:

- Visual Masquerading: **10** (highest)
- Unsigned Binaries: **8**
- Baseline-Driven Suspicious Paths: **6** (with suspicion level multipliers)
- Hidden Characters: **5**
- Baseline Deviations: **3**
- Anomaly Detection: **2**

### Suspicion Level Multipliers:

- **Critical** (System files, hash mismatches): **2.0x**
- **High** (Unknown executables in Program Files): **1.5x**
- **Medium-High** (Unknown autorun entries): **1.3x**
- **Medium** (Other unknown executables): **1.0x**
- **Low** (Watched locations): **0.8x**

##  Core Utilities

### File Compatibility (`core/utils.py`)

**Techniques:**

- **Encoding Detection:** BOM detection, UTF-16/UTF-8 heuristics
- **Delimiter Detection:** Automatic tab/comma detection
- **Path Normalization:** Case-insensitive, environment variable handling
- **Shannon Entropy:** Information theory for randomness measurement

### PySAD Integration (`core/pysad.py`)

**Advanced Features:**

- **Feature Engineering:** Multi-dimensional numeric feature extraction
- **Model Selection:** HalfSpaceTrees vs LODA algorithms
- **Score Normalization:** 0-1 range normalization
- **Robust Processing:** Fallback handling for individual samples

##  Report Generation

**File:** `reports/excel.py`

### Report Structure:

1. **Executive Summary:** Key metrics, risk assessment
2. **Detection Summary:** All detector results overview
3. **High-Priority Combined:** Items flagged by multiple detectors
4. **Individual Detection Sheets:** Detailed findings per detector
5. **Overlap Analysis:** Detector intersection analysis
6. **All Rows:** Complete dataset reference

### Formatting Features:

- Auto-sized columns with intelligent width calculation
- Conditional formatting for different data types
- Freeze panes and autofilters
- Text wrapping for long content
- Color-coded risk levels

##  Usage Examples

### Basic Analysis (Fallback Mode):

```bash
python -m autorun_analyzer_dis autoruns.csv

```

*Note: Without baseline, suspicious path detection uses minimal fallback rules*

### **Recommended: Baseline-Enhanced Analysis:**

```bash
python -m autorun_analyzer_dis autoruns.csv report.xlsx 5.0 clean_baseline.csv loda

```

*Much higher accuracy with environment-aware detection*

### Creating a Clean Baseline:

```bash
# On a clean, known-good system:
Autoruns.exe -c -h -s > clean_baseline.csv

```

### Programmatic Usage:

```python
from autorun_analyzer_dis import main, autoruns_to_dataframe
from autorun_analyzer_dis.detectors import run_all_detections

# Load data
df = autoruns_to_dataframe("autoruns.csv")

# Baseline-enhanced detection (recommended)
results, registry = run_all_detections(df, baseline_csv="clean_baseline.csv")

# Get high-priority combined findings
combined = registry.get_combined_findings(df, results)

# test

```