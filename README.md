# Autoruns Analyzer - Simplified Clean Architecture

A streamlined Windows persistence detection system for analyzing Microsoft Sysinternals Autoruns CSV exports. Built with clean architecture principles emphasizing simplicity, reliability, and single-responsibility detectors.

## Project Overview

This tool analyzes Windows autoruns data to identify potentially malicious software through multiple focused detection techniques. The system prioritizes simplicity and reliability over complexity, using direct function calls and clear separation of concerns.

## Architecture Philosophy

**Simplified Design Principles:**
- Each detector has exactly one focused responsibility  
- Direct function calls replace complex registry management
- Clear, readable code over sophisticated abstractions
- Graceful error handling with independent detector operation
- Baseline enhancement improves accuracy without complexity

## File Structure

```
autorun_analyzer_dis/
├── __init__.py              # Package exports (main, autoruns_to_dataframe)
├── main.py                  # Main analysis orchestration
├── 
├── core/                    # Core utilities and analysis
│   ├── __init__.py         # Core function exports
│   ├── utils.py            # File handling, encoding, path normalization
│   ├── pysad.py            # Statistical analysis and feature engineering
│   └── baseline.py         # Baseline comparison utilities
├── 
├── detectors/               # Detection modules (single responsibility)
│   ├── __init__.py         # Simple orchestration (run_all_detections)
│   ├── visual_masquerading.py     # Mixed Unicode script detection
│   ├── unsigned_binaries.py       # Ultra-strict signature verification
│   ├── suspicious_paths.py        # Location analysis (baseline-aware)
│   ├── hidden_characters.py       # Non-printable character detection
│   ├── baseline_comparison.py     # File integrity verification
│   └── anomaly_detection.py       # Statistical outlier detection
└── 
└── reports/                 # Report generation
    ├── __init__.py         # Report function exports
    └── excel.py            # Excel report generation
```

## Detection Capabilities

### 1. Visual Masquerading Detection
- **Method**: Mixed Unicode script analysis
- **Detects**: Filenames mixing Latin with Cyrillic/Greek/Arabic scripts
- **Use Case**: Legitimate process name spoofing (e.g., svсhost.exe using Cyrillic 'с')

### 2. Unsigned Binaries Detection
- **Policy**: Ultra-strict verification
- **Accepts**: Only "✓ (Verified) Microsoft Windows" with integrity checking
- **Flags**: Everything else including tampered Microsoft signatures

### 3. Suspicious Paths Analysis
- **Primary Mode**: Baseline-driven environment intelligence
- **Fallback**: Pattern-based malicious path detection
- **Focus**: File location analysis only (no hash verification)

### 4. Hidden Characters Detection
- **Method**: Unicode category-based analysis using unicodedata
- **Detects**: Format characters, control characters, RTL overrides
- **Advantage**: Comprehensive coverage beyond hardcoded character lists

### 5. Baseline Comparison
- **Purpose**: Pure file integrity verification
- **Method**: SHA256/SHA1/MD5 hash comparison against baseline
- **Requires**: Baseline CSV with hash data

### 6. Statistical Anomaly Detection
- **Engine**: PySAD (Half-Space Trees or LODA algorithms)
- **Features**: Path length, entropy, argument count, signature status
- **Output**: Top percentile statistical outliers only

## Key Features

### Simplified Architecture Benefits
- **Direct Function Calls**: No complex registry or object management overhead
- **Independent Operation**: Each detector fails gracefully without affecting others
- **Clear Code Paths**: Easy to debug, maintain, and extend
- **Memory Efficient**: Streamlined processing without complex abstractions

### Baseline Enhancement
- **Automatic Intelligence**: Detectors improve accuracy when baseline provided
- **Environment Awareness**: Compares against known-good system configurations
- **Reduced False Positives**: Baseline-driven analysis vs generic pattern matching

### Interactive Runner
- **Smart File Selection**: Search and pagination for large file collections
- **Metadata Display**: File size, modification date, and organization
- **Baseline Management**: Organized subfolder structure with enhanced search

## Installation and Setup

### Requirements
```
Python 3.8+
pandas >= 1.5.0
xlsxwriter >= 3.0.0
pysad >= 0.2.0
numpy >= 1.20.0
unicodedata (built-in)
```

### Installation
```bash
# Clone repository
git clone <repository-url>
cd autorun_analyzer_dis

# Install dependencies  
pip install -r requirements.txt

# Create directory structure
mkdir csv baseline output
```

## Usage

### Interactive Mode (Recommended)
```bash
python runner.py
```
Provides guided file selection, parameter configuration, and execution.

### Command Line Mode
```bash
python -m autorun_analyzer_dis.main input.csv output.xlsx 3.0 baseline.csv hst
```

### Programmatic Usage
```python
from autorun_analyzer_dis import autoruns_to_dataframe
from autorun_analyzer_dis.detectors import run_autoruns_analysis

# Load and analyze data
df = autoruns_to_dataframe("autoruns.csv")
results, registry, combined = run_autoruns_analysis(
    df, baseline_csv="baseline.csv", pysad_method="hst", top_pct=3.0
)

# Access individual detector results
unsigned_findings = results['unsigned_binaries']
path_findings = results['suspicious_paths']
```

## Configuration Options

### Statistical Methods
- **HST (Half-Space Trees)**: Default, fast execution, effective for high-dimensional data
- **LODA**: Alternative algorithm with different detection characteristics

### Analysis Parameters
- **Top Percentage**: 1-10% (3% recommended) - controls statistical anomaly sensitivity
- **Baseline Mode**: Automatic enhancement when baseline CSV provided

## Output Structure

### Excel Report Sheets
1. **Executive Summary**: Key metrics, configuration, risk assessment
2. **Detection Summary**: Detector status and finding counts
3. **Overlap Analysis**: Items flagged by multiple detectors
4. **Individual Detector Sheets**: Detailed findings per detector
5. **All Rows**: Complete original data preservation

### Key Output Features
- **Auto-sized columns** with intelligent width calculation
- **Freeze panes and autofilters** for easy navigation
- **Professional formatting** with conditional formatting
- **Comprehensive data preservation** for forensic analysis

## Detector Implementation Details

### Visual Masquerading (`visual_masquerading.py`)
```python
def detect_visual_masquerading(df: pd.DataFrame) -> pd.DataFrame:
    # Returns DataFrame with mixed script findings
    # Uses unicodedata for script classification
    # Focuses on Latin + non-Latin combinations
```

### Unsigned Binaries (`unsigned_binaries.py`)
```python
def detect_unsigned_binaries(df: pd.DataFrame) -> pd.DataFrame:
    # Ultra-strict: only accepts "✓ (Verified) Microsoft Windows"
    # Includes signature integrity verification
    # Flags tampering attempts and format manipulation
```

### Suspicious Paths (`suspicious_paths.py`)
```python  
def detect_suspicious_paths(df: pd.DataFrame, baseline_csv: str = None) -> pd.DataFrame:
    # Two-mode operation: baseline-driven vs pattern-based
    # Environment-aware intelligence when baseline available
    # Location-based severity assessment
```

### Hidden Characters (`hidden_characters.py`)
```python
def detect_hidden_characters(df: pd.DataFrame) -> pd.DataFrame:
    # Unicode category-based detection (Cf, Cc, Co, Cs, Cn)
    # RTL override detection for filename spoofing
    # Comprehensive beyond hardcoded character lists
```

### Baseline Comparison (`baseline_comparison.py`)
```python
def detect_baseline_deviations(df: pd.DataFrame, baseline_csv: str) -> pd.DataFrame:
    # Pure file integrity checking via hash comparison
    # SHA256 > SHA1 > MD5 priority
    # Location-based severity assessment
```

### Anomaly Detection (`anomaly_detection.py`)
```python
def detect_anomalies_pysad(df: pd.DataFrame, method: str = "hst", top_pct: float = 3.0) -> pd.DataFrame:
    # Feature engineering: length, entropy, path depth, signature status
    # PySAD model training and scoring
    # Returns top percentile only
```


## Performance Characteristics

- **Memory Usage**: Low overhead through direct processing
- **Execution Speed**: Typical analysis under 60 seconds
- **Scalability**: Handles hundreds to hundreds of thousands of entries
- **Error Recovery**: Graceful degradation with partial results

## Adding New Detectors

1. Create new detector file: `detectors/new_detector.py`
2. Implement detection function returning DataFrame
3. Add import to `detectors/__init__.py`  
4. Add function call to `run_all_detections()`
5. Update display names and descriptions

No complex registry registration required.

## Security Applications

- **Incident Response**: Rapid analysis of compromised systems
- **Threat Hunting**: Baseline comparison for environmental changes
- **System Validation**: Integrity verification against known-good configurations
- **Malware Analysis**: Statistical and behavioral analysis of persistence mechanisms

## Contributing

The simplified architecture makes contributions straightforward:
- Clear separation of concerns per detector
- Standard DataFrame input/output patterns
- Independent testing per detector module  
- No complex integration requirements

## Responsible Use
This tool is intended for legitimate security analysis only. 
Users are responsible for compliance with applicable laws and policies.