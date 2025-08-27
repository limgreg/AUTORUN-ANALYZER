# Core Detectors and Reports Documentation

This document provides detailed technical information about the simplified detection modules and reporting system used in the Autoruns Analyzer.

## Simplified Detection System Architecture

The detection system uses a clean, direct approach where each detector module focuses on a single responsibility. The complex DetectionRegistry has been replaced with simple function orchestration in `detectors/__init__.py`.

### Core Detection Philosophy

1. **Single Responsibility**: Each detector focuses on one specific threat vector
2. **No Functional Overlap**: Path analysis, signature verification, and character analysis are completely separate
3. **Direct Function Calls**: Simple orchestration replaces complex registry management
4. **Baseline Enhancement**: Detectors automatically improve when baseline data is available
5. **Clear Output**: Each detector returns a standard DataFrame with detection details

## Detection System Implementation

### Main Orchestration (`detectors/__init__.py`)

The system uses `run_all_detections()` which directly calls each detector:

```python
results['visual_masquerading'] = detect_visual_masquerading(df)
results['unsigned_binaries'] = detect_unsigned_binaries(df)
results['suspicious_paths'] = detect_suspicious_paths(df, baseline_csv)
# etc.
```

Key functions:
- `run_all_detections()`: Main orchestration with progress logging
- `get_combined_findings()`: Simple overlap analysis
- `create_detection_summary()`: Basic summary generation
- `SimpleRegistry`: Compatibility class for report generation

## Individual Detector Modules

### 1. Visual Masquerading Detector
**File**: `visual_masquerading.py`
**Responsibility**: Character Analysis

Detects Unicode characters that visually mimic legitimate filenames to deceive users and security tools.

**Detection Methods**:
- Homoglyph character detection (e.g., Cyrillic 'а' vs Latin 'a')
- Mixed script analysis (legitimate files rarely mix character sets)
- Suspicious Unicode ranges (mathematical symbols, box drawing)
- Right-to-left override character abuse

**Output Columns**:
- `detection_reason`: Specific Unicode issue identified
- `suspicious_chars`: Character codes and descriptions
- `severity_level`: Risk assessment (Low/Medium/High/Critical)

### 2. Unsigned Binaries Detector
**File**: `unsigned_binaries.py`
**Responsibility**: Signature Analysis

Identifies executables and libraries without valid digital signatures or with suspicious signing characteristics.

**Detection Methods**:
- Missing digital signatures
- Self-signed certificates
- Expired or revoked certificates
- Weak signature algorithms
- Unusual certificate authorities

**Output Columns**:
- `detection_reason`: Signature issue description
- `signature_status`: Detailed signature analysis
- `signer_info`: Certificate authority and validity

### 3. Suspicious Paths Detector
**File**: `suspicious_paths.py`
**Responsibility**: Location Analysis

Analyzes file paths for indicators of malicious placement or unusual system locations.

**Detection Methods**:
- Pattern-based suspicious location detection
- Temporary directory abuse detection
- User profile exploitation analysis
- System directory tampering
- Baseline deviation analysis (when baseline available)

**Baseline Enhancement**: When baseline data is provided, this detector compares current paths against known-good configurations, significantly improving detection accuracy.

**Output Columns**:
- `detection_reason`: Path-specific concern
- `path_category`: Classification of path type
- `baseline_status`: Present/Absent/Modified (when baseline used)

### 4. Hidden Characters Detector
**File**: `hidden_characters.py`
**Responsibility**: Character Encoding Analysis

Detects non-printable characters and encoding anomalies that may indicate evasion techniques.

**Detection Methods**:
- Non-printable ASCII character detection
- Unicode control character analysis
- Encoding consistency verification
- Null byte injection detection
- Invisible character identification

**Output Columns**:
- `detection_reason`: Encoding issue description
- `character_details`: Specific problematic characters
- `position_info`: Location of hidden characters

### 5. Baseline Comparison Detector
**File**: `baseline_comparison.py`
**Responsibility**: Integrity Analysis

Compares file hashes and metadata against known-good baseline systems to detect tampering or unauthorized changes.

**Requirements**: This detector only runs when baseline CSV data is provided.

**Detection Methods**:
- File hash comparison
- Size verification
- Timestamp analysis
- New file detection
- Modified file identification

**Output Columns**:
- `detection_reason`: Type of integrity violation
- `baseline_hash`: Expected file hash
- `current_hash`: Observed file hash
- `change_type`: Added/Modified/Suspicious

### 6. Anomaly Detection Detector
**File**: `anomaly_detection.py`
**Responsibility**: Meta-Statistical Analysis

Uses machine learning algorithms to identify statistical outliers across multiple dimensions of file characteristics.

**Algorithms Supported**:
- **HST (Half-Space Trees)**: Default method, fast and effective for high-dimensional data
- **LODA (Lightweight On-line Detector of Anomalies)**: Alternative method with different detection characteristics

**Feature Engineering**:
- Path length and complexity metrics
- File size distributions
- String entropy calculations
- Character frequency analysis
- Directory depth measurements

**Output Columns**:
- `anomaly_score`: Statistical anomaly ranking
- `feature_contributions`: Which characteristics drove the detection
- `percentile_rank`: Relative ranking among all files

## Report Generation System

### Excel Report Structure
**File**: `reports/excel.py`

The reporting system generates comprehensive Excel workbooks with multiple worksheets:

#### Summary Sheet
- Detection methodology overview
- Total findings by detector type
- Analysis parameters and configuration
- Execution metadata (runtime, file counts, etc.)

#### Combined Findings Sheet
- High-priority items flagged by multiple detectors
- Priority scoring based on detection count and severity
- Consolidated threat assessment
- Recommended investigation order

#### Individual Detector Sheets
- Separate worksheet for each detector's findings
- Complete detection details and reasoning
- Source data context for each finding
- Sortable and filterable columns

#### Raw Data Sheet
- Original autoruns data with enhanced metadata
- Detector flags and annotations
- Preserved for detailed forensic analysis

### Report Features

**Professional Formatting**:
- Freeze panes for easy navigation
- Conditional formatting for severity levels
- Automatic column width optimization
- Header formatting and protection

**Data Integrity**:
- All source data preserved
- Detection methodology documented
- Timestamps and analysis parameters recorded
- Reproducible analysis trail

**Export Compatibility**:
- Standard Excel format (.xlsx)
- Compatible with enterprise security tools
- Importable to SIEM systems
- CSV export capability maintained

## Technical Implementation Details

### Feature Engineering for Statistical Analysis
The system extracts multiple quantitative features from each autorun entry:

1. **Path Characteristics**:
   - Total path length
   - Directory depth
   - Character distribution
   - Special character frequency

2. **String Analysis**:
   - Entropy measurements
   - Language detection
   - Character set consistency
   - Unusual character patterns

3. **Size Metrics**:
   - File size distributions
   - Size-to-path ratios
   - Outlier identification

4. **Temporal Features**:
   - Timestamp analysis
   - Age calculations
   - Modification patterns

### Performance Characteristics

**Memory Efficiency**:
- Streaming processing for large datasets
- Minimal memory footprint per detector
- Garbage collection optimization

**Processing Speed**:
- Parallel processing where applicable
- Optimized pandas operations
- Efficient regex compilation

**Scalability**:
- Linear time complexity for most detectors
- Handles datasets from hundreds to hundreds of thousands of entries
- Memory usage scales appropriately with data size

## Configuration and Customization

### Detection Sensitivity
Most detectors support adjustable sensitivity levels through configuration parameters:
- Threshold adjustment for anomaly scores
- Pattern matching strictness
- Baseline comparison tolerances

### Adding New Detectors
The clean architecture enables easy extension:

1. Create new detector file following the established pattern
2. Implement single responsibility detection logic
3. Return standardized DataFrame with required columns
4. Register in `detection_system.py`
5. Add to report generation pipeline

### Baseline Integration
Detectors that benefit from baseline data should:
- Function independently without baseline
- Enhance accuracy when baseline is available
- Document baseline requirements clearly
- Handle missing baseline gracefully

## Quality Assurance

### Testing Strategy
- Unit tests for each detector module
- Integration tests for combined analysis
- Performance benchmarking
- False positive rate measurement

### Error Handling
- Graceful degradation when detectors fail
- Comprehensive error logging
- Partial result preservation
- User-friendly error messages

### Validation
- Known malware sample testing
- Clean system baseline validation
- Cross-platform compatibility verification
- Large dataset stress testing