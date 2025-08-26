# 🔍 Autoruns Analyzer User Guide

## Quick Start

The Autoruns Analyzer is a clean architecture detection system that analyzes Windows Autoruns data for security threats and anomalies.

### 📁 Folder Structure Setup

Before running, organize your files in these folders:

```
SIT-DIS-VA/
├── csv/                    # Place your Autoruns CSV files here
├── baseline/               # Place your baseline CSV files here
│   ├── Windows10/
│   ├── W8.1_Pro_9600/
│   └── WindowsServer/
├── output/                 # Analysis reports will be saved here
├── autorun_analyzer_dis/   # Main package (don't modify)
├── requirements.txt
└── run_analyzer.py         # Main runner script
```

### 🚀 Basic Usage

1. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

2. **Place your files:**
   - Drop Autoruns CSV files in `csv/` folder
   - Drop baseline CSV files in `baseline/` folder (organized by Windows version)

3. **Run the analyzer:**
   ```bash
   python run_analyzer.py
   ```

4. **Follow the interactive prompts** to select files and configure analysis

---

## 📊 Analysis Components

The analyzer uses a **Clean Architecture** approach with single-responsibility modules:

### 🏗️ Detection Modules

| Module | Responsibility | What it Detects |
|--------|---------------|-----------------|
| **Character Analysis** | Visual masquerading | Mixed Unicode scripts (Latin + Greek/Cyrillic) |
| **Signature Analysis** | Digital signatures | Only trusts "✓ (Verified) Microsoft Windows" |
| **Location Analysis** | File paths | Suspicious locations, unauthorized directories |
| **Character Encoding** | Hidden characters | Zero-width chars, Unicode manipulation |
| **Integrity Analysis** | File verification | Hash mismatches vs baseline (baseline required) |
| **Meta-Statistical** | Anomaly detection | PySAD statistical analysis |

### 🔒 Ultra-Strict Signature Policy

**ONLY TRUSTED:**
- `✓ (Verified) Microsoft Windows`

**FLAGGED AS SUSPICIOUS:**
- Missing signatures
- Unverified signatures  
- Third-party signatures (Adobe, Google, etc.)
- Modified/tampered signatures
- Any other variation

---

## 🎛️ Interactive Usage Guide

### Step 1: CSV File Selection

**For small collections (≤10 files):**
```
🔍 Select Autoruns CSV file:
📁 Directory: csv/

📋 Available CSV files:
#   Filename                    Size    Modified
--- ---------------------------------- -------- ------------
1   rd03.shieldbase.com         2.1MB    12/15/2024
2   server02.domain.com         1.8MB    12/14/2024

📌 Select file (1-2): 1
```

**For large collections (>10 files):**
```
🔍 Found 47 CSV file(s)
🔍 Search interface (type to filter, Enter to see all)
Search: shieldbase

📋 CSV files matching 'shieldbase' (3 found):
#   Filename                    Size    Modified  
--- ---------------------------------- -------- ------------
1   rd03.shieldbase.com         2.1MB    12/15/2024
2   rd02.shieldbase.com         2.0MB    12/14/2024

📌 Select file (1-2, s to search again): 1
```

### Step 2: Baseline Selection (Optional)

Baseline files are organized in subfolders by Windows version:

```
📋 Select baseline CSV file (optional):
📁 Directory: baseline/ (searching subfolders for CSV files only)

🔍 Found 12 CSV files in baseline subfolders
📋 (Automatically ignoring README.md and .txt files)

Search interface (type Windows version, build, or filename)
💡 Examples: 'W10', '22H2', 'Pro_9600', 'Windows11'
Search: W8.1

📋 CSV files matching 'W8.1' (2 found):
#   Folder/Filename                           Size    Date
--- --------------------------------------------- -------- ----------
1   W8.1_Pro_9600/W8.1_Pro_9600               1.8MB    12/15/24
2   Windows8/W8.1_Enterprise_Build9600        2.1MB    12/14/24

📌 Select file (1-2): 1
✅ Selected: W8.1_Pro_9600/W8.1_Pro_9600.csv
```

### Step 3: Output Configuration

```
📊 Output filename (without .xlsx extension)
💡 Suggestion: autoruns_analysis_20241215_143022
Enter filename (or press Enter for suggestion): my_security_scan
✅ Output: output/my_security_scan.xlsx
```

### Step 4: Analysis Parameters

```
🎛️  ANALYSIS PARAMETERS
🔍 PySAD Method (hst/loda, default: hst): [Enter for default]
📊 Top percentage (default: 3.0): 5.0
✅ Configuration: HST method, top 5.0%
```

### Step 5: Final Confirmation

```
🚀 READY TO ANALYZE
📁 CSV:          rd03.shieldbase.com.csv
📋 Baseline:     W8.1_Pro_9600/W8.1_Pro_9600.csv
📊 Output:       my_security_scan.xlsx
🎯 Method:       HST
📈 Percentage:   5.0%

▶️  Start analysis? (Y/n): y
```

---

## 📊 Understanding the Results

### Excel Report Structure

The generated Excel report contains these tabs (in order):

1. **Executive_Summary** - High-level overview and key metrics
2. **Detection_Summary** - Summary of all detection modules
3. **Overlap_Analysis** - Items detected by multiple modules
4. **Meta_PySAD** - Statistical anomaly analysis (if available)
5. **Unsigned_Binaries** - Files without valid Microsoft signatures
6. **Suspicious_Paths** - Files in suspicious locations
7. **Baseline_Comparison** - File integrity violations (if baseline used)
8. **Visual_Masquerading** - Mixed Unicode script attacks
9. **Hidden_Characters** - Files with hidden/non-printable characters
10. **Anomaly_Detection** - Pure statistical anomalies
11. **All_Rows** - Complete dataset for reference

### Key Columns to Review

**Priority Columns:**
- `detection_reason` - Why this item was flagged
- `detection_type` - What type of threat
- `severity_level` - Risk assessment (Critical/High/Medium/Low)

**Analysis Columns:**
- `flagged_by_detectors` - Which modules detected this item
- `detection_count` - How many modules flagged it
- `meta_pysad_score` - Statistical anomaly score (0-1)

### Severity Levels

| Level | Description | Examples |
|-------|-------------|----------|
| **Critical** | Immediate attention required | No signature, tampered files |
| **High** | Likely threats | Unverified signatures, system directory violations |
| **Medium-High** | Suspicious activity | Non-Microsoft components, unusual paths |
| **Medium** | Worth investigating | Third-party software in autorun |
| **Low** | Minor anomalies | Statistical outliers, encoding issues |

---

## 🎯 Best Practices

### File Organization

1. **CSV Files:** Use descriptive names like `hostname-date-autoruns.csv`
2. **Baselines:** Organize by Windows version/build for easy selection
3. **Outputs:** Use descriptive names with timestamps

### Analysis Tips

1. **Use Baselines:** Always use a baseline when possible for better accuracy
2. **Start with High Severity:** Focus on Critical/High findings first
3. **Multi-Detection Items:** Pay special attention to items flagged by multiple modules
4. **Context Matters:** Consider the environment (domain vs standalone)

### Workflow Recommendations

1. **Initial Scan:** Run without baseline for broad overview
2. **Targeted Analysis:** Re-run with appropriate baseline for detailed analysis
3. **Compare Results:** Look for items that appear across multiple systems
4. **Document Findings:** Use Excel comments to track investigation notes

---

## 🛠️ Troubleshooting

### Common Issues

**"No CSV files found"**
- Ensure files are in the correct folder (`csv/` or `baseline/`)
- Check file extensions (must be `.csv`)
- Verify file permissions

**"Analysis failed"**
- Check that the CSV file is valid Autoruns output
- Ensure sufficient disk space in `output/` folder
- Verify all dependencies are installed

**"Baseline not working"**
- Ensure baseline file has hash columns (SHA256, SHA1, or MD5)
- Check that baseline file is from compatible Autoruns version
- Verify baseline file isn't corrupted

### Performance Tips

- **Large Files:** Use higher PySAD percentages (5-10%) to reduce processing time
- **Many Baselines:** Use search function to quickly find relevant baseline
- **Disk Space:** Clean old reports from `output/` folder periodically

---

## 🔧 Advanced Configuration

### PySAD Methods

- **HST (HalfSpaceTrees):** Default, fast, good for most cases
- **LODA:** Alternative method, may catch different patterns

### Custom Workflows

For batch processing or automation, you can directly call:
```bash
python -m autorun_analyzer_dis.main input.csv output.xlsx 3.0 baseline.csv hst
```

---

## 🆘 Support

### Getting Help

1. **Check this guide** for common questions
2. **Verify file formats** - ensure proper Autoruns CSV export
3. **Test with smaller files** if having performance issues
4. **Check dependencies** with `pip list`

### Expected File Formats

**Autoruns CSV Requirements:**
- Must contain "Signer" column for signature analysis
- Should contain "Image Path" or similar path column
- Must be proper CSV format (comma or tab separated)

**Baseline CSV Requirements:**
- Must contain path column (Path, FullName, Image Path, etc.)
- Should contain hash columns (SHA256, SHA1, or MD5)
- Compatible with Autoruns output format

---

## 🔄 Updates and Maintenance

### Keeping Baselines Current

- Update baselines when Windows updates are installed
- Maintain separate baselines for different OS versions/builds
- Document baseline creation dates and system configurations

### Report Management

- Archive old reports periodically
- Use consistent naming conventions
- Consider automated backup of critical findings

---

*This tool implements a Clean Architecture approach where each detection module has a single, focused responsibility. This ensures reliable, maintainable security analysis with minimal false positives.*