## Understanding Tool Output

### Actual Severity Levels Used

Your tool outputs three different severity systems depending on the detector:

**Unsigned Binaries Detector**:
- Critical: No signature, tampered signatures
- High: Invalid Microsoft formats, unverified signatures  
- Medium: Third-party signatures

**Suspicious Paths Detector**:
- Critical: Unknown files in system32/syswow64
- High: Unknown executables in Microsoft directories
- Medium-High: Unknown autorun entries
- Medium: Unknown executables in Program Files
- Low: Unknown files in temporary locations

**Anomaly Detection**:
- Numerical scores (0-1 range, higher = more anomalous)
- Typically shows top 3% as statistical outliers

**Other Detectors**: 
- Return findings without explicit severity rankings
- Presence of finding indicates suspicion level

### Excel Report Structure Analysis Priority

## Phase 1: Executive Overview

Start with the **Executive Summary** sheet to understand:
- Total entries analyzed and detection coverage
- Which detectors found issues and in what quantities
- Multi-detection analysis summary (items flagged by multiple detectors)

Key metrics to note:
- High concentration of unsigned binaries may indicate compromised system
- Suspicious paths with baseline comparison shows environmental deviations  
- Multiple detectors flagging same items increases confidence

## Phase 2: Multi-Detection Triage

Check the **Overlap Analysis** sheet for:
- Items detected by multiple different analysis types
- Cross-validation between detectors increases confidence
- Focus investigation on entries appearing in multiple detector results

Investigation priority order:
1. Items in 3+ detector results (highest confidence)
2. Items in 2 detector results with Critical/High severity
3. Single detector results with Critical severity

## Phase 3: Individual Detector Analysis

Review detector sheets in this priority order:

### 1. Unsigned Binaries Sheet
**Priority**: System files without valid signatures
- Filter by severity level: Critical first, then High
- Focus on executables in system directories (C:\Windows\System32\)
- Cross-reference with suspicious paths findings
- Note: Ultra-strict policy flags everything except "✓ (Verified) Microsoft Windows"

### 2. Suspicious Paths Sheet  
**Priority**: Baseline deviations in critical locations
- If baseline used: Focus on "Unknown Path" entries in system directories
- Check suspicion_level column: Critical and High first
- Pay attention to location_category for context
- Cross-reference with baseline comparison for integrity issues

### 3. Baseline Comparison Sheet (if baseline used)
**Priority**: File integrity violations  
- Focus on violation_severity: CRITICAL and HIGH first
- Look for hash mismatches in system files
- Note expected_hash vs actual_hash discrepancies
- System32 modifications are highest priority

### 4. Anomaly Detection Sheet
**Priority**: Statistical outliers with context
- Sort by pysad_score (highest first)
- Focus on scores above 0.8 for detailed analysis
- Consider context - some anomalies may be legitimate but unusual software
- Cross-reference high scores with other detector findings

### 5. Visual Masquerading Sheet
**Priority**: Filename spoofing attempts
- Review detection_reason for mixed character scripts
- Check script_count - higher numbers more suspicious
- Look for system process name mimicry (svchost, explorer, etc.)

### 6. Hidden Characters Sheet  
**Priority**: Evasion techniques
- Focus on Right-to-left override (filename spoofing)
- Review detection_reason for specific character issues
- Check cleaned_comparison to see what was hidden

## Investigation Methodology

### Evidence Collection Priorities

**Immediate Documentation**:
- File paths and hashes for all flagged executables
- Digital signature details and verification status
- File timestamps and metadata
- Detection reasons and severity levels from tool

**Contextual Information**:
- System purpose and expected software profile
- Recent changes or installations
- User activity patterns
- Network behavior of flagged processes

### Threat Assessment Framework

**High Confidence Indicators**:
- Multiple detectors flagging same item with Critical/High severity
- System files with integrity violations (hash mismatches)
- Unsigned executables in system32 with suspicious paths
- Mixed-script filenames mimicking system processes

**Moderate Confidence Indicators**:
- Single detector Critical findings
- Statistical anomalies above 0.9 with suspicious characteristics
- New files in system directories not in baseline
- Hidden characters in critical file paths

**Lower Confidence Areas**:
- Third-party software without signatures (if expected)
- Statistical anomalies with business justification
- New legitimate software not yet in baseline
- Single detector findings with Medium/Low severity

### False Positive Identification

**Common False Positives**:
- Recently installed legitimate software (check with IT/user)
- Development tools and administrative utilities
- Antivirus software components
- System updates not yet reflected in baseline

**Validation Steps**:
1. Verify file signatures against vendor websites
2. Check installation dates against system/user activity
3. Research unfamiliar software through threat intelligence
4. Validate findings with additional security tools

## Practical Investigation Workflow

### Initial Assessment Questions
- What is the system's role and expected software profile?
- When was the baseline created and is it current?  
- Have there been recent software installations or system changes?
- Are there known security incidents or suspicious activity reports?

### Documentation Requirements
- Complete list of flagged files with detection reasons
- File hashes and digital signature status
- Timeline of file creation/modification
- Cross-references between detector findings
- Business justification for any legitimate findings

### Escalation Criteria
- System files with integrity violations
- Multiple high-confidence malware indicators
- Evidence of ongoing compromise or persistence
- Files matching known threat intelligence indicators

## Tool-Specific Considerations

### Baseline Usage Impact
- **With Baseline**: Focus on environmental deviations and integrity violations
- **Without Baseline**: Rely more heavily on signature analysis and pattern detection
- Baseline quality directly affects false positive rates

### Statistical Analysis Interpretation  
- Anomaly scores are relative to the analyzed dataset
- Higher scores don't automatically mean malware
- Consider file context and business justification
- Use statistical findings to guide deeper analysis rather than as definitive indicators

### Signature Verification Limitations
- Ultra-strict policy may flag legitimate non-Microsoft software
- Consider business need for third-party applications
- Verify unsigned legitimate software through other means
- Focus signature analysis on system and security-critical files
