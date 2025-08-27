"""
Excel report generation for modular detection system.
"""

import os
import datetime as dt
import pandas as pd
from typing import Dict


def ensure_xlsx(path: str) -> str:
    """Ensure output path has Excel extension."""
    lower = path.lower()
    if lower.endswith(".xlsx") or lower.endswith(".xlsm"):
        return path
    base, _ = os.path.splitext(path)
    fixed = base + ".xlsx"
    print(f"[!] Output file '{path}' is not an Excel file; writing to '{fixed}' instead.")
    return fixed


def autosize_worksheet(ws, df, wb):
    """Auto-size worksheet columns and apply formatting."""
    if len(df) == 0:
        return
        
    # Create format objects
    wrap_fmt = wb.add_format({"text_wrap": True, "valign": "top"})
    num_fmt = wb.add_format({"num_format": "0.000", "valign": "top"})
    int_fmt = wb.add_format({"num_format": "0", "valign": "top"})
    max_width, min_width = 100, 10

    # Calculate optimal column widths
    col_widths = []
    for j, col in enumerate(df.columns):
        w = len(str(col))
        sample = df[col].astype(str).values
        for s in sample[:200]:  # Sample first 200 rows for performance
            if s is None:
                continue
            s = s.replace("\r", "")
            w = max(w, max((len(line) for line in s.split("\n")), default=0))
        w = max(min_width, min(max_width, w))
        col_widths.append(w)

    # Apply column formatting based on data type
    for j, col in enumerate(df.columns):
        ser = df[col]
        if pd.api.types.is_numeric_dtype(ser):
            if pd.api.types.is_integer_dtype(ser):
                ws.set_column(j, j, max(12, min(18, col_widths[j])), int_fmt)
            else:
                ws.set_column(j, j, max(12, min(18, col_widths[j])), num_fmt)
        else:
            ws.set_column(j, j, col_widths[j], wrap_fmt)

    # Add freeze panes and autofilter
    ws.freeze_panes(1, 0)
    ws.autofilter(0, 0, max(len(df), 1), max(len(df.columns) - 1, 0))


def write_modular_report(out_path: str,
                        df_src: pd.DataFrame,
                        results: Dict[str, pd.DataFrame],
                        registry,
                        df_combined: pd.DataFrame,
                        top_pct: float,
                        pysad_method: str,
                        baseline_csv: str = None):
    """
    Generate comprehensive Excel report for modular detection system.
    
    Args:
        out_path: Output Excel file path
        df_src: Source DataFrame
        results: Dictionary of detection results
        registry: DetectionRegistry instance
        df_combined: Combined high-priority findings
        top_pct: PySAD percentage threshold
        pysad_method: PySAD method used
        baseline_csv: Baseline CSV path
    """
    out_path = ensure_xlsx(out_path)
    
    # Calculate summary statistics
    total_rows = len(df_src)
    detection_counts = {}
    for name, result_df in results.items():
        if isinstance(result_df, pd.DataFrame):
            detection_counts[name] = len(result_df)
        else:
            detection_counts[name] = 0
    
    with pd.ExcelWriter(out_path, engine="xlsxwriter") as writer:
        wb = writer.book
        
        # 1. EXECUTIVE SUMMARY SHEET
        create_executive_summary(writer, wb, df_src, detection_counts, df_combined, 
                               top_pct, pysad_method, baseline_csv)
        
        # 2. DETECTION SUMMARY SHEET
        summary_df = registry.get_summary()
        summary_df.to_excel(writer, sheet_name="Detection_Summary", index=False)
        autosize_worksheet(writer.sheets["Detection_Summary"], summary_df, wb)
        
        # 3. OVERLAP ANALYSIS
        create_overlap_analysis(writer, wb, df_src, results)
        
        # 4. ENHANCED PYSAD (if available)
        if 'enhanced_pysad' in results and isinstance(results['enhanced_pysad'], pd.DataFrame) and len(results['enhanced_pysad']) > 0:
            results['enhanced_pysad'].to_excel(writer, sheet_name="Enhanced_PySAD", index=False)
            autosize_worksheet(writer.sheets["Enhanced_PySAD"], results['enhanced_pysad'], wb)
        
        # 5. INDIVIDUAL DETECTION SHEETS
        detector_order = [
            'unsigned_binaries',
            'suspicious_paths', 
            'baseline_comparison',
            'visual_masquerading',
            'hidden_characters',
            'anomaly_detection'
        ]
        
        for detector_name in detector_order:
            if detector_name in results:
                df_results = results[detector_name]
                if isinstance(df_results, pd.DataFrame) and len(df_results) > 0:
                    sheet_name_map = {
                        'unsigned_binaries': 'Unsigned_Binaries',
                        'suspicious_paths': 'Suspicious_Paths',
                        'baseline_comparison': 'Baseline_Comparison', 
                        'visual_masquerading': 'Visual_Masquerading',
                        'hidden_characters': 'Hidden_Characters',
                        'anomaly_detection': 'Anomaly_Detection'
                    }
                    
                    sheet_name = sheet_name_map.get(detector_name, detector_name.replace('_', ' ').title())
                    sheet_name = sheet_name[:31]  # Excel sheet name limit
                    
                    df_results.to_excel(writer, sheet_name=sheet_name, index=False)
                    autosize_worksheet(writer.sheets[sheet_name], df_results, wb)
        
        # 6. ALL ROWS (for reference)
        df_src.to_excel(writer, sheet_name="All_Rows", index=False)
        autosize_worksheet(writer.sheets["All_Rows"], df_src, wb)

    print(f"[+] Excel report written to: {out_path}")


def create_executive_summary(writer, wb, df_src, detection_counts, df_combined, 
                           top_pct, pysad_method, baseline_csv):
    """Create executive summary sheet with key metrics."""
    
    total_rows = len(df_src)
    
    # Create summary data
    summary_data = []
    
    # Basic metrics
    summary_data.append(["SCAN OVERVIEW", ""])
    summary_data.append(["Total entries scanned", f"{total_rows:,}"])
    summary_data.append(["Columns analyzed", f"{len(df_src.columns)}"])
    summary_data.append(["Scan timestamp", dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    summary_data.append(["", ""])
    
    # Detection results
    summary_data.append(["DETECTION RESULTS", ""])
    
    detector_order = [
        'unsigned_binaries',
        'suspicious_paths',
        'baseline_comparison', 
        'visual_masquerading',
        'hidden_characters',
        'anomaly_detection'
    ]
    
    display_names = {
        'unsigned_binaries': 'Unsigned Binaries',
        'suspicious_paths': 'Suspicious Paths',
        'baseline_comparison': 'Baseline Comparison',
        'visual_masquerading': 'Visual Masquerading', 
        'hidden_characters': 'Hidden Characters',
        'anomaly_detection': 'Anomaly Detection'
    }
    
    for detector_name in detector_order:
        if detector_name in detection_counts:
            count = detection_counts[detector_name]
            display_name = display_names.get(detector_name, detector_name.replace('_', ' ').title())
            percentage = (count / total_rows * 100) if total_rows > 0 else 0
            summary_data.append([display_name, f"{count:,}/{total_rows:,} ({percentage:.1f}%)"])
    
    # Add other detectors
    for detector_name, count in detection_counts.items():
        if detector_name not in detector_order:
            display_name = detector_name.replace('_', ' ').title()
            percentage = (count / total_rows * 100) if total_rows > 0 else 0
            summary_data.append([display_name, f"{count:,}/{total_rows:,} ({percentage:.1f}%)"])
    
    # Combined findings info
    summary_data.append(["", ""])
    summary_data.append(["MULTI-DETECTION ANALYSIS", ""])
    summary_data.append(["Items flagged by multiple detectors", f"{len(df_combined):,}"])
    
    if len(df_combined) > 0:
        summary_data.append(["", ""])
        summary_data.append(["TOP MULTI-DETECTION FINDINGS", ""])
        
        for i, (idx, row) in enumerate(df_combined.head(3).iterrows()):
            detection_modules = row.get('detection_modules', 'Unknown')
            severity = row.get('max_severity', 'Unknown')
            path = row.get('Image Path', row.get('Path', 'Unknown'))
            priority = row.get('priority_score', 0)
            
            # Truncate path if too long
            if len(path) > 50:
                path = path[:47] + "..."
            
            summary_data.append([f"#{i+1} [{severity}] {detection_modules}", f"Score: {priority}"])
            summary_data.append([f"   Path", path])
    
    # Configuration
    summary_data.append(["", ""])
    summary_data.append(["CONFIGURATION", ""])
    summary_data.append(["PySAD Method", pysad_method])
    summary_data.append(["PySAD Top Percentile", f"{top_pct}%"])
    summary_data.append(["Baseline Used", "Yes" if baseline_csv else "No"])
    if baseline_csv:
        summary_data.append(["Baseline File", os.path.basename(baseline_csv)])
    
    # Risk assessment
    summary_data.append(["", ""])
    summary_data.append(["RISK ASSESSMENT", ""])
    
    high_risk = detection_counts.get('visual_masquerading', 0) + len(df_combined)
    medium_risk = detection_counts.get('unsigned_binaries', 0) + detection_counts.get('suspicious_paths', 0)
    low_risk = detection_counts.get('hidden_characters', 0) + detection_counts.get('anomaly_detection', 0)
    
    summary_data.append(["High Risk Items", f"{high_risk:,}"])
    summary_data.append(["Medium Risk Items", f"{medium_risk:,}"])
    summary_data.append(["Low Risk Items", f"{low_risk:,}"])
    
    # Create DataFrame and write to Excel
    summary_df = pd.DataFrame(summary_data, columns=["Metric", "Value"])
    summary_df.to_excel(writer, sheet_name="Executive_Summary", index=False)
    
    # Format the summary sheet
    ws = writer.sheets["Executive_Summary"]
    
    # Create formats
    header_fmt = wb.add_format({
        'bold': True, 
        'font_size': 12,
        'bg_color': '#D7E4BC',
        'border': 1
    })
    
    section_fmt = wb.add_format({
        'bold': True,
        'font_size': 11,
        'bg_color': '#F2F2F2'
    })
    
    # Apply formatting
    ws.set_column('A:A', 30)
    ws.set_column('B:B', 25)
    
    # Color code sections
    for i, (metric, value) in enumerate(summary_data):
        if metric in ["SCAN OVERVIEW", "DETECTION RESULTS", "MULTI-DETECTION ANALYSIS", 
                     "TOP MULTI-DETECTION FINDINGS", "CONFIGURATION", "RISK ASSESSMENT"]:
            ws.set_row(i + 1, None, section_fmt)


def create_overlap_analysis(writer, wb, df_src, results):
    """Create overlap analysis showing items detected by multiple methods."""
    
    # Get indices for each detector
    detector_indices = {}
    for detector_name, df_results in results.items():
        if isinstance(df_results, pd.DataFrame) and len(df_results) > 0:
            detector_indices[detector_name] = set(df_results.index)
    
    overlap_data = []
    
    # Calculate pairwise overlaps
    detector_names = list(detector_indices.keys())
    for i, detector1 in enumerate(detector_names):
        for j, detector2 in enumerate(detector_names):
            if i < j:  # Avoid duplicates
                overlap = detector_indices[detector1] & detector_indices[detector2]
                if len(overlap) > 0:
                    name1 = detector1.replace('_', ' ').title()
                    name2 = detector2.replace('_', ' ').title()
                    overlap_data.append({
                        'Detector 1': name1,
                        'Detector 2': name2,
                        'Overlap Count': len(overlap),
                        'Percentage': f"{len(overlap) / len(df_src) * 100:.2f}%"
                    })
    
    # Calculate items detected by multiple methods
    multi_detection_counts = {}
    for idx in df_src.index:
        detection_count = sum(1 for indices in detector_indices.values() if idx in indices)
        if detection_count > 1:
            multi_detection_counts[detection_count] = multi_detection_counts.get(detection_count, 0) + 1
    
    # Add multi-detection summary
    for count, items in multi_detection_counts.items():
        overlap_data.append({
            'Detector 1': f'Items detected by {count} methods',
            'Detector 2': '',
            'Overlap Count': items,
            'Percentage': f"{items / len(df_src) * 100:.2f}%"
        })
    
    if overlap_data:
        overlap_df = pd.DataFrame(overlap_data)
        overlap_df.to_excel(writer, sheet_name="Overlap_Analysis", index=False)
        autosize_worksheet(writer.sheets["Overlap_Analysis"], overlap_df, wb)