"""
Excel report generation functionality.
"""

import os
import datetime as dt
import pandas as pd


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


def write_report(out_path: str,
                 df_src: pd.DataFrame,
                 df_all: pd.DataFrame,
                 df_rules: pd.DataFrame,
                 df_pysad_all: pd.DataFrame | None,
                 df_pysad_top: pd.DataFrame | None,
                 df_baseline: pd.DataFrame | None,
                 df_unsigned: pd.DataFrame | None,
                 top_pct: float,
                 pysad_method: str):
    """
    Generate comprehensive Excel report with multiple worksheets.
    
    Args:
        out_path: Output Excel file path
        df_src: Source DataFrame (for metrics)
        df_all: All rows DataFrame
        df_rules: Rules flagged DataFrame
        df_pysad_all: PySAD scored DataFrame (optional)
        df_pysad_top: Top PySAD scores DataFrame (optional)
        df_baseline: Baseline findings DataFrame (optional)
        df_unsigned: Unsigned items DataFrame (optional)
        top_pct: Percentage for top PySAD scores
        pysad_method: PySAD method used
    """
    out_path = ensure_xlsx(out_path)
    
    with pd.ExcelWriter(out_path, engine="xlsxwriter") as writer:
        wb = writer.book
        
        # Generate summary sheet
        summary = pd.DataFrame({
            "Metric": [
                "Rows scanned",
                "Columns",
                "Rules flagged",
                (f"PySAD top {top_pct}%" if df_pysad_top is not None else "PySAD (skipped)"),
                "Baseline findings",
                "Unsigned items",
                "PySAD method",
                "Generated at",
            ],
            "Value": [
                len(df_src),
                ", ".join(df_src.columns.astype(str).tolist()),
                len(df_rules),
                (0 if df_pysad_top is None else len(df_pysad_top)),
                (0 if df_baseline is None else len(df_baseline)),
                (0 if df_unsigned is None else len(df_unsigned)),
                (pysad_method if df_pysad_top is not None else "-"),
                dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ],
        })
        summary.to_excel(writer, sheet_name="Summary", index=False)
        autosize_worksheet(writer.sheets["Summary"], summary, wb)

        # All rows sheet
        df_all.to_excel(writer, sheet_name="AllRows", index=False)
        autosize_worksheet(writer.sheets["AllRows"], df_all, wb)

        # Rules flagged sheet
        df_rules.to_excel(writer, sheet_name="Rules_Flagged", index=False)
        autosize_worksheet(writer.sheets["Rules_Flagged"], df_rules, wb)

        # PySAD sheets (only if available)
        if df_pysad_all is not None:
            df_pysad_all.to_excel(writer, sheet_name="PySAD_Scored", index=False)
            autosize_worksheet(writer.sheets["PySAD_Scored"], df_pysad_all, wb)
        
        if df_pysad_top is not None:
            df_pysad_top.to_excel(writer, sheet_name="PySAD_TopN", index=False)
            autosize_worksheet(writer.sheets["PySAD_TopN"], df_pysad_top, wb)

        # Baseline findings sheet
        if df_baseline is not None and len(df_baseline) > 0:
            df_baseline.to_excel(writer, sheet_name="Baseline_Findings", index=False)
            autosize_worksheet(writer.sheets["Baseline_Findings"], df_baseline, wb)
        
        # Unsigned items sheet
        if df_unsigned is not None and len(df_unsigned) > 0:
            df_unsigned.to_excel(writer, sheet_name="Unsigned_Items", index=False)
            autosize_worksheet(writer.sheets["Unsigned_Items"], df_unsigned, wb)

    print(f"[+] Excel report written to: {out_path}")