#!/usr/bin/env python3
"""
Clean Architecture Main - Each detector has a single, focused responsibility.
"""

import sys
import pandas as pd
from .core.utils import AutorunsFileCompat


def autoruns_to_dataframe(path: str) -> pd.DataFrame:
    """Convert Autoruns CSV/TSV to DataFrame with normalized columns."""
    af = AutorunsFileCompat(path)
    df = pd.DataFrame(af.rows, columns=af.headers)

    # Normalize common column variants
    cols_lower = {c.lower(): c for c in df.columns}

    def alias(existing: dict, names: list[str]) -> str | None:
        for n in names:
            if n in existing:
                return existing[n]
        return None

    mapping = {}
    img_col = alias(cols_lower, ["image path", "image", "path", "location", "command", "fullname"])
    if img_col and img_col != "Image Path":
        mapping[img_col] = "Image Path"

    if mapping:
        df.rename(columns=mapping, inplace=True)

    return df


def main(csv_path: str,
         out_xlsx: str = "autoruns_report.xlsx",
         top_pct: float = 3.0,
         baseline_csv: str | None = None,
         pysad_method: str = "hst"):
    """
    Clean Architecture Analysis - Single responsibility per detector.
    """
    print(f"[+] Starting Clean Architecture Autoruns Analysis...")
    print(f"[+] Input: {csv_path}")
    
    # Load data
    try:
        df = autoruns_to_dataframe(csv_path)
        print(f"[+] Loaded {len(df)} entries with {len(df.columns)} columns")
    except Exception as e:
        print(f"[!] Failed to load data: {e}")
        return
    
    # Initialize clean architecture detection
    try:
        from .detectors import run_autoruns_analysis
        results, registry, df_combined = run_autoruns_analysis(df, baseline_csv, pysad_method, top_pct)
        
        # Create combined analysis
        print(f"\n[+] Creating combined analysis...")
        df_combined = registry.get_combined_findings(df, results)
        
        # Optional: Meta-PySAD analysis
        df_meta_top = None
        try:
            from .core.pysad import run_meta_pysad_analysis
            print(f"[+] Running meta-statistical analysis...")
            df_meta_top, df_meta_all = run_meta_pysad_analysis(df, results, pysad_method, top_pct)
            results['meta_pysad'] = df_meta_top
            print(f"[+] Meta-analysis: {len(df_meta_top)} findings")
        except Exception as e:
            print(f"[!] Meta-analysis skipped: {e}")
        
        # Generate report
        print(f"\n[+] Generating clean architecture report...")
        from .reports.excel import write_modular_report
        write_modular_report(out_xlsx, df, results, registry, df_combined, 
                           top_pct, pysad_method, baseline_csv)
        
        # Print simple completion message
        print(f"[+] Analysis complete. Report saved: {out_xlsx}")
        
    except ImportError as e:
        print(f"[!] Clean architecture import failed: {e}")
        run_fallback_analysis(df, out_xlsx, top_pct, pysad_method)
    except Exception as e:
        print(f"[!] Clean architecture analysis failed: {e}")
        import traceback
        traceback.print_exc()
        run_fallback_analysis(df, out_xlsx, top_pct, pysad_method)


def run_fallback_analysis(df, out_xlsx, top_pct, pysad_method):
    """Simple fallback if clean architecture fails."""
    print(f"\n[+] Running simple fallback analysis...")
    
    results = {}
    
    # Basic unsigned detection
    try:
        if "Signer" in df.columns:
            signer_s = df["Signer"].astype("string")
            unsigned_mask = (
                signer_s.isna() | (signer_s == "") | (signer_s.str.strip() == "") |
                signer_s.str.contains(r"^\(not verified\)", case=False, regex=True, na=False)
            )
            df_unsigned = df.loc[unsigned_mask].copy()
            if len(df_unsigned) > 0:
                df_unsigned.insert(len(df_unsigned.columns), "detection_reason", "No valid digital signature")
                df_unsigned.insert(len(df_unsigned.columns), "detection_type", "Unsigned Binary")
            results['unsigned_binaries'] = df_unsigned
            print(f"[+] Unsigned binaries: {len(df_unsigned)}")
    except Exception as e:
        print(f"[!] Unsigned detection failed: {e}")
        results['unsigned_binaries'] = pd.DataFrame()
    
    # Basic anomaly detection
    try:
        from .core.pysad import build_features_for_pysad, pysad_scores
        import math
        
        features = build_features_for_pysad(df)
        scores = pysad_scores(features, method=pysad_method)
        
        k = max(1, int(math.ceil(len(df) * (top_pct / 100.0))))
        df_pysad = df.copy()
        df_pysad['pysad_score'] = scores
        df_pysad_top = df_pysad.nlargest(k, 'pysad_score')
        
        if len(df_pysad_top) > 0:
            df_pysad_top.insert(len(df_pysad_top.columns), "detection_reason", 
                               [f"Statistical anomaly (score: {score:.3f})" for score in df_pysad_top['pysad_score']])
            df_pysad_top.insert(len(df_pysad_top.columns), "detection_type", "Statistical Anomaly")
        
        results['anomaly_detection'] = df_pysad_top
        print(f"[+] Statistical anomalies: {len(df_pysad_top)}")
        
    except Exception as e:
        print(f"[!] Anomaly detection failed: {e}")
        results['anomaly_detection'] = pd.DataFrame()
    
    # Generate simple report
    try:
        from .reports.excel import ensure_xlsx
        out_xlsx = ensure_xlsx(out_xlsx)
        
        with pd.ExcelWriter(out_xlsx, engine="xlsxwriter") as writer:
            # Summary
            summary_data = []
            for name, result_df in results.items():
                count = len(result_df) if isinstance(result_df, pd.DataFrame) else 0
                summary_data.append([name.replace('_', ' ').title(), count])
            
            summary_df = pd.DataFrame(summary_data, columns=["Detection Type", "Findings"])
            summary_df.to_excel(writer, sheet_name="Summary", index=False)
            
            # Data sheets
            df.to_excel(writer, sheet_name="All_Rows", index=False)
            
            for name, result_df in results.items():
                if isinstance(result_df, pd.DataFrame) and len(result_df) > 0:
                    sheet_name = name.replace('_', ' ').title()[:31]
                    result_df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        print(f"[+] Fallback report saved: {out_xlsx}")
        
    except Exception as e:
        print(f"[!] Report generation failed: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m autorun_analyzer_dis <autoruns.csv> [out.xlsx] [top_pct] [baseline.csv] [pysad_method]")
        print("\nClean Architecture Autoruns Analyzer:")
        print("  Character Analysis: Visual masquerading, hidden characters")
        print("  Signature Analysis: Digital signature verification")
        print("  Location Analysis: Suspicious path intelligence") 
        print("  Integrity Analysis: File hash verification")
        print("  Meta-Statistical Analysis: PySAD anomaly detection")
        print("\nEach module has a single, focused responsibility!")
        sys.exit(1)
    
    csv_path = sys.argv[1]
    out = sys.argv[2] if len(sys.argv) >= 3 else "autoruns_report.xlsx"
    pct = float(sys.argv[3]) if len(sys.argv) >= 4 else 3.0
    base = sys.argv[4] if len(sys.argv) >= 5 else None
    method = sys.argv[5].lower() if len(sys.argv) >= 6 else "hst"
    
    if method not in ("hst", "loda"):
        print("[!] Unknown PySAD method, defaulting to 'hst'")
        method = "hst"
    
    main(csv_path, out, pct, base, method)