#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main entry point for Autoruns analyzer - PROPER MODULAR VERSION.
This is what you actually want - clean modular architecture.
"""

import sys
import pandas as pd

from .core.utils import AutorunsFileCompat


def autoruns_to_dataframe(path: str) -> pd.DataFrame:
    """Convert Autoruns CSV/TSV to DataFrame with normalized columns."""
    af = AutorunsFileCompat(path)
    df = pd.DataFrame(af.rows, columns=af.headers)

    # Normalize a few common column name variants
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
    Main analysis function using the MODULAR detection system.
    
    Args:
        csv_path: Path to Autoruns CSV/TSV export
        out_xlsx: Output Excel report path
        top_pct: Percentage of top PySAD scores to include
        baseline_csv: Optional baseline CSV for comparison
        pysad_method: PySAD method ('hst' or 'loda')
    """
    print(f"[+] Starting Modular Autoruns Analysis...")
    print(f"[+] Input file: {csv_path}")
    
    # Load Autoruns data
    try:
        df = autoruns_to_dataframe(csv_path)
        print(f"[+] Loaded {len(df)} rows with {len(df.columns)} columns")
    except Exception as e:
        print(f"[!] Failed to load data: {e}")
        return
    
    # Initialize modular detection system
    try:
        from .detectors import DetectionRegistry
        print(f"[+] Initializing modular detection system...")
        
        registry = DetectionRegistry()
        
        # Enable baseline comparison if provided
        if baseline_csv:
            print(f"[+] Baseline comparison enabled: {baseline_csv}")
            registry.enable('baseline_comparison')
        else:
            registry.disable('baseline_comparison')
        
        # Run all detections using the modular system
        print(f"[+] Running all detection modules...")
        results = registry.run_all(df, 
                                  baseline_csv=baseline_csv,
                                  pysad_method=pysad_method,
                                  top_pct=top_pct)
        
        # Create combined high-priority findings
        print(f"[+] Creating combined priority analysis...")
        df_combined = registry.get_combined_findings(df, results)
        
        # Optional: Run meta-PySAD (your brilliant idea!)
        df_meta_top = None
        try:
            from .core.pysad import run_meta_pysad_analysis
            print(f"[+] Running meta-PySAD analysis...")
            df_meta_top, df_meta_all = run_meta_pysad_analysis(df, results, pysad_method, top_pct)
            results['meta_pysad'] = df_meta_top
            print(f"[+] Meta-PySAD complete: {len(df_meta_top)} findings")
        except Exception as e:
            print(f"[!] Meta-PySAD skipped: {e}")
        
        # Generate comprehensive modular report
        print(f"[+] Generating modular Excel report...")
        from .reports.excel import write_modular_report
        write_modular_report(out_xlsx, df, results, registry, df_combined, 
                           top_pct, pysad_method, baseline_csv)
        
        # Print modular summary
        print(f"\n{'='*60}")
        print(f"MODULAR ANALYSIS SUMMARY")
        print(f"{'='*60}")
        print(f"Total rows scanned: {len(df)}")
        
        total_findings = 0
        for name, result_df in results.items():
            if isinstance(result_df, pd.DataFrame):
                count = len(result_df)
                total_findings += count
                detector_name = name.replace('_', ' ').title()
                if name == 'meta_pysad':
                    print(f"🔥 {detector_name}: {count} (meta-detection using ALL modules)")
                else:
                    print(f"   {detector_name}: {count} findings")
        
        if len(df_combined) > 0:
            print(f"\n🎯 HIGH-PRIORITY COMBINED: {len(df_combined)} findings")
            print(f"   (Items flagged by multiple detection modules)")
            
            # Show top 3 combined findings
            if len(df_combined) > 0:
                print(f"\n   Top 3 High-Priority Items:")
                for i, (idx, row) in enumerate(df_combined.head(3).iterrows()):
                    methods = row.get('detection_methods', 'Unknown')
                    path = row.get('Image Path', row.get('Path', 'Unknown'))
                    print(f"   {i+1}. {methods}")
                    print(f"      → {path}")
        
        unique_flagged = len(set().union(*[set(df.index) for df in results.values() 
                                         if isinstance(df, pd.DataFrame) and len(df) > 0]))
        print(f"\nUnique entries flagged: {unique_flagged}/{len(df)} ({unique_flagged/len(df)*100:.1f}%)")
        print(f"Report saved to: {out_xlsx}")
        print(f"{'='*60}")
        
    except ImportError as e:
        print(f"[!] Modular detection system import failed: {e}")
        print(f"[!] Falling back to simple analysis...")
        
        # Fallback to simple analysis if modular system not available
        run_simple_fallback_analysis(df, out_xlsx, top_pct, pysad_method)


def run_simple_fallback_analysis(df, out_xlsx, top_pct, pysad_method):
    """
    Fallback to simple analysis if modular system imports fail.
    This is temporary until we fix the modular imports.
    """
    print(f"[+] Running fallback analysis...")
    
    results = {}
    
    # Simple unsigned detection
    try:
        if "Signer" in df.columns:
            signer_s = df["Signer"].astype("string")
            unsigned_mask = (
                signer_s.isna() | (signer_s == "") | (signer_s.str.strip() == "") |
                signer_s.str.contains(r"^\(not verified\)", case=False, regex=True, na=False) |
                (signer_s.str.lower() == "microsoft windows publisher") |
                (signer_s.str.lower() == "n/a") | (signer_s.str.lower() == "unknown") |
                (signer_s.str.lower() == "unsigned") | (signer_s.str.lower() == "not verified")
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
    
    # Simple PySAD
    try:
        from .core.pysad import build_features_for_pysad, pysad_scores
        import math
        
        features = build_features_for_pysad(df)
        scores = pysad_scores(features, method=pysad_method)
        
        df_pysad = df.copy()
        df_pysad['pysad_score'] = scores
        
        k = max(1, int(math.ceil(len(df_pysad) * (top_pct / 100.0))))
        df_pysad_top = df_pysad.nlargest(k, 'pysad_score')
        
        if len(df_pysad_top) > 0:
            df_pysad_top.insert(len(df_pysad_top.columns), "detection_reason", 
                               [f"Statistical anomaly (score: {score})" for score in df_pysad_top['pysad_score']])
            df_pysad_top.insert(len(df_pysad_top.columns), "detection_type", "Statistical Anomaly")
        
        results['anomaly_detection'] = df_pysad_top
        print(f"[+] PySAD anomalies: {len(df_pysad_top)}")
        
    except Exception as e:
        print(f"[!] PySAD analysis failed: {e}")
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
            
            # All rows
            df.to_excel(writer, sheet_name="All_Rows", index=False)
            
            # Individual results
            for name, result_df in results.items():
                if isinstance(result_df, pd.DataFrame) and len(result_df) > 0:
                    sheet_name = name.replace('_', ' ').title()[:31]
                    result_df.to_excel(writer, sheet_name=sheet_name, index=False)
        
        print(f"[+] Fallback report saved to: {out_xlsx}")
        
    except Exception as e:
        print(f"[!] Report generation failed: {e}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m autorun_analyzer_dis <autoruns.csv> [out.xlsx] [top_pct] [baseline.csv] [pysad_method]")
        print("\nModular Autoruns Analyzer:")
        print("  🔍 Visual Masquerading Detection")
        print("  📝 Unsigned Binary Detection") 
        print("  📂 Suspicious Path Detection")
        print("  👻 Hidden Character Detection")
        print("  📊 Baseline Comparison")
        print("  🤖 PySAD Anomaly Detection")
        print("  🔥 Meta-PySAD (combines all detectors)")
        print("  🎯 Combined Priority Analysis")
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