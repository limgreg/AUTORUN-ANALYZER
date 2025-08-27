#!/usr/bin/env python3
"""
Autoruns Analyzer - Clean Architecture Main Entry Point
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
    print(f"[+] Starting Autoruns Analysis...")
    print(f"[+] Input: {csv_path}")
    
    # Load data
    try:
        df = autoruns_to_dataframe(csv_path)
        print(f"[+] Loaded {len(df)} entries with {len(df.columns)} columns")
    except Exception as e:
        print(f"[!] Failed to load data: {e}")
        return
    
    # Run analysis
    try:
        from .detectors import run_autoruns_analysis
        results, registry, df_combined = run_autoruns_analysis(df, baseline_csv, pysad_method, top_pct)
        
        # Create combined analysis
        print(f"\n[+] Creating combined analysis...")
        df_combined = registry.get_combined_findings(df, results)
        
        # Optional: Meta-PySAD analysis (if available)
        try:
            from .core.pysad import build_features_for_pysad, pysad_scores
            import math
            import numpy as np
            
            print(f"[+] Running enhanced statistical analysis...")
            
            # Build enhanced features using detection results
            base_features = build_features_for_pysad(df)
            
            # Add detection flags as features
            for detector_name, result_df in results.items():
                feature_name = f"flagged_by_{detector_name}"
                base_features[feature_name] = 0
                if isinstance(result_df, pd.DataFrame) and len(result_df) > 0:
                    base_features.loc[result_df.index, feature_name] = 1
            
            # Add total detections feature
            detection_columns = [col for col in base_features.columns if col.startswith('flagged_by_')]
            if detection_columns:
                base_features['total_detections'] = base_features[detection_columns].sum(axis=1)
            
            # Run PySAD on enhanced features
            enhanced_scores = pysad_scores(base_features, method=pysad_method)
            
            # Create enhanced results
            df_enhanced = df.copy()
            df_enhanced['enhanced_pysad_score'] = np.round(enhanced_scores, 4)
            
            # Add detection summary
            flagged_by = []
            for idx in df.index:
                detectors = []
                for detector_name, result_df in results.items():
                    if isinstance(result_df, pd.DataFrame) and idx in result_df.index:
                        detectors.append(detector_name.replace('_', ' ').title())
                flagged_by.append(' + '.join(detectors) if detectors else 'None')
            
            df_enhanced['flagged_by_detectors'] = flagged_by
            
            # Get top results
            k = max(1, int(math.ceil(len(df_enhanced) * (top_pct / 100.0))))
            df_enhanced_top = df_enhanced.nlargest(k, 'enhanced_pysad_score')
            
            results['enhanced_pysad'] = df_enhanced_top
            print(f"[+] Enhanced analysis: {len(df_enhanced_top)} findings")
            
        except Exception as e:
            print(f"[+] Enhanced analysis skipped: {e}")
        
        # Generate report
        print(f"\n[+] Generating report...")
        from .reports.excel import write_modular_report
        write_modular_report(out_xlsx, df, results, registry, df_combined, 
                           top_pct, pysad_method, baseline_csv)
        
        print(f"[+] Analysis complete. Report saved: {out_xlsx}")
        
    except Exception as e:
        print(f"[!] Analysis failed: {e}")
        import traceback
        traceback.print_exc()


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m autorun_analyzer_dis <autoruns.csv> [out.xlsx] [top_pct] [baseline.csv] [pysad_method]")
        print("\nAutoruns Analyzer - Clean Architecture:")
        print("  Character Analysis: Visual masquerading, hidden characters")
        print("  Signature Analysis: Digital signature verification")
        print("  Location Analysis: Suspicious path intelligence") 
        print("  Integrity Analysis: File hash verification")
        print("  Statistical Analysis: PySAD anomaly detection")
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