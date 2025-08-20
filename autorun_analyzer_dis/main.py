#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Main entry point for Autoruns analyzer.
"""

import sys
import math
import pandas as pd
import numpy as np

from .core.rules import rule_flags_with_reason
from .core.pysad import build_features_for_pysad, pysad_scores
from .core.baseline import load_baseline, compare_against_baseline
from .core.unsigned import unsigned_series
from .core.utils import AutorunsFileCompat
from .reports.excel import write_report


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
    Main analysis function.
    
    Args:
        csv_path: Path to Autoruns CSV/TSV export
        out_xlsx: Output Excel report path
        top_pct: Percentage of top PySAD scores to include
        baseline_csv: Optional baseline CSV for comparison
        pysad_method: PySAD method ('hst' or 'loda')
    """
    # Load Autoruns data
    df = autoruns_to_dataframe(csv_path)
    unsigned = unsigned_series(df.get("Signer"), len(df))
    print(f"Unsigned binaries detected: {unsigned.sum()}/{len(df)}")

    # Rules-based detection (visual masquerading only)
    rules_mask, rule_reason = rule_flags_with_reason(df)
    df_rules = df.loc[rules_mask].copy()
    df_rules.insert(len(df_rules.columns), "rule_reason", rule_reason[rules_mask].values)

    # PySAD anomaly detection (optional if not installed)
    df_pysad_all, df_pysad_top = None, None
    try:
        feats = build_features_for_pysad(df)
        pysad = pysad_scores(feats, method=pysad_method)
        df_pysad_all = df.copy()
        df_pysad_all.insert(len(df_pysad_all.columns), "pysad_score", np.round(pysad, 3))

        k = max(1, int(math.ceil(len(df_pysad_all) * (top_pct / 100.0))))
        thresh = np.partition(pysad, -k)[-k] if len(pysad) else float("inf")
        df_pysad_top = df_pysad_all[pysad >= thresh].sort_values("pysad_score", ascending=False)
    except RuntimeError as e:
        print(f"[!] PySAD skipped: {e}")

    # Baseline comparison (separate analysis)
    df_baseline = pd.DataFrame()
    if baseline_csv:
        try:
            baseline_paths, baseline_hash_by_path = load_baseline(baseline_csv)
            print(f"[+] Baseline loaded: {len(baseline_paths):,} paths / {len(baseline_hash_by_path):,} hashes")
            df_baseline = compare_against_baseline(df, baseline_paths, baseline_hash_by_path)
        except Exception as e:
            print(f"[!] Baseline analysis failed: {e}")

    # Unsigned items detection
    unsigned_mask = unsigned_series(df.get("Signer"), len(df))
    df_unsigned = df.loc[unsigned_mask].copy()
    df_unsigned.insert(len(df_unsigned.columns), "unsigned_reason", 
                      "No valid digital signature detected")
    print(f"[+] Unsigned items detected: {len(df_unsigned)}")

    # Prepare all rows data
    df_all = df.copy()

    # Generate Excel report
    write_report(out_xlsx, df, df_all, df_rules, df_pysad_all, 
                df_pysad_top, df_baseline, df_unsigned, top_pct, pysad_method)

    # Print summary
    print(f"[+] Scanned: {len(df)} rows")
    print(f"[+] Rules flagged: {len(df_rules)}")
    if df_pysad_top is not None:
        print(f"[+] PySAD top {top_pct}%: {len(df_pysad_top)} (method={pysad_method})")
    if baseline_csv:
        print(f"[+] Baseline findings: {len(df_baseline)}")
    print(f"[+] Report saved to: {out_xlsx}")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python -m autoruns_analyzer <autoruns.csv> [out.xlsx] [top_pct] [baseline.csv] [pysad_method=hst|loda]")
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