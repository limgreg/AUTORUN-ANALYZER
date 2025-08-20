#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Autoruns analyzer (separated outputs):

- Rules (explainable flags)
- PySAD (real PySAD models: HalfSpaceTrees or LODA) – scores only
- Baseline (VanillaWindowsReference-style CSV)

Exports: Summary, AllRows, Rules_Flagged, PySAD_Scored, PySAD_TopN, Baseline_Findings

Requires: pandas, numpy, xlsxwriter
"""

# ============================= Imports & helpers =============================
import re
import os
import sys
import math
import csv
import io
import codecs
import datetime as dt
import numpy as np
import pandas as pd

##??
def _ensure_xlsx(path: str) -> str:
    lower = path.lower()
    if lower.endswith(".xlsx") or lower.endswith(".xlsm"):
        return path
    base, _ = os.path.splitext(path)
    fixed = base + ".xlsx"
    print(f"[!] Output file '{path}' is not an Excel file; writing to '{fixed}' instead.")
    return fixed

def _normalize_path(p: str) -> str:
    if not isinstance(p, str) or not p:
        return ""
    
    # Remove quotes and extra whitespace
    p = p.strip().strip('"').strip("'")
    
    # Handle different path separators
    p = p.replace("/", "\\")
    
    # Normalize case and handle environment variables
    p = p.lower()
    p = re.sub(r'%[^%]+%', lambda m: m.group(0).lower(), p)
    
    # Remove duplicate backslashes
    p = re.sub(r'\\+', r'\\', p)

    
    return p

# ---------- A copy of autorunalyzer----------
class AutorunsFileCompat:
    """
    Minimal, robust reader for Sysinternals Autoruns CSV/TSV exports.
    - Handles UTF-16 LE/BE, UTF-8/UTF-8-SIG
    - Handles comma- or tab-delimited
    - Handles quoted or unquoted headers/fields
    """
    def __init__(self, path: str):
        self.path = path
        self.headers: list[str] = []
        self.rows: list[list[str]] = []
        self._read()

    @staticmethod
    def _detect_encoding(raw: bytes) -> str:
        if raw.startswith(codecs.BOM_UTF16_LE):
            return "utf-16-le"
        if raw.startswith(codecs.BOM_UTF16_BE):
            return "utf-16-be"
        if raw.startswith(codecs.BOM_UTF8):
            return "utf-8-sig"
        # Autoruns most often = UTF-16 LE with BOM; some tools strip BOM.
        # Try to sniff: if there are many NUL bytes in even positions, assume UTF-16-LE.
        if b'\x00' in raw[:200]:
            # Heuristic: LE is much more common in Windows tools
            return "utf-16-le"
        return "utf-8"

    @staticmethod
    def _detect_delimiter(first_line: str) -> str:
        # Prefer tab if present; otherwise comma
        if "\t" in first_line and first_line.count("\t") >= first_line.count(","):
            return "\t"
        return ","

    def _read(self):
        raw = open(self.path, "rb").read()
        enc = self._detect_encoding(raw)
        text = raw.decode(enc, errors="replace")

        # Normalize newlines and strip leading/trailing empties
        text = text.replace("\r\n", "\n").replace("\r", "\n")
        lines = [ln for ln in text.split("\n") if ln.strip() != ""]
        if not lines:
            raise RuntimeError("Empty file or unreadable content.")

        delimiter = self._detect_delimiter(lines[0])

        # Use csv module to properly parse quoted/unquoted fields.
        sio = io.StringIO("\n".join(lines))
        reader = csv.reader(sio, delimiter=delimiter, quotechar='"', skipinitialspace=False)

        rows = list(reader)
        if not rows:
            raise RuntimeError("No rows after CSV parse.")

        # First row is header
        headers = [h.strip() for h in rows[0]]
        data = rows[1:]

        # Some exports have duplicate header names or trailing empties; fix them
        fixed_headers = []
        seen = {}
        for h in headers:
            key = h if h else "Unnamed"
            if key in seen:
                seen[key] += 1
                key = f"{key}.{seen[h]}"
            else:
                seen[key] = 1
            fixed_headers.append(key)
        self.headers = fixed_headers

        # Normalize ragged rows to header length
        width = len(self.headers)
        norm_rows = []
        for r in data:
            if len(r) < width:
                r = r + [""] * (width - len(r))
            elif len(r) > width:
                # join any overflow (rare) into the last column
                r = r[:width-1] + [",".join(r[width-1:])]
            norm_rows.append(r)
        self.rows = norm_rows

def autoruns_to_dataframe(path: str) -> pd.DataFrame:
    af = AutorunsFileCompat(path)
    df = pd.DataFrame(af.rows, columns=af.headers)

    # Normalize a few common column name variants (so your downstream rules keep working)
    cols_lower = {c.lower(): c for c in df.columns}

    def alias(existing: dict, names: list[str]) -> str | None:
        for n in names:
            if n in existing:
                return existing[n]
        return None

    # If missing quotes around headers in export, we still get the same names — this is just a safety net
    mapping = {}
    img_col = alias(cols_lower, ["image path", "image", "path", "location", "command", "fullname"])
    if img_col and img_col != "Image Path":
        mapping[img_col] = "Image Path"

    # Some exports include "Signer" and/or "PSComputerName"; if not, that's fine.
    # We don't force-add them here; your rules don't require them.
    if mapping:
        df.rename(columns=mapping, inplace=True)

    return df

# ============================= Rule constants =============================
#https://lolbas-project.github.io
LOL_BINS = {
    # Original ones
    'rundll32.exe','regsvr32.exe','mshta.exe','powershell.exe','pwsh.exe',
    'wscript.exe','cscript.exe','cmd.exe','wmic.exe','forfiles.exe','schtasks.exe',
    'installutil.exe','certutil.exe','bitsadmin.exe',
    # Additional important ones
    'msiexec.exe','regasm.exe','regsvcs.exe','cmstp.exe','odbcconf.exe',
    'mavinject.exe','dllhost.exe','verclsid.exe','infdefaultinstall.exe',
    'ieexec.exe','presentationhost.exe','msdt.exe','winrm.exe','winrs.exe',
    'wsl.exe','bash.exe','hh.exe','mmc.exe','mpcmdrun.exe','pcalua.exe',
    # Without .exe extension for flexibility
    'rundll32','regsvr32','mshta','powershell','pwsh','wscript','cscript',
    'cmd','wmic','forfiles','schtasks','installutil','certutil','bitsadmin',
    'msiexec','regasm','regsvcs','cmstp','odbcconf','mavinject','dllhost'
}
ZERO_WIDTH = re.compile(r'[\u200B-\u200D\u200E\u200F\uFEFF]')
RLO = re.compile(r'[\u202A-\u202E\u2066-\u2069]')
NBSP = re.compile(r'[\u00A0\u202F]')
ADS = re.compile(r'(?i)^[a-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*:[^\\/:*?"<>|\r\n]+$')
DEVICE_PREFIX = re.compile(r'^(?:\\\\\?\\|\\\?\\|\\\\Device\\|\\\\\?\\GLOBALROOT\\|\\\\\?\\Volume\{)', re.I)

def improved_ads_detection(text_series):
    """Better ADS detection that avoids false positives"""
    ads_mask = text_series.str.contains(ADS, na=False)
    # Exclude common false positives
    false_positives = text_series.str.contains(
    r'(?i)(?:file not found:|http:|https:|ftp:|\b\w+://)',
    na=False, regex=True
    )

    return ads_mask & ~false_positives

# ============================= Utilities =============================
def safe_lower(s):
    return str(s).lower() if pd.notna(s) else ""

def file_name(path):
    s = str(path) if pd.notna(path) else ""
    return os.path.basename(s.replace('"', '').strip())

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    b = s.encode('utf-8', errors='ignore')
    if not b:
        return 0.0
    counts = np.bincount(np.frombuffer(b, dtype=np.uint8), minlength=256)
    p = counts[counts > 0] / len(b)
    return float(-(p * np.log2(p)).sum())

def unsigned_series(signer_s: pd.Series | None, n: int) -> pd.Series:
    """
    Updated to handle the 'Signer' column format:
    - "(Verified) Microsoft Windows" → Signed
    - "Microsoft Windows Publisher"  → Unsigned
    - Missing/empty                 → Unsigned
    """
    if signer_s is not None:
        s = signer_s.astype("string")
    else:
        s = pd.Series([pd.NA] * n, dtype="string")

    # Check for unsigned patterns
    unsigned_mask = (
        s.isna() |
        (s == "") |
        # Case: No "(Verified)" prefix
        ~s.str.startswith("(Verified)", na=False) |
        # Case: "Microsoft Windows Publisher" (common unsigned placeholder)
        s.str.contains(
            r"(?i)microsoft windows publisher|n/?a|unknown|unavailable|not available|unsigned|not verified",
            regex=True, na=False
        )
    )
    return unsigned_mask.fillna(False).astype(int)


# =============================  PySAD (Create the input) =============================
# Note: PySAD **needs numeric vectors**. We keep this small and generic; no “pseudo-PySAD”.
def build_features_for_pysad(df: pd.DataFrame) -> pd.DataFrame:
    col_img = next((c for c in df.columns if c.lower() in ['image path','image','path','location','command','fullname']), None)
    col_desc = next((c for c in df.columns if c.lower() in ['description','entry','entryname','entry name']), None)
    col_publisher = next((c for c in df.columns if c.lower() in ['publisher','company']), None)
    col_verified  = next((c for c in df.columns if c.lower() in ['verified','signature','signer']), None)

    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    desc = df[col_desc].astype(str) if col_desc else pd.Series([""] * len(df))
    combined = (text.fillna('') + " " + desc.fillna('')).str.strip()

    # small, stable set of numeric features
    feat = pd.DataFrame({
        "len": combined.apply(len),
        "args": combined.apply(lambda s: len([t for t in re.split(r'\s+', s.strip()) if t])),
        "slashes": combined.str.count(r'[\\/]'),
        "dots": combined.str.count(r'\.'),
        "entropy": combined.apply(shannon_entropy),
        "zwsp": combined.apply(lambda s: 1 if ZERO_WIDTH.search(s) else 0),
        "rlo": combined.apply(lambda s: 1 if RLO.search(s) else 0),
        "nbsp": combined.apply(lambda s: 1 if NBSP.search(s) else 0),
        "ads": combined.apply(lambda s: 1 if ADS.search(s) else 0),
        "device": combined.apply(lambda s: 1 if DEVICE_PREFIX.search(s) else 0),
        "unsigned": unsigned_series(
            df.get("Signer"),  # <-- Only pass the "Signer" column
            len(df)            # <-- Number of rows
        ).astype(int),
    })
    return feat.replace([np.inf, -np.inf], np.nan).fillna(0)

# ============================= Rules =============================
def rule_flags_with_reason(df: pd.DataFrame) -> tuple[pd.Series, pd.Series]:
    col_img = next((c for c in df.columns if c.lower() in
                   ['image path','image','path','location','command','fullname']), None)
    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    fname = text.apply(file_name)

    # Enhanced path classifications
    user_writable = text.str.contains(
        r'\\Users\\|\\AppData\\|\\Temp\\|\\ProgramData\\|%temp%|%appdata%', 
        case=False, na=False
    )
    
    suspicious_paths = text.str.contains(
        r'\\Windows\\Tasks\\|\\Windows\\System32\\Tasks\\|\\Startup\\|\\Start Menu\\',
        case=False, na=False
    )
    
    # Enhanced LOLBin detection
    lolbin = fname.apply(lambda s: safe_lower(s) in LOL_BINS)
    
    # Unicode attacks
    has_zwsp = text.str.contains(ZERO_WIDTH, na=False)
    has_rlo = text.str.contains(RLO, na=False)
    has_nbsp = text.str.contains(NBSP, na=False)
    
    # File system attacks
    has_ads = improved_ads_detection(text)
    has_dev = text.str.contains(DEVICE_PREFIX, na=False)
    
    # High entropy detection (potential obfuscation)
    high_entropy = text.apply(lambda s: shannon_entropy(s) > 4.5)
    
    # Command line injection patterns
    has_injection = text.str.contains(
        r'[;&|`$(){}]|powershell|cmd\.exe|wscript|cscript',
        case=False, na=False, regex=True
    )
    
    # Combine flags
    lolbin_user = (user_writable & lolbin)
    lolbin_suspicious = (suspicious_paths & lolbin)
    
    mask = (lolbin_user | lolbin_suspicious | has_zwsp | has_rlo | 
            has_nbsp | has_ads | has_dev | high_entropy | has_injection)

    # Enhanced reason generation
    reasons = []
    for i in df.index:
        rset = []
        if lolbin_user.iat[i]: rset.append("LOLBin in user-writable path")
        if lolbin_suspicious.iat[i]: rset.append("LOLBin in suspicious system path")
        if has_zwsp.iat[i]: rset.append("Hidden zero-width Unicode")
        if has_rlo.iat[i]: rset.append("RLO/Unicode override")
        if has_nbsp.iat[i]: rset.append("Non-breaking space")
        if has_ads.iat[i]: rset.append("Alternate Data Stream")
        if has_dev.iat[i]: rset.append("Device/Volume path")
        if high_entropy.iat[i]: rset.append("High entropy (possible obfuscation)")
        if has_injection.iat[i]: rset.append("Command injection pattern")
        reasons.append("; ".join(dict.fromkeys(rset)))
    
    return mask, pd.Series(reasons, index=df.index)

# ============================= PySAD (real models only) (Uses the input) =============================
def pysad_scores(features: pd.DataFrame, method: str = "hst") -> np.ndarray:
    """
    Return normalized 0..1 scores using **real PySAD models**.
    method: 'hst' (HalfSpaceTrees) or 'loda'
    """
    try:
        if method == "loda":
            from pysad.models import LODA
        else:
            from pysad.models import HalfSpaceTrees
    except Exception as e:
        raise RuntimeError("PySAD is not installed or import failed.") from e

    X = features.values.astype(np.float64)
    if X.shape[0] == 0:
        return np.zeros(0, dtype=np.float64)

    if method == "loda":
        model = LODA()
    else:
        fmins = X.min(axis=0) - 1e-6
        fmaxs = X.max(axis=0) + 1e-6
        model = HalfSpaceTrees(feature_mins=fmins, feature_maxes=fmaxs)

    try:
        scores = model.fit_score(X)
    except Exception:
        scores = np.zeros(X.shape[0], dtype=np.float64)
        for i, xi in enumerate(X):
            s = 0.0
            try:    s = float(model.score_partial(xi))
            except Exception: pass
            try:    model.fit_partial(xi)
            except Exception: pass
            scores[i] = s

    # normalize to 0..1 (post-processing only)
    if np.ptp(scores) > 0:
        scores = (scores - scores.min()) / (scores.max() - scores.min())
    else:
        scores = np.zeros_like(scores)
    return scores

# ============================= Baseline (Vanila windows Ref)=============================
def load_baseline(baseline_csv: str) -> tuple[set, dict]:
    if not baseline_csv:
        return set(), {}
    try:
        bdf = pd.read_csv(baseline_csv, engine="python")
    except UnicodeError:
        bdf = pd.read_csv(baseline_csv, engine="python", encoding="utf-16")

    cols_lower = {c.lower(): c for c in bdf.columns}
    path_candidates = ["fullname", "path", "image path", "image", "full path", "filepath"]
    path_col = next((cols_lower[n] for n in path_candidates if n in cols_lower), None)
    if not path_col:
        raise ValueError("Baseline CSV missing a Path-like column (e.g., FullName/Path/Image).")
    bdf.rename(columns={path_col: "Path"}, inplace=True)

    sha256_col = cols_lower.get("sha256") or cols_lower.get("sha-256")
    sha1_col   = cols_lower.get("sha1")   or cols_lower.get("sha-1")
    md5_col    = cols_lower.get("md5")

    baseline_paths = set()
    baseline_hash_by_path = {}

    for _, row in bdf.iterrows():
        p = _normalize_path(row.get("Path"))
        if not p:
            continue
        baseline_paths.add(p)

        h = None
        if sha256_col and pd.notna(row.get(sha256_col)):
            h = str(row.get(sha256_col)).strip().lower()
        elif sha1_col and pd.notna(row.get(sha1_col)):
            h = str(row.get(sha1_col)).strip().lower()
        elif md5_col and pd.notna(row.get(md5_col)):
            h = str(row.get(md5_col)).strip().lower()

        if h:
            baseline_hash_by_path[p] = h

    return baseline_paths, baseline_hash_by_path

def compare_against_baseline(df: pd.DataFrame, baseline_paths: set, baseline_hash_by_path: dict) -> pd.DataFrame:
    col_img = next((c for c in df.columns if c.lower() in
                   ["image path","image","path","location","command","fullname"]), None)
    text = df[col_img].astype(str) if col_img else pd.Series([""] * len(df))
    norm_path = text.apply(_normalize_path)

    cols_lower = {c.lower(): c for c in df.columns}
    sha256_col = cols_lower.get("sha-256") or cols_lower.get("sha256")
    sha1_col   = cols_lower.get("sha-1")   or cols_lower.get("sha1")
    md5_col    = cols_lower.get("md5")

    findings = []
    for i in df.index:
        p = norm_path.iat[i]
        if not p:
            continue

        reason = []
        if p not in baseline_paths:
            reason.append("Not present in Vanilla baseline")
            if p.startswith(r"c:\windows") or p.startswith(r"c:\program files") or p.startswith(r"c:\program files (x86)"):
                reason.append("Unexpected path under system/program dirs")
        else:
            baseline_hash = baseline_hash_by_path.get(p)
            if baseline_hash:
                row_hash = None
                if sha256_col and pd.notna(df.at[i, sha256_col]):
                    row_hash = str(df.at[i, sha256_col]).strip().lower()
                elif sha1_col and pd.notna(df.at[i, sha1_col]):
                    row_hash = str(df.at[i, sha1_col]).strip().lower()
                elif md5_col and pd.notna(df.at[i, md5_col]):
                    row_hash = str(df.at[i, md5_col]).strip().lower()
                if row_hash and row_hash != baseline_hash:
                    reason.append("Hash mismatch vs baseline")

        if reason:
            row_out = df.loc[i].copy()
            row_out["baseline_reason"] = "; ".join(reason)
            findings.append(row_out)

    return pd.DataFrame(findings)

# ============================= Excel writer =============================
def _autosize(ws, df, wb):
    wrap_fmt = wb.add_format({"text_wrap": True, "valign": "top"})
    num_fmt  = wb.add_format({"num_format": "0.000", "valign": "top"})
    int_fmt  = wb.add_format({"num_format": "0", "valign": "top"})
    max_width, min_width = 100, 10

    col_widths = []
    for j, col in enumerate(df.columns):
        w = len(str(col))
        sample = df[col].astype(str).values
        for s in sample[:200]:
            if s is None: continue
            s = s.replace("\r", "")
            w = max(w, max((len(line) for line in s.split("\n")), default=0))
        w = max(min_width, min(max_width, w))
        col_widths.append(w)

    for j, col in enumerate(df.columns):
        ser = df[col]
        if pd.api.types.is_numeric_dtype(ser):
            if pd.api.types.is_integer_dtype(ser):
                ws.set_column(j, j, max(12, min(18, col_widths[j])), int_fmt)
            else:
                ws.set_column(j, j, max(12, min(18, col_widths[j])), num_fmt)
        else:
            ws.set_column(j, j, col_widths[j], wrap_fmt)

    ws.freeze_panes(1, 0)
    ws.autofilter(0, 0, max(len(df), 1), max(len(df.columns) - 1, 0))

def write_report(out_path: str,
                 df_src: pd.DataFrame,
                 df_all: pd.DataFrame,
                 df_rules: pd.DataFrame,
                 df_pysad_all: pd.DataFrame | None,
                 df_pysad_top: pd.DataFrame | None,
                 df_baseline: pd.DataFrame | None,
                 df_unsigned: pd.DataFrame | None,  # New parameter
                 top_pct: float,
                 pysad_method: str):

    out_path = _ensure_xlsx(out_path)
    with pd.ExcelWriter(out_path, engine="xlsxwriter") as writer:
        # Summary
        summary = pd.DataFrame({
            "Metric": [
                "Rows scanned",
                "Columns",
                "Rules flagged",
                (f"PySAD top {top_pct}%" if df_pysad_top is not None else "PySAD (skipped)"),
                "Baseline findings",
                "Unsigned items",  # New metric
                "PySAD method",
                "Generated at",
            ],
            "Value": [
                len(df_src),
                ", ".join(df_src.columns.astype(str).tolist()),
                len(df_rules),
                (0 if df_pysad_top is None else len(df_pysad_top)),
                (0 if df_baseline is None else len(df_baseline)),
                (0 if df_unsigned is None else len(df_unsigned)),  # New count
                (pysad_method if df_pysad_top is not None else "-"),
                dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            ],
        })
        summary.to_excel(writer, sheet_name="Summary", index=False)
        wb = writer.book
        _autosize(writer.sheets["Summary"], summary, wb)

        # AllRows
        df_all.to_excel(writer, sheet_name="AllRows", index=False)
        _autosize(writer.sheets["AllRows"], df_all, wb)

        # Rules_Flagged
        df_rules.to_excel(writer, sheet_name="Rules_Flagged", index=False)
        _autosize(writer.sheets["Rules_Flagged"], df_rules, wb)

        # PySAD sheets (only if available)
        if df_pysad_all is not None:
            df_pysad_all.to_excel(writer, sheet_name="PySAD_Scored", index=False)
            _autosize(writer.sheets["PySAD_Scored"], df_pysad_all, wb)
        if df_pysad_top is not None:
            df_pysad_top.to_excel(writer, sheet_name="PySAD_TopN", index=False)
            _autosize(writer.sheets["PySAD_TopN"], df_pysad_top, wb)

        # Baseline_Findings
        if df_baseline is not None and len(df_baseline):
            df_baseline.to_excel(writer, sheet_name="Baseline_Findings", index=False)
            _autosize(writer.sheets["Baseline_Findings"], df_baseline, wb)
        
        #unsigned items
        if df_unsigned is not None and len(df_unsigned):
            df_unsigned.to_excel(writer, sheet_name="Unsigned_Items", index=False)
            _autosize(writer.sheets["Unsigned_Items"], df_unsigned, wb)

# ============================= Main =============================
def main(csv_path: str,
         out_xlsx: str = "autoruns_report.xlsx",
         top_pct: float = 3.0,
         baseline_csv: str | None = None,
         pysad_method: str = "hst"):

    # Load Autoruns (robust across UTF-16/UTF-8, CSV/TSV, quoted/unquoted)
    df = autoruns_to_dataframe(csv_path)
    unsigned = unsigned_series(df.get("Signer"), len(df))  # Only pass Signer column and length
    print(f"Unsigned binaries detected: {unsigned.sum()}/{len(df)}")


    # ==== Rules ====
    rules_mask, rule_reason = rule_flags_with_reason(df)
    df_rules = df.loc[rules_mask].copy()
    df_rules.insert(len(df_rules.columns), "rule_reason", rule_reason[rules_mask].values)

    # ==== PySAD (real modules; skip entirely if not installed) ====
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

    # ==== Baseline (optional) ====
    df_baseline = pd.DataFrame()
    if baseline_csv:
        try:
            base_paths, base_hashes = load_baseline(baseline_csv)
            print(f"[+] Baseline loaded: {len(base_paths):,} paths / {len(base_hashes):,} hashes")
            df_baseline = compare_against_baseline(df, base_paths, base_hashes)
        except Exception as e:
            print(f"[!] Baseline load failed: {e}")

    # ==== Unsigned Items ====
    unsigned_mask = unsigned_series(df.get("Signer"), len(df))
    df_unsigned = df.loc[unsigned_mask].copy()
    df_unsigned.insert(len(df_unsigned.columns), "unsigned_reason", 
                      "No valid digital signature detected")
    print(f"[+] Unsigned items detected: {len(df_unsigned)}")


    # ==== AllRows ====
    df_all = df.copy()

    # ==== Write report ====
    write_report(out_xlsx, df, df_all, df_rules, df_pysad_all, 
                df_pysad_top, df_baseline, df_unsigned, top_pct, pysad_method)

    print(f"[+] Scanned: {len(df)} rows")
    print(f"[+] Rules flagged: {len(df_rules)}")
    if df_pysad_top is not None:
        print(f"[+] PySAD top {top_pct}%: {len(df_pysad_top)} (method={pysad_method})")
    if baseline_csv:
        print(f"[+] Baseline findings: {len(df_baseline)}")
    print(f"[+] Report saved to: {_ensure_xlsx(out_xlsx)}")

# ============================= CLI =============================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python autoruns_separated.py <autoruns.csv> [out.xlsx] [top_pct] [baseline.csv] [pysad_method=hst|loda]")
        sys.exit(1)
    csv_path  = sys.argv[1]
    out       = sys.argv[2] if len(sys.argv) >= 3 else "autoruns_report.xlsx"
    pct       = float(sys.argv[3]) if len(sys.argv) >= 4 else 3.0
    base      = sys.argv[4] if len(sys.argv) >= 5 else None
    method    = sys.argv[5].lower() if len(sys.argv) >= 6 else "hst"
    if method not in ("hst", "loda"):
        print("[!] Unknown PySAD method, defaulting to 'hst'")
        method = "hst"
    main(csv_path, out, pct, base, method)
