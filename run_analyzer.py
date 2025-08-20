#!/usr/bin/env python3
"""
Quick runner that installs dependencies and runs analysis.
Minimal version for simple use cases.
"""

import subprocess
import sys
import os

def install_deps():
    """Install dependencies."""
    packages = ["pandas", "numpy", "xlsxwriter", "pysad"]
    for pkg in packages:
        try:
            __import__(pkg)
        except ImportError:
            print(f"Installing {pkg}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

def main():
    print("Installing dependencies...")
    install_deps()
    
    # File paths
    csv_file = r".\csv\rd03.shieldbase.com-Autorunsc.csv"
    output_file = r".\report.xlsx"
    baseline_file = r".\baseline\W10_22H2_Pro_20221115_19045.2251.csv"
    
    # Check files exist
    if not os.path.exists(csv_file):
        print(f"Error: {csv_file} not found!")
        return
    
    # Build command
    cmd = [sys.executable, "-m", "autorun_analyzer_dis.main", csv_file, output_file, "3.0"]
    if os.path.exists(baseline_file):
        cmd.extend([baseline_file, "hst"])
    
    print("Running analysis...")
    subprocess.run(cmd)
    print(f"Done! Check {output_file}")

if __name__ == "__main__":
    main()