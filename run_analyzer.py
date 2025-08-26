#!/usr/bin/env python3
"""
Hybrid runner: Search + Menu approach for scalability
Works great with 1 file or 100+ files
"""

import subprocess
import sys
import os
from pathlib import Path
from datetime import datetime


def setup_directories():
    """Ensure required directories exist."""
    directories = ["csv", "baseline", "output"]
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)


def get_file_info(file_path: Path) -> dict:
    """Get file metadata for better file selection."""
    stat = file_path.stat()
    return {
        'name': file_path.stem,
        'size': stat.st_size,
        'modified': datetime.fromtimestamp(stat.st_mtime),
        'size_mb': round(stat.st_size / (1024*1024), 2)
    }


def search_files(directory: str, extension: str = ".csv", query: str = "") -> list:
    """
    Search files in directory with CSV-only filtering and subfolder support.
    For baseline directory, recursively searches subfolders and ignores non-CSV files.
    """
    dir_path = Path(directory)
    if not dir_path.exists():
        return []
    
    files = []
    
    if directory == "baseline":
        # For baseline: Search recursively and show folder structure
        for file_path in dir_path.rglob(f"*{extension}"):  # Recursive search
            if file_path.is_file():
                file_info = get_file_info(file_path)
                # Add folder context for baseline files
                relative_path = file_path.relative_to(dir_path)
                folder_context = str(relative_path.parent) if relative_path.parent != Path('.') else ""
                file_info['folder'] = folder_context
                file_info['full_name'] = str(relative_path.with_suffix(''))  # Without extension
                
                # Filter by query if provided (search in both filename and folder)
                search_text = f"{file_info['name']} {folder_context}".lower()
                if not query or query.lower() in search_text:
                    files.append(file_info)
    else:
        # For csv directory: Simple flat search
        for file_path in dir_path.glob(f"*{extension}"):
            if file_path.is_file():
                file_info = get_file_info(file_path)
                # Filter by query if provided
                if not query or query.lower() in file_info['name'].lower():
                    files.append(file_info)
    
    # Sort by modification time (newest first)
    return sorted(files, key=lambda x: x['modified'], reverse=True)


def display_files(files: list, max_display: int = 10, is_baseline: bool = False) -> None:
    """Display files with metadata, special formatting for baseline files."""
    if not files:
        print("   (No CSV files found)")
        return
    
    if is_baseline:
        # Special format for baseline files with folder context
        print(f"   {'#':<3} {'Folder/Filename':<45} {'Size':<8} {'Date':<10}")
        print(f"   {'-'*3} {'-'*45} {'-'*8} {'-'*10}")
        
        for i, file_info in enumerate(files[:max_display], 1):
            if file_info.get('folder'):
                display_name = f"{file_info['folder']}/{file_info['name']}"
            else:
                display_name = file_info['name']
            
            # Truncate long names
            display_name = display_name[:44] + "…" if len(display_name) > 45 else display_name
            size_str = f"{file_info['size_mb']}MB"
            date_str = file_info['modified'].strftime('%m/%d/%y')
            
            print(f"   {i:<3} {display_name:<45} {size_str:<8} {date_str:<10}")
    else:
        # Standard format for CSV files
        print(f"   {'#':<3} {'Filename':<40} {'Size':<8} {'Modified':<12}")
        print(f"   {'-'*3} {'-'*40} {'-'*8} {'-'*12}")
        
        for i, file_info in enumerate(files[:max_display], 1):
            name = file_info['name'][:39] + "…" if len(file_info['name']) > 40 else file_info['name']
            size_str = f"{file_info['size_mb']}MB"
            date_str = file_info['modified'].strftime('%m/%d/%Y')
            
            print(f"   {i:<3} {name:<40} {size_str:<8} {date_str:<12}")
    
    if len(files) > max_display:
        print(f"   ... and {len(files) - max_display} more CSV files")


def select_file_hybrid(directory: str, prompt: str, extension: str = ".csv", required: bool = True) -> str:
    """
    Hybrid file selection with special baseline folder handling.
    """
    is_baseline = (directory == "baseline")
    
    print(f"\n{prompt}")
    if is_baseline:
        print(f"📁 Directory: {directory}/ (searching subfolders for CSV files only)")
    else:
        print(f"📁 Directory: {directory}/")
    
    while True:
        try:
            # Get CSV files only
            all_files = search_files(directory, extension)
            
            if not all_files:
                if required:
                    print(f"❌ No {extension} files found in {directory}/ directory!")
                    if is_baseline:
                        print(f"💡 Place your baseline CSV files in {directory}/ subfolders")
                        print(f"    (README.md and .txt files are automatically ignored)")
                    else:
                        print(f"💡 Place your CSV files in the {directory}/ folder")
                    return None
                else:
                    if is_baseline:
                        print(f"⚠️  No CSV files found in {directory}/ (non-CSV files ignored)")
                    else:
                        print(f"⚠️  No CSV files found in {directory}/")
                    return ""
            
            # Show search interface
            csv_count = len(all_files)
            if is_baseline:
                print(f"\n🔍 Found {csv_count} CSV file(s) in baseline subfolders")
                print(f"📋 (Automatically ignoring README.md and .txt files)")
            else:
                print(f"\n🔍 Found {csv_count} CSV file(s)")
            
            if csv_count <= 10:
                # Small list: Show all files directly
                print("📋 Available CSV files:")
                display_files(all_files, is_baseline=is_baseline)
                
                if not required:
                    print(f"   0   Skip (no {directory})")
                
                choice = input(f"\n📌 Select file (1-{csv_count}" + (", 0 to skip" if not required else "") + "): ").strip()
                
                if not required and choice == "0":
                    return ""
                
                try:
                    choice_num = int(choice)
                    if 1 <= choice_num <= csv_count:
                        selected_file = all_files[choice_num - 1]
                        
                        if is_baseline:
                            selected_name = selected_file['full_name']  # Include folder path
                            print(f"✅ Selected: {selected_name}.csv")
                        else:
                            selected_name = selected_file['name']
                            print(f"✅ Selected: {selected_name}.csv")
                        
                        return selected_name
                    else:
                        print(f"❌ Please enter a number between 1 and {csv_count}")
                        continue
                except ValueError:
                    print("❌ Please enter a valid number")
                    continue
            
            else:
                # Large list: Search interface
                print("🔍 Search interface (type Windows version, build, or filename)")
                if is_baseline:
                    print("💡 Examples: 'W10', '22H2', 'Pro_9600', 'Windows11'")
                
                search_query = input("Search: ").strip()
                
                if search_query:
                    filtered_files = search_files(directory, extension, search_query)
                    print(f"\n📋 CSV files matching '{search_query}' ({len(filtered_files)} found):")
                else:
                    filtered_files = all_files
                    print(f"\n📋 All CSV files (showing first 10 of {len(filtered_files)}):")
                
                display_files(filtered_files, max_display=10, is_baseline=is_baseline)
                
                if not filtered_files:
                    print("❌ No CSV files match your search. Try a different search term.")
                    continue
                
                if not required:
                    print(f"   0   Skip (no {directory})")
                
                # Selection input
                choice = input(f"\n📌 Select file (1-{min(len(filtered_files), 10)}" + 
                             (", 0 to skip" if not required else "") + 
                             ", 's' to search again): ").strip()
                
                if choice.lower() == 's':
                    continue  # Search again
                
                if not required and choice == "0":
                    return ""
                
                try:
                    choice_num = int(choice)
                    if 1 <= choice_num <= min(len(filtered_files), 10):
                        selected_file = filtered_files[choice_num - 1]
                        
                        if is_baseline:
                            selected_name = selected_file['full_name']  # Include folder path
                            print(f"✅ Selected: {selected_name}.csv")
                        else:
                            selected_name = selected_file['name']
                            print(f"✅ Selected: {selected_name}.csv")
                        
                        return selected_name
                    else:
                        print(f"❌ Please enter a number between 1 and {min(len(filtered_files), 10)}")
                        continue
                except ValueError:
                    print("❌ Please enter a valid number or 's' to search")
                    continue
                    
        except KeyboardInterrupt:
            print("\n👋 Cancelled by user")
            sys.exit(0)


def get_output_filename() -> str:
    """Get output filename with suggestions based on input files."""
    # Suggest filename based on current timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suggested = f"autoruns_analysis_{timestamp}"
    
    print(f"\n📊 Output filename (without .xlsx extension)")
    print(f"💡 Suggestion: {suggested}")
    
    while True:
        try:
            filename = input("Enter filename (or press Enter for suggestion): ").strip()
            
            if not filename:
                filename = suggested
            
            # Clean filename
            invalid_chars = '<>:"/\\|?*'
            for char in invalid_chars:
                filename = filename.replace(char, "_")
            
            # Ensure .xlsx extension
            if not filename.lower().endswith('.xlsx'):
                filename += '.xlsx'
            
            output_path = Path("output") / filename
            print(f"✅ Output: {output_path}")
            return filename
            
        except KeyboardInterrupt:
            print("\n👋 Cancelled by user")
            sys.exit(0)


def get_analysis_parameters() -> tuple:
    """Get analysis parameters with smart defaults."""
    print("\n" + "="*50)
    print("🎛️  ANALYSIS PARAMETERS")
    print("="*50)
    
    # PySAD method
    method = "hst"  # Default
    method_input = input("🔍 PySAD Method (hst/loda, default: hst): ").strip().lower()
    if method_input == "loda":
        method = "loda"
    
    # Top percentage
    top_pct = 3.0  # Default
    pct_input = input("📊 Top percentage (default: 3.0): ").strip()
    if pct_input:
        try:
            top_pct = float(pct_input)
            if not (0 < top_pct <= 100):
                print("⚠️  Invalid percentage, using default 3.0%")
                top_pct = 3.0
        except ValueError:
            print("⚠️  Invalid input, using default 3.0%")
    
    print(f"✅ Configuration: {method.upper()} method, top {top_pct}%")
    return top_pct, method


def run_analysis(csv_filename: str, baseline_filename: str, output_filename: str, 
                top_pct: float, method: str) -> bool:
    """Execute the analysis with proper path handling for baseline subfolders."""
    
    # Build paths - baseline might include subfolder path
    csv_path = Path("csv") / f"{csv_filename}.csv"
    
    if baseline_filename:
        if "/" in baseline_filename or "\\" in baseline_filename:
            # Baseline includes subfolder path (e.g., "W8.1_Pro_9600/W8.1_Pro_9600")
            baseline_path = Path("baseline") / f"{baseline_filename}.csv"
        else:
            # Simple filename
            baseline_path = Path("baseline") / f"{baseline_filename}.csv"
    else:
        baseline_path = ""
    
    output_path = Path("output") / output_filename
    
    print(f"\n🚀 Starting Analysis...")
    print(f"📁 Input:    {csv_path}")
    print(f"📋 Baseline: {baseline_path if baseline_path else 'None (pattern-based detection)'}")
    print(f"📊 Output:   {output_path}")
    print("-" * 50)
    
    # Build command
    cmd = [
        sys.executable, "-m", "autorun_analyzer_dis.main",
        str(csv_path),
        str(output_path),
        str(top_pct),
        str(baseline_path) if baseline_path else "",
        method
    ]
    
    try:
        result = subprocess.run(cmd, check=True)
        print(f"\n✅ Analysis completed successfully!")
        print(f"📊 Report saved: {output_path}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"\n❌ Analysis failed with error code {e.returncode}")
        return False
    except Exception as e:
        print(f"\n❌ Error: {e}")
        return False


def print_banner():
    """Print application banner."""
    print("="*60)
    print("🔍 AUTORUNS ANALYZER - Hybrid File Selection")
    print("="*60)
    print("📁 Folder Structure:")
    print("   csv/       - Autoruns CSV files")
    print("   baseline/  - Baseline CSV files")  
    print("   output/    - Analysis reports")
    print("")
    print("🎯 Smart Selection:")
    print("   • Small file lists: Direct menu")
    print("   • Large file lists: Search + filter")
    print("   • File metadata: Size, date modified")
    print("="*60)


def main():
    """Main hybrid runner."""
    try:
        print_banner()
        
        # Setup
        print("\n📁 Initializing...")
        setup_directories()
        
        # File selection with hybrid approach
        csv_filename = select_file_hybrid("csv", "🔍 Select Autoruns CSV file:", required=True)
        if not csv_filename:
            return
        
        baseline_filename = select_file_hybrid("baseline", "📋 Select baseline CSV file (optional):", required=False)
        
        output_filename = get_output_filename()
        
        top_pct, method = get_analysis_parameters()
        
        # Final confirmation
        print(f"\n" + "="*50)
        print("🚀 READY TO ANALYZE")
        print("="*50)
        print(f"📁 CSV:          {csv_filename}.csv")
        print(f"📋 Baseline:     {baseline_filename + '.csv' if baseline_filename else 'None'}")
        print(f"📊 Output:       {output_filename}")
        print(f"🎯 Method:       {method.upper()}")
        print(f"📈 Percentage:   {top_pct}%")
        
        confirm = input(f"\n▶️  Start analysis? (Y/n): ").strip().lower()
        if confirm and not confirm.startswith('y'):
            print("👋 Analysis cancelled")
            return
        
        # Execute
        success = run_analysis(csv_filename, baseline_filename, output_filename, top_pct, method)
        
        if success:
            print(f"\n🎉 Analysis Complete!")
            print(f"📂 Report: output/{output_filename}")
        else:
            print(f"\n💔 Analysis failed - check error messages above")
            
    except KeyboardInterrupt:
        print(f"\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()