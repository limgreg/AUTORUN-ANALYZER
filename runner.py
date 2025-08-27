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
    Enhanced search that matches full paths, filenames, and folder names.
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
                
                # Enhanced search - match multiple patterns
                if not query:
                    files.append(file_info)
                else:
                    query_lower = query.lower()
                    
                    # Search in multiple places:
                    search_targets = [
                        file_info['name'].lower(),                    # Just filename
                        folder_context.lower(),                       # Just folder name
                        file_info['full_name'].lower(),              # Full path without extension
                        str(relative_path).lower(),                   # Full path with extension
                        f"{folder_context}/{file_info['name']}".lower(),  # Combined display format
                    ]
                    
                    # Also handle Windows path separators in query
                    normalized_query = query_lower.replace('\\', '/')
                    
                    # Match if query found in any target
                    if any(normalized_query in target or query_lower in target for target in search_targets):
                        files.append(file_info)
    else:
        # For csv directory: Simple flat search
        for file_path in dir_path.glob(f"*{extension}"):
            if file_path.is_file():
                file_info = get_file_info(file_path)
                # Enhanced search for CSV files too
                if not query or query.lower() in file_info['name'].lower():
                    files.append(file_info)
    
    # Sort by modification time (newest first)
    return sorted(files, key=lambda x: x['modified'], reverse=True)


def display_files_paginated(files: list, page: int = 1, per_page: int = 15, is_baseline: bool = False) -> tuple:
    """
    Display files with pagination support.
    
    Returns:
        tuple: (displayed_files, total_pages, current_page)
    """
    if not files:
        print("   (No CSV files found)")
        return [], 0, 0
    
    total_pages = (len(files) + per_page - 1) // per_page
    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    displayed_files = files[start_idx:end_idx]
    
    if is_baseline:
        # Special format for baseline files with folder context
        print(f"   {'#':<3} {'Folder/Filename':<45} {'Size':<8} {'Date':<10}")
        print(f"   {'-'*3} {'-'*45} {'-'*8} {'-'*10}")
        
        for i, file_info in enumerate(displayed_files, start_idx + 1):
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
        
        for i, file_info in enumerate(displayed_files, start_idx + 1):
            name = file_info['name'][:39] + "…" if len(file_info['name']) > 40 else file_info['name']
            size_str = f"{file_info['size_mb']}MB"
            date_str = file_info['modified'].strftime('%m/%d/%Y')
            
            print(f"   {i:<3} {name:<40} {size_str:<8} {date_str:<12}")
    
    # Show pagination info
    print(f"\n   Page {page} of {total_pages} | Showing {len(displayed_files)} of {len(files)} files")
    
    # Show navigation options
    nav_options = []
    if page > 1:
        nav_options.append("'p' for previous page")
    if page < total_pages:
        nav_options.append("'n' for next page")
    nav_options.append("'s' to search")
    
    if nav_options:
        print(f"   Navigation: {', '.join(nav_options)}")
    
    return displayed_files, total_pages, page


def select_file_hybrid(directory: str, prompt: str, extension: str = ".csv", required: bool = True) -> str:
    """
    Hybrid file selection with pagination and enhanced search.
    """
    is_baseline = (directory == "baseline")
    current_page = 1
    per_page = 15
    current_search = ""
    
    print(f"\n{prompt}")
    if is_baseline:
        print(f"Directory: {directory}/ (searching subfolders for CSV files only)")
    else:
        print(f"Directory: {directory}/")
    
    while True:
        try:
            # Get files based on current search
            if current_search:
                all_files = search_files(directory, extension, current_search)
                search_display = f" matching '{current_search}'"
            else:
                all_files = search_files(directory, extension)
                search_display = ""
            
            if not all_files:
                if required:
                    print(f"No CSV files found{search_display} in {directory}/ directory!")
                    if current_search:
                        print("Try a different search term, or press 's' to search again")
                        choice = input("Search again or quit (s/q): ").strip().lower()
                        if choice == 's':
                            current_search = ""
                            current_page = 1
                            continue
                        elif choice == 'q':
                            return None
                        continue
                    else:
                        if is_baseline:
                            print(f"Place your baseline CSV files in {directory}/ subfolders")
                        else:
                            print(f"Place your CSV files in the {directory}/ folder")
                        return None
                else:
                    if is_baseline:
                        print(f"No CSV files found{search_display} in {directory}/")
                    else:
                        print(f"No CSV files found{search_display} in {directory}/")
                    return ""
            
            csv_count = len(all_files)
            if is_baseline:
                print(f"\nFound {csv_count} CSV file(s){search_display} in baseline subfolders")
            else:
                print(f"\nFound {csv_count} CSV file(s){search_display}")
            
            # Always use pagination for consistency
            print(f"Available CSV files{search_display}:")
            displayed_files, total_pages, current_page = display_files_paginated(
                all_files, current_page, per_page, is_baseline
            )
            
            if not required:
                print(f"   0   Skip (no {directory})")
            
            # Build input prompt
            max_choice = len(displayed_files)
            start_idx = (current_page - 1) * per_page
            
            prompt_options = [f"1-{max_choice}"]
            if not required:
                prompt_options.append("0 to skip")
            if current_page > 1:
                prompt_options.append("'p' for previous")
            if current_page < total_pages:
                prompt_options.append("'n' for next")
            prompt_options.append("'s' to search")
            
            choice = input(f"\nSelect file ({', '.join(prompt_options)}): ").strip().lower()
            
            # Handle navigation
            if choice == 'n' and current_page < total_pages:
                current_page += 1
                continue
            elif choice == 'p' and current_page > 1:
                current_page -= 1
                continue
            elif choice == 's':
                # Search interface
                print(f"\nEnhanced Search")
                if is_baseline:
                    print("You can search by:")
                    print("   • Windows version: 'W10', 'Windows11'")
                    print("   • Build info: '22H2', 'Pro', '19045'")
                    print("   • Dates: '20221115', '2022'")
                    print("   • Full paths: 'W10_22H2_Pro_20221115_19045.2251\\W10_22H2_Pro_20221115_19045.2251'")
                else:
                    print("Search by filename or partial name")
                
                if current_search:
                    print(f"Current search: '{current_search}' (press Enter to clear)")
                
                new_search = input("Search: ").strip()
                if new_search:
                    current_search = new_search
                elif current_search:
                    current_search = ""  # Clear search
                current_page = 1  # Reset to first page
                continue
            elif not required and choice == "0":
                return ""
            
            # Handle file selection
            try:
                choice_num = int(choice)
                if 1 <= choice_num <= max_choice:
                    # Calculate actual index in the full list
                    actual_index = start_idx + choice_num - 1
                    selected_file = all_files[actual_index]
                    
                    if is_baseline:
                        selected_name = selected_file['full_name']  # Include folder path
                        print(f"Selected: {selected_name}.csv")
                    else:
                        selected_name = selected_file['name']
                        print(f"Selected: {selected_name}.csv")
                    
                    return selected_name
                else:
                    print(f"Please enter a number between 1 and {max_choice}")
                    continue
            except ValueError:
                print("Please enter a valid number or navigation command")
                continue
                
        except KeyboardInterrupt:
            print("\nCancelled by user")
            sys.exit(0)


def get_output_filename() -> str:
    """Get output filename with suggestions based on input files."""
    # Suggest filename based on current timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    suggested = f"autoruns_analysis_{timestamp}"
    
    print(f"\nOutput filename (without .xlsx extension)")
    print(f"Suggestion: {suggested}")
    
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
            print(f"Output: {output_path}")
            return filename
            
        except KeyboardInterrupt:
            print("\nCancelled by user")
            sys.exit(0)


def get_analysis_parameters() -> tuple:
    """Get analysis parameters with smart defaults."""
    print("\n" + "="*50)
    print("ANALYSIS PARAMETERS")
    print("="*50)
    
    # PySAD method
    method = "hst"  # Default
    method_input = input("PySAD Method (hst/loda, default: hst): ").strip().lower()
    if method_input == "loda":
        method = "loda"
    
    # Top percentage
    top_pct = 3.0  # Default
    pct_input = input("Top percentage (default: 3.0): ").strip()
    if pct_input:
        try:
            top_pct = float(pct_input)
            if not (0 < top_pct <= 100):
                print("Invalid percentage, using default 3.0%")
                top_pct = 3.0
        except ValueError:
            print("Invalid input, using default 3.0%")
    
    print(f"Configuration: {method.upper()} method, top {top_pct}%")
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
    
    print(f"\nStarting Analysis...")
    print(f"Input:    {csv_path}")
    print(f"Baseline: {baseline_path if baseline_path else 'None (pattern-based detection)'}")
    print(f"Output:   {output_path}")
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
        print(f"\nAnalysis completed successfully!")
        print(f"Report saved: {output_path}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"\nAnalysis failed with error code {e.returncode}")
        return False
    except Exception as e:
        print(f"\nError: {e}")
        return False


def print_banner():
    """Print application banner."""
    print("="*60)
    print("AUTORUNS ANALYZER - Hybrid File Selection")
    print("="*60)
    print("Folder Structure:")
    print("   csv/       - Autoruns CSV files")
    print("   baseline/  - Baseline CSV files")  
    print("   output/    - Analysis reports")
    print("")
    print("Smart Selection:")
    print("   • Small file lists: Direct menu")
    print("   • Large file lists: Search + filter")
    print("   • File metadata: Size, date modified")
    print("="*60)


def main():
    """Main hybrid runner."""
    try:
        print_banner()
        
        # Setup
        print("\nInitializing...")
        setup_directories()
        
        # File selection with hybrid approach
        csv_filename = select_file_hybrid("csv", "Select Autoruns CSV file:", required=True)
        if not csv_filename:
            return
        
        baseline_filename = select_file_hybrid("baseline", "Select baseline CSV file (optional):", required=False)
        
        output_filename = get_output_filename()
        
        top_pct, method = get_analysis_parameters()
        
        # Final confirmation
        print(f"\n" + "="*50)
        print("READY TO ANALYZE")
        print("="*50)
        print(f"CSV:          {csv_filename}.csv")
        print(f"Baseline:     {baseline_filename + '.csv' if baseline_filename else 'None'}")
        print(f"Output:       {output_filename}")
        print(f"Method:       {method.upper()}")
        print(f"Percentage:   {top_pct}%")
        
        confirm = input(f"\nStart analysis? (Y/n): ").strip().lower()
        if confirm and not confirm.startswith('y'):
            print("Analysis cancelled")
            return
        
        # Execute
        success = run_analysis(csv_filename, baseline_filename, output_filename, top_pct, method)
        
        if success:
            print(f"\nAnalysis Complete!")
            print(f"Report: output/{output_filename}")
        else:
            print(f"\nAnalysis failed - check error messages above")
            
    except KeyboardInterrupt:
        print(f"\nGoodbye!")
    except Exception as e:
        print(f"\nUnexpected error: {e}")


if __name__ == "__main__":
    main()