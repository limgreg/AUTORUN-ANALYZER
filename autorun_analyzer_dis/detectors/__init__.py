"""
Simplified Detection System - Replace the complex DetectionRegistry
Clean, reliable, and focused on results.
"""

import pandas as pd
from typing import Dict

# Import all detectors directly
from .visual_masquerading import detect_visual_masquerading
from .unsigned_binaries import detect_unsigned_binaries
from .suspicious_paths import detect_suspicious_paths
from .hidden_characters import detect_hidden_characters
from .baseline_comparison import detect_baseline_deviations
from .anomaly_detection import detect_anomalies_pysad


def run_all_detections(df: pd.DataFrame, baseline_csv: str = None, 
                      pysad_method: str = "hst", top_pct: float = 3.0) -> tuple:
    """
    Run all detection modules with clean, simple execution.
    No complex registry - just direct function calls and clear output.
    
    Args:
        df: Input DataFrame
        baseline_csv: Optional baseline file path
        pysad_method: PySAD method ('hst' or 'loda')
        top_pct: Percentage for PySAD top results
        
    Returns:
        tuple: (results_dict, summary_info)
    """
    print(f"\n🔍 Starting Security Analysis")
    print(f"📊 Analyzing {len(df):,} autorun entries...")
    print("=" * 50)
    
    results = {}
    summary_info = {
        'total_entries': len(df),
        'detectors_run': 0,
        'baseline_used': bool(baseline_csv),
        'findings_summary': {}
    }
    
    # 1. Character Analysis - Visual Masquerading
    print("🔤 Character Analysis: Visual masquerading detection")
    try:
        results['visual_masquerading'] = detect_visual_masquerading(df)
        count = len(results['visual_masquerading'])
        print(f"   ✅ Complete: {count:,} suspicious character patterns found")
        summary_info['detectors_run'] += 1
        summary_info['findings_summary']['visual_masquerading'] = count
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        results['visual_masquerading'] = pd.DataFrame()
        summary_info['findings_summary']['visual_masquerading'] = 0
    
    # 2. Signature Analysis - Unsigned Binaries  
    print("\n🔏 Signature Analysis: Digital signature verification")
    try:
        results['unsigned_binaries'] = detect_unsigned_binaries(df)
        count = len(results['unsigned_binaries'])
        print(f"   ✅ Complete: {count:,} unsigned/suspicious signatures found")
        summary_info['detectors_run'] += 1
        summary_info['findings_summary']['unsigned_binaries'] = count
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        results['unsigned_binaries'] = pd.DataFrame()
        summary_info['findings_summary']['unsigned_binaries'] = 0
    
    # 3. Location Analysis - Suspicious Paths
    print("\n📂 Location Analysis: Suspicious path detection")
    try:
        results['suspicious_paths'] = detect_suspicious_paths(df, baseline_csv)
        count = len(results['suspicious_paths'])
        mode = "baseline-driven" if baseline_csv else "pattern-based"
        print(f"   ✅ Complete: {count:,} suspicious paths found ({mode})")
        summary_info['detectors_run'] += 1
        summary_info['findings_summary']['suspicious_paths'] = count
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        results['suspicious_paths'] = pd.DataFrame()
        summary_info['findings_summary']['suspicious_paths'] = 0
    
    # 4. Character Encoding Analysis - Hidden Characters
    print("\n👻 Character Encoding: Hidden character detection")
    try:
        results['hidden_characters'] = detect_hidden_characters(df)
        count = len(results['hidden_characters'])
        print(f"   ✅ Complete: {count:,} hidden character issues found")
        summary_info['detectors_run'] += 1
        summary_info['findings_summary']['hidden_characters'] = count
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        results['hidden_characters'] = pd.DataFrame()
        summary_info['findings_summary']['hidden_characters'] = 0
    
    # 5. Integrity Analysis - Baseline Comparison (only if baseline provided)
    print("\n🔒 Integrity Analysis: File hash verification")
    if baseline_csv:
        try:
            results['baseline_comparison'] = detect_baseline_deviations(df, baseline_csv)
            count = len(results['baseline_comparison'])
            print(f"   ✅ Complete: {count:,} integrity violations found")
            summary_info['detectors_run'] += 1
            summary_info['findings_summary']['baseline_comparison'] = count
        except Exception as e:
            print(f"   ❌ Failed: {e}")
            results['baseline_comparison'] = pd.DataFrame()
            summary_info['findings_summary']['baseline_comparison'] = 0
    else:
        print(f"   ⚠️  Skipped: No baseline provided (hash-based verification disabled)")
        results['baseline_comparison'] = pd.DataFrame()
        summary_info['findings_summary']['baseline_comparison'] = 0
    
    # 6. Meta-Statistical Analysis - Anomaly Detection
    print(f"\n📈 Meta-Statistical: Anomaly detection ({pysad_method.upper()}, top {top_pct}%)")
    try:
        results['anomaly_detection'] = detect_anomalies_pysad(df, pysad_method, top_pct)
        count = len(results['anomaly_detection'])
        print(f"   ✅ Complete: {count:,} statistical anomalies found")
        summary_info['detectors_run'] += 1
        summary_info['findings_summary']['anomaly_detection'] = count
    except Exception as e:
        print(f"   ❌ Failed: {e}")
        results['anomaly_detection'] = pd.DataFrame()
        summary_info['findings_summary']['anomaly_detection'] = 0
    
    # Generate summary
    print("\n" + "=" * 50)
    print("📊 ANALYSIS COMPLETE")
    print("=" * 50)
    
    total_findings = sum(summary_info['findings_summary'].values())
    unique_flagged = len(set().union(*[
        set(df_result.index) for df_result in results.values() 
        if isinstance(df_result, pd.DataFrame) and len(df_result) > 0
    ]))
    
    print(f"🎯 Results Summary:")
    print(f"   Detectors run: {summary_info['detectors_run']}/6")
    print(f"   Total findings: {total_findings:,}")
    print(f"   Unique flagged entries: {unique_flagged:,}/{len(df):,} ({unique_flagged/len(df)*100:.1f}%)")
    if baseline_csv:
        print(f"   Baseline: {baseline_csv.split('/')[-1] if '/' in baseline_csv else baseline_csv}")
    
    print(f"\n📋 Findings by Type:")
    detector_names = {
        'visual_masquerading': 'Visual Masquerading',
        'unsigned_binaries': 'Unsigned Binaries', 
        'suspicious_paths': 'Suspicious Paths',
        'hidden_characters': 'Hidden Characters',
        'baseline_comparison': 'Integrity Violations',
        'anomaly_detection': 'Statistical Anomalies'
    }
    
    for detector, count in summary_info['findings_summary'].items():
        name = detector_names.get(detector, detector.replace('_', ' ').title())
        if count > 0:
            print(f"   {name}: {count:,}")
    
    return results, summary_info


def get_combined_findings(df_src: pd.DataFrame, results: Dict[str, pd.DataFrame]) -> pd.DataFrame:
    """
    Create combined high-priority findings from multiple detectors.
    Simple version without complex registry logic.
    """
    detector_indices = {}
    
    # Get indices for each detector that found something
    for detector_name, df_results in results.items():
        if isinstance(df_results, pd.DataFrame) and len(df_results) > 0:
            detector_indices[detector_name] = set(df_results.index)
    
    combined_findings = []
    
    # Find entries flagged by multiple detectors
    for idx in df_src.index:
        detecting_modules = []
        detection_details = []
        max_severity = "Low"
        
        for detector_name, indices in detector_indices.items():
            if idx in indices:
                # Format detector name nicely
                display_name = detector_name.replace('_', ' ').title()
                detecting_modules.append(display_name)
                
                # Get detection reason if available
                detector_df = results[detector_name]
                if 'detection_reason' in detector_df.columns:
                    reason = detector_df.loc[idx, 'detection_reason']
                    detection_details.append(f"{display_name}: {reason}")
                
                # Track severity
                if 'severity_level' in detector_df.columns:
                    level = detector_df.loc[idx, 'severity_level']
                elif 'suspicion_level' in detector_df.columns:
                    level = detector_df.loc[idx, 'suspicion_level']
                else:
                    level = "Medium"
                
                # Update max severity
                severity_order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
                if severity_order.get(level, 2) > severity_order.get(max_severity, 1):
                    max_severity = level
        
        # Include if flagged by at least one detector
        if len(detecting_modules) >= 1:
            row = df_src.loc[idx].copy()
            row['detection_modules'] = ' + '.join(detecting_modules)
            row['detection_count'] = len(detecting_modules)
            row['max_severity'] = max_severity
            row['all_detection_details'] = ' | '.join(detection_details)
            
            # Simple priority score
            priority_score = len(detecting_modules) * 10
            severity_multipliers = {"Critical": 2.0, "High": 1.5, "Medium": 1.0, "Low": 0.8}
            priority_score *= severity_multipliers.get(max_severity, 1.0)
            row['priority_score'] = round(priority_score, 2)
            
            combined_findings.append(row)
    
    if combined_findings:
        df_combined = pd.DataFrame(combined_findings)
        df_combined = df_combined.sort_values(['priority_score', 'detection_count'], ascending=[False, False])
        return df_combined
    
    return pd.DataFrame()


def create_detection_summary(results: Dict[str, pd.DataFrame], summary_info: dict) -> pd.DataFrame:
    """
    Create simple detection summary for Excel reports.
    Replaces the complex registry.get_summary() method.
    """
    summary_data = []
    
    detector_info = {
        'visual_masquerading': {
            'name': 'Visual Masquerading',
            'description': 'Unicode character analysis'
        },
        'unsigned_binaries': {
            'name': 'Unsigned Binaries', 
            'description': 'Digital signature verification'
        },
        'suspicious_paths': {
            'name': 'Suspicious Paths',
            'description': 'File location analysis'
        },
        'hidden_characters': {
            'name': 'Hidden Characters',
            'description': 'Non-printable character detection'
        },
        'baseline_comparison': {
            'name': 'Baseline Comparison',
            'description': 'File integrity verification'
        },
        'anomaly_detection': {
            'name': 'Anomaly Detection',
            'description': 'Statistical analysis'
        }
    }
    
    for detector_key, info in detector_info.items():
        count = summary_info['findings_summary'].get(detector_key, 0)
        enabled = detector_key in results and isinstance(results[detector_key], pd.DataFrame)
        
        summary_data.append({
            'Detector': info['name'],
            'Description': info['description'], 
            'Findings': count,
            'Enabled': enabled
        })
    
    return pd.DataFrame(summary_data)


# Clean convenience function - replaces the complex DetectionRegistry
def run_autoruns_analysis(df: pd.DataFrame, baseline_csv: str = None,
                         pysad_method: str = "hst", top_pct: float = 3.0) -> tuple:
    """
    Main entry point for autoruns analysis.
    Clean and simple - no complex registry overhead.
    
    Returns:
        tuple: (results_dict, registry_compatible_object)
    """
    
    # Run all detections
    results, summary_info = run_all_detections(df, baseline_csv, pysad_method, top_pct)
    
    # Create combined findings
    df_combined = get_combined_findings(df, results) 
    
    # Create a simple object that mimics what the Excel report expects
    class SimpleRegistry:
        def __init__(self, results, summary_info):
            self.results = results
            self.summary_info = summary_info
            
            # Create detectors dict for compatibility with main.py
            self.detectors = {
                'visual_masquerading': {
                    'enabled': True,
                    'description': 'Unicode character analysis',
                    'responsibility': 'Character Analysis',
                    'requires_baseline': False,
                    'enhanced_by_baseline': False,
                    'results': results.get('visual_masquerading', pd.DataFrame())
                },
                'unsigned_binaries': {
                    'enabled': True,
                    'description': 'Digital signature verification',
                    'responsibility': 'Signature Analysis', 
                    'requires_baseline': False,
                    'enhanced_by_baseline': False,
                    'results': results.get('unsigned_binaries', pd.DataFrame())
                },
                'suspicious_paths': {
                    'enabled': True,
                    'description': 'File location analysis',
                    'responsibility': 'Location Analysis',
                    'requires_baseline': False,
                    'enhanced_by_baseline': True,
                    'results': results.get('suspicious_paths', pd.DataFrame())
                },
                'hidden_characters': {
                    'enabled': True,
                    'description': 'Non-printable character detection', 
                    'responsibility': 'Character Encoding Analysis',
                    'requires_baseline': False,
                    'enhanced_by_baseline': False,
                    'results': results.get('hidden_characters', pd.DataFrame())
                },
                'baseline_comparison': {
                    'enabled': len(results.get('baseline_comparison', pd.DataFrame())) > 0 or baseline_csv is not None,
                    'description': 'File integrity verification',
                    'responsibility': 'Integrity Analysis',
                    'requires_baseline': True,
                    'enhanced_by_baseline': False,
                    'results': results.get('baseline_comparison', pd.DataFrame())
                },
                'anomaly_detection': {
                    'enabled': True,
                    'description': 'Statistical analysis',
                    'responsibility': 'Meta-Statistical Analysis',
                    'requires_baseline': False,
                    'enhanced_by_baseline': False,
                    'results': results.get('anomaly_detection', pd.DataFrame())
                }
            }
        
        def get_summary(self):
            return create_detection_summary(self.results, self.summary_info)
        
        def get_combined_findings(self, df_src, results_dict):
            return get_combined_findings(df_src, results_dict)
    
    registry = SimpleRegistry(results, summary_info)
    
    return results, registry, df_combined