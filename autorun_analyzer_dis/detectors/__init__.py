"""
Clean Architecture Detection Registry
Each module has a single, focused responsibility.
"""

import pandas as pd
from typing import Dict, Callable, Any

# Import all focused detectors
from .visual_masquerading import detect_visual_masquerading
from .unsigned_binaries import detect_unsigned_binaries
from .suspicious_paths import detect_suspicious_paths      # Pure path analysis
from .hidden_characters import detect_hidden_characters
from .baseline_comparison import detect_baseline_deviations  # Pure integrity checking
from .anomaly_detection import detect_anomalies_pysad


class DetectionRegistry:
    """
    Clean Architecture Detection Registry
    Each detector has a single, focused responsibility.
    """
    
    def __init__(self):
        self.detectors = {}
        self._register_focused_detectors()
    
    def _register_focused_detectors(self):
        """Register all detectors with their focused responsibilities."""
        
        # Character-based detection
        self.register('visual_masquerading', detect_visual_masquerading, 
                     "Unicode confusable character analysis", 
                     responsibility="Character Analysis",
                     enabled=True, requires_baseline=False)
        
        # Signature-based detection  
        self.register('unsigned_binaries', detect_unsigned_binaries,
                     "Digital signature verification", 
                     responsibility="Signature Analysis",
                     enabled=True, requires_baseline=False)
        
        # Location-based detection
        self.register('suspicious_paths', detect_suspicious_paths,
                     "File path location intelligence", 
                     responsibility="Location Analysis",
                     enabled=True, requires_baseline=False, enhanced_by_baseline=True)
        
        # Character encoding detection
        self.register('hidden_characters', detect_hidden_characters,
                     "Hidden/non-printable character detection", 
                     responsibility="Character Encoding Analysis",
                     enabled=True, requires_baseline=False)
        
        # File integrity detection
        self.register('baseline_comparison', detect_baseline_deviations,
                     "File integrity verification (hash-based)", 
                     responsibility="Integrity Analysis",
                     enabled=False, requires_baseline=True)  # Only enabled if baseline provided
        
        # Statistical analysis
        self.register('anomaly_detection', detect_anomalies_pysad,
                     "Statistical anomaly detection", 
                     responsibility="Meta-Statistical Analysis",
                     enabled=True, requires_baseline=False)
    
    def register(self, name: str, detector_func: Callable, description: str = "", 
                responsibility: str = "", enabled: bool = True, requires_baseline: bool = False,
                enhanced_by_baseline: bool = False):
        """Register a detector with clean responsibility definition."""
        self.detectors[name] = {
            'function': detector_func,
            'description': description,
            'responsibility': responsibility,
            'enabled': enabled,
            'requires_baseline': requires_baseline,
            'enhanced_by_baseline': enhanced_by_baseline,
            'results': None
        }
    
    def enable(self, name: str):
        """Enable a detector."""
        if name in self.detectors:
            self.detectors[name]['enabled'] = True
            print(f"[+] Enabled: {name}")
        else:
            print(f"[!] Unknown detector: {name}")
    
    def disable(self, name: str):
        """Disable a detector."""
        if name in self.detectors:
            self.detectors[name]['enabled'] = False
            print(f"[+] Disabled: {name}")
        else:
            print(f"[!] Unknown detector: {name}")
    
    def configure_for_baseline(self, baseline_csv: str = None):
        """
        Intelligent configuration based on baseline availability.
        """
        print(f"\n[+] Configuring detection modules...")
        
        if baseline_csv:
            print(f"[+] Baseline available: {baseline_csv}")
            
            # Enable baseline-requiring modules
            baseline_modules = [name for name, detector in self.detectors.items() 
                              if detector['requires_baseline']]
            for module in baseline_modules:
                self.enable(module)
                print(f"    ✅ {module}: Enabled (baseline required)")
            
            # Show enhanced modules
            enhanced_modules = [name for name, detector in self.detectors.items() 
                              if detector['enhanced_by_baseline'] and detector['enabled']]
            for module in enhanced_modules:
                print(f"    🚀 {module}: Enhanced (baseline-driven intelligence)")
            
            # Load and show baseline summaries
            self._print_baseline_summaries(baseline_csv)
            
        else:
            print(f"[+] No baseline provided")
            
            # Disable baseline-requiring modules
            baseline_modules = [name for name, detector in self.detectors.items() 
                              if detector['requires_baseline']]
            for module in baseline_modules:
                self.disable(module)
                print(f"    ❌ {module}: Disabled (requires baseline)")
            
            # Show degraded modules
            enhanced_modules = [name for name, detector in self.detectors.items() 
                              if detector['enhanced_by_baseline'] and detector['enabled']]
            for module in enhanced_modules:
                print(f"    ⚠️  {module}: Pattern-based fallback (baseline would enhance)")
    
    def _print_baseline_summaries(self, baseline_csv: str):
        """Print configuration summaries for baseline-enhanced modules."""
        try:
            # Path analysis summary
            from .suspicious_paths import get_path_analysis_summary
            path_summary = get_path_analysis_summary(baseline_csv)
            print(f"    📂 Path Analysis: {path_summary['accuracy']}")
            
            # Integrity analysis summary  
            from .baseline_comparison import get_integrity_analysis_summary, print_integrity_summary
            integrity_summary = get_integrity_analysis_summary(baseline_csv)
            print(f"    🔒 Integrity Analysis: {integrity_summary['status']}")
            
            # Print detailed integrity summary
            print_integrity_summary(integrity_summary)
            
        except Exception as e:
            print(f"    ⚠️  Could not load baseline summaries: {e}")
    
    def print_architecture_overview(self):
        """Print clean architecture overview."""
        print("\n" + "="*70)
        print("CLEAN DETECTION ARCHITECTURE")
        print("="*70)
        
        print("🏗️  Single Responsibility Principle:")
        print("   Each module has ONE focused job - no overlap!")
        print("")
        
        for name, detector in self.detectors.items():
            status = "✅ Enabled" if detector['enabled'] else "❌ Disabled"
            baseline_note = ""
            
            if detector['requires_baseline']:
                baseline_note = " [Requires Baseline]"
            elif detector['enhanced_by_baseline']:
                baseline_note = " [Enhanced by Baseline]"
            
            print(f"{detector['responsibility']:<25} {status}{baseline_note}")
            print(f"{'└─ ' + name:<25} {detector['description']}")
            print("")
        
        print("🎯 Meta-Analysis Flow:")
        print("   All detection signals → PySAD → Combined risk assessment")
        print("="*70)
    
    def run_detector(self, name: str, df: pd.DataFrame, **kwargs) -> pd.DataFrame:
        """Run a specific detector with clean parameter handling."""
        if name not in self.detectors:
            raise ValueError(f"Unknown detector: {name}")
        
        detector = self.detectors[name]
        if not detector['enabled']:
            return pd.DataFrame()
        
        try:
            baseline_csv = kwargs.get('baseline_csv')
            
            # Clean parameter dispatch based on detector requirements
            if detector['requires_baseline']:
                if not baseline_csv:
                    print(f"[!] {name} requires baseline but none provided - skipping")
                    return pd.DataFrame()
                result = detector['function'](df, baseline_csv)
            
            elif detector['enhanced_by_baseline']:
                # Pass baseline if available (detector handles None gracefully)
                result = detector['function'](df, baseline_csv)
            
            elif name == 'anomaly_detection':
                # Special parameters for PySAD
                method = kwargs.get('pysad_method', 'hst')
                top_pct = kwargs.get('top_pct', 3.0)
                result = detector['function'](df, method, top_pct)
            
            else:
                # Standard detectors with no special requirements
                result = detector['function'](df)
            
            detector['results'] = result
            return result
            
        except Exception as e:
            print(f"[!] {name} ({detector['responsibility']}) failed: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()
    
    def run_all(self, df: pd.DataFrame, **kwargs) -> Dict[str, pd.DataFrame]:
        """Run all enabled detectors with clean architecture."""
        baseline_csv = kwargs.get('baseline_csv')
        
        # Configure based on baseline availability
        self.configure_for_baseline(baseline_csv)
        
        results = {}
        
        print(f"\n[+] Running focused detection modules on {len(df)} entries...")
        print("=" * 60)
        
        # Group by responsibility for cleaner output
        responsibilities = {}
        for name, detector in self.detectors.items():
            if detector['enabled']:
                resp = detector['responsibility']
                if resp not in responsibilities:
                    responsibilities[resp] = []
                responsibilities[resp].append(name)
        
        # Run detectors grouped by responsibility
        for responsibility, detector_names in responsibilities.items():
            print(f"\n🔍 {responsibility}:")
            
            for name in detector_names:
                detector = self.detectors[name]
                
                # Enhanced status info
                baseline_note = ""
                if detector['requires_baseline'] and baseline_csv:
                    baseline_note = " (baseline-required)"
                elif detector['enhanced_by_baseline'] and baseline_csv:
                    baseline_note = " (baseline-enhanced)"
                elif detector['enhanced_by_baseline'] and not baseline_csv:
                    baseline_note = " (fallback mode)"
                
                print(f"   Running {name.replace('_', ' ')}{baseline_note}...")
                
                result = self.run_detector(name, df, **kwargs)
                results[name] = result
                
                count = len(result) if isinstance(result, pd.DataFrame) else 0
                if count > 0:
                    print(f"   ✅ {count} findings")
                else:
                    print(f"   ✅ No issues detected")
        
        print("=" * 60)
        return results
    
    def get_summary(self) -> pd.DataFrame:
        """Get clean summary with architecture info (for compatibility with excel report)."""
        summary = []
        for name, detector in self.detectors.items():
            results = detector.get('results')
            count = len(results) if isinstance(results, pd.DataFrame) else 0
            
            # Enhanced status
            status = "Enabled" if detector['enabled'] else "Disabled"
            if detector['requires_baseline']:
                status += " (Baseline Required)"
            elif detector['enhanced_by_baseline']:
                status += " (Baseline Enhanced)"
            
            summary.append({
                'Detector': name.replace('_', ' ').title(),  # Use 'Detector' for excel compatibility
                'Description': detector['description'],
                'Findings': count,
                'Enabled': detector['enabled'],
                'Responsibility': detector['responsibility']
            })
        
        return pd.DataFrame(summary)
    
    def get_combined_findings(self, df_src: pd.DataFrame, results: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """Enhanced combined findings with responsibility tracking."""
        detector_indices = {}
        responsibility_map = {}
        
        for detector_name, df_results in results.items():
            if isinstance(df_results, pd.DataFrame) and len(df_results) > 0:
                detector_indices[detector_name] = set(df_results.index)
                responsibility_map[detector_name] = self.detectors[detector_name]['responsibility']
        
        combined_findings = []
        
        for idx in df_src.index:
            detecting_modules = []
            responsibilities = []
            detection_details = []
            max_severity = "Low"
            
            for detector_name, indices in detector_indices.items():
                if idx in indices:
                    detecting_modules.append(detector_name.replace('_', ' ').title())
                    responsibilities.append(responsibility_map[detector_name])
                    
                    # Get detection details
                    detector_df = results[detector_name]
                    if 'detection_reason' in detector_df.columns:
                        reason = detector_df.loc[idx, 'detection_reason']
                        detection_details.append(f"{detector_name}: {reason}")
                    
                    # Track highest severity
                    if 'suspicion_level' in detector_df.columns:
                        level = detector_df.loc[idx, 'suspicion_level']
                    elif 'violation_severity' in detector_df.columns:
                        level = detector_df.loc[idx, 'violation_severity']
                    else:
                        level = "Medium"
                    
                    severity_order = {"Critical": 4, "HIGH": 4, "High": 3, "Medium-High": 2.5, "Medium": 2, "LOW": 1, "Low": 1}
                    if severity_order.get(level, 2) > severity_order.get(max_severity, 1):
                        max_severity = level
            
            if len(detecting_modules) >= 1:
                row = df_src.loc[idx].copy()
                row['detection_modules'] = ' + '.join(detecting_modules)
                row['detection_count'] = len(detecting_modules)
                row['analysis_types'] = ' + '.join(set(responsibilities))
                row['max_severity'] = max_severity
                row['all_detection_details'] = ' | '.join(detection_details)
                
                # Enhanced priority scoring with architecture awareness
                priority_score = 0
                
                # Base scores by responsibility/detector
                responsibility_scores = {
                    'Character Analysis': 10,      # visual_masquerading
                    'Signature Analysis': 8,       # unsigned_binaries  
                    'Location Analysis': 6,        # suspicious_paths
                    'Character Encoding Analysis': 5,  # hidden_characters
                    'Integrity Analysis': 9,       # baseline_comparison (high value)
                    'Meta-Statistical Analysis': 3 # anomaly_detection
                }
                
                for resp in responsibilities:
                    priority_score += responsibility_scores.get(resp, 2)
                
                # Severity multiplier
                severity_multipliers = {
                    "Critical": 2.0, "CRITICAL": 2.0,
                    "High": 1.5, "HIGH": 1.5,
                    "Medium-High": 1.3,
                    "Medium": 1.0, "MEDIUM": 1.0,
                    "Low": 0.8, "LOW": 0.8
                }
                priority_score *= severity_multipliers.get(max_severity, 1.0)
                
                # Multi-detection bonus (different analysis types working together)
                priority_score += len(set(responsibilities)) * 3
                
                row['priority_score'] = round(priority_score, 2)
                combined_findings.append(row)
        
        if combined_findings:
            df_combined = pd.DataFrame(combined_findings)
            df_combined = df_combined.sort_values(['priority_score', 'detection_count'], ascending=[False, False])
            return df_combined
        
        return pd.DataFrame()


# Clean convenience function
def run_all_detections(df: pd.DataFrame, baseline_csv: str = None, 
                      pysad_method: str = "hst", top_pct: float = 3.0) -> tuple:
    """
    Run all detections with clean architecture.
    Each detector focuses on its single responsibility.
    """
    print("[+] Initializing Clean Architecture Detection Registry...")
    registry = DetectionRegistry()
    
    # Show architecture overview
    registry.print_architecture_overview()
    
    # Run all detections
    results = registry.run_all(df, 
                              baseline_csv=baseline_csv,
                              pysad_method=pysad_method,
                              top_pct=top_pct)
    
    return results, registry