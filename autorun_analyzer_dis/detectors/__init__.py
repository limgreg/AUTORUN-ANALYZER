"""
Updated Detection Registry - Streamlined with baseline-focused suspicious paths.
"""

import pandas as pd
from typing import Dict, Callable, Any, Optional

# Import all detectors
from .visual_masquerading import detect_visual_masquerading
from .unsigned_binaries import detect_unsigned_binaries
from .suspicious_paths import detect_suspicious_paths  # Now baseline-focused only
from .hidden_characters import detect_hidden_characters
from .baseline_comparison import detect_baseline_deviations
from .anomaly_detection import detect_anomalies_pysad


class DetectionRegistry:
    """
    Streamlined detection registry with baseline-focused suspicious path detection.
    """
    
    def __init__(self):
        self.detectors = {}
        self._register_default_detectors()
    
    def _register_default_detectors(self):
        """Register all built-in detectors with updated descriptions."""
        self.register('visual_masquerading', detect_visual_masquerading, 
                     "Visual masquerading using confusable characters", 
                     enabled=True, baseline_enhanced=False)
        
        self.register('unsigned_binaries', detect_unsigned_binaries,
                     "Unsigned or unverified digital signatures", 
                     enabled=True, baseline_enhanced=False)
        
        self.register('suspicious_paths', detect_suspicious_paths,
                     "Baseline-driven suspicious path analysis (requires baseline for best results)", 
                     enabled=True, baseline_enhanced=True)  # Now baseline-focused
        
        self.register('hidden_characters', detect_hidden_characters,
                     "Hidden characters (NBSP, zero-width, control chars)", 
                     enabled=True, baseline_enhanced=False)
        
        self.register('baseline_comparison', detect_baseline_deviations,
                     "Comprehensive baseline deviation analysis", 
                     enabled=False, baseline_enhanced=True)  # Only enabled if baseline provided
        
        self.register('anomaly_detection', detect_anomalies_pysad,
                     "Statistical anomalies using PySAD", 
                     enabled=True, baseline_enhanced=False)
    
    def register(self, name: str, detector_func: Callable, description: str = "", 
                enabled: bool = True, baseline_enhanced: bool = False):
        """Register a new detection method."""
        self.detectors[name] = {
            'function': detector_func,
            'description': description,
            'enabled': enabled,
            'baseline_enhanced': baseline_enhanced,
            'results': None
        }
    
    def enable(self, name: str):
        """Enable a detector."""
        if name in self.detectors:
            self.detectors[name]['enabled'] = True
            print(f"[+] Enabled detector: {name}")
        else:
            print(f"[!] Warning: Unknown detector '{name}' - cannot enable")
    
    def disable(self, name: str):
        """Disable a detector."""
        if name in self.detectors:
            self.detectors[name]['enabled'] = False
            print(f"[+] Disabled detector: {name}")
        else:
            print(f"[!] Warning: Unknown detector '{name}' - cannot disable")
    
    def configure_for_baseline(self, baseline_csv: str = None):
        """
        Configure detectors based on whether baseline is available.
        Provides intelligent recommendations.
        """
        if baseline_csv:
            print(f"\n[+] Configuring for baseline-enhanced detection...")
            print(f"[+] Baseline file: {baseline_csv}")
            
            # Enable baseline comparison
            self.enable('baseline_comparison')
            
            # Show which detectors benefit from baseline
            baseline_detectors = [name for name, detector in self.detectors.items() 
                                if detector['baseline_enhanced'] and detector['enabled']]
            print(f"[+] Baseline-enhanced detectors: {', '.join(baseline_detectors)}")
            
            # Get baseline statistics for suspicious paths
            try:
                from .suspicious_paths import get_baseline_statistics, print_detection_summary
                baseline_stats = get_baseline_statistics(baseline_csv)
                print_detection_summary(baseline_stats)
            except Exception as e:
                print(f"[!] Could not load baseline statistics: {e}")
        
        else:
            print(f"\n[+] No baseline provided - using standalone detection...")
            print(f"[!] Note: suspicious_paths will use minimal fallback detection")
            print(f"[💡] Recommendation: Provide a baseline CSV for much better path analysis")
            
            # Disable baseline comparison
            self.disable('baseline_comparison')
    
    def list_detectors(self):
        """List all available detectors with enhanced information."""
        print("\n" + "="*70)
        print("DETECTION MODULES")
        print("="*70)
        
        for name, detector in self.detectors.items():
            status = "✅ Enabled" if detector['enabled'] else "❌ Disabled"
            baseline_note = " 📊 [Baseline-Enhanced]" if detector['baseline_enhanced'] else ""
            
            print(f"{name.replace('_', ' ').title().ljust(25)} {status}{baseline_note}")
            print(f"{''.ljust(25)} {detector['description']}")
            print("")
        
        print("="*70)
    
    def run_detector(self, name: str, df: pd.DataFrame, **kwargs) -> pd.DataFrame:
        """Run a specific detector with enhanced baseline support."""
        if name not in self.detectors:
            raise ValueError(f"Unknown detector: {name}")
        
        detector = self.detectors[name]
        if not detector['enabled']:
            return pd.DataFrame()
        
        try:
            baseline_csv = kwargs.get('baseline_csv')
            
            # Enhanced parameter handling
            if name == 'baseline_comparison':
                if not baseline_csv:
                    print(f"[!] Baseline detector enabled but no baseline_csv provided - skipping")
                    return pd.DataFrame()
                result = detector['function'](df, baseline_csv)
            
            elif name == 'suspicious_paths':
                # Always pass baseline_csv (function handles None gracefully)
                result = detector['function'](df, baseline_csv)
                
            elif name == 'anomaly_detection':
                method = kwargs.get('pysad_method', 'hst')
                top_pct = kwargs.get('top_pct', 3.0)
                result = detector['function'](df, method, top_pct)
            
            else:
                # Standard detectors
                result = detector['function'](df)
            
            detector['results'] = result
            return result
            
        except Exception as e:
            print(f"[!] {name} detection failed: {e}")
            import traceback
            traceback.print_exc()
            return pd.DataFrame()
    
    def run_all(self, df: pd.DataFrame, **kwargs) -> Dict[str, pd.DataFrame]:
        """Run all enabled detectors with smart baseline configuration."""
        baseline_csv = kwargs.get('baseline_csv')
        
        # Configure detectors based on baseline availability
        self.configure_for_baseline(baseline_csv)
        
        results = {}
        
        print(f"\n[+] Running detection on {len(df)} entries...")
        print("=" * 60)
        
        for name, detector in self.detectors.items():
            if not detector['enabled']:
                continue
            
            # Enhanced logging with baseline info
            baseline_note = " (baseline-enhanced)" if detector['baseline_enhanced'] and baseline_csv else ""
            fallback_note = " (fallback mode)" if name == 'suspicious_paths' and not baseline_csv else ""
            
            print(f"[🔍] {name.replace('_', ' ').title()}{baseline_note}{fallback_note}...")
            
            result = self.run_detector(name, df, **kwargs)
            results[name] = result
            
            count = len(result) if isinstance(result, pd.DataFrame) else 0
            if count > 0:
                print(f"    ✅ {count} findings")
            else:
                print(f"    ✅ No issues detected")
        
        print("=" * 60)
        return results
    
    def get_summary(self) -> pd.DataFrame:
        """Get enhanced summary with baseline information."""
        summary = []
        for name, detector in self.detectors.items():
            results = detector.get('results')
            count = len(results) if isinstance(results, pd.DataFrame) else 0
            
            # Enhanced description
            description = detector['description']
            if detector['baseline_enhanced']:
                description += " [Baseline-Enhanced]"
            
            summary.append({
                'Detector': name.replace('_', ' ').title(),
                'Description': description,
                'Findings': count,
                'Enabled': detector['enabled'],
                'Baseline Enhanced': detector['baseline_enhanced']
            })
        
        return pd.DataFrame(summary)
    
    def get_detection_recommendations(self, baseline_csv: str = None) -> list:
        """
        Provide recommendations for optimal detection configuration.
        """
        recommendations = []
        
        if not baseline_csv:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Create a baseline CSV from clean system',
                'benefit': 'Dramatically improves suspicious path detection accuracy'
            })
            recommendations.append({
                'priority': 'Medium', 
                'recommendation': 'Focus on visual_masquerading and unsigned_binaries',
                'benefit': 'These work well without baseline data'
            })
        else:
            recommendations.append({
                'priority': 'High',
                'recommendation': 'Enable both suspicious_paths AND baseline_comparison',
                'benefit': 'Comprehensive coverage with baseline-driven analysis'
            })
            recommendations.append({
                'priority': 'Medium',
                'recommendation': 'Consider running meta-PySAD analysis',
                'benefit': 'Combines all detection results for advanced analysis'
            })
        
        return recommendations
    
    def get_combined_findings(self, df_src: pd.DataFrame, results: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """Enhanced combined findings with suspicion level integration."""
        detector_indices = {}
        for detector_name, df_results in results.items():
            if isinstance(df_results, pd.DataFrame) and len(df_results) > 0:
                detector_indices[detector_name] = set(df_results.index)
        
        combined_findings = []
        
        for idx in df_src.index:
            detecting_methods = []
            detection_details = []
            max_suspicion_level = "Low"
            
            for detector_name, indices in detector_indices.items():
                if idx in indices:
                    detecting_methods.append(detector_name.replace('_', ' ').title())
                    
                    # Get detection details
                    detector_df = results[detector_name]
                    if 'detection_reason' in detector_df.columns:
                        reason = detector_df.loc[idx, 'detection_reason']
                        detection_details.append(f"{detector_name}: {reason}")
                    
                    # Track highest suspicion level
                    if 'suspicion_level' in detector_df.columns:
                        level = detector_df.loc[idx, 'suspicion_level']
                        if level == "Critical":
                            max_suspicion_level = "Critical"
                        elif level == "High" and max_suspicion_level not in ["Critical"]:
                            max_suspicion_level = "High"
                        elif level == "Medium-High" and max_suspicion_level not in ["Critical", "High"]:
                            max_suspicion_level = "Medium-High"
                        elif level == "Medium" and max_suspicion_level == "Low":
                            max_suspicion_level = "Medium"
            
            if len(detecting_methods) >= 1:
                row = df_src.loc[idx].copy()
                row['detection_methods'] = ' + '.join(detecting_methods)
                row['detection_count'] = len(detecting_methods)
                row['max_suspicion_level'] = max_suspicion_level
                row['all_detection_details'] = ' | '.join(detection_details)
                
                # Enhanced priority scoring with suspicion levels
                priority_score = 0
                method_names = [d.lower().replace(' ', '_') for d in detecting_methods]
                
                # Base scores by detector type
                if 'visual_masquerading' in method_names:
                    priority_score += 10
                if 'unsigned_binaries' in method_names:
                    priority_score += 8
                if 'suspicious_paths' in method_names:
                    priority_score += 6
                if 'hidden_characters' in method_names:
                    priority_score += 5
                if 'baseline_comparison' in method_names:
                    priority_score += 3
                if 'anomaly_detection' in method_names:
                    priority_score += 2
                
                # Bonus for multiple detections
                priority_score += len(detecting_methods) * 2
                
                # Suspicion level multiplier
                suspicion_multipliers = {
                    "Critical": 2.0,
                    "High": 1.5,
                    "Medium-High": 1.3,
                    "Medium": 1.0,
                    "Low": 0.8
                }
                priority_score *= suspicion_multipliers.get(max_suspicion_level, 1.0)
                
                row['priority_score'] = round(priority_score, 2)
                combined_findings.append(row)
        
        if combined_findings:
            df_combined = pd.DataFrame(combined_findings)
            df_combined = df_combined.sort_values(['priority_score', 'detection_count'], ascending=[False, False])
            return df_combined
        
        return pd.DataFrame()


# Updated convenience function
def run_all_detections(df: pd.DataFrame, baseline_csv: str = None, 
                      pysad_method: str = "hst", top_pct: float = 3.0) -> tuple:
    """
    Streamlined convenience function with baseline-focused detection.
    """
    print("[+] Initializing Baseline-Focused Detection Registry...")
    registry = DetectionRegistry()
    
    # Run all detections (registry automatically configures based on baseline)
    results = registry.run_all(df, 
                              baseline_csv=baseline_csv,
                              pysad_method=pysad_method,
                              top_pct=top_pct)
    
    return results, registry