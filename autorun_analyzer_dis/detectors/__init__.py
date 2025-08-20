"""
Detection Registry System - Central management for all detectors.
"""

import pandas as pd
from typing import Dict, Callable, Any, Optional

# Import all detectors
from .visual_masquerading import detect_visual_masquerading
from .unsigned_binaries import detect_unsigned_binaries
from .suspicious_paths import detect_suspicious_paths
from .hidden_characters import detect_hidden_characters
from .baseline_comparison import detect_baseline_deviations
from .anomaly_detection import detect_anomalies_pysad


class DetectionRegistry:
    """
    Central registry for all detection modules.
    Makes it easy to add new detectors and manage them.
    """
    
    def __init__(self):
        self.detectors = {}
        self._register_default_detectors()
    
    def _register_default_detectors(self):
        """Register all built-in detectors."""
        self.register('visual_masquerading', detect_visual_masquerading, 
                     "Visual masquerading using confusable characters", enabled=True)
        
        self.register('unsigned_binaries', detect_unsigned_binaries,
                     "Unsigned or unverified digital signatures", enabled=True)
        
        self.register('suspicious_paths', detect_suspicious_paths,
                     "Suspicious file paths and locations", enabled=True)
        
        self.register('hidden_characters', detect_hidden_characters,
                     "Hidden characters (NBSP, zero-width, control chars)", enabled=True)
        
        self.register('baseline_comparison', detect_baseline_deviations,
                     "Deviations from known-good baseline", enabled=False)  # Only enabled if baseline provided
        
        self.register('anomaly_detection', detect_anomalies_pysad,
                     "Statistical anomalies using PySAD", enabled=True)
    
    def register(self, name: str, detector_func: Callable, description: str = "", enabled: bool = True):
        """Register a new detection method."""
        self.detectors[name] = {
            'function': detector_func,
            'description': description,
            'enabled': enabled,
            'results': None
        }
    
    def enable(self, name: str):
        """Enable a detector."""
        if name in self.detectors:
            self.detectors[name]['enabled'] = True
    
    def disable(self, name: str):
        """Disable a detector."""
        if name in self.detectors:
            self.detectors[name]['enabled'] = False
    
    def run_detector(self, name: str, df: pd.DataFrame, **kwargs) -> pd.DataFrame:
        """Run a specific detector."""
        if name not in self.detectors:
            raise ValueError(f"Unknown detector: {name}")
        
        detector = self.detectors[name]
        if not detector['enabled']:
            return pd.DataFrame()
        
        try:
            # Handle different detector parameter requirements
            if name == 'baseline_comparison':
                baseline_csv = kwargs.get('baseline_csv')
                if not baseline_csv:
                    return pd.DataFrame()
                result = detector['function'](df, baseline_csv)
            elif name == 'anomaly_detection':
                method = kwargs.get('pysad_method', 'hst')
                top_pct = kwargs.get('top_pct', 3.0)
                result = detector['function'](df, method, top_pct)
            else:
                result = detector['function'](df)
            
            detector['results'] = result
            return result
            
        except Exception as e:
            print(f"[!] {name} detection failed: {e}")
            return pd.DataFrame()
    
    def run_all(self, df: pd.DataFrame, **kwargs) -> Dict[str, pd.DataFrame]:
        """Run all enabled detectors on the DataFrame."""
        results = {}
        
        for name, detector in self.detectors.items():
            if not detector['enabled']:
                continue
            
            print(f"[+] Running {name} detection...")
            result = self.run_detector(name, df, **kwargs)
            results[name] = result
            
            count = len(result) if isinstance(result, pd.DataFrame) else 0
            print(f"    -> {count} findings")
        
        return results
    
    def get_summary(self) -> pd.DataFrame:
        """Get summary of all detection results."""
        summary = []
        for name, detector in self.detectors.items():
            results = detector.get('results')
            count = len(results) if isinstance(results, pd.DataFrame) else 0
            
            summary.append({
                'Detector': name.replace('_', ' ').title(),
                'Description': detector['description'],
                'Findings': count,
                'Enabled': detector['enabled']
            })
        
        return pd.DataFrame(summary)
    
    def get_combined_findings(self, df_src: pd.DataFrame, results: Dict[str, pd.DataFrame]) -> pd.DataFrame:
        """Create combined findings showing items detected by multiple methods."""
        # Get indices for each detector
        detector_indices = {}
        for detector_name, df_results in results.items():
            if isinstance(df_results, pd.DataFrame) and len(df_results) > 0:
                detector_indices[detector_name] = set(df_results.index)
        
        # Find items detected by multiple methods
        combined_findings = []
        
        for idx in df_src.index:
            detecting_methods = []
            detection_details = []
            
            for detector_name, indices in detector_indices.items():
                if idx in indices:
                    detecting_methods.append(detector_name.replace('_', ' ').title())
                    
                    # Get the detection reason if available
                    detector_df = results[detector_name]
                    if 'detection_reason' in detector_df.columns:
                        reason = detector_df.loc[idx, 'detection_reason']
                        detection_details.append(f"{detector_name}: {reason}")
            
            # Only include items detected by 2+ methods for high priority
            if len(detecting_methods) >= 1:  # Change to 2 if you only want overlaps
                row = df_src.loc[idx].copy()
                row['detection_methods'] = ' + '.join(detecting_methods)
                row['detection_count'] = len(detecting_methods)
                row['all_detection_details'] = ' | '.join(detection_details)
                
                # Priority scoring
                priority_score = 0
                if 'visual_masquerading' in [d.lower().replace(' ', '_') for d in detecting_methods]:
                    priority_score += 10  # Visual masquerading is high priority
                if 'unsigned_binaries' in [d.lower().replace(' ', '_') for d in detecting_methods]:
                    priority_score += 8   # Unsigned is high priority
                if 'suspicious_paths' in [d.lower().replace(' ', '_') for d in detecting_methods]:
                    priority_score += 6   # Suspicious paths are medium-high
                if 'hidden_characters' in [d.lower().replace(' ', '_') for d in detecting_methods]:
                    priority_score += 5   # Hidden chars are medium
                if 'baseline_comparison' in [d.lower().replace(' ', '_') for d in detecting_methods]:
                    priority_score += 3   # Baseline is medium
                if 'anomaly_detection' in [d.lower().replace(' ', '_') for d in detecting_methods]:
                    priority_score += 2   # Anomaly is lower priority
                
                row['priority_score'] = priority_score
                combined_findings.append(row)
        
        if combined_findings:
            df_combined = pd.DataFrame(combined_findings)
            df_combined = df_combined.sort_values(['priority_score', 'detection_count'], ascending=[False, False])
            return df_combined
        
        return pd.DataFrame()


# Convenience function for easy usage
def run_all_detections(df: pd.DataFrame, baseline_csv: str = None, 
                      pysad_method: str = "hst", top_pct: float = 3.0) -> Dict[str, pd.DataFrame]:
    """
    Convenience function to run all detections with standard parameters.
    
    Args:
        df: Input DataFrame
        baseline_csv: Optional path to baseline CSV
        pysad_method: PySAD method ('hst' or 'loda')
        top_pct: Percentage for PySAD top scores
        
    Returns:
        Dictionary of results from all detectors
    """
    registry = DetectionRegistry()
    
    # Enable baseline comparison if baseline CSV is provided
    if baseline_csv:
        registry.enable('baseline_comparison')
    
    # Run all detections
    results = registry.run_all(df, 
                              baseline_csv=baseline_csv,
                              pysad_method=pysad_method,
                              top_pct=top_pct)
    
    return results, registry