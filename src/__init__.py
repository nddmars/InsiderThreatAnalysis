"""
InsiderThreatAnalysis - Core package for detecting malicious developer behavior

Exposes:
- InsiderThreatAnalyzer: Main analysis class
- analyze_repository: Convenience function
- DEFAULT_CONFIG: Default configuration values
"""

from .analyzer import InsiderThreatAnalyzer

__version__ = "1.0.0"
__all__ = ['InsiderThreatAnalyzer', 'analyze_repository', 'DEFAULT_CONFIG']

DEFAULT_CONFIG = {
    'git_repo': '.',
    'risk_threshold': 50,
    'work_hours': {'start': 9, 'end': 17},
    'timezone': 'UTC'
}

def analyze_repository(repo_path, since="30 days ago", config=None):
    """Convenience function for quick analysis"""
    cfg = DEFAULT_CONFIG | (config or {})
    cfg['git_repo'] = repo_path
    analyzer = InsiderThreatAnalyzer(cfg)
    analyzer.analyze_git_repo(since)
    return analyzer.calculate_risk_scores()