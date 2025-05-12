import unittest
from src.analyzer import InsiderThreatAnalyzer
import os

class TestAnalysis(unittest.TestCase):
    def setUp(self):
        self.config = {
            "git_repo": ".",
            "risk_threshold": 50
        }
        self.analyzer = InsiderThreatAnalyzer(self.config)
        
    def test_score_calculation(self):
        test_metrics = {
            "commits": 10,
            "loc_added": 6000,  # 600/day
            "off_hour_commits": 6,
            "rapid_commits": 4
        }
        score = self.analyzer.calculate_individual_score(test_metrics)
        self.assertGreaterEqual(score, 70)
        
if __name__ == "__main__":
    unittest.main()