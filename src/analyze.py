#!/usr/bin/env python3
"""
InsiderThreatAnalysis - Detect malicious developer behavior using Git/Time tracking heuristics
"""

import argparse
import csv
from datetime import datetime, time
import os
import re
import yaml
from git import Repo
import requests
from collections import defaultdict

# Constants
CONFIG_FILE = "config.yaml"
DEFAULT_RISK_THRESHOLD = 50
MAX_SCORE = 100

class InsiderThreatAnalyzer:
    def __init__(self, config):
        self.config = config
        self.developer_metrics = defaultdict(dict)
        
    def analyze_git_repo(self, since_date):
        """Extract commit history and calculate metrics"""
        repo = Repo(self.config["git_repo"])
        
        for commit in repo.iter_commits(since=since_date):
            dev = commit.author.name
            dt = commit.authored_datetime
            stats = commit.stats.total
            
            # Track metrics per developer
            if dev not in self.developer_metrics:
                self.developer_metrics[dev] = {
                    "commits": 0,
                    "loc_added": 0,
                    "loc_deleted": 0,
                    "off_hour_commits": 0,
                    "rapid_commits": 0,
                    "last_commit_time": None
                }
                
            metrics = self.developer_metrics[dev]
            metrics["commits"] += 1
            metrics["loc_added"] += stats["insertions"]
            metrics["loc_deleted"] += stats["deletions"]
            
            # Check for off-hour commits (10PM-6AM)
            if dt.hour < 6 or dt.hour >= 22:
                metrics["off_hour_commits"] += 1
                
            # Detect rapid commits (<5 mins apart)
            if metrics["last_commit_time"]:
                delta = dt - metrics["last_commit_time"]
                if delta.total_seconds() < 300:  # 5 minutes
                    metrics["rapid_commits"] += 1
                    
            metrics["last_commit_time"] = dt

    def calculate_risk_scores(self):
        """Compute normalized risk scores (0-100) for each developer"""
        results = []
        
        for dev, metrics in self.developer_metrics.items():
            score = 0
            
            # Code Churn (30% weight)
            avg_loc_per_day = metrics["loc_added"] / max(1, (metrics["commits"]/5))  # Assume 5 commits/day avg
            if avg_loc_per_day > 500:
                score += 20 * 0.3
            
            # Off-hour commits (25% weight)
            if metrics["off_hour_commits"] > 5:
                score += 25 * 0.25
                
            # Rapid commits (15% weight)
            if metrics["rapid_commits"] > 3:
                score += 15 * 0.15
                
            # Normalize to 0-100 scale
            normalized_score = min(int((score / MAX_SCORE) * 100), 100)
            
            results.append({
                "developer": dev,
                "score": normalized_score,
                "loc_per_day": int(avg_loc_per_day),
                "off_hour_commits": metrics["off_hour_commits"],
                "rapid_commits": metrics["rapid_commits"]
            })
            
        return sorted(results, key=lambda x: x["score"], reverse=True)

    def generate_report(self, results, threshold):
        """Generate CSV and console output"""
        high_risk = [r for r in results if r["score"] >= threshold]
        
        # Console output
        print(f"\n{' Developer Risk Analysis ':=^50}")
        for dev in high_risk:
            print(f"\n[{'HIGH' if dev['score'] > 75 else 'MEDIUM'} RISK] {dev['developer']} (Score: {dev['score']}/100)")
            print(f"- Avg LOC/day: {dev['loc_per_day']} | Off-hour commits: {dev['off_hour_commits']}")
            
        # CSV report
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"risk_scores_{timestamp}.csv"
        
        with open(filename, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=results[0].keys())
            writer.writeheader()
            writer.writerows(results)
            
        print(f"\nReport saved to {filename}")

    def send_alerts(self, high_risk_devs):
        """Send Slack alerts for high-risk developers"""
        if not self.config.get("slack_webhook"):
            return
            
        message = {"text": "🚨 Insider Threat Alert"}
        attachments = []
        
        for dev in high_risk_devs:
            attachments.append({
                "color": "#ff0000" if dev["score"] > 75 else "#ffcc00",
                "title": f"{dev['developer']} (Score: {dev['score']}/100)",
                "fields": [
                    {"title": "LOC/day", "value": dev["loc_per_day"], "short": True},
                    {"title": "Off-hour commits", "value": dev["off_hour_commits"], "short": True}
                ]
            })
            
        message["attachments"] = attachments
        requests.post(self.config["slack_webhook"], json=message)

def load_config():
    """Load configuration from YAML file"""
    if not os.path.exists(CONFIG_FILE):
        raise FileNotFoundError(f"Config file {CONFIG_FILE} not found")
        
    with open(CONFIG_FILE) as f:
        return yaml.safe_load(f)

def main():
    parser = argparse.ArgumentParser(description="Insider Threat Risk Analyzer")
    parser.add_argument("--since", help="Start date (YYYY-MM-DD)", default="30 days ago")
    parser.add_argument("--risk-threshold", type=int, default=DEFAULT_RISK_THRESHOLD,
                       help=f"Risk score threshold (default: {DEFAULT_RISK_THRESHOLD})")
    
    args = parser.parse_args()
    
    try:
        config = load_config()
        analyzer = InsiderThreatAnalyzer(config)
        
        print(f"Analyzing repository: {config['git_repo']}")
        analyzer.analyze_git_repo(args.since)
        
        results = analyzer.calculate_risk_scores()
        analyzer.generate_report(results, args.risk_threshold)
        
        high_risk = [r for r in results if r["score"] >= args.risk_threshold]
        if high_risk:
            analyzer.send_alerts(high_risk)
            
    except Exception as e:
        print(f"Error: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()