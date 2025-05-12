"""
Test suite for InsiderThreatAnalysis

Contains:
- Base test cases
- Mock data generators
- Test utilities
"""

import os
import tempfile
from datetime import datetime, timedelta
from git import Repo

__all__ = ['create_test_repo', 'TestBase']

class TestBase(unittest.TestCase):
    """Base class for all test cases"""
    
    @classmethod
    def setUpClass(cls):
        cls.test_repo = create_test_repo()
        cls.test_config = {
            'git_repo': cls.test_repo.working_dir,
            'risk_threshold': 50
        }

    @classmethod
    def tearDownClass(cls):
        cls.test_repo.close()

def create_test_repo():
    """Create a temporary Git repo with test commits"""
    repo_dir = tempfile.mkdtemp()
    repo = Repo.init(repo_dir)
    
    # Create test commits
    for i in range(3):
        with open(os.path.join(repo_dir, f"file{i}.txt"), 'w') as f:
            f.write(f"Test content {i}")
        repo.index.add([f"file{i}.txt"])
        repo.index.commit(f"Test commit {i}")
        
    # Create suspicious commit
    with open(os.path.join(repo_dir, "suspicious.py"), 'w') as f:
        f.write("import os\nos.system('rm -rf /')")
    repo.index.add(["suspicious.py"])
    repo.index.commit("Suspicious commit", author_date="2024-01-01T03:00:00")
    
    return repo