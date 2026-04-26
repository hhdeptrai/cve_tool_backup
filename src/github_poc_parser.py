"""GitHub PoC parser for cross-referencing CVEs with GitHub repositories."""

import os
import re
from pathlib import Path
from typing import Set


class GitHubPoCEngine:
    """Engine for cross-referencing CVEs with GitHub PoC repositories like nomi-sec/PoC-in-GitHub."""
    
    def __init__(self, poc_repo_path: str):
        """
        Initialize the cross-reference engine.
        
        Args:
            poc_repo_path: Path to the cloned PoC repository (e.g., PoC-in-GitHub)
        """
        self.poc_repo_path = Path(poc_repo_path)
        self._cve_cache: Set[str] = set()
        self._load_pocs()
    
    def _load_pocs(self) -> None:
        """Scan the repository directory for CVE IDs in file and folder names."""
        if not self.poc_repo_path.exists() or not self.poc_repo_path.is_dir():
            raise FileNotFoundError(
                f"GitHub PoC repository directory not found: {self.poc_repo_path}"
            )
        
        # Regex to match standard CVE format
        cve_pattern = re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE)
        
        # Traverse the directory tree
        try:
            for root, dirs, files in os.walk(self.poc_repo_path):
                for name in dirs + files:
                    match = cve_pattern.search(name)
                    if match:
                        self._cve_cache.add(match.group(0).upper())
        except Exception as e:
            raise RuntimeError(f"Failed to parse GitHub PoC repository: {e}")
            
    def has_poc(self, cve_id: str) -> bool:
        """
        Check if a PoC exists for the given CVE ID.
        
        Args:
            cve_id: CVE identifier (e.g., CVE-2021-12345)
            
        Returns:
            True if a PoC is found in the repository, False otherwise.
        """
        return cve_id.upper() in self._cve_cache
