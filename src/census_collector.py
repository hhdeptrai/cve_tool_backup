"""Census collector for automated CVE data collection."""

import time
import threading
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from src.models import CVEData, Ecosystem, CWECategory
from src.validator import DataValidator
from src.exploitdb_parser import CrossReferenceEngine
from src.github_poc_parser import GitHubPoCEngine
from src.github_advisory_client import GitHubAdvisoryClient
from src.cwe_tree import CWETreeEngine


class CensusCollector:
    """
    Orchestrates CVE data collection from GitHub Advisory Database.
    
    NEW ARCHITECTURE:
    - Collects ALL CVEs from web ecosystems (no CWE filtering at API level)
    - Labels priority CWEs post-collection
    - Ensures 100% coverage of web vulnerabilities
    - Uses concurrent processing for validation and cross-referencing
    
    Integrates:
    - GitHubAdvisoryClient for API queries
    - DataValidator for data validation
    - CrossReferenceEngine for Exploit-DB lookup
    """
    
    
    def __init__(
        self,
        github_token: Optional[str] = None,
        exploitdb_csv_path: Optional[str] = None,
        github_poc_path: Optional[str] = None,
        batch_size: int = 100,
        max_workers: int = 4
    ):
        """
        Initialize census collector.
        
        Args:
            github_token: GitHub personal access token
            exploitdb_csv_path: Path to Exploit-DB files_exploits.csv
            github_poc_path: Path to GitHub PoC repository (e.g., PoC-in-GitHub)
            batch_size: Number of CVEs to collect per API request (default: 100)
            max_workers: Number of threads for concurrent CVE processing (default: 4)
        """
        self.github_client = GitHubAdvisoryClient(token=github_token, batch_size=batch_size)
        self.validator = DataValidator()
        self.max_workers = max_workers
        self._lock = threading.Lock()
        
        # Load the Hierarchical CWE Tree (will use cached JSON if it exists)
        self.cwe_tree = CWETreeEngine()
        
        # Initialize cross-reference engine if path provided
        self.cross_ref_engine: Optional[CrossReferenceEngine] = None
        if exploitdb_csv_path:
            try:
                self.cross_ref_engine = CrossReferenceEngine(exploitdb_csv_path)
            except Exception as e:
                print(f"Warning: Failed to initialize CrossReferenceEngine: {e}")
                print("Continuing without Exploit-DB cross-referencing")

        # Initialize GitHub PoC engine if path provided
        self.github_poc_engine: Optional[GitHubPoCEngine] = None
        if github_poc_path:
            try:
                self.github_poc_engine = GitHubPoCEngine(github_poc_path)
            except Exception as e:
                print(f"Warning: Failed to initialize GitHubPoCEngine: {e}")
                print("Continuing without GitHub PoC cross-referencing")
        
        
        # Statistics
        self.stats = {
            'total_collected': 0,
            'validated': 0,
            'validation_failed': 0,
            'priority_cves': 0,
            'exploits_found': 0,
            'github_pocs_found': 0,
            'errors': []
        }
    
    def _process_single_cve(self, cve: CVEData) -> Optional[CVEData]:
        """
        Process a single CVE: label priority CWE, validate, cross-reference.
        
        Thread-safe method used by ThreadPoolExecutor.
        
        Args:
            cve: CVEData object to process
            
        Returns:
            The processed CVEData if valid, None if validation failed
        """
        self._label_priority_cwe(cve)
        if not self._validate_cve(cve):
            return None
        self._cross_reference_exploit(cve)
        self._cross_reference_github_poc(cve)
        return cve
    
    def collect_cves(
        self,
        start_year: int,
        end_year: int,
        ecosystems: List[str],
        max_retries: int = 3
    ) -> List[CVEData]:
        """
        Collect ALL CVEs from GitHub Advisory Database.
        
        Uses ThreadPoolExecutor for concurrent validation and cross-referencing.
        
        Args:
            start_year: Starting year (2015-2025)
            end_year: Ending year (2015-2025)
            ecosystems: List of package ecosystems to include
            max_retries: Maximum retry attempts for failed operations (default: 3)
            
        Returns:
            List of validated CVEData objects with is_priority_cwe labeled
        """
        # Reset statistics
        self.stats = {
            'total_collected': 0,
            'validated': 0,
            'validation_failed': 0,
            'priority_cves': 0,
            'exploits_found': 0,
            'errors': []
        }
        
        print(f"\n=== Starting CVE Census Collection ===")
        print(f"Year range: {start_year}-{end_year}")
        print(f"Ecosystems: {', '.join(ecosystems)}")
        print(f"Strategy: Collect ALL CVEs, label priority CWEs post-collection")
        print(f"Batch size: {self.github_client.batch_size}")
        print(f"Workers: {self.max_workers}")
        print()
        
        # --- STATE MANAGEMENT ---
        state_file = "census_state.json"
        import json
        import os
        
        cursor = None
        state_key = f"{start_year}-{end_year}-{'-'.join(sorted(ecosystems))}"
        
        # Load state if exists
        if os.path.exists(state_file):
            try:
                with open(state_file, 'r') as f:
                    state = json.load(f)
                    if state.get('key') == state_key:
                        cursor = state.get('cursor')
                        print(f"RESUMING collection from saved state (cursor: {cursor[:20]}...)")
            except Exception as e:
                print(f"Warning: Failed to load state file: {e}")
        
        # Collect ALL CVEs from GitHub (NO CWE filtering)
        validated_cves = []
        
        try:
            generator = self._collect_with_retry(
                start_year=start_year,
                end_year=end_year,
                ecosystems=ecosystems,
                max_retries=max_retries,
                cursor=cursor
            )
            
            for batch_cves, next_cursor in generator:
                if not batch_cves and not next_cursor:
                    continue
                    
                self.stats['total_collected'] += len(batch_cves)
                
                # Process batch concurrently using ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                    futures = {
                        executor.submit(self._process_single_cve, cve): cve
                        for cve in batch_cves
                    }
                    for future in as_completed(futures):
                        try:
                            result = future.result()
                            if result is not None:
                                validated_cves.append(result)
                        except Exception as e:
                            cve = futures[future]
                            error_msg = f"Processing failed for {cve.cve_id}: {e}"
                            print(f"Warning: {error_msg}")
                            with self._lock:
                                self.stats['errors'].append(error_msg)
                
                # Save state
                if next_cursor:
                    try:
                        with open(state_file, 'w') as f:
                            json.dump({
                                'key': state_key,
                                'cursor': next_cursor,
                                'updated_at': str(time.time())
                            }, f)
                    except Exception as e:
                        print(f"Warning: Failed to save state: {e}")
                        
        except Exception as e:
            print(f"Collection failed: {e}")
            self.stats['errors'].append(str(e))
        
        # Cleanup state file on completion
        if os.path.exists(state_file):
            try:
                os.remove(state_file)
                print("Collection complete. State file removed.")
            except:
                pass
        
        print(f"\nCollected {self.stats['total_collected']} CVEs from GitHub Advisory")
        
        # Print summary
        self._print_summary()
        
        return validated_cves
    
    def _collect_with_retry(
        self,
        start_year: int,
        end_year: int,
        ecosystems: List[str],
        max_retries: int,
        cursor: Optional[str] = None
    ):
        """
        Collect CVEs with exponential backoff retry logic.
        
        Args:
            start_year: Starting year
            end_year: Ending year
            ecosystems: List of ecosystems
            max_retries: Maximum retry attempts
            cursor: Optional starting cursor for resume
            
        Yields:
            Tuple of (batch_results, next_cursor)
        """
        for attempt in range(max_retries):
            try:
                # Use the generator
                generator = self.github_client.collect_cves(
                    start_year=start_year,
                    end_year=end_year,
                    ecosystems=ecosystems,
                    cursor=cursor
                    # NO cwe_filters parameter - collect ALL CVEs
                )
                
                # Verify generator works by yielding first item
                for batch, next_cursor in generator:
                    yield batch, next_cursor
                    
                    # Update local cursor in case we need to retry from THIS point
                    cursor = next_cursor
                    
                return
                
            except Exception as e:
                error_msg = f"Attempt {attempt + 1}/{max_retries} failed: {e}"
                print(f"Error: {error_msg}")
                self.stats['errors'].append(error_msg)
                
                if attempt < max_retries - 1:
                    # Exponential backoff: 5s, 10s, 20s
                    wait_time = 5 * (2 ** attempt)
                    print(f"Retrying in {wait_time} seconds (cursor: {cursor})...")
                    time.sleep(wait_time)
                else:
                    print("Max retries reached. Returning empty result.")
                    return
    
    def _label_priority_cwe(self, cve: CVEData) -> None:
        """
        Label CVE with is_priority_cwe using Hierarchical CWE Tree Traversal.
        
        Updates cve.is_priority_cwe and cve.owasp_category in place.
        
        Args:
            cve: CVEData object to label
        """
        matched_category = None
        
        for cwe_id in cve.cwe_ids:
            owasp_category = self.cwe_tree.find_owasp_root_category(cwe_id)
            if owasp_category:
                matched_category = owasp_category
                break
                
        if matched_category:
            cve.is_priority_cwe = True
            cve.owasp_category = matched_category  # Update to standard root category Name
            with self._lock:
                self.stats['priority_cves'] += 1
        else:
            cve.is_priority_cwe = False
    
    def _validate_cve(self, cve: CVEData) -> bool:
        """
        Validate CVE data using DataValidator.
        
        Args:
            cve: CVEData object to validate
            
        Returns:
            True if valid, False otherwise
        """
        # Convert CVEData to dict for validation
        cve_dict = {
            'cve_id': cve.cve_id,
            'cvss_base_score': cve.cvss_base_score,
            'cvss_exploitability_score': cve.cvss_exploitability_score,
            'publication_year': cve.publication_year,
            'ecosystem': cve.ecosystem,
            'primary_cwe_id': cve.primary_cwe_id
        }
        
        result = self.validator.validate_cve(cve_dict)
        
        if result.is_valid:
            with self._lock:
                self.stats['validated'] += 1
            return True
        else:
            error_msg = f"Validation failed for {cve.cve_id}: {', '.join(result.errors)}"
            print(f"Warning: {error_msg}")
            with self._lock:
                self.stats['validation_failed'] += 1
                self.stats['errors'].append(error_msg)
            return False
    
    def _cross_reference_exploit(self, cve: CVEData) -> None:
        """
        Cross-reference CVE with Exploit-DB.
        
        Updates cve.exploit_available and cve.exploit_db_id in place.
        
        Args:
            cve: CVEData object to cross-reference
        """
        if not self.cross_ref_engine:
            # No cross-reference engine available
            cve.exploit_available = False
            cve.exploit_db_id = None
            return
        
        try:
            exploit = self.cross_ref_engine.find_exploit(
                cve_id=cve.cve_id,
                package_name=cve.affected_package,
                vulnerability_type=cve.owasp_category
            )
            
            if exploit:
                cve.exploit_available = True
                cve.exploit_db_id = exploit.exploit_db_id
                with self._lock:
                    self.stats['exploits_found'] += 1
            else:
                cve.exploit_available = False
                cve.exploit_db_id = None
        
        except Exception as e:
            # Log error but continue processing
            error_msg = f"Exploit lookup failed for {cve.cve_id}: {e}"
            print(f"Warning: {error_msg}")
            with self._lock:
                self.stats['errors'].append(error_msg)
            cve.exploit_available = False
            cve.exploit_db_id = None

    def _cross_reference_github_poc(self, cve: CVEData) -> None:
        """
        Cross-reference CVE with GitHub PoC repositories.
        
        Updates cve.has_github_poc in place.
        
        Args:
            cve: CVEData object to cross-reference
        """
        if not self.github_poc_engine:
            cve.has_github_poc = False
            return
            
        try:
            if self.github_poc_engine.has_poc(cve.cve_id):
                cve.has_github_poc = True
                with self._lock:
                    self.stats['github_pocs_found'] = self.stats.get('github_pocs_found', 0) + 1
            else:
                cve.has_github_poc = False
        except Exception as e:
            error_msg = f"GitHub PoC lookup failed for {cve.cve_id}: {e}"
            print(f"Warning: {error_msg}")
            with self._lock:
                self.stats['errors'].append(error_msg)
            cve.has_github_poc = False
    
    def _print_summary(self) -> None:
        """Print collection summary statistics."""
        print("\n=== Census Collection Summary ===")
        print(f"Total collected: {self.stats['total_collected']}")
        print(f"Validated: {self.stats['validated']}")
        print(f"Priority CVEs (labeled): {self.stats['priority_cves']}")
        print(f"Validation failed: {self.stats['validation_failed']}")
        print(f"Exploits found: {self.stats['exploits_found']}")
        print(f"GitHub PoCs found: {self.stats.get('github_pocs_found', 0)}")
        
        if self.stats['validated'] > 0:
            priority_rate = (self.stats['priority_cves'] / self.stats['validated']) * 100
            exploit_rate = (self.stats['exploits_found'] / self.stats['validated']) * 100
            poc_rate = (self.stats.get('github_pocs_found', 0) / self.stats['validated']) * 100
            print(f"Priority CVE rate: {priority_rate:.1f}%")
            print(f"Exploit availability rate: {exploit_rate:.1f}%")
            print(f"GitHub PoC availability rate: {poc_rate:.1f}%")
        
        if self.stats['errors']:
            print(f"\nErrors encountered: {len(self.stats['errors'])}")
            print("First 5 errors:")
            for error in self.stats['errors'][:5]:
                print(f"  - {error}")
        
        print("=" * 35)
    
    def get_statistics(self) -> dict:
        """
        Get collection statistics.
        
        Returns:
            Dictionary containing collection statistics
        """
        return self.stats.copy()
