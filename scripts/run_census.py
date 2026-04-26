#!/usr/bin/env python3
"""
Automated census orchestration script for CVE data collection.

This script orchestrates the complete census collection workflow:
1. Processes all configured ecosystems sequentially
2. Collects ALL CVEs (no CWE filtering at API level)
3. Labels priority CWEs automatically during collection
4. Cross-references with Exploit-DB automatically
5. Stores CVEs in the database
6. Generates summary report with total CVEs, priority CVEs, exploits found, and errors
7. Implements error logging and continuation on failures

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5
"""

import sys
import os
import logging
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Any

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import Config
from src.census_collector import CensusCollector
from src.database import db_manager, CVERepository
from src.models import CVEData


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('logs/census_run.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


class CensusOrchestrator:
    """
    Orchestrates automated census collection across all ecosystems.
    
    NEW ARCHITECTURE:
    - Collects ALL CVEs from web ecosystems (no CWE filtering)
    - Labels priority CWEs post-collection
    - Ensures 100% coverage of web vulnerabilities
    """
    
    def __init__(
        self,
        github_token: str,
        exploitdb_csv_path: str,
        start_year: int,
        end_year: int,
        ecosystems: List[str],
        batch_size: int = 100
    ):
        """
        Initialize census orchestrator.
        
        Args:
            github_token: GitHub personal access token
            exploitdb_csv_path: Path to Exploit-DB files_exploits.csv
            start_year: Starting year for collection (2015-2025)
            end_year: Ending year for collection (2015-2025)
            ecosystems: List of ecosystems to process
            batch_size: Number of CVEs per API request (default: 100)
        """
        self.github_token = github_token
        self.exploitdb_csv_path = exploitdb_csv_path
        self.start_year = start_year
        self.end_year = end_year
        self.ecosystems = ecosystems
        self.batch_size = batch_size
        
        # Initialize database
        self.repository = CVERepository(db_manager)
        
        # Summary statistics
        self.summary = {
            'total_cves_collected': 0,
            'total_priority_cves': 0,
            'total_exploits_found': 0,
            'total_stored': 0,
            'total_duplicates': 0,
            'total_errors': 0,
            'by_ecosystem': {},
            'errors': []
        }
    
    def run(self) -> Dict[str, Any]:
        """
        Execute automated census collection.
        
        Processes all configured ecosystems sequentially, collecting ALL CVEs,
        labeling priority CWEs, cross-referencing with Exploit-DB, and storing
        in the database.
        
        Returns:
            Summary report dictionary
        """
        logger.info("=" * 70)
        logger.info("AUTOMATED CENSUS COLLECTION - NEW ARCHITECTURE")
        logger.info("=" * 70)
        logger.info(f"Year range: {self.start_year}-{self.end_year}")
        logger.info(f"Ecosystems: {', '.join(self.ecosystems)}")
        logger.info(f"Strategy: Collect ALL CVEs, label priority CWEs post-collection")
        logger.info(f"Batch size: {self.batch_size}")
        logger.info("=" * 70)
        
        # Process each ecosystem sequentially
        for ecosystem in self.ecosystems:
            try:
                self._process_ecosystem(ecosystem)
            except Exception as e:
                # Log error and continue with next ecosystem
                error_msg = f"Failed to process ecosystem {ecosystem}: {e}"
                logger.error(error_msg)
                self.summary['errors'].append(error_msg)
                self.summary['total_errors'] += 1
                continue
        
        # Generate and display summary report
        self._generate_summary_report()
        
        return self.summary
    
    def _process_ecosystem(self, ecosystem: str) -> None:
        """
        Process a single ecosystem.
        
        Args:
            ecosystem: Ecosystem name (npm, maven, pip, composer, go, rubygems)
        """
        logger.info("")
        logger.info("=" * 70)
        logger.info(f"Processing ecosystem: {ecosystem}")
        logger.info("=" * 70)
        
        # Initialize collector for this ecosystem
        collector = CensusCollector(
            github_token=self.github_token,
            exploitdb_csv_path=self.exploitdb_csv_path,
            batch_size=self.batch_size
        )
        
        # Collect CVEs (ALL CVEs, no CWE filtering)
        try:
            cves = collector.collect_cves(
                start_year=self.start_year,
                end_year=self.end_year,
                ecosystems=[ecosystem],
                max_retries=3
            )
            
            logger.info(f"Collected {len(cves)} CVEs from {ecosystem}")
            
            # Store CVEs in database
            stored_count = 0
            duplicate_count = 0
            priority_count = 0
            exploit_count = 0
            
            for cve in cves:
                try:
                    # Track priority CVEs
                    if cve.is_priority_cwe:
                        priority_count += 1
                    
                    # Track exploits
                    if cve.exploit_available:
                        exploit_count += 1
                    
                    # Store in database
                    if self.repository.insert_cve(cve):
                        stored_count += 1
                    else:
                        duplicate_count += 1
                
                except Exception as e:
                    # Log error and continue with next CVE
                    error_msg = f"Failed to store CVE {cve.cve_id}: {e}"
                    logger.error(error_msg)
                    self.summary['errors'].append(error_msg)
                    self.summary['total_errors'] += 1
                    continue
            
            # Update summary statistics
            self.summary['total_cves_collected'] += len(cves)
            self.summary['total_priority_cves'] += priority_count
            self.summary['total_exploits_found'] += exploit_count
            self.summary['total_stored'] += stored_count
            self.summary['total_duplicates'] += duplicate_count
            
            # Track per-ecosystem statistics
            self.summary['by_ecosystem'][ecosystem] = {
                'collected': len(cves),
                'priority_cves': priority_count,
                'exploits_found': exploit_count,
                'stored': stored_count,
                'duplicates': duplicate_count
            }
            
            # Get collector statistics for errors
            collector_stats = collector.get_statistics()
            if collector_stats['errors']:
                self.summary['errors'].extend(collector_stats['errors'])
                self.summary['total_errors'] += len(collector_stats['errors'])
            
            logger.info(f"Stored {stored_count} new CVEs from {ecosystem}")
            logger.info(f"Found {duplicate_count} duplicates")
            logger.info(f"Priority CVEs: {priority_count}")
            logger.info(f"Exploits found: {exploit_count}")
        
        except Exception as e:
            # Log error and re-raise to be caught by run()
            error_msg = f"Collection failed for {ecosystem}: {e}"
            logger.error(error_msg)
            raise
    
    def _generate_summary_report(self) -> None:
        """Generate and display summary report."""
        logger.info("")
        logger.info("=" * 70)
        logger.info("CENSUS COLLECTION SUMMARY REPORT")
        logger.info("=" * 70)
        logger.info("")
        logger.info("OVERALL STATISTICS:")
        logger.info(f"  Total CVEs collected: {self.summary['total_cves_collected']}")
        logger.info(f"  Priority CVEs (labeled): {self.summary['total_priority_cves']}")
        logger.info(f"  Exploits found: {self.summary['total_exploits_found']}")
        logger.info(f"  New CVEs stored: {self.summary['total_stored']}")
        logger.info(f"  Duplicates skipped: {self.summary['total_duplicates']}")
        logger.info(f"  Errors encountered: {self.summary['total_errors']}")
        
        # Calculate percentages
        if self.summary['total_cves_collected'] > 0:
            priority_rate = (self.summary['total_priority_cves'] / self.summary['total_cves_collected']) * 100
            exploit_rate = (self.summary['total_exploits_found'] / self.summary['total_cves_collected']) * 100
            logger.info(f"  Priority CVE rate: {priority_rate:.1f}%")
            logger.info(f"  Exploit availability rate: {exploit_rate:.1f}%")
        
        # Per-ecosystem breakdown
        if self.summary['by_ecosystem']:
            logger.info("")
            logger.info("BY ECOSYSTEM:")
            for ecosystem, stats in self.summary['by_ecosystem'].items():
                logger.info(f"  {ecosystem}:")
                logger.info(f"    Collected: {stats['collected']}")
                logger.info(f"    Priority CVEs: {stats['priority_cves']}")
                logger.info(f"    Exploits: {stats['exploits_found']}")
                logger.info(f"    Stored: {stats['stored']}")
                logger.info(f"    Duplicates: {stats['duplicates']}")
        
        # Error summary
        if self.summary['errors']:
            logger.info("")
            logger.info(f"ERRORS ({len(self.summary['errors'])} total):")
            logger.info("  First 10 errors:")
            for error in self.summary['errors'][:10]:
                logger.info(f"    - {error}")
            
            if len(self.summary['errors']) > 10:
                logger.info(f"    ... and {len(self.summary['errors']) - 10} more errors")
        
        logger.info("")
        logger.info("=" * 70)
        logger.info("CENSUS COLLECTION COMPLETE")
        logger.info("=" * 70)


def main():
    """Main entry point for census orchestration."""
    # Validate configuration
    if not Config.GITHUB_TOKEN:
        logger.error("GITHUB_TOKEN not set in environment")
        logger.error("Please set GITHUB_TOKEN in .env file")
        return 1
    
    # Check for Exploit-DB CSV
    exploitdb_path = Path("data/exploitdb/files_exploits.csv")
    if not exploitdb_path.exists():
        logger.warning(f"Exploit-DB CSV not found at: {exploitdb_path}")
        logger.warning("Continuing without Exploit-DB cross-referencing")
        exploitdb_path = None
    
    # Get configuration
    start_year = Config.CENSUS_START_YEAR
    end_year = Config.CENSUS_END_YEAR
    batch_size = Config.CENSUS_BATCH_SIZE
    
    # All web ecosystems
    ecosystems = ["npm", "maven", "pip", "composer", "go", "rubygems"]
    
    # Initialize orchestrator
    orchestrator = CensusOrchestrator(
        github_token=Config.GITHUB_TOKEN,
        exploitdb_csv_path=str(exploitdb_path) if exploitdb_path else None,
        start_year=start_year,
        end_year=end_year,
        ecosystems=ecosystems,
        batch_size=batch_size
    )
    
    # Run census collection
    try:
        summary = orchestrator.run()
        
        # Save summary to file
        summary_path = Path("reports") / f"census_summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        summary_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(summary_path, 'w') as f:
            f.write("CENSUS COLLECTION SUMMARY REPORT\n")
            f.write("=" * 70 + "\n")
            f.write(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Year range: {start_year}-{end_year}\n")
            f.write(f"Ecosystems: {', '.join(ecosystems)}\n")
            f.write("\n")
            f.write("OVERALL STATISTICS:\n")
            f.write(f"  Total CVEs collected: {summary['total_cves_collected']}\n")
            f.write(f"  Priority CVEs (labeled): {summary['total_priority_cves']}\n")
            f.write(f"  Exploits found: {summary['total_exploits_found']}\n")
            f.write(f"  New CVEs stored: {summary['total_stored']}\n")
            f.write(f"  Duplicates skipped: {summary['total_duplicates']}\n")
            f.write(f"  Errors encountered: {summary['total_errors']}\n")
            
            if summary['by_ecosystem']:
                f.write("\nBY ECOSYSTEM:\n")
                for ecosystem, stats in summary['by_ecosystem'].items():
                    f.write(f"  {ecosystem}:\n")
                    f.write(f"    Collected: {stats['collected']}\n")
                    f.write(f"    Priority CVEs: {stats['priority_cves']}\n")
                    f.write(f"    Exploits: {stats['exploits_found']}\n")
                    f.write(f"    Stored: {stats['stored']}\n")
                    f.write(f"    Duplicates: {stats['duplicates']}\n")
            
            if summary['errors']:
                f.write(f"\nERRORS ({len(summary['errors'])} total):\n")
                for error in summary['errors']:
                    f.write(f"  - {error}\n")
        
        logger.info(f"Summary report saved to: {summary_path}")
        
        return 0
    
    except KeyboardInterrupt:
        logger.info("Census collection interrupted by user")
        return 130
    
    except Exception as e:
        logger.error(f"Census collection failed: {e}")
        import traceback
        traceback.print_exc()
        return 1
    
    finally:
        # Clean up database connections
        db_manager.close_pool()


if __name__ == "__main__":
    sys.exit(main())
