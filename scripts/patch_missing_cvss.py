#!/usr/bin/env python3
"""
Patch script to update missing CVSS base scores for existing CVEs.
This re-fetches CVE data from GitHub Advisory Database and updates the CVSS scores.
"""

import sys
import os
import logging
from typing import List, Set

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import Config
from src.database import DatabaseManager
from src.github_advisory_client import GitHubAdvisoryClient

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

def update_missing_scores():
    """Find CVEs with missing scores and update them."""
    db_manager = DatabaseManager(Config.DATABASE_URL)
    
    conn = None
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # 1. Identify CVEs with missing scores
        logger.info("Checking for CVEs with missing CVSS scores...")
        cursor.execute("SELECT cve_id FROM web_cve_census_master WHERE cvss_base_score IS NULL")
        missing_cves = [row[0] for row in cursor.fetchall()]
        
        if not missing_cves:
            logger.info("No CVEs found with missing scores.")
            return

        logger.info(f"Found {len(missing_cves)} CVEs with missing scores.")
        
        # 2. Determine affected years to optimize fetching
        cursor.execute("""
            SELECT DISTINCT publication_year 
            FROM web_cve_census_master 
            WHERE cvss_base_score IS NULL
            ORDER BY publication_year
        """)
        years = [row[0] for row in cursor.fetchall()]
        logger.info(f"Missing scores span years: {years}")
        
        # 3. Re-fetch data year by year
        client = GitHubAdvisoryClient(token=Config.GITHUB_TOKEN)
        
        updated_count = 0
        
        for year in years:
            logger.info(f"Refetching data for year {year}...")
            # Collect all CVEs for the year (simplest way to get updated data)
            cves = client.collect_cves(
                start_year=year,
                end_year=year,
                ecosystems=Config.CENSUS_ECOSYSTEMS
            )
            
            # Update scores for matching CVEs
            for cve in cves:
                if cve.cve_id in missing_cves and cve.cvss_base_score is not None:
                    cursor.execute("""
                        UPDATE web_cve_census_master
                        SET cvss_base_score = %s,
                            cvss_exploitability_score = %s,
                            updated_at = NOW()
                        WHERE cve_id = %s
                    """, (cve.cvss_base_score, cve.cvss_exploitability_score, cve.cve_id))
                    
                    if cursor.rowcount > 0:
                        updated_count += 1
                        if updated_count % 100 == 0:
                            conn.commit()
                            logger.info(f"Updated {updated_count} scores so far...")
        
        conn.commit()
        logger.info(f"Successfully updated {updated_count} CVE scores.")
        
    except Exception as e:
        if conn:
            conn.rollback()
        logger.error(f"Failed to update scores: {e}")
        sys.exit(1)
    finally:
        if conn:
            db_manager.return_connection(conn)

if __name__ == "__main__":
    update_missing_scores()
