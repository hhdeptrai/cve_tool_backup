"""Exclusion service for managing CVE exclusion and restoration for dataset curation."""

import logging
from datetime import datetime
from typing import Optional, List, Dict, Any

from .database import DatabaseManager, CVERepository
from .models import CVEData

logger = logging.getLogger(__name__)


class ExclusionService:
    """
    Service for managing CVE exclusion and restoration for dataset curation.
    
    Business Rules:
    - Exclusion reason must be non-empty
    - Only researchers (Minh/Hoàng) can exclude/restore CVEs
    - Exclusion metadata (excluded_by, excluded_at, exclusion_reason) is preserved
    - Excluded CVEs are hidden from default queries but remain in database
    """
    
    VALID_RESEARCHERS = {"Minh", "Hoàng"}
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize exclusion service.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.repository = CVERepository(db_manager)
    
    def exclude_cve(
        self,
        cve_id: str,
        researcher_id: str,
        reason: str
    ) -> bool:
        """
        Exclude a CVE from the active dataset.
        
        Sets is_excluded=TRUE and records excluded_by, excluded_at, and exclusion_reason.
        
        Args:
            cve_id: CVE identifier
            researcher_id: Researcher performing exclusion (Minh/Hoàng)
            reason: Explanation for exclusion (e.g., "Desktop app, not web-related")
            
        Returns:
            True if exclusion successful, False otherwise
        """
        # Validate researcher ID
        if researcher_id not in self.VALID_RESEARCHERS:
            logger.warning(f"Invalid researcher ID: {researcher_id}")
            return False
        
        # Validate reason is non-empty
        if not reason or not reason.strip():
            logger.warning(f"Exclusion reason is required for CVE {cve_id}")
            return False
        
        conn = None
        try:
            conn = self.db_manager.get_connection()
            conn.autocommit = False
            cursor = conn.cursor()
            
            # Check if CVE exists
            cursor.execute("""
                SELECT cve_id, is_excluded
                FROM web_cve_census_master
                WHERE cve_id = %s
                FOR UPDATE
            """, (cve_id,))
            
            row = cursor.fetchone()
            
            if row is None:
                conn.rollback()
                logger.warning(f"CVE {cve_id} not found")
                return False
            
            cve_id_db, is_excluded = row
            
            if is_excluded:
                conn.rollback()
                logger.info(f"CVE {cve_id} is already excluded")
                return False
            
            # Exclude the CVE
            now = datetime.now()
            
            cursor.execute("""
                UPDATE web_cve_census_master
                SET is_excluded = TRUE,
                    excluded_by = %s,
                    excluded_at = %s,
                    exclusion_reason = %s,
                    updated_at = %s
                WHERE cve_id = %s
            """, (researcher_id, now, reason.strip(), now, cve_id))
            
            conn.commit()
            logger.info(f"CVE {cve_id} excluded by {researcher_id}: {reason}")
            
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to exclude CVE {cve_id}: {e}")
            return False
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def restore_cve(
        self,
        cve_id: str,
        researcher_id: str
    ) -> bool:
        """
        Restore a previously excluded CVE.
        
        Sets is_excluded=FALSE and clears exclusion metadata.
        
        Args:
            cve_id: CVE identifier
            researcher_id: Researcher performing restoration
            
        Returns:
            True if restoration successful, False otherwise
        """
        # Validate researcher ID
        if researcher_id not in self.VALID_RESEARCHERS:
            logger.warning(f"Invalid researcher ID: {researcher_id}")
            return False
        
        conn = None
        try:
            conn = self.db_manager.get_connection()
            conn.autocommit = False
            cursor = conn.cursor()
            
            # Check if CVE exists and is excluded
            cursor.execute("""
                SELECT cve_id, is_excluded
                FROM web_cve_census_master
                WHERE cve_id = %s
                FOR UPDATE
            """, (cve_id,))
            
            row = cursor.fetchone()
            
            if row is None:
                conn.rollback()
                logger.warning(f"CVE {cve_id} not found")
                return False
            
            cve_id_db, is_excluded = row
            
            if not is_excluded:
                conn.rollback()
                logger.info(f"CVE {cve_id} is not excluded")
                return False
            
            # Restore the CVE
            now = datetime.now()
            
            cursor.execute("""
                UPDATE web_cve_census_master
                SET is_excluded = FALSE,
                    excluded_by = NULL,
                    excluded_at = NULL,
                    exclusion_reason = NULL,
                    updated_at = %s
                WHERE cve_id = %s
            """, (now, cve_id))
            
            conn.commit()
            logger.info(f"CVE {cve_id} restored by {researcher_id}")
            
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to restore CVE {cve_id}: {e}")
            return False
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def list_excluded_cves(
        self,
        filters: Optional[Dict[str, Any]] = None
    ) -> List[CVEData]:
        """
        List all excluded CVEs with exclusion metadata.
        
        Args:
            filters: Optional filters (ecosystem, year, excluded_by)
            
        Returns:
            List of excluded CVEs with exclusion_reason, excluded_by, excluded_at
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Build WHERE clause dynamically
            where_conditions = ["is_excluded = TRUE"]
            values = []
            
            if filters:
                if 'ecosystem' in filters:
                    where_conditions.append("ecosystem = %s")
                    values.append(filters['ecosystem'])
                
                if 'year' in filters:
                    where_conditions.append("cve_id LIKE %s")
                    values.append(f"CVE-{filters['year']}-%")
                
                if 'excluded_by' in filters:
                    where_conditions.append("excluded_by = %s")
                    values.append(filters['excluded_by'])
            
            # Build query
            query = """
                SELECT cve_id, description, severity, cvss_base_score,
                       cvss_exploitability_score, affected_package, ecosystem,
                       publication_year, primary_cwe_id, owasp_category, is_priority_cwe,
                       exploit_available, exploit_db_id, has_github_poc, is_excluded,
                       excluded_by, excluded_at, exclusion_reason
                FROM web_cve_census_master
                WHERE """ + " AND ".join(where_conditions) + """
                ORDER BY excluded_at DESC, cve_id
            """
            
            cursor.execute(query, values)
            
            # Convert results to CVEData objects
            results = []
            for row in cursor.fetchall():
                cve_data = CVEData(
                    cve_id=row[0],
                    description=row[1],
                    severity=row[2],
                    cvss_base_score=float(row[3]) if row[3] is not None else 0.0,
                    cvss_exploitability_score=float(row[4]) if row[4] is not None else 0.0,
                    affected_package=row[5],
                    ecosystem=row[6],
                    publication_year=row[7],
                    primary_cwe_id=row[8],
                    owasp_category=row[9],
                    is_priority_cwe=row[10],
                    exploit_available=row[11],
                    exploit_db_id=row[12],
                    has_github_poc=row[13],
                    is_excluded=row[14],
                    excluded_by=row[15],
                    excluded_at=row[16],
                    exclusion_reason=row[17]
                )
                results.append(cve_data)
            
            logger.info(f"Retrieved {len(results)} excluded CVEs")
            return results
            
        except Exception as e:
            logger.error(f"Failed to list excluded CVEs: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
