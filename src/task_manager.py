"""Task management for CVE verification workflow."""

import logging
from typing import List, Optional, Dict, Any
from datetime import datetime

from .database import DatabaseManager
from .models import CVETask

logger = logging.getLogger(__name__)


class TaskManager:
    """Manages verification task lifecycle."""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize task manager.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
    
    def get_available_tasks(
        self,
        filters: Optional[Dict[str, Any]] = None,
        limit: int = 5,
        order_by_score: bool = False
    ) -> List[CVETask]:
        """
        Retrieve unclaimed or incomplete verification tasks.
        
        Task Selection Logic:
        - Priority: CVEs with exploit_available = TRUE
        - Order: Descending by publication year (2025 → 2015)
        - Filter: Exclude tasks with exploit_status = 'VERIFIED_SUCCESS'
        - Filter: Include only unclaimed OR expired claims
        - Filter: Exclude tasks marked as 'is_excluded'
        
        Args:
            filters: Optional filters (ecosystem, year, exploit_available)
            limit: Maximum number of tasks to return (default: 5)
            order_by_score: If True, sort by CVSS score descending
            
        Returns:
            List of available CVE tasks
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Build WHERE clause
            where_conditions = [
                "(assigned_to IS NULL OR claim_expires_at < NOW())",
                "exploit_status != 'VERIFIED_SUCCESS'",
                "is_excluded = FALSE"
            ]
            values = []
            
            # Apply optional filters
            if filters:
                if 'ecosystem' in filters:
                    where_conditions.append("ecosystem = %s")
                    values.append(filters['ecosystem'])
                
                if 'year' in filters:
                    where_conditions.append("cve_id LIKE %s")
                    values.append(f"CVE-{filters['year']}-%")
                
                if 'exploit_available' in filters:
                    where_conditions.append("exploit_available = %s")
                    values.append(filters['exploit_available'])
            
            # Build query with priority ordering
            if order_by_score:
                order_clause = "cvss_base_score DESC NULLS LAST, cve_id"
            else:
                order_clause = "exploit_available DESC, publication_year DESC, cve_id"
                
            query = f"""
                SELECT 
                    cve_id, description, ecosystem, publication_year,
                    exploit_available, exploit_db_id, build_status,
                    exploit_status, research_depth, assigned_to,
                    assigned_at, claim_expires_at, exploit_notes,
                    cvss_base_score
                FROM web_cve_census_master
                WHERE {' AND '.join(where_conditions)}
                ORDER BY {order_clause}
                LIMIT %s
            """
            
            values.append(limit)
            
            cursor.execute(query, values)
            
            # Convert results to CVETask objects
            tasks = []
            for row in cursor.fetchall():
                task = CVETask(
                    cve_id=row[0],
                    description=row[1],
                    ecosystem=row[2],
                    publication_year=row[3],
                    exploit_available=row[4],
                    exploit_db_id=row[5],
                    build_status=row[6],
                    exploit_status=row[7],
                    research_depth=row[8],
                    assigned_to=row[9],
                    assigned_at=row[10],
                    claim_expires_at=row[11],
                    exploit_notes=row[12],
                    cvss_base_score=row[13]
                )
                tasks.append(task)
            
            logger.info(f"Retrieved {len(tasks)} available tasks")
            return tasks
            
        except Exception as e:
            logger.error(f"Failed to get available tasks: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def get_researcher_tasks(
        self, 
        researcher_id: str,
        order_by_score: bool = False,
        hide_excluded: bool = True,
        hide_completed: bool = True,
        year: Optional[int] = None
    ) -> List[CVETask]:
        """
        Get all tasks assigned to a specific researcher.
        
        Args:
            researcher_id: Researcher identifier (e.g., "Minh" or "Hoàng")
            order_by_score: If True, sort by CVSS score descending
            hide_excluded: If True, filter out excluded tasks (default: True)
            hide_completed: If True, filter out completed tasks (default: True)
            year: If specified, filter by CVE ID year (e.g., 2025 for CVE-2025-*)
            
        Returns:
            List of CVE tasks assigned to the researcher
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            where_conditions = ["assigned_to = %s"]
            values = [researcher_id]
            
            if year:
                where_conditions.append("cve_id LIKE %s")
                values.append(f"CVE-{year}-%")
            
            if hide_excluded:
                where_conditions.append("is_excluded = FALSE")
                
            if hide_completed:
                where_conditions.append("exploit_status NOT IN ('VERIFIED_SUCCESS', 'UNEXPLOITABLE')")
            
            if order_by_score:
                order_clause = "cvss_base_score DESC NULLS LAST, cve_id"
            else:
                order_clause = "publication_year DESC, cve_id"
            
            query = f"""
                SELECT 
                    cve_id, description, ecosystem, publication_year,
                    exploit_available, exploit_db_id, build_status,
                    exploit_status, research_depth, assigned_to,
                    assigned_at, claim_expires_at, exploit_notes,
                    cvss_base_score
                FROM web_cve_census_master
                WHERE {' AND '.join(where_conditions)}
                ORDER BY {order_clause}
            """
            
            cursor.execute(query, values)
            
            # Convert results to CVETask objects
            tasks = []
            for row in cursor.fetchall():
                task = CVETask(
                    cve_id=row[0],
                    description=row[1],
                    ecosystem=row[2],
                    publication_year=row[3],
                    exploit_available=row[4],
                    exploit_db_id=row[5],
                    build_status=row[6],
                    exploit_status=row[7],
                    research_depth=row[8],
                    assigned_to=row[9],
                    assigned_at=row[10],
                    claim_expires_at=row[11],
                    exploit_notes=row[12],
                    cvss_base_score=row[13]
                )
                tasks.append(task)
            
            logger.info(f"Retrieved {len(tasks)} tasks for researcher {researcher_id}")
            return tasks
            
        except Exception as e:
            logger.error(f"Failed to get tasks for researcher {researcher_id}: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)

    def get_researcher_stats(self, researcher_id: str) -> Dict[str, int]:
        """
        Get task statistics for a researcher.
        
        Args:
            researcher_id: Researcher identifier
            
        Returns:
            Dictionary with counts for active, completed, and excluded tasks
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            stats = {
                'active': 0,
                'completed': 0,
                'excluded': 0
            }
            
            # Get active (assigned, not completed, not excluded)
            cursor.execute("""
                SELECT COUNT(*) FROM web_cve_census_master 
                WHERE assigned_to = %s 
                AND exploit_status NOT IN ('VERIFIED_SUCCESS', 'UNEXPLOITABLE')
                AND is_excluded = FALSE
            """, (researcher_id,))
            stats['active'] = cursor.fetchone()[0]
            
            # Get completed (assigned, completed status)
            cursor.execute("""
                SELECT COUNT(*) FROM web_cve_census_master 
                WHERE assigned_to = %s 
                AND exploit_status IN ('VERIFIED_SUCCESS', 'UNEXPLOITABLE')
            """, (researcher_id,))
            stats['completed'] = cursor.fetchone()[0]
            
            # Get excluded by researcher
            cursor.execute("""
                SELECT COUNT(*) FROM web_cve_census_master 
                WHERE excluded_by = %s 
                AND is_excluded = TRUE
            """, (researcher_id,))
            stats['excluded'] = cursor.fetchone()[0]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get stats for researcher {researcher_id}: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)

    def get_system_stats(self) -> Dict[str, int]:
        """
        Get system-wide task statistics.
        
        Returns:
            Dictionary with counts for available tasks, etc.
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            stats = {}
            
            # Get available tasks count
            cursor.execute("""
                SELECT COUNT(*) FROM web_cve_census_master 
                WHERE (assigned_to IS NULL OR claim_expires_at < NOW())
                AND exploit_status != 'VERIFIED_SUCCESS'
                AND is_excluded = FALSE
            """)
            stats['available'] = cursor.fetchone()[0]
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get system stats: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
