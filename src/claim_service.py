"""Claim service for managing CVE task claims with concurrency control."""

import logging
from datetime import datetime, timedelta
from typing import Optional, List
from dataclasses import dataclass

from .database import DatabaseManager, CVERepository
from psycopg2.extensions import connection as Connection

logger = logging.getLogger(__name__)


@dataclass
class ClaimResult:
    """Result of a claim operation."""
    success: bool
    message: str
    cve_id: Optional[str] = None


class ClaimService:
    """
    Service for handling CVE task claims with concurrency control.
    
    Uses database-level locking (SELECT FOR UPDATE) to prevent concurrent claims.
    Only accepts researcher IDs "Minh" or "Hoàng".
    Sets claim expiration to 7 days from claim time.
    """
    
    VALID_RESEARCHERS = {"Minh", "Hoàng"}
    CLAIM_EXPIRATION_DAYS = 7
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize claim service.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.repository = CVERepository(db_manager)
    
    def claim_task(self, cve_id: str, researcher_id: str) -> ClaimResult:
        """
        Attempt to claim a CVE task for verification.
        
        Uses database-level locking (SELECT FOR UPDATE) to prevent concurrent claims.
        Sets claim expiration to 7 days from claim time.
        
        Args:
            cve_id: CVE identifier to claim
            researcher_id: Researcher claiming the task (must be "Minh" or "Hoàng")
            
        Returns:
            ClaimResult with success status and message
        """
        # Validate researcher ID
        if researcher_id not in self.VALID_RESEARCHERS:
            return ClaimResult(
                success=False,
                message=f"Invalid researcher ID. Must be one of: {', '.join(self.VALID_RESEARCHERS)}",
                cve_id=cve_id
            )
        
        conn = None
        try:
            conn = self.db_manager.get_connection()
            conn.autocommit = False
            cursor = conn.cursor()
            
            # Use SELECT FOR UPDATE to lock the row
            cursor.execute("""
                SELECT cve_id, assigned_to, claim_expires_at
                FROM web_cve_census_master
                WHERE cve_id = %s
                FOR UPDATE
            """, (cve_id,))
            
            row = cursor.fetchone()
            
            if row is None:
                conn.rollback()
                return ClaimResult(
                    success=False,
                    message=f"CVE {cve_id} not found",
                    cve_id=cve_id
                )
            
            cve_id_db, assigned_to, claim_expires_at = row
            
            # Check if task is available for claiming
            now = datetime.now()
            
            if assigned_to is not None and claim_expires_at is not None:
                # Task is claimed, check if claim has expired
                if claim_expires_at > now:
                    conn.rollback()
                    return ClaimResult(
                        success=False,
                        message=f"Task already claimed by {assigned_to} until {claim_expires_at}",
                        cve_id=cve_id
                    )
            
            # Task is available, claim it
            claim_expires_at = now + timedelta(days=self.CLAIM_EXPIRATION_DAYS)
            
            cursor.execute("""
                UPDATE web_cve_census_master
                SET assigned_to = %s,
                    assigned_at = %s,
                    claim_expires_at = %s,
                    updated_at = %s
                WHERE cve_id = %s
            """, (researcher_id, now, claim_expires_at, now, cve_id))
            
            conn.commit()
            logger.info(f"CVE {cve_id} claimed by {researcher_id} until {claim_expires_at}")
            
            return ClaimResult(
                success=True,
                message=f"Successfully claimed {cve_id} until {claim_expires_at}",
                cve_id=cve_id
            )
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to claim task {cve_id}: {e}")
            return ClaimResult(
                success=False,
                message=f"Error claiming task: {str(e)}",
                cve_id=cve_id
            )
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def claim_batch(
        self,
        researcher_id: str,
        year: int,
        count: int = 10
    ) -> List[ClaimResult]:
        """
        Claim a batch of tasks from a specific year.
        
        Prioritizes tasks with exploit_available = TRUE.
        Only claims unclaimed tasks or tasks with expired claims.
        
        Args:
            researcher_id: Researcher claiming tasks ("Minh" or "Hoàng")
            year: CVE ID year to claim from (e.g., 2025 for CVE-2025-*)
            count: Number of tasks to claim (default: 10)
            
        Returns:
            List of ClaimResult for each claimed task
        """
        # Validate researcher ID
        if researcher_id not in self.VALID_RESEARCHERS:
            return [ClaimResult(
                success=False,
                message=f"Invalid researcher ID. Must be one of: {', '.join(self.VALID_RESEARCHERS)}"
            )]
        
        # Validate year
        if not (2015 <= year <= 2025):
            return [ClaimResult(
                success=False,
                message=f"Invalid year. Must be between 2015 and 2025"
            )]
        
        conn = None
        results = []
        
        try:
            conn = self.db_manager.get_connection()
            conn.autocommit = False
            cursor = conn.cursor()
            
            # Find available tasks for the specified year
            # Prioritize exploit_available = TRUE
            now = datetime.now()
            
            cve_year_pattern = f"CVE-{year}-%"
            cursor.execute("""
                SELECT cve_id
                FROM web_cve_census_master
                WHERE cve_id LIKE %s
                  AND (assigned_to IS NULL OR claim_expires_at < %s)
                  AND exploit_status != 'VERIFIED_SUCCESS'
                ORDER BY exploit_available DESC, cve_id
                LIMIT %s
            """, (cve_year_pattern, now, count))
            
            available_tasks = cursor.fetchall()
            
            if not available_tasks:
                conn.rollback()
                return [ClaimResult(
                    success=False,
                    message=f"No available tasks found for year {year}"
                )]
            
            # Claim each task
            claim_expires_at = now + timedelta(days=self.CLAIM_EXPIRATION_DAYS)
            
            for (cve_id,) in available_tasks:
                try:
                    # Lock and claim the task
                    cursor.execute("""
                        SELECT cve_id, assigned_to, claim_expires_at
                        FROM web_cve_census_master
                        WHERE cve_id = %s
                        FOR UPDATE
                    """, (cve_id,))
                    
                    row = cursor.fetchone()
                    if row is None:
                        results.append(ClaimResult(
                            success=False,
                            message=f"CVE {cve_id} not found",
                            cve_id=cve_id
                        ))
                        continue
                    
                    cve_id_db, assigned_to, current_claim_expires = row
                    
                    # Double-check availability (in case of race condition)
                    if assigned_to is not None and current_claim_expires is not None:
                        if current_claim_expires > now:
                            results.append(ClaimResult(
                                success=False,
                                message=f"Task already claimed by {assigned_to}",
                                cve_id=cve_id
                            ))
                            continue
                    
                    # Claim the task
                    cursor.execute("""
                        UPDATE web_cve_census_master
                        SET assigned_to = %s,
                            assigned_at = %s,
                            claim_expires_at = %s,
                            updated_at = %s
                        WHERE cve_id = %s
                    """, (researcher_id, now, claim_expires_at, now, cve_id))
                    
                    results.append(ClaimResult(
                        success=True,
                        message=f"Successfully claimed {cve_id}",
                        cve_id=cve_id
                    ))
                    logger.info(f"CVE {cve_id} claimed by {researcher_id} in batch")
                    
                except Exception as e:
                    logger.error(f"Failed to claim {cve_id} in batch: {e}")
                    results.append(ClaimResult(
                        success=False,
                        message=f"Error claiming {cve_id}: {str(e)}",
                        cve_id=cve_id
                    ))
            
            conn.commit()
            logger.info(f"Batch claim completed: {sum(1 for r in results if r.success)}/{len(results)} successful")
            
            return results
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to claim batch for year {year}: {e}")
            return [ClaimResult(
                success=False,
                message=f"Error claiming batch: {str(e)}"
            )]
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def release_task(self, cve_id: str, researcher_id: str) -> bool:
        """
        Release a claimed task back to the pool.
        
        Only the researcher who claimed the task can release it.
        
        Args:
            cve_id: CVE identifier to release
            researcher_id: Researcher releasing the task
            
        Returns:
            True if released successfully, False otherwise
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
            
            # Check if task is assigned to the researcher
            cursor.execute("""
                SELECT assigned_to
                FROM web_cve_census_master
                WHERE cve_id = %s
                FOR UPDATE
            """, (cve_id,))
            
            row = cursor.fetchone()
            
            if row is None:
                conn.rollback()
                logger.warning(f"CVE {cve_id} not found")
                return False
            
            assigned_to = row[0]
            
            if assigned_to != researcher_id:
                conn.rollback()
                logger.warning(f"CVE {cve_id} is not assigned to {researcher_id}")
                return False
            
            # Release the task
            cursor.execute("""
                UPDATE web_cve_census_master
                SET assigned_to = NULL,
                    assigned_at = NULL,
                    claim_expires_at = NULL,
                    updated_at = %s
                WHERE cve_id = %s
            """, (datetime.now(), cve_id))
            
            conn.commit()
            logger.info(f"CVE {cve_id} released by {researcher_id}")
            
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to release task {cve_id}: {e}")
            return False
        finally:
            if conn:
                self.db_manager.return_connection(conn)
