"""Verification service for updating CVE verification status and results."""

import logging
from datetime import datetime
from typing import Optional

from .database import DatabaseManager, CVERepository
from .models import BuildStatus, ExploitStatus, ResearchDepth

logger = logging.getLogger(__name__)


class VerificationService:
    """
    Service for updating verification status and results.
    
    Business Rules:
    - Only assigned researcher can update their tasks
    - VERIFIED_SUCCESS or UNEXPLOITABLE requires exploit_notes to be non-empty
    - updated_at timestamp automatically updated on any change
    - Validates enum values before database update
    """
    
    VALID_RESEARCHERS = {"Minh", "Hoàng"}
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize verification service.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.repository = CVERepository(db_manager)
    
    def update_build_status(
        self,
        cve_id: str,
        researcher_id: str,
        status: BuildStatus,
        notes: Optional[str] = None
    ) -> bool:
        """
        Update build status for a claimed CVE.
        
        Only the assigned researcher can update their tasks.
        
        Args:
            cve_id: CVE identifier
            researcher_id: Researcher updating the status
            status: New build status
            notes: Optional notes about the build attempt
            
        Returns:
            True if updated successfully, False otherwise
        """
        # Validate researcher ID
        if researcher_id not in self.VALID_RESEARCHERS:
            logger.warning(f"Invalid researcher ID: {researcher_id}")
            return False
        
        # Validate status is a BuildStatus enum
        if not isinstance(status, BuildStatus):
            logger.warning(f"Invalid build status type: {type(status)}")
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
            
            # Update build status
            now = datetime.now()
            
            if notes:
                cursor.execute("""
                    UPDATE web_cve_census_master
                    SET build_status = %s,
                        exploit_notes = COALESCE(exploit_notes, '') || %s,
                        updated_at = %s
                    WHERE cve_id = %s
                """, (status.value, f"\n[Build] {notes}", now, cve_id))
            else:
                cursor.execute("""
                    UPDATE web_cve_census_master
                    SET build_status = %s,
                        updated_at = %s
                    WHERE cve_id = %s
                """, (status.value, now, cve_id))
            
            conn.commit()
            logger.info(f"Build status for CVE {cve_id} updated to {status.value} by {researcher_id}")
            
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to update build status for {cve_id}: {e}")
            return False
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def update_exploit_status(
        self,
        cve_id: str,
        researcher_id: str,
        status: ExploitStatus,
        notes: str
    ) -> bool:
        """
        Update exploit verification status.
        
        Only the assigned researcher can update their tasks.
        VERIFIED_SUCCESS or UNEXPLOITABLE requires non-empty notes.
        
        Args:
            cve_id: CVE identifier
            researcher_id: Researcher updating the status
            status: New exploit status
            notes: Notes documenting the verification attempt (required for VERIFIED_SUCCESS/UNEXPLOITABLE)
            
        Returns:
            True if updated successfully, False otherwise
        """
        # Validate researcher ID
        if researcher_id not in self.VALID_RESEARCHERS:
            logger.warning(f"Invalid researcher ID: {researcher_id}")
            return False
        
        # Validate status is an ExploitStatus enum
        if not isinstance(status, ExploitStatus):
            logger.warning(f"Invalid exploit status type: {type(status)}")
            return False
        
        # Validate notes requirement for VERIFIED_SUCCESS and UNEXPLOITABLE
        if status in (ExploitStatus.VERIFIED_SUCCESS, ExploitStatus.UNEXPLOITABLE):
            if not notes or not notes.strip():
                logger.warning(f"Notes required for status {status.value}")
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
            
            # Update exploit status
            now = datetime.now()
            
            cursor.execute("""
                UPDATE web_cve_census_master
                SET exploit_status = %s,
                    exploit_notes = %s,
                    updated_at = %s
                WHERE cve_id = %s
            """, (status.value, notes, now, cve_id))
            
            conn.commit()
            logger.info(f"Exploit status for CVE {cve_id} updated to {status.value} by {researcher_id}")
            
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to update exploit status for {cve_id}: {e}")
            return False
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def update_research_depth(
        self,
        cve_id: str,
        researcher_id: str,
        depth: ResearchDepth
    ) -> bool:
        """
        Update research depth classification.
        
        Only the assigned researcher can update their tasks.
        
        Args:
            cve_id: CVE identifier
            researcher_id: Researcher updating the depth
            depth: New research depth level
            
        Returns:
            True if updated successfully, False otherwise
        """
        # Validate researcher ID
        if researcher_id not in self.VALID_RESEARCHERS:
            logger.warning(f"Invalid researcher ID: {researcher_id}")
            return False
        
        # Validate depth is a ResearchDepth enum
        if not isinstance(depth, ResearchDepth):
            logger.warning(f"Invalid research depth type: {type(depth)}")
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
            
            # Update research depth
            now = datetime.now()
            
            cursor.execute("""
                UPDATE web_cve_census_master
                SET research_depth = %s,
                    updated_at = %s
                WHERE cve_id = %s
            """, (depth.value, now, cve_id))
            
            conn.commit()
            logger.info(f"Research depth for CVE {cve_id} updated to {depth.value} by {researcher_id}")
            
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to update research depth for {cve_id}: {e}")
            return False
        finally:
            if conn:
                self.db_manager.return_connection(conn)
