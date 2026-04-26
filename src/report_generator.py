"""Report generation for the Web CVE Census System."""

import logging
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from datetime import datetime

from .database import CVERepository, DatabaseManager

logger = logging.getLogger(__name__)


@dataclass
class CensusReport:
    """Comprehensive census statistics report."""
    
    # Report metadata
    generated_at: datetime
    report_mode: str  # 'priority' or 'full'
    filters_applied: Dict[str, Any]
    
    # Total counts
    total_cves: int
    priority_cves: int  # is_priority_cwe=TRUE AND is_excluded=FALSE
    excluded_cves: int  # is_excluded=TRUE
    
    # Breakdown by year
    cves_by_year: Dict[int, int]
    
    # Breakdown by ecosystem
    cves_by_ecosystem: Dict[str, int]
    
    # Breakdown by CWE category
    cves_by_cwe: Dict[str, int]
    
    # Exploit statistics
    exploit_available_count: int
    exploit_availability_percentage: float
    github_poc_available_count: int
    github_poc_availability_percentage: float
    
    # Verification statistics
    verification_completion_count: int
    verification_completion_percentage: float
    
    # Build status distribution
    build_status_distribution: Dict[str, int]
    
    # Exploit status distribution
    exploit_status_distribution: Dict[str, int]
    
    # Research depth distribution
    research_depth_distribution: Dict[str, int] = field(default_factory=dict)


@dataclass
class ResearcherReport:
    """Per-researcher verification metrics."""
    
    researcher_id: str
    generated_at: datetime
    
    # Task counts
    total_tasks_assigned: int
    tasks_completed: int  # exploit_status != 'NONE'
    tasks_in_progress: int  # assigned but not completed
    
    # Completion rate
    completion_percentage: float
    
    # Build status breakdown
    build_success_count: int
    build_failed_count: int
    build_in_progress_count: int
    
    # Exploit status breakdown
    verified_success_count: int
    unexploitable_count: int
    exploit_db_count: int
    poc_public_count: int
    
    # Research depth breakdown
    level_0_count: int
    level_1_count: int
    level_2_count: int


class ReportGenerator:
    """Generate statistical reports and metrics with exclusion awareness."""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize report generator.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
        self.repository = CVERepository(db_manager)
    
    def generate_census_report(
        self,
        filters: Optional[Dict[str, Any]] = None,
        mode: str = 'priority'
    ) -> CensusReport:
        """
        Generate comprehensive census statistics.
        
        Args:
            filters: Optional filters (year, ecosystem, status, is_priority_cwe, is_excluded)
            mode: Report mode - 'priority' (default, excludes is_excluded=TRUE) or 'full' (includes all)
        
        Returns:
            CensusReport with comprehensive statistics
        """
        if filters is None:
            filters = {}
        
        # Apply mode-specific filtering
        if mode == 'priority':
            # Priority mode: exclude is_excluded=TRUE by default
            if 'is_excluded' not in filters:
                filters['is_excluded'] = False
        elif mode != 'full':
            raise ValueError(f"Invalid report mode: {mode}. Must be 'priority' or 'full'")
        
        logger.info(f"Generating census report in {mode} mode with filters: {filters}")
        
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Build WHERE clause from filters
            where_conditions = []
            values = []
            
            if 'year' in filters:
                where_conditions.append("cve_id LIKE %s")
                values.append(f"CVE-{filters['year']}-%")
            
            if 'ecosystem' in filters:
                where_conditions.append("ecosystem = %s")
                values.append(filters['ecosystem'])
            
            if 'build_status' in filters:
                where_conditions.append("build_status = %s")
                values.append(filters['build_status'])
            
            if 'exploit_status' in filters:
                where_conditions.append("exploit_status = %s")
                values.append(filters['exploit_status'])
            
            if 'is_priority_cwe' in filters:
                where_conditions.append("is_priority_cwe = %s")
                values.append(filters['is_priority_cwe'])
            
            if 'is_excluded' in filters:
                where_conditions.append("is_excluded = %s")
                values.append(filters['is_excluded'])
            
            where_clause = ""
            if where_conditions:
                where_clause = "WHERE " + " AND ".join(where_conditions)
            
            # Calculate total CVEs
            cursor.execute(
                f"SELECT COUNT(*) FROM web_cve_census_master {where_clause}",
                values
            )
            total_cves = cursor.fetchone()[0]
            
            # Calculate priority CVEs (is_priority_cwe=TRUE AND is_excluded=FALSE)
            priority_where = list(where_conditions)
            priority_values = list(values)
            priority_where.append("is_priority_cwe = TRUE")
            priority_where.append("is_excluded = FALSE")
            priority_clause = "WHERE " + " AND ".join(priority_where) if priority_where else ""
            
            cursor.execute(
                f"SELECT COUNT(*) FROM web_cve_census_master {priority_clause}",
                priority_values
            )
            priority_cves = cursor.fetchone()[0]
            
            # Calculate excluded CVEs (is_excluded=TRUE)
            excluded_where = list(where_conditions)
            excluded_values = list(values)
            excluded_where.append("is_excluded = TRUE")
            excluded_clause = "WHERE " + " AND ".join(excluded_where) if excluded_where else ""
            
            cursor.execute(
                f"SELECT COUNT(*) FROM web_cve_census_master {excluded_clause}",
                excluded_values
            )
            excluded_cves = cursor.fetchone()[0]
            
            # CVEs by year
            cursor.execute(
                f"""
                SELECT publication_year, COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                GROUP BY publication_year 
                ORDER BY publication_year
                """,
                values
            )
            cves_by_year = {row[0]: row[1] for row in cursor.fetchall()}
            
            # CVEs by ecosystem
            cursor.execute(
                f"""
                SELECT ecosystem, COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                GROUP BY ecosystem 
                ORDER BY ecosystem
                """,
                values
            )
            cves_by_ecosystem = {row[0]: row[1] for row in cursor.fetchall()}
            
            # CVEs by CWE category
            cursor.execute(
                f"""
                SELECT owasp_category, COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                GROUP BY owasp_category 
                ORDER BY owasp_category
                """,
                values
            )
            cves_by_cwe = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Exploit availability
            cursor.execute(
                f"""
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                {"AND" if where_clause else "WHERE"} exploit_available = TRUE
                """,
                values
            )
            exploit_available_count = cursor.fetchone()[0]
            exploit_availability_percentage = (
                (exploit_available_count / total_cves * 100) if total_cves > 0 else 0.0
            )

            # GitHub PoC availability
            cursor.execute(
                f"""
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                {"AND" if where_clause else "WHERE"} has_github_poc = TRUE
                """,
                values
            )
            github_poc_available_count = cursor.fetchone()[0]
            github_poc_availability_percentage = (
                (github_poc_available_count / total_cves * 100) if total_cves > 0 else 0.0
            )
            
            # Verification completion (exploit_status != 'NONE')
            cursor.execute(
                f"""
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                {"AND" if where_clause else "WHERE"} exploit_status != 'NONE'
                """,
                values
            )
            verification_completion_count = cursor.fetchone()[0]
            verification_completion_percentage = (
                (verification_completion_count / total_cves * 100) if total_cves > 0 else 0.0
            )
            
            # Build status distribution
            cursor.execute(
                f"""
                SELECT build_status, COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                GROUP BY build_status 
                ORDER BY build_status
                """,
                values
            )
            build_status_distribution = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Exploit status distribution
            cursor.execute(
                f"""
                SELECT exploit_status, COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                GROUP BY exploit_status 
                ORDER BY exploit_status
                """,
                values
            )
            exploit_status_distribution = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Research depth distribution
            cursor.execute(
                f"""
                SELECT research_depth, COUNT(*) 
                FROM web_cve_census_master 
                {where_clause}
                GROUP BY research_depth 
                ORDER BY research_depth
                """,
                values
            )
            research_depth_distribution = {row[0]: row[1] for row in cursor.fetchall()}
            
            report = CensusReport(
                generated_at=datetime.now(),
                report_mode=mode,
                filters_applied=filters,
                total_cves=total_cves,
                priority_cves=priority_cves,
                excluded_cves=excluded_cves,
                cves_by_year=cves_by_year,
                cves_by_ecosystem=cves_by_ecosystem,
                cves_by_cwe=cves_by_cwe,
                exploit_available_count=exploit_available_count,
                exploit_availability_percentage=exploit_availability_percentage,
                github_poc_available_count=github_poc_available_count,
                github_poc_availability_percentage=github_poc_availability_percentage,
                verification_completion_count=verification_completion_count,
                verification_completion_percentage=verification_completion_percentage,
                build_status_distribution=build_status_distribution,
                exploit_status_distribution=exploit_status_distribution,
                research_depth_distribution=research_depth_distribution
            )
            
            logger.info(f"Census report generated successfully: {total_cves} total CVEs")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate census report: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def generate_researcher_report(self, researcher_id: str) -> ResearcherReport:
        """
        Generate per-researcher verification metrics.
        
        Args:
            researcher_id: Researcher identifier (e.g., "Minh" or "Hoàng")
        
        Returns:
            ResearcherReport with researcher-specific metrics
        """
        logger.info(f"Generating researcher report for {researcher_id}")
        
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Total tasks assigned
            cursor.execute(
                "SELECT COUNT(*) FROM web_cve_census_master WHERE assigned_to = %s",
                (researcher_id,)
            )
            total_tasks_assigned = cursor.fetchone()[0]
            
            # Tasks completed (exploit_status != 'NONE')
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND exploit_status != 'NONE'
                """,
                (researcher_id,)
            )
            tasks_completed = cursor.fetchone()[0]
            
            # Tasks in progress (assigned but exploit_status = 'NONE')
            tasks_in_progress = total_tasks_assigned - tasks_completed
            
            # Completion percentage
            completion_percentage = (
                (tasks_completed / total_tasks_assigned * 100) if total_tasks_assigned > 0 else 0.0
            )
            
            # Build status breakdown
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND build_status = 'SUCCESS'
                """,
                (researcher_id,)
            )
            build_success_count = cursor.fetchone()[0]
            
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND build_status = 'FAILED'
                """,
                (researcher_id,)
            )
            build_failed_count = cursor.fetchone()[0]
            
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND build_status = 'IN_PROGRESS'
                """,
                (researcher_id,)
            )
            build_in_progress_count = cursor.fetchone()[0]
            
            # Exploit status breakdown
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND exploit_status = 'VERIFIED_SUCCESS'
                """,
                (researcher_id,)
            )
            verified_success_count = cursor.fetchone()[0]
            
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND exploit_status = 'UNEXPLOITABLE'
                """,
                (researcher_id,)
            )
            unexploitable_count = cursor.fetchone()[0]
            
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND exploit_status = 'EXPLOIT_DB'
                """,
                (researcher_id,)
            )
            exploit_db_count = cursor.fetchone()[0]
            
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND exploit_status = 'POC_PUBLIC'
                """,
                (researcher_id,)
            )
            poc_public_count = cursor.fetchone()[0]
            
            # Research depth breakdown
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND research_depth = 'LEVEL_0'
                """,
                (researcher_id,)
            )
            level_0_count = cursor.fetchone()[0]
            
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND research_depth = 'LEVEL_1'
                """,
                (researcher_id,)
            )
            level_1_count = cursor.fetchone()[0]
            
            cursor.execute(
                """
                SELECT COUNT(*) 
                FROM web_cve_census_master 
                WHERE assigned_to = %s AND research_depth = 'LEVEL_2'
                """,
                (researcher_id,)
            )
            level_2_count = cursor.fetchone()[0]
            
            report = ResearcherReport(
                researcher_id=researcher_id,
                generated_at=datetime.now(),
                total_tasks_assigned=total_tasks_assigned,
                tasks_completed=tasks_completed,
                tasks_in_progress=tasks_in_progress,
                completion_percentage=completion_percentage,
                build_success_count=build_success_count,
                build_failed_count=build_failed_count,
                build_in_progress_count=build_in_progress_count,
                verified_success_count=verified_success_count,
                unexploitable_count=unexploitable_count,
                exploit_db_count=exploit_db_count,
                poc_public_count=poc_public_count,
                level_0_count=level_0_count,
                level_1_count=level_1_count,
                level_2_count=level_2_count
            )
            
            logger.info(f"Researcher report generated for {researcher_id}: {total_tasks_assigned} tasks")
            return report
            
        except Exception as e:
            logger.error(f"Failed to generate researcher report for {researcher_id}: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
