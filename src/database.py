"""Database connection and schema management for the Web CVE Census System."""

import psycopg2
from psycopg2 import pool
from psycopg2.extras import execute_values
from psycopg2.extensions import connection as Connection
from typing import Optional, TYPE_CHECKING
from datetime import datetime
import logging

from .config import Config

if TYPE_CHECKING:
    from .models import CVEData

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manages database connections and schema operations."""
    
    def __init__(self, database_url: Optional[str] = None):
        """
        Initialize database manager.
        
        Args:
            database_url: PostgreSQL connection URL. If None, uses Config.DATABASE_URL
        """
        self.database_url = database_url or Config.DATABASE_URL
        self._connection_pool: Optional[pool.SimpleConnectionPool] = None
    
    def initialize_pool(self, minconn: int = 1, maxconn: int = 10) -> None:
        """
        Initialize connection pool.
        
        Args:
            minconn: Minimum number of connections in pool
            maxconn: Maximum number of connections in pool
        """
        try:
            self._connection_pool = pool.SimpleConnectionPool(
                minconn,
                maxconn,
                self.database_url
            )
            logger.info("Database connection pool initialized")
        except Exception as e:
            logger.error(f"Failed to initialize connection pool: {e}")
            raise
    
    def get_connection(self) -> Connection:
        """
        Get a connection from the pool.
        
        Returns:
            Database connection
        """
        if self._connection_pool is None:
            self.initialize_pool()
        
        return self._connection_pool.getconn()
    
    def return_connection(self, conn: Connection) -> None:
        """
        Return a connection to the pool.
        
        Args:
            conn: Database connection to return
        """
        if self._connection_pool is not None:
            self._connection_pool.putconn(conn)
    
    def close_pool(self) -> None:
        """Close all connections in the pool."""
        if self._connection_pool is not None:
            self._connection_pool.closeall()
            self._connection_pool = None
            logger.info("Database connection pool closed")
    
    def create_schema(self) -> None:
        """Create the database schema if it doesn't exist."""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            # Create the main table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS web_cve_census_master (
                    -- Primary identification
                    cve_id VARCHAR(20) PRIMARY KEY,
                    
                    -- CVE metadata
                    description TEXT NOT NULL,
                    severity VARCHAR(20),
                    cvss_base_score DECIMAL(3,1),
                    cvss_exploitability_score DECIMAL(3,1),
                    affected_package VARCHAR(255),
                    ecosystem VARCHAR(20) NOT NULL,
                    publication_year INTEGER NOT NULL,
                    primary_cwe_id VARCHAR(50),
                    
                    -- CWE labeling (NEW)
                    owasp_category VARCHAR(50),
                    is_priority_cwe BOOLEAN DEFAULT FALSE,
                    
                    -- Exploit-DB cross-reference
                    exploit_available BOOLEAN DEFAULT FALSE,
                    exploit_db_id VARCHAR(50),
                    has_github_poc BOOLEAN DEFAULT FALSE,
                    
                    -- CVE exclusion mechanism (NEW),
                    
                    -- CVE exclusion mechanism (NEW)
                    is_excluded BOOLEAN DEFAULT FALSE,
                    excluded_by VARCHAR(100),
                    excluded_at TIMESTAMP,
                    exclusion_reason TEXT,
                    
                    -- Verification workflow
                    build_status VARCHAR(20) DEFAULT 'NOT_ATTEMPTED',
                    exploit_status VARCHAR(20) DEFAULT 'NONE',
                    research_depth VARCHAR(20) DEFAULT 'LEVEL_0',
                    assigned_to VARCHAR(100),
                    assigned_at TIMESTAMP,
                    claim_expires_at TIMESTAMP,
                    exploit_notes TEXT,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    
                    -- Constraints
                    CONSTRAINT chk_cvss_base CHECK (cvss_base_score BETWEEN 0.0 AND 10.0),
                    CONSTRAINT chk_cvss_exploit CHECK (cvss_exploitability_score BETWEEN 0.0 AND 10.0),
                    CONSTRAINT chk_year CHECK (publication_year BETWEEN 2013 AND 2030),
                    CONSTRAINT chk_ecosystem CHECK (ecosystem IN ('npm', 'maven', 'pip', 'composer', 'go', 'rubygems', 'nuget', 'rust', 'erlang')),
                    CONSTRAINT chk_build_status CHECK (build_status IN ('NOT_ATTEMPTED', 'IN_PROGRESS', 'SUCCESS', 'FAILED')),
                    CONSTRAINT chk_exploit_status CHECK (exploit_status IN ('NONE', 'POC_PUBLIC', 'EXPLOIT_DB', 'VERIFIED_SUCCESS', 'UNEXPLOITABLE')),
                    CONSTRAINT chk_research_depth CHECK (research_depth IN ('LEVEL_0', 'LEVEL_1', 'LEVEL_2')),
                    CONSTRAINT chk_exclusion_reason CHECK (is_excluded = FALSE OR exclusion_reason IS NOT NULL)
                );
            """)
            
            # Create indexes for common queries
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_publication_year 
                ON web_cve_census_master(publication_year);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_ecosystem 
                ON web_cve_census_master(ecosystem);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_primary_cwe_id 
                ON web_cve_census_master(primary_cwe_id);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_owasp_category 
                ON web_cve_census_master(owasp_category);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_is_priority_cwe 
                ON web_cve_census_master(is_priority_cwe);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_is_excluded 
                ON web_cve_census_master(is_excluded);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_exploit_available 
                ON web_cve_census_master(exploit_available);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_has_github_poc 
                ON web_cve_census_master(has_github_poc);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_assigned_to 
                ON web_cve_census_master(assigned_to);
            """)
            
            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_exploit_status 
                ON web_cve_census_master(exploit_status);
            """)
            
            conn.commit()
            logger.info("Database schema created successfully")
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to create schema: {e}")
            raise
        finally:
            if conn:
                self.return_connection(conn)
    
    def drop_schema(self) -> None:
        """Drop the database schema. WARNING: This deletes all data!"""
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("DROP TABLE IF EXISTS web_cve_census_master CASCADE;")
            
            conn.commit()
            logger.info("Database schema dropped successfully")
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to drop schema: {e}")
            raise
        finally:
            if conn:
                self.return_connection(conn)
    
    def test_connection(self) -> bool:
        """
        Test database connection.
        
        Returns:
            True if connection successful, False otherwise
        """
        conn = None
        try:
            conn = self.get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1;")
            result = cursor.fetchone()
            logger.info("Database connection test successful")
            return result[0] == 1
        except Exception as e:
            logger.error(f"Database connection test failed: {e}")
            return False
        finally:
            if conn:
                self.return_connection(conn)


# Global database manager instance
db_manager = DatabaseManager()


class CVERepository:
    """Repository for CVE data operations with support for new architecture fields."""
    
    def __init__(self, db_manager: DatabaseManager):
        """
        Initialize CVE repository.
        
        Args:
            db_manager: Database manager instance
        """
        self.db_manager = db_manager
    
    def insert_cve(self, cve_data: 'CVEData') -> bool:
        """
        Insert a new CVE record with duplicate handling.
        
        If a CVE with the same ID already exists, the insertion is skipped
        and the existing record is preserved.
        
        Args:
            cve_data: CVE data to insert
            
        Returns:
            True if inserted successfully, False if duplicate exists
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Check if CVE already exists
            cursor.execute(
                "SELECT cve_id FROM web_cve_census_master WHERE cve_id = %s",
                (cve_data.cve_id,)
            )
            
            if cursor.fetchone() is not None:
                logger.info(f"CVE {cve_data.cve_id} already exists, skipping insertion")
                return False
            
            # Insert new CVE
            cursor.execute("""
                INSERT INTO web_cve_census_master (
                    cve_id, description, severity, cvss_base_score, 
                    cvss_exploitability_score, affected_package, ecosystem, 
                    publication_year, primary_cwe_id, owasp_category, is_priority_cwe,
                    exploit_available, exploit_db_id, has_github_poc, is_excluded, 
                    excluded_by, excluded_at, exclusion_reason
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """, (
                cve_data.cve_id,
                cve_data.description,
                cve_data.severity,
                cve_data.cvss_base_score,
                cve_data.cvss_exploitability_score,
                cve_data.affected_package,
                cve_data.ecosystem,
                cve_data.publication_year,
                cve_data.primary_cwe_id,
                cve_data.owasp_category,
                cve_data.is_priority_cwe,
                cve_data.exploit_available,
                cve_data.exploit_db_id,
                cve_data.has_github_poc,
                cve_data.is_excluded,
                cve_data.excluded_by,
                cve_data.excluded_at,
                cve_data.exclusion_reason
            ))
            
            conn.commit()
            logger.info(f"CVE {cve_data.cve_id} inserted successfully")
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to insert CVE {cve_data.cve_id}: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def insert_cves_batch(self, cve_list: list) -> int:
        """
        Batch insert CVEs using INSERT ... ON CONFLICT DO NOTHING.
        
        Much faster than inserting one-by-one: uses a single transaction
        and skips duplicates at the database level.
        
        Args:
            cve_list: List of CVEData objects to insert
            
        Returns:
            Number of CVEs actually inserted (excludes duplicates)
        """
        if not cve_list:
            return 0
        
        # Deduplicate to prevent PostgreSQL CardinalityViolation during DO UPDATE
        unique_cves = {}
        for cve in cve_list:
            unique_cves[cve.cve_id] = cve
        deduped_list = list(unique_cves.values())
        
        conn = None
        try:
            conn = self.db_manager.get_connection()
            conn.autocommit = False
            cursor = conn.cursor()
            
            insert_sql = """
                INSERT INTO web_cve_census_master (
                    cve_id, description, severity, cvss_base_score, 
                    cvss_exploitability_score, affected_package, ecosystem, 
                    publication_year, primary_cwe_id, owasp_category, is_priority_cwe,
                    exploit_available, exploit_db_id, has_github_poc, is_excluded, 
                    excluded_by, excluded_at, exclusion_reason
                ) VALUES %s
                ON CONFLICT (cve_id) DO UPDATE SET
                    primary_cwe_id = EXCLUDED.primary_cwe_id,
                    owasp_category = EXCLUDED.owasp_category,
                    is_priority_cwe = EXCLUDED.is_priority_cwe,
                    exploit_available = EXCLUDED.exploit_available,
                    exploit_db_id = EXCLUDED.exploit_db_id,
                    has_github_poc = EXCLUDED.has_github_poc
            """
            
            rows = [
                (
                    cve.cve_id, cve.description, cve.severity,
                    cve.cvss_base_score, cve.cvss_exploitability_score,
                    cve.affected_package, cve.ecosystem,
                    cve.publication_year, cve.primary_cwe_id, cve.owasp_category, cve.is_priority_cwe,
                    cve.exploit_available, cve.exploit_db_id, cve.has_github_poc,
                    cve.is_excluded, cve.excluded_by, cve.excluded_at,
                    cve.exclusion_reason
                )
                for cve in deduped_list
            ]
            
            execute_values(cursor, insert_sql, rows, page_size=500)
            inserted = cursor.rowcount
            
            conn.commit()
            logger.info(f"Batch insert: {inserted}/{len(cve_list)} CVEs inserted (rest were duplicates)")
            return inserted
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to batch insert CVEs: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def update_cve(self, cve_id: str, updates: dict, expected_updated_at: Optional[datetime] = None) -> bool:
        """
        Update a CVE record with optimistic locking.
        
        Uses the updated_at timestamp for optimistic locking to prevent
        concurrent update conflicts.
        
        Args:
            cve_id: CVE identifier
            updates: Dictionary of field names and values to update
            expected_updated_at: Expected current updated_at timestamp for optimistic locking
            
        Returns:
            True if updated successfully, False if optimistic lock failed
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Build UPDATE query dynamically
            if not updates:
                logger.warning(f"No updates provided for CVE {cve_id}")
                return False
            
            # Always update the updated_at timestamp
            updates['updated_at'] = datetime.now()
            
            set_clause = ", ".join([f"{key} = %s" for key in updates.keys()])
            values = list(updates.values())
            
            # Add WHERE clause with optimistic locking
            where_clause = "cve_id = %s"
            values.append(cve_id)
            
            if expected_updated_at is not None:
                where_clause += " AND updated_at = %s"
                values.append(expected_updated_at)
            
            query = f"UPDATE web_cve_census_master SET {set_clause} WHERE {where_clause}"
            
            cursor.execute(query, values)
            
            if cursor.rowcount == 0:
                if expected_updated_at is not None:
                    logger.warning(f"Optimistic lock failed for CVE {cve_id}")
                else:
                    logger.warning(f"CVE {cve_id} not found")
                return False
            
            conn.commit()
            logger.info(f"CVE {cve_id} updated successfully")
            return True
            
        except Exception as e:
            if conn:
                conn.rollback()
            logger.error(f"Failed to update CVE {cve_id}: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def query_cves(
        self,
        year: Optional[int] = None,
        ecosystem: Optional[str] = None,
        primary_cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        build_status: Optional[str] = None,
        exploit_status: Optional[str] = None,
        is_priority_cwe: Optional[bool] = None,
        is_excluded: Optional[bool] = None,
        limit: Optional[int] = None,
        offset: Optional[int] = None
    ) -> list:
        """
        Query CVE records with filtering.
        
        Args:
            year: Filter by publication year
            ecosystem: Filter by ecosystem
            primary_cwe_id: Filter by exact CWE ID
            owasp_category: Filter by OWASP category
            build_status: Filter by build status
            exploit_status: Filter by exploit status
            is_priority_cwe: Filter by priority CWE flag
            is_excluded: Filter by exclusion status
            limit: Maximum number of records to return
            offset: Number of records to skip
            
        Returns:
            List of CVE records as dictionaries
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            # Build WHERE clause dynamically
            where_conditions = []
            values = []
            
            if year is not None:
                where_conditions.append("cve_id LIKE %s")
                values.append(f"CVE-{year}-%")
            
            if ecosystem is not None:
                where_conditions.append("ecosystem = %s")
                values.append(ecosystem)
            
            if primary_cwe_id is not None:
                where_conditions.append("primary_cwe_id = %s")
                values.append(primary_cwe_id)
            
            if owasp_category is not None:
                where_conditions.append("owasp_category = %s")
                values.append(owasp_category)
            
            if build_status is not None:
                where_conditions.append("build_status = %s")
                values.append(build_status)
            
            if exploit_status is not None:
                where_conditions.append("exploit_status = %s")
                values.append(exploit_status)
            
            if is_priority_cwe is not None:
                where_conditions.append("is_priority_cwe = %s")
                values.append(is_priority_cwe)
            
            if is_excluded is not None:
                where_conditions.append("is_excluded = %s")
                values.append(is_excluded)
            
            # Build query
            query = "SELECT * FROM web_cve_census_master"
            
            if where_conditions:
                query += " WHERE " + " AND ".join(where_conditions)
            
            # Add ordering
            query += " ORDER BY publication_year DESC, cve_id"
            
            # Add pagination
            if limit is not None:
                query += f" LIMIT {limit}"
            
            if offset is not None:
                query += f" OFFSET {offset}"
            
            cursor.execute(query, values)
            
            # Fetch results and convert to dictionaries
            columns = [desc[0] for desc in cursor.description]
            results = []
            
            for row in cursor.fetchall():
                results.append(dict(zip(columns, row)))
            
            logger.info(f"Query returned {len(results)} CVE records")
            return results
            
        except Exception as e:
            logger.error(f"Failed to query CVEs: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def get_cve_by_id(self, cve_id: str) -> Optional[dict]:
        """
        Get a single CVE by ID.
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            CVE record as dictionary, or None if not found
        """
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            cursor.execute(
                "SELECT * FROM web_cve_census_master WHERE cve_id = %s",
                (cve_id,)
            )
            
            row = cursor.fetchone()
            
            if row is None:
                return None
            
            columns = [desc[0] for desc in cursor.description]
            return dict(zip(columns, row))
            
        except Exception as e:
            logger.error(f"Failed to get CVE {cve_id}: {e}")
            raise
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def begin_transaction(self) -> Connection:
        """
        Begin a database transaction.
        
        Returns:
            Database connection with active transaction
        """
        conn = self.db_manager.get_connection()
        conn.autocommit = False
        return conn
    
    def commit_transaction(self, conn: Connection) -> None:
        """
        Commit a database transaction.
        
        Args:
            conn: Database connection with active transaction
        """
        try:
            conn.commit()
            logger.info("Transaction committed successfully")
        except Exception as e:
            logger.error(f"Failed to commit transaction: {e}")
            raise
        finally:
            self.db_manager.return_connection(conn)
    
    def rollback_transaction(self, conn: Connection) -> None:
        """
        Rollback a database transaction.
        
        Args:
            conn: Database connection with active transaction
        """
        try:
            conn.rollback()
            logger.info("Transaction rolled back")
        except Exception as e:
            logger.error(f"Failed to rollback transaction: {e}")
            raise
        finally:
            self.db_manager.return_connection(conn)
