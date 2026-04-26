#!/usr/bin/env python3
"""Comprehensive verification of Neon PostgreSQL integration."""

import sys
import os
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import Config
from src.database import db_manager
import psycopg2


def print_header(text):
    """Print a formatted header."""
    print()
    print("=" * 70)
    print(f"  {text}")
    print("=" * 70)


def print_section(text):
    """Print a section header."""
    print()
    print(f"→ {text}")
    print("-" * 70)


def print_success(text):
    """Print a success message."""
    print(f"  ✓ {text}")


def print_error(text):
    """Print an error message."""
    print(f"  ✗ {text}")


def print_info(text, indent=2):
    """Print an info message."""
    print(f"{' ' * indent}{text}")


def verify_environment():
    """Verify environment configuration."""
    print_section("1. Environment Configuration")
    
    try:
        # Check .env file exists
        env_path = Path('.env')
        if not env_path.exists():
            print_error(".env file not found")
            return False
        print_success(".env file exists")
        
        # Check DATABASE_URL is set
        if not Config.DATABASE_URL:
            print_error("DATABASE_URL not set in .env")
            return False
        print_success("DATABASE_URL is configured")
        print_info(f"Host: {Config.DATABASE_URL.split('@')[1].split('/')[0]}")
        
        # Check configuration values
        print_success(f"Census years: {Config.CENSUS_START_YEAR}-{Config.CENSUS_END_YEAR}")
        print_success(f"Batch size: {Config.CENSUS_BATCH_SIZE}")
        print_success(f"Claim expiration: {Config.CLAIM_EXPIRATION_DAYS} days")
        
        return True
    except Exception as e:
        print_error(f"Configuration error: {e}")
        return False


def verify_connection():
    """Verify database connection."""
    print_section("2. Database Connection")
    
    try:
        conn = db_manager.get_connection()
        print_success("Connection established")
        
        cursor = conn.cursor()
        
        # Get PostgreSQL version
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        pg_version = version.split(',')[0].replace('PostgreSQL ', '')
        print_success(f"PostgreSQL version: {pg_version}")
        
        # Check if we're connected to Neon
        if 'neon' in Config.DATABASE_URL.lower():
            print_success("Connected to Neon PostgreSQL (remote)")
        else:
            print_info("Connected to local/other PostgreSQL")
        
        # Test write permissions
        cursor.execute("CREATE TEMP TABLE test_write (id INTEGER);")
        cursor.execute("INSERT INTO test_write VALUES (1);")
        cursor.execute("SELECT * FROM test_write;")
        result = cursor.fetchone()
        print_success("Write permissions confirmed")
        
        cursor.close()
        db_manager.return_connection(conn)
        
        return True
    except Exception as e:
        print_error(f"Connection failed: {e}")
        return False


def verify_schema():
    """Verify database schema."""
    print_section("3. Database Schema")
    
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # Check table exists
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'public' 
                AND table_name = 'web_cve_census_master'
            );
        """)
        exists = cursor.fetchone()[0]
        
        if not exists:
            print_error("web_cve_census_master table not found")
            return False
        print_success("web_cve_census_master table exists")
        
        # Count columns
        cursor.execute("""
            SELECT COUNT(*) 
            FROM information_schema.columns 
            WHERE table_name = 'web_cve_census_master';
        """)
        col_count = cursor.fetchone()[0]
        print_success(f"{col_count} columns defined")
        
        # List key columns
        cursor.execute("""
            SELECT column_name, data_type, is_nullable
            FROM information_schema.columns 
            WHERE table_name = 'web_cve_census_master'
            AND column_name IN ('cve_id', 'description', 'ecosystem', 'publication_year')
            ORDER BY ordinal_position;
        """)
        key_cols = cursor.fetchall()
        print_info("Key columns:")
        for col in key_cols:
            nullable = "NULL" if col[2] == 'YES' else "NOT NULL"
            print_info(f"  • {col[0]}: {col[1]} ({nullable})", indent=4)
        
        cursor.close()
        db_manager.return_connection(conn)
        
        return True
    except Exception as e:
        print_error(f"Schema verification failed: {e}")
        return False


def verify_indexes():
    """Verify database indexes."""
    print_section("4. Database Indexes")
    
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT indexname 
            FROM pg_indexes 
            WHERE tablename = 'web_cve_census_master'
            ORDER BY indexname;
        """)
        indexes = cursor.fetchall()
        
        expected_indexes = [
            'web_cve_census_master_pkey',
            'idx_publication_year',
            'idx_ecosystem',
            'idx_cwe_category',
            'idx_exploit_available',
            'idx_assigned_to',
            'idx_exploit_status'
        ]
        
        found_indexes = [idx[0] for idx in indexes]
        
        all_found = True
        for expected in expected_indexes:
            if expected in found_indexes:
                print_success(f"{expected}")
            else:
                print_error(f"{expected} - MISSING")
                all_found = False
        
        cursor.close()
        db_manager.return_connection(conn)
        
        return all_found
    except Exception as e:
        print_error(f"Index verification failed: {e}")
        return False


def verify_constraints():
    """Verify database constraints."""
    print_section("5. Database Constraints")
    
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        cursor.execute("""
            SELECT conname, contype 
            FROM pg_constraint 
            WHERE conrelid = 'web_cve_census_master'::regclass
            ORDER BY conname;
        """)
        constraints = cursor.fetchall()
        
        constraint_types = {
            'p': 'PRIMARY KEY',
            'c': 'CHECK',
            'f': 'FOREIGN KEY',
            'u': 'UNIQUE'
        }
        
        expected_constraints = [
            'chk_cvss_base',
            'chk_cvss_exploit',
            'chk_year',
            'chk_ecosystem',
            'chk_build_status',
            'chk_exploit_status',
            'chk_research_depth',
            'web_cve_census_master_pkey'
        ]
        
        found_constraints = [con[0] for con in constraints]
        
        all_found = True
        for expected in expected_constraints:
            if expected in found_constraints:
                con_type = next((c[1] for c in constraints if c[0] == expected), None)
                type_name = constraint_types.get(con_type, 'UNKNOWN')
                print_success(f"{expected} ({type_name})")
            else:
                print_error(f"{expected} - MISSING")
                all_found = False
        
        cursor.close()
        db_manager.return_connection(conn)
        
        return all_found
    except Exception as e:
        print_error(f"Constraint verification failed: {e}")
        return False


def test_crud_operations():
    """Test basic CRUD operations."""
    print_section("6. CRUD Operations Test")
    
    try:
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        
        # CREATE
        test_cve_id = 'CVE-9999-99999'
        cursor.execute("""
            INSERT INTO web_cve_census_master 
            (cve_id, description, ecosystem, publication_year)
            VALUES (%s, %s, %s, %s);
        """, (test_cve_id, 'Test CVE for verification', 'npm', 2021))
        conn.commit()
        print_success("CREATE: Inserted test record")
        
        # READ
        cursor.execute("""
            SELECT cve_id, description, ecosystem, publication_year
            FROM web_cve_census_master
            WHERE cve_id = %s;
        """, (test_cve_id,))
        result = cursor.fetchone()
        if result and result[0] == test_cve_id:
            print_success(f"READ: Retrieved test record")
        else:
            print_error("READ: Failed to retrieve test record")
            return False
        
        # UPDATE
        cursor.execute("""
            UPDATE web_cve_census_master
            SET description = %s
            WHERE cve_id = %s;
        """, ('Updated test description', test_cve_id))
        conn.commit()
        print_success("UPDATE: Modified test record")
        
        # DELETE
        cursor.execute("""
            DELETE FROM web_cve_census_master
            WHERE cve_id = %s;
        """, (test_cve_id,))
        conn.commit()
        print_success("DELETE: Removed test record")
        
        # Verify deletion
        cursor.execute("""
            SELECT COUNT(*) FROM web_cve_census_master
            WHERE cve_id = %s;
        """, (test_cve_id,))
        count = cursor.fetchone()[0]
        if count == 0:
            print_success("Cleanup: Test record removed")
        else:
            print_error("Cleanup: Test record still exists")
        
        cursor.close()
        db_manager.return_connection(conn)
        
        return True
    except Exception as e:
        print_error(f"CRUD operations failed: {e}")
        return False


def verify_project_structure():
    """Verify project structure."""
    print_section("7. Project Structure")
    
    required_files = [
        'src/__init__.py',
        'src/config.py',
        'src/database.py',
        'src/models.py',
        'tests/__init__.py',
        'tests/conftest.py',
        'tests/test_database.py',
        'scripts/setup_database.py',
        'scripts/test_connection.py',
        'scripts/verify_setup.py',
        'requirements.txt',
        '.env',
        'README.md'
    ]
    
    all_exist = True
    for file_path in required_files:
        path = Path(file_path)
        if path.exists():
            print_success(f"{file_path}")
        else:
            print_error(f"{file_path} - MISSING")
            all_exist = False
    
    return all_exist


def main():
    """Run comprehensive verification."""
    print_header("COMPREHENSIVE NEON POSTGRESQL VERIFICATION")
    print()
    print("This script will verify:")
    print("  • Environment configuration")
    print("  • Database connection to Neon")
    print("  • Schema creation and structure")
    print("  • Indexes and constraints")
    print("  • CRUD operations")
    print("  • Project file structure")
    
    results = {
        'Environment': verify_environment(),
        'Connection': verify_connection(),
        'Schema': verify_schema(),
        'Indexes': verify_indexes(),
        'Constraints': verify_constraints(),
        'CRUD Operations': test_crud_operations(),
        'Project Structure': verify_project_structure()
    }
    
    # Summary
    print_header("VERIFICATION SUMMARY")
    print()
    
    all_passed = True
    for check, passed in results.items():
        status = "✓ PASS" if passed else "✗ FAIL"
        print(f"  {status}: {check}")
        if not passed:
            all_passed = False
    
    print()
    print("=" * 70)
    
    if all_passed:
        print()
        print("  🎉 ALL CHECKS PASSED!")
        print()
        print("  Your Neon PostgreSQL database is fully integrated with the project.")
        print("  The system is ready for development and testing.")
        print()
        print("=" * 70)
        return 0
    else:
        print()
        print("  ⚠️  SOME CHECKS FAILED")
        print()
        print("  Please review the errors above and fix any issues.")
        print()
        print("=" * 70)
        return 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    finally:
        db_manager.close_pool()
