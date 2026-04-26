#!/usr/bin/env python3
"""Script to verify the Web CVE Census System setup."""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def verify_imports():
    """Verify that all required modules can be imported."""
    logger.info("Verifying imports...")
    try:
        import psycopg2
        import dotenv
        import pydantic
        logger.info("✓ All required packages are installed")
        return True
    except ImportError as e:
        logger.error(f"✗ Missing package: {e}")
        return False


def verify_config():
    """Verify that configuration is valid."""
    logger.info("Verifying configuration...")
    try:
        from src.config import Config
        Config.validate()
        logger.info("✓ Configuration is valid")
        logger.info(f"  - Database URL: {Config.DATABASE_URL[:30]}...")
        logger.info(f"  - Census years: {Config.CENSUS_START_YEAR}-{Config.CENSUS_END_YEAR}")
        logger.info(f"  - Batch size: {Config.CENSUS_BATCH_SIZE}")
        return True
    except Exception as e:
        logger.error(f"✗ Configuration error: {e}")
        return False


def verify_database():
    """Verify database connection and schema."""
    logger.info("Verifying database connection...")
    try:
        from src.database import db_manager
        
        if not db_manager.test_connection():
            logger.error("✗ Database connection failed")
            return False
        
        logger.info("✓ Database connection successful")
        
        # Check if schema exists
        conn = db_manager.get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_name = 'web_cve_census_master'
            );
        """)
        exists = cursor.fetchone()[0]
        db_manager.return_connection(conn)
        
        if exists:
            logger.info("✓ Database schema exists")
        else:
            logger.warning("⚠ Database schema not found. Run 'python scripts/setup_database.py' to create it.")
        
        return True
    except Exception as e:
        logger.error(f"✗ Database error: {e}")
        return False


def main():
    """Run all verification checks."""
    logger.info("=" * 60)
    logger.info("Web CVE Census System - Setup Verification")
    logger.info("=" * 60)
    
    checks = [
        ("Package imports", verify_imports),
        ("Configuration", verify_config),
        ("Database", verify_database),
    ]
    
    results = []
    for name, check_func in checks:
        logger.info("")
        try:
            result = check_func()
            results.append((name, result))
        except Exception as e:
            logger.error(f"✗ {name} check failed with exception: {e}")
            results.append((name, False))
    
    logger.info("")
    logger.info("=" * 60)
    logger.info("Verification Summary")
    logger.info("=" * 60)
    
    all_passed = True
    for name, result in results:
        status = "✓ PASS" if result else "✗ FAIL"
        logger.info(f"{status}: {name}")
        if not result:
            all_passed = False
    
    logger.info("=" * 60)
    
    if all_passed:
        logger.info("✓ All checks passed! The system is ready to use.")
        sys.exit(0)
    else:
        logger.error("✗ Some checks failed. Please fix the issues above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
