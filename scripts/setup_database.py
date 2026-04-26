#!/usr/bin/env python3
"""Script to set up the database schema for the Web CVE Census System."""

import sys
import logging
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.database import db_manager
from src.config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)


def main():
    """Set up the database schema."""
    try:
        logger.info("Starting database setup...")
        logger.info(f"Database URL: {Config.DATABASE_URL[:30]}...")
        
        # Test connection
        logger.info("Testing database connection...")
        if not db_manager.test_connection():
            logger.error("Database connection test failed!")
            sys.exit(1)
        
        logger.info("Database connection successful!")
        
        # Create schema
        logger.info("Creating database schema...")
        db_manager.create_schema()
        
        logger.info("Database setup completed successfully!")
        logger.info("The web_cve_census_master table has been created with all constraints and indexes.")
        
    except Exception as e:
        logger.error(f"Database setup failed: {e}")
        sys.exit(1)
    finally:
        db_manager.close_pool()


if __name__ == "__main__":
    main()
