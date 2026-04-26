#!/usr/bin/env python3
"""Test database connection before setting up schema."""

import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.config import Config
import psycopg2


def test_connection():
    """Test the database connection."""
    print("Testing database connection...")
    print(f"Database URL: {Config.DATABASE_URL[:30]}..." if len(Config.DATABASE_URL) > 30 else Config.DATABASE_URL)
    print()
    
    try:
        # Test basic connection
        print("→ Attempting to connect...")
        conn = psycopg2.connect(Config.DATABASE_URL)
        print("✓ Connection established")
        
        # Test query execution
        print("→ Testing query execution...")
        cursor = conn.cursor()
        cursor.execute("SELECT version();")
        version = cursor.fetchone()[0]
        print(f"✓ Query successful")
        print(f"  PostgreSQL version: {version.split(',')[0]}")
        
        # Test write permissions
        print("→ Testing write permissions...")
        cursor.execute("CREATE TEMP TABLE test_table (id INTEGER);")
        cursor.execute("INSERT INTO test_table VALUES (1);")
        cursor.execute("SELECT * FROM test_table;")
        result = cursor.fetchone()
        print(f"✓ Write permissions confirmed")
        
        cursor.close()
        conn.close()
        
        print()
        print("=" * 50)
        print("✓ Database connection successful!")
        print("✓ Connection string is valid")
        print("✓ Ready to create schema")
        print("=" * 50)
        print()
        print("Next step: Run 'python scripts/setup_database.py'")
        
        return True
        
    except psycopg2.OperationalError as e:
        print()
        print("✗ Connection failed!")
        print(f"  Error: {e}")
        print()
        print("Troubleshooting:")
        print("  1. Check your DATABASE_URL in .env file")
        print("  2. Verify the connection string format:")
        print("     postgresql://user:password@host.neon.tech/dbname?sslmode=require")
        print("  3. Make sure you're using the pooled connection from Neon")
        print("  4. Check that ?sslmode=require is at the end")
        print()
        return False
        
    except Exception as e:
        print()
        print("✗ Unexpected error!")
        print(f"  Error: {e}")
        print()
        return False


if __name__ == "__main__":
    success = test_connection()
    sys.exit(0 if success else 1)
