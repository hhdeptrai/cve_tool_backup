# Quick Start Guide

Get the Web CVE Census System up and running in 5 minutes!

## Prerequisites

- Python 3.10 or higher
- Internet connection
- A Neon account (free tier is fine)

## Step-by-Step Setup

### 1. Get Your Database Connection String

**Option A: Use Neon (Recommended - Free & Easy)**

1. Go to [https://neon.tech](https://neon.tech) and sign up
2. Create a new project (e.g., "web-cve-census")
3. Copy the **Pooled connection** string
4. It should look like: `postgresql://user:pass@ep-xxx.region.aws.neon.tech/dbname?sslmode=require`

**Option B: Use Your Own PostgreSQL**

If you have your own PostgreSQL server, use its connection string.

### 2. Configure Environment

```bash
# Navigate to project directory
cd data_cve_report

# Copy environment template
cp .env.example .env

# Edit .env and paste your connection string
nano .env  # or use your preferred editor
```

Update the `DATABASE_URL` line with your actual connection string:
```
DATABASE_URL=postgresql://your_user:your_pass@your_host.neon.tech/your_db?sslmode=require
```

Save and close the file.

### 3. Set Up Python Environment

```bash
# Create virtual environment
python3 -m venv venv

# Activate it
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 4. Test Database Connection

```bash
python scripts/test_connection.py
```

**Expected output:**
```
✓ Database connection successful!
✓ Connection string is valid
✓ Ready to create schema
```

If you see errors, check the [Troubleshooting](#troubleshooting) section below.

### 5. Create Database Schema

```bash
python scripts/setup_database.py
```

**Expected output:**
```
INFO - Database connection successful!
INFO - Creating database schema...
INFO - Database schema created successfully!
```

### 6. Verify Setup

```bash
python scripts/verify_setup.py
```

This will check:
- ✓ Database connection
- ✓ Table creation
- ✓ Indexes
- ✓ Constraints

### 7. Run Tests (Optional but Recommended)

```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run only database tests
pytest tests/test_database.py -v
```

## What's Next?

Now that your database is set up, you can:

1. **Collect CVE data**: Run the census collector (once implemented)
2. **Claim tasks**: Use the task management system
3. **Generate reports**: Create statistics and analysis

## Troubleshooting

### "Connection refused" or "Could not connect"

**Problem:** Can't connect to the database

**Solutions:**
- Verify your connection string in `.env` is correct
- Make sure `?sslmode=require` is at the end of the URL
- Check your internet connection
- Try the connection string directly in a PostgreSQL client

### "Authentication failed"

**Problem:** Username or password is incorrect

**Solutions:**
- Double-check the connection string from Neon dashboard
- Make sure there are no extra spaces in `.env`
- Try regenerating the password in Neon
- Copy-paste the connection string again (don't type it manually)

### "SSL connection required"

**Problem:** Missing SSL configuration

**Solutions:**
- Add `?sslmode=require` to the end of your connection string
- Update psycopg2: `pip install --upgrade psycopg2-binary`

### "Module not found" errors

**Problem:** Dependencies not installed or virtual environment not activated

**Solutions:**
```bash
# Make sure virtual environment is activated
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Reinstall dependencies
pip install -r requirements.txt
```

### "Permission denied" on database

**Problem:** Database user doesn't have required permissions

**Solutions:**
- Neon databases come with full permissions by default
- If using your own PostgreSQL, grant permissions:
  ```sql
  GRANT ALL PRIVILEGES ON DATABASE your_db TO your_user;
  ```

### Tests failing

**Problem:** Tests can't connect or fail unexpectedly

**Solutions:**
- Make sure the database schema is created: `python scripts/setup_database.py`
- Check that `.env` file exists and has correct DATABASE_URL
- Try running tests individually: `pytest tests/test_database.py::TestDatabaseSchema::test_table_creation -v`

## Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | Yes | - | PostgreSQL connection string |
| `GITHUB_TOKEN` | No | - | GitHub API token (for higher rate limits) |
| `EXPLOITDB_CSV_PATH` | No | `./data/files_exploits.csv` | Path to Exploit-DB CSV |
| `CENSUS_BATCH_SIZE` | No | `100` | CVEs per batch |
| `CENSUS_START_YEAR` | No | `2015` | Start year for census |
| `CENSUS_END_YEAR` | No | `2025` | End year for census |
| `CLAIM_EXPIRATION_DAYS` | No | `7` | Days before task claim expires |

## Useful Commands

```bash
# Activate virtual environment
source venv/bin/activate

# Test connection
python scripts/test_connection.py

# Set up database
python scripts/setup_database.py

# Verify setup
python scripts/verify_setup.py

# Run all tests
pytest

# Run tests with coverage
pytest --cov=src --cov-report=html

# Deactivate virtual environment
deactivate
```

## Getting Help

- **Detailed setup guide**: See `docs/setup/NEON_SETUP_GUIDE.md`
- **Project documentation**: See `README.md`
- **Spec documents**: See `.kiro/specs/web-cve-census-system/`

## Quick Reference

**Project structure:**
```
data_cve_report/
├── src/              # Source code
├── tests/            # Test suite
├── scripts/          # Utility scripts
├── docs/             # Documentation
├── .env              # Your configuration (not in git)
└── requirements.txt  # Python dependencies
```

**Key files:**
- `.env` - Your database connection and config
- `src/database.py` - Database connection and schema
- `src/config.py` - Configuration management
- `tests/test_database.py` - Database tests

---

**Ready to go?** Start with `python scripts/test_connection.py` and follow the steps above!
