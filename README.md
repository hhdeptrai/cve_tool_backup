# Web CVE Census System

A research tool for systematically collecting, analyzing, and verifying web-related Common Vulnerabilities and Exposures (CVEs) from 2020-2026.

## Overview

The Web CVE Census System automates the collection of CVE data from GitHub Advisory Database and Exploit-DB, stores structured information in a PostgreSQL database, and supports a manual verification workflow where researchers can claim tasks, build exploit environments, and verify exploit feasibility.

The system collects **ALL CVEs** from web ecosystems (npm, maven, pip, composer, go, rubygems) to ensure 100% coverage, then automatically labels priority CVEs based on CWE categories. Researchers can manually exclude non-web CVEs to curate the dataset.

## Features

- **Comprehensive CVE Collection**: Collects ALL CVEs from web ecosystems without CWE filtering at API level
- **Priority CWE Labeling**: Automatically labels CVEs with priority CWE categories (Injection, XSS, Authentication, Deserialization, SSRF, Path Traversal)
- **CVE Exclusion Mechanism**: Manual curation to exclude non-web CVEs with audit trail
- **Exploit Cross-Reference**: Automatically match CVEs with Exploit-DB exploits
- **Structured Storage**: PostgreSQL database with comprehensive schema and indexes
- **Verification Workflow**: Task management system for researchers to claim and verify CVEs
- **Dual Report Modes**: Priority mode (curated dataset) and full mode (complete transparency)
- **Reporting**: Generate statistics on CVE trends, exploit availability, and verification progress

## Project Structure

```
web-cve-census-system/
├── src/                           # Source code
│   ├── __init__.py
│   ├── census_collector.py        # CVE collection from GitHub Advisory
│   ├── claim_service.py           # Task claiming with concurrency control
│   ├── cli.py                     # Command-line interface
│   ├── config.py                  # Configuration management
│   ├── database.py                # Database connection and schema
│   ├── exclusion_service.py       # CVE exclusion and curation
│   ├── exploitdb_parser.py        # Exploit-DB CSV parsing
│   ├── github_advisory_client.py  # GitHub API client
│   ├── models.py                  # Data models and enumerations
│   ├── report_generator.py        # Statistical reporting
│   ├── task_manager.py            # Task lifecycle management
│   ├── validator.py               # Data validation
│   └── verification_service.py    # Verification status updates
├── tests/                         # Test suite
│   ├── __init__.py
│   ├── conftest.py                # Pytest fixtures
│   ├── test_*.py                  # Unit tests
│   └── test_*_properties.py       # Property-based tests
├── scripts/                       # Utility scripts
│   ├── run_census.py              # Automated census execution
│   ├── setup_database.py          # Database setup script
│   └── verify_setup.py            # Setup verification
├── docs/                          # Documentation
│   ├── CLI_USAGE.md               # CLI usage guide
│   ├── CONFIGURATION.md           # Configuration reference
│   └── NEON_SETUP_GUIDE.md        # Database setup guide
├── data/                          # Data files
│   └── exploitdb/                 # Exploit-DB CSV files
├── logs/                          # Log files
├── reports/                       # Generated reports
├── requirements.txt               # Python dependencies
├── config.yaml                    # YAML configuration
├── .env.example                   # Example environment variables
└── README.md                      # This file
```

## Setup

### Prerequisites

- Python 3.10 or higher
- PostgreSQL database (Neon or local)
- Git

### Installation

1. **Clone the repository** (if not already done)

2. **Create a virtual environment**:
   ```bash
   cd data_cve_report
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   ```bash
   cp .env.example .env
   # Edit .env and set your DATABASE_URL and other configuration
   ```

   Required environment variables:
   - `DATABASE_URL`: PostgreSQL connection string (e.g., `postgresql://user:password@host.neon.tech/dbname?sslmode=require`)
   - `GITHUB_TOKEN`: (Optional) GitHub personal access token for higher API rate limits
   - `EXPLOITDB_CSV_PATH`: Path to Exploit-DB CSV file

5. **Set up the database**:
   ```bash
   python scripts/setup_database.py
   ```

   This will:
   - Test the database connection
   - Create the `web_cve_census_master` table
   - Create all required indexes and constraints

### Database Schema

The system uses a single main table: `web_cve_census_master`

**Key fields**:
- **Identification**: `cve_id` (primary key)
- **Metadata**: `description`, `severity`, `cvss_base_score`, `cvss_exploitability_score`, `affected_package`, `ecosystem`, `publication_year`, `cwe_category`
- **Priority Labeling**: `is_priority_cwe` (TRUE for priority CWE categories)
- **Exploit Info**: `exploit_available`, `exploit_db_id`
- **Exclusion Mechanism**: `is_excluded`, `excluded_by`, `excluded_at`, `exclusion_reason`
- **Verification**: `build_status`, `exploit_status`, `research_depth`, `assigned_to`, `assigned_at`, `claim_expires_at`, `exploit_notes`, `updated_at`

**Constraints**:
- CVSS scores: 0.0 - 10.0
- Publication year: 2015 - 2025
- Ecosystem: npm, maven, pip, composer, go, rubygems
- Build status: NOT_ATTEMPTED, IN_PROGRESS, SUCCESS, FAILED
- Exploit status: NONE, POC_PUBLIC, EXPLOIT_DB, VERIFIED_SUCCESS, UNEXPLOITABLE
- Research depth: LEVEL_0, LEVEL_1, LEVEL_2
- Exclusion reason: Required when is_excluded = TRUE

For detailed schema documentation, see [Database Schema](#database-schema-details) section below.

## Testing

Run the test suite:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run specific test file
pytest tests/test_database.py

# Run with verbose output
pytest -v
```

**Note**: Tests require a test database. Set the `TEST_DATABASE_URL` environment variable to point to your test database, or the tests will use a default local PostgreSQL instance.

## Development

### Code Quality

The project uses:
- **black**: Code formatting
- **flake8**: Linting
- **mypy**: Type checking

Run quality checks:
```bash
black src/ tests/
flake8 src/ tests/
mypy src/
```

### Adding New Features

1. Review the design document in `.kiro/specs/web-cve-census-system/design.md`
2. Check the task list in `.kiro/specs/web-cve-census-system/tasks.md`
3. Write tests first (TDD approach)
4. Implement the feature
5. Ensure all tests pass

## Configuration

All configuration is managed through environment variables and YAML configuration. See `.env.example` for available options:

- **Database**: `DATABASE_URL`
- **GitHub API**: `GITHUB_TOKEN` (recommended for higher rate limits: 5000 req/hour vs 60 req/hour)
- **Exploit-DB**: `EXPLOITDB_CSV_PATH`
- **Census**: `CENSUS_BATCH_SIZE`, `CENSUS_START_YEAR`, `CENSUS_END_YEAR`, `CENSUS_PRIORITY_CWES`
- **Tasks**: `CLAIM_EXPIRATION_DAYS`, `VALID_RESEARCHERS`
- **Exclusion**: `EXCLUSION_REQUIRE_REASON`, `EXCLUSION_AUDIT_ENABLED`
- **Reporting**: `REPORT_DEFAULT_MODE` (priority or full)

For detailed configuration documentation, see [docs/CONFIGURATION.md](docs/CONFIGURATION.md).

## Usage

### Quick Start

```bash
# 1. Collect CVEs from 2020-2021
python census census collect --year-start 2020 --year-end 2021

# 2. Claim 10 tasks for verification
python census task claim --researcher Minh --year 2021 --count 10

# 3. Update task status
python census task update --cve-id CVE-2021-12345 --researcher Minh \
  --exploit-status VERIFIED_SUCCESS \
  --notes "Successfully exploited using Docker environment"

# 4. Exclude non-web CVEs
python census task exclude --cve-id CVE-2021-99999 --researcher Minh \
  --reason "Desktop application, not web-related"

# 5. Generate priority report (excludes excluded CVEs)
python census report generate --output report.json --mode priority
```

### Verification Workflow

Follow these steps when verifying a claimed task:

1.  **Analyze (Level 0)**: Read the description and referenced advisory.
    *   *Goal*: Understand the vulnerability (what, where, which versions).
    *   *Command*: `python census task list --researcher Minh` (gives basic info)

2.  **Build (Level 1)**: Attempt to set up a reproduction environment.
    *   *Goal*: Create a safe, isolated environment (e.g., using Docker) with the vulnerable package.
    *   *Update Command*:
        ```bash
        python census task update --cve-id CVE-2021-12345 --researcher Minh --build-status SUCCESS
        ```

3.  **Exploit (Level 2)**: Try to reproduce the vulnerability.
    *   *Goal*: Prove existence by triggering it (e.g., pop a shell, alert(1)).
    *   *Update Command*:
        ```bash
        python census task update \
          --cve-id CVE-2021-12345 \
          --researcher Minh \
          --build-status SUCCESS \
          --exploit-status VERIFIED_SUCCESS \
          --research-depth LEVEL_2 \
          --notes "Successfully reproduced using Docker container. RCE confirmed with payload..."
        ```

For detailed CLI usage, see [docs/CLI_USAGE.md](docs/CLI_USAGE.md).

## Architecture

### New Collection Approach

The system uses a **collect-all-then-label** approach:

1. **Collection**: Collect ALL CVEs from web ecosystems (npm, maven, pip, composer, go, rubygems) without CWE filtering at API level
2. **Labeling**: Automatically label CVEs with `is_priority_cwe=TRUE` for priority CWE categories (Injection, XSS, Authentication, Deserialization, SSRF, Path Traversal)
3. **Storage**: Store ALL CVEs regardless of CWE category to ensure 100% coverage
4. **Curation**: Researchers manually exclude non-web CVEs using the exclusion mechanism
5. **Reporting**: Generate reports in priority mode (default, excludes excluded CVEs) or full mode (includes all CVEs)

**Rationale**: Web ecosystems are 95% web-related. Collecting all CVEs ensures no web vulnerabilities are missed, while priority labeling helps researchers focus on high-value targets.

### API Rate Limits

**GitHub Advisory API**:
- Without token: 60 requests/hour
- With token: 5000 requests/hour
- Batch size: 100 CVEs per request (recommended)
- Rate limit handling: Exponential backoff with retry

**Best Practices**:
- Always use a GitHub personal access token (set `GITHUB_TOKEN` in `.env`)
- Monitor rate limit headers in logs
- Adjust `CENSUS_BATCH_SIZE` if needed (default: 100)
- Run census collection during off-peak hours for large datasets

## Database Schema Details

### Table: web_cve_census_master

```sql
CREATE TABLE web_cve_census_master (
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
    cwe_category VARCHAR(50),
    
    -- CWE labeling (NEW)
    is_priority_cwe BOOLEAN DEFAULT FALSE,
    
    -- Exploit-DB cross-reference
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_db_id VARCHAR(50),
    
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
    CONSTRAINT chk_year CHECK (publication_year BETWEEN 2015 AND 2025),
    CONSTRAINT chk_ecosystem CHECK (ecosystem IN ('npm', 'maven', 'pip', 'composer', 'go', 'rubygems')),
    CONSTRAINT chk_build_status CHECK (build_status IN ('NOT_ATTEMPTED', 'IN_PROGRESS', 'SUCCESS', 'FAILED')),
    CONSTRAINT chk_exploit_status CHECK (exploit_status IN ('NONE', 'POC_PUBLIC', 'EXPLOIT_DB', 'VERIFIED_SUCCESS', 'UNEXPLOITABLE')),
    CONSTRAINT chk_research_depth CHECK (research_depth IN ('LEVEL_0', 'LEVEL_1', 'LEVEL_2')),
    CONSTRAINT chk_exclusion_reason CHECK (is_excluded = FALSE OR exclusion_reason IS NOT NULL)
);
```

### Indexes

The system creates indexes for common query patterns:

- `idx_publication_year`: Filter by year
- `idx_ecosystem`: Filter by ecosystem
- `idx_cwe_category`: Filter by CWE category
- `idx_is_priority_cwe`: Filter by priority CWE flag (NEW)
- `idx_is_excluded`: Filter by exclusion status (NEW)
- `idx_exploit_available`: Filter by exploit availability
- `idx_assigned_to`: Filter by researcher
- `idx_exploit_status`: Filter by verification status

### Data Models

**CVEData**:
```python
@dataclass
class CVEData:
    cve_id: str
    description: str
    severity: str
    cvss_base_score: float
    cvss_exploitability_score: float
    affected_package: str
    ecosystem: str
    publication_year: int
    cwe_category: str
    is_priority_cwe: bool = False          # NEW
    exploit_available: bool = False
    exploit_db_id: Optional[str] = None
    is_excluded: bool = False              # NEW
    excluded_by: Optional[str] = None      # NEW
    excluded_at: Optional[datetime] = None # NEW
    exclusion_reason: Optional[str] = None # NEW
```

**Enumerations**:
- `BuildStatus`: NOT_ATTEMPTED, IN_PROGRESS, SUCCESS, FAILED
- `ExploitStatus`: NONE, POC_PUBLIC, EXPLOIT_DB, VERIFIED_SUCCESS, UNEXPLOITABLE
- `ResearchDepth`: LEVEL_0 (metadata only), LEVEL_1 (code review), LEVEL_2 (complete analysis)
- `Ecosystem`: npm, maven, pip, composer, go, rubygems
- `CWECategory`: Injection, XSS, Authentication, Deserialization, SSRF, Path Traversal

## License

This is a research project. Please check with the project maintainers for licensing information.

## Documentation

📚 **All documentation has been organized in the `docs/` folder**

### Quick Links
- **[Quick Start Guide](docs/setup/QUICKSTART.md)** - Get up and running in 5 minutes
- **[Usage Guide](docs/guides/USAGE.md)** - Comprehensive usage examples and workflows
- **[Verification Criteria](docs/guides/VERIFICATION_CRITERIA.md)** - Criteria for builds and exploits
- **[CLI Reference](docs/guides/CLI_USAGE.md)** - Command-line interface guide
- **[Configuration Guide](docs/reference/CONFIGURATION.md)** - All configuration options
- **[Database Schema](docs/reference/DATABASE_SCHEMA.md)** - Database structure and models
- **[Full Documentation Index](docs/README.md)** - Complete documentation index

### Documentation Structure
```
docs/
├── setup/          # Setup and installation guides
├── guides/         # User guides and tutorials
├── reference/      # Technical reference documentation
├── architecture/   # Architecture and design docs
├── status/         # Project status and reports
└── tasks/          # Implementation task summaries
```

See **[DOCUMENTATION.md](DOCUMENTATION.md)** for the complete documentation guide.

## Contributing

This project follows a specification-driven development approach. All features are documented in the `.kiro/specs/` directory with requirements, design, and tasks.

## Support

For issues or questions, please refer to the documentation above or contact the project maintainers.

**Email of the project maintainer**: tqminhhcm@gmail.com
