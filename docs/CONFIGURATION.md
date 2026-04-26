# Configuration Guide

This document explains how to configure the Web CVE Census System using environment variables and configuration files.

## Configuration Files

The system uses two configuration approaches:

1. **Environment Variables** (`.env` file) - Primary configuration method
2. **YAML Configuration** (`config.yaml`) - Advanced configuration with structured settings

### Priority Order

Configuration values are loaded in the following priority order (highest to lowest):

1. Environment variables (from `.env` or system environment)
2. YAML configuration file (`config.yaml`)
3. Default values (hardcoded in `src/config.py`)

## Quick Start

### 1. Set Up Environment Variables

Copy the example environment file:

```bash
cp .env.example .env
```

Edit `.env` and configure at minimum:

```bash
# Required: Database connection
DATABASE_URL=postgresql://user:password@host.neon.tech/dbname?sslmode=require

# Recommended: GitHub API token for higher rate limits
GITHUB_TOKEN=your_github_personal_access_token_here
```

### 2. (Optional) Customize YAML Configuration

The `config.yaml` file provides advanced configuration options. Most users can use the defaults.

## Configuration Reference

### Database Configuration

#### Required Settings

- **DATABASE_URL**: PostgreSQL connection string
  - Format: `postgresql://user:password@host.neon.tech/dbname?sslmode=require`
  - Example: `postgresql://myuser:mypass@ep-cool-name-123456.us-east-2.aws.neon.tech/cve_census?sslmode=require`

#### Optional Settings

- **DB_POOL_MIN_SIZE**: Minimum connection pool size (default: 2)
- **DB_POOL_MAX_SIZE**: Maximum connection pool size (default: 10)
- **DB_POOL_TIMEOUT**: Connection timeout in seconds (default: 30)
- **DB_QUERY_TIMEOUT**: Query timeout in seconds (default: 60)

### GitHub API Configuration

#### Recommended Settings

- **GITHUB_TOKEN**: Personal access token for GitHub API
  - Without token: 60 requests/hour
  - With token: 5000 requests/hour
  - Create at: https://github.com/settings/tokens
  - Required scopes: `public_repo` (read-only access to public repositories)

#### Optional Settings

- **GITHUB_API_URL**: GraphQL API endpoint (default: `https://api.github.com/graphql`)
- **GITHUB_RATE_LIMIT_MAX**: Maximum requests per hour (default: 5000)
- **GITHUB_RETRY_ATTEMPTS**: Number of retry attempts on failure (default: 3)
- **GITHUB_RETRY_DELAY**: Initial retry delay in seconds (default: 5)

### Exploit-DB Configuration

- **EXPLOITDB_CSV_PATH**: Path to Exploit-DB CSV file (default: `./data/exploitdb/files_exploits.csv`)
- **EXPLOITDB_CSV_URL**: Download URL for CSV file (default: GitLab URL)
- **EXPLOITDB_CACHE_ENABLED**: Enable caching (default: true)
- **EXPLOITDB_CACHE_TTL**: Cache time-to-live in seconds (default: 604800 = 7 days)

### Census Collection Configuration

#### Year Range

- **CENSUS_START_YEAR**: Starting year for CVE collection (default: 2015, range: 2015-2025)
- **CENSUS_END_YEAR**: Ending year for CVE collection (default: 2025, range: 2015-2025)

#### Collection Settings

- **CENSUS_BATCH_SIZE**: Number of CVEs per API request (default: 100, recommended: 100)
- **CENSUS_ECOSYSTEMS**: Comma-separated list of ecosystems (default: `npm,maven,pip,composer,go,rubygems`)
- **CENSUS_PRIORITY_CWES**: Comma-separated list of priority CWE categories (default: `Injection,XSS,Authentication,Deserialization,SSRF,Path Traversal`)

#### Error Handling

- **CENSUS_CONTINUE_ON_ERROR**: Continue processing on errors (default: true)
- **CENSUS_MAX_CONSECUTIVE_ERRORS**: Maximum consecutive errors before stopping (default: 10)

### Task Management Configuration

#### Claim Settings

- **CLAIM_EXPIRATION_DAYS**: Days until claim expires (default: 7)
- **TASK_BATCH_DEFAULT_SIZE**: Default batch size for task claiming (default: 10)
- **TASK_BATCH_MAX_SIZE**: Maximum batch size (default: 50)

#### Researcher Settings

- **VALID_RESEARCHERS**: Comma-separated list of valid researcher IDs (default: `Minh,Hoàng`)

#### Prioritization

- **TASK_PREFER_EXPLOIT_AVAILABLE**: Prioritize CVEs with exploits (default: true)
- **TASK_ORDER_BY_YEAR**: Sort order by year - `desc` (newest first) or `asc` (oldest first) (default: desc)

### Verification Workflow Configuration

- **VERIFICATION_REQUIRE_NOTES**: Require notes for verified/unexploitable status (default: true)
- **VERIFICATION_MIN_NOTES_LENGTH**: Minimum length for notes (default: 10)

### CVE Exclusion Configuration

- **EXCLUSION_REQUIRE_REASON**: Require reason for exclusion (default: true)
- **EXCLUSION_MIN_REASON_LENGTH**: Minimum length for exclusion reason (default: 10)
- **EXCLUSION_AUDIT_ENABLED**: Enable audit logging (default: true)
- **EXCLUSION_AUDIT_LOG_PATH**: Path to audit log file (default: `./logs/exclusion_audit.log`)

### Reporting Configuration

- **REPORT_DEFAULT_MODE**: Default report mode - `priority` or `full` (default: priority)
- **REPORT_OUTPUT_DIR**: Output directory for reports (default: `./reports`)
- **REPORT_FORMATS**: Comma-separated list of formats - `json`, `csv`, `markdown` (default: `json,csv,markdown`)

### Logging Configuration

#### Log Level

- **LOG_LEVEL**: Logging level - `DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL` (default: INFO)

#### File Logging

- **LOG_FILE_ENABLED**: Enable file logging (default: true)
- **LOG_FILE_PATH**: Path to log file (default: `./logs/census.log`)
- **LOG_FILE_MAX_BYTES**: Maximum log file size in bytes (default: 10485760 = 10 MB)
- **LOG_FILE_BACKUP_COUNT**: Number of backup log files (default: 5)

#### Console Logging

- **LOG_CONSOLE_ENABLED**: Enable console logging (default: true)
- **LOG_CONSOLE_COLORIZE**: Enable colored console output (default: true)

### Data Validation Configuration

- **CVE_ID_PATTERN**: Regex pattern for CVE ID validation (default: `^CVE-\d{4}-\d{4,}$`)
- **CVSS_MIN**: Minimum CVSS score (default: 0.0)
- **CVSS_MAX**: Maximum CVSS score (default: 10.0)
- **YEAR_MIN**: Minimum publication year (default: 2015)
- **YEAR_MAX**: Maximum publication year (default: 2025)

### Performance Configuration

#### Query Optimization

- **QUERY_USE_INDEXES**: Use database indexes (default: true)
- **QUERY_EXPLAIN_SLOW**: Explain slow queries (default: true)
- **QUERY_SLOW_THRESHOLD**: Slow query threshold in milliseconds (default: 1000)

#### Caching

- **CACHE_ENABLED**: Enable caching (default: true)
- **CACHE_BACKEND**: Cache backend - `memory` or `redis` (default: memory)
- **CACHE_TTL**: Cache time-to-live in seconds (default: 3600 = 1 hour)

#### Concurrency

- **CONCURRENCY_MAX_WORKERS**: Maximum concurrent workers (default: 4)
- **CONCURRENCY_USE_POOLING**: Use connection pooling (default: true)

### Development Configuration

- **DEBUG**: Enable debug mode (default: false)
- **USE_TEST_DB**: Use test database (default: false)
- **MOCK_APIS**: Mock external APIs for testing (default: false)
- **SEED_ENABLED**: Enable database seeding (default: false)
- **SEED_SAMPLE_SIZE**: Number of sample records to seed (default: 100)

## YAML Configuration

The `config.yaml` file provides a structured way to configure the system. It supports:

- Hierarchical configuration
- Environment variable substitution
- Comments and documentation
- Default values

### Environment Variable Substitution

In `config.yaml`, you can reference environment variables using:

- `${VAR}` - Use environment variable VAR, or keep placeholder if not set
- `${VAR:default}` - Use environment variable VAR, or use default value if not set

Example:

```yaml
database:
  url: ${DATABASE_URL}
  pool:
    max_size: ${DB_POOL_MAX_SIZE:10}
```

### Accessing YAML Configuration in Code

```python
from src.config import Config

# Get a nested value from YAML
max_size = Config.get_yaml_value('database', 'pool', 'max_size', default=10)

# Get all configuration as dictionary
all_config = Config.get_all()
```

## Configuration Validation

The system validates configuration on startup and will raise errors for:

- Missing required settings (e.g., DATABASE_URL)
- Invalid value ranges (e.g., year outside 2015-2025)
- Invalid enum values (e.g., invalid report mode)

## Best Practices

### Security

1. **Never commit `.env` to version control** - It contains sensitive credentials
2. **Use strong database passwords** - Generate random passwords with sufficient entropy
3. **Rotate GitHub tokens regularly** - Create new tokens and revoke old ones
4. **Restrict database access** - Use IP allowlists in Neon dashboard

### Performance

1. **Use GitHub token** - Increases rate limit from 60 to 5000 requests/hour
2. **Adjust batch size** - Larger batches (up to 100) reduce API calls
3. **Enable caching** - Reduces database queries and API calls
4. **Use connection pooling** - Improves database performance

### Reliability

1. **Enable error continuation** - System continues on individual CVE failures
2. **Set appropriate timeouts** - Prevent hanging on slow operations
3. **Configure retry logic** - Automatic retry on transient failures
4. **Enable audit logging** - Track exclusion operations

### Development

1. **Use test database** - Set `USE_TEST_DB=true` for development
2. **Enable debug logging** - Set `LOG_LEVEL=DEBUG` for troubleshooting
3. **Mock APIs** - Set `MOCK_APIS=true` to avoid rate limits during testing
4. **Seed test data** - Set `SEED_ENABLED=true` for quick testing

## Troubleshooting

### Database Connection Issues

**Error**: `ValueError: DATABASE_URL environment variable is required`

**Solution**: Set DATABASE_URL in `.env` file

**Error**: `psycopg2.OperationalError: could not connect to server`

**Solution**: 
- Check database URL is correct
- Verify network connectivity
- Check Neon dashboard for database status
- Ensure IP is allowlisted (if configured)

### GitHub API Issues

**Error**: `Rate limit exceeded`

**Solution**:
- Add GITHUB_TOKEN to `.env` file
- Wait for rate limit reset (check response headers)
- Reduce CENSUS_BATCH_SIZE

**Error**: `Bad credentials`

**Solution**:
- Verify GITHUB_TOKEN is valid
- Check token has required scopes
- Generate new token if expired

### Exploit-DB Issues

**Error**: `FileNotFoundError: files_exploits.csv not found`

**Solution**:
- Download CSV manually to configured path
- Check EXPLOITDB_CSV_PATH is correct
- Ensure data directory exists

## Examples

### Minimal Configuration

```bash
# .env
DATABASE_URL=postgresql://user:pass@host.neon.tech/db?sslmode=require
```

### Production Configuration

```bash
# .env
DATABASE_URL=postgresql://user:pass@host.neon.tech/db?sslmode=require
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx

# Performance tuning
DB_POOL_MAX_SIZE=20
CENSUS_BATCH_SIZE=100
CACHE_ENABLED=true

# Logging
LOG_LEVEL=INFO
LOG_FILE_ENABLED=true

# Security
EXCLUSION_AUDIT_ENABLED=true
```

### Development Configuration

```bash
# .env
DATABASE_URL=postgresql://user:pass@localhost:5432/test_db
USE_TEST_DB=true
DEBUG=true
LOG_LEVEL=DEBUG
MOCK_APIS=true
SEED_ENABLED=true
```

## Support

For configuration issues:

1. Check this documentation
2. Review `.env.example` for correct format
3. Check `config.yaml` for advanced options
4. Review logs in `./logs/census.log`
5. Consult the main README.md for setup instructions
