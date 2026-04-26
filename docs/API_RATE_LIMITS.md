# API Rate Limits and Best Practices

This document provides comprehensive information about API rate limits, best practices for API usage, and strategies for optimizing data collection in the Web CVE Census System.

## Table of Contents

1. [GitHub Advisory API](#github-advisory-api)
2. [Exploit-DB](#exploit-db)
3. [Rate Limit Handling](#rate-limit-handling)
4. [Best Practices](#best-practices)
5. [Optimization Strategies](#optimization-strategies)
6. [Monitoring and Troubleshooting](#monitoring-and-troubleshooting)

## GitHub Advisory API

### Rate Limits

GitHub uses different rate limits based on authentication:

#### Unauthenticated Requests

- **Rate Limit**: 60 requests per hour
- **Throughput**: ~6,000 CVEs per hour (at 100 CVEs per request)
- **Use Case**: Testing, small datasets
- **Recommendation**: Not recommended for production use

#### Authenticated Requests (Personal Access Token)

- **Rate Limit**: 5,000 requests per hour
- **Throughput**: ~500,000 CVEs per hour (at 100 CVEs per request)
- **Use Case**: Production census collection
- **Recommendation**: Always use for production

### Creating a GitHub Personal Access Token

1. Go to https://github.com/settings/tokens
2. Click "Generate new token" → "Generate new token (classic)"
3. Set token name: "CVE Census System"
4. Set expiration: 90 days (or custom)
5. Select scopes:
   - `public_repo` (read-only access to public repositories)
6. Click "Generate token"
7. Copy token and add to `.env` file:
   ```bash
   GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
   ```

### Rate Limit Headers

GitHub returns rate limit information in response headers:

```
X-RateLimit-Limit: 5000
X-RateLimit-Remaining: 4999
X-RateLimit-Reset: 1642089600
X-RateLimit-Used: 1
X-RateLimit-Resource: graphql
```

**Headers**:
- `X-RateLimit-Limit`: Maximum requests per hour
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Unix timestamp when rate limit resets
- `X-RateLimit-Used`: Requests used in current window
- `X-RateLimit-Resource`: API resource type (graphql, core, search)

### GraphQL API Specifics

The system uses GitHub's GraphQL API for efficient querying:

**Endpoint**: `https://api.github.com/graphql`

**Query Structure**:
```graphql
query {
  securityVulnerabilities(
    first: 100
    ecosystem: NPM
    after: $cursor
  ) {
    nodes {
      advisory {
        ghsaId
        summary
        severity
        cvss {
          score
          vectorString
        }
        cwes(first: 10) {
          nodes {
            cweId
            name
          }
        }
        publishedAt
      }
      package {
        name
        ecosystem
      }
      vulnerableVersionRange
    }
    pageInfo {
      hasNextPage
      endCursor
    }
  }
}
```

**Pagination**:
- Use `first` parameter to specify batch size (recommended: 100)
- Use `after` parameter with `endCursor` for pagination
- Check `hasNextPage` to determine if more results exist

### Rate Limit Calculation

**Example**: Collecting CVEs from 2015-2025 for npm ecosystem

Assumptions:
- ~50,000 CVEs in npm ecosystem
- Batch size: 100 CVEs per request
- Requests needed: 50,000 / 100 = 500 requests

**With Token** (5,000 req/hour):
- Time: 500 / 5,000 = 0.1 hours = 6 minutes
- ✅ Feasible

**Without Token** (60 req/hour):
- Time: 500 / 60 = 8.3 hours
- ⚠️ Not recommended

### Rate Limit Exceeded Response

When rate limit is exceeded, GitHub returns:

```json
{
  "message": "API rate limit exceeded",
  "documentation_url": "https://docs.github.com/rest/overview/resources-in-the-rest-api#rate-limiting"
}
```

**HTTP Status**: 403 Forbidden

**System Response**:
1. Log rate limit exceeded error
2. Calculate wait time until reset
3. Implement exponential backoff
4. Retry after rate limit resets

## Exploit-DB

### Data Source

Exploit-DB provides a CSV file with all exploits:

**URL**: https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv

**Update Frequency**: Daily

**File Size**: ~5-10 MB

**Records**: ~50,000 exploits

### Access Method

Exploit-DB CSV is accessed via direct file download (no API):

```bash
# Download CSV
wget https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv \
  -O data/exploitdb/files_exploits.csv
```

### Rate Limits

**GitLab Rate Limits**:
- No strict rate limits for file downloads
- Recommended: Download once per day
- Cache locally to avoid repeated downloads

### CSV Structure

```csv
id,file,description,date,author,type,platform,port
1,exploits/php/webapps/1.txt,Description,2000-01-01,Author,webapps,php,0
```

**Columns**:
- `id`: Exploit-DB ID
- `file`: File path
- `description`: Exploit description (may contain CVE ID)
- `date`: Publication date
- `author`: Exploit author
- `type`: Exploit type (webapps, remote, local, dos)
- `platform`: Platform (php, python, java, etc.)
- `port`: Port number (if applicable)

### CVE Matching

The system searches for CVE IDs in the `description` field:

**Primary Search**: Exact CVE ID match
```python
# Example: "CVE-2021-12345" in description
if re.search(r'CVE-\d{4}-\d{4,}', description):
    # Match found
```

**Fallback Search**: Keyword matching
```python
# Example: "express" + "injection" in description
if package_name in description.lower() and vulnerability_type in description.lower():
    # Potential match
```

### Caching

The system caches Exploit-DB data in memory:

**Configuration**:
```yaml
exploitdb:
  cache:
    enabled: true
    ttl: 604800  # 7 days in seconds
```

**Benefits**:
- Fast lookups (O(1) for CVE ID search)
- No repeated file parsing
- Reduced disk I/O

**Memory Usage**: ~50-100 MB for full dataset

## Rate Limit Handling

### Exponential Backoff

The system implements exponential backoff for rate limit errors:

**Algorithm**:
```python
def exponential_backoff(attempt: int, base_delay: int = 5) -> int:
    """Calculate delay with exponential backoff."""
    return base_delay * (2 ** attempt)
```

**Example**:
- Attempt 1: 5 seconds
- Attempt 2: 10 seconds
- Attempt 3: 20 seconds
- Attempt 4: 40 seconds

**Configuration**:
```yaml
github:
  rate_limit:
    retry_attempts: 3
    retry_delay: 5  # seconds
    backoff_multiplier: 2
```

### Rate Limit Monitoring

The system monitors rate limits in real-time:

**Logging**:
```
2025-01-15 10:30:45 - INFO - Rate limit: 4999/5000 remaining
2025-01-15 10:35:20 - WARNING - Rate limit: 100/5000 remaining
2025-01-15 10:40:15 - ERROR - Rate limit exceeded, waiting 1200 seconds
```

**Metrics**:
- Requests made
- Requests remaining
- Reset time
- Wait time

### Graceful Degradation

When rate limits are approached:

1. **Reduce Batch Size**: Decrease from 100 to 50 CVEs per request
2. **Increase Delay**: Add delay between requests
3. **Pause Collection**: Wait for rate limit reset
4. **Resume Collection**: Continue from last cursor

## Best Practices

### GitHub API

#### 1. Always Use Authentication

```bash
# .env
GITHUB_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Benefits**:
- 5,000 req/hour vs 60 req/hour
- More reliable for large datasets
- Better error handling

#### 2. Optimize Batch Size

```yaml
census:
  batch_size: 100  # Recommended
```

**Considerations**:
- Larger batches: Fewer requests, more data per request
- Smaller batches: More requests, less data per request
- Optimal: 100 CVEs per request

#### 3. Use Pagination Efficiently

```python
# Good: Use cursor-based pagination
cursor = None
while True:
    results = query_github(cursor=cursor)
    process_results(results)
    if not results.has_next_page:
        break
    cursor = results.end_cursor
```

#### 4. Monitor Rate Limits

```python
# Check rate limit before making requests
if remaining_requests < 100:
    wait_time = reset_time - current_time
    logger.warning(f"Low rate limit, waiting {wait_time} seconds")
    time.sleep(wait_time)
```

#### 5. Handle Errors Gracefully

```python
try:
    results = query_github()
except RateLimitExceeded:
    logger.error("Rate limit exceeded, waiting for reset")
    wait_for_reset()
    retry()
except NetworkError:
    logger.error("Network error, retrying with backoff")
    exponential_backoff_retry()
```

### Exploit-DB

#### 1. Cache Locally

```bash
# Download once, cache for 7 days
wget https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv \
  -O data/exploitdb/files_exploits.csv
```

#### 2. Update Periodically

```bash
# Cron job: Update daily at 2 AM
0 2 * * * cd /path/to/project && wget -q https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv -O data/exploitdb/files_exploits.csv
```

#### 3. Parse Once, Cache in Memory

```python
# Load CSV once at startup
exploitdb_data = load_exploitdb_csv()

# Cache in memory for fast lookups
exploit_cache = {exploit.cve_id: exploit for exploit in exploitdb_data}
```

#### 4. Use Efficient Search

```python
# Good: O(1) lookup with dictionary
exploit = exploit_cache.get(cve_id)

# Bad: O(n) search through list
exploit = next((e for e in exploitdb_data if e.cve_id == cve_id), None)
```

## Optimization Strategies

### 1. Parallel Collection

Collect from multiple ecosystems in parallel:

```python
from concurrent.futures import ThreadPoolExecutor

ecosystems = ['npm', 'maven', 'pip', 'composer', 'go', 'rubygems']

with ThreadPoolExecutor(max_workers=3) as executor:
    futures = [executor.submit(collect_ecosystem, eco) for eco in ecosystems]
    results = [f.result() for f in futures]
```

**Benefits**:
- Faster collection
- Better resource utilization
- Independent error handling per ecosystem

**Considerations**:
- Rate limits are shared across all requests
- Monitor total requests across all threads
- Adjust max_workers based on rate limit

### 2. Incremental Collection

Collect CVEs incrementally by year:

```python
for year in range(2015, 2026):
    collect_cves(year_start=year, year_end=year)
    generate_report(year=year)
```

**Benefits**:
- Smaller batches, easier to manage
- Progress tracking per year
- Resume from last year on failure

### 3. Smart Filtering

Filter at API level to reduce data transfer:

```python
# Good: Filter at API level
query = """
  securityVulnerabilities(
    first: 100
    ecosystem: NPM
    publishedSince: "2021-01-01"
  )
"""

# Bad: Fetch all, filter in application
all_cves = fetch_all_cves()
filtered = [cve for cve in all_cves if cve.year == 2021]
```

### 4. Batch Database Inserts

Insert CVEs in batches:

```python
# Good: Batch insert
batch = []
for cve in cves:
    batch.append(cve)
    if len(batch) >= 100:
        db.insert_batch(batch)
        batch = []

# Bad: Individual inserts
for cve in cves:
    db.insert(cve)
```

**Benefits**:
- Fewer database round-trips
- Better transaction management
- Faster insertion

### 5. Connection Pooling

Use connection pooling for database:

```python
# Configuration
DB_POOL_MIN_SIZE = 2
DB_POOL_MAX_SIZE = 10

# Benefits:
# - Reuse connections
# - Reduce connection overhead
# - Better concurrency
```

## Monitoring and Troubleshooting

### Monitoring

#### 1. Rate Limit Metrics

```python
# Log rate limit metrics
logger.info(f"Rate limit: {remaining}/{limit} remaining")
logger.info(f"Reset time: {reset_time}")
logger.info(f"Requests used: {used}")
```

#### 2. Collection Progress

```python
# Log collection progress
logger.info(f"Collected {count} CVEs from {ecosystem}")
logger.info(f"Progress: {count}/{total} ({percentage}%)")
```

#### 3. Error Tracking

```python
# Track errors
error_count = 0
consecutive_errors = 0

if error:
    error_count += 1
    consecutive_errors += 1
    logger.error(f"Error: {error}, total: {error_count}")
    
    if consecutive_errors > 10:
        logger.critical("Too many consecutive errors, stopping")
        raise
```

### Troubleshooting

#### Rate Limit Exceeded

**Symptoms**:
- 403 Forbidden responses
- "API rate limit exceeded" message

**Solutions**:
1. Check if GitHub token is set
2. Wait for rate limit reset
3. Reduce batch size
4. Add delays between requests

#### Network Timeouts

**Symptoms**:
- Connection timeout errors
- Slow responses

**Solutions**:
1. Increase timeout values
2. Retry with exponential backoff
3. Check network connectivity
4. Use different network if possible

#### Exploit-DB File Not Found

**Symptoms**:
- FileNotFoundError
- "files_exploits.csv not found"

**Solutions**:
1. Download CSV manually
2. Check file path in configuration
3. Ensure data directory exists
4. Check file permissions

#### Database Connection Issues

**Symptoms**:
- Connection refused
- Timeout errors

**Solutions**:
1. Check DATABASE_URL
2. Verify network connectivity
3. Check Neon dashboard
4. Increase connection timeout

### Performance Tuning

#### 1. Adjust Batch Size

```yaml
# Small datasets or low rate limits
census:
  batch_size: 50

# Large datasets with token
census:
  batch_size: 100
```

#### 2. Adjust Retry Settings

```yaml
# Aggressive retries
github:
  rate_limit:
    retry_attempts: 5
    retry_delay: 3
    backoff_multiplier: 2

# Conservative retries
github:
  rate_limit:
    retry_attempts: 3
    retry_delay: 10
    backoff_multiplier: 3
```

#### 3. Adjust Connection Pool

```yaml
# High concurrency
database:
  pool:
    min_size: 5
    max_size: 20

# Low concurrency
database:
  pool:
    min_size: 2
    max_size: 10
```

## Summary

### Key Takeaways

1. **Always use GitHub token** for production (5,000 req/hour vs 60 req/hour)
2. **Batch size of 100** is optimal for most use cases
3. **Cache Exploit-DB data** locally and update daily
4. **Monitor rate limits** in real-time to avoid exceeding
5. **Implement exponential backoff** for error handling
6. **Use connection pooling** for database efficiency
7. **Collect incrementally** by year for better management
8. **Log everything** for troubleshooting and monitoring

### Quick Reference

| Resource | Rate Limit | Recommendation |
|----------|------------|----------------|
| GitHub (no token) | 60 req/hour | Testing only |
| GitHub (with token) | 5,000 req/hour | Production |
| Exploit-DB | No limit | Download daily |
| Database | Connection pool | 2-10 connections |

### Configuration Template

```yaml
# Optimal configuration for production
github:
  token: ${GITHUB_TOKEN}
  rate_limit:
    max_requests_per_hour: 5000
    retry_attempts: 3
    retry_delay: 5
    backoff_multiplier: 2

census:
  batch_size: 100
  error_handling:
    continue_on_error: true
    max_consecutive_errors: 10

exploitdb:
  cache:
    enabled: true
    ttl: 604800  # 7 days

database:
  pool:
    min_size: 2
    max_size: 10
    timeout: 30
```
