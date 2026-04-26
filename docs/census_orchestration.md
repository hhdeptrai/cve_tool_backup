# Census Orchestration Guide

## Overview

The census orchestration script (`scripts/run_census.py`) automates the complete CVE data collection workflow for the Web CVE Census System.

## New Architecture

The system now follows a **collect-all-then-label** approach:

1. **Collect ALL CVEs** from web ecosystems (npm, maven, pip, composer, go, rubygems)
2. **NO CWE filtering** at the GitHub API level - only ecosystem and year filters
3. **Label priority CWEs** post-collection based on configured categories
4. **Store ALL CVEs** regardless of CWE category to ensure 100% coverage
5. **Cross-reference** with Exploit-DB automatically
6. **Generate summary reports** with detailed statistics

### Rationale

- Web ecosystems (npm, maven, pip, composer, go, rubygems) are 95% web-related
- Collecting all CVEs ensures no web vulnerabilities are missed
- Priority labeling helps researchers focus on high-value targets
- Manual exclusion mechanism allows dataset curation
- This approach balances completeness with usability

## Features

### Sequential Ecosystem Processing

The orchestrator processes each ecosystem sequentially:
- npm
- maven
- pip
- composer
- go
- rubygems

### Automatic Priority CWE Labeling

CVEs are automatically labeled with `is_priority_cwe=TRUE` if they match priority categories:
- Injection
- XSS
- Authentication
- Deserialization
- SSRF
- Path Traversal

### Exploit-DB Cross-Referencing

Each CVE is automatically cross-referenced with Exploit-DB to identify publicly available exploits.

### Error Handling and Continuation

The orchestrator implements robust error handling:
- Logs all errors with detailed context
- Continues processing remaining ecosystems after failures
- Continues processing remaining CVEs after individual failures
- Generates comprehensive error reports

### Summary Reporting

Generates detailed summary reports including:
- Total CVEs collected
- Priority CVEs labeled
- Exploits found
- New CVEs stored vs duplicates
- Per-ecosystem breakdown
- Error summary

## Usage

### Running Census Collection

#### Using Make (Recommended)

```bash
make run-census
```

#### Direct Execution

```bash
python scripts/run_census.py
```

### Prerequisites

1. **Environment Configuration**
   - Set `GITHUB_TOKEN` in `.env` file
   - Set `DATABASE_URL` for Neon PostgreSQL
   - Configure census parameters in `.env`:
     - `CENSUS_START_YEAR` (default: 2015)
     - `CENSUS_END_YEAR` (default: 2025)
     - `CENSUS_BATCH_SIZE` (default: 100)

2. **Exploit-DB CSV (Optional)**
   - Download `files_exploits.csv` from Exploit-DB
   - Place in `data/exploitdb/files_exploits.csv`
   - If not present, collection continues without exploit cross-referencing

3. **Database Setup**
   ```bash
   make db-setup
   ```

### Configuration

Edit `.env` file:

```bash
# GitHub API
GITHUB_TOKEN=your_github_token_here

# Database
DATABASE_URL=postgresql://user:password@host/database

# Census Configuration
CENSUS_START_YEAR=2015
CENSUS_END_YEAR=2025
CENSUS_BATCH_SIZE=100
```

## Output

### Console Output

The script provides real-time progress updates:
- Ecosystem being processed
- CVEs collected per ecosystem
- Priority CVEs labeled
- Exploits found
- Storage statistics
- Error messages

### Log Files

Detailed logs are written to:
- `logs/census_run.log` - Complete execution log with timestamps

### Summary Reports

Summary reports are saved to:
- `reports/census_summary_YYYYMMDD_HHMMSS.txt` - Detailed summary with statistics

## Architecture

### CensusOrchestrator Class

The main orchestration class that coordinates the collection workflow.

**Key Methods:**

- `run()` - Execute complete census collection
- `_process_ecosystem(ecosystem)` - Process a single ecosystem
- `_generate_summary_report()` - Generate and display summary

**Statistics Tracked:**

- `total_cves_collected` - Total CVEs collected from all ecosystems
- `total_priority_cves` - CVEs labeled as priority
- `total_exploits_found` - CVEs with Exploit-DB matches
- `total_stored` - New CVEs stored in database
- `total_duplicates` - Duplicate CVEs skipped
- `total_errors` - Errors encountered
- `by_ecosystem` - Per-ecosystem breakdown
- `errors` - List of error messages

### Integration with Existing Components

The orchestrator integrates with:

1. **CensusCollector** - Collects CVEs from GitHub Advisory
2. **CVERepository** - Stores CVEs in database
3. **DataValidator** - Validates CVE data
4. **CrossReferenceEngine** - Matches with Exploit-DB
5. **Config** - Loads configuration from environment

## Error Handling

### Ecosystem-Level Errors

If an ecosystem fails completely:
- Error is logged with full context
- Remaining ecosystems continue processing
- Error is included in summary report

### CVE-Level Errors

If a single CVE fails to store:
- Error is logged with CVE ID
- Remaining CVEs continue processing
- Error is included in summary report

### API Errors

GitHub API errors are handled with:
- Exponential backoff retry (3 attempts)
- Rate limit detection and waiting
- Detailed error logging

### Database Errors

Database errors are handled with:
- Transaction rollback on failures
- Connection pool management
- Duplicate detection and skipping

## Performance

### Expected Performance

- **Collection Rate**: ~100 CVEs per minute (depends on API rate limits)
- **Batch Size**: 100 CVEs per API request (configurable)
- **Rate Limits**: 5000 requests/hour for authenticated GitHub users

### Optimization Tips

1. **Batch Size**: Adjust `CENSUS_BATCH_SIZE` based on API quota
2. **Year Range**: Narrow year range for faster testing
3. **Ecosystems**: Process specific ecosystems by modifying script
4. **Parallel Processing**: Future enhancement for concurrent ecosystem processing

## Monitoring

### Real-Time Monitoring

Monitor progress through:
- Console output (real-time updates)
- Log file (`tail -f logs/census_run.log`)

### Post-Execution Analysis

Review:
- Summary report in `reports/` directory
- Complete log in `logs/census_run.log`
- Database statistics using report generator

## Troubleshooting

### Common Issues

**Issue: GitHub API rate limit exceeded**
- Solution: Wait for rate limit reset (check `X-RateLimit-Reset` header)
- Solution: Reduce `CENSUS_BATCH_SIZE`

**Issue: Database connection timeout**
- Solution: Check `DATABASE_URL` in `.env`
- Solution: Verify Neon database is accessible
- Solution: Check network connectivity

**Issue: Exploit-DB CSV not found**
- Solution: Download from Exploit-DB repository
- Solution: Place in `data/exploitdb/files_exploits.csv`
- Note: Collection continues without exploit cross-referencing

**Issue: Out of memory**
- Solution: Reduce `CENSUS_BATCH_SIZE`
- Solution: Process fewer years at a time
- Solution: Process ecosystems individually

### Debug Mode

Enable debug logging by modifying `scripts/run_census.py`:

```python
logging.basicConfig(
    level=logging.DEBUG,  # Change from INFO to DEBUG
    ...
)
```

## Future Enhancements

Planned improvements:

1. **Parallel Processing** - Process multiple ecosystems concurrently
2. **Resume Capability** - Resume interrupted collections
3. **Incremental Updates** - Collect only new CVEs since last run
4. **Progress Persistence** - Save progress to database
5. **Web UI** - Monitor collection progress through web interface
6. **Scheduling** - Automated periodic collection (cron/systemd)

## Related Documentation

- [Requirements Document](../.kiro/specs/web-cve-census-system/requirements.md)
- [Design Document](../.kiro/specs/web-cve-census-system/design.md)
- [Task List](../.kiro/specs/web-cve-census-system/tasks.md)
- [Neon Setup Guide](NEON_SETUP_GUIDE.md)

## Requirements Validation

This orchestration script implements:

- **Requirement 9.1**: Process all configured ecosystems sequentially ✓
- **Requirement 9.2**: Collect ALL CVEs without CWE filtering, label priority CWEs ✓
- **Requirement 9.3**: Cross-reference with Exploit-DB automatically ✓
- **Requirement 9.4**: Generate summary report with statistics ✓
- **Requirement 9.5**: Implement error logging and continuation ✓
