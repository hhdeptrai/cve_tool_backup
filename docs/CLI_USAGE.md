# CLI Usage Guide

This document provides examples and usage instructions for the Web CVE Census System command-line interface.

## Installation

The CLI is available through the `census` script in the project root:

```bash
python census [command] [options]
```

## Available Commands

### 1. Census Collection

Collect CVE data from GitHub Advisory Database and Exploit-DB.

```bash
# Collect CVEs from 2015 to 2025
python census census collect --year-start 2015 --year-end 2025

# Collect CVEs for a specific year range
python census census collect --year-start 2020 --year-end 2021
```

**What it does:**
- Queries GitHub Advisory Database for all CVEs in web ecosystems (npm, maven, pip, composer, go, rubygems)
- Labels priority CVEs based on CWE categories (Injection, XSS, Authentication, Deserialization, SSRF, Path Traversal)
- Cross-references with Exploit-DB to identify available exploits
- Stores all CVEs in the database

### 2. Task Management

#### Claim Tasks

Claim CVE verification tasks for a researcher.

```bash
# Claim 10 tasks from year 2021 for researcher Minh
python census task claim --researcher Minh --year 2021 --count 10

# Claim a specific CVE
python census task claim --researcher Hoàng --cve-id CVE-2021-12345
```

**Notes:**
- Only "Minh" and "Hoàng" are valid researcher names
- Batch claims prioritize CVEs with available exploits
- Claims expire after 7 days if not updated

#### List Tasks

View available or assigned tasks. By default, **excluded and completed tasks are hidden** from your personal list.

```bash
# List active tasks assigned to a researcher (excludes completed & excluded)
python census task list --researcher Minh

# List available tasks (unclaimed or expired)
python census task list --limit 20

# Filter by year and ecosystem
python census task list --year 2021 --ecosystem npm --limit 10

# List tasks sorted by CVSS score (highest risk first)
python census task list --researcher Minh --sort-by-score

# Show completed tasks in the list
python census task list --researcher Minh --show-completed

# Show excluded tasks in the list
python census task list --researcher Minh --show-excluded

# Show all tasks (active, completed, and excluded)
python census task list --researcher Minh --show-completed --show-excluded
```

**Output includes direct resource links:**
- NVD (National Vulnerability Database)
- GitHub Advisory Database
- Exploit-DB (if exploit exists)

#### Task History

View your completed tasks (`VERIFIED_SUCCESS` or `UNEXPLOITABLE`).

```bash
# List completed tasks for a researcher
python census task history --researcher Minh
```

#### Task Statistics

View a summary of task counts for a researcher or the entire system.

```bash
# Researcher statistics (active, completed, excluded)
python census task stats --researcher Minh

# System-wide statistics (total available tasks)
python census task stats
```

**Example output (researcher):**
```
Statistics for Minh:
  Active Tasks:    5
  Completed Tasks: 3
  Excluded Tasks:  1
```

#### Update Task Status

Update the status of claimed tasks.

```bash
# Update build status
python census task update --cve-id CVE-2021-12345 --researcher Minh --build-status SUCCESS

# Update exploit status (requires notes)
python census task update --cve-id CVE-2021-12345 --researcher Minh \
  --exploit-status VERIFIED_SUCCESS \
  --notes "Successfully exploited using Docker environment. RCE confirmed."

# Update research depth
python census task update --cve-id CVE-2021-12345 --researcher Minh --research-depth LEVEL_2
```

**Valid Status Values:**
- Build Status: `NOT_ATTEMPTED`, `IN_PROGRESS`, `SUCCESS`, `FAILED`
- Exploit Status: `NONE`, `POC_PUBLIC`, `EXPLOIT_DB`, `VERIFIED_SUCCESS`, `UNEXPLOITABLE`
- Research Depth: `LEVEL_0`, `LEVEL_1`, `LEVEL_2`

**Important:**
- `VERIFIED_SUCCESS` and `UNEXPLOITABLE` require `--notes` parameter
- Only the assigned researcher can update their tasks

### 3. CVE Exclusion

Exclude non-web CVEs from the dataset after manual review.

#### Exclude a CVE

```bash
# Exclude a CVE with reason
python census task exclude --cve-id CVE-2021-12345 --researcher Minh \
  --reason "Desktop application vulnerability, not web-related"
```

**Notes:**
- Exclusion reason is required and must be non-empty
- Excluded CVEs are hidden from default queries but remain in database
- Exclusion metadata (who, when, why) is preserved

#### Restore an Excluded CVE

```bash
# Restore a previously excluded CVE
python census task restore --cve-id CVE-2021-12345 --researcher Hoàng
```

#### List Excluded CVEs

```bash
# List all excluded CVEs
python census task list-excluded

# Filter by year, ecosystem, or researcher
python census task list-excluded --year 2021 --ecosystem npm
python census task list-excluded --researcher Minh
```

### 4. Cleaning Up CVE Reproduction Environments

After building and confirming CVE reproduction results, use this command to tear down all Docker environments and reclaim disk space from the `tmp/` directory.

```bash
make clean-cve
```

**What it does:**
1. Scans every subdirectory inside `tmp/` for a `docker-compose.yml` file
2. Runs `docker compose down -v --rmi all` for each found environment (stops containers, removes volumes and images)
3. Deletes all contents of `tmp/`
4. Recreates `tmp/.gitkeep` so the directory stays tracked by Git

> **Warning:** This permanently deletes everything in `tmp/`. Only run it after you have confirmed all results and no longer need the Docker environments.

**Example output:**
```
Cleaning all CVE reproduction environments in tmp/...
Found environment in tmp/CVE-2021-12345
Stopping containers and removing resources...
…
Removing all contents of tmp/...
Recreating .gitkeep...
✓ All found environments and tmp contents cleaned
```

---

### 5. Report Generation

Generate statistical reports on the CVE census.

```bash
# Generate priority report (excludes excluded CVEs)
python census report generate --output reports/census_report.json --mode priority

# Generate full report (includes all CVEs)
python census report generate --output reports/census_report.json --mode full

# Filter by year or ecosystemx
python census report generate --output reports/report_2021.json --mode priority --year 2021
python census report generate --output reports/report_npm.json --mode priority --ecosystem npm
```

**Report Modes:**
- `priority` (default): Shows only non-excluded CVEs, focuses on priority CWEs
- `full`: Shows all CVEs including excluded ones, for transparency

**Report Contents:**
- Total CVEs, priority CVEs, excluded CVEs
- Exploit availability statistics
- Verification completion rates
- Breakdown by year, ecosystem, CWE category
- Build status and exploit status distributions
- Research depth distribution

### 6. Updating CVSS Scores

Update the CVSS score for a specific CVE by fetching the latest CVSS v3/v4 scores from GitHub Advisory Database and updating the local database. This is useful if a CVE initially had missing or incorrect scores when first collected.

```bash
# Update CVSS score for a specific CVE
python scripts/update_cvss.py CVE-x-y
```

**Notes:**
- Prioritizes CVSS v4 over CVSS v3 (if both are available).
- The updated score will be reflected in `task list` and generated reports.

## Example Workflows

### Workflow 1: Initial Census Collection

```bash
# 1. Collect CVEs for 2020-2021
python census census collect --year-start 2020 --year-end 2021

# 2. Generate initial report
python census report generate --output reports/initial_report.json --mode full

# 3. View available tasks
python census task list --limit 20
```

### Workflow 2: Researcher Verification

```bash
# 1. Claim 10 tasks from 2021
python census task claim --researcher Minh --year 2021 --count 10

# 2. View my tasks
python census task list --researcher Minh

# 3. Update task status as work progresses
python census task update --cve-id CVE-2021-12345 --researcher Minh --build-status IN_PROGRESS
python census task update --cve-id CVE-2021-12345 --researcher Minh --build-status SUCCESS
python census task update --cve-id CVE-2021-12345 --researcher Minh \
  --exploit-status VERIFIED_SUCCESS \
  --notes "RCE confirmed in Docker environment" 

# 4. Update research depth
python census task update --cve-id CVE-2021-12345 --researcher Minh --research-depth LEVEL_2

# 5. Or just update it altogether: 
python census task update --cve-id CVE-2025-0148 --researcher Minh --build-status SUCCESS --exploit-status VERIFIED_SUCCESS --notes "There really is information disclosure." --research-depth LEVEL_2
```



### Workflow 3: Dataset Curation



```bash
# 1. Review CVEs and exclude non-web ones
python census task exclude --cve-id CVE-2021-99999 --researcher Minh \
  --reason "Desktop application, not web-related"

# 2. List excluded CVEs to review
python census task list-excluded

# 3. Restore if excluded by mistake
python census task restore --cve-id CVE-2021-99999 --researcher Minh

# 4. Generate priority report (excludes excluded CVEs)
python census report generate --output reports/curated_report.json --mode priority
```

### Workflow 4: Progress Tracking

```bash
# 1. View active tasks
python census task list --researcher Minh

# 2. View completed task history
python census task history --researcher Minh

# 3. Check your stats (active, completed, excluded)
python census task stats --researcher Minh

# 4. Check system-wide availability
python census task stats

# 5. Generate overall progress report
python census report generate --output reports/progress_report.json --mode priority
```

## Tips and Best Practices

1. **Batch Claiming**: Use `--count` parameter to claim multiple tasks at once for efficiency
2. **Regular Updates**: Update task status regularly to prevent claim expiration (7 days)
3. **Detailed Notes**: Provide detailed notes when marking CVEs as `VERIFIED_SUCCESS` or `UNEXPLOITABLE`
4. **Exclusion Reasons**: Be specific when excluding CVEs to maintain audit trail
5. **Report Modes**: Use `priority` mode for research analysis, `full` mode for transparency
6. **Filtering**: Use year and ecosystem filters to focus on specific subsets
7. **Track Progress**: Use `task stats` to quickly see your active/completed/excluded task counts
8. **Review History**: Use `task history` to see all your completed tasks

## Error Handling

The CLI provides clear error messages for common issues:

- **Invalid researcher**: Only "Minh" and "Hoàng" are accepted
- **Missing required parameters**: CLI will prompt for required arguments
- **Invalid status values**: CLI will show valid options
- **Database connection errors**: Check `.env` configuration
- **Task already claimed**: Another researcher has claimed the task

## Configuration

The CLI uses environment variables from `.env` file:

```bash
# Database connection
DATABASE_URL=postgresql://user:password@host:port/database

# GitHub API token (optional but recommended)
GITHUB_TOKEN=your_github_token

# Exploit-DB CSV path
EXPLOITDB_CSV_PATH=./data/exploitdb/files_exploits.csv
```

See `.env.example` for a complete configuration template.

## Getting Help

Use `--help` flag with any command to see available options:

```bash
python census --help
python census task --help
python census task claim --help
python census task list --help
python census task history --help
python census task stats --help
python census report generate --help
```
