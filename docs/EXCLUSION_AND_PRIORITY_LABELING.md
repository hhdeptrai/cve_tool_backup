# CVE Exclusion Mechanism and Priority CWE Labeling

This document explains the new architecture features introduced in v2.0: the CVE exclusion mechanism for dataset curation and automatic priority CWE labeling.

## Table of Contents

1. [Overview](#overview)
2. [Architecture Changes](#architecture-changes)
3. [Priority CWE Labeling](#priority-cwe-labeling)
4. [CVE Exclusion Mechanism](#cve-exclusion-mechanism)
5. [Dual Report Modes](#dual-report-modes)
6. [Workflows](#workflows)
7. [Best Practices](#best-practices)

## Overview

### The Problem

In v1.0, the system filtered CVEs at the GitHub API level using CWE categories. This approach had limitations:

- **Missed CVEs**: Some web vulnerabilities were excluded due to incorrect or missing CWE labels
- **No Flexibility**: Once filtered out, CVEs couldn't be recovered
- **Limited Coverage**: Researchers couldn't review excluded CVEs to verify correctness

### The Solution (v2.0)

The new architecture uses a **collect-all-then-label-and-curate** approach:

1. **Collect ALL CVEs** from web ecosystems (npm, maven, pip, composer, go, rubygems)
2. **Label priority CVEs** automatically based on CWE category matching
3. **Store ALL CVEs** regardless of CWE category (100% coverage)
4. **Manual curation** by researchers to exclude non-web CVEs
5. **Dual report modes** for research (priority) and transparency (full)

### Benefits

- ✅ **100% Coverage**: No web vulnerabilities are missed
- ✅ **Flexibility**: Researchers can review and curate the dataset
- ✅ **Transparency**: Full mode shows all CVEs including excluded ones
- ✅ **Prioritization**: Priority labeling helps focus on high-value targets
- ✅ **Audit Trail**: All exclusions are logged with reason and timestamp

## Architecture Changes

### v1.0 Architecture (Old)

```
GitHub Advisory API
        ↓
[Filter by CWE at API level] ← CWE filters applied here
        ↓
[Store filtered CVEs]
        ↓
Database (only filtered CVEs)
```

**Problems**:
- CVEs with incorrect CWE labels are excluded
- No way to recover excluded CVEs
- Limited dataset coverage

### v2.0 Architecture (New)

```
GitHub Advisory API
        ↓
[Collect ALL CVEs] ← NO CWE filtering at API level
        ↓
[Label priority CWEs] ← Automatic labeling based on CWE matching
        ↓
[Store ALL CVEs] ← 100% coverage
        ↓
Database (all CVEs with priority labels)
        ↓
[Manual curation] ← Researchers exclude non-web CVEs
        ↓
[Dual report modes] ← Priority (curated) or Full (all)
```

**Benefits**:
- 100% coverage of web ecosystem CVEs
- Flexible curation by researchers
- Transparent reporting

## Priority CWE Labeling

### What is Priority CWE Labeling?

Priority CWE labeling automatically marks CVEs with high-value CWE categories as `is_priority_cwe=TRUE` during collection.

### Priority CWE Categories

The system labels CVEs with the following CWE categories as priority:

1. **Injection** (SQL Injection, Command Injection, etc.)
2. **XSS** (Cross-Site Scripting)
3. **Authentication** (Broken Authentication, Session Management)
4. **Deserialization** (Insecure Deserialization)
5. **SSRF** (Server-Side Request Forgery)
6. **Path Traversal** (Directory Traversal, File Inclusion)

### Why These Categories?

These categories represent the most common and impactful web vulnerabilities:

- **High Severity**: Often lead to critical security issues (RCE, data breach)
- **Common**: Frequently found in web applications
- **Exploitable**: Often have public exploits available
- **Research Value**: High value for AI-powered penetration testing research

### How Labeling Works

During census collection:

```python
# Pseudo-code
for cve in collected_cves:
    if cve.cwe_category in PRIORITY_CWES:
        cve.is_priority_cwe = True
    else:
        cve.is_priority_cwe = False
    
    # Store ALL CVEs regardless of priority status
    database.insert(cve)
```

### Database Schema

```sql
-- New field in v2.0
is_priority_cwe BOOLEAN DEFAULT FALSE
```

### Querying Priority CVEs

```sql
-- Get all priority CVEs (excluding excluded)
SELECT * FROM web_cve_census_master
WHERE is_priority_cwe = TRUE
  AND is_excluded = FALSE;

-- Get priority CVEs by ecosystem
SELECT * FROM web_cve_census_master
WHERE is_priority_cwe = TRUE
  AND is_excluded = FALSE
  AND ecosystem = 'npm';

-- Count priority CVEs by year
SELECT publication_year, COUNT(*) as count
FROM web_cve_census_master
WHERE is_priority_cwe = TRUE
  AND is_excluded = FALSE
GROUP BY publication_year
ORDER BY publication_year DESC;
```

### CLI Usage

```bash
# List priority CVEs
python census task list --is-priority-cwe true --limit 20

# Claim priority CVEs
python census task claim --researcher Minh --year 2021 --count 10
# System automatically prioritizes CVEs with is_priority_cwe=TRUE

# Generate priority report (default)
python census report generate --output report.json --mode priority
```

### Configuration

```yaml
# config.yaml
census:
  # Priority CWE categories for labeling
  priority_cwes:
    - Injection
    - XSS
    - Authentication
    - Deserialization
    - SSRF
    - Path Traversal
```

## CVE Exclusion Mechanism

### What is CVE Exclusion?

CVE exclusion allows researchers to manually mark CVEs as non-web-related, removing them from the active dataset while preserving them in the database for audit purposes.

### Why Exclusion?

Web ecosystems (npm, maven, pip, etc.) are ~95% web-related, but some CVEs are:

- Desktop applications
- Mobile applications (native iOS/Android)
- CLI tools
- System libraries
- Non-web components

Exclusion allows researchers to curate the dataset for web-specific research.

### Database Schema

```sql
-- New fields in v2.0
is_excluded BOOLEAN DEFAULT FALSE,
excluded_by VARCHAR(100),
excluded_at TIMESTAMP,
exclusion_reason TEXT,

-- Constraint: exclusion reason required when excluded
CONSTRAINT chk_exclusion_reason 
    CHECK (is_excluded = FALSE OR exclusion_reason IS NOT NULL)
```

### Exclusion Workflow

#### 1. Exclude a CVE

```bash
python census task exclude --cve-id CVE-2021-99999 --researcher Minh \
  --reason "Desktop application vulnerability, not web-related"
```

**What happens**:
1. System validates researcher ID (only Minh or Hoàng)
2. System validates exclusion reason (non-empty, min 10 characters)
3. System updates database:
   - `is_excluded = TRUE`
   - `excluded_by = "Minh"`
   - `excluded_at = NOW()`
   - `exclusion_reason = "Desktop application vulnerability, not web-related"`
4. System logs exclusion to audit log

#### 2. List Excluded CVEs

```bash
# List all excluded CVEs
python census task list-excluded

# Filter by year
python census task list-excluded --year 2021

# Filter by researcher
python census task list-excluded --researcher Minh
```

**Output**:
```
Excluded CVEs:

CVE-2021-99999 (npm)
  Excluded by: Minh
  Excluded at: 2025-01-15 10:30:45
  Reason: Desktop application vulnerability, not web-related

CVE-2021-88888 (pip)
  Excluded by: Hoàng
  Excluded at: 2025-01-14 14:20:30
  Reason: Mobile app vulnerability (iOS native), no web component

Total: 2 excluded CVEs
```

#### 3. Restore an Excluded CVE

```bash
python census task restore --cve-id CVE-2021-99999 --researcher Minh
```

**What happens**:
1. System validates researcher ID
2. System updates database:
   - `is_excluded = FALSE`
   - `excluded_by = NULL`
   - `excluded_at = NULL`
   - `exclusion_reason = NULL`
3. System logs restoration to audit log

### Exclusion Audit Log

All exclusion and restoration operations are logged to `./logs/exclusion_audit.log`:

```
2025-01-15 10:30:45 - EXCLUSION - CVE-2021-99999 - Minh - Desktop application vulnerability, not web-related
2025-01-15 11:15:20 - EXCLUSION - CVE-2021-88888 - Hoàng - Mobile app vulnerability (iOS native), no web component
2025-01-16 09:15:20 - RESTORATION - CVE-2021-99999 - Minh - Restored after review
```

**Format**:
```
<timestamp> - <action> - <cve_id> - <researcher> - <reason>
```

### Querying Excluded CVEs

```sql
-- Get all excluded CVEs
SELECT * FROM web_cve_census_master
WHERE is_excluded = TRUE;

-- Get excluded CVEs by researcher
SELECT * FROM web_cve_census_master
WHERE is_excluded = TRUE
  AND excluded_by = 'Minh';

-- Count excluded CVEs by ecosystem
SELECT ecosystem, COUNT(*) as count
FROM web_cve_census_master
WHERE is_excluded = TRUE
GROUP BY ecosystem;

-- Get exclusion statistics
SELECT 
    COUNT(*) as total_cves,
    SUM(CASE WHEN is_excluded = TRUE THEN 1 ELSE 0 END) as excluded_count,
    ROUND(SUM(CASE WHEN is_excluded = TRUE THEN 1 ELSE 0 END) * 100.0 / COUNT(*), 2) as exclusion_percentage
FROM web_cve_census_master;
```

### Configuration

```yaml
# config.yaml
exclusion:
  # Validation rules
  validation:
    require_reason: true
    min_reason_length: 10
  
  # Audit logging
  audit:
    enabled: true
    log_path: ./logs/exclusion_audit.log

# Valid researchers
tasks:
  valid_researchers:
    - Minh
    - Hoàng
```

## Dual Report Modes

### Priority Mode (Default)

Priority mode generates reports excluding excluded CVEs, focusing on the curated dataset.

```bash
python census report generate --output report.json --mode priority
```

**What's included**:
- Total CVEs (excluding excluded)
- Priority CVEs (is_priority_cwe=TRUE, excluding excluded)
- Exploit availability statistics
- Verification completion rates
- Breakdown by year, ecosystem, CWE category
- Build status and exploit status distributions
- Research depth distribution
- Researcher statistics

**What's excluded**:
- CVEs with is_excluded=TRUE

**Use case**: Research analysis, statistics, publications

### Full Mode

Full mode generates reports including all CVEs, providing complete transparency.

```bash
python census report generate --output report.json --mode full
```

**What's included**:
- All CVEs including excluded ones
- Exclusion statistics (count, percentage, breakdown by researcher)
- All metrics from priority mode
- Transparency for audit purposes

**Use case**: Audit, transparency, dataset review

### Report Comparison

| Metric | Priority Mode | Full Mode |
|--------|---------------|-----------|
| Total CVEs | Excludes excluded | Includes all |
| Priority CVEs | Excludes excluded | Includes all |
| Exclusion stats | Not shown | Shown |
| Use case | Research | Audit |

### Sample Report Output

**Priority Mode**:
```json
{
  "mode": "priority",
  "summary": {
    "total_cves": 1189,
    "priority_cves": 567,
    "cves_with_exploits": 89,
    "verification_completion_rate": 23.5
  },
  "by_year": { ... },
  "by_ecosystem": { ... },
  "by_cwe": { ... }
}
```

**Full Mode**:
```json
{
  "mode": "full",
  "summary": {
    "total_cves": 1234,
    "priority_cves": 567,
    "excluded_cves": 45,
    "exclusion_percentage": 3.65,
    "cves_with_exploits": 89,
    "verification_completion_rate": 23.5
  },
  "exclusion_stats": {
    "total_excluded": 45,
    "by_researcher": {
      "Minh": 23,
      "Hoàng": 22
    },
    "by_ecosystem": {
      "npm": 12,
      "pip": 15,
      "maven": 8,
      "composer": 5,
      "go": 3,
      "rubygems": 2
    }
  },
  "by_year": { ... },
  "by_ecosystem": { ... },
  "by_cwe": { ... }
}
```

## Workflows

### Workflow 1: Initial Collection and Labeling

```bash
# Step 1: Collect ALL CVEs from 2020-2021
python census census collect --year-start 2020 --year-end 2021

# Step 2: Generate full report to see what was collected
python census report generate --output initial_full_report.json --mode full

# Step 3: Check priority CVEs
python census task list --is-priority-cwe true --limit 20

# Step 4: Check non-priority CVEs
python census task list --is-priority-cwe false --limit 20
```

### Workflow 2: Dataset Curation

```bash
# Step 1: Review CVEs to identify non-web ones
python census task list --year 2021 --limit 50

# Step 2: Exclude non-web CVEs
python census task exclude --cve-id CVE-2021-99999 --researcher Minh \
  --reason "Desktop application, not web-related"

python census task exclude --cve-id CVE-2021-88888 --researcher Minh \
  --reason "Mobile app vulnerability (iOS native), no web component"

# Step 3: Review excluded CVEs
python census task list-excluded

# Step 4: Restore if excluded by mistake
python census task restore --cve-id CVE-2021-99999 --researcher Minh

# Step 5: Generate priority report (curated dataset)
python census report generate --output curated_report.json --mode priority

# Step 6: Generate full report (transparency)
python census report generate --output full_report.json --mode full
```

### Workflow 3: Priority-Focused Verification

```bash
# Step 1: Claim priority CVEs
python census task claim --researcher Minh --year 2021 --count 10
# System automatically prioritizes is_priority_cwe=TRUE

# Step 2: Verify priority CVEs
python census task update --cve-id CVE-2021-12345 --researcher Minh \
  --exploit-status VERIFIED_SUCCESS \
  --notes "Successfully exploited..."

# Step 3: Generate priority report
python census report generate --output priority_report.json --mode priority
```

### Workflow 4: Team Coordination

```bash
# Minh focuses on priority CVEs from 2021
python census task claim --researcher Minh --year 2021 --count 10

# Hoàng focuses on priority CVEs from 2020
python census task claim --researcher Hoàng --year 2020 --count 10

# Both researchers exclude non-web CVEs as they encounter them
python census task exclude --cve-id CVE-2021-99999 --researcher Minh \
  --reason "Desktop application"

python census task exclude --cve-id CVE-2020-88888 --researcher Hoàng \
  --reason "Mobile app"

# Generate team progress report
python census report generate --output team_report.json --mode priority
```

## Best Practices

### Priority CWE Labeling

1. **Trust the Labeling**: The system automatically labels priority CVEs based on CWE matching
2. **Focus on Priority**: Prioritize verification of priority CVEs for high-value research
3. **Don't Ignore Non-Priority**: Non-priority CVEs may still be web-related and valuable
4. **Review CWE Categories**: Periodically review priority CWE categories and adjust if needed

### CVE Exclusion

1. **Be Specific**: Provide detailed exclusion reasons for audit trail
2. **Review Before Excluding**: Double-check that CVE is truly non-web before excluding
3. **Team Coordination**: Coordinate with team members on exclusion criteria
4. **Regular Review**: Periodically review excluded CVEs to ensure consistency
5. **Use Audit Log**: Check `./logs/exclusion_audit.log` for exclusion history

### Reporting

1. **Priority Mode for Research**: Use priority mode for research analysis and publications
2. **Full Mode for Audit**: Use full mode for transparency and audit purposes
3. **Regular Reports**: Generate reports regularly to track progress
4. **Compare Modes**: Compare priority and full reports to understand exclusion impact

### Dataset Curation

1. **Iterative Curation**: Curate dataset iteratively as you review CVEs
2. **Document Criteria**: Document exclusion criteria for consistency
3. **Team Alignment**: Ensure team members use consistent exclusion criteria
4. **Transparency**: Always provide full reports alongside priority reports for transparency

### Quality Assurance

1. **Spot Check**: Periodically spot-check excluded CVEs to verify correctness
2. **Peer Review**: Have team members review each other's exclusions
3. **Audit Trail**: Use audit log to track exclusion patterns and identify issues
4. **Restoration**: Don't hesitate to restore CVEs if exclusion was incorrect

## Summary

### Key Takeaways

1. **100% Coverage**: System collects ALL CVEs from web ecosystems
2. **Automatic Labeling**: Priority CVEs are automatically labeled based on CWE matching
3. **Manual Curation**: Researchers manually exclude non-web CVEs
4. **Dual Reporting**: Priority mode for research, full mode for transparency
5. **Audit Trail**: All exclusions are logged with reason and timestamp

### Architecture Benefits

| Feature | v1.0 | v2.0 |
|---------|------|------|
| Coverage | Filtered at API level | 100% coverage |
| Flexibility | No curation | Manual curation |
| Transparency | Limited | Full transparency |
| Prioritization | API-level filtering | Automatic labeling |
| Audit Trail | None | Complete audit log |

### Quick Reference

**Priority CWE Categories**:
- Injection
- XSS
- Authentication
- Deserialization
- SSRF
- Path Traversal

**Exclusion Commands**:
```bash
# Exclude
python census task exclude --cve-id <id> --researcher <name> --reason "<reason>"

# List excluded
python census task list-excluded

# Restore
python census task restore --cve-id <id> --researcher <name>
```

**Report Modes**:
```bash
# Priority (curated)
python census report generate --output report.json --mode priority

# Full (all CVEs)
python census report generate --output report.json --mode full
```
