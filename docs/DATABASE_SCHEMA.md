# Database Schema and Data Models

This document provides comprehensive documentation of the database schema, data models, and data flow for the Web CVE Census System.

## Table of Contents

1. [Overview](#overview)
2. [Database Schema](#database-schema)
3. [Data Models](#data-models)
4. [Indexes](#indexes)
5. [Constraints](#constraints)
6. [Data Flow](#data-flow)
7. [Query Patterns](#query-patterns)
8. [Performance Considerations](#performance-considerations)

## Overview

The Web CVE Census System uses a PostgreSQL database (hosted on Neon) with a single main table `web_cve_census_master` that stores all CVE data, verification status, and exclusion metadata.

**Database**: Neon PostgreSQL (cloud-hosted, serverless)
**Connection**: SSL required
**Schema Version**: 2.0 (with priority CWE labeling and exclusion mechanism)

## Database Schema

### Table: web_cve_census_master

The main table storing all CVE census data.

```sql
CREATE TABLE web_cve_census_master (
    -- =========================================================================
    -- PRIMARY IDENTIFICATION
    -- =========================================================================
    cve_id VARCHAR(20) PRIMARY KEY,
    
    -- =========================================================================
    -- CVE METADATA
    -- =========================================================================
    description TEXT NOT NULL,
    severity VARCHAR(20),
    cvss_base_score DECIMAL(3,1),
    cvss_exploitability_score DECIMAL(3,1),
    affected_package VARCHAR(255),
    ecosystem VARCHAR(20) NOT NULL,
    publication_year INTEGER NOT NULL,
    cwe_category VARCHAR(50),
    
    -- =========================================================================
    -- CWE LABELING (NEW IN v2.0)
    -- =========================================================================
    -- Automatically labeled during collection based on CWE category matching
    is_priority_cwe BOOLEAN DEFAULT FALSE,
    
    -- =========================================================================
    -- EXPLOIT-DB CROSS-REFERENCE
    -- =========================================================================
    exploit_available BOOLEAN DEFAULT FALSE,
    exploit_db_id VARCHAR(50),
    
    -- =========================================================================
    -- CVE EXCLUSION MECHANISM (NEW IN v2.0)
    -- =========================================================================
    -- Manual curation to exclude non-web CVEs
    is_excluded BOOLEAN DEFAULT FALSE,
    excluded_by VARCHAR(100),
    excluded_at TIMESTAMP,
    exclusion_reason TEXT,
    
    -- =========================================================================
    -- VERIFICATION WORKFLOW
    -- =========================================================================
    build_status VARCHAR(20) DEFAULT 'NOT_ATTEMPTED',
    exploit_status VARCHAR(20) DEFAULT 'NONE',
    research_depth VARCHAR(20) DEFAULT 'LEVEL_0',
    assigned_to VARCHAR(100),
    assigned_at TIMESTAMP,
    claim_expires_at TIMESTAMP,
    exploit_notes TEXT,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- =========================================================================
    -- CONSTRAINTS
    -- =========================================================================
    CONSTRAINT chk_cvss_base 
        CHECK (cvss_base_score BETWEEN 0.0 AND 10.0),
    
    CONSTRAINT chk_cvss_exploit 
        CHECK (cvss_exploitability_score BETWEEN 0.0 AND 10.0),
    
    CONSTRAINT chk_year 
        CHECK (publication_year BETWEEN 2015 AND 2025),
    
    CONSTRAINT chk_ecosystem 
        CHECK (ecosystem IN ('npm', 'maven', 'pip', 'composer', 'go', 'rubygems')),
    
    CONSTRAINT chk_build_status 
        CHECK (build_status IN ('NOT_ATTEMPTED', 'IN_PROGRESS', 'SUCCESS', 'FAILED')),
    
    CONSTRAINT chk_exploit_status 
        CHECK (exploit_status IN ('NONE', 'POC_PUBLIC', 'EXPLOIT_DB', 'VERIFIED_SUCCESS', 'UNEXPLOITABLE')),
    
    CONSTRAINT chk_research_depth 
        CHECK (research_depth IN ('LEVEL_0', 'LEVEL_1', 'LEVEL_2')),
    
    CONSTRAINT chk_exclusion_reason 
        CHECK (is_excluded = FALSE OR exclusion_reason IS NOT NULL)
);
```

### Field Descriptions

#### Primary Identification

| Field | Type | Description | Required | Example |
|-------|------|-------------|----------|---------|
| `cve_id` | VARCHAR(20) | CVE identifier (primary key) | Yes | CVE-2021-12345 |

#### CVE Metadata

| Field | Type | Description | Required | Example |
|-------|------|-------------|----------|---------|
| `description` | TEXT | CVE description | Yes | SQL injection vulnerability in package X |
| `severity` | VARCHAR(20) | Severity level | No | CRITICAL, HIGH, MEDIUM, LOW |
| `cvss_base_score` | DECIMAL(3,1) | CVSS base score (0.0-10.0) | No | 9.8 |
| `cvss_exploitability_score` | DECIMAL(3,1) | CVSS exploitability score (0.0-10.0) | No | 3.9 |
| `affected_package` | VARCHAR(255) | Package name | No | express |
| `ecosystem` | VARCHAR(20) | Package ecosystem | Yes | npm |
| `publication_year` | INTEGER | Publication year (2015-2025) | Yes | 2021 |
| `cwe_category` | VARCHAR(50) | CWE category | No | Injection |

#### CWE Labeling (NEW)

| Field | Type | Description | Required | Example |
|-------|------|-------------|----------|---------|
| `is_priority_cwe` | BOOLEAN | TRUE if CWE matches priority categories | Yes | TRUE |

**Priority CWE Categories**:
- Injection
- XSS (Cross-Site Scripting)
- Authentication
- Deserialization
- SSRF (Server-Side Request Forgery)
- Path Traversal

#### Exploit-DB Cross-Reference

| Field | Type | Description | Required | Example |
|-------|------|-------------|----------|---------|
| `exploit_available` | BOOLEAN | TRUE if exploit found in Exploit-DB | Yes | TRUE |
| `exploit_db_id` | VARCHAR(50) | Exploit-DB identifier | No | EDB-12345 |

#### CVE Exclusion Mechanism (NEW)

| Field | Type | Description | Required | Example |
|-------|------|-------------|----------|---------|
| `is_excluded` | BOOLEAN | TRUE if manually excluded | Yes | FALSE |
| `excluded_by` | VARCHAR(100) | Researcher who excluded | No | Minh |
| `excluded_at` | TIMESTAMP | When CVE was excluded | No | 2025-01-15 10:30:45 |
| `exclusion_reason` | TEXT | Why CVE was excluded | Conditional* | Desktop app, not web-related |

*Required when `is_excluded = TRUE`

#### Verification Workflow

| Field | Type | Description | Required | Example |
|-------|------|-------------|----------|---------|
| `build_status` | VARCHAR(20) | Build environment status | Yes | SUCCESS |
| `exploit_status` | VARCHAR(20) | Exploit verification status | Yes | VERIFIED_SUCCESS |
| `research_depth` | VARCHAR(20) | Investigation depth level | Yes | LEVEL_2 |
| `assigned_to` | VARCHAR(100) | Researcher assigned | No | Minh |
| `assigned_at` | TIMESTAMP | When task was claimed | No | 2025-01-10 09:00:00 |
| `claim_expires_at` | TIMESTAMP | When claim expires | No | 2025-01-17 09:00:00 |
| `exploit_notes` | TEXT | Verification notes | No | Successfully exploited... |
| `updated_at` | TIMESTAMP | Last update timestamp | Yes | 2025-01-15 14:30:00 |

## Data Models

### CVEData

Primary data model for CVE records.

```python
from dataclasses import dataclass
from typing import Optional
from datetime import datetime

@dataclass
class CVEData:
    """CVE data model with support for priority labeling and exclusion."""
    
    # Primary identification
    cve_id: str
    
    # CVE metadata
    description: str
    severity: str
    cvss_base_score: float
    cvss_exploitability_score: float
    affected_package: str
    ecosystem: str
    publication_year: int
    cwe_category: str
    
    # CWE labeling (NEW)
    is_priority_cwe: bool = False
    
    # Exploit-DB cross-reference
    exploit_available: bool = False
    exploit_db_id: Optional[str] = None
    
    # CVE exclusion mechanism (NEW)
    is_excluded: bool = False
    excluded_by: Optional[str] = None
    excluded_at: Optional[datetime] = None
    exclusion_reason: Optional[str] = None
```

### ExploitData

Data model for Exploit-DB exploits.

```python
@dataclass
class ExploitData:
    """Exploit-DB exploit data model."""
    
    exploit_db_id: str
    exploit_type: str
    publication_date: datetime
    description: str
```

### CVETask

Data model for verification tasks.

```python
@dataclass
class CVETask:
    """CVE verification task model."""
    
    cve_id: str
    description: str
    ecosystem: str
    publication_year: int
    exploit_available: bool
    exploit_db_id: Optional[str]
    build_status: str
    exploit_status: str
    research_depth: str
    assigned_to: Optional[str]
    assigned_at: Optional[datetime]
    claim_expires_at: Optional[datetime]
    exploit_notes: Optional[str]
```

### Enumerations

#### BuildStatus

```python
from enum import Enum

class BuildStatus(Enum):
    """Build environment status."""
    
    NOT_ATTEMPTED = "NOT_ATTEMPTED"  # No build attempt yet
    IN_PROGRESS = "IN_PROGRESS"      # Currently setting up environment
    SUCCESS = "SUCCESS"              # Environment built successfully
    FAILED = "FAILED"                # Failed to build environment
```

#### ExploitStatus

```python
class ExploitStatus(Enum):
    """Exploit verification status (hierarchical order)."""
    
    NONE = "NONE"                          # No exploit found
    POC_PUBLIC = "POC_PUBLIC"              # Found on GitHub/Blog (unverified)
    EXPLOIT_DB = "EXPLOIT_DB"              # Found on Exploit-DB (higher reliability)
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"  # Team verified successful exploitation (ground truth)
    UNEXPLOITABLE = "UNEXPLOITABLE"        # Team attempted but failed (also ground truth)
```

**Hierarchical Order**: NONE < POC_PUBLIC < EXPLOIT_DB < VERIFIED_SUCCESS/UNEXPLOITABLE

#### ResearchDepth

```python
class ResearchDepth(Enum):
    """Research investigation depth level."""
    
    LEVEL_0 = "LEVEL_0"  # Metadata only, no code review
    LEVEL_1 = "LEVEL_1"  # Code review and initial assessment
    LEVEL_2 = "LEVEL_2"  # Complete analysis with Docker and exploitation
```

#### Ecosystem

```python
class Ecosystem(Enum):
    """Package manager ecosystem."""
    
    NPM = "npm"
    MAVEN = "maven"
    PIP = "pip"
    COMPOSER = "composer"
    GO = "go"
    RUBYGEMS = "rubygems"
```

#### CWECategory

```python
class CWECategory(Enum):
    """Priority CWE categories for labeling."""
    
    INJECTION = "Injection"
    XSS = "XSS"
    AUTHENTICATION = "Authentication"
    DESERIALIZATION = "Deserialization"
    SSRF = "SSRF"
    PATH_TRAVERSAL = "Path Traversal"
```

## Indexes

The system creates indexes for common query patterns to optimize performance.

```sql
-- Filter by publication year
CREATE INDEX idx_publication_year 
ON web_cve_census_master(publication_year);

-- Filter by ecosystem
CREATE INDEX idx_ecosystem 
ON web_cve_census_master(ecosystem);

-- Filter by CWE category
CREATE INDEX idx_cwe_category 
ON web_cve_census_master(cwe_category);

-- Filter by priority CWE flag (NEW)
CREATE INDEX idx_is_priority_cwe 
ON web_cve_census_master(is_priority_cwe);

-- Filter by exclusion status (NEW)
CREATE INDEX idx_is_excluded 
ON web_cve_census_master(is_excluded);

-- Filter by exploit availability
CREATE INDEX idx_exploit_available 
ON web_cve_census_master(exploit_available);

-- Filter by researcher assignment
CREATE INDEX idx_assigned_to 
ON web_cve_census_master(assigned_to);

-- Filter by verification status
CREATE INDEX idx_exploit_status 
ON web_cve_census_master(exploit_status);
```

### Index Usage

| Query Pattern | Index Used | Performance |
|---------------|------------|-------------|
| Filter by year | `idx_publication_year` | O(log n) |
| Filter by ecosystem | `idx_ecosystem` | O(log n) |
| Filter by CWE | `idx_cwe_category` | O(log n) |
| Filter by priority CWE | `idx_is_priority_cwe` | O(log n) |
| Filter by exclusion | `idx_is_excluded` | O(log n) |
| Filter by exploit | `idx_exploit_available` | O(log n) |
| Filter by researcher | `idx_assigned_to` | O(log n) |
| Filter by status | `idx_exploit_status` | O(log n) |
| Get by CVE ID | Primary key | O(1) |

## Constraints

### Data Integrity Constraints

#### CVSS Score Constraints

```sql
CONSTRAINT chk_cvss_base 
    CHECK (cvss_base_score BETWEEN 0.0 AND 10.0)

CONSTRAINT chk_cvss_exploit 
    CHECK (cvss_exploitability_score BETWEEN 0.0 AND 10.0)
```

**Purpose**: Ensure CVSS scores are within valid range (0.0-10.0)

#### Year Range Constraint

```sql
CONSTRAINT chk_year 
    CHECK (publication_year BETWEEN 2015 AND 2025)
```

**Purpose**: Ensure publication year is within census scope (2015-2025)

#### Ecosystem Constraint

```sql
CONSTRAINT chk_ecosystem 
    CHECK (ecosystem IN ('npm', 'maven', 'pip', 'composer', 'go', 'rubygems'))
```

**Purpose**: Ensure ecosystem is one of the supported web ecosystems

#### Build Status Constraint

```sql
CONSTRAINT chk_build_status 
    CHECK (build_status IN ('NOT_ATTEMPTED', 'IN_PROGRESS', 'SUCCESS', 'FAILED'))
```

**Purpose**: Ensure build status is a valid enum value

#### Exploit Status Constraint

```sql
CONSTRAINT chk_exploit_status 
    CHECK (exploit_status IN ('NONE', 'POC_PUBLIC', 'EXPLOIT_DB', 'VERIFIED_SUCCESS', 'UNEXPLOITABLE'))
```

**Purpose**: Ensure exploit status is a valid enum value

#### Research Depth Constraint

```sql
CONSTRAINT chk_research_depth 
    CHECK (research_depth IN ('LEVEL_0', 'LEVEL_1', 'LEVEL_2'))
```

**Purpose**: Ensure research depth is a valid enum value

#### Exclusion Reason Constraint

```sql
CONSTRAINT chk_exclusion_reason 
    CHECK (is_excluded = FALSE OR exclusion_reason IS NOT NULL)
```

**Purpose**: Ensure exclusion reason is provided when CVE is excluded

## Data Flow

### 1. Census Collection Flow

```
GitHub Advisory API
        ↓
[Query CVEs by ecosystem and year]
        ↓
[Extract CVE metadata]
        ↓
[Label priority CWEs] ← Priority CWE categories
        ↓
[Cross-reference with Exploit-DB] ← Exploit-DB CSV
        ↓
[Validate data] ← DataValidator
        ↓
[Insert into database] ← CVERepository
        ↓
web_cve_census_master table
```

### 2. Task Claiming Flow

```
Researcher request
        ↓
[Query available tasks] ← TaskManager
        ↓
[SELECT FOR UPDATE] ← Database lock
        ↓
[Check claim status]
        ↓
[Update assigned_to, assigned_at, claim_expires_at]
        ↓
[COMMIT transaction]
        ↓
Task claimed
```

### 3. Verification Flow

```
Researcher update
        ↓
[Verify researcher owns task] ← VerificationService
        ↓
[Validate status values]
        ↓
[Check notes requirement]
        ↓
[Update build_status/exploit_status/research_depth]
        ↓
[Update updated_at timestamp]
        ↓
[COMMIT transaction]
        ↓
Status updated
```

### 4. Exclusion Flow

```
Researcher exclusion request
        ↓
[Validate researcher ID] ← ExclusionService
        ↓
[Validate exclusion reason]
        ↓
[Update is_excluded, excluded_by, excluded_at, exclusion_reason]
        ↓
[Log to audit log]
        ↓
[COMMIT transaction]
        ↓
CVE excluded
```

## Query Patterns

### Common Queries

#### Get All Priority CVEs (Excluding Excluded)

```sql
SELECT * FROM web_cve_census_master
WHERE is_priority_cwe = TRUE
  AND is_excluded = FALSE
ORDER BY publication_year DESC, cve_id;
```

#### Get Available Tasks for Claiming

```sql
SELECT * FROM web_cve_census_master
WHERE (assigned_to IS NULL OR claim_expires_at < NOW())
  AND exploit_status != 'VERIFIED_SUCCESS'
  AND is_excluded = FALSE
ORDER BY exploit_available DESC, publication_year DESC
LIMIT 10;
```

#### Get Researcher's Tasks

```sql
SELECT * FROM web_cve_census_master
WHERE assigned_to = 'Minh'
  AND claim_expires_at > NOW()
ORDER BY assigned_at DESC;
```

#### Get Excluded CVEs

```sql
SELECT * FROM web_cve_census_master
WHERE is_excluded = TRUE
ORDER BY excluded_at DESC;
```

#### Get CVEs by Year and Ecosystem

```sql
SELECT * FROM web_cve_census_master
WHERE publication_year = 2021
  AND ecosystem = 'npm'
  AND is_excluded = FALSE
ORDER BY cvss_base_score DESC;
```

#### Get Verification Statistics

```sql
SELECT 
    exploit_status,
    COUNT(*) as count,
    ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM web_cve_census_master
WHERE is_excluded = FALSE
GROUP BY exploit_status
ORDER BY count DESC;
```

### Optimized Query Patterns

#### Use Indexes for Filtering

```sql
-- Good: Uses idx_publication_year and idx_ecosystem
SELECT * FROM web_cve_census_master
WHERE publication_year = 2021
  AND ecosystem = 'npm';

-- Bad: Full table scan
SELECT * FROM web_cve_census_master
WHERE EXTRACT(YEAR FROM updated_at) = 2021;
```

#### Use Covering Indexes

```sql
-- Good: Uses idx_is_priority_cwe
SELECT COUNT(*) FROM web_cve_census_master
WHERE is_priority_cwe = TRUE;

-- Good: Uses idx_exploit_available
SELECT COUNT(*) FROM web_cve_census_master
WHERE exploit_available = TRUE;
```

#### Avoid SELECT *

```sql
-- Good: Select only needed columns
SELECT cve_id, description, ecosystem
FROM web_cve_census_master
WHERE publication_year = 2021;

-- Bad: Fetches all columns
SELECT * FROM web_cve_census_master
WHERE publication_year = 2021;
```

## Performance Considerations

### Connection Pooling

The system uses connection pooling to manage database connections efficiently:

```python
# Configuration
DB_POOL_MIN_SIZE = 2
DB_POOL_MAX_SIZE = 10
DB_POOL_TIMEOUT = 30  # seconds
```

### Query Optimization

1. **Use Indexes**: All common query patterns have corresponding indexes
2. **Limit Results**: Use `LIMIT` clause for large result sets
3. **Pagination**: Use `OFFSET` and `LIMIT` for pagination
4. **Avoid N+1 Queries**: Fetch related data in single query when possible
5. **Use Prepared Statements**: All queries use parameterized statements

### Transaction Management

1. **Atomic Operations**: Use transactions for multi-step operations
2. **Optimistic Locking**: Use `updated_at` timestamp for concurrent updates
3. **SELECT FOR UPDATE**: Use for task claiming to prevent race conditions
4. **Short Transactions**: Keep transactions short to avoid lock contention

### Monitoring

1. **Slow Query Log**: Queries > 1000ms are logged
2. **Connection Pool Metrics**: Monitor pool usage and wait times
3. **Index Usage**: Monitor index hit rates
4. **Table Size**: Monitor table growth and vacuum operations

### Maintenance

1. **VACUUM**: Run VACUUM ANALYZE periodically to update statistics
2. **REINDEX**: Rebuild indexes if fragmented
3. **Backup**: Regular backups using Neon's built-in backup system
4. **Monitoring**: Use Neon dashboard for performance monitoring

## Schema Migration

### Version History

- **v1.0**: Initial schema with basic CVE data and verification workflow
- **v2.0**: Added `is_priority_cwe`, `is_excluded`, `excluded_by`, `excluded_at`, `exclusion_reason` fields

### Migration from v1.0 to v2.0

```sql
-- Add new columns
ALTER TABLE web_cve_census_master
ADD COLUMN is_priority_cwe BOOLEAN DEFAULT FALSE,
ADD COLUMN is_excluded BOOLEAN DEFAULT FALSE,
ADD COLUMN excluded_by VARCHAR(100),
ADD COLUMN excluded_at TIMESTAMP,
ADD COLUMN exclusion_reason TEXT;

-- Add new indexes
CREATE INDEX idx_is_priority_cwe ON web_cve_census_master(is_priority_cwe);
CREATE INDEX idx_is_excluded ON web_cve_census_master(is_excluded);

-- Add new constraint
ALTER TABLE web_cve_census_master
ADD CONSTRAINT chk_exclusion_reason 
CHECK (is_excluded = FALSE OR exclusion_reason IS NOT NULL);

-- Backfill is_priority_cwe for existing records
UPDATE web_cve_census_master
SET is_priority_cwe = TRUE
WHERE cwe_category IN ('Injection', 'XSS', 'Authentication', 'Deserialization', 'SSRF', 'Path Traversal');
```

## Best Practices

### Data Insertion

1. **Check for Duplicates**: Always check if CVE exists before inserting
2. **Validate Data**: Use DataValidator before insertion
3. **Handle Errors**: Catch and log insertion errors
4. **Batch Inserts**: Use batch inserts for large datasets

### Data Updates

1. **Optimistic Locking**: Use `updated_at` timestamp for concurrent updates
2. **Partial Updates**: Update only changed fields
3. **Validate Changes**: Validate new values before updating
4. **Audit Trail**: Log important updates (exclusions, status changes)

### Data Queries

1. **Use Indexes**: Ensure queries use appropriate indexes
2. **Limit Results**: Always use LIMIT for large result sets
3. **Filter Early**: Apply filters in WHERE clause, not in application
4. **Avoid SELECT ***: Select only needed columns

### Data Maintenance

1. **Regular Backups**: Use Neon's automated backup system
2. **Monitor Growth**: Track table size and plan for scaling
3. **Vacuum Regularly**: Run VACUUM ANALYZE to maintain performance
4. **Review Indexes**: Periodically review index usage and add/remove as needed
