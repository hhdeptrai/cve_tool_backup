"""Data models for the Web CVE Census System."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


class BuildStatus(Enum):
    """Status of exploit environment setup."""
    NOT_ATTEMPTED = "NOT_ATTEMPTED"
    IN_PROGRESS = "IN_PROGRESS"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class ExploitStatus(Enum):
    """Status of exploit verification."""
    NONE = "NONE"  # No exploit found
    POC_PUBLIC = "POC_PUBLIC"  # Found on GitHub/Blog (unverified)
    EXPLOIT_DB = "EXPLOIT_DB"  # Found on Exploit-DB (higher reliability)
    VERIFIED_SUCCESS = "VERIFIED_SUCCESS"  # Team verified successful exploitation (ground truth)
    UNEXPLOITABLE = "UNEXPLOITABLE"  # Team attempted but failed (also ground truth)


class ResearchDepth(Enum):
    """Level of investigation performed."""
    LEVEL_0 = "LEVEL_0"  # Metadata only, no code review
    LEVEL_1 = "LEVEL_1"  # Code review and initial assessment
    LEVEL_2 = "LEVEL_2"  # Complete analysis with Docker and exploitation


class Ecosystem(Enum):
    """Package manager ecosystem."""
    NPM = "npm"
    MAVEN = "maven"
    NUGET = "nuget"
    PIP = "pip"
    COMPOSER = "composer"
    GO = "go"
    RUBYGEMS = "rubygems"
    RUST = "rust"
    ERLANG = "erlang"


class CWECategory(Enum):
    """Common Weakness Enumeration categories."""
    BROKEN_ACCESS_CONTROL = "BROKEN_ACCESS_CONTROL"
    INJECTION_FLAWS = "INJECTION_FLAWS"
    CRYPTOGRAPHIC_FAILURES = "CRYPTOGRAPHIC_FAILURES"
    INSECURE_DESIGN_AND_ARCH = "INSECURE_DESIGN_AND_ARCH"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    AUTHENTICATION_FAILURES = "AUTHENTICATION_FAILURES"
    SOFTWARE_AND_DATA_INTEGRITY = "SOFTWARE_AND_DATA_INTEGRITY"


@dataclass
class CVEData:
    """CVE data collected from GitHub Advisory Database."""
    cve_id: str
    description: str
    severity: str
    cvss_base_score: float
    cvss_exploitability_score: float
    affected_package: str
    ecosystem: str
    publication_year: int
    primary_cwe_id: str
    cwe_ids: list[str] = field(default_factory=list)
    owasp_category: Optional[str] = None
    exploit_available: bool = False
    exploit_db_id: Optional[str] = None
    # New fields for priority labeling and exclusion mechanism
    is_priority_cwe: bool = False
    is_excluded: bool = False
    excluded_by: Optional[str] = None
    excluded_at: Optional[datetime] = None
    exclusion_reason: Optional[str] = None
    has_github_poc: bool = False


@dataclass
class ExploitData:
    """Exploit data from Exploit-DB."""
    exploit_db_id: str
    exploit_type: str
    publication_date: datetime
    description: str


@dataclass
class CVETask:
    """CVE verification task."""
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
    cvss_base_score: Optional[float] = None
