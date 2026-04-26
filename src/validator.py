"""Data validation for the Web CVE Census System."""

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from .models import BuildStatus, CWECategory, Ecosystem, ExploitStatus, ResearchDepth


@dataclass
class ValidationResult:
    """Result of data validation."""
    is_valid: bool
    errors: List[str]
    
    def __bool__(self) -> bool:
        """Allow using ValidationResult in boolean context."""
        return self.is_valid


class DataValidator:
    """Validates CVE data against schema and business rules."""
    
    # CVE ID format: CVE-YYYY-NNNNN (where YYYY is 4 digits and NNNNN is 4+ digits)
    CVE_ID_PATTERN = re.compile(r'^CVE-\d{4}-\d{4,}$')
    
    # Valid researcher IDs
    VALID_RESEARCHERS = {"Minh", "Hoàng"}
    
    # CVSS score range
    MIN_CVSS_SCORE = 0.0
    MAX_CVSS_SCORE = 10.0
    
    # Publication year range
    MIN_YEAR = 2015
    MAX_YEAR = datetime.now().year + 1  # Dynamic: current year + 1 to allow early publications
    
    def validate_cve_id(self, cve_id: str) -> ValidationResult:
        """
        Validate CVE ID format.
        
        Args:
            cve_id: CVE identifier to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(cve_id, str):
            errors.append(f"CVE ID must be a string, got {type(cve_id).__name__}")
        elif not self.CVE_ID_PATTERN.match(cve_id):
            errors.append(
                f"CVE ID '{cve_id}' does not match required format CVE-YYYY-NNNNN"
            )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_cvss_score(
        self,
        score: float,
        score_name: str = "CVSS score"
    ) -> ValidationResult:
        """
        Validate CVSS score is in range [0.0, 10.0].
        
        Args:
            score: CVSS score to validate
            score_name: Name of the score field for error messages
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(score, (int, float)):
            errors.append(
                f"{score_name} must be a number, got {type(score).__name__}"
            )
        elif score < self.MIN_CVSS_SCORE or score > self.MAX_CVSS_SCORE:
            errors.append(
                f"{score_name} {score} is out of valid range "
                f"[{self.MIN_CVSS_SCORE}, {self.MAX_CVSS_SCORE}]"
            )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)

    def validate_publication_year(self, year: int) -> ValidationResult:
        """
        Validate publication year is in range [2015, 2025].
        
        Args:
            year: Publication year to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(year, int):
            errors.append(
                f"Publication year must be an integer, got {type(year).__name__}"
            )
        elif year < self.MIN_YEAR or year > self.MAX_YEAR:
            errors.append(
                f"Publication year {year} is out of valid range "
                f"[{self.MIN_YEAR}, {self.MAX_YEAR}]"
            )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_ecosystem(self, ecosystem: str) -> ValidationResult:
        """
        Validate ecosystem is in allowed list.
        
        Args:
            ecosystem: Ecosystem to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(ecosystem, str):
            errors.append(
                f"Ecosystem must be a string, got {type(ecosystem).__name__}"
            )
        else:
            valid_ecosystems = {e.value for e in Ecosystem}
            if ecosystem not in valid_ecosystems:
                errors.append(
                    f"Ecosystem '{ecosystem}' is not valid. "
                    f"Must be one of: {', '.join(sorted(valid_ecosystems))}"
                )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_primary_cwe_id(self, primary_cwe_id: str) -> ValidationResult:
        """
        Validate primary CWE ID is a non-empty string.
        
        NOTE: In the new architecture, we accept ANY CWE ID (not just priority ones).
        The system labels CVEs as priority/non-priority post-collection based on CWE ID.
        
        Args:
            primary_cwe_id: Primary CWE ID to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(primary_cwe_id, str):
            errors.append(
                f"Primary CWE ID must be a string, got {type(primary_cwe_id).__name__}"
            )
        elif not primary_cwe_id.strip():
            errors.append("Primary CWE ID cannot be empty")
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_researcher_id(self, researcher_id: str) -> ValidationResult:
        """
        Validate researcher ID is either "Minh" or "Hoàng".
        
        Args:
            researcher_id: Researcher ID to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(researcher_id, str):
            errors.append(
                f"Researcher ID must be a string, got {type(researcher_id).__name__}"
            )
        elif researcher_id not in self.VALID_RESEARCHERS:
            errors.append(
                f"Researcher ID '{researcher_id}' is not valid. "
                f"Must be one of: {', '.join(sorted(self.VALID_RESEARCHERS))}"
            )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_build_status(self, status: str) -> ValidationResult:
        """
        Validate build status is a valid enum value.
        
        Args:
            status: Build status to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(status, str):
            errors.append(
                f"Build status must be a string, got {type(status).__name__}"
            )
        else:
            valid_statuses = {s.value for s in BuildStatus}
            if status not in valid_statuses:
                errors.append(
                    f"Build status '{status}' is not valid. "
                    f"Must be one of: {', '.join(sorted(valid_statuses))}"
                )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_exploit_status(self, status: str) -> ValidationResult:
        """
        Validate exploit status is a valid enum value.
        
        Args:
            status: Exploit status to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(status, str):
            errors.append(
                f"Exploit status must be a string, got {type(status).__name__}"
            )
        else:
            valid_statuses = {s.value for s in ExploitStatus}
            if status not in valid_statuses:
                errors.append(
                    f"Exploit status '{status}' is not valid. "
                    f"Must be one of: {', '.join(sorted(valid_statuses))}"
                )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_research_depth(self, depth: str) -> ValidationResult:
        """
        Validate research depth is a valid enum value.
        
        Args:
            depth: Research depth to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        errors = []
        
        if not isinstance(depth, str):
            errors.append(
                f"Research depth must be a string, got {type(depth).__name__}"
            )
        else:
            valid_depths = {d.value for d in ResearchDepth}
            if depth not in valid_depths:
                errors.append(
                    f"Research depth '{depth}' is not valid. "
                    f"Must be one of: {', '.join(sorted(valid_depths))}"
                )
        
        return ValidationResult(is_valid=len(errors) == 0, errors=errors)
    
    def validate_cve(self, cve_data: Dict[str, Any]) -> ValidationResult:
        """
        Validate CVE data against schema and business rules.
        
        Validations:
            - CVE ID format: CVE-YYYY-NNNNN
            - CVSS scores: 0.0 - 10.0
            - Publication year: 2015 - 2025
            - Ecosystem: allowed list
            - Primary CWE ID: non-empty string
            
        Args:
            cve_data: Dictionary containing CVE data to validate
            
        Returns:
            ValidationResult with success status and error messages
        """
        all_errors = []
        
        # Validate CVE ID
        if 'cve_id' in cve_data:
            result = self.validate_cve_id(cve_data['cve_id'])
            all_errors.extend(result.errors)
        else:
            all_errors.append("Missing required field: cve_id")
        
        # Validate CVSS base score
        if 'cvss_base_score' in cve_data:
            result = self.validate_cvss_score(
                cve_data['cvss_base_score'],
                "CVSS base score"
            )
            all_errors.extend(result.errors)
        
        # Validate CVSS exploitability score
        if 'cvss_exploitability_score' in cve_data:
            result = self.validate_cvss_score(
                cve_data['cvss_exploitability_score'],
                "CVSS exploitability score"
            )
            all_errors.extend(result.errors)
        
        # Validate publication year
        if 'publication_year' in cve_data:
            result = self.validate_publication_year(cve_data['publication_year'])
            all_errors.extend(result.errors)
        else:
            all_errors.append("Missing required field: publication_year")
        
        # Validate ecosystem
        if 'ecosystem' in cve_data:
            result = self.validate_ecosystem(cve_data['ecosystem'])
            all_errors.extend(result.errors)
        else:
            all_errors.append("Missing required field: ecosystem")
        
        # Validate primary CWE ID
        if 'primary_cwe_id' in cve_data:
            result = self.validate_primary_cwe_id(cve_data['primary_cwe_id'])
            all_errors.extend(result.errors)
        
        # Validate researcher ID if present
        if 'assigned_to' in cve_data and cve_data['assigned_to'] is not None:
            result = self.validate_researcher_id(cve_data['assigned_to'])
            all_errors.extend(result.errors)
        
        # Validate build status if present
        if 'build_status' in cve_data:
            result = self.validate_build_status(cve_data['build_status'])
            all_errors.extend(result.errors)
        
        # Validate exploit status if present
        if 'exploit_status' in cve_data:
            result = self.validate_exploit_status(cve_data['exploit_status'])
            all_errors.extend(result.errors)
        
        # Validate research depth if present
        if 'research_depth' in cve_data:
            result = self.validate_research_depth(cve_data['research_depth'])
            all_errors.extend(result.errors)
        
        return ValidationResult(is_valid=len(all_errors) == 0, errors=all_errors)
