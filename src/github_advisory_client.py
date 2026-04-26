"""GitHub Advisory API client for CVE data collection."""

import time
from datetime import datetime
from typing import List, Optional, Dict, Any
import requests
from src.models import CVEData, Ecosystem, CWECategory
from src.config import Config


class RateLimiter:
    """Rate limiter for GitHub API requests (5000 req/hour)."""
    
    def __init__(self, max_requests: int = 5000, time_window: int = 3600):
        """
        Initialize rate limiter.
        
        Args:
            max_requests: Maximum requests allowed in time window
            time_window: Time window in seconds (default: 3600 = 1 hour)
        """
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests: List[float] = []
    
    def wait_if_needed(self) -> None:
        """Wait if rate limit would be exceeded."""
        now = time.time()
        
        # Remove requests outside the time window
        self.requests = [req_time for req_time in self.requests 
                        if now - req_time < self.time_window]
        
        # If at limit, wait until oldest request expires
        if len(self.requests) >= self.max_requests:
            oldest_request = self.requests[0]
            wait_time = self.time_window - (now - oldest_request)
            if wait_time > 0:
                time.sleep(wait_time + 1)  # Add 1 second buffer
                # Clean up again after waiting
                now = time.time()
                self.requests = [req_time for req_time in self.requests 
                               if now - req_time < self.time_window]
        
        # Record this request
        self.requests.append(now)


class GitHubAdvisoryClient:
    """Client for querying GitHub Security Advisory Database via GraphQL API."""
    
    GRAPHQL_ENDPOINT = "https://api.github.com/graphql"
    
    
    def __init__(self, token: Optional[str] = None, batch_size: int = 100):
        """
        Initialize GitHub Advisory client.
        
        Args:
            token: GitHub personal access token (optional but recommended)
            batch_size: Number of advisories to fetch per request (default: 100)
        """
        self.token = token or Config.GITHUB_TOKEN
        self.batch_size = min(batch_size, 100)  # Cap at 100 per GitHub API limits
        self.rate_limiter = RateLimiter()
        
        if not self.token:
            raise ValueError("GitHub token is required. Set GITHUB_TOKEN environment variable.")
    
    def _build_graphql_query(
        self,
        published_since: Optional[str] = None,
        cursor: Optional[str] = None
    ) -> str:
        """
        Build GraphQL query for security advisories.
        
        Args:
            published_since: ISO date string for minimum publication date
            cursor: Pagination cursor
            
        Returns:
            GraphQL query string
        """
        # Note: GitHub API doesn't support direct ecosystem filtering in the query
        # We'll filter results after fetching by ecosystem and year only
        
        after_clause = f', after: "{cursor}"' if cursor else ''
        
        query = f"""
        query {{
          securityVulnerabilities(first: {self.batch_size}{after_clause}) {{
            pageInfo {{
              hasNextPage
              endCursor
            }}
            nodes {{
              advisory {{
                ghsaId
                summary
                description
                severity
                publishedAt
                cvssSeverities {{
                  cvssV3 {{
                    score
                    vectorString
                  }}
                  cvssV4 {{
                    score
                    vectorString
                  }}
                }}
                cwes(first: 10) {{
                  nodes {{
                    cweId
                    name
                  }}
                }}
                identifiers {{
                  type
                  value
                }}
              }}
              package {{
                name
                ecosystem
              }}
              vulnerableVersionRange
            }}
          }}
        }}
        """
        
        return query
    
    def _execute_query(self, query: str) -> Dict[str, Any]:
        """
        Execute GraphQL query against GitHub API.
        
        Args:
            query: GraphQL query string
            
        Returns:
            Response data dictionary
            
        Raises:
            requests.HTTPError: If API request fails
        """
        self.rate_limiter.wait_if_needed()
        
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/json",
        }
        
        response = requests.post(
            self.GRAPHQL_ENDPOINT,
            json={"query": query},
            headers=headers,
            timeout=30
        )
        
        response.raise_for_status()
        data = response.json()
        
        if "errors" in data:
            raise ValueError(f"GraphQL errors: {data['errors']}")
        
        return data["data"]
    
    def _extract_cve_id(self, identifiers: List[Dict[str, str]]) -> Optional[str]:
        """Extract CVE ID from advisory identifiers."""
        for identifier in identifiers:
            if identifier.get("type") == "CVE":
                return identifier.get("value")
        return None

    @staticmethod
    def _extract_cve_year(cve_id: str) -> Optional[int]:
        """Extract the year from a CVE ID (e.g., CVE-2025-12345 → 2025)."""
        try:
            parts = cve_id.split('-')
            if len(parts) >= 2:
                return int(parts[1])
        except (ValueError, IndexError):
            pass
        return None
    


    
    def _parse_advisory(self, vulnerability: Dict[str, Any]) -> Optional[CVEData]:
        """
        Parse a vulnerability node into CVEData.
        
        Args:
            vulnerability: Vulnerability node from GraphQL response
            
        Returns:
            CVEData object or None if parsing fails
        """
        try:
            advisory = vulnerability.get("advisory", {})
            package = vulnerability.get("package", {})
            
            # Extract CVE ID
            cve_id = self._extract_cve_id(advisory.get("identifiers", []))
            if not cve_id:
                return None  # Skip advisories without CVE ID
            
            # Extract CWE information
            cwes = advisory.get("cwes", {}).get("nodes", [])
            cwe_ids = [cwe.get("cweId", "") for cwe in cwes if cwe.get("cweId")]
            
            cwe_category = cwe_ids[0] if cwe_ids else "Unknown"            
            # Extract ecosystem
            ecosystem = package.get("ecosystem", "").lower()
            if not ecosystem:
                return None
            
            # Parse publication date
            published_at = advisory.get("publishedAt", "")
            try:
                pub_date = datetime.fromisoformat(published_at.replace("Z", "+00:00"))
                publication_year = pub_date.year
            except (ValueError, AttributeError):
                return None
            
            # Extract CVSS scores — prefer v4 over v3 (some CVEs only have v4)
            cvss_severities = advisory.get("cvssSeverities", {})
            cvss_v4 = cvss_severities.get("cvssV4") or {}
            cvss_v3 = cvss_severities.get("cvssV3") or {}
            cvss_base_score = cvss_v4.get("score") or cvss_v3.get("score") or 0.0
            
            # GitHub doesn't provide exploitability score directly
            # We'll use a default or calculate based on severity
            severity = advisory.get("severity", "UNKNOWN").upper()
            cvss_exploitability_score = self._estimate_exploitability(severity)
            
            # Create CVEData object (ALL CVEs collected, no CWE filtering)
            return CVEData(
                cve_id=cve_id,
                description=advisory.get("description") or advisory.get("summary", ""),
                severity=severity,
                cvss_base_score=float(cvss_base_score),
                cvss_exploitability_score=cvss_exploitability_score,
                affected_package=package.get("name", ""),
                ecosystem=ecosystem,
                publication_year=publication_year,
                primary_cwe_id=cwe_category,
                cwe_ids=cwe_ids,
                exploit_available=False,  # Will be updated by cross-reference engine
                exploit_db_id=None,
                is_priority_cwe=False  # Will be set by CensusCollector
            )
        except Exception as e:
            # Log error and skip this advisory
            print(f"Error parsing advisory: {e}")
            return None
    
    def _estimate_exploitability(self, severity: str) -> float:
        """
        Estimate exploitability score based on severity.
        
        This is a rough estimate since GitHub doesn't provide exploitability scores.
        
        Args:
            severity: Severity level (CRITICAL, HIGH, MODERATE, LOW)
            
        Returns:
            Estimated exploitability score (0.0-10.0)
        """
        severity_map = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MODERATE": 5.0,
            "MEDIUM": 5.0,
            "LOW": 2.5,
        }
        return severity_map.get(severity, 5.0)
    
    def collect_cves(
        self,
        start_year: int = 2015,
        end_year: int = 2025,
        ecosystems: Optional[List[str]] = None,
        cursor: Optional[str] = None,
        max_results: Optional[int] = None
    ) -> List[CVEData]:
        """
        Collect ALL CVEs from GitHub Advisory Database.
        
        NO CWE filtering - collects all CVEs for 100% coverage.
        Filters ONLY by year range (2015-2025) and ecosystem.
        
        Args:
            start_year: Starting year (2015-2025)
            end_year: Ending year (2015-2025)
            ecosystems: List of package ecosystems to include (e.g., ['npm', 'pip'])
            max_results: Maximum number of results to return (None = no limit)
            
        Returns:
            List of CVEData objects (is_priority_cwe will be set by CensusCollector)
        """
        # Validate inputs
        current_year = datetime.now().year
        if start_year < 2015 or start_year > current_year:
            raise ValueError(f"start_year must be between 2015 and {current_year}")
        if end_year < 2015 or end_year > current_year:
            raise ValueError(f"end_year must be between 2015 and {current_year}")
        if start_year > end_year:
            raise ValueError("start_year must be <= end_year")
        
        # Set default filters
        if ecosystems is None:
            ecosystems = [e.value for e in Ecosystem]
        
        # Convert to lowercase for comparison
        ecosystems_lower = [e.lower() for e in ecosystems]
        
        # Build published_since parameter
        published_since = f"{start_year}-01-01T00:00:00Z"
        
        results: List[CVEData] = []
        # cursor argument used as initial cursor
        has_next_page = True
        
        print(f"Collecting ALL CVEs from {start_year} to {end_year}...")
        print(f"Ecosystems: {ecosystems}")
        print(f"NOTE: NO CWE filtering - collecting all CVEs for 100% coverage")
        
        total_scanned = 0
        
        while has_next_page:
            # Build and execute query (NO CWE filters)
            query = self._build_graphql_query(
                published_since=published_since,
                cursor=cursor
            )
            
            try:
                data = self._execute_query(query)
            except Exception as e:
                print(f"Error executing query: {e}")
                break
            
            # Parse results
            vulnerabilities = data.get("securityVulnerabilities", {})
            nodes = vulnerabilities.get("nodes", [])
            total_scanned += len(nodes)
            
            batch_results = []
            for node in nodes:
                cve_data = self._parse_advisory(node)
                if cve_data:
                    # Apply ecosystem and CVE ID year filters (NOT publication year)
                    cve_year = self._extract_cve_year(cve_data.cve_id)
                    if cve_year is None or cve_year < start_year or cve_year > end_year:
                        continue
                    if cve_data.ecosystem not in ecosystems_lower:
                        continue
                    
                    batch_results.append(cve_data)
                    
            # Check pagination
            page_info = vulnerabilities.get("pageInfo", {})
            has_next_page = page_info.get("hasNextPage", False)
            next_cursor = page_info.get("endCursor")
            
            # YIELD BATCH RESULTS AND CURSOR
            if batch_results:
                # Truncate batch if max_results would be exceeded
                if max_results and len(results) + len(batch_results) > max_results:
                    remaining = max_results - len(results)
                    batch_results = batch_results[:remaining]
                results.extend(batch_results)
                yield batch_results, next_cursor
            elif next_cursor:
                # Even if no matches in this batch, yield empty list with cursor to save progress
                yield [], next_cursor
                
            cursor = next_cursor
            
            print(f"Collected {len(results)} CVEs so far (Scanned {total_scanned} advisories)...", end="\r", flush=True)
            
            # Check max results limit
            if max_results and len(results) >= max_results:
                print(f"Reached max results limit: {max_results}")
                break

            # Safety check: don't paginate forever
            if len(results) > 10000:
                print("Safety limit reached (10000 CVEs). Stopping pagination.")
                break
        
        print(f"\nCollection complete. Total CVEs: {len(results)}")
