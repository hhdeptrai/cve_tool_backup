"""Demo script for GitHub Advisory API client."""

import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from src.github_advisory_client import GitHubAdvisoryClient
from src.models import Ecosystem, CWECategory
from src.config import Config


def main():
    """Demonstrate GitHub Advisory client usage."""
    print("=" * 60)
    print("GitHub Advisory API Client Demo")
    print("=" * 60)
    print()
    
    # Check if token is configured
    if not Config.GITHUB_TOKEN:
        print("ERROR: GITHUB_TOKEN environment variable not set")
        print("Please set your GitHub personal access token in .env file")
        return
    
    # Initialize client
    print("Initializing GitHub Advisory client...")
    client = GitHubAdvisoryClient(batch_size=10)  # Small batch for demo
    print(f"✓ Client initialized with batch size: {client.batch_size}")
    print()
    
    # Example 1: Collect CVEs for a specific year and ecosystem
    print("Example 1: Collect npm CVEs from 2021 with Injection vulnerabilities")
    print("-" * 60)
    
    try:
        cves = client.collect_cves(
            start_year=2021,
            end_year=2021,
            ecosystems=["npm"],
            cwe_filters=[CWECategory.INJECTION.value],
            max_results=5  # Limit to 5 for demo
        )
        
        print(f"✓ Collected {len(cves)} CVEs")
        print()
        
        # Display results
        for i, cve in enumerate(cves, 1):
            print(f"CVE #{i}:")
            print(f"  ID: {cve.cve_id}")
            print(f"  Package: {cve.affected_package}")
            print(f"  Ecosystem: {cve.ecosystem}")
            print(f"  Severity: {cve.severity}")
            print(f"  CVSS Base Score: {cve.cvss_base_score}")
            print(f"  CWE Category: {cve.cwe_category}")
            print(f"  Description: {cve.description[:100]}...")
            print()
    
    except Exception as e:
        print(f"✗ Error collecting CVEs: {e}")
        return
    
    # Example 2: Collect CVEs across multiple ecosystems
    print()
    print("Example 2: Collect CVEs from multiple ecosystems (2022)")
    print("-" * 60)
    
    try:
        cves = client.collect_cves(
            start_year=2022,
            end_year=2022,
            ecosystems=["npm", "pip", "maven"],
            cwe_filters=[CWECategory.XSS.value, CWECategory.INJECTION.value],
            max_results=10
        )
        
        print(f"✓ Collected {len(cves)} CVEs")
        
        # Group by ecosystem
        by_ecosystem = {}
        for cve in cves:
            if cve.ecosystem not in by_ecosystem:
                by_ecosystem[cve.ecosystem] = []
            by_ecosystem[cve.ecosystem].append(cve)
        
        print()
        print("Distribution by ecosystem:")
        for ecosystem, ecosystem_cves in by_ecosystem.items():
            print(f"  {ecosystem}: {len(ecosystem_cves)} CVEs")
    
    except Exception as e:
        print(f"✗ Error collecting CVEs: {e}")
        return
    
    # Example 3: Rate limiter demonstration
    print()
    print("Example 3: Rate limiter in action")
    print("-" * 60)
    print("The client automatically handles rate limiting (5000 req/hour)")
    print("Rate limiter tracks requests and waits if limit is approached")
    print(f"Current requests tracked: {len(client.rate_limiter.requests)}")
    print()
    
    print("=" * 60)
    print("Demo complete!")
    print("=" * 60)


if __name__ == "__main__":
    main()
