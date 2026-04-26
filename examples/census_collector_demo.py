"""Demo script for CensusCollector usage."""

import os
from pathlib import Path
from src.census_collector import CensusCollector
from src.config import Config


def demo_basic_collection():
    """Demonstrate basic CVE collection."""
    print("=" * 60)
    print("Demo: Basic CVE Collection")
    print("=" * 60)
    
    # Initialize collector
    collector = CensusCollector(
        github_token=Config.GITHUB_TOKEN,
        batch_size=10  # Small batch for demo
    )
    
    # Collect CVEs for a specific year and ecosystem
    print("\nCollecting npm CVEs from 2023 with Injection vulnerabilities...")
    cves = collector.collect_cves(
        start_year=2023,
        end_year=2023,
        ecosystems=["npm"],
        cwe_filters=["Injection"],
        max_retries=3
    )
    
    # Display results
    print(f"\nCollected {len(cves)} CVEs")
    
    if cves:
        print("\nFirst 3 CVEs:")
        for cve in cves[:3]:
            print(f"\n  CVE ID: {cve.cve_id}")
            print(f"  Package: {cve.affected_package}")
            print(f"  Severity: {cve.severity}")
            print(f"  CVSS Base: {cve.cvss_base_score}")
            print(f"  Exploit Available: {cve.exploit_available}")
    
    # Get statistics
    stats = collector.get_statistics()
    print("\nCollection Statistics:")
    print(f"  Total collected: {stats['total_collected']}")
    print(f"  Validated: {stats['validated']}")
    print(f"  Validation failed: {stats['validation_failed']}")
    print(f"  Exploits found: {stats['exploits_found']}")


def demo_with_exploit_db():
    """Demonstrate CVE collection with Exploit-DB cross-referencing."""
    print("\n" + "=" * 60)
    print("Demo: CVE Collection with Exploit-DB Cross-Reference")
    print("=" * 60)
    
    # Path to Exploit-DB CSV
    exploitdb_path = Path("data/exploitdb/files_exploits.csv")
    
    if not exploitdb_path.exists():
        print(f"\nExploit-DB CSV not found at: {exploitdb_path}")
        print("Skipping Exploit-DB demo.")
        print("To enable: Download files_exploits.csv from Exploit-DB")
        return
    
    # Initialize collector with Exploit-DB
    collector = CensusCollector(
        github_token=Config.GITHUB_TOKEN,
        exploitdb_csv_path=str(exploitdb_path),
        batch_size=10
    )
    
    # Collect CVEs
    print("\nCollecting CVEs with Exploit-DB cross-referencing...")
    cves = collector.collect_cves(
        start_year=2022,
        end_year=2022,
        ecosystems=["npm", "pip"],
        cwe_filters=["Injection", "XSS"],
        max_retries=3
    )
    
    # Display CVEs with exploits
    cves_with_exploits = [cve for cve in cves if cve.exploit_available]
    
    print(f"\nFound {len(cves_with_exploits)} CVEs with public exploits:")
    for cve in cves_with_exploits[:5]:
        print(f"\n  CVE ID: {cve.cve_id}")
        print(f"  Package: {cve.affected_package}")
        print(f"  Exploit-DB ID: {cve.exploit_db_id}")
        print(f"  CWE Category: {cve.cwe_category}")


def demo_multi_ecosystem():
    """Demonstrate collection across multiple ecosystems."""
    print("\n" + "=" * 60)
    print("Demo: Multi-Ecosystem Collection")
    print("=" * 60)
    
    # Initialize collector
    collector = CensusCollector(
        github_token=Config.GITHUB_TOKEN,
        batch_size=20
    )
    
    # Collect from multiple ecosystems
    ecosystems = ["npm", "pip", "maven"]
    print(f"\nCollecting from ecosystems: {', '.join(ecosystems)}")
    
    cves = collector.collect_cves(
        start_year=2023,
        end_year=2023,
        ecosystems=ecosystems,
        cwe_filters=["Injection", "XSS", "Authentication"],
        max_retries=3
    )
    
    # Group by ecosystem
    by_ecosystem = {}
    for cve in cves:
        ecosystem = cve.ecosystem
        if ecosystem not in by_ecosystem:
            by_ecosystem[ecosystem] = []
        by_ecosystem[ecosystem].append(cve)
    
    # Display distribution
    print("\nCVE Distribution by Ecosystem:")
    for ecosystem, ecosystem_cves in sorted(by_ecosystem.items()):
        print(f"  {ecosystem}: {len(ecosystem_cves)} CVEs")


def demo_error_handling():
    """Demonstrate error handling and retry logic."""
    print("\n" + "=" * 60)
    print("Demo: Error Handling and Retry Logic")
    print("=" * 60)
    
    # Initialize collector with invalid token to trigger errors
    print("\nTesting with invalid GitHub token...")
    
    try:
        collector = CensusCollector(
            github_token="invalid_token_for_demo",
            batch_size=5
        )
        
        # This will fail but demonstrate retry logic
        cves = collector.collect_cves(
            start_year=2023,
            end_year=2023,
            ecosystems=["npm"],
            cwe_filters=["Injection"],
            max_retries=2  # Fewer retries for demo
        )
        
        print(f"\nCollected {len(cves)} CVEs (expected: 0 due to auth error)")
        
        # Show error statistics
        stats = collector.get_statistics()
        print(f"\nErrors encountered: {len(stats['errors'])}")
        if stats['errors']:
            print("Error messages:")
            for error in stats['errors'][:3]:
                print(f"  - {error}")
    
    except Exception as e:
        print(f"\nExpected error occurred: {e}")


def main():
    """Run all demos."""
    print("\n" + "=" * 60)
    print("CensusCollector Demo Script")
    print("=" * 60)
    
    # Check for GitHub token
    if not Config.GITHUB_TOKEN:
        print("\nError: GITHUB_TOKEN not set in environment")
        print("Please set GITHUB_TOKEN before running demos")
        return
    
    # Run demos
    try:
        demo_basic_collection()
        demo_with_exploit_db()
        demo_multi_ecosystem()
        # demo_error_handling()  # Commented out to avoid API errors
    except KeyboardInterrupt:
        print("\n\nDemo interrupted by user")
    except Exception as e:
        print(f"\n\nDemo error: {e}")
        import traceback
        traceback.print_exc()
    
    print("\n" + "=" * 60)
    print("Demo Complete")
    print("=" * 60)


if __name__ == "__main__":
    main()
