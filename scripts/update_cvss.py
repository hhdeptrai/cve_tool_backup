import sys
import os
import argparse

# Add src to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from src.database import DatabaseManager
from src.github_advisory_client import GitHubAdvisoryClient

def main():
    parser = argparse.ArgumentParser(description="Update CVSS score for a specific CVE from GitHub Advisory")
    parser.add_argument("cve_id", help="CVE ID to update (e.g., CVE-2025-0868)")
    args = parser.parse_args()
    
    cve_id = args.cve_id
    
    print(f"Updating CVSS score for {cve_id}...")
    
    # 1. Fetch from GitHub Advisory
    client = GitHubAdvisoryClient()
    
    # Use a specific query for single CVE
    query = f"""
    query {{
      securityAdvisories(first: 1, identifier: {{type: CVE, value: "{cve_id}"}}) {{
        nodes {{
          ghsaId
          cvssSeverities {{
             cvssV3 {{ score }}
             cvssV4 {{ score }}
          }}
          cvss {{ score }}
        }}
      }}
    }}
    """
    
    try:
        data = client._execute_query(query)
        nodes = data.get("securityAdvisories", {}).get("nodes", [])
        
        if not nodes:
            print(f"Error: {cve_id} not found in GitHub Advisory Database.")
            return
            
        advisory = nodes[0]
        
        # Extract score using our new logic
        cvss_severities = advisory.get("cvssSeverities", {})
        cvss_v4 = cvss_severities.get("cvssV4") or {}
        cvss_v3 = cvss_severities.get("cvssV3") or {}
        
        old_legacy_score = (advisory.get("cvss") or {}).get("score") or 0.0
        new_score = cvss_v4.get("score") or cvss_v3.get("score") or 0.0
        
        print(f"Found on GitHub:")
        print(f"  - Legacy CVSS v3 (old logic): {old_legacy_score}")
        print(f"  - CVSS v4: {cvss_v4.get('score', 'N/A')}")
        print(f"  - CVSS v3: {cvss_v3.get('score', 'N/A')}")
        print(f"  -> New calculated score: {new_score}")
        
        # 2. Update Database
        db = DatabaseManager()
        with db.get_connection() as conn:
            cursor = conn.cursor()
            
            # Check current score in DB
            cursor.execute("SELECT cvss_base_score FROM web_cve_census_master WHERE cve_id = %s", (cve_id,))
            result = cursor.fetchone()
            
            if not result:
                print(f"Error: {cve_id} not found in local database.")
                return
                
            current_db_score = float(result[0])
            print(f"Current score in local DB: {current_db_score}")
            
            if current_db_score == new_score:
                print("Score is already up to date in DB. No changes made.")
            else:
                # Update DB
                cursor.execute(
                    "UPDATE web_cve_census_master SET cvss_base_score = %s WHERE cve_id = %s",
                    (new_score, cve_id)
                )
                conn.commit()
                print(f"✅ Successfully updated {cve_id} in database: {current_db_score} -> {new_score}")
                
    except Exception as e:
        print(f"Error updating {cve_id}: {e}")

if __name__ == "__main__":
    main()
