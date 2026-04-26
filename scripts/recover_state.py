#!/usr/bin/env python3
"""
Recover state script.
Fast-forwards through GitHub stream to find a specific CVE and save the cursor.
"""

import sys
import os
import json
import time
import argparse
from typing import List

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.github_advisory_client import GitHubAdvisoryClient
from src.models import Ecosystem

def fast_forward(target_cve: str, year: int, ecosystems: List[str]):
    print(f"Searching for {target_cve} in year {year}...")
    print(f"Ecosystems: {ecosystems}")
    
    client = GitHubAdvisoryClient()
    
    # Generate the key used by census_collector to save state
    # Format: "{start}-{end}-{sorted_ecosystems}"
    state_key = f"{year}-{year}-{'-'.join(sorted(ecosystems))}"
    state_file = "census_state.json"
    
    generator = client.collect_cves(
        start_year=year,
        end_year=year,
        ecosystems=ecosystems
    )
    
    found = False
    total_scanned = 0
    
    for batch, cursor in generator:
        total_scanned += len(batch)
        print(f"Scanning... ({total_scanned} processed) - Current Batch: {len(batch)} items")
        
        # Check if target is in this batch
        for cve in batch:
            if cve.cve_id == target_cve:
                print(f"\nFOUND {target_cve}!")
                print(f"Saving cursor: {cursor[:20]}...")
                
                # Save state
                with open(state_file, 'w') as f:
                    json.dump({
                        'key': state_key,
                        'cursor': cursor,
                        'updated_at': str(time.time())
                    }, f)
                
                print(f"State saved to {state_file}")
                print("You can now run 'census collect' and it will resume from here.")
                found = True
                break
        
        if found:
            break
            
    if not found:
        print(f"\nCould not find {target_cve} in the stream.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recover census state")
    parser.add_argument("--target", required=True, help="Last CVE ID you saw (e.g., CVE-2025-46730)")
    parser.add_argument("--year", type=int, default=2025, help="Collection year")
    
    args = parser.parse_args()
    
    # Default ecosystems matching the main CLI defaults
    ecosystems = [e.value for e in Ecosystem]
    
    fast_forward(args.target, args.year, ecosystems)
