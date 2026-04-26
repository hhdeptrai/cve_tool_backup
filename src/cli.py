#!/usr/bin/env python3
"""Command-line interface for the Web CVE Census System."""

import argparse
import sys
import json
import logging
import os
from typing import Optional
from pathlib import Path
from datetime import datetime
import warnings

# Suppress Vertex AI Deprecation Warnings
warnings.filterwarnings("ignore", category=UserWarning, module="vertexai")
warnings.filterwarnings("ignore", category=UserWarning, module="google.auth")

from src.config import Config
from src.database import DatabaseManager
from src.census_collector import CensusCollector
from src.claim_service import ClaimService
from src.task_manager import TaskManager
from src.verification_service import VerificationService
from src.exclusion_service import ExclusionService
from src.report_generator import ReportGenerator
from .ai_reporter import APIKeyRotator, CVEAnalystAgent, AIReporter
from src.models import BuildStatus, ExploitStatus, ResearchDepth

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class CLI:
    """Command-line interface for the Web CVE Census System."""
    
    def __init__(self):
        """Initialize CLI with database connection and services."""
        self.db_manager = DatabaseManager(Config.DATABASE_URL)
        
        # Initialize services
        self.claim_service = ClaimService(self.db_manager)
        self.task_manager = TaskManager(self.db_manager)
        self.verification_service = VerificationService(self.db_manager)
        self.exclusion_service = ExclusionService(self.db_manager)
        self.report_generator = ReportGenerator(self.db_manager)
    
    def census_collect(self, args):
        """Execute census collection."""
        print(f"\n=== Starting Census Collection ===")
        print(f"Year range: {args.year_start} - {args.year_end}")
        
        # Get ecosystems from Config (loaded from config.yaml, defaults to 9 web systems)
        ecosystems = Config.get_yaml_value("census", "ecosystems", default=Config.CENSUS_ECOSYSTEMS)
        
        # Initialize census collector
        github_token = Config.GITHUB_TOKEN
        exploitdb_csv_path = Config.EXPLOITDB_CSV_PATH
        github_poc_path = Config.GITHUB_POC_REPO_PATH
        
        collector = CensusCollector(
            github_token=github_token,
            exploitdb_csv_path=exploitdb_csv_path,
            github_poc_path=github_poc_path
        )
        
        # Collect CVEs
        cves = collector.collect_cves(
            start_year=args.year_start,
            end_year=args.year_end,
            ecosystems=ecosystems
        )
        
        # Store CVEs in database
        from src.database import CVERepository
        repository = CVERepository(self.db_manager)
        
        print(f"\nStoring {len(cves)} CVEs in database (batch mode)...")
        stored_count = repository.insert_cves_batch(cves)
        
        print(f"Successfully stored {stored_count}/{len(cves)} CVEs")
        print("\n=== Census Collection Complete ===\n")
        
    def census_scan_exploits(self, args):
        """Scan existing CVEs for Exploit-DB matches."""
        print("\n=== Scanning Existing CVEs for Exploits ===")
        
        # Initialize Exploit-DB engine
        exploitdb_path = Config.EXPLOITDB_CSV_PATH
        if not os.path.exists(exploitdb_path):
            print(f"Error: Exploit-DB CSV not found at {exploitdb_path}")
            sys.exit(1)
            
        try:
            from src.exploitdb_parser import CrossReferenceEngine
            engine = CrossReferenceEngine(exploitdb_path)
            print(f"Loaded Exploit-DB from {exploitdb_path}")
        except Exception as e:
            print(f"Error loading Exploit-DB: {e}")
            sys.exit(1)
            
        # Get all CVEs from DB
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT cve_id, exploit_db_id FROM web_cve_census_master")
            cves = cursor.fetchall()
            print(f"Scanning {len(cves)} CVEs...")
            
            matches_found = 0
            new_matches = 0
            
            for cve_id, current_exploit_id in cves:
                # Check for exploit
                exploit = engine.find_exploit(cve_id)
                
                if exploit:
                    matches_found += 1
                    
                    # Update if new match or different ID
                    if exploit.exploit_db_id != current_exploit_id:
                        print(f"  [NEW] {cve_id} matched to Exploit-DB ID: {exploit.exploit_db_id}")
                        cursor.execute("""
                            UPDATE web_cve_census_master 
                            SET exploit_available = TRUE,
                                exploit_db_id = %s,
                                updated_at = NOW()
                            WHERE cve_id = %s
                        """, (exploit.exploit_db_id, cve_id))
                        new_matches += 1
            
            conn.commit()
            print(f"\nScan Complete.")
            print(f"Total Matches Found: {matches_found}")
            print(f"New Updates Applied: {new_matches}")
            
        except Exception as e:
            if conn:
                conn.rollback()
            print(f"Error during scan: {e}")
            sys.exit(1)
            
        finally:
            if conn:
                self.db_manager.return_connection(conn)

    def census_scan_github_pocs(self, args):
        """Scan existing CVEs for GitHub PoC matches."""
        print("\n=== Scanning Existing CVEs for GitHub PoCs ===")
        
        poc_repo_path = Config.GITHUB_POC_REPO_PATH
        if not os.path.exists(poc_repo_path):
            print(f"Error: GitHub PoC repository not found at {poc_repo_path}")
            print("Please clone a PoC repository like 'nomi-sec/PoC-in-GitHub' to the configured path.")
            sys.exit(1)
            
        try:
            from src.github_poc_parser import GitHubPoCEngine
            engine = GitHubPoCEngine(poc_repo_path)
            print(f"Loaded GitHub PoC index from {poc_repo_path}")
        except Exception as e:
            print(f"Error loading GitHub PoC engine: {e}")
            sys.exit(1)
            
        conn = None
        try:
            conn = self.db_manager.get_connection()
            cursor = conn.cursor()
            
            cursor.execute("SELECT cve_id, has_github_poc, exploit_status FROM web_cve_census_master")
            cves = cursor.fetchall()
            print(f"Scanning {len(cves)} CVEs...")
            
            matches_found = 0
            new_matches = 0
            
            for cve_id, current_has_poc, current_exploit_status in cves:
                has_poc = engine.has_poc(cve_id)
                
                if has_poc:
                    matches_found += 1
                    
                    if not current_has_poc or current_exploit_status == 'NONE':
                        # Print the first few new matches so the user can see progress without flooding output
                        if new_matches < 10:
                            print(f"  [UPDATE] {cve_id} exploit_status set to POC_PUBLIC")
                        elif new_matches == 10:
                            print(f"  ... and more")
                            
                        # Set POC_PUBLIC if it's currently NONE
                        if current_exploit_status == 'NONE':
                            cursor.execute("""
                                UPDATE web_cve_census_master 
                                SET has_github_poc = TRUE,
                                    exploit_status = 'POC_PUBLIC',
                                    updated_at = NOW()
                                WHERE cve_id = %s
                            """, (cve_id,))
                        else:
                            # Also update if exploit_status is already set to something else, just update the github flag
                            cursor.execute("""
                                UPDATE web_cve_census_master 
                                SET has_github_poc = TRUE,
                                    updated_at = NOW()
                                WHERE cve_id = %s
                            """, (cve_id,))
                        
                        new_matches += 1
            
            conn.commit()
            print(f"\nScan Complete.")
            print(f"Total Matches Found: {matches_found}")
            print(f"New Updates Applied: {new_matches}")
            
        except Exception as e:
            if conn:
                conn.rollback()
            print(f"Error during scan: {e}")
            sys.exit(1)
            
        finally:
            if conn:
                self.db_manager.return_connection(conn)
    
    def task_claim(self, args):
        """Claim CVE tasks."""
        if args.count:
            # Batch claim
            print(f"\nClaiming {args.count} tasks for {args.researcher} from year {args.year}...")
            results = self.claim_service.claim_batch(
                researcher_id=args.researcher,
                year=args.year,
                count=args.count
            )
            
            # Print results
            successful = sum(1 for r in results if r.success)
            print(f"\nClaimed {successful}/{len(results)} tasks:")
            for result in results:
                status = "✓" if result.success else "✗"
                print(f"  {status} {result.cve_id}: {result.message}" if result.cve_id else f"  {status} {result.message}")
        else:
            # Single claim (requires --cve-id)
            if not args.cve_id:
                print("Error: --cve-id required for single task claim")
                sys.exit(1)
            
            print(f"\nClaiming task {args.cve_id} for {args.researcher}...")
            result = self.claim_service.claim_task(
                cve_id=args.cve_id,
                researcher_id=args.researcher
            )
            
            status = "✓" if result.success else "✗"
            print(f"{status} {result.message}")
    
    def task_list(self, args):
        """List tasks."""
        if args.researcher:
            # List tasks for specific researcher
            print(f"\nTasks assigned to {args.researcher}:")
            tasks = self.task_manager.get_researcher_tasks(
                args.researcher,
                order_by_score=args.sort_by_score,
                hide_excluded=not args.show_excluded,
                hide_completed=not args.show_completed,
                year=args.year
            )
        else:
            # List available tasks
            print("\nAvailable tasks:")
            filters = {}
            if args.year:
                filters['year'] = args.year
            if args.ecosystem:
                filters['ecosystem'] = args.ecosystem
            
            tasks = self.task_manager.get_available_tasks(
                filters=filters,
                limit=args.limit or 10,
                order_by_score=args.sort_by_score
            )
        
        if not tasks:
            print("  No tasks found")
            return
        
        # Apply limit if specified (for researcher tasks)
        if args.limit and args.researcher:
            tasks = tasks[:args.limit]
        
        # Print tasks
        for task in tasks:
            print(f"\n  CVE: {task.cve_id}")
            print(f"  CVSS Score: {task.cvss_base_score if task.cvss_base_score is not None else 'N/A'}")
            cve_year = task.cve_id.split('-')[1] if task.cve_id and len(task.cve_id.split('-')) >= 2 else str(task.publication_year)
            print(f"  Ecosystem: {task.ecosystem} | Year: {cve_year}")
            print(f"  Exploit Available: {'Yes' if task.exploit_available else 'No'}")
            if task.exploit_db_id:
                print(f"  Exploit-DB ID: {task.exploit_db_id}")
            print(f"  Build Status: {task.build_status}")
            print(f"  Exploit Status: {task.exploit_status}")
            if task.assigned_to:
                print(f"  Assigned to: {task.assigned_to}")
                if task.claim_expires_at:
                    print(f"  Claim expires: {task.claim_expires_at}")
            print(f"  Description: {task.description[:100]}...")
            print(f"  Resources:")
            print(f"    - NVD: https://nvd.nist.gov/vuln/detail/{task.cve_id}")
            print(f"    - GitHub: https://github.com/advisories?query={task.cve_id}")
            if task.exploit_db_id:
                print(f"    - Exploit-DB: https://www.exploit-db.com/exploits/{task.exploit_db_id}")

    def task_history(self, args):
        """List completed tasks history."""
        if not args.researcher:
            print("Error: --researcher required")
            sys.exit(1)
            
        print(f"\nTask History for {args.researcher}:")
        
        # Get tasks with completed tasks visible
        all_tasks = self.task_manager.get_researcher_tasks(
            args.researcher,
            hide_excluded=True, 
            hide_completed=False 
        )
        
        # Filter for completed only
        completed_tasks = [
            t for t in all_tasks 
            if t.exploit_status in ('VERIFIED_SUCCESS', 'UNEXPLOITABLE')
        ]
        
        if not completed_tasks:
            print("  No completed tasks found")
            return
            
        for task in completed_tasks:
            print(f"\n  CVE: {task.cve_id}")
            print(f"  Status: {task.exploit_status}")
            print(f"  Assigned: {task.assigned_at}")
            print(f"  Notes: {task.exploit_notes}")

    def task_stats(self, args):
        """Show task statistics."""
        if args.researcher:
            print(f"\nStatistics for {args.researcher}:")
            stats = self.task_manager.get_researcher_stats(args.researcher)
            print(f"  Active Tasks:    {stats['active']}")
            print(f"  Completed Tasks: {stats['completed']}")
            print(f"  Excluded Tasks:  {stats['excluded']}")
        else:
            print("\nSystem Statistics:")
            stats = self.task_manager.get_system_stats()
            print(f"  Available Tasks: {stats['available']}")
    
    def task_update(self, args):
        """Update task status."""
        if not args.cve_id:
            print("Error: --cve-id required")
            sys.exit(1)
        
        if not args.researcher:
            print("Error: --researcher required")
            sys.exit(1)
        
        # Update build status
        if args.build_status:
            try:
                status = BuildStatus[args.build_status.upper()]
                success = self.verification_service.update_build_status(
                    cve_id=args.cve_id,
                    researcher_id=args.researcher,
                    status=status,
                    notes=args.notes
                )
                
                if success:
                    print(f"✓ Build status updated to {args.build_status}")
                else:
                    print(f"✗ Failed to update build status")
                    sys.exit(1)
            except KeyError:
                print(f"Error: Invalid build status '{args.build_status}'")
                print(f"Valid values: {', '.join([s.name for s in BuildStatus])}")
                sys.exit(1)
        
        # Update exploit status
        if args.exploit_status:
            if not args.notes:
                print("Error: --notes required when updating exploit status")
                sys.exit(1)
            
            try:
                status = ExploitStatus[args.exploit_status.upper()]
                success = self.verification_service.update_exploit_status(
                    cve_id=args.cve_id,
                    researcher_id=args.researcher,
                    status=status,
                    notes=args.notes
                )
                
                if success:
                    print(f"✓ Exploit status updated to {args.exploit_status}")
                else:
                    print(f"✗ Failed to update exploit status")
                    sys.exit(1)
            except KeyError:
                print(f"Error: Invalid exploit status '{args.exploit_status}'")
                print(f"Valid values: {', '.join([s.name for s in ExploitStatus])}")
                sys.exit(1)
        
        # Update research depth
        if args.research_depth:
            try:
                depth = ResearchDepth[args.research_depth.upper()]
                success = self.verification_service.update_research_depth(
                    cve_id=args.cve_id,
                    researcher_id=args.researcher,
                    depth=depth
                )
                
                if success:
                    print(f"✓ Research depth updated to {args.research_depth}")
                else:
                    print(f"✗ Failed to update research depth")
                    sys.exit(1)
            except KeyError:
                print(f"Error: Invalid research depth '{args.research_depth}'")
                print(f"Valid values: {', '.join([d.name for d in ResearchDepth])}")
                sys.exit(1)
    
    def task_exclude(self, args):
        """Exclude a CVE from the dataset."""
        if not args.cve_id:
            print("Error: --cve-id required")
            sys.exit(1)
        
        if not args.researcher:
            print("Error: --researcher required")
            sys.exit(1)
        
        if not args.reason:
            print("Error: --reason required")
            sys.exit(1)
        
        print(f"\nExcluding CVE {args.cve_id}...")
        success = self.exclusion_service.exclude_cve(
            cve_id=args.cve_id,
            researcher_id=args.researcher,
            reason=args.reason
        )
        
        if success:
            print(f"✓ CVE {args.cve_id} excluded successfully")
            print(f"  Reason: {args.reason}")
        else:
            print(f"✗ Failed to exclude CVE {args.cve_id}")
            sys.exit(1)
    
    def task_restore(self, args):
        """Restore a previously excluded CVE."""
        if not args.cve_id:
            print("Error: --cve-id required")
            sys.exit(1)
        
        if not args.researcher:
            print("Error: --researcher required")
            sys.exit(1)
        
        print(f"\nRestoring CVE {args.cve_id}...")
        success = self.exclusion_service.restore_cve(
            cve_id=args.cve_id,
            researcher_id=args.researcher
        )
        
        if success:
            print(f"✓ CVE {args.cve_id} restored successfully")
        else:
            print(f"✗ Failed to restore CVE {args.cve_id}")
            sys.exit(1)
    
    def task_list_excluded(self, args):
        """List excluded CVEs."""
        print("\nExcluded CVEs:")
        
        filters = {}
        if args.year:
            filters['year'] = args.year
        if args.ecosystem:
            filters['ecosystem'] = args.ecosystem
        if args.researcher:
            filters['excluded_by'] = args.researcher
        
        excluded_cves = self.exclusion_service.list_excluded_cves(filters=filters)
        
        if not excluded_cves:
            print("  No excluded CVEs found")
            return
        
        for cve in excluded_cves:
            print(f"\n  CVE: {cve.cve_id}")
            print(f"  Ecosystem: {cve.ecosystem} | Year: {cve.publication_year}")
            print(f"  Excluded by: {cve.excluded_by}")
            print(f"  Excluded at: {cve.excluded_at}")
            print(f"  Reason: {cve.exclusion_reason}")
            print(f"  Description: {cve.description[:100]}...")
    
    def report_generate(self, args):
        """Generate census report."""
        print(f"\nGenerating census report in {args.mode} mode...")
        
        filters = {}
        if args.year:
            filters['year'] = args.year
        if args.ecosystem:
            filters['ecosystem'] = args.ecosystem
        
        report = self.report_generator.generate_census_report(
            filters=filters,
            mode=args.mode
        )
        
        # Prepare report data
        report_data = {
            'generated_at': report.generated_at.isoformat(),
            'report_mode': report.report_mode,
            'filters_applied': report.filters_applied,
            'summary': {
                'total_cves': report.total_cves,
                'priority_cves': report.priority_cves,
                'excluded_cves': report.excluded_cves,
                'exploit_available_count': report.exploit_available_count,
                'exploit_availability_percentage': round(report.exploit_availability_percentage, 2),
                'verification_completion_count': report.verification_completion_count,
                'verification_completion_percentage': round(report.verification_completion_percentage, 2)
            },
            'breakdown': {
                'by_year': report.cves_by_year,
                'by_ecosystem': report.cves_by_ecosystem,
                'by_cwe': report.cves_by_cwe,
                'build_status': report.build_status_distribution,
                'exploit_status': report.exploit_status_distribution,
                'research_depth': report.research_depth_distribution
            }
        }
        
        # Save to file
        output_path = Path(args.output)
        if not output_path.is_absolute():
            output_path = Path(Config.REPORT_OUTPUT_DIR) / output_path
            
        output_path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        print(f"✓ Report saved to {output_path}")
        
        # Print summary
        print(f"\n=== Census Report Summary ===")
        print(f"Report Mode: {report.report_mode}")
        print(f"Total CVEs: {report.total_cves}")
        print(f"Priority CVEs: {report.priority_cves}")
        print(f"Excluded CVEs: {report.excluded_cves}")
        print(f"Exploit Availability: {report.exploit_availability_percentage:.1f}%")
        print(f"Verification Completion: {report.verification_completion_percentage:.1f}%")
        print(f"\nDetailed report saved to: {args.output}")


def main():
    """Main entry point for CLI."""
    parser = argparse.ArgumentParser(
        description='Web CVE Census System - Command Line Interface',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Census collect command
    census_parser = subparsers.add_parser('census', help='Census collection operations')
    census_subparsers = census_parser.add_subparsers(dest='census_command')
    
    collect_parser = census_subparsers.add_parser('collect', help='Collect CVE data')
    collect_parser.add_argument('--year-start', type=int, required=True, help='Start year (2015-2025)')
    collect_parser.add_argument('--year-end', type=int, required=True, help='End year (2015-2025)')

    # Census scan-exploits
    scan_parser = census_subparsers.add_parser('scan-exploits', help='Scan existing CVEs for Exploit-DB matches')
    
    # Census scan-github-pocs
    poc_parser = census_subparsers.add_parser('scan-github-pocs', help='Scan existing CVEs for GitHub PoC repositories')
    
    # Task commands
    task_parser = subparsers.add_parser('task', help='Task management operations')
    task_subparsers = task_parser.add_subparsers(dest='task_command')
    
    # Task claim
    claim_parser = task_subparsers.add_parser('claim', help='Claim CVE tasks')
    claim_parser.add_argument('--researcher', required=True, help='Researcher name (Minh or Hoàng)')
    claim_parser.add_argument('--year', type=int, help='Publication year for batch claim')
    claim_parser.add_argument('--count', type=int, help='Number of tasks to claim (default: 10)')
    claim_parser.add_argument('--cve-id', help='Specific CVE ID to claim')
    
    # Task list
    list_parser = task_subparsers.add_parser('list', help='List tasks')
    list_parser.add_argument('--researcher', help='Filter by researcher')
    list_parser.add_argument('--year', type=int, help='Filter by year')
    list_parser.add_argument('--ecosystem', help='Filter by ecosystem')
    list_parser.add_argument('--limit', type=int, help='Maximum number of tasks to show')
    list_parser.add_argument('--sort-by-score', action='store_true', help='Sort by CVSS score (descending)')
    list_parser.add_argument('--show-excluded', action='store_true', help='Show excluded tasks')
    list_parser.add_argument('--show-completed', action='store_true', help='Show completed tasks')
    
    # Task history
    history_parser = task_subparsers.add_parser('history', help='List completed tasks history')
    history_parser.add_argument('--researcher', required=True, help='Researcher name')
    
    # Task stats
    stats_parser = task_subparsers.add_parser('stats', help='Show task statistics')
    stats_parser.add_argument('--researcher', help='Researcher name (optional, shows system stats if omitted)')
    
    # Task update
    update_parser = task_subparsers.add_parser('update', help='Update task status')
    update_parser.add_argument('--cve-id', required=True, help='CVE ID')
    update_parser.add_argument('--researcher', required=True, help='Researcher name')
    update_parser.add_argument('--build-status', help='Build status (NOT_ATTEMPTED, IN_PROGRESS, SUCCESS, FAILED)')
    update_parser.add_argument('--exploit-status', help='Exploit status (NONE, POC_PUBLIC, EXPLOIT_DB, VERIFIED_SUCCESS, UNEXPLOITABLE)')
    update_parser.add_argument('--research-depth', help='Research depth (LEVEL_0, LEVEL_1, LEVEL_2)')
    update_parser.add_argument('--notes', help='Notes about the update')
    
    # Task exclude
    exclude_parser = task_subparsers.add_parser('exclude', help='Exclude a CVE from the dataset')
    exclude_parser.add_argument('--cve-id', required=True, help='CVE ID')
    exclude_parser.add_argument('--researcher', required=True, help='Researcher name')
    exclude_parser.add_argument('--reason', required=True, help='Reason for exclusion')
    
    # Task restore
    restore_parser = task_subparsers.add_parser('restore', help='Restore a previously excluded CVE')
    restore_parser.add_argument('--cve-id', required=True, help='CVE ID')
    restore_parser.add_argument('--researcher', required=True, help='Researcher name')
    
    # Task list-excluded
    list_excluded_parser = task_subparsers.add_parser('list-excluded', help='List excluded CVEs')
    list_excluded_parser.add_argument('--year', type=int, help='Filter by year')
    list_excluded_parser.add_argument('--ecosystem', help='Filter by ecosystem')
    list_excluded_parser.add_argument('--researcher', help='Filter by researcher who excluded')
    
    # Report commands
    report_parser = subparsers.add_parser('report', help='Report generation operations')
    report_subparsers = report_parser.add_subparsers(dest='report_command')
    
    generate_parser = report_subparsers.add_parser('generate', help='Generate census report')
    generate_parser.add_argument('--output', required=True, help='Output file path (JSON)')
    generate_parser.add_argument('--mode', choices=['priority', 'full'], default='priority', 
                                 help='Report mode: priority (excludes excluded CVEs) or full (includes all)')
    generate_parser.add_argument('--year', type=int, help='Filter by year')
    generate_parser.add_argument('--ecosystem', help='Filter by ecosystem')
    
    # --- AI Report Subparser ---
    ai_parser = subparsers.add_parser(
        "ai-report",
        help="Run the Distributed AI Reporter to automatically generate Markdown reports."
    )
    
    # --- AI Agent Subparser ---
    agent_parser = subparsers.add_parser(
        "ai-agent",
        help="Run the Agentic Workflow to build Docker, execute Exploits, and Self-Heal."
    )
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Initialize CLI
    try:
        cli = CLI()
    except Exception as e:
        print(f"Error initializing CLI: {e}")
        sys.exit(1)
    
    # Execute command
    try:
        if args.command == 'census':
            if args.census_command == 'collect':
                cli.census_collect(args)
            elif args.census_command == 'scan-exploits':
                cli.census_scan_exploits(args)
            elif args.census_command == 'scan-github-pocs':
                cli.census_scan_github_pocs(args)
            else:
                census_parser.print_help()
        
        elif args.command == 'task':
            if args.task_command == 'claim':
                cli.task_claim(args)
            elif args.task_command == 'list':
                cli.task_list(args)
            elif args.task_command == 'history':
                cli.task_history(args)
            elif args.task_command == 'stats':
                cli.task_stats(args)
            elif args.task_command == 'update':
                cli.task_update(args)
            elif args.task_command == 'exclude':
                cli.task_exclude(args)
            elif args.task_command == 'restore':
                cli.task_restore(args)
            elif args.task_command == 'list-excluded':
                cli.task_list_excluded(args)
            else:
                task_parser.print_help()
        
        elif args.command == 'report':
            if args.report_command == 'generate':
                cli.report_generate(args)
            else:
                report_parser.print_help()
        
        elif args.command == 'ai-report':
            import os
            from dotenv import load_dotenv
            load_dotenv()
            
            api_keys = os.getenv("GEMINI_API_KEYS")
            proxies = os.getenv("GEMINI_PROXIES", "")
            if not api_keys:
                print("Error: No API keys found. Please set GEMINI_API_KEYS in your .env file (e.g., GEMINI_API_KEYS=key1,key2)")
                sys.exit(1)
                
            try:
                from .database import CVERepository
                
                rotator = APIKeyRotator(api_keys, proxies)
                prompt_path = os.path.join("reports", "templates", "cve_report_prompt.txt")
                agent = CVEAnalystAgent(rotator, prompt_path)
                
                repo = CVERepository(cli.db_manager)
                output_dir = os.path.join("docs", "cves_findings")
                
                reporter = AIReporter(cli.db_manager, repo, agent, output_dir)
                reporter.run_worker_loop()
                
            except Exception as e:
                print(f"Failed to start AI Reporter: {e}")
                sys.exit(1)
                
        elif args.command == 'ai-agent':
            import os
            from dotenv import load_dotenv
            load_dotenv()
            
            api_keys = os.getenv("GEMINI_API_KEYS")
            proxies = os.getenv("GEMINI_PROXIES", "")
            if not api_keys:
                print("Error: No API keys found in .env")
                sys.exit(1)
                
            try:
                from .ai_reporter import APIKeyRotator
                from .agent_verifier import AgentVerifier
                
                rotator = APIKeyRotator(api_keys, proxies)
                output_dir = os.path.join("docs", "cves_findings")
                
                agent = AgentVerifier(cli.db_manager, rotator, output_dir)
                agent.run_worker_loop()
            except Exception as e:
                print(f"Failed to start AI Agent: {e}")
                sys.exit(1)
        
        else:
            parser.print_help()
    
    except KeyboardInterrupt:
        print("\n\nOperation cancelled by user")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Command failed: {e}", exc_info=True)
        print(f"\nError: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()
