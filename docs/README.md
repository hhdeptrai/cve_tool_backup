# Documentation Index

Welcome to the Web CVE Census System documentation!

## Quick Links

- **New to the project?** Start with [Quick Start Guide](setup/QUICKSTART.md)
- **Setting up database?** See [Database Setup Guide](setup/DATABASE_SETUP.md)
- **Using the CLI?** Check [CLI Usage Guide](guides/CLI_USAGE.md)
- **Need configuration help?** See [Configuration Guide](reference/CONFIGURATION.md)

## Documentation Structure

### 📦 Setup Guides (`setup/`)
Getting started and initial configuration

- [Quick Start Guide](setup/QUICKSTART.md) - Get up and running in 5 minutes
- [Database Setup Guide](setup/DATABASE_SETUP.md) - Detailed Neon PostgreSQL setup
- [Project Structure](setup/PROJECT_STRUCTURE.md) - Understanding the codebase

### 📚 User Guides (`guides/`)
How to use the system

- [Usage Guide](guides/USAGE.md) - Comprehensive usage examples and workflows
- [CLI Usage](guides/CLI_USAGE.md) - Command-line interface reference
- [Makefile Guide](guides/MAKEFILE_GUIDE.md) - Using the Makefile for automation

### 📖 Reference Documentation (`reference/`)
Technical specifications and API documentation

- [Configuration Reference](reference/CONFIGURATION.md) - All configuration options
- [Database Schema](reference/DATABASE_SCHEMA.md) - Database structure and models
- [API Rate Limits](reference/API_RATE_LIMITS.md) - GitHub and Exploit-DB rate limits

### 🏗️ Architecture (`architecture/`)
System design and architecture decisions

- [Exclusion and Priority Labeling](architecture/EXCLUSION_AND_PRIORITY_LABELING.md) - New v2.0 architecture
- [Census Orchestration](architecture/census_orchestration.md) - Collection workflow
- [Compatibility Analysis](architecture/compatibility_analysis.md) - Technical compatibility

### 📊 Status & Reports (`status/`)
Project status and completion reports

- [Setup Complete](status/NEON_SETUP_COMPLETE.md) - Database setup status
- [Organization Complete](status/ORGANIZATION_COMPLETE.md) - Project organization status
- [Verification Report](status/VERIFICATION_REPORT.md) - System verification results
- [Refactoring Status](status/REFACTORING_STATUS.md) - Architecture refactoring progress
- [Optimization Summary](status/OPTIMIZATION_SUMMARY.txt) - Property test optimization

### 📝 Task Summaries (`tasks/`)
Implementation task summaries

- [Task 4.1 Summary](tasks/task_4.1_summary.md) - ExploitDB parser implementation
- [Task 5.1 Summary](tasks/task_5.1_summary.md) - GitHub Advisory client implementation
- [Task 5.2 Summary](tasks/task_5.2_summary.md) - Census collector implementation
- [Task 7.2 Summary](tasks/task_7.2_summary.md) - Report generator implementation

## Documentation by Topic

### Getting Started
1. [Quick Start Guide](setup/QUICKSTART.md) - 5-minute setup
2. [Database Setup](setup/DATABASE_SETUP.md) - Detailed database configuration
3. [Usage Guide](guides/USAGE.md) - Basic usage and workflows

### Configuration
1. [Configuration Reference](reference/CONFIGURATION.md) - All configuration options
2. [Environment Variables](setup/QUICKSTART.md#environment-variables-reference) - Required and optional variables

### Using the System
1. [CLI Usage](guides/CLI_USAGE.md) - Command-line interface
2. [Usage Guide](guides/USAGE.md) - Workflows and examples
3. [Makefile Guide](guides/MAKEFILE_GUIDE.md) - Automation commands

### Technical Reference
1. [Database Schema](reference/DATABASE_SCHEMA.md) - Database structure
2. [API Rate Limits](reference/API_RATE_LIMITS.md) - API usage and limits
3. [Project Structure](setup/PROJECT_STRUCTURE.md) - Codebase organization

### Architecture & Design
1. [Exclusion and Priority Labeling](architecture/EXCLUSION_AND_PRIORITY_LABELING.md) - v2.0 architecture
2. [Census Orchestration](architecture/census_orchestration.md) - Collection workflow
3. [Compatibility Analysis](architecture/compatibility_analysis.md) - Technical decisions

## Quick Reference

### Common Tasks

**Setup**
```bash
# Initial setup
cp .env.example .env
python scripts/setup_database.py
python scripts/verify_setup.py
```

**Testing**
```bash
# Run tests
pytest
pytest --cov=src --cov-report=html
```

**Using the CLI**
```bash
# Collect CVEs
python census census collect --year-start 2020 --year-end 2021

# Claim tasks
python census task claim --researcher Minh --year 2021 --count 10

# Generate report
python census report generate --output report.json --mode priority
```

### Key Concepts

- **Priority CWE Labeling**: Automatic labeling of high-value CVEs based on CWE categories
- **CVE Exclusion**: Manual curation to exclude non-web CVEs from the dataset
- **Dual Report Modes**: Priority mode (curated) vs Full mode (all CVEs)
- **Task Management**: Claim, update, and track CVE verification tasks

### Important Files

- `.env` - Your configuration (DATABASE_URL, tokens, etc.)
- `config.yaml` - Advanced YAML configuration
- `requirements.txt` - Python dependencies
- `Makefile` - Automation commands

## Contributing

This project follows a specification-driven development approach. All features are documented in the `.kiro/specs/` directory with requirements, design, and tasks.

## Support

For issues or questions:
1. Check the relevant documentation section above
2. Review the [Quick Start Guide](setup/QUICKSTART.md)
3. Check the main [README.md](../README.md)
4. Consult the spec documents in `.kiro/specs/web-cve-census-system/`

## Documentation Maintenance

This documentation is organized for easy navigation and maintenance:

- **Setup guides** help new users get started
- **User guides** explain how to use the system
- **Reference docs** provide technical specifications
- **Architecture docs** explain design decisions
- **Status docs** track project progress

When adding new documentation:
1. Choose the appropriate folder based on content type
2. Update this index with a link to the new document
3. Follow the existing documentation style and format
4. Include code examples and practical usage where applicable
