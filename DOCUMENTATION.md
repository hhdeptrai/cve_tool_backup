# Documentation Guide

All project documentation has been organized into the `docs/` folder for better navigation and maintenance.

## 📚 Quick Access

### For New Users
- **[Quick Start](docs/setup/QUICKSTART.md)** - Get up and running in 5 minutes
- **[Usage Guide](docs/guides/USAGE.md)** - Learn how to use the system
- **[CLI Reference](docs/guides/CLI_USAGE.md)** - Command-line interface guide

### For Developers
- **[Project Structure](docs/setup/PROJECT_STRUCTURE.md)** - Understand the codebase
- **[Makefile Guide](docs/guides/MAKEFILE_GUIDE.md)** - Automation commands
- **[Database Schema](docs/reference/DATABASE_SCHEMA.md)** - Database structure

### For Configuration
- **[Configuration Guide](docs/reference/CONFIGURATION.md)** - All configuration options
- **[Database Setup](docs/setup/DATABASE_SETUP.md)** - Neon PostgreSQL setup
- **[API Rate Limits](docs/reference/API_RATE_LIMITS.md)** - GitHub and Exploit-DB limits

## 📂 Documentation Structure

```
docs/
├── README.md                          # Documentation index
│
├── setup/                             # Setup and installation guides
│   ├── QUICKSTART.md                  # 5-minute quick start
│   ├── DATABASE_SETUP.md              # Detailed database setup
│   └── PROJECT_STRUCTURE.md           # Codebase organization
│
├── guides/                            # User guides and tutorials
│   ├── USAGE.md                       # Comprehensive usage guide
│   ├── CLI_USAGE.md                   # CLI command reference
│   └── MAKEFILE_GUIDE.md              # Makefile automation guide
│
├── reference/                         # Technical reference documentation
│   ├── CONFIGURATION.md               # Configuration options
│   ├── DATABASE_SCHEMA.md             # Database structure
│   └── API_RATE_LIMITS.md             # API usage and limits
│
├── architecture/                      # Architecture and design docs
│   ├── EXCLUSION_AND_PRIORITY_LABELING.md  # v2.0 architecture
│   ├── census_orchestration.md        # Collection workflow
│   └── compatibility_analysis.md      # Technical compatibility
│
├── status/                            # Project status and reports
│   ├── NEON_SETUP_COMPLETE.md         # Database setup status
│   ├── ORGANIZATION_COMPLETE.md       # Project organization status
│   ├── VERIFICATION_REPORT.md         # System verification results
│   ├── REFACTORING_STATUS.md          # Architecture refactoring progress
│   ├── PROPERTY_TEST_OPTIMIZATION.md  # Test optimization details
│   └── OPTIMIZATION_SUMMARY.txt       # Quick optimization summary
│
└── tasks/                             # Implementation task summaries
    ├── task_4.1_summary.md            # ExploitDB parser
    ├── task_5.1_summary.md            # GitHub Advisory client
    ├── task_5.2_summary.md            # Census collector
    └── task_7.2_summary.md            # Report generator
```

## 🚀 Common Tasks

### Getting Started
```bash
# 1. Read the quick start guide
cat docs/setup/QUICKSTART.md

# 2. Set up your environment
cp .env.example .env
# Edit .env with your DATABASE_URL

# 3. Set up the database
python scripts/setup_database.py

# 4. Verify everything works
python scripts/verify_setup.py
```

### Using the System
```bash
# Collect CVEs
python census census collect --year-start 2020 --year-end 2021

# Claim tasks
python census task claim --researcher Minh --year 2021 --count 10

# Generate reports
python census report generate --output report.json --mode priority
```

### Development
```bash
# Format code
make format

# Run tests
make test

# Run quality checks
make quality

# Verify system
make verify
```

## 📖 Documentation by Topic

### Setup & Installation
1. [Quick Start Guide](docs/setup/QUICKSTART.md) - 5-minute setup
2. [Database Setup](docs/setup/DATABASE_SETUP.md) - Detailed Neon PostgreSQL setup
3. [Project Structure](docs/setup/PROJECT_STRUCTURE.md) - Understanding the codebase

### Usage & Workflows
1. [Usage Guide](docs/guides/USAGE.md) - Comprehensive usage examples
2. [CLI Usage](docs/guides/CLI_USAGE.md) - Command-line interface reference
3. [Makefile Guide](docs/guides/MAKEFILE_GUIDE.md) - Automation with Makefile

### Configuration & Reference
1. [Configuration Guide](docs/reference/CONFIGURATION.md) - All configuration options
2. [Database Schema](docs/reference/DATABASE_SCHEMA.md) - Database structure and models
3. [API Rate Limits](docs/reference/API_RATE_LIMITS.md) - GitHub and Exploit-DB rate limits

### Architecture & Design
1. [Exclusion and Priority Labeling](docs/architecture/EXCLUSION_AND_PRIORITY_LABELING.md) - v2.0 architecture
2. [Census Orchestration](docs/architecture/census_orchestration.md) - Collection workflow
3. [Compatibility Analysis](docs/architecture/compatibility_analysis.md) - Technical decisions

### Project Status
1. [Setup Complete](docs/status/NEON_SETUP_COMPLETE.md) - Database setup status
2. [Organization Complete](docs/status/ORGANIZATION_COMPLETE.md) - Project organization
3. [Verification Report](docs/status/VERIFICATION_REPORT.md) - System verification
4. [Refactoring Status](docs/status/REFACTORING_STATUS.md) - Architecture refactoring

## 🔍 Finding Documentation

### By Role

**New User**
- Start: [Quick Start Guide](docs/setup/QUICKSTART.md)
- Then: [Usage Guide](docs/guides/USAGE.md)
- Reference: [CLI Usage](docs/guides/CLI_USAGE.md)

**Developer**
- Start: [Project Structure](docs/setup/PROJECT_STRUCTURE.md)
- Then: [Makefile Guide](docs/guides/MAKEFILE_GUIDE.md)
- Reference: [Database Schema](docs/reference/DATABASE_SCHEMA.md)

**System Administrator**
- Start: [Database Setup](docs/setup/DATABASE_SETUP.md)
- Then: [Configuration Guide](docs/reference/CONFIGURATION.md)
- Reference: [API Rate Limits](docs/reference/API_RATE_LIMITS.md)

### By Task

**Setting up the system**
→ [Quick Start Guide](docs/setup/QUICKSTART.md)

**Configuring the system**
→ [Configuration Guide](docs/reference/CONFIGURATION.md)

**Using the CLI**
→ [CLI Usage](docs/guides/CLI_USAGE.md)

**Understanding the database**
→ [Database Schema](docs/reference/DATABASE_SCHEMA.md)

**Understanding the architecture**
→ [Exclusion and Priority Labeling](docs/architecture/EXCLUSION_AND_PRIORITY_LABELING.md)

**Checking project status**
→ [Status Documents](docs/status/)

## 💡 Tips

1. **Start with the Quick Start** - Get the system running first, then explore
2. **Use the Documentation Index** - See [docs/README.md](docs/README.md) for a complete index
3. **Check Status Documents** - See what's been completed and what's in progress
4. **Follow the Guides** - Step-by-step instructions for common tasks
5. **Reference Documentation** - Technical details when you need them

## 🆘 Getting Help

1. Check the relevant documentation section
2. Review the [Quick Start Guide](docs/setup/QUICKSTART.md)
3. Check the main [README.md](README.md)
4. Consult the spec documents in `.kiro/specs/web-cve-census-system/`

## 📝 Contributing to Documentation

When adding new documentation:

1. Choose the appropriate folder:
   - `setup/` - Installation and setup guides
   - `guides/` - User guides and tutorials
   - `reference/` - Technical reference documentation
   - `architecture/` - Architecture and design docs
   - `status/` - Project status and reports
   - `tasks/` - Implementation task summaries

2. Update the documentation index in [docs/README.md](docs/README.md)

3. Follow the existing documentation style:
   - Use clear headings and structure
   - Include code examples
   - Provide practical usage examples
   - Add troubleshooting sections where appropriate

4. Link related documents for easy navigation

---

**Full Documentation Index**: See [docs/README.md](docs/README.md)
