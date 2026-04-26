# Makefile for Web CVE Census System
# Python-based CVE data collection and verification system

.PHONY: help install setup test lint format clean verify run-census dev docs

# Default target
.DEFAULT_GOAL := help

# Variables
PYTHON := python3
PIP := $(PYTHON) -m pip
PYTEST := $(PYTHON) -m pytest
BLACK := $(PYTHON) -m black
FLAKE8 := $(PYTHON) -m flake8
MYPY := $(PYTHON) -m mypy

# Directories
SRC_DIR := src
TEST_DIR := tests
SCRIPTS_DIR := scripts
DOCS_DIR := docs
DATA_DIR := data
LOGS_DIR := logs
REPORTS_DIR := reports

# Colors for output
BLUE := \033[0;34m
GREEN := \033[0;32m
YELLOW := \033[0;33m
RED := \033[0;31m
NC := \033[0m # No Color

##@ Help

help: ## Display this help message
	@echo "$(BLUE)Web CVE Census System - Makefile Commands$(NC)"
	@echo ""
	@awk 'BEGIN {FS = ":.*##"; printf "Usage:\n  make $(GREEN)<target>$(NC)\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  $(GREEN)%-20s$(NC) %s\n", $$1, $$2 } /^##@/ { printf "\n$(BLUE)%s$(NC)\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Setup & Installation

install: ## Install all dependencies
	@echo "$(BLUE)Installing dependencies...$(NC)"
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt
	@echo "$(GREEN)✓ Dependencies installed$(NC)"

install-dev: install ## Install development dependencies
	@echo "$(BLUE)Installing development dependencies...$(NC)"
	$(PIP) install black flake8 mypy pytest-cov hypothesis
	@echo "$(GREEN)✓ Development dependencies installed$(NC)"

setup: install create-dirs ## Complete setup (install + create directories)
	@echo "$(BLUE)Running initial setup...$(NC)"
	@if [ ! -f .env ]; then \
		echo "$(YELLOW)⚠ Creating .env from .env.example$(NC)"; \
		cp .env.example .env; \
		echo "$(YELLOW)⚠ Please edit .env with your database credentials$(NC)"; \
	fi
	@echo "$(GREEN)✓ Setup complete$(NC)"
	@echo "$(YELLOW)Next steps:$(NC)"
	@echo "  1. Edit .env with your Neon database URL"
	@echo "  2. Run: make db-setup"
	@echo "  3. Run: make verify"

create-dirs: ## Create necessary directories
	@echo "$(BLUE)Creating project directories...$(NC)"
	@mkdir -p $(DATA_DIR)
	@mkdir -p $(LOGS_DIR)
	@mkdir -p $(REPORTS_DIR)
	@mkdir -p $(DATA_DIR)/exploitdb
	@mkdir -p $(DATA_DIR)/cache
	@echo "$(GREEN)✓ Directories created$(NC)"

##@ Database

db-test: ## Test database connection
	@echo "$(BLUE)Testing database connection...$(NC)"
	@$(PYTHON) $(SCRIPTS_DIR)/test_connection.py

db-setup: ## Set up database schema
	@echo "$(BLUE)Setting up database schema...$(NC)"
	@$(PYTHON) $(SCRIPTS_DIR)/setup_database.py
	@echo "$(GREEN)✓ Database schema created$(NC)"

db-verify: ## Verify database setup
	@echo "$(BLUE)Verifying database setup...$(NC)"
	@$(PYTHON) $(SCRIPTS_DIR)/verify_setup.py

db-reset: ## Reset database (WARNING: Deletes all data!)
	@echo "$(RED)⚠ WARNING: This will delete all data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		$(PYTHON) -c "from src.database import db_manager; db_manager.drop_schema(); db_manager.create_schema(); print('Database reset complete')"; \
	else \
		echo "Cancelled"; \
	fi

##@ Testing

test: ## Run all tests
	@echo "$(BLUE)Running tests...$(NC)"
	$(PYTEST) $(TEST_DIR) -v

test-unit: ## Run unit tests only
	@echo "$(BLUE)Running unit tests...$(NC)"
	$(PYTEST) $(TEST_DIR) -v -m "not integration"

test-integration: ## Run integration tests only
	@echo "$(BLUE)Running integration tests...$(NC)"
	$(PYTEST) $(TEST_DIR) -v -m "integration"

test-coverage: ## Run tests with coverage report
	@echo "$(BLUE)Running tests with coverage...$(NC)"
	$(PYTEST) $(TEST_DIR) --cov=$(SRC_DIR) --cov-report=html --cov-report=term
	@echo "$(GREEN)✓ Coverage report generated in htmlcov/$(NC)"

test-watch: ## Run tests in watch mode
	@echo "$(BLUE)Running tests in watch mode...$(NC)"
	$(PYTEST) $(TEST_DIR) -v --looponfail

##@ Code Quality

lint: ## Run linting checks
	@echo "$(BLUE)Running linting checks...$(NC)"
	$(FLAKE8) $(SRC_DIR) $(TEST_DIR) --max-line-length=100 --exclude=__pycache__,.pytest_cache
	@echo "$(GREEN)✓ Linting passed$(NC)"

format: ## Format code with black
	@echo "$(BLUE)Formatting code...$(NC)"
	$(BLACK) $(SRC_DIR) $(TEST_DIR) $(SCRIPTS_DIR)
	@echo "$(GREEN)✓ Code formatted$(NC)"

format-check: ## Check code formatting without modifying
	@echo "$(BLUE)Checking code formatting...$(NC)"
	$(BLACK) --check $(SRC_DIR) $(TEST_DIR) $(SCRIPTS_DIR)

type-check: ## Run type checking with mypy
	@echo "$(BLUE)Running type checks...$(NC)"
	$(MYPY) $(SRC_DIR) --ignore-missing-imports
	@echo "$(GREEN)✓ Type checking passed$(NC)"

quality: format lint type-check ## Run all code quality checks
	@echo "$(GREEN)✓ All quality checks passed$(NC)"

##@ Verification

verify: ## Run comprehensive verification
	@echo "$(BLUE)Running comprehensive verification...$(NC)"
	@$(PYTHON) $(SCRIPTS_DIR)/comprehensive_verification.py

verify-quick: db-test ## Quick verification (connection only)
	@echo "$(GREEN)✓ Quick verification complete$(NC)"

verify-full: verify test ## Full verification (comprehensive + tests)
	@echo "$(GREEN)✓ Full verification complete$(NC)"

##@ Development

dev: install-dev setup ## Set up development environment
	@echo "$(GREEN)✓ Development environment ready$(NC)"

run-census: ## Run automated CVE census collection
	@echo "$(BLUE)Running automated census collection...$(NC)"
	@$(PYTHON) $(SCRIPTS_DIR)/run_census.py
	@echo "$(GREEN)✓ Census collection complete$(NC)"

shell: ## Start Python shell with project context
	@echo "$(BLUE)Starting Python shell...$(NC)"
	@$(PYTHON) -i -c "import sys; sys.path.insert(0, '.'); from src.config import Config; from src.database import db_manager; print('Loaded: Config, db_manager')"

##@ Cleaning

clean: ## Clean temporary files
	@echo "$(BLUE)Cleaning temporary files...$(NC)"
	@find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	@find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	@find . -type f -name "*.pyc" -delete 2>/dev/null || true
	@find . -type f -name "*.pyo" -delete 2>/dev/null || true
	@find . -type f -name ".coverage" -delete 2>/dev/null || true
	@rm -rf htmlcov/ 2>/dev/null || true
	@rm -rf .mypy_cache/ 2>/dev/null || true
	@rm -rf .hypothesis/ 2>/dev/null || true
	@echo "$(GREEN)✓ Cleaned$(NC)"

clean-logs: ## Clean log files
	@echo "$(BLUE)Cleaning log files...$(NC)"
	@rm -rf $(LOGS_DIR)/*.log 2>/dev/null || true
	@echo "$(GREEN)✓ Logs cleaned$(NC)"

clean-data: ## Clean cached data (WARNING: Deletes downloaded data!)
	@echo "$(RED)⚠ WARNING: This will delete cached data!$(NC)"
	@read -p "Are you sure? [y/N] " -n 1 -r; \
	echo; \
	if [[ $$REPLY =~ ^[Yy]$$ ]]; then \
		rm -rf $(DATA_DIR)/cache/* 2>/dev/null || true; \
		echo "$(GREEN)✓ Data cache cleaned$(NC)"; \
	else \
		echo "Cancelled"; \
	fi

clean-all: clean clean-logs ## Clean everything (except data)
	@echo "$(GREEN)✓ All temporary files cleaned$(NC)"

##@ Documentation

docs: ## Generate documentation
	@echo "$(BLUE)Documentation is in $(DOCS_DIR)/$(NC)"
	@echo "Available docs:"
	@ls -1 $(DOCS_DIR)/*.md 2>/dev/null || echo "No documentation files found"

docs-serve: ## Serve documentation (if using mkdocs)
	@echo "$(YELLOW)Documentation server not configured yet$(NC)"

##@ Information

info: ## Show project information
	@echo "$(BLUE)Web CVE Census System$(NC)"
	@echo ""
	@echo "$(GREEN)Project Structure:$(NC)"
	@echo "  src/          - Source code"
	@echo "  tests/        - Test suite"
	@echo "  scripts/      - Utility scripts"
	@echo "  docs/         - Documentation"
	@echo "  data/         - Data files"
	@echo "  logs/         - Log files"
	@echo "  reports/      - Generated reports"
	@echo ""
	@echo "$(GREEN)Configuration:$(NC)"
	@echo "  .env          - Environment variables"
	@echo "  requirements.txt - Python dependencies"
	@echo ""
	@echo "$(GREEN)Database:$(NC)"
	@if [ -f .env ]; then \
		grep "^DATABASE_URL" .env | head -1 | sed 's/DATABASE_URL=postgresql:\/\/[^:]*:[^@]*@/DATABASE_URL=postgresql:\/\/***:***@/' || echo "  Not configured"; \
	else \
		echo "  Not configured (.env missing)"; \
	fi

status: ## Show system status
	@echo "$(BLUE)System Status$(NC)"
	@echo ""
	@echo -n "Python version: "
	@$(PYTHON) --version
	@echo -n "Pip version: "
	@$(PIP) --version | cut -d' ' -f2
	@echo ""
	@echo "$(GREEN)Installed packages:$(NC)"
	@$(PIP) list | grep -E "(psycopg2|python-dotenv|pytest|hypothesis)" || echo "Core packages not installed"
	@echo ""
	@echo "$(GREEN)Environment:$(NC)"
	@if [ -f .env ]; then \
		echo "  ✓ .env file exists"; \
	else \
		echo "  ✗ .env file missing"; \
	fi
	@if [ -d data ]; then \
		echo "  ✓ data/ directory exists"; \
	else \
		echo "  ✗ data/ directory missing"; \
	fi

##@ Exploits

clean-cve: ## Clean up all CVE reproduction environments in tmp/ (WARNING: DELETES ALL tmp/ CONTENTS)
	@echo "$(BLUE)Cleaning all CVE reproduction environments in tmp/...$(NC)"
	@if [ -d "tmp" ]; then \
		for dir in tmp/*; do \
			if [ -d "$$dir" ] && [ -f "$$dir/docker-compose.yml" ]; then \
				echo "Found environment in $$dir"; \
				echo "Stopping containers and removing resources..."; \
				docker compose -f "$$dir/docker-compose.yml" down -v --rmi all 2>/dev/null || true; \
			fi \
		done; \
		echo "Removing all contents of tmp/..."; \
		rm -rf tmp/*; \
		echo "Recreating .gitkeep..."; \
		touch tmp/.gitkeep; \
		echo "$(GREEN)✓ All found environments and tmp contents cleaned$(NC)"; \
	else \
		echo "$(YELLOW)tmp directory not found$(NC)"; \
	fi

##@ Quick Commands

all: install setup db-setup verify test ## Run complete setup and verification
	@echo "$(GREEN)✓ Complete setup finished$(NC)"

check: lint test ## Quick check (lint + test)
	@echo "$(GREEN)✓ Quick check passed$(NC)"

ci: install-dev lint type-check test-coverage ## CI pipeline (for automation)
	@echo "$(GREEN)✓ CI pipeline complete$(NC)"

##@ Aliases

t: test ## Alias for 'test'
l: lint ## Alias for 'lint'
f: format ## Alias for 'format'
c: clean ## Alias for 'clean'
v: verify ## Alias for 'verify'
