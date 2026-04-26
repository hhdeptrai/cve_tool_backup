"""Configuration management for the Web CVE Census System."""

import os
import yaml
from typing import Optional, List, Dict, Any
from pathlib import Path
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Application configuration loaded from environment variables and config.yaml."""
    
    # Configuration file path
    CONFIG_FILE: str = os.getenv("CONFIG_FILE", "config.yaml")
    
    # Database configuration
    DATABASE_URL: str = os.getenv("DATABASE_URL", "")
    DB_POOL_MIN_SIZE: int = int(os.getenv("DB_POOL_MIN_SIZE", "2"))
    DB_POOL_MAX_SIZE: int = int(os.getenv("DB_POOL_MAX_SIZE", "10"))
    DB_POOL_TIMEOUT: int = int(os.getenv("DB_POOL_TIMEOUT", "30"))
    DB_QUERY_TIMEOUT: int = int(os.getenv("DB_QUERY_TIMEOUT", "60"))
    
    # GitHub API configuration
    GITHUB_TOKEN: Optional[str] = os.getenv("GITHUB_TOKEN")
    GITHUB_API_URL: str = os.getenv("GITHUB_API_URL", "https://api.github.com/graphql")
    GITHUB_RATE_LIMIT_MAX: int = int(os.getenv("GITHUB_RATE_LIMIT_MAX", "5000"))
    GITHUB_RETRY_ATTEMPTS: int = int(os.getenv("GITHUB_RETRY_ATTEMPTS", "3"))
    GITHUB_RETRY_DELAY: int = int(os.getenv("GITHUB_RETRY_DELAY", "5"))
    
    # Exploit-DB configuration
    EXPLOITDB_CSV_PATH: str = os.getenv("EXPLOITDB_CSV_PATH", "./data/exploitdb/files_exploits.csv")
    EXPLOITDB_CSV_URL: str = os.getenv(
        "EXPLOITDB_CSV_URL",
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )
    EXPLOITDB_CACHE_ENABLED: bool = os.getenv("EXPLOITDB_CACHE_ENABLED", "true").lower() == "true"
    EXPLOITDB_CACHE_TTL: int = int(os.getenv("EXPLOITDB_CACHE_TTL", "604800"))
    
    # GitHub PoC configuration
    GITHUB_POC_REPO_PATH: str = os.getenv("GITHUB_POC_REPO_PATH", "./data/PoC-in-GitHub")
    
    # Census configuration
    CENSUS_BATCH_SIZE: int = int(os.getenv("CENSUS_BATCH_SIZE", "100"))
    CENSUS_START_YEAR: int = int(os.getenv("CENSUS_START_YEAR", "2015"))
    CENSUS_END_YEAR: int = int(os.getenv("CENSUS_END_YEAR", "2025"))
    CENSUS_ECOSYSTEMS: List[str] = os.getenv(
        "CENSUS_ECOSYSTEMS",
        "npm,maven,nuget,pip,composer,go,rubygems,rust,erlang"
    ).split(",")
    CENSUS_PRIORITY_CWES: List[str] = os.getenv(
        "CENSUS_PRIORITY_CWES",
        "Injection,XSS,Authentication,Deserialization,SSRF,Path Traversal"
    ).split(",")
    CENSUS_CONTINUE_ON_ERROR: bool = os.getenv("CENSUS_CONTINUE_ON_ERROR", "true").lower() == "true"
    CENSUS_MAX_CONSECUTIVE_ERRORS: int = int(os.getenv("CENSUS_MAX_CONSECUTIVE_ERRORS", "10"))
    
    # Task configuration
    CLAIM_EXPIRATION_DAYS: int = int(os.getenv("CLAIM_EXPIRATION_DAYS", "7"))
    TASK_BATCH_DEFAULT_SIZE: int = int(os.getenv("TASK_BATCH_DEFAULT_SIZE", "10"))
    TASK_BATCH_MAX_SIZE: int = int(os.getenv("TASK_BATCH_MAX_SIZE", "50"))
    VALID_RESEARCHERS: List[str] = os.getenv("VALID_RESEARCHERS", "Minh,Hoàng").split(",")
    TASK_PREFER_EXPLOIT_AVAILABLE: bool = os.getenv("TASK_PREFER_EXPLOIT_AVAILABLE", "true").lower() == "true"
    TASK_ORDER_BY_YEAR: str = os.getenv("TASK_ORDER_BY_YEAR", "desc")
    
    # Verification configuration
    VERIFICATION_REQUIRE_NOTES: bool = os.getenv("VERIFICATION_REQUIRE_NOTES", "true").lower() == "true"
    VERIFICATION_MIN_NOTES_LENGTH: int = int(os.getenv("VERIFICATION_MIN_NOTES_LENGTH", "10"))
    
    # Exclusion configuration
    EXCLUSION_REQUIRE_REASON: bool = os.getenv("EXCLUSION_REQUIRE_REASON", "true").lower() == "true"
    EXCLUSION_MIN_REASON_LENGTH: int = int(os.getenv("EXCLUSION_MIN_REASON_LENGTH", "10"))
    EXCLUSION_AUDIT_ENABLED: bool = os.getenv("EXCLUSION_AUDIT_ENABLED", "true").lower() == "true"
    EXCLUSION_AUDIT_LOG_PATH: str = os.getenv("EXCLUSION_AUDIT_LOG_PATH", "./logs/exclusion_audit.log")
    
    # Reporting configuration
    REPORT_DEFAULT_MODE: str = os.getenv("REPORT_DEFAULT_MODE", "priority")
    REPORT_OUTPUT_DIR: str = os.getenv("REPORT_OUTPUT_DIR", "./reports")
    REPORT_FORMATS: List[str] = os.getenv("REPORT_FORMATS", "json,csv,markdown").split(",")
    
    # Logging configuration
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE_ENABLED: bool = os.getenv("LOG_FILE_ENABLED", "true").lower() == "true"
    LOG_FILE_PATH: str = os.getenv("LOG_FILE_PATH", "./logs/census.log")
    LOG_FILE_MAX_BYTES: int = int(os.getenv("LOG_FILE_MAX_BYTES", "10485760"))
    LOG_FILE_BACKUP_COUNT: int = int(os.getenv("LOG_FILE_BACKUP_COUNT", "5"))
    LOG_CONSOLE_ENABLED: bool = os.getenv("LOG_CONSOLE_ENABLED", "true").lower() == "true"
    LOG_CONSOLE_COLORIZE: bool = os.getenv("LOG_CONSOLE_COLORIZE", "true").lower() == "true"
    
    # Validation configuration
    CVE_ID_PATTERN: str = os.getenv("CVE_ID_PATTERN", r"^CVE-\d{4}-\d{4,}$")
    CVSS_MIN: float = float(os.getenv("CVSS_MIN", "0.0"))
    CVSS_MAX: float = float(os.getenv("CVSS_MAX", "10.0"))
    YEAR_MIN: int = int(os.getenv("YEAR_MIN", "2015"))
    YEAR_MAX: int = int(os.getenv("YEAR_MAX", "2025"))
    
    # Performance configuration
    QUERY_USE_INDEXES: bool = os.getenv("QUERY_USE_INDEXES", "true").lower() == "true"
    QUERY_EXPLAIN_SLOW: bool = os.getenv("QUERY_EXPLAIN_SLOW", "true").lower() == "true"
    QUERY_SLOW_THRESHOLD: int = int(os.getenv("QUERY_SLOW_THRESHOLD", "1000"))
    CACHE_ENABLED: bool = os.getenv("CACHE_ENABLED", "true").lower() == "true"
    CACHE_BACKEND: str = os.getenv("CACHE_BACKEND", "memory")
    CACHE_TTL: int = int(os.getenv("CACHE_TTL", "3600"))
    CONCURRENCY_MAX_WORKERS: int = int(os.getenv("CONCURRENCY_MAX_WORKERS", "4"))
    CONCURRENCY_USE_POOLING: bool = os.getenv("CONCURRENCY_USE_POOLING", "true").lower() == "true"
    
    # Development configuration
    DEBUG: bool = os.getenv("DEBUG", "false").lower() == "true"
    USE_TEST_DB: bool = os.getenv("USE_TEST_DB", "false").lower() == "true"
    MOCK_APIS: bool = os.getenv("MOCK_APIS", "false").lower() == "true"
    SEED_ENABLED: bool = os.getenv("SEED_ENABLED", "false").lower() == "true"
    SEED_SAMPLE_SIZE: int = int(os.getenv("SEED_SAMPLE_SIZE", "100"))
    
    # YAML configuration cache
    _yaml_config: Optional[Dict[str, Any]] = None
    
    @classmethod
    def load_yaml_config(cls) -> Dict[str, Any]:
        """Load configuration from YAML file."""
        if cls._yaml_config is not None:
            return cls._yaml_config
        
        config_path = Path(cls.CONFIG_FILE)
        if not config_path.exists():
            # YAML config is optional, return empty dict if not found
            cls._yaml_config = {}
            return cls._yaml_config
        
        try:
            with open(config_path, 'r') as f:
                content = f.read()
                # Replace environment variable placeholders
                content = cls._replace_env_vars(content)
                cls._yaml_config = yaml.safe_load(content) or {}
                return cls._yaml_config
        except Exception as e:
            print(f"Warning: Failed to load config.yaml: {e}")
            cls._yaml_config = {}
            return cls._yaml_config
    
    @classmethod
    def _replace_env_vars(cls, content: str) -> str:
        """Replace ${VAR} and ${VAR:default} placeholders with environment variables."""
        import re
        
        def replacer(match):
            var_expr = match.group(1)
            if ':' in var_expr:
                var_name, default = var_expr.split(':', 1)
                return os.getenv(var_name, default)
            else:
                return os.getenv(var_expr, match.group(0))
        
        return re.sub(r'\$\{([^}]+)\}', replacer, content)
    
    @classmethod
    def get_yaml_value(cls, *keys: str, default: Any = None) -> Any:
        """Get a value from YAML config using dot notation."""
        config = cls.load_yaml_config()
        value = config
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return default
            if value is None:
                return default
        return value
    
    @classmethod
    def validate(cls) -> None:
        """Validate that required configuration is present."""
        if not cls.DATABASE_URL:
            raise ValueError("DATABASE_URL environment variable is required")
        
        if cls.CENSUS_START_YEAR < cls.YEAR_MIN or cls.CENSUS_START_YEAR > cls.YEAR_MAX:
            raise ValueError(f"CENSUS_START_YEAR must be between {cls.YEAR_MIN} and {cls.YEAR_MAX}")
        
        if cls.CENSUS_END_YEAR < cls.YEAR_MIN or cls.CENSUS_END_YEAR > cls.YEAR_MAX:
            raise ValueError(f"CENSUS_END_YEAR must be between {cls.YEAR_MIN} and {cls.YEAR_MAX}")
        
        if cls.CENSUS_START_YEAR > cls.CENSUS_END_YEAR:
            raise ValueError("CENSUS_START_YEAR must be <= CENSUS_END_YEAR")
        
        if cls.REPORT_DEFAULT_MODE not in ["priority", "full"]:
            raise ValueError("REPORT_DEFAULT_MODE must be 'priority' or 'full'")
        
        if cls.TASK_ORDER_BY_YEAR not in ["asc", "desc"]:
            raise ValueError("TASK_ORDER_BY_YEAR must be 'asc' or 'desc'")
    
    @classmethod
    def get_all(cls) -> Dict[str, Any]:
        """Get all configuration values as a dictionary."""
        return {
            key: getattr(cls, key)
            for key in dir(cls)
            if not key.startswith('_') and key.isupper()
        }


# Validate configuration on import
try:
    Config.validate()
except ValueError as e:
    print(f"Configuration validation warning: {e}")
    print("Some features may not work correctly. Please check your .env file.")

