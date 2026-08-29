from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List

class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file='.env', case_sensitive=True, extra='ignore')
    APP_NAME: str = 'RUACH Cross-Border Compliance Engine'
    APP_VERSION: str = '2.6.3'
    DEBUG: bool = False
    ENVIRONMENT: str = 'production'
    DATABASE_URL: str = 'postgresql://postgres:postgres@localhost:5432/clearance_db'
    REDIS_URL: str = 'redis://localhost:6379/0'
    ALLOWED_CORS_ORIGINS: List[str] = []
    RATE_LIMIT_ENABLED: bool = True
    RATE_LIMIT_PER_MINUTE: int = 60
    RATE_LIMIT_FAIL_MODE: str = 'closed'
    CIRCUIT_BREAKER_FAIL_THRESHOLD: int = 5
    CIRCUIT_BREAKER_COOLDOWN: int = 30
    VIES_API_URL: str = 'https://ec.europa.eu/taxation_customs/vies/services/checkVatService'
    TAX_VALIDATION_TIMEOUT: int = 8
    COMPLIANCE_RULE_VERSION: str = 'EU-B2B-BASELINE-2026.08'
    COMPLIANCE_PRIMARY_REGION: str = 'EU'
    IP_GEO_URL_TEMPLATE: str = 'https://ipapi.co/{ip}/json/'
    IP_GEO_TIMEOUT: int = 3
    TRUSTED_PROXY_IPS: List[str] = []
    COOKIE_SECURE: bool = True
    DASHBOARD_SESSION_SECRET: str = 'CHANGE-ME-IN-PRODUCTION'
    DASHBOARD_SESSION_TTL_SECONDS: int = 3600
    SEED_TEST_API_KEY: bool = False
    REGULATORY_MONITOR_ENABLED: bool = True
    REGULATORY_MONITOR_INTERVAL_SECONDS: int = 3600
    REGULATORY_SOURCE_TIMEOUT: int = 20
    REGULATORY_MAX_SOURCE_BYTES: int = 5_000_000
    REGULATORY_MAX_TEXT_CHARS: int = 2_000_000
    REGULATORY_MAX_REDIRECTS: int = 5
    REGULATORY_MAX_PDF_PAGES: int = 200
    REGULATORY_USER_AGENT: str = 'RUACH-Regulatory-Monitor/2.6.1'
    REGULATORY_ALLOWED_HOSTS: List[str] = []
    REGULATORY_DNS_TIMEOUT: int = 5
    REQUEST_TIMEOUT_SECONDS: int = 30
    AUDIT_CHAIN_VERIFY_ON_STARTUP: bool = False
    BACKUP_RETENTION_DAYS: int = 30
    PLATFORM_ADMIN_SECRET: str = 'CHANGE-ME-IN-PRODUCTION'

    @field_validator('ALLOWED_CORS_ORIGINS')
    @classmethod
    def no_wildcard_cors(cls, value):
        if '*' in value:
            raise ValueError('Wildcard CORS is not permitted')
        return value

    @field_validator('REGULATORY_ALLOWED_HOSTS')
    @classmethod
    def normalize_allowed_hosts(cls, value):
        return sorted({str(v).strip().lower().rstrip('.') for v in value if str(v).strip()})

settings = Settings()
