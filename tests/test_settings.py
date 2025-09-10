# Test settings configuration
from pydantic import Field
from pydantic_settings import BaseSettings
import secrets
import logging
from enum import IntEnum

class LogLevel(IntEnum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL

class TestSettings(BaseSettings):
    """Test settings without CLI parsing"""
    ADMIN_PASSWORD: str | None = None
    ROOT_PATH: str = ''
    LOG_LEVEL: LogLevel = LogLevel.INFO
    SESSION_SECRET: str = secrets.token_urlsafe(16)
    DB_URL: str = "sqlite:///test.sqlite"
    LISTEN_ADDRESS: str = "127.0.0.1"
    LISTEN_PORT: int = 8085
    DEFAULT_TTL: int = 3600
    DDNS_RR_TTL: int = 60
    
    # Authentication settings
    JWT_SECRET_KEY: str = secrets.token_urlsafe(32)
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
    
    # 2FA settings
    TOTP_ISSUER_NAME: str = "TeleDDNS"
    BACKUP_CODES_COUNT: int = 10
    
    # PassKeys settings
    WEBAUTHN_RP_ID: str = "localhost"
    WEBAUTHN_RP_NAME: str = "TeleDDNS Server"
    WEBAUTHN_ORIGIN: str = "http://localhost:8085"
    
    # Authorization settings
    DEFAULT_GROUP_NAME: str = "users"
    
    # Backend sync settings
    UPDATE_DELAY: int = 10
    UPDATE_MINIMUM_DELAY: int = 30
    UPDATE_INTERVAL: int = 600
    
    # Health monitoring settings
    WARN_ON_NOUPDATE: int = 7200
    WARN_ON_NOPUSH: int = 3600

test_settings = TestSettings()