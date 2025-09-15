# TeleDDNS-Server
# (C) 2015-2024 Tomas Hlavacek (tmshlvck@gmail.com)
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

from typing import Optional, Union
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings
import secrets
import logging
import os
from enum import IntEnum

class LogLevel(IntEnum):
    DEBUG = logging.DEBUG
    INFO = logging.INFO
    WARNING = logging.WARNING
    ERROR = logging.ERROR
    CRITICAL = logging.CRITICAL


class Settings(BaseSettings, cli_parse_args=not os.getenv('DISABLE_CLI_PARSING', False)):
    ADMIN_PASSWORD: Optional[str] = None
    ROOT_PATH: str = ''
    LOG_LEVEL: LogLevel = LogLevel.INFO
    SESSION_SECRET: str = secrets.token_urlsafe(16)
    DB_URL: str = "sqlite:///teleddns.sqlite"
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
    BACKEND_SYNC_PERIOD: int = 300  # Background sync period in seconds
    BACKEND_SYNC_DELAY: int = 10    # Delay before starting sync to batch updates

    # Health monitoring settings
    WARN_ON_NOUPDATE: int = 7200
    WARN_ON_NOPUSH: int = 3600

    @field_validator('LOG_LEVEL', mode='before')
    @classmethod
    def validate_log_level(cls, v) -> Union[LogLevel, int, str]:
        if isinstance(v, str):
            try:
                return LogLevel[v.upper()]
            except KeyError:
                try:
                    return LogLevel(int(v))
                except (ValueError, TypeError):
                    raise ValueError(f"Invalid log level: {v}. Must be one of: DEBUG, INFO, WARNING, ERROR, CRITICAL or their numeric equivalents")
        return v

settings = Settings()

logging.basicConfig(format='%(levelname)s:%(message)s', level=int(settings.LOG_LEVEL))
