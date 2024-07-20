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

from typing import Optional
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

    @classmethod
    def __get_validators__(cls):
        cls.lookup = {v: k.value for v, k in cls.__members__.items()}
        yield cls.validate
    

    @classmethod
    def validate(cls, v, _):
        try:
            return cls.lookup[v]
        except KeyError:
            raise ValueError(f'Invalid value: {v}')


class Settings(BaseSettings, cli_parse_args=True):
    ADMIN_PASSWORD: Optional[str] = None
    ROOT_PATH: str = '/'
    LOG_LEVEL: LogLevel = LogLevel.INFO
    SESSION_SECRET: str = secrets.token_urlsafe(16)
    DB_URL: str = "sqlite:///teleddns.sqlite"
    LISTEN_ADDRESS: str = "127.0.0.1"
    LISTEN_PORT: int = 8085
    DEFAULT_TTL: int = 3600
    DDNS_RR_TTL: int = 60

settings = Settings()

logging.basicConfig(format='%(levelname)s:%(message)s', level=int(settings.LOG_LEVEL))