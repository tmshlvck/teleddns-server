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

from __future__ import annotations
from typing import Optional, List, TYPE_CHECKING, ClassVar
from sqlalchemy.orm import Mapped, relationship
from enum import StrEnum
import uuid
# from fastapi_users_db_sqlalchemy import SQLAlchemyBaseUserTable

from fastapi import Request
from markupsafe import escape

from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship, create_engine
from sqlalchemy.sql import func
from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, relationship
from pydantic import field_validator


from .settings import settings

import re
import ipaddress
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


class UserGroupLink(SQLModel, table=True):
    user_id: int | None = Field(default=None, foreign_key="user.id", primary_key=True)
    group_id: int | None = Field(default=None, foreign_key="group.id", primary_key=True)


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(min_length=2, unique=True, index=True)
    email: Optional[str] = Field(default=None, unique=True, index=True)
    password: str
    is_admin: bool = Field(default=False)
    is_active: bool = Field(default=True)
    is_verified: bool = Field(default=False)
    has_2fa: bool = Field(default=False)
    has_passkey: bool = Field(default=False)
    totp_secret: Optional[str] = Field(default=None)
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )
    
    # Relationships for admin display
    api_tokens: ClassVar = relationship("APIToken", back_populates="user")
    owned_zones: ClassVar = relationship("Zone", back_populates="owner")  
    groups: ClassVar = relationship("Group", secondary="usergrouplink", back_populates="users")

    @classmethod
    def gen_hash(cls, passwd: str):
        return pwd_context.hash(passwd)
    
    def verify_password(self, passwd: str):
        return pwd_context.verify(passwd, self.password)


class Group(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(min_length=2)
    description: Optional[str] = None
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )
    
    # Relationships for admin display
    users: ClassVar = relationship("User", secondary="usergrouplink", back_populates="groups")
    zones: ClassVar = relationship("Zone", back_populates="group")


class APIToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token: str = Field(index=True)
    description: Optional[str] = None
    user_id: int = Field(foreign_key="user.id")
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )
    
    # Relationships for admin display
    user: ClassVar = relationship("User", back_populates="api_tokens")


class PasskeyCredential(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    credential_id: str = Field(unique=True)
    public_key: str
    name: Optional[str] = None
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )


class Server(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    api_url: str
    api_key: str
    master_template: str
    needs_config_update: bool = Field(default=False)
    config_last_updated: Optional[datetime] = None
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )
    
    # Relationships for admin display
    zones: ClassVar = relationship("Zone", back_populates="server")


class RRClass(StrEnum):
    IN = "IN"


# DNS name validation patterns
_ORIGIN_REGEX = r"^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,253}(?<!-))\.$"  # FQDN with trailing dot
_NAME_REGEX = r"^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,253}(?<!-))$"      # DNS name without trailing dot
class Zone(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    origin: str
    soa_NAME: str
    soa_CLASS: RRClass
    soa_TTL: int
    soa_MNAME: str
    soa_RNAME: str
    soa_SERIAL: int
    soa_REFRESH: int
    soa_RETRY: int
    soa_EXPIRE: int
    soa_MINIMUM: int
    server_id: int | None = Field(default=None, foreign_key="server.id")
    user_id: int = Field(foreign_key="user.id")
    group_id: int | None = Field(default=None, foreign_key="group.id")
    needs_update: bool = Field(default=False)
    last_updated: Optional[datetime] = None
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )
    
    # Relationships for admin display
    server: ClassVar = relationship("Server", back_populates="zones")
    owner: ClassVar = relationship("User", back_populates="owned_zones")
    group: ClassVar = relationship("Group", back_populates="zones")

    @field_validator("origin")
    def validate_origin(cls, value):
        value = value.strip()
        if re.match(_ORIGIN_REGEX, value):
            return value
        else:
            raise ValueError(f"Origin {value} does not match '{_ORIGIN_REGEX}'")
        
    @field_validator("soa_NAME")
    def validate_name(cls, value):
        value = value.strip()
        if value == '@':
            return value
        elif re.match(_NAME_REGEX, value):
            return value
        else:
            raise ValueError(f"SOA name {value} does not match '{_NAME_REGEX}'")
        
    @field_validator("soa_MNAME")
    def validate_mname(cls, value):
        value = value.strip()
        if value == '@':
            return value
        elif re.match(_NAME_REGEX, value):
            return value
        else:
            raise ValueError(f"SOA master name {value} does not match '{_NAME_REGEX}'")
        
    @field_validator("soa_RNAME")
    def validate_rname(cls, value):
        value = value.strip()
        if value == '@':
            return value
        elif re.match(_NAME_REGEX, value):
            return value
        else:
            raise ValueError(f"SOA root name {value} does not match '{_NAME_REGEX}'")

    async def __admin_repr__(self, request: Request):
        return f"{escape(self.origin)}"
    
    async def __admin_select2_repr__(self, request: Request) -> str:
        return f"<span>{escape(await self.__admin_repr__(request))}</span>"
    
    def format_bind_zone(self):
        return f"""$ORIGIN {self.origin};
$TTL {settings.DEFAULT_TTL};
{self.soa_NAME : <63} {self.soa_TTL : <5} {self.soa_CLASS: <2} SOA {self.soa_MNAME} {self.soa_RNAME.replace('@', '.')} {self.soa_SERIAL} {self.soa_REFRESH} {self.soa_RETRY} {self.soa_EXPIRE} {self.soa_MINIMUM}"""




_RRLABEL_REGEX = r"^(?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,63}(?<!-)$"
class RR(SQLModel):
    id: Optional[int] = Field(default=None, primary_key=True)
    zone_id: int = Field(default=None, foreign_key="zone.id")
    placeholder: bool = Field(default=False)
    label: str
    ttl: int = Field(default=3600)
    rrclass: RRClass
    value: str
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )
    updated_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"onupdate": func.now(), "server_default": func.now()},
    )

    @field_validator("label")
    def validate_label(cls, value):
        value = value.strip()
        if value == '@':
            return value
        elif re.match(_RRLABEL_REGEX, value):
            return value
        else:
            raise ValueError(f"Label {value} does not match '{_RRLABEL_REGEX}'")


class A(RR, table=True):

    @field_validator("value")
    def validate_value(cls, value):
        ipaddress.IPv4Address(value)
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} A {self.value}"


class AAAA(RR, table=True):

    @field_validator("value")
    def validate_value(cls, value):
        ipaddress.IPv6Address(value)
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} AAAA	{self.value}"

_DNSNAME_REGEX = r"^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,253}(?<!-))$"    # Standard DNS name validation
def _validate_dns_name(name: str):
    name = name.strip()
    if name == '@':
        return name
    elif re.match(_DNSNAME_REGEX, name):
        return name
    else:
        raise ValueError(f"DNS name {name} does not match '{_DNSNAME_REGEX}'")


class PTR(RR, table=True):

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)
    
    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} PTR	{self.value}"


class NS(RR, table=True):

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} NS	{self.value}"


class CNAME(RR, table=True):

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)
    
    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} CNAME	{self.value}"


class TXT(RR, table=True):

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} TXT	"{self.value}"'


class CAATag(StrEnum):
    issue = "issue"
    issuewild = "issuewild"
    iodef = "iodef"
    contactemail = "contactemail"
    contactphone = "contactphone"


class CAA(RR, table=True):
    flag: int
    tag: CAATag

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} CAA	{self.flag}	{self.tag} "{self.value}"'


class MX(RR, table=True):
    priority: int

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} MX {self.priority} {self.value}"


class SRV(RR, table=True):
    priority: int
    weight: int
    port: int
    
    @field_validator("label")
    def validate_label(cls, value):
        return value.strip()
    
    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} SRV	{self.priority} {self.weight} {self.port} {self.value}'


if settings.DB_URL.startswith("sqlite://"):
    # SQLite-specific configuration
    engine = create_engine(
        settings.DB_URL,
        connect_args={"check_same_thread": False},
        echo=False  # Set to True for SQL debugging
    )
else:
    # PostgreSQL/MySQL configuration with connection pooling
    engine = create_engine(
        settings.DB_URL, 
        pool_size=settings.DB_POOL_SIZE,
        max_overflow=settings.DB_MAX_OVERFLOW,
        pool_timeout=settings.DB_POOL_TIMEOUT,
        pool_recycle=settings.DB_POOL_RECYCLE,
        echo=False  # Set to True for SQL debugging
    )
SQLModel.metadata.create_all(engine)

RR_CLASSES = [A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV]