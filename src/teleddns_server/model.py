# TeleDDNS-Server
# (C) 2015-2025 Tomas Hlavacek (tmshlvck@gmail.com)
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

from typing import Optional, List, Union
from enum import StrEnum

from fastapi import Request
from markupsafe import escape

from datetime import datetime
from sqlmodel import Field, SQLModel, Relationship, create_engine
from sqlalchemy.sql import func
from sqlalchemy import DateTime
from sqlalchemy.pool import StaticPool
from pydantic import field_validator
import re
import ipaddress
import hashlib
from pwdlib import PasswordHash
from pwdlib.hashers.argon2 import Argon2Hasher

from .settings import settings

# Modern password hashing with Argon2 only
password_hash = PasswordHash((Argon2Hasher(),))


class UserGroup(SQLModel, table=True):
    user_id: int = Field(foreign_key="user.id", primary_key=True)
    group_id: int = Field(foreign_key="group.id", primary_key=True)

    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(min_length=2)
    email: Optional[str] = Field(default=None, unique=True)
    password: str
    is_admin: bool = Field(default=False)

    # 2FA TOTP fields
    totp_secret: Optional[str] = Field(default=None)
    totp_enabled: bool = Field(default=False)
    totp_backup_codes: Optional[str] = Field(default=None)

    # SSO Integration fields
    sso_provider: Optional[str] = Field(default=None)
    sso_subject_id: Optional[str] = Field(default=None)
    sso_enabled: bool = Field(default=False)

    # Account status fields
    is_active: bool = Field(default=True)
    last_login: Optional[datetime] = Field(default=None)

    # Relationships
    api_tokens: List["UserToken"] = Relationship(back_populates="user")
    group_memberships: List["Group"] = Relationship(back_populates="user_memberships", link_model=UserGroup)
    user_label_authorizations: List["UserLabelAuthorization"] = Relationship(back_populates="user")
    owned_zones: List["MasterZone"] = Relationship(back_populates="owner")
    passkeys: List["UserPassKey"] = Relationship(back_populates="user")

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

    @classmethod
    def gen_hash(cls, passwd: str):
        return password_hash.hash(passwd)

    def verify_password(self, passwd: str):
        return password_hash.verify(passwd, self.password)

    def __str__(self):
        return self.username


class UserToken(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    token_hash: str = Field(unique=True)
    description: Optional[str] = Field(default=None)
    user_id: int = Field(foreign_key="user.id")
    user: "User" = Relationship(back_populates="api_tokens")

    def __str__(self):
        return f"{self.description or 'Token'} ({self.user.username if self.user else 'Unknown'})"

    expires_at: Optional[datetime] = Field(default=None)
    last_used: Optional[datetime] = Field(default=None)
    is_active: bool = Field(default=True)

    scopes: Optional[str] = Field(default="*")

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

    @classmethod
    def hash(cls, plaintext: str) -> str:
        return hashlib.sha256(plaintext.encode()).hexdigest()


class UserPassKey(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    user: "User" = Relationship(back_populates="passkeys")

    credential_id: str = Field(unique=True)
    public_key: str
    sign_count: int = Field(default=0)

    name: Optional[str] = Field(default=None)
    created_at: Optional[datetime] = Field(
        default=None,
        sa_type=DateTime(timezone=True),
        sa_column_kwargs={"server_default": func.now()},
        nullable=False,
    )
    last_used: Optional[datetime] = Field(default=None)
    is_active: bool = Field(default=True)


class Group(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(unique=True, min_length=2)
    description: Optional[str] = Field(default=None)

    user_memberships: List["User"] = Relationship(back_populates="group_memberships", link_model=UserGroup)
    group_label_authorizations: List["GroupLabelAuthorization"] = Relationship(back_populates="group")
    owned_zones: List["MasterZone"] = Relationship(back_populates="group")

    def __str__(self):
        return self.name

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


class SlaveZoneServer(SQLModel, table=True):
    server_id: Union[int, None] = Field(default=None, foreign_key="server.id", primary_key=True)
    zone_id: Union[int, None] = Field(default=None, foreign_key="masterzone.id", primary_key=True)
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


class Server(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    api_url: str
    api_key: str
    master_template: str
    slave_template: str
    is_active: bool = Field(default=True)

    # Server status tracking
    last_config_sync: Optional[datetime] = Field(default=None)
    config_dirty: bool = Field(default=True)

    def __str__(self):
        return self.name

    # Relationships
    master_zones: List["MasterZone"] = Relationship(back_populates="master_server")
    slave_zones: List["MasterZone"] = Relationship(back_populates="slave_servers", link_model=SlaveZoneServer)
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


class RRClass(StrEnum):
    IN = "IN"


_ORIGIN_REGEX = r"^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-))\.$"
_NAME_REGEX = r"^((?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,1024}(?<!-))$"
class MasterZone(SQLModel, table=True):
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

    # Owner and group assignment
    owner_id: int = Field(foreign_key="user.id")
    owner: "User" = Relationship(back_populates="owned_zones")

    group_id: Optional[int] = Field(default=None, foreign_key="group.id")
    group: Optional["Group"] = Relationship(back_populates="owned_zones")

    # Backend sync tracking
    content_dirty: bool = Field(default=True)
    last_content_sync: Optional[datetime] = Field(default=None)

    def __str__(self):
        return self.origin

    # Relationships
    master_server_id: Union[int, None] = Field(default=None, foreign_key="server.id")
    master_server: Union["Server", None] = Relationship(back_populates="master_zones")
    slave_servers: List["Server"] = Relationship(back_populates="slave_zones", link_model=SlaveZoneServer)
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

    #async def __admin_repr__(self, request: Request):
    #    return f"{escape(self.origin)}"
    #
    #async def __admin_select2_repr__(self, request: Request) -> str:
    #    return f"<span>{escape(await self.__admin_repr__(request))}</span>"

    def format_bind_zone(self):
        return f"""$ORIGIN {self.origin};
$TTL {settings.DEFAULT_TTL};
{self.soa_NAME : <63} {self.soa_TTL : <5} {self.soa_CLASS: <2} SOA {self.soa_MNAME} {self.soa_RNAME.replace('@', '.')} {self.soa_SERIAL} {self.soa_REFRESH} {self.soa_RETRY} {self.soa_EXPIRE} {self.soa_MINIMUM}"""


class UserLabelAuthorization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int = Field(foreign_key="user.id")
    user: "User" = Relationship(back_populates="user_label_authorizations")

    zone_id: int = Field(foreign_key="masterzone.id")
    zone: "MasterZone" = Relationship()

    label_pattern: str

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

    def verify_access(self, label):
        if not self.label_pattern:
            return True
        elif re.match(self.label_pattern, label):
            return True
        else:
            return False


class GroupLabelAuthorization(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    group_id: int = Field(foreign_key="group.id")
    group: "Group" = Relationship(back_populates="group_label_authorizations")

    zone_id: int = Field(foreign_key="masterzone.id")
    zone: "MasterZone" = Relationship()

    label_pattern: str

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

    def verify_access(self, label):
        if not self.label_pattern:
            return True
        elif re.match(self.label_pattern, label):
            return True
        else:
            return False




_RRLABEL_REGEX = r"^(?![0-9]+$)(?!-)[a-zA-Z0-9\.-]{,63}(?<!-)$"
class RR(SQLModel):
    id: Optional[int] = Field(default=None, primary_key=True)
    zone_id: int = Field(default=None, foreign_key="masterzone.id")
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
    zone: "MasterZone" = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        ipaddress.IPv4Address(value)
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} A {self.value}"


class AAAA(RR, table=True):
    zone: "MasterZone" = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        ipaddress.IPv6Address(value)
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} AAAA	{self.value}"

_DNSNAME_REGEX = r"[a-zA-Z0-9\.-]+"
def _validate_dns_name(name: str):
    name = name.strip()
    if re.match(_DNSNAME_REGEX, name):
        return name
    else:
        raise ValueError(f"DNS name {name} does not match '{_DNSNAME_REGEX}'")


class PTR(RR, table=True):
    zone: "MasterZone" = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} PTR	{self.value}"


class NS(RR, table=True):
    zone: "MasterZone" = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} NS	{self.value}"


class CNAME(RR, table=True):
    zone: "MasterZone" = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} CNAME	{self.value}"


class TXT(RR, table=True):
    zone: "MasterZone" = Relationship()

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} TXT	"{self.value}"'


class CAATag(StrEnum):
    issue = "issue"
    issuewild = "issuewild"
    iodef = "iodef"
    contactemail = "contactemail"
    contactphone = "contactphone"


class CAA(RR, table=True):
    zone: "MasterZone" = Relationship()
    flag: int
    tag: CAATag

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} CAA	{self.flag}	{self.tag} "{self.value}"'


class MX(RR, table=True):
    zone: "MasterZone" = Relationship()
    priority: int

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} MX {self.priority} {self.value}"


class SRV(RR, table=True):
    zone: "MasterZone" = Relationship()
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


class SSHFP(RR, table=True):
    zone: "MasterZone" = Relationship()
    algorithm: int
    hash_type: int
    fingerprint: str

    @field_validator("algorithm")
    def validate_algorithm(cls, value):
        if value not in [1, 2, 3, 4]:  # RSA, DSA, ECDSA, Ed25519
            raise ValueError(f"Invalid algorithm: {value}")
        return value

    @field_validator("hash_type")
    def validate_hash_type(cls, value):
        if value not in [1, 2]:  # SHA-1, SHA-256
            raise ValueError(f"Invalid hash type: {value}")
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} SSHFP {self.algorithm} {self.hash_type} {self.fingerprint}"


class TLSA(RR, table=True):
    zone: "MasterZone" = Relationship()
    cert_usage: int
    selector: int
    matching_type: int
    cert_data: str

    @field_validator("cert_usage")
    def validate_cert_usage(cls, value):
        if value not in [0, 1, 2, 3]:
            raise ValueError(f"Invalid cert usage: {value}")
        return value

    @field_validator("selector")
    def validate_selector(cls, value):
        if value not in [0, 1]:
            raise ValueError(f"Invalid selector: {value}")
        return value

    @field_validator("matching_type")
    def validate_matching_type(cls, value):
        if value not in [0, 1, 2]:
            raise ValueError(f"Invalid matching type: {value}")
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} TLSA {self.cert_usage} {self.selector} {self.matching_type} {self.cert_data}"


class DNSKEY(RR, table=True):
    zone: "MasterZone" = Relationship()
    flags: int
    protocol: int = Field(default=3)
    algorithm: int
    public_key: str

    @field_validator("flags")
    def validate_flags(cls, value):
        if value < 0 or value > 65535:
            raise ValueError(f"Invalid flags: {value}")
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} DNSKEY {self.flags} {self.protocol} {self.algorithm} {self.public_key}"


class DS(RR, table=True):
    zone: "MasterZone" = Relationship()
    key_tag: int
    algorithm: int
    digest_type: int
    digest: str

    @field_validator("key_tag")
    def validate_key_tag(cls, value):
        if value < 0 or value > 65535:
            raise ValueError(f"Invalid key tag: {value}")
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} DS {self.key_tag} {self.algorithm} {self.digest_type} {self.digest}"


class NAPTR(RR, table=True):
    zone: "MasterZone" = Relationship()
    order: int
    preference: int
    flags: str
    service: str
    regexp: str
    replacement: str

    @field_validator("order", "preference")
    def validate_order_preference(cls, value):
        if value < 0 or value > 65535:
            raise ValueError(f"Invalid order/preference: {value}")
        return value

    @field_validator("replacement")
    def validate_replacement(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} NAPTR {self.order} {self.preference} "{self.flags}" "{self.service}" "{self.regexp}" {self.replacement}'


# Configure engine based on database type
if settings.DB_URL.startswith('sqlite://'):
    # SQLite configuration with StaticPool
    engine = create_engine(
        settings.DB_URL,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        pool_pre_ping=True
    )
else:
    # Other databases (PostgreSQL, MySQL, etc.) with connection pool settings
    engine = create_engine(
        settings.DB_URL,
        poolclass=StaticPool,
        pool_size=20,
        max_overflow=0,
        pool_pre_ping=True
    )
SQLModel.metadata.create_all(engine)

RR_CLASSES = [A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV, SSHFP, TLSA, DNSKEY, DS, NAPTR]
