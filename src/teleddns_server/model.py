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

from typing import Optional, List
from enum import StrEnum

from fastapi import Request
from markupsafe import escape

from sqlmodel import Field, SQLModel, Relationship, create_engine
from pydantic import field_validator


from .settings import settings

import re
import ipaddress
from passlib.context import CryptContext
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")



def fqdn(name):
    if name.strip().endswith('.'):
        return name.strip().lower()
    else:
        return f"{name.strip()}.".lower()


class User(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    username: str = Field(min_length=2)
    password: str
    is_admin: bool
    access_rules: List["AccessRule"] = Relationship(back_populates="user")

    @classmethod
    def gen_hash(cls, passwd: str):
        return pwd_context.hash(passwd)
    
    def verify_password(self, passwd: str):
        return pwd_context.verify(passwd, self.password)


class SlaveZoneServer(SQLModel, table=True):
    server_id: int | None = Field(default=None, foreign_key="server.id", primary_key=True)
    zone_id: int | None = Field(default=None, foreign_key="masterzone.id", primary_key=True)


class Server(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    api_url: str
    api_key: str
    master_template: str
    slave_template: str
    master_zones: List["MasterZone"] = Relationship(back_populates="master_server")
    slave_zones: List["MasterZone"] = Relationship(back_populates="slave_servers", link_model=SlaveZoneServer)


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
    access_rules: List["AccessRule"] = Relationship(back_populates="zone")
    master_server_id: int | None = Field(default=None, foreign_key="server.id")
    master_server: Server | None = Relationship(back_populates="master_zones")
    slave_servers: List[Server] = Relationship(back_populates="slave_zones", link_model=SlaveZoneServer)

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
        return f"""$ORIGIN {fqdn(self.origin)};
$TTL {settings.DEFAULT_TTL};
{fqdn(self.soa_NAME) : <63} {self.soa_TTL : <5} {self.soa_CLASS: <2} SOA {fqdn(self.soa_MNAME)} {fqdn(self.soa_RNAME.replace('@', '.'))} {self.soa_SERIAL} {self.soa_REFRESH} {self.soa_RETRY} {self.soa_EXPIRE} {self.soa_MINIMUM}"""


class AccessRule(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    user_id: int | None = Field(default=None, foreign_key="user.id")
    user: User | None = Relationship(back_populates="access_rules")
    zone_id: Optional[int] = Field(default=None, foreign_key="masterzone.id")
    zone: Optional[MasterZone] = Relationship(back_populates="access_rules")
    pattern: Optional[str]

    def verify_access(self, label):
        if not self.pattern: # no pattern means allow all
            return True
        elif re.match(self.pattern, label):
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
    zone: MasterZone = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        ipaddress.IPv4Address(value)
        return value

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} A {self.value}"


class AAAA(RR, table=True):
    zone: MasterZone = Relationship()

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
    zone: MasterZone = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)
    
    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} PTR	{self.value}"


class NS(RR, table=True):
    zone: MasterZone = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} NS	{self.value}"


class CNAME(RR, table=True):
    zone: MasterZone = Relationship()

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)
    
    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} CNAME	{self.value}"


class TXT(RR, table=True):
    zone: MasterZone = Relationship()

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} TXT	"{self.value}"'


class CAATag(StrEnum):
    issue = "issue"
    issuewild = "issuewild"
    iodef = "iodef"
    contactemail = "contactemail"
    contactphone = "contactphone"


class CAA(RR, table=True):
    zone: MasterZone = Relationship()
    flag: int
    tag: CAATag

    def format_bind_zone(self):
        return f'{self.label : <63} {self.ttl : <5} {self.rrclass : <2} CAA	{self.flag}	{self.tag} "{self.value}"'


class MX(RR, table=True):
    zone: MasterZone = Relationship()
    priority: int

    @field_validator("value")
    def validate_value(cls, value):
        return _validate_dns_name(value)

    def format_bind_zone(self):
        return f"{self.label : <63} {self.ttl : <5} {self.rrclass : <2} MX {self.priority} {self.value}"


class SRV(RR, table=True):
    zone: MasterZone = Relationship()
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


engine = create_engine("sqlite:///test.sqlite", connect_args={"check_same_thread": False})
SQLModel.metadata.create_all(engine)

RR_CLASSES = [A, AAAA, NS, PTR, CNAME, TXT, CAA, MX, SRV]