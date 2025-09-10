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

from typing import Dict, Any, Awaitable

from fastapi.responses import RedirectResponse
from starlette.requests import Request
from sqlmodel import Session

from starlette_admin.contrib.sqlmodel import Admin, ModelView
from starlette_admin.views import Link, CustomView
from starlette_admin import PasswordField, EmailField, RowActionsDisplayType, BaseField
from starlette_admin._types import RequestAction
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

from teleddns_server.model import *
from teleddns_server.auth import AdminAuthProvider


class EmptyPasswordField(PasswordField):
    """Custom password field that displays empty in edit forms"""

    async def serialize_value(self, request: Request, value: Any, action: RequestAction) -> Any:
        """Override to return empty string in edit forms"""
        if action == RequestAction.EDIT:
            return ""
        return await super().serialize_value(request, value, action)


class RRView(ModelView):
    sortable_fields = ["label", "zone"]
    sortable_fields_mapping = { "zone": MasterZone.id, }
    exclude_fields_from_create = ["id"]
    exclude_fields_from_list = ["id"]
    exclude_fields_from_edit = ["id"]

    async def after_create(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            rr = session.merge(obj)
            rr.zone.content_dirty = True
            session.commit()

    async def after_edit(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            rr = session.merge(obj)
            rr.zone.content_dirty = True
            session.commit()

    async def after_delete(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            zone_id = obj.zone_id
            zone = session.get(MasterZone, zone_id)
            if zone:
                zone.content_dirty = True
                session.commit()


class UserView(ModelView):
    fields = [
        "id",
        "username",
        EmailField("email"),
        EmptyPasswordField("password", exclude_from_list=True),
        "is_admin",
        "totp_enabled",
        "sso_enabled",
        "is_active",
        "api_tokens",
        "group_memberships",
        "user_label_authorizations",
        "owned_zones",
        "passkeys",
        "created_at",
        "updated_at",
    ]

    async def before_create(self, request: Request, data: Dict[str, Any], obj: Any) -> None:
        # Handle empty email field - convert empty string to None to avoid unique constraint issues
        if obj.email is not None and obj.email.strip() == '':
            obj.email = None

        if obj.password:
            obj.password = obj.gen_hash(obj.password)

    async def before_edit(self, request: Request, data: Dict[str, Any], obj: Any) -> None:
        # Handle empty email field - convert empty string to None to avoid unique constraint issues
        if data.get('email') is not None and data['email'].strip() == '':
            obj.email = None

        # Handle password field
        if data.get('password') and data['password'].strip():
            obj.password = obj.gen_hash(data['password'])
        else:
            existing_user = await self.find_by_pk(request, obj.id)
            obj.password = existing_user.password


class ServerView(ModelView):
    fields = [
        "id",
        "name",
        "api_url",
        "api_key",
        "master_template",
        "slave_template",
        "config_dirty",
        "last_config_sync",
        "master_zones",
        "slave_zones",
        "created_at",
        "updated_at",
    ]



class MasterZoneView(ModelView):
    fields = [
        "id",
        "origin",
        "soa_NAME",
        "soa_CLASS",
        "soa_TTL",
        "soa_MNAME",
        "soa_RNAME",
        "soa_SERIAL",
        "soa_REFRESH",
        "soa_RETRY",
        "soa_EXPIRE",
        "soa_MINIMUM",
        "owner",
        "group",
        "content_dirty",
        "last_content_sync",
        "master_server",
        "slave_servers",
        "created_at",
        "updated_at",
        ]

    async def after_create(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            zone = session.merge(obj)
            zone.content_dirty = True
            if zone.master_server:
                zone.master_server.config_dirty = True
            for slave_server in zone.slave_servers:
                slave_server.server.config_dirty = True
            session.commit()

    async def after_edit(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            zone = session.merge(obj)
            zone.content_dirty = True
            if zone.master_server:
                zone.master_server.config_dirty = True
            for slave_server in zone.slave_servers:
                slave_server.server.config_dirty = True
            session.commit()


def add_admin(app):
    admin = Admin(engine, title="Telephant DDNS admin",
                  auth_provider=AdminAuthProvider(allow_paths=["/statics/logo.svg"]),
                  middlewares=[Middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)],)

    admin.add_view(ServerView(Server))
    admin.add_view(UserView(User))
    admin.add_view(ModelView(UserToken))
    admin.add_view(ModelView(Group))
    admin.add_view(ModelView(UserPassKey))
    admin.add_view(ModelView(UserLabelAuthorization))
    admin.add_view(ModelView(GroupLabelAuthorization))
    admin.add_view(MasterZoneView(MasterZone))
    for cls in RR_CLASSES:
        admin.add_view(RRView(cls, name=cls.__name__, label=cls.__name__))

    admin.mount_to(app)
