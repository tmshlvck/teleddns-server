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

from typing import Dict, Any, Awaitable

from fastapi.responses import RedirectResponse

from starlette_admin.contrib.sqlmodel import Admin, ModelView
from starlette_admin.views import Link, CustomView
from starlette_admin import PasswordField, EmailField, action, row_action, RowActionsDisplayType
from starlette_admin.exceptions import ActionFailed
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

from teleddns_server.model import *
from teleddns_server.auth import AdminAuthProvider

from teleddns_server.view import mark_zone_for_update, mark_server_for_config_update, run_check_zone, extract_zone_data, extract_server_config_data


class RRView(ModelView):
    sortable_fields = ["label", "zone"]
    sortable_fields_mapping = { "zone": Zone.id, }
    exclude_fields_from_create = ["id"]
    exclude_fields_from_list = ["id", "placeholder"]
    exclude_fields_from_edit = ["id"]
    
    async def after_create(self, request: Request, obj: Any) -> None:
        self._mark_zone_dirty(obj.zone_id)

    async def after_edit(self, request: Request, obj: Any) -> None:
        self._mark_zone_dirty(obj.zone_id)

    async def after_delete(self, request: Request, obj: Any) -> None:
        self._mark_zone_dirty(obj.zone_id)
        
    def _mark_zone_dirty(self, zone_id: int):
        """Mark zone as needing update"""
        mark_zone_for_update(zone_id)


class UserView(ModelView):
    fields = [
        "id",
        "username",
        PasswordField("password", exclude_from_list=True, ),
        "is_admin",
        "has_2fa",
        "has_passkey",
        "created_at",
        "updated_at",
    ]

    async def before_create(self, request: Request, data: Dict[str, Any], obj: Any) -> None:
        obj.password = obj.gen_hash(obj.password)

    async def before_edit(self, request: Request, data: Dict[str, Any], obj: Any) -> None:
        obj.password = obj.gen_hash(obj.password)


class ServerView(ModelView):
    fields = [
        "id",
        "name",
        "api_url",
        "api_key",
        "master_template",
        "needs_config_update",
        "config_last_updated",
        "created_at",
        "updated_at",
    ]
    
    async def after_create(self, request: Request, obj: Any) -> None:
        mark_server_for_config_update(obj.id)
        
    async def after_edit(self, request: Request, obj: Any) -> None:
        mark_server_for_config_update(obj.id)



class GroupView(ModelView):
    fields = [
        "id",
        "name", 
        "description",
        "created_at",
        "updated_at",
    ]
    exclude_fields_from_create = ["id", "created_at", "updated_at"]
    exclude_fields_from_edit = ["id", "created_at", "updated_at"]


class ZoneView(ModelView):
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
        "server_id",
        "user_id",
        "group_id",
        "needs_update",
        "last_updated",
        "created_at",
        "updated_at",
        ]
    
    async def after_create(self, request: Request, obj: Any) -> None:
        self._mark_zone_dirty(obj.id)

    async def after_edit(self, request: Request, obj: Any) -> None:
        self._mark_zone_dirty(obj.id)

    async def after_delete(self, request: Request, obj: Any) -> None:
        if obj.server_id:
            mark_server_for_config_update(obj.server_id)
            
    def _mark_zone_dirty(self, zone_id: int):
        """Mark zone as needing update"""
        mark_zone_for_update(zone_id)


def add_admin(app):
    admin = Admin(engine, title="Telephant DDNS admin",
                  auth_provider=AdminAuthProvider(allow_paths=["/statics/logo.svg"]),
                  middlewares=[Middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)],)

    admin.add_view(ServerView(Server))
    admin.add_view(UserView(User))
    admin.add_view(GroupView(Group))
    admin.add_view(ModelView(APIToken))
    admin.add_view(ZoneView(Zone))
    for cls in RR_CLASSES:
        admin.add_view(RRView(cls, name=cls.__name__, label=cls.__name__))
    
    admin.mount_to(app)