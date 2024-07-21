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

from teleddns_server.view import defer_update_zone, defer_update_config, run_check_zone


class RRView(ModelView):
    sortable_fields = ["label", "zone"]
    sortable_fields_mapping = { "zone": MasterZone.id, }
    exclude_fields_from_create = ["id"]
    exclude_fields_from_list = ["id"]
    exclude_fields_from_edit = ["id"]

#    async def after_create(self, request: Request, obj: Any) -> None:
#        await update_zone(obj.zone)
#
#    async def after_edit(self, request: Request, obj: Any) -> None:
#        await update_zone(obj.zone)
#
#    async def after_delete(self, request: Request, obj: Any) -> None:
#        await update_zone(obj.zone)


class UserView(ModelView):
    fields = [
        "id",
        "username",
        PasswordField("password", exclude_from_list=True, ),
        "is_admin",
        "access_rules",
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
        "slave_template",
        "master_zones",
        "slave_zones",
        "created_at",
        "updated_at",
    ]
    
    actions = ["update_many", "delete"]
    row_actions = ["update_one", "view", "edit", "delete"]
    #row_actions_display_type = RowActionsDisplayType.DROPDOWN

    @action(
        name="update_many",
        text="Push configs",
        confirmation="Are you sure you want to push config updates to selected servers?",
        submit_btn_text="Yes, proceed",
        submit_btn_class="btn-success",
    )
    async def update_many(self, request: Request, pks: List[Any]) -> str:
        #session = request.state.session
        affected = []
        for pk in pks:
            server: Server = await self.find_by_pk(request, pk)
            await defer_update_config(server)
            affected.append(server.name)
        return f"Started config update for servers {', '.join(affected)}"

    @row_action(
        name="update_one",
        text="Push config",
        confirmation="Are you sure you want to push config updates to the server?",
        icon_class="fas fa-cogs",
        submit_btn_text="Yes, proceed",
        submit_btn_class="btn-success",
        action_btn_class="btn-info",
    )
    async def update_one(self, request: Request, pk: Any) -> str:
        #session = request.state.session
        affected = []
        server: Server = await self.find_by_pk(request, pk)
        await defer_update_config(server)
        return f"Started config update for server {server.name}"



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
        "access_rules",
        "master_server",
        "slave_servers",
        "created_at",
        "updated_at",
        ]
    
    actions = ["update_many", "delete"]
    row_actions = ["check_one", "update_one", "view", "edit", "delete"]
    #row_actions_display_type = RowActionsDisplayType.DROPDOWN

    @action(
        name="update_many",
        text="Update Zones on Master Server",
        confirmation="Are you sure you want to Update Zones on Master Server?",
        submit_btn_text="Yes, proceed",
        submit_btn_class="btn-success",
    )
    async def update_many(self, request: Request, pks: List[Any]) -> str:
        #session = request.state.session
        affected = []
        for pk in pks:
            zone: MasterZone = await self.find_by_pk(request, pk)
            await defer_update_zone(zone)
            affected.append(zone.origin)
        return f"Started zone update for zones {', '.join(affected)}"

    @row_action(
        name="check_one",
        text="Check Zone on Master Server",
        icon_class="fas fa-check-circle",
        action_btn_class="btn-info",
    )
    async def check_one(self, request: Request, pk: Any) -> str:
        zone: MasterZone = await self.find_by_pk(request, pk)
        result = await run_check_zone(zone)
        sdo = result.get('stdout', '').replace("\n", "<br>")
        if result.get('retcode', 1) != 0:
            raise ActionFailed(f"Zone check failed for {zone.origin}:<br>{sdo}")
        else:
            return f"Zone check succeeded for {zone.origin}:<br>{sdo}"
    
    @row_action(
        name="update_one",
        text="Update Zones on Master Server",
        confirmation="Are you sure you want to Update Zone on Master Server?",
        icon_class="fas fa-cloud-upload-alt",
        submit_btn_text="Yes, proceed",
        submit_btn_class="btn-success",
        action_btn_class="btn-info",
    )
    async def update_one(self, request: Request, pk: Any) -> str:
        #session = request.state.session
        zone: MasterZone = await self.find_by_pk(request, pk)
        await defer_update_zone(zone)
        return f"Started zone update for zone {zone.origin}"

#    async def after_create(self, request: Request, obj: Any) -> None:
#        await update_config(obj)
#
#    async def after_edit(self, request: Request, obj: Any) -> None:
#        await update_config(obj)
#
#    async def after_delete(self, request: Request, obj: Any) -> None:
#        await update_config(obj)


def add_admin(app):
    admin = Admin(engine, title="Telephant DDNS admin",
                  auth_provider=AdminAuthProvider(allow_paths=["/statics/logo.svg"]),
                  middlewares=[Middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)],)

    admin.add_view(ServerView(Server))
    admin.add_view(UserView(User))
    admin.add_view(MasterZoneView(MasterZone))
    admin.add_view(ModelView(AccessRule))
    for cls in RR_CLASSES:
        admin.add_view(RRView(cls, name=cls.__name__, label=cls.__name__))
    
    admin.mount_to(app)