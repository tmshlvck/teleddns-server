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
from starlette_admin import PasswordField, EmailField, RelationField
from starlette_admin._types import RequestAction
from starlette.middleware import Middleware
from starlette.middleware.sessions import SessionMiddleware

from teleddns_server.model import *
from teleddns_server.auth import AdminAuthProvider
from teleddns_server.view import trigger_background_sync

from starlette_admin.helpers import pydantic_error_to_form_validation_errors
from pydantic import ValidationError
from starlette_admin.exceptions import FormValidationError
from typing import Type
from starlette_admin.contrib.sqla.converters import BaseSQLAModelConverter

class ExtendedModelView(ModelView):
    async def before_create(self, request: Request, data: dict, obj: Any) -> None:
        """Hook called before creating a new object."""
        print("PARRENT HOOK CALL")
        if hasattr(obj, 'last_update_info'):
            client_ip = request.client.host if request.client else "unknown"
            obj.last_update_info = f"Admin {client_ip}"

    async def before_edit(self, request: Request, data: dict, obj: Any) -> None:
        """Hook called before editing an existing object."""
        if hasattr(obj, 'last_update_info'):
            client_ip = request.client.host if request.client else "unknown"
            obj.last_update_info = f"Admin {client_ip}"

    async def _arrange_data(
            self,
            request: Request,
            data: Dict[str, Any],
            is_edit: bool = False,
    ) -> Dict[str, Any]:
        """
        This function will return a new dict with relationships loaded from
        database.
        """
        arranged_data: Dict[str, Any] = {}
        for field in self.get_fields_list(request, request.state.action):
            if isinstance(field, RelationField) and data[field.name] is not None:
                foreign_model = self._find_foreign_model(field.identity)  # type: ignore
                if not field.multiple:
                    arranged_data[field.name] = await foreign_model.find_by_pk(
                        request, data[field.name]
                    )
                    arranged_data[f"{field.name}_id"] = arranged_data[field.name].id
                else:
                    arranged_data[field.name] = await foreign_model.find_by_pks(
                        request, data[field.name]
                    )
            else:
                arranged_data[field.name] = data[field.name]
        return arranged_data

    def handle_exception(self, exc: Exception) -> None:
        logging.exception("ExtendedModelView: ")
        if isinstance(exc, ValidationError):
                raise pydantic_error_to_form_validation_errors(exc)
        return super().handle_exception(exc)  # pragma: no cover

    def __init__(
            self,
            model: Type[Any],
            icon: Optional[str] = None,
            name: Optional[str] = None,
            label: Optional[str] = None,
            identity: Optional[str] = None,
            converter: Optional[BaseSQLAModelConverter] = None,
        ):

        orig_model = model
        super().__init__(model, icon, name, label, identity, converter)
        for f in self.fields:
            if f.type == 'HasOne':
                if orig_model.model_fields.get(f"{f.name}_id"):
                    if orig_model.model_fields.get(f"{f.name}_id").is_required(): # based on pydantic model
                        f.required = True
                    if not orig_model.model_fields.get(f"{f.name}_id").nullable: # based on Field(..., nullable=False)
                        f.required = True

    async def validate(self, request: Request, data: Dict[str, Any]) -> None:
        errors: Dict[str, str] = {}

        for f in self.get_fields_list(request, request.state.action):
                if isinstance(f, RelationField) and f.required:
                    if data.get(f.name, None) is None:
                        errors[f.name] = f"Field {f.label} is required"

        if len(errors) > 0:
            raise FormValidationError(errors)

        return await super().validate(request, data)


class RRView(ExtendedModelView):
    sortable_fields = ["label", "zone"]
    sortable_fields_mapping = { "zone": MasterZone.id, }
    exclude_fields_from_create = ["id"]
    exclude_fields_from_list = ["id"]
    exclude_fields_from_edit = ["id"]

    async def before_create(self, request: Request, data: dict, obj: Any) -> None:
        # Call parent hook for last_update_info
        await super().before_create(request, data, obj)

    async def before_edit(self, request: Request, data: dict, obj: Any) -> None:
        # Call parent hook for last_update_info
        await super().before_edit(request, data, obj)

    async def after_create(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            rr = session.merge(obj)
            rr.zone.content_dirty = True
            session.commit()
            trigger_background_sync()

    async def after_edit(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            rr = session.merge(obj)
            rr.zone.content_dirty = True
            session.commit()
        trigger_background_sync()

    async def after_delete(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            zone_id = obj.zone_id
            zone = session.get(MasterZone, zone_id)
            if zone:
                zone.content_dirty = True
                session.commit()
        trigger_background_sync()


class EmptyPasswordField(PasswordField):
    """Custom password field that displays empty in edit forms"""

    async def serialize_value(self, request: Request, value: Any, action: RequestAction) -> Any:
        """Override to return empty string in edit forms"""
        if action == RequestAction.EDIT:
            return ""
        return await super().serialize_value(request, value, action)

class UserView(ExtendedModelView):
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
        "last_update_info",
    ]

    async def before_create(self, request: Request, data: Dict[str, Any], obj: Any) -> None:
        # Call parent hook for last_update_info
        await super().before_create(request, data, obj)

        # Handle empty email field - convert empty string to None to avoid unique constraint issues
        if obj.email is not None and obj.email.strip() == '':
            obj.email = None
        if obj.password and len(obj.password.strip()) > 2:
            obj.password = obj.gen_hash(obj.password)

    async def before_edit(self, request: Request, data: Dict[str, Any], obj: Any) -> None:
        # Call parent hook for last_update_info
        await super().before_edit(request, data, obj)

        # Handle empty email field - convert empty string to None to avoid unique constraint issues
        if data.get('email') is not None and data['email'].strip() == '':
            obj.email = None
        # Handle password field
        if data.get('password') and len(data['password'].strip()) > 2:
            obj.password = obj.gen_hash(data['password'])
        else:
            existing_user = await self.find_by_pk(request, obj.id)
            obj.password = existing_user.password


class ServerView(ExtendedModelView):
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
        "last_update_info",
    ]

    async def before_create(self, request: Request, data: dict, obj: Any) -> None:
        # Call parent hook for last_update_info
        await super().before_create(request, data, obj)

    async def before_edit(self, request: Request, data: dict, obj: Any) -> None:
       # Call parent hook for last_update_info
       await super().before_edit(request, data, obj)

    async def after_create(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            server = session.merge(obj)
            server.config_dirty = True
            session.commit()
        trigger_background_sync()

    async def after_edit(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            server = session.merge(obj)
            server.config_dirty = True
            session.commit()
        trigger_background_sync()

    async def after_delete(self, request: Request, obj: Any) -> None:
        # For server deletion, we need to mark all related zones as dirty
        with Session(engine) as session:
            # Mark all master zones that were using this server
            master_zones = session.query(MasterZone).filter(MasterZone.master_server_id == obj.id).all()
            for zone in master_zones:
                zone.content_dirty = True
            # Mark all slave zones that were using this server
            slave_zones = session.query(MasterZone).join(SlaveZoneServer).filter(SlaveZoneServer.server_id == obj.id).all()
            for zone in slave_zones:
                zone.content_dirty = True
            session.commit()
        trigger_background_sync()


class MasterZoneView(ExtendedModelView):
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
        "last_update_info",
        ]
    exclude_fields_from_create = ["id", "last_content_sync", "created_at", "updated_at"]
    exclude_fields_from_list = ["id"]
    exclude_fields_from_edit = ["id", "created_at", "updated_at"]

    async def before_create(self, request: Request, data: dict, obj: Any) -> None:
        # Call parent hook for last_update_info
        await super().before_create(request, data, obj)

    async def before_edit(self, request: Request, data: dict, obj: Any) -> None:
        # Call parent hook for last_update_info
        await super().before_edit(request, data, obj)

    async def after_create(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            zone = session.merge(obj)
            zone.content_dirty = True
            if zone.master_server:
                zone.master_server.config_dirty = True
            for slave_server in zone.slave_servers:
                slave_server.config_dirty = True
            session.commit()
        trigger_background_sync()

    async def after_edit(self, request: Request, obj: Any) -> None:
        with Session(engine) as session:
            zone = session.merge(obj)
            zone.content_dirty = True
            if zone.master_server:
                zone.master_server.config_dirty = True
            for slave_server in zone.slave_servers:
                slave_server.config_dirty = True
            session.commit()
        trigger_background_sync()

    async def after_delete(self, request: Request, obj: Any) -> None:
        # When a zone is deleted, mark related servers as dirty
        with Session(engine) as session:
            # Mark master server as dirty if it was assigned
            if obj.master_server_id:
                master_server = session.get(Server, obj.master_server_id)
                if master_server:
                    master_server.config_dirty = True
            # Mark all slave servers as dirty
            slave_server_links = session.query(SlaveZoneServer).filter(SlaveZoneServer.zone_id == obj.id).all()
            for link in slave_server_links:
                slave_server = session.get(Server, link.server_id)
                if slave_server:
                    slave_server.config_dirty = True
            session.commit()
        trigger_background_sync()


def add_admin(app):
    admin = Admin(engine, title="Telephant DDNS admin",
                  auth_provider=AdminAuthProvider(allow_paths=["/statics/logo.svg"]),
                  middlewares=[Middleware(SessionMiddleware, secret_key=settings.SESSION_SECRET)],)

    admin.add_view(ServerView(Server))
    admin.add_view(UserView(User))
    admin.add_view(ExtendedModelView(UserToken))
    admin.add_view(ExtendedModelView(UserPassKey))
    admin.add_view(ExtendedModelView(Group))
    admin.add_view(ExtendedModelView(UserLabelAuthorization))
    admin.add_view(ExtendedModelView(GroupLabelAuthorization))
    admin.add_view(MasterZoneView(MasterZone))
    for cls in RR_CLASSES:
        admin.add_view(RRView(cls, name=cls.__name__, label=cls.__name__))

    admin.mount_to(app)
