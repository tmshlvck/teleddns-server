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

from starlette.requests import Request
from starlette.responses import Response
from starlette_admin.auth import AdminConfig, AdminUser, AuthProvider
from starlette_admin.exceptions import FormValidationError, LoginFailed

from .view import verify_user

class AdminAuthProvider(AuthProvider):
    async def login(self, username: str, password: str, remember_me: bool,
                    request: Request, response: Response) -> Response:
        if len(username) < 2:
            raise FormValidationError(
                {"username": "Ensure username has at least 3 characters"}
            )

        if user := verify_user(username, password):
            if user.is_admin:
                request.session.update({"username": user.username})
                return response

        raise LoginFailed("Invalid username or password")

    async def is_authenticated(self, request) -> bool:
        if request.session.get("username", None):
            return True
        else:
            return False

    def get_admin_config(self, request: Request) -> AdminConfig:
        return AdminConfig(app_title=f"Hello, {request.session.get("username", None)}!")

    def get_admin_user(self, request: Request) -> AdminUser:
        return AdminUser(username=request.session.get("username", None))

    async def logout(self, request: Request, response: Response) -> Response:
        request.session.clear()
        return response
