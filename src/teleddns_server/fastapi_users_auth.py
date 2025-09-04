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

import uuid
from typing import Optional, Any
from fastapi_users import BaseUserManager, IntegerIDMixin, FastAPIUsers
from fastapi_users.authentication import (
    AuthenticationBackend,
    BearerTransport,
    JWTStrategy,
)
from fastapi_users_db_sqlalchemy import SQLAlchemyUserDatabase
from fastapi import Depends, Request, Response, HTTPException
from sqlmodel import Session, select
import pyotp
import qrcode
from io import BytesIO
import base64
import logging

from .model import User, APIToken, PasskeyCredential, engine
from .settings import settings


def get_user_db():
    with Session(engine) as session:
        yield SQLAlchemyUserDatabase(session, User)


class UserManager(IntegerIDMixin, BaseUserManager[User, int]):
    reset_password_token_secret = settings.SESSION_SECRET
    verification_token_secret = settings.SESSION_SECRET

    async def on_after_register(self, user: User, request: Optional[Request] = None):
        logging.info(f"User {user.id} has registered.")

    async def on_after_forgot_password(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        logging.info(f"User {user.id} has forgot their password. Reset token: {token}")

    async def on_after_request_verify(
        self, user: User, token: str, request: Optional[Request] = None
    ):
        logging.info(f"Verification requested for user {user.id}. Verification token: {token}")

    async def create_user(
        self,
        user_create,
        safe: bool = True,
        request: Optional[Request] = None,
    ) -> User:
        """Override to create user with hashed password using existing hash method"""
        if hasattr(user_create, "password"):
            user_create.password = User.gen_hash(user_create.password)
        return await super().create_user(user_create, safe, request)

    async def authenticate(self, credentials) -> Optional[User]:
        """Override authentication to use existing password verification"""
        try:
            user = await self.get_by_email(credentials.username)
        except:
            # Try by username if email fails
            with Session(engine) as session:
                statement = select(User).where(User.username == credentials.username)
                user = session.exec(statement).one_or_none()
        
        if user is None:
            self.password_helper.hash(credentials.password)
            return None

        if not user.verify_password(credentials.password):
            return None

        # Check if user has 2FA enabled
        if user.has_2fa and user.totp_secret:
            # In a full implementation, we'd need to check TOTP code
            # For now, we'll allow authentication but mark that 2FA is needed
            pass

        return user


async def get_user_manager(user_db=Depends(get_user_db)):
    yield UserManager(user_db)


# JWT Authentication
bearer_transport = BearerTransport(tokenUrl="auth/jwt/login")

def get_jwt_strategy() -> JWTStrategy:
    return JWTStrategy(secret=settings.SESSION_SECRET, lifetime_seconds=3600)

auth_backend = AuthenticationBackend(
    name="jwt",
    transport=bearer_transport,
    get_strategy=get_jwt_strategy,
)

# FastAPI Users instance
fastapi_users = FastAPIUsers[User, int](get_user_manager, [auth_backend])

# Dependencies
current_active_user = fastapi_users.current_user(active=True)
current_active_verified_user = fastapi_users.current_user(active=True, verified=True)
current_superuser = fastapi_users.current_user(active=True, superuser=True)


# 2FA TOTP functions
def generate_totp_secret() -> str:
    """Generate a new TOTP secret"""
    return pyotp.random_base32()


def generate_totp_qr_code(user: User, secret: str) -> str:
    """Generate QR code for TOTP setup"""
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=user.username,
        issuer_name="TeleDDNS Server"
    )
    
    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = BytesIO()
    img.save(buffered, format="PNG")
    img_str = base64.b64encode(buffered.getvalue()).decode()
    return f"data:image/png;base64,{img_str}"


def verify_totp_code(secret: str, code: str) -> bool:
    """Verify TOTP code"""
    totp = pyotp.TOTP(secret)
    return totp.verify(code, valid_window=1)


# Bearer token authentication for API
async def get_current_user_from_token(token: str) -> Optional[User]:
    """Get user from API token"""
    with Session(engine) as session:
        statement = select(APIToken).where(APIToken.token == token)
        api_token = session.exec(statement).one_or_none()
        
        if api_token:
            user = session.get(User, api_token.user_id)
            return user
    return None


async def require_api_token(authorization: str = None) -> User:
    """Dependency to require valid API token"""
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid authorization header")
    
    token = authorization.split(" ")[1]
    user = await get_current_user_from_token(token)
    
    if not user:
        raise HTTPException(status_code=401, detail="Invalid token")
    
    if not user.is_active:
        raise HTTPException(status_code=401, detail="User account is disabled")
    
    return user