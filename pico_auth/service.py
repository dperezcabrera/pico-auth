"""Auth business logic: register, login, refresh, profile, roles."""

import hashlib
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from pico_ioc import component

from pico_auth.config import AuthSettings
from pico_auth.errors import (
    AuthError,
    InvalidCredentialsError,
    TokenExpiredError,
    TokenInvalidError,
    UserExistsError,
    UserNotFoundError,
    UserSuspendedError,
)
from pico_auth.jwt_provider import JWTProvider
from pico_auth.models import RefreshToken, User
from pico_auth.passwords import PasswordService
from pico_auth.repository import RefreshTokenRepository, UserRepository

VALID_ROLES = frozenset({"superadmin", "org_admin", "operator", "viewer"})


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _hash_token(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()


def _build_refresh_token(user_id: str, raw_token: str, expire_days: int) -> RefreshToken:
    return RefreshToken(
        id=uuid4().hex[:12],
        user_id=user_id,
        token_hash=_hash_token(raw_token),
        expires_at=(datetime.now(timezone.utc) + timedelta(days=expire_days)).isoformat(),
        created_at=_now_iso(),
    )


@component
class AuthService:
    """Core auth operations."""

    def __init__(
        self,
        users: UserRepository,
        tokens: RefreshTokenRepository,
        passwords: PasswordService,
        jwt_provider: JWTProvider,
        settings: AuthSettings,
    ):
        self._users = users
        self._tokens = tokens
        self._passwords = passwords
        self._jwt = jwt_provider
        self._settings = settings

    async def register(
        self,
        email: str,
        password: str,
        display_name: str,
        role: str = "viewer",
    ) -> User:
        existing = await self._users.find_by_email(email)
        if existing:
            raise UserExistsError(email)

        user = User(
            id=uuid4().hex[:12],
            email=email,
            display_name=display_name,
            password_hash=self._passwords.hash(password),
            role=role,
            org_id="default",
            status="active",
            created_at=_now_iso(),
        )
        await self._users.save(user)
        return user

    async def login(self, email: str, password: str) -> dict:
        user = await self._users.find_by_email(email)
        if not user or not self._passwords.verify(password, user.password_hash):
            raise InvalidCredentialsError()
        if user.status == "suspended":
            raise UserSuspendedError()

        await self._users.update_last_login(user.id, _now_iso())

        access_token = self._jwt.create_access_token(
            user.id,
            user.email,
            user.role,
            user.org_id,
        )
        raw_refresh = self._jwt.create_refresh_token()
        refresh = _build_refresh_token(
            user.id, raw_refresh, self._settings.refresh_token_expire_days
        )
        await self._tokens.save(refresh)

        return {
            "access_token": access_token,
            "refresh_token": raw_refresh,
            "token_type": "Bearer",
            "expires_in": self._settings.access_token_expire_minutes * 60,
        }

    async def refresh(self, raw_refresh_token: str) -> dict:
        stored = await self._tokens.find_by_hash(_hash_token(raw_refresh_token))
        if not stored:
            raise TokenInvalidError()

        if datetime.fromisoformat(stored.expires_at) < datetime.now(timezone.utc):
            await self._tokens.delete_by_hash(stored.token_hash)
            raise TokenExpiredError()

        user = await self._users.find_by_id(stored.user_id)
        if not user:
            raise TokenInvalidError()

        # Rotate: delete old, create new
        await self._tokens.delete_by_hash(stored.token_hash)
        new_raw = self._jwt.create_refresh_token()
        new_refresh = _build_refresh_token(
            user.id, new_raw, self._settings.refresh_token_expire_days
        )
        await self._tokens.save(new_refresh)

        access_token = self._jwt.create_access_token(
            user.id,
            user.email,
            user.role,
            user.org_id,
        )
        return {
            "access_token": access_token,
            "refresh_token": new_raw,
            "token_type": "Bearer",
            "expires_in": self._settings.access_token_expire_minutes * 60,
        }

    async def get_profile(self, user_id: str) -> User:
        user = await self._users.find_by_id(user_id)
        if not user:
            raise UserNotFoundError(user_id)
        return user

    async def change_password(
        self,
        user_id: str,
        old_password: str,
        new_password: str,
    ) -> None:
        user = await self._users.find_by_id(user_id)
        if not user:
            raise UserNotFoundError(user_id)
        if not self._passwords.verify(old_password, user.password_hash):
            raise InvalidCredentialsError()
        await self._users.update_password(user_id, self._passwords.hash(new_password))
        await self._tokens.delete_by_user(user_id)

    async def list_users(self) -> list[User]:
        return await self._users.list_all()

    async def update_role(self, user_id: str, role: str) -> User:
        if role not in VALID_ROLES:
            raise AuthError(f"Invalid role: {role}")
        user = await self._users.update_role(user_id, role)
        if not user:
            raise UserNotFoundError(user_id)
        return user

    async def ensure_admin(self, email: str, password: str) -> None:
        """Create the initial admin if it does not exist."""
        existing = await self._users.find_by_email(email)
        if existing:
            return
        await self.register(email, password, "Admin", role="superadmin")
