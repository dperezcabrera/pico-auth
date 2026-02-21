"""REST API controllers for auth endpoints."""

from typing import Any

from fastapi import Body
from pico_client_auth import SecurityContext, allow_anonymous, requires_role
from pico_fastapi import controller, delete, get, post, put

from pico_auth.errors import AuthError
from pico_auth.jwt_provider import JWTProvider
from pico_auth.service import AuthService, GroupService


@controller(prefix="/api/v1/auth", tags=["auth"])
class AuthController:
    """Auth endpoints: register, login, refresh, profile, admin."""

    def __init__(self, service: AuthService, jwt_provider: JWTProvider):
        self._service = service
        self._jwt = jwt_provider

    @post("/register")
    @allow_anonymous
    async def register(
        self,
        email: str = Body(...),
        password: str = Body(...),
        display_name: str = Body(""),
    ) -> dict[str, Any]:
        try:
            user = await self._service.register(email, password, display_name)
            return {
                "id": user.id,
                "email": user.email,
                "role": user.role,
                "status": user.status,
            }
        except AuthError as exc:
            return {"error": exc.message}

    @post("/login")
    @allow_anonymous
    async def login(
        self,
        email: str = Body(...),
        password: str = Body(...),
    ) -> dict[str, Any]:
        try:
            return await self._service.login(email, password)
        except AuthError as exc:
            return {"error": exc.message}

    @post("/refresh")
    @allow_anonymous
    async def refresh(
        self,
        refresh_token: str = Body(...),
    ) -> dict[str, Any]:
        try:
            return await self._service.refresh(refresh_token)
        except AuthError as exc:
            return {"error": exc.message}

    @get("/me")
    async def me(self) -> dict[str, Any]:
        claims = SecurityContext.require()
        try:
            user = await self._service.get_profile(claims.sub)
            return {
                "id": user.id,
                "email": user.email,
                "display_name": user.display_name,
                "role": user.role,
                "org_id": user.org_id,
                "status": user.status,
                "created_at": user.created_at,
                "last_login_at": user.last_login_at,
            }
        except AuthError as exc:
            return {"error": exc.message}

    @post("/me/password")
    async def change_password(
        self,
        old_password: str = Body(...),
        new_password: str = Body(...),
    ) -> dict[str, Any]:
        claims = SecurityContext.require()
        try:
            await self._service.change_password(
                claims.sub,
                old_password,
                new_password,
            )
            return {"message": "Password changed"}
        except AuthError as exc:
            return {"error": exc.message}

    @get("/users")
    @requires_role("superadmin", "org_admin")
    async def list_users(self) -> dict[str, Any]:
        users = await self._service.list_users()
        return {
            "users": [
                {
                    "id": u.id,
                    "email": u.email,
                    "display_name": u.display_name,
                    "role": u.role,
                    "org_id": u.org_id,
                    "status": u.status,
                }
                for u in users
            ],
            "total": len(users),
        }

    @put("/users/{user_id}/role")
    @requires_role("superadmin", "org_admin")
    async def update_role(
        self,
        user_id: str,
        role: str = Body(...),
    ) -> dict[str, Any]:
        try:
            user = await self._service.update_role(user_id, role)
            return {"id": user.id, "email": user.email, "role": user.role}
        except AuthError as exc:
            return {"error": exc.message}

    @get("/jwks")
    @allow_anonymous
    async def jwks(self) -> dict[str, Any]:
        return self._jwt.jwks()


@controller(prefix="/api/v1/groups", tags=["groups"])
class GroupController:
    """Group management endpoints."""

    def __init__(self, service: GroupService):
        self._service = service

    @post("")
    @requires_role("superadmin", "org_admin")
    async def create_group(
        self,
        name: str = Body(...),
        description: str = Body(""),
    ) -> dict[str, Any]:
        claims = SecurityContext.require()
        try:
            group = await self._service.create_group(name, claims.org_id, description)
            return {"id": group.id, "name": group.name, "org_id": group.org_id}
        except AuthError as exc:
            return {"error": exc.message}

    @get("")
    async def list_groups(self) -> dict[str, Any]:
        claims = SecurityContext.require()
        groups = await self._service.list_groups(claims.org_id)
        return {
            "groups": [
                {"id": g.id, "name": g.name, "description": g.description, "org_id": g.org_id}
                for g in groups
            ],
            "total": len(groups),
        }

    @get("/{group_id}")
    async def get_group(self, group_id: str) -> dict[str, Any]:
        try:
            group = await self._service.get_group(group_id)
            members = await self._service.get_members(group_id)
            return {
                "id": group.id,
                "name": group.name,
                "description": group.description,
                "org_id": group.org_id,
                "members": [{"user_id": m.user_id, "joined_at": m.joined_at} for m in members],
            }
        except AuthError as exc:
            return {"error": exc.message}

    @put("/{group_id}")
    @requires_role("superadmin", "org_admin")
    async def update_group(
        self,
        group_id: str,
        name: str = Body(None),
        description: str = Body(None),
    ) -> dict[str, Any]:
        try:
            group = await self._service.update_group(group_id, name, description)
            return {"id": group.id, "name": group.name, "description": group.description}
        except AuthError as exc:
            return {"error": exc.message}

    @delete("/{group_id}")
    @requires_role("superadmin", "org_admin")
    async def delete_group(self, group_id: str) -> dict[str, Any]:
        try:
            await self._service.delete_group(group_id)
            return {"message": "Group deleted"}
        except AuthError as exc:
            return {"error": exc.message}

    @post("/{group_id}/members")
    @requires_role("superadmin", "org_admin")
    async def add_member(
        self,
        group_id: str,
        user_id: str = Body(...),
    ) -> dict[str, Any]:
        try:
            await self._service.add_member(group_id, user_id)
            return {"message": "Member added"}
        except AuthError as exc:
            return {"error": exc.message}

    @delete("/{group_id}/members/{user_id}")
    @requires_role("superadmin", "org_admin")
    async def remove_member(self, group_id: str, user_id: str) -> dict[str, Any]:
        try:
            await self._service.remove_member(group_id, user_id)
            return {"message": "Member removed"}
        except AuthError as exc:
            return {"error": exc.message}


@controller(prefix="/.well-known", tags=["oidc"])
class OIDCController:
    """OIDC discovery endpoint."""

    def __init__(self, jwt_provider: JWTProvider):
        self._jwt = jwt_provider

    @get("/openid-configuration")
    @allow_anonymous
    async def openid_configuration(self) -> dict[str, Any]:
        return self._jwt.openid_configuration()
