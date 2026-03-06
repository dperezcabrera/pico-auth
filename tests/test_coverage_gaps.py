"""Tests covering uncovered code paths in pico-auth."""

import pytest
from fastapi import FastAPI
from pico_boot import init
from pico_ioc import DictSource, configuration

from pico_auth.passwords import PasswordService
from pico_auth.service import AuthService

API = "/api/v1/auth"


@pytest.fixture
def service(container):
    return container.get(AuthService)


# ===================================================================
# Registration: duplicate email returns error detail
# ===================================================================


@pytest.mark.asyncio
class TestRegisterDuplicateDetail:
    async def test_duplicate_returns_error_with_message(self, client):
        await client.post(
            f"{API}/register",
            json={"email": "dup@example.com", "password": "pass", "display_name": "Dup"},
        )
        resp = await client.post(
            f"{API}/register",
            json={"email": "dup@example.com", "password": "pass2", "display_name": "Dup2"},
        )
        data = resp.json()
        assert "error" in data
        assert "dup@example.com" in data["error"]


# ===================================================================
# Login: full flow and suspended user
# ===================================================================


@pytest.mark.asyncio
class TestLoginCoverage:
    async def test_login_returns_full_token_response(self, client):
        await client.post(
            f"{API}/register",
            json={"email": "login@cov.com", "password": "pass"},
        )
        resp = await client.post(
            f"{API}/login",
            json={"email": "login@cov.com", "password": "pass"},
        )
        data = resp.json()
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 15 * 60
        assert "access_token" in data
        assert "refresh_token" in data


# ===================================================================
# Refresh: full rotation flow
# ===================================================================


@pytest.mark.asyncio
class TestRefreshCoverage:
    async def _register_login(self, client, email):
        await client.post(
            f"{API}/register",
            json={"email": email, "password": "pass"},
        )
        resp = await client.post(
            f"{API}/login",
            json={"email": email, "password": "pass"},
        )
        return resp.json()

    async def test_refresh_returns_new_token_pair(self, client):
        tokens = await self._register_login(client, "refresh@cov.com")
        resp = await client.post(f"{API}/refresh", json=tokens["refresh_token"])
        data = resp.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["refresh_token"] != tokens["refresh_token"]

    async def test_refresh_invalid_returns_error(self, client):
        resp = await client.post(f"{API}/refresh", json="nonexistent-token")
        assert "error" in resp.json()


# ===================================================================
# Profile: success response fields
# ===================================================================


@pytest.mark.asyncio
class TestProfileCoverage:
    async def test_me_returns_all_fields(self, client):
        await client.post(
            f"{API}/register",
            json={"email": "me@cov.com", "password": "pass", "display_name": "Me"},
        )
        login_resp = await client.post(
            f"{API}/login",
            json={"email": "me@cov.com", "password": "pass"},
        )
        token = login_resp.json()["access_token"]

        resp = await client.get(
            f"{API}/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        assert data["email"] == "me@cov.com"
        assert data["display_name"] == "Me"
        assert data["role"] == "viewer"
        assert "id" in data
        assert "org_id" in data
        assert "status" in data
        assert "created_at" in data
        assert "last_login_at" in data


# ===================================================================
# Change password: success path and token invalidation
# ===================================================================


@pytest.mark.asyncio
class TestChangePasswordCoverage:
    async def test_change_password_returns_message(self, client):
        await client.post(
            f"{API}/register",
            json={"email": "chp@cov.com", "password": "old"},
        )
        login_resp = await client.post(
            f"{API}/login",
            json={"email": "chp@cov.com", "password": "old"},
        )
        token = login_resp.json()["access_token"]

        resp = await client.post(
            f"{API}/me/password",
            json={"old_password": "old", "new_password": "new"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json()["message"] == "Password changed"


# ===================================================================
# Admin: update role success, invalid role, viewer forbidden
# ===================================================================


@pytest.mark.asyncio
class TestAdminCoverage:
    async def _admin_login(self, client, service):
        await service.ensure_admin("admcov@test.com", "adminpass")
        resp = await client.post(
            f"{API}/login",
            json={"email": "admcov@test.com", "password": "adminpass"},
        )
        return resp.json()["access_token"]

    async def test_update_role_returns_updated_user(self, client, service):
        admin_token = await self._admin_login(client, service)

        reg_resp = await client.post(
            f"{API}/register",
            json={"email": "role@cov.com", "password": "pass"},
        )
        user_id = reg_resp.json()["id"]

        resp = await client.put(
            f"{API}/users/{user_id}/role",
            json="operator",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        data = resp.json()
        assert data["role"] == "operator"
        assert data["email"] == "role@cov.com"

    async def test_update_role_invalid_role(self, client, service):
        admin_token = await self._admin_login(client, service)

        reg_resp = await client.post(
            f"{API}/register",
            json={"email": "badrole@cov.com", "password": "pass"},
        )
        user_id = reg_resp.json()["id"]

        resp = await client.put(
            f"{API}/users/{user_id}/role",
            json="dictator",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert "error" in resp.json()
        assert "Invalid role" in resp.json()["error"]

    async def test_update_role_nonexistent_user(self, client, service):
        admin_token = await self._admin_login(client, service)

        resp = await client.put(
            f"{API}/users/nonexistent/role",
            json="operator",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        assert "error" in resp.json()

    async def test_update_role_as_viewer_forbidden(self, client):
        await client.post(
            f"{API}/register",
            json={"email": "noadm@cov.com", "password": "pass"},
        )
        login_resp = await client.post(
            f"{API}/login",
            json={"email": "noadm@cov.com", "password": "pass"},
        )
        token = login_resp.json()["access_token"]

        resp = await client.put(
            f"{API}/users/whatever/role",
            json="operator",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "detail" in resp.json()

    async def test_list_users_returns_details(self, client, service):
        admin_token = await self._admin_login(client, service)

        await client.post(
            f"{API}/register",
            json={"email": "list@cov.com", "password": "pass"},
        )

        resp = await client.get(
            f"{API}/users",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        data = resp.json()
        assert "users" in data
        assert "total" in data
        assert data["total"] >= 1


# ===================================================================
# Ensure admin: idempotent (existing user returns early)
# ===================================================================


@pytest.mark.asyncio
class TestEnsureAdmin:
    async def test_ensure_admin_idempotent(self, app, service):
        await service.ensure_admin("idempotent@test.com", "pass")
        await service.ensure_admin("idempotent@test.com", "pass")
        # No error = early return on second call

    async def test_ensure_admin_creates_superadmin(self, app, service):
        await service.ensure_admin("super@test.com", "pass")
        user = await service.get_profile((await service._users.find_by_email("super@test.com")).id)
        assert user.role == "superadmin"


# ===================================================================
# PasswordService edge cases
# ===================================================================


# ===================================================================
# Groups: coverage gaps (error paths, edge cases)
# ===================================================================


@pytest.mark.asyncio
class TestGroupServiceCoverage:
    async def _admin_login(self, client, service):
        await service.ensure_admin("grpcov@test.com", "adminpass")
        resp = await client.post(
            f"{API}/login",
            json={"email": "grpcov@test.com", "password": "adminpass"},
        )
        return resp.json()["access_token"]

    def _auth(self, token):
        return {"Authorization": f"Bearer {token}"}

    async def test_update_nonexistent_group(self, client, service):
        token = await self._admin_login(client, service)
        resp = await client.put(
            "/api/v1/groups/nonexistent",
            json={"name": "Nope"},
            headers=self._auth(token),
        )
        assert "error" in resp.json()
        assert "not found" in resp.json()["error"].lower()

    async def test_delete_nonexistent_group(self, client, service):
        token = await self._admin_login(client, service)
        resp = await client.delete(
            "/api/v1/groups/nonexistent",
            headers=self._auth(token),
        )
        assert "error" in resp.json()

    async def test_add_member_nonexistent_group(self, client, service):
        token = await self._admin_login(client, service)
        resp = await client.post(
            "/api/v1/groups/nonexistent/members",
            json="some-user-id",
            headers=self._auth(token),
        )
        assert "error" in resp.json()

    async def test_add_member_nonexistent_user(self, client, service):
        token = await self._admin_login(client, service)
        # Create a real group
        create_resp = await client.post(
            "/api/v1/groups",
            json={"name": "CovGroup"},
            headers=self._auth(token),
        )
        group_id = create_resp.json()["id"]
        # Add nonexistent user
        resp = await client.post(
            f"/api/v1/groups/{group_id}/members",
            json="nonexistent-user",
            headers=self._auth(token),
        )
        assert "error" in resp.json()
        assert "not found" in resp.json()["error"].lower()

    async def test_add_duplicate_member(self, client, service):
        token = await self._admin_login(client, service)
        # Create group
        create_resp = await client.post(
            "/api/v1/groups",
            json={"name": "DupMemberGroup"},
            headers=self._auth(token),
        )
        group_id = create_resp.json()["id"]
        # Register user
        reg_resp = await client.post(
            f"{API}/register",
            json={"email": "dupmem@cov.com", "password": "pass"},
        )
        user_id = reg_resp.json()["id"]
        # Add once
        await client.post(
            f"/api/v1/groups/{group_id}/members",
            json=user_id,
            headers=self._auth(token),
        )
        # Add again → error
        resp = await client.post(
            f"/api/v1/groups/{group_id}/members",
            json=user_id,
            headers=self._auth(token),
        )
        assert "error" in resp.json()
        assert "already" in resp.json()["error"].lower()

    async def test_remove_nonexistent_member(self, client, service):
        token = await self._admin_login(client, service)
        # Create group
        create_resp = await client.post(
            "/api/v1/groups",
            json={"name": "RemNonGroup"},
            headers=self._auth(token),
        )
        group_id = create_resp.json()["id"]
        resp = await client.delete(
            f"/api/v1/groups/{group_id}/members/nonexistent",
            headers=self._auth(token),
        )
        assert "error" in resp.json()

    async def test_get_members_nonexistent_group(self, client, service):
        token = await self._admin_login(client, service)
        resp = await client.get(
            "/api/v1/groups/nonexistent",
            headers=self._auth(token),
        )
        assert "error" in resp.json()

    async def test_update_group_partial_name_only(self, client, service):
        token = await self._admin_login(client, service)
        create_resp = await client.post(
            "/api/v1/groups",
            json={"name": "PartialUpdate", "description": "Original"},
            headers=self._auth(token),
        )
        group_id = create_resp.json()["id"]
        # Update only name, not description
        resp = await client.put(
            f"/api/v1/groups/{group_id}",
            json={"name": "NewPartial"},
            headers=self._auth(token),
        )
        data = resp.json()
        assert data["name"] == "NewPartial"
        assert data["description"] == "Original"


# ===================================================================
# Suspended user login
# ===================================================================


@pytest.mark.asyncio
class TestSuspendedUser:
    async def test_login_suspended_user(self, app, service):
        user = await service.register("suspended@cov.com", "pass", "Susp")
        # Suspend the user via direct DB update
        async with service._users._sm.transaction() as session:
            from pico_auth.models import User

            u = await session.get(User, user.id)
            u.status = "suspended"
            await session.flush()
        from pico_auth.errors import UserSuspendedError

        with pytest.raises(UserSuspendedError):
            await service.login("suspended@cov.com", "pass")


# ===================================================================
# Expired refresh token
# ===================================================================


@pytest.mark.asyncio
class TestExpiredRefreshToken:
    async def test_refresh_expired_token(self, app, service):
        """Refresh with an expired token raises TokenExpiredError."""
        from datetime import UTC, datetime, timedelta

        from pico_auth.errors import TokenExpiredError

        user = await service.register("expired@cov.com", "pass", "Exp")
        tokens = await service.login("expired@cov.com", "pass")
        # Manually expire the stored refresh token
        import hashlib

        raw = tokens["refresh_token"]
        token_hash = hashlib.sha256(raw.encode()).hexdigest()
        stored = await service._tokens.find_by_hash(token_hash)
        stored.expires_at = (datetime.now(UTC) - timedelta(days=1)).isoformat()
        async with service._tokens._sm.transaction() as session:
            await session.merge(stored)

        with pytest.raises(TokenExpiredError):
            await service.refresh(raw)


# ===================================================================
# Refresh with deleted user
# ===================================================================


@pytest.mark.asyncio
class TestRefreshDeletedUser:
    async def test_refresh_token_for_deleted_user(self, app, service):
        """Refresh token valid but user no longer exists."""
        from pico_auth.errors import TokenInvalidError

        user = await service.register("ghost@cov.com", "pass", "Ghost")
        tokens = await service.login("ghost@cov.com", "pass")
        # Delete user directly via DB
        async with service._users._sm.transaction() as session:
            from sqlalchemy import delete as sql_delete

            from pico_auth.models import User

            await session.execute(sql_delete(User).where(User.id == user.id))

        with pytest.raises(TokenInvalidError):
            await service.refresh(tokens["refresh_token"])


# ===================================================================
# Service-level: get_profile and change_password for nonexistent user
# ===================================================================


@pytest.mark.asyncio
class TestServiceEdgeCases:
    async def test_get_profile_nonexistent(self, app, service):
        from pico_auth.errors import UserNotFoundError

        with pytest.raises(UserNotFoundError):
            await service.get_profile("no-such-id")

    async def test_change_password_nonexistent(self, app, service):
        from pico_auth.errors import UserNotFoundError

        with pytest.raises(UserNotFoundError):
            await service.change_password("no-such-id", "old", "new")

    async def test_admin_create_user_invalid_role(self, app, service):
        from pico_auth.errors import AuthError

        with pytest.raises(AuthError, match="Invalid role"):
            await service.admin_create_user("bad@cov.com", "pass", "Bad", role="dictator")


# ===================================================================
# Routes: admin_create_user duplicate email
# ===================================================================


@pytest.mark.asyncio
class TestAdminCreateUserDuplicate:
    async def _admin_login(self, client, service):
        await service.ensure_admin("admdup@test.com", "adminpass")
        resp = await client.post(
            f"{API}/login",
            json={"email": "admdup@test.com", "password": "adminpass"},
        )
        return resp.json()["access_token"]

    async def test_admin_create_duplicate_returns_error(self, client, service):
        token = await self._admin_login(client, service)
        headers = {"Authorization": f"Bearer {token}"}
        await client.post(
            f"{API}/users",
            json={"email": "admcreated@cov.com", "password": "pass"},
            headers=headers,
        )
        resp = await client.post(
            f"{API}/users",
            json={"email": "admcreated@cov.com", "password": "pass2"},
            headers=headers,
        )
        assert "error" in resp.json()


# ===================================================================
# Email credentials: unconfigured token
# ===================================================================


@pytest.mark.asyncio
class TestEmailCredsUnconfigured:
    async def test_no_token_configured_returns_403(self, tmp_path):
        """When email_credentials_token is empty, all requests get 403."""
        db_path = tmp_path / "test.db"
        auth_data = tmp_path / "auth-keys"
        config = configuration(
            DictSource(
                {
                    "auth": {
                        "data_dir": str(auth_data),
                        "access_token_expire_minutes": 15,
                        "refresh_token_expire_days": 7,
                        "issuer": "http://test",
                        "audience": "pico-bot",
                        "auto_create_admin": False,
                        "admin_email": "",
                        "admin_password": "",
                        "registration_enabled": True,
                        "email_credentials_token": "",
                    },
                    "database": {
                        "url": f"sqlite+aiosqlite:///{db_path}",
                        "echo": False,
                    },
                    "fastapi": {"title": "Test", "version": "0.1.0"},
                    "auth_client": {
                        "enabled": True,
                        "issuer": "http://test",
                        "audience": "pico-bot",
                    },
                }
            )
        )
        from pico_sqlalchemy import SessionManager

        from pico_auth.schema import create_tables

        container = init(modules=["pico_auth"], config=config)
        sm = container.get(SessionManager)
        await create_tables(sm)
        app = container.get(FastAPI)

        from httpx import ASGITransport, AsyncClient

        transport = ASGITransport(app=app)
        async with AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(
                "/api/v1/email-credentials/some-agent",
                headers={"Authorization": "Bearer any-token"},
            )
            assert resp.status_code == 403

    async def test_missing_bearer_prefix_returns_401(self, client):
        resp = await client.get(
            "/api/v1/email-credentials/some-agent",
            headers={"Authorization": "Token bad"},
        )
        assert resp.status_code == 401


class TestPasswordService:
    def test_verify_malformed_hash_returns_false(self):
        svc = PasswordService()
        assert svc.verify("password", "not-a-valid-bcrypt-hash") is False

    def test_verify_empty_hash_returns_false(self):
        svc = PasswordService()
        assert svc.verify("password", "") is False


# ===================================================================
# JWTProvider: key loading from existing files
# ===================================================================


@pytest.mark.asyncio
class TestJWTProviderKeyLoading:
    async def test_loads_existing_keys(self, tmp_path):
        """Second init should load keys from files (not regenerate)."""

        config = configuration(
            DictSource(
                {
                    "auth": {
                        "data_dir": str(tmp_path / "keys"),
                        "access_token_expire_minutes": 15,
                        "refresh_token_expire_days": 7,
                        "issuer": "http://test",
                        "audience": "pico-bot",
                        "auto_create_admin": False,
                        "admin_email": "",
                        "admin_password": "",
                    },
                    "database": {"url": "sqlite+aiosqlite:///unused.db", "echo": False},
                    "fastapi": {"title": "Test", "version": "0.1.0"},
                    "auth_client": {
                        "enabled": True,
                        "issuer": "http://test",
                        "audience": "pico-bot",
                    },
                }
            )
        )
        container1 = init(modules=["pico_auth"], config=config)
        from pico_auth.jwt_provider import JWTProvider

        provider1 = container1.get(JWTProvider)
        pub1 = provider1._public_key

        # Second init reads from files
        container2 = init(modules=["pico_auth"], config=config)
        provider2 = container2.get(JWTProvider)
        pub2 = provider2._public_key

        assert pub1 == pub2
