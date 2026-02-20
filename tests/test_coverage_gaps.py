"""Tests covering uncovered code paths in pico-auth."""

import pytest
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
