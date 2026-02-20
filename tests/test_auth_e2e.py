"""End-to-end tests for pico-auth -- full HTTP flows."""

import pytest

API = "/api/v1/auth"


# ===================================================================
# Registration and login
# ===================================================================


@pytest.mark.asyncio
class TestRegisterAndLogin:
    async def test_register_new_user(self, client):
        resp = await client.post(
            f"{API}/register",
            json={
                "email": "alice@example.com",
                "password": "secret123",
                "display_name": "Alice",
            },
        )
        data = resp.json()
        assert "error" not in data
        assert data["email"] == "alice@example.com"
        assert data["role"] == "viewer"
        assert data["status"] == "active"
        assert "id" in data

    async def test_register_duplicate_email(self, client):
        await client.post(
            f"{API}/register",
            json={
                "email": "bob@example.com",
                "password": "pass",
            },
        )
        resp = await client.post(
            f"{API}/register",
            json={
                "email": "bob@example.com",
                "password": "pass2",
            },
        )
        assert "error" in resp.json()

    async def test_login_success(self, client):
        await client.post(
            f"{API}/register",
            json={
                "email": "carol@example.com",
                "password": "mypass",
            },
        )
        resp = await client.post(
            f"{API}/login",
            json={
                "email": "carol@example.com",
                "password": "mypass",
            },
        )
        data = resp.json()
        assert "error" not in data
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"
        assert data["expires_in"] == 15 * 60

    async def test_login_wrong_password(self, client):
        await client.post(
            f"{API}/register",
            json={
                "email": "dave@example.com",
                "password": "correct",
            },
        )
        resp = await client.post(
            f"{API}/login",
            json={
                "email": "dave@example.com",
                "password": "wrong",
            },
        )
        assert "error" in resp.json()

    async def test_login_nonexistent_user(self, client):
        resp = await client.post(
            f"{API}/login",
            json={
                "email": "nobody@example.com",
                "password": "pass",
            },
        )
        assert "error" in resp.json()


# ===================================================================
# Token refresh
# ===================================================================


@pytest.mark.asyncio
class TestTokenRefresh:
    async def _register_and_login(self, client, email="user@example.com"):
        await client.post(
            f"{API}/register",
            json={
                "email": email,
                "password": "pass",
            },
        )
        resp = await client.post(
            f"{API}/login",
            json={
                "email": email,
                "password": "pass",
            },
        )
        return resp.json()

    async def test_refresh_returns_new_tokens(self, client):
        tokens = await self._register_and_login(client)
        resp = await client.post(f"{API}/refresh", json=tokens["refresh_token"])
        data = resp.json()
        assert "error" not in data
        assert "access_token" in data
        assert "refresh_token" in data
        # New refresh token should differ (rotation)
        assert data["refresh_token"] != tokens["refresh_token"]

    async def test_refresh_old_token_invalid(self, client):
        tokens = await self._register_and_login(client, "rotate@example.com")
        old_refresh = tokens["refresh_token"]
        # Use it once -> rotates
        await client.post(f"{API}/refresh", json=old_refresh)
        # Use old token again -> invalid
        resp = await client.post(f"{API}/refresh", json=old_refresh)
        assert "error" in resp.json()

    async def test_refresh_invalid_token(self, client):
        resp = await client.post(f"{API}/refresh", json="garbage-token")
        assert "error" in resp.json()


# ===================================================================
# Profile (GET /me)
# ===================================================================


@pytest.mark.asyncio
class TestProfile:
    async def _get_token(self, client, email="profile@example.com"):
        await client.post(
            f"{API}/register",
            json={
                "email": email,
                "password": "pass",
                "display_name": "Test User",
            },
        )
        resp = await client.post(
            f"{API}/login",
            json={
                "email": email,
                "password": "pass",
            },
        )
        return resp.json()["access_token"]

    async def test_me_returns_profile(self, client):
        token = await self._get_token(client)
        resp = await client.get(
            f"{API}/me",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        assert "error" not in data
        assert data["email"] == "profile@example.com"
        assert data["display_name"] == "Test User"
        assert data["role"] == "viewer"

    async def test_me_invalid_token(self, client):
        resp = await client.get(
            f"{API}/me",
            headers={"Authorization": "Bearer invalid.token.here"},
        )
        assert resp.status_code == 401
        assert "detail" in resp.json()

    async def test_me_no_token(self, client):
        resp = await client.get(f"{API}/me")
        assert resp.status_code == 401
        assert "detail" in resp.json()


# ===================================================================
# Change password
# ===================================================================


@pytest.mark.asyncio
class TestChangePassword:
    async def test_change_password_success(self, client):
        await client.post(
            f"{API}/register",
            json={
                "email": "chpass@example.com",
                "password": "old",
            },
        )
        login_resp = await client.post(
            f"{API}/login",
            json={
                "email": "chpass@example.com",
                "password": "old",
            },
        )
        token = login_resp.json()["access_token"]

        resp = await client.post(
            f"{API}/me/password",
            json={"old_password": "old", "new_password": "new"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.json().get("message") == "Password changed"

        # Login with new password works
        resp = await client.post(
            f"{API}/login",
            json={
                "email": "chpass@example.com",
                "password": "new",
            },
        )
        assert "access_token" in resp.json()

        # Login with old password fails
        resp = await client.post(
            f"{API}/login",
            json={
                "email": "chpass@example.com",
                "password": "old",
            },
        )
        assert "error" in resp.json()

    async def test_change_password_wrong_old(self, client):
        await client.post(
            f"{API}/register",
            json={
                "email": "chpass2@example.com",
                "password": "real",
            },
        )
        login_resp = await client.post(
            f"{API}/login",
            json={
                "email": "chpass2@example.com",
                "password": "real",
            },
        )
        token = login_resp.json()["access_token"]

        resp = await client.post(
            f"{API}/me/password",
            json={"old_password": "wrong", "new_password": "new"},
            headers={"Authorization": f"Bearer {token}"},
        )
        assert "error" in resp.json()


# ===================================================================
# Admin: list users & update roles
# ===================================================================


@pytest.mark.asyncio
class TestAdminEndpoints:
    async def test_list_users_as_admin(self, client, container):
        from pico_auth.service import AuthService

        service = container.get(AuthService)
        await service.ensure_admin("admin@test.com", "adminpass")

        # Login as admin
        login_resp = await client.post(
            f"{API}/login",
            json={
                "email": "admin@test.com",
                "password": "adminpass",
            },
        )
        token = login_resp.json()["access_token"]

        # Register a regular user
        await client.post(
            f"{API}/register",
            json={
                "email": "viewer@test.com",
                "password": "pass",
            },
        )

        resp = await client.get(
            f"{API}/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        data = resp.json()
        assert "error" not in data
        assert data["total"] >= 2
        emails = [u["email"] for u in data["users"]]
        assert "admin@test.com" in emails
        assert "viewer@test.com" in emails

    async def test_list_users_as_viewer_forbidden(self, client):
        await client.post(
            f"{API}/register",
            json={
                "email": "viewer2@test.com",
                "password": "pass",
            },
        )
        login_resp = await client.post(
            f"{API}/login",
            json={
                "email": "viewer2@test.com",
                "password": "pass",
            },
        )
        token = login_resp.json()["access_token"]

        resp = await client.get(
            f"{API}/users",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert resp.status_code == 403
        assert "detail" in resp.json()

    async def test_update_role(self, client, container):
        from pico_auth.service import AuthService

        service = container.get(AuthService)
        await service.ensure_admin("admin2@test.com", "adminpass")

        login_resp = await client.post(
            f"{API}/login",
            json={
                "email": "admin2@test.com",
                "password": "adminpass",
            },
        )
        admin_token = login_resp.json()["access_token"]

        # Register a viewer
        reg_resp = await client.post(
            f"{API}/register",
            json={
                "email": "promote@test.com",
                "password": "pass",
            },
        )
        user_id = reg_resp.json()["id"]

        # Promote to operator
        resp = await client.put(
            f"{API}/users/{user_id}/role",
            json="operator",
            headers={"Authorization": f"Bearer {admin_token}"},
        )
        data = resp.json()
        assert "error" not in data
        assert data["role"] == "operator"


# ===================================================================
# OIDC discovery & JWKS
# ===================================================================


@pytest.mark.asyncio
class TestOIDCDiscovery:
    async def test_jwks_endpoint(self, client):
        resp = await client.get(f"{API}/jwks")
        data = resp.json()
        assert "keys" in data
        assert len(data["keys"]) == 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"
        assert "n" in key
        assert "e" in key

    async def test_openid_configuration(self, client):
        resp = await client.get("/.well-known/openid-configuration")
        data = resp.json()
        assert data["issuer"] == "http://test"
        assert "jwks_uri" in data
        assert "token_endpoint" in data
