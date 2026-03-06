"""End-to-end tests against a real Docker container running pico-auth.

Run with: pytest tests/test_docker_e2e.py -m docker -v
"""

import subprocess
import time

import httpx
import pytest

pytestmark = pytest.mark.docker

API = "http://localhost:8100/api/v1/auth"
WELLKNOWN = "http://localhost:8100/.well-known"

ADMIN_EMAIL = "admin@pico.local"
ADMIN_PASSWORD = "admin"


# ------------------------------------------------------------------
# Fixture: build image, run container, wait for ready, teardown
# ------------------------------------------------------------------


@pytest.fixture(scope="module")
def docker_container():
    pico_auth_dir = subprocess.check_output(
        ["git", "rev-parse", "--show-toplevel"], text=True
    ).strip()

    # Build client wheel
    subprocess.run(
        ["make", "client-wheel"],
        cwd=pico_auth_dir,
        check=True,
        capture_output=True,
    )

    # Build Docker image
    subprocess.run(
        [
            "docker",
            "build",
            "-f",
            "Dockerfile.local",
            "-t",
            "pico-auth:e2e-test",
            "--no-cache",
            ".",
        ],
        cwd=pico_auth_dir,
        check=True,
        capture_output=True,
    )

    # Run container
    result = subprocess.run(
        [
            "docker",
            "run",
            "-d",
            "-p",
            "8100:8100",
            "pico-auth:e2e-test",
        ],
        capture_output=True,
        text=True,
        check=True,
    )
    container_id = result.stdout.strip()

    # Wait for healthy
    base = "http://localhost:8100"
    ready = False
    for _ in range(30):
        try:
            r = httpx.get(f"{base}/api/v1/auth/jwks", timeout=2)
            if r.status_code == 200:
                ready = True
                break
        except (httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError):
            pass
        time.sleep(0.5)

    if not ready:
        logs = subprocess.run(
            ["docker", "logs", container_id], capture_output=True, text=True
        )
        subprocess.run(["docker", "rm", "-f", container_id], check=True)
        pytest.fail(f"Container never became ready.\nLogs:\n{logs.stdout}\n{logs.stderr}")

    yield base

    # Teardown
    subprocess.run(["docker", "stop", container_id], check=True)
    subprocess.run(["docker", "rm", container_id], check=True)


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------


def _auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _admin_login() -> dict:
    r = httpx.post(
        f"{API}/login",
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
        timeout=5,
    )
    assert r.status_code == 200
    data = r.json()
    assert "access_token" in data
    return data


# ------------------------------------------------------------------
# Tests
# ------------------------------------------------------------------


class TestJWKSAndDiscovery:
    def test_jwks_endpoint(self, docker_container):
        r = httpx.get(f"{API}/jwks", timeout=5)
        data = r.json()
        assert "keys" in data
        assert len(data["keys"]) >= 1
        key = data["keys"][0]
        assert key["kty"] == "RSA"
        assert key["alg"] == "RS256"

    def test_oidc_discovery(self, docker_container):
        r = httpx.get(f"{WELLKNOWN}/openid-configuration", timeout=5)
        data = r.json()
        assert data["issuer"] == "http://localhost:8100"
        assert "jwks_uri" in data
        assert "token_endpoint" in data


class TestRegisterLoginTokens:
    def test_register_login_and_tokens(self, docker_container):
        # Register
        r = httpx.post(
            f"{API}/register",
            json={
                "email": "e2e-user@example.com",
                "password": "testpass",
                "display_name": "E2E User",
            },
            timeout=5,
        )
        data = r.json()
        assert "error" not in data
        assert data["email"] == "e2e-user@example.com"
        assert data["role"] == "viewer"
        user_id = data["id"]

        # Login
        r = httpx.post(
            f"{API}/login",
            json={"email": "e2e-user@example.com", "password": "testpass"},
            timeout=5,
        )
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "Bearer"

    def test_refresh_token_rotation(self, docker_container):
        # Register + login
        httpx.post(
            f"{API}/register",
            json={"email": "refresh@example.com", "password": "pass"},
            timeout=5,
        )
        login = httpx.post(
            f"{API}/login",
            json={"email": "refresh@example.com", "password": "pass"},
            timeout=5,
        )
        tokens = login.json()

        # Refresh
        r = httpx.post(
            f"{API}/refresh", json=tokens["refresh_token"], timeout=5
        )
        data = r.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["refresh_token"] != tokens["refresh_token"]

    def test_profile(self, docker_container):
        httpx.post(
            f"{API}/register",
            json={
                "email": "profile@example.com",
                "password": "pass",
                "display_name": "Profile User",
            },
            timeout=5,
        )
        login = httpx.post(
            f"{API}/login",
            json={"email": "profile@example.com", "password": "pass"},
            timeout=5,
        )
        token = login.json()["access_token"]

        r = httpx.get(f"{API}/me", headers=_auth(token), timeout=5)
        data = r.json()
        assert data["email"] == "profile@example.com"
        assert data["display_name"] == "Profile User"
        assert data["role"] == "viewer"


class TestAdminOperations:
    def test_admin_login_and_list_users(self, docker_container):
        data = _admin_login()
        token = data["access_token"]

        r = httpx.get(f"{API}/users", headers=_auth(token), timeout=5)
        data = r.json()
        assert "users" in data
        assert data["total"] >= 1
        emails = [u["email"] for u in data["users"]]
        assert ADMIN_EMAIL in emails

    def test_admin_change_user_role(self, docker_container):
        admin_token = _admin_login()["access_token"]

        # Register a user
        reg = httpx.post(
            f"{API}/register",
            json={"email": "rolechange@example.com", "password": "pass"},
            timeout=5,
        )
        user_id = reg.json()["id"]

        # Promote to operator
        r = httpx.put(
            f"{API}/users/{user_id}/role",
            json="operator",
            headers=_auth(admin_token),
            timeout=5,
        )
        data = r.json()
        assert data["role"] == "operator"


class TestRegistrationToggle:
    def test_registration_enabled_by_default(self, docker_container):
        admin_token = _admin_login()["access_token"]
        r = httpx.get(
            f"{API}/users/registration", headers=_auth(admin_token), timeout=5
        )
        assert r.json()["registration_enabled"] is True

    def test_disable_and_reenable_registration(self, docker_container):
        admin_token = _admin_login()["access_token"]

        # Disable
        r = httpx.put(
            f"{API}/users/registration",
            json={"enabled": False},
            headers=_auth(admin_token),
            timeout=5,
        )
        assert r.json()["registration_enabled"] is False

        # Public register should fail
        r = httpx.post(
            f"{API}/register",
            json={"email": "blocked@example.com", "password": "pass"},
            timeout=5,
        )
        assert r.status_code == 403

        # Admin can still create users
        r = httpx.post(
            f"{API}/users",
            json={
                "email": "adminmade@example.com",
                "password": "pass",
                "display_name": "Admin Made",
                "role": "operator",
            },
            headers=_auth(admin_token),
            timeout=5,
        )
        data = r.json()
        assert "error" not in data
        assert data["email"] == "adminmade@example.com"
        assert data["role"] == "operator"

        # Re-enable
        r = httpx.put(
            f"{API}/users/registration",
            json={"enabled": True},
            headers=_auth(admin_token),
            timeout=5,
        )
        assert r.json()["registration_enabled"] is True

        # Public register works again
        r = httpx.post(
            f"{API}/register",
            json={"email": "reenabled@example.com", "password": "pass"},
            timeout=5,
        )
        data = r.json()
        assert "error" not in data
        assert data["email"] == "reenabled@example.com"


class TestAdminPasswordReset:
    def test_admin_reset_password(self, docker_container):
        admin_token = _admin_login()["access_token"]

        # Create user
        reg = httpx.post(
            f"{API}/register",
            json={"email": "resetme@example.com", "password": "oldpass"},
            timeout=5,
        )
        user_id = reg.json()["id"]

        # Admin resets password
        r = httpx.put(
            f"{API}/users/{user_id}/password",
            json={"new_password": "newpass"},
            headers=_auth(admin_token),
            timeout=5,
        )
        assert r.json()["message"] == "Password reset"

        # Login with new password
        r = httpx.post(
            f"{API}/login",
            json={"email": "resetme@example.com", "password": "newpass"},
            timeout=5,
        )
        assert "access_token" in r.json()

        # Old password fails
        r = httpx.post(
            f"{API}/login",
            json={"email": "resetme@example.com", "password": "oldpass"},
            timeout=5,
        )
        assert "error" in r.json()


class TestViewerRestrictions:
    def test_viewer_cannot_access_admin_endpoints(self, docker_container):
        # Register a viewer
        httpx.post(
            f"{API}/register",
            json={"email": "viewer@example.com", "password": "pass"},
            timeout=5,
        )
        login = httpx.post(
            f"{API}/login",
            json={"email": "viewer@example.com", "password": "pass"},
            timeout=5,
        )
        viewer_token = login.json()["access_token"]

        # List users -> 403
        r = httpx.get(f"{API}/users", headers=_auth(viewer_token), timeout=5)
        assert r.status_code == 403

        # Registration status -> 403
        r = httpx.get(
            f"{API}/users/registration", headers=_auth(viewer_token), timeout=5
        )
        assert r.status_code == 403

        # Toggle registration -> 403
        r = httpx.put(
            f"{API}/users/registration",
            json={"enabled": False},
            headers=_auth(viewer_token),
            timeout=5,
        )
        assert r.status_code == 403
