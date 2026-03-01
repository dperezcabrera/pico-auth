"""Tests for email credential CRUD endpoints."""

import pytest

AUTH = {"Authorization": "Bearer test-token"}


@pytest.mark.asyncio
async def test_create_email_credential(client):
    resp = await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "agent-alpha",
            "email": "alpha@agents.local",
            "imap_host": "stalwart",
            "imap_port": 993,
            "smtp_host": "stalwart",
            "smtp_port": 465,
            "username": "alpha@agents.local",
            "password": "secret123",
        },
        headers=AUTH,
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "agent-alpha"
    assert data["email"] == "alpha@agents.local"


@pytest.mark.asyncio
async def test_get_email_credential(client):
    await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "agent-beta",
            "email": "beta@agents.local",
            "imap_host": "stalwart",
            "imap_port": 993,
            "smtp_host": "stalwart",
            "smtp_port": 465,
            "username": "beta@agents.local",
            "password": "pass",
        },
        headers=AUTH,
    )
    resp = await client.get("/api/v1/email-credentials/agent-beta", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "agent-beta"
    assert data["email"] == "beta@agents.local"
    assert data["password"] == "pass"
    assert data["use_tls"] is True


@pytest.mark.asyncio
async def test_get_nonexistent_returns_error(client):
    resp = await client.get("/api/v1/email-credentials/nonexistent", headers=AUTH)
    assert resp.status_code == 200
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_list_email_credentials(client):
    await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "agent-one",
            "email": "one@agents.local",
            "imap_host": "stalwart",
            "smtp_host": "stalwart",
            "username": "one",
            "password": "pw",
        },
        headers=AUTH,
    )
    await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "agent-two",
            "email": "two@agents.local",
            "imap_host": "stalwart",
            "smtp_host": "stalwart",
            "username": "two",
            "password": "pw",
        },
        headers=AUTH,
    )
    resp = await client.get("/api/v1/email-credentials", headers=AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 2


@pytest.mark.asyncio
async def test_upsert_overwrites(client):
    payload = {
        "agent_id": "agent-upsert",
        "email": "old@agents.local",
        "imap_host": "stalwart",
        "smtp_host": "stalwart",
        "username": "user",
        "password": "pw1",
    }
    await client.post("/api/v1/email-credentials", json=payload, headers=AUTH)
    payload["email"] = "new@agents.local"
    payload["password"] = "pw2"
    await client.post("/api/v1/email-credentials", json=payload, headers=AUTH)

    resp = await client.get("/api/v1/email-credentials/agent-upsert", headers=AUTH)
    data = resp.json()
    assert data["email"] == "new@agents.local"
    assert data["password"] == "pw2"


@pytest.mark.asyncio
async def test_delete_email_credential(client):
    await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "agent-del",
            "email": "del@agents.local",
            "imap_host": "stalwart",
            "smtp_host": "stalwart",
            "username": "del",
            "password": "pw",
        },
        headers=AUTH,
    )
    resp = await client.delete("/api/v1/email-credentials/agent-del", headers=AUTH)
    assert resp.status_code == 200
    assert "deleted" in resp.json()["message"]

    resp = await client.get("/api/v1/email-credentials/agent-del", headers=AUTH)
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_list_includes_password(client):
    """List endpoint includes passwords since it's token-protected."""
    await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "agent-secure",
            "email": "s@agents.local",
            "imap_host": "h",
            "smtp_host": "h",
            "username": "u",
            "password": "secret",
        },
        headers=AUTH,
    )
    resp = await client.get("/api/v1/email-credentials", headers=AUTH)
    data = resp.json()
    for c in data["credentials"]:
        if c["agent_id"] == "agent-secure":
            assert c["password"] == "secret"
            break
    else:
        pytest.fail("agent-secure not found in list")


@pytest.mark.asyncio
async def test_upsert_rejects_missing_token(client):
    resp = await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "x",
            "email": "x@x.com",
            "imap_host": "h",
            "smtp_host": "h",
            "username": "u",
            "password": "p",
        },
    )
    assert resp.status_code == 422  # missing required header


@pytest.mark.asyncio
async def test_upsert_rejects_wrong_token(client):
    resp = await client.post(
        "/api/v1/email-credentials",
        json={
            "agent_id": "x",
            "email": "x@x.com",
            "imap_host": "h",
            "smtp_host": "h",
            "username": "u",
            "password": "p",
        },
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert resp.status_code == 401
