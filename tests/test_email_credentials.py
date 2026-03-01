"""Tests for email credential CRUD endpoints."""

import pytest


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
    )
    resp = await client.get("/api/v1/email-credentials/agent-beta")
    assert resp.status_code == 200
    data = resp.json()
    assert data["agent_id"] == "agent-beta"
    assert data["email"] == "beta@agents.local"
    assert data["password"] == "pass"
    assert data["use_tls"] is True


@pytest.mark.asyncio
async def test_get_nonexistent_returns_error(client):
    resp = await client.get("/api/v1/email-credentials/nonexistent")
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
    )
    resp = await client.get("/api/v1/email-credentials")
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
    await client.post("/api/v1/email-credentials", json=payload)
    payload["email"] = "new@agents.local"
    payload["password"] = "pw2"
    await client.post("/api/v1/email-credentials", json=payload)

    resp = await client.get("/api/v1/email-credentials/agent-upsert")
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
    )
    resp = await client.delete("/api/v1/email-credentials/agent-del")
    assert resp.status_code == 200
    assert "deleted" in resp.json()["message"]

    resp = await client.get("/api/v1/email-credentials/agent-del")
    assert "error" in resp.json()


@pytest.mark.asyncio
async def test_list_excludes_password(client):
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
    )
    resp = await client.get("/api/v1/email-credentials")
    data = resp.json()
    for c in data["credentials"]:
        assert "password" not in c
