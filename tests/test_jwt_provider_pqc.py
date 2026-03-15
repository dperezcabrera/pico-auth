"""Tests for JWTProvider PQC (ML-DSA) support using mocked oqs."""

import base64
import json
from unittest.mock import MagicMock, patch

import pytest
from pico_boot import init
from pico_ioc import DictSource, configuration

from pico_auth.config import AuthSettings


def _b64url_decode(data: str) -> bytes:
    padded = data + "=" * (4 - len(data) % 4)
    return base64.urlsafe_b64decode(padded)


class TestAuthSettingsPQC:
    def test_is_pqc_false_for_rs256(self):
        s = AuthSettings(algorithm="RS256")
        assert s.is_pqc is False

    def test_is_pqc_true_for_mldsa65(self):
        s = AuthSettings(algorithm="ML-DSA-65")
        assert s.is_pqc is True

    def test_is_pqc_true_for_mldsa87(self):
        s = AuthSettings(algorithm="ML-DSA-87")
        assert s.is_pqc is True

    def test_pqc_key_paths(self, tmp_path):
        s = AuthSettings(data_dir=str(tmp_path), algorithm="ML-DSA-65")
        assert s.pqc_key_path == tmp_path / "pqc_secret.bin"
        assert s.pqc_pub_path == tmp_path / "pqc_public.bin"


class TestJWTProviderPQCMocked:
    """Test PQC paths in JWTProvider using mocked oqs."""

    def _make_mock_oqs(self):
        mock_oqs = MagicMock()
        mock_signer = MagicMock()
        mock_signer.generate_keypair.return_value = b"public-key-bytes"
        mock_signer.export_secret_key.return_value = b"secret-key-bytes"
        mock_signer.sign.return_value = b"fake-signature"
        mock_oqs.Signature.return_value = mock_signer
        return mock_oqs, mock_signer

    def test_pqc_key_generation(self, tmp_path):
        mock_oqs, mock_signer = self._make_mock_oqs()

        settings = AuthSettings(
            data_dir=str(tmp_path / "keys"),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            provider = JWTProvider(settings=settings)

        assert provider._algorithm == "ML-DSA-65"
        assert provider._secret_key == b"secret-key-bytes"
        assert provider._public_key_bytes == b"public-key-bytes"
        assert provider._private_key is None
        mock_oqs.Signature.assert_called_with("ML-DSA-65")

    def test_pqc_key_loading_from_files(self, tmp_path):
        mock_oqs, _ = self._make_mock_oqs()

        key_dir = tmp_path / "keys"
        key_dir.mkdir(parents=True)
        (key_dir / "pqc_secret.bin").write_bytes(b"stored-secret")
        (key_dir / "pqc_public.bin").write_bytes(b"stored-public")

        settings = AuthSettings(
            data_dir=str(key_dir),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            provider = JWTProvider(settings=settings)

        assert provider._secret_key == b"stored-secret"
        assert provider._public_key_bytes == b"stored-public"
        # Should NOT have called Signature to generate
        mock_oqs.Signature.assert_not_called()

    def test_pqc_create_access_token(self, tmp_path):
        mock_oqs, mock_signer = self._make_mock_oqs()

        key_dir = tmp_path / "keys"
        key_dir.mkdir(parents=True)
        (key_dir / "pqc_secret.bin").write_bytes(b"secret")
        (key_dir / "pqc_public.bin").write_bytes(b"public")

        settings = AuthSettings(
            data_dir=str(key_dir),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            provider = JWTProvider(settings=settings)
            token = provider.create_access_token("u1", "u@test.com", "admin", "org-1")

        parts = token.split(".")
        assert len(parts) == 3

        header = json.loads(_b64url_decode(parts[0]))
        assert header["alg"] == "ML-DSA-65"
        assert header["typ"] == "JWT"
        assert header["kid"] == "pico-auth-1"

        payload = json.loads(_b64url_decode(parts[1]))
        assert payload["sub"] == "u1"
        assert payload["email"] == "u@test.com"
        assert payload["iss"] == "http://test"
        assert payload["aud"] == "pico-bot"

    def test_pqc_decode_access_token(self, tmp_path):
        mock_oqs = MagicMock()
        # Signer that returns real bytes
        mock_signer = MagicMock()
        mock_signer.sign.return_value = b"fake-signature"
        # Verifier that approves
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True

        key_dir = tmp_path / "keys"
        key_dir.mkdir(parents=True)
        (key_dir / "pqc_secret.bin").write_bytes(b"secret")
        (key_dir / "pqc_public.bin").write_bytes(b"public")

        settings = AuthSettings(
            data_dir=str(key_dir),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            # For create_access_token: sign returns bytes
            mock_oqs.Signature.return_value = mock_signer
            provider = JWTProvider(settings=settings)
            token = provider.create_access_token("u1", "u@test.com", "admin", "org-1")

            # For decode: verify returns True
            mock_oqs.Signature.return_value = mock_verifier
            claims = provider.decode_access_token(token)

        assert claims["sub"] == "u1"
        assert claims["email"] == "u@test.com"

    def test_pqc_jwks(self, tmp_path):
        mock_oqs, _ = self._make_mock_oqs()

        key_dir = tmp_path / "keys"
        key_dir.mkdir(parents=True)
        (key_dir / "pqc_secret.bin").write_bytes(b"secret")
        (key_dir / "pqc_public.bin").write_bytes(b"public")

        settings = AuthSettings(
            data_dir=str(key_dir),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            provider = JWTProvider(settings=settings)
            jwks = provider.jwks()

        assert len(jwks["keys"]) == 1
        key = jwks["keys"][0]
        assert key["kty"] == "AKP"
        assert key["alg"] == "ML-DSA-65"
        assert key["kid"] == "pico-auth-1"
        assert "pub" in key
        # Verify pub decodes to original bytes
        assert _b64url_decode(key["pub"]) == b"public"

    def test_pqc_openid_configuration(self, tmp_path):
        mock_oqs, _ = self._make_mock_oqs()

        key_dir = tmp_path / "keys"
        key_dir.mkdir(parents=True)
        (key_dir / "pqc_secret.bin").write_bytes(b"secret")
        (key_dir / "pqc_public.bin").write_bytes(b"public")

        settings = AuthSettings(
            data_dir=str(key_dir),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            provider = JWTProvider(settings=settings)
            config = provider.openid_configuration()

        assert config["id_token_signing_alg_values_supported"] == ["ML-DSA-65"]

    def test_pqc_mldsa87(self, tmp_path):
        mock_oqs, _ = self._make_mock_oqs()

        key_dir = tmp_path / "keys"
        key_dir.mkdir(parents=True)
        (key_dir / "pqc_secret.bin").write_bytes(b"secret-87")
        (key_dir / "pqc_public.bin").write_bytes(b"public-87")

        settings = AuthSettings(
            data_dir=str(key_dir),
            algorithm="ML-DSA-87",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            provider = JWTProvider(settings=settings)
            jwks = provider.jwks()

        assert jwks["keys"][0]["alg"] == "ML-DSA-87"
        assert jwks["keys"][0]["kty"] == "AKP"


class TestPQCDecodeErrors:
    """Test error paths in _decode_pqc_token."""

    def _make_provider(self, tmp_path, mock_oqs):
        key_dir = tmp_path / "keys"
        key_dir.mkdir(parents=True, exist_ok=True)
        (key_dir / "pqc_secret.bin").write_bytes(b"secret")
        (key_dir / "pqc_public.bin").write_bytes(b"public")
        settings = AuthSettings(
            data_dir=str(key_dir),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )
        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            from pico_auth.jwt_provider import JWTProvider

            return JWTProvider(settings=settings)

    def test_malformed_token_raises(self, tmp_path):
        mock_oqs = MagicMock()
        provider = self._make_provider(tmp_path, mock_oqs)
        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            with pytest.raises(ValueError, match="expected 3 parts"):
                provider.decode_access_token("only.two")

    def test_invalid_signature_raises(self, tmp_path):
        mock_oqs = MagicMock()
        mock_signer = MagicMock()
        mock_signer.sign.return_value = b"fake-sig"
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = False
        mock_oqs.Signature.return_value = mock_signer

        provider = self._make_provider(tmp_path, mock_oqs)

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            mock_oqs.Signature.return_value = mock_signer
            token = provider.create_access_token("u1", "u@t.com", "admin", "org-1")
            mock_oqs.Signature.return_value = mock_verifier
            with pytest.raises(ValueError, match="Invalid signature"):
                provider.decode_access_token(token)

    def test_expired_token_raises(self, tmp_path):
        import time

        mock_oqs = MagicMock()
        mock_signer = MagicMock()
        mock_signer.sign.return_value = b"fake-sig"
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True

        provider = self._make_provider(tmp_path, mock_oqs)

        # Build a token with exp in the past
        from pico_auth.jwt_provider import _b64url_encode

        header = json.dumps(
            {"alg": "ML-DSA-65", "typ": "JWT", "kid": "pico-auth-1"}, separators=(",", ":")
        )
        payload = json.dumps(
            {"sub": "u1", "iss": "http://test", "aud": "pico-bot", "exp": int(time.time()) - 60},
            separators=(",", ":"),
        )
        h = _b64url_encode(header.encode())
        p = _b64url_encode(payload.encode())
        s = _b64url_encode(b"sig")
        token = f"{h}.{p}.{s}"

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            mock_oqs.Signature.return_value = mock_verifier
            with pytest.raises(ValueError, match="expired"):
                provider.decode_access_token(token)

    def test_wrong_issuer_raises(self, tmp_path):
        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True

        provider = self._make_provider(tmp_path, mock_oqs)

        from pico_auth.jwt_provider import _b64url_encode

        header = json.dumps(
            {"alg": "ML-DSA-65", "typ": "JWT", "kid": "pico-auth-1"}, separators=(",", ":")
        )
        payload = json.dumps(
            {"sub": "u1", "iss": "http://wrong", "aud": "pico-bot", "exp": 9999999999},
            separators=(",", ":"),
        )
        h = _b64url_encode(header.encode())
        p = _b64url_encode(payload.encode())
        s = _b64url_encode(b"sig")
        token = f"{h}.{p}.{s}"

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            mock_oqs.Signature.return_value = mock_verifier
            with pytest.raises(ValueError, match="issuer"):
                provider.decode_access_token(token)

    def test_wrong_audience_raises(self, tmp_path):
        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True

        provider = self._make_provider(tmp_path, mock_oqs)

        from pico_auth.jwt_provider import _b64url_encode

        header = json.dumps(
            {"alg": "ML-DSA-65", "typ": "JWT", "kid": "pico-auth-1"}, separators=(",", ":")
        )
        payload = json.dumps(
            {"sub": "u1", "iss": "http://test", "aud": "wrong-aud", "exp": 9999999999},
            separators=(",", ":"),
        )
        h = _b64url_encode(header.encode())
        p = _b64url_encode(payload.encode())
        s = _b64url_encode(b"sig")
        token = f"{h}.{p}.{s}"

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            mock_oqs.Signature.return_value = mock_verifier
            with pytest.raises(ValueError, match="audience"):
                provider.decode_access_token(token)

    def test_audience_list_invalid_raises(self, tmp_path):
        mock_oqs = MagicMock()
        mock_verifier = MagicMock()
        mock_verifier.verify.return_value = True

        provider = self._make_provider(tmp_path, mock_oqs)

        from pico_auth.jwt_provider import _b64url_encode

        header = json.dumps(
            {"alg": "ML-DSA-65", "typ": "JWT", "kid": "pico-auth-1"}, separators=(",", ":")
        )
        payload = json.dumps(
            {"sub": "u1", "iss": "http://test", "aud": ["other-api"], "exp": 9999999999},
            separators=(",", ":"),
        )
        h = _b64url_encode(header.encode())
        p = _b64url_encode(payload.encode())
        s = _b64url_encode(b"sig")
        token = f"{h}.{p}.{s}"

        with patch.dict("sys.modules", {"oqs": mock_oqs}):
            mock_oqs.Signature.return_value = mock_verifier
            with pytest.raises(ValueError, match="audience"):
                provider.decode_access_token(token)


class TestJWTProviderPQCImportError:
    def test_raises_when_oqs_not_installed(self, tmp_path):
        settings = AuthSettings(
            data_dir=str(tmp_path / "keys"),
            algorithm="ML-DSA-65",
            issuer="http://test",
            audience="pico-bot",
        )

        with patch.dict("sys.modules", {"oqs": None}):
            from pico_auth.jwt_provider import JWTProvider

            with pytest.raises(RuntimeError, match="liboqs-python"):
                JWTProvider(settings=settings)
