"""Password hashing service using bcrypt directly."""

import bcrypt
from pico_ioc import component


@component
class PasswordService:
    """Bcrypt password hashing and verification."""

    def hash(self, password: str) -> str:
        return bcrypt.hashpw(
            password.encode("utf-8")[:72],
            bcrypt.gensalt(),
        ).decode("utf-8")

    def verify(self, password: str, password_hash: str) -> bool:
        try:
            return bcrypt.checkpw(
                password.encode("utf-8")[:72],
                password_hash.encode("utf-8"),
            )
        except (ValueError, TypeError):
            return False
