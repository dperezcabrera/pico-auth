"""SQLAlchemy entity models for pico-auth."""

from pico_sqlalchemy import AppBase, Mapped, mapped_column
from sqlalchemy import String


class User(AppBase):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    display_name: Mapped[str] = mapped_column(String(255), default="")
    password_hash: Mapped[str] = mapped_column(String(255))
    role: Mapped[str] = mapped_column(String(50), default="viewer")
    org_id: Mapped[str] = mapped_column(String(100), default="default")
    status: Mapped[str] = mapped_column(String(50), default="active")
    created_at: Mapped[str] = mapped_column(String(50))
    last_login_at: Mapped[str | None] = mapped_column(String(50), nullable=True)


class RefreshToken(AppBase):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[str] = mapped_column(String(50))
