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


class Group(AppBase):
    __tablename__ = "groups"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    description: Mapped[str] = mapped_column(String(500), default="")
    org_id: Mapped[str] = mapped_column(String(100), index=True)
    created_at: Mapped[str] = mapped_column(String(50))
    updated_at: Mapped[str] = mapped_column(String(50))


class GroupMember(AppBase):
    __tablename__ = "group_members"

    group_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), primary_key=True, index=True)
    joined_at: Mapped[str] = mapped_column(String(50))


class RefreshToken(AppBase):
    __tablename__ = "refresh_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    user_id: Mapped[str] = mapped_column(String(36), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[str] = mapped_column(String(50))
    created_at: Mapped[str] = mapped_column(String(50))


class ServiceToken(AppBase):
    __tablename__ = "service_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    name: Mapped[str] = mapped_column(String(255), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    role: Mapped[str] = mapped_column(String(50), default="operator")
    org_id: Mapped[str] = mapped_column(String(100), default="default")
    description: Mapped[str] = mapped_column(String(500), default="")
    created_at: Mapped[str] = mapped_column(String(50))
    revoked_at: Mapped[str | None] = mapped_column(String(50), nullable=True)


class EmailCredential(AppBase):
    __tablename__ = "email_credentials"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    agent_id: Mapped[str] = mapped_column(String(128), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(256))
    imap_host: Mapped[str] = mapped_column(String(256))
    imap_port: Mapped[int]
    smtp_host: Mapped[str] = mapped_column(String(256))
    smtp_port: Mapped[int]
    username: Mapped[str] = mapped_column(String(256))
    password: Mapped[str] = mapped_column(String(512))
    use_tls: Mapped[bool] = mapped_column(default=True)
    created_at: Mapped[str] = mapped_column(String(50))
