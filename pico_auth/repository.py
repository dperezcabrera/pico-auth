"""User and refresh-token repositories."""

from pico_ioc import component
from pico_sqlalchemy import SessionManager
from sqlalchemy import delete, select

from pico_auth.models import Group, GroupMember, RefreshToken, User


@component
class UserRepository:
    """Data access for User entities."""

    def __init__(self, sm: SessionManager):
        self._sm = sm

    async def find_by_email(self, email: str) -> User | None:
        async with self._sm.transaction() as session:
            result = await session.execute(
                select(User).where(User.email == email),
            )
            return result.scalar_one_or_none()

    async def find_by_id(self, user_id: str) -> User | None:
        async with self._sm.transaction() as session:
            return await session.get(User, user_id)

    async def save(self, user: User) -> None:
        async with self._sm.transaction() as session:
            merged = await session.merge(user)
            await session.flush()
            user.id = merged.id

    async def list_all(self) -> list[User]:
        async with self._sm.transaction(read_only=True) as session:
            result = await session.execute(select(User))
            return list(result.scalars().all())

    async def update_role(self, user_id: str, role: str) -> User | None:
        async with self._sm.transaction() as session:
            user = await session.get(User, user_id)
            if user:
                user.role = role
                await session.flush()
            return user

    async def update_password(self, user_id: str, password_hash: str) -> None:
        async with self._sm.transaction() as session:
            user = await session.get(User, user_id)
            if user:
                user.password_hash = password_hash
                await session.flush()

    async def update_last_login(self, user_id: str, timestamp: str) -> None:
        async with self._sm.transaction() as session:
            user = await session.get(User, user_id)
            if user:
                user.last_login_at = timestamp
                await session.flush()


@component
class GroupRepository:
    """Data access for Group and GroupMember entities."""

    def __init__(self, sm: SessionManager):
        self._sm = sm

    async def find_by_id(self, group_id: str) -> Group | None:
        async with self._sm.transaction() as session:
            return await session.get(Group, group_id)

    async def find_by_name_and_org(self, name: str, org_id: str) -> Group | None:
        async with self._sm.transaction() as session:
            result = await session.execute(
                select(Group).where(Group.name == name, Group.org_id == org_id),
            )
            return result.scalar_one_or_none()

    async def save(self, group: Group) -> None:
        async with self._sm.transaction() as session:
            merged = await session.merge(group)
            await session.flush()
            group.id = merged.id

    async def list_by_org(self, org_id: str) -> list[Group]:
        async with self._sm.transaction(read_only=True) as session:
            result = await session.execute(
                select(Group).where(Group.org_id == org_id),
            )
            return list(result.scalars().all())

    async def update(self, group: Group) -> None:
        async with self._sm.transaction() as session:
            await session.merge(group)
            await session.flush()

    async def delete(self, group_id: str) -> None:
        async with self._sm.transaction() as session:
            await session.execute(
                delete(GroupMember).where(GroupMember.group_id == group_id),
            )
            await session.execute(
                delete(Group).where(Group.id == group_id),
            )

    async def add_member(self, member: GroupMember) -> None:
        async with self._sm.transaction() as session:
            await session.merge(member)
            await session.flush()

    async def remove_member(self, group_id: str, user_id: str) -> None:
        async with self._sm.transaction() as session:
            await session.execute(
                delete(GroupMember).where(
                    GroupMember.group_id == group_id,
                    GroupMember.user_id == user_id,
                ),
            )

    async def find_member(self, group_id: str, user_id: str) -> GroupMember | None:
        async with self._sm.transaction() as session:
            return await session.get(GroupMember, (group_id, user_id))

    async def list_members(self, group_id: str) -> list[GroupMember]:
        async with self._sm.transaction(read_only=True) as session:
            result = await session.execute(
                select(GroupMember).where(GroupMember.group_id == group_id),
            )
            return list(result.scalars().all())

    async def get_group_ids_for_user(self, user_id: str) -> list[str]:
        async with self._sm.transaction(read_only=True) as session:
            result = await session.execute(
                select(GroupMember.group_id).where(GroupMember.user_id == user_id),
            )
            return list(result.scalars().all())


@component
class RefreshTokenRepository:
    """Data access for RefreshToken entities."""

    def __init__(self, sm: SessionManager):
        self._sm = sm

    async def find_by_hash(self, token_hash: str) -> RefreshToken | None:
        async with self._sm.transaction() as session:
            result = await session.execute(
                select(RefreshToken).where(RefreshToken.token_hash == token_hash),
            )
            return result.scalar_one_or_none()

    async def save(self, token: RefreshToken) -> None:
        async with self._sm.transaction() as session:
            await session.merge(token)
            await session.flush()

    async def delete_by_user(self, user_id: str) -> None:
        async with self._sm.transaction() as session:
            await session.execute(
                delete(RefreshToken).where(RefreshToken.user_id == user_id),
            )

    async def delete_by_hash(self, token_hash: str) -> None:
        async with self._sm.transaction() as session:
            await session.execute(
                delete(RefreshToken).where(RefreshToken.token_hash == token_hash),
            )
