"""Auth error hierarchy."""


class AuthError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


class UserExistsError(AuthError):
    def __init__(self, email: str):
        super().__init__(f"User already exists: {email}")


class InvalidCredentialsError(AuthError):
    def __init__(self):
        super().__init__("Invalid email or password")


class TokenExpiredError(AuthError):
    def __init__(self):
        super().__init__("Token has expired")


class TokenInvalidError(AuthError):
    def __init__(self):
        super().__init__("Invalid token")


class UserNotFoundError(AuthError):
    def __init__(self, user_id: str):
        super().__init__(f"User not found: {user_id}")


class InsufficientPermissionsError(AuthError):
    def __init__(self):
        super().__init__("Insufficient permissions")


class UserSuspendedError(AuthError):
    def __init__(self):
        super().__init__("User account is suspended")


class GroupNotFoundError(AuthError):
    def __init__(self, group_id: str):
        super().__init__(f"Group not found: {group_id}")


class GroupExistsError(AuthError):
    def __init__(self, name: str):
        super().__init__(f"Group already exists: {name}")


class MemberAlreadyInGroupError(AuthError):
    def __init__(self, user_id: str, group_id: str):
        super().__init__(f"User {user_id} is already in group {group_id}")


class MemberNotInGroupError(AuthError):
    def __init__(self, user_id: str, group_id: str):
        super().__init__(f"User {user_id} is not in group {group_id}")
