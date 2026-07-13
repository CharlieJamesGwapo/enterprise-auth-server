"""Model exports and RBAC seed constants."""

from __future__ import annotations

from app.models.associations import role_permissions, user_roles
from app.models.permission import Permission
from app.models.role import Role
from app.models.user import User

# --- RBAC seed definitions (used by migrations and bootstrap) ---
PERMISSIONS: dict[str, str] = {
    "manage_users": "Create, update, and delete users",
    "manage_roles": "Create, update, and delete roles",
    "manage_permissions": "Assign permissions to roles",
    "view_dashboard": "View the admin dashboard",
    "manage_api_keys": "Create, rotate, and revoke API keys",
}

ROLES: dict[str, list[str]] = {
    "super_admin": list(PERMISSIONS),
    "admin": ["manage_users", "manage_roles", "view_dashboard", "manage_api_keys"],
    "staff": ["view_dashboard"],
    "user": [],
}

__all__ = [
    "User",
    "Role",
    "Permission",
    "user_roles",
    "role_permissions",
    "PERMISSIONS",
    "ROLES",
]
