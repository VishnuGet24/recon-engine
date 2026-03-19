"""RBAC bootstrap helpers."""

from __future__ import annotations

from extensions import db
from models import Permission, Role


DEFAULT_PERMISSIONS = {
    "scan:passive": "Run passive scans",
    "scan:active": "Run active scans",
    "scan:read": "Read scan results",
    "user:create": "Create new users",
    "user:read": "Read user list",
    "audit:read": "Read audit logs",
}

DEFAULT_ROLES = {
    "basic": {
        "description": "Passive scan access",
        "permissions": ["scan:passive", "scan:read"],
    },
    "authorized": {
        "description": "Passive and active scan access",
        "permissions": ["scan:passive", "scan:active", "scan:read"],
    },
    "admin": {
        "description": "Full access with user management",
        "permissions": ["scan:passive", "scan:active", "scan:read", "user:create", "user:read", "audit:read"],
    },
}


def seed_rbac_data() -> None:
    permissions_by_name: dict[str, Permission] = {}

    for permission_name, description in DEFAULT_PERMISSIONS.items():
        permission = Permission.query.filter_by(name=permission_name).first()
        if permission is None:
            permission = Permission(name=permission_name, description=description)
            db.session.add(permission)
        permissions_by_name[permission_name] = permission

    db.session.flush()

    for role_name, payload in DEFAULT_ROLES.items():
        role = Role.query.filter_by(name=role_name).first()
        if role is None:
            role = Role(name=role_name, description=payload["description"])
            db.session.add(role)
            db.session.flush()

        required_permissions = [permissions_by_name[name] for name in payload["permissions"]]
        role.permissions = required_permissions

    db.session.commit()
