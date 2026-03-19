"""SQLAlchemy models mapped to existing scanner_db schema."""

from __future__ import annotations

from sqlalchemy import JSON

from extensions import db


class UserRole(db.Model):
    __tablename__ = "user_roles"

    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True)
    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)


class RolePermission(db.Model):
    __tablename__ = "role_permissions"

    role_id = db.Column(db.Integer, db.ForeignKey("roles.id", ondelete="CASCADE"), primary_key=True)
    permission_id = db.Column(db.Integer, db.ForeignKey("permissions.id", ondelete="CASCADE"), primary_key=True)


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), nullable=False, unique=True, index=True)
    email = db.Column(db.String(150), nullable=False, unique=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_active = db.Column(db.Boolean, nullable=True, default=True, server_default=db.text("1"))
    created_at = db.Column(db.DateTime, nullable=True, server_default=db.func.current_timestamp())

    roles = db.relationship("Role", secondary="user_roles", back_populates="users", lazy="selectin")
    scans = db.relationship("Scan", back_populates="user", lazy="selectin")

    @property
    def role_names(self) -> set[str]:
        return {role.name for role in self.roles}

    @property
    def permission_names(self) -> set[str]:
        names: set[str] = set()
        for role in self.roles:
            names.update(permission.name for permission in role.permissions)
        return names

    def has_role(self, role_name: str) -> bool:
        return role_name in self.role_names

    def has_permission(self, permission_name: str) -> bool:
        return permission_name in self.permission_names

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email,
            "is_active": bool(self.is_active),
            "roles": sorted(self.role_names),
            "permissions": sorted(self.permission_names),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Role(db.Model):
    __tablename__ = "roles"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column("role_name", db.String(50), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)

    users = db.relationship("User", secondary="user_roles", back_populates="roles", lazy="selectin")
    permissions = db.relationship(
        "Permission",
        secondary="role_permissions",
        back_populates="roles",
        lazy="selectin",
    )


class Permission(db.Model):
    __tablename__ = "permissions"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column("permission_name", db.String(100), nullable=False, unique=True, index=True)
    description = db.Column(db.Text, nullable=True)

    roles = db.relationship(
        "Role",
        secondary="role_permissions",
        back_populates="permissions",
        lazy="selectin",
    )


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    target = db.Column(db.String(255), nullable=False, index=True)
    scan_mode = db.Column(db.String(16), nullable=False, index=True)
    status = db.Column(db.String(16), nullable=True, default="queued", server_default="queued")
    risk_score = db.Column(db.Numeric(5, 2), nullable=True)
    overall_risk = db.Column(db.String(16), nullable=True, index=True)
    confidence_score = db.Column(db.Numeric(5, 2), nullable=True)
    results_json = db.Column("result_json", JSON, nullable=False)
    created_at = db.Column(db.DateTime, nullable=True, server_default=db.func.current_timestamp())
    completed_at = db.Column(db.DateTime, nullable=True)

    user = db.relationship("User", back_populates="scans", lazy="selectin")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "target": self.target,
            "scan_mode": self.scan_mode,
            "status": self.status,
            "risk_score": float(self.risk_score) if self.risk_score is not None else None,
            "overall_risk": self.overall_risk,
            "confidence_score": float(self.confidence_score) if self.confidence_score is not None else None,
            "results": self.results_json,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
        }


class Finding(db.Model):
    __tablename__ = "findings"

    id = db.Column(db.String(24), primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, index=True)

    severity = db.Column(db.String(16), nullable=False, index=True)
    title = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text, nullable=True)
    category = db.Column(db.String(64), nullable=True, index=True)
    status = db.Column(db.String(32), nullable=False, default="open", server_default="open", index=True)

    asset_name = db.Column(db.String(255), nullable=True, index=True)
    asset_type = db.Column(db.String(32), nullable=True)

    discovered_at = db.Column(db.DateTime, nullable=True, server_default=db.func.current_timestamp(), index=True)
    updated_at = db.Column(db.DateTime, nullable=True, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    scan = db.relationship("Scan", lazy="joined")

    def to_api_dict(self) -> dict:
        asset_name = self.asset_name or ""
        asset_type = self.asset_type or "domain"
        return {
            "id": str(self.id),
            "severity": (self.severity or "").lower(),
            "title": self.title,
            "description": self.description or "",
            "category": self.category or "reconnaissance",
            "cvss": None,
            "cve": None,
            "asset": {"id": None, "name": asset_name, "type": asset_type},
            "scan": {"id": str(self.scan_id), "timestamp": self.discovered_at.isoformat() if self.discovered_at else None},
            "status": self.status or "open",
            "discoveredAt": self.discovered_at.isoformat() if self.discovered_at else None,
            "updatedAt": self.updated_at.isoformat() if self.updated_at else (self.discovered_at.isoformat() if self.discovered_at else None),
            "assignedTo": None,
            "proof": {},
            "remediation": {},
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)
    action = db.Column(db.String(255), nullable=False)
    target = db.Column(db.String(255), nullable=True)
    ip_address = db.Column(db.String(45), nullable=True)
    created_at = db.Column(db.DateTime, nullable=True, server_default=db.func.current_timestamp(), index=True)

    user = db.relationship("User", lazy="joined")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "action": self.action,
            "target": self.target,
            "ip_address": self.ip_address,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
