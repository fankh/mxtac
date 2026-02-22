"""ORM model for Permission Sets (Feature 3.9).

A PermissionSet is a named, reusable collection of RBAC permission strings.
API keys can be created referencing a permission set so that consistent
permission profiles can be applied and audited across many keys.
"""

from sqlalchemy import Boolean, JSON, String
from sqlalchemy.orm import Mapped, mapped_column

from .base import Base, TimestampMixin, new_uuid


class PermissionSet(Base, TimestampMixin):
    __tablename__ = "permission_sets"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_uuid)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    # List of permission strings (e.g. ["detections:read", "incidents:write"])
    permissions: Mapped[list] = mapped_column(JSON, nullable=False)
    # UUID of the user who created this set
    created_by: Mapped[str] = mapped_column(String(36), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    def __repr__(self) -> str:
        return f"<PermissionSet {self.id} name={self.name!r}>"
