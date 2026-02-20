from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class AuditLogResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: str
    timestamp: datetime
    actor: str
    action: str
    resource_type: str
    resource_id: str | None
    details: dict[str, Any] | None
    request_ip: str | None
    request_method: str | None
    request_path: str | None
    user_agent: str | None
