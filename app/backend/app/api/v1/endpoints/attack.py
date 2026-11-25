"""ATT&CK reference data."""

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ....core.security import get_current_user
from ....services.attack_techniques import attack_retrieved, attack_version, technique_names

router = APIRouter(prefix="/attack", tags=["attack"])


class AttackTechniques(BaseModel):
    # ATT&CK release and download date of the bundled table
    attack_version: str
    retrieved: str
    # Technique ID -> name; a sub-technique carries its parent ("Parent: Sub")
    techniques: dict[str, str]


@router.get("/techniques", response_model=AttackTechniques)
async def list_attack_techniques(_: dict[str, Any] = Depends(get_current_user)) -> AttackTechniques:
    """Names of the MITRE ATT&CK Enterprise techniques and sub-techniques.

    The table is bundled with the backend, so no request leaves the server.
    Revoked and deprecated techniques are not part of it.
    """
    return AttackTechniques(
        attack_version=attack_version(),
        retrieved=attack_retrieved(),
        techniques=technique_names(),
    )
