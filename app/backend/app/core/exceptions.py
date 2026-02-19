"""Application-level exception hierarchy and FastAPI exception handlers."""

from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse


# ── Exception classes ─────────────────────────────────────────────────────────

class MxTacError(Exception):
    """Base exception for all MxTac application errors."""
    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    detail: str = "Internal server error"

    def __init__(self, detail: str | None = None) -> None:
        self.detail = detail or self.__class__.detail
        super().__init__(self.detail)


class NotFoundError(MxTacError):
    status_code = status.HTTP_404_NOT_FOUND
    detail = "Resource not found"


class UnauthorizedError(MxTacError):
    status_code = status.HTTP_401_UNAUTHORIZED
    detail = "Authentication required"


class ForbiddenError(MxTacError):
    status_code = status.HTTP_403_FORBIDDEN
    detail = "Insufficient permissions"


class ConflictError(MxTacError):
    status_code = status.HTTP_409_CONFLICT
    detail = "Resource conflict"


class ValidationError(MxTacError):
    status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
    detail = "Validation failed"


# ── Handlers ──────────────────────────────────────────────────────────────────

def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(MxTacError)
    async def mxtac_error_handler(request: Request, exc: MxTacError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content={"detail": exc.detail, "type": type(exc).__name__},
        )

    @app.exception_handler(Exception)
    async def generic_error_handler(request: Request, exc: Exception) -> JSONResponse:
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"detail": "An unexpected error occurred", "type": "InternalServerError"},
        )
