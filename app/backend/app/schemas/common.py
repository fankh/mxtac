from typing import Any, Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class Pagination(BaseModel):
    page: int
    page_size: int
    total: int
    total_pages: int


class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    pagination: Pagination


class ErrorResponse(BaseModel):
    error: str
    message: str
    detail: Any = None
