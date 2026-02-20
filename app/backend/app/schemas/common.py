from pydantic import BaseModel
from typing import Generic, TypeVar, Any

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
