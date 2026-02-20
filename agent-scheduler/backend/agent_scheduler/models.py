import datetime
import enum
import json

from sqlalchemy import (
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class TaskStatus(str, enum.Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    CANCELLED = "cancelled"


class RunStatus(str, enum.Enum):
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class Task(Base):
    __tablename__ = "tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(500))
    category: Mapped[str] = mapped_column(String(100), default="")
    phase: Mapped[str] = mapped_column(String(100), default="")
    priority: Mapped[int] = mapped_column(Integer, default=0)
    status: Mapped[TaskStatus] = mapped_column(
        Enum(TaskStatus), default=TaskStatus.PENDING, index=True
    )
    prompt: Mapped[str] = mapped_column(Text, default="")
    depends_on: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    working_directory: Mapped[str] = mapped_column(String(500), default="")
    target_files: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    acceptance_criteria: Mapped[str] = mapped_column(Text, default="")
    retry_count: Mapped[int] = mapped_column(Integer, default=0)
    max_retries: Mapped[int] = mapped_column(Integer, default=3)
    git_commit_sha: Mapped[str | None] = mapped_column(String(40), nullable=True)
    model: Mapped[str | None] = mapped_column(String(50), nullable=True)
    allowed_tools: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    created_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    updated_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now(), onupdate=func.now()
    )

    runs: Mapped[list["Run"]] = relationship(back_populates="task", cascade="all, delete-orphan")

    @property
    def depends_on_list(self) -> list[str]:
        return json.loads(self.depends_on) if self.depends_on else []

    @depends_on_list.setter
    def depends_on_list(self, value: list[str]):
        self.depends_on = json.dumps(value)

    @property
    def target_files_list(self) -> list[str]:
        return json.loads(self.target_files) if self.target_files else []

    @property
    def allowed_tools_list(self) -> list[str]:
        return json.loads(self.allowed_tools) if self.allowed_tools else []

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "title": self.title,
            "category": self.category,
            "phase": self.phase,
            "priority": self.priority,
            "status": self.status.value,
            "prompt": self.prompt,
            "depends_on": self.depends_on_list,
            "working_directory": self.working_directory,
            "target_files": self.target_files_list,
            "acceptance_criteria": self.acceptance_criteria,
            "retry_count": self.retry_count,
            "max_retries": self.max_retries,
            "git_commit_sha": self.git_commit_sha,
            "model": self.model,
            "allowed_tools": self.allowed_tools_list,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class Run(Base):
    __tablename__ = "runs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    task_id: Mapped[int] = mapped_column(ForeignKey("tasks.id"), index=True)
    attempt: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[RunStatus] = mapped_column(
        Enum(RunStatus), default=RunStatus.RUNNING
    )
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    pid: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout: Mapped[str] = mapped_column(Text, default="")
    stderr: Mapped[str] = mapped_column(Text, default="")
    git_diff: Mapped[str] = mapped_column(Text, default="")
    files_changed: Mapped[str] = mapped_column(Text, default="[]")  # JSON list
    duration_seconds: Mapped[float | None] = mapped_column(Float, nullable=True)
    started_at: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )
    finished_at: Mapped[datetime.datetime | None] = mapped_column(
        DateTime, nullable=True
    )

    task: Mapped["Task"] = relationship(back_populates="runs")
    logs: Mapped[list["Log"]] = relationship(back_populates="run", cascade="all, delete-orphan")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "task_id": self.task_id,
            "attempt": self.attempt,
            "status": self.status.value,
            "exit_code": self.exit_code,
            "pid": self.pid,
            "stdout": self.stdout,
            "stderr": self.stderr,
            "git_diff": self.git_diff,
            "files_changed": json.loads(self.files_changed) if self.files_changed else [],
            "duration_seconds": self.duration_seconds,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
        }


class Log(Base):
    __tablename__ = "logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[int] = mapped_column(ForeignKey("runs.id"), index=True)
    level: Mapped[str] = mapped_column(String(20), default="INFO")
    message: Mapped[str] = mapped_column(Text, default="")
    timestamp: Mapped[datetime.datetime] = mapped_column(
        DateTime, server_default=func.now()
    )

    run: Mapped["Run"] = relationship(back_populates="logs")

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "run_id": self.run_id,
            "level": self.level,
            "message": self.message,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }
