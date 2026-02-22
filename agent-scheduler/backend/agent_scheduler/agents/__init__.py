from ..config import settings
from .base import BaseAgent
from .integration_agent import IntegrationAgent
from .lint_agent import LintAgent
from .security_audit import SecurityAuditAgent
from .task_creator import TaskCreatorAgent
from .test_agent import TestAgent
from .verifier import VerifierAgent

# Module-level singletons
task_creator_agent = TaskCreatorAgent()
verifier_agent = VerifierAgent()
test_agent = TestAgent()
lint_agent = LintAgent()
integration_agent = IntegrationAgent()
security_audit_agent = SecurityAuditAgent()

ALL_NEW_AGENTS: list[BaseAgent] = [
    task_creator_agent,
    verifier_agent,
    test_agent,
    lint_agent,
    integration_agent,
    security_audit_agent,
]

# Name -> instance lookup
_AGENT_MAP: dict[str, BaseAgent] = {a.NAME: a for a in ALL_NEW_AGENTS}


def get_enabled_agents() -> list[BaseAgent]:
    """Return only agents whose config flag is enabled."""
    enabled = []
    config_flags = {
        "TaskCreatorAgent": settings.agent_task_creator_enabled,
        "VerifierAgent": settings.agent_verifier_enabled,
        "TestAgent": settings.agent_test_enabled,
        "LintAgent": settings.agent_lint_enabled,
        "IntegrationAgent": settings.agent_integration_enabled,
        "SecurityAuditAgent": settings.agent_security_enabled,
    }
    for agent in ALL_NEW_AGENTS:
        if config_flags.get(agent.NAME, False):
            enabled.append(agent)
    return enabled


def get_agent_by_name(name: str) -> BaseAgent | None:
    """Look up an agent singleton by name."""
    return _AGENT_MAP.get(name)


__all__ = [
    "BaseAgent",
    "TaskCreatorAgent",
    "VerifierAgent",
    "TestAgent",
    "LintAgent",
    "IntegrationAgent",
    "SecurityAuditAgent",
    "task_creator_agent",
    "verifier_agent",
    "test_agent",
    "lint_agent",
    "integration_agent",
    "security_audit_agent",
    "ALL_NEW_AGENTS",
    "get_enabled_agents",
    "get_agent_by_name",
]
