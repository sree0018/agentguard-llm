"""AgentGuard: output-side authorization of agent tool calls.

Quick start::

    from agentguard import AgentGuard, make_payload_checker

    _, checker = make_payload_checker("llm=llama3.1:8b", llm_mode="replay")
    guard = AgentGuard(payload_checker=checker)
    decision = guard.authorize(action, spec)

The default pipeline (regex check 4) needs no LLM, no network and no
third-party packages.
"""

from agentguard.core import (
    Action,
    AgentGuard,
    Check,
    Decision,
    Spec,
    authorize,
    authorize_timed,
    check_payload,
)
from agentguard.llm import DEFAULT_VERSION, make_payload_checker

__version__ = "1.0.0"

__all__ = [
    "DEFAULT_VERSION",
    "Action",
    "AgentGuard",
    "Check",
    "Decision",
    "Spec",
    "__version__",
    "authorize",
    "authorize_timed",
    "check_payload",
    "make_payload_checker",
]
