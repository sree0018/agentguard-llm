"""Shared types for the authorization pipeline."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

#: A proposed tool call, e.g. ``{"tool": "send_email", "to": "a@b.c", "body": "..."}``.
Action = dict[str, Any]
#: The user's pinned task: ``intent``, ``allowed_tools``, ``scope``, ``read_only``.
Spec = dict[str, Any]


@dataclass(frozen=True, repr=False)
class Decision:
    """Outcome of one check (or of the whole pipeline).

    Attributes:
        allowed: ``True`` if the action may proceed.
        reason: Human-readable explanation.
        check: Name of the check that produced the decision.
        meta: Optional diagnostics (for LLM checks: latency, cache flag, raw output).
    """

    allowed: bool
    reason: str
    check: str
    meta: dict[str, Any] | None = None

    def __repr__(self) -> str:
        verdict = "ALLOW" if self.allowed else "BLOCK"
        return f"<Decision {verdict} via {self.check}: {self.reason}>"


#: A check maps ``(action, spec)`` to a :class:`Decision`.
Check = Callable[[Action, Spec], Decision]
