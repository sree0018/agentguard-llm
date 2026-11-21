"""The authorization pipeline: structural checks, then payload consistency."""

from __future__ import annotations

import time
from collections.abc import Sequence

from agentguard.core.checks import (
    check_payload,
    check_read_only,
    check_scope_containment,
    check_tool_admission,
)
from agentguard.core.types import Action, Check, Decision, Spec

#: Deterministic checks, run in order; the first block wins.
STRUCTURAL_CHECKS: tuple[Check, ...] = (
    check_tool_admission,
    check_scope_containment,
    check_read_only,
)


class AgentGuard:
    """Output-side tool-call authorizer.

    The guard never sees retrieved content; it sees only the pinned task
    ``spec`` and the proposed ``action``.

    Args:
        payload_checker: Implementation of check 4. ``None`` keeps the original
            regex proxy. Use :func:`agentguard.make_payload_checker` to build an
            LLM-backed one.
        structural_checks: Checks 1-3 (override to extend the pipeline).
        payload_check: Set ``False`` to run the structural checks only.
    """

    def __init__(
        self,
        payload_checker: Check | None = None,
        structural_checks: Sequence[Check] = STRUCTURAL_CHECKS,
        payload_check: bool = True,
    ) -> None:
        self.payload_checker: Check = payload_checker or check_payload
        self.structural_checks = tuple(structural_checks)
        self.payload_check = payload_check

    def authorize(self, action: Action, spec: Spec) -> Decision:
        """Return the first blocking decision, or a final ALLOW."""
        for check in self.structural_checks:
            decision = check(action, spec)
            if not decision.allowed:
                return decision
        if self.payload_check:
            decision = self.payload_checker(action, spec)
            if not decision.allowed:
                return decision
        return Decision(True, "passed all checks", "all")

    def trace(self, action: Action, spec: Spec) -> list[tuple[str, Decision | None, float]]:
        """Run every stage, recording ``(stage, decision, milliseconds)`` per stage.

        Stages after the first block are reported with ``decision=None`` (skipped),
        mirroring the short-circuit in :meth:`authorize`. Used by the demo and for
        debugging; it makes the same decisions as :meth:`authorize`.
        """
        stages: list[tuple[str, Check]] = [(c.__name__, c) for c in self.structural_checks]
        if self.payload_check:
            stages.append(("payload_consistency", self.payload_checker))
        out: list[tuple[str, Decision | None, float]] = []
        blocked = False
        for name, check in stages:
            if blocked:
                out.append((name, None, 0.0))
                continue
            t0 = time.perf_counter()
            decision = check(action, spec)
            out.append((name, decision, (time.perf_counter() - t0) * 1000.0))
            blocked = not decision.allowed
        return out

    def authorize_timed(self, action: Action, spec: Spec) -> tuple[Decision, float]:
        """Like :meth:`authorize` but also returns wall-clock microseconds."""
        t0 = time.perf_counter_ns()
        decision = self.authorize(action, spec)
        t1 = time.perf_counter_ns()
        return decision, (t1 - t0) / 1000.0


def authorize(
    action: Action,
    spec: Spec,
    payload_check: bool = True,
    payload_checker: Check | None = None,
) -> Decision:
    """Functional form of :meth:`AgentGuard.authorize` (default: regex check 4)."""
    return AgentGuard(payload_checker=payload_checker, payload_check=payload_check).authorize(
        action, spec
    )


def authorize_timed(
    action: Action,
    spec: Spec,
    payload_check: bool = True,
    payload_checker: Check | None = None,
) -> tuple[Decision, float]:
    """Functional form of :meth:`AgentGuard.authorize_timed`."""
    return AgentGuard(payload_checker=payload_checker, payload_check=payload_check).authorize_timed(
        action, spec
    )
