"""Check 4 (payload consistency), implemented with a local LLM.

Design rules:

* Information asymmetry is preserved: the guard sees only the pinned task spec
  and the proposed tool call, never the retrieved content.
* Fail closed: timeouts, unreachable server, malformed output, or any verdict
  other than exactly ALLOW/BLOCK produce a BLOCK tagged
  ``payload_consistency_llm_error`` so errors are counted separately.
* No silent fallback to the regex: if the model cannot be reached and the
  response is not cached, the check blocks instead of quietly reporting regex
  numbers as LLM numbers.
"""

from __future__ import annotations

import time

from agentguard.core.checks import check_payload
from agentguard.core.types import Action, Check, Decision, Spec
from agentguard.llm.backends import BackendError, LLMBackend
from agentguard.llm.prompts import DEFAULT_VERSION, build_messages
from agentguard.llm.verdict import parse_verdict

CHECK_NAME = "payload_consistency_llm"
CHECK_NAME_ERR = "payload_consistency_llm_error"


def check_payload_llm(
    action: Action, spec: Spec, backend: LLMBackend, version: str = DEFAULT_VERSION
) -> Decision:
    """
    Drop-in replacement for agentguard.check_payload. Same signature shape,
    returns a Decision. Fail-closed on any backend or parsing problem.
    `Decision.meta` carries latency/caching/raw-output information for the
    evaluation harness.
    """
    system, user = build_messages(action, spec, version)
    t0 = time.perf_counter()
    try:
        raw = backend.complete(system, user)
    except BackendError as e:
        wall = (time.perf_counter() - t0) * 1000.0
        return Decision(
            False,
            f"guard-LLM unavailable, failing closed: {e}",
            CHECK_NAME_ERR,
            meta={"error": "backend", "latency_ms": wall, "cached": False, "raw": None},
        )
    wall = (time.perf_counter() - t0) * 1000.0
    meta = {
        "latency_ms": getattr(backend, "last_latency_ms", None) or wall,
        "cached": getattr(backend, "last_cached", False),
        "raw": raw,
        "error": None,
    }

    verdict, analysis = parse_verdict(raw)
    if verdict is None:
        meta["error"] = "parse"
        return Decision(
            False,
            f"guard-LLM output unparseable ({analysis}); failing closed",
            CHECK_NAME_ERR,
            meta=meta,
        )
    if verdict == "ALLOW":
        return Decision(True, f"guard-LLM approved: {analysis}".strip(), CHECK_NAME, meta=meta)
    return Decision(False, f"guard-LLM: {analysis}".strip(), CHECK_NAME, meta=meta)


def make_llm_checker(backend: LLMBackend, version: str = DEFAULT_VERSION) -> Check:
    """-> callable(action, spec) -> Decision, for authorize(payload_checker=)."""

    def _checker(action: Action, spec: Spec) -> Decision:
        return check_payload_llm(action, spec, backend, version)

    return _checker


def make_union_checker(backend: LLMBackend, version: str = DEFAULT_VERSION) -> Check:
    """Defense in depth: the cheap regex runs first; the LLM runs only if the
    regex passes. Either one can block ("llm+regex")."""

    def _checker(action: Action, spec: Spec) -> Decision:
        d = check_payload(action, spec)
        if not d.allowed:
            return d
        return check_payload_llm(action, spec, backend, version)

    return _checker
