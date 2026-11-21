"""The four AgentGuard checks.

Checks 1-3 (tool admission, scope containment, read-only enforcement) are
deterministic and structural. Check 4 (payload consistency) has two
implementations: the regex proxy below (the default, no LLM needed) and the
local-LLM guard in :mod:`agentguard.llm.guard`.
"""

from __future__ import annotations

import re

from agentguard.core.types import Action, Decision, Spec

# Tools that have side effects (write/send/destroy/transfer state). All
# others are treated as read-only.
SIDE_EFFECTING_TOOLS = {
    "send_email",
    "forward_email",
    "draft_email",
    "transfer_funds",
    "book_hotel",
    "delete_account",
    "calendar_share",
    "approve_pr",
    "merge_pr",
    "web_fetch",  # web_fetch can exfiltrate via URL
}

# Suspicious payload patterns (used by check 4). In production these are
# replaced by a guard-LLM call.
_SECRET_PATTERNS = [
    re.compile(r"\bAPI[_-]?KEY\b", re.IGNORECASE),
    re.compile(r"\bsk-(live|test)-[A-Za-z0-9]+", re.IGNORECASE),
    re.compile(r"\bpassword\s*[:=]", re.IGNORECASE),
    re.compile(r"\baws_?(secret|access)_?key", re.IGNORECASE),
    re.compile(r"\bbearer\s+[A-Za-z0-9._-]+", re.IGNORECASE),
    re.compile(r"\bsession[_-]?token", re.IGNORECASE),
]


def check_tool_admission(action: Action, spec: Spec) -> Decision:
    """Check 1: the tool must be in the task's ``allowed_tools``."""
    allowed = set(spec.get("allowed_tools", []))
    t = action.get("tool")
    if t not in allowed:
        return Decision(
            False, f"tool {t!r} not in allowed_tools {sorted(allowed)}", "tool_admission"
        )
    return Decision(True, "tool admitted", "tool_admission")


def check_scope_containment(action: Action, spec: Spec) -> Decision:
    """Check 2: recipient, repository and path must stay inside the pinned scope."""
    scope = spec.get("scope", {})

    if "recipients" in scope and "to" in action and action["to"] not in scope["recipients"]:
        return Decision(
            False,
            f"recipient {action['to']!r} outside scope.recipients {scope['recipients']}",
            "scope_containment",
        )

    if "repo" in scope and "repo" in action and action["repo"] != scope["repo"]:
        return Decision(
            False,
            f"repo {action['repo']!r} outside scope.repo {scope['repo']!r}",
            "scope_containment",
        )

    if (
        "path_prefix" in scope
        and "path" in action
        and not action["path"].startswith(scope["path_prefix"])
    ):
        return Decision(
            False,
            f"path {action['path']!r} outside scope.path_prefix {scope['path_prefix']!r}",
            "scope_containment",
        )

    return Decision(True, "scope satisfied", "scope_containment")


def check_read_only(action: Action, spec: Spec) -> Decision:
    """Check 3: a read-only task may not use side-effecting tools."""
    if not spec.get("read_only", False):
        return Decision(True, "task is not read-only", "read_only")
    if action.get("tool") in SIDE_EFFECTING_TOOLS:
        return Decision(
            False,
            f"side-effecting tool {action['tool']!r} used during a read-only task",
            "read_only",
        )
    return Decision(True, "no side-effecting tool", "read_only")


def check_payload(action: Action, spec: Spec) -> Decision:
    """
    Check 4: payload consistency. Run only when the structural checks (1-3)
    have passed - i.e., the tool, scope and side-effect class look fine.
    Inspect the proposed payload for obvious indicators of misuse: secret
    disclosure, attacker-controlled URLs, etc.
    """
    body = (
        str(action.get("body", ""))
        + " "
        + str(action.get("query", ""))
        + " "
        + str(action.get("url", ""))
    )
    for pat in _SECRET_PATTERNS:
        if pat.search(body):
            return Decision(
                False,
                f"payload matches secret-disclosure pattern {pat.pattern!r}",
                "payload_consistency",
            )

    # URL exfiltration: in-scope tool + suspicious URL anywhere in the action
    for url_match in re.finditer(r"https?://([^\s/]+)", body):
        host = url_match.group(1).lower()
        if any(bad in host for bad in ["attacker", "evil", "exfil", "malicious"]):
            return Decision(
                False, f"payload references suspicious host {host!r}", "payload_consistency"
            )

    return Decision(True, "payload looks consistent", "payload_consistency")
