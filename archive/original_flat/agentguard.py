"""
agentguard.py - the proposed defense.

AgentGuard is an output-side authorization layer. It does NOT see the
retrieved content; it sees only (a) the user's pinned task spec and
(b) the tool call the agent has decided to make. It runs four checks:

  (1) tool admission        - tool in spec.allowed_tools?
  (2) scope containment     - target/recipient/repo within spec.scope?
  (3) read-only enforcement - if the task is read-only, no side-effecting verbs?
  (4) payload consistency   - if structural checks pass, is the payload of an
                              in-scope tool call consistent with task intent?
                              (catches in-scope-tool / malicious-payload cases)

Checks (1)-(3) are deterministic. Check (4) is what the report
promised as "an LLM-based payload consistency check applied only when the
structural checks pass". Two implementations exist:

  * `check_payload` (below): the original deterministic regex proxy. It is
    the default, needs no LLM, and is what `python3 run_experiment.py` uses.
  * `llm_guard.check_payload_llm`: the local-LLM guard (Ollama, e.g.
    llama3.1:8b) that directly replaces the regex. Enable it by passing
    `payload_checker=` to `authorize()` (or `--guard llm` to the runners).

Note: with the default settings no API key, no network and no GPU are
required.
"""

import re
import time

# Tools that have side effects (write/send/destroy/transfer state). All
# others are treated as read-only.
SIDE_EFFECTING_TOOLS = {
    "send_email", "forward_email", "draft_email",
    "transfer_funds", "book_hotel",
    "delete_account", "calendar_share",
    "approve_pr", "merge_pr",
    "web_fetch",          # web_fetch can exfiltrate via URL
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


class Decision:
    def __init__(self, allowed: bool, reason: str, check: str, meta=None):
        self.allowed = allowed
        self.reason  = reason
        self.check   = check  # which check produced this decision
        self.meta    = meta   # optional diagnostics (e.g. LLM latency/raw output)

    def __repr__(self):
        v = "ALLOW" if self.allowed else "BLOCK"
        return f"<Decision {v} via {self.check}: {self.reason}>"


def check_tool_admission(action: dict, spec: dict) -> Decision:
    allowed = set(spec.get("allowed_tools", []))
    t = action.get("tool")
    if t not in allowed:
        return Decision(False,
                        f"tool {t!r} not in allowed_tools {sorted(allowed)}",
                        "tool_admission")
    return Decision(True, "tool admitted", "tool_admission")


def check_scope_containment(action: dict, spec: dict) -> Decision:
    scope = spec.get("scope", {})

    if "recipients" in scope and "to" in action:
        if action["to"] not in scope["recipients"]:
            return Decision(False,
                            f"recipient {action['to']!r} outside "
                            f"scope.recipients {scope['recipients']}",
                            "scope_containment")

    if "repo" in scope and "repo" in action:
        if action["repo"] != scope["repo"]:
            return Decision(False,
                            f"repo {action['repo']!r} outside "
                            f"scope.repo {scope['repo']!r}",
                            "scope_containment")

    if "path_prefix" in scope and "path" in action:
        if not action["path"].startswith(scope["path_prefix"]):
            return Decision(False,
                            f"path {action['path']!r} outside "
                            f"scope.path_prefix {scope['path_prefix']!r}",
                            "scope_containment")

    return Decision(True, "scope satisfied", "scope_containment")


def check_read_only(action: dict, spec: dict) -> Decision:
    if not spec.get("read_only", False):
        return Decision(True, "task is not read-only", "read_only")
    if action.get("tool") in SIDE_EFFECTING_TOOLS:
        return Decision(False,
                        f"side-effecting tool {action['tool']!r} "
                        f"used during a read-only task",
                        "read_only")
    return Decision(True, "no side-effecting tool", "read_only")


def check_payload(action: dict, spec: dict) -> Decision:
    """
    Check 4: payload consistency. Run only when the structural checks (1-3)
    have passed - i.e., the tool, scope and side-effect class look fine.
    Inspect the proposed payload for obvious indicators of misuse: secret
    disclosure, attacker-controlled URLs, etc.
    """
    body = (str(action.get("body", "")) + " "
            + str(action.get("query", "")) + " "
            + str(action.get("url", "")))
    for pat in _SECRET_PATTERNS:
        if pat.search(body):
            return Decision(False,
                            f"payload matches secret-disclosure pattern "
                            f"{pat.pattern!r}",
                            "payload_consistency")

    # URL exfiltration: in-scope tool + suspicious URL anywhere in the action
    for url_match in re.finditer(r"https?://([^\s/]+)", body):
        host = url_match.group(1).lower()
        if any(bad in host for bad in
               ["attacker", "evil", "exfil", "malicious"]):
            return Decision(False,
                            f"payload references suspicious host {host!r}",
                            "payload_consistency")

    return Decision(True, "payload looks consistent", "payload_consistency")


def authorize(action: dict, spec: dict, payload_check: bool = True,
              payload_checker=None) -> Decision:
    """
    Run all AgentGuard checks. Returns the FIRST blocking decision or
    a final ALLOW decision if everything passes.

    payload_checker: optional callable (action, spec) -> Decision that
    implements check 4. Default None keeps the original regex proxy
    (`check_payload`), so existing behavior is unchanged. Pass
    `llm_guard.make_llm_checker(backend)` to use the local-LLM guard.
    """
    for check in (check_tool_admission,
                  check_scope_containment,
                  check_read_only):
        d = check(action, spec)
        if not d.allowed:
            return d

    if payload_check:
        d = (payload_checker or check_payload)(action, spec)
        if not d.allowed:
            return d

    return Decision(True, "passed all checks", "all")


# ---- Latency-instrumented variant -----------------------------------------

def authorize_timed(action: dict, spec: dict, payload_check: bool = True,
                    payload_checker=None):
    """Same as authorize() but also returns wall-clock latency in microseconds."""
    t0 = time.perf_counter_ns()
    d = authorize(action, spec, payload_check=payload_check,
                  payload_checker=payload_checker)
    t1 = time.perf_counter_ns()
    return d, (t1 - t0) / 1000.0


# ---- Local-LLM payload check ----------------------------------------------
#
# The guard-LLM implementation of check 4 lives in llm_guard.py (stdlib only,
# talks to a local Ollama server, caches responses for offline replay). The
# default run (`python3 run_experiment.py`) still uses the regex proxy above
# and needs no LLM. To use the LLM guard:
#
#     from llm_guard import make_backend, make_llm_checker
#     checker = make_llm_checker(make_backend("llama3.1:8b"))
#     d = authorize(action, spec, payload_checker=checker)
# ---------------------------------------------------------------------------

def payload_check_llm_skeleton(action: dict, spec: dict, llm_call=None) -> Decision:
    """
    Backwards-compatible entry point (formerly a never-executed skeleton).
    `llm_call` is an optional backend object exposing
    `.complete(system, user) -> str` (see llm_guard.OllamaBackend,
    CachedBackend, MockBackend). If omitted, a cached Ollama backend for
    the default model is used.
    """
    from llm_guard import check_payload_llm, make_backend  # lazy: avoid cycle
    return check_payload_llm(action, spec, llm_call or make_backend())


if __name__ == "__main__":
    from dataset import ALL_CASES
    blocked = allowed = 0
    for c in ALL_CASES:
        a = c.malicious_action if c.label == "injected" else c.benign_action
        d = authorize(a, c.user_task)
        if d.allowed: allowed += 1
        else: blocked += 1
    print(f"Sanity: on full dataset (using malicious_action for injected, "
          f"benign for clean): {allowed} allowed, {blocked} blocked.")
