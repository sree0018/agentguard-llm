"""Terminal renderer and driver for the demo."""

from __future__ import annotations

import json
import os
import sys
import textwrap
from collections.abc import Callable
from dataclasses import dataclass

from agentguard.core.pipeline import AgentGuard
from agentguard.core.types import Action, Decision, Spec
from agentguard.demo.scenarios import SCENARIOS, Scenario, by_key
from agentguard.llm.backends import DEFAULT_CACHE
from agentguard.llm.factory import make_payload_checker
from agentguard.llm.prompts import DEFAULT_VERSION, prompt_hash

WIDTH = 78
_STAGE_LABELS = {
    "check_tool_admission": "1  tool admission",
    "check_scope_containment": "2  scope containment",
    "check_read_only": "3  read-only enforcement",
    "payload_consistency": "4  payload consistency",
}


class Style:
    """ANSI styling that turns itself off for pipes and ``NO_COLOR``."""

    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def green(self, t: str) -> str:
        return self._wrap("32;1", t)

    def red(self, t: str) -> str:
        return self._wrap("31;1", t)

    def amber(self, t: str) -> str:
        return self._wrap("33;1", t)

    def cyan(self, t: str) -> str:
        return self._wrap("36", t)


@dataclass
class Outcome:
    """Result of one scenario, used for the closing scoreboard."""

    scenario: Scenario
    regex_allowed: bool | None
    llm_allowed: bool | None
    final_allowed: bool


def _load_case(cid: str) -> tuple[Action, Spec]:
    from agentguard.evaluation.redteam import build_items

    for item in build_items():
        if item.cid == cid:
            return item.action, item.spec
    raise KeyError(f"case {cid!r} not found in the red-team datasets")


def _short(text: str, limit: int = 110) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _rule(st: Style, label: str = "") -> str:
    line = "─" * WIDTH
    if not label:
        return st.dim(line)
    pad = f"── {label} "
    return st.dim(pad + "─" * max(0, WIDTH - len(pad)))


def _verdict(st: Style, allowed: bool) -> str:
    return st.green("ALLOW") if allowed else st.red("BLOCK")


def _print_trace(
    st: Style, guard: AgentGuard, action: Action, spec: Spec, out: Callable[[str], None]
) -> Decision:
    final = Decision(True, "passed all checks", "all")
    for name, decision, ms in guard.trace(action, spec):
        label = _STAGE_LABELS.get(name, name)
        if decision is None:
            out(f"   {st.dim('·')} {st.dim(label + '  (skipped)')}")
            continue
        mark = st.green("✔") if decision.allowed else st.red("✘")
        # LLM decisions carry the model's own latency (recorded, even when replayed
        # from the cache); everything else is timed here.
        ms = float((decision.meta or {}).get("latency_ms") or ms)
        timing = f"{ms:8.0f} ms" if ms >= 1 else f"{ms * 1000:8.0f} µs"
        out(f"   {mark} {label:<26}{st.dim(timing)}")
        if not decision.allowed:
            final = decision
            for line in textwrap.wrap(decision.reason, WIDTH - 9):
                out(f"       {st.dim(line)}")
    return final


def run_scenario(
    sc: Scenario,
    llm_checker: Callable[[Action, Spec], Decision] | None,
    st: Style,
    out: Callable[[str], None] = print,
) -> Outcome:
    """Render one scenario and return its outcome."""
    action, spec = _load_case(sc.cid) if sc.cid else (sc.action, sc.spec)
    out("")
    out(_rule(st, sc.title))
    for line in textwrap.wrap(sc.story, WIDTH):
        out(line)
    out("")
    out(
        st.bold("Pinned task   ")
        + f"{spec.get('intent', '?')}  "
        + st.dim(f"tools={spec.get('allowed_tools')} read_only={spec.get('read_only')}")
    )
    out(st.bold("Agent wants   ") + st.cyan(_short(json.dumps(action, ensure_ascii=False))))
    out("")

    regex_allowed: bool | None = None
    llm_allowed: bool | None = None
    if sc.compare_regex and llm_checker is not None:
        out(st.bold(" Regex check 4 (original)"))
        regex_final = _print_trace(st, AgentGuard(), action, spec, out)
        regex_allowed = regex_final.allowed
        out("")
        out(st.bold(" LLM check 4 (this project)"))
        llm_final = _print_trace(st, AgentGuard(payload_checker=llm_checker), action, spec, out)
        llm_allowed = llm_final.allowed
        out("")
        out(f"   regex → {_verdict(st, regex_allowed)}     LLM guard → {_verdict(st, llm_allowed)}")
        final_allowed = llm_allowed
    else:
        guard = AgentGuard(payload_checker=llm_checker) if llm_checker else AgentGuard()
        final = _print_trace(st, guard, action, spec, out)
        final_allowed = final.allowed
        out("")
        out(f"   Final decision: {_verdict(st, final_allowed)}")
    out("")
    wrapped = textwrap.wrap(sc.takeaway, WIDTH - 5)
    out(st.amber("   → ") + wrapped[0])
    for line in wrapped[1:]:
        out("     " + line)
    return Outcome(sc, regex_allowed, llm_allowed, final_allowed)


def _scoreboard(outcomes: list[Outcome], st: Style, out: Callable[[str], None]) -> None:
    out("")
    out(_rule(st, "scoreboard"))
    out(f"  {'scenario':<34}{'regex':>8}{'LLM guard':>12}")
    for o in outcomes:
        r = "-" if o.regex_allowed is None else ("ALLOW" if o.regex_allowed else "BLOCK")
        lm = "ALLOW" if o.final_allowed else "BLOCK"
        if o.llm_allowed is None:
            lm = "(same)" if o.regex_allowed is None else lm
        out(f"  {o.scenario.title[:33]:<34}{r:>8}{lm:>12}")
    out("")
    out("  Pooled held-out result (139 attacks): regex lets 96% through, strict LLM guard 12%;")
    out("  the price is a ~12% false-alarm rate. Full numbers: docs/results.md")


def run_demo(
    scenario_keys: list[str] | None = None,
    llm_mode: str = "replay",
    model: str = "llama3.1:8b",
    version: str = DEFAULT_VERSION,
    pause: bool = False,
    color: bool | None = None,
    cache_path: str = DEFAULT_CACHE,
    out: Callable[[str], None] = print,
) -> int:
    """Run the walkthrough. Returns a process exit code."""
    if color is None:
        color = sys.stdout.isatty() and "NO_COLOR" not in os.environ
    st = Style(color)
    _, llm_checker = make_payload_checker(f"llm={model}#{version}", llm_mode, cache_path)

    chosen = [by_key(k) for k in scenario_keys] if scenario_keys else list(SCENARIOS)
    out(
        st.bold("AgentGuard demo")
        + st.dim(f"   guard {version} ({prompt_hash(version)}) · model {model} · mode {llm_mode}")
    )
    out(
        st.dim(
            "The guard sees only the pinned task and the proposed tool call, never the "
            "retrieved content."
        )
    )
    outcomes: list[Outcome] = []
    for sc in chosen:
        if pause and outcomes:
            input(st.dim("\n  [Enter] next scenario "))
        try:
            outcomes.append(run_scenario(sc, llm_checker, st, out))
        except KeyError as exc:
            out(f"  skipped {sc.key}: {exc}")
    _scoreboard(outcomes, st, out)
    return 0
