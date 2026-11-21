"""Tests for the framework layer: pipeline class, factory, CLI and demo."""

from __future__ import annotations

import io
import json
import unittest
from contextlib import redirect_stdout

from agentguard import AgentGuard, Decision, authorize, make_payload_checker
from agentguard.cli import main as cli_main
from agentguard.demo.runner import run_demo
from agentguard.demo.scenarios import SCENARIOS
from agentguard.llm import ConfigError, MockBackend, make_llm_checker

SPEC = {
    "intent": "summarize_pdf",
    "allowed_tools": ["read_pdf", "respond"],
    "scope": {"recipients": ["self"]},
    "read_only": True,
}
GOOD = {"tool": "respond", "to": "self", "body": "Summary."}
BAD_TOOL = {"tool": "transfer_funds", "to": "x", "amount": 1}


class PipelineTests(unittest.TestCase):
    def test_trace_matches_authorize(self) -> None:
        guard = AgentGuard()
        for action in (GOOD, BAD_TOOL):
            final = guard.authorize(action, SPEC)
            trace = guard.trace(action, SPEC)
            blocked = [d for _, d, _ in trace if d is not None and not d.allowed]
            self.assertEqual(final.allowed, not blocked)
            if blocked:
                self.assertEqual(blocked[0].check, final.check)

    def test_trace_marks_later_stages_skipped(self) -> None:
        trace = AgentGuard().trace(BAD_TOOL, SPEC)
        self.assertIsNotNone(trace[0][1])
        self.assertTrue(all(d is None for _, d, _ in trace[1:]))

    def test_custom_structural_checks_extend_pipeline(self) -> None:
        def never(_a: dict, _s: dict) -> Decision:
            return Decision(False, "custom", "custom")

        guard = AgentGuard(structural_checks=[never])
        self.assertEqual(guard.authorize(GOOD, SPEC).check, "custom")

    def test_payload_check_can_be_disabled(self) -> None:
        checker = make_llm_checker(MockBackend(lambda s, u: self.fail("must not run")))
        guard = AgentGuard(payload_checker=checker, payload_check=False)
        self.assertTrue(guard.authorize(GOOD, SPEC).allowed)

    def test_function_and_class_agree(self) -> None:
        self.assertEqual(authorize(GOOD, SPEC).allowed, AgentGuard().authorize(GOOD, SPEC).allowed)


class FactoryTests(unittest.TestCase):
    def test_regex_has_no_checker(self) -> None:
        self.assertEqual(make_payload_checker("regex"), ("regex", None))

    def test_llm_label_and_callable(self) -> None:
        label, checker = make_payload_checker("llm=llama3.1:8b#v1p", llm_mode="replay")
        self.assertEqual(label, "llm:llama3.1:8b#v1p")
        self.assertTrue(callable(checker))

    def test_unknown_config(self) -> None:
        with self.assertRaises(ConfigError):
            make_payload_checker("magic=1")


class CliTests(unittest.TestCase):
    def _run(self, argv: list[str]) -> tuple[int, str]:
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = cli_main(argv)
        return code, buf.getvalue()

    def test_versions_lists_default_and_hash(self) -> None:
        code, out = self._run(["versions"])
        self.assertEqual(code, 0)
        self.assertIn("d4c05c622fca", out)
        self.assertIn("(default)", out)

    def test_check_regex_blocks_disallowed_tool(self) -> None:
        code, out = self._run(
            [
                "check",
                "--guard",
                "regex",
                "--action",
                json.dumps(BAD_TOOL),
                "--spec",
                json.dumps(SPEC),
            ]
        )
        self.assertEqual(code, 1)
        self.assertIn("BLOCK", out)

    def test_check_rejects_bad_json(self) -> None:
        code, _ = self._run(["check", "--guard", "regex", "--action", "{", "--spec", "{}"])
        self.assertEqual(code, 2)

    def test_demo_list(self) -> None:
        code, out = self._run(["demo", "--list"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), len(SCENARIOS))


class DemoTests(unittest.TestCase):
    def test_structural_scenarios_need_no_llm(self) -> None:
        lines: list[str] = []
        code = run_demo(scenario_keys=["tool", "scope", "readonly"], color=False, out=lines.append)
        text = "\n".join(lines)
        self.assertEqual(code, 0)
        self.assertEqual(text.count("Final decision: BLOCK"), 3)

    def test_replay_scenarios_reproduce_committed_decisions(self) -> None:
        lines: list[str] = []
        run_demo(scenario_keys=["blindspot", "miss", "false-alarm"], color=False, out=lines.append)
        text = "\n".join(lines)
        self.assertIn("regex → ALLOW     LLM guard → BLOCK", text)  # blind spot caught
        self.assertEqual(text.count("regex → ALLOW     LLM guard → ALLOW"), 1)  # honest miss
        self.assertEqual(text.count("LLM guard → BLOCK"), 2)  # blind spot + false alarm


if __name__ == "__main__":
    unittest.main()
