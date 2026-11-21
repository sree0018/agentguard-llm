"""Command-line interface: ``agentguard <command>`` (or ``python -m agentguard``)."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Sequence

from agentguard import __version__
from agentguard.core.pipeline import AgentGuard
from agentguard.llm.backends import DEFAULT_CACHE, DEFAULT_HOST, DEFAULT_MODEL
from agentguard.llm.factory import ConfigError, make_payload_checker
from agentguard.llm.prompts import DEFAULT_VERSION, GUARD_VERSIONS, prompt_hash

#: Commands that forward their remaining arguments to an evaluation runner.
_RUNNERS = {
    "benchmark": ("agentguard.evaluation.benchmark", "original 70-case benchmark (no LLM needed)"),
    "redteam": ("agentguard.evaluation.redteam", "red-team check 4 on the attack/benign sets"),
    "adaptive": ("agentguard.evaluation.adaptive", "adaptive attacker with a query budget"),
    "liu": ("agentguard.evaluation.liu", "Liu et al. attack-strategy benchmark"),
    "report": ("agentguard.evaluation.report", "regenerate docs/results.md from the CSVs"),
}


def _cmd_check(args: argparse.Namespace) -> int:
    try:
        action = json.loads(args.action)
        spec = json.loads(args.spec)
    except json.JSONDecodeError as exc:
        print(f"error: invalid JSON: {exc}", file=sys.stderr)
        return 2
    try:
        label, checker = make_payload_checker(args.guard, args.llm_mode, args.cache)
    except ConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    guard = AgentGuard(payload_checker=checker)
    for name, decision, ms in guard.trace(action, spec):
        if decision is None:
            print(f"  -  {name:<26} skipped")
        else:
            mark = "ok " if decision.allowed else "BLOCK"
            print(f"  {mark:<5} {name:<26} {ms:9.1f} ms  {decision.reason[:90]}")
    final = guard.authorize(action, spec)
    print(f"\n{'ALLOW' if final.allowed else 'BLOCK'}  [{label}]  via {final.check}")
    return 0 if final.allowed else 1


def _cmd_demo(args: argparse.Namespace) -> int:
    from agentguard.demo.runner import run_demo
    from agentguard.demo.scenarios import SCENARIOS

    if args.list:
        for s in SCENARIOS:
            print(f"{s.key:<14} {s.title}")
        return 0
    return run_demo(
        scenario_keys=args.scenario or None,
        llm_mode="live" if args.live else "replay",
        model=args.model,
        version=args.guard_version,
        pause=args.pause,
        color=False if args.no_color else None,
        cache_path=args.cache,
    )


def _cmd_versions(_: argparse.Namespace) -> int:
    print(f"{'version':<8}{'hash':<14}{'pre-pass':<10}")
    for v, (_, with_notes) in GUARD_VERSIONS.items():
        star = "  (default)" if v == DEFAULT_VERSION else ""
        print(f"{v:<8}{prompt_hash(v):<14}{'yes' if with_notes else 'no':<10}{star}")
    return 0


def _cmd_doctor(args: argparse.Namespace) -> int:
    import os

    ok = True
    print(f"agentguard {__version__}, python {sys.version.split()[0]}")
    if os.path.exists(args.cache):
        with open(args.cache, encoding="utf-8") as f:
            n = len(json.load(f))
        print(f"[ok]   response cache: {n} saved model responses ({args.cache})")
    else:
        ok = False
        print(f"[warn] no response cache at {args.cache}: replay mode will not work")
    try:
        with urllib.request.urlopen(args.host.rstrip("/") + "/api/tags", timeout=2) as r:
            models = [m["name"] for m in json.loads(r.read())["models"]]
        have = args.model in models
        print(f"[ok]   Ollama reachable at {args.host}; models: {', '.join(models) or 'none'}")
        if not have:
            print(f"[warn] model {args.model} not pulled: run `ollama pull {args.model}`")
    except (urllib.error.URLError, OSError, KeyError, ValueError):
        print(
            f"[info] Ollama not reachable at {args.host} (fine: demo/replay works offline;"
            " start it with `ollama serve` for live mode)"
        )
    return 0 if ok else 1


def build_parser() -> argparse.ArgumentParser:
    """Create the top-level argument parser."""
    p = argparse.ArgumentParser(
        prog="agentguard",
        description="Output-side authorization of agent tool calls with a local-LLM payload guard.",
    )
    p.add_argument("--version", action="version", version=f"agentguard {__version__}")
    sub = p.add_subparsers(dest="command", required=True, metavar="<command>")

    d = sub.add_parser("demo", help="presenter-friendly walkthrough (works offline)")
    d.add_argument("--scenario", action="append", help="run only this scenario (repeatable)")
    d.add_argument("--list", action="store_true", help="list scenarios and exit")
    d.add_argument(
        "--live", action="store_true", help="query a running Ollama instead of the cache"
    )
    d.add_argument("--pause", action="store_true", help="wait for Enter between scenarios")
    d.add_argument("--no-color", action="store_true")
    d.add_argument("--model", default=DEFAULT_MODEL)
    d.add_argument("--guard-version", default=DEFAULT_VERSION, choices=list(GUARD_VERSIONS))
    d.add_argument("--cache", default=DEFAULT_CACHE)
    d.set_defaults(func=_cmd_demo)

    c = sub.add_parser("check", help="authorize one tool call (JSON in, verdict out)")
    c.add_argument("--action", required=True, help='JSON, e.g. \'{"tool":"respond","body":"hi"}\'')
    c.add_argument("--spec", required=True, help="JSON pinned task spec")
    c.add_argument(
        "--guard", default=f"llm={DEFAULT_MODEL}", help="regex | llm=<model>[#v] | union=..."
    )
    c.add_argument("--llm-mode", choices=["auto", "live", "replay"], default="auto")
    c.add_argument("--cache", default=DEFAULT_CACHE)
    c.set_defaults(func=_cmd_check)

    v = sub.add_parser("versions", help="list guard prompt versions and hashes")
    v.set_defaults(func=_cmd_versions)

    dr = sub.add_parser("doctor", help="check the environment (cache, Ollama)")
    dr.add_argument("--model", default=DEFAULT_MODEL)
    dr.add_argument("--host", default=DEFAULT_HOST)
    dr.add_argument("--cache", default=DEFAULT_CACHE)
    dr.set_defaults(func=_cmd_doctor)

    for name, (_, helptext) in _RUNNERS.items():
        # Dispatched in main() before parsing (argparse.REMAINDER cannot forward a
        # leading option); registered here so the command shows up in --help.
        sub.add_parser(name, help=helptext, add_help=False)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point. Returns a process exit code."""
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in _RUNNERS:
        import importlib

        importlib.import_module(_RUNNERS[argv[0]][0]).main(argv[1:])
        return 0
    args = build_parser().parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
