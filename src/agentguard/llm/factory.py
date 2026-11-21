"""Build a check-4 implementation from a short configuration string.

Syntax::

    regex
    llm=<model>[@analysis|@verdict][#<version>]
    union=<model>[@schema][#<version>]

``union`` runs the regex first and the LLM only if the regex passes (either may
block). The default guard version is :data:`agentguard.llm.prompts.DEFAULT_VERSION`.
"""

from __future__ import annotations

from agentguard.core.types import Check
from agentguard.llm.backends import DEFAULT_CACHE, DEFAULT_MODEL, make_backend
from agentguard.llm.guard import make_llm_checker, make_union_checker
from agentguard.llm.prompts import DEFAULT_VERSION


class ConfigError(ValueError):
    """The guard configuration string could not be parsed."""


def make_payload_checker(
    config: str,
    llm_mode: str = "auto",
    cache_path: str = DEFAULT_CACHE,
) -> tuple[str, Check | None]:
    """Parse ``config`` and return ``(label, checker)``.

    ``checker`` is ``None`` for the regex proxy (the pipeline default).

    Raises:
        ConfigError: if ``config`` is not a recognised guard configuration.
    """
    if config == "regex":
        return "regex", None
    kind, _, rest = config.partition("=")
    rest, _, version = rest.partition("#")
    version = version or DEFAULT_VERSION
    model, _, schema = rest.partition("@")
    schema = schema or "analysis"
    if kind not in ("llm", "union"):
        raise ConfigError(f"unknown guard config {config!r}")
    backend = make_backend(
        model=model or DEFAULT_MODEL,
        mode=llm_mode,
        cache_path=cache_path,
        schema_mode=schema,
    )
    label = f"{kind}:{model}" + ("" if schema == "analysis" else f"@{schema}") + f"#{version}"
    if kind == "llm":
        return label, make_llm_checker(backend, version)
    return label, make_union_checker(backend, version)
