"""Local-LLM implementation of check 4 and its supporting pieces."""

from agentguard.llm.backends import (
    DEFAULT_CACHE,
    DEFAULT_HOST,
    DEFAULT_MODEL,
    BackendError,
    CachedBackend,
    CacheMiss,
    MockBackend,
    OllamaBackend,
    make_backend,
)
from agentguard.llm.factory import ConfigError, make_payload_checker
from agentguard.llm.guard import (
    CHECK_NAME,
    CHECK_NAME_ERR,
    check_payload_llm,
    make_llm_checker,
    make_union_checker,
)
from agentguard.llm.prompts import (
    DEFAULT_VERSION,
    GUARD_VERSIONS,
    build_messages,
    prompt_hash,
)
from agentguard.llm.verdict import parse_verdict

__all__ = [
    "CHECK_NAME",
    "CHECK_NAME_ERR",
    "DEFAULT_CACHE",
    "DEFAULT_HOST",
    "DEFAULT_MODEL",
    "DEFAULT_VERSION",
    "GUARD_VERSIONS",
    "BackendError",
    "CacheMiss",
    "CachedBackend",
    "ConfigError",
    "MockBackend",
    "OllamaBackend",
    "build_messages",
    "check_payload_llm",
    "make_backend",
    "make_llm_checker",
    "make_payload_checker",
    "make_union_checker",
    "parse_verdict",
    "prompt_hash",
]
