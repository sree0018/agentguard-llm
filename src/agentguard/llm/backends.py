"""LLM backends for the guard: Ollama client, on-disk cache, and a test mock.

Everything here is standard-library only. The guard talks to a *local* Ollama
server; no API key and no remote service is involved.

``CachedBackend`` is what makes the evaluation reproducible: every response is
stored on disk keyed by ``(model options, system prompt, user prompt)``. In
``replay`` mode the cache is the only source of responses, so published numbers
can be reproduced offline with no model installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.error
import urllib.request
from typing import Protocol

from agentguard.paths import results_dir

DEFAULT_MODEL = "llama3.1:8b"
DEFAULT_HOST = "http://localhost:11434"
DEFAULT_CACHE = str(results_dir() / "llm" / "llm_cache.json")


class LLMBackend(Protocol):
    """Anything that can answer a (system, user) prompt pair with text."""

    def complete(self, system: str, user: str) -> str:
        """Return the model's raw reply or raise :class:`BackendError`."""
        ...


class BackendError(Exception):
    """The LLM backend could not produce a response."""


class CacheMiss(BackendError):
    """replay mode: the requested response is not in the cache."""


def _schema(schema_mode):
    """JSON schema used for constrained decoding. Property order matters:
    with 'analysis' first the model reasons briefly before committing."""
    verdict = {"type": "string", "enum": ["ALLOW", "BLOCK"]}
    if schema_mode == "verdict":
        return {"type": "object", "properties": {"verdict": verdict}, "required": ["verdict"]}
    return {
        "type": "object",
        "properties": {"analysis": {"type": "string"}, "verdict": verdict},
        "required": ["analysis", "verdict"],
    }


class OllamaBackend:
    """Minimal Ollama /api/chat client (stdlib urllib)."""

    def __init__(
        self,
        model=DEFAULT_MODEL,
        host=DEFAULT_HOST,
        seed=42,
        num_predict=200,
        num_ctx=4096,
        timeout=180,
        schema_mode="analysis",
    ):
        self.model = model
        self.host = host.rstrip("/")
        self.seed = seed
        self.num_predict = num_predict
        self.num_ctx = num_ctx
        self.timeout = timeout
        self.schema_mode = schema_mode
        self.last_latency_ms = None
        self.last_cached = False

    def fingerprint(self):
        """Everything that changes the model's output, for the cache key."""
        return json.dumps(
            {
                "model": self.model,
                "seed": self.seed,
                "temperature": 0,
                "num_predict": self.num_predict,
                "num_ctx": self.num_ctx,
                "schema": self.schema_mode,
            },
            sort_keys=True,
        )

    def complete(self, system, user):
        body = {
            "model": self.model,
            "stream": False,
            "format": _schema(self.schema_mode),
            "messages": [{"role": "system", "content": system}, {"role": "user", "content": user}],
            "options": {
                "temperature": 0,
                "seed": self.seed,
                "num_predict": self.num_predict,
                "num_ctx": self.num_ctx,
            },
        }
        req = urllib.request.Request(
            self.host + "/api/chat",
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        t0 = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=self.timeout) as r:
                payload = json.loads(r.read().decode("utf-8"))
        except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as e:
            raise BackendError(f"Ollama request failed: {e}") from e
        self.last_latency_ms = (time.perf_counter() - t0) * 1000.0
        self.last_cached = False
        try:
            return payload["message"]["content"]
        except (KeyError, TypeError) as e:
            raise BackendError(f"unexpected Ollama response: {payload!r}") from e


class MockBackend:
    """Deterministic stand-in for tests: `fn(system, user) -> str`."""

    def __init__(self, fn, model="mock"):
        self.fn = fn
        self.model = model
        self.calls = 0
        self.last_latency_ms = 0.0
        self.last_cached = False

    def fingerprint(self):
        return json.dumps({"model": self.model})

    def complete(self, system, user):
        self.calls += 1
        return self.fn(system, user)


class CachedBackend:
    """
    On-disk response cache in front of another backend.

    mode = "auto"   : use the cache if present, else call the backend and store.
    mode = "live"   : always call the backend (refreshing the cache entry).
    mode = "replay" : cache only; a miss raises CacheMiss (offline repro).
    """

    def __init__(self, inner, path=DEFAULT_CACHE, mode="auto"):
        assert mode in ("auto", "live", "replay")
        self.inner = inner
        self.path = path
        self.mode = mode
        self.model = getattr(inner, "model", "unknown")
        self.last_latency_ms = None
        self.last_cached = False
        self._cache = {}
        if os.path.exists(path):
            with open(path, encoding="utf-8") as f:
                self._cache = json.load(f)

    def fingerprint(self):
        return self.inner.fingerprint()

    def _key(self, system, user):
        h = hashlib.sha256()
        for part in (self.inner.fingerprint(), system, user):
            h.update(part.encode("utf-8"))
            h.update(b"\x00")
        return h.hexdigest()

    def _save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self._cache, f, indent=1, sort_keys=True, ensure_ascii=True)
        os.replace(tmp, self.path)

    def complete(self, system, user):
        key = self._key(system, user)
        if self.mode != "live" and key in self._cache:
            e = self._cache[key]
            self.last_cached = True
            self.last_latency_ms = e.get("latency_ms")
            return e["response"]
        if self.mode == "replay":
            raise CacheMiss(
                f"no cached response for key {key[:12]}... "
                f"(model {self.model}); re-run with Ollama in --llm-mode auto "
                f"to populate {self.path}"
            )
        text = self.inner.complete(system, user)
        self.last_cached = False
        self.last_latency_ms = self.inner.last_latency_ms
        self._cache[key] = {
            "model": self.model,
            "response": text,
            "latency_ms": round(self.inner.last_latency_ms or 0.0, 1),
        }
        self._save()
        return text


def make_backend(
    model=DEFAULT_MODEL, mode="auto", cache_path=DEFAULT_CACHE, schema_mode="analysis", **kw
):
    """Convenience factory used by the runners."""
    return CachedBackend(
        OllamaBackend(model=model, schema_mode=schema_mode, **kw), path=cache_path, mode=mode
    )
