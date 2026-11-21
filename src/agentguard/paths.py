"""Filesystem locations for results and caches."""

from __future__ import annotations

import os
from pathlib import Path


def project_root() -> Path:
    """Repository root when running from a checkout, else the current directory.

    Override with the ``AGENTGUARD_HOME`` environment variable.
    """
    env = os.environ.get("AGENTGUARD_HOME")
    if env:
        return Path(env)
    candidate = Path(__file__).resolve().parents[2]
    return candidate if (candidate / "pyproject.toml").exists() else Path.cwd()


def results_dir() -> Path:
    """Directory that holds result files (``results/``)."""
    return project_root() / "results"


def docs_dir() -> Path:
    """Directory that holds generated documentation (``docs/``)."""
    return project_root() / "docs"
