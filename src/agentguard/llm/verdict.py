"""Strict, fail-closed parsing of the guard model's reply."""

from __future__ import annotations

import json
import re


def parse_verdict(text):
    """
    Returns (verdict, analysis) with verdict in {"ALLOW", "BLOCK"}, or
    (None, reason) if the response is not a well-formed verdict.

    Deliberately strict: we accept only a JSON object whose "verdict" is
    exactly ALLOW or BLOCK. We never scan free text for the word ALLOW,
    because the (attacker-influenced) payload could be echoed back there.
    """
    if not isinstance(text, str):
        return None, "non-string response"
    s = text.strip()
    obj = None
    try:
        obj = json.loads(s)
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", s, re.DOTALL)
        if m:
            try:
                obj = json.loads(m.group(0))
            except json.JSONDecodeError:
                obj = None
    if not isinstance(obj, dict):
        return None, "response is not a JSON object"
    v = obj.get("verdict")
    if not isinstance(v, str) or v.strip().upper() not in ("ALLOW", "BLOCK"):
        return None, f"invalid verdict field: {v!r}"
    analysis = obj.get("analysis", "")
    return v.strip().upper(), analysis if isinstance(analysis, str) else ""
