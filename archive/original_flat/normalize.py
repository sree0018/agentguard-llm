"""
normalize.py - deterministic EVIDENCE pre-pass for the guard LLM (guard v2).

A small local LLM cannot reliably decode base64, see zero-width characters or
tell a Cyrillic "a" from a Latin one. This module computes such facts with
plain code and hands them to the guard as *evidence*. It never decides
anything: there are no secret-looking patterns and no ALLOW/BLOCK outcome here
(that is what the old regex did and why it was brittle). Decoded text is still
untrusted attacker-controlled data and is shown to the guard as such.

What it reports for the proposed tool call:
  hidden_or_lookalike_characters : invisible format characters (zero-width,
                                   bidi controls, Unicode tag chars) and
                                   Latin words that mix in Cyrillic/Greek
                                   letters. Pure non-Latin text is NOT flagged.
  normalized_text                : NFKC-normalised, invisibles removed,
                                   look-alike letters folded - only when it
                                   differs from the raw field.
  decoded_candidates             : mechanically unambiguous decodings of
                                   substrings: base64, hex, percent-encoding,
                                   HTML entities, decimal character codes,
                                   8-bit binary, letters spaced out one by one.
                                   A candidate is reported only if the decoding
                                   is structurally valid AND yields mostly
                                   printable ASCII (so a git SHA is not
                                   "decoded").
Deliberately NOT covered (left to the LLM): ROT13/Caesar/Atbash, reversal,
Morse, phonetic/NATO spelling, leetspeak, acrostics, etc.
"""

import base64
import binascii
import html
import re
import unicodedata
import urllib.parse

MAX_CANDIDATES = 6
MAX_TEXT = 160

# Latin <-> look-alike letters (folded to Latin for the normalised view)
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ѕ": "s", "ј": "j",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v", "ι": "i",
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H",
    "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N", "Ο": "O",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
}


def _is_invisible(ch):
    o = ord(ch)
    return (unicodedata.category(ch) == "Cf" or 0xE0000 <= o <= 0xE007F
            or 0xFE00 <= o <= 0xFE0F)


def _script(ch):
    if not ch.isalpha():
        return None
    name = unicodedata.name(ch, "")
    for s in ("LATIN", "CYRILLIC", "GREEK"):
        if name.startswith(s):
            return s
    return "OTHER"


def _strings(obj, path=""):
    """Yield (path, string) for every string value in the action, except the
    tool name (which is checked structurally by check 1)."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "tool":
                continue
            yield from _strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, (list, tuple)):
        for i, v in enumerate(obj):
            yield from _strings(v, f"{path}[{i}]")
    elif isinstance(obj, str):
        yield path, obj


def _printable_ratio(b):
    if not b:
        return 0.0
    return sum(1 for x in b if 32 <= x < 127) / len(b)


def _ok_text(b):
    return len(b) >= 4 and _printable_ratio(b) >= 0.9


def _decode_b64(tok):
    t = tok.rstrip("=")
    if len(t) < 12:
        return None
    try:
        raw = base64.b64decode(t + "=" * (-len(t) % 4), validate=True)
    except (binascii.Error, ValueError):
        return None
    return raw.decode("ascii") if _ok_text(raw) and raw.isascii() else None


def _decode_hex(tok):
    if len(tok) < 12 or len(tok) % 2:
        return None
    try:
        raw = bytes.fromhex(tok)
    except ValueError:
        return None
    return raw.decode("ascii") if _ok_text(raw) and raw.isascii() else None


def _decode_pct(tok):
    s = urllib.parse.unquote(tok)
    return s if s != tok and _ok_text(s.encode("utf-8", "ignore")) else None


def _decode_entities(tok):
    s = html.unescape(tok)
    return s if s != tok and _ok_text(s.encode("utf-8", "ignore")) else None


def _decode_decimal(tok):
    nums = re.findall(r"\d{2,3}", tok)
    if len(nums) < 5:
        return None
    vals = [int(n) for n in nums]
    if all(32 <= v < 127 for v in vals):
        return "".join(chr(v) for v in vals)
    return None


def _decode_binary(tok):
    groups = tok.split()
    if len(groups) < 3 or any(len(g) != 8 for g in groups):
        return None
    try:
        raw = bytes(int(g, 2) for g in groups)
    except ValueError:
        return None
    return raw.decode("ascii") if _ok_text(raw) and raw.isascii() else None


def _decode_spaced(tok):
    chars = tok.split(" ")
    return "".join(chars) if len(chars) >= 7 and all(len(c) == 1 for c in chars) else None


_FINDERS = [
    ("base64", re.compile(r"[A-Za-z0-9+/_-]{12,}={0,2}"), _decode_b64),
    ("hex", re.compile(r"(?<![0-9A-Za-z])(?:[0-9a-fA-F]{2}){6,}(?![0-9A-Za-z])"), _decode_hex),
    ("percent-encoding", re.compile(r"(?:%[0-9a-fA-F]{2}[^\s%]{0,2}){4,}"), _decode_pct),
    ("html-entities", re.compile(r"(?:&#(?:\d{2,5}|x[0-9a-fA-F]{2,4});){4,}"), _decode_entities),
    ("decimal-codes", re.compile(r"(?<!\d)\d{2,3}(?:[ ,]+\d{2,3}){4,}(?!\d)"), _decode_decimal),
    ("binary", re.compile(r"(?<![01])[01]{8}(?: [01]{8}){2,}(?![01])"), _decode_binary),
    ("spaced-letters", re.compile(r"(?<!\S)\S(?: \S){6,}(?!\S)"), _decode_spaced),
]


def _candidates(text, depth=0):
    found = []
    for name, rx, dec in _FINDERS:
        for m in rx.finditer(text):
            tok = m.group(0)
            if name == "base64":
                tok = tok.replace("-", "+").replace("_", "/")
            out = dec(tok)
            if out and out != tok:
                found.append((name, out))
                if depth < 1:                      # one level of nesting
                    for n2, o2 in _candidates(out, depth + 1):
                        found.append((f"{name}>{n2}", o2))
    return found


def _compat_letters(s):
    """True if NFKC turns some non-ASCII char into ASCII letters/digits
    (fullwidth forms, mathematical alphanumerics, ...)."""
    for ch in s:
        if ord(ch) > 127:
            n = unicodedata.normalize("NFKC", ch)
            if n.isascii() and n.isalnum():
                return True
    return False


def _fold_mixed_words(s):
    """Fold look-alike letters, but only inside words that mix Latin with
    Cyrillic/Greek. Legitimate pure-Cyrillic or Greek text is left alone."""
    def fix(m):
        w = m.group(0)
        scripts = {_script(c) for c in w if _script(c)}
        if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
            return "".join(_CONFUSABLES.get(c, c) for c in w)
        return w
    return re.sub(r"\w+", fix, s)


def _normalize(s):
    s = unicodedata.normalize("NFKC", s)
    s = "".join(ch for ch in s if not _is_invisible(ch))
    return _fold_mixed_words(s)


def preprocess(action):
    """Return a small JSON-serialisable dict of evidence about `action`."""
    hidden = []
    normalized = {}
    cands = []
    seen = set()
    for path, s in _strings(action):
        inv = sorted({f"U+{ord(c):04X}" for c in s if _is_invisible(c)})
        mixed = []
        for w in re.findall(r"\w+", s):
            scripts = {_script(c) for c in w if _script(c)}
            if "LATIN" in scripts and scripts & {"CYRILLIC", "GREEK"}:
                mixed.append(w)
        if inv or mixed:
            hidden.append({"field": path,
                           **({"invisible_characters": inv,
                               "count": sum(1 for c in s if _is_invisible(c))} if inv else {}),
                           **({"latin_words_with_lookalike_letters": mixed[:5]} if mixed else {})})
        n = _normalize(s)
        # report the normalised view only when it carries real information
        if n != s and (inv or mixed or _compat_letters(s)):
            normalized[path] = n[:MAX_TEXT * 2]
        for name, out in _candidates(n if n != s else s):
            key = (name, out)
            if key not in seen:
                seen.add(key)
                cands.append({"field": path, "method": name, "text": out[:MAX_TEXT]})
    notes = {"hidden_or_lookalike_characters": hidden or "none",
             "normalized_text": normalized or "same as raw",
             "decoded_candidates": cands[:MAX_CANDIDATES] or "none"}
    return notes
