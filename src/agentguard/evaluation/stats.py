"""Small statistics helpers shared by the evaluation runners."""

from __future__ import annotations

import math


def wilson(k, n, z=1.96):
    """95% Wilson score interval for a proportion (small-n friendly)."""
    if n == 0:
        return (0.0, 0.0)
    p = k / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return (max(0.0, centre - half), min(1.0, centre + half))


def pct(x):
    return f"{100 * x:5.1f}%"


def percentile(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    i = min(len(xs) - 1, int(round(q * (len(xs) - 1))))
    return xs[i]
