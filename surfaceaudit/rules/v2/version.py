"""Version string parsing and comparison utilities for the v2 rule engine."""

from __future__ import annotations

import re


def parse_version(version_str: str) -> tuple[int, ...]:
    """Parse a version string into a tuple of integers.

    Strips non-numeric suffixes (e.g. ``'1.20.3-ubuntu'`` → ``(1, 20, 3)``).
    Missing or unparseable strings return ``(0,)``.
    """
    cleaned = re.match(r"[\d.]+", version_str.strip())
    if not cleaned:
        return (0,)
    parts = cleaned.group().split(".")
    return tuple(int(p) for p in parts if p)


def _compare(a: tuple[int, ...], b: tuple[int, ...], op: str) -> bool:
    """Segment-by-segment version comparison with zero-padding.

    Supported operators: ``lt``, ``lte``, ``gt``, ``gte``, ``eq``.
    """
    max_len = max(len(a), len(b))
    a_padded = a + (0,) * (max_len - len(a))
    b_padded = b + (0,) * (max_len - len(b))
    ops = {
        "lt": a_padded < b_padded,
        "lte": a_padded <= b_padded,
        "gt": a_padded > b_padded,
        "gte": a_padded >= b_padded,
        "eq": a_padded == b_padded,
    }
    return ops[op]
