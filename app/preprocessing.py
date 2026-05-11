"""
Data preprocessing pipeline.

Steps:
  1. URL-decode using unquote_plus  (handles %3C -> < and + -> space)
  2. Lowercase + strip whitespace
"""

import re
from urllib.parse import unquote_plus

# Special characters that may indicate injection or encoding tricks
_SPECIAL_CHARS_RE = re.compile(r"""['"*=\-;/<>.%\\]""")

# Critical threat keywords – presence triggers the heuristic override
_THREAT_KEYWORDS = frozenset(
    [
        "select",
        "drop",
        "where",
        "union",
        "insert",
        "delete",
        "update",
        "exec",
        "execute",
        "<script",
        "alert(",
        "onerror",
        "onload",
        "javascript:",
        "etc/passwd",
        "../",
        "cmd.exe",
        "/bin/sh",
        "base64",
        "eval(",
        "fromcharcode",
    ]
)


def decode_and_clean(raw: str) -> str:
    """URL-decode then lowercase + strip."""
    decoded = unquote_plus(raw)
    return decoded.lower().strip()


def compute_features(cleaned: str) -> dict:
    """
    Extract numerical features for the ML model.

    Returns
    -------
    dict with keys:
        length          – total character count
        symbol_density  – ratio of special chars to total length (0 if empty)
        has_threat_kw   – 1 if a critical keyword is found, else 0
    """
    length = len(cleaned)
    special_count = len(_SPECIAL_CHARS_RE.findall(cleaned))
    symbol_density = special_count / length if length > 0 else 0.0
    has_threat = int(any(kw in cleaned for kw in _THREAT_KEYWORDS))

    return {
        "length": length,
        "symbol_density": round(symbol_density, 6),
        "has_threat_kw": has_threat,
    }


def preprocess(raw: str) -> tuple[str, dict]:
    """
    Full preprocessing pipeline.

    Parameters
    ----------
    raw : str
        Raw log message (may be URL-encoded).

    Returns
    -------
    cleaned : str
        The cleaned, lowercased, decoded message.
    features : dict
        Numerical feature dictionary ready for the model.
    """
    cleaned = decode_and_clean(raw)
    features = compute_features(cleaned)
    return cleaned, features
