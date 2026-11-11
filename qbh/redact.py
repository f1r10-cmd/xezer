"""Həssas dəyərlərin maskalanması (redaction).

Tapılan secret-lər adi loglarda və hesabatlarda göstərilməməlidir.
`mask_value` yalnız başlanğıc və son simvolları saxlayır; `redact`
isə sərbəst mətndə secret oxşarlarını maskalayır.
"""
from __future__ import annotations

import re

_REDACT_PATTERNS = [
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"https://hooks\.slack\.com/services/\S+"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?i)\b(password|passwd|secret|token|api[_-]?key)\b\s*[:=]\s*"
               r"['\"]?([^\s'\"]{6,})"),
    re.compile(r"(?i)\bAuthorization:\s*(?:Bearer|Basic)\s+\S+"),
]


def mask_value(value: str, keep: int = 4) -> str:
    """Dəyərin yalnız başını/sonunu saxlayır, ortasını `*` edir."""
    if value is None:
        return ""
    s = str(value)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * 6}{s[-keep:]}"


def redact(text: str) -> str:
    """Mətndəki secret oxşarlarını maskalayır."""
    if not text:
        return text
    out = str(text)
    for pat in _REDACT_PATTERNS:
        def _sub(m: re.Match) -> str:
            if m.re.groups >= 2 and m.group(2) is not None:
                return f"{m.group(1)}=<redacted>"
            return "<redacted>"
        out = pat.sub(_sub, out)
    return out
