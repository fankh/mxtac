"""Shared input validation helpers for MxTac.

Provides:
- escape_like()                 — escape SQL LIKE wildcard characters
- validate_ip_address()         — IPv4 / IPv6 validation
- validate_cidr()               — CIDR notation validation
- validate_hostname()           — RFC 952 / 1123 hostname validation
- validate_password_complexity() — min 8 chars + 3 of 4 character types (feature 2.1)
- EMAIL_MAX_LENGTH              — RFC 5321 maximum email address length
- PASSWORD_MIN_LENGTH / PASSWORD_MAX_LENGTH — password length bounds
"""

from __future__ import annotations

import ipaddress
import re

# ── Constants ─────────────────────────────────────────────────────────────────

EMAIL_MAX_LENGTH = 254       # RFC 5321 §4.5.3.1
PASSWORD_MIN_LENGTH = 8
PASSWORD_MAX_LENGTH = 128

# RFC 952 / 1123 — labels up to 63 chars, total up to 253
_HOSTNAME_LABEL_RE = re.compile(r"^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$")


# ── SQL LIKE helpers ──────────────────────────────────────────────────────────

def escape_like(value: str) -> str:
    """Escape SQL LIKE wildcard characters in *value*.

    After escaping, pass the result with ``escape="\\\\"`` to SQLAlchemy's
    ``.ilike()`` / ``.like()`` so that ``%`` and ``_`` in user-supplied
    strings are treated as literals, not wildcards.

    Example::

        from app.core.validators import escape_like
        pattern = f"%{escape_like(search)}%"
        q = q.where(col.ilike(pattern, escape="\\\\"))
    """
    # Order matters: escape backslash first, then wildcards
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


# ── IP / Network validators ───────────────────────────────────────────────────

def validate_ip_address(v: str) -> str:
    """Return *v* if it is a valid IPv4 or IPv6 address, else raise ValueError."""
    try:
        ipaddress.ip_address(v)
    except ValueError:
        raise ValueError(f"Invalid IP address: {v!r}")
    return v


def validate_cidr(v: str) -> str:
    """Return *v* if it is a valid CIDR network string, else raise ValueError."""
    try:
        ipaddress.ip_network(v, strict=False)
    except ValueError:
        raise ValueError(f"Invalid CIDR notation: {v!r}")
    return v


# ── Password complexity validator ─────────────────────────────────────────────

# Feature 2.1 — Password policy: min 8 chars, at least 3 of 4 character types.
# Character types: uppercase letters, lowercase letters, digits, special chars.
_CHAR_TYPE_CHECKS = [
    (re.compile(r"[A-Z]"), "uppercase letters"),
    (re.compile(r"[a-z]"), "lowercase letters"),
    (re.compile(r"[0-9]"), "digits"),
    (re.compile(r"[^A-Za-z0-9]"), "special characters"),
]
_PASSWORD_COMPLEXITY_MIN_TYPES = 3


def validate_password_complexity(v: str) -> str:
    """Return *v* if it satisfies the password complexity policy, else raise ValueError.

    Policy (feature 2.1): password must contain characters from at least 3 of
    the following 4 categories: uppercase letters, lowercase letters, digits,
    special characters (any character that is not alphanumeric).

    Length is enforced separately via Pydantic field min_length / max_length.
    """
    matched = sum(1 for pattern, _ in _CHAR_TYPE_CHECKS if pattern.search(v))
    if matched < _PASSWORD_COMPLEXITY_MIN_TYPES:
        raise ValueError(
            "Password must contain at least 3 of the following character types: "
            "uppercase letters, lowercase letters, digits, special characters"
        )
    return v


# ── Hostname validator ────────────────────────────────────────────────────────

def validate_hostname(v: str) -> str:
    """Return *v* if it is a valid RFC 952/1123 hostname, else raise ValueError.

    Accepts short names (``srv01``), FQDNs (``srv01.example.com``), and
    `.local` names used by mDNS / internal services.
    """
    if len(v) > 253:
        raise ValueError("Hostname exceeds 253 characters")
    labels = v.rstrip(".").split(".")
    for label in labels:
        if not _HOSTNAME_LABEL_RE.match(label):
            raise ValueError(f"Invalid hostname label: {label!r}")
    return v
