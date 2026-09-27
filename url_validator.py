"""
url_validator.py

Small helper module for validating and normalizing user-submitted
URLs before they are passed to the feature extractor / model.
"""

import re
from urllib.parse import urlparse

# Basic hostname pattern: at least one dot, valid characters,
# no spaces. This intentionally stays permissive -- the goal is to
# reject obvious junk input, not to be a full RFC validator.
_HOSTNAME_PATTERN = re.compile(
    r"^(([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)\.)+[a-zA-Z]{2,}$"
    r"|^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def normalize_url(raw_url: str) -> str:
    """Add a default http:// scheme if none is present."""
    url = raw_url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def is_valid_url(raw_url: str) -> bool:
    """Return True if raw_url looks like a usable URL.

    This never raises -- any parsing failure is treated as invalid.
    """
    if not raw_url or not raw_url.strip():
        return False

    if len(raw_url) > 2048:
        return False

    if any(ch.isspace() for ch in raw_url):
        return False

    try:
        normalized = normalize_url(raw_url)
        parsed = urlparse(normalized)
    except ValueError:
        return False

    if parsed.scheme not in ("http", "https"):
        return False

    hostname = parsed.hostname or ""
    if not hostname:
        return False

    if not _HOSTNAME_PATTERN.match(hostname):
        return False

    return True
