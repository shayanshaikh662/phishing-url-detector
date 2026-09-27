"""
feature_extractor.py

Extracts numerical features from a URL string for use by the
phishing detection machine learning model.

IMPORTANT: The exact same function (extract_features) must be used
both when training the model (training.py) and when making live
predictions (app.py). This guarantees the feature order and meaning
stay consistent between training and inference.
"""

import re
from urllib.parse import urlparse

# The exact order of feature names. Both training.py and app.py
# import this list so the column order can never drift apart.
FEATURE_NAMES = [
    "url_length",
    "num_dots",
    "num_hyphens",
    "num_special_chars",
    "num_digits",
    "has_at_symbol",
    "has_https",
    "hostname_length",
    "num_subdomains",
    "has_ip_address",
    "has_suspicious_words",
    "has_port",
    "path_length",
    "query_length",
    "num_params",
]

# A small set of words commonly seen in phishing URLs. This is only
# ONE of many features used by the model -- it is not the sole basis
# for classification, since the trained Random Forest model looks at
# all features together.
SUSPICIOUS_WORDS = [
    "login", "verify", "update", "secure", "account", "banking",
    "confirm", "signin", "webscr", "password", "suspend", "billing",
]

IP_PATTERN = re.compile(
    r"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"
)


def _ensure_protocol(url: str) -> str:
    """Add a default http:// protocol if the URL is missing one.
    Only used internally for parsing; does not mutate the original
    user-facing URL.
    """
    url = url.strip()
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    return url


def extract_features(raw_url: str) -> list:
    """Extract a fixed-length list of numeric features from a URL.

    Args:
        raw_url: The URL string exactly as entered by the user (or
            as read from the training dataset).

    Returns:
        A list of numbers in the same order as FEATURE_NAMES.
    """
    url = _ensure_protocol(raw_url)

    try:
        parsed = urlparse(url)
    except ValueError:
        # Fall back to an empty parse result if the URL is too
        # malformed for urlparse to handle.
        parsed = urlparse("")

    hostname = parsed.hostname or ""
    path = parsed.path or ""
    query = parsed.query or ""

    url_length = len(raw_url)
    num_dots = raw_url.count(".")
    num_hyphens = raw_url.count("-")
    num_digits = sum(c.isdigit() for c in raw_url)

    # Count special characters (anything that is not alphanumeric,
    # a dot, hyphen, or a standard URL separator character).
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_/:?&=")
    num_special_chars = sum(1 for c in raw_url if c not in allowed)

    has_at_symbol = 1 if "@" in raw_url else 0
    has_https = 1 if parsed.scheme == "https" else 0
    hostname_length = len(hostname)

    # Number of subdomains: count dot-separated labels in the
    # hostname, minus the main domain and TLD (roughly labels - 2).
    if hostname:
        labels = [label for label in hostname.split(".") if label]
        num_subdomains = max(len(labels) - 2, 0)
    else:
        num_subdomains = 0

    has_ip_address = 1 if hostname and IP_PATTERN.match(hostname) else 0

    lowered_url = raw_url.lower()
    has_suspicious_words = 1 if any(word in lowered_url for word in SUSPICIOUS_WORDS) else 0

    has_port = 1 if (parsed.port is not None) else 0

    path_length = len(path)
    query_length = len(query)
    num_params = len(query.split("&")) if query else 0

    return [
        url_length,
        num_dots,
        num_hyphens,
        num_special_chars,
        num_digits,
        has_at_symbol,
        has_https,
        hostname_length,
        num_subdomains,
        has_ip_address,
        has_suspicious_words,
        has_port,
        path_length,
        query_length,
        num_params,
    ]


def extract_features_dict(raw_url: str) -> dict:
    """Same as extract_features but returns a name -> value dict.
    Useful for debugging or displaying feature values.
    """
    values = extract_features(raw_url)
    return dict(zip(FEATURE_NAMES, values))
