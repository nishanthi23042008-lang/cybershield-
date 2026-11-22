"""Simple, explainable URL text checks. This module never opens a URL."""

import ipaddress
import re
from urllib.parse import urlsplit


MAX_URL_LENGTH = 2048
SUSPICIOUS_WORDS = ("login", "verify", "account", "secure", "update", "password", "wallet")
SHORTENER_HOSTS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "ow.ly"}


def analyze_url(value):
    """Return a score and reasons, or (None, error) for invalid input."""
    if len(value) > MAX_URL_LENGTH:
        return None, f"URL text must be {MAX_URL_LENGTH} characters or fewer."
    if any(character.isspace() for character in value):
        return None, "A URL cannot contain spaces."

    candidate = value if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", value) else f"https://{value}"
    try:
        parsed = urlsplit(candidate)
        host = parsed.hostname
        # Accessing .port also validates malformed port values.
        port = parsed.port
    except ValueError:
        return None, "That URL has an invalid address or port."

    if parsed.scheme.lower() not in {"http", "https"}:
        return None, "Only http:// and https:// URLs are supported."
    if not host or "." not in host and host.lower() != "localhost":
        return None, "Enter a complete web address, such as example.com."

    reasons = []
    score = 0
    hostname = host.lower().rstrip(".")

    try:
        ipaddress.ip_address(hostname.strip("[]"))
        reasons.append("The address uses a numeric IP instead of a domain name.")
        score += 25
    except ValueError:
        pass

    if "@" in parsed.netloc:
        reasons.append("The address contains an @ sign, which can disguise the actual destination.")
        score += 25
    if "xn--" in hostname:
        reasons.append("The domain uses internationalized (punycode) characters that can resemble other letters.")
        score += 20
    if parsed.scheme.lower() == "http":
        reasons.append("The link uses HTTP, so the connection is not encrypted by HTTPS.")
        score += 10
    if hostname in SHORTENER_HOSTS:
        reasons.append("This is a URL shortener, so the final destination is hidden in the text.")
        score += 15

    labels = hostname.split(".")
    if len(labels) >= 5:
        reasons.append("The domain has many subdomain parts, which can make its owner harder to recognize.")
        score += 10
    if port and port not in {80, 443}:
        reasons.append(f"The address uses the less common port {port}.")
        score += 10

    lowered = value.lower()
    found_words = [word for word in SUSPICIOUS_WORDS if word in lowered]
    if found_words:
        reasons.append("The text includes words often used in account or credential lures: " + ", ".join(found_words) + ".")
        score += min(20, 5 * len(found_words))
    if len(value) > 100:
        reasons.append("The URL is unusually long, which can make it harder to inspect.")
        score += 10

    score = min(score, 100)
    if score >= 50:
        level = "Higher indicator level"
    elif score >= 20:
        level = "Some indicators"
    else:
        level = "Few indicators"

    if not reasons:
        reasons.append("These basic text checks did not find the indicators they look for.")

    return {
        "submitted_url": value,
        "risk_score": score,
        "level": level,
        "reasons": reasons,
        "notice": "These are heuristic indicators only, not a definitive safety verdict. No network request was made.",
    }, None
