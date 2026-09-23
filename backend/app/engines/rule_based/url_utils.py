from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def canonicalize_url(value: str) -> str:
    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"https://{candidate}"
    try:
        parsed = urlsplit(candidate)
        scheme = parsed.scheme.casefold() or "https"
        host = (parsed.hostname or "").casefold().rstrip(".")
        host = host.encode("idna").decode("ascii") if host else ""
        port = parsed.port
        if port and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
            host = f"{host}:{port}"
        path = re.sub(r"/{2,}", "/", parsed.path or "/")
        if path != "/":
            path = path.rstrip("/")
        query = urlencode(sorted(parse_qsl(parsed.query, keep_blank_values=True)), doseq=True)
        return urlunsplit((scheme, host, path if path != "/" else "", query, ""))
    except (UnicodeError, ValueError):
        return candidate.casefold().rstrip("/")
