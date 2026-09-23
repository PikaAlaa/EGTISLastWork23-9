from __future__ import annotations

import ipaddress
from math import prod
from urllib.parse import urlparse

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "rebrand.ly"}
SUSPICIOUS_TLDS = {"top", "xyz", "click", "lol", "work", "support", "zip"}


def analyze_url_patterns(url: str | None) -> dict:
    if not url:
        return {"applicable": False, "score": None, "flags": [], "reason": "No URL supplied"}
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else f"http://{raw}")
    host = (parsed.hostname or "").casefold()
    flags: list[dict] = []

    def add(name: str, weight: float, detail: str) -> None:
        flags.append({"name": name, "weight": weight, "detail": detail})

    try:
        ipaddress.ip_address(host)
        add("ip_host", 70, "Uses a raw IP address instead of a domain")
    except ValueError:
        pass
    if "@" in raw:
        add("at_symbol", 55, "Contains @, which can hide the real destination")
    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", 45, "Uses an internationalized punycode hostname")
    if host in SHORTENERS:
        add("shortener", 38, "Uses a URL shortening service")
    labels = [part for part in host.split(".") if part]
    if len(labels) > 4:
        add("excessive_subdomains", 24, "Uses an unusually deep hostname")
    if host.count("-") >= 3:
        add("excessive_hyphens", 25, "Hostname contains many hyphens")
    if parsed.scheme.casefold() != "https":
        add("no_https", 16, "Does not use HTTPS")
    if labels and labels[-1] in SUSPICIOUS_TLDS:
        add("suspicious_tld", 32, f"Uses .{labels[-1]} TLD")
    combined = f"{parsed.path}?{parsed.query}".casefold()
    keywords = [word for word in ("login", "verify", "secure", "account", "update", "confirm", "password", "otp") if word in combined]
    if keywords:
        add("credential_path", min(45, 14 + 7 * len(keywords)), f"Credential-themed path/query: {', '.join(keywords)}")
    score = round(100 * (1 - prod(1 - item["weight"] / 100 for item in flags)), 2) if flags else 0.0
    return {"applicable": True, "score": score, "domain": host, "flags": flags, "reason": "Suspicious URL structure detected" if flags else "No suspicious URL structure detected"}
