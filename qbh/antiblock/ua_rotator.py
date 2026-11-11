"""Host başına SABİT User-Agent seçimi.

Burada rotasiya YOXDUR. UA yalnız identifikasiya üçündür, blok aşma
mexanizmi deyil. Hər host üçün bir dəfə təyin olunur və sabit qalır.
"""
import hashlib

UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) "
    "Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.3 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:122.0) Gecko/20100101 Firefox/122.0",
]

_assigned: dict[str, str] = {}


def ua_for(host: str) -> str:
    """Hər host üçün DETERMINIST sabit UA (təsadüfi deyil, rotasiya deyil)."""
    if host not in _assigned:
        idx = int(hashlib.sha256(host.encode()).hexdigest(), 16) % len(UA_POOL)
        _assigned[host] = UA_POOL[idx]
    return _assigned[host]
