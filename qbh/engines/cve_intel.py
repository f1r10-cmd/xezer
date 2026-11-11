"""M6+ CVE İntellekti — NVD, OSV, GitHub Advisory, CISA KEV, EPSS.

Prinsiplər:
  * `match_type` AÇIQ şəkildə saxlanılır:
      - `confirmed` → OSV dəqiq paket+versiya uyğunluğu təsdiqləyir;
      - `possible`  → yalnız ad/keyword uyğunluğu (NVD, GitHub Advisory).
  * Yalnız məhsul banner-inə görə zəiflik İDDİA EDİLMİR: finding yalnız
    `confirmed` uyğunluqda, ya da KEV-də olan `possible` uyğunluqda yaradılır
    və həmin halda "manual təsdiq" açıq şəkildə göstərilir.
  * Hər nəticə üçün mənbə (source) atribusiyası saxlanılır.
  * API timeout-ları tətbiq olunur, nəticələr keşlənir (dedup + az sorğu).
  * Bu mənbələr SKAN HƏDƏFİ DEYİL → onlara qarşı hədəf scope-u tətbiq edilmir.
"""
from __future__ import annotations

import asyncio
import time

import aiohttp
from packaging.version import InvalidVersion, Version

from .. import db
from ..redact import redact
from ..results import EngineResult

KEV_URL = ("https://www.cisa.gov/sites/default/files/feeds/"
           "known_exploited_vulnerabilities.json")
EPSS_URL = "https://api.first.org/data/v1/epss"
OSV_URL = "https://api.osv.dev/v1/query"
GH_ADV_URL = "https://api.github.com/advisories"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

API_TIMEOUT = 30
CACHE_TTL = 3600
MAX_HOSTS = 40
MAX_CVES_PER_PAIR = 30

PRODUCT_ALIASES = {
    "wordpress": "WordPress", "nginx": "nginx", "apache": "httpd",
    "php": "PHP", "drupal": "Drupal", "joomla": "Joomla",
    "jquery": "jquery", "lodash": "lodash", "express": "express",
}

_cache: dict[str, tuple[float, object]] = {}


def _cache_get(key: str):
    item = _cache.get(key)
    if not item:
        return None
    ts, value = item
    if time.time() - ts > CACHE_TTL:
        _cache.pop(key, None)
        return None
    return value


def _cache_put(key: str, value) -> None:
    _cache[key] = (time.time(), value)


async def _get_json(session, url, params=None, headers=None):
    try:
        async with session.get(
                url, params=params, headers=headers,
                timeout=aiohttp.ClientTimeout(total=API_TIMEOUT)) as r:
            if r.status == 200:
                return await r.json(content_type=None)
            return {"__status": r.status}
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None


async def get_kev(session) -> set:
    cached = _cache_get("kev")
    if cached is not None:
        return cached
    data = await _get_json(session, KEV_URL)
    kev = {v["cveID"] for v in data.get("vulnerabilities", [])} \
        if isinstance(data, dict) and data.get("vulnerabilities") else set()
    if kev:
        _cache_put("kev", kev)
    return kev


async def search_nvd(session, product: str, version: str,
                     api_key: str | None = None) -> list[str]:
    headers = {"apiKey": api_key} if api_key else {}
    data = await _get_json(session, NVD_URL,
                           params={"keywordSearch": f"{product} {version}",
                                   "resultsPerPage": 20},
                           headers=headers)
    if not isinstance(data, dict):
        return []
    ids = []
    for item in data.get("vulnerabilities", []):
        cid = (item.get("cve") or {}).get("id")
        if cid:
            ids.append(cid)
    return ids


async def search_github_advisory(session, product: str) -> list[str]:
    data = await _get_json(session, GH_ADV_URL,
                           params={"affects": PRODUCT_ALIASES.get(product, product),
                                   "per_page": 20})
    if not isinstance(data, list):
        return []
    hits = []
    alias = PRODUCT_ALIASES.get(product, "")
    for adv in data:
        cid = adv.get("cve_id") or adv.get("ghsa_id")
        if not cid:
            continue
        for v in adv.get("vulnerabilities", []):
            pkg = (v.get("package", {}).get("name") or "").lower()
            if pkg and pkg in (product.lower(), alias.lower()):
                hits.append(cid)
                break
    return hits[:10]


async def search_osv(session, product: str, version: str) -> list[str]:
    try:
        async with session.post(
                OSV_URL, json={"package": {"name": product}, "version": version},
                timeout=aiohttp.ClientTimeout(total=API_TIMEOUT)) as r:
            if r.status != 200:
                return []
            data = await r.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return []
    return [v.get("id") for v in (data or {}).get("vulns", [])[:15] if v.get("id")]


async def rank_batch(session, cve_ids: list[str], kev: set) -> dict:
    """EPSS-i BİR batch sorğu ilə alır (dedup + az şəbəkə sorğusu)."""
    result: dict[str, dict] = {}
    unknown: list[str] = []
    for cid in cve_ids:
        cached = _cache_get(f"epss:{cid}")
        if cached is not None:
            result[cid] = {"cve": cid, "kev": cid in kev, "epss": float(cached)}
        else:
            unknown.append(cid)

    if unknown:
        data = await _get_json(session, EPSS_URL,
                               params={"cve": ",".join(unknown[:100])})
        scores = {}
        if isinstance(data, dict):
            for item in data.get("data", []) or []:
                try:
                    scores[item["cve"]] = float(item.get("epss", 0))
                except (KeyError, TypeError, ValueError):
                    continue
        for cid in unknown:
            score = scores.get(cid, 0.0)
            _cache_put(f"epss:{cid}", score)
            result[cid] = {"cve": cid, "kev": cid in kev, "epss": score}
    return result


def _tech_versions(tech_raw: str) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for part in (tech_raw or "").replace(",", "|").split("|"):
        if ":" not in part:
            continue
        prod, ver = part.rsplit(":", 1)
        prod, ver = prod.strip().lower(), ver.strip()
        if not prod or not ver:
            continue
        try:
            Version(ver)
        except (InvalidVersion, ValueError):
            continue
        out.append((prod, ver))
    return out


def _priority(kev: bool, epss: float) -> str:
    if kev:
        return "critical"
    if epss > 0.5:
        return "high"
    if epss > 0.1:
        return "medium"
    return "low"


async def run(ctx) -> EngineResult:
    res = EngineResult(stage="cve_intel")
    hosts = db.alive_hosts(ctx.scan_id)[:MAX_HOSTS]
    if not hosts:
        return res.skip("yaşayan host yoxdur — CVE intellekti atlandı")

    nvd_key = getattr(ctx.cfg, "nvd_api_key", "") or None
    print("[═══ M6+ CVE İNTELLEKTİ (NVD/OSV/GitHub/KEV/EPSS) ═══]")

    async with aiohttp.ClientSession() as session:
        kev = await get_kev(session)
        if not kev:
            res.warn("CISA KEV məlumatı alına bilmədi (şəbəkə/timeout)")
        print(f"[+] KEV: {len(kev)} aktiv istismar CVE")

        for host in hosts:
            pairs = _tech_versions(host["tech_raw"])
            if not pairs:
                continue
            for product, version in pairs:
                try:
                    await self_pair(host, product, version, kev, nvd_key,
                                    session, res)
                except (aiohttp.ClientError, asyncio.TimeoutError) as exc:
                    res.warn(f"{host['subdomain']} {product}: "
                             f"{redact(str(exc))}")
    return res


async def self_pair(host, product, version, kev, nvd_key, session,
                    res: EngineResult) -> None:
    """Bir (məhsul, versiya) cütü üçün bütün mənbələri birləşdirir."""
    nvd, ghsa, osv = await asyncio.gather(
        search_nvd(session, product, version, nvd_key),
        search_github_advisory(session, product),
        search_osv(session, product, version),
        return_exceptions=True)

    sources: dict[str, set] = {}
    confirmed: set[str] = set()
    for ids, label, is_confirmed in ((nvd if isinstance(nvd, list) else [],
                                      "nvd", False),
                                     (ghsa if isinstance(ghsa, list) else [],
                                      "github-advisory", False),
                                     (osv if isinstance(osv, list) else [],
                                      "osv", True)):
        for cid in ids:
            sources.setdefault(cid, set()).add(label)
            if is_confirmed:
                confirmed.add(cid)

    cve_ids = list(sources)[:MAX_CVES_PER_PAIR]
    if not cve_ids:
        return

    ranked = await rank_batch(session, cve_ids, kev)
    for cid in cve_ids:
        item = ranked.get(cid) or {"cve": cid, "kev": cid in kev, "epss": 0.0}
        match_type = "confirmed" if cid in confirmed else "possible"
        prio = _priority(item["kev"], item["epss"])
        db.insert_cve(host["id"], cid, product, version, item["kev"],
                      item["epss"], prio, match_type=match_type,
                      source=",".join(sorted(sources[cid])))

        if match_type == "confirmed":
            db.insert_finding(
                host["id"], "cve-intel", prio,
                f"CVE uyğunluğu (təsdiqlənmiş): {cid}",
                f"OSV {product} {version} üçün bu zəifliyi təsdiqləyir. "
                f"KEV={'bəli' if item['kev'] else 'xeyr'}, "
                f"EPSS={item['epss']:.2f}. Mənbələr: "
                f"{', '.join(sorted(sources[cid]))}. Manual reproduksiya tələb olunur.",
                evidence=f"{product} {version} → {cid}",
                confidence=0.7, status="potential",
                source="cve-intel")
            res.findings += 1
            print(f"[{'🔴' if prio == 'critical' else '🟠'}] "
                  f"{host['subdomain']}: {cid} (confirmed) "
                  f"KEV={'✓' if item['kev'] else '✗'} EPSS={item['epss']:.2f}")
        elif item["kev"]:
            # Yalnız ad uyğunluğu, lakin real istismar edilir → məlumatlandırıcı
            db.insert_finding(
                host["id"], "cve-intel", "medium",
                f"CVE mümkün uyğunluq (KEV): {cid}",
                f"{product} {version} banner-inə əsasən MÜMKÜN uyğunluq "
                f"(təsdiqlənməyib). Bu CVE CISA KEV siyahısındadır (aktiv "
                f"istismar). Manual versiya təsdiqi tələb olunur — banner "
                f"tək başına zəiflik sübutu DEYİL.",
                evidence=f"{product} {version} → {cid} (possible)",
                confidence=0.3, status="potential", source="cve-intel")
            res.findings += 1
