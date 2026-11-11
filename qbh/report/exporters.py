"""Bounty-ready hesabat ixracı (Faza 5).

Üç format:
  * **Markdown** — əsas hesabat (generator yazır),
  * **JSON** — strukturlaşdırılmış maşın oxuna bilən çıxış,
  * **HackerOne** — platformaya uyğun tapıntı strukturu.

Hər tapıntı üçün verilir: başlıq, severity (CVSS-xəritələnmiş), CWE, təsir
olunan URL/endpoint, reproduksiya addımları (curl), sübut, remediasiya və
confidence səviyyəsi.
"""
from __future__ import annotations

import json
import os

from ..redact import redact

#: Daxili severity → HackerOne `severity_rating`.
H1_SEVERITY = {
    "critical": "critical", "high": "high", "medium": "medium",
    "low": "low", "info": "none",
}

#: Severity → təxmini CVSS v3.1 baza balı (hesabat üçün göstəriş).
CVSS_HINT = {
    "critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0,
}

#: Modul → CWE təklifi (heuristik; boş ola bilər).
CWE_HINT = {
    "bypass": "CWE-863",              # Incorrect Authorization
    "apifuzz": "CWE-20",              # Improper Input Validation
    "param_enum": "CWE-20",
    "cve-intel": "CWE-1104",          # Use of Unmaintained Third Party Components
    "js": "CWE-200",                  # Exposure of Sensitive Information
    "content": "CWE-538",             # File and Directory Information Exposure
    "ferox": "CWE-538",
    "api_enum": "CWE-200",
}


def remediation_for(finding: dict) -> str:
    """Tapıntı sinfinə uyğun remediasiya mətni."""
    module = (finding.get("module") or "").lower()
    generic = ("Resursu yenidən konfiqurasiya edin, minimum imtiyaz prinsipini "
               "tətbiq edin və tapıntını təkrarlayaraq bağlandığını təsdiqləyin.")
    mapping = {
        "bypass": "Server-səviyyəli avtorizasiya yoxlamasını (yalnız client-side "
                  "deyil) tətbiq edin; reverse-proxy path normalizasiyasını "
                  "sərtləşdirin və `X-Forwarded-*`/`X-Original-URL` başlıqlarına "
                  "etibar etməyin.",
        "apifuzz": "API girişlərini sxem üzrə ciddi validasiya edin; "
                   "property-based testlərdə aşkarlanan nasazlıqları düzəldin.",
        "cve-intel": "Təsirlənən komponenti dəstəklənən versiyaya yeniləyin və "
                     "vendor təlimatına əməl edin.",
        "js": "Kliyent tərəfində secret/API açarı saxlamaqdan çəkinin; "
              "açarları server tərəfində saxlayın və dövri rotasiya edin.",
    }
    return mapping.get(module, generic)


def _severity_rank(finding: dict) -> float:
    return CVSS_HINT.get((finding.get("severity") or "info").lower(), 0.0)


def hackerone_reports(findings, hosts, evidence_by_finding) -> list[dict]:
    """Tapıntıları HackerOne-uyğun struktur siyahısına çevirir."""
    reports: list[dict] = []
    for f in findings:
        host = (hosts.get(f.get("host_id")) or {}).get("subdomain", "?")
        evs = evidence_by_finding.get(f.get("id"), [])
        body = [
            f"## Təsvir\n{redact(str(f.get('description') or ''))}",
            f"\n## Təsirlənən resurs\n`{host}`",
            f"\n## Reproduksiya\n```bash\n{redact(str(f.get('curl_repro') or ''))}\n```",
            f"\n## Sübut\n`{redact(str(f.get('evidence') or ''))}`",
        ]
        for e in evs:
            body.append(f"- [{e.get('kind')}] {redact(str(e.get('content') or ''))[:500]}")
        body.append(f"\n## Remediasiya\n{remediation_for(f)}")
        body.append(f"\n## Confidence\n{f.get('confidence', '—')} "
                    f"(status: {f.get('status')})")
        sev = (f.get("severity") or "info").lower()
        reports.append({
            "data": {
                "type": "report",
                "attributes": {
                    "title": redact(str(f.get("title") or "Finding")),
                    "severity_rating": H1_SEVERITY.get(sev, "none"),
                    "cvss_score": _severity_rank(f),
                    "weakness": CWE_HINT.get((f.get("module") or "").lower(), ""),
                    "vulnerability_information": "\n".join(body),
                    "impact": "Yuxarıdakı resurs üzərində "
                              f"{sev} səviyyəli risk.",
                    "structured_scope": {"asset_identifier": host,
                                         "asset_type": "URL"},
                    "source": f.get("source") or f.get("module"),
                },
            }
        })
    return reports


def export(base_path: str, *, findings, hosts, evidence_by_finding,
           min_severity: str = "low") -> str:
    """HackerOne formatlı JSON faylını yazır və yolunu qaytarır.

    `min_severity`-dən aşağı (və rədd edilmiş) tapıntılar ixrac olunmur.
    """
    order = ["critical", "high", "medium", "low", "info"]
    floor = order.index(min_severity) if min_severity in order else 0
    keep = [f for f in findings
            if order.index((f.get("severity") or "info").lower()) <= floor
            and f.get("status") != "rejected"]
    reports = hackerone_reports(keep, hosts, evidence_by_finding)
    path = base_path.replace(".md", ".h1.json")
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"reports": reports, "count": len(reports)}, fh,
                  ensure_ascii=False, indent=2, default=str)
    return path
