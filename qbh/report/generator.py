"""Hesabat generatoru — peşəkar Markdown + JSON çıxışı.

Təhlükəsizlik prinsipləri:
  * Gizli dəyərlər (secret/token/parol) MASKALANIR (redact/mask_value).
  * Etibarsız məzmun (başlıq, sübut, cavab mətnləri) HTML/Markdown üçün
    ESCAPE olunur → report injection / XSS mümkün deyil.
  * Təsdiqlənmiş (`verified`/`confirmed`) tapıntılar `potential` olanlardan
    AYDIQ şəkildə göstərilir — heuristik siqnal "təsdiqlənmiş" kimi təqdim
    olunmur.
  * Mərhələ xətaları və atlanan addımlar hesabata daxil edilir.
  * Bəzi mühərriklər uğursuz olsa da hesabat yaradılır.
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime

from .. import db
from ..redact import mask_value, redact

SEV_LABEL = {"critical": "🔴 KRİTİK", "high": "🟠 YÜKSƏK",
             "medium": "🟡 ORTA", "low": "🟢 AŞAĞI", "info": "ℹ️ MƏLUMAT"}
ORDER = ["critical", "high", "medium", "low", "info"]

STATUS_LABEL = {
    "confirmed": "təsdiqlənmiş",
    "reported": "hesabatda göstərilmiş",
    "candidate": "potensial (kandidat)",
    "rejected": "rədd edilmiş (false-positive)",
}

LIMITATIONS = [
    "Yalnız konfiqurasiyada AÇIQ şəkildə icazə verilmiş scope daxilində test aparılır "
    "(scope — yeganə toxunulmaz sərhəd).",
    "Dağıdıcı testlər (DoS, daimi state dəyişən əməliyyatlar, credential hücumu) "
    "default olaraq DEAKTİVDİR; aktiv fuzz/bypass profil ilə idarə olunur.",
    "Race testi yalnız `--race-fixture` ilə lokal (loopback) fixture üzərində mümkündür.",
    "403/429 → adaptiv Guardian: cooldown, identiklik rotasiyası və ya bypass "
    "matrisi (konfiqurasiyadan asılı).",
    "Heuristik siqnallar (banner, başlıq, sənəd aşkarlanması) tək başına zəiflik "
    "sübutu DEYİL; yalnız `confirmed` statuslu tapıntılar təsdiqlənmiş sayılır.",
    "Vasitə (tool) çatışmazlığı, timeout və şəbəkə xətaları əhatəni azalda bilər.",
]

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+|])")


def _esc(text, limit: int | None = None) -> str:
    """Etibarsız məzmunu təhlükəsiz Markdown mətninə çevirir."""
    s = redact(str(text if text is not None else ""))
    if limit:
        s = s[:limit]
    s = s.replace("<", "&lt;").replace(">", "&gt;")
    return _MD_SPECIAL.sub(r"\\\1", s)


def _code(text, limit: int = 160) -> str:
    """Təhlükəsiz inline code span (backtick escape + newline təmizləmə)."""
    s = redact(str(text if text is not None else ""))[:limit]
    return "`" + s.replace("`", "'").replace("\n", " ").strip() + "`"


def _sev_rank() -> dict:
    return {s: i for i, s in enumerate(ORDER)}


def _tech_items(tech_raw: str) -> list[str]:
    if not tech_raw:
        return []
    parts = tech_raw.replace(",", "|").split("|")
    return [p.strip() for p in parts if p.strip()]


def generate(severity_min: str = "low", stages=None, meta=None) -> str | None:
    stages = stages or []
    meta = meta or {}
    conn = db.get_db()

    # Per-scan izolyasiya (v4): hesabat YALNIZ cari skanın məlumatlarını göstərir.
    # `scan_id` yoxdursa → legacy qrupu (0); heç vaxt başqa skanın sətirləri
    # qarışmır. `hosts` cədvəli əsas filtrdir; qalan cədvəllər `host_id` ilə
    # ona bağlanır.
    sid = db.effective_scan_id(meta.get("scan_id"))
    scan_sub = "SELECT id FROM hosts WHERE scan_id=?"
    hosts = {r["id"]: dict(r) for r in db.all_hosts(meta.get("scan_id"))}
    findings = [dict(r) for r in conn.execute(
        f"SELECT * FROM findings WHERE host_id IN ({scan_sub}) ORDER BY CASE "
        "severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' "
        "THEN 3 WHEN 'low' THEN 4 ELSE 5 END", (sid,)).fetchall()]
    cves = [dict(r) for r in conn.execute(
        f"SELECT * FROM cve_matches WHERE host_id IN ({scan_sub}) "
        "ORDER BY in_kev DESC, epss DESC", (sid,)).fetchall()]
    # `value_enc` (Faza 3.2 şifrəli token) QƏSDƏN seçilmir — hesabata düşməz.
    secrets = [dict(r) for r in conn.execute(
        "SELECT id, host_id, js_url, kind, value_preview FROM secrets "
        f"WHERE host_id IN ({scan_sub})", (sid,)).fetchall()]
    evidence = [dict(r) for r in conn.execute(
        "SELECT e.* FROM evidence e JOIN findings f ON f.id=e.finding_id "
        f"WHERE f.host_id IN ({scan_sub}) ORDER BY e.id", (sid,)).fetchall()]
    evidence_by_finding: dict[int, list] = {}
    for e in evidence:
        evidence_by_finding.setdefault(e["finding_id"], []).append(e)
    validated = {r["finding_id"]: dict(r) for r in
                 conn.execute("SELECT * FROM validated").fetchall()}
    halted = [dict(r) for r in conn.execute(
        "SELECT * FROM hosts WHERE halted=1 AND scan_id=?", (sid,)).fetchall()]

    sev_rank = _sev_rank()
    min_rank = sev_rank.get(severity_min, 0)
    kept = [f for f in findings if sev_rank.get(f["severity"], 4) <= min_rank]
    filtered = len(findings) - len(kept)

    scan_row = None
    if meta.get("scan_id"):
        row = conn.execute("SELECT * FROM scans WHERE id=?",
                           (meta["scan_id"],)).fetchone()
        scan_row = dict(row) if row else None

    ts = datetime.now().strftime("%Y-%m-%d_%H%M")
    os.makedirs("reports", exist_ok=True)
    path = os.path.join("reports", f"qbh_{ts}.md")
    generated_at = datetime.now().strftime("%d.%m.%Y %H:%M")

    by_sev: dict[str, list] = {}
    for f in kept:
        by_sev.setdefault(f["severity"], []).append(f)
    counts = {s: len(by_sev.get(s, [])) for s in ORDER}
    verified = [f for f in kept if (f.get("status") == "confirmed")]
    reported = [f for f in kept if (f.get("status") == "reported")]
    fp = [f for f in kept if f.get("status") == "rejected"]
    possible_cves = [c for c in cves if (c.get("match_type") or "possible") != "confirmed"]
    confirmed_cves = [c for c in cves if (c.get("match_type") or "") == "confirmed"]

    L: list[str] = []
    L += ["# 🎯 QBH — Bug Bounty Hesabatı", ""]
    L += [f"*Yaradılma tarixi: {generated_at}*", ""]

    # 1. İcra xülasəsi
    L += ["## 1. İcra Xülasəsi", "",
          f"- Yoxlanan host: **{len(hosts)}**",
          f"- Tapıntı (göstərilən): **{len(kept)}**"
          + (f" (severity filtri ilə {filtered} gizlədildi)" if filtered else ""),
          f"  - Kritik: **{counts['critical']}** · Yüksək: **{counts['high']}** · "
          f"Orta: **{counts['medium']}** · Aşağı: **{counts['low']}** · "
          f"Məlumat: **{counts['info']}**",
          f"- Təsdiqlənmiş tapıntı: **{len(verified)}** · "
          f"Hesabatda göstərilən: **{len(reported)}** · "
          f"Kandidat: "
          f"**{len(kept) - len(verified) - len(reported) - len(fp)}** · "
          f"Rədd edilmiş: **{len(fp)}**",
          f"- CVE uyğunluğu: **{len(cves)}** "
          f"(təsdiqlənmiş: {len(confirmed_cves)}, mümkün: {len(possible_cves)})",
          f"- Aşkarlanan secret (maskalanmış): **{len(secrets)}**",
          f"- Blok/cooldown hadisəsi: **{len(halted)}** host", ""]

    # 2. Skan metadata
    L += ["## 2. Skan Metadatası", ""]
    if scan_row:
        L += [f"- Proqram: {_esc(scan_row.get('program'))}",
              f"- Rejim: {_esc(scan_row.get('mode'))}",
              f"- Skan ID: {scan_row.get('id')}",
              f"- Başlama: {_esc(scan_row.get('started_at'))}",
              f"- Bitmə: {_esc(scan_row.get('finished_at'))}",
              f"- Status: {_esc(scan_row.get('status'))}"]
    for key in ("program", "mode", "rate"):
        if meta.get(key) is not None:
            L.append(f"- {key}: {_esc(meta[key])}")
    L.append("")

    # 3. İcazəli scope
    L += ["## 3. İcazəli Scope (authorized)", ""]
    targets = meta.get("targets") or []
    if targets:
        L.append("Yalnız aşağıdakı hədəflər icazəlidir:")
        L.append("")
        for t in targets:
            L.append(f"- {_code(t, 200)}")
    else:
        L.append("_Scope məlumatı mövcud deyil._")
    L.append("")

    # 4. Hostlar
    L += ["## 4. Aşkarlanan Hostlar", ""]
    if hosts:
        L += ["| Host | Status | Başlıq | Texnologiya | Mənbə |",
              "|---|---|---|---|---|"]
        for h in list(hosts.values())[:300]:
            L.append("| {} | {} | {} | {} | {} |".format(
                _code(h.get("subdomain"), 100),
                h.get("status_code") if h.get("status_code") is not None else "—",
                _esc(h.get("title"), 60) or "—",
                _esc(h.get("tech_raw"), 60) or "—",
                _esc(h.get("source"), 40) or "—"))
    else:
        L.append("_Host tapılmadı._")
    L.append("")

    # 5. Xidmətlər (recon tapıntıları)
    L += ["## 5. Aşkarlanan Xidmətlər", ""]
    services = [f for f in kept if f["module"] == "recon"]
    if services:
        for f in services:
            host = hosts.get(f["host_id"], {}).get("subdomain", "?")
            L.append(f"- {_code(host, 100)}: {_esc(f['title'], 120)} — "
                     f"{_code(f.get('evidence'), 120)}")
    else:
        L.append("_Xidmət məlumatı yoxdur._")
    L.append("")

    # 6. Texnologiyalar
    L += ["## 6. Aşkarlanan Texnologiyalar", ""]
    tech_rows = [(h.get("subdomain"), _tech_items(h.get("tech_raw")))
                 for h in hosts.values() if h.get("tech_raw")]
    if tech_rows:
        for sub, items in tech_rows[:200]:
            L.append(f"- {_code(sub, 100)}: {_esc(', '.join(items), 200)}")
    else:
        L.append("_Texnologiya məlumatı yoxdur._")
    L.append("")

    # 7. Tapıntılar (severity üzrə)
    L += ["## 7. Tapıntılar (severity üzrə)", ""]
    for sev in ORDER:
        items = by_sev.get(sev)
        if not items:
            continue
        L += [f"### {SEV_LABEL.get(sev, sev)} ({len(items)} tapıntı)", ""]
        for i, f in enumerate(items, 1):
            host = hosts.get(f["host_id"], {}).get("subdomain", "?")
            status = STATUS_LABEL.get(f.get("status"), f.get("status") or "?")
            v = validated.get(f["id"])
            if v:
                v_label = ("yoxlanıldı: uğurlu" if v["passed"] == 1 else
                           "yoxlanıldı: uğursuz" if v["passed"] == 0 else
                           "yoxlanıla bilmədi")
            else:
                v_label = "yoxlanılmadı"
            L += [f"**{i}. {_esc(f['title'], 200)}**",
                  f"- Host: {_code(host, 100)}",
                  f"- Modul: {_esc(f['module'])} | Severity: {_esc(sev)} | "
                  f"Status: **{_esc(status)}**",
                  f"- Confidence: {f.get('confidence', '—')} | "
                  f"Mənbə: {_esc(f.get('source'), 60) or '—'}",
                  f"- Validation: {_esc(v_label)}"
                  + (f" ({_esc(v.get('note'), 120)})" if v else "")]
            if f.get("description"):
                L.append(f"- Təsvir: {_esc(f['description'], 500)}")
            if f.get("evidence"):
                L.append(f"- Sübut: {_code(f['evidence'], 200)}")
            if f.get("template"):
                L.append(f"- Template: {_code(f['template'], 120)}")
            if f.get("curl_repro"):
                L += ["- Reproduksiya:", "```bash", redact(str(f["curl_repro"]))[:1000],
                      "```"]
            evs = evidence_by_finding.get(f["id"])
            if evs:
                L.append("- Sübut əlavələri:")
                for e in evs[:10]:
                    L.append(f"  - [{_esc(e.get('kind'), 40)}] "
                             f"{_code(e.get('content'), 240)}")
            L.append("")

    # 8. CVE intellekti
    L += ["## 8. CVE İntellekti", ""]
    if cves:
        L += ["| Host | CVE | Produkt | Versiya | Uyğunluq | KEV | EPSS | "
              "Prioritet | Mənbə |",
              "|---|---|---|---|---|---|---|---|---|"]
        for c in cves:
            host = hosts.get(c["host_id"], {}).get("subdomain", "?")
            L.append("| {} | {} | {} | {} | {} | {} | {} | {} | {} |".format(
                _code(host, 60), _esc(c.get("cve_id"), 30),
                _esc(c.get("product"), 40), _esc(c.get("version_detected"), 30),
                _esc(c.get("match_type") or "possible"),
                "✅" if c.get("in_kev") else "—",
                f"{(c.get('epss') or 0):.2f}", _esc(c.get("priority")),
                _esc(c.get("source"), 60) or "—"))
        L.append("")
        L.append("> `confirmed` yalnız OSV dəqiq versiya uyğunluğu deməkdir; "
                 "`possible` ad/keyword uyğunluğudur və tək başına zəiflik "
                 "sübutu deyil.")
    else:
        L.append("_CVE uyğunluğu tapılmadı._")
    L.append("")

    # 9. Sübut (evidence) indeksi
    L += ["## 9. Sübut İndeksi", ""]
    with_evidence = [f for f in kept if f.get("evidence")]
    if with_evidence:
        for f in with_evidence[:200]:
            L.append(f"- [{_esc(f['severity'])}] {_esc(f['title'], 120)} → "
                     f"{_code(f['evidence'], 160)}")
    else:
        L.append("_Sübut qeydə alınmadı._")
    L.append("")

    # 10. Confidence
    L += ["## 10. Confidence (güvən) Səviyyələri", ""]
    if kept:
        buckets: dict[str, int] = {}
        for f in kept:
            conf = f.get("confidence")
            key = ("yüksək (≥0.7)" if (conf or 0) >= 0.7 else
                   "orta (0.4–0.7)" if (conf or 0) >= 0.4 else
                   "aşağı (<0.4)" if conf is not None else "bilinmir")
            buckets[key] = buckets.get(key, 0) + 1
        for k, v in buckets.items():
            L.append(f"- {k}: **{v}**")
    L.append("")

    # 11/12. False-positive & Validation statusu
    L += ["## 11. Rədd Edilmiş (false-positive) Statusu", ""]
    if fp:
        for f in fp:
            host = hosts.get(f["host_id"], {}).get("subdomain", "?")
            L.append(f"- {_code(host, 80)}: {_esc(f['title'], 120)} "
                     f"— {_esc(validated.get(f['id'], {}).get('note'), 120)}")
    else:
        L.append("_Rədd edilmiş tapıntı yoxdur._")
    L.append("")

    L += ["## 12. Validation Statusu", ""]
    if validated:
        ok = sum(1 for v in validated.values() if v["passed"] == 1)
        bad = sum(1 for v in validated.values() if v["passed"] == 0)
        unk = len(validated) - ok - bad
        L += [f"- Yenidən yoxlanıldı: **{len(validated)}**",
              f"  - Uğurlu: {ok} · Uğursuz (false-positive): {bad} · "
              f"Yoxlanıla bilməyən: {unk}", ""]
        L.append("> Yenidən yoxlamanın uğurlu olması tapıntının TƏSDİQLƏNDİYİ "
                 "mənasına gəlmir; yalnız resursun əlçatan qaldığını göstərir.")
    else:
        L.append("_Heç bir tapıntı yenidən yoxlanılmadı._")
    L.append("")

    # 13. Xətalar və atlanan mərhələlər
    L += ["## 13. Xətalar və Atlanan Mərhələlər", ""]
    if stages:
        L += ["| Mərhələ | Status | Müddət | Tapıntı | Xəta / Xəbərdarlıq |",
              "|---|---|---|---|---|"]
        for s in stages:
            name = getattr(s, "stage", "?")
            status = getattr(s, "status", "?")
            dur = getattr(s, "duration", 0.0)
            fc = getattr(s, "findings_count", 0)
            notes = "; ".join(list(getattr(s, "errors", [])) +
                              list(getattr(s, "warnings", [])))
            L.append(f"| {_esc(name)} | {_esc(status)} | {dur:.2f}s | {fc} | "
                     f"{_esc(notes, 300) or '—'} |")
        skipped = [s for s in stages if getattr(s, "status", "") == "skipped"]
        failed = [s for s in stages if getattr(s, "status", "") == "failed"]
        if skipped:
            L += ["", "**Atlanan mərhələlər:** " +
                  ", ".join(_esc(getattr(s, "stage", "?")) for s in skipped)]
        if failed:
            L += ["", "**Uğursuz mərhələlər:** " +
                  ", ".join(_esc(getattr(s, "stage", "?")) for s in failed)]
    else:
        L.append("_Mərhələ məlumatı yoxdur._")
    L.append("")

    # 14. Məhdudiyyətlər
    L += ["## 14. Skan Məhdudiyyətləri", ""]
    for lim in LIMITATIONS:
        L.append(f"- {_esc(lim)}")
    block_audit = meta.get("block_audit") or []
    if block_audit:
        L += ["", "**Blok hadisələri (adaptiv strategiya tətbiq olundu):**", ""]
        for ev in block_audit:
            L.append(f"- {_code(ev.get('host'), 80)} → HTTP {ev.get('status')}: "
                     f"{_esc(ev.get('reason'), 160)}")
    for w in meta.get("config_warnings") or []:
        L.append(f"- Konfiq xəbərdarlığı: {_esc(w, 200)}")
    L.append("")

    # 15. Zəncirləmə pipeline
    chain_audit = meta.get("chain_audit") or {}
    L += ["## 15. Zəncirləmə Pipeline (finding maximization)", ""]
    if chain_audit:
        L += [f"- Trigger hadisəsi: **{len(chain_audit.get('events') or [])}**",
              f"- İcra olunan addımlar: "
              f"{_esc(', '.join(chain_audit.get('executed') or []) or '—', 200)}",
              f"- Delegasiya olunan addımlar: "
              f"{_esc(', '.join(chain_audit.get('delegated') or []) or '—', 300)}",
              f"- İcazə/qayda səbəbindən atlanan: "
              f"**{len(chain_audit.get('skipped') or [])}**", ""]
        for s in (chain_audit.get("skipped") or [])[:30]:
            L.append(f"  - atlandı: {_esc(s, 200)}")
    else:
        L.append("_Zəncirləmə audit məlumatı yoxdur._")
    L.append("")

    # 16. İdentiklik rotasiyası (OPSEC)
    rotation_audit = meta.get("rotation_audit") or []
    L += ["## 16. İdentiklik Rotasiyası (OPSEC)", ""]
    if rotation_audit:
        L += [f"- Rotasiya hadisəsi: **{len(rotation_audit)}**", ""]
        for ev in rotation_audit[:50]:
            L.append(f"- {_code(ev.get('host'), 80)}: {_esc(ev.get('reason'), 120)} "
                     f"(UA={ev.get('ua_changed')}, başlıq={ev.get('headers_changed')}, "
                     f"proxy={ev.get('proxy_changed')})")
    else:
        L.append("_Rotasiya baş vermədi (ya konfiqurasiya söndürülüb, ya blok olmadı)._")
    L.append("")

    with open(path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(L))

    doc = {
        "generated_at": generated_at,
        "meta": {k: v for k, v in meta.items() if k != "block_audit"},
        "block_audit": block_audit,
        "summary": {
            "hosts": len(hosts),
            "findings_total": len(findings),
            "findings_shown": len(kept),
            "by_severity": counts,
            "verified": len(verified),
            "reported": len(reported),
            "false_positive": len(fp),
            "cves_total": len(cves),
            "cves_confirmed": len(confirmed_cves),
            "secrets": len(secrets),
            "evidence": len(evidence),
            "halted_hosts": len(halted),
        },
        "stages": [s.to_dict() if hasattr(s, "to_dict") else s for s in stages],
        "hosts": [dict(h) for h in hosts.values()],
        # JSON-da da həssas dəyərlər maskalanır (Markdown ilə eyni siyasət).
        "findings": [
            {**f,
             "title": redact(str(f.get("title") or "")),
             "description": redact(str(f.get("description") or "")),
             "evidence": redact(str(f.get("evidence") or "")),
             "curl_repro": redact(str(f.get("curl_repro") or ""))}
            for f in kept
        ],
        "cves": cves,
        # Secret dəyərləri JSON-da da MASKALANMIŞ saxlanılır.
        "secrets": [{**s, "value_preview": mask_value(s.get("value_preview") or "")}
                    for s in secrets],
        "validation": list(validated.values()),
        "evidence": [{**e, "content": redact(str(e.get("content") or ""))}
                     for e in evidence],
        "limitations": LIMITATIONS,
    }
    with open(path.replace(".md", ".json"), "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2, default=str)

    # Faza 5: bounty-ready ixrac (HackerOne-uyğun JSON).
    try:
        from . import exporters

        h1_path = exporters.export(
            path, findings=kept, hosts=hosts,
            evidence_by_finding=evidence_by_finding, min_severity=severity_min)
        print(f"[✅] HackerOne ixracı: {h1_path}")
    except Exception as exc:  # noqa: BLE001 - ixrac uğursuz olsa hesabat qalır
        print(f"[!] HackerOne ixracı alınmadı: {type(exc).__name__}: {exc}")

    print(f"\n[✅] Hesabat hazırdır: {path}")
    return path
