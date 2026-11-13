"""Faza 4.3 — zəiflikli loopback tətbiqinə qarşı UÇDAN-UCA inteqrasiya testi.

Bu test REAL CLI-ni (`main.main`) işlədir və tam zənciri loopback-də yoxlayır:

  * `--mode hunt` — recon → vuln → zəncir → dərin pass (bypass) tam dövrü;
  * tapıntıların `confirmed` statusuna ÇATDIĞINI sübut edir;
  * DB həyat dövrü keçidlərini (candidate → confirmed) yoxlayır;
  * hesabatın üç formatda (Markdown + JSON + HackerOne `.h1.json`) yazıldığını
    təsdiqləyir.

Fixtures: `vuln_app` (conftest.py) — loopback-də REAL HTTP server. Recon
alətləri (httpx/katana) mühitdə YOXDUR; onların çıxışı
`qbh.engines.recon.run_process` səviyyəsində deterministik təqlid olunur ki,
boru xətti həmin endpoint-ləri kəşf etsin. Bütün digər alt-proseslər bloklanır
və DNS yalnız loopback üçün həll olunur — test tam HERMETİKDİR.
"""
from __future__ import annotations

import asyncio
import json
import socket

import pytest

import main as main_mod
from qbh import db
from qbh.adapters.base import ProcResult, current_process_guard

#: `socket.getaddrinfo` üçün icazəli (loopback) host adları.
_LOOPBACK_HOSTS = {
    "127.0.0.1", "localhost", "localhost.localdomain",
    "::1", "ip6-localhost", "0.0.0.0", "::", "", "none",
}


def _fernet_key() -> str:
    """Runtime-da etibarlı Fernet açarı törədir (hardcoded secret YOXDUR).

    `QBH_VAULT_KEY` fixture-da dəyişən (`monkeypatch.setenv`) ilə ötürülür;
    açar heç vaxt mənbə kodunda saxlanmır — beləliklə secret-scanning
    (gitleaks) yalançı-pozitivi yaranmır. Açar eyni test icrası boyu
    sabitdir (vault HƏMİN açarı oxuyur).
    """
    from cryptography.fernet import Fernet

    return Fernet.generate_key().decode()


@pytest.fixture
def no_external_network(monkeypatch):
    """Xarici şəbəkə və subprocess çıxışını qəti şəkildə bloklayır.

    `yield` ilə bloklanmış xarici DNS sorğularının siyahısını verir.
    """
    blocked: list[str] = []

    async def _no_subprocess(*_a, **_kw):
        raise FileNotFoundError("e2e: subprocess qadağandır")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", _no_subprocess)

    real_getaddrinfo = socket.getaddrinfo

    def _guarded_getaddrinfo(host, *args, **kwargs):
        key = str(host).strip("[]").lower()
        if key in _LOOPBACK_HOSTS:
            return real_getaddrinfo(host, *args, **kwargs)
        blocked.append(str(host))
        raise socket.gaierror(
            socket.EAI_NONAME, f"e2e: xarici DNS bloklandı ({host})")

    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    yield blocked


@pytest.fixture
def fake_recon_tools(vuln_app, monkeypatch):
    """httpx/katana çıxışını loopback tətbiqinə yönəldən deterministik mock.

    Mühitdə bu alətlər YOXDUR (real olaraq çağırılmır) — buna görə onların
    "tapdığı" host/URL-lər fixture tərəfindən verilir. Bu, canlı alətləri olan
    real mühitin yerinə yetirdiyi kəşfi təqlid edir; HTTP-nin ÖZÜ isə realdır.
    """
    base = vuln_app["base"]
    httpx_line = json.dumps({
        "url": base, "status_code": 200, "title": "QBH demo",
        "tech": ["Express"], "a": ["127.0.0.1"], "cdn": None,
    }).encode()
    katana = "\n".join([
        f"{base}/admin",
        f"{base}/app.js",
        f"{base}/openapi.json",
        f"{base}/api/v1/users",
        f"{base}/search?q=1",
    ]).encode()

    async def _fake_run(cmd, **_kw):
        name = cmd[0] if cmd else ""
        if name == "httpx":
            return ProcResult(0, stdout=httpx_line + b"\n")
        if name == "katana":
            return ProcResult(0, stdout=katana + b"\n")
        # naabu/gau və digər recon alətləri yoxdur → dürüst `missing`.
        return ProcResult(-1, missing=True)

    monkeypatch.setattr("qbh.engines.recon.run_process", _fake_run)
    return vuln_app


def _latest_scan() -> tuple[int, str]:
    row = db.get_db().execute(
        "SELECT id, status FROM scans ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None, "heç bir skan qeydə alınmadı"
    return row["id"], row["status"]


def _findings(scan_id: int) -> list[dict]:
    return [dict(r) for r in db.get_db().execute(
        "SELECT f.* FROM findings f JOIN hosts h ON h.id=f.host_id "
        "WHERE h.scan_id=? ORDER BY f.id", (scan_id,)).fetchall()]


def _reports(tmp_path):
    reports = tmp_path / "reports"
    md = sorted(reports.glob("qbh_*.md"))
    h1 = sorted(reports.glob("qbh_*.h1.json"))
    # `qbh_*.json` HackerOne ixracını (`.h1.json`) da tutur → onu xaric et.
    js = sorted(p for p in reports.glob("qbh_*.json")
                if not p.name.endswith(".h1.json"))
    return md, js, h1


def _hunt_args(cfg: str):
    """`--mode hunt` CLI arqumentlərini qurur (birbaşa `run()` üçün)."""
    return main_mod.build_parser().parse_args(
        ["--config", cfg, "--mode", "hunt"])


class TestHuntEndToEnd:
    """`--mode hunt` zəiflikli loopback tətbiqinə qarşı tam dövr edir.

    CLI `main.run(args)` korutini kimi ÇAĞIRILIR (main() deyil): beləliklə
    `vuln_app` loopback serveri ilə EYNİ event loop-da işləyir və server
    sorğulara real cavab verə bilir.
    """

    async def test_hunt_confirms_findings_and_writes_all_reports(
            self, tmp_db, write_config, vuln_app, fake_recon_tools,
            no_external_network, monkeypatch, tmp_path):
        monkeypatch.chdir(tmp_path)
        # Şifrəli secret vault aktiv olsun (secret replay üçün).
        monkeypatch.setenv("QBH_VAULT_KEY", _fernet_key())
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        rc = await main_mod.run(_hunt_args(cfg))
        assert rc in (main_mod.EXIT_OK, main_mod.EXIT_FAILURE)

        scan_id, status = _latest_scan()
        assert scan_id >= 1
        assert status in ("completed", "partial")

        findings = _findings(scan_id)
        reported = [f for f in findings if f["status"] == "reported"]
        candidates = [f for f in findings if f["status"] == "candidate"]

        # --- həyat dövrü: candidate qaldı, təsdiqlənənlər `reported` oldu ---
        # Faza 4.4: hesabat (H1 ixracı daxil) yazıldıqdan sonra `confirmed`
        # tapıntılar terminal `reported` statusuna keçir.
        assert candidates, f"kandidat tapıntı yoxdur: {findings}"
        assert reported, f"`reported` tapıntı YOXDUR (lifecycle bağlanmadı): {findings}"

        # --- 401/403 bypass texnikası `/admin`-i açdı → confirmed → reported ---
        bypass = [f for f in reported if f["module"] == "bypass"]
        assert bypass, f"bypass tapıntısı `reported` olmadı: {findings}"
        assert any("admin" in (f["title"] or "").lower()
                   or "admin" in (f["evidence"] or "").lower() for f in bypass)

        # --- JS faylındakı yalançı secret aşkarlandı (candidate qalır) ---
        js = [f for f in candidates if f["module"] == "jsanalysis"]
        assert js, f"JS secret tapıntısı yoxdur: {findings}"

        # --- secret replay: JWT qüvvədədir → confirmed → reported ---
        replay = [f for f in reported if f["module"] == "secret_replay"]
        assert replay, f"secret replay `reported` olmadı: {findings}"

        # --- hesabat: MD + JSON + HackerOne ---
        md, js_files, h1_files = _reports(tmp_path)
        assert len(md) == 1, f"Markdown hesabat yoxdur: {md}"
        assert len(js_files) == 1, f"JSON hesabat yoxdur: {js_files}"
        assert len(h1_files) == 1, f"HackerOne ixracı yoxdur: {h1_files}"
        assert md[0].stat().st_size > 0

        text = md[0].read_text(encoding="utf-8")
        assert "QBH" in text
        assert "təsdiqlənmiş" in text
        # JS secret dəyəri hesabatda MASKALANMALIDIR (tam JWT görünməz).
        assert vuln_app["jwt"] not in text

        doc = json.loads(js_files[0].read_text(encoding="utf-8"))
        assert doc["summary"]["verified"] >= 1

        h1 = json.loads(h1_files[0].read_text(encoding="utf-8"))
        assert h1["count"] >= 1

        # Egress qapısı pipeline-dan SONRA sıfırlanmalıdır (sızma yoxdur).
        assert current_process_guard() is None

    async def test_hunt_is_hermetic_against_external_network(
            self, tmp_db, write_config, vuln_app, fake_recon_tools,
            no_external_network, monkeypatch, tmp_path):
        """Xarici DNS sorğusu bloklanır və heç bir paket kənara çıxmır."""
        monkeypatch.chdir(tmp_path)
        monkeypatch.setenv("QBH_VAULT_KEY", _fernet_key())
        cfg = write_config([
            {"domain": "127.0.0.1", "in_scope": ["127.0.0.1"],
             "out_of_scope": []}])

        await main_mod.run(_hunt_args(cfg))

        assert no_external_network, "xarici DNS qapısı işə düşmədi"
        assert all("127.0.0.1" not in b for b in no_external_network)

        # Bütün qeydə alınmış host/URL-lər yalnız loopback-dir.
        rows = db.get_db().execute(
            "SELECT subdomain FROM hosts").fetchall()
        assert rows, "heç bir host tapılmadı"
        assert all(r["subdomain"] == "127.0.0.1" for r in rows)
        assert current_process_guard() is None
