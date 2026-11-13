"""Faza 2.3 — `report/generator.py` test dəsti.

Yoxlanılan prinsiplər:
  * Boş / qismən / uğursuz skanlarda da hesabat yaradılır (heç vaxt "uğur"
    uydurulmur).
  * `confirmed` / `reported` / `candidate` / `rejected` tapıntılar AYDIQ
    şəkildə göstərilir.
  * Secret-lər həm Markdown, həm JSON-da MASKALANIR; etibarsız məzmun
    (HTML/Markdown) ESCAPE olunur → report injection mümkün deyil.
  * Böyük sübut mətnləri kəsilir.
  * HackerOne ixracı yaradılır; o uğursuz olsa da hesabat qalır.
  * Hesabat YALNIZ cari skanın məlumatlarını göstərir (per-scan izolyasiya).

Heç bir test xarici şəbəkəyə müraciət etmir — yalnız lokal SQLite + tmp fayllar.
"""
from __future__ import annotations

import json
import pathlib

from qbh import db
from qbh.report import generator
from qbh.results import StageResult, now_iso

# ------------------------------------------------------------------ helpers


def _md(path: str) -> str:
    return pathlib.Path(path).read_text(encoding="utf-8")


def _json(path: str) -> dict:
    return json.loads(pathlib.Path(path.replace(".md", ".json"))
                      .read_text(encoding="utf-8"))


def _seed(scan_id: int = 1):
    """Zəngin skan məlumatı: hostlar, tapıntılar, CVE, secret, sübut."""
    h1 = db.upsert_host("app.example.com", scan_id=scan_id, status_code=200,
                        title="App", tech_raw="nginx, php", source="httpx")
    h2 = db.upsert_host("api.example.com", scan_id=scan_id, status_code=403,
                        title="API", tech_raw="nodejs", source="httpx")
    db.halt_host(h2)

    confirmed = db.insert_finding(
        h1, "bypass", "critical", "Admin bypass", description="auth bypass",
        evidence="HTTP 200 admin panel", curl_repro="curl -sk https://app/x",
        confidence=0.95, status="confirmed", source="bypass:x", scan_id=scan_id)
    reported = db.insert_finding(
        h1, "content", "medium", "Backup file", evidence="/backup.zip",
        confidence=0.6, status="reported", source="ferox:x", scan_id=scan_id)
    candidate = db.insert_finding(
        h2, "apifuzz", "low", "Verbose error", evidence="stack trace",
        confidence=0.3, status="candidate", source="apifuzz:x", scan_id=scan_id)
    rejected = db.insert_finding(
        h2, "bypass", "high", "False positive", evidence="smth",
        confidence=0.2, status="rejected", source="bypass:x", scan_id=scan_id)

    db.upsert_validated(confirmed, True, "yenidən təsdiqləndi")
    db.upsert_validated(rejected, False, "artıq əlçatan deyil")
    db.add_evidence(confirmed, "http_response", "HTTP/1.1 200 OK")

    db.insert_cve(h1, "CVE-2021-1234", "nginx", "1.18.0", True, 0.9, "P1",
                  match_type="confirmed", source="osv")
    db.insert_cve(h1, "CVE-2020-9999", "php", "7.4", False, 0.2, "P3",
                  match_type="possible", source="nvd")
    db.insert_secret(h1, "https://app.example.com/app.js", "aws_key",
                     "AKIA1234567890ABCDEF")
    return {"h1": h1, "h2": h2, "confirmed": confirmed, "rejected": rejected,
            "candidate": candidate, "reported": reported}


# ------------------------------------------------------------------ helpers


class TestHelpers:
    def test_esc_escapes_html_and_markdown(self):
        out = generator._esc("<script>x</script> #tag *bold*")
        assert "<script>" not in out
        assert "&lt;script&gt;" in out
        assert "\\#tag" in out
        assert "\\*bold\\*" in out

    def test_esc_redacts_secrets(self):
        assert "hunter2xyz" not in generator._esc("password=hunter2xyz")

    def test_esc_none_and_limit(self):
        assert generator._esc(None) == ""
        assert len(generator._esc("abcdef", 3)) == 3

    def test_code_escapes_backticks_and_newlines(self):
        out = generator._code("a`b\nc")
        assert out.startswith("`") and out.endswith("`")
        assert "`b" not in out
        assert "'b c" in out

    def test_code_truncates(self):
        out = generator._code("x" * 500, 10)
        assert len(out) == 12   # 10 simvol + 2 backtick

    def test_tech_items(self):
        assert generator._tech_items("") == []
        assert generator._tech_items("nginx, php|node") == \
            ["nginx", "php", "node"]

    def test_sev_rank(self):
        assert generator._sev_rank()["critical"] == 0
        assert generator._sev_rank()["info"] == 4


# ------------------------------------------------------------------- skanlar


class TestEmptyScan:
    def test_empty_scan_still_generates(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = generator.generate()
        assert path and pathlib.Path(path).exists()
        text = _md(path)
        assert "QBH — Bug Bounty Hesabatı" in text
        assert "_Host tapılmadı._" in text
        assert "_CVE uyğunluğu tapılmadı._" in text
        assert "_Mərhələ məlumatı yoxdur._" in text

    def test_empty_scan_json_shape(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        doc = _json(generator.generate())
        assert doc["summary"]["hosts"] == 0
        assert doc["summary"]["findings_total"] == 0
        assert doc["limitations"]
        assert (pathlib.Path(tmp_path) / "reports").is_dir()


class TestFullScan:
    def test_sections_and_counts(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _seed()
        path = generator.generate(
            meta={"scan_id": 1, "program": "Acme", "mode": "full",
                  "targets": ["app.example.com"], "rate": 5.0})
        text = _md(path)
        assert "## 1. İcra Xülasəsi" in text
        assert "## 7. Tapıntılar" in text
        assert "Admin bypass" in text
        assert "təsdiqlənmiş" in text
        assert "potensial" in text
        assert "AKIA1234567890ABCDEF" not in text

    def test_candidate_vs_confirmed_separation(self, tmp_db, tmp_path,
                                               monkeypatch):
        monkeypatch.chdir(tmp_path)
        _seed()
        doc = _json(generator.generate(meta={"scan_id": 1}))
        s = doc["summary"]
        assert s["verified"] == 1        # confirmed
        assert s["reported"] == 1
        assert s["false_positive"] == 1
        assert s["findings_shown"] == 4
        assert s["cves_total"] == 2
        assert s["cves_confirmed"] == 1
        assert s["secrets"] == 1
        assert s["halted_hosts"] == 1
        assert s["evidence"] == 1

    def test_secret_masked_in_json(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _seed()
        doc = _json(generator.generate(meta={"scan_id": 1}))
        preview = doc["secrets"][0]["value_preview"]
        assert "AKIA1234567890ABCDEF" not in preview
        assert preview.startswith("AKIA")
        assert "*" in preview

    def test_stale_scan_row_reported(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        scan_id = db.start_scan("Acme", "full")
        db.finish_scan(scan_id, "partial")
        _seed(scan_id)
        text = _md(generator.generate(meta={"scan_id": scan_id}))
        assert "## 2. Skan Metadatası" in text
        assert "partial" in text

    def test_h1_export_written(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _seed()
        path = generator.generate(meta={"scan_id": 1})
        assert pathlib.Path(path.replace(".md", ".h1.json")).exists()

    def test_h1_export_failure_keeps_report(self, tmp_db, tmp_path, monkeypatch,
                                            capsys):
        monkeypatch.chdir(tmp_path)
        _seed()
        from qbh.report import exporters

        def boom(*a, **k):
            raise RuntimeError("ixrac partladı")

        monkeypatch.setattr(exporters, "export", boom)
        path = generator.generate(meta={"scan_id": 1})
        assert path and pathlib.Path(path).exists()
        assert "HackerOne ixracı alınmadı" in capsys.readouterr().out


class TestSeverityFilter:
    def test_min_severity_hides_lower(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        _seed()
        path = generator.generate(severity_min="high", meta={"scan_id": 1})
        text = _md(path)
        assert "gizlədildi" in text
        doc = _json(path)
        assert doc["summary"]["findings_shown"] < doc["summary"]["findings_total"]
        assert all(f["severity"] in ("critical", "high") for f in doc["findings"])


class TestInjection:
    def test_title_and_evidence_escaped(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        hid = db.upsert_host("evil.example.com", scan_id=1, status_code=200)
        db.insert_finding(hid, "xss", "high", "<script>alert(1)</script>",
                          description="<img src=x onerror=alert(1)>",
                          evidence="# header <b>bold</b>", status="confirmed",
                          scan_id=1)
        path = generator.generate(meta={"scan_id": 1})
        text = _md(path)
        assert "<script>" not in text
        assert "<img src=x" not in text
        assert "&lt;script&gt;" in text
        # Sübut `_code()` (inline span) ilə render olunur → məzmun
        # literal qalır, lakin backtick span içində təhlükəsizdir.
        assert "`# header <b>bold</b>`" in text


class TestBigEvidence:
    def test_large_evidence_truncated(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        hid = db.upsert_host("big.example.com", scan_id=1, status_code=200)
        fid = db.insert_finding(hid, "content", "medium", "Big",
                                evidence="A" * 5000, status="confirmed",
                                scan_id=1)
        db.add_evidence(fid, "data", "B" * 5000)
        path = generator.generate(meta={"scan_id": 1})
        text = _md(path)
        assert "A" * 5000 not in text
        doc = _json(path)
        # JSON-da sübut redact olunur, lakin tam saxlanılır (kəsilmir).
        assert len(doc["evidence"][0]["content"]) == 5000


class TestFailedStages:
    def test_failed_and_skipped_listed(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        stages = [
            StageResult(stage="vuln", status="failed", started_at=now_iso(),
                        duration=1.2, errors=["boom"]),
            StageResult(stage="bbot", status="skipped", started_at=now_iso(),
                        warnings=["alət yoxdur"]),
        ]
        path = generator.generate(stages=stages)
        text = _md(path)
        assert "## 13. Xətalar və Atlanan Mərhələlər" in text
        assert "**Uğursuz mərhələlər:** vuln" in text
        assert "**Atlanan mərhələlər:** bbot" in text
        assert "boom" in text

    def test_chain_and_rotation_audit_rendered(self, tmp_db, tmp_path,
                                               monkeypatch):
        monkeypatch.chdir(tmp_path)
        path = generator.generate(meta={
            "scan_id": 1,
            "chain_audit": {"events": ["a"], "executed": ["bypass"],
                            "delegated": ["param_fuzz"],
                            "skipped": ["secret_replay (RoE)"]},
            "rotation_audit": [{"host": "app.example.com", "reason": "429",
                               "ua_changed": True, "headers_changed": False,
                               "proxy_changed": False}],
            "block_audit": [{"host": "app.example.com", "status": 429,
                             "reason": "rate limit"}],
            "config_warnings": ["naməlum açar: x"],
        })
        text = _md(path)
        assert "## 15. Zəncirləmə Pipeline" in text
        # Audit mətnləri `_esc()`-dən keçir → underscore escape olunur.
        assert "param\\_fuzz" in text
        assert "secret\\_replay \\(RoE\\)" in text
        assert "## 16. İdentiklik Rotasiyası" in text
        assert "Blok hadisələri" in text
        assert "naməlum açar: x" in text


class TestModuleSections:
    def test_recon_services_and_template_rendered(self, tmp_db, tmp_path,
                                                  monkeypatch):
        """recon tapıntıları (§5 Xidmətlər) və template sahəsi göstərilir."""
        monkeypatch.chdir(tmp_path)
        hid = db.upsert_host("svc.example.com", scan_id=1, status_code=200)
        db.insert_finding(hid, "recon", "low", "Open port 22",
                          evidence="ssh banner", status="confirmed",
                          scan_id=1)
        db.insert_finding(hid, "nuclei", "high", "Templated hit",
                          template="CVE-2021-1234", status="confirmed",
                          scan_id=1)
        path = generator.generate(meta={"scan_id": 1})
        text = _md(path)
        assert "## 5. Aşkarlanan Xidmətlər" in text
        assert "Open port 22" in text
        assert "ssh banner" in text
        assert "- Template: `CVE-2021-1234`" in text


class TestScanIsolation:
    def test_report_only_current_scan(self, tmp_db, tmp_path, monkeypatch):
        monkeypatch.chdir(tmp_path)
        a = db.upsert_host("a.example.com", scan_id=1, status_code=200)
        b = db.upsert_host("b.example.com", scan_id=2, status_code=200)
        db.insert_finding(a, "content", "high", "FindingA", scan_id=1)
        db.insert_finding(b, "content", "high", "FindingB", scan_id=2)
        doc = _json(generator.generate(meta={"scan_id": 1}))
        titles = [f["title"] for f in doc["findings"]]
        assert titles == ["FindingA"]
        assert doc["summary"]["hosts"] == 1
