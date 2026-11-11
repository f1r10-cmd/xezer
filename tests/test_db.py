"""Baza testləri — sxem, miqrasiya, dedup, tranzaksiyalar, tarixçə."""
from __future__ import annotations

import sqlite3

from qbh import db


class TestSchema:
    def test_init_idempotent(self, tmp_db):
        tmp_db.init_db()
        tmp_db.init_db()
        conn = tmp_db.get_db()
        assert conn.execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'"
        ).fetchone()[0] == str(tmp_db.SCHEMA_VERSION)

    def test_all_tables_present(self, tmp_db):
        conn = tmp_db.get_db()
        names = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        for t in ("scans", "hosts", "urls", "findings", "cve_matches",
                  "secrets", "stage_status", "validated", "schema_meta"):
            assert t in names

    def test_index_present(self, tmp_db):
        conn = tmp_db.get_db()
        idx = {r[0] for r in conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index'")}
        assert "idx_findings_fp" in idx


class TestMigration:
    def test_legacy_db_migrated_without_data_loss(self, tmp_path, monkeypatch):
        path = tmp_path / "legacy.db"
        conn = sqlite3.connect(path)
        # `fingerprint` sütunu OLMAYAN köhnə sxem
        conn.executescript(
            "CREATE TABLE findings (id INTEGER PRIMARY KEY, host_id INTEGER,"
            " module TEXT, severity TEXT, title TEXT, created_at TEXT);")
        conn.execute("INSERT INTO findings(module,severity,title) "
                     "VALUES('old','low','köhnə tapıntı')")
        conn.commit()
        conn.close()

        monkeypatch.setattr(db, "DB_PATH", str(path))
        db.close_db()
        db.init_db()  # ƏVVƏLLƏR bu "no such column: fingerprint" atırdı

        c = db.get_db()
        cols = {r["name"] for r in c.execute("PRAGMA table_info(findings)")}
        assert {"fingerprint", "confidence", "status", "source"} <= cols
        assert c.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        assert c.execute("SELECT title FROM findings").fetchone()[0] == \
            "köhnə tapıntı"
        db.close_db()


class TestHosts:
    def test_upsert_dedup(self, tmp_db):
        a = tmp_db.upsert_host("a.example.com", status_code=200)
        b = tmp_db.upsert_host("a.example.com", status_code=404)
        assert a == b
        row = tmp_db.get_db().execute(
            "SELECT status_code FROM hosts WHERE id=?", (a,)).fetchone()
        assert row["status_code"] == 404  # yenilənir

    def test_halt_excluded_from_alive(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        assert len(tmp_db.alive_hosts()) == 1
        tmp_db.halt_host(hid)
        assert len(tmp_db.alive_hosts()) == 0

    def test_alive_requires_status_code(self, tmp_db):
        tmp_db.upsert_host("no-status.example.com")
        assert len(tmp_db.alive_hosts()) == 0


class TestUrls:
    def test_url_dedup(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        tmp_db.insert_url(hid, "https://a.example.com/x", "katana")
        tmp_db.insert_url(hid, "https://a.example.com/x", "katana")
        n = tmp_db.get_db().execute(
            "SELECT COUNT(*) FROM urls").fetchone()[0]
        assert n == 1


class TestFindings:
    def test_insert_returns_correct_id(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        fid = tmp_db.insert_finding(hid, "m", "high", "t1", evidence="e1")
        assert fid > 0

    def test_dedup_same_fingerprint(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        f1 = tmp_db.insert_finding(hid, "m", "high", "t1", evidence="e1")
        f2 = tmp_db.insert_finding(hid, "m", "high", "t1", evidence="e1")
        assert f1 == f2
        assert tmp_db.get_db().execute(
            "SELECT COUNT(*) FROM findings").fetchone()[0] == 1

    def test_dedup_returns_original_id_after_other_inserts(self, tmp_db):
        """Regressiya: təkrar insert ƏVVƏLKİ sətrin id-sini qaytarmalıdır."""
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        f1 = tmp_db.insert_finding(hid, "m", "high", "t1", evidence="e1")
        f2 = tmp_db.insert_finding(hid, "m", "low", "t2", evidence="e2")
        f1_again = tmp_db.insert_finding(hid, "m", "high", "t1", evidence="e1")
        assert f1 != f2
        assert f1_again == f1

    def test_distinct_findings_kept(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        tmp_db.insert_finding(hid, "m", "high", "t1", evidence="e1")
        tmp_db.insert_finding(hid, "m", "high", "t2", evidence="e2")
        assert tmp_db.get_db().execute(
            "SELECT COUNT(*) FROM findings").fetchone()[0] == 2

    def test_set_finding_status(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        fid = tmp_db.insert_finding(hid, "m", "high", "t1")
        tmp_db.set_finding_status(fid, "rejected", confidence=0.1)
        row = tmp_db.get_db().execute(
            "SELECT status, confidence FROM findings WHERE id=?", (fid,)
        ).fetchone()
        assert row["status"] == "rejected"
        assert row["confidence"] == 0.1

    def test_legacy_status_normalized(self, tmp_db):
        """Köhnə status adları yeni həyat dövrünə çevrilir."""
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        fid = tmp_db.insert_finding(hid, "m", "high", "t1")
        tmp_db.set_finding_status(fid, "false-positive")
        row = tmp_db.get_db().execute(
            "SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
        assert row["status"] == "rejected"


class TestCve:
    def test_cve_dedup(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        tmp_db.insert_cve(hid, "CVE-2024-1", "nginx", "1.20",
                          kev=False, epss=0.1, priority="low",
                          match_type="possible", source="nvd")
        tmp_db.insert_cve(hid, "CVE-2024-1", "nginx", "1.20",
                          kev=True, epss=0.9, priority="high",
                          match_type="confirmed", source="osv")
        rows = tmp_db.get_db().execute(
            "SELECT * FROM cve_matches").fetchall()
        assert len(rows) == 1
        assert rows[0]["match_type"] == "possible"  # ilk qeyd qorunur


class TestSecrets:
    def test_secret_dedup(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        tmp_db.insert_secret(hid, "https://a.example.com/x.js", "AWS", "AKIA***")
        tmp_db.insert_secret(hid, "https://a.example.com/x.js", "AWS", "AKIA***")
        assert tmp_db.get_db().execute(
            "SELECT COUNT(*) FROM secrets").fetchone()[0] == 1


class TestValidated:
    def test_upsert_validated_none(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        fid = tmp_db.insert_finding(hid, "m", "high", "t1")
        tmp_db.upsert_validated(fid, None, "yoxlanıla bilmədi")
        row = tmp_db.get_db().execute(
            "SELECT passed FROM validated WHERE finding_id=?", (fid,)
        ).fetchone()
        assert row["passed"] is None

    def test_upsert_validated_updates(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        fid = tmp_db.insert_finding(hid, "m", "high", "t1")
        tmp_db.upsert_validated(fid, True, "ok")
        tmp_db.upsert_validated(fid, False, "artıq yox")
        row = tmp_db.get_db().execute(
            "SELECT * FROM validated WHERE finding_id=?", (fid,)).fetchone()
        assert row["passed"] == 0
        assert row["note"] == "artıq yox"


class TestScansAndStages:
    def test_scan_lifecycle_preserves_history(self, tmp_db):
        s1 = tmp_db.start_scan("p", "full")
        tmp_db.finish_scan(s1, "done")
        s2 = tmp_db.start_scan("p", "recon")
        tmp_db.finish_scan(s2, "done")
        rows = tmp_db.get_db().execute("SELECT * FROM scans").fetchall()
        assert len(rows) == 2
        assert all(r["status"] == "done" for r in rows)

    def test_record_stage_upsert(self, tmp_db):
        sid = tmp_db.start_scan("p", "full")
        tmp_db.record_stage(sid, "t", "recon", "ok", 1.0)
        tmp_db.record_stage(sid, "t", "recon", "failed", 2.0, errors="boom")
        rows = tmp_db.get_db().execute("SELECT * FROM stage_status").fetchall()
        assert len(rows) == 1
        assert rows[0]["status"] == "failed"
        assert rows[0]["errors"] == "boom"


class TestParameterizedSql:
    def test_injection_attempt_is_stored_literally(self, tmp_db):
        hid = tmp_db.upsert_host("a.example.com", status_code=200)
        evil = "t'); DROP TABLE findings;--"
        tmp_db.insert_finding(hid, "m", "low", evil)
        assert tmp_db.get_db().execute(
            "SELECT COUNT(*) FROM findings").fetchone()[0] == 1
        row = tmp_db.get_db().execute("SELECT title FROM findings").fetchone()
        assert row["title"] == evil
