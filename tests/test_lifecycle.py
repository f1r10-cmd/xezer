"""Tapıntı həyat dövrü + sübut (v3) testləri.

Yoxlanılan prinsiplər:
  * Lifecycle: `candidate → confirmed | rejected | reported` (vahid kanonik).
  * Köhnə statuslar (`potential`/`verified`/`false-positive`) avtomatik
    normallaşdırılır (data itirmədən miqrasiya).
  * Sübut (`evidence`) tapıntıya əlavə olunur və təkrarlar UNIQUE ilə süzülür.
  * Heç bir test xarici hədəfə müraciət etmir.
"""
from __future__ import annotations

import sqlite3

import pytest

from qbh import db


def _add_host():
    return db.upsert_host("example.com", status_code=200)


# ---------------------------------------------------------------- normalize
class TestNormalizeStatus:
    @pytest.mark.parametrize("raw,expected", [
        ("potential", "candidate"),
        ("verified", "confirmed"),
        ("confirmed", "confirmed"),
        ("false-positive", "rejected"),
        ("false_positive", "rejected"),
        ("reported", "reported"),
        ("candidate", "candidate"),
        ("BOGUS", "candidate"),
        ("", "candidate"),
    ])
    def test_mapping(self, raw, expected):
        assert db.normalize_status(raw) == expected

    def test_schema_version_is_5(self, tmp_db):
        # v4/v5: `hosts.scan_id` + UNIQUE(scan_id, subdomain) → skan izolyasiyası.
        assert db.SCHEMA_VERSION == 5
        row = tmp_db.get_db().execute(
            "SELECT value FROM schema_meta WHERE key='schema_version'").fetchone()
        assert row["value"] == "5"


# ---------------------------------------------------------------- lifecycle
class TestFindingLifecycle:
    def test_default_status_is_candidate(self, tmp_db):
        hid = _add_host()
        fid = db.insert_finding(hid, "content", "high", "Exposure")
        row = tmp_db.get_db().execute(
            "SELECT status FROM findings WHERE id=?", (fid,)).fetchone()
        assert row["status"] == "candidate"

    def test_set_status_normalizes_legacy(self, tmp_db):
        hid = _add_host()
        fid = db.insert_finding(hid, "content", "high", "T")
        db.set_finding_status(fid, "verified")   # köhnə ad
        assert db.findings_by_status("confirmed")[0]["id"] == fid

    def test_transitions_and_findings_by_status(self, tmp_db):
        hid = _add_host()
        fid = db.insert_finding(hid, "bypass", "high", "B", status="confirmed")
        assert [r["id"] for r in db.findings_by_status("confirmed")] == [fid]
        db.set_finding_status(fid, "reported")
        assert db.findings_by_status("confirmed") == []
        assert [r["id"] for r in db.findings_by_status("reported")] == [fid]

    def test_rejected_excluded_from_candidate(self, tmp_db):
        hid = _add_host()
        fid = db.insert_finding(hid, "js", "medium", "S")
        db.set_finding_status(fid, "rejected")
        assert db.findings_by_status("candidate") == []
        assert [r["id"] for r in db.findings_by_status("rejected")] == [fid]


# ---------------------------------------------------------------- evidence
class TestEvidence:
    def test_add_and_read(self, tmp_db):
        hid = _add_host()
        fid = db.insert_finding(hid, "bypass", "high", "B")
        assert db.add_evidence(fid, "http_response", "HTTP 200 OK", scan_id=1) > 0
        evs = db.evidence_for(fid)
        assert len(evs) == 1
        assert evs[0]["kind"] == "http_response"
        assert evs[0]["content"] == "HTTP 200 OK"

    def test_duplicate_evidence_deduped(self, tmp_db):
        hid = _add_host()
        fid = db.insert_finding(hid, "bypass", "high", "B")
        db.add_evidence(fid, "marker", "same")
        db.add_evidence(fid, "marker", "same")   # UNIQUE → süzülür
        assert len(db.evidence_for(fid)) == 1

    def test_evidence_cascade_delete(self, tmp_db):
        hid = _add_host()
        fid = db.insert_finding(hid, "bypass", "high", "B")
        db.add_evidence(fid, "note", "x")
        with tmp_db.get_db() as conn:
            conn.execute("DELETE FROM findings WHERE id=?", (fid,))
        assert db.evidence_for(fid) == []


# ---------------------------------------------------------------- migration
class TestMigration:
    def test_legacy_statuses_migrated(self, tmp_path, monkeypatch):
        legacy = tmp_path / "legacy.db"
        conn = sqlite3.connect(str(legacy))
        conn.executescript(
            "CREATE TABLE findings ("
            " id INTEGER PRIMARY KEY, host_id INTEGER, module TEXT,"
            " severity TEXT, title TEXT, description TEXT, evidence TEXT,"
            " curl_repro TEXT, template TEXT, status TEXT);"
            "INSERT INTO findings(id,host_id,module,severity,title,status)"
            " VALUES(1,1,'content','high','A','verified');"
            "INSERT INTO findings(id,host_id,module,severity,title,status)"
            " VALUES(2,1,'js','medium','B','potential');"
            "INSERT INTO findings(id,host_id,module,severity,title,status)"
            " VALUES(3,1,'ferox','low','C','false-positive');")
        conn.commit()
        conn.close()

        monkeypatch.setattr(db, "DB_PATH", str(legacy))
        db.close_db()
        db.init_db()
        try:
            rows = {r["id"]: r["status"] for r in
                    db.get_db().execute("SELECT id,status FROM findings")}
            assert rows == {1: "confirmed", 2: "candidate", 3: "rejected"}
            # v3 cədvəli də yaradılmalıdır (data itmədən).
            assert db.get_db().execute(
                "SELECT COUNT(*) c FROM evidence").fetchone()["c"] == 0
        finally:
            db.close_db()
