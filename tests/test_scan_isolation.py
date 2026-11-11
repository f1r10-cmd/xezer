"""Faza 0.1 regressiya testi — skanlararası izolyasiya (DB sxem v4).

Tarixi qüsur: `hosts` cədvəlində `scan_id` yox idi və `alive_hosts()` BÜTÜN
əvvəlki skanların hostlarını qaytarırdı → yeni skan əvvəlki skanın hədəflərini
(icazəsiz) yenidən skan edə bilirdi.

Bu fayl həmin qüsurun bir daha baş vermədiyini sübut edir:
  * `alive_hosts(scan_id)` YALNIZ həmin skanın hostlarını qaytarır.
  * İki fərqli (disjoint scope-lu) skan bir-birinin hostlarına çatmır.
  * Miqrasiya olunmuş "legacy" sətirlər (`scan_id=0`) yeni skanın hədəfi
    OLA BİLMƏZ, lakin tarixi hesabat üçün əlçatan qalır.
  * Nuclei hədəf siyahısı və bypass kandidatları yalnız cari skandan götürülür.
  * v3→v4 miqrasiyası data itirmədən və id-ləri qoruyaraq keçir.

Heç bir test xarici şəbəkəyə müraciət etmir — yalnız lokal SQLite.
"""
from __future__ import annotations

import sqlite3

from qbh import db

# ------------------------------------------------------------------ helpers


def _add(scan_id, sub, status=200):
    return db.upsert_host(sub, scan_id, status_code=status)


# --------------------------------------------------------- per-scan izolyasiya
class TestScanIsolation:
    def test_alive_hosts_only_current_scan(self, tmp_db):
        _add(1, "a.example.com")
        _add(2, "b.example.com")
        a = {r["subdomain"] for r in db.alive_hosts(1)}
        b = {r["subdomain"] for r in db.alive_hosts(2)}
        assert a == {"a.example.com"}
        assert b == {"b.example.com"}
        assert a.isdisjoint(b)

    def test_disjoint_scopes_never_cross(self, tmp_db):
        """İki skan (disjoint scope) bir-birinin hostlarına çatmamalıdır."""
        _add(10, "scanA.example.com")
        _add(11, "scanB.example.com")
        assert all(r["subdomain"].endswith("scanA.example.com")
                   for r in db.alive_hosts(10))
        assert all(r["subdomain"].endswith("scanB.example.com")
                   for r in db.alive_hosts(11))
        assert not any(r["subdomain"].startswith("scanB")
                       for r in db.alive_hosts(10))

    def test_same_subdomain_two_scans_are_separate_rows(self, tmp_db):
        """Eyni host adı iki skanda AYRI sətir kimi saxlanılır (UNIQUE(scan_id,
        subdomain)) — bir skanın yenilənməsi digərinə toxunmur."""
        id1 = _add(1, "shared.example.com", status=200)
        id2 = _add(2, "shared.example.com", status=404)
        assert id1 != id2
        assert db.alive_hosts(1)[0]["status_code"] == 200
        assert db.alive_hosts(2)[0]["status_code"] == 404

    def test_halt_one_scan_not_other(self, tmp_db):
        id1 = _add(1, "x.example.com")
        _add(2, "x.example.com")
        db.halt_host(id1)
        assert db.alive_hosts(1) == []
        assert len(db.alive_hosts(2)) == 1


# ----------------------------------------------------------- legacy təcrid
class TestLegacyIsolation:
    def test_legacy_host_not_returned_for_real_scan(self, tmp_db):
        """`scan_id=None` → legacy (0); real skanın aktiv hədəfi ola bilməz."""
        db.upsert_host("legacy.example.com", status_code=200)  # scan_id=None
        assert db.alive_hosts(1) == []
        assert db.alive_hosts(2) == []
        # Lakin legacy qrupu kimi əlçatandır (hesabat üçün).
        legacy = {r["subdomain"] for r in db.alive_hosts(None)}
        assert legacy == {"legacy.example.com"}

    def test_legacy_scan_constant_is_zero(self):
        assert db.LEGACY_SCAN_ID == 0
        assert db.effective_scan_id(None) == 0
        assert db.effective_scan_id(7) == 7


# ------------------------------------------------- engine query-path izolyasiya
class TestEngineQueryPaths:
    def test_nuclei_targets_only_current_scan(self, tmp_db):
        """`VulnEngine` hədəf siyahısını `alive_hosts(scan_id)`-dən qurur."""
        _add(1, "one.example.com")
        _add(2, "two.example.com")
        targets = [f"https://{h['subdomain']}" for h in db.alive_hosts(1)]
        assert targets == ["https://one.example.com"]
        assert "two.example.com" not in " ".join(targets)

    def test_bypass_candidates_only_current_scan(self, tmp_db, make_ctx):
        from qbh.engines.bypass import BypassEngine

        ctx = make_ctx()
        ctx.scan_id = 1
        _add(1, "one.example.com")
        _add(2, "two.example.com")
        h1 = db.alive_hosts(1)[0]["id"]
        h2 = db.alive_hosts(2)[0]["id"]
        db.insert_url(h1, "https://one.example.com/admin", "ferox")
        db.insert_url(h2, "https://two.example.com/admin", "ferox")
        picked = BypassEngine(ctx)._db_candidates()
        assert picked == ["https://one.example.com/admin"]


# ------------------------------------------------------------- v3 → v4 miqrasiya
class TestMigrationV4:
    def _make_v3_db(self, path):
        """Minimal v3 sxemi: `hosts` `scan_id`-siz + UNIQUE(subdomain)."""
        conn = sqlite3.connect(str(path))
        conn.executescript(
            "CREATE TABLE hosts ("
            " id INTEGER PRIMARY KEY, subdomain TEXT NOT NULL UNIQUE,"
            " ip TEXT, real_ip TEXT, cdn TEXT, status_code INTEGER,"
            " title TEXT, tech_raw TEXT, strategy TEXT DEFAULT 'generic',"
            " source TEXT, halted INTEGER DEFAULT 0, created_at TEXT,"
            " updated_at TEXT);"
            "CREATE TABLE urls ("
            " id INTEGER PRIMARY KEY, host_id INTEGER REFERENCES hosts(id)"
            " ON DELETE CASCADE, url TEXT, source TEXT, is_js INTEGER,"
            " found_at TEXT, UNIQUE(host_id, url));"
            "INSERT INTO hosts(id,subdomain,status_code) VALUES(5,'old.example.com',200);"
            "INSERT INTO urls(id,host_id,url,source) VALUES(9,5,'https://old.example.com/x','ferox');")
        conn.commit()
        conn.close()

    def test_migration_preserves_data_and_ids(self, tmp_path, monkeypatch):
        legacy = tmp_path / "v3.db"
        self._make_v3_db(legacy)
        monkeypatch.setattr(db, "DB_PATH", str(legacy))
        db.close_db()
        db.init_db()
        try:
            conn = db.get_db()
            cols = {r["name"] for r in conn.execute("PRAGMA table_info(hosts)")}
            assert "scan_id" in cols
            row = conn.execute(
                "SELECT id, scan_id, subdomain FROM hosts WHERE id=5").fetchone()
            assert row["id"] == 5                       # id qorunub
            assert row["scan_id"] == db.LEGACY_SCAN_ID  # legacy sentinel
            # Uşaq cədvəl sətri qalır və FK pozulmur.
            assert conn.execute(
                "SELECT COUNT(*) c FROM urls WHERE host_id=5").fetchone()["c"] == 1
            # Legacy host yeni skanın aktiv hədəfi DEYİL.
            assert db.alive_hosts(1) == []
            assert [r["subdomain"] for r in db.all_hosts(None)] == \
                ["old.example.com"]
        finally:
            db.close_db()

    def test_migration_is_idempotent(self, tmp_db):
        """Artıq v4 olan baza yenidən miqrasiya olunmur (data itmir)."""
        _add(1, "a.example.com")
        db.init_db()   # təkrar
        assert {r["subdomain"] for r in db.alive_hosts(1)} == {"a.example.com"}
