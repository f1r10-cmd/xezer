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


# ------------------------------------------------------------- v4 → v5 miqrasiya
class TestMigrationV5:
    """v4 → v5: `evidence`/`stage_status`/`validated` cədvəlləri + findings
    üzrə əlavə sütunlar (`scan_id`, `confidence`, `status`, `source`,
    `fingerprint`, `first_seen`, `last_seen`), `urls.scan_id`,
    `cve_matches.match_type/source`. Mövcud sətirlər və id-lər QORUNMALI,
    köhnə statuslar yeni həyat dövrünə köçməlidir."""

    def _make_v4_db(self, path):
        conn = sqlite3.connect(str(path))
        conn.executescript(
            "CREATE TABLE hosts ("
            " id INTEGER PRIMARY KEY, scan_id INTEGER NOT NULL DEFAULT 0,"
            " subdomain TEXT NOT NULL, ip TEXT, real_ip TEXT, cdn TEXT,"
            " status_code INTEGER, title TEXT, tech_raw TEXT,"
            " strategy TEXT DEFAULT 'generic', source TEXT,"
            " halted INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT,"
            " UNIQUE(scan_id, subdomain));"
            "CREATE TABLE urls ("
            " id INTEGER PRIMARY KEY, host_id INTEGER REFERENCES hosts(id)"
            " ON DELETE CASCADE, url TEXT, source TEXT, is_js INTEGER,"
            " found_at TEXT, UNIQUE(host_id, url));"
            "CREATE TABLE findings ("
            " id INTEGER PRIMARY KEY, host_id INTEGER, module TEXT,"
            " severity TEXT, title TEXT, description TEXT, evidence TEXT,"
            " curl_repro TEXT, template TEXT, status TEXT);"
            "CREATE TABLE cve_matches ("
            " id INTEGER PRIMARY KEY, host_id INTEGER, cve_id TEXT,"
            " product TEXT, version_detected TEXT, in_kev INTEGER DEFAULT 0,"
            " epss REAL DEFAULT 0, priority TEXT DEFAULT 'low',"
            " created_at TEXT, UNIQUE(host_id, cve_id));"
            "INSERT INTO hosts(id,scan_id,subdomain,status_code)"
            " VALUES(7,1,'v4host.example.com',200);"
            "INSERT INTO urls(id,host_id,url,source)"
            " VALUES(8,7,'https://v4host.example.com/x','ferox');"
            "INSERT INTO findings(id,host_id,module,severity,title,status)"
            " VALUES(11,7,'content','high','V4 finding','verified');"
            "INSERT INTO cve_matches(id,host_id,cve_id,product)"
            " VALUES(12,7,'CVE-2024-0001','nginx');")
        conn.commit()
        conn.close()

    def test_v4_upgrade_adds_tables_and_columns(self, tmp_path, monkeypatch):
        legacy = tmp_path / "v4.db"
        self._make_v4_db(legacy)
        monkeypatch.setattr(db, "DB_PATH", str(legacy))
        db.close_db()
        db.init_db()
        try:
            conn = db.get_db()
            tables = {r["name"] for r in conn.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            assert {"evidence", "stage_status", "validated"} <= tables

            fcols = {r["name"] for r in conn.execute(
                "PRAGMA table_info(findings)")}
            assert {"scan_id", "confidence", "status", "source", "fingerprint",
                    "first_seen", "last_seen"} <= fcols
            assert "scan_id" in {r["name"] for r in
                                 conn.execute("PRAGMA table_info(urls)")}
            assert {"match_type", "source"} <= {r["name"] for r in
                                               conn.execute(
                                                   "PRAGMA table_info(cve_matches)")}

            assert conn.execute(
                "SELECT value FROM schema_meta WHERE key='schema_version'"
            ).fetchone()["value"] == "6"

            # Data və id-lər qorunur; köhnə status yeni həyat dövrünə köçür.
            f = conn.execute("SELECT id,status FROM findings WHERE id=11"
                             ).fetchone()
            assert f["id"] == 11
            assert f["status"] == "confirmed"
            assert conn.execute(
                "SELECT COUNT(*) c FROM urls WHERE host_id=7").fetchone()["c"] == 1
            assert conn.execute(
                "SELECT COUNT(*) c FROM cve_matches WHERE host_id=7"
            ).fetchone()["c"] == 1
            # v4 host real skan altında qalır (scan_id=1).
            assert [r["subdomain"] for r in db.alive_hosts(1)] == \
                ["v4host.example.com"]
            assert db.alive_hosts(2) == []
        finally:
            db.close_db()

    def test_v5_migration_idempotent(self, tmp_path, monkeypatch):
        legacy = tmp_path / "v4b.db"
        self._make_v4_db(legacy)
        monkeypatch.setattr(db, "DB_PATH", str(legacy))
        db.close_db()
        for _ in range(3):
            db.init_db()   # təkrar-təkrar → data itmir, sütun təkrarlanmır
        try:
            conn = db.get_db()
            assert conn.execute(
                "SELECT COUNT(*) c FROM findings").fetchone()["c"] == 1
            assert conn.execute(
                "SELECT COUNT(*) c FROM schema_meta WHERE key='schema_version'"
            ).fetchone()["c"] == 1
            cols = [r["name"] for r in conn.execute("PRAGMA table_info(findings)")]
            assert cols.count("scan_id") == 1
        finally:
            db.close_db()


# ------------------------------------------------------------- paralel skanlar
class TestParallelScans:
    def test_concurrent_scans_stay_isolated(self, tmp_db):
        """Paralel işləyən skanlar bir-birinin hostlarını/tapıntılarını
        görməməlidir (thread — real WAL yazıları)."""
        import threading

        n = 15
        scans = (1, 2, 3)
        errors: list[BaseException] = []

        def worker(scan_id):
            try:
                for i in range(n):
                    sub = f"s{scan_id}-{i}.example.com"
                    hid = db.upsert_host(sub, scan_id, status_code=200)
                    db.insert_finding(hid, "content", "high",
                                      f"F{scan_id}-{i}", scan_id=scan_id)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                db.close_db()

        threads = [threading.Thread(target=worker, args=(s,)) for s in scans]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        for s in scans:
            hosts = db.alive_hosts(s)
            assert len(hosts) == n
            assert all(h["subdomain"].startswith(f"s{s}-") for h in hosts)

    def test_concurrent_same_subdomain_separate_rows(self, tmp_db):
        """Eyni host adı paralel iki skanda AYRI sətir kimi saxlanılır."""
        import threading

        errors: list[BaseException] = []

        def worker(scan_id):
            try:
                db.upsert_host("shared.example.com", scan_id, status_code=scan_id)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)
            finally:
                db.close_db()

        threads = [threading.Thread(target=worker, args=(s,)) for s in (5, 6)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert errors == []
        assert db.alive_hosts(5)[0]["status_code"] == 5
        assert db.alive_hosts(6)[0]["status_code"] == 6

    def test_sequential_multi_scan_accumulates_without_crossing(self, tmp_db):
        """Çoxsaylı ardıcıl skan: hər skanın nəticəsi öz qrupunda qalır."""
        for scan_id in range(1, 6):
            _add(scan_id, f"scan{scan_id}.example.com")
        for scan_id in range(1, 6):
            got = {r["subdomain"] for r in db.alive_hosts(scan_id)}
            assert got == {f"scan{scan_id}.example.com"}
        assert db.all_hosts(None) == []   # heç bir sətir legacy qrupuna düşməyib
        assert sum(len(db.all_hosts(s)) for s in range(1, 6)) == 5
