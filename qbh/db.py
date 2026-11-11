"""SQLite findings bazası — bütün modullar bununla danışır.

Xüsusiyyətlər:
  * açıq sxem + təhlükəsiz miqrasiya (mövcud istifadəçi datası silinmir)
  * UNIQUE məhdudiyyətləri → təkrar tapıntıların qarşısı
  * indekslər, tranzaksiyalar (WAL)
  * parametrləşdirilmiş SQL
  * provenance (mənbə/modul) və confidence/status saxlanması
  * vahid ISO-8601 UTC zaman formatı
"""
from __future__ import annotations

import hashlib
import sqlite3
import threading
from datetime import datetime, timezone

DB_PATH = "findings.db"
SCHEMA_VERSION = 2

_local = threading.local()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def get_db() -> sqlite3.Connection:
    conn = getattr(_local, "conn", None)
    if conn is None:
        conn = sqlite3.connect(DB_PATH, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        _local.conn = conn
    return conn


def close_db():
    conn = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
        _local.conn = None


SCHEMA_TABLES = """
CREATE TABLE IF NOT EXISTS schema_meta (
  key TEXT PRIMARY KEY, value TEXT
);
CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY,
  program TEXT, mode TEXT, started_at TEXT, finished_at TEXT,
  status TEXT DEFAULT 'running'
);
CREATE TABLE IF NOT EXISTS hosts (
  id INTEGER PRIMARY KEY,
  subdomain TEXT NOT NULL UNIQUE,
  ip TEXT, real_ip TEXT, cdn TEXT,
  status_code INTEGER, title TEXT, tech_raw TEXT,
  strategy TEXT DEFAULT 'generic',
  source TEXT,
  halted INTEGER DEFAULT 0,
  created_at TEXT, updated_at TEXT
);
CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY,
  host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  url TEXT NOT NULL, source TEXT, is_js INTEGER DEFAULT 0,
  found_at TEXT,
  UNIQUE(host_id, url)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  module TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
  description TEXT, evidence TEXT, curl_repro TEXT, template TEXT,
  confidence REAL DEFAULT 0.5,
  status TEXT DEFAULT 'potential',
  source TEXT,
  fingerprint TEXT,
  first_seen TEXT, last_seen TEXT
);
CREATE TABLE IF NOT EXISTS cve_matches (
  id INTEGER PRIMARY KEY,
  host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  cve_id TEXT, product TEXT, version_detected TEXT,
  match_type TEXT DEFAULT 'possible', source TEXT,
  in_kev INTEGER DEFAULT 0, epss REAL DEFAULT 0,
  priority TEXT DEFAULT 'low', created_at TEXT,
  UNIQUE(host_id, cve_id)
);
CREATE TABLE IF NOT EXISTS secrets (
  id INTEGER PRIMARY KEY,
  host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  js_url TEXT, kind TEXT, value_preview TEXT,
  UNIQUE(host_id, js_url, kind, value_preview)
);
CREATE TABLE IF NOT EXISTS stage_status (
  scan_id INTEGER, target TEXT, module TEXT,
  status TEXT, started_at TEXT, finished_at TEXT,
  duration REAL, errors TEXT, warnings TEXT,
  PRIMARY KEY(scan_id, target, module)
);
CREATE TABLE IF NOT EXISTS validated (
  finding_id INTEGER PRIMARY KEY,
  passed INTEGER, note TEXT, checked_at TEXT
);
"""

# İndekslər AYRI verilir: köhnə bazalarda çatışmayan sütunlar (məsələn
# `fingerprint`) əvvəlcə `_migrate` ilə əlavə olunmalıdır, YALNIZ sonra
# indeks yaradıla bilər. Əks halda `no such column: fingerprint` xətası
# yaranır və baza heç açılmır.
SCHEMA_INDEXES = """
CREATE INDEX IF NOT EXISTS idx_urls_host ON urls(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_host ON findings(host_id);
CREATE INDEX IF NOT EXISTS idx_findings_sev ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_cve_host ON cve_matches(host_id);
CREATE INDEX IF NOT EXISTS idx_stage_scan ON stage_status(scan_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
"""

# Köhnə bazalara təhlükəsiz sütun əlavələri
_EXPECTED_COLUMNS = {
    "hosts": {
        "halted": "INTEGER DEFAULT 0",
        "updated_at": "TEXT",
        "source": "TEXT",
    },
    "findings": {
        "confidence": "REAL DEFAULT 0.5",
        "status": "TEXT DEFAULT 'potential'",
        "source": "TEXT",
        "fingerprint": "TEXT",
        "first_seen": "TEXT",
        "last_seen": "TEXT",
    },
    "cve_matches": {
        "match_type": "TEXT DEFAULT 'possible'",
        "source": "TEXT",
    },
    "urls": {},
}


def _migrate(conn: sqlite3.Connection):
    for table, cols in _EXPECTED_COLUMNS.items():
        existing = {r["name"] for r in conn.execute(
            f"PRAGMA table_info({table})").fetchall()}
        if not existing:
            continue
        for col, ddl in cols.items():
            if col not in existing:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {ddl}")
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),))


def init_db():
    """Cədvəlləri yaradır, köhnə bazaları miqrasiya edir, sonra indeksləri qurur.

    Sıra VACİBDİR: əvvəl cədvəllər → sonra çatışmayan sütunlar (`_migrate`)
    → ən sonda indekslər. Beləliklə köhnə baza da açıla bilir və HEÇ BİR
    istifadəçi datası silinmir.
    """
    conn = get_db()
    with conn:
        conn.executescript(SCHEMA_TABLES)
        _migrate(conn)
        conn.executescript(SCHEMA_INDEXES)


def start_scan(program: str, mode: str) -> int:
    conn = get_db()
    with conn:
        cur = conn.execute(
            "INSERT INTO scans(program, mode, started_at, status) "
            "VALUES(?,?,?,'running')", (program, mode, _now()))
    return cur.lastrowid


def finish_scan(scan_id: int, status: str = "done"):
    conn = get_db()
    with conn:
        conn.execute("UPDATE scans SET finished_at=?, status=? WHERE id=?",
                     (_now(), status, scan_id))


def record_stage(scan_id: int | None, target: str, module: str, status: str,
                 duration: float = 0.0, errors: str = "", warnings: str = ""):
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO stage_status(scan_id,target,module,status,started_at,"
            "finished_at,duration,errors,warnings) "
            "VALUES(?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(scan_id,target,module) DO UPDATE SET "
            "status=excluded.status, finished_at=excluded.finished_at, "
            "duration=excluded.duration, errors=excluded.errors, "
            "warnings=excluded.warnings",
            (scan_id, target, module, status, _now(), _now(), duration,
             errors, warnings))


def upsert_host(subdomain: str, **kw) -> int:
    conn = get_db()
    kw = {k: v for k, v in kw.items() if v is not None}
    with conn:
        if kw:
            cols = ", ".join(kw.keys())
            qs = ", ".join(["?"] * len(kw))
            conn.execute(
                f"INSERT INTO hosts(subdomain, {cols}, created_at, updated_at) "
                f"VALUES(?, {qs}, ?, ?) "
                f"ON CONFLICT(subdomain) DO UPDATE SET "
                f"{', '.join(f'{k}=excluded.{k}' for k in kw)}, "
                f"updated_at=excluded.updated_at",
                [subdomain, *kw.values(), _now(), _now()])
        else:
            conn.execute(
                "INSERT OR IGNORE INTO hosts(subdomain, created_at, updated_at) "
                "VALUES(?,?,?)", (subdomain, _now(), _now()))
    row = conn.execute("SELECT id FROM hosts WHERE subdomain=?",
                       (subdomain,)).fetchone()
    return row["id"]


def insert_url(host_id: int, url: str, source: str, is_js: bool = False):
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO urls(host_id,url,source,is_js,found_at) "
            "VALUES(?,?,?,?,?)", (host_id, url, source, int(is_js), _now()))


def _fingerprint(host_id: int, module: str, title: str, evidence: str) -> str:
    raw = f"{host_id}|{module}|{title}|{evidence}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def insert_finding(host_id: int, module: str, severity: str, title: str,
                   description: str = "", evidence: str = "", curl_repro: str = "",
                   template: str = "", *, confidence: float = 0.5,
                   status: str = "potential", source: str = "") -> int:
    severity = (severity or "info").lower()
    fp = _fingerprint(host_id, module, title, evidence or "")
    conn = get_db()
    with conn:
        # `RETURNING id` — təkrar (ON CONFLICT) halında da HƏQİQİ sətri qaytarır.
        # (lastrowid təkrar halında köhnə/dəyişmiş qiymət verə bilər → səhv id.)
        cur = conn.execute(
            "INSERT INTO findings(host_id,module,severity,title,description,"
            "evidence,curl_repro,template,confidence,status,source,fingerprint,"
            "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(fingerprint) DO UPDATE SET last_seen=excluded.last_seen "
            "RETURNING id",
            (host_id, module, severity, title, description, evidence,
             curl_repro, template, confidence, status, source, fp, _now(), _now()))
        row = cur.fetchone()
    return row["id"] if row else -1


def insert_secret(host_id: int, js_url: str, kind: str, preview: str):
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO secrets(host_id,js_url,kind,value_preview) "
            "VALUES(?,?,?,?)", (host_id, js_url, kind, preview))


def insert_cve(host_id: int, cve_id: str, product: str, version: str,
               kev: bool, epss: float, priority: str, *,
               match_type: str = "possible", source: str = ""):
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO cve_matches(host_id,cve_id,product,"
            "version_detected,match_type,source,in_kev,epss,priority,created_at) "
            "VALUES(?,?,?,?,?,?,?,?,?,?)",
            (host_id, cve_id, product, version, match_type, source,
             int(kev), epss, priority, _now()))


def set_finding_status(finding_id: int, status: str,
                       confidence: float | None = None):
    """Tapıntının statusunu (potential/verified/false-positive) yeniləyir."""
    conn = get_db()
    fields = ["status=?"]
    params: list = [status]
    if confidence is not None:
        fields.append("confidence=?")
        params.append(float(confidence))
    params.append(finding_id)
    with conn:
        conn.execute(
            f"UPDATE findings SET {', '.join(fields)} WHERE id=?", params)


def upsert_validated(finding_id: int, passed: bool | None, note: str = ""):
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT INTO validated(finding_id,passed,note,checked_at) "
            "VALUES(?,?,?,?) ON CONFLICT(finding_id) DO UPDATE SET "
            "passed=excluded.passed, note=excluded.note, "
            "checked_at=excluded.checked_at",
            (finding_id,
             None if passed is None else int(passed), note, _now()))


def halt_host(host_id: int, val: bool = True):
    conn = get_db()
    with conn:
        conn.execute("UPDATE hosts SET halted=? WHERE id=?", (int(val), host_id))


def alive_hosts(include_halted: bool = False):
    """status_code məlum olan hostlar (defolt: dayandırılmışlar istisna)."""
    sql = "SELECT * FROM hosts WHERE status_code IS NOT NULL"
    if not include_halted:
        sql += " AND (halted IS NULL OR halted=0)"
    return get_db().execute(sql).fetchall()


def all_hosts():
    return get_db().execute("SELECT * FROM hosts").fetchall()


def findings_all():
    return get_db().execute("SELECT * FROM findings").fetchall()
