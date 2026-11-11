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
SCHEMA_VERSION = 5

#: Miqrasiya olunmuş (v3 və əvvəlki) sətirlərə verilən "legacy" scan id-si.
#: Bu dəyər HEÇ VAXT aktiv skanın hədəfi ola bilməz — `alive_hosts(scan_id)`
#: yalnız konkret scan_id ilə süzür. Real skan id-ləri 1-dən başlayır.
LEGACY_SCAN_ID = 0


def effective_scan_id(scan_id) -> int:
    """`None` → legacy sentinel; əks halda tam ədəd."""
    return LEGACY_SCAN_ID if scan_id is None else int(scan_id)

#: Tapıntı həyat dövrü (Faza 2/5). Kandidat → təsdiqlənmiş/rədd edilmiş →
#: hesabatda göstərilmiş.
FINDING_STATUSES = ("candidate", "confirmed", "rejected", "reported")

#: Köhnə (v2.1) statusların yeni həyat dövrünə uyğunlaşdırılması.
_LEGACY_STATUS = {
    "potential": "candidate",
    "verified": "confirmed",
    "confirmed": "confirmed",
    "false-positive": "rejected",
    "false_positive": "rejected",
    "reported": "reported",
    "candidate": "candidate",
    "rejected": "rejected",
}


def normalize_status(status: str) -> str:
    """Statusu kanonik həyat dövrü dəyərinə çevirir."""
    s = (status or "candidate").strip().lower()
    s = _LEGACY_STATUS.get(s, s)
    return s if s in FINDING_STATUSES else "candidate"

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
  scan_id INTEGER NOT NULL DEFAULT 0,
  subdomain TEXT NOT NULL,
  ip TEXT, real_ip TEXT, cdn TEXT,
  status_code INTEGER, title TEXT, tech_raw TEXT,
  strategy TEXT DEFAULT 'generic',
  source TEXT,
  halted INTEGER DEFAULT 0,
  created_at TEXT, updated_at TEXT,
  UNIQUE(scan_id, subdomain)
);
CREATE TABLE IF NOT EXISTS urls (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL DEFAULT 0,
  host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  url TEXT NOT NULL, source TEXT, is_js INTEGER DEFAULT 0,
  found_at TEXT,
  UNIQUE(scan_id, host_id, url)
);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY,
  scan_id INTEGER NOT NULL DEFAULT 0,
  host_id INTEGER REFERENCES hosts(id) ON DELETE CASCADE,
  module TEXT NOT NULL, severity TEXT NOT NULL, title TEXT NOT NULL,
  description TEXT, evidence TEXT, curl_repro TEXT, template TEXT,
  confidence REAL DEFAULT 0.5,
  status TEXT DEFAULT 'candidate',
  source TEXT,
  fingerprint TEXT,
  first_seen TEXT, last_seen TEXT,
  UNIQUE(scan_id, fingerprint)
);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY,
  finding_id INTEGER REFERENCES findings(id) ON DELETE CASCADE,
  scan_id INTEGER,
  kind TEXT,               -- http_response | marker | callback | data | note
  content TEXT,
  created_at TEXT,
  UNIQUE(finding_id, kind, content)
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
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_fp ON findings(fingerprint);
"""

# Köhnə bazalara təhlükəsiz sütun əlavələri
_EXPECTED_COLUMNS = {
    "hosts": {
        "scan_id": "INTEGER NOT NULL DEFAULT 0",
        "halted": "INTEGER DEFAULT 0",
        "updated_at": "TEXT",
        "source": "TEXT",
    },
    "findings": {
        "scan_id": "INTEGER NOT NULL DEFAULT 0",
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
    "urls": {
        "scan_id": "INTEGER NOT NULL DEFAULT 0",
    },
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
    # v3: köhnə tapıntı statuslarını yeni həyat dövrünə köçür (data itirmədən).
    try:
        for old, new in _LEGACY_STATUS.items():
            if old == new:
                continue
            conn.execute("UPDATE findings SET status=? WHERE status=?",
                         (new, old))
    except sqlite3.OperationalError:
        pass
    conn.execute(
        "INSERT INTO schema_meta(key, value) VALUES('schema_version', ?) "
        "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(SCHEMA_VERSION),))


def _rebuild_hosts_v4(conn: sqlite3.Connection) -> bool:
    """v3 → v4: `hosts` cədvəlini `scan_id` + `UNIQUE(scan_id, subdomain)` ilə
    yenidən qurur.

    Nə üçün rebuild: SQLite `UNIQUE(subdomain)` məhdudiyyətini `ALTER TABLE`
    ilə dəyişmək mümkün deyil. Köhnə sətirlərə `scan_id = LEGACY_SCAN_ID (0)`
    verilir → onlar YENİ skanların aktiv hədəfi ola bilməz, lakin tarixi
    hesabat üçün əlçatan qalır. Uşaq cədvəllər (urls/findings/...) `hosts.id`-ə
    istinad etdiyi üçün FK müvəqqəti söndürülür və id-lər QORUNUR.

    `True` qaytarır, əgər rebuild baş verdisə.
    """
    cols = {r["name"] for r in conn.execute("PRAGMA table_info(hosts)").fetchall()}
    if not cols or "scan_id" in cols:
        return False

    conn.execute("PRAGMA foreign_keys=OFF")
    try:
        conn.execute("BEGIN")
        conn.execute(
            "CREATE TABLE hosts_v4 ("
            " id INTEGER PRIMARY KEY,"
            " scan_id INTEGER NOT NULL DEFAULT 0,"
            " subdomain TEXT NOT NULL,"
            " ip TEXT, real_ip TEXT, cdn TEXT,"
            " status_code INTEGER, title TEXT, tech_raw TEXT,"
            " strategy TEXT DEFAULT 'generic', source TEXT,"
            " halted INTEGER DEFAULT 0, created_at TEXT, updated_at TEXT,"
            " UNIQUE(scan_id, subdomain))")
        conn.execute(
            "INSERT INTO hosts_v4(id,scan_id,subdomain,ip,real_ip,cdn,"
            "status_code,title,tech_raw,strategy,source,halted,"
            "created_at,updated_at) "
            "SELECT id, ?, subdomain, ip, real_ip, cdn, status_code, title,"
            "tech_raw, strategy, source, halted, created_at, updated_at "
            "FROM hosts", (LEGACY_SCAN_ID,))
        conn.execute("DROP TABLE hosts")
        conn.execute("ALTER TABLE hosts_v4 RENAME TO hosts")
        conn.execute("COMMIT")
    except sqlite3.Error:
        conn.execute("ROLLBACK")
        raise
    finally:
        conn.execute("PRAGMA foreign_keys=ON")
    return True


def init_db():
    """Cədvəlləri yaradır, köhnə bazaları miqrasiya edir, sonra indeksləri qurur.

    Sıra VACİBDİR: əvvəl cədvəllər → sonra hosts rebuild (v4) → çatışmayan
    sütunlar (`_migrate`) → ən sonda indekslər. Beləliklə köhnə baza da açıla
    bilir və HEÇ BİR istifadəçi datası silinmir. Miqrasiya boyu avtocommit
    rejimi istifadə olunur ki, `PRAGMA foreign_keys` effektiv olsun.
    """
    conn = get_db()
    prev_isolation = conn.isolation_level
    conn.isolation_level = None  # autocommit → PRAGMA foreign_keys işləyir
    try:
        conn.executescript(SCHEMA_TABLES)
        _rebuild_hosts_v4(conn)
        _migrate(conn)
        conn.executescript(SCHEMA_INDEXES)
    finally:
        conn.isolation_level = prev_isolation


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


def upsert_host(subdomain: str, scan_id=None, **kw) -> int:
    """Hostu cari skanın altında yaradır/yeniləyir.

    `scan_id=None` → `LEGACY_SCAN_ID` (skan konteksti olmayan çağırışlar).
    `UNIQUE(scan_id, subdomain)` sayəsində eyni host iki fərqli skanda AYRI
    sətir kimi saxlanılır → skanlar bir-birinin hostlarına qarışmır.
    """
    sid = effective_scan_id(scan_id)
    conn = get_db()
    kw = {k: v for k, v in kw.items() if v is not None}
    data = {"scan_id": sid, **kw}
    with conn:
        cols = ", ".join(data.keys())
        qs = ", ".join(["?"] * len(data))
        conn.execute(
            f"INSERT INTO hosts(subdomain, {cols}, created_at, updated_at) "
            f"VALUES(?, {qs}, ?, ?) "
            f"ON CONFLICT(scan_id, subdomain) DO UPDATE SET "
            f"{', '.join(f'{k}=excluded.{k}' for k in data)}, "
            f"updated_at=excluded.updated_at",
            [subdomain, *data.values(), _now(), _now()])
    row = conn.execute("SELECT id FROM hosts WHERE subdomain=? AND scan_id=?",
                       (subdomain, sid)).fetchone()
    return row["id"] if row else -1


def insert_url(host_id: int, url: str, source: str, is_js: bool = False, scan_id=None):
    sid = effective_scan_id(scan_id)
    conn = get_db()
    with conn:
        conn.execute(
            "INSERT OR IGNORE INTO urls(scan_id,host_id,url,source,is_js,found_at) "
            "VALUES(?,?,?,?,?,?)", (sid, host_id, url, source, int(is_js), _now()))


def _fingerprint(host_id: int, module: str, title: str, evidence: str) -> str:
    raw = f"{host_id}|{module}|{title}|{evidence}".encode()
    return hashlib.sha256(raw).hexdigest()[:32]


def insert_finding(host_id: int, module: str, severity: str, title: str,
                   description: str = "", evidence: str = "", curl_repro: str = "",
                   template: str = "", *, confidence: float = 0.5,
                   status: str = "candidate", source: str = "", scan_id=None) -> int:
    sid = effective_scan_id(scan_id)
    severity = (severity or "info").lower()
    status = normalize_status(status)
    fp = _fingerprint(host_id, module, title, evidence or "")
    conn = get_db()
    with conn:
        # `RETURNING id` — təkrar (ON CONFLICT) halında da HƏQİQİ sətri qaytarır.
        # (lastrowid təkrar halında köhnə/dəyişmiş qiymət verə bilər → səhv id.)
        cur = conn.execute(
            "INSERT INTO findings(scan_id,host_id,module,severity,title,description,"
            "evidence,curl_repro,template,confidence,status,source,fingerprint,"
            "first_seen,last_seen) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(scan_id, fingerprint) DO UPDATE SET last_seen=excluded.last_seen "
            "RETURNING id",
            (sid, host_id, module, severity, title, description, evidence,
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
    """Tapıntının həyat dövrü statusunu yeniləyir.

    Status `candidate | confirmed | rejected | reported` olmalıdır; köhnə
    adlar (`potential`, `verified`, `false-positive`) avtomatik çevrilir.
    """
    status = normalize_status(status)
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


def add_evidence(finding_id: int, kind: str, content: str,
                 scan_id: int | None = None) -> int:
    """Tapıntıya sübut əlavə edir (təkrarlar UNIQUE ilə süzülür).

    `kind`: `http_response | marker | callback | data | note`.
    """
    conn = get_db()
    with conn:
        cur = conn.execute(
            "INSERT OR IGNORE INTO evidence(finding_id,scan_id,kind,content,"
            "created_at) VALUES(?,?,?,?,?)",
            (finding_id, scan_id, str(kind)[:40], str(content),
             _now()))
    return cur.lastrowid or -1


def evidence_for(finding_id: int):
    return get_db().execute(
        "SELECT * FROM evidence WHERE finding_id=? ORDER BY id",
        (finding_id,)).fetchall()


def all_evidence():
    return get_db().execute("SELECT * FROM evidence ORDER BY id").fetchall()


def findings_by_status(status: str, scan_id=None):
    sid = effective_scan_id(scan_id)
    return get_db().execute(
        "SELECT * FROM findings WHERE status=? AND scan_id=? ORDER BY id",
        (normalize_status(status), sid)).fetchall()


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


def alive_hosts(scan_id=None, include_halted: bool = False):
    """Cari skanın status_code-u məlum hostları.

    YALNIZ həmin `scan_id`-ə aid hostlar qaytarılır → əvvəlki skanın
    hədəfləri yeni skanda AVTOMATİK yenidən skan edilə bilməz. Miqrasiya
    olunmuş "legacy" sətirlər (`scan_id=0`) heç vaxt bura düşmür
    (real skan id-ləri ≥ 1).
    """
    sid = effective_scan_id(scan_id)
    sql = "SELECT * FROM hosts WHERE scan_id=? AND status_code IS NOT NULL"
    params: list = [sid]
    if not include_halted:
        sql += " AND (halted IS NULL OR halted=0)"
    return get_db().execute(sql, params).fetchall()


def all_hosts(scan_id=None):
    """Conkret skanın bütün hostları (default: legacy qrupu)."""
    sid = effective_scan_id(scan_id)
    return get_db().execute(
        "SELECT * FROM hosts WHERE scan_id=?", (sid,)).fetchall()


def findings_all(scan_id=None):
    sid = effective_scan_id(scan_id)
    return get_db().execute("SELECT * FROM findings WHERE scan_id=?", (sid,)).fetchall()
