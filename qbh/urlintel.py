"""URL Intelligence qatı (Faza 1) — kəşflə mühərrik seçimi arasında mərkəzi qərar.

Axın::

    Raw URL-lər → Normalizasiya → Təsnifat → Parametr intellekti →
    Dublikat aşkarlanması → Endpoint ailələri → Mühərrik uyğunluğu →
    Prioritetləşdirmə → Tapşırıq planlaşdırıcısı

Prinsiplər:
  * MÖVCUD abstraksiyanı genişləndirir: `urls` cədvəli yeganə URL mənbəyidir —
    bu modul YENİ URL anbarı YARATMIR.
  * Orijinal URL, normalizə olunmuş URL və endpoint kimliyi AYRI saxlanılır.
  * Semantik fərqlər QORUNUR: `/product?id=1` ilə `/product?id=2`, yaxud
    `/search?q=admin` ilə `/search?q=user` BİRLƏŞDİRİLMİR (sorğu parametrinin
    həm ADI, həm DƏYƏRİ normalizə olunmuş formaya daxildir).
  * Naməlum (`unknown`) endpoint SƏSSİZCƏ ATILMIR — `deferred` kimi saxlanılır.
  * Bütün qərarlar DETERMİNİSTİK və test edilə biləndir.
  * Yeni zəiflik modulu YOXDUR — yalnız mövcud mühərriklər üçün uyğunluq.

Bu modul şəbəkəyə ÇIXMIR və tapıntı yaratmır — yalnız qərar verir.

Cavab metadata-sı ilə təsnifatın dəqiqləşdirilməsi (Faza 2):
  * `classify_url(..., content_type=...)` real cavab `Content-Type`-ını qəbul edə
    bilir. Lakin bu, mühərrik uyğunluğunu AVTOMATİK dəyişməməlidir: `Content-Type`
    hədəf (hücumçu) tərəfindən idarə olunur — ona əsaslanıb endpoint-i "statik"
    kimi işarələmək injeksiya testini SUSTURMAQ (evasion) deməkdir. Bu, mövcud
    təhlükəsizlik testini zəiflədir → QADAĞANDIR.
  * Buna görə cavab metadata-sı YALNIZ uyğunluğu DƏYİŞMƏYƏN təsnifat dəqiqləş-
    dirməsi üçün istifadə olunur (`UrlIntelligence.refine_from_response`).
    Dəqiqləşdirmə:
      1. orijinal URL-i SAXLAYIR (yalnız `category` dəqiqləşir);
      2. yeni dəlili (content-type + mənbə) qeyd edir;
      3. BİRTƏRƏFLİDİR — bir endpoint üçün İLK dəlil qalib gəlir, sonrakı
         fərqli cavab metadata-sı tətbiq OLUNMUR (salınım/oscillation yoxdur);
      4. HEÇ BİR mühərrikin `eligible/ineligible/deferred` qərarını DƏYİŞMİR —
         yəni mühərrik-uyğunluğunu kənardan keçmir (bypass etmir).
    Uyğunluğu dəyişəcək dəqiqləşdirmələr SƏBƏBLƏ RƏDD olunur və qeyd olunur.
  * Cavab metadata-sı əlavə HTTP sorğusu YARATmir — artıq çəkilmiş cavabdan
    (məs. `ffuf` JSON çıxışındakı `content-type`) götürülür.
"""
from __future__ import annotations

import hashlib
import re
from collections import Counter
from dataclasses import asdict, dataclass, field, replace
from urllib.parse import parse_qsl, quote, urlencode, urlsplit, urlunsplit

# --------------------------------------------------------------------------- #
# Kateqoriyalar
# --------------------------------------------------------------------------- #
CAT_DYNAMIC = "dynamic"
CAT_HTML = "html"
CAT_SEARCH = "search"
CAT_AUTH = "auth"
CAT_API = "api"
CAT_DOWNLOAD = "download"
CAT_JS = "javascript"
CAT_CSS = "css"
CAT_IMAGE = "image"
CAT_FONT = "font"
CAT_STATIC = "static"
CAT_UNKNOWN = "unknown"

#: Dinamik injeksiya testinə (SQLi/XSS/SSTI/SSRF) UYĞUN OLMAYAN statik siniflər.
STATIC_CATEGORIES = frozenset({CAT_CSS, CAT_IMAGE, CAT_FONT, CAT_STATIC})

#: XEzer-də MÖVCUD olan mühərriklər (yalnız bunlar üçün qərar verilir).
ENGINES = ("sqli", "xss", "ssti", "ssrf", "param", "js", "library_cve",
           "api", "content", "jwt", "sourcecode")

DEFAULT_PORTS = {"http": 80, "https": 443}

#: Uzantı → kateqoriya (statik resurslar).
EXT_CATEGORY = {
    ".js": CAT_JS, ".mjs": CAT_JS,
    ".css": CAT_CSS,
    ".png": CAT_IMAGE, ".jpg": CAT_IMAGE, ".jpeg": CAT_IMAGE,
    ".gif": CAT_IMAGE, ".svg": CAT_IMAGE, ".ico": CAT_IMAGE,
    ".webp": CAT_IMAGE, ".bmp": CAT_IMAGE, ".avif": CAT_IMAGE,
    ".woff": CAT_FONT, ".woff2": CAT_FONT, ".ttf": CAT_FONT,
    ".otf": CAT_FONT, ".eot": CAT_FONT,
    ".pdf": CAT_STATIC, ".zip": CAT_STATIC, ".gz": CAT_STATIC,
    ".tar": CAT_STATIC, ".rar": CAT_STATIC, ".7z": CAT_STATIC,
    ".doc": CAT_STATIC, ".docx": CAT_STATIC, ".xls": CAT_STATIC,
    ".xlsx": CAT_STATIC, ".ppt": CAT_STATIC, ".pptx": CAT_STATIC,
    ".mp4": CAT_STATIC, ".webm": CAT_STATIC, ".mp3": CAT_STATIC,
    ".wav": CAT_STATIC, ".avi": CAT_STATIC, ".mov": CAT_STATIC,
    ".map": CAT_STATIC, ".wasm": CAT_STATIC,
    ".json": CAT_STATIC, ".xml": CAT_STATIC, ".csv": CAT_STATIC,
    ".txt": CAT_STATIC, ".rss": CAT_STATIC, ".atom": CAT_STATIC,
}

API_RE = re.compile(r"(?i)(^|/)(api|rest|graphql|gql|v[0-9]+)(/|$)")
AUTH_RE = re.compile(
    r"(?i)(login|signin|sign-in|signup|sign-up|auth|oauth|token|session|"
    r"logout|register|password|passwd|reset|account)")
DOWNLOAD_RE = re.compile(r"(?i)(download|export|attachment|backup)")
INTERESTING_RE = re.compile(
    r"(?i)(admin|api|internal|private|login|upload|debug|config|backup|"
    r"\.git|swagger|actuator|manage|dashboard|/v\d+/|graphql)")

#: Parametr adı kateqoriyaları.
SEARCH_PARAMS = frozenset({"q", "query", "s", "search", "keyword", "kw",
                           "term", "find", "lookup"})
PAGINATION_PARAMS = frozenset({"page", "p", "offset", "limit", "start", "count",
                               "size", "per_page", "perpage", "from", "skip",
                               "after", "before", "cursor", "n"})
SORT_PARAMS = frozenset({"sort", "order", "orderby", "order_by", "sortby",
                         "sort_by", "dir", "direction", "asc", "desc"})
REDIRECT_PARAMS = frozenset({"url", "uri", "link", "src", "source", "dest",
                             "destination", "redirect", "redirect_uri",
                             "next", "return", "returnurl", "return_url",
                             "continue", "callback", "webhook", "goto",
                             "target", "to", "out", "host", "domain", "u",
                             "href", "site", "address", "feed", "rss",
                             "remote", "proxy", "fetch", "import", "load",
                             "open", "resource", "view"})
FILE_PARAMS = frozenset({"file", "filename", "file_name", "path", "filepath",
                         "file_path", "dir", "folder", "doc", "document",
                         "template", "image", "img", "photo",
                         "attachment"})
ID_PARAMS = frozenset({"id", "uid", "pid", "gid", "nid", "item", "itemid",
                       "product", "productid", "user", "userid", "order",
                       "orderid", "account", "accountid", "no", "num", "key"})

CAT_NUMERIC = "numeric_id"
CAT_SEARCHP = "search"
CAT_PAGINATION = "pagination"
CAT_SORT = "sort"
CAT_REDIRECT = "redirect"
CAT_FILE = "file"
CAT_UNKNOWN_P = "unknown"

_UNRESERVED = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
_HEX = re.compile(r"%([0-9A-Fa-f]{2})")
_NUM_SEG = re.compile(r"^\d+$")
_UUID_SEG = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                       r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_HASH_SEG = re.compile(r"^[0-9a-fA-F]{16,}$")
_URLISH = re.compile(r"^https?://", re.I)


# --------------------------------------------------------------------------- #
# Normalizasiya
# --------------------------------------------------------------------------- #
def _decode_unreserved(text: str) -> str:
    """Yalnız `unreserved` simvolları açır; qalan `%XX` BÖYÜK hərflə qalır.

    `%2F` (kodlanmış slash) AÇILMIR → `/a%2Fb` ilə `/a/b` səhvən birləşmir.
    """
    if "%" not in text:
        return text

    def repl(m: re.Match) -> str:
        ch = chr(int(m.group(1), 16))
        return ch if ch in _UNRESERVED else "%" + m.group(1).upper()

    return _HEX.sub(repl, text)


def normalize_path(path: str) -> str:
    """Yolun kanonik forması: təkrarlanan slash-lar birləşir, encoding sabitlənir.

    `%XX` ardıcıllıqları QORUNUR (yalnız `unreserved` simvollar açılır):
    `/a%2Fb` ilə `/a/b` BİRLƏŞMİR — kodlanmış slash semantik fərqdir.
    """
    if not path:
        return "/"
    path = re.sub(r"/{2,}", "/", path)
    path = _decode_unreserved(path)
    # `%` təhlükəsiz siyahıya daxildir → mövcud `%XX` İKİ DƏFƏ kodlanmır və
    # kodlanmış rezerv simvollar (məs. `%2F`) toxunulmaz qalır.
    path = quote(path, safe="/%:@!$&'()*+,;=~-._")
    if len(path) > 1 and path.endswith("/"):
        path = path.rstrip("/") or "/"
    return path


def normalize_query(query: str) -> str:
    """Sorğu sətirinin kanonik forması (parametr sırası sabitlənir).

    Parametr ADI və DƏYƏRİ kimliyə daxildir — `id=1` ilə `id=2` AYRILIR.
    Təkrar parametr adları (`id=1&id=2`) qorunur.
    """
    if not query:
        return ""
    pairs = parse_qsl(query, keep_blank_values=True)
    norm = [(_decode_unreserved(k), _decode_unreserved(v)) for k, v in pairs]
    norm.sort(key=lambda kv: (kv[0], kv[1]))
    return urlencode(norm)


def normalize_url(url: str) -> str | None:
    """Deterministik normalizasiya. Etibarsız URL üçün `None`.

    * hostname kiçik hərfə salınır
    * scheme kiçik hərfə salınır (yoxdursa `http`)
    * default port (80/443) silinir
    * fragment (`#...`) atılır
    * yol kanonikləşir, sorğu parametrləri sıralanır
    * orijinal URL SAXLANILIR (bu funksiya yalnız kimlik üçündür)
    """
    if not url or not isinstance(url, str):
        return None
    raw = url.strip()
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return None
    scheme = (parts.scheme or "http").lower()
    if scheme not in ("http", "https"):
        # qeyri-HTTP sxemlər (mailto:, javascript:) — normalizasiya olunmur
        return None
    try:
        host = (parts.hostname or "").lower()
    except ValueError:
        return None
    if not host:
        return None
    try:
        port = parts.port
    except ValueError:
        port = None
    if ":" in host:                      # IPv6 literal
        host = f"[{host}]"
    netloc = host
    if port and port != DEFAULT_PORTS.get(scheme):
        netloc = f"{host}:{port}"

    path = normalize_path(parts.path)
    query = normalize_query(parts.query)
    return urlunsplit((scheme, netloc, path, query, ""))   # fragment atılır


def endpoint_identity(url: str) -> str:
    """Endpoint kimliyi — sxem + host + yol (sorğu parametrləri ÇIXARILIR)."""
    norm = normalize_url(url)
    if norm is None:
        return ""
    p = urlsplit(norm)
    return urlunsplit((p.scheme, p.netloc, p.path, "", ""))


def endpoint_family(url: str) -> str:
    """Endpoint ailəsi — eyni marşrutu paylaşan endpoint-lər üçün ortaq açar.

    Rəqəmsal/UUID/hash yol seqmentləri `{id}` ilə əvəz olunur: yəni
    `/product/1`, `/product/2` → eyni ailə. Sorğu parametrləri ailəyə DAXİL
    DEYİL (onlar `endpoint_identity` səviyyəsində qorunur).
    """
    ident = endpoint_identity(url)
    if not ident:
        return ""
    p = urlsplit(ident)
    segs = []
    for seg in p.path.split("/"):
        if seg and (_NUM_SEG.match(seg) or _UUID_SEG.match(seg)
                    or _HASH_SEG.match(seg)):
            segs.append("{id}")
        else:
            segs.append(seg)
    return urlunsplit((p.scheme, p.netloc, "/".join(segs), "", ""))


# --------------------------------------------------------------------------- #
# Parametr intellekti
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Param:
    name: str
    value: str
    location: str = "query"      # query | path | form | json
    category: str = CAT_UNKNOWN_P


def classify_param(name: str, value: str = "") -> str:
    """Parametrin məna kateqoriyası (aşkarlanma qaydası DETERMİNİSTİKDİR)."""
    n = (name or "").strip().lower()
    v = (value or "").strip()
    if n in FILE_PARAMS:
        return CAT_FILE
    if n in REDIRECT_PARAMS:
        return CAT_REDIRECT
    if n in SEARCH_PARAMS:
        return CAT_SEARCHP
    if n in PAGINATION_PARAMS:
        return CAT_PAGINATION
    if n in SORT_PARAMS:
        return CAT_SORT
    if n in ID_PARAMS:
        return CAT_NUMERIC
    if v.isdigit():
        return CAT_NUMERIC
    if _URLISH.match(v):
        return CAT_REDIRECT
    if n.endswith(("id", "_id")) or n.endswith("url") or n.endswith("uri"):
        return CAT_NUMERIC if n.endswith(("id", "_id")) else CAT_REDIRECT
    if n.startswith(("is_", "has_", "show", "enable", "disable")):
        return CAT_UNKNOWN_P
    return CAT_UNKNOWN_P


def extract_params(url: str, *, location: str = "query") -> tuple[Param, ...]:
    """URL-dən parametrləri (ad, dəyər, yer, kateqoriya) çıxarır."""
    try:
        query = urlsplit(url).query
    except ValueError:
        return ()
    if not query:
        return ()
    out = []
    for name, value in parse_qsl(query, keep_blank_values=True):
        out.append(Param(name=name, value=value, location=location,
                         category=classify_param(name, value)))
    return tuple(out)


# --------------------------------------------------------------------------- #
# Çox-səviyyəli URL kimliyi (Faza 1, §3.1)
# --------------------------------------------------------------------------- #
#: Kimlik səviyyələri — HƏR biri ÖZ test məqsədi üçündür və QARIŞDIRILMIR.
#: Bir səviyyədə birləşdirmə YALNIZ o test növü üçün təhlükəsizdirsə edilir.
IDENTITY_LEVELS = ("infra", "testing", "param", "idor", "auth")

_IDENTITY_REASONS = {
    "infra": ("İnfrastruktur kəşfi: yalnız sxem+host+port — yol, parametr, "
              "metod və obyekt ID-ləri BURAXILIR ki, eyni xidmət bir host kimi "
              "qruplaşsın (/user/1 ilə /user/2 eyni infrastrukturdur)."),
    "testing": ("Ümumi zəiflik testi: sxem+host+port+yol+METOD. Parametr "
                "DƏYƏRLƏRİ buraxılır — onlar `param` səviyyəsində qorunur; "
                "metod AYRI saxlanılır (GET/POST fərqli testdir)."),
    "param": ("Parametr testi: üstəlik parametr ADI və DƏYƏRİ. `?id=1` ilə "
              "`?id=2` AYRILIR — dəyər semantik fərqdir, birləşdirilmir."),
    "idor": ("IDOR/BOLA: üstəlik istifadəçi-kontekst markerləri və obyekt "
             "ID-ləri. Rəqəmsal/UUID/hash yol seqmentləri QORUNUR — onlar "
             "dəyişdirilə bilən obyekt açarıdır (birləşdirmə təhlükəsiz deyil)."),
    "auth": ("Autentifikasiya konteksti: üstəlik auth halı (sessiya/rol/"
             "token). Fərqli auth kontekstdə eyni yol AYRILIR — sorğu "
             "eyniləşdirilməsi dəyişir."),
}


def _identity_host(url: str) -> str:
    """Sxem + host + qeyri-default port (default port silinir)."""
    try:
        p = urlsplit(url)
    except ValueError:
        return ""
    scheme = (p.scheme or "http").lower()
    try:
        host = (p.hostname or "").lower()
    except ValueError:
        host = ""
    if not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = p.port
    except ValueError:
        port = None
    if port and port != DEFAULT_PORTS.get(scheme):
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _identity_path(url: str) -> str:
    try:
        path = urlsplit(url).path
    except ValueError:
        return "/"
    return normalize_path(path)


def _identity_query(url: str) -> str:
    try:
        query = urlsplit(url).query
    except ValueError:
        return ""
    return normalize_query(query)


def _object_segments(url: str) -> tuple[str, ...]:
    """Yoldaki rəqəmsal/UUID/hash seqmentlər (obyekt ID-ləri), SIRA ilə.

    Bunlar IDOR/BOLA testində dəyişən açar ola bilər → `idor_id`-də QORUNUR.
    """
    path = _identity_path(url)
    return tuple(seg for seg in path.split("/")
                 if seg and (_NUM_SEG.match(seg) or _UUID_SEG.match(seg)
                             or _HASH_SEG.match(seg)))


def _identity_hash(level: str, payload: str) -> str:
    raw = f"{level}\x1f{payload}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass
class URLIdentity:
    """Bir URL üçün ÇOX-SƏVİYYƏLİ kimliklər (normalizasiya ORİJİNALI silmir).

    Hər səviyyə fərqli test məqsədi üçün təhlükəsiz birləşdirmə dərəcəsini
    təmsil edir; heç bir səviyyə digərini əvəz etmir.
    """

    original: str
    method: str = "GET"
    auth_context: str = ""
    infra_id: str = ""
    testing_id: str = ""
    param_id: str = ""
    idor_id: str = ""
    auth_id: str = ""
    reasons: dict = field(default_factory=dict)

    def get(self, level: str) -> str:
        """Səviyyə adı ilə kimliyi qaytarır (naməlum səviyyə → boş sətir)."""
        if level not in IDENTITY_LEVELS:
            return ""
        return getattr(self, f"{level}_id")

    def reason(self, level: str) -> str:
        """Verilmiş səviyyənin NİYƏ təhlükəsiz olduğunu izah edir."""
        return str(self.reasons.get(level, ""))

    def preserves_original(self) -> bool:
        """Normalizasiya orijinalı saxlayıbmı (həmişə `True` olmalıdır)."""
        return bool(self.original)

    def as_dict(self) -> dict:
        return {level: self.get(level) for level in IDENTITY_LEVELS}


def url_identity(url: str, *, method: str = "GET",
                 auth_context: str = "") -> URLIdentity:
    """URL-dən çox-səviyyəli kimlik qurur (DETERMİNİSTİK, şəbəkəsiz).

    Birləşdirmə qaydaları:
      * `infra_id`  → yalnız host (yol/parametr/metod/obyekt ID-ləri buraxılır);
      * `testing_id`→ + yol + metod (parametr DƏYƏRLƏRİ buraxılır);
      * `param_id`  → + parametr adı və dəyəri;
      * `idor_id`   → + obyekt ID-ləri (rəqəmsal/UUID/hash seqmentlər);
      * `auth_id`   → + auth konteksti.

    Orijinal URL həmişə `original`-də SAXLANILIR — normalizasiya onu silmir.
    """
    raw = "" if url is None else str(url)
    m = (method or "GET").upper()
    ac = auth_context or ""
    host_base = _identity_host(raw)
    path = _identity_path(raw)
    query = _identity_query(raw)
    objs = _object_segments(raw)

    base_payload = "\x1f".join([host_base, path, m])
    with_query = base_payload + "\x1f" + query
    return URLIdentity(
        original=raw,
        method=m,
        auth_context=ac,
        infra_id=_identity_hash("infra", host_base),
        testing_id=_identity_hash("testing", base_payload),
        param_id=_identity_hash("param", with_query),
        idor_id=_identity_hash("idor", with_query + "\x1f" + "/".join(objs)),
        auth_id=_identity_hash("auth", base_payload + "\x1f" + ac),
        reasons=dict(_IDENTITY_REASONS),
    )


# --------------------------------------------------------------------------- #
# Təsnifat
# --------------------------------------------------------------------------- #
def _extension(path: str) -> str:
    seg = path.rsplit("/", 1)[-1]
    if "." in seg:
        return "." + seg.rsplit(".", 1)[-1].lower()
    return ""


def classify_url(url: str, *, content_type: str | None = None,
                 is_js: bool = False, params: tuple[Param, ...] = ()) -> str:
    """Endpoint-i mövcud dəlilə görə təsnif edir.

    Naməlum hal `unknown` qaytarır — bu, `deferred` deməkdir, ATILMA deyil.
    """
    try:
        p = urlsplit(url)
    except ValueError:
        return CAT_UNKNOWN
    if is_js:
        return CAT_JS

    ext = _extension(p.path)
    if ext in EXT_CATEGORY:
        return EXT_CATEGORY[ext]

    if content_type:
        ct = content_type.split(";", 1)[0].strip().lower()
        if ct:
            if "css" in ct:
                return CAT_CSS
            if "javascript" in ct or ct.endswith("ecmascript"):
                return CAT_JS
            if ct.startswith("image/"):
                return CAT_IMAGE
            if ct.startswith("font/") or "font" in ct:
                return CAT_FONT
            if ct in ("application/json", "application/xml", "text/xml"):
                return CAT_STATIC
            if ct == "text/html":
                if params and any(pp.category == CAT_SEARCHP for pp in params):
                    return CAT_SEARCH
                return CAT_HTML

    if API_RE.search(p.path):
        return CAT_API
    if AUTH_RE.search(p.path):
        return CAT_AUTH
    if DOWNLOAD_RE.search(p.path):
        return CAT_DOWNLOAD
    if params:
        if any(pp.category == CAT_SEARCHP for pp in params):
            return CAT_SEARCH
        return CAT_DYNAMIC
    return CAT_UNKNOWN


# --------------------------------------------------------------------------- #
# Endpoint modeli
# --------------------------------------------------------------------------- #
@dataclass
class Endpoint:
    original: str
    normalized: str
    identity: str
    family: str
    category: str
    params: tuple[Param, ...] = ()
    source: str = ""
    host: str = ""
    row_id: int | None = None

    @property
    def has_params(self) -> bool:
        return bool(self.params)

    @property
    def param_categories(self) -> frozenset:
        return frozenset(pp.category for pp in self.params)

    @property
    def param_names(self) -> tuple[str, ...]:
        return tuple(pp.name for pp in self.params)


def _get(row, key, default=None):
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return default


def analyze(url: str, *, is_js: bool = False, source: str = "",
            host: str = "", row_id: int | None = None) -> Endpoint:
    """Tək URL-i `Endpoint`-ə çevirir (uğursuz normalizasiyada `unknown`)."""
    params = () if is_js else extract_params(url)
    norm = normalize_url(url)
    if norm is None:
        return Endpoint(original=str(url), normalized="", identity="",
                        family="", category=CAT_UNKNOWN, params=params,
                        source=source, host=host, row_id=row_id)
    return Endpoint(
        original=str(url),
        normalized=norm,
        identity=endpoint_identity(url),
        family=endpoint_family(url),
        category=classify_url(url, is_js=is_js, params=params),
        params=params,
        source=source,
        host=host,
        row_id=row_id,
    )


def analyze_row(row, *, host: str = "") -> Endpoint:
    """DB sətrindən (`urls`) `Endpoint` yaradır."""
    url = _get(row, "url", "") or ""
    return analyze(
        url,
        is_js=bool(_get(row, "is_js", 0)),
        source=_get(row, "source", "") or "",
        host=host or (_get(row, "subdomain", "") or ""),
        row_id=_get(row, "id", None),
    )


# --------------------------------------------------------------------------- #
# Dublikat aşkarlanması + endpoint ailələri
# --------------------------------------------------------------------------- #
def dedupe_endpoints(endpoints):
    """`(unikal, dublikatlar)` qaytarır — dublikat = eyni normalizə formalı.

    İLK görünən orijinal saxlanılır (izlənə bilənlik üçün).
    """
    seen: dict[str, Endpoint] = {}
    unique: list[Endpoint] = []
    duplicates: list[tuple[str, str]] = []      # (normalizə, orijinal)
    for ep in endpoints:
        key = ep.normalized or ep.original
        if key in seen:
            duplicates.append((key, ep.original))
            continue
        seen[key] = ep
        unique.append(ep)
    return unique, duplicates


def families(endpoints) -> dict[str, list[str]]:
    """Ailə → orijinal URL-lər xəritəsi (izlənə bilənlik QORUNUR)."""
    out: dict[str, list[str]] = {}
    for ep in endpoints:
        if not ep.family:
            continue
        out.setdefault(ep.family, []).append(ep.original)
    return out


# --------------------------------------------------------------------------- #
# Mühərrik uyğunluğu
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Decision:
    engine: str
    eligible: bool | None          # True | False | None (deferred/unknown)
    status: str                    # eligible | ineligible | deferred | unknown
    reason: str
    evidence: str = ""


#: Uyğunluq halları (Faza 1, §3.2 — 4 hallı).
STATUS_ELIGIBLE = "eligible"
STATUS_INELIGIBLE = "ineligible"
STATUS_DEFERRED = "deferred"
#: Texnologiya profili (fingerprint) MÖVCUD DEYİL və ya NATAMAMdır.
#: Bu, `ineligible` DEYİL — mühərrik HƏLƏ DƏ tətbiq oluna bilər → test edilir.
STATUS_UNKNOWN = "unknown"


#: Texnologiya (fingerprint) ÖN ŞƏRTİ olan mühərriklər. Fingerprint məlumatı
#: yoxdursa/natamamdırsa, bu mühərriklər üçün `unknown` qaytarılır — onları
#: `ineligible` etmək naməlumluq üzündən testi SUSTURMAQ olardı (qadağandır).
TEMPLATE_TECHS = frozenset({
    "php", "wordpress", "drupal", "joomla", "express", "nodejs", "django",
    "flask", "jinja2", "twig", "rails", "laravel", "thymeleaf", "spring",
    "aspnet", "mako", "velocity", "freemarker", "handlebars", "ejs",
})
AUTH_TECHS = frozenset({
    "jwt", "oauth", "oidc", "auth0", "keycloak", "okta", "express", "nodejs",
    "php", "django", "flask", "spring", "rails", "laravel", "aspnet",
})
LIBRARY_TECHS = frozenset({
    "nodejs", "express", "react", "vue", "angular", "jquery", "bootstrap",
    "ember", "svelte", "nextjs", "nuxt", "webpack",
})

FINGERPRINT_REQUIRES = {
    "ssti": TEMPLATE_TECHS,
    "jwt": AUTH_TECHS,
    "library_cve": LIBRARY_TECHS,
}
FINGERPRINT_GATED = tuple(FINGERPRINT_REQUIRES)


@dataclass(frozen=True)
class Fingerprint:
    """Tətbiq texnologiya profili (təsnifat/uyğunluq üçün).

    `complete=False` → profil NATAMAMdır (məsələn yalnız `nginx` bilinir, lakin
    backend texnologiyası hələ məlum deyil). Bu halda texnologiya-şərtli
    mühərriklər `unknown` qaytarır → test EDİLİR (atılmır).
    `complete=True` → profil bütövdür; texnologiya açıq şəkildə müəyyən
    mühərriki inkar edirsə, `ineligible` (səbəblə) qaytarıla bilər.
    """

    technologies: frozenset = frozenset()
    complete: bool = False
    source: str = ""

    @classmethod
    def from_iterable(cls, techs, *, complete: bool = True,
                      source: str = "") -> "Fingerprint":
        items = frozenset(
            str(t).strip().lower() for t in (techs or ()) if str(t).strip())
        return cls(items, bool(complete), source)


def compute_eligibility(ep: Endpoint, engine: str, *,
                        fingerprint: "Fingerprint | None" = None) -> Decision:
    """4-hallı uyğunluq: `eligible | ineligible | deferred | unknown`.

    `fingerprint=None` → yalnız URL-nümunəsi üzrə qiymətləndirmə (geriyə
    uyğun `evaluate()` davranışı — dəyişmir).

    `fingerprint` verildikdə texnologiya-şərtli mühərriklər üçün:
      * profil NATAMAMdırsa → `unknown` (MAY still apply → test edilir);
      * profil bütövdürsə və tələb olunan texnologiyanı ehtiva etmirsə →
        `ineligible` (açıq səbəblə);
      * profil tələbi ödəyirsə → əsas (`evaluate`) qərarı qalır.
    URL-nümunəsi özü qəti şəkildə istisna edirsə (statik resurs), həmişə
    `ineligible` qalır — fingerprint bu qərarı YUMŞALTMAZ.
    """
    base = evaluate(ep, engine)
    if fingerprint is None or engine not in FINGERPRINT_REQUIRES:
        return base
    if base.status == STATUS_INELIGIBLE:
        return base                     # URL özü qəti istisna edir
    need = FINGERPRINT_REQUIRES[engine]
    if not fingerprint.complete:
        return Decision(
            engine, None, STATUS_UNKNOWN,
            f"UNKNOWN: texnologiya profili natamamdır — {engine.upper()} "
            "hələ də tətbiq oluna bilər (test edilir)", ep.original)
    techs = {str(t).lower() for t in fingerprint.technologies}
    if techs & need:
        return base
    return Decision(
        engine, False, STATUS_INELIGIBLE,
        f"SKIPPED: texnologiya profili {engine.upper()} üçün tələb olunan "
        f"texnologiyanı ehtiva etmir ({','.join(sorted(need))})", ep.original)


#: Dinamik injeksiya testi aparan mühərriklər. `param` BURADA DEYİL: o,
#: injeksiya testi deyil, parametr KƏŞFİ mühərrikidir (aşağıdakı `param`
#: qaydasına bax).
INJECT_ENGINES = ("sqli", "xss", "ssti", "ssrf")


def _static_blocked(ep: Endpoint) -> bool:
    return ep.category in STATIC_CATEGORIES or ep.category == CAT_JS


def evaluate(ep: Endpoint, engine: str) -> Decision:
    """Tək endpoint üçün mühərrik uyğunluğu (AÇIQLANAN səbəblə)."""
    if engine == "param":
        # Parametr KƏŞFİ (param_enum): statik resurslar mənasızdır, lakin
        # parametrsiz dinamik endpoint MƏHZ hədəfdir (gizli parametr axtarışı
        # belə endpoint-lər üzərində aparılır) → burada `deferred` etmək
        # kəşfi boğardı. Ona görə yalnız statik resurslar istisna olunur.
        if _static_blocked(ep):
            return Decision(
                engine, False, "ineligible",
                f"SKIPPED: statik resurs ({ep.category}) — "
                "parametr kəşfi üçün mənasız", ep.original)
        return Decision(
            engine, True, "eligible",
            "ELIGIBLE: parametr kəşfi üçün uyğun endpoint", ep.original)

    if engine in INJECT_ENGINES:
        if _static_blocked(ep):
            return Decision(
                engine, False, "ineligible",
                f"SKIPPED: statik resurs ({ep.category}) — "
                f"{engine.upper()} mühərriki üçün uyğun deyil", ep.original)
        if not ep.params:
            return Decision(
                engine, None, "deferred",
                f"DEFERRED: parametr yoxdur — {engine.upper()} namizədliyi "
                f"təsdiqlənmədi", ep.original)
        cats = ep.param_categories
        if engine == "ssrf":
            if cats & {CAT_REDIRECT, CAT_FILE}:
                return Decision(
                    engine, True, "eligible",
                    "ELIGIBLE: yönləndirmə/fayl parametri — SSRF namizədi",
                    ep.original)
            return Decision(
                engine, None, "deferred",
                "DEFERRED: SSRF-yə meyilli parametr aşkarlanmadı", ep.original)
        if engine == "ssti":
            if (cats & {CAT_SEARCHP, CAT_UNKNOWN_P}
                    or ep.category in (CAT_DYNAMIC, CAT_SEARCH, CAT_HTML)):
                return Decision(
                    engine, True, "eligible",
                    "ELIGIBLE: istifadəçi girişi olan dinamik endpoint",
                    ep.original)
            return Decision(
                engine, None, "deferred",
                "DEFERRED: SSTI üçün siqnal zəifdir", ep.original)
        return Decision(
            engine, True, "eligible",
            f"ELIGIBLE: dinamik endpoint, parametr kateqoriyaları: "
            f"{','.join(sorted(cats))}", ep.original)

    if engine in ("js", "library_cve"):
        if ep.category == CAT_JS:
            return Decision(engine, True, "eligible",
                            "ELIGIBLE: JavaScript faylı", ep.original)
        return Decision(engine, False, "ineligible",
                        f"SKIPPED: {ep.category} — JS analizi üçün deyil",
                        ep.original)

    if engine == "api":
        if ep.category == CAT_API:
            return Decision(engine, True, "eligible",
                            "ELIGIBLE: API marşrutu", ep.original)
        return Decision(engine, False, "ineligible",
                        f"SKIPPED: {ep.category} — API mühərriki üçün deyil",
                        ep.original)

    if engine == "content":
        if _static_blocked(ep):
            return Decision(engine, False, "ineligible",
                            f"SKIPPED: statik resurs ({ep.category})",
                            ep.original)
        return Decision(engine, True, "eligible",
                        "ELIGIBLE: kontent kəşfi üçün uyğun yol", ep.original)

    if engine == "jwt":
        if ep.category == CAT_AUTH:
            return Decision(engine, True, "eligible",
                            "ELIGIBLE: autentifikasiya endpointi", ep.original)
        return Decision(engine, None, "deferred",
                        "DEFERRED: autentifikasiya siqnalı yoxdur", ep.original)

    if engine == "sourcecode":
        if _static_blocked(ep):
            return Decision(engine, True, "eligible",
                            "ELIGIBLE: mənbə sızması namizədi", ep.original)
        return Decision(engine, None, "deferred",
                        "DEFERRED: mənbə siqnalı qeyri-müəyyən", ep.original)

    return Decision(engine, None, "deferred",
                    f"DEFERRED: naməlum mühərrik ({engine})", ep.original)


# --------------------------------------------------------------------------- #
# Prioritetləşdirmə
# --------------------------------------------------------------------------- #
def priority(ep: Endpoint) -> int:
    """Endpoint prioriteti (böyük = daha mənalı). Deterministik."""
    if _static_blocked(ep):
        return 0
    score = 0
    if ep.category in (CAT_API, CAT_AUTH):
        score += 3
    elif ep.category in (CAT_DYNAMIC, CAT_SEARCH):
        score += 2
    elif ep.category == CAT_HTML:
        score += 1
    if INTERESTING_RE.search(ep.original):
        score += 3
    cats = ep.param_categories
    if CAT_NUMERIC in cats:
        score += 2
    if cats & {CAT_SEARCHP, CAT_REDIRECT, CAT_FILE}:
        score += 1
    if ep.has_params:
        score += 1
    return max(0, score)


@dataclass
class UrlPlan:
    """Bir mühərrik üçün planlaşdırma nəticəsi (metrikalar üçün)."""

    engine: str | None
    raw: int = 0
    unique: int = 0
    duplicates: int = 0
    families: int = 0
    eligible: int = 0
    excluded: int = 0
    deferred: int = 0
    decisions: dict = field(default_factory=dict)
    excluded_details: list = field(default_factory=list)
    deferred_details: list = field(default_factory=list)

    @property
    def exclusion_reasons(self) -> Counter:
        return Counter(d.reason for d in self.excluded_details)

    def summary(self) -> dict:
        return {
            "engine": self.engine,
            "raw": self.raw,
            "unique": self.unique,
            "duplicates": self.duplicates,
            "families": self.families,
            "eligible": self.eligible,
            "excluded": self.excluded,
            "deferred": self.deferred,
            "exclusion_reasons": dict(self.exclusion_reasons),
        }


# --------------------------------------------------------------------------- #
# Yüksək səviyyəli giriş nöqtəsi
# --------------------------------------------------------------------------- #
@dataclass
class UrlIntake:
    raw: int = 0
    unique: int = 0
    duplicates: int = 0
    families: int = 0
    by_category: Counter = field(default_factory=Counter)

    def summary(self) -> dict:
        return {
            "raw": self.raw,
            "unique": self.unique,
            "duplicates": self.duplicates,
            "families": self.families,
            "by_category": dict(self.by_category),
        }


@dataclass
class DeferredEntry:
    """Təxirə salınmış endpoint qeydi (F-07).

    `signature` — təxirə salınma anındakı DƏLİL imzası (adətən parametr
    adları). Yenidən qiymətləndirmə YALNIZ dəlil dəyişdikdə baş verir →
    dəyişməyən dəlil təkrar emal olunmur (sonsuz dövr qarşısı).
    `rechecks` — bu yazı üçün aparılmış yenidən-qiymətləndirmə sayı (bounded).
    """

    engine: str
    identity: str
    original: str
    reason: str
    signature: tuple = ()
    rechecks: int = 0


def evidence_signature(ep: Endpoint) -> tuple:
    """Endpoint üçün dəlil imzası — parametr adları (deterministik, sıralı)."""
    return tuple(sorted(ep.param_names))


@dataclass(frozen=True)
class Refinement:
    """Cavab metadata-sı əsaslı təsnifat dəqiqləşdirməsinin qeydi (Faza 2).

    `applied=True` — dəqiqləşdirmə TƏTBİQ olundu (uyğunluq dəyişməz).
    `applied=False` — RƏDD olundu (mühərrik uyğunluğunu dəyişəcəkdi) və səbəb
    `reason`-da saxlanılır. Hər iki halda orijinal URL və dəlil qorunur.
    Bir endpoint üçün YALNIZ İLK qeyd saxlanılır → salınım (oscillation) yoxdur.
    """

    identity: str
    original: str
    from_category: str
    to_category: str
    applied: bool
    reason: str
    evidence: str = ""


class UrlIntelligence:
    """URL Intelligence orkestratoru — mühərriklər və Conductor bunu paylaşır."""

    def __init__(self, metrics=None):
        self.metrics = metrics
        self.last_plan: UrlPlan | None = None
        #: F-07: təxirə salınmış (`deferred`) endpoint-lərin reyestri.
        #: Açar: `(engine, endpoint_identity)`. Naməlum endpoint SƏSSİZCƏ
        #: atılmır — kimliyi və səbəbi ilə burada saxlanılır ki, YENİ dəlil
        #: yarandıqda yenidən qiymətləndirilə bilsin.
        self.deferred_registry: dict[tuple[str, str], DeferredEntry] = {}
        #: Faza 2: cavab metadata-sı əsaslı təsnifat dəqiqləşdirmələri.
        #: Açar: TAM normalizə olunmuş URL (sorğu parametrləri DAXİL) — dəlil
        #: müşahidə olunduğu DƏQİQ URL-ə bağlanır, başqa URL-ə ekstrapolyasiya
        #: olunmur. Yalnız İLK dəlil saxlanılır (birtərəfli → salınım yoxdur).
        self.refinements: dict[str, Refinement] = {}
        #: Tətbiq/rədd sayları (uydurma yox — faktiki qərarlar).
        self.refinement_stats: Counter = Counter({"applied": 0, "refused": 0})

    # ------------------------------------------------------------------ intake
    def intake(self, rows) -> UrlIntake:
        """Bütün kəşf olunmuş URL-lər üzrə ümumi metrikaları hesablayır."""
        eps = [analyze_row(r) for r in rows]
        unique, dups = dedupe_endpoints(eps)
        by_cat = Counter(ep.category for ep in unique)
        intake = UrlIntake(
            raw=len(rows),
            unique=len(unique),
            duplicates=len(dups),
            families=len({ep.family for ep in unique if ep.family}),
            by_category=by_cat,
        )
        if self.metrics is not None:
            self.metrics.record_url_intake(intake)
        return intake

    # -------------------------------------------------------------- planning
    def plan_rows(self, rows, *, engine: str | None = None,
                  limit: int | None = None):
        """Sətirləri prioritet sırasına salır, (lazım gələrsə) uyğunluğa süzür.

        Qaytarır: `(seçilmiş_sətirlər, UrlPlan)`. Sətir obyektləri OLDUĞU
        KİMİ qaytarılır — mövcud mühərrik kontraktı dəyişmir.
        """
        pairs = [(self.apply_refinement(analyze_row(r)), r) for r in rows]
        seen: set[str] = set()
        unique: list = []
        dup_count = 0
        for ep, row in pairs:
            key = ep.normalized or ep.original
            if key in seen:
                dup_count += 1
                continue
            seen.add(key)
            unique.append((ep, row))
        unique.sort(key=lambda p: (-priority(p[0]),
                                   p[0].normalized or p[0].original))

        plan = UrlPlan(
            engine=engine,
            raw=len(rows),
            unique=len(unique),
            duplicates=dup_count,
            families=len({ep.family for ep, _ in unique if ep.family}),
        )

        kept: list = []
        for ep, row in unique:
            if engine is None:
                kept.append(row)
                continue
            d = evaluate(ep, engine)
            plan.decisions[ep.normalized or ep.original] = d
            if d.eligible is True:
                plan.eligible += 1
                kept.append(row)
            elif d.eligible is False:
                plan.excluded += 1
                plan.excluded_details.append(d)
            else:
                plan.deferred += 1
                plan.deferred_details.append(d)
                self._note_deferred(d, ep)

        if limit is not None:
            kept = kept[:limit]
        self.last_plan = plan
        if self.metrics is not None and engine is not None:
            self.metrics.record_plan(plan)
        return kept, plan

    # --------------------------------------------------- F-07: yenidən baxış
    def _note_deferred(self, d: Decision, ep: Endpoint) -> None:
        """Təxirə salınmış qərarı reyestrə yazır (kimlik + səbəb + dəlil)."""
        identity = ep.identity or ep.original
        key = (d.engine, identity)
        if key in self.deferred_registry:
            return                      # ilk qeyd saxlanılır (səbəb sabitdir)
        self.deferred_registry[key] = DeferredEntry(
            engine=d.engine, identity=identity, original=ep.original,
            reason=d.reason, signature=evidence_signature(ep))

    def reconsider(self, engine: str, evidence_map: dict | None = None,
                   *, max_rounds: int = 1) -> list[dict]:
        """YENİ dəlil əsasında təxirə salınmış endpoint-ləri yenidən qiymətləndirir.

        `evidence_map`: `{endpoint_identity: cari_dəlil_imzası}` (məsələn
        parametr kəşfinin tapdığı YENİ parametr adları). Yalnız imzası
        DƏYİŞƏN və yenidən-yoxlama büdcəsi (`max_rounds`) qalan yazılar
        baxılır → dəyişməyən dəlil TƏKRAR emal olunmur və sonsuz dövr qurulmur.

        Uyğun hala keçənlər reyestrdən ÇIXARILIR (təkrar yüksəliş yoxdur) və
        səbəblə birlikdə qaytarılır. Qalan hər yazı üçün də yeni dəlil
        imzası saxlanılır (növbəti dəfə yalnız YENİ dəyişiklik tetikleyəcək).
        """
        evidence_map = dict(evidence_map or {})
        promoted: list[dict] = []
        remained = 0
        for key, entry in list(self.deferred_registry.items()):
            if entry.engine != engine:
                continue
            new_sig = evidence_map.get(entry.identity)
            if new_sig is None:
                continue                # bu endpoint üçün yeni dəlil yoxdur
            new_sig = tuple(sorted(new_sig))
            if new_sig == entry.signature:
                continue                # dəlil dəyişməyib → təkrar YOX
            if entry.rechecks >= max_rounds:
                continue                # bounded: sonsuz dövr qarşısı
            entry.rechecks += 1
            entry.signature = new_sig
            ep = self._with_evidence(entry.original, new_sig)
            decision = evaluate(ep, engine)
            if decision.eligible is True:
                promoted.append({
                    "engine": engine, "identity": entry.identity,
                    "reason": decision.reason,
                    "from": entry.reason, "evidence": list(new_sig),
                })
                del self.deferred_registry[key]
            else:
                remained += 1
                entry.reason = decision.reason
        if promoted or remained:
            self._record_reconsider(engine, len(promoted), remained)
        return promoted

    @staticmethod
    def _with_evidence(original: str, param_names: tuple) -> Endpoint:
        """Orijinal URL-i SAXLAYARAQ yeni parametr dəlili ilə endpoint qurur."""
        ep = analyze(original)
        params = tuple(
            Param(name=str(n), value="", category=classify_param(str(n), ""))
            for n in param_names)
        ep.params = params
        return ep

    def _record_reconsider(self, engine: str, promoted: int,
                           remained: int) -> None:
        rec = getattr(self.metrics, "record_reconsider", None)
        if callable(rec):
            rec(engine, promoted=promoted, remained=remained)

    # ------------------------------- Faza 2: cavab metadata-sı ilə dəqiqləşdirmə
    @staticmethod
    def _eligibility_diff(base: Endpoint, candidate: Endpoint) -> list[str]:
        """`candidate` bir mühərrikin uyğunluq qərarını dəyişirsə onları qaytarır.

        Çıxarış BOŞ olarsa — dəyişdirmə uyğunluğa toxunmur (təhlükəsiz).
        """
        changed = []
        for engine in ENGINES:
            if evaluate(base, engine).eligible != evaluate(candidate, engine).eligible:
                changed.append(engine)
        return changed

    def apply_refinement(self, ep: Endpoint) -> Endpoint:
        """Qeyd olunmuş dəqiqləşdirməni endpoint-ə TƏTBİQ edirsə tətbiq edir.

        Yalnız DƏQİQ (normalizə olunmuş) URL üzrə uyğunluğu DƏYİŞMƏYƏN
        dəqiqləşdirmə tətbiq olunur — bu, ikinci qoruma qatıdır.
        Orijinal URL və digər sahələr TOXUNULMAZ qalır (yalnız `category`).
        """
        key = ep.normalized or ep.original
        ref = self.refinements.get(key)
        if ref is None or not ref.applied or ref.to_category == ep.category:
            return ep
        candidate = replace(ep, category=ref.to_category)
        if self._eligibility_diff(ep, candidate):
            return ep                     # təhlükəsizlik: uyğunluq dəyişir → tətbiq yox
        return candidate

    def refine_from_response(self, url: str, *, content_type: str | None = None,
                             source: str = "",
                             params: tuple[Param, ...] | None = None
                             ) -> Refinement | None:
        """Cavab metadata-sı (Content-Type) ilə təsnifatı DƏQİQLƏŞDİRİR.

        Nəzarət qaydaları (bax: modul başlığı):
          * orijinal URL saxlanılır (yalnız `category` dəqiqləşir);
          * yeni dəlil (content-type + mənbə) qeyd olunur;
          * BİRTƏRƏFLİ — endpoint üçün ilk dəlil qalib gəlir, təkrarlar no-op;
          * mühərrik uyğunluğunu DƏYİŞMƏZ → uyğunluq kənardan keçilmir.
        Uyğunluğu dəyişəcək dəqiqləşdirmələr RƏDD olunur (səbəblə qeyd olunur).

        Tətbiq olunan/rədd edilən qeydi qaytarır; dəyişiklik yoxdursa `None`.
        """
        if not content_type:
            return None
        base = analyze(url)
        key = base.normalized or base.original
        if not key:
            return None
        existing = self.refinements.get(key)
        if existing is not None:
            return existing               # birtərəfli: ilk dəlil qalib gəlir
        if params is None:
            params = base.params
        observed = classify_url(url, content_type=content_type, params=params)
        if observed == base.category:
            return None                   # dəyişiklik yox → qeyd lazım deyil
        evidence = f"content-type={content_type.strip()}"
        if source:
            evidence = f"{evidence} (mənbə: {source})"
        changed = self._eligibility_diff(base, replace(base, category=observed))
        if changed:
            ref = Refinement(
                identity=base.identity, original=base.original,
                from_category=base.category, to_category=observed,
                applied=False, evidence=evidence,
                reason=("REFUSED: cavab metadata-sı mühərrik uyğunluğunu "
                        f"dəyişərdi ({', '.join(changed)}) — evasion/əhatə "
                        "genişlənməsinin qarşısı alındı"))
            self.refinement_stats["refused"] += 1
        else:
            ref = Refinement(
                identity=base.identity, original=base.original,
                from_category=base.category, to_category=observed,
                applied=True, evidence=evidence,
                reason=(f"APPLIED: {base.category} → {observed} "
                        "(uyğunluq dəyişməz)"))
            self.refinement_stats["applied"] += 1
        self.refinements[key] = ref
        self._record_refinement(applied=ref.applied)
        return ref

    def refinements_summary(self) -> dict:
        """Dəqiqləşdirmə qərarlarının izlənə bilən xülasəsi (deterministik)."""
        entries = [asdict(r) for r in self.refinements.values()]
        return {
            "applied": self.refinement_stats["applied"],
            "refused": self.refinement_stats["refused"],
            "entries": entries,
        }

    def _record_refinement(self, *, applied: bool) -> None:
        rec = getattr(self.metrics, "record_refinement", None)
        if callable(rec):
            rec(applied=applied)


def get_url_intelligence(ctx) -> UrlIntelligence:
    """`ctx` üzərində tək (lazy) `UrlIntelligence` nüsxəsi."""
    intel = getattr(ctx, "_urlintel", None)
    if intel is None:
        intel = UrlIntelligence(metrics=getattr(ctx, "orchestration", None))
        try:
            ctx._urlintel = intel
        except AttributeError:      # pragma: no cover - ctx slots olsa
            pass
    return intel


#: Uyğunluq süzgəci aktiv olduqda SQL `LIMIT`-inin genişləndirmə faktoru:
#: süzgəcdən sonra kifayət qədər hədəf qalması üçün əvvəlcə daha çox sətir oxunur.
FETCH_FACTOR = 6


def fetch_limit(limit: int | None, default: int, *, filtering: bool) -> int:
    base = int(limit or default)
    return max(base * FETCH_FACTOR, 100) if filtering else base


def record_intake(ctx) -> UrlIntake | None:
    """Cari skanın URL intake metrikalarını hesablayıb qeyd edir."""
    from . import db

    rows = db.get_db().execute(
        "SELECT u.id, u.url, u.is_js, u.source, h.subdomain FROM urls u "
        "JOIN hosts h ON h.id=u.host_id WHERE h.scan_id=?",
        (db.effective_scan_id(getattr(ctx, "scan_id", None)),)).fetchall()
    return get_url_intelligence(ctx).intake(rows)
