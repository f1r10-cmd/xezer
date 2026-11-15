"""Təhlükəsiz cavab təsnifatı (Faza 1, §3.3).

MƏQSƏD: cavab kodlarını (403/404/405/500 və s.) "ölü yol" kimi ATMAQ ƏVƏZİNƏ
test üçün ƏHƏMİYYƏTLİ siqnal kimi QORUMAQ. Bu modul HTTP trafiki YARATMIR,
rate-limit tətbiq etmir və Guardian-ı ƏVƏZ ETMİR:
  * Guardian → blok/rate-limit/cooldown (nə vaxt sorğu GÖNDƏRMƏK olar);
  * `ResponseClassifier` → test ƏHƏMİYYƏTLİLİYİ (bu cavab nə DEMƏK olar).

Prinsiplər:
  * 403 → auth tələb oluna bilər → bypass/auth-kontekst testi üçün SAXLANILIR.
  * 404 → soft-404 ola bilər → AŞAĞI prioritetlə SAXLANILIR (atılmır).
  * 405 → metod uyğunsuzluğu → DİGƏR metodlar sınanır (siqnal, son deyil).
  * 500 → injeksiya oluna bilən parametr → ƏLAVƏ test üçün SAXLANILIR.
  * `HEAD` cavabı `GET` cavabına BƏRABƏR SAYILMIR (heç vaxt).
  * Hər təsnifat `reason` və `evidence_refs` qeyd edir.
  * `Content-Type` hədəf tərəfindən idarə olunur → test qabiliyyətini
    DƏYİŞMİR (yalnız qeyd olunur) — evasion qapısı açılmır.
"""
from __future__ import annotations

from dataclasses import dataclass

# --- Təsnifat növləri ------------------------------------------------------- #
CLASS_SUCCESS = "success"
CLASS_AUTH_REQUIRED = "auth_required"
CLASS_SOFT_NOT_FOUND = "soft_not_found"
CLASS_METHOD_MISMATCH = "method_mismatch"
CLASS_SERVER_ERROR = "server_error"
CLASS_RATE_LIMITED = "rate_limited"
CLASS_FORBIDDEN = "forbidden"
CLASS_CLIENT_ERROR = "client_error"
CLASS_REDIRECT = "redirect"
CLASS_UNKNOWN = "unknown"

#: 405 halında sınanacaq alternativ metodlar (`HEAD` daxil — ayrıca yoxlanılır).
DEFAULT_METHODS = ("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD")

#: Cavab kodu → prioritet çarpanı (böyük = daha çox araşdırılmalı).
#: 404 BİLƏRLƏKDƏN aşağıdır, lakin SIFIR DEYİL (soft-404 → atılmır).
_PRIORITY = {
    CLASS_SERVER_ERROR: 4,
    CLASS_AUTH_REQUIRED: 3,
    CLASS_METHOD_MISMATCH: 3,
    CLASS_SUCCESS: 2,
    CLASS_REDIRECT: 2,
    CLASS_RATE_LIMITED: 1,
    CLASS_CLIENT_ERROR: 1,
    CLASS_SOFT_NOT_FOUND: 1,
    CLASS_UNKNOWN: 1,
}


def _as_tuple(value) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,) if value else ()
    if isinstance(value, dict):
        return tuple(f"{k}={v}" for k, v in value.items())
    try:
        return tuple(str(x) for x in value)
    except TypeError:
        return (str(value),)


@dataclass(frozen=True)
class ResponseClass:
    """Bir cavabın test-əhəmiyyətli təsnifatı."""

    status: int
    method: str
    kind: str
    testable: bool                     # bu cavab ƏLAVƏ testə dəyərmi?
    priority: int                      # böyük = daha çox araşdırılmalı
    action: str                        # tövsiyə olunan növbəti addım
    reason: str
    evidence_refs: tuple = ()
    suggests_bypass: bool = False      # auth/blok keçmə testi işə düşsünmü
    try_methods: tuple = ()            # 405/sonrası sınanacaq metodlar
    head_get_equivalent: bool = False  # HƏMİŞƏ `False` (HEAD ≠ GET)
    content_type: str = ""
    status_change: bool = False        # əvvəlki müşahidəyə nisbətən dəyişdi

    def as_dict(self) -> dict:
        return {
            "status": self.status,
            "method": self.method,
            "kind": self.kind,
            "testable": self.testable,
            "priority": self.priority,
            "action": self.action,
            "reason": self.reason,
            "evidence_refs": list(self.evidence_refs),
            "suggests_bypass": self.suggests_bypass,
            "try_methods": list(self.try_methods),
            "head_get_equivalent": self.head_get_equivalent,
            "content_type": self.content_type,
            "status_change": self.status_change,
        }


def _allowed_methods(response_structure) -> tuple:
    """`allow` başlığı və ya struktur daxilində verilmiş metod siyahısı."""
    if isinstance(response_structure, dict):
        allow = response_structure.get("allow") or response_structure.get(
            "allowed_methods")
        if allow:
            return tuple(m.strip().upper() for m in _split_allowed(allow))
    return ()


def _split_allowed(allow) -> list[str]:
    if isinstance(allow, str):
        return [m for m in allow.replace(",", " ").split() if m]
    return list(allow)


def _prior_status(previous_observations) -> int | None:
    """Əvvəlki müşahidələrdən ən son status kodunu çıxarır (varsa)."""
    if previous_observations is None:
        return None
    if isinstance(previous_observations, dict):
        value = previous_observations.get("status")
        return int(value) if value is not None else None
    if isinstance(previous_observations, (list, tuple)):
        for item in reversed(previous_observations):
            if isinstance(item, dict) and item.get("status") is not None:
                return int(item["status"])
            if isinstance(item, int):
                return item
    if isinstance(previous_observations, int):
        return previous_observations
    return None


class ResponseClassifier:
    """Cavabı test-əhəmiyyətli sinfə çevirir (şəbəkəsiz, deterministik)."""

    def classify(self, status, method="GET", auth_context=None,
                 content_type=None, redirect_behavior=None,
                 response_structure=None, endpoint_role=None,
                 previous_observations=None) -> ResponseClass:
        try:
            code = int(status)
        except (TypeError, ValueError):
            code = 0
        m = (method or "GET").upper()
        ct = str(content_type or "")
        role = str(endpoint_role or "")

        evidence = [f"status={code}", f"method={m}"]
        if ct:
            evidence.append(f"content_type={ct}")
        if auth_context not in (None, ""):
            evidence.append(f"auth_context={auth_context}")
        if role:
            evidence.append(f"endpoint_role={role}")
        if redirect_behavior not in (None, ""):
            evidence.append(f"redirect_behavior={redirect_behavior}")

        prev = _prior_status(previous_observations)
        changed = prev is not None and prev != code

        # HEAD heç vaxt GET-ə ekvivalent sayılmır (ayrıca siqnal).
        head_note = ""
        if m == "HEAD":
            head_note = (" HEAD cavabı GET cavabına BƏRABƏR SAYILMIR — "
                         "ayrıca yoxlanmalıdır.")

        cls = self._base(
            code=code, m=m, ct=ct, role=role, evidence=evidence,
            head_note=head_note, response_structure=response_structure,
            changed=changed, prev=prev)
        return cls

    # ------------------------------------------------------------------ #
    def compare_head_get(self, head: ResponseClass,
                         get: ResponseClass) -> ResponseClass:
        """HEAD ilə GET nəticələrini MÜQAYİSƏ edir (ekvivalentlik İDDİA ETMİR).

        Qaytarılan təsnifat `head_get_equivalent=False` olur; fərq varsa
        bunu `reason`-da qeyd edir.
        """
        same = (head.status == get.status
                and head.content_type == get.content_type)
        reason = ("HEAD ≠ GET: cavablar fərqlidir (status/Content-Type) — "
                  "eynilik fərz EDİLMİR." if not same else
                  "HEAD və GET status/Content-Type üzrə üst-üstə düşür, lakin "
                  "ekvivalentlik fərz EDİLMİR — gövdə ayrıca yoxlanılır.")
        return ResponseClass(
            status=get.status, method="HEAD/GET",
            kind=get.kind if same else CLASS_METHOD_MISMATCH,
            testable=True,
            priority=max(head.priority, get.priority),
            action="HEAD və GET-i ayrıca test et",
            reason=reason,
            evidence_refs=head.evidence_refs + get.evidence_refs,
            head_get_equivalent=False,
            status_change=not same,
        )

    # ------------------------------------------------------------------ #
    def _base(self, *, code, m, ct, role, evidence, head_note,
              response_structure, changed, prev) -> ResponseClass:
        def build(kind, testable, action, reason, *, suggests_bypass=False,
                  try_methods=()):
            base = _PRIORITY.get(kind, 1)
            if changed:
                base += 1
                reason = (f"{reason} Status dəyişdi ({prev}→{code}) — yenidən "
                          "test üçün ƏHƏMİYYƏTLİDİR.")
            if role:
                reason = f"{reason} (endpoint_role={role})"
            return ResponseClass(
                status=code, method=m, kind=kind, testable=testable,
                priority=base, action=action, reason=reason + head_note,
                evidence_refs=tuple(evidence), suggests_bypass=suggests_bypass,
                try_methods=tuple(try_methods),
                head_get_equivalent=False, content_type=ct,
                status_change=changed,
            )

        if code == 403:
            return build(
                CLASS_AUTH_REQUIRED, True,
                "auth-kontekst / bypass matrisini işə sal",
                "403 → autentifikasiya tələb oluna bilər; bu, ÖLÜ YOL DEYİL — "
                "auth-kontekst və bypass testləri üçün SAXLANILIR.",
                suggests_bypass=True,
                try_methods=("OPTIONS", "HEAD", "POST"))

        if code == 401:
            return build(
                CLASS_AUTH_REQUIRED, True,
                "auth konteksti ilə təkrar sına",
                "401 → autentifikasiya tələb olunur; auth-kontekst testi üçün "
                "SAXLANILIR.", suggests_bypass=True)

        if code == 404:
            return build(
                CLASS_SOFT_NOT_FOUND, True,
                "soft-404 imzasını yoxla, AŞAĞI prioritetlə davam et",
                "404 → endpoint mövcud olmaya BİLƏR, lakin soft-404 mümkündür; "
                "ATILMIR, aşağı prioritetlə SAXLANILIR.")

        if code == 405:
            allowed = _allowed_methods(response_structure)
            try_methods = allowed or tuple(
                x for x in DEFAULT_METHODS if x != m)
            return build(
                CLASS_METHOD_MISMATCH, True,
                "digər HTTP metodlarını sına",
                f"405 → metod uyğunsuzluğu (bu metod qəbul olunmur); bu SİQNALDIR, "
                f"son deyil — {','.join(try_methods)} sınanır.",
                try_methods=try_methods)

        if code == 429:
            return build(
                CLASS_RATE_LIMITED, False,
                "HttpPolicy/Guardian-ın cooldown + Retry-After mexanizminə burax",
                "429 → rate-limit (blok), test nəticəsi DEYİL — Guardian "
                "cooldown/Retry-After idarə edir; bu cavab testi SUSTURMUR, "
                "yalnız təxirə salır.")

        if code and 500 <= code < 600:
            return build(
                CLASS_SERVER_ERROR, True,
                "parametr injeksiyası/davranış testini dərinləşdir",
                f"{code} → server xətası; injeksiya oluna bilən parametrə işarə "
                "OLA BİLƏR — ƏLAVƏ test üçün SAXLANILIR (aşağı tezliklə).")

        if code == 0:
            return build(
                CLASS_UNKNOWN, True,
                "cavab əlçatmaz — yenidən sına",
                "status yoxdur (timeout/bağlantı xətası) → naməlum; test "
                "SUSTURULMUR, yenidən sınanır.")

        if 200 <= code < 300:
            return build(
                CLASS_SUCCESS, True,
                "gövdə üzərində dərin test apar",
                "2xx → uğurlu cavab; gövdə/parametr testləri üçün uyğundur.")

        if 300 <= code < 400:
            return build(
                CLASS_REDIRECT, True,
                "yönləndirməni izləyərkən scope qapısını qoru",
                f"{code} → yönləndirmə; hədəf dəyişə bilər — scope yoxlaması "
                "hər addımda tətbiq olunur.")

        if 400 <= code < 500:
            return build(
                CLASS_CLIENT_ERROR, True,
                "sərhəd/validasiya davranışını yoxla",
                f"{code} → müştəri xətası; giriş validasiyası davranışı üçün "
                "SAXLANILIR.")

        return build(
            CLASS_UNKNOWN, True, "əlavə dəlil topla",
            f"naməlum status ({code}) → atılmır, əlavə dəlillə yenidən "
            "qiymətləndirilir.")
