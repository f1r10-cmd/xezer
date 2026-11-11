"""Guardian eskalasiya nərdivanı — Faza 2.5.

Guardian əyləc pedalı DEYİL; ardıcıl bloklara görə **addım-addım** reaksiya verir:

| Səviyyə | Hərəkət                | Nə edir                                              |
|--------:|------------------------|------------------------------------------------------|
| 1       | `respect_retry_after`  | 429 + Retry-After → hörmət edir (ilk çarə)            |
| 2       | `rotate_identity`      | israrlı 429/403 → UA/başlıq/proxy rotasiyası          |
| 3       | `waf_adapt_backoff`    | WAF-şüurlu payload uyğunlaşdırması + cooldown backoff |
| 4       | `stealth_mode`         | rate düşürülür, pacing ON, tək identikliklə "isınma"  |
| 5       | `defer_intrusive`      | SQLi/PoC kimi intrusiv fazalar görünürlük düzələnə qədər TƏXİRƏ SALINIR |

`on_success()` nərdivanı bir pillə AŞAĞI salır (histerezis) → tək uğur
bütün vəziyyəti silmir, lakin israrlı uğur tam normal rejimə qaytarır.
"""
from __future__ import annotations

from dataclasses import dataclass, field

#: Səviyyə (1-indeksli) → (hərəkət adı, rate faktoru, intrusiv təxirə).
LEVELS: dict[int, tuple[str, float, bool]] = {
    1: ("respect_retry_after", 1.0, False),
    2: ("rotate_identity", 1.0, False),
    3: ("waf_adapt_backoff", 0.6, False),
    4: ("stealth_mode", 0.25, False),
    5: ("defer_intrusive", 0.25, True),
}
MAX_LEVEL = max(LEVELS)


@dataclass(frozen=True)
class LadderDecision:
    """Nərdivanın verdiyi qərar (audit oluna bilən)."""

    level: int
    action: str
    rate_factor: float
    defer_intrusive: bool
    reason: str
    waf: str = ""

    def to_dict(self) -> dict:
        return {
            "level": self.level, "action": self.action,
            "rate_factor": self.rate_factor,
            "defer_intrusive": self.defer_intrusive,
            "reason": self.reason, "waf": self.waf,
        }


@dataclass
class EscalationLadder:
    """Ardıcıl bloklar boyu eskalasiya edən və uğurda enən vəziyyət maşını."""

    max_level: int = MAX_LEVEL
    blocks: int = field(default=0, init=False)
    level: int = field(default=0, init=False)
    history: list = field(default_factory=list, init=False)

    @property
    def blocked(self) -> bool:
        return self.level > 0

    @property
    def defer_intrusive(self) -> bool:
        return LEVELS.get(self.level, ("", 1.0, False))[2]

    @property
    def rate_factor(self) -> float:
        return LEVELS.get(self.level, ("", 1.0, False))[1]

    def allows_intrusive(self) -> bool:
        """İntrusiv fazalar (SQLi/PoC) hazırda icazəlidirmi?"""
        return not self.defer_intrusive

    # ------------------------------------------------------------------ hadisə
    def on_block(self, status: int, *, retry_after: float = 0.0,
                 waf: str = "") -> LadderDecision:
        """Blok hadisəsini qeyd edir və yeni qərarı qaytarır."""
        self.blocks += 1
        # Səviyyə 1 yalnız ilk 429 + Retry-After üçün (ilk çarə hörmət).
        if self.blocks == 1 and status == 429 and retry_after > 0:
            level = 1
        else:
            level = min(self.max_level, self.blocks + 1)
        self.level = level
        action, rate_factor, defer = LEVELS[level]
        reason = (f"{status} bloku (#{self.blocks})" +
                  (f", Retry-After={retry_after:.0f}s" if retry_after > 0 else "") +
                  (f", WAF={waf}" if waf else ""))
        dec = LadderDecision(level, action, rate_factor, defer, reason, waf)
        self.history.append(dec.to_dict())
        return dec

    def on_success(self) -> LadderDecision:
        """Uğurlu cavab → bir pillə aşağı (histerezis ilə)."""
        if self.blocks > 0:
            self.blocks -= 1
        self.level = 0 if self.blocks == 0 else min(self.max_level, self.blocks + 1)
        action, rate_factor, defer = LEVELS.get(
            self.level, ("normal", 1.0, False))
        dec = LadderDecision(self.level, action, rate_factor, defer,
                             "uğurlu cavab → nərdivan aşağı")
        self.history.append(dec.to_dict())
        return dec

    def reset(self) -> None:
        self.blocks = 0
        self.level = 0

    def state(self) -> dict:
        return {
            "level": self.level,
            "blocks": self.blocks,
            "action": LEVELS.get(self.level, ("normal", 1.0, False))[0],
            "rate_factor": self.rate_factor,
            "defer_intrusive": self.defer_intrusive,
        }
