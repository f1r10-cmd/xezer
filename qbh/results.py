"""Mühərrik və mərhələ nəticə kontraktları.

Bütün mühərriklər `EngineResult` qaytarır; Conductor hər çağırışı
`StageResult` ilə əhatə edir. Beləliklə uğur/uğursuzluq HƏMİŞƏ açıq
şəkildə raportlanır — heç bir xəta səssizcə udulmur və heç vaxt
`None` aşağı axına ötürülmür.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class EngineResult:
    """Bir mühərrikin nəticəsi."""

    stage: str
    ok: bool = True
    skipped: bool = False
    findings: int = 0
    hosts: int = 0
    urls: int = 0
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def warn(self, msg: str) -> None:
        self.warnings.append(str(msg))

    def fail(self, msg: str) -> None:
        self.errors.append(str(msg))
        self.ok = False

    def skip(self, reason: str) -> "EngineResult":
        self.skipped = True
        self.warn(reason)
        return self


@dataclass
class StageResult:
    """Conductor-un hər mərhələ üçün strukturlaşdırılmış xülasəsi."""

    stage: str
    status: str                  # ok | failed | skipped | cancelled
    started_at: str
    completed_at: str = ""
    duration: float = 0.0
    target: str = ""
    findings_count: int = 0
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "stage_name": self.stage,
            "target": self.target,
            "status": self.status,
            "started_at": self.started_at,
            "completed_at": self.completed_at,
            "duration": self.duration,
            "findings_count": self.findings_count,
            "errors": list(self.errors),
            "warnings": list(self.warnings),
        }
