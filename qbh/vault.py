"""Faza 3.2 — şifrəli secret vault (Fernet).

JS təhlilində tapılan XAM secret-lər (credential-lar) bazada DÜZ MƏTN kimi
saxlanılmamalıdır. Bu modul onları `cryptography.fernet.Fernet` ilə
şifrələyir; açar ya `vault.key_file`-dan, ya da `QBH_VAULT_KEY` mühit
dəyişənindən oxunur.

**Dürüstlük / fail-closed:**
  * Açar yoxdursa vault `available=False` olur — bu halda HEÇ VAXT düz mətn
    (və ya şifrəli mətn) yazılmır; JS analizi əvvəlki kimi yalnız maskalanmış
    önizləmə saxlayır.
  * `cryptography` quraşdırılmayıbsa modul ÖZÜNÜ əlçatmaz elan edir və import
    xətası atmır.
  * Şifrəli mətn hesabatlara/loglara HEÇ VAXT düşmür (bax: `report/generator`).

Açar materialı iki formada qəbul olunur:
  1. Etibarlı Fernet açarı (44 simvol url-safe base64).
  2. İxtiyari parol → SHA-256 ilə deterministik 32 baytlıq açar törədilir.
"""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from typing import Any

#: Açar faylı göstərilmədikdə oxunacaq mühit dəyişəni.
ENV_VAR = "QBH_VAULT_KEY"


def _fernet_class():
    """`Fernet` sinfini qaytarır; paket yoxdursa `None` (uydurma yoxdur)."""
    try:
        from cryptography.fernet import Fernet
    except Exception:  # noqa: BLE001 - paket çatışmırsa dürüst fallback
        return None
    return Fernet


def normalize_key(material: str) -> bytes | None:
    """Açar materialını etibarlı Fernet açarına (bytes) çevirir.

    Əvvəlcə materialın özünü Fernet açarı kimi sınayır; alınmasa SHA-256 ilə
    deterministik açar törədir. Boş material → `None`.
    """
    raw = (material or "").strip().encode()
    if not raw:
        return None
    Fernet = _fernet_class()
    if Fernet is not None:
        try:
            Fernet(raw)
            return raw
        except Exception:  # noqa: BLE001 - Fernet açarı deyil → törədək
            pass
    return base64.urlsafe_b64encode(hashlib.sha256(raw).digest())


@dataclass
class SecretVault:
    """Şifrələmə/şifrə-açma qabiliyyətli vault.

    `available` yalnız açar yüklənib və Fernet qurula bildikdə `True` olur.
    """

    key_file: str = ""
    enabled: bool = True
    env_var: str = ENV_VAR
    _cipher: Any = field(default=None, init=False, repr=False)
    _reason: str = field(default="açar yüklənməyib", init=False)

    def __post_init__(self) -> None:
        self._init_cipher()

    # ------------------------------------------------------------------ açar
    def _key_material(self) -> str:
        """Açar faylı (varsa) və ya mühit dəyişənindən material oxuyur."""
        if self.key_file:
            try:
                with open(self.key_file, "r", encoding="utf-8") as fh:
                    return fh.read().strip()
            except OSError as exc:
                self._reason = f"açar faylı oxunmadı: {exc}"
                return ""
        return (os.environ.get(self.env_var) or "").strip()

    def _init_cipher(self) -> None:
        if not self.enabled:
            self._reason = "vault deaktivdir"
            return
        Fernet = _fernet_class()
        if Fernet is None:
            self._reason = "cryptography paketi quraşdırılmayıb"
            return
        material = self._key_material()
        if not material:
            self._reason = (f"açar tapılmadı (vault.key_file / {self.env_var}) — "
                            f"secret-lər yalnız maskalanmış saxlanılacaq")
            return
        key = normalize_key(material)
        if not key:
            self._reason = "açar materialı etibarsızdır"
            return
        try:
            self._cipher = Fernet(key)
            self._reason = ""
        except Exception as exc:  # noqa: BLE001
            self._cipher = None
            self._reason = f"açar qurula bilmədi: {exc}"

    # -------------------------------------------------------------- xassələr
    @property
    def available(self) -> bool:
        return self._cipher is not None

    @property
    def reason(self) -> str:
        return self._reason

    # --------------------------------------------------------------- əməliyyat
    def encrypt(self, plaintext: str | None) -> str | None:
        """Mətni şifrələyir. Vault əlçatan deyilsə `None` (uydurma yoxdur)."""
        if not self.available or plaintext is None:
            return None
        return self._cipher.encrypt(str(plaintext).encode()).decode()

    def decrypt(self, token: str | None) -> str | None:
        """Şifrəli mətni açar. Uğursuz/əlçatmaz olduqda `None`."""
        if not self.available or not token:
            return None
        try:
            return self._cipher.decrypt(str(token).encode()).decode()
        except Exception:  # noqa: BLE001 - yanlış açar/dəyişdirilmiş token
            return None

    def summary(self) -> dict:
        """Hesabat/audit üçün dürüst vəziyyət (açar AÇIQLANMIR)."""
        return {"available": self.available, "enabled": self.enabled,
                "reason": self._reason}

    # ------------------------------------------------------------------ factory
    @classmethod
    def from_config(cls, cfg) -> "SecretVault":
        """`Config.vault` bölməsindən vault qurur."""
        vcfg = getattr(cfg, "vault", None)
        return cls(
            key_file=getattr(vcfg, "key_file", "") or "",
            enabled=bool(getattr(vcfg, "enabled", True)))
