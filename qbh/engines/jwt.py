"""JWT Engine — JSON Web Token zəiflik analizi.

Kəşf: canlı host cavabları (Set-Cookie / body) və JS analizindən çıxarılmış
token-lər. Analiz:
  * **Oflayn (ələtdən asılı olmayan):** header/payload açılır, `alg`, iddialar
    (claims) və müddət (`exp`) yoxlanılır → informativ `candidate`.
  * **jwt_tool** mövcuddursa: `alg:none` (`-X a`) və `kid` inyeksiyası
    (`-X i`) yoxlanılır → yalnız alət pozitivliyi ilə `confirmed`.

Dürüstlük: xam token/signature HEÇ VAXT saxlanmır — yalnız maskalanmış
(`redact`) və dekodlanmış iddialar hesabata düşür.
"""
from __future__ import annotations

import asyncio
import base64
import json
import re
import time

import aiohttp

from .. import db
from ..antiblock.ua_rotator import ua_for
from ..redact import redact
from ..results import EngineResult
from ..scope import ScopeError
from .offensive import OffensiveEngine

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
WEAK_ALGS = {"none", "None", "NONE"}


def _b64url_decode(seg: str) -> dict:
    pad = "=" * (-len(seg) % 4)
    try:
        raw = base64.urlsafe_b64decode(seg + pad)
        return json.loads(raw.decode("utf-8", errors="ignore"))
    except (ValueError, json.JSONDecodeError):
        return {}


class JWTEngine(OffensiveEngine):
    name = "jwt"
    tool = "jwt_tool"
    timeout = 300
    max_tokens = 10

    async def run(self) -> EngineResult:
        res = EngineResult(stage=self.name)
        if not self.ctx.allows("active_fuzz"):
            return res.skip("aktiv fuzz qadağandır — JWT atlandı")
        hosts = db.alive_hosts(self.ctx.scan_id)[:20]
        tokens: dict[str, tuple[int, str]] = {}   # token → (host_id, subdomain)
        if hosts and self.ctx.guardian:
            async with aiohttp.ClientSession() as session:
                for h in hosts:
                    for tok in await self._harvest(session, h, res):
                        tokens.setdefault(tok, (h["id"], h["subdomain"]))
        for tok in self._from_secrets():
            tokens.setdefault(tok, self._token_host(tok))
        tokens = dict(list(tokens.items())[: self.max_tokens])
        if not tokens:
            return res.skip("JWT token tapılmadı")

        print(f"[═══ JWT ({self.tool if self.tool_present() else 'oflayn'}) ═══] "
              f"{len(tokens)} token")
        for tok, (host_id, sub) in tokens.items():
            if host_id <= 0:
                continue
            await self._analyze(tok, host_id, sub, res)
        return res

    # ---------------------------------------------------------- harvesting
    async def _harvest(self, session, host, res: EngineResult) -> list[str]:
        url = f"https://{host['subdomain']}/"
        if not self.cfg.in_scope(url):
            return []
        try:
            r = await self.ctx.guardian.get(
                session, url, allow_redirects=False,
                headers={"User-Agent": ua_for(host["subdomain"])})
        except (aiohttp.ClientError, asyncio.TimeoutError, ScopeError):
            return []
        text = ""
        for name, val in r.headers.items():
            text += f"{name}: {val}\n"
        text += r.text
        return list(dict.fromkeys(JWT_RE.findall(text)))

    def _from_secrets(self) -> list[str]:
        try:
            rows = db.get_db().execute(
                "SELECT s.value_preview FROM secrets s JOIN hosts h "
                "ON h.id=s.host_id WHERE h.scan_id=? AND "
                "(s.kind LIKE '%jwt%' OR s.kind LIKE '%token%') LIMIT 20",
                (db.effective_scan_id(self.ctx.scan_id),)).fetchall()
        except Exception:  # noqa: BLE001 — köhnə bazada cədvəl yoxdursa
            return []
        toks = []
        for row in rows:
            m = JWT_RE.search(row["value_preview"] or "")
            if m:
                toks.append(m.group(0))
        return toks

    def _token_host(self, tok: str) -> tuple[int, str]:
        row = db.get_db().execute(
            "SELECT s.host_id, h.subdomain FROM secrets s JOIN hosts h "
            "ON h.id=s.host_id WHERE h.scan_id=? AND s.value_preview LIKE ? "
            "LIMIT 1", (db.effective_scan_id(self.ctx.scan_id),
                        f"%{tok[:16]}%")).fetchone()
        if row:
            return row["host_id"], row["subdomain"]
        return -1, ""

    # ---------------------------------------------------------- analysis
    async def _analyze(self, tok: str, host_id: int, sub: str,
                       res: EngineResult) -> None:
        parts = tok.split(".")
        header = _b64url_decode(parts[0]) if parts else {}
        payload = _b64url_decode(parts[1]) if len(parts) > 1 else {}
        alg = str(header.get("alg", "?"))
        claims = {k: payload.get(k) for k in
                  ("sub", "iss", "aud", "exp", "iat", "role", "admin")
                  if k in payload}
        exp = payload.get("exp")
        expired = isinstance(exp, (int, float)) and exp < time.time()

        notes = [f"alg={alg}"]
        if alg in WEAK_ALGS:
            notes.append("WEAK-ALG (none)")
        if expired:
            notes.append("expired token (acceptance ayrıca yoxlanmalıdır)")
        if "kid" in header:
            notes.append(f"kid={header['kid']} (kid-injection namizədi)")
        title = "JWT analizi"
        desc = (f"{sub}: JWT aşkarlandı. {', '.join(notes)}. "
                f"Dekodlanmış iddialar (signature/secret saxlanmır).")
        fid = self.record(
            host_id, "low", title, desc,
            evidence=redact(f"claims={claims} header_keys={list(header)}"),
            confidence=0.4, status="candidate", source="jwt-analysis")

        if not self.tool_present():
            return
        out = await self._run_tool(tok)
        if out and re.search(r"(\[+\]\s*(VULNERABLE|success|accepted)|"
                             r"alg.*none|cracked|key found)", out, re.I):
            self.confirm(fid, "marker",
                         redact(f"jwt_tool sübutu: {out[:800]}"),
                         confidence=0.9)
            res.findings += 1
            print(f"[🔴] {sub}: JWT zəifliyi TƏSDİQLƏNDİ (jwt_tool)")
        else:
            res.findings += 1

    async def _run_tool(self, tok: str) -> str:
        from ..adapters.base import run_process

        combined = ""
        for mode in ("a", "i"):        # alg:none, kid-injection
            proc = await run_process(
                ["jwt_tool", tok, "-X", mode], timeout=self.timeout)
            if proc.missing:
                return ""
            combined += "\n" + (proc.stdout.decode(errors="ignore")
                                + proc.stderr.decode(errors="ignore"))
        return combined
