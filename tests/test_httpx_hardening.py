"""ProjectDiscovery httpx inteqrasiyası — binari aşkarlama + recon xəta idarəsi.

Yoxlanılan prinsiplər:
  * `httpx` binari-si YALNIZ ProjectDiscovery olmalıdır — PATH-də birinci
    görünən əlaqəsiz Python `httpx` CLI qəbul EDİLMİR (fail-closed).
  * Prioritet: açıq konfiqurasiya → `~/go/bin/httpx` → PATH (yalnız doğrulanan).
  * Recon alt-prosesin HƏR `ProcResult` vəziyyətini AÇIQ raportlayır; uğursuz
    proses HEÇ VAXT "0 canlı host" kimi uğurlu təqdim olunmur.

Mocks və lokal fayl fixture-ləri istifadə olunur — XARİCİ ŞƏBƏKƏ TRAFİKİ YOXDUR
(`run_process` həmişə mock-lanır).
"""
from __future__ import annotations

import json
import types

import pytest

from qbh import db, installer
from qbh.adapters.base import ProcResult
from qbh.engines.recon import ReconEngine
from qbh.results import EngineResult

#: ProjectDiscovery httpx `-version` çıxışı (v1.12.0).
_PD_VERSION_OUT = b"httpx version v1.12.0\n"
#: Əlaqəsiz Python `httpx` CLI (click) versiya çıxışı.
_PY_VERSION_OUT = b"httpx, version 0.28.1\n"

_HTTPX_SPEC = next(s for s in installer.TOOLS if s.name == "httpx")


# ------------------------------------------------------------------ helpers


def _fake_exe(tmp_path, rel: str) -> str:
    """Müvəqqəti saxta icra oluna bilən fayl yaradır və yolunu qaytarır."""
    path = tmp_path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(0o755)
    return str(path)


def _home(monkeypatch, tmp_path):
    """`~`-i müvəqqəti home qovluğuna yönəldir (real home hardcode edilmir)."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    real = installer.os.path.expanduser
    monkeypatch.setattr(
        installer.os.path, "expanduser",
        lambda p: str(home) if p == "~" else real(p))
    return home


# --------------------------------------------------------- imza (məzmun) testi


class TestPdHttpxSignature:
    """Binari YALNIZ adına görə deyil, `-version` məzmununa görə tanınır."""

    @pytest.mark.parametrize("text", [
        "httpx version v1.12.0",
        "httpx v1.12.0",
        "        projectdiscovery.io\n[INF] Current Version: v1.12.0",
        "[INF] Current Version: v1.12.0",
    ])
    def test_accepts_projectdiscovery(self, text):
        assert installer.looks_like_pd_httpx(text) is True

    @pytest.mark.parametrize("text", [
        "",
        "   ",
        "httpx, version 0.28.1",            # Python `httpx` CLI (click)
        "Usage: httpx [OPTIONS] URL",       # əlaqəsiz proqram
    ])
    def test_rejects_non_projectdiscovery(self, text):
        assert installer.looks_like_pd_httpx(text) is False


# ------------------------------------------------------------- binari aşkarlama


class TestExecutableResolution:
    """Ssenari 1-3: `~/go/bin/httpx`, PATH-dəki saxta `httpx`, itkin binari."""

    async def test_go_bin_pd_binary_preferred(self, tmp_path, monkeypatch):
        """1) `~/go/bin/httpx` PD binari-sidir → PATH-dən ÜSTÜN tutulur."""
        _home(monkeypatch, tmp_path)
        go_exe = _fake_exe(tmp_path, "home/go/bin/httpx")
        path_exe = _fake_exe(tmp_path, "usr/bin/httpx")
        monkeypatch.setattr(installer.shutil, "which", lambda name: path_exe)

        async def fake_run(cmd, **kw):
            assert cmd[0] == go_exe
            return ProcResult(0, stdout=_PD_VERSION_OUT)

        monkeypatch.setattr(installer, "run_process", fake_run)
        assert await installer.resolve_httpx() == go_exe

    async def test_python_httpx_in_path_rejected(self, tmp_path, monkeypatch):
        """2) `/usr/bin/httpx` əlaqəsiz Python CLI-dir → RƏDD edilir."""
        _home(monkeypatch, tmp_path)                       # go/bin yoxdur
        py_exe = _fake_exe(tmp_path, "usr/bin/httpx")
        monkeypatch.setattr(installer.shutil, "which", lambda name: py_exe)

        async def fake_run(cmd, **kw):
            return ProcResult(0, stdout=_PY_VERSION_OUT)

        monkeypatch.setattr(installer, "run_process", fake_run)
        assert await installer.resolve_httpx() == ""

    async def test_missing_executable_returns_empty(self, tmp_path, monkeypatch):
        """3) Heç bir namizəd yoxdur → boş sətir (alt-proses ÇAĞIRILMIR)."""
        _home(monkeypatch, tmp_path)
        monkeypatch.setattr(installer.shutil, "which", lambda name: None)

        async def fake_run(cmd, **kw):
            raise AssertionError("alt-proses çağırılmamalıdır")

        monkeypatch.setattr(installer, "run_process", fake_run)
        assert await installer.resolve_httpx() == ""

    async def test_explicit_config_has_top_priority(self, tmp_path, monkeypatch):
        """Prioritet 1: açıq konfiqurasiya (`QBH_HTTPX_BIN`)."""
        _home(monkeypatch, tmp_path)
        explicit = _fake_exe(tmp_path, "custom/httpx")
        monkeypatch.setenv("QBH_HTTPX_BIN", explicit)
        monkeypatch.setattr(installer.shutil, "which", lambda name: None)

        async def fake_run(cmd, **kw):
            assert cmd[0] == explicit
            return ProcResult(0, stdout=_PD_VERSION_OUT)

        monkeypatch.setattr(installer, "run_process", fake_run)
        assert await installer.resolve_httpx() == explicit

    async def test_path_pd_binary_accepted_when_no_go_bin(
            self, tmp_path, monkeypatch):
        """Prioritet 3: go/bin yoxdursa, doğrulanan PATH binari-si qəbul olunur."""
        _home(monkeypatch, tmp_path)
        pd_exe = _fake_exe(tmp_path, "opt/httpx")
        monkeypatch.setattr(installer.shutil, "which", lambda name: pd_exe)

        async def fake_run(cmd, **kw):
            return ProcResult(0, stdout=_PD_VERSION_OUT)

        monkeypatch.setattr(installer, "run_process", fake_run)
        assert await installer.resolve_httpx() == pd_exe

    @pytest.mark.parametrize("bad", [
        ProcResult(2, stderr=b"usage: httpx ..."),   # qeyri-sıfır çıxış kodu
        ProcResult(-1, timed_out=True),              # versiya yoxlaması timeout
        ProcResult(-1, missing=True),                # binari itdi
    ])
    async def test_validation_rejects_failed_probe(self, tmp_path, monkeypatch,
                                                    bad):
        """Doğrulama MƏHDUD alt-proses uğursuz olarsa → rədd (fail-closed)."""
        _home(monkeypatch, tmp_path)
        _fake_exe(tmp_path, "home/go/bin/httpx")
        monkeypatch.setattr(installer.shutil, "which", lambda name: None)

        async def fake_run(cmd, **kw):
            return bad

        monkeypatch.setattr(installer, "run_process", fake_run)
        assert await installer.resolve_httpx() == ""

    async def test_detect_one_reports_verified_pd_httpx(
            self, tmp_path, monkeypatch):
        """`_detect_one` ProjectDiscovery httpx-i doğrulanmış kimi bildirir."""
        _home(monkeypatch, tmp_path)
        _fake_exe(tmp_path, "home/go/bin/httpx")
        monkeypatch.setattr(installer.shutil, "which", lambda name: None)

        async def fake_run(cmd, **kw):
            return ProcResult(0, stdout=_PD_VERSION_OUT)

        monkeypatch.setattr(installer, "run_process", fake_run)
        st = await installer._detect_one(_HTTPX_SPEC)
        assert st.present is True
        assert st.verified is True
        assert st.version == "1.12.0"
        assert st.install_status == "present"

    async def test_detect_one_absent_when_only_python_httpx(
            self, tmp_path, monkeypatch):
        """Yalnız əlaqəsiz Python `httpx` varsa → `present=False` (qurulum tələb)."""
        _home(monkeypatch, tmp_path)
        py_exe = _fake_exe(tmp_path, "usr/bin/httpx")
        monkeypatch.setattr(installer.shutil, "which", lambda name: py_exe)

        async def fake_run(cmd, **kw):
            return ProcResult(0, stdout=_PY_VERSION_OUT)

        monkeypatch.setattr(installer, "run_process", fake_run)
        st = await installer._detect_one(_HTTPX_SPEC)
        assert st.present is False
        assert st.verified is False


# --------------------------------------------------------------- recon ssenariləri


async def _run_httpx(monkeypatch, make_ctx, result, *, exe="httpx",
                     subs=("127.0.0.1",)):
    """`ReconEngine._httpx`-i təcrid olunmuş şəkildə işlədir (şəbəkəsiz)."""
    calls: list[list[str]] = []

    async def fake_resolve(**_kw):
        return exe

    async def fake_run(cmd, **kw):
        calls.append(list(cmd))
        return result

    monkeypatch.setattr("qbh.engines.recon.resolve_httpx", fake_resolve)
    monkeypatch.setattr("qbh.engines.recon.run_process", fake_run)

    ctx = make_ctx()
    ctx.scan_id = 1
    res = EngineResult(stage="recon")
    alive = await ReconEngine(ctx)._httpx(list(subs), res)
    return res, alive, calls


def _json_line(**fields) -> bytes:
    return (json.dumps(fields) + "\n").encode()


class TestReconProcResultStates:
    """Ssenari 4-9: hər `ProcResult` vəziyyəti dürüst raportlanır."""

    async def test_blocked_reported_distinctly(self, tmp_db, make_ctx,
                                               monkeypatch):
        """4) `blocked=True`: egress/scope bloklanması AYRI bildirilir."""
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(-1, blocked=True))
        assert alive == []
        assert res.ok is False
        assert any("blok" in e.lower() for e in res.errors)
        assert any("egress" in e.lower() for e in res.errors)
        assert not any("tapılmadı" in w for w in res.warnings)

    async def test_timeout_reported(self, tmp_db, make_ctx, monkeypatch):
        """5) `timed_out=True`: timeout AÇIQ bildirilir, uğur kimi yox."""
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(-1, timed_out=True))
        assert alive == []
        assert res.ok is False
        assert any("timeout" in e.lower() for e in res.errors)

    async def test_nonzero_exit_reports_bounded_stderr(self, tmp_db, make_ctx,
                                                       monkeypatch):
        """6) qeyri-sıfır `returncode`: proses uğursuzluğu + MƏHDUD stderr."""
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(1, stderr=b"x" * 2000))
        assert alive == []
        assert res.ok is False
        err = " ".join(res.errors)
        assert "çıxış kodu 1" in err
        assert len(err) < 1000                 # stderr MƏHDUDLAŞDIRILIR
        assert "x" * 401 not in err            # tam stderr sızmır

    async def test_stderr_secret_is_redacted(self, tmp_db, make_ctx, monkeypatch):
        """6b) stderr-dəki secret loglara DÜZ yazılmır (maskalanır)."""
        res, _, _ = await _run_httpx(
            monkeypatch, make_ctx,
            ProcResult(1, stderr=b'api_key="super-secret-value-123"'))
        err = " ".join(res.errors)
        assert "super-secret-value-123" not in err
        assert "redacted" in err.lower()

    async def test_valid_json_produces_hosts(self, tmp_db, make_ctx, monkeypatch):
        """7) uğurlu icra + etibarlı JSON → canlı host düzgün çıxarılır."""
        stdout = _json_line(url="http://127.0.0.1:8080/", status_code=200,
                            title="home", tech=["nginx"], a=["127.0.0.1"],
                            cdn=None)
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(0, stdout=stdout))
        assert res.ok is True
        assert res.errors == []
        assert [a["host"] for a in alive] == ["127.0.0.1"]
        assert alive[0]["status"] == 200

    async def test_empty_stdout_is_not_unreachable(self, tmp_db, make_ctx,
                                                   monkeypatch):
        """8) uğurlu icra + BOŞ çıxış → "nəticə yoxdur", "əlçatmaz" DEYİL."""
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(0, stdout=b""))
        assert alive == []
        assert res.ok is True
        assert any("boş çıxış" in w for w in res.warnings)
        assert all("əlçatmaz" not in e for e in res.errors)

    async def test_malformed_json_lines_counted(self, tmp_db, make_ctx,
                                                monkeypatch):
        """9) xətalı JSON sətirləri SAYILIR və crash YARATMIR."""
        good = _json_line(url="http://127.0.0.1/", status_code=200)
        stdout = b"{not json}\n" + good + b"{oops\n"
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(0, stdout=stdout))
        assert len(alive) == 1
        assert res.ok is True
        assert any("2 xətalı JSON" in w for w in res.warnings)


class TestReconScopeEnforcement:
    """Ssenari 10-11: scope/egress nəzarəti toxunulmaz qalır."""

    async def test_out_of_scope_hosts_rejected(self, tmp_db, make_ctx,
                                               monkeypatch):
        """10) scope xarici host JSON-dan RƏDD olunur, scope-daxili qalır."""
        stdout = (_json_line(url="http://evil.example.com/", status_code=200)
                  + _json_line(url="http://127.0.0.1/", status_code=200))
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(0, stdout=stdout))
        assert [a["host"] for a in alive] == ["127.0.0.1"]
        rows = db.get_db().execute("SELECT subdomain FROM hosts").fetchall()
        assert all(r["subdomain"] == "127.0.0.1" for r in rows)

    async def test_all_out_of_scope_reports_no_valid_results(
            self, tmp_db, make_ctx, monkeypatch):
        """10b) hamısı scope xarici → canlı host YOX + dürüst xəbərdarlıq."""
        stdout = _json_line(url="http://evil.example.com/", status_code=200)
        res, alive, _ = await _run_httpx(
            monkeypatch, make_ctx, ProcResult(0, stdout=stdout))
        assert alive == []
        assert any("etibarlı nəticə tapılmadı" in w for w in res.warnings)

    async def test_run_rejects_out_of_scope_domain(self, tmp_db, make_ctx,
                                                   monkeypatch):
        """11) `run()` scope xarici domaini alt-proses başlatmadan rədd edir."""
        launched: list[str] = []

        async def fake_run(cmd, **kw):
            launched.append(cmd[0])
            return ProcResult(0)

        monkeypatch.setattr("qbh.engines.recon.run_process", fake_run)
        res = await ReconEngine(make_ctx()).run("evil.example.com")
        assert res.ok is False
        assert any("scope" in e.lower() for e in res.errors)
        assert launched == []

    async def test_egress_rejection_launches_no_subprocess(
            self, tmp_db, make_ctx, monkeypatch):
        """11b) egress hədəfi rədd edərsə HEÇ BİR alt-proses başladılmır."""
        launched: list[str] = []

        async def fake_resolve(**_kw):
            return "/usr/local/bin/httpx"

        async def fake_run(cmd, **kw):
            launched.append(cmd[0])
            return ProcResult(0)

        monkeypatch.setattr("qbh.engines.recon.resolve_httpx", fake_resolve)
        monkeypatch.setattr("qbh.engines.recon.run_process", fake_run)

        class _Egress:
            async def authorize_process_targets(self, hosts):
                return types.SimpleNamespace(hostnames=[])

        ctx = make_ctx()
        ctx._egress = _Egress()
        res = await ReconEngine(ctx).run("127.0.0.1", subdomains=["127.0.0.1"])
        assert res.ok is False
        assert any("egress" in e for e in res.errors)
        assert launched == []
