"""Faza 2.2 — `installer.py` testləri.

Yoxlanılan prinsiplər:
  * Aşkarlama (detection) qurulumdan TAM ayrılıb; `check_tools` heç nə qurmur.
  * `sudo` və `curl | bash` kimi uzaqdan shell skriptləri HEÇ VAXT işlədilmir.
  * `go install` / `pip install` yalnız açıq `--auto-install` (dry_run=False) ilə
    və yalnız Go/pip mövcud olduqda; əks halda "manual" tövsiyəsi verilir.
  * Qurulumdan SONRA binary MÜTLƏQ yenidən yoxlanılır; yoxlanmadan "uğurlu"
    hesab edilmir.

Heç bir test xarici şəbəkəyə müraciət etmir və heç bir real quraşdırma
etmir — `run_process` və `shutil.which` mock-lanır.
"""
from __future__ import annotations

import pytest

from qbh import installer
from qbh.adapters.base import ProcResult
from qbh.installer import ToolReport, ToolSpec, ToolStatus

# ------------------------------------------------------------------ helpers

_SPEC = ToolSpec("nuclei", ("nuclei", "-version"), "go",
                 ("go", "install", "x"), True, manual_hint="əl ilə quraşdır")


def _tool(name: str, *, required: bool = False, present: bool = True,
          install_kind: str = "go") -> ToolStatus:
    return ToolStatus(name=name, required=required, present=present,
                      install_kind=install_kind)


def _report(tools: list[ToolStatus], *, go_available: bool = True,
            os_ok: bool = True) -> ToolReport:
    return ToolReport(os_ok=os_ok, os_detail="Linux x86_64",
                      go_available=go_available, go_version="1.22.0",
                      tools=tools)


# ------------------------------------------------------------- kontraktlar


class TestContracts:
    def test_binary_name_defaults_to_name(self):
        spec = ToolSpec("nuclei", ("nuclei", "-v"), "go", None, False)
        assert spec.binary_name() == "nuclei"

    def test_binary_name_override(self):
        spec = ToolSpec("nuclei", ("n",), "go", None, False, binary="nuclei.exe")
        assert spec.binary_name() == "nuclei.exe"

    def test_toolstatus_to_dict(self):
        d = ToolStatus("nuclei", True, True, "go", version="1.2.3",
                       install_status="present", verified=True).to_dict()
        assert d["tool"] == "nuclei"
        assert d["detected_version"] == "1.2.3"
        assert d["verified"] is True
        assert d["error"] is None

    def test_missing_required_only_required(self):
        rep = _report([
            _tool("nuclei", required=True, present=False),
            _tool("ffuf", required=True, present=True),
            _tool("amass", required=False, present=False),
        ])
        assert [t.name for t in rep.missing_required] == ["nuclei"]

    def test_report_to_dict(self):
        rep = _report([_tool("nuclei", required=True, present=True)])
        d = rep.to_dict()
        assert d["go_available"] is True
        assert d["tools"][0]["tool"] == "nuclei"


# --------------------------------------------------------------- aşkarlama


class TestParseVersion:
    @pytest.mark.parametrize("text,expected", [
        ("nuclei v1.2.3", "1.2.3"),
        ("version 1.2", "1.2"),
        ("ffuf 2.1.0-dev", "2.1.0"),
        ("no digits here", ""),
        ("", ""),
    ])
    def test_parse_version(self, text, expected):
        assert installer._parse_version(text) == expected


class TestCheckOs:
    def test_check_os_shape(self):
        ok, detail = installer.check_os()
        assert isinstance(ok, bool)
        assert "Python" in detail


class TestDetectOne:
    async def test_binary_absent(self, monkeypatch):
        monkeypatch.setattr(installer.shutil, "which", lambda name: None)
        st = await installer._detect_one(_SPEC)
        assert st.present is False
        assert st.verified is False

    async def test_version_from_stdout(self, monkeypatch):
        monkeypatch.setattr(installer.shutil, "which", lambda name: "/usr/bin/x")

        async def fake_run(cmd, **kw):
            return ProcResult(0, stdout=b"nuclei v1.2.3")

        monkeypatch.setattr(installer, "run_process", fake_run)
        st = await installer._detect_one(_SPEC)
        assert st.present is True
        assert st.verified is True
        assert st.version == "1.2.3"
        assert st.install_status == "present"

    async def test_version_falls_back_to_stderr(self, monkeypatch):
        monkeypatch.setattr(installer.shutil, "which", lambda name: "/usr/bin/x")

        async def fake_run(cmd, **kw):
            return ProcResult(0, stderr=b"v2.0.0")

        monkeypatch.setattr(installer, "run_process", fake_run)
        st = await installer._detect_one(_SPEC)
        assert st.version == "2.0.0"


class TestCheckGo:
    async def test_go_absent(self, monkeypatch):
        monkeypatch.setattr(installer.shutil, "which", lambda name: None)
        ok, ver = await installer._check_go()
        assert (ok, ver) == (False, "")

    async def test_go_present(self, monkeypatch):
        monkeypatch.setattr(installer.shutil, "which", lambda name: "/usr/bin/go")

        async def fake_run(cmd, **kw):
            return ProcResult(0, stdout=b"go version go1.22.0 linux/amd64")

        monkeypatch.setattr(installer, "run_process", fake_run)
        ok, ver = await installer._check_go()
        assert ok is True
        assert ver == "1.22.0"


class TestCheckTools:
    async def test_check_tools_filters_and_gathers(self, monkeypatch):
        async def fake_detect(spec):
            return _tool(spec.name, required=spec.required, present=True)

        async def fake_go():
            return True, "1.22.0"

        monkeypatch.setattr(installer, "_detect_one", fake_detect)
        monkeypatch.setattr(installer, "_check_go", fake_go)
        rep = await installer.check_tools(only=["nuclei", "ffuf"])
        assert {t.name for t in rep.tools} == {"nuclei", "ffuf"}
        assert rep.go_available is True
        assert rep.missing_required == []

    async def test_check_tools_detection_only(self, monkeypatch):
        """`check_tools` HEÇ NƏ qurmur — `install_status` boş qalır."""
        async def fake_detect(spec):
            return _tool(spec.name, required=spec.required, present=False)

        async def fake_go():
            return False, ""

        monkeypatch.setattr(installer, "_detect_one", fake_detect)
        monkeypatch.setattr(installer, "_check_go", fake_go)
        rep = await installer.check_tools(only=["nuclei"])
        assert rep.tools[0].install_status == ""


# ---------------------------------------------------------------- qurulum


class TestInstallTools:
    async def test_present_tool_skipped(self):
        rep = _report([_tool("nuclei", required=True, present=True)])
        await installer.install_tools(rep, dry_run=False)
        assert rep.tools[0].install_status == "present"

    async def test_manual_kind_gets_hint(self):
        rep = _report([_tool("feroxbuster", present=False)])
        await installer.install_tools(rep, dry_run=False)
        t = rep.tools[0]
        assert t.install_status == "manual"
        assert t.manual_action

    async def test_go_tool_without_go_is_manual(self):
        rep = _report([_tool("nuclei", required=True, present=False)],
                      go_available=False)
        await installer.install_tools(rep, dry_run=False)
        t = rep.tools[0]
        assert t.install_status == "manual"
        assert "Go tapılmadı" in t.manual_action

    async def test_dry_run_never_installs(self, monkeypatch):
        called = []

        async def fake_install(spec, status):
            called.append(spec.name)

        monkeypatch.setattr(installer, "_do_install", fake_install)
        rep = _report([_tool("nuclei", required=True, present=False)])
        await installer.install_tools(rep, dry_run=True)
        t = rep.tools[0]
        assert t.install_status == "skipped"
        assert t.manual_action.startswith("dry-run:")
        assert called == []

    async def test_real_install_invokes_do_install(self, monkeypatch):
        called = []

        async def fake_install(spec, status):
            called.append(spec.name)

        monkeypatch.setattr(installer, "_do_install", fake_install)
        rep = _report([_tool("nuclei", required=True, present=False)])
        await installer.install_tools(rep, dry_run=False)
        assert called == ["nuclei"]


class TestDoInstall:
    async def test_runner_missing_marks_failed(self, monkeypatch):
        async def fake_run(cmd, **kw):
            return ProcResult(-1, missing=True)

        monkeypatch.setattr(installer, "run_process", fake_run)
        st = _tool("nuclei", required=True, present=False)
        await installer._do_install(_SPEC, st)
        assert st.install_status == "failed"
        assert "tapılmadı" in st.error
        assert st.manual_action == "əl ilə quraşdır"

    async def test_nonzero_exit_marks_failed(self, monkeypatch):
        async def fake_run(cmd, **kw):
            return ProcResult(1)

        monkeypatch.setattr(installer, "run_process", fake_run)
        st = _tool("nuclei", required=True, present=False)
        await installer._do_install(_SPEC, st)
        assert st.install_status == "failed"
        assert "çıxış kodu 1" in st.error

    async def test_timeout_marks_failed(self, monkeypatch):
        async def fake_run(cmd, **kw):
            return ProcResult(124, timed_out=True)

        monkeypatch.setattr(installer, "run_process", fake_run)
        st = _tool("nuclei", required=True, present=False)
        await installer._do_install(_SPEC, st)
        assert st.install_status == "failed"
        assert "(timeout)" in st.error

    async def test_success_requires_verification(self, monkeypatch):
        async def fake_run(cmd, **kw):
            return ProcResult(0)

        async def fake_detect(spec):
            return ToolStatus(spec.name, spec.required, True, spec.install_kind,
                              version="1.2.3", install_status="present",
                              verified=True)

        monkeypatch.setattr(installer, "run_process", fake_run)
        monkeypatch.setattr(installer, "_detect_one", fake_detect)
        st = _tool("nuclei", required=True, present=False)
        await installer._do_install(_SPEC, st)
        assert st.install_status == "installed"
        assert st.present is True
        assert st.verified is True
        assert st.version == "1.2.3"

    async def test_unverified_install_is_failed(self, monkeypatch):
        async def fake_run(cmd, **kw):
            return ProcResult(0)

        async def fake_detect(spec):
            return ToolStatus(spec.name, spec.required, False, spec.install_kind)

        monkeypatch.setattr(installer, "run_process", fake_run)
        monkeypatch.setattr(installer, "_detect_one", fake_detect)
        st = _tool("nuclei", required=True, present=False)
        await installer._do_install(_SPEC, st)
        assert st.install_status == "failed"
        assert st.verified is False
        assert "qurulumdan sonra tapılmadı" in st.error


# ---------------------------------------------------------------- hesabat


class TestFormatReport:
    def test_marks_and_errors(self):
        rep = ToolReport(os_ok=False, os_detail="Windows", go_available=False,
                         go_version="", tools=[
                             ToolStatus("nuclei", True, False, "go",
                                        install_status="failed",
                                        error="çıxış kodu 1",
                                        manual_action="əl ilə quraşdır"),
                             ToolStatus("ffuf", True, True, "go",
                                        version="2.1.0",
                                        install_status="present"),
                         ])
        out = installer.format_report(rep)
        assert "QURULUM HESABATI" in out
        assert "DƏSTƏKLƏNMİR" in out
        assert "Go: YOXDUR" in out
        assert "xəta: çıxış kodu 1" in out
        assert "tövsiyə: əl ilə quraşdır" in out
        assert "v2.1.0" in out
