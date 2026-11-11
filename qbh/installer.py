"""Tool aşkarlanması və TƏHLÜKƏSİZ qurulum.

Prinsiplər:
  * Aşkarlama (detection) qurulumdan (installation) TAM ayrılıb.
  * `sudo` HEÇ VAXT avtomatik işlədilmir; sistem paketləri üçün yalnız
    "manual action" tövsiyəsi verilir.
  * Uzaqdan gələn shell skriptləri (curl | bash) İCRA EDİLMİR.
  * PATH və shell profil faylları DƏYİŞDİRİLMİR.
  * Qurulumdan sonra binary MÜTLƏQ yenidən yoxlanılır — yoxlanmadan
    "uğurlu" hesab edilmir.
  * `go install` / `pip install` yalnız açıq `--auto-install` ilə və
    yalnız Go/pip mövcud olduqda işlədilir (istifadəçi səviyyəsində).
  * Nuclei template-ləri adi skan zamanı AVTOMATİK yenilənmir.
"""
from __future__ import annotations

import platform
import re
import shutil
from dataclasses import dataclass, field

from .adapters.base import run_process

_VERSION_RE = re.compile(r"(\d+)\.(\d+)(?:\.(\d+))?")


@dataclass(frozen=True)
class ToolSpec:
    name: str
    version_cmd: tuple[str, ...]
    install_kind: str            # "go" | "pip" | "manual"
    install_cmd: tuple[str, ...] | None
    required: bool
    binary: str = ""
    manual_hint: str = ""

    def binary_name(self) -> str:
        return self.binary or self.name


TOOLS: tuple[ToolSpec, ...] = (
    ToolSpec("subfinder", ("subfinder", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"),
             True, manual_hint="go install ...subfinder..."),
    ToolSpec("dnsx", ("dnsx", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/dnsx/cmd/dnsx@latest"), True),
    ToolSpec("httpx", ("httpx", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/httpx/cmd/httpx@latest"), True),
    ToolSpec("naabu", ("naabu", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"), True),
    ToolSpec("katana", ("katana", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/katana/cmd/katana@latest"), True),
    ToolSpec("nuclei", ("nuclei", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"), True),
    ToolSpec("ffuf", ("ffuf", "-V"), "go",
             ("go", "install", "github.com/ffuf/ffuf/v2@latest"), True),
    ToolSpec("alterx", ("alterx", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/alterx/cmd/alterx@latest"), False),
    ToolSpec("gau", ("gau", "--version"), "go",
             ("go", "install", "-v",
              "github.com/lc/gau/v2/cmd/gau@latest"), False),
    ToolSpec("jsluice", ("jsluice", "version"), "go",
             ("go", "install", "-v",
              "github.com/BishopFox/jsluice/cmd/jsluice@latest"), False),
    ToolSpec("x8", ("x8", "--help"), "go",
             ("go", "install", "github.com/Ne0nd0g/x8@latest"), False),
    ToolSpec("arjun", ("arjun", "--version"), "pip",
             ("python", "-m", "pip", "install", "arjun"), False),
    ToolSpec("schemathesis", ("schemathesis", "--version"), "pip",
             ("python", "-m", "pip", "install", "schemathesis"), False),
    ToolSpec("feroxbuster", ("feroxbuster", "--version"), "manual", None, False,
             manual_hint="cargo install feroxbuster  (və ya distro paketi)"),
    ToolSpec("amass", ("amass", "version"), "manual", None, False,
             manual_hint="sudo apt install amass"),
    ToolSpec("nmap", ("nmap", "--version"), "manual", None, False,
             manual_hint="sudo apt install nmap"),
    # ---- Faza 1: yeni offensive alətlər ----
    ToolSpec("sqlmap", ("sqlmap", "--version"), "manual", None, False,
             manual_hint="sudo apt install sqlmap  (və ya pip install sqlmap)"),
    ToolSpec("ghauri", ("ghauri", "--help"), "pip",
             ("python", "-m", "pip", "install", "ghauri"), False),
    ToolSpec("dalfox", ("dalfox", "version"), "go",
             ("go", "install", "-v",
              "github.com/hahwul/dalfox/v2@latest"), False),
    ToolSpec("sstimap", ("sstimap", "--help"), "manual", None, False,
             manual_hint="git clone https://github.com/vladko312/SSTImap"),
    ToolSpec("jwt_tool", ("jwt_tool", "-h"), "manual", None, False,
             manual_hint="git clone https://github.com/ticarpi/jwt_tool"),
    ToolSpec("semgrep", ("semgrep", "--version"), "pip",
             ("python", "-m", "pip", "install", "semgrep"), False),
    ToolSpec("git-dumper", ("git-dumper", "--help"), "pip",
             ("python", "-m", "pip", "install", "git-dumper"), False),
    ToolSpec("kr", ("kr", "--help"), "go",
             ("go", "install", "-v",
              "github.com/assetnote/kiterunner/cmd/kr@latest"), False,
             manual_hint="go install github.com/assetnote/kiterunner/cmd/kr@latest"),
    # ---- Faza 1.2: recon dərinləşdirmə ----
    ToolSpec("bbot", ("bbot", "--version"), "pip",
             ("python", "-m", "pip", "install", "bbot"), False),
    ToolSpec("waymore", ("waymore", "--help"), "pip",
             ("python", "-m", "pip", "install", "waymore"), False),
    ToolSpec("gowitness", ("gowitness", "version"), "go",
             ("go", "install", "-v",
              "github.com/sensepost/gowitness@latest"), False),
    ToolSpec("dnstwist", ("dnstwist", "--version"), "pip",
             ("python", "-m", "pip", "install", "dnstwist"), False),
    # ---- Faza 1.4: OOB geri-zəng ----
    ToolSpec("interactsh-server", ("interactsh-server", "-version"), "go",
             ("go", "install", "-v",
              "github.com/projectdiscovery/interactsh/cmd/interactsh-server@latest"),
             False),
)


@dataclass
class ToolStatus:
    name: str
    required: bool
    present: bool
    install_kind: str
    version: str = ""
    install_status: str = ""      # present | installed | failed | skipped | manual
    verified: bool = False
    error: str = ""
    manual_action: str = ""

    def to_dict(self) -> dict:
        return {
            "tool": self.name,
            "required": self.required,
            "present": self.present,
            "detected_version": self.version or None,
            "install_kind": self.install_kind,
            "install_status": self.install_status,
            "verified": self.verified,
            "error": self.error or None,
            "manual_action": self.manual_action or None,
        }


@dataclass
class ToolReport:
    os_ok: bool
    os_detail: str
    go_available: bool
    go_version: str
    tools: list[ToolStatus] = field(default_factory=list)

    @property
    def missing_required(self) -> list[ToolStatus]:
        return [t for t in self.tools if t.required and not t.present]

    def to_dict(self) -> dict:
        return {
            "os_ok": self.os_ok,
            "os_detail": self.os_detail,
            "go_available": self.go_available,
            "go_version": self.go_version,
            "tools": [t.to_dict() for t in self.tools],
        }


def _parse_version(text: str) -> str:
    m = _VERSION_RE.search(text or "")
    return m.group(0) if m else ""


async def _detect_one(spec: ToolSpec) -> ToolStatus:
    if shutil.which(spec.binary_name()) is None:
        return ToolStatus(spec.name, spec.required, False, spec.install_kind)
    res = await run_process(list(spec.version_cmd), timeout=20)
    version = _parse_version(res.stdout.decode(errors="ignore")
                             or res.stderr.decode(errors="ignore"))
    return ToolStatus(spec.name, spec.required, True, spec.install_kind,
                      version=version, install_status="present",
                      verified=True)


async def _check_go() -> tuple[bool, str]:
    if shutil.which("go") is None:
        return False, ""
    res = await run_process(["go", "version"], timeout=20)
    return res.ok, _parse_version(res.stdout.decode(errors="ignore"))


def check_os() -> tuple[bool, str]:
    system = platform.system()
    machine = platform.machine()
    ok = system == "Linux"
    return ok, f"{system} {machine} (Python {platform.python_version()})"


async def check_tools(only: list[str] | None = None) -> ToolReport:
    """YALNIZ aşkarlama — heç nə quraşdırılmır."""
    os_ok, os_detail = check_os()
    go_ok, go_ver = await _check_go()
    specs = [t for t in TOOLS if only is None or t.name in only]
    statuses = await _gather_detect(specs)
    return ToolReport(os_ok, os_detail, go_ok, go_ver, statuses)


async def _gather_detect(specs: list[ToolSpec]) -> list[ToolStatus]:
    import asyncio
    return list(await asyncio.gather(*[_detect_one(s) for s in specs]))


async def install_tools(report: ToolReport, *, dry_run: bool = False) -> ToolReport:
    """Yalnız ÇATIŞMAYAN tool-ları, təhlükəsiz üsulla quraşdırır.

    `dry_run=True` olduqda heç bir əmr icra edilmir — yalnız nə ediləcəyi
    göstərilir. `sudo` və uzaq shell skriptləri heç vaxt işlədilmir.
    """
    specs = {s.name: s for s in TOOLS}
    for status in report.tools:
        if status.present:
            status.install_status = "present"
            continue
        spec = specs[status.name]
        if spec.install_kind == "manual" or spec.install_cmd is None:
            status.install_status = "manual"
            status.manual_action = spec.manual_hint or "manual qurulum tələb olunur"
            continue
        if spec.install_kind == "go" and not report.go_available:
            status.install_status = "manual"
            status.manual_action = ("Go tapılmadı — əvvəlcə Go quraşdırın, "
                                    "sonra: " + " ".join(spec.install_cmd))
            continue
        if dry_run:
            status.install_status = "skipped"
            status.manual_action = "dry-run: " + " ".join(spec.install_cmd)
            continue

        await _do_install(spec, status)
    return report


async def _do_install(spec: ToolSpec, status: ToolStatus) -> None:
    print(f"   [*] {spec.name} quraşdırılır: {' '.join(spec.install_cmd)}")
    res = await run_process(list(spec.install_cmd), timeout=900)
    if res.missing:
        status.install_status = "failed"
        status.error = f"{spec.install_cmd[0]} tapılmadı"
        status.manual_action = spec.manual_hint
        return
    if res.timed_out or res.returncode != 0:
        status.install_status = "failed"
        status.error = (f"çıxış kodu {res.returncode}"
                        + (" (timeout)" if res.timed_out else ""))
        status.manual_action = spec.manual_hint
        return

    # Qurulumdan SONRA mütləq yoxlama — "uğurlu" yalnız binary işləyirsə
    verify = await _detect_one(spec)
    if verify.present:
        status.present = True
        status.verified = True
        status.version = verify.version
        status.install_status = "installed"
    else:
        status.install_status = "failed"
        status.verified = False
        status.error = "binary qurulumdan sonra tapılmadı"
        status.manual_action = (spec.manual_hint or
                                "~/go/bin PATH-dədir? (PATH avtomatik "
                                "dəyişdirilmir — əl ilə əlavə edin)")


def format_report(report: ToolReport) -> str:
    lines = ["", "=== QURULUM HESABATI ===",
             f"OS: {report.os_detail} ({'OK' if report.os_ok else 'DƏSTƏKLƏNMİR'})",
             f"Go: {'mövcud ' + report.go_version if report.go_available else 'YOXDUR'}"]
    for t in report.tools:
        mark = {"present": "✓", "installed": "＋", "manual": "!", "failed": "✗",
                "skipped": "·"}.get(t.install_status, "?")
        label = "məcburi" if t.required else "opsional"
        lines.append(f"  [{mark}] {t.name:<13} {label:<9} "
                     f"{t.install_status or '-':<10} "
                     f"{('v' + t.version) if t.version else ''}")
        if t.error:
            lines.append(f"        xəta: {t.error}")
        if t.manual_action:
            lines.append(f"        tövsiyə: {t.manual_action}")
    return "\n".join(lines)
