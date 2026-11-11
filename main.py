#!/usr/bin/env python3
"""QBH — Qarabug Autonomous Hunter v2.2 'Xəzər'. Tək CLI giriş nöqtəsi.

Prinsiplər:
  * **Yeganə toxunulmaz sərhəd — avtorizasiya scope-u.** Scope xaricində heç bir
    trafik mümkün deyil; scope daxilində hər şey (aktiv fuzz, bypass, PoC)
    icazəlidir.
  * `--targets` HEÇ VAXT konfiqurasiyadakı avtorizasiyanı keçmir — hər hədəf
    `Config.authorize_target` (fail-closed scope) ilə yoxlanılır.
  * Aktiv fuzzinq profil default-una görə ON-dur; `--no-active-fuzz` ilə söndürülə
    bilər, proqram qaydaları (`program_rules.forbidden`) həmişə qalib gəlir.
  * Identiklik/UA/proxy rotasiyası legitim OPSEC-dir və audit olunur.
  * Ctrl+C zamanı yarımçıq nəticələr saxlanılır və hesabat yenə yazılır.
"""
from __future__ import annotations

import argparse
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from qbh.conductor import Conductor, PipelineAbort
from qbh.config import Config, ConfigError

BANNER = r"""
╔══════════════════════════════════════════╗
║   Q A R A B U G   A U T O N O M O U S    ║
║        H U N T E R  v2.2  'Xəzər'        ║
║  (offensive — yalnız İCAZƏLİ scope-da)   ║
╚══════════════════════════════════════════╝
"""

EXIT_OK = 0
EXIT_FAILURE = 1
EXIT_USAGE = 2
EXIT_INTERRUPTED = 130


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="qbh",
        description="QBH — Qarabug Autonomous Hunter v2.2 'Xəzər'. "
                    "Yalnız konfiqurasiyada icazə verilmiş scope daxilində işləyir.")
    p.add_argument("--config", default="config/targets.yaml",
                   help="YAML konfiq faylı (default: config/targets.yaml)")
    p.add_argument("--mode", default="full",
                   choices=["full", "recon", "vuln", "report", "install"],
                   help="icra rejimi")
    p.add_argument("--aggressiveness", default=None,
                   choices=["passive", "normal", "aggressive"],
                   help="icra profili (konfiqdəki dəyəri override edir)")
    p.add_argument("--proxy", default="off", choices=["off", "single"],
                   help="proxy rotasiyası/rejimi (OPSEC, yalnız scope daxilində)")
    p.add_argument("--rate", type=int, default=None,
                   help="saniyədə sorğu limiti (effektiv profildən yuxarı ola bilməz)")
    p.add_argument("--severity", default="low",
                   choices=["low", "medium", "high", "critical"],
                   help="hesabatda göstəriləcək minimum severity")
    p.add_argument("--auto-install", action="store_true",
                   help="çatışmayan tool-ları təhlükəsiz üsulla quraşdır")
    p.add_argument("--dry-run", action="store_true",
                   help="heç nə icra etmə, yalnız nə ediləcəyini göstər")
    p.add_argument("--targets", default=None,
                   help="domain1,domain2 — konfiq scope-undan KƏNARA ÇIXA BİLMƏZ")
    p.add_argument("--active-fuzz", dest="active_fuzz", action="store_true",
                   default=None,
                   help="aktiv fuzzinqi MƏCBURİ YANDIR (profil default-u ON)")
    p.add_argument("--no-active-fuzz", dest="active_fuzz", action="store_false",
                   help="aktiv fuzzinqi söndür (passive yoxlama rejimi)")
    p.add_argument("--race-fixture", default=None,
                   help="race testi üçün YALNIZ lokal loopback fixture URL-i")
    p.add_argument("--race-count", type=int, default=10,
                   help="race fixture-ə göndəriləcək sorğu sayı (maks 20)")
    p.add_argument("--race-concurrency", type=int, default=4,
                   help="race fixture concurrency (maks 5)")
    return p


async def run(args: argparse.Namespace) -> int:
    cfg = Config.load(args.config)
    if getattr(args, "aggressiveness", None):
        cfg.aggressiveness = args.aggressiveness
    if cfg.warnings:
        for w in cfg.warnings:
            print(f"   [!] konfiq xəbərdarlığı: {w}")
    print(f"   [i] profil: {cfg.aggressiveness} · rate: {cfg.effective_rate:.1f}/s · "
          f"concurrency: {cfg.effective_concurrency} · "
          f"aktiv fuzz: {'ON' if cfg.is_allowed('active_fuzz') else 'OFF'}")

    conductor = Conductor(cfg, args)

    if args.mode == "install":
        return await conductor.install_only()

    if args.mode == "report":
        path = conductor.generate_report()
        conductor.print_summary()
        return EXIT_OK if path else EXIT_FAILURE

    if args.mode == "full":
        await conductor.run_full()
    elif args.mode == "recon":
        await conductor.run_recon_mode()
    elif args.mode == "vuln":
        await conductor.run_vuln_mode()

    return EXIT_FAILURE if conductor.failed_stages else EXIT_OK


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    print(BANNER)
    try:
        return asyncio.run(run(args))
    except KeyboardInterrupt:
        print("\n[!] İstifadəçi tərəfindən dayandırıldı (Ctrl+C)")
        return EXIT_INTERRUPTED
    except PipelineAbort as exc:
        print(f"[✗] Pipeline dayandırıldı: {exc}")
        return EXIT_FAILURE
    except ConfigError as exc:
        print(f"[✗] Konfiqurasiya xətası: {exc}")
        return EXIT_USAGE
    except FileNotFoundError as exc:
        print(f"[✗] Fayl tapılmadı: {exc}")
        return EXIT_USAGE


if __name__ == "__main__":
    sys.exit(main())
