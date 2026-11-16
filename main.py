#!/usr/bin/env python3
"""QBH — Qarabug Autonomous Hunter v3.0 'Xəzər'. Tək CLI giriş nöqtəsi.

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
║        H U N T E R  v3.0  'Xəzər'        ║
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
        description="QBH — Qarabug Autonomous Hunter v3.0 'Xəzər'. "
                    "Yalnız konfiqurasiyada icazə verilmiş scope daxilində işləyir.")
    p.add_argument("--config", default="config/targets.yaml",
                   help="YAML konfiq faylı (default: config/targets.yaml)")
    p.add_argument("--mode", default="full",
                   choices=["full", "recon", "vuln", "hunt", "report",
                            "install"],
                   help="icra rejimi (hunt: avtomatik tam zəncir + dərin pass)")
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
    p.add_argument("--allow-state-changing", dest="allow_state_changing",
                   action="store_true", default=False,
                   help="state dəyişən HTTP metodlarına (POST/PUT/PATCH/DELETE) "
                        "uyğunluq flag-i; icazəni YAML təyin edir, əlavə təsdiq tələb edilmir")
    p.add_argument("--race-fixture", default=None,
                   help="race testi üçün YALNIZ lokal loopback fixture URL-i")
    p.add_argument("--race-count", type=int, default=10,
                   help="race fixture-ə göndəriləcək sorğu sayı (maks 20)")
    p.add_argument("--race-concurrency", type=int, default=4,
                   help="race fixture concurrency (maks 5)")
    # Faza 2 (§4.2/§14): davamlı icra və bərpa.
    p.add_argument("--resume", nargs="?", const=-1, default=None, type=int,
                   metavar="SCAN_ID",
                   help="yarımçıq (çökmüş) skanı davam etdir; SCAN_ID "
                        "verilməzsə ən son `running` skan seçilir")
    p.add_argument("--pending-followups", dest="pending_followups",
                   action="store_true",
                   help="gözləyən davam testlərini (followup_queue) göstər")
    p.add_argument("--scan-id", dest="scan_id", type=int, default=None,
                   help="əməliyyatı konkret skana tətbiq et")
    p.add_argument("--import-har", help="HAR faylını offline idxal et")
    p.add_argument("--list-imported", action="store_true")
    p.add_argument("--request-graph", action="store_true")
    p.add_argument("--test-plan", action="store_true", help="test planları və ilkin şərtləri göstər")
    decisions = p.add_mutually_exclusive_group()
    decisions.add_argument("--approve", nargs="?", const="*", metavar="PLAN_ID")
    decisions.add_argument("--reject", metavar="PLAN_ID")
    p.add_argument("--reason", default="cli_decision", help="plan qərarının səbəbi")
    return p


def _show_pending_followups(args: argparse.Namespace) -> int:
    """Gözləyən davam testlərini (`followup_queue`) göstərir (Faza 2 §4.2).

    `--scan-id` verilməzsə ən son yarımçıq (running) skan, o yoxdursa ən son
    skan seçilir.
    """
    from qbh import db

    db.init_db()   # sxem (o cümlədən `followup_queue`) mövcud olsun
    sid = getattr(args, "scan_id", None)
    if sid is None:
        row = db.latest_running_scan()
        if row is None:
            rows = db.get_db().execute(
                "SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
            sid = rows["id"] if rows else None
        else:
            sid = row["id"]
    if sid is None:
        print("[i] Heç bir skan tapılmadı")
        return EXIT_OK
    rows = db.load_followups(int(sid), status="pending")
    print(f"[i] Skan {sid}: {len(rows)} gözləyən davam testi")
    for r in rows:
        print(f"   #{r['id']} {r['proposed_action']} "
              f"(prereq={r['prerequisite_hash'] or '-'})")
    return EXIT_OK


async def run(args: argparse.Namespace) -> int:
    if getattr(args, "test_plan", False):
        import json
        from qbh import db
        from qbh.brain import store
        from qbh.brain.planner import BrainPlanner
        from qbh.redact import redact
        db.init_db()
        sid = args.scan_id
        if sid is None:
            row = db.get_db().execute("SELECT id FROM scans ORDER BY id DESC LIMIT 1").fetchone()
            sid = row['id'] if row else None
        if sid is None or db.get_scan(sid) is None:
            print("[!] Skan tapılmadı")
            return EXIT_USAGE
        cfg = Config.load(args.config)
        conductor = Conductor(cfg, args)
        conductor.ctx.scan_id = sid
        try:
            planner = BrainPlanner(conductor.ctx)
            rows = planner.prepare_scan()
            choice = args.approve or args.reject
            if choice:
                selected = [r['id'] for r in rows] if choice == '*' and args.approve else [choice]
                for plan_id in selected:
                    store.decide(plan_id, sid, approve=bool(args.approve), reason=redact(args.reason))
                if args.approve:
                    await conductor.ctx.initialize_auth()
                planner.prepare_scan()
                if args.approve:
                    await planner.execute_ready()
            print(json.dumps(store.list_plans(sid), ensure_ascii=False))
            return EXIT_OK
        except ValueError:
            print("[!] Plan və ya plan üçün tələb olunan sübut əlçatan deyil")
            return EXIT_USAGE
        finally:
            await conductor.ctx.aclose()
    if any(getattr(args, flag, False) for flag in ("import_har", "list_imported", "request_graph")):
        import json
        from qbh import db
        from qbh.ingest.har_importer import HarImporter, list_imported
        from qbh.ingest.request_graph import RequestGraph
        from qbh.vault import SecretVault
        db.init_db()
        if args.import_har:
            cfg = Config.load(args.config)
            vault = SecretVault.from_config(cfg)
            try:
                result = HarImporter(vault).import_file(args.import_har, args.scan_id)
                if vault.available:
                    RequestGraph(result['scan_id'], vault).infer()
                    from qbh.context import Context
                    from qbh.brain.planner import BrainPlanner
                    runtime = Context(cfg, args, None, scan_id=result['scan_id'])
                    runtime._vault = vault
                    await runtime.initialize_auth(offline=True)
                    from qbh.adaptive import note_evidence
                    from qbh.ingest.har_importer import digest
                    note_evidence(runtime, 'har_import_completed', digest(
                        [entry.get('request_id') for entry in result['entries']]))
                    result['feedback_plans'] = len(BrainPlanner(runtime).prepare_scan())
            except (ValueError, KeyError, TypeError):
                print("[!] HAR formatı və ya skan identifikatoru etibarsızdır")
                return EXIT_USAGE
            print(json.dumps(result, ensure_ascii=False))
            return EXIT_FAILURE if result['blocked'] or result['invalid'] else EXIT_OK
        nodes = list_imported(args.scan_id)
        if args.request_graph:
            scans = sorted({n['scan_id'] for n in nodes})
            print(json.dumps({'nodes': nodes, 'edges': [e for sid in scans for e in RequestGraph(sid).edges()]}, ensure_ascii=False))
        else:
            print(json.dumps(nodes, ensure_ascii=False))
        return EXIT_OK
    # Faza 2: davam-testləri sorğusu skan konfiqurasiyası olmadan da işləyir.
    if getattr(args, "pending_followups", False):
        return _show_pending_followups(args)

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

    if getattr(args, "resume", None) is not None:
        sid = int(args.resume)
        return await conductor.resume(None if sid <= 0 else sid)

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
    elif args.mode == "hunt":
        from qbh.hunter import Hunter

        await Hunter(conductor).hunt()

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
