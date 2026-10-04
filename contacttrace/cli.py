"""`hermes contacttrace ...` subcommands."""
from __future__ import annotations

import argparse

from .recall import apply_recall, plan_recall
from .store import TRUST_NAMES, LineageStore


def setup(parser: argparse.ArgumentParser) -> None:
    sub = parser.add_subparsers(dest="lineage_cmd", required=True)
    sub.add_parser("skills", help="List live skills with their inherited trust")
    p = sub.add_parser("trace", help="Show where a skill came from")
    p.add_argument("skill")
    p = sub.add_parser("recall", help="Revoke a source and everything derived from it")
    p.add_argument("target", help="source ref (e.g. a URL), src:<id> or ver:<id>")
    p.add_argument("--apply", action="store_true", help="quarantine affected skills (default: dry run)")
    p.add_argument("--reason", default="manually revoked")
    sub.add_parser("verify", help="Check the tamper-evident event log")


def _trace(store: LineageStore, node: str, depth: int = 0, seen=None) -> None:
    seen = seen if seen is not None else set()
    print("  " * depth + "- " + store.describe(node) + f"  [{TRUST_NAMES[store.node_trust(node)]}]")
    if node in seen:
        return
    seen.add(node)
    for row in store.parents(node):
        print("  " * (depth + 1) + f"({row['relation']})")
        _trace(store, row["parent"], depth + 1, seen)


def handle(args: argparse.Namespace) -> int:
    store = LineageStore()
    if args.lineage_cmd == "skills":
        for r in store.db.execute("SELECT skill, MAX(id) id, trust FROM skill_versions "
                                  "WHERE live=1 GROUP BY skill ORDER BY skill"):
            print(f"{r['skill']:<32} {TRUST_NAMES[r['trust']]}")
    elif args.lineage_cmd == "trace":
        row = store.latest_version(args.skill)
        if not row:
            print(f"no lineage recorded for {args.skill}")
            return 1
        _trace(store, f"ver:{row['id']}")
    elif args.lineage_cmd == "recall":
        report = plan_recall(store, args.target)
        print(f"Root: {store.describe(report.root)}")
        print(f"Derived versions: {len(report.affected_versions)}; live skills affected: "
              f"{len(report.affected_live_skills)}")
        for skill, chain in report.paths.items():
            print(f"  * {skill}:  " + "  <-  ".join(chain))
        if args.apply:
            moved = apply_recall(store, report, args.reason)
            print(f"Quarantined: {', '.join(moved) or 'none on disk'}")
        else:
            print("Dry run. Re-run with --apply to quarantine.")
    elif args.lineage_cmd == "verify":
        ok, n = store.verify_chain()
        print(f"event log {'intact' if ok else 'TAMPERED at seq ' + str(n)} ({n} events)")
        return 0 if ok else 2
    return 0
