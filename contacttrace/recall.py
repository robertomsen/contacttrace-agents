"""Cascade recall: revoke a source and find every skill version derived from it."""
from __future__ import annotations

import json
import shutil
import time
from collections import deque
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .store import LineageStore, default_home, src_node


@dataclass
class RecallReport:
    root: str
    affected_versions: list[int] = field(default_factory=list)
    affected_live_skills: list[str] = field(default_factory=list)
    paths: dict[str, list[str]] = field(default_factory=dict)  # skill -> chain back to the root


def _resolve(store: LineageStore, target: str) -> Optional[str]:
    if target.startswith(("src:", "ver:")):
        return target
    row = store.find_source(target)
    if row:
        return src_node(row["id"])
    # Allow partial match on a source ref (e.g. just the URL).
    hit = store.db.execute("SELECT id FROM sources WHERE ref LIKE ?", (f"%{target}%",)).fetchone()
    return src_node(hit["id"]) if hit else None


def descendants(store: LineageStore, root: str) -> dict[str, str]:
    """BFS over derivation edges. Returns node -> the parent through which it was reached."""
    seen: dict[str, str] = {root: ""}
    queue = deque([root])
    while queue:
        node = queue.popleft()
        for row in store.children(node):
            if row["child"] not in seen:
                seen[row["child"]] = node
                queue.append(row["child"])
    return seen


def plan_recall(store: LineageStore, target: str) -> RecallReport:
    root = _resolve(store, target)
    if root is None:
        raise ValueError(f"no source or version matches {target!r}")
    reached = descendants(store, root)
    report = RecallReport(root=root)
    live_latest = {r["skill"]: r["id"] for r in store.db.execute(
        "SELECT skill, MAX(id) AS id FROM skill_versions WHERE live=1 GROUP BY skill")}
    for node in reached:
        if not node.startswith("ver:"):
            continue
        vid = int(node.split(":")[1])
        report.affected_versions.append(vid)
        row = store.db.execute("SELECT skill FROM skill_versions WHERE id=?", (vid,)).fetchone()
        if row and live_latest.get(row["skill"]) == vid:
            report.affected_live_skills.append(row["skill"])
            chain, cur = [], node
            while cur:
                chain.append(store.describe(cur))
                cur = reached[cur]
            report.paths[row["skill"]] = chain
    report.affected_live_skills.sort()
    return report


def apply_recall(store: LineageStore, report: RecallReport, reason: str) -> list[str]:
    """Revoke the root and move affected live skills into a restorable quarantine."""
    store.revoke(report.root, reason)
    skills_root = default_home() / "skills"
    qdir = default_home() / "contacttrace" / "quarantine" / time.strftime("%Y%m%dT%H%M%S")
    moved = []
    for skill in report.affected_live_skills:
        for md in skills_root.rglob("SKILL.md") if skills_root.exists() else []:
            if md.parent.name == skill and ".archive" not in md.parts:
                dest = qdir / md.parent.relative_to(skills_root)
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.move(str(md.parent), str(dest))
                moved.append(skill)
                break
        store.mark_dead(skill)
    if moved:
        (qdir / "manifest.json").write_text(json.dumps(
            {"root": report.root, "reason": reason, "skills": moved,
             "paths": report.paths}, indent=2, ensure_ascii=False), encoding="utf-8")
    return moved
