"""Turns Hermes tool calls into lineage: what a session read, and what it wrote."""
from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Any, Optional

from .store import (TRUST_HIGH, TRUST_LOW, TRUST_MEDIUM, LineageStore, default_home,
                    src_node, ver_node)

logger = logging.getLogger(__name__)

# Conservative defaults: anything fetched from outside the machine is low trust.
WEB_TOOLS = {"web_search", "web_extract", "x_search", "browser_cdp", "browser_exec", "browser_dialog"}
LOCAL_TOOLS = {"read_file", "search_files", "terminal", "read_terminal", "execute_code", "session_search"}
VERSIONING_ACTIONS = {"create", "patch", "edit", "write_file", "remove_file"}
REMOVING_ACTIONS = {"delete", "archive", "purge"}


def _origin() -> str:
    try:
        from tools.skill_provenance import get_current_write_origin  # type: ignore
        return get_current_write_origin()
    except Exception:
        return "unknown"


def _skill_md_hash(skill: str) -> Optional[str]:
    root = default_home() / "skills"
    if not root.exists():
        return None
    for md in root.rglob("SKILL.md"):
        if md.parent.name == skill and ".archive" not in md.parts:
            return hashlib.sha256(md.read_bytes()).hexdigest()[:16]
    return None


def _ops(args: dict) -> list[dict]:
    ops = args.get("operations")
    if isinstance(ops, list):
        return [o for o in ops if isinstance(o, dict)]
    if args.get("action"):  # legacy flat shape
        return [args]
    return []


def _web_ref(tool: str, args: dict) -> str:
    for key in ("url", "urls", "query"):
        val = args.get(key)
        if val:
            return f"{tool}:{val if isinstance(val, str) else ','.join(map(str, val))}"
    return f"{tool}:{sorted(args.items())!r}"[:300]


class Observer:
    def __init__(self, store: Optional[LineageStore] = None):
        self.store = store or LineageStore()

    def _skill_node(self, skill: str) -> str:
        """Node for the current version of a skill; unknown skills get a baseline version."""
        row = self.store.latest_version(skill)
        if row is None:
            vid = self.store.add_version(skill, "baseline", "", "baseline", _skill_md_hash(skill),
                                         parents=[], trust=TRUST_MEDIUM)
            return ver_node(vid)
        return ver_node(row["id"])

    # ---- hook entry point ----
    def on_post_tool_call(self, tool_name: str = "", args: Any = None, result: Any = None,
                          session_id: Optional[str] = None, status: Optional[str] = None,
                          **_: Any) -> None:
        try:
            args = args if isinstance(args, dict) else {}
            sid = session_id or ""
            if tool_name == "skill_view" and args.get("name"):
                self.store.add_context(sid, self._skill_node(str(args["name"])))
            elif tool_name in WEB_TOOLS:
                s = self.store.upsert_source("web", _web_ref(tool_name, args), TRUST_LOW)
                self.store.add_context(sid, src_node(s))
            elif tool_name in LOCAL_TOOLS:
                ref = args.get("path") or args.get("command") or args.get("query") or tool_name
                s = self.store.upsert_source("local", f"{tool_name}:{ref}"[:300], TRUST_MEDIUM)
                self.store.add_context(sid, src_node(s))
            elif tool_name == "skill_manage" and status != "error":
                self._on_skill_write(sid, args)
        except Exception as e:  # observer must never break the agent
            logger.warning("contacttrace: failed to record %s (%s)", tool_name, e)

    def _on_skill_write(self, sid: str, args: dict) -> None:
        origin = _origin()
        context = [(n, "context") for n in self.store.session_context(sid)]
        ops = _ops(args)
        # Modifications first, removals after, so absorptions point at the new umbrella version.
        for op in [o for o in ops if o.get("action") in VERSIONING_ACTIONS]:
            skill = str(op.get("name", ""))
            prev = self.store.latest_version(skill)
            parents = list(context)
            if prev is not None:
                parents.append((ver_node(prev["id"]), "previous"))
            own = ver_node(prev["id"]) if prev is not None else None
            parents = [p for p in parents if p[0] != own or p[1] == "previous"]
            vid = self.store.add_version(skill, op["action"], sid, origin, _skill_md_hash(skill), parents)
            self.store.add_context(sid, ver_node(vid))
        for op in [o for o in ops if o.get("action") in REMOVING_ACTIONS]:
            skill = str(op.get("name", ""))
            prev = self.store.latest_version(skill)
            into = op.get("absorbed_into")
            if prev is not None and into:
                umbrella = self.store.latest_version(str(into))
                if umbrella is not None:
                    self.store.add_edge(ver_node(umbrella["id"]), ver_node(prev["id"]), "absorbed")
                    self.store.lower_trust(umbrella["id"], prev["trust"])
            self.store.mark_dead(skill)
