"""SQLite lineage store with a tamper-evident hash-chained event log."""
from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Optional

# Trust levels: lower is worse. A version's trust is the minimum of its parents.
TRUST_COMPROMISED, TRUST_LOW, TRUST_MEDIUM, TRUST_HIGH = 0, 1, 2, 3
TRUST_NAMES = {0: "compromised", 1: "low", 2: "medium", 3: "high"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS sources (
  id INTEGER PRIMARY KEY, kind TEXT NOT NULL, ref TEXT NOT NULL, trust INTEGER NOT NULL,
  first_seen REAL NOT NULL, UNIQUE(kind, ref));
CREATE TABLE IF NOT EXISTS session_context (
  session_id TEXT NOT NULL, node TEXT NOT NULL, ts REAL NOT NULL, PRIMARY KEY(session_id, node));
CREATE TABLE IF NOT EXISTS skill_versions (
  id INTEGER PRIMARY KEY, skill TEXT NOT NULL, action TEXT NOT NULL, session_id TEXT,
  origin TEXT, ts REAL NOT NULL, content_hash TEXT, trust INTEGER NOT NULL, live INTEGER NOT NULL DEFAULT 1);
CREATE TABLE IF NOT EXISTS edges (
  child TEXT NOT NULL, parent TEXT NOT NULL, relation TEXT NOT NULL, PRIMARY KEY(child, parent, relation));
CREATE TABLE IF NOT EXISTS revoked (node TEXT PRIMARY KEY, reason TEXT, ts REAL NOT NULL);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY, ts REAL NOT NULL, type TEXT NOT NULL, payload TEXT NOT NULL,
  prev_hash TEXT NOT NULL, hash TEXT NOT NULL);
"""


def default_home() -> Path:
    try:
        from hermes_constants import get_hermes_home  # type: ignore
        return Path(get_hermes_home())
    except Exception:
        return Path(os.environ.get("HERMES_HOME", Path.home() / ".hermes"))


def src_node(source_id: int) -> str:
    return f"src:{source_id}"


def ver_node(version_id: int) -> str:
    return f"ver:{version_id}"


class LineageStore:
    def __init__(self, path: Optional[Path] = None):
        self.path = Path(path) if path else default_home() / "contacttrace" / "lineage.db"
        self.path.parent.mkdir(parents=True, exist_ok=True)
        legacy = default_home() / "skill_lineage" / "lineage.db"
        if path is None and not self.path.exists() and legacy.exists():
            import shutil  # one-time migration from the pre-rename "skill-lineage" plugin
            shutil.copy2(legacy, self.path)
        self._lock = threading.Lock()
        self.db = sqlite3.connect(str(self.path), check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.executescript(SCHEMA)
        self.db.commit()

    # ---------- integrity ----------
    def _log(self, type_: str, payload: dict) -> None:
        row = self.db.execute("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").fetchone()
        prev = row["hash"] if row else "genesis"
        body = json.dumps(payload, sort_keys=True, ensure_ascii=False)
        ts = time.time()
        h = hashlib.sha256(f"{prev}|{ts}|{type_}|{body}".encode()).hexdigest()
        self.db.execute("INSERT INTO events(ts,type,payload,prev_hash,hash) VALUES(?,?,?,?,?)",
                        (ts, type_, body, prev, h))

    def verify_chain(self) -> tuple[bool, int]:
        prev = "genesis"
        n = 0
        for r in self.db.execute("SELECT * FROM events ORDER BY seq"):
            h = hashlib.sha256(f"{prev}|{r['ts']}|{r['type']}|{r['payload']}".encode()).hexdigest()
            if r["prev_hash"] != prev or r["hash"] != h:
                return False, r["seq"]
            prev, n = h, n + 1
        return True, n

    # ---------- sources & context ----------
    def upsert_source(self, kind: str, ref: str, trust: int) -> int:
        with self._lock:
            row = self.db.execute("SELECT id FROM sources WHERE kind=? AND ref=?", (kind, ref)).fetchone()
            if row:
                return row["id"]
            cur = self.db.execute("INSERT INTO sources(kind,ref,trust,first_seen) VALUES(?,?,?,?)",
                                  (kind, ref, trust, time.time()))
            self._log("source", {"id": cur.lastrowid, "kind": kind, "ref": ref, "trust": trust})
            self.db.commit()
            return cur.lastrowid

    def add_context(self, session_id: str, node: str) -> None:
        with self._lock:
            self.db.execute("INSERT OR IGNORE INTO session_context VALUES(?,?,?)",
                            (session_id or "", node, time.time()))
            self.db.commit()

    def session_context(self, session_id: str) -> list[str]:
        return [r["node"] for r in self.db.execute(
            "SELECT node FROM session_context WHERE session_id=?", (session_id or "",))]

    # ---------- skill versions ----------
    def latest_version(self, skill: str) -> Optional[sqlite3.Row]:
        return self.db.execute(
            "SELECT * FROM skill_versions WHERE skill=? ORDER BY id DESC LIMIT 1", (skill,)).fetchone()

    def node_trust(self, node: str) -> int:
        kind, _, ident = node.partition(":")
        table = "sources" if kind == "src" else "skill_versions"
        row = self.db.execute(f"SELECT trust FROM {table} WHERE id=?", (int(ident),)).fetchone()
        return row["trust"] if row else TRUST_LOW

    def add_version(self, skill: str, action: str, session_id: str, origin: str,
                    content_hash: Optional[str], parents: Iterable[tuple[str, str]],
                    live: bool = True, trust: Optional[int] = None) -> int:
        parents = list(dict.fromkeys(parents))
        if trust is None:
            trust = min([self.node_trust(p) for p, _ in parents], default=TRUST_HIGH)
        with self._lock:
            cur = self.db.execute(
                "INSERT INTO skill_versions(skill,action,session_id,origin,ts,content_hash,trust,live)"
                " VALUES(?,?,?,?,?,?,?,?)",
                (skill, action, session_id, origin, time.time(), content_hash, trust, int(live)))
            vid = cur.lastrowid
            for parent, rel in parents:
                self.db.execute("INSERT OR IGNORE INTO edges VALUES(?,?,?)", (ver_node(vid), parent, rel))
            self._log("version", {"id": vid, "skill": skill, "action": action, "session": session_id,
                                  "origin": origin, "hash": content_hash, "trust": trust,
                                  "parents": parents})
            self.db.commit()
            return vid

    def add_edge(self, child: str, parent: str, relation: str) -> None:
        with self._lock:
            self.db.execute("INSERT OR IGNORE INTO edges VALUES(?,?,?)", (child, parent, relation))
            self._log("edge", {"child": child, "parent": parent, "relation": relation})
            self.db.commit()

    def lower_trust(self, version_id: int, trust: int) -> None:
        with self._lock:
            self.db.execute("UPDATE skill_versions SET trust=MIN(trust,?) WHERE id=?", (trust, version_id))
            self.db.commit()

    def mark_dead(self, skill: str) -> None:
        with self._lock:
            self.db.execute("UPDATE skill_versions SET live=0 WHERE skill=?", (skill,))
            self.db.commit()

    # ---------- graph queries ----------
    def children(self, node: str) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT child, relation FROM edges WHERE parent=?", (node,)))

    def parents(self, node: str) -> list[sqlite3.Row]:
        return list(self.db.execute("SELECT parent, relation FROM edges WHERE child=?", (node,)))

    def find_source(self, ref: str) -> Optional[sqlite3.Row]:
        return self.db.execute("SELECT * FROM sources WHERE ref=?", (ref,)).fetchone()

    def revoke(self, node: str, reason: str) -> None:
        with self._lock:
            self.db.execute("INSERT OR REPLACE INTO revoked VALUES(?,?,?)", (node, reason, time.time()))
            self._log("revoke", {"node": node, "reason": reason})
            self.db.commit()

    def describe(self, node: str) -> str:
        kind, _, ident = node.partition(":")
        if kind == "src":
            r = self.db.execute("SELECT * FROM sources WHERE id=?", (int(ident),)).fetchone()
            return f"{r['kind']}:{r['ref']}" if r else node
        r = self.db.execute("SELECT * FROM skill_versions WHERE id=?", (int(ident),)).fetchone()
        return f"skill {r['skill']} (v{r['id']}, {r['action']})" if r else node
