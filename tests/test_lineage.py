"""End-to-end scenario: a poisoned web page infects skills, directly and by inheritance."""
import os
import sqlite3
from pathlib import Path

import pytest

from contacttrace.observer import Observer
from contacttrace.recall import apply_recall, plan_recall
from contacttrace.store import TRUST_LOW, TRUST_MEDIUM, LineageStore

EVIL = "https://evil.example/deploy-tips"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("HERMES_HOME", str(tmp_path))
    store = LineageStore(tmp_path / "contacttrace" / "lineage.db")
    return tmp_path, store, Observer(store)


def write_skill(home: Path, name: str, body: str = "x") -> None:
    d = home / "skills" / "devops" / name
    d.mkdir(parents=True, exist_ok=True)
    (d / "SKILL.md").write_text(f"---\nname: {name}\n---\n{body}\n")


def create(obs, home, sid, name):
    write_skill(home, name)
    obs.on_post_tool_call(tool_name="skill_manage", session_id=sid, status="ok",
                          args={"operations": [{"action": "create", "name": name, "content": "..."}]})


def build_scenario(home, obs):
    # S1: trusted local work -> deploy-checks
    obs.on_post_tool_call(tool_name="read_file", session_id="s1", args={"path": "docs/deploy.md"})
    create(obs, home, "s1", "deploy-checks")
    # S2: agent reads a poisoned page -> api-helper
    obs.on_post_tool_call(tool_name="web_extract", session_id="s2", args={"urls": [EVIL]})
    create(obs, home, "s2", "api-helper")
    # S3: agent consults both skills -> release-flow (inherits the poison silently)
    obs.on_post_tool_call(tool_name="skill_view", session_id="s3", args={"name": "api-helper"})
    obs.on_post_tool_call(tool_name="skill_view", session_id="s3", args={"name": "deploy-checks"})
    create(obs, home, "s3", "release-flow")
    # S4: only consults the clean skill -> lint-rules
    obs.on_post_tool_call(tool_name="skill_view", session_id="s4", args={"name": "deploy-checks"})
    create(obs, home, "s4", "lint-rules")
    # Curator merges deploy-checks into a new umbrella "shipping"
    obs.on_post_tool_call(tool_name="skill_view", session_id="cur", args={"name": "deploy-checks"})
    create(obs, home, "cur", "shipping")
    obs.on_post_tool_call(tool_name="skill_manage", session_id="cur", status="ok", args={
        "operations": [{"action": "delete", "name": "deploy-checks", "absorbed_into": "shipping"}]})


def test_trust_is_inherited(env):
    home, store, obs = env
    build_scenario(home, obs)
    trust = {r["skill"]: r["trust"] for r in store.db.execute(
        "SELECT skill, trust FROM skill_versions WHERE action='create'")}
    assert trust["api-helper"] == TRUST_LOW
    assert trust["release-flow"] == TRUST_LOW      # never touched the web, still low
    assert trust["lint-rules"] == TRUST_MEDIUM


def test_source_only_deletion_leaves_infection(env):
    """The baseline defenders use today: delete the skill that read the bad page."""
    home, store, obs = env
    build_scenario(home, obs)
    obs.on_post_tool_call(tool_name="skill_manage", session_id="ops", status="ok",
                          args={"operations": [{"action": "delete", "name": "api-helper"}]})
    report = plan_recall(store, EVIL)
    assert report.affected_live_skills == ["release-flow"]   # still alive and infected


def test_cascade_recall(env):
    home, store, obs = env
    build_scenario(home, obs)
    report = plan_recall(store, EVIL)
    assert report.affected_live_skills == ["api-helper", "release-flow"]
    moved = apply_recall(store, report, "poisoned page")
    assert sorted(moved) == ["api-helper", "release-flow"]
    remaining = {p.parent.name for p in (home / "skills").rglob("SKILL.md")}
    assert remaining == {"deploy-checks", "lint-rules", "shipping"}
    assert (home / "contacttrace" / "quarantine").exists()


def test_absorption_carries_taint(env):
    home, store, obs = env
    build_scenario(home, obs)
    # If the clean local doc later turns out to be bad, the merged umbrella must be recalled too.
    report = plan_recall(store, "docs/deploy.md")
    assert {"shipping", "lint-rules", "release-flow"} <= set(report.affected_live_skills)


def test_event_log_detects_tampering(env):
    home, store, obs = env
    build_scenario(home, obs)
    assert store.verify_chain()[0]
    store.db.execute("UPDATE events SET payload='{}' WHERE seq=3")
    store.db.commit()
    assert store.verify_chain() == (False, 3)


def test_observer_never_raises(env):
    _, _, obs = env
    obs.on_post_tool_call(tool_name="skill_manage", args="garbage", session_id=None)
    obs.on_post_tool_call(tool_name="skill_view", args={"name": None})
