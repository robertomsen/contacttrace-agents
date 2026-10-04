# ContactTrace

**Contact tracing for AI agent skills.**

Self-evolving agents like [Hermes Agent](https://github.com/NousResearch/hermes-agent) turn their
experience into persistent skills. When that experience is poisoned (a manipulated README, a
malicious web page), the poison becomes a skill, and every skill written later with it in context
can inherit it. Deleting the infected skill does not remove its descendants.

ContactTrace records who was in contact with whom, so one command finds and quarantines every
skill derived from a poisoned source, and leaves clean skills alone.

## What we observed with a real model (Hermes Agent, Oct 2026)
1. The agent read a manipulated vendor README and copied an injected instruction into a new skill without questioning it.
2. A naive injected step was dropped when skills were combined; the same marker disguised as a required API header survived into a second-generation skill.
3. Deleting the first infected skill left the second one infected.
4. `hermes contacttrace recall` found the surviving descendant through the deleted link, quarantined it, and kept the two clean skills untouched.

The "poison" in these tests is a harmless canary string.

## How it works
- **Capture**: every source a session reads (skills, web, files, terminal) is linked to each skill the session writes.
- **Trust inheritance**: a skill version's trust is the minimum of everything that influenced it; Curator merges (`absorbed_into`) carry trust into the umbrella.
- **Cascade recall**: revoke a source and every live descendant is listed (dry run) or moved to a restorable quarantine.
- **Tamper-evident log**: every event is hash-chained.

## Install
```
cp -r contacttrace ~/.hermes/plugins/contacttrace
hermes plugins enable contacttrace
hermes plugins validate ~/.hermes/plugins/contacttrace
```

## Commands
```
hermes contacttrace skills                   # live skills and inherited trust
hermes contacttrace trace <skill>            # where a skill came from
hermes contacttrace recall <source> [--apply]
hermes contacttrace verify
```

## Limitations (v0.1)
- Attribution is session-scoped: everything read in a session counts as a parent of every skill written later in it. It never hides contamination, but it over-recalls (we observed a clean descendant being flagged).
- Built-in Hermes skills get medium trust by default.
- Trust levels per tool category are hard-coded.

## Roadmap
- High trust for official built-in skills.
- Content-evidence check: confirm a flagged parent actually left a trace in the descendant before recalling it.

## License
MIT
