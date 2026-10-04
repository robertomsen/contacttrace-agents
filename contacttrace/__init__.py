"""contacttrace: provenance, trust inheritance and cascade recall for self-evolving Hermes skills."""
from __future__ import annotations

from .observer import Observer

_observer: Observer | None = None


def _get() -> Observer:
    global _observer
    if _observer is None:
        _observer = Observer()
    return _observer


def _on_post_tool_call(**kwargs):
    _get().on_post_tool_call(**kwargs)


def register(ctx) -> None:
    from . import cli
    ctx.register_hook("post_tool_call", _on_post_tool_call)
    ctx.register_cli_command("contacttrace", "Contact tracing for agent skills: provenance and cascade recall",
                             cli.setup, cli.handle)
