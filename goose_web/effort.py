"""Thinking effort defaults (spec 021, goose-web 1.16.1).

- New chats start at the HIGHEST effort Goose offers for the chosen provider and model (`max`, else the top of the
  offered list); an explicit choice wins. The ranking below is shared with the front end (chatoptions.js).
- Isolated profiles are provisioned with `GOOSE_THINKING_EFFORT: max` (profiles.py) when they have no value.
- Goose sends an effort field only for some provider/model pairs. On the OpenAI engine it sends one only for OpenAI
  reasoning models (and xAI Grok); a GLM or DeepSeek model behind an OpenAI-compatible gateway gets NO effort field,
  whatever the picker says. For those, the effort is a static per-model `request_params` entry in the custom
  provider file. The front end needs each provider's engine to say so; `providers/list` does not carry it, so the
  gateway adds `gwEngine` from the profile's `custom_providers/*.json` (read-only).
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("goose_web.effort")

DEFAULT_EFFORT = "max"
# Goose's levels plus the provider-specific names Goose may offer (OpenAI catalog, ACP agents), lowest first.
RANK = ("off", "none", "minimal", "low", "medium", "high", "xhigh", "max")
# Built-in Goose providers whose engine is the OpenAI chat format.
BUILTIN_ENGINES = {"openai": "openai"}
MAX_PROVIDER_FILES = 200
MAX_PROVIDER_BYTES = 1_000_000


def top_effort(values: Iterable[str]) -> str:
    """The highest of the offered values by RANK; unknown names only if nothing is known (then the last one)."""
    vals = [str(v) for v in values if v not in (None, "")]
    known = [v for v in vals if v.lower() in RANK]
    if known:
        return max(known, key=lambda v: RANK.index(v.lower()))
    return vals[-1] if vals else ""


def provider_engines(config_dir: str | Path) -> dict[str, str]:
    """{provider id: engine} for the custom providers in `<config_dir>/custom_providers`. Read-only; bad files skipped."""
    out: dict[str, str] = {}
    d = Path(config_dir) / "custom_providers"
    try:
        files = sorted(d.glob("*.json"))[:MAX_PROVIDER_FILES]
    except OSError:
        return out
    for f in files:
        try:
            if f.stat().st_size > MAX_PROVIDER_BYTES:
                continue
            j = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if not isinstance(j, dict):
            continue
        name = str(j.get("name") or f.stem)
        engine = j.get("engine")
        if isinstance(engine, str) and engine:
            out[name] = engine.lower()
    return out


def annotate_providers(result: Any, engines: dict[str, str]) -> Any:
    """Add `gwEngine` to the entries of a `providers/list` result (a new dict; the input is not changed)."""
    if not isinstance(result, dict) or not isinstance(result.get("entries"), list):
        return result
    entries = []
    for e in result["entries"]:
        if isinstance(e, dict):
            pid = str(e.get("providerId") or "")
            eng = engines.get(pid) or BUILTIN_ENGINES.get(pid)
            if eng:
                e = {**e, "gwEngine": eng}
        entries.append(e)
    return {**result, "entries": entries}
