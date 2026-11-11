"""Spec 021 (1.16.1): the highest thinking effort by default, the engine hint for "Goose sends no effort for this
model", and `GOOSE_THINKING_EFFORT: max` for isolated profiles."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

import goose_web
from goose_web import effort
from goose_web.config import load_settings
from goose_web.db import Database
from goose_web.hub import PROVIDERS_LIST
from goose_web.profiles import Profiles

from test_team_profiles import ANYCHAT, team, user

JS = Path(goose_web.__file__).parent / "static" / "js"


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")   # GOOSE_WEB_CONFIG must exist (A-10)
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    db = Database(tmp_path / "gw.db")
    yield db, Profiles(load_settings(), db)
    db.close()


# ------------------------------------------------------------------ ranking (shared with chatoptions.js)
@pytest.mark.parametrize("values,top", [
    (["off", "low", "medium", "high", "max"], "max"),
    (["low", "high", "max"], "max"),                       # a low/high/max menu (Goose catalog, e.g. Kimi K3)
    (["off", "low", "medium", "high"], "high"),            # a model without max
    (["none", "minimal", "low", "medium", "high", "xhigh"], "xhigh"),
    (["off"], "off"),                                      # not a reasoning model: nothing to raise
    (["fast", "deep"], "deep"),                            # unknown names: the last one
    ([], ""),
])
def test_top_effort(values, top):
    assert effort.top_effort(values) == top


def test_rank_matches_frontend():
    js = (JS / "chatoptions.js").read_text(encoding="utf-8")
    m = re.search(r"EFFORT_RANK = \[([^\]]*)\]", js)
    assert m and [x.strip().strip("'") for x in m.group(1).split(",")] == list(effort.RANK)
    assert effort.DEFAULT_EFFORT == "max"


# ------------------------------------------------------------------ engines for providers/list
def test_provider_engines_and_annotation(tmp_path):
    cp = tmp_path / "custom_providers"
    cp.mkdir()
    (cp / "custom_gw.json").write_text(json.dumps({"name": "custom_gw", "engine": "openai", "models": []}))
    (cp / "custom_claude.json").write_text(json.dumps({"name": "custom_claude", "engine": "Anthropic"}))
    (cp / "broken.json").write_text("{not json")
    (cp / "list.json").write_text("[]")
    eng = effort.provider_engines(tmp_path)
    assert eng == {"custom_gw": "openai", "custom_claude": "anthropic"}
    assert effort.provider_engines(tmp_path / "missing") == {}
    res = {"entries": [{"providerId": "custom_gw"}, {"providerId": "openai"}, {"providerId": "custom_claude"},
                       {"providerId": "ollama"}, "junk"], "other": 1}
    out = effort.annotate_providers(res, eng)
    assert [e.get("gwEngine") if isinstance(e, dict) else e for e in out["entries"]] == \
        ["openai", "openai", "anthropic", None, "junk"]
    assert out["other"] == 1 and "gwEngine" not in res["entries"][0]       # input untouched
    assert effort.annotate_providers(None, eng) is None
    assert effort.annotate_providers({"x": 1}, eng) == {"x": 1}


def test_hub_annotates_providers_list_reply():
    hub = (Path(goose_web.__file__).parent / "hub.py").read_text(encoding="utf-8")
    assert PROVIDERS_LIST == "_goose/unstable/providers/list"
    assert "if method == PROVIDERS_LIST:" in hub and "self._with_engines(out[\"result\"])" in hub
    body = hub.split("def _with_engines", 1)[1].split("def _db_paths", 1)[0]
    assert "except Exception" in body and "return result" in body      # never fails the reply


# ------------------------------------------------------------------ provisioning (isolated profiles)
def test_provision_sets_max_and_keeps_a_saved_value(env, tmp_path):
    db, pr = env
    tid = team(db, "T", dict(ANYCHAT))
    u = user(db, "dora")
    db.set_user_team(u["id"], tid)
    changes = pr.provision(u)
    cfgp = tmp_path / "profiles" / "dora" / "config" / "config.yaml"
    assert yaml.safe_load(cfgp.read_text())["GOOSE_THINKING_EFFORT"] == "max"
    assert "thinking effort max (default)" in changes
    assert "thinking effort max (default)" not in pr.provision(u)          # idempotent
    cfg = yaml.safe_load(cfgp.read_text())
    cfg["GOOSE_THINKING_EFFORT"] = "low"                                   # the member's own preference
    cfgp.write_text(yaml.safe_dump(cfg))
    pr.provision(u)
    assert yaml.safe_load(cfgp.read_text())["GOOSE_THINKING_EFFORT"] == "low"


# ------------------------------------------------------------------ front end
def test_frontend_wiring():
    co = (JS / "chatoptions.js").read_text(encoding="utf-8")
    home = (JS / "views" / "home.js").read_text(encoding="utf-8")
    chat = (JS / "views" / "chat.js").read_text(encoding="utf-8")
    # no explicit effort -> the highest offered level is applied to the new chat
    apply = co.split("export async function applyNewChatOptions", 1)[1]
    assert "topEffort(flat(o))" in apply and "chat.setConfig(o.id, top)" in apply
    # applyChoice always runs (no early return when nothing was picked)
    assert "if (!choice.provider && !choice.model && !choice.effort && !choice.mode) return;" not in home
    assert "'Default effort (' +" in home and "effortNote(" in home
    assert "engine: e.gwEngine" in co and "rememberEngines(providers)" in co
    assert "effortNote(" in chat


def _node():
    n = shutil.which("node") or str(Path(os.environ.get("LOCALAPPDATA", "")) / "Goose" / "node" / "node.exe")
    return n if Path(n).is_file() else None


def test_frontend_rules_in_node():
    node = _node()
    if not node:
        pytest.skip("node not available")
    co = (JS / "chatoptions.js").read_text(encoding="utf-8")
    block = co.split("// ----- spec 021", 1)[1].split("\n", 1)[1].split("const ENGINE_KEY", 1)[0].replace("export ", "")
    script = block + (
        "console.log(JSON.stringify(["
        "topEffort([{value:'off'},{value:'low'},{value:'high'},{value:'max'}]), topEffort(['low','medium','high']),"
        "topEffort(['off']), topEffort([]),"
        "effortSent('openai','qwen3-max'), effortSent('openai','deepseek-v4.1-flash'),"
        "effortSent('openai','gpt-5.4'), effortSent('openai','o3-mini'), effortSent('openai','grok-4.3'),"
        "effortSent('anthropic','claude-opus-5-5'), effortSent('','qwen3-max'), effortSent('openai','gemma-4-31b')"
        "]));")
    r = subprocess.run([node, "--input-type=module", "-e", script], capture_output=True, text=True, timeout=60)
    assert r.returncode == 0, r.stderr
    assert json.loads(r.stdout.strip().splitlines()[-1]) == [
        "max", "high", "off", "", False, False, True, True, True, True, True, False]
