"""Spec 010: edit a sent prompt (gateway side), custom Goose paths, native-root command."""
import asyncio
import os

from goose_web.hub import TRUNCATE
from tests import test_hub as th
from tests.test_hub import _fp_settled, _load, mk_client

env = th.env   # the hub tests' FakeAgent fixture


async def test_prompt_is_stamped_for_edit(env):
    agent, hub = env
    up = hub.upstream("alice", "alice")
    c1, s1 = mk_client()
    c2, s2 = mk_client()
    hub.attach(up, c1)
    hub.attach(up, c2)
    cwd = os.path.abspath("/ws")
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 1, "method": "session/new", "params": {"cwd": cwd}})
    sid = (await s1.wait_for(lambda m: m.get("id") == 1))["result"]["sessionId"]
    c2.watch.add(sid)
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 2, "method": "session/prompt",
                              "params": {"sessionId": sid, "prompt": [{"type": "text", "text": "hi"}]}})
    stamp = await s1.wait_for(lambda m: m.get("method") == "_gw/prompt_created")
    created = stamp["params"]["created"]
    assert stamp["params"]["sessionId"] == sid and isinstance(created, int) and created > 1_700_000_000
    echo = await s2.wait_for(lambda m: m.get("method") == "session/update" and
                             m["params"]["update"].get("sessionUpdate") == "user_message_chunk")
    assert echo["params"]["update"]["_meta"]["goose"]["created"] == created
    assert not any(m.get("method") == "_gw/prompt_created" for m in s2.msgs)     # only the sending tab


async def test_truncate_guard_and_buffer_invalidation(env):
    agent, hub = env
    up = hub.upstream("alice", "alice")
    c1, s1 = mk_client()
    c2, s2 = mk_client()
    hub.attach(up, c1)
    hub.attach(up, c2)
    agent.counts["t1"] = 4
    await _load(up, c1, s1, "t1", 1)
    await _fp_settled(up, "t1")
    s = up.sessions["t1"]
    assert s.loaded and s.buffer
    # refused while the chat runs (Goose itself does not check)
    s.prompts = 1
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 2, "method": TRUNCATE, "params": {"sessionId": "t1", "truncateFrom": 1762598040}})
    r = await s1.wait_for(lambda m: m.get("id") == 2)
    assert r["error"]["code"] == -32002 and "running" in r["error"]["message"]
    s.prompts = 0
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 3, "method": TRUNCATE, "params": {"sessionId": "t1", "truncateFrom": "x"}})
    assert (await s1.wait_for(lambda m: m.get("id") == 3))["error"]["code"] == -32602
    # success: buffer dropped, other tabs told to reload, the editing tab is not
    await up.from_client(c1, {"jsonrpc": "2.0", "id": 4, "method": TRUNCATE, "params": {"sessionId": "t1", "truncateFrom": 1762598040}})
    assert "result" in await s1.wait_for(lambda m: m.get("id") == 4)
    note = await s2.wait_for(lambda m: m.get("method") == "_gw/session_changed")
    assert note["params"] == {"sessionId": "t1", "reason": "truncated"}
    assert not any(m.get("method") == "_gw/session_changed" for m in s1.msgs)
    assert s.loaded is False and not s.buffer and s.load_result is None
    await _load(up, c1, s1, "t1", 5)                  # next load goes to Goose, not to the stale buffer
    assert agent.loads == 2
    await asyncio.sleep(0)


def test_native_root_command(tmp_path, monkeypatch, capsys):
    from goose_web.__main__ import main
    from goose_web.db import Database
    cfg = tmp_path / "config.yaml"
    cfg.write_text(f"paths:\n  profiles_root: \"{tmp_path.as_posix()}\"\n", encoding="utf-8")
    old = tmp_path / "old"
    (old / "config").mkdir(parents=True)
    (old / "config" / "config.yaml").write_text("{}", encoding="utf-8")
    new = tmp_path / "AI" / "Goose_appdata"
    (new / "config").mkdir(parents=True)
    (new / "config" / "config.yaml").write_text("{}", encoding="utf-8")
    assert main(["--config", str(cfg), "init", "--admin", "boss", "--password", "Long-enough-pw-1!", "--native-root", str(old)]) == 0
    db = Database(tmp_path / "_system" / "goose-web.db")
    iso = db.create_user(username="iso", display_name="iso", role="user", auth_source="local", password_hash="x",
                         must_change_pw=0, profile_mode="isolated", profile_path="")
    assert main(["--config", str(cfg), "native-root"]) == 0
    assert str(old) in capsys.readouterr().out
    assert main(["--config", str(cfg), "native-root", str(tmp_path / "missing")]) == 2
    assert main(["--config", str(cfg), "native-root", str(new / "config")]) == 0   # ...\config is accepted too
    out = capsys.readouterr().out
    assert "updated 1 native user(s): boss" in out and "GOOSE_PATH_ROOT=" in out
    db = Database(tmp_path / "_system" / "goose-web.db")
    assert db.get_setting("native_root") == str(new)
    assert db.user_by_name("boss")["profile_path"] == str(new)
    assert db.user_by_name("iso")["profile_mode"] == "isolated" and iso
    assert db.one("SELECT action FROM audit WHERE action='system.native_root'")


def test_auto_native_root_prefers_goose_path_root(tmp_path, monkeypatch):
    from goose_web.__main__ import _resolve_native_root
    custom = tmp_path / "Goose_appdata"
    (custom / "config").mkdir(parents=True)
    monkeypatch.setenv("GOOSE_PATH_ROOT", str(custom))
    assert _resolve_native_root("auto", None) == str(custom)


def test_no_author_specific_goose_path(monkeypatch):
    import goose_web.config as cfgmod
    seen = []
    monkeypatch.setattr(cfgmod.shutil, "which", lambda name: None)
    monkeypatch.setattr(cfgmod.os.path, "isfile", lambda p: seen.append(p) or False)
    assert cfgmod._find_goose() == "goose"
    assert seen and not any("dist-windows" in p for p in seen)
