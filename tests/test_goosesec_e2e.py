"""Spec 026 end to end with the REAL goose binary (skipped unless GOOSE_WEB_TEST_GOOSE names goose.exe).

    set GOOSE_WEB_TEST_GOOSE=C:\\path\\to\\goose.exe
    python -m pytest tests/test_goosesec_e2e.py -q

Run it after every Goose upgrade: it proves, with Goose Web's own code and no credentials or model cost, that
  1. a member profile written by Profiles.provision makes Goose ask Goose Web's classification endpoint, with the
     profile's token from the profile's secret store, and accept the answer;
  2. the worker environment keeps detection on when the profile's config.yaml was edited to switch it off;
  3. an adversary.md written by Profiles.provision makes Goose ask the reviewer, and a BLOCK stops the call;
  4. goosesec.apply_native sets, reads back and removes the settings through Goose's own configuration API
     (`goose acp`, _goose/unstable/config/*), the secret ending up in Goose's secret store and not in config.yaml.

The model is a local fake (an OpenAI-compatible server that asks for one `echo` through the shell tool); the chat
folder and the Goose profile are temporary. Every command is an `echo` into a marker file.
"""
import asyncio
import json
import os
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import yaml

from goose_web import classifyapi as CA
from goose_web import goosesec as GS
from goose_web import guard as G
from goose_web.hub import INIT_PARAMS

import test_team_profiles as _tp
from test_classifyapi import FakeClassifier
from test_goosesec import member

GOOSE = os.environ.get("GOOSE_WEB_TEST_GOOSE", "")
pytestmark = pytest.mark.skipif(not (GOOSE and os.path.isfile(GOOSE)),
                                reason="set GOOSE_WEB_TEST_GOOSE to goose.exe to run the real-Goose checks")
env = _tp.env
REVIEWER = "adversarial security reviewer"


class Model:
    """A fake OpenAI-compatible provider: one shell call (`command`), then "Done."; ALLOW/BLOCK for the reviewer."""

    def __init__(self):
        self.command, self.verdict, self.reviews, self.tool_results, self.tools = "echo x", "ALLOW", 0, [], []
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def _send(self, obj):
                raw = json.dumps(obj).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                self._send({"object": "list", "data": [{"id": "fake-model", "object": "model"}]})

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
                msgs = body.get("messages") or []
                system = " ".join(str(m.get("content")) for m in msgs if m.get("role") in ("system", "developer"))
                names = [(t.get("function") or {}).get("name", "") for t in body.get("tools") or []]
                tool_msgs = [m for m in msgs if m.get("role") == "tool"]
                if REVIEWER in system.lower():
                    outer.reviews += 1
                    msg, finish = {"role": "assistant", "content": f"{outer.verdict}\ntest verdict"}, "stop"
                elif tool_msgs or "shell" not in names:
                    if tool_msgs:
                        outer.tool_results.append(str(tool_msgs[-1].get("content"))[:300])
                    msg, finish = {"role": "assistant", "content": "Done."}, "stop"
                else:
                    outer.tools = names
                    call = {"id": "call_1", "type": "function",
                            "function": {"name": "shell", "arguments": json.dumps({"command": outer.command})}}
                    msg, finish = {"role": "assistant", "content": None, "tool_calls": [call]}, "tool_calls"
                self._send({"id": "c", "object": "chat.completion", "created": int(time.time()), "model": "fake-model",
                            "choices": [{"index": 0, "message": msg, "finish_reason": finish}],
                            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})

        self.srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def close(self):
        self.srv.shutdown()


@pytest.fixture
def model():
    m = Model()
    yield m
    m.close()


def add_fake_provider(config_dir: Path, port: int, **config) -> None:
    """What a team provider item would add to the profile, plus the developer extension (the `shell` tool)."""
    cfg = yaml.safe_load((config_dir / "config.yaml").read_text(encoding="utf-8")) or {}
    cfg.update({"GOOSE_PROVIDER": "custom_fake", "GOOSE_MODEL": "fake-model", "GOOSE_MODE": "auto", **config})
    cfg.setdefault("extensions", {})["developer"] = {"enabled": True, "type": "platform", "name": "developer",
                                                    "display_name": "Developer", "bundled": True,
                                                    "description": "Write and edit files, and execute shell commands"}
    (config_dir / "config.yaml").write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
    sp = config_dir / "secrets.yaml"
    sec = (yaml.safe_load(sp.read_text(encoding="utf-8")) or {}) if sp.exists() else {}
    sec["CUSTOM_FAKE_API_KEY"] = "not-a-real-key"
    sp.write_text(yaml.safe_dump(sec), encoding="utf-8")
    (config_dir / "custom_providers").mkdir(exist_ok=True)
    (config_dir / "custom_providers" / "custom_fake.json").write_text(json.dumps({
        "name": "custom_fake", "engine": "openai", "display_name": "Fake", "description": "test",
        "api_key_env": "CUSTOM_FAKE_API_KEY", "base_url": f"http://127.0.0.1:{port}/v1",
        "models": [{"name": "fake-model", "context_limit": 32000}], "supports_streaming": False,
        "requires_auth": True, "timeout_seconds": 60}), encoding="utf-8")


def goose_env(root: Path, extra: dict | None = None) -> dict:
    e = {k: v for k, v in os.environ.items() if not k.upper().startswith(("GOOSE_", "SECURITY_"))
         and k.upper() not in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
    e.update({"GOOSE_PATH_ROOT": str(root), "GOOSE_DISABLE_KEYRING": "1", "GOOSE_DISABLE_SESSION_NAMING": "true",
              "NO_PROXY": "127.0.0.1,localhost", **(extra or {})})
    return e


async def run_goose(root: Path, work: Path, extra: dict | None = None) -> str:
    def go():
        p = subprocess.run([GOOSE, "run", "--no-session", "--max-turns", "6", "-t",
                            "Test prompt: run the echo command you were given, then say Done."],
                           cwd=str(work), env=goose_env(root, extra), stdin=subprocess.DEVNULL, capture_output=True,
                           timeout=180)
        return (p.stdout + b"\n" + p.stderr).decode("utf-8", "replace")
    return await asyncio.to_thread(go)


async def listener(s, db):
    svc = CA.ClassifyService(s, db, G.GuardService(s, db, classifier=FakeClassifier()), ephemeral=True)
    await svc.start()
    assert svc.listening
    return svc


async def test_goose_asks_the_gateway_endpoint_with_the_profile_token(env, model, tmp_path):
    s, db, pr, c = env
    svc = await listener(s, db)
    try:
        pr.security_endpoint = lambda: svc.endpoint
        alice = member(db)
        pr.provision(alice)
        cdir = pr.config_dir(alice)
        add_fake_provider(cdir, model.port)
        work = tmp_path / "work"
        work.mkdir()
        model.command = "echo e2e-ok > marker1.txt"
        out = await run_goose(pr.root_for(alice), work)
        assert (work / "marker1.txt").exists(), out[-800:]
        assert "shell" in model.tools                                      # the tool Goose inspects is named `shell`
        st = svc.stats
        assert st["ok"] >= 1 and st["unauthorized"] == 0 and st["bad"] == 0, (st, out[-800:])
        # the profile's file switched off by hand, the worker's environment still on (R4)
        before = svc.stats["ok"]
        add_fake_provider(cdir, model.port, SECURITY_PROMPT_ENABLED=False, SECURITY_PROMPT_CLASSIFIER_ENABLED=False)
        sec = yaml.safe_load((cdir / "secrets.yaml").read_text(encoding="utf-8"))
        sec.pop(GS.CLS_TOKEN)
        (cdir / "secrets.yaml").write_text(yaml.safe_dump(sec), encoding="utf-8")
        model.command = "echo e2e-ok > marker2.txt"
        await run_goose(pr.root_for(alice), work)                          # no environment: detection really is off
        assert (work / "marker2.txt").exists() and svc.stats["ok"] == before
        model.command = "echo e2e-ok > marker3.txt"
        out = await run_goose(pr.root_for(alice), work, pr.security_plan(alice)["env"])
        assert (work / "marker3.txt").exists() and svc.stats["ok"] > before and svc.stats["unauthorized"] == 0, out[-800:]
        # a wrong token: Goose is refused, logs it, and still runs the call on its patterns (fail open, S5)
        before_unauth = svc.stats["unauthorized"]
        model.command = "echo e2e-ok > marker4.txt"
        await run_goose(pr.root_for(alice), work, {**pr.security_plan(alice)["env"], GS.CLS_TOKEN: "gwc1.1." + "0" * 64})
        assert (work / "marker4.txt").exists() and svc.stats["unauthorized"] > before_unauth
    finally:
        await svc.stop()


async def test_goose_honours_the_adversary_file_goose_web_writes(env, model, tmp_path):
    s, db, pr, c = env
    GS.save(db, GS.clean({"enabled": False, "adversary": {"members": True, "rules": "BLOCK every tool call (test)."}}))
    alice = member(db)
    pr.provision(alice)
    cdir = pr.config_dir(alice)
    assert (cdir / "adversary.md").read_bytes() == b"tools: shell\n---\nBLOCK every tool call (test).\n"
    add_fake_provider(cdir, model.port)
    work = tmp_path / "work"
    work.mkdir()
    model.command, model.verdict = "echo e2e > blocked.txt", "BLOCK"
    out = await run_goose(pr.root_for(alice), work)
    assert model.reviews >= 1 and not (work / "blocked.txt").exists(), out[-800:]
    assert model.tool_results and "declined" in model.tool_results[-1].lower()
    model.command, model.verdict, n = "echo e2e > allowed.txt", "ALLOW", model.reviews
    out = await run_goose(pr.root_for(alice), work)
    assert model.reviews > n and (work / "allowed.txt").exists(), out[-800:]
    GS.save(db, GS.clean({"enabled": False}))                              # off: the file goes, the reviewer is not asked
    pr.provision(alice)
    add_fake_provider(cdir, model.port)
    model.command, n = "echo e2e > off.txt", model.reviews
    await run_goose(pr.root_for(alice), work)
    assert not (cdir / "adversary.md").exists() and model.reviews == n and (work / "off.txt").exists()


class AcpStdio:
    """The gateway-internal request (hub.Upstream.request) over `goose acp`'s stdio, enough for config/* calls."""

    def __init__(self, root: Path):
        self.root, self.proc, self.next, self.pending = root, None, 0, {}

    async def start(self):
        self.proc = await asyncio.create_subprocess_exec(GOOSE, "acp", env=goose_env(self.root), cwd=str(self.root),
                                                         stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE,
                                                         stderr=asyncio.subprocess.DEVNULL, limit=8 * 1024 * 1024)
        self.reader = asyncio.create_task(self._read())
        return await self.request("initialize", INIT_PARAMS, timeout=60)

    async def _read(self):
        while True:
            line = await self.proc.stdout.readline()
            if not line:
                break
            try:
                m = json.loads(line)
            except ValueError:
                continue
            fut = self.pending.pop(m.get("id"), None) if "method" not in m else None
            if fut is not None and not fut.done():
                if "error" in m:
                    fut.set_exception(RuntimeError(json.dumps(m["error"])[:300]))
                else:
                    fut.set_result(m.get("result"))

    async def request(self, method, params=None, timeout=30):
        self.next += 1
        fut = asyncio.get_running_loop().create_future()
        self.pending[self.next] = fut
        self.proc.stdin.write((json.dumps({"jsonrpc": "2.0", "id": self.next, "method": method,
                                           "params": params or {}}) + "\n").encode())
        await self.proc.stdin.drain()
        return await asyncio.wait_for(fut, timeout)

    async def stop(self):
        self.reader.cancel()
        try:
            self.proc.kill()
        except ProcessLookupError:
            pass
        await self.proc.wait()


async def test_native_apply_through_goose_own_configuration_api(env, tmp_path):
    s, db, pr, c = env
    root = tmp_path / "native"
    cdir = root / "config"
    cdir.mkdir(parents=True)
    for sub in ("data", "state"):
        (root / sub).mkdir()
    (cdir / "config.yaml").write_text(yaml.safe_dump({"GOOSE_MODE": "auto", "GOOSE_MAX_TURNS": 77}), encoding="utf-8")
    admin = _tp.user(db, "root", role="admin", profile_mode="native", profile_path=str(root))
    endpoint = "http://127.0.0.1:8711/classify"
    GS.save(db, GS.clean({"threshold": 0.6, "adversary": {"native": True, "rules": "BLOCK x"}}))
    up = AcpStdio(root)
    await up.start()
    try:
        st = await GS.apply_native(db=db, settings=s, upstream=up, config_dir=cdir, user=admin, endpoint=endpoint,
                                   goose_version="e2e")
        assert st["ok"], st
        cfg = yaml.safe_load((cdir / "config.yaml").read_text(encoding="utf-8"))
        assert cfg["SECURITY_PROMPT_ENABLED"] is True and cfg["SECURITY_PROMPT_THRESHOLD"] == 0.6
        assert cfg["SECURITY_PROMPT_CLASSIFIER_ENABLED"] is True and cfg["SECURITY_PROMPT_CLASSIFIER_ENDPOINT"] == endpoint
        assert cfg["GOOSE_MODE"] == "auto" and cfg["GOOSE_MAX_TURNS"] == 77          # the rest is Goose's, untouched
        assert GS.CLS_TOKEN not in cfg                                               # the secret is not in config.yaml
        token = GS.token_for(db, admin["id"])
        sec = yaml.safe_load((cdir / "secrets.yaml").read_text(encoding="utf-8"))    # keyring off: Goose's secrets file
        assert sec[GS.CLS_TOKEN] == token
        assert (cdir / "adversary.md").read_bytes() == b"tools: shell\n---\nBLOCK x\n"
        plan = GS.profile_plan(GS.load(db), native=True, token=token, endpoint=endpoint)
        st["tokenFp"] = GS.token_fingerprint(token)
        assert GS.native_drift(cdir, plan, st) == []                                 # what Goose wrote reads back equal
        st2 = await GS.apply_native(db=db, settings=s, upstream=up, config_dir=cdir, user=admin, endpoint=endpoint)
        assert st2["ok"] and st2["changed"] == [], st2                               # idempotent against real Goose
        GS.save(db, GS.clean({"enabled": False}))                                    # everything off
        st3 = await GS.apply_native(db=db, settings=s, upstream=up, config_dir=cdir, user=admin, endpoint=endpoint)
        assert st3["ok"], st3
        cfg = yaml.safe_load((cdir / "config.yaml").read_text(encoding="utf-8"))
        # (Goose itself adds its bundled `extensions` defaults when it writes a config.yaml that has none)
        assert not any(k.startswith("SECURITY_") for k in cfg)
        assert cfg["GOOSE_MODE"] == "auto" and cfg["GOOSE_MAX_TURNS"] == 77 and set(cfg) <= {"GOOSE_MODE", "GOOSE_MAX_TURNS", "extensions"}
        sp = cdir / "secrets.yaml"
        assert GS.CLS_TOKEN not in ((yaml.safe_load(sp.read_text(encoding="utf-8")) or {}) if sp.exists() else {})
        assert not (cdir / "adversary.md").exists()
        st4 = await GS.apply_native(db=db, settings=s, upstream=up, config_dir=cdir, user=admin, endpoint=endpoint)
        assert st4["ok"] and st4["changed"] == [], st4                               # removing what is not there
    finally:
        await up.stop()
