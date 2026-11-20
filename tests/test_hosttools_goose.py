"""Spec 035 A7 (1.26.0): the real goose CLI reaches a host tool through a member's real egress proxy.

Measured before the design (2026-11-20, goose 1.57.0): Goose's HTTP extension client goes through HTTP_PROXY, asks
`server/discover` first and falls back to `initialize` on "method not found". Here the whole chain runs: goose ->
EgressProxy (credential) -> HostTools -> a fake stdio MCP server. The model call fails on purpose afterwards (no
provider); what matters is the extension's handshake and tool list.
"""
import asyncio
import os
import shutil
import sys

import pytest

from goose_web.egress import EgressProxy
from tests.test_hosttools import env  # noqa: F401  (fixture)


def _goose() -> str:
    for c in (os.environ.get("GOOSE_WEB_TEST_GOOSE", ""), r"C:\Goose\dist-windows\resources\bin\goose.exe",
              shutil.which("goose") or ""):
        if c and os.path.isfile(c):
            return c
    return ""


@pytest.mark.skipif(not _goose(), reason="needs the goose CLI")
async def test_real_goose_through_the_egress_proxy(env, tmp_path):  # noqa: F811
    h = env["h"]
    h.start()
    seen = []
    real = h.message

    async def recording(member, name, msg, sid, gen=None):
        seen.append(msg.get("method"))
        return await real(member, name, msg, sid, gen)
    h.message = recording
    p = await EgressProxy("alice", network="none", audit=lambda *a: None).start()
    p.broker = h
    root = tmp_path / "goose-root"
    root.mkdir()
    keep = ("SystemRoot", "windir", "SystemDrive", "ComSpec", "PATHEXT", "PATH", "TEMP", "TMP", "LOCALAPPDATA",
            "APPDATA", "USERPROFILE", "HOMEDRIVE", "HOMEPATH")
    environ = {k: os.environ[k] for k in keep if k in os.environ}
    environ.update({"GOOSE_PATH_ROOT": str(root), "GOOSE_DISABLE_KEYRING": "1", "OPENAI_API_KEY": "dummy",
                    "OPENAI_HOST": "http://127.0.0.1:9", "HTTP_PROXY": p.url(), "HTTPS_PROXY": p.url()})
    cmd = [_goose(), "run", "--no-session", "--no-profile", "--with-streamable-http-extension",
           "http://fake.goose-web.invalid/mcp", "--provider", "openai", "--model", "gpt-4o-mini", "--max-turns", "1",
           "-t", "hi"]
    proc = await asyncio.create_subprocess_exec(*cmd, env=environ, cwd=str(tmp_path), stdout=asyncio.subprocess.PIPE,
                                                stderr=asyncio.subprocess.STDOUT)
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), 120)
    except asyncio.TimeoutError:
        proc.kill()
        out = b"(timed out)"
    await p.close()
    try:
        text = out.decode("utf-8", "replace")
        assert "server/discover" in seen and "initialize" in seen, (seen, text[-2000:])
        assert seen.index("initialize") > seen.index("server/discover")
        assert "tools/list" in seen, (seen, text[-2000:])
        assert "failed to start extension" not in text.lower(), text[-2000:]
        assert ("fake", "alice") in h.procs                           # the gateway started the server for alice
        assert any(t == "fake:initialize" and d["decision"] == "allowed" for _, t, d in env["audit"])
    finally:
        await h.close()
