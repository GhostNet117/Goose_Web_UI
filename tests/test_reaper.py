"""FIX idle-sessions-keep-mcp-servers: the orphan reaper (reaper.py) on a mocked job list and process table, plus a
small check of its Windows calls on a real job object."""
import asyncio
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest

from goose_web import reaper as rp
from goose_web.config import Settings

CONFIG = """extensions:
  developer: {type: builtin, name: developer, enabled: true}
  fetch: {type: stdio, name: fetch, cmd: uvx, args: [mcp-server-fetch], enabled: true}
  files: {type: stdio, name: files, cmd: npx, args: ['-y', '@modelcontextprotocol/server-filesystem', 'C:/w'],
          enabled: false}
"""


class Procs:
    """A fake process table: pid -> (parent pid, image, creation time, command line); `job` = the job's members."""

    def __init__(self):
        self.table = {}
        self.job = set()
        self.ended = []
        self.refuse = set()

    def add(self, pid, ppid, exe, born, line="", job=True):
        self.table[pid] = (ppid, exe, born, line)
        if job:
            self.job.add(pid)

    def gone(self, pid):
        self.table.pop(pid, None)
        self.job.discard(pid)

    def job_pids(self, handle):
        assert handle == 7
        return sorted(self.job)

    def snapshot(self):
        return [(p, v[0], v[1]) for p, v in self.table.items()]

    def created(self, pid):
        v = self.table.get(pid)
        return v[2] if v else None

    def cmdline(self, pid):
        v = self.table.get(pid)
        return v[3] if v else None

    def terminate(self, pid, born):
        v = self.table.get(pid)
        if pid in self.refuse or v is None or v[2] != born:
            return False
        self.ended.append(pid)
        self.gone(pid)
        return True


@pytest.fixture
def world(tmp_path):
    cfg = tmp_path / "config" / "config.yaml"
    cfg.parent.mkdir()
    cfg.write_text(CONFIG, encoding="utf-8")
    p = Procs()
    p.add(1, 0, "services.exe", 1, job=False)
    p.add(10, 1, "python.exe", 50, "python -m goose_web serve", job=False)                     # the gateway
    p.add(100, 10, "goose.exe", 100, "goose serve --port 1")                                    # the worker
    p.add(200, 100, "uvx.exe", 200, r'"D:\tools\u\.local\bin\uvx.exe" mcp-server-fetch')        # fetch's launcher
    p.add(300, 200, "python.exe", 300, r"D:\tools\u\AppData\Local\uv\cache\archive-v0\abc\Scripts\python.exe "
                                       r"-m mcp_server_fetch --api-key sk-NOT-A-REAL-KEY-0123456789")   # the server
    p.add(400, 100, "cmd.exe", 400, r"C:\WINDOWS\system32\cmd.exe /c start /b uvicorn app:api")  # a shell command
    p.add(500, 400, "uvicorn.exe", 500, "uvicorn app:api")                                      # ... left running
    p.add(600, 1, "python.exe", 600, "uvx mcp-server-fetch", job=False)                        # outside the job
    r = rp.OrphanReaper(Settings({"goose": {}}, None), workers=None, procs=p)
    return r, p, {"key": "alice", "username": "alice", "handle": 7, "config": cfg}


def test_a_released_servers_orphan_is_ended_after_the_grace(world):
    r, p, t = world
    assert r.sweep([t], 1000.0, 120) == []
    assert set(r.trees["alice"]) == {(200, 200), (300, 300)}   # the fetch launcher and its server
    p.gone(200)          # Goose ends the launcher only
    p.gone(400)          # the shell command ended; its background program lives on, never classified
    assert r.sweep([t], 1060.0, 120) == []     # cut off now: the grace period starts
    assert r.sweep([t], 1150.0, 120) == []     # 90 s
    ended = r.sweep([t], 1190.0, 120)          # 130 s
    assert [e["pid"] for e in ended] == [300] and p.ended == [300]
    e = ended[0]
    assert e["extension"] == "fetch" and e["profile"] == "alice" and e["detachedSeconds"] == 130
    assert "mcp_server_fetch" in e["commandLine"] and "sk-NOT-A-REAL-KEY" not in e["commandLine"]
    assert r.sweep([t], 9999.0, 120) == [] and p.ended == [300]
    assert {100, 500, 600, 10} <= set(p.table)   # the worker, the unclassified program, outside the job, the gateway


def test_live_servers_are_left_alone(world):
    r, p, t = world
    p.add(250, 200, "python.exe", 250, "python -m launcher")     # an intermediate process of a live server ...
    p.add(350, 250, "python.exe", 350, "python -m real_server")
    for now in (0.0, 60.0):
        assert r.sweep([t], now, 120) == []
    p.gone(250)          # ... ends while the tree's root (still Goose's child) lives: the extension may still work
    for now in (120.0, 600.0, 6000.0, 60000.0):
        assert r.sweep([t], now, 120) == []
    assert p.ended == [] and (350, 350) in r.trees["alice"]


def test_creation_times_are_respected(world):
    r, p, t = world
    r.sweep([t], 0.0, 120)
    p.gone(200)
    r.sweep([t], 10.0, 120)                      # the server is cut off since 10 s
    p.gone(300)
    p.add(300, 1, "notepad.exe", 9000, "notepad")   # its pid now belongs to another process, in the job even
    assert r.sweep([t], 500.0, 120) == [] and p.ended == []
    assert (300, 300) not in r.trees["alice"]


def test_a_reused_parent_pid_does_not_count_as_attached(world):
    r, p, t = world
    r.sweep([t], 0.0, 120)
    p.gone(200)
    p.add(200, 100, "node.exe", 9000, "node other.js")   # the launcher's pid, reused under goose by a newer process
    assert r.sweep([t], 10.0, 120) == []
    assert [e["pid"] for e in r.sweep([t], 200.0, 120)] == [300]
    assert 200 in p.table                                 # the newer process is not touched


def test_nothing_outside_the_job_or_never_classified_is_touched(world):
    r, p, t = world
    p.gone(200)          # the launcher ended before the reaper ever saw the tree: its child was never classified
    for now in (0.0, 500.0, 5000.0):
        assert r.sweep([t], now, 120) == []
    assert p.ended == [] and 300 in p.table and 600 in p.table


def test_a_process_that_cannot_be_ended_is_left_after_a_few_tries(world):
    r, p, t = world
    r.sweep([t], 0.0, 120)
    p.gone(200)
    p.refuse.add(300)
    r.sweep([t], 10.0, 120)
    for now in (200.0, 300.0, 400.0, 500.0, 600.0):
        assert r.sweep([t], now, 120) == []
    assert (300, 300) not in r.trees["alice"] and 300 in p.table


def test_a_stopped_worker_is_forgotten(world):
    r, p, t = world
    r.sweep([t], 0.0, 120)
    assert r.trees["alice"]
    r.sweep([], 10.0, 120)
    assert "alice" not in r.trees


def test_off_windows_or_switched_off_it_does_nothing(monkeypatch, world):
    r, p, t = world
    r.sweep([t], 0.0, 120)
    r.s = Settings({"goose": {"orphan_reaper": False}}, None)
    assert asyncio.run(r.run_once()) == [] and not r.trees
    monkeypatch.setattr(rp, "IS_WINDOWS", False)
    r2 = rp.OrphanReaper(Settings({"goose": {}}, None), workers=None)
    r2.start()
    assert r2._task is None
    assert asyncio.run(r2.run_once()) == []
    assert r2.sweep([t], 0.0, 120) == []


def test_command_lines_match_configured_stdio_extensions():
    exts = [("fetch", "uvx", ["mcp-server-fetch"]),
            ("files", "npx", ["-y", "@modelcontextprotocol/server-filesystem", "C:/w"]),
            ("guarded", r"C:\Py\python.exe", ["-I", r"C:\P\m\.goose-web\stdio_guard.py", "--limit", "120", "--name",
                                             "x", "--", "uvx", "mcp-x"])]
    assert rp.match_extension(r'"D:\tools\u\.local\bin\uvx.exe" mcp-server-fetch', exts) == "fetch"
    assert rp.match_extension(r'C:\WINDOWS\system32\cmd.exe /e:ON /v:OFF /d /c "C:\nodejs\npx.cmd -y '
                              r'@modelcontextprotocol/server-filesystem C:/w"', exts) == "files"
    assert rp.match_extension(r'"C:\Py\python.exe" -I C:\P\m\.goose-web\stdio_guard.py --limit 120 --name x -- '
                              r'uvx mcp-x', exts) == "guarded"
    assert rp.match_extension("uvx mcp-server-time", exts) is None
    assert rp.match_extension("", exts) is None
    assert rp.split_cmdline(r'a "b c" d\"e "f\\" g') == ["a", "b c", 'd"e', "f\\", "g"]
    m = rp.mask_cmdline("srv --token abc123 --api-key=XYZ PASSWORD=hunter2 https://u:pw@example.org/x " + "A" * 40)
    for secret in ("abc123", "XYZ", "hunter2", "u:pw@", "A" * 40):
        assert secret not in m
    assert m.startswith("srv --token ***") and "example.org/x" in m


@pytest.mark.skipif(os.name != "nt", reason="Windows job objects")
def test_windows_calls_on_a_real_job():
    from goose_web.workers import _Job
    job = _Job()
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)  # reaper-probe"],
                            creationflags=0x08000000)   # CREATE_NO_WINDOW
    try:
        assert job.add(proc)
        w = rp.WinProcs()
        assert proc.pid in w.job_pids(job.handle)
        rows = {pid: (ppid, exe) for pid, ppid, exe in w.snapshot()}
        assert rows[proc.pid][0] == os.getpid() and rows[proc.pid][1].lower().startswith("python")
        assert "reaper-probe" in (w.cmdline(proc.pid) or "")
        born = w.created(proc.pid)
        assert born and not w.terminate(proc.pid, born + 1)    # another creation time: not this process
        assert w.terminate(proc.pid, born)
        proc.wait(10)
        end = time.monotonic() + 5
        while proc.pid in w.job_pids(job.handle) and time.monotonic() < end:
            time.sleep(0.05)
        assert proc.pid not in w.job_pids(job.handle)
    finally:
        if proc.poll() is None:
            proc.kill()
        job.close()
