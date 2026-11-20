"""Spec 036 (1.26.0): the programs a sandboxed member may run are first on its PATH, and uv uses them.

Measured 2026-11-20: in an MXC container `uvx <tool>` fails when uv downloads a Python (it cannot create the link it
makes for one), and works with a Python granted read-only and UV_PYTHON_DOWNLOADS=never; the goose folder (uv, uvx)
was not on the member's PATH at all.
"""
import os

from goose_web import mxc
import goose_web.workers as wk


def _settings(tmp_path, monkeypatch, **sandbox):
    from goose_web.config import load_settings
    monkeypatch.setenv("GOOSE_WEB__PATHS__PROFILES_ROOT", str(tmp_path / "profiles"))
    (tmp_path / "none.yaml").write_text("", encoding="utf-8")
    monkeypatch.setenv("GOOSE_WEB_CONFIG", str(tmp_path / "none.yaml"))
    s = load_settings()
    s.data.setdefault("sandbox", {}).update(sandbox)
    return s


def test_sandbox_env_puts_the_programs_first_and_keeps_uv_from_downloading(tmp_path, monkeypatch):
    s = _settings(tmp_path, monkeypatch)
    wm = wk.WorkerManager(s)
    root = tmp_path / "sb"
    root.mkdir()
    goose_dir, py = str(tmp_path / "goose"), str(tmp_path / "py313")
    monkeypatch.setenv("PATH", os.pathsep.join([r"C:\Windows\System32", py, r"C:\Windows"]))
    spec = {"name": "x", "profile_root": str(root), "backend": "mxc", "path_dirs": [goose_dir, py]}
    w = wk.Worker(key="bob", username="bob", path_root=str(root), native=False, sandbox=spec)
    env = wm._sandbox_env(w, "mxc")
    parts = env["PATH"].split(os.pathsep)
    assert parts[:2] == [goose_dir, py]
    assert parts.count(py) == 1                               # not twice: the gateway's entry is dropped
    assert r"C:\Windows\System32" in parts
    assert env["UV_PYTHON_DOWNLOADS"] == "never" and env["UV_LINK_MODE"] == "copy"
    # the administrator decides last
    s.data["goose"]["extra_env"] = {"UV_PYTHON_DOWNLOADS": "automatic", "UV_LINK_MODE": "hardlink"}
    env = wm._sandbox_env(w, "mxc")
    assert env["UV_PYTHON_DOWNLOADS"] == "automatic" and env["UV_LINK_MODE"] == "hardlink"
    # a spec of an older gateway (no path_dirs): PATH as before
    w.sandbox = {k: v for k, v in spec.items() if k != "path_dirs"}
    assert wm._sandbox_env(w, "mxc")["PATH"] == os.environ["PATH"]


def test_sandbox_spec_lists_the_goose_folder_and_read_dirs(tmp_path, monkeypatch):
    from tests.test_team_profiles import ANYCHAT, team, user
    from goose_web.auth import AuthService
    from goose_web.context import Ctx
    from goose_web.db import Database
    from goose_web.profiles import Profiles
    rd1, rd2 = str(tmp_path / "py313"), str(tmp_path / "node22")
    s = _settings(tmp_path, monkeypatch, enabled=True, read_dirs=[rd1, rd2,
                                                                  str(tmp_path / "profiles")])   # refused: profiles root
    s.data["goose"]["binary"] = str(tmp_path / "goose" / "goose.exe")
    db = Database(tmp_path / "gw.db")
    c = Ctx(settings=s, db=db, auth=AuthService(db, s), profiles=Profiles(s, db), workers=None, hub=None, version="t")
    tid = team(db, "A", ANYCHAT)
    bob = user(db, "bob")
    db.set_user_team(bob["id"], tid)
    spec = c.sandbox_spec(db.user_by_id(bob["id"]))
    assert spec["path_dirs"] == [str(tmp_path / "goose"), rd1, rd2]
    db.close()


def test_node_versions_that_ignore_the_proxy():
    for v in ("v22.14.0", "v20.18.1", "v23.11.0", "v18.0.0"):
        assert mxc.node_ignores_proxy(v), v
    for v in ("v22.21.0", "v22.22.1", "v24.0.0", "v26.1.0", "", "garbage"):
        assert not mxc.node_ignores_proxy(v), v


def test_runtime_lines(tmp_path, monkeypatch):
    py, node, empty = tmp_path / "py", tmp_path / "node", tmp_path / "empty"
    for d in (py, node, empty):
        d.mkdir()
    exe = ".exe" if os.name == "nt" else ""
    (py / ("python.exe" if os.name == "nt" else "python3")).write_bytes(b"")
    (node / f"node{exe}").write_bytes(b"")
    versions = {str(py): "3.13.11", str(node): "v22.14.0"}
    monkeypatch.setattr(mxc, "_runtime_version", lambda p: versions[os.path.dirname(p)])
    s = _settings(tmp_path, monkeypatch, read_dirs=[str(py), str(node), str(empty)])
    lines = mxc.runtime_lines(s)
    assert (f"members' python: 3.13.11 ({os.path.join(str(py), 'python.exe' if os.name == 'nt' else 'python3')})",
            True) in lines
    old = [t for t, good in lines if "node" in t]
    assert len(old) == 1 and "22.21" in old[0] and not [g for t, g in lines if "node" in t][0]
    s.data["sandbox"]["read_dirs"] = [str(empty)]
    lines = mxc.runtime_lines(s)
    assert len(lines) == 1 and lines[0][0].startswith("no Python in sandbox.read_dirs")
    # RT-2: a runtime in a folder other accounts can change is not run by `check`
    ran = []
    monkeypatch.setattr(mxc, "_runtime_version", lambda p: ran.append(p) or "3.13.11")
    monkeypatch.setattr(mxc, "_broad_writers", lambda p: ["Authenticated Users"] if str(py) in p else [])
    s.data["sandbox"]["read_dirs"] = [str(py)]
    lines = mxc.runtime_lines(s)
    assert not ran and not lines[0][1] and "Authenticated Users" in lines[0][0]
