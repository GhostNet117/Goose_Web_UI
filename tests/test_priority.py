"""The gateway puts its own process priority back to normal at start (FIX gateway-below-normal-priority).

Task Scheduler starts a task at task priority 7 unless the task says otherwise: CPU priority class BELOW_NORMAL, low
I/O priority, low memory priority. A gateway left like that is starved whenever the computer is busy. These tests
lower a CHILD process the way Task Scheduler does and let the product code repair it; the test process itself is
never changed.
"""
from __future__ import annotations

import copy
import json
import logging
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from goose_web import __main__ as cli
from goose_web import winsec
from goose_web.config import DEFAULTS, Settings

REPO = Path(__file__).resolve().parents[1]
windows_only = pytest.mark.skipif(os.name != "nt", reason="Windows process priorities")

# Runs in a child: lower this process (CPU class, I/O priority, memory priority), call the product code, report.
CHILD = textwrap.dedent("""
    import ctypes, json, sys
    from ctypes import wintypes
    from goose_web import winsec
    k32, nt = winsec.kernel32, winsec.ntdll
    h = k32.GetCurrentProcess()
    cpu, io, mem = (int(x) for x in sys.argv[1:4])
    assert k32.SetPriorityClass(h, cpu)
    v = wintypes.ULONG(io)
    assert nt.NtSetInformationProcess(h, 33, ctypes.byref(v), ctypes.sizeof(v)) == 0
    v = wintypes.ULONG(mem)
    assert k32.SetProcessInformation(h, 0, ctypes.byref(v), ctypes.sizeof(v))
    started = winsec.process_priority()
    result = winsec.ensure_normal_priority()
    import subprocess
    child = subprocess.run([sys.executable, "-c", "import json; from goose_web import winsec; "
                            "print(json.dumps(winsec.process_priority()))"], capture_output=True, text=True, timeout=120)
    print(json.dumps({"started": started, "result": result, "now": winsec.process_priority(),
                      "child_started_afterwards": json.loads(child.stdout.strip().splitlines()[-1])}))
""")


def run_child(cpu: int, io: int, mem: int) -> dict:
    p = subprocess.run([sys.executable, "-c", CHILD, str(cpu), str(io), str(mem)], cwd=str(REPO),
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout.strip().splitlines()[-1])


@windows_only
def test_a_process_started_like_a_scheduled_task_is_raised_to_normal():
    r = run_child(0x4000, 1, 2)     # BELOW_NORMAL, I/O low, memory low: what Task Scheduler priority 7 gives
    assert r["started"] == {"cpu": "below_normal", "io": "low", "memory": "low"}
    assert sorted(r["result"]["changed"]) == ["cpu", "io", "memory"]
    assert r["result"]["errors"] == []
    assert r["result"]["before"] == r["started"]
    assert r["now"] == r["result"]["after"] == {"cpu": "normal", "io": "normal", "memory": "normal"}


@windows_only
def test_a_process_started_after_the_repair_gets_normal_priority():
    # a child gets its parent's CPU class, I/O priority and memory priority when it is created (measured: a child of
    # the lowered process has all three low), so the agents the gateway starts follow the gateway
    r = run_child(0x4000, 1, 2)
    assert r["child_started_afterwards"] == {"cpu": "normal", "io": "normal", "memory": "normal"}


@windows_only
def test_the_lowest_priorities_are_raised_too():
    r = run_child(0x40, 0, 1)       # IDLE, I/O very low, memory very low (task priority 9-10)
    assert r["started"] == {"cpu": "idle", "io": "very_low", "memory": "very_low"}
    assert r["now"] == {"cpu": "normal", "io": "normal", "memory": "normal"}


@windows_only
def test_nothing_is_lowered_and_nothing_goes_above_normal():
    r = run_child(0x8000, 2, 5)     # ABOVE_NORMAL, I/O normal, memory normal: an administrator's own choice
    assert r["result"]["changed"] == [] and r["result"]["errors"] == []
    assert r["now"] == {"cpu": "above_normal", "io": "normal", "memory": "normal"}


@windows_only
def test_a_normal_process_is_left_alone():
    before = winsec.process_priority()
    r = winsec.ensure_normal_priority() if before == {"cpu": "normal", "io": "normal", "memory": "normal"} else None
    if r is None:
        pytest.skip(f"the test run itself is not at normal priority ({before})")
    assert r["changed"] == [] and r["errors"] == [] and r["after"] == before


def _settings(**server) -> Settings:
    data = copy.deepcopy(DEFAULTS)
    data["server"].update(server)
    return Settings(data, None)


def test_serve_raises_the_priority_by_default_and_logs_it(monkeypatch, caplog):
    assert DEFAULTS["server"]["priority"] == "normal"
    calls = []
    low = {"cpu": "below_normal", "io": "low", "memory": "low"}
    ok = {"cpu": "normal", "io": "normal", "memory": "normal"}
    monkeypatch.setattr(winsec, "ensure_normal_priority",
                        lambda: calls.append(1) or {"before": low, "after": ok, "changed": ["cpu", "io", "memory"], "errors": []})
    with caplog.at_level(logging.INFO, logger="goose_web"):
        r = cli._apply_priority(_settings())
    assert calls == [1] and r["changed"] == ["cpu", "io", "memory"]
    text = caplog.text
    assert "raised to normal (cpu, io, memory)" in text and "CPU below_normal, I/O low, memory low" in text


def test_serve_says_nothing_when_nothing_had_to_change(monkeypatch, caplog):
    ok = {"cpu": "normal", "io": "normal", "memory": "normal"}
    monkeypatch.setattr(winsec, "ensure_normal_priority", lambda: {"before": ok, "after": ok, "changed": [], "errors": []})
    with caplog.at_level(logging.INFO, logger="goose_web"):
        cli._apply_priority(_settings())
    assert "process priority" not in caplog.text


def test_a_priority_that_cannot_be_raised_is_a_warning_and_never_stops_the_start(monkeypatch, caplog):
    low = {"cpu": "below_normal", "io": "low", "memory": "low"}
    monkeypatch.setattr(winsec, "ensure_normal_priority",
                        lambda: {"before": low, "after": low, "changed": [],
                                 "errors": ["cpu: SetPriorityClass failed (WinError 5)"]})
    with caplog.at_level(logging.INFO, logger="goose_web"):
        r = cli._apply_priority(_settings())
    assert r["errors"] and "could not be raised to normal (cpu: SetPriorityClass failed (WinError 5))" in caplog.text
    assert any(rec.levelno == logging.WARNING for rec in caplog.records)


@pytest.mark.parametrize("value", ["inherit", "INHERIT", " Inherit "])
def test_server_priority_inherit_leaves_the_process_alone(monkeypatch, caplog, value):
    monkeypatch.setattr(winsec, "ensure_normal_priority", lambda: pytest.fail("must not be called"))
    with caplog.at_level(logging.INFO, logger="goose_web"):
        assert cli._apply_priority(_settings(priority=value)) is None
    assert "left as started (server.priority: inherit)" in caplog.text


@pytest.mark.parametrize("value", ["normal", "", None, "something else"])
def test_any_other_value_means_normal(monkeypatch, value):
    calls = []
    ok = {"cpu": "normal", "io": "normal", "memory": "normal"}
    monkeypatch.setattr(winsec, "ensure_normal_priority",
                        lambda: calls.append(1) or {"before": ok, "after": ok, "changed": [], "errors": []})
    cli._apply_priority(_settings(priority=value))
    assert calls == [1]


def test_the_task_is_registered_with_normal_priority():
    # Task Scheduler's default (7) is below normal; a new installation asks for 4
    text = (REPO / "scripts" / "register-service.ps1").read_text(encoding="utf-8")
    line = next(ln for ln in text.splitlines() if "-MultipleInstances IgnoreNew" in ln)
    assert "-Priority 4" in line


def test_the_priority_is_applied_before_the_application_is_built():
    # children get what the gateway has when they are created, so it must happen before anything is started
    src = (REPO / "goose_web" / "__main__.py").read_text(encoding="utf-8")
    body = src[src.index("def cmd_serve("):]
    assert body.index("_apply_priority(settings)") < body.index("create_app(settings)")
    assert body.index("_setup_logging(settings)") < body.index("_apply_priority(settings)")
