"""Admin view of the host's Windows scheduled tasks, with an elevation/ownership warning per task.

Why: tasks that run as SYSTEM, with "Run with highest privileges", or with a non-interactive (Password/S4U)
logon get an admin token. Files that Goose writes from such tasks become owned by Administrators/SYSTEM
(or by the other account), and the normal user can no longer read or update them - for example a secrets or
OAuth token file that Goose refreshes, which then locks the user's own Goose out of that integration.
The gateway itself never changes a task's principal; it only shows, runs, ends, enables or disables tasks
that the gateway user is allowed to see.
"""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import time

IS_WINDOWS = os.name == "nt"
_cache: tuple[float, list] = (0.0, [])

_LIST_PS = r"""
$ErrorActionPreference = 'SilentlyContinue'
$filter = $env:GW_TASK_FILTER; if (-not $filter) { $filter = '\*' }
$out = foreach ($t in Get-ScheduledTask -TaskPath $filter) {
  if ($t.TaskPath -like '\Microsoft\*') { continue }
  $i = $t | Get-ScheduledTaskInfo
  [pscustomobject]@{
    path = $t.TaskPath + $t.TaskName; folder = $t.TaskPath; name = $t.TaskName; state = [string]$t.State
    runAs = $t.Principal.UserId; runLevel = [string]$t.Principal.RunLevel; logonType = [string]$t.Principal.LogonType
    author = $t.Author; description = $t.Description
    actions = @($t.Actions | ForEach-Object { (($_.Execute, $_.Arguments) -join ' ').Trim() })
    lastRun = if ($i.LastRunTime -and $i.LastRunTime.Year -gt 2000) { $i.LastRunTime.ToString('o') } else { $null }
    nextRun = if ($i.NextRunTime) { $i.NextRunTime.ToString('o') } else { $null }
    lastResult = $i.LastTaskResult
  }
}
@($out) | ConvertTo-Json -Depth 4 -Compress
"""

_ACTION_PS = r"""
$ErrorActionPreference = 'Stop'
$p = $env:GW_TASK_PATH; $idx = $p.LastIndexOf('\'); $folder = $p.Substring(0, $idx + 1); $name = $p.Substring($idx + 1)
switch ($env:GW_TASK_ACTION) {
  'run'     { Start-ScheduledTask -TaskPath $folder -TaskName $name }
  'end'     { Stop-ScheduledTask -TaskPath $folder -TaskName $name }
  'enable'  { Enable-ScheduledTask -TaskPath $folder -TaskName $name | Out-Null }
  'disable' { Disable-ScheduledTask -TaskPath $folder -TaskName $name | Out-Null }
}
'ok'
"""


def _ps(script: str, env_extra: dict, timeout: int = 90) -> subprocess.CompletedProcess:
    env = {**os.environ, **env_extra}
    return subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                           "-Command", script], capture_output=True, text=True, env=env, timeout=timeout,
                          creationflags=0x08000000, encoding="utf-8", errors="replace")


def elevation_risk(t: dict) -> str:
    """Why a task would run with an admin token ('' = runs as a normal user)."""
    run_as = (t.get("runAs") or "").upper()
    if run_as in ("SYSTEM", "NT AUTHORITY\\SYSTEM", "S-1-5-18", "LOCAL SERVICE", "NETWORK SERVICE"):
        return "runs as a system account: files it creates are not owned by the user"
    if (t.get("runLevel") or "").lower() == "highest":
        return "runs with highest privileges (admin token)"
    if (t.get("logonType") or "").lower() in ("password", "s4u", "serviceaccount"):
        return ("non-interactive logon: admin accounts get their full admin token, so files may become "
                "owned by Administrators (use the de-elevation wrapper)")
    return ""


def _list_sync(path_filter: str) -> list[dict]:
    if not IS_WINDOWS:
        return []
    r = _ps(_LIST_PS, {"GW_TASK_FILTER": path_filter})
    try:
        data = json.loads(r.stdout or "[]")
    except ValueError:
        raise RuntimeError((r.stderr or r.stdout or "task listing failed").strip()[:500])
    if isinstance(data, dict):
        data = [data]
    for t in data:
        t["elevationRisk"] = elevation_risk(t)
        t["elevated"] = bool(t["elevationRisk"])
    return sorted(data, key=lambda t: t["path"].lower())


async def list_tasks(path_filter: str = "\\*", max_age: float = 15) -> list[dict]:
    global _cache
    if time.time() - _cache[0] < max_age:
        return _cache[1]
    tasks = await asyncio.to_thread(_list_sync, path_filter or "\\*")
    _cache = (time.time(), tasks)
    return tasks


async def task_action(path: str, action: str) -> None:
    global _cache
    if action not in ("run", "end", "enable", "disable"):
        raise ValueError("unknown action")
    if not IS_WINDOWS:
        raise RuntimeError("host tasks are Windows-only")
    if not path.startswith("\\") or path.lower().startswith("\\microsoft\\") or any(c in path for c in "\r\n\x00"):
        raise ValueError("invalid task path")
    r = await asyncio.to_thread(_ps, _ACTION_PS, {"GW_TASK_PATH": path, "GW_TASK_ACTION": action}, 60)
    if r.returncode != 0 or "ok" not in (r.stdout or ""):
        raise RuntimeError((r.stderr or r.stdout or "failed").strip().splitlines()[-1][:400])
    _cache = (0.0, [])
