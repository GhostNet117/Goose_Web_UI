"""Review 20261119_6 (code no independent reviewer had read: the start-up task of 1.24.1, and the browser code as a
whole). What is tested here by reading and by running what can be run without an elevated prompt; the task itself
is registered and run by the CI job on Windows Server (tests/ci/devices-grant.ps1)."""
import re
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import goose_web
from goose_web import sandbox as sb

ROOT = Path(goose_web.__file__).resolve().parents[1]
JS = ROOT / "goose_web" / "static" / "js"
windows = pytest.mark.skipif(sys.platform != "win32", reason="Windows only")


def test_the_start_up_task_copy_lives_where_only_administrators_can_prepare_anything():
    """S-1 (High): 1.24.1 copied the script SYSTEM runs to <ProgramData>\\GooseWeb and adopted a folder that was
    already there. Any account of the machine can create a folder in ProgramData and then owns it - and a handle
    kept open with the right to change the access list outlasts the new access list. Now: Program Files (where
    only administrators can create anything), a new folder made WITH its access list, an existing one used only
    when nobody else owns or can change it."""
    reg = (ROOT / "scripts" / "register-devices-task.ps1").read_text(encoding="utf-8")
    code = "\n".join(l for l in reg.split("#>", 1)[1].splitlines() if not l.strip().startswith("#"))
    assert "$dir = Join-Path $programFiles 'GooseWeb.Startup'" in code
    assert "$env:ProgramW6432" in code and "$env:ProgramFiles" in code
    # ProgramData is named only as the place of the earlier copy, which is removed
    assert [l.split("  #")[0].strip() for l in code.splitlines() if "ProgramData" in l] == \
        ["$oldDir = Join-Path $env:ProgramData 'GooseWeb'"]
    assert "function Remove-OldCopy" in code and "[IO.Directory]::Delete($oldDir)" in code
    # a new folder is made with its access list; an existing one is refused when it is not the administrators' alone
    assert "[void][IO.Directory]::CreateDirectory($dir, $acl)" in code and "New-Item -ItemType Directory" not in code
    there = code.split("if (Test-Path -LiteralPath $dir) {", 1)[1].split("} else {", 1)[0]
    assert there.index("ReparsePoint") < there.index("Get-OtherWriters $dir @()") < there.index("SetAccessControl($dir, $acl)")
    assert "is not the administrators' alone" in there and "restart Windows" in there
    assert "AreAccessRulesProtected" in code
    # S-2 (High): what is copied, and the script itself, must be changeable by nobody but administrators and the caller
    src = code.split("# ---- 1.", 1)[0]
    assert "foreach ($p in @((Split-Path $PSScriptRoot -Parent), $PSScriptRoot, $source, $PSCommandPath))" in src
    assert "if ($open.Count -and -not $TrustSource) {" in src and "Nothing was changed." in src
    assert code.index("if ($open.Count -and -not $TrustSource)") < code.index("CreateDirectory($dir, $acl)")
    assert "SHA-256 of what runs as SYSTEM" in code
    # a task folder that an account which is no administrator made is not used
    assert "Get-TaskFolderOwner $TaskPath" in code and "$TaskPath = $FallbackTaskPath" in code
    assert "$PSVersionTable.PSEdition -eq 'Core'" in code
    assert sb.DEVICES_TASK_FALLBACK == "\\GooseWeb.Startup\\GooseWeb_Devices"


@windows
def test_who_else_can_change_a_folder_is_answered_as_windows_has_it():
    """The function the script decides with, taken out of the script as it is and asked about folders whose answer
    is known on every Windows: ProgramData can be changed by Users; Program Files and System32 by nobody else."""
    import os
    reg = (ROOT / "scripts" / "register-devices-task.ps1").read_text(encoding="utf-8")
    block = re.search(r"(?s)\$sidType = .*?(?=function Get-TaskFolderOwner)", reg).group(0)
    script = block + r"""
foreach ($p in $env:ProgramData, $env:ProgramFiles, (Join-Path $env:SystemRoot 'System32')) {
    $w = Get-OtherWriters $p @()
    '{0}|{1}' -f $p, ($w -join ',')
}
"""
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True,
                       text=True, timeout=120)
    assert r.returncode == 0, r.stdout + r.stderr
    got = dict(l.split("|", 1) for l in r.stdout.strip().splitlines())
    pd = got[os.environ["ProgramData"]]
    if "S-1-5-32-545" not in pd and "S-1-5-11" not in pd and "S-1-1-0" not in pd:
        pytest.skip(f"this machine's ProgramData is closed to ordinary accounts ({pd!r})")
    assert got[os.environ["ProgramFiles"]] == "" and got[os.path.join(os.environ["SystemRoot"], "System32")] == ""


def test_the_task_is_found_in_either_task_folder(monkeypatch):
    seen = []

    def run(cmd, **kw):
        seen.append(cmd[-1])
        return SimpleNamespace(returncode=0 if cmd[-1] == there else 1)
    monkeypatch.setattr(sb, "IS_WINDOWS", True)
    monkeypatch.setattr(sb.subprocess, "run", run)
    for there, want in ((sb.DEVICES_TASK, True), (sb.DEVICES_TASK_FALLBACK, True), ("nowhere", False)):
        assert sb.devices_task() is want
    assert sb.DEVICES_TASK in seen and sb.DEVICES_TASK_FALLBACK in seen

    def boom(cmd, **kw):
        raise OSError("no schtasks")
    monkeypatch.setattr(sb.subprocess, "run", boom)
    assert sb.devices_task() is None


def test_an_expired_sign_in_leaves_as_little_in_the_browser_as_signing_out():
    """F-1: a sign-in that ends by itself (after eight hours: the usual end since 1.25.0) cleared the drafts only.
    Folders, pinned chats and provider lists of the last person stayed in the browser's storage for the next."""
    app = (JS / "app.js").read_text(encoding="utf-8")
    lost = app.split("bus.on('unauthorized', () => {", 1)[1].split("\n});", 1)[0]
    assert lost.index("clearDrafts(true)") < lost.index("clearClientState();") < lost.index("showLogin()")
    boot = next(l for l in app.splitlines() if "e.status === 401 || e.status === 403" in l)
    assert "clearClientState();" in boot and boot.index("clearClientState()") < boot.index("showLogin()")
    clear = app.split("async function clearClientState() {", 1)[1].split("\n}\n", 1)[0]
    assert "/^gw[.\\-_]/" in clear and "sessionStorage.clear()" in clear and "caches.delete" in clear


def test_markdown_lets_no_media_element_fetch_an_address():
    """F-2: only an image's address was held to this site. video, audio, source, track and the poster/background
    attributes passed the sanitiser, so only the Content-Security-Policy stood between a model's or a tool's text
    and a request to an address of its choosing."""
    md = (JS / "markdown.js").read_text(encoding="utf-8")
    opts = md.split("const PURIFY_OPTS = {", 1)[1].split("};", 1)[0]
    tags = set(re.findall(r"'([a-z]+)'", opts.split("FORBID_TAGS:", 1)[1].split("FORBID_ATTR:", 1)[0]))
    attrs = set(re.findall(r"'([a-z]+)'", opts.split("FORBID_ATTR:", 1)[1]))
    assert {"video", "audio", "source", "track", "picture", "iframe", "object", "embed", "style", "form"} <= tags
    assert {"poster", "background", "srcset", "style", "ping"} <= attrs
    assert "if (!isLocalImageSrc(src))" in md        # images: this site only, as before
