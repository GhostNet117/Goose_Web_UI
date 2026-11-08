<#
.SYNOPSIS
  Upgrades an existing goose-web installation on Windows in place and keeps every setting.

.DESCRIPTION
  Run it as the same normal (non-elevated) Windows user that runs the gateway, from the install folder
  (the git clone that holds .venv):

    powershell -ExecutionPolicy Bypass -File scripts\upgrade.ps1

  What it does, in this order (it stops at the first failure, before the gateway is touched):
    1. Finds the gateway's scheduled task (any task folder) and its config.yaml from the task's arguments.
    2. Refuses while a worker is busy (an agent is running), unless -Force.
    3. Backs up the database (SQLite online backup) and config.yaml to <profiles_root>\backups\upgrade-<time>\.
    4. Updates the code: "git pull --ff-only" (default), "git checkout <Ref>" with -Ref, or nothing with -NoGit
       (you already replaced the files, e.g. from a release zip).
    5. Installs the locked dependencies (uv when available - Goose ships it - else pip) and the package itself.
    6. Runs "goose-web check".
    7. Restarts the task and waits until /healthz answers; prints the old and new version.
  Never changed: the task definition, the firewall rule, config.yaml, the database content (schema migrations run
  automatically when the new version opens it - after the backup), user profiles, Goose's own folders.

  -Detached: re-launches itself outside the calling process tree and returns immediately (use it when you run the
  upgrade from a chat that itself runs through goose-web: the restart would otherwise end that chat's shell before
  the gateway is started again). Output then goes only to the log file.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\upgrade.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\upgrade.ps1 -Ref v1.6.0 -Detached
#>
[CmdletBinding()]
param(
    [string]$Ref = '',                # tag/commit/branch to check out; '' = git pull --ff-only on the current branch
    [switch]$NoGit,                   # files were already replaced; only reinstall + restart
    [switch]$Force,                   # restart even if a worker looks busy
    [switch]$Detached,
    [int]$DelaySeconds = 60,          # with -Detached: wait this long first (lets the calling chat's turn finish)
    [string]$TaskName = '',           # full task path\name if auto-detection finds none or several
    [string]$Log = '',
    [int]$WaitFirst = 0               # internal (set by -Detached): seconds to wait before starting
)
$ErrorActionPreference = 'Stop'
$InstallDir = Split-Path -Parent $PSScriptRoot
$venvPy = Join-Path $InstallDir '.venv\Scripts\python.exe'
$venvPyw = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
if (-not $Log) { $Log = Join-Path $env:TEMP ('goose-web-upgrade-{0}.log' -f (Get-Date -Format 'yyyyMMdd-HHmmss')) }
# -Ref is passed to git: only a plain tag/branch/commit name (no option-like or shell-special values).
if ($Ref -and $Ref -notmatch '^[A-Za-z0-9][A-Za-z0-9._/-]{0,199}$') { throw "Invalid -Ref '$Ref' (use a tag, branch or commit id)." }

if ($Detached) {
    # WMI starts the process outside the caller's process tree and job, so a gateway restart cannot kill it.
    $argsList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-WindowStyle', 'Hidden', '-File', "`"$PSCommandPath`"",
        '-Log', "`"$Log`"", '-WaitFirst', $DelaySeconds)
    if ($Ref) { $argsList += @('-Ref', "`"$Ref`"") }
    if ($NoGit) { $argsList += '-NoGit' }
    if ($Force) { $argsList += '-Force' }
    if ($TaskName) { $argsList += @('-TaskName', "`"$TaskName`"") }
    $r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
        CommandLine = 'powershell.exe ' + ($argsList -join ' '); CurrentDirectory = $InstallDir }
    if ($r.ReturnValue -ne 0) { throw "Could not start the detached upgrade (Win32_Process.Create returned $($r.ReturnValue))." }
    Write-Host "Detached upgrade starts in $DelaySeconds s (pid $($r.ProcessId)). Log: $Log"
    return
}
if ($WaitFirst -gt 0) { Start-Sleep -Seconds $WaitFirst }

function Say($m) { $line = "[{0}] {1}" -f (Get-Date -Format 'HH:mm:ss'), $m; Write-Host $line; Add-Content -Path $Log -Value $line -Encoding UTF8 }
function Run($exe, [string[]]$a) {
    # Native tools (uv, git, pip) write progress to stderr; judge them by their exit code only.
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    try { $out = & $exe @a 2>&1 | ForEach-Object { "$_" }; $code = $LASTEXITCODE } finally { $ErrorActionPreference = $prev }
    $out | ForEach-Object { Add-Content -Path $Log -Value "    $_" -Encoding UTF8 }
    return @{ code = $code; out = $out }
}
try {
    Say "goose-web upgrade in $InstallDir (log $Log)"
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    if ((New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw "Run the upgrade as the normal Windows user (not elevated): files created elevated break goose-web."
    }
    if (-not (Test-Path $venvPy)) { throw "No .venv in $InstallDir. This script upgrades an existing install; use scripts\install.ps1 first." }

    # 1. task + config
    $tasks = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
        $_.Actions | Where-Object { $_.Execute -and ($_.Execute.Trim('"') -ieq $venvPyw -or $_.Execute.Trim('"') -ieq $venvPy) } })
    if ($TaskName) { $tasks = @($tasks | Where-Object { ($_.TaskPath + $_.TaskName) -ieq $TaskName }) }
    if ($tasks.Count -ne 1) {
        throw "Expected one gateway task for this install, found $($tasks.Count) ($((($tasks | ForEach-Object { $_.TaskPath + $_.TaskName }) -join ', '))). Pass -TaskName '\Folder\Name'."
    }
    $task = $tasks[0]; $taskFull = $task.TaskPath + $task.TaskName
    $taskArgs = ($task.Actions | Select-Object -First 1).Arguments
    $cfg = if ($taskArgs -match '--config\s+"([^"]+)"') { $Matches[1] } elseif ($taskArgs -match '--config\s+(\S+)') { $Matches[1] } else { 'C:\Goose_Web_Profiles\_system\config.yaml' }
    if (-not (Test-Path $cfg)) { throw "Config not found: $cfg" }
    Say "Task $taskFull ($($task.State)); config $cfg"
    $cfgText = Get-Content $cfg -Raw
    $root = if ($cfgText -match '(?m)^\s*profiles_root:\s*"?([^"\r\n#]+?)"?\s*$') { $Matches[1].Replace('\\', '\') } else { Split-Path (Split-Path $cfg) }
    $sysDir = if ($cfgText -match '(?m)^\s*system_dir:\s*"?([^"\r\n#]+?)"?\s*$' -and $Matches[1]) { $Matches[1].Replace('\\', '\') } else { Join-Path $root '_system' }
    $bindHost = if ($cfgText -match '(?m)^\s*host:\s*"?([^"\s#]+)') { $Matches[1] } else { '127.0.0.1' }
    if ($bindHost -eq '0.0.0.0' -or $bindHost -eq '::') { $bindHost = '127.0.0.1' }
    $port = if ($cfgText -match '(?m)^\s*port:\s*(\d+)') { $Matches[1] } else { '8710' }
    function RunningVersion() {   # the version the running gateway reports (public endpoint), '' if it does not answer
        try { return (Invoke-RestMethod "http://${bindHost}:${port}/api/auth/config" -TimeoutSec 5).version } catch { return '' }
    }
    $oldVer = RunningVersion
    if (-not $oldVer) { $oldVer = '(not running)' }

    # 2. busy check: a goose serve worker of this gateway using CPU means an agent is working
    if ($task.State -eq 'Running' -and -not $Force) {
        # The gateway = processes running "goose_web ... serve" with this config (a uv venv's pythonw.exe is a launcher
        # whose child runs the same command line); its workers are the goose.exe "serve" children.
        $all = @(Get-CimInstance Win32_Process)
        $gwIds = @($all | Where-Object { $_.CommandLine -and $_.CommandLine -match 'goose_web' -and $_.CommandLine -match '\bserve\b' -and
            $_.CommandLine.IndexOf($cfg, [StringComparison]::OrdinalIgnoreCase) -ge 0 } | ForEach-Object { $_.ProcessId })
        $workers = @($all | Where-Object { $_.Name -ieq 'goose.exe' -and $_.CommandLine -match '\bserve\b' -and $gwIds -contains $_.ParentProcessId })
        Say "gateway processes: $($gwIds.Count); workers: $($workers.Count)"
        foreach ($w in $workers) {
            $a = (Get-Process -Id $w.ProcessId -ErrorAction SilentlyContinue).TotalProcessorTime.TotalMilliseconds; Start-Sleep 5
            $b = (Get-Process -Id $w.ProcessId -ErrorAction SilentlyContinue).TotalProcessorTime.TotalMilliseconds
            $cpu = [int]($b - $a); Say "worker $($w.ProcessId): cpu $cpu ms in 5 s"
            if ($cpu -gt 1500) { throw "A worker looks busy (an agent is running). Try again later, or pass -Force." }
        }
    }

    # 3. backup BEFORE anything changes
    $bdir = Join-Path $root ('backups\upgrade-{0}' -f (Get-Date -Format 'yyyyMMdd-HHmmss'))
    New-Item -ItemType Directory -Force -Path $bdir | Out-Null
    Copy-Item $cfg (Join-Path $bdir 'config.yaml')
    $db = Join-Path $sysDir 'goose-web.db'
    if (Test-Path $db) {
        $r = Run $venvPy @('-c', 'import sqlite3,sys;s=sqlite3.connect(sys.argv[1]);d=sqlite3.connect(sys.argv[2]);s.backup(d);d.close();s.close()', $db, (Join-Path $bdir 'goose-web.db'))
        if ($r.code) { throw "Database backup failed; nothing was changed." }
    }
    Say "Backup: $bdir (config.yaml, goose-web.db)"
    # The backups hold full database copies (password hashes, 2FA and directory secrets): keep the newest 10 only.
    Get-ChildItem (Join-Path $root 'backups') -Directory -Filter 'upgrade-*' | Sort-Object Name -Descending |
        Select-Object -Skip 10 | ForEach-Object { Remove-Item $_.FullName -Recurse -Force; Say "Removed old backup $($_.Name)" }

    # 4. code
    if (-not $NoGit) {
        if (-not (Test-Path (Join-Path $InstallDir '.git'))) { throw "$InstallDir is not a git clone. Replace the files yourself and run again with -NoGit." }
        $dirty = @(git -C $InstallDir status --porcelain --untracked-files=no)
        if ($dirty.Count) { throw "The install folder has local changes to tracked files; commit/stash them first (git -C `"$InstallDir`" status)." }
        $r = Run git @('-C', $InstallDir, 'fetch', '--tags', 'origin'); if ($r.code) { throw "git fetch failed." }
        if ($Ref) {
            $sha = (Run git @('-C', $InstallDir, 'rev-parse', '--verify', '--quiet', "$Ref^{commit}")).out | Select-Object -Last 1
            if (-not $sha -or $sha -notmatch '^[0-9a-f]{40}$') { throw "Unknown -Ref '$Ref' (not a commit, tag or branch in the clone)." }
            $r = Run git @('-C', $InstallDir, 'checkout', '--quiet', $sha)
        } else { $r = Run git @('-C', $InstallDir, 'pull', '--ff-only') }
        if ($r.code) { throw "Updating the code failed (see the log). Nothing else was changed; the gateway still runs the old version." }
        Say ("Code now at " + ((git -C $InstallDir log -1 --format='%h %s') | Select-Object -First 1))
    }

    # 5. dependencies (uv venvs have no pip; Goose ships uv)
    $uv = (Get-Command uv -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $uv) { $c = Join-Path $env:LOCALAPPDATA 'Goose\bin\uv.exe'; if (Test-Path $c) { $uv = $c } }
    Push-Location $InstallDir
    try {
        if ($uv) {
            $r = Run $uv @('pip', 'install', '--python', $venvPy, '--require-hashes', '-r', 'requirements.lock'); if ($r.code) { throw "Dependency installation failed (uv)." }
            $r = Run $uv @('pip', 'install', '--python', $venvPy, '--no-deps', '-e', '.'); if ($r.code) { throw "Package installation failed (uv)." }
        } else {
            $r = Run $venvPy @('-m', 'pip', 'install', '--require-hashes', '-r', 'requirements.lock'); if ($r.code) { throw "Dependency installation failed (pip). Install uv, or run: $venvPy -m ensurepip" }
            $r = Run $venvPy @('-m', 'pip', 'install', '--no-deps', '-e', '.'); if ($r.code) { throw "Package installation failed (pip)." }
        }
    } finally { Pop-Location }
    Say "Dependencies installed ($(if ($uv) { 'uv' } else { 'pip' }))"

    # 6. check (the gateway still runs; "port in use" is expected)
    $r = Run $venvPy @('-m', 'goose_web', '--config', $cfg, 'check')
    $r.out | Where-Object { $_ -match '^\[' } | ForEach-Object { Say "check $_" }
    if ($r.code) { throw "goose-web check failed; the gateway was NOT restarted and still runs the old version. Fix the [!!] items and run upgrade.ps1 -NoGit." }

    # 7. restart + health
    try {
        Stop-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName
        Start-Sleep 3
        Start-ScheduledTask -TaskPath $task.TaskPath -TaskName $task.TaskName
    } catch {
        # A task that runs as a service account usually needs administrator rights to stop/start: ask once (UAC).
        Say "Restarting $taskFull needs administrator rights (it runs as $($task.Principal.UserId)); asking once."
        $restart = "Stop-ScheduledTask -TaskPath '$($task.TaskPath)' -TaskName '$($task.TaskName)'; Start-Sleep 3; " +
                   "Start-ScheduledTask -TaskPath '$($task.TaskPath)' -TaskName '$($task.TaskName)'"
        $p = Start-Process powershell -Verb RunAs -ArgumentList @('-NoProfile', '-Command', $restart) -Wait -PassThru
        if ($p.ExitCode) { throw "The restart was refused. The new version is installed; restart the task as an administrator: $restart" }
    }
    $ok = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep 2
        try { if ((Invoke-WebRequest -UseBasicParsing "http://${bindHost}:${port}/healthz" -TimeoutSec 5).StatusCode -eq 200) { $ok = $true; break } } catch { }
    }
    $newVer = RunningVersion
    if (-not $ok) { throw "The gateway did not answer http://${bindHost}:${port}/healthz within 60 s. Check $sysDir\logs\gateway.log. Backup: $bdir" }
    Say "Upgraded $oldVer -> $newVer; healthz OK; backup $bdir"
    exit 0
} catch {
    Say "FAILED: $($_.Exception.Message)"
    exit 1
}
