<#
.SYNOPSIS
  CI only (a GitHub-hosted runner, which is thrown away after the job). Runs the AppContainer self-test the way a
  gateway started at boot runs: from a scheduled task, as a local account that is not an administrator and has never
  signed in - session 0, on the window station of that logon, with no desktop of a signed-in user anywhere near.

.DESCRIPTION
  Creates a local account with a random password and a scheduled task that runs tests\ci\selftest_as_service.py as
  that account, starts the task, reads the result and deletes the task and the account again. For comparison the
  same file is run first in the job's own session. Each result is printed as an annotation of the run.

  -Enforce makes a failed self-test fail the step (CI uses it since the test was seen to pass on Windows Server
  2022 and 2025, with 1.22.2). Without it the step only reports.

  -OwnSessionOnly runs the comparison only and creates nothing (for trying the script on a machine of your own).
  Without it the script refuses to run anywhere but in GitHub Actions: it creates an account and lets every
  application package read the Python folder, which nobody wants on a machine that is kept.
#>
[CmdletBinding()]
param(
    [string]$Python = (Get-Command python).Source,
    [switch]$Enforce,
    [switch]$OwnSessionOnly
)
$ErrorActionPreference = 'Stop'
if (-not $OwnSessionOnly -and $env:GITHUB_ACTIONS -ne 'true') {
    throw 'This creates a Windows account and changes folder permissions: for a GitHub-hosted runner only. Use -OwnSessionOnly elsewhere.'
}
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$probe = Join-Path $PSScriptRoot 'selftest_as_service.py'
$tmp = $env:RUNNER_TEMP
if (-not $tmp) { $tmp = $env:TEMP }
$out = Join-Path $tmp ('gwsvc-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
$user = 'gwsvc' + (Get-Random -Minimum 1000 -Maximum 9999)
$task = 'GooseWeb_SelfTest_' + $user
$failed = $false
$made = $false

function Say([string]$level, [string]$title, [string]$text) {
    # one annotation; % and line ends are escaped as workflow commands want them
    $t = $text.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    Write-Host "::${level} title=${title}::${t}"
}

function Steps($list) {
    if (-not $list) { return '(none)' }
    $parts = foreach ($s in @($list)) {
        $state = 'FAILED'
        if ($s.ok) { $state = 'ok' }
        "$($s.what) = $state $($s.exit) $($s.detail)".Trim()
    }
    return ($parts -join ' | ')
}

function Line($r) {
    return ("user $($r.user), Windows build $($r.build), session $($r.session), window station '$($r.windowStation)', " +
            "desktop '$($r.desktop)'. They let application packages in as they are: $($r.windowStationLetsContainersIn) / " +
            "$($r.desktopLetsContainersIn). Missing: [$(@($r.missing) -join '; ')]. Named by the self-test: " +
            "[$(@($r.admitted) -join '; ')]. AS IT WAS: $(Steps $r.stepsBefore). RESULT: $(Steps $r.steps). " +
            "$($r.text) $($r.error)").Trim()
}

# ---- for comparison: the job's own session (a failure here is reported and does not stop the rest)
try {
    New-Item -ItemType Directory -Force $out | Out-Null
    $own = Join-Path $out 'own.json'
    & $Python $probe $own
    $r = Get-Content $own -Raw | ConvertFrom-Json
    $level = 'notice'
    if (-not $r.ok) { $level = 'warning' }
    Say $level 'AppContainer self-test in the session of the job' (Line $r)
} catch {
    Say 'warning' 'AppContainer self-test in the session of the job' ("it could not be run: " + $_.Exception.Message)
}
if ($OwnSessionOnly) { exit 0 }

try {
    # ---- a local account that never signs in
    $chars = 'abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'.ToCharArray()
    $pw = (-join (1..10 | ForEach-Object { $chars | Get-Random })) + 'aZ3!'
    Write-Host "::add-mask::${pw}"      # nothing prints it; should anything ever, the log shows *** instead
    & net.exe user $user $pw /add /y | Out-Null
    if ($LASTEXITCODE) { throw "the account could not be created (net user: $LASTEXITCODE)" }
    $made = $true
    # "Log on as a batch job": Task Scheduler gives it when a task is registered with a password; this group has
    # it on every Windows and gives nothing else of use (S-1-5-32-559, Performance Log Users)
    try { Add-LocalGroupMember -SID 'S-1-5-32-559' -Member $user } catch { Write-Host "note: $($_.Exception.Message)" }

    # what the installer does on an installation: the account reads the program, and sandboxes read the Python
    $pyBase = (& $Python -c "import sys; print(sys.base_prefix)").Trim()
    & icacls.exe $repo /grant "${user}:(OI)(CI)RX" /Q | Out-Null
    if ($LASTEXITCODE) { throw "icacls on the checkout failed ($LASTEXITCODE)" }
    & icacls.exe $pyBase /grant "${user}:(OI)(CI)RX" '*S-1-15-2-1:(OI)(CI)RX' '*S-1-15-2-2:(OI)(CI)RX' /Q | Out-Null
    if ($LASTEXITCODE) { throw "icacls on the Python folder failed ($LASTEXITCODE)" }
    & icacls.exe $out /grant "${user}:(OI)(CI)M" /Q | Out-Null
    if ($LASTEXITCODE) { throw "icacls on the result folder failed ($LASTEXITCODE)" }

    $result = Join-Path $out 'service.json'
    $action = New-ScheduledTaskAction -Execute $Python -Argument ('"{0}" "{1}"' -f $probe, $result) -WorkingDirectory $repo
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
    Register-ScheduledTask -TaskName $task -Action $action -Settings $settings -User "$env:COMPUTERNAME\$user" `
        -Password $pw -RunLevel Limited -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    $deadline = (Get-Date).AddMinutes(5)
    while (-not (Test-Path $result) -and (Get-Date) -lt $deadline) { Start-Sleep -Seconds 2 }
    if (-not (Test-Path $result)) {
        $info = Get-ScheduledTaskInfo -TaskName $task
        throw ('no result after 5 minutes; the last result of the task is 0x{0:X8}' -f [int64]$info.LastTaskResult)
    }
    $r = Get-Content $result -Raw | ConvertFrom-Json
    if ($r.ok) {
        Say 'notice' 'AppContainer self-test as a boot task' (Line $r)
    } else {
        Say 'warning' 'AppContainer self-test as a boot task' (Line $r)
        $failed = $true
    }
} catch {
    Say 'warning' 'AppContainer self-test as a boot task' ("it could not be run: " + $_.Exception.Message)
    $failed = $true
} finally {
    try { Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue } catch { }
    try { Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue } catch { }
    if ($made) { & net.exe user $user /delete | Out-Null }
}
if ($failed -and $Enforce) { exit 1 }
exit 0
