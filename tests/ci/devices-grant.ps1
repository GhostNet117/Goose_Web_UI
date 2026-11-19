<#
.SYNOPSIS
  CI only (a GitHub-hosted runner, thrown away after the job; the job runs as an administrator). Measures on this
  Windows what lets application containers in on the NUL device and the mount manager: `goose-web sandbox devices
  grant`, and the start-up task of scripts\register-devices-task.ps1 (registered, run once as SYSTEM, removed).
  What a program in a container cannot do is asked before, between and after. One annotation of the run.

.DESCRIPTION
  -TaskFirst lets the start-up task do the granting and the command come second (it then finds nothing to do);
  without it the other way round. So each of the two is seen to do the work on one of the two Windows versions.
  -Enforce fails the step when something is still out of reach in the end, or one of the two did not end well.
#>
[CmdletBinding()]
param(
    [string]$Python = (Get-Command python).Source,
    [switch]$TaskFirst,
    [switch]$Enforce
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This changes the access lists of two devices of this machine and registers a task as SYSTEM: for a GitHub-hosted runner only.' }
$probe = Join-Path $PSScriptRoot 'selftest_as_service.py'
$register = (Resolve-Path (Join-Path $PSScriptRoot '..\..\scripts\register-devices-task.ps1')).Path
$tmp = Join-Path $env:RUNNER_TEMP ('gwdev-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$title = 'What a container cannot do and what lets it'

function Say([string]$level, [string]$text) {
    $t = $text.Replace('%', '%25').Replace("`r", '%0D').Replace("`n", '%0A')
    Write-Host "::${level} title=${title}::${t}"
}
function Limits([string]$name) {
    $f = Join-Path $tmp $name
    & $Python $probe $f
    $r = Get-Content $f -Raw | ConvertFrom-Json
    if (-not $r.ok) { return "self-test FAILED: $($r.text) $($r.error)" }
    return "[$(@($r.limits) -join '; ')]"
}
function Native([string]$exe, [string[]]$a) {
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $o = (& $exe @a 2>&1 | ForEach-Object { "$_" }) -join ' | '
    $c = $LASTEXITCODE
    $ErrorActionPreference = $prev
    return @{ code = $c; text = "exit ${c}: $o" }
}
function Lists() { return (Native $Python @('-c', 'from goose_web import sandbox as sb; print(sb.devices_status())')).text }
function Grant() { return Native $Python @('-m', 'goose_web', 'sandbox', 'devices', 'grant') }
function Seen() {
    # What this Windows gives the things the task rests on (review 20261119_6: nobody had looked): the owner and
    # access list of the task folder and of the task, and of the folder the copy SYSTEM runs is in.
    $out = @()
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        foreach ($p in '\GooseWeb', '\GooseWeb.Startup') {
            try {
                $f = $svc.GetFolder($p)
                $out += "task folder ${p}: " + $f.GetSecurityDescriptor(7)
                try { $out += "task ${p}\GooseWeb_Devices: " + $f.GetTask('GooseWeb_Devices').GetSecurityDescriptor(7) } catch { }
            } catch { }
        }
    } catch { $out += "task scheduler could not be asked: $($_.Exception.Message)" }
    $pf = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
    foreach ($p in (Join-Path $pf 'GooseWeb.Startup'), (Join-Path $pf 'GooseWeb.Startup\grant-devices.ps1'), (Join-Path $env:ProgramData 'GooseWeb')) {
        if (Test-Path -LiteralPath $p) { $out += "${p}: " + (Get-Acl -LiteralPath $p).Sddl } else { $out += "${p}: not there" }
    }
    return ($out -join ' ; ')
}
function Task() {
    # -TrustSource: the checkout of a throw-away runner; what the source check found is in the script's own output
    $r = Native 'powershell.exe' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $register, '-TrustSource')
    $r.text = $r.text + ' || SEEN: ' + (Seen)
    return $r
}

$failed = $false
try {
    $before = Limits 'before.json'
    $listsBefore = Lists
    if ($TaskFirst) { $one = Task; $oneName = 'START-UP TASK' } else { $one = Grant; $oneName = 'GRANT' }
    $between = Limits 'between.json'
    $listsBetween = Lists
    if ($TaskFirst) { $two = Grant; $twoName = 'GRANT' } else { $two = Task; $twoName = 'START-UP TASK' }
    $after = Limits 'after.json'
    $status = (Native $Python @('-m', 'goose_web', 'sandbox', 'devices')).text
    $line = "BEFORE a program in a container cannot: $before; devices: $listsBefore. FIRST $oneName ($($one.text)). " +
            "THEN it cannot: $between; devices: $listsBetween. SECOND $twoName ($($two.text)). IN THE END it cannot: $after. STATUS: $status"
    if ($between -eq '[]' -and $after -eq '[]' -and -not $one.code -and -not $two.code) { Say 'notice' $line } else { Say 'warning' $line; $failed = $true }
} catch {
    Say 'warning' ("it could not be run: " + $_.Exception.Message)
    $failed = $true
} finally {
    try { [void](Native 'powershell.exe' @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', $register, '-Remove')) } catch { }
}
if ($failed -and $Enforce) { exit 1 }
exit 0
