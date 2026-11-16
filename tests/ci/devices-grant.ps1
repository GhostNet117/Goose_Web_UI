<#
.SYNOPSIS
  CI only (a GitHub-hosted runner, thrown away after the job; the job runs as an administrator). Measures what
  `goose-web sandbox devices grant` does on this Windows: what a program in an application container cannot do
  before it (the NUL device, real paths), the access lists of the two devices before and after, and what it
  cannot do afterwards. Each result is an annotation of the run.

.DESCRIPTION
  -Enforce fails the step when something is still out of reach after the grant. Without it the step only reports:
  this was written before the grant had been seen to work on Windows Server.
#>
[CmdletBinding()]
param(
    [string]$Python = (Get-Command python).Source,
    [switch]$Enforce
)
$ErrorActionPreference = 'Stop'
if ($env:GITHUB_ACTIONS -ne 'true') { throw 'This changes the access lists of two devices of this machine: for a GitHub-hosted runner only.' }
$probe = Join-Path $PSScriptRoot 'selftest_as_service.py'
$tmp = Join-Path $env:RUNNER_TEMP ('gwdev-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Force $tmp | Out-Null
$title = 'What a container cannot do and the devices grant'

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
function Lists() {
    $code = 'from goose_web import sandbox as sb' + "`n" + 'print(sb.devices_status())'
    return ((& $Python -c $code) -join ' ')
}
$failed = $false
try {
    $before = Limits 'before.json'
    $listsBefore = Lists
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
    $grant = (& $Python -m goose_web sandbox devices grant 2>&1 | ForEach-Object { "$_" }) -join ' | '
    $code = $LASTEXITCODE
    $ErrorActionPreference = $prev
    $after = Limits 'after.json'
    $line = "BEFORE a program in a container cannot: $before; devices: $listsBefore. GRANT (exit $code): $grant. AFTER it cannot: $after; devices: $(Lists)."
    if ($after -eq '[]') { Say 'notice' $line } else { Say 'warning' $line; $failed = $true }
} catch {
    Say 'warning' ("it could not be run: " + $_.Exception.Message)
    $failed = $true
}
if ($failed -and $Enforce) { exit 1 }
exit 0
