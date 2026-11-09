<#
.SYNOPSIS
  Removes the goose-web logon task and firewall rule (elevated prompt) and the agents' sandbox containers. Data is kept.

.DESCRIPTION
  Stops the gateway task, then runs "goose-web sandbox remove --all": every per-user AppContainer's folder grants
  (profiles, team folders, the goose and Python folders, sandbox.read_dirs) are revoked, relayed provider URLs are
  restored and the containers are deleted. AppContainer profiles belong to the account that runs the gateway: run
  this as that account (for a service account, run the sandbox step as it: <install>\.venv\Scripts\python.exe -m
  goose_web --config <config.yaml> sandbox remove --all). -KeepSandbox skips the step. Then the task and the
  firewall rule are removed.

  Profiles, the database and logs under the profiles root are NOT deleted, and the Goose profile is never
  touched. Delete the profiles root and the install folder by hand if you want everything gone.
#>
[CmdletBinding()]
param(
    [int]$Port = 8710,
    [string]$TaskPath = '\GooseWeb\',
    [string]$TaskName = 'GooseWeb_Gateway',
    [string]$ConfigPath = '',          # config.yaml; '' = taken from the task's --config argument
    [switch]$KeepSandbox               # leave the sandbox containers and their folder grants in place
)
$ErrorActionPreference = 'Continue'
if (-not $TaskPath.EndsWith('\')) { $TaskPath += '\' }
$InstallDir = Split-Path -Parent $PSScriptRoot
$venvPy = Join-Path $InstallDir '.venv\Scripts\python.exe'
$t = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
if ($t -and -not $ConfigPath) {
    $taskArgs = ($t.Actions | Select-Object -First 1).Arguments
    if ($taskArgs -match '--config\s+"([^"]+)"') { $ConfigPath = $Matches[1] } elseif ($taskArgs -match '--config\s+(\S+)') { $ConfigPath = $Matches[1] }
}
if ($t) {
    Stop-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue   # the workers must end before their containers go
    Start-Sleep 3
}
if (-not $KeepSandbox) {
    if ((Test-Path $venvPy) -and $ConfigPath -and (Test-Path $ConfigPath)) {
        & $venvPy -m goose_web --config $ConfigPath sandbox remove --all
        if ($LASTEXITCODE) { Write-Warning "goose-web sandbox remove --all exited with $LASTEXITCODE; run it again as the gateway's account." }
    } else {
        Write-Warning ("Sandbox containers were not removed (no .venv or config.yaml found). Run as the gateway's account: " +
            "<install>\.venv\Scripts\python.exe -m goose_web --config <config.yaml> sandbox remove --all")
    }
}
if ($t) {
    Unregister-ScheduledTask -InputObject $t -Confirm:$false
    Write-Host "Removed task $TaskPath$TaskName"
}
Get-NetFirewallRule -Name "GooseWeb-Gateway-TCP-$Port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Removed firewall rule GooseWeb-Gateway-TCP-$Port (if present). Data was kept."
