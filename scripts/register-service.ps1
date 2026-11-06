<#
.SYNOPSIS
  Registers the goose-web logon task and inbound firewall rule. Needs an elevated prompt.

.DESCRIPTION
  The task ALWAYS runs as the given user with an Interactive logon and RunLevel Limited (a normal,
  non-elevated token), even though this script itself runs elevated. That keeps every file goose-web and
  Goose create owned by that user - never SYSTEM or Administrators. The gateway also refuses to run
  elevated by itself (it relaunches with a normal token or exits).

  The firewall rule allows TCP <Port> only from -FirewallRemoteAddress (default LocalSubnet). Put the
  reverse proxy's IP there when one fronts the gateway.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$User,          # DOMAIN\user or user
    [Parameter(Mandatory)] [string]$InstallDir,
    [Parameter(Mandatory)] [string]$ConfigPath,
    [int]$Port = 8710,
    [string]$TaskPath = '\GooseWeb\',
    [string]$TaskName = 'GooseWeb_Gateway',
    [string]$FirewallRemoteAddress = 'LocalSubnet',  # comma separated
    [switch]$NoFirewall,
    [switch]$NoTask
)
$ErrorActionPreference = 'Stop'
if (-not $TaskPath.StartsWith('\')) { $TaskPath = '\' + $TaskPath }
if (-not $TaskPath.EndsWith('\')) { $TaskPath += '\' }

if (-not $NoTask) {
    $pyw = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
    if (-not (Test-Path $pyw)) { throw "Not found: $pyw (run install.ps1 first)" }
    $action = New-ScheduledTaskAction -Execute $pyw -Argument "-m goose_web --config `"$ConfigPath`" serve" -WorkingDirectory $InstallDir
    $trigger = New-ScheduledTaskTrigger -AtLogOn -User $User
    $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType Interactive -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
        -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
        -MultipleInstances IgnoreNew
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'Goose AI Web Interface gateway. Runs as the signed-in user, never elevated.'
    Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -InputObject $task -Force | Out-Null
    $t = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
    Write-Host "Task $TaskPath$TaskName -> user $($t.Principal.UserId), logon $($t.Principal.LogonType), run level $($t.Principal.RunLevel)"
    if ($t.Principal.RunLevel -ne 'Limited') { throw 'Task run level is not Limited - refusing to leave it like this.' }
}

if (-not $NoFirewall) {
    $name = "GooseWeb-Gateway-TCP-$Port"
    Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
    $remote = $FirewallRemoteAddress -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    New-NetFirewallRule -Name $name -DisplayName "Goose Web gateway (TCP $Port)" -Direction Inbound -Protocol TCP `
        -LocalPort $Port -RemoteAddress $remote -Action Allow -Profile Any | Out-Null
    Write-Host "Firewall rule $name allows TCP $Port from: $($remote -join ', ')"
}
