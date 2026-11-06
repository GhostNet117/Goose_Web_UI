<#
.SYNOPSIS
  Removes the goose-web logon task and firewall rule (elevated prompt). Data is kept.

.DESCRIPTION
  Profiles, the database and logs under the profiles root are NOT deleted, and the Goose profile is never
  touched. Delete the profiles root and the install folder by hand if you want everything gone.
#>
[CmdletBinding()]
param(
    [int]$Port = 8710,
    [string]$TaskPath = '\GooseWeb\',
    [string]$TaskName = 'GooseWeb_Gateway'
)
$ErrorActionPreference = 'Continue'
if (-not $TaskPath.EndsWith('\')) { $TaskPath += '\' }
$t = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -ErrorAction SilentlyContinue
if ($t) {
    Stop-ScheduledTask -InputObject $t -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -InputObject $t -Confirm:$false
    Write-Host "Removed task $TaskPath$TaskName"
}
Get-NetFirewallRule -Name "GooseWeb-Gateway-TCP-$Port" -ErrorAction SilentlyContinue | Remove-NetFirewallRule
Write-Host "Removed firewall rule GooseWeb-Gateway-TCP-$Port (if present). Data was kept."
