<#
.SYNOPSIS
  Registers the goose-web gateway task and inbound firewall rule. Needs an elevated prompt (except -DryRun).

.DESCRIPTION
  Two ways to run the gateway (both with RunLevel Limited, a normal non-elevated token; the gateway also refuses
  to run elevated by itself):

  -Mode Logon (default): the task starts when -User signs in to Windows and runs as that user (Interactive
     logon). For a personal machine where you use Goose under your own account.

  -Mode Service: the task starts at boot, without anyone signing in, as -User - a dedicated service account
     (DOMAIN\svc-goose or .\svc-goose) or a group managed service account (DOMAIN\gmsa-goose$). For a normal
     account you are asked for its password in a secure prompt (Windows stores it for the task; it is never
     written to a file); a gMSA needs no password. The account needs "Log on as a batch job" (Task Scheduler
     grants it when the task is registered; a domain policy may have to allow it). Use an account that is NOT
     an administrator.

  The firewall rule allows TCP <Port> only from -FirewallRemoteAddress (default LocalSubnet). Put the reverse
  proxy's IP there when one fronts the gateway.

  -DryRun prints what would be registered and changes nothing.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string]$User,          # DOMAIN\user, .\user, user, or DOMAIN\gmsa$
    [Parameter(Mandatory)] [string]$InstallDir,
    [Parameter(Mandatory)] [string]$ConfigPath,
    [ValidateSet('Logon', 'Service')] [string]$Mode = 'Logon',
    [int]$Port = 8710,
    [string]$TaskPath = '\GooseWeb\',
    [string]$TaskName = 'GooseWeb_Gateway',
    [string]$FirewallRemoteAddress = 'LocalSubnet',  # comma separated
    [switch]$NoFirewall,
    [switch]$NoTask,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
if (-not $TaskPath.StartsWith('\')) { $TaskPath = '\' + $TaskPath }
if (-not $TaskPath.EndsWith('\')) { $TaskPath += '\' }
$gmsa = $User.EndsWith('$')
if ($Mode -eq 'Logon' -and $gmsa) { throw "A group managed service account cannot sign in interactively: use -Mode Service." }

if (-not $NoTask) {
    $pyw = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
    if (-not (Test-Path $pyw)) {
        if ($DryRun) { Write-Host "[dry run] note: $pyw does not exist yet (run install.ps1 first)" }
        else { throw "Not found: $pyw (run install.ps1 first)" }
    }
    $arg = "-m goose_web --config `"$ConfigPath`" serve"
    if ($Mode -eq 'Service') {
        $desc = "Goose AI Web Interface gateway. Starts at boot as $User (no sign-in needed), never elevated."
        $logon = 'Password'
    } else {
        $desc = 'Goose AI Web Interface gateway. Runs as the signed-in user, never elevated.'
        $logon = 'Interactive'
    }
    if ($DryRun) {
        Write-Host "[dry run] task $TaskPath$TaskName"
        Write-Host "[dry run]   action:   `"$pyw`" $arg   (working folder $InstallDir)"
        Write-Host "[dry run]   trigger:  $(if ($Mode -eq 'Service') { 'at system startup' } else { "at logon of $User" })"
        Write-Host "[dry run]   runs as:  $User, logon type $logon$(if ($gmsa) { ' (gMSA, no password)' } elseif ($Mode -eq 'Service') { ' (password asked in a secure prompt)' }), run level Limited"
        Write-Host "[dry run]   restart:  every 1 min on failure (999 times), no time limit, one instance"
    } else {
        $action = New-ScheduledTaskAction -Execute $pyw -Argument $arg -WorkingDirectory $InstallDir
        $trigger = if ($Mode -eq 'Service') { New-ScheduledTaskTrigger -AtStartup } else { New-ScheduledTaskTrigger -AtLogOn -User $User }
        $principal = New-ScheduledTaskPrincipal -UserId $User -LogonType $logon -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
            -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) `
            -MultipleInstances IgnoreNew
        $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Description $desc
        if ($Mode -eq 'Service' -and -not $gmsa) {
            $cred = Get-Credential -UserName $User -Message "Password of $User (stored by Windows for the Goose Web task only)"
            if (-not $cred) { throw 'No password given; the task was not registered.' }
            Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -InputObject $task -User $cred.UserName `
                -Password $cred.GetNetworkCredential().Password -Force | Out-Null
        } else {
            Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -InputObject $task -Force | Out-Null
        }
        $t = Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
        Write-Host "Task $TaskPath$TaskName -> user $($t.Principal.UserId), logon $($t.Principal.LogonType), run level $($t.Principal.RunLevel)"
        if ($t.Principal.RunLevel -ne 'Limited') { throw 'Task run level is not Limited - refusing to leave it like this.' }
    }
}

if (-not $NoFirewall) {
    $name = "GooseWeb-Gateway-TCP-$Port"
    $remote = $FirewallRemoteAddress -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    if ($DryRun) {
        Write-Host "[dry run] firewall rule $name allows TCP $Port from: $($remote -join ', ')"
    } else {
        Get-NetFirewallRule -Name $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule
        New-NetFirewallRule -Name $name -DisplayName "Goose Web gateway (TCP $Port)" -Direction Inbound -Protocol TCP `
            -LocalPort $Port -RemoteAddress $remote -Action Allow -Profile Any | Out-Null
        Write-Host "Firewall rule $name allows TCP $Port from: $($remote -join ', ')"
    }
}
