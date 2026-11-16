<#
.SYNOPSIS
  Registers a start-up task that lets application containers use the NUL device and the mount manager at every
  start of Windows (grant-devices.ps1). For Windows Server with the AppContainer backend; ADMINISTRATION 11.6.
  Needs an elevated prompt (except -DryRun).

.DESCRIPTION
  What `goose-web sandbox devices grant` gives lasts until Windows restarts. This makes it stay:

    1. copies grant-devices.ps1 to <ProgramData>\GooseWeb\ - a folder that is given to the Administrators and that
       only SYSTEM and administrators can write (the folder's access list is REPLACED, nothing is inherited);
    2. registers the task \GooseWeb\GooseWeb_Devices: at system start-up, as SYSTEM, it runs Windows PowerShell
       with that copy. Nothing of Goose Web's own folder is run as SYSTEM;
    3. runs the task once now and checks that it ended well.

  -Remove takes the task and the copy away again (what was granted stays until Windows restarts).
  -DryRun prints what would be done and changes nothing.
#>
[CmdletBinding()]
param(
    [string]$TaskPath = '\GooseWeb\',
    [string]$TaskName = 'GooseWeb_Devices',
    [switch]$Remove,
    [switch]$NoRunNow,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
if (-not $TaskPath.StartsWith('\')) { $TaskPath = '\' + $TaskPath }
if (-not $TaskPath.EndsWith('\')) { $TaskPath += '\' }
$source = Join-Path $PSScriptRoot 'grant-devices.ps1'
$dir = Join-Path $env:ProgramData 'GooseWeb'
$target = Join-Path $dir 'grant-devices.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $target

if ($DryRun) {
    if ($Remove) {
        Write-Host "[dry run] would remove the task $TaskPath$TaskName and the file $target"
    } else {
        Write-Host "[dry run] copy:    $source -> $target"
        Write-Host "[dry run] folder:  $dir - owner Administrators; only SYSTEM and Administrators may write; nothing inherited"
        Write-Host "[dry run] task:    $TaskPath$TaskName, at system start-up, as SYSTEM"
        Write-Host "[dry run] action:  `"$ps`" $arguments"
        Write-Host "[dry run] then:    run it once now and check its result"
    }
    exit 0
}

$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This registers a task that runs as SYSTEM: run it from an elevated prompt (Run as administrator).'
}

if ($Remove) {
    Unregister-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }
    Write-Host "Removed the task $TaskPath$TaskName and $target. What was granted stays until Windows restarts."
    exit 0
}

if (-not (Test-Path -LiteralPath $source)) { throw "Not found: $source" }

# ---- 1. a folder nobody but SYSTEM and administrators can write, and the copy in it
if (Test-Path -LiteralPath $dir) {
    $item = Get-Item -LiteralPath $dir -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$dir exists and is not a plain folder (a link?). Remove it and run this again."
    }
} else {
    New-Item -ItemType Directory -Path $dir | Out-Null
}
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)                 # protected: nothing from above
foreach ($sid in @($system, $admins)) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')))
}
[IO.Directory]::SetAccessControl($dir, $acl)
if (Test-Path -LiteralPath $target) { Remove-Item -LiteralPath $target -Force }      # never written through what was there
Copy-Item -LiteralPath $source -Destination $target
$facl = New-Object Security.AccessControl.FileSecurity
$facl.SetOwner($admins)
$facl.SetAccessRuleProtection($true, $false)
foreach ($sid in @($system, $admins)) {
    $facl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')))
}
[IO.File]::SetAccessControl($target, $facl)
# checked with .NET alone: Windows PowerShell started from PowerShell 7 cannot always load its own cmdlets for this
$sha = [Security.Cryptography.SHA256]::Create()
$same = [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($target))) -eq
        [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($source)))
if (-not $same) { throw "The copy $target is not what was copied; nothing was registered." }
$rules = [IO.File]::GetAccessControl($target).GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])
$seen = @($rules | Where-Object { $_.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') })
if ($seen.Count) { throw "The copy $target can be reached by more than SYSTEM and Administrators; nothing was registered." }
Write-Host "Copied to $target (only SYSTEM and Administrators may write it)"

# ---- 2. the task
$action = New-ScheduledTaskAction -Execute $ps -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtStartup
$systemName = $system.Translate([Security.Principal.NTAccount]).Value      # its name in the language of this Windows
$principal = New-ScheduledTaskPrincipal -UserId $systemName -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 5)
$description = 'Goose Web: lets application containers use the NUL device and the mount manager, as Windows 11 does (ADMINISTRATION 11.6).'
Register-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal `
    -Settings $settings -Description $description -Force | Out-Null
Write-Host "Registered $TaskPath$TaskName (at system start-up, as SYSTEM)"

# ---- 3. once now
if (-not $NoRunNow) {
    Start-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName
    $deadline = (Get-Date).AddSeconds(90)
    do {
        Start-Sleep -Seconds 2
        $state = (Get-ScheduledTask -TaskPath $TaskPath -TaskName $TaskName).State
    } while ($state -eq 'Running' -and (Get-Date) -lt $deadline)
    $result = (Get-ScheduledTaskInfo -TaskPath $TaskPath -TaskName $TaskName).LastTaskResult
    if ($state -eq 'Running') { throw 'The task is still running after 90 seconds.' }
    if ($result -ne 0) {
        $text = 'The task ended with 0x{0:X8}. If this machine allows only signed scripts, the task cannot run this ' +
                'file: use "goose-web sandbox devices grant" from an elevated prompt after each restart instead.'
        throw ($text -f [int64]$result)
    }
    Write-Host 'The task ran: application containers are let in on both devices now and after every restart.'
}
exit 0
