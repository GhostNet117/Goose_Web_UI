<#
.SYNOPSIS
  Registers a start-up task that lets application containers use the NUL device and the mount manager at every
  start of Windows (grant-devices.ps1). For Windows Server with the AppContainer backend; ADMINISTRATION 11.6.
  Needs an elevated Windows PowerShell prompt (except -DryRun).

.DESCRIPTION
  What `goose-web sandbox devices grant` gives lasts until Windows restarts. This makes it stay:

    1. copies grant-devices.ps1 to <Program Files>\GooseWeb.Startup\ - a place only administrators can create
       anything in. The folder is made WITH its final access list (owner Administrators; SYSTEM and Administrators,
       nothing inherited); a folder that is already there is used only when nobody else can change it;
    2. registers the task \GooseWeb\GooseWeb_Devices: at system start-up, as SYSTEM, it runs Windows PowerShell
       with that copy;
    3. runs the task once now and checks that it ended well.

  WHAT IS TRUSTED. The copy is made from the grant-devices.ps1 beside this script, and this script itself runs
  elevated. Whoever can change these two files decides what runs as SYSTEM at every start. So both must come from
  a place only administrators (and you) can change. The script looks at that and stops when somebody else can
  write them; -TrustSource says you have compared them with the published release yourself. If Goose Web's install
  folder is writable by the account the gateway runs as, copy the two scripts from the release into a folder only
  administrators can write, and run them from there. (The check is a help for an honest mistake: somebody who can
  change this file can also take the check out.)

  1.24.1 and 1.24.2 put the copy in <ProgramData>\GooseWeb. A folder there can be made beforehand by any account
  of the machine, which then owns it (review of 2026-11-19, S-1). This version does not use it and removes that
  copy. If you registered the task with one of those versions: run this again, then restart Windows.

  -Remove takes the task and the copy away again (what was granted stays until Windows restarts).
  -DryRun prints what would be done and changes nothing.
#>
[CmdletBinding()]
param(
    [string]$TaskPath = '\GooseWeb\',
    [string]$TaskName = 'GooseWeb_Devices',
    [switch]$Remove,
    [switch]$NoRunNow,
    [switch]$DryRun,
    [switch]$TrustSource
)
$ErrorActionPreference = 'Stop'
if (-not $TaskPath.StartsWith('\')) { $TaskPath = '\' + $TaskPath }
if (-not $TaskPath.EndsWith('\')) { $TaskPath += '\' }
$FallbackTaskPath = '\GooseWeb.Startup\'      # used when the usual task folder was made by an account that is no administrator
$source = Join-Path $PSScriptRoot 'grant-devices.ps1'
$programFiles = if ($env:ProgramW6432) { $env:ProgramW6432 } else { $env:ProgramFiles }
$dir = Join-Path $programFiles 'GooseWeb.Startup'
$target = Join-Path $dir 'grant-devices.ps1'
$oldDir = Join-Path $env:ProgramData 'GooseWeb'             # where 1.24.1 and 1.24.2 put the copy
$oldTarget = Join-Path $oldDir 'grant-devices.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$arguments = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}"' -f $target

if ($DryRun) {
    if ($Remove) {
        Write-Host "[dry run] would remove the task $TaskPath$TaskName (and $FallbackTaskPath$TaskName), the file $target and an earlier copy $oldTarget"
    } else {
        Write-Host "[dry run] source:  $source - must be writable by nobody but SYSTEM, the Administrators and you (or -TrustSource)"
        Write-Host "[dry run] copy:    $source -> $target"
        Write-Host "[dry run] folder:  $dir - made with its access list: owner Administrators; only SYSTEM and Administrators; nothing inherited"
        Write-Host "[dry run] task:    $TaskPath$TaskName, at system start-up, as SYSTEM"
        Write-Host "[dry run] action:  `"$ps`" $arguments"
        Write-Host "[dry run] then:    run it once now and check its result; remove an earlier copy $oldTarget"
    }
    exit 0
}

if ($PSVersionTable.PSEdition -eq 'Core') {
    throw 'Run this with Windows PowerShell (powershell.exe), not PowerShell 7: it sets access lists with what only Windows PowerShell has.'
}
$me = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not (New-Object Security.Principal.WindowsPrincipal($me)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'This registers a task that runs as SYSTEM: run it from an elevated prompt (Run as administrator).'
}

$sidType = [Security.Principal.SecurityIdentifier]
$admins = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
$system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
# SYSTEM, the Administrators, and Windows' own installer (the owner of much of Program Files)
$trusted = @('S-1-5-18', 'S-1-5-32-544', 'S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464')
# rights with which a file or folder can be changed, replaced or taken over (file rights and the generic ones)
$changeMask = 0x116 -bor 0x40 -bor 0x10000 -bor 0x40000 -bor 0x80000 -bor 0x40000000 -bor 0x10000000

function Get-OtherWriters([string]$path, [string[]]$also) {
    # Who, other than SYSTEM, the Administrators, Windows' installer and $also, owns $path or may change it.
    $ok = $trusted + $also
    $acl = if (Test-Path -LiteralPath $path -PathType Container) { [IO.Directory]::GetAccessControl($path) } else { [IO.File]::GetAccessControl($path) }
    $found = @()
    $owner = $acl.GetOwner($sidType).Value
    if ($owner -notin $ok) { $found += "owner $owner" }
    foreach ($r in $acl.GetAccessRules($true, $true, $sidType)) {
        $sid = $r.IdentityReference.Value
        if ($r.AccessControlType -ne 'Allow' -or $sid -in $ok -or $sid -eq 'S-1-3-0') { continue }    # S-1-3-0: "whoever creates something below"
        if (([int]$r.FileSystemRights -band $changeMask) -ne 0) { $found += $sid }
    }
    return @($found | Select-Object -Unique)
}
function Get-TaskFolderOwner([string]$path) {
    # The owner of a Task Scheduler folder, or $null when it is not there (or cannot be asked).
    try {
        $svc = New-Object -ComObject Schedule.Service
        $svc.Connect()
        $sddl = $svc.GetFolder($path.TrimEnd('\')).GetSecurityDescriptor(1)
        return (New-Object Security.AccessControl.RawSecurityDescriptor($sddl)).Owner.Value
    } catch { return $null }
}
function Remove-OldCopy {
    # The copy 1.24.1 / 1.24.2 made in <ProgramData>\GooseWeb. Nothing is followed through a link.
    if (-not (Test-Path -LiteralPath $oldDir)) { return }
    $item = Get-Item -LiteralPath $oldDir -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Write-Host "NOTE: $oldDir is not a plain folder (a link?). It is not used any more and was left alone: look at it and remove it."
        return
    }
    if (Test-Path -LiteralPath $oldTarget -PathType Leaf) {
        Remove-Item -LiteralPath $oldTarget -Force
        Write-Host "Removed the copy an earlier version made: $oldTarget"
    }
    if (-not (Get-ChildItem -LiteralPath $oldDir -Force)) { [IO.Directory]::Delete($oldDir) }      # only when empty
}

if ($Remove) {
    foreach ($p in @($TaskPath, $FallbackTaskPath) | Select-Object -Unique) {
        Unregister-ScheduledTask -TaskPath $p -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $target -PathType Leaf) { Remove-Item -LiteralPath $target -Force }
    if ((Test-Path -LiteralPath $dir -PathType Container) -and -not (Get-ChildItem -LiteralPath $dir -Force)) { [IO.Directory]::Delete($dir) }
    Remove-OldCopy
    Write-Host "Removed the task $TaskName and $target. What was granted stays until Windows restarts."
    exit 0
}

if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Not found: $source" }

# ---- 0. what is about to be copied, and this script: can anybody but administrators (and you) change them?
$mine = @($me.User.Value)
$open = @()
foreach ($p in @((Split-Path $PSScriptRoot -Parent), $PSScriptRoot, $source, $PSCommandPath)) {
    if (-not $p) { continue }
    $w = Get-OtherWriters $p $mine
    if ($w.Count) { $open += ("{0}: {1}" -f $p, ($w -join ', ')) }
}
if ($open.Count -and -not $TrustSource) {
    throw ("What this script copies runs as SYSTEM at every start of Windows, and this script runs elevated now - so both must come " +
           "from a place only administrators can change. These can be changed by others:`n  " + ($open -join "`n  ") + "`n" +
           "Copy register-devices-task.ps1 and grant-devices.ps1 from the published release into a folder only administrators can " +
           "write, compare them with the release (Get-FileHash) and run this from there. -TrustSource skips this check when you " +
           "have compared them yourself. Nothing was changed.")
}
if ($open.Count) { Write-Host "NOTE (-TrustSource): the scripts can be changed by accounts that are not administrators: $($open -join '; ')" }

# ---- 1. a folder nobody but SYSTEM and administrators can write, and the copy in it
$inherit = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
$acl = New-Object Security.AccessControl.DirectorySecurity
$acl.SetOwner($admins)
$acl.SetAccessRuleProtection($true, $false)                 # protected: nothing from above
foreach ($sid in @($system, $admins)) {
    $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', $inherit, 'None', 'Allow')))
}
if (Test-Path -LiteralPath $dir) {
    $item = Get-Item -LiteralPath $dir -Force
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw "$dir exists and is not a plain folder (a link?). Remove it and run this again."
    }
    # A folder that is there is used only when it is the administrators' already: one that somebody else owns or
    # may change could have been prepared (a handle kept open outlasts a new access list).
    $w = Get-OtherWriters $dir @()
    if ($w.Count) {
        throw ("$dir exists and is not the administrators' alone ($($w -join ', ')). This script did not make it. Look at what " +
               "it is, remove it as an administrator, restart Windows (so that nothing keeps it open) and run this again.")
    }
    [IO.Directory]::SetAccessControl($dir, $acl)
} else {
    # made WITH its access list: there is no moment in which the folder has another one
    [void][IO.Directory]::CreateDirectory($dir, $acl)
}
$now = [IO.Directory]::GetAccessControl($dir)
if (-not $now.AreAccessRulesProtected -or (Get-OtherWriters $dir @()).Count) {
    throw "$dir did not get the access list it was given; nothing was registered."
}
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
$hash = [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($target))).Replace('-', '')
$same = $hash -eq [BitConverter]::ToString($sha.ComputeHash([IO.File]::ReadAllBytes($source))).Replace('-', '')
if (-not $same) { throw "The copy $target is not what was copied; nothing was registered." }
$rules = [IO.File]::GetAccessControl($target).GetAccessRules($true, $true, $sidType)
$seen = @($rules | Where-Object { $_.IdentityReference.Value -notin @('S-1-5-18', 'S-1-5-32-544') })
if ($seen.Count) { throw "The copy $target can be reached by more than SYSTEM and Administrators; nothing was registered." }
Write-Host "Copied to $target (only SYSTEM and Administrators may write it)"
Write-Host "SHA-256 of what runs as SYSTEM: $hash - compare it with grant-devices.ps1 of the published release"

# ---- 2. the task. Its folder in Task Scheduler: one that an account that is no administrator made is not used.
$owner = Get-TaskFolderOwner $TaskPath
if ($owner -and $owner -notin ($trusted + $mine)) {
    $other = Get-TaskFolderOwner $FallbackTaskPath
    if ($other -and $other -notin ($trusted + $mine)) {
        throw "The task folders $TaskPath and $FallbackTaskPath both belong to accounts that are not administrators ($owner, $other). Name another with -TaskPath."
    }
    Write-Host "NOTE: the task folder $TaskPath belongs to $owner, which is not an administrator: the task is registered in $FallbackTaskPath instead."
    $TaskPath = $FallbackTaskPath
}
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
# a task of the same name an earlier run left in the other folder would run the same file twice: taken away
foreach ($p in @('\GooseWeb\', $FallbackTaskPath) | Where-Object { $_ -ne $TaskPath }) {
    Unregister-ScheduledTask -TaskPath $p -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
}
Remove-OldCopy

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
