<#
.SYNOPSIS
  Lets application containers use the NUL device and the mount manager, as Windows 11 does. For Windows Server,
  where a member's agent in an AppContainer otherwise cannot start a program ("failed to open NUL device for child
  stdin") and Goose skips the member's hints ("Import boundary directory not found"). ADMINISTRATION 11.6.

.DESCRIPTION
  The same as `goose-web sandbox devices grant`, without Goose Web: this file needs nothing but Windows, so that a
  start-up task can run it as SYSTEM from a folder only administrators can write (register-devices-task.ps1 puts
  a copy there). A task that ran Goose Web's own Python as SYSTEM would let whoever can change the install folder
  become SYSTEM.

  On each of the two devices, ALL APPLICATION PACKAGES (S-1-15-2-1) and ALL RESTRICTED APPLICATION PACKAGES
  (S-1-15-2-2) get what Windows 11 gives them, where they do not have it. Only ever adds. Applies to every
  application container on the machine. Lasts until Windows restarts.

  Needs an administrator when something has to be added; says so otherwise. Exit code 0 = both devices let
  application packages in, 1 = not.
#>
$ErrorActionPreference = 'Stop'
$devices = [ordered]@{ '\\.\NUL' = 0x001201BF; '\\.\MountPointManager' = 0x001200A0 }
$groups = @('S-1-15-2-1', 'S-1-15-2-2')

Add-Type -Namespace GooseWeb -Name Device -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
public static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security, uint disposition, uint flags, IntPtr template);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool GetKernelObjectSecurity(IntPtr handle, uint information, byte[] descriptor, uint length, out uint needed);
[DllImport("advapi32.dll", SetLastError = true)]
public static extern bool SetKernelObjectSecurity(IntPtr handle, uint information, byte[] descriptor);
[DllImport("kernel32.dll")]
public static extern bool CloseHandle(IntPtr handle);
'@

function Open-Device([string]$name, [uint32]$access) {
    $h = [GooseWeb.Device]::CreateFileW($name, $access, 7, [IntPtr]::Zero, 3, 0, [IntPtr]::Zero)
    if ($h -eq [IntPtr]::Zero -or $h.ToInt64() -eq -1) { return $null }
    return $h
}

function Read-Descriptor([IntPtr]$h) {
    $needed = [uint32]0
    [void][GooseWeb.Device]::GetKernelObjectSecurity($h, 4, $null, 0, [ref]$needed)      # 4 = the access list
    if (-not $needed) { throw "its access list cannot be read ($([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
    $buf = New-Object byte[] $needed
    if (-not [GooseWeb.Device]::GetKernelObjectSecurity($h, 4, $buf, $needed, [ref]$needed)) {
        throw "its access list cannot be read ($([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    }
    return New-Object System.Security.AccessControl.RawSecurityDescriptor($buf, 0)
}

function Get-Missing($sd, [int]$mask) {
    # the groups that the entries applying to the device itself do not give all of $mask
    $missing = @()
    foreach ($g in $groups) {
        $sid = New-Object System.Security.Principal.SecurityIdentifier($g)
        $have = 0
        foreach ($ace in $sd.DiscretionaryAcl) {
            if ($ace -is [System.Security.AccessControl.CommonAce] -and
                $ace.AceQualifier -eq [System.Security.AccessControl.AceQualifier]::AccessAllowed -and
                $ace.SecurityIdentifier -eq $sid -and
                -not ([int]$ace.AceFlags -band 8)) {                 # 8 = an entry for what is inside only
                $have = $have -bor $ace.AccessMask
            }
        }
        if (($have -band $mask) -ne $mask) { $missing += $g }
    }
    return ,$missing
}

$failed = $false
foreach ($name in $devices.Keys) {
    $mask = [int]$devices[$name]
    try {
        $h = Open-Device $name 0x00020000                    # READ_CONTROL
        if (-not $h) { throw "it cannot be opened ($([Runtime.InteropServices.Marshal]::GetLastWin32Error()))" }
        try { $sd = Read-Descriptor $h } finally { [void][GooseWeb.Device]::CloseHandle($h) }
        if ($null -eq $sd.DiscretionaryAcl) { Write-Output "ok       ${name}: it has no access list, everybody is let in"; continue }
        $missing = Get-Missing $sd $mask
        if (-not $missing.Count) { Write-Output "ok       ${name}: application packages are let in"; continue }
        $h = Open-Device $name 0x00060000                    # READ_CONTROL | WRITE_DAC
        if (-not $h) {
            throw "application packages are NOT let in, and this account may not change that ($([Runtime.InteropServices.Marshal]::GetLastWin32Error())): run this as an administrator"
        }
        try {
            $sd = Read-Descriptor $h
            $missing = Get-Missing $sd $mask
            foreach ($g in $missing) {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($g)
                $ace = New-Object System.Security.AccessControl.CommonAce(
                    [System.Security.AccessControl.AceFlags]::None, [System.Security.AccessControl.AceQualifier]::AccessAllowed,
                    $mask, $sid, $false, $null)
                $sd.DiscretionaryAcl.InsertAce($sd.DiscretionaryAcl.Count, $ace)      # added at the end; nothing is taken off
            }
            $out = New-Object byte[] $sd.BinaryLength
            $sd.GetBinaryForm($out, 0)
            if (-not [GooseWeb.Device]::SetKernelObjectSecurity($h, 4, $out)) {
                throw "its access list could not be changed ($([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
            }
            if ((Get-Missing (Read-Descriptor $h) $mask).Count) { throw 'application packages are still not let in' }
            Write-Output "granted  ${name}: $($missing -join ', ') (until Windows restarts)"
        } finally { [void][GooseWeb.Device]::CloseHandle($h) }
    } catch {
        Write-Output "FAILED   ${name}: $($_.Exception.Message)"
        $failed = $true
    }
}
if ($failed) { exit 1 }
exit 0
