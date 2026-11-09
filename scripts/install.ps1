<#
.SYNOPSIS
  Installs Goose AI Web Interface (goose-web) on Windows with a guided setup.

.DESCRIPTION
  Run it from a normal (NOT elevated) PowerShell in the install folder (the git clone). Without -NonInteractive it
  asks, with detected defaults, for:
    1. the Goose program (the folder Goose is installed in, or goose.exe itself),
    2. the first administrator's Goose data: an existing Goose appdata folder (config\, data\, state\ - Goose
       Desktop's folder is %APPDATA%\Block\goose unless GOOSE_PATH_ROOT points elsewhere) with its chat sessions, or
       a fresh, empty one; and, if the chat sessions live in another folder, that folder (it is linked in as
       <appdata>\data\sessions, which is the only place Goose reads them from),
    3. the administrator's Goose Web user name,
    4. where Goose Web keeps its own data (users, teams, per-user profiles),
    5. which Windows account runs the gateway: you, starting when you sign in; or a service account (or gMSA)
       that starts it at boot without anyone signing in,
    6. whether non-admin users' agents are sandboxed (Windows AppContainer, recommended).
  It shows a summary and asks before changing anything. Every question also has a parameter, so the same install
  can be scripted with -NonInteractive.

  Steps after the questions: .venv with the hash-locked dependencies; <ProfilesRoot>\_system\config.yaml (kept if it
  exists); permissions for the service account (if one runs the gateway); "goose-web init" (first admin with a random
  initial password, shown once at the end); "goose-web check"; the gateway task + firewall rule via
  register-service.ps1 (one elevation prompt; for a service account it asks for the account's password there).
  The installer never changes files inside the Goose appdata folder; it can only add the sessions link and grant the
  service account access.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -NonInteractive -GooseBinary C:\AI\Goose `
    -GooseAppData C:\AI\Goose_appdata -ProfilesRoot C:\AI\Goose_Web_Profiles -RunAs CORP\svc-goose `
    -BindHost 192.168.1.50 -PublicUrl https://goose.example.org -TrustedProxy 192.168.1.10
#>
[CmdletBinding()]
param(
    [string]$ProfilesRoot = 'C:\Goose_Web_Profiles',
    [string]$GooseAppData = '',              # existing Goose appdata folder; '' = auto-detect; 'fresh' = new at <ProfilesRoot>\appdata
    [switch]$Fresh,                          # create a NEW, empty Goose appdata folder at -GooseAppData
    [string]$SessionsDir = '',               # chat sessions kept outside <appdata>\data\sessions: linked in (directory junction)
    [string]$GooseBinary = '',               # goose.exe, or the folder Goose is installed in; '' = auto-detect
    [string]$RunAs = '',                     # Windows account for the gateway: '' = you (at logon); DOMAIN\svc or DOMAIN\gmsa$ = at boot
    [ValidateSet('on', 'off', '')] [string]$Sandbox = '',   # sandbox non-admin users' agents ('' = on)
    [ValidateSet('auto', 'self-signed', 'off', '')] [string]$Tls = '',   # HTTPS: built-in certificate, or off behind a proxy ('' = auto)
    [switch]$TrustCert,                      # trust the built-in certificate's CA on this computer (current user)
    [string]$BindHost = '127.0.0.1',         # use the LAN IP (or 0.0.0.0) when a reverse proxy on another host connects
    [int]$Port = 8710,
    [string]$PublicUrl = '',                 # e.g. https://goose.example.org (enables Secure cookies + HSTS)
    [string[]]$TrustedProxy = @(),           # reverse proxy IPs whose X-Forwarded-For is trusted
    [string[]]$FirewallRemoteAddress = @('LocalSubnet'),
    [string]$TaskPath = '\GooseWeb\',
    [string]$Admin = '',                     # first administrator's Goose Web user name ('' = your Windows user name)
    [switch]$NoService,                      # skip task + firewall registration
    [switch]$NonInteractive,
    [switch]$AllowElevated,
    [switch]$Reregister                      # register the gateway task again although one exists for this install
)

$ErrorActionPreference = 'Stop'
$InstallDir = Split-Path -Parent $PSScriptRoot
function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }
function Ask($q, $default) {
    if ($NonInteractive) { return $default }
    $a = Read-Host ("$q" + $(if ($default) { " [$default]" } else { '' }))
    if ([string]::IsNullOrWhiteSpace($a)) { return $default } else { return $a.Trim().Trim('"') }
}
function Is-DesktopApp([string]$exe) {   # Goose Desktop's own Goose.exe (Electron) sits next to resources\app.asar
    return (Test-Path (Join-Path (Split-Path $exe) 'resources\app.asar'))
}
function Resolve-Goose([string]$p) {   # the goose CLI: goose.exe, or a folder that contains it (Goose Desktop: resources\bin)
    if (-not $p) { return '' }
    if (Test-Path $p -PathType Leaf) {
        $p = (Resolve-Path $p).Path
        if (-not (Is-DesktopApp $p)) { return $p }
        $p = Split-Path $p            # the Desktop app was given: look for its bundled CLI instead
    }
    foreach ($sub in @('resources\bin\goose.exe', 'bin\goose.exe', 'goose.exe')) {
        $c = Join-Path $p $sub
        if ((Test-Path $c -PathType Leaf) -and -not (Is-DesktopApp $c)) { return (Resolve-Path $c).Path }
    }
    return ''
}
function Find-Goose {
    $c = (Get-Command goose -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if ($c) { return $c }
    foreach ($d in @("$env:LOCALAPPDATA\Programs\Goose", "$env:ProgramFiles\Goose", "$env:USERPROFILE\.local\bin")) {
        $g = Resolve-Goose $d; if ($g) { return $g }
    }
    return ''
}
function Count-Chats([string]$root) {
    $db = Join-Path $root 'data\sessions\sessions.db'
    if (-not (Test-Path $db)) { return -1 }
    $py = (Get-Command python -ErrorAction SilentlyContinue | Select-Object -First 1).Source
    if (-not $py) { return -2 }
    $prev = $ErrorActionPreference; $ErrorActionPreference = 'Continue'   # information only: never stop the setup
    try {
        $n = & $py -c "import pathlib,sqlite3,sys;c=sqlite3.connect(pathlib.Path(sys.argv[1]).resolve().as_uri()+'?mode=ro',uri=True);print(c.execute('select count(*) from sessions').fetchone()[0])" $db 2>$null
        if ($LASTEXITCODE -or -not ("$n" -match '^\s*\d+\s*$')) { return -2 } else { return [int]"$n".Trim() }
    } catch { return -2 } finally { $ErrorActionPreference = $prev }
}

# --- 0. never elevated -------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($elevated -and -not $AllowElevated) {
    Write-Host "This installer must run as the normal Windows user (not 'Run as administrator')." -ForegroundColor Red
    Write-Host "Files created elevated are owned by Administrators and break Goose. Open a normal PowerShell and re-run." -ForegroundColor Red
    exit 3
}
Say "goose-web setup in $InstallDir (you are $($id.Name))"
$venvPyw = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
$existingTask = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.Actions | Where-Object { $_.Execute -and ($_.Execute.Trim('"') -ieq $venvPyw) } })
if ($existingTask.Count) {
    Warn ("This install already has a gateway task: " + (($existingTask | ForEach-Object { $_.TaskPath + $_.TaskName }) -join ', ') +
        ". To upgrade, stop here and run scripts\upgrade.ps1 (keeps every setting, backs up first).")
}
if ($InstallDir -like "$env:SystemDrive\Users\*" -and $RunAs) {
    Warn "The install folder is inside a user profile; a service account may not be able to read it. Prefer e.g. C:\AI\Goose_Web."
}

# --- 1. guided questions ---------------------------------------------------------
if (-not $NonInteractive) {
    Write-Host ""
    Write-Host "Guided setup - press Enter to accept the value in [brackets]." -ForegroundColor Green
    Write-Host ""
    Write-Host "1/6  Goose program: the folder Goose is installed in (e.g. C:\AI\Goose), or goose.exe itself."
}
$gooseExe = Resolve-Goose $(if ($GooseBinary) { $GooseBinary } else { Ask '     Goose folder or goose.exe' (Find-Goose) })
while (-not $gooseExe -and -not $NonInteractive) {
    Warn "No goose.exe there (looked for goose.exe, resources\bin\goose.exe, bin\goose.exe)."
    $gooseExe = Resolve-Goose (Ask '     Goose folder or goose.exe' '')
}
if (-not $gooseExe) { throw "Goose CLI not found. Pass -GooseBinary <Goose folder or goose.exe>." }
$gv = & $gooseExe --version 2>&1 | Select-Object -First 1
if ($LASTEXITCODE) { throw "The Goose CLI did not run: $gooseExe ($gv)" }
Say "Goose CLI: $gooseExe ($("$gv".Trim()))"
# Goose Web supports Goose 1.50 and later (tested with every release 1.50.0 - 1.57.0); see docs/ADMINISTRATION.md 11.7.
$gvm = [regex]::Match("$gv", '(\d+)\.(\d+)')
if ($gvm.Success) {
    $gvt = [version]("{0}.{1}" -f $gvm.Groups[1].Value, $gvm.Groups[2].Value)
    if ($gvt -lt [version]'1.50') { throw "Goose $gvt is too old for Goose Web (1.50 or later is needed). Upgrade Goose first." }
    if ($gvt -lt [version]'1.55') { Warn "Goose $gvt works with Goose Web. Later Goose versions add: tool shim (1.51), live voice (1.52), a per-chat system prompt that survives restarts and the GOOSE_AUTO_COMPACT_TOKEN_LIMIT setting (1.55). See docs\ADMINISTRATION.md 11.7." }
}

$detected = ''
if ($env:GOOSE_PATH_ROOT -and (Test-Path (Join-Path $env:GOOSE_PATH_ROOT 'config'))) { $detected = $env:GOOSE_PATH_ROOT }
elseif (Test-Path (Join-Path $env:APPDATA 'Block\goose\config')) { $detected = Join-Path $env:APPDATA 'Block\goose' }
$native = $GooseAppData
if (-not $NonInteractive -and -not $native) {
    Write-Host ""
    Write-Host "2/6  The first administrator's Goose data."
    Write-Host "     [1] use an existing Goose appdata folder (keeps its chats, recipes, extensions, providers)"
    Write-Host "     [2] start fresh: a new, empty Goose appdata folder"
    $choice = Ask '     Choose 1 or 2' $(if ($detected) { '1' } else { '2' })
    if ($choice -eq '2') {
        $native = Ask '     New Goose appdata folder' 'C:\AI\Goose_appdata'
        $Fresh = $true
    } else {
        $native = Ask '     Goose appdata folder (contains config\ and data\)' $detected
    }
}
if (-not $native) { $native = if ($detected) { $detected } else { 'fresh' } }
if ($native -ne 'fresh') {
    if ($Fresh) {
        if ((Test-Path (Join-Path $native 'config')) -and (Get-ChildItem (Join-Path $native 'config') -ErrorAction SilentlyContinue)) {
            throw "$native already contains a Goose configuration; choose 'existing' or another folder."
        }
        foreach ($s in 'config', 'data', 'state') { New-Item -ItemType Directory -Force -Path (Join-Path $native $s) | Out-Null }
        Say "Created a fresh Goose appdata folder: $native"
    } elseif (-not (Test-Path (Join-Path $native 'config'))) {
        throw "Not a Goose appdata folder (no config\ inside): $native"
    }
    $chats = Count-Chats $native
    if ($chats -ge 0) { Say "Chat sessions in $native\data\sessions: $chats" }
    elseif ($chats -eq -1) { Say "No chat sessions yet in $native\data\sessions" }
    if (-not $NonInteractive -and -not $SessionsDir) {
        $SessionsDir = Ask "     Are your chat sessions in another folder? Path, or Enter to keep $native\data\sessions" ''
    }
    if ($SessionsDir) {
        $link = Join-Path $native 'data\sessions'
        $target = (Resolve-Path $SessionsDir -ErrorAction Stop).Path
        if (-not (Test-Path (Join-Path $target 'sessions.db'))) { Warn "No sessions.db in $target (Goose will create one there)." }
        if (Test-Path $link) {
            $item = Get-Item $link -Force
            if ($item.LinkType) {
                if ($item.Target -contains $target) { Say "Sessions already linked: $link -> $target" }
                else { throw "$link is already a link to $($item.Target -join ', '); remove it first if it should point to $target." }
            } elseif (Get-ChildItem $link -Force -ErrorAction SilentlyContinue) {
                throw "$link already contains sessions. Move them into $target (with Goose Desktop and the gateway stopped), delete the empty folder, and run again."
            } else { Remove-Item $link -Force }
        }
        if (-not (Test-Path $link)) {
            New-Item -ItemType Directory -Force -Path (Split-Path $link) | Out-Null
            & cmd /c mklink /J "$link" "$target" | Out-Null
            if ($LASTEXITCODE) { throw "Could not link $link -> $target" }
            Say "Linked chat sessions: $link -> $target"
            $chats = Count-Chats $native
            if ($chats -ge 0) { Say "Chat sessions now visible: $chats" }
        }
    }
}

if (-not $Admin) { $Admin = Ask "`n3/6  The administrator's Goose Web user name" $env:USERNAME }
if (-not $NonInteractive) { $ProfilesRoot = Ask "`n4/6  Folder for Goose Web's own data (users, teams, per-user profiles)" $ProfilesRoot }

if (-not $NonInteractive -and -not $RunAs) {
    Write-Host ""
    Write-Host "5/6  Which Windows account runs the gateway?"
    Write-Host "     [1] me ($($id.Name)) - starts when I sign in to Windows"
    Write-Host "     [2] a service account or gMSA - starts at boot, nobody needs to sign in"
    if ((Ask '     Choose 1 or 2' '1') -eq '2') {
        $RunAs = Ask '     Account (DOMAIN\name, .\name for a local account, DOMAIN\name$ for a gMSA)' ''
    }
}
$service = [bool]$RunAs -and ($RunAs -ine $id.Name) -and ($RunAs -ine $env:USERNAME)
if (-not $service) { $RunAs = $id.Name }

if (-not $NonInteractive -and -not $Sandbox) {
    Write-Host ""
    Write-Host "6/6  Sandbox non-admin users' agents in a Windows AppContainer? Each one can then reach only its own"
    Write-Host "     profile, its team folder and the team's approved folders (administrators are never sandboxed)."
    $Sandbox = if ((Ask '     Sandbox (Y/n)' 'Y') -match '^[nN]') { 'off' } else { 'on' }
}
if (-not $Sandbox) { $Sandbox = 'on' }

Write-Host ""
Say "Summary"
Write-Host "     Goose program      $gooseExe"
Write-Host "     Goose appdata      $(if ($native -eq 'fresh') { "fresh, in $ProfilesRoot\appdata" } else { $native })$(if ($SessionsDir) { "  (sessions -> $SessionsDir)" })"
Write-Host "     First admin        $Admin (Goose Web user, bound to that Goose appdata)"
Write-Host "     Goose Web data     $ProfilesRoot"
Write-Host "     Gateway runs as    $RunAs, $(if ($service) { 'at boot (service account)' } else { 'when you sign in' })"
Write-Host "     Sandbox            $Sandbox for non-admin users"
if (-not $Tls) { $Tls = 'auto' }
$tlsOn = $Tls -eq 'self-signed' -or ($Tls -eq 'auto' -and -not $PublicUrl)
$scheme = if ($tlsOn) { 'https' } else { 'http' }
Write-Host "     HTTPS              $(if ($tlsOn) { 'built-in certificate (local CA, renewed automatically)' } else { 'off - TLS at your reverse proxy' }) (Admin > System > HTTPS)"
Write-Host "     Address            $($scheme)://$($BindHost):$Port$(if ($PublicUrl) { "  (public $PublicUrl)" })"
if (-not $NonInteractive -and ((Ask 'Continue (Y/n)' 'Y') -match '^[nN]')) { Write-Host 'Nothing changed.'; exit 0 }

# --- 2. virtualenv -------------------------------------------------------------
$venvPy = Join-Path $InstallDir '.venv\Scripts\python.exe'
$uv = (Get-Command uv -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $uv) {   # Goose ships uv; use it when uv is not on PATH
    foreach ($c in @((Join-Path $env:LOCALAPPDATA 'Goose\bin\uv.exe'), (Join-Path (Split-Path $gooseExe) 'uv.exe'))) {
        if ($c -and (Test-Path $c)) { $uv = $c; break }
    }
}
Push-Location $InstallDir
try {
    if (-not (Test-Path $venvPy)) {
        if ($uv) { Say "Creating .venv with uv"; & $uv venv --python 3.13 .venv; if ($LASTEXITCODE) { & $uv venv .venv } }
        else {
            $py = (Get-Command py -ErrorAction SilentlyContinue)
            if ($py) { & py -3 -m venv .venv } else { & python -m venv .venv }
        }
        if (-not (Test-Path $venvPy)) { throw "Could not create the virtualenv (install Python 3.11+ or uv)." }
    }
    & $venvPy -c "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)"
    if ($LASTEXITCODE) { throw "The virtualenv's Python is older than 3.11 ($(& $venvPy --version)). Delete .venv and install Python 3.11+ or uv." }
    Say "Installing dependencies (hash-locked, requirements.lock)"
    if ($uv) {
        & $uv pip install --python $venvPy --require-hashes -r requirements.lock
        if ($LASTEXITCODE) { throw "Dependency installation failed." }
        & $uv pip install --python $venvPy --no-deps -e .
    } else {
        & $venvPy -m pip install --upgrade pip
        & $venvPy -m pip install --require-hashes -r requirements.lock
        if ($LASTEXITCODE) { throw "Dependency installation failed." }
        & $venvPy -m pip install --no-deps -e .
    }
    if ($LASTEXITCODE) { throw "Dependency installation failed." }
} finally { Pop-Location }

# --- 3. config + permissions ---------------------------------------------------------
$sys = Join-Path $ProfilesRoot '_system'
New-Item -ItemType Directory -Force -Path $sys | Out-Null
# Private to the gateway's account(s) (plus SYSTEM/Administrators for backups): profiles hold chats and secrets.
$grants = @("$($id.Name):(OI)(CI)F", "*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
if ($service) { $grants += "$($RunAs):(OI)(CI)F" }
& icacls $ProfilesRoot /inheritance:r /grant:r @grants /Q | Out-Null
if ($LASTEXITCODE) { Warn "Could not restrict permissions on $ProfilesRoot (icacls exit $LASTEXITCODE)" }
if ($service) {
    # The service account must read the install folder, the venv's Python and Goose, and use the Goose appdata.
    $base = (& $venvPy -c "import sys; print(sys.base_prefix)").Trim()
    $read = @($InstallDir, $base, (Split-Path $gooseExe)) | Select-Object -Unique
    # A sessions folder linked in as <appdata>\data\sessions needs its own grant (ACLs do not follow junctions).
    $linkedSessions = ''
    if ($native -ne 'fresh') {
        $li = Get-Item (Join-Path $native 'data\sessions') -Force -ErrorAction SilentlyContinue
        if ($li -and $li.LinkType) { $linkedSessions = @($li.Target)[0] }
    }
    $modify = @($(if ($native -ne 'fresh') { $native }), $(if ($SessionsDir) { (Resolve-Path $SessionsDir).Path }), $linkedSessions) |
        Where-Object { $_ } | Select-Object -Unique
    foreach ($d in $read) {
        & icacls $d /grant "$($RunAs):(OI)(CI)RX" /Q | Out-Null
        if ($LASTEXITCODE) { Warn "Could not grant $RunAs read access to $d (grant it yourself, or install Goose/Python for all users)." }
        else { Say "Granted $RunAs read & execute on $d" }
    }
    foreach ($d in $modify) {
        & icacls $d /grant "$($RunAs):(OI)(CI)M" /Q | Out-Null
        if ($LASTEXITCODE) { Warn "Could not grant $RunAs modify access to $d." } else { Say "Granted $RunAs modify on $d" }
    }
}
$cfg = Join-Path $sys 'config.yaml'
$bin = "  binary: `"$($gooseExe -replace '\\','\\')`""
if (-not (Test-Path $cfg)) {
    $proxies = @('127.0.0.1', '::1') + $TrustedProxy | Select-Object -Unique
    $yaml = @(
        '# goose-web configuration (see docs/CONFIGURATION.md). Environment overrides: GOOSE_WEB__SECTION__KEY.',
        'server:',
        "  host: `"$BindHost`"",
        "  port: $Port",
        "  public_url: `"$PublicUrl`"",
        "  tls: `"$Tls`"            # auto | self-signed | files | off (Admin > System > HTTPS overrides it)",
        '  trusted_proxies:'
    ) + ($proxies | ForEach-Object { "    - `"$_`"" }) + @(
        'paths:',
        "  profiles_root: `"$($ProfilesRoot -replace '\\','\\')`"",
        'goose:',
        $bin,
        '  idle_minutes: 30',
        '  native_scheduler: auto   # auto = only while Goose Desktop is closed (prevents double-firing)',
        'sandbox:',
        "  enabled: $(if ($Sandbox -eq 'off') { 'false' } else { 'true' })   # non-admin users' agents in a Windows AppContainer",
        '  network: internet        # none | internet | internet+lan (loopback is never reachable)',
        '  read_dirs: []            # extra program folders agents may run (Python, node, uv installs)'
    )
    [IO.File]::WriteAllLines($cfg, $yaml, (New-Object Text.UTF8Encoding $false))
    Say "Wrote $cfg"
} else {
    Say "Keeping existing $cfg (only goose.binary is updated)"
    $lines = [Collections.Generic.List[string]]([IO.File]::ReadAllLines($cfg))
    $g = $lines.FindIndex([Predicate[string]]{ param($l) $l -match '^goose:\s*$' })
    if ($g -lt 0) { $lines.Add('goose:'); $lines.Add($bin) }
    else {
        $b = -1
        for ($i = $g + 1; $i -lt $lines.Count -and ($lines[$i] -match '^\s' -or $lines[$i] -eq ''); $i++) { if ($lines[$i] -match '^\s+binary:') { $b = $i } }
        if ($b -ge 0) { $lines[$b] = $bin } else { $lines.Insert($g + 1, $bin) }
    }
    [IO.File]::WriteAllLines($cfg, $lines, (New-Object Text.UTF8Encoding $false))
}

# --- 4. database + admin ---------------------------------------------------------------
Say "Initialising (admin '$Admin'; a random initial password is generated and shown at the end)"
# init prints the generated password (first install only); keep its output and show it once, at the end.
$initOut = @(& $venvPy -m goose_web --config $cfg init --admin $Admin --native-root $native)
if ($LASTEXITCODE) { $initOut | ForEach-Object { Write-Host $_ }; throw "goose-web init failed." }
& $venvPy -m goose_web --config $cfg check
if ($LASTEXITCODE) {
    throw "goose-web check failed (see the [!!] lines above). If the goose CLI was not found, re-run with -GooseBinary <path to goose.exe>."
}

# --- 5. service ----------------------------------------------------------------------------
$reg = Join-Path $PSScriptRoot 'register-service.ps1'
$regArgs = @('-User', "`"$RunAs`"", '-InstallDir', "`"$InstallDir`"", '-ConfigPath', "`"$cfg`"", '-Port', $Port,
    '-TaskPath', "`"$TaskPath`"", '-FirewallRemoteAddress', ($FirewallRemoteAddress -join ','),
    '-Mode', $(if ($service) { 'Service' } else { 'Logon' }))
if ($existingTask.Count -and -not $Reregister) {
    Say "Keeping the existing gateway task (pass -Reregister to register it again)."
} elseif (-not $NoService) {
    Say "Registering the gateway task and firewall rule (one elevation prompt$(if ($service -and -not $RunAs.EndsWith('$')) { "; it asks for the password of $RunAs" }))"
    try {
        $p = Start-Process powershell -Verb RunAs -ArgumentList (@('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$reg`"") + $regArgs) -Wait -PassThru
        if ($p.ExitCode) { Warn "register-service.ps1 exited with $($p.ExitCode)" }
    } catch {
        Warn "Elevation was declined or is unavailable. Run this from an elevated prompt later:"
        Write-Host "  powershell -ExecutionPolicy Bypass -File `"$reg`" $($regArgs -join ' ')"
    }
}

if ($tlsOn) {   # create the certificate now (the gateway renews it itself) and show what it covers
    & $venvPy -m goose_web --config $cfg tls status | ForEach-Object { Write-Host "     $_" }
    $trust = $TrustCert -or (-not $NonInteractive -and ((Ask 'Trust the built-in certificate in your browsers on this computer (Y/n)' 'Y') -notmatch '^[nN]'))
    if ($trust) { & $venvPy -m goose_web --config $cfg tls trust | ForEach-Object { Write-Host "     $_" } }
    Write-Host "     Other computers: import $sys\tls\ca.crt (or download it from Admin > System > HTTPS) as a trusted root." -ForegroundColor Yellow
}
$url = if ($PublicUrl) { $PublicUrl } else { "$($scheme)://$(if ($BindHost -eq '0.0.0.0') { 'localhost' } else { $BindHost }):$Port" }
Write-Host ""
if ($service) {
    Write-Host "Done. The gateway starts at boot as $RunAs; start it now with: Start-ScheduledTask -TaskPath '$TaskPath' -TaskName GooseWeb_Gateway" -ForegroundColor Green
    Write-Host "Provider keys kept in YOUR Windows credential store are not visible to ${RunAs}: enter them again in Goose Web (Settings > Providers)." -ForegroundColor Yellow
} else {
    Write-Host "Done. Start now with:  scripts\start-gateway.cmd   (or sign out/in to start the logon task)" -ForegroundColor Green
}
Write-Host "Open $url and sign in as '$Admin'." -ForegroundColor Green
Write-Host ""
$initOut | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
if (($initOut -join "`n") -match 'Already initialised') {
    Write-Host "(Existing installation: the admin password was not changed.)" -ForegroundColor Green
}
