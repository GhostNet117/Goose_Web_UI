<#
.SYNOPSIS
  Installs Goose AI Web Interface (goose-web) for the CURRENT Windows user.

.DESCRIPTION
  Run this as the normal (non-elevated) Windows user that already uses Goose.
  Everything it creates - the virtualenv, the profiles folder, the database -
  is owned by that user. It refuses to run elevated, because files created by
  an elevated process end up owned by Administrators and Goose can no longer
  manage them.

  Steps:
    1. Creates .venv in the install folder (uv if available, else python -m venv + pip), installs the
       dependencies from requirements.lock with --require-hashes, then goose-web itself with --no-deps.
    2. Finds the existing Goose profile (%APPDATA%\Block\goose). If it is missing you are asked for the
       folder; leave the answer empty for a fresh install (<ProfilesRoot>\appdata).
    3. Writes <ProfilesRoot>\_system\config.yaml (only if it does not exist yet).
    4. Runs "goose-web init": the admin is %USERNAME% with a random initial password, shown once at the end
       of the installer (must be changed at first sign-in), and is bound to the existing Goose profile, so it
       keeps all chats, recipes and settings.
    5. Registers the logon task and the firewall rule via register-service.ps1 (asks for elevation once;
       the task itself always runs as you, non-elevated).

  The installer never writes into the Goose profile folder.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1
.EXAMPLE
  powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BindHost 192.168.1.50 -PublicUrl https://goose.example.org -TrustedProxy 192.168.1.10 -FirewallRemoteAddress 192.168.1.10
#>
[CmdletBinding()]
param(
    [string]$ProfilesRoot = 'C:\Goose_Web_Profiles',
    [string]$GooseAppData = '',              # Goose appdata folder (contains config\); '' = auto-detect (GOOSE_PATH_ROOT, then %APPDATA%\Block\goose), 'fresh' = new
    [string]$GooseBinary = '',               # path to the goose CLI (e.g. C:\AI\Goose\resources\bin\goose.exe); '' = auto-detect
    [string]$BindHost = '127.0.0.1',         # use the LAN IP (or 0.0.0.0) when a reverse proxy on another host connects
    [int]$Port = 8710,
    [string]$PublicUrl = '',                 # e.g. https://goose.example.org (enables Secure cookies + HSTS)
    [string[]]$TrustedProxy = @(),           # reverse proxy IPs whose X-Forwarded-For is trusted
    [string[]]$FirewallRemoteAddress = @('LocalSubnet'),
    [string]$TaskPath = '\GooseWeb\',
    [string]$Admin = $env:USERNAME,
    [switch]$NoService,                      # skip task + firewall registration
    [switch]$NonInteractive,
    [switch]$AllowElevated,
    [switch]$Reregister                      # register the logon task again although one exists for this install
)

$ErrorActionPreference = 'Stop'
$InstallDir = Split-Path -Parent $PSScriptRoot
function Say($m) { Write-Host "==> $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "!!  $m" -ForegroundColor Yellow }

# --- 0. never elevated -------------------------------------------------------
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$elevated = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($elevated -and -not $AllowElevated) {
    Write-Host "This installer must run as the normal Windows user (not 'Run as administrator')." -ForegroundColor Red
    Write-Host "Files created elevated are owned by Administrators and break Goose. Open a normal PowerShell and re-run." -ForegroundColor Red
    exit 3
}
Say "Installing goose-web for $($id.Name) in $InstallDir"
if ($GooseBinary) {
    if (-not (Test-Path $GooseBinary -PathType Leaf)) { throw "Goose CLI not found: $GooseBinary" }
    $gv = & $GooseBinary --version 2>&1 | Select-Object -First 1
    if ($LASTEXITCODE) { throw "The Goose CLI did not run: $GooseBinary ($gv)" }
    Say "Goose CLI: $GooseBinary ($gv)"
}
# An existing gateway task for THIS install means this is a re-run: keep the task (use scripts\upgrade.ps1 to upgrade).
$venvPyw = Join-Path $InstallDir '.venv\Scripts\pythonw.exe'
$existingTask = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object {
    $_.Actions | Where-Object { $_.Execute -and ($_.Execute.Trim('"') -ieq $venvPyw) } })
if ($existingTask.Count) {
    Warn ("This install already has a gateway task: " + (($existingTask | ForEach-Object { $_.TaskPath + $_.TaskName }) -join ', ') +
        ". To upgrade, stop here and run scripts\upgrade.ps1 (keeps every setting, backs up first).")
}

# --- 1. virtualenv -------------------------------------------------------------
$venvPy = Join-Path $InstallDir '.venv\Scripts\python.exe'
$uv = (Get-Command uv -ErrorAction SilentlyContinue | Select-Object -First 1).Source
if (-not $uv) {   # Goose ships uv; use it when uv is not on PATH
    foreach ($c in @((Join-Path $env:LOCALAPPDATA 'Goose\bin\uv.exe'), $(if ($GooseBinary) { Join-Path (Split-Path $GooseBinary) 'uv.exe' }))) {
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

# --- 2. Goose profile discovery --------------------------------------------------
$native = $GooseAppData
if (-not $native) {
    $default = Join-Path $env:APPDATA 'Block\goose'
    if ($env:GOOSE_PATH_ROOT -and (Test-Path (Join-Path $env:GOOSE_PATH_ROOT 'config'))) {
        $native = $env:GOOSE_PATH_ROOT
        Say "Found the Goose profile from GOOSE_PATH_ROOT: $native"
    } elseif (Test-Path (Join-Path $default 'config')) {
        $native = $default
        Say "Found the existing Goose profile: $native"
    } elseif (-not $NonInteractive) {
        Warn "No Goose profile at $default."
        $native = Read-Host "Path to your Goose appdata folder (the one containing config\), or press Enter for a fresh install"
    }
    if (-not $native) { $native = 'fresh' }
}
if ($native -ne 'fresh' -and -not (Test-Path $native)) { throw "Goose profile folder not found: $native" }

# --- 3. config -----------------------------------------------------------------------
$sys = Join-Path $ProfilesRoot '_system'
New-Item -ItemType Directory -Force -Path $sys | Out-Null
# Private to this user (plus SYSTEM/Administrators for backups): profiles hold chats and provider secrets.
& icacls $ProfilesRoot /inheritance:r /grant:r "$($id.Name):(OI)(CI)F" "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" /Q | Out-Null
if ($LASTEXITCODE) { Warn "Could not restrict permissions on $ProfilesRoot (icacls exit $LASTEXITCODE)" }
$cfg = Join-Path $sys 'config.yaml'
if (-not (Test-Path $cfg)) {
    $proxies = @('127.0.0.1', '::1') + $TrustedProxy | Select-Object -Unique
    $yaml = @(
        '# goose-web configuration (see docs/CONFIGURATION.md). Environment overrides: GOOSE_WEB__SECTION__KEY.',
        'server:',
        "  host: `"$BindHost`"",
        "  port: $Port",
        "  public_url: `"$PublicUrl`"",
        '  trusted_proxies:'
    ) + ($proxies | ForEach-Object { "    - `"$_`"" }) + @(
        'paths:',
        "  profiles_root: `"$($ProfilesRoot -replace '\\','\\')`"",
        'goose:'
    ) + $(if ($GooseBinary) { @("  binary: `"$($GooseBinary -replace '\\','\\')`"") } else { @() }) + @(
        '  idle_minutes: 30',
        '  native_scheduler: auto   # auto = only while Goose Desktop is closed (prevents double-firing)'
    )
    [IO.File]::WriteAllLines($cfg, $yaml, (New-Object Text.UTF8Encoding $false))
    Say "Wrote $cfg"
} else {
    Say "Keeping existing $cfg"
    if ($GooseBinary) {   # set or replace goose.binary, leave everything else (and comments) as it is
        $lines = [Collections.Generic.List[string]]([IO.File]::ReadAllLines($cfg))
        $bin = "  binary: `"$($GooseBinary -replace '\\','\\')`""
        $g = $lines.FindIndex([Predicate[string]]{ param($l) $l -match '^goose:\s*$' })
        if ($g -lt 0) { $lines.Add('goose:'); $lines.Add($bin) }
        else {
            $b = -1
            for ($i = $g + 1; $i -lt $lines.Count -and ($lines[$i] -match '^\s' -or $lines[$i] -eq ''); $i++) { if ($lines[$i] -match '^\s+binary:') { $b = $i } }
            if ($b -ge 0) { $lines[$b] = $bin } else { $lines.Insert($g + 1, $bin) }
        }
        [IO.File]::WriteAllLines($cfg, $lines, (New-Object Text.UTF8Encoding $false))
        Say "Set goose.binary in $cfg"
    }
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
if ($existingTask.Count -and -not $Reregister) {
    Say "Keeping the existing gateway task (pass -Reregister to register it again)."
} elseif (-not $NoService) {
    $reg = Join-Path $PSScriptRoot 'register-service.ps1'
    $argList = @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$reg`"",
        '-User', "`"$($id.Name)`"", '-InstallDir', "`"$InstallDir`"", '-ConfigPath', "`"$cfg`"",
        '-Port', $Port, '-TaskPath', "`"$TaskPath`"", '-FirewallRemoteAddress', ($FirewallRemoteAddress -join ','))
    Say "Registering the logon task and firewall rule (one elevation prompt)"
    try {
        $p = Start-Process powershell -Verb RunAs -ArgumentList $argList -Wait -PassThru
        if ($p.ExitCode) { Warn "register-service.ps1 exited with $($p.ExitCode)" }
    } catch {
        Warn "Elevation was declined or is unavailable. Run this from an elevated prompt later:"
        Write-Host "  powershell -ExecutionPolicy Bypass -File `"$reg`" -User `"$($id.Name)`" -InstallDir `"$InstallDir`" -ConfigPath `"$cfg`" -Port $Port"
    }
}

$url = if ($PublicUrl) { $PublicUrl } else { "http://$(if ($BindHost -eq '0.0.0.0') { 'localhost' } else { $BindHost }):$Port" }
Write-Host ""
Write-Host "Done. Start now with:  scripts\start-gateway.cmd   (or sign out/in to start the logon task)" -ForegroundColor Green
Write-Host "Open $url and sign in as '$Admin'." -ForegroundColor Green
Write-Host ""
$initOut | ForEach-Object { Write-Host $_ -ForegroundColor Yellow }
if (($initOut -join "`n") -match 'Already initialised') {
    Write-Host "(Existing installation: the admin password was not changed.)" -ForegroundColor Green
}
