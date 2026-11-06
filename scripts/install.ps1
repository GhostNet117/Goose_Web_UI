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
    1. Creates .venv in the install folder and installs goose-web (uv if available, else python -m venv + pip).
    2. Finds the existing Goose profile (%APPDATA%\Block\goose). If it is missing you are asked for the
       folder; leave the answer empty for a fresh install (<ProfilesRoot>\appdata).
    3. Writes <ProfilesRoot>\_system\config.yaml (only if it does not exist yet).
    4. Runs "goose-web init": the admin is %USERNAME% with password ChangeMe (must be changed at first sign-in)
       and is bound to the existing Goose profile, so it keeps all chats, recipes and settings.
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
    [string]$GooseAppData = '',              # existing Goose profile folder; '' = auto-detect, 'fresh' = new
    [string]$BindHost = '127.0.0.1',         # use the LAN IP (or 0.0.0.0) when a reverse proxy on another host connects
    [int]$Port = 8710,
    [string]$PublicUrl = '',                 # e.g. https://goose.example.org (enables Secure cookies + HSTS)
    [string[]]$TrustedProxy = @(),           # reverse proxy IPs whose X-Forwarded-For is trusted
    [string[]]$FirewallRemoteAddress = @('LocalSubnet'),
    [string]$TaskPath = '\GooseWeb\',
    [string]$Admin = $env:USERNAME,
    [switch]$NoService,                      # skip task + firewall registration
    [switch]$NonInteractive,
    [switch]$AllowElevated
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

# --- 1. virtualenv -------------------------------------------------------------
$venvPy = Join-Path $InstallDir '.venv\Scripts\python.exe'
$uv = (Get-Command uv -ErrorAction SilentlyContinue | Select-Object -First 1).Source
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
    Say "Installing dependencies"
    if ($uv) { & $uv pip install --python $venvPy -e . } else { & $venvPy -m pip install --upgrade pip; & $venvPy -m pip install -e . }
    if ($LASTEXITCODE) { throw "Dependency installation failed." }
} finally { Pop-Location }

# --- 2. Goose profile discovery --------------------------------------------------
$native = $GooseAppData
if (-not $native) {
    $default = Join-Path $env:APPDATA 'Block\goose'
    if (Test-Path (Join-Path $default 'config')) {
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
        'goose:',
        '  idle_minutes: 30',
        '  native_scheduler: auto   # auto = only while Goose Desktop is closed (prevents double-firing)'
    )
    [IO.File]::WriteAllLines($cfg, $yaml, (New-Object Text.UTF8Encoding $false))
    Say "Wrote $cfg"
} else { Say "Keeping existing $cfg" }

# --- 4. database + admin ---------------------------------------------------------------
Say "Initialising (admin '$Admin', password 'ChangeMe' - you must change it at first sign-in)"
& $venvPy -m goose_web --config $cfg init --admin $Admin --native-root $native
if ($LASTEXITCODE) { throw "goose-web init failed." }
& $venvPy -m goose_web --config $cfg check

# --- 5. service ----------------------------------------------------------------------------
if (-not $NoService) {
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
Write-Host "Open $url and sign in as '$Admin' / 'ChangeMe'." -ForegroundColor Green
