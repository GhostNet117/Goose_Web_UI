# Administration guide

This guide is for the person who installs and runs a Goose AI Web Interface (goose-web) gateway. It explains how
to install it, expose it safely, manage users, teams and policies, look after the Goose workers, and back up,
upgrade and remove it.

Related documents:

| Document | Contents |
|---|---|
| [../README.md](../README.md) | overview, quick start, limitations |
| [CONFIGURATION.md](CONFIGURATION.md) | every `config.yaml` key, environment variable, CLI flag and script parameter |
| [API.md](API.md) | the REST and WebSocket contract |
| [ARCHITECTURE.md](ARCHITECTURE.md) | how the gateway, the hub and the workers fit together |
| [USER-GUIDE.md](USER-GUIDE.md) | the web UI from a user's point of view |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | symptoms, causes and fixes |
| [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md) | threat model, findings (GW-xx, NEW-xx) and the deployment hardening checklist |
| [../SECURITY.md](../SECURITY.md) | supported versions and how to report a vulnerability |

Examples in this guide use the host name `goose.example.org`, the gateway address `192.168.1.10`, a reverse proxy at
`192.168.1.2`, the users `alice` and `bob`, the install folder `C:\GooseWeb` (Windows) or `/opt/goose-web`
(Linux), and the default profiles root `C:\Goose_Web_Profiles` (Windows). Replace them with your own values.

## Contents

1. [How the gateway works, in short](#1-how-the-gateway-works-in-short)
2. [Choosing an installation](#2-choosing-an-installation)
3. [Installing](#3-installing)
4. [First start and the initial admin password](#4-first-start-and-the-initial-admin-password)
5. [Running as a service](#5-running-as-a-service)
6. [Network exposure: reverse proxy, TLS, hosts and origins](#6-network-exposure-reverse-proxy-tls-hosts-and-origins)
7. [Users and sign-in](#7-users-and-sign-in)
8. [API tokens](#8-api-tokens)
9. [Teams and policies](#9-teams-and-policies)
10. [Shared goose hints](#10-shared-goose-hints)
11. [Profiles](#11-profiles)
12. [Workers](#12-workers)
13. [Schedules and the native scheduler](#13-schedules-and-the-native-scheduler)
14. [Notifications and webhooks](#14-notifications-and-webhooks)
15. [Herd view, peers and viewing another user's chats](#15-herd-view-peers-and-viewing-another-users-chats)
16. [Audit log](#16-audit-log)
17. [Windows tools: ownership check and host tasks](#17-windows-tools-ownership-check-and-host-tasks)
18. [Logs](#18-logs)
19. [Backups and restore](#19-backups-and-restore)
20. [Upgrades](#20-upgrades)
21. [Uninstalling](#21-uninstalling)
22. [Checklist for a new deployment](#22-checklist-for-a-new-deployment)
23. [Security hardening checklist](#23-security-hardening-checklist)
24. [Quick reference](#24-quick-reference)

## 1. How the gateway works, in short

- The gateway is one Python process (Starlette + uvicorn) that serves the web UI, a REST API under `/api/` and a
  JSON-RPC WebSocket at `/ws`. It listens on `server.host:server.port` (default `127.0.0.1:8710`). It has no TLS of
  its own.
- For every user profile it starts one `goose serve` worker on demand. A worker listens on `127.0.0.1` on a random
  port, with a random per-worker secret, and the gateway holds one ACP connection to it. All browser tabs of that
  user share this connection, so closing a tab never stops an agent.
- Every ACP call from a non-admin goes through a default-deny method firewall (`goose_web/policy.py`). Admins are
  not restricted.
- State lives in a SQLite database `<system_dir>/goose-web.db` (default `<profiles_root>/_system/goose-web.db`) and in
  the profile folders under `paths.profiles_root`.
- All workers run as the same OS account as the gateway. Profile isolation keeps users' chats, settings and secrets
  apart, but it is a privacy boundary, not a hard security boundary (see section 11).

## 2. Choosing an installation

| Option | Use it when | Notes |
|---|---|---|
| Native Windows (`scripts/install.ps1`) | Goose Desktop or the goose CLI is already used on a Windows machine and the admin wants to keep that Goose profile | The admin is bound to the existing profile in `%APPDATA%\Block\goose`, so Goose Desktop and the browser see the same chats, recipes and settings. You update Goose yourself. Includes a logon task, a firewall rule, the ownership check and the host-task view. |
| Native Linux or macOS (`scripts/install.sh`) | the goose CLI is installed on a server or workstation and extensions need tools installed on the host | Needs `goose` on `PATH`. The admin starts with a fresh profile unless `--goose-appdata` points at a `GOOSE_PATH_ROOT`-style folder (`config/`, `data/`, `state/`). `--systemd` creates a systemd user service (Linux). |
| Docker (`docker/compose.yaml`) | you want a self-contained Linux server with a pinned, checksum-verified goose CLI and container hardening | Image for amd64 and arm64, built locally from `docker/Dockerfile`. Everything persistent is in the `/data` volume. The image contains Python, `git` and `curl`, but no Node.js or `uv`, so stdio MCP extensions that need `npx` or `uvx` do not run unless you extend the image. The root file system is read-only and the home folder is a tmpfs, so anything written to `~` is lost when the container restarts. |

All three install the Python dependencies from the hash-locked `requirements.lock` (`pip install --require-hashes`)
and then goose-web itself with `--no-deps`. Python 3.11 or later is required for native installs (the installers
prefer `uv` with Python 3.13 when `uv` is available).

## 3. Installing

### 3.1 Windows

Run the installer as the normal Windows user that uses Goose, from a normal (not elevated) PowerShell in the
repository folder. It refuses to run elevated (exit code 3), because files created by an elevated process become
owned by Administrators and Goose can then no longer manage them.

```powershell
cd C:\GooseWeb
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

What it does:

1. Creates `.venv` in the install folder and installs the locked dependencies, then the package (editable, `-e .`).
2. Finds the Goose profile: `-GooseAppData` if given, otherwise `%APPDATA%\Block\goose` if it has a `config`
   subfolder, otherwise it asks. An empty answer (or `-GooseAppData fresh`) creates a fresh profile in
   `<ProfilesRoot>\appdata`.
3. Creates `<ProfilesRoot>\_system`, restricts the profiles root ACL to the installing user, SYSTEM and
   Administrators (`icacls ... /inheritance:r`), and writes `<ProfilesRoot>\_system\config.yaml` if it does not
   exist yet.
4. Runs `goose-web init` (first admin, random initial password) and `goose-web check`.
5. Unless `-NoService` is given, runs `scripts\register-service.ps1` through one elevation prompt to create the logon
   task and the firewall rule (section 5). If the prompt is declined, it prints the command to run later.
6. Prints the initial admin password at the very end of its output.

Main parameters (full list in [CONFIGURATION.md](CONFIGURATION.md), section 8):

| Parameter | Default | Meaning |
|---|---|---|
| `-ProfilesRoot` | `C:\Goose_Web_Profiles` | parent of all profiles and of `_system` |
| `-GooseAppData` | auto-detect | the admin's existing Goose profile folder, or `fresh` |
| `-BindHost` | `127.0.0.1` | listen address; use the gateway's LAN address when a proxy on another host connects |
| `-Port` | `8710` | listen port |
| `-PublicUrl` | empty | external `https://` URL (section 6) |
| `-TrustedProxy` | none | reverse proxy addresses, added to `127.0.0.1` and `::1` |
| `-FirewallRemoteAddress` | `LocalSubnet` | who may connect to the port; use the proxy's address |
| `-Admin` | `%USERNAME%` | admin user name |
| `-NoService` | off | skip the logon task and the firewall rule |
| `-NonInteractive` | off | do not ask for the profile folder (fresh profile if none is found) |

Example for a gateway behind a reverse proxy:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BindHost 192.168.1.10 `
  -PublicUrl https://goose.example.org -TrustedProxy 192.168.1.2 -FirewallRemoteAddress 192.168.1.2
```

The installer never writes into the Goose profile folder. Running it again on an existing installation keeps
`config.yaml`, keeps the database and the admin password ("Already initialised"), reinstalls the dependencies and
registers the task again.

### 3.2 Linux and macOS

Run as the normal user that uses goose, not as root (the script exits with code 3 as root). The goose CLI must be
on `PATH`; if it is missing, the script prints the official download command and stops.

```bash
cd /opt/goose-web
./scripts/install.sh --systemd \
  --host 192.168.1.10 --public-url https://goose.example.org --trusted-proxy 192.168.1.2
```

| Option | Default | Meaning |
|---|---|---|
| `--profiles-root DIR` | `~/.local/share/goose-web` | parent of all profiles and of `_system` (made `chmod 700`) |
| `--goose-appdata DIR\|fresh` | `auto` | the admin's Goose profile. An existing `~/.config/goose` has no `config/` subfolder and is therefore not picked up, so the admin starts fresh in `<profiles-root>/appdata` |
| `--host`, `--port` | `127.0.0.1`, `8710` | listen address and port |
| `--public-url URL` | empty | external `https://` URL |
| `--trusted-proxy IP` | none | repeatable; added to `127.0.0.1` and `::1` |
| `--systemd` | off | create and start the user unit `goose-web.service` |

The script writes `<profiles-root>/_system/config.yaml` (with `goose.binary` set to the goose found on `PATH`) if it
is missing, runs `init` and `check`, and prints the initial admin password at the end. Because the profiles root is
not the built-in default, always pass `--config <profiles-root>/_system/config.yaml` to later commands.

### 3.3 Docker

From the repository root:

```bash
docker compose -f docker/compose.yaml up -d --build
docker compose -f docker/compose.yaml logs goose-web     # shows the initial admin password, first start only
```

The image runs as uid 1000 (`goose`) under `tini`. The compose file publishes the port on `127.0.0.1:8710` only and
already applies this hardening: read-only root file system, tmpfs for `/tmp` and `/home/goose`, `cap_drop: [ALL]`,
`no-new-privileges`, `pids_limit: 1024`, `mem_limit: 4g`.

Settings are passed as environment variables (there is no `config.yaml` in the container unless you mount one and
set `GOOSE_WEB_CONFIG`). The image already sets:

| Variable | Value |
|---|---|
| `GOOSE_WEB__SERVER__HOST` | `0.0.0.0` |
| `GOOSE_WEB__SERVER__PORT` | `8710` |
| `GOOSE_WEB__PATHS__PROFILES_ROOT` | `/data` |
| `GOOSE_WEB__GOOSE__BINARY` | `/usr/local/bin/goose` |
| `GOOSE_WEB__GOOSE__NATIVE_SCHEDULER` | `on` (there is no Goose Desktop in the container) |
| `GOOSE_WEB__GOOSE__DEFAULT_WORKDIR_NATIVE` | `/data/workspace` |
| `GOOSE_DISABLE_KEYRING` | `1` |

Variables read only on the first start (when `/data/_system/goose-web.db` does not exist yet):

| Variable | Default | Meaning |
|---|---|---|
| `GOOSE_WEB_ADMIN` | `admin` | admin user name |
| `GOOSE_WEB_NATIVE_ROOT` | `fresh` (`/data/appdata`) | the admin's Goose profile folder; mount an existing `GOOSE_PATH_ROOT`-style profile and point this at it to reuse it |
| `GOOSE_WEB_ADMIN_PASSWORD_FILE` | not set | file with the initial admin password, for example a compose secret |
| `GOOSE_WEB_ADMIN_PASSWORD` | not set | the password itself; visible in `docker inspect`, so prefer the `_FILE` variant |

To give users access to host folders, mount them (for example `/srv/projects:/workspaces`) and add the container
path to a team's allowed folders (section 9).

Behind a reverse proxy, add to `environment:`:

```yaml
      GOOSE_WEB__SERVER__PUBLIC_URL: https://goose.example.org
      GOOSE_WEB__SERVER__TRUSTED_PROXIES: '["127.0.0.1", "::1", "192.168.1.2"]'
      # only if users open the gateway under another name or address:
      # GOOSE_WEB__SERVER__ALLOWED_HOSTS: goose,192.168.1.10
```

Trust only the proxy's own address. Every host in a trusted range can forge the client IP that rate limiting, the
lockout and the audit log rely on, so do not trust a whole Docker network range unless you must.

## 4. First start and the initial admin password

There is no default password. `goose-web init` creates the first admin:

- user name: `--admin`, otherwise the current OS user (`%USERNAME%` / `$USER`), otherwise `admin`
- sign-in: local password, role `admin`, profile mode `native` (bound to the folder chosen by `--native-root`)
- password: a random 20-character password, printed once in a framed block. Only its hash is stored.
- the change of this password is enforced at the first sign-in (`must_change_pw`); until then the account can do
  nothing else (API calls return `403 password_change_required`, the WebSocket is refused)
- a team called **Everyone** is created and made the default team for new users

The installers keep the output of `init` and print it at the end; Docker prints it to the container log on the
first start only.

To preset the password instead of generating one:

| Method | Example |
|---|---|
| `--password-file FILE` | `python -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml init --admin alice --password-file C:\secure\initial.txt` (first line of the file; trailing CR/LF removed) |
| `--password-file -` | read the first line from stdin, so the password never appears on a command line |
| `--password PW` | possible, but the password is then visible in the process list and shell history |
| Docker | `GOOSE_WEB_ADMIN_PASSWORD_FILE=/run/secrets/goose_web_admin_password` (preferred) or `GOOSE_WEB_ADMIN_PASSWORD` |

A preset password that does not meet the password rules only produces a warning, because it must be changed at
first sign-in anyway. Both Docker variables are removed from the environment before the gateway starts.

`init` on an existing database does nothing except report "Already initialised" (and record the native root if none
was stored). `init --force` rewrites the admin: it sets role `admin`, a new password with forced change, local
sign-in, profile mode `native`, and re-enables the account.

Lost the initial password? Reset it from the console of the gateway host (section 7.6):

```powershell
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml user reset alice
```

## 5. Running as a service

### 5.1 Windows: logon task

goose-web does not install a Windows service. `scripts\register-service.ps1` (run elevated, normally by the
installer) creates:

- the scheduled task `\GooseWeb\GooseWeb_Gateway`, which runs
  `.venv\Scripts\pythonw.exe -m goose_web --config "<config>" serve` in the install folder. It starts at logon of
  the given user, runs as that user with an Interactive logon and `RunLevel Limited` (a normal, non-elevated token),
  restarts every minute on failure (up to 999 times), has no execution time limit and ignores a second instance.
  The script reads the task back and fails if the run level is not Limited.
- the inbound firewall rule `GooseWeb-Gateway-TCP-<port>`, which allows the port only from
  `-FirewallRemoteAddress` (default `LocalSubnet`).

Because the task is a logon task, the gateway runs while that user is signed in to Windows (a locked screen is
fine). It stops when the user signs out.

```powershell
# start, stop and inspect the task
Start-ScheduledTask -TaskPath '\GooseWeb\' -TaskName 'GooseWeb_Gateway'
Stop-ScheduledTask  -TaskPath '\GooseWeb\' -TaskName 'GooseWeb_Gateway'
Get-ScheduledTask   -TaskPath '\GooseWeb\' -TaskName 'GooseWeb_Gateway' | Get-ScheduledTaskInfo

# register again later (elevated PowerShell)
powershell -ExecutionPolicy Bypass -File C:\GooseWeb\scripts\register-service.ps1 -User "$env:USERDOMAIN\$env:USERNAME" `
  -InstallDir C:\GooseWeb -ConfigPath C:\Goose_Web_Profiles\_system\config.yaml -Port 8710 -FirewallRemoteAddress 192.168.1.2
```

To run the gateway in the foreground instead (for example while testing), use `scripts\start-gateway.cmd`. Pass
`--config FILE` or set `GOOSE_WEB_CONFIG` if your profiles root is not `C:\Goose_Web_Profiles`.

Never run the gateway elevated ("Run as administrator", a SYSTEM task, a task with "Run with highest privileges",
or a Password/S4U logon task). If it is started elevated anyway, it relaunches itself with a normal-user,
Medium-integrity token, or refuses to run (exit code 3). `server.allow_elevated: true` disables this guard; leave it
off.

### 5.2 Linux: systemd user service

`install.sh --systemd` writes `~/.config/systemd/user/goose-web.service` (`Restart=on-failure`, `RestartSec=5`,
`NoNewPrivileges=yes`) and enables it.

```bash
systemctl --user status goose-web
systemctl --user restart goose-web
journalctl --user -u goose-web -f
loginctl enable-linger "$USER"     # start the user service at boot, without an interactive login
```

The gateway refuses to run as root (exit code 3) unless `server.allow_elevated` is true. Do not run it as root.

### 5.3 macOS

The installer offers no service integration on macOS. Run the gateway as the normal user with:

```bash
/opt/goose-web/.venv/bin/python -m goose_web --config ~/.local/share/goose-web/_system/config.yaml serve
```

If you want it to start automatically, wrap that command in your own launchd agent for the same user.

### 5.4 Docker

The compose file uses `restart: unless-stopped` and a health check (`curl -fsS http://127.0.0.1:8710/healthz`).

```bash
docker compose -f docker/compose.yaml ps
docker compose -f docker/compose.yaml restart goose-web
docker compose -f docker/compose.yaml logs -f goose-web
```

### 5.5 What happens at start and stop

At start the gateway opens the database (applying migrations and the audit purge), reads the goose version, and
registers a worker for every enabled user so that profiles with schedules can run without anyone connected. It
records `system.start` in the audit log. At stop it stops all workers and records `system.stop`. On Windows the
workers are in a kill-on-close job object, so they also end if the gateway process dies.

## 6. Network exposure: reverse proxy, TLS, hosts and origins

The gateway speaks plain HTTP. For anything beyond the gateway host itself, put a TLS reverse proxy in front of it.

### 6.1 The settings that must match

| Setting | Effect |
|---|---|
| `server.host` | Listen address. Bind to the interface the proxy uses (for example `192.168.1.10`), not `0.0.0.0`, unless a firewall covers every interface. A non-wildcard bind address is automatically on the Host allow-list. |
| `server.public_url` | The address users open, for example `https://goose.example.org`. When set: the allowed browser Origins are only this origin plus `server.allowed_origins` (the request's own Host is not used); its host name is on the Host allow-list; with `https://` the session cookie is `__Host-gw` with `Secure` and every response carries `Strict-Transport-Security: max-age=31536000`; it is the base of the OIDC redirect URI (OIDC is refused without it) and of the links in webhook messages. |
| `server.trusted_proxies` | IPs or CIDRs whose `X-Forwarded-For` (rightmost entry), `X-Forwarded-Proto` and `X-Forwarded-Host` are trusted. Default: `127.0.0.1`, `::1`. Add only the proxy's address. |
| `server.allowed_hosts` | Extra names or IPs (no ports, no wildcards) accepted in the `Host` header. Always allowed: the `public_url` host, `localhost`, `127.0.0.1`, `::1` and `server.host` (unless `0.0.0.0` or `::`). Any other Host gets `400 invalid host` (DNS-rebinding guard, `HostGuard`). A trusted proxy's `X-Forwarded-Host` must also be on this list. `GET /healthz` is exempt. |
| `server.allowed_origins` | Extra Origins (`scheme://host[:port]`) accepted for cookie-authenticated writes, sign-in and the WebSocket. Needed only if, with `public_url` set, people also open the gateway directly, for example `http://192.168.1.10:8710`. |

Without `public_url`, the gateway accepts the Origin built from the request's own scheme and Host (which has
already passed the Host allow-list), and from `X-Forwarded-Proto`/`X-Forwarded-Host` when they come from a trusted
proxy.

Changes to `config.yaml` take effect after a gateway restart.

### 6.2 Proxy requirements

- Forward the original `Host` (or make sure the Host the gateway receives is on the allow-list).
- Proxy WebSocket upgrades on `/ws`.
- Set `X-Forwarded-For` (preferably overwrite it with the real client address), `X-Forwarded-Proto` and, if you
  rewrite the host, `X-Forwarded-Host`.
- Do not cut long-lived connections. The gateway pings WebSocket clients every 25 seconds (60-second timeout), but
  agent runs can last much longer than typical proxy timeouts, so disable or raise read/write timeouts.
- Allow request bodies of at least `server.max_upload_mb` (default 25 MB) for file uploads.
- Do not cache `/api/`, `/ws`, `/sw.js` or `/` at the proxy.

Caddy (proxies WebSockets and sets `X-Forwarded-*` by default):

```
goose.example.org {
    reverse_proxy 192.168.1.10:8710 {
        header_up X-Forwarded-For {remote_host}
        transport http {
            read_timeout 0
            write_timeout 0
        }
    }
}
```

nginx:

```nginx
server {
    listen 443 ssl;
    server_name goose.example.org;
    # ssl_certificate / ssl_certificate_key ...

    client_max_body_size 26m;

    location / {
        proxy_pass http://192.168.1.10:8710;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 1h;
        proxy_send_timeout 1h;
        proxy_buffering off;
    }
}
```

Matching gateway configuration (`<profiles_root>/_system/config.yaml`):

```yaml
server:
  host: "192.168.1.10"
  port: 8710
  public_url: "https://goose.example.org"
  trusted_proxies: ["127.0.0.1", "::1", "192.168.1.2"]
  allowed_hosts: []
  allowed_origins: []
```

Then limit the gateway port in the host firewall to the proxy (`register-service.ps1 -FirewallRemoteAddress
192.168.1.2` on Windows).

### 6.3 TLS

- TLS is terminated by the proxy. Use a certificate that browsers trust; the PWA and service worker need a secure
  context (HTTPS, or `http://localhost`).
- Set `public_url` to an `https://` URL only when TLS is permanent for that host name: browsers remember the HSTS
  header for one year.
- With an `https://` public URL the cookie is `Secure`, so signing in over plain `http://` under another address
  does not keep you signed in. Use the public URL.

### 6.4 Uploads and other fixed limits

`server.max_upload_mb` (default 25) limits the size of an upload request; up to 20 files per request. Other limits
are fixed: 2 MiB JSON bodies, 64 MiB WebSocket frames, a 12 MiB live transcript buffer per session and 256 MiB in
total (the oldest idle buffers are dropped first).

## 7. Users and sign-in

User management is in **Admin > Users**. Sign-in methods are in **Admin > Auth providers**, account-wide settings
in **Admin > Settings**.

### 7.1 Roles

| Role | Can do |
|---|---|
| `admin` | everything: the admin console, every ACP method without policy checks, any absolute folder on the host, all users' agents in the herd, opening another user's chats. Policy and per-user overrides do not apply to admins. |
| `user` | what the effective policy of their teams and overrides allows (section 9), inside their workspace and allowed folders |

Keep the number of admins low. At least one enabled admin must remain: you cannot delete the last admin, delete or
disable your own account, or remove your own admin role. The admin with the native profile cannot be changed to
`user` ("The native profile belongs to an administrator").

### 7.2 Creating accounts

| Where | How |
|---|---|
| Admin > Users > New user | user name, display name, e-mail, role, sign-in source (Local password, LDAP / AD, OIDC / SSO), profile mode, initial password, "Must change at first sign-in", teams, shared hints. If no password is given for a local account, a temporary password is generated and shown once. Without explicit teams the user joins the default team. The isolated profile is created right away. |
| Console | `python -m goose_web --config <config> user add bob` creates a local user with a temporary password (printed) and a forced change, and adds it to the default team. `--admin` makes it an admin, `--password` sets the password. The profile is created at the first sign-in. |
| LDAP | users are created at their first successful directory sign-in when "autoCreate" is on (section 7.4) |
| OIDC | users are created at their first sign-in when "Create users automatically" is on (section 7.5) |

User names: letters, digits, `.`, `_` and `-`, starting with a letter or digit, up to 64 characters. Windows device
names and the reserved names `appdata`, `workspace`, `_system`, `_deleted`, `library`, `backups` and `logs` are
refused, because the user name becomes the profile folder name.

Password rules (`auth.min_password_length`, default 10): at least that many characters, not equal to the user name,
not a common password, and 3 of lower case, upper case, digit and symbol unless the password has 16 or more
characters. Passwords are stored as scrypt hashes.

### 7.3 Local accounts

- Local sign-in can be turned off for non-admins in Admin > Auth providers ("Allow local username/password
  sign-in"). Local admins can always sign in, so keep one local admin as a break-glass account.
- Users change their own password in their account settings. A password change ends all their other sessions and
  revokes all their API tokens.
- Accounts whose sign-in source is LDAP or OIDC cannot change their password in goose-web ("This account's password
  is managed by your directory").

### 7.4 LDAP and Active Directory

Configure in Admin > Auth providers > LDAP / Active Directory:

| Field | Meaning |
|---|---|
| Server URL | `ldaps://dc01.example.org:636` (recommended) or `ldap://...` with StartTLS |
| Bind DN, Bind password | service account used to search for the user (least privilege; the password is write-only in the UI) |
| User search base, User filter | where and how to find the user; `{username}` is escaped. Default filter `(&(objectClass=user)(sAMAccountName={username}))` |
| Admin group DN | a `memberOf` value that makes the user an admin |
| Group to team mapping | one line per group: `<group DN> = <team id>` |
| Use StartTLS | StartTLS on an `ldap://` URL |
| Allow unencrypted LDAP | allows plain `ldap://` without StartTLS; not recommended |
| `caFile` | CA bundle for a private CA (stored in the auth settings; certificates are always verified) |

How it works:

- A user name that does not exist locally, or a user whose sign-in source is `ldap`, is checked against the
  directory: service bind, search (exactly one entry must match), then a bind as the user with the given password.
- A plain `ldap://` URL without StartTLS is refused when the settings are saved (`400 bad_config`) and at sign-in
  (`503 ldap_insecure`, no bind is attempted), unless "Allow unencrypted LDAP" is on.
- First sign-in with "autoCreate" on (the default): the account is created with sign-in source `ldap`, an isolated
  profile, role `admin` if the user is in the admin group (otherwise `user`), and membership of the mapped teams, or
  of the default team when no group maps.
- Every later sign-in updates role, display name and e-mail from the directory (the native-profile admin is never
  demoted) and adds the user to mapped teams. Team memberships are never removed by a sign-in.
- With autoCreate off, create the user first in Admin > Users with sign-in "LDAP / AD".
- A local account with the same name is never checked against the directory; it keeps using its local password.
- Resetting the password of an LDAP account (Admin reset or `user reset`) switches it to a local account.

### 7.5 OpenID Connect (single sign-on)

OIDC needs `server.public_url`. Without it, sign-in is refused with `oidc_needs_public_url`, so the redirect URI
never depends on the request's Host header.

Add a provider in Admin > Auth providers > OpenID Connect providers:

| Field | Meaning |
|---|---|
| ID | lower-case slug (`a-z`, `0-9`, `-`), part of the redirect URI |
| Button label | text on the sign-in page ("Continue with ...") |
| Issuer URL | discovery is read from `<issuer>/.well-known/openid-configuration` (cached for one hour) |
| Client ID, Client secret | from the identity provider; the secret is write-only in the UI |
| Scopes | default `openid profile email` |
| Admin claim, Admin claim value | the user becomes admin when the claim contains the value (or, with no value, when the claim is `true`) |
| Team claim | claim whose values are matched against team names (case-insensitive) |
| Create users automatically | create accounts on first sign-in (off by default for a provider added in the UI) |

Register this redirect URI at the identity provider:

```
https://goose.example.org/api/auth/oidc/<id>/callback
```

The admin UI shows a redirect URI based on the address you are browsing; the gateway always uses `public_url`, so
register the `public_url` form.

How it works:

- Authorization code flow with PKCE, state and nonce (valid for 10 minutes). The ID token's issuer, audience,
  expiry and nonce are checked, and userinfo claims are merged when available.
- The user name comes from `preferred_username`, else `email`, else `sub`. By default the domain part is removed
  (`alice@example.org` becomes `alice`; the provider option `stripDomain: false`, settable through the API, keeps
  it). Characters other than letters, digits, `.`, `_` and `-` become `-`.
- The account is bound to the stable issuer + subject pair of its first sign-in. Later sign-ins must come from the
  same identity. A different identity for the same user name gets `oidc_conflict`, and a local or LDAP account with
  that name is never taken over.
- To pre-create a user, add it in Admin > Users with sign-in "OIDC / SSO" and the expected user name; the first
  sign-in binds it.
- Role and team claims are applied at every sign-in (the native-profile admin is never demoted; teams are only
  added). New users without a matching team join the default team.

### 7.6 Disabling, unlocking, resetting and deleting

| Task | Admin UI (Admin > Users > actions menu) | Console |
|---|---|---|
| Disable or enable | "Disable account" / "Enable account". Disabling ends every session and revokes every API token of the user. A disabled user cannot sign in (the sign-in page says "Invalid username or password") and their worker is not started at gateway start. | none |
| Unlock after failed sign-ins | "Unlock" (clears the failure counter and the lock) | `user reset NAME` also unlocks |
| Reset password | "Reset password" (local accounts only): shows a temporary password once, forces a change, ends all sessions, revokes all API tokens, unlocks | `user reset NAME [--password PW]`: same effect, prints the temporary password, also re-enables a disabled account and switches the account to local sign-in |
| Reset two-factor (lost authenticator) | "Reset two-factor" (only for users with the "2FA" badge, never your own account): removes the two-factor enrolment, unlocks, ends all sessions, revokes all API tokens. The user signs in with the password and enrols again (section 7.8) | `user reset-totp NAME`: same effect |
| Set a password | Edit > password field (admin API `PATCH`), with "must change" on by default; ends sessions and revokes tokens | none |
| Re-provision the profile | "Re-provision profile": applies teams, hints and policy again and lists the changes | none |
| Delete | "Delete...": stops the worker and removes the account. The isolated profile folder is moved to `<profiles_root>/_deleted/<user>-<timestamp>`, or deleted permanently if you tick the box. The native profile is never moved or deleted. | none |

Console commands work on the database directly. Run them on the gateway host, as the same OS account as the
gateway (not elevated, not root), and with the same `--config`:

```powershell
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml user list
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml user reset bob
```

```bash
docker compose -f docker/compose.yaml exec goose-web python -m goose_web user reset admin
```

### 7.7 Sign-in protection and sessions

| Mechanism | Behaviour |
|---|---|
| Rate limit | at most 40 sign-in attempts per 5 minutes per client IP and 10 per 5 minutes per IP and user name (`429`, in memory, cleared by a gateway restart) |
| Lockout | after `auth.lockout_threshold` (8) failed factors - wrong passwords and wrong or replayed TOTP codes both count - the account is locked for `auth.lockout_minutes` (15) (`423`, also with the right password) |
| Session length | fixed from sign-in, never extended. Without "Keep me signed in": `session_hours` (Admin > Settings > Sign-in lifetime, 1 to 720 hours, default `auth.session_hours` = 12). With "Keep me signed in" (ticked by default on the sign-in page): `auth.remember_days` (30 days, config only) |
| Cookie | `HttpOnly`, `SameSite=Strict`; `__Host-gw` with `Secure` when `public_url` is `https://`, otherwise `gw` |
| Writes | need the CSRF header and an allowed Origin |
| Signed-in devices | users see and revoke their own sessions in their account settings |

### 7.8 Two-factor authentication (TOTP)

- Users enrol in their account settings: the gateway creates a secret, shows it with a QR code (`otpauth://`, SHA1,
  6 digits, 30 seconds), and enables two-factor after the first valid code. Each code can be used only once.
- Sign-in with two-factor asks for the code after the password. Codes from one time step before or after are
  accepted, so the phone's clock must be roughly correct.
- Turning it off requires the account password (local accounts).
- Admin > Settings > "Users may enable two-factor themselves" (`allow_self_totp`, default on). When off, non-admins
  cannot set up or enable two-factor (`403 totp_self_disabled`). Admins can always enrol.
- Admin > Settings > "Require two-factor for administrators" (`require_totp_admins`, default off). It can only be
  switched on by an admin who already uses two-factor (`409 totp_needed_first`). While it is on, admins cannot turn
  their two-factor off. Admins without two-factor are reported as `totpEnrolmentRequired` by the sign-in response
  and `/api/me`; enrolment is not forced at sign-in, so check that every admin has enrolled (the user list shows a
  "2FA" badge).
- **Lost authenticator.** Admin > Users > actions menu > "Reset two-factor" (or `user reset-totp NAME` on the
  gateway host, or `POST /api/admin/users/{id}/reset-totp`) removes the user's two-factor, clears the lock, ends
  all of their sessions and revokes their API tokens. It is audited as `user.totp.reset`. The user signs in with
  the password alone and enrols a new authenticator. The admin console does not offer it for your own account
  (`400 self`): turn your own two-factor off in your account settings, or have another admin reset it. Resetting
  another admin while "Require two-factor for administrators" is on is allowed; that admin is then reported as
  `totpEnrolmentRequired` until they enrol again. Step by step: [TROUBLESHOOTING.md](TROUBLESHOOTING.md#lost-authenticator).

## 8. API tokens

API tokens let scripts and other gateways (herd peers) use the REST API and the `/ws` WebSocket.

- Users create them in their account settings (API tokens), with a name and an optional lifetime in days. The token
  (`gwt_...`) is shown once; only a hash and a short prefix are stored. A token cannot create other tokens.
- A token is sent only as `Authorization: Bearer gwt_...`. It is never accepted in a URL. A WebSocket handshake with
  a token must not carry an `Origin` header (browsers authenticate with the session cookie instead).
- A token has the rights of its user. An admin's token can call the admin API.
- Tokens are not checked for CSRF or Origin, because they are not sent automatically by browsers.

A token stops working when:

| Event | Effect |
|---|---|
| it expires | refused |
| the user deletes it | deleted |
| the user changes their password | all of the user's tokens are deleted |
| an admin sets or resets the password (UI, API or `user reset`) | all tokens deleted |
| an admin resets the user's two-factor (UI, API or `user reset-totp`) | all tokens deleted |
| the account is disabled | all tokens deleted (and refused while disabled) |
| the account must change its password | refused until the password is changed |
| the account is deleted | deleted with the account |

Admins cannot list or revoke another user's individual tokens; disable the account or reset its password to revoke
all of them.

Example:

```bash
curl -H "Authorization: Bearer gwt_xxxxxxxx" https://goose.example.org/api/me
```

## 9. Teams and policies

Teams are managed in **Admin > Teams & policy**. A team has a name, a description, a policy, members, assigned
shared hints and library items.

### 9.1 The default team

`init` creates the team **Everyone** with an empty policy (that is, the default policy: no shell, no extension
changes) and makes it the default team. Users created in the admin UI without explicit teams, users created with
`user add`, and LDAP/OIDC users without a mapped team join the default team. Change it in Admin > Settings >
"Default team for new users". If you delete the default team, choose another default (or none) in Admin > Settings.

### 9.2 Policy settings

Policies apply to non-admins only. The admin UI shows the flags as switches and the lists as text fields
(comma-separated, or one folder per line); an empty list means "unrestricted" (for folders: only the workspace).

| Key | UI label | Default | When on (or set), the user may |
|---|---|---|---|
| `recipes_edit` | Edit recipes | on | save and delete recipes, create recipe and subrecipe sources. Team recipes cannot be deleted by members. |
| `skills_edit` | Edit skills | on | create, update, delete and import skills, agents and project sources |
| `extensions_edit` | Edit extensions | off | add, remove, enable and disable extensions, and choose extensions for a new session |
| `providers_edit` | Edit providers & models | off | manage custom providers, provider configuration and secrets, default provider/model, local model downloads, onboarding import |
| `schedules` | Manage schedules | on | create, update, delete, pause, resume and run schedules |
| `apps` | Manage apps | on | import and delete MCP Apps, and call tools directly from an app (`tools/call`) |
| `prompts_edit` | Edit system prompts | off | change system prompts |
| `hints_edit` | Edit personal hints | on | edit their personal goose hints |
| `tools_permissions` | Set tool permissions | on | change per-tool permission settings |
| `config_edit` | Edit raw config | off | read and write the raw Goose configuration (treat like `allow_shell`) |
| `allow_shell` | Allow shell / stdio extensions | off | use command-running extensions (`developer`, `computercontroller`, `code_execution`, `orchestrator`), stdio MCP extensions, per-session MCP servers and direct shell tool calls |
| `notify_webhook` | Notification webhooks | off | set a personal notification webhook |
| `allowed_modes` | Allowed modes | any | only these Goose modes (`auto`, `approve`, `smart_approve`, `chat`) |
| `allowed_providers` | Allowed providers | any | only these provider ids |
| `allowed_models` | Allowed models | any | only these model ids |
| `allowed_roots` | Allowed folders | workspace only | use these folders in addition to their workspace (chat folders, file browser, uploads, downloads). Symlinks and junctions are resolved, so a link inside an allowed folder cannot lead outside. |
| `max_concurrent_runs` | Max concurrent runs | 3 | have at most this many agents running at once (0 or empty = no limit) |

Every ACP method that is not explicitly allowed is denied for non-admins, so a new Goose release cannot open new
functions by itself. Denials are returned as `forbidden: <reason>` and recorded in the audit log as `acp.denied`.

Two rules apply to everyone, admins included: an MCP App's direct tool call may only use tools of the extension it
names, and `session/new` is always tagged with the client name `goose-web`.

Teams can also carry `default_provider` and `default_model`, which are written into members' profiles when they
have no provider yet. These two keys are not shown in the admin UI; set them through the admin API
(`PATCH /api/admin/teams/{id}` with `policy.default_provider` and `policy.default_model`, see [API.md](API.md)).

### 9.3 How team policies combine

| Situation | Effective policy |
|---|---|
| user is an admin | everything allowed, no lists, no run limit; overrides are ignored |
| user in no team | the default policy (table above) |
| user in one or more teams | each team's policy is first laid over the default policy, then: switches are OR-ed (any team that allows it grants it); `allowed_modes`, `allowed_providers` and `allowed_models` are unioned, but if any team leaves a list empty the result is unrestricted; `allowed_roots` are unioned; `max_concurrent_runs` is the highest number of all teams (0 = unlimited results only when every team says 0) |
| per-user overrides | applied last; each key in the override replaces the combined value |

Per-user overrides are set in Admin > Users > Edit > "Policy overrides (advanced)" as a JSON object, for example:

```json
{ "allow_shell": false, "allowed_modes": ["approve"], "max_concurrent_runs": 1 }
```

Only known policy keys are kept. An empty field removes all overrides.

### 9.4 What a policy change does to a profile

Saving a team (policy, members or hints), changing a user's teams, hints or overrides, or adding or removing a team
item re-provisions the affected isolated profiles:

- shell extensions are disabled in the profile's `config.yaml` when `allow_shell` is off
- team items are written, updated or removed
- if `allowed_providers` is set and the profile's provider is not allowed, the provider is reset to the team default
  or the first allowed provider
- if `allowed_modes` is set and the profile's mode is not allowed, the mode is set to the first allowed mode
- the composed `.goosehints` is rewritten

When something changed while the user's worker is running, the worker is marked "restart pending" and restarts
when it has no active runs and no open questions. Policy checks on ACP calls use the new policy at the next
WebSocket connection of the user.

### 9.5 Team library items

A team can hand recipes, skills, extensions and providers to its members. In the team's "Library items" section,
choose "Add from library", pick a profile (any user, including your own native profile) and a kind, then add an
item. It is copied into the team:

| Kind | Delivered to members as |
|---|---|
| recipe | a file in `<system_dir>/library/teams/<team id>/recipes/`, which is on the members' `GOOSE_RECIPE_PATH`. Members cannot delete it. |
| skill | a folder in the member's `config/skills/<name>/`, marked as managed. A skill the user created with the same name is never overwritten. Up to 2 MB of text files per skill; binary files are not shared. |
| extension | an entry in the member's `config.yaml`. Shell and stdio extensions stay disabled for members without `allow_shell`. |
| provider | a custom provider file in `config/custom_providers/` |

For extensions and providers added from a profile library, the secrets named by the item (the extension's
`env_keys`, the provider's API key variable) are copied from the source profile's `secrets.yaml` into each member's
`secrets.yaml`. Members therefore receive a copy of those credentials; share only credentials you intend to share.
Items added manually through the API never copy secrets from another profile. Removing an item, or removing a user
from the team, removes what was provisioned (but never items the user created).

## 10. Shared goose hints

The **Admin > Hints library** holds shared `.goosehints` documents. Assign a document to teams (team > Assigned hints)
or to individual users (Admin > Users > Edit > Goose hints).

For each isolated profile the gateway composes `config/.goosehints` from:

1. a header saying the file is managed by Goose Web
2. every assigned document (directly or through a team), sorted by name
3. the user's personal hints (editable by the user when `hints_edit` is on)

Saving, renaming or deleting a document rewrites the hints of every user it is assigned to immediately; this is
safe while Goose runs. Edits made directly in an isolated profile's `.goosehints` file are overwritten.

The native profile is different: its `.goosehints` belongs to the admin and is never composed. The admin edits it in
their own settings, and the previous file is copied to `<system_dir>/backups/native-hints/` before each save.
Shared documents assigned to a native-profile admin are listed but not written into that file.

## 11. Profiles

### 11.1 Isolated profiles (default)

Every non-native user gets `<profiles_root>/<username>/`, which is the `GOOSE_PATH_ROOT` of their worker:

```
<profiles_root>/<username>/
  config/        config.yaml, secrets.yaml, .goosehints (composed), custom_providers/, recipes/, skills/
  data/          sessions/sessions.db, logs/        (written by Goose)
  state/                                            (written by Goose)
  workspace/     default folder for new chats
  .goose-web/managed.json                           what the gateway provisioned
```

- The profile is created when the user is created in the admin UI or at their first sign-in.
- The first provisioning copies the base platform extensions (`todo`, `skills`, `apps`, `chatrecall`, `summarize`,
  `extensionmanager`, `analyze`, `memory`, `summon`, `tom`) from the native admin's configuration when they exist
  there, sets `GOOSE_MODE: approve`, and writes the `developer` extension as disabled unless `allow_shell` is on.
  If the admin's provider is also provided to the user as a team item (and allowed), the admin's provider and model
  become the user's default.
- Isolated workers get `GOOSE_DISABLE_KEYRING=1` (secrets stay in the profile's `secrets.yaml`), a
  `GOOSE_RECIPE_PATH` with only their team recipe folders, and none of the gateway's `GOOSE_*` environment variables
  (except `GOOSE_DISABLE_KEYRING` and `GOOSE_TELEMETRY_ENABLED`). Values in `goose.extra_env` are passed to every
  worker, isolated ones included.

### 11.2 The native profile

Profile mode `native` binds an admin to an existing Goose profile folder (on Windows normally `%APPDATA%\Block\goose`;
on a fresh install `<profiles_root>/appdata`; in Docker `/data/appdata`). It is stored as the `native_root` setting.

Implications:

- Goose Desktop, the goose CLI and the browser all work on the same chats, recipes, extensions, providers and
  settings. Changes made elsewhere show up in an open web chat within a few seconds.
- The gateway never provisions the native profile: no team items, no policy, no composed hints. It writes there
  only when the admin saves their own goose hints (after a backup).
- When the folder is Goose's default location, `GOOSE_PATH_ROOT` is not set for the native worker, and the worker
  inherits the gateway's full environment (including any `GOOSE_*` variables and the OS keyring).
- The native admin's default folder for new chats is `goose.default_workdir_native` (default: the home folder),
  and the file browser offers every drive (Windows) or `/`.
- Only admins can have the native profile. Use it for one admin at most: every native user gets the same folder,
  and two workers on one profile would, for example, both run its scheduler. Additional admins should use isolated
  profiles.
- Scheduler ownership must be shared with Goose Desktop (section 13).
- Deleting the native admin never deletes the native profile folder.

### 11.3 Isolation limits

All workers run as the gateway's OS account. A tool that can read files or run commands can reach other profiles,
the database and the native profile. That is why the shell extensions and stdio MCP servers are off for non-admins
unless `allow_shell` is on; grant it only to people you would trust with that OS account. Home-folder skill and
recipe folders such as `~/.agents/skills` and `~/.agents/recipes` are not moved by `GOOSE_PATH_ROOT` and are visible to
all profiles. Admins always have the full power of the OS account.

## 12. Workers

Admin > System lists every worker with its state (`stopped`, `starting`, `ready`, `crashed`), PID and port, uptime,
connected clients, active runs, whether it owns the scheduler, restart count and last error. It refreshes every
10 seconds and offers **Restart** and **Stop** per worker. The page also shows the gateway and goose versions, the
goose binary, the OS account and integrity level, the profiles root, the native root and whether Goose Desktop is
running.

| Behaviour | Details |
|---|---|
| Start | on first use (sign-in, opening the UI, a REST call that needs Goose), or at gateway start / by the monitor for profiles with schedules. Command: `goose serve --host 127.0.0.1 --port <random> --platform desktop [--enable-scheduler]`, with a random secret in `GOOSE_SERVER__SECRET_KEY`. |
| Ready check | the gateway polls `http://127.0.0.1:<port>/status` until it answers, for at most `goose.start_timeout_seconds` (45) |
| Idle shutdown | the monitor (every 15 seconds) stops a worker after `goose.idle_minutes` (30) without browser clients, active runs, open questions or scheduler duty |
| Crash restart | a crashed worker is restarted with exponential backoff (2, 4, 8 ... seconds, at most 5 minutes) while browsers are connected or it owns a scheduler with jobs; otherwise it starts again on next use |
| Pending restart | after a profile change (section 9.4) or a scheduler hand-over (section 13), when no run is active |
| Stop by admin | Admin > System > Stop: in-flight calls fail with "stopped by an administrator"; the worker starts again when the user connects |
| Restart by admin | Admin > System > Restart: active runs are interrupted (the UI asks for confirmation) |
| Process tree | stopping a worker also stops its MCP server processes (Windows: `taskkill /T`; Linux/macOS: the worker's process group) |
| Concurrency | `max_concurrent_runs` per profile for non-admins |

Worker output goes to `<system_dir>/logs/worker-<username>.log` (section 18).

## 13. Schedules and the native scheduler

Schedules are created by users on the Schedules page (needs the `schedules` permission) and are run by Goose's own
scheduler inside the worker. A worker runs the scheduler when it is started with `--enable-scheduler`:

| Profile | `goose.native_scheduler` | Scheduler runs in the gateway's worker |
|---|---|---|
| isolated | ignored | always |
| native | `on` | always |
| native | `off` | never (schedules run in Goose Desktop, or not at all) |
| native | `auto` (default) | only while Goose Desktop is not running |

- In `auto` mode the gateway checks for Goose Desktop (Windows only; on other systems `auto` behaves like `on`).
  When Desktop starts or stops, the native worker is restarted once no run is active, which hands the scheduler
  over. If detection fails, the gateway assumes Desktop is running, so jobs never fire twice.
- A worker whose profile has jobs in `data/schedule.json` and that owns its scheduler is started even when nobody is
  connected, is never stopped for idleness, and is restarted after a crash.
- When the gateway does not own the scheduler, the Schedules page shows "The scheduler is not active in this Goose
  Web instance" with the reason, and schedules are read-only there.
- The gateway must be running for schedules to fire. With the Windows logon task, that means the gateway user must
  be signed in.
- Disabled users' workers are not started at gateway start, so their schedules do not run.

The Docker image sets `native_scheduler: on`, because there is no Goose Desktop in the container.

## 14. Notifications and webhooks

Users can be told when an agent needs them, finishes, or fails (events `needs_you`, `done`, `error`):

- **Browser notifications and a sound**, configured by each user in their settings.
- **A personal webhook**, which needs the `notify_webhook` permission (admins always have it). The user sets an
  `http://` or `https://` URL (at most 500 characters) and the events.

A webhook is sent only when no open tab of that user is watching the session. URLs containing `ntfy` receive a
plain-text message with `Title`, `Tags`, `Click` and `Priority` headers (ntfy style); all other URLs receive JSON:

```json
{ "event": "done", "title": "Goose finished", "message": "<chat title>: <last text>",
  "url": "https://goose.example.org/#/chat/<session id>", "agent": { "...": "..." } }
```

The link is included only when `server.public_url` is set.

SSRF guard: every address the webhook host resolves to must be a public internet address. Loopback, private
(RFC 1918, IPv6 ULA), link-local, carrier-grade NAT, reserved, multicast and unspecified addresses, including IPv4
addresses embedded in IPv6, are refused - when the webhook is saved (`400 webhook_blocked`) and again when it is
sent (logged as "webhook refused"). The request goes to the checked IP address, redirects are not followed, proxy
environment variables are ignored, and the timeout is 8 seconds.

To allow internal targets such as a self-hosted ntfy on the LAN:

```yaml
notify:
  allow_private_targets: true
```

This lets every user with `notify_webhook` make the gateway send requests into your internal network, so turn it on
only if you need it, and grant `notify_webhook` sparingly.

## 15. Herd view, peers and viewing another user's chats

The Herd page lists live agents with their state (`working`, `needs_you`, `done`, `idle`, `error`). Agents keep
running after a tab is closed.

- Admins can switch on **All users** to see every profile's agents.
- **Herd peers** (Admin > Settings > Herd peers) add agents from other goose-web gateways. Each peer has a name, a
  URL and an API token of a user on that gateway; the gateway calls `<url>/api/herd` with that token and shows that
  user's agents. Peer data is shown only to admins signed in through the browser, peers are not queried
  recursively, and peer tokens are masked when the settings are read. Use a token of an account whose agents admins
  may see.
- **Open their Herd / chats** (Admin > Users > actions menu) opens a new tab connected to that user's profile
  (`/?profile=<username>`). Only admins can do this. It is recorded as `ws.impersonate`, and calls made on another
  user's profile are recorded as `acp.*` entries in the audit log.

## 16. Audit log

**Admin > Audit log** shows the newest entries first, with filters for the user (prefix) and the action (substring),
and loads more as you scroll. Each entry has a time, user, client IP, action, target, details and a success flag.
Failed actions are highlighted.

Recorded actions:

| Area | Actions |
|---|---|
| System | `system.init`, `system.start`, `system.stop` |
| Sign-in | `auth.login` (success and failure), `auth.logout`, `auth.totp` (wrong code), `auth.ldap` (insecure LDAP refused), `auth.oidc` (OIDC failure), `user.oidc.bind` |
| Own account | `user.password`, `user.totp.enable`, `user.totp.disable`, `user.token.create`, `user.token.delete`, `hints.personal.save`, `hints.native.save` |
| User admin | `user.create`, `user.update` (changed field names, never the password), `user.delete`, `user.reset_password`, `user.totp.reset` (two-factor reset, `"via": "cli"` from the console), `user.unlock`, `user.provision` |
| Teams and hints | `team.create`, `team.update`, `team.delete`, `team.item.add`, `team.item.remove`, `hints.create`, `hints.update`, `hints.delete` |
| Settings | `settings.auth`, `settings.update` |
| Operations | `worker.restart`, `worker.stop`, `hosttask.<action>`, `fs.upload` |
| Agent calls | `acp.denied` (policy denials, with the reason), `acp.<method>` for sensitive methods (configuration, providers and secrets, recipes save/delete, schedules create/delete, apps import/delete, sources, tool permissions, direct tool calls, adding session extensions, defaults, session delete) and for every call on another user's profile, `acp.answer` (answers to permission prompts and forms, with the choice) |
| Admin access | `ws.impersonate` |

Retention: entries older than 365 days are deleted whenever the database is opened (at gateway start, and by console
commands). There is no export button; for longer retention, copy entries out regularly through
`GET /api/admin/audit?limit=500&before=<id>` (admin token) or from your database backups.

The client IP is the proxy-reported address only for requests from `server.trusted_proxies`; otherwise it is the
TCP peer.

## 17. Windows tools: ownership check and host tasks

**Admin > Ownership check** scans a profile's `config` folder (up to 20,000 items) and lists files that are not owned
by the gateway's OS account. Such files are usually created by an elevated process and can lock Goose out of its own
configuration. Fix them from an elevated prompt with `icacls <path> /setowner <user> /T`, then stop running Goose
elevated.

**Admin > Host tasks** (Windows only) lists the host's scheduled tasks (except `\Microsoft\*`), with a warning for
tasks that run as a system account, with highest privileges, or with a non-interactive logon, because files they
create may not be owned by the user. Admins can run, end, enable and disable tasks the gateway user is allowed to
manage; each action is audited. The gateway never changes a task's principal. Restrict the list with
`host_tasks.path_filter`, or turn the view off:

```yaml
host_tasks:
  enabled: false
```

## 18. Logs

| Log | Location | Rotation |
|---|---|---|
| Gateway | `<system_dir>/logs/gateway.log`, and stderr when there is a console (systemd journal, `docker logs`; not under the Windows logon task, which uses `pythonw.exe`) | 5 MB, 5 old files (`gateway.log.1` ... `.5`) |
| Worker (Goose stdout/stderr) | `<system_dir>/logs/worker-<username>.log`; each start writes a `==== <time> start serve ... root=<profile>` line | checked before each worker start: above 10 MB it is rotated, 3 old files (`.1` ... `.3`). A worker that runs for a long time is not rotated until it restarts. |
| Goose's own logs | `<profile>/data/logs/` (isolated profiles), or the native profile's log folder | managed by Goose |
| Audit | in the database (section 16) | 365 days |

**Admin > Logs** shows the tail of the gateway log or any worker log (200 to 2000 lines, filter, auto-refresh,
copy). Set the log level with the environment variable `GOOSE_WEB_LOG_LEVEL` (for example `DEBUG`; default
`INFO`). Logs can contain user names, IP addresses, folder paths and error text; protect them like the database.

## 19. Backups and restore

### 19.1 What to back up

| Item | Default location | Why |
|---|---|---|
| Database | `<system_dir>/goose-web.db` (plus `-wal` and `-shm` while running) | users, password hashes, TOTP secrets, teams, policies, shared hints, team items, API token hashes, settings including the LDAP bind password, OIDC client secrets and peer tokens, audit log |
| Configuration | `<system_dir>/config.yaml` (or the file you pass with `--config`), or the compose file and its environment | server, paths, goose and auth settings |
| Team library | `<system_dir>/library/` | team recipe files |
| Native hints backups | `<system_dir>/backups/native-hints/` | earlier versions of the admin's hints |
| Isolated profiles | `<profiles_root>/<username>/` | each user's chats (`data/sessions/sessions.db`), recipes, skills, extensions, providers and `secrets.yaml` |
| Archived profiles | `<profiles_root>/_deleted/` | profiles of deleted users |
| Native profile | `%APPDATA%\Block\goose` on Windows when bound to the existing profile (outside the profiles root); `<profiles_root>/appdata` on fresh installs; `/data/appdata` in Docker | the admin's Goose profile |
| Docker | the `goose-web-data` volume (all of the above) and any host folders you mounted | |

The database and the profiles contain credentials. Encrypt and restrict backups like the originals.

### 19.2 Online backup of the database

The database uses SQLite in WAL mode. Do not copy `goose-web.db` alone while the gateway runs; use SQLite's backup
API, which produces a consistent copy:

```powershell
C:\GooseWeb\.venv\Scripts\python.exe -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()" C:\Goose_Web_Profiles\_system\goose-web.db D:\Backups\goose-web.db
```

```bash
sqlite3 ~/.local/share/goose-web/_system/goose-web.db ".backup '/backup/goose-web.db'"
```

```bash
# Docker: write the copy into the volume, then copy it out
docker compose -f docker/compose.yaml exec goose-web python -c "import sqlite3; s=sqlite3.connect('/data/_system/goose-web.db'); d=sqlite3.connect('/data/_system/backups/goose-web.db'); s.backup(d); d.close(); s.close()"
docker compose -f docker/compose.yaml cp goose-web:/data/_system/backups/goose-web.db ./goose-web.db
```

(Create `/data/_system/backups` first if it does not exist yet.)

### 19.3 Full backup

Goose writes each profile's `sessions.db` while workers run. For a fully consistent backup of the profiles, stop
the gateway (which stops all workers), copy the profiles root, the native profile and the configuration, and start
it again:

```powershell
Stop-ScheduledTask -TaskPath '\GooseWeb\' -TaskName 'GooseWeb_Gateway'
robocopy C:\Goose_Web_Profiles D:\Backups\Goose_Web_Profiles /MIR /COPY:DAT /R:1 /W:1
robocopy "$env:APPDATA\Block\goose" D:\Backups\goose-native /MIR /COPY:DAT /R:1 /W:1
Start-ScheduledTask -TaskPath '\GooseWeb\' -TaskName 'GooseWeb_Gateway'
```

```bash
docker compose -f docker/compose.yaml stop goose-web
docker run --rm -v goose-web_goose-web-data:/data:ro -v "$PWD":/backup goose-web:latest \
  tar -czf /backup/goose-web-data.tgz -C /data .
docker compose -f docker/compose.yaml start goose-web
```

(The compose project is called `goose-web`, so the volume is normally `goose-web_goose-web-data`; check with
`docker volume ls`.)

### 19.4 Restore

1. Stop the gateway.
2. Put back the profiles root (or volume), the native profile and the configuration.
3. When you restore `goose-web.db`, delete any `goose-web.db-wal` and `goose-web.db-shm` files next to it that do not
   belong to the restored copy.
4. Restore files as the gateway's OS account (or fix ownership afterwards), so the gateway and Goose can write them.
5. Start the gateway and run `goose-web check`.

## 20. Upgrades

### 20.1 Native installs

1. Read the release notes and back up (section 19).
2. Stop the gateway (`Stop-ScheduledTask ...` or `systemctl --user stop goose-web`).
3. Replace the install folder's contents with the new release (for example update your clone of the repository).
4. Reinstall the dependencies from the lock file and the package:

   ```powershell
   cd C:\GooseWeb
   .venv\Scripts\python.exe -m pip install --require-hashes -r requirements.lock
   .venv\Scripts\python.exe -m pip install --no-deps -e .
   ```

   ```bash
   cd /opt/goose-web
   .venv/bin/python -m pip install --require-hashes -r requirements.lock
   .venv/bin/python -m pip install --no-deps -e .
   ```

   Alternatively, run the installer again: it keeps `config.yaml`, the database and the admin password, and
   registers the task again (use `-NoService` on Windows to skip that step).
5. Start the gateway and run `goose-web check`.
6. Ask users to reload the page (a hard refresh if the old UI still shows, see [TROUBLESHOOTING.md](TROUBLESHOOTING.md)).

Database schema changes are applied automatically when the gateway (or a console command) opens the database. The
migrations only add nullable columns and indexes and never rename or drop anything; the version is kept in the
`meta` table (`schema_version`, currently 2). Keep the pre-upgrade database backup as your rollback path.

### 20.2 Updating Goose (native)

Update the goose CLI or Goose Desktop as usual. Workers use the new binary the next time they start: restart them in
Admin > System, or restart the gateway (the goose version shown in Admin > System is read at gateway start).
`goose.binary` pins a specific binary; when it is empty the gateway uses `goose` on `PATH`, then the usual install
locations.

### 20.3 Docker

The image is built locally from the repository. To upgrade goose-web, update the repository and rebuild:

```bash
docker compose -f docker/compose.yaml up -d --build
```

To change the bundled goose CLI, set `GOOSE_VERSION` and both checksums together - `GOOSE_SHA256_AMD64` and
`GOOSE_SHA256_ARM64` in `docker/Dockerfile`, and the `GOOSE_VERSION` build argument in `docker/compose.yaml` - then
rebuild. A checksum mismatch fails the build on purpose. The base image is pinned by digest; bump it the same way
(the Dockerfile explains how). The `/data` volume is kept across rebuilds.

## 21. Uninstalling

Windows (elevated PowerShell):

```powershell
powershell -ExecutionPolicy Bypass -File C:\GooseWeb\scripts\uninstall.ps1 -Port 8710
```

This stops and removes the logon task and the firewall rule. The profiles root, the database and the logs are kept,
and the Goose profile is never touched. Delete `C:\Goose_Web_Profiles` and the install folder by hand if you want
everything gone (back up first).

Linux:

```bash
systemctl --user disable --now goose-web
rm ~/.config/systemd/user/goose-web.service
systemctl --user daemon-reload
# then delete the install folder and the profiles root if you no longer need them
```

Docker:

```bash
docker compose -f docker/compose.yaml down        # keeps the goose-web-data volume
docker compose -f docker/compose.yaml down -v     # also deletes the volume and all data
```

## 22. Checklist for a new deployment

1. Pick the installation type (section 2) and install as the normal Goose user, never elevated or as root.
2. Store the initial admin password from the installer output or the container log. Sign in and change it.
3. Run `goose-web check` and fix anything marked `!!`.
4. Set up the reverse proxy with TLS. Set `server.public_url`, add only the proxy to `server.trusted_proxies`, bind
   `server.host` to the interface the proxy uses, and limit the port in the firewall to the proxy. Restart the
   gateway.
5. Open the public URL and confirm sign-in, the WebSocket (the connection indicator shows connected) and a test chat.
6. Enrol two-factor for your admin account, then switch on "Require two-factor for administrators".
7. Configure sign-in methods: LDAP (`ldaps://` or StartTLS, CA file, least-privilege bind account) and/or OIDC
   (`public_url` set, exact redirect URI registered). Keep one local admin as break-glass.
8. Review the **Everyone** team policy and create teams with the permissions, allowed modes, providers, models,
   folders and run limits each group needs.
9. Set the default team, the sign-in lifetime and the branding in Admin > Settings. Consider lowering
   `auth.remember_days`.
10. Add shared providers, extensions, skills and recipes as team items, and shared hints documents.
11. Create user accounts (or let LDAP/OIDC create them) and check one user's experience with a non-admin account.
12. Decide who owns the native profile's scheduler (`goose.native_scheduler`) if Goose Desktop is used on the same
    machine.
13. Set up backups (section 19) and test a restore.
14. Note where the logs are, and add `/healthz` to your monitoring.

## 23. Security hardening checklist

This list follows the code's behaviour; the full reasoning is in
[SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md#6-deployment-hardening-checklist).

| Area | Do this |
|---|---|
| OS account | Run the gateway and every console command as the normal Goose user, not elevated and not root. Keep `server.allow_elevated: false`. On Windows use the logon task with RunLevel Limited. |
| Exposure | Bind `server.host` to one interface; avoid `0.0.0.0` unless the firewall covers every interface. Allow the port only from the reverse proxy. Docker: keep the port published on `127.0.0.1` or reachable only by the proxy. |
| TLS | Terminate TLS at the proxy and set an `https://` `server.public_url` (Secure `__Host-` cookie, HSTS, strict Origins). |
| Proxies | Put only the proxy's own address in `server.trusted_proxies`, and make the proxy overwrite `X-Forwarded-For`. |
| Host and Origin | Keep `server.allowed_hosts` and `server.allowed_origins` empty unless users really use another name or a direct address. |
| Admin accounts | Few admins. Two-factor for all of them, then "Require two-factor for administrators". One local break-glass admin with a strong password stored safely. |
| Sessions | Lower `auth.remember_days` and the sign-in lifetime if devices are shared. Users can revoke sessions in their settings. |
| Directory sign-in | LDAP over `ldaps://` or StartTLS with `caFile` for a private CA, least-privilege bind account, `allowInsecure` off. OIDC with an `https://` issuer, exact redirect URI, and `stripDomain: false` if the identity provider has more than one domain. |
| Policies | Leave `allow_shell`, `config_edit`, `extensions_edit`, `providers_edit` and `notify_webhook` off for ordinary teams. Set `allowed_modes`, `allowed_providers`, `allowed_models`, `allowed_roots` and `max_concurrent_runs`. |
| Shared items | Share extensions and providers only when every member may hold the copied credentials. Import MCP Apps and extensions only from trusted sources. |
| Webhooks | Keep `notify.allow_private_targets: false`. |
| Native profile | Bind at most one admin to it. Restrict its folder's permissions to the gateway user (plus SYSTEM and Administrators on Windows). |
| File permissions | Keep the profiles root private (the installers set this: Windows ACL, `chmod 700` on Linux/macOS). Run the ownership check after any elevated activity on Windows. |
| Host tasks | Set `host_tasks.enabled: false` if admins do not need the view. |
| Peers | Use peer tokens of accounts whose agents admins may see; prefer `https://` peer URLs with certificate checks on. |
| Tokens | Give API tokens an expiry. Disable accounts promptly when people leave (this revokes their sessions and tokens). |
| Supply chain | Install only with `--require-hashes` from `requirements.lock`; in Docker change the goose version only together with its checksums. |
| Backups and logs | Encrypt and restrict backups of the database and profiles; protect the log folder. Review the audit log for `acp.denied`, failed sign-ins and `ws.impersonate`. |
| Verification | Run `goose-web check` after every change. |

## 24. Quick reference

Console commands (`python -m goose_web` or the `goose-web` script in the virtual environment; `--config` goes before
the command):

| Command | Purpose |
|---|---|
| `serve [--host H] [--port P]` | run the gateway (default command); a `--host` value also joins the Host allow-list |
| `init [--admin NAME] [--password PW \| --password-file FILE] [--native-root auto\|fresh\|PATH] [--force]` | create the database, the first admin and the Everyone team |
| `user list` | list users (id, name, role, profile mode, disabled) |
| `user add NAME [--password PW] [--admin]` | create a local user |
| `user reset NAME [--password PW]` | temporary password, forced change, unlock, re-enable, switch to local sign-in, sign out everywhere, revoke API tokens |
| `user reset-totp NAME` | remove the user's two-factor (lost authenticator), unlock, sign out everywhere, revoke API tokens |
| `check` | diagnostics; exit code 1 if something is wrong |
| `version` | print the version |

Admin console tabs: Users, Teams & policy, Hints library, Auth providers, Settings, System, Ownership check, Host
tasks, Audit log, Logs.

Admin REST endpoints (all under `/api/admin/`, admin session or admin API token; details in [API.md](API.md)):
`users`, `users/{id}`, `users/{id}/reset-password`, `users/{id}/reset-totp`, `users/{id}/unlock`,
`users/{id}/provision`, `teams`, `teams/{id}`, `teams/{id}/items`, `teams/{id}/items/{item}`, `library`, `hints`, `hints/{id}`, `auth`, `settings`,
`audit`, `system`, `system/workers/{key}/{restart|stop}`, `ownership`, `hosttasks`, `hosttasks/action`, `logs`.

Health check: `GET /healthz` returns `ok` (exempt from the Host allow-list). It shows that the gateway process
answers; it does not check workers or the database.
