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
`192.168.1.2`, the users `alice` and `bob`, the install folder `C:\GooseWeb`
and the default profiles root `C:\Goose_Web_Profiles`. Replace them with your own values.

## Contents

1. [How the gateway works, in short](#1-how-the-gateway-works-in-short)
2. [Supported platform: Windows only](#2-supported-platform-windows-only)
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
18. [Logs](#18-logs) (18.1 [Forwarding to Splunk or another SIEM](#181-forwarding-logs-to-splunk-universal-forwarder-or-another-siem))
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
  apart, but it is a privacy boundary, not a hard security boundary (see section 11). The Windows sandbox makes the
  operating system enforce the folder boundaries of non-admin users' agents (section 11.6).

## 2. Supported platform: Windows only

Goose Web 1.13 runs on Windows only: Windows 10/11 or Windows Server 2019 and later, with Python 3.11 or later (the
installer prefers `uv` with Python 3.13 when `uv` is available). `goose-web serve` refuses to start on any other
system.

Why: on Windows each isolated non-admin user's agent runs in its own AppContainer (section 11.6), so the operating
system enforces the folder boundaries between users and blocks loopback. Linux and macOS have no equivalent per-user
sandbox in Goose Web yet. There, every team member's agent would run under one shared OS account with full access to
the other profiles, the database and the admin's Goose profile (the accepted risk GW-01, see
[SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md#72-known-risk-one-windows-account-for-all-team-profiles) 7.2).

Linux and macOS support, and the Docker image, may return once Goose Web has a sandbox for them (candidates: Linux
user namespaces with bubblewrap, or one OS account per user; macOS sandbox profiles). Releases up to 1.12.0 in the
git history still contain the Linux/macOS installer and the Docker files, but they are unsupported.

There is one installation type: native, with `scripts\install.ps1` (section 3). Use it on the Windows machine where
Goose Desktop or the goose CLI is already used. The admin is bound to the existing profile in
`%APPDATA%\Block\goose`, so Goose Desktop and the browser see the same chats, recipes and settings. You update Goose
yourself. The installer adds a logon task and a firewall rule; the ownership check and the host-task view are in the
admin console. It installs the Python dependencies from the hash-locked `requirements.lock`
(`pip install --require-hashes`) and then goose-web itself with `--no-deps`.

## 3. Installing

### 3.1 Windows

Run the installer as the normal Windows user that uses Goose, from a normal (not elevated) PowerShell in the
repository folder. It refuses to run elevated (exit code 3), because files created by an elevated process become
owned by Administrators and Goose can then no longer manage them.

Get the code with git, so that later upgrades are one command (section 20). The folder you clone into **is** the
installation (the package is installed in editable mode), so pick its final place:

```powershell
git clone https://github.com/GhostNet117/Goose_Web_UI.git C:\GooseWeb
cd C:\GooseWeb
powershell -ExecutionPolicy Bypass -File scripts\install.ps1
```

**Guided setup.** Without `-NonInteractive` the installer asks six questions, each with a detected default, shows a
summary and changes nothing until you confirm:

1. **Goose program** - the folder Goose is installed in (for example `C:\AI\Goose`; for a Goose Desktop install the
   command-line tool in `resources\bin\goose.exe` is used, never the Desktop app itself) or `goose.exe`.
2. **The first administrator's Goose data** - [1] an existing Goose appdata folder (`config\`, `data\`, `state\`;
   Goose Desktop's is `%APPDATA%\Block\goose`, or `GOOSE_PATH_ROOT` if set), shown with the number of chats it holds,
   or [2] **start fresh** in a new, empty folder (for example `C:\AI\Goose_appdata`). If your chat sessions live in
   another folder, give it: Goose only reads sessions from `<appdata>\data\sessions`, so the installer links that
   folder there (a directory junction; refused if `data\sessions` already holds sessions - move them first).
3. **The administrator's Goose Web user name** (default: your Windows user name).
4. **Goose Web's own data folder** (users, teams, per-user profiles; default `C:\Goose_Web_Profiles`).
5. **Which Windows account runs the gateway** - [1] you, starting when you sign in, or [2] a **service account** or
   gMSA, starting at boot without anyone signing in (section 5.1).
6. **Sandbox** non-admin users' agents (default yes; section 11.6).

The same answers can be given as parameters with `-NonInteractive`: `-GooseBinary`, `-GooseAppData` (+ `-Fresh` to
create it), `-SessionsDir`, `-Admin`, `-ProfilesRoot`, `-RunAs`, `-Sandbox on|off`.

Without git, download the release ZIP from GitHub and unpack it to the final folder; upgrades then use
`upgrade.ps1 -NoGit` after you replace the files.

Goose installed somewhere else, or its appdata folder moved (for example Goose in `C:\AI\Goose` and its data in
`C:\AI\Goose_appdata`):

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -GooseBinary C:\AI\Goose\resources\bin\goose.exe `
  -GooseAppData C:\AI\Goose_appdata -ProfilesRoot C:\AI\Goose_Web_Profiles
```

See section 3.2 for what these folders are and how to change them later.

What it does:

1. Creates `.venv` in the install folder and installs the locked dependencies, then the package (editable, `-e .`).
2. Finds the Goose profile: `-GooseAppData` if given, otherwise the folder in the `GOOSE_PATH_ROOT` environment
   variable if it has a `config` subfolder, otherwise `%APPDATA%\Block\goose` if it has a `config` subfolder,
   otherwise it asks. An empty answer (or `-GooseAppData fresh`) creates a fresh profile in
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

### 3.2 Custom Goose folders (program and appdata)

Two Goose folders matter, and both can live anywhere:

| Folder | What it is | Default | How to point goose-web at it |
|---|---|---|---|
| Goose program | the `goose` CLI (`goose.exe`; Goose Desktop ships it in `resources\bin\`) | auto-detected: `goose` on `PATH`, `%LOCALAPPDATA%\Programs\Goose\resources\bin`, `%ProgramFiles%\Goose\resources\bin`, `%USERPROFILE%\.local\bin` | `install.ps1 -GooseBinary <path>` (also on a re-run: it sets `goose.binary` and keeps the rest of `config.yaml`), or edit `goose.binary` in `config.yaml` and restart |
| Goose appdata ("native profile") | Goose's `config\`, `data\`, `state\`: settings, providers, extensions, secrets, chats | `%APPDATA%\Block\goose` | `install.ps1 -GooseAppData <folder>` (or set `GOOSE_PATH_ROOT` before installing); later: `goose-web native-root <folder>` and restart the gateway |

`goose-web native-root` (no argument) shows the current folder. With a folder it checks that `<folder>\config`
exists, stores it, moves every native user that used the old folder to the new one and writes an audit entry
(`system.native_root`). It does not copy any files: move or copy the Goose appdata yourself first, with Goose
Desktop and the gateway stopped.

Goose itself finds a moved appdata folder through the user environment variable `GOOSE_PATH_ROOT`. Set it for the
Windows account so that Goose Desktop and the goose CLI use the same folder as the gateway:

```powershell
[Environment]::SetEnvironmentVariable('GOOSE_PATH_ROOT', 'C:\AI\Goose_appdata', 'User')   # then sign out and in
```

The gateway passes `GOOSE_PATH_ROOT` to the native worker itself, so it works even without that variable. Isolated
web users never use the native profile; their profiles are below the profiles root.

## 4. First start and the initial admin password

There is no default password. `goose-web init` creates the first admin:

- user name: `--admin`, otherwise the current OS user (`%USERNAME%`), otherwise `admin`
- sign-in: local password, role `admin`, profile mode `native` (bound to the folder chosen by `--native-root`)
- password: a random 20-character password, printed once in a framed block. Only its hash is stored.
- the change of this password is enforced at the first sign-in (`must_change_pw`); until then the account can do
  nothing else (API calls return `403 password_change_required`, the WebSocket is refused)
- a team called **Everyone** is created and made the default team for new users. Like every new team it starts
  with nothing allowed: choose its providers, models and approval modes before its members can chat (section 9)

The installer keeps the output of `init` and prints it at the end.

To preset the password instead of generating one:

| Method | Example |
|---|---|
| `--password-file FILE` | `python -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml init --admin alice --password-file C:\secure\initial.txt` (first line of the file; trailing CR/LF removed) |
| `--password-file -` | read the first line from stdin, so the password never appears on a command line |
| `--password PW` | possible, but the password is then visible in the process list and shell history |

A preset password that does not meet the password rules only produces a warning, because it must be changed at
first sign-in anyway.

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
fine). It stops when the user signs out. `goose-web check` shows the task (`[OK] autostart task: ...`), or
`[--] ... none registered` when it is missing; the installer registers it, a re-run of the installer keeps an
existing one (`-Reregister` registers it again), and `upgrade.ps1` never changes it.

#### Running as a service account (start at boot, nobody signed in)

Choose [2] in the installer's question 5, or pass `-RunAs DOMAIN\svc-goose` (a normal account; use one that is **not**
an administrator) or `-RunAs DOMAIN\gmsa-goose$` (a group managed service account). Then:

- `register-service.ps1 -Mode Service` registers the task with an **at startup** trigger and the logon type
  "run whether the user is logged on or not", RunLevel Limited. For a normal account it asks for the password in a
  secure prompt in the elevated window (Windows stores it for the task; it is never written to a file); a gMSA needs
  no password. Task Scheduler gives the account "Log on as a batch job"; a domain policy may have to allow it.
  `register-service.ps1 -DryRun ...` shows what would be registered.
- The installer grants the account what it needs: full control of Goose Web's data folder; Read & execute on the
  install folder, the virtualenv's Python and the Goose program folder; Modify on the first administrator's Goose
  appdata folder and a linked sessions folder. Put the install folder outside any user profile (for example
  `C:\AI\Goose_Web`). Python and Goose installed per user (in a user profile) work only if that grant succeeds;
  installs under `C:\Program Files` are readable anyway.
- You sign in to Goose Web with the administrator's **Goose Web** account; the Windows account only runs the
  processes. Goose Desktop (under your own Windows account) and the gateway (under the service account) can share
  the same Goose appdata folder.
- Provider keys that Goose stored in **your** Windows Credential Manager are not visible to the service account:
  enter them again in Goose Web (Settings > Providers) - they then go to the service account's store.
- `upgrade.ps1` is run by you (not the service account); stopping and starting a task that runs as another account
  usually needs administrator rights, so the upgrade asks once (UAC) at the restart step.
- Every program the agents depend on (for example a local model proxy) must also run without a signed-in user.

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

### 5.2 What happens at start and stop

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

Goose Web can serve HTTPS itself, or leave TLS to a reverse proxy. Choose in **Admin > System > HTTPS** (stored in
the database, wins over the file) or with `server.tls` in `config.yaml`; a change applies when the gateway restarts.

| Mode | What it does |
|---|---|
| `auto` (default) | `self-signed`, unless `server.public_url` is set: then a proxy in front terminates TLS and the gateway speaks plain HTTP (`off`). |
| `self-signed` | **Built-in certificate.** Goose Web creates its own local certificate authority (`<system_dir>/tls/ca.crt`, 10 years) and a server certificate signed by it (90 days) for every name and address of the machine: `localhost`, `127.0.0.1`, `::1`, the host name and FQDN, the machine's IP addresses, the bind address, the `public_url` host, `server.allowed_hosts` and `server.tls_names`. The gateway renews it by itself 30 days before it expires and whenever a new name or address appears (checked every `logs.check_minutes`), and loads the new certificate without a restart. |
| `files` | Your own certificate and key in PEM format (`server.tls_cert_file`, `server.tls_key_file`), for example from a company CA. Replace the files and restart to renew. |
| `off` | Plain HTTP. Use it behind a reverse proxy (Caddy, nginx, IIS) that terminates TLS (6.2). |

**Trusting the built-in certificate.** Browsers warn about it until the local CA is trusted. On the gateway machine,
`goose-web tls trust` adds it to the current user's trusted roots (Windows asks once to confirm; `install.ps1`
offers this, or pass `-TrustCert`). On other computers, download the CA from **Admin > System > HTTPS** or from
`https://<host>:<port>/tls/ca.crt`, compare its SHA-256 fingerprint with the one shown there or by
`goose-web tls status`, and import it as a trusted root (Windows: open the file > Install certificate > Trusted Root
Certification Authorities; macOS: Keychain Access, "Always Trust"; Linux: `/usr/local/share/ca-certificates` +
`update-ca-certificates`; Firefox uses its own store unless `security.enterprise_roots.enabled` is on). Renewals do
not change the CA, so a client trusts every later certificate too. The CA key (`ca.key`) never leaves the
`_system` folder; anyone who can read that folder could issue certificates trusted by those clients, so keep its
permissions as tight as the database's.

Commands: `goose-web tls status` (mode, certificate, names, fingerprints), `goose-web tls renew` (new server
certificate now; the running gateway picks it up at its next check, or use **Renew certificate now** in the admin
page, which loads it at once), `goose-web tls export-ca FILE`, `goose-web tls trust`.

With HTTPS on (built-in or files), the session cookie is the `Secure` `__Host-gw` cookie; HSTS is sent only when
`public_url` is an `https://` URL. Plain `http://` to the port no longer answers: update bookmarks, monitoring and
health checks (`scripts\upgrade.ps1` tries `https` first).

Behind a reverse proxy:

- Use a certificate that browsers trust; the PWA and service worker need a secure context (HTTPS, or
  `http://localhost`).
- Set `public_url` to an `https://` URL only when TLS is permanent for that host name: browsers remember the HSTS
  header for one year.
- With an `https://` public URL the cookie is `Secure`, so signing in over plain `http://` under another address
  does not keep you signed in. Use the public URL.
- If the proxy should talk HTTPS to the gateway as well, keep the built-in certificate and give the proxy the CA
  (for example Caddy `transport http { tls_trust_pool file <ca.crt> }`), or set `server.tls: off` and keep the hop on
  a trusted network.

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
| `user` | what the policy of their one team and their overrides allow (section 9), inside their workspace, their team folder and the team's extra folders. A user without a team can sign in and read old chats, but cannot chat. |

Keep the number of admins low. At least one enabled admin must remain: you cannot delete the last admin, delete or
disable your own account, or remove your own admin role. The admin with the native profile cannot be changed to
`user` ("The native profile belongs to an administrator").

### 7.2 Creating accounts

| Where | How |
|---|---|
| Admin > Users > New user | user name, display name, e-mail, role, sign-in source (Local password, LDAP / AD, OIDC / SSO), profile mode, initial password, team (one per user), extra hints documents. If no password is given for a local account, a temporary password is generated and shown once. A password typed here (or generated) must always be changed by the user at the first sign-in. The Team select starts at the default team; choose "No team (can sign in, cannot chat)" to create a user without one. The isolated profile is created right away. |
| Console | `python -m goose_web --config <config> user add bob` creates a local user with a temporary password (printed) and a forced change, and adds it to the default team. `--admin` makes it an admin, `--password` sets the password. The profile is created at the first sign-in. |
| LDAP | users are created at their first successful directory sign-in when "autoCreate" is on (section 7.4) |
| OIDC | users are created at their first sign-in when "Create users automatically" is on (section 7.5) |

User names: letters, digits, `.`, `_` and `-`, starting with a letter or digit, up to 64 characters. Windows device
names and the reserved names `appdata`, `workspace`, `_system`, `_deleted`, `_teams`, `library`, `backups` and
`logs` are refused, because the user name becomes the profile folder name (`_teams` holds the team folders).

Password rules (strong passwords, enforced by the server for every new password: own change, admin create and
edit, `init` warns):

- at least 12 characters (`auth.min_password_length`, default 12, can raise this but never lower it below 12);
- at least one lower-case letter, one upper-case letter, one number and one symbol (a space counts as a symbol);
- must not contain the user name (user names of 3 or more characters);
- not a common password, and not a common word with digits or symbols added at the start or end or simple letter
  swaps (for example `P@ssw0rd123!`, `Summer2026!`, `Welcome-2026#` are refused);
- no character repeated 4 or more times in a row.

Passwords are stored as scrypt hashes. A local account whose existing password does not meet these rules (set before
version 1.3.0) is asked to change it at its next successful sign-in (audit `auth.password.weak`). Changing the
password ends the user's other sessions and revokes their API tokens, as every password change does.

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
  profile, role `admin` if the user is in the admin group (otherwise `user`), and the team of the first mapped
  group, or the default team when no group maps.
- Every later sign-in updates role, display name and e-mail from the directory (the native-profile admin is never
  demoted). When a group maps to a team, that team replaces the user's previous team (one team per user). If
  several mapped groups match, the first one wins and the audit log records `user.team.directory`. When no group
  maps, an existing user keeps their team.
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
- The user name comes from `preferred_username`, else `email`, else `sub`. New providers keep the domain part
  (`stripDomain` defaults to off since 1.12; providers saved before keep their setting). Characters other than
  letters, digits, `.`, `_` and `-` become `-`.
- The account is bound to the stable issuer + subject pair of its first sign-in. Later sign-ins must come from the
  same identity. A different identity for the same user name gets `oidc_conflict`, and a local or LDAP account with
  that name is never taken over.
- An existing account that is not bound yet (pre-created, or from an older version) is bound only when the identity
  provider reports a **verified** e-mail (`email_verified: true`) equal to the account's e-mail. Otherwise sign-in is
  refused with `oidc_unlinked` ("ask an administrator to link the account"): give the account its e-mail address in
  Admin > Users first. A matching user name alone is never enough (1.12).
- The sign-in is tied to the browser that started it (a short-lived `gw_oidc` cookie): a link to the callback
  opened in another browser fails with `oidc_browser`.
- Accounts with two-factor enabled must enter their code after the identity provider (a short server page) since
  1.12.
- To pre-create a user, add it in Admin > Users with sign-in "OIDC / SSO", the expected user name **and its e-mail
  address**; the first sign-in with that verified e-mail binds it.
- Role and team claims are applied at every sign-in (the native-profile admin is never demoted). A matching team
  replaces the user's previous team; if several team names match, the first one wins (audit
  `user.team.directory`). Without a match an existing user keeps their team, and a new user joins the default
  team.

### 7.6 Disabling, unlocking, resetting and deleting

| Task | Admin UI (Admin > Users > actions menu) | Console |
|---|---|---|
| Disable or enable | "Disable account" / "Enable account". Disabling ends every session and revokes every API token of the user. A disabled user cannot sign in (the sign-in page says "Invalid username or password") and their worker is not started at gateway start. | none |
| Unlock after failed sign-ins | "Unlock" (clears the failure counter and the lock) | `user reset NAME` also unlocks |
| Reset password | "Reset password" (local accounts only): shows a temporary password once, forces a change, ends all sessions, revokes all API tokens, unlocks | `user reset NAME [--password PW]`: same effect, prints the temporary password, also re-enables a disabled account and switches the account to local sign-in |
| Reset two-factor (lost authenticator) | "Reset two-factor" (only for users with the "2FA" badge, never your own account): removes the two-factor enrolment, unlocks, ends all sessions, revokes all API tokens. The user signs in with the password and enrols again (section 7.8) | `user reset-totp NAME`: same effect |
| Set a password | Edit > password field (admin API `PATCH`): the user must always change it at the next sign-in; ends sessions and revokes tokens | none |
| Re-provision the profile | "Re-provision profile": applies the team, hints and policy again and lists the changes | none |
| Delete | "Delete...": stops the worker and removes the account. The isolated profile folder is moved to `<profiles_root>/_deleted/<user>-<timestamp>`, or deleted permanently if you tick the box. The native profile is never moved or deleted. | none |

Console commands work on the database directly. Run them on the gateway host, as the same OS account as the
gateway (not elevated), and with the same `--config`:

```powershell
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml user list
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml user reset bob
```

### 7.7 Sign-in protection and sessions

| Mechanism | Behaviour |
|---|---|
| Rate limit | at most 40 sign-in attempts per 5 minutes per client IP and 10 per 5 minutes per IP and user name (`429`, in memory, cleared by a gateway restart) |
| Lockout | after `auth.lockout_threshold` (8) failed factors - wrong passwords and wrong or replayed TOTP codes both count - the account is locked for `auth.lockout_minutes` (15) (`423`, also with the right password) |
| Address block | after `auth.ip_block_threshold` (10) failed sign-ins in a row from one client address within `auth.ip_block_window_days` (30), that address is blocked for `auth.ip_block_days` (30; `0` = until an admin unblocks it). Stored in the database, so it survives restarts. See section 7.9. |
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
  their two-factor off, and **an admin without two-factor can do nothing but enrol** (since 1.12): after signing in
  they see a "Set up two-factor sign-in" screen, and every other API call, API token and the WebSocket answer
  `403 totp_enrolment_required` until they have enrolled.
- Turning two-factor off always asks for proof: the password (local accounts and LDAP) or a current code (OIDC
  accounts).
- **Lost authenticator.** Admin > Users > actions menu > "Reset two-factor" (or `user reset-totp NAME` on the
  gateway host, or `POST /api/admin/users/{id}/reset-totp`) removes the user's two-factor, clears the lock, ends
  all of their sessions and revokes their API tokens. It is audited as `user.totp.reset`. The user signs in with
  the password alone and enrols a new authenticator. The admin console does not offer it for your own account
  (`400 self`): turn your own two-factor off in your account settings, or have another admin reset it. Resetting
  another admin while "Require two-factor for administrators" is on is allowed; that admin is then reported as
  `totpEnrolmentRequired` until they enrol again. Step by step: [TROUBLESHOOTING.md](TROUBLESHOOTING.md#lost-authenticator).

### 7.9 Blocked addresses (failed sign-ins)

Every failed password sign-in counts against the client address: wrong password, unknown user name, disabled
account, local sign-in turned off, locked account, wrong or replayed two-factor code. Not counted: the "enter your
code" step, rate-limited attempts, empty forms and the LDAP-misconfiguration refusal. A successful sign-in from the
address clears its count, so only failures in a row count.

| Setting | Default | Meaning |
|---|---|---|
| `auth.ip_block_threshold` | `10` | failures in a row that block the address; `0` turns blocking off |
| `auth.ip_block_window_days` | `30` | only failures from the last N days count |
| `auth.ip_block_days` | `30` | how long a block lasts; `0` = until an administrator unblocks it |
| `auth.ip_block_exempt` | `[]` | addresses or networks (CIDR) that are never counted or blocked |

- A blocked address gets `403` on every page and API call (`{"error": "ip_blocked"}` under `/api/`) and its
  WebSocket is refused, also for users who are already signed in from it. `GET /healthz` stays open. The sign-in that
  reaches the limit already answers `403 ip_blocked`, and the sign-in page explains it.
- The address is the client IP the gateway sees: the rightmost `X-Forwarded-For` entry when the request comes from a
  trusted proxy, otherwise the peer address. IPv6 addresses are counted and blocked per /64 network. The trusted
  proxies themselves (`server.trusted_proxies`) are never blocked, because that would lock out every user behind
  the proxy.
- Several users behind one NAT share an address: one person's failures count for all of them. Put such an office
  network in `auth.ip_block_exempt` if that is a problem (the per-account lockout still applies).
- **Admin > Blocked addresses** lists blocked addresses and addresses that are collecting failures (count, last user
  name tried, last failure, blocked until), with **Unblock** / **Clear** per row and **Unblock all**.
- Console (works while the gateway runs; it picks up the change within 15 seconds):

```powershell
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml ip list
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml ip unblock 203.0.113.7
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml ip unblock --all
```

- Audit: `auth.ip.blocked` (address, last user name tried, count, end of the block) and `auth.ip.unblocked`.

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

Teams are managed in **Admin > Teams & policy**. A team has a name, a description, members, a policy, team hints, a
team folder and library items. Since version 1.5.0 the team decides a member's whole experience, and policies follow
least privilege: nothing is allowed until you allow it.

### 9.1 One team per user

- Each user belongs to one team at most (the database enforces this with a unique index on
  `team_members(user_id)`).
- Ticking a user in a team's **Members** list moves them out of their previous team. The list shows "now in ... (moves here)" next to such
  users; after saving, a message lists who moved, and the `team.update` audit
  entry records them under `moved`.
- In **Admin > Users** the **Team** column shows each user's team, or a "no team" badge. The edit dialog has a
  single **Team** select; "No team (can sign in, cannot chat)" removes the membership.
- A user without a team can sign in, browse and read their old chats, but cannot chat: new chats, forks and
  prompts are refused with "You are not in a team yet, so you cannot chat. Ask your administrator to add you to a
  team." The home page shows the same text as a banner.
- Directory sign-ins set the team from the group or claim mapping (sections 7.4 and 7.5).
- Admins are never restricted, whatever their team.

### 9.2 The default team

`init` creates the team **Everyone** and makes it the default team. Users created in the admin UI (the Team select
starts at the default team), users created with `user add`, and new LDAP/OIDC users without a mapped team join it.
Change it in Admin > Settings > "Default team for new users". If you delete the default team, choose another
default (or none) in Admin > Settings.

On a new install **Everyone**, like every new team, starts with every switch off and nothing allowed. Allow its
providers, models and approval modes before its members can chat.

### 9.3 The team's Experience page

Selecting a team shows its name and description, its warnings, the **Members** list, and an **Experience** section
grouped by topic:

| Group | What you set there |
|---|---|
| Hints | **Team hints** (documents from the Hints library) and "Members may add personal hints" (`hints_edit`) |
| Providers & models | **Allowed providers** and **Allowed models**, picked from lists (1.12): the providers your own Goose knows (configured ones first, "Show all" for the rest) and, per allowed provider, its models with their context size and All/None buttons; each list has an **Any** switch, and ids Goose does not list can be added by hand. **Default provider** and **Default model** are drop-downs of what is allowed. "Edit providers & models" (`providers_edit`), provider library items |
| Approval modes | **Allowed approval modes**: Auto, Approve, Smart approve, Chat only, or **Any** |
| Folders | **Team folder**, **Extra folders**, **Max concurrent runs** |
| Extensions & tools | `allow_shell`, `extensions_edit`, `tools_permissions`, `apps`, extension library items |
| Recipes, skills & schedules | `recipes_edit`, `skills_edit`, `schedules`, recipe and skill library items |
| Other | `prompts_edit`, `config_edit`, `notify_webhook` |

The warnings at the top of the team (also returned by `GET /api/admin/teams` as `warnings`) tell you what members
will experience:

| Level | Examples |
|---|---|
| error | "No models allowed: members can't chat." (the same for providers and approval modes). The team list marks such a team "cannot chat". |
| warning | the default provider or model is not in the allowed list; "Shell is on: members' agents can run commands as the gateway's Windows account and read other profiles (known risk)."; raw config editing is on; members can add providers and API keys of their own |
| info | no default model; "No team hints assigned: members get no team instructions."; members may add personal hints; "No members yet." |

### 9.4 Policy settings

Policies apply to non-admins only. A switch that is off grants nothing. For the three chat lists (approval modes,
providers, models) an empty list allows **nothing**, and the **Any** switch stores `"*"`, which allows every value.
A new team starts with every switch off and every list empty.

| Key | UI label | New team | When on (or set), members may |
|---|---|---|---|
| `recipes_edit` | Edit recipes | off | save and delete recipes, create recipe and subrecipe sources. Team recipes cannot be deleted by members. |
| `skills_edit` | Edit skills | off | create, update, delete and import skills, agents and project sources |
| `extensions_edit` | Edit extensions | off | add, remove, enable and disable extensions, and choose extensions for a new session |
| `providers_edit` | Edit providers & models | off | manage custom providers, provider configuration and secrets, default provider/model, local model downloads, onboarding import |
| `schedules` | Manage schedules | off | create, update, delete, pause, resume and run schedules |
| `apps` | Manage apps | off | import and delete MCP Apps, and call tools directly from an app (`tools/call`) |
| `prompts_edit` | Edit system prompts | off | change system prompts |
| `hints_edit` | Members may add personal hints | off | write personal goose hints, which are then included before the team hints (section 10) |
| `tools_permissions` | Set tool permissions | off | change per-tool permission settings |
| `config_edit` | Edit raw config | off | read and write the raw Goose configuration (treat like `allow_shell`) |
| `allow_shell` | Allow shell / stdio extensions | off | use command-running extensions (`developer`, `computercontroller`, `code_execution`, `orchestrator`), stdio MCP extensions, per-session MCP servers and direct shell tool calls. See the known risk in section 11.3. |
| `notify_webhook` | Notification webhooks | off | set a personal notification webhook |
| `allowed_modes` | Allowed approval modes | nothing | only these Goose modes (`auto`, `approve`, `smart_approve`, `chat`); `*` = any. Empty = members cannot chat. |
| `allowed_providers` | Allowed providers | nothing | only these provider ids; `*` = any. Empty = members cannot chat. |
| `allowed_models` | Allowed models | nothing | only these model ids; `*` = any. Empty = members cannot chat. |
| `allowed_roots` | Extra folders | none | use these folders in addition to their workspace and the team folder (chat folders, file browser, uploads, downloads). Every entry must be an absolute path and `*` is not accepted (`400 bad_folder`). Symlinks and junctions are resolved, so a link inside an allowed folder cannot lead outside. |
| `max_concurrent_runs` | Max concurrent runs | 3 | have at most this many agents running at once. Empty = the default (3), `0` = unlimited. |
| `default_provider`, `default_model` | Default provider, Default model | not set | the provider and model new members start with (section 9.6). Both should be in the allowed lists; the page warns if they are not. |
| `share_folder` | Team folder | empty = `<profiles_root>\_teams\<team id>` | the team's shared folder (section 9.7). Must be an absolute path (`400 bad_folder`). |

Chat checks for non-admins:

- A user whose team allows no providers, no models or no approval modes cannot chat ("Your team allows no models,
  so you cannot chat. Ask your administrator.").
- A prompt in an existing chat is refused when that chat's current provider, model or approval mode is not allowed,
  for example after the team narrowed its lists: "this chat uses the model 'example-model', which your team does
  not allow. Pick an allowed model for this chat first." The user picks an allowed value in the chat header.
- Choosing a mode, provider or model in a chat, `config/upsert` of `GOOSE_PROVIDER`, `GOOSE_MODEL` or `GOOSE_MODE`
  (with `config_edit`), and `defaults/save` (with `providers_edit`) are checked against the lists.
- `config/upsert` and `config/remove` of `CONTEXT_FILE_NAMES` are refused for every non-admin, with or without
  `config_edit`, because Goose Web manages that key (section 10).

Every ACP method that is not explicitly allowed is denied for non-admins, so a new Goose release cannot open new
functions by itself. Denials are returned as `forbidden: <reason>` and recorded in the audit log as `acp.denied`.

Two rules apply to everyone, admins included: an MCP App's direct tool call may only use tools of the extension it
names, and `session/new` is always tagged with the client name `goose-web`.

### 9.5 How the effective policy is built

| Situation | Effective policy |
|---|---|
| user is an admin | everything allowed, no lists, no run limit; the team and overrides are ignored |
| user without a team | nothing allowed, and chatting is blocked |
| user in a team | the team's policy laid over the least-privilege base (every switch off, every list empty, 3 runs) |
| per-user overrides | applied last; each key in the override replaces the team's value |

There is no merging of several teams any more: a user has one team, and that team's policy applies.

Per-user overrides are set in Admin > Users > Edit > "Policy overrides (advanced)" as a JSON object, for example:

```json
{ "allow_shell": false, "allowed_modes": ["approve"], "max_concurrent_runs": 1 }
```

In overrides too, an empty list allows nothing and `["*"]` allows everything. Only known policy keys are kept. An
empty field removes all overrides.

### 9.6 The team default model, and what a policy change does to a profile

Saving a team (policy, members or hints), changing a user's team, hints or overrides, or adding or removing a team
item re-provisions the affected isolated profiles, including users who were moved out of another team:

- shell extensions are disabled in the profile's `config.yaml` when `allow_shell` is off
- team items are written, updated or removed
- the team folder is created if it does not exist yet
- the team default model: a new member's profile gets the team's `default_provider` and `default_model` (when they
  are allowed). When you change the team default, members whose profile still uses the previous default follow
  the new one; members who picked another model keep their choice
- if the profile's provider is no longer allowed, it is reset to the team default, or else to the first provider
  listed explicitly in `allowed_providers`; a model that is no longer allowed is reset to the default model, or
  removed so that the provider's default applies
- if the profile's mode is not allowed, it is set to `approve` when that is allowed, otherwise to the first allowed
  mode
- the composed hints file `config/.goose-web-hints.md` is rewritten (section 10)

When something changed while the user's worker is running, the worker is marked "restart pending" and restarts
when it has no active runs and no open questions. Policy checks on ACP calls use the new policy at the next
WebSocket connection of the user.

### 9.7 The team folder

- Every team has a shared folder: by default `<profiles_root>\_teams\<team id>` (for example
  `C:\Goose_Web_Profiles\_teams\3`), or the absolute path in the team's **Team folder** field, for example a share
  such as `D:\Shares\Risk`. A relative path is refused (`400 bad_folder`).
- The folder is created when a member's profile is provisioned or when a member connects.
- Members can use it as a chat folder and in the file browser, where it is labelled **Team:** and the team name, next to their
  own Workspace and the team's extra folders.
- `_teams` is a reserved user name, so no profile folder can take its place.
- Deleting a team keeps its folder on disk. The team's members are left without a team (and cannot chat) until you
  add them to another team.
- The folder is protected by the gateway's checks, not by Windows permissions: see the known risk in section 11.3.
- **Goose plugins (since 1.13.1).** Goose loads every folder under `<chat folder>\.agents\plugins` as a plugin when
  a chat starts there and runs the plugin's MCP servers, which are commands; Goose has no setting to turn this off.
  So non-admins cannot create or upload into any folder named `.agents` through the file browser
  (`403 agents_folder_refused`), and cannot save project skills or agents (`sources/create`, *project* scope) anywhere
  but their own workspace (since 1.15.1). A plugin runs as the person who starts the chat, so since 1.15.1 no member
  can start a chat in the **team folder or the team's extra folders** while their `.agents\plugins` holds a plugin,
  with or without `allow_shell` ("this shared folder has Goose plugins"); in their own workspace a member needs
  `allow_shell`. Members with `allow_shell` can still create `.agents` with their shell. An **administrator** who
  starts a chat in a folder members can write (the profiles root, any team folder or extra folder) that holds plugins
  sees the list and must confirm it ("Run the Goose plugins in this folder?", audited `chat.plugins_allowed`); a
  confirmed chat runs them unsandboxed. Remove plugins you did not put there (SECURITY-ASSESSMENT 10 and 12).

### 9.8 Upgrading from 1.4: the policy migration

The first start of 1.5.0 converts the database once (schema version 4, `meta` key `policy_model` = 2), so that
existing teams keep behaving as before:

- every team's stored policy is completed with the 1.4 defaults (recipes, skills, schedules, apps, personal hints
  and tool permissions on; everything else off), and its empty approval mode, provider and model lists, which meant
  "unrestricted" in 1.4, become `["*"]` (Any);
- empty approval mode, provider and model lists in per-user overrides become `["*"]` as well;
- a user who was in several teams keeps only the team with the lowest id; each dropped membership is recorded in the
  audit log as `team.migrate.membership`;
- the unique index that allows one team per user is created.

Back up the database before the upgrade (section 19). Afterwards, review every team on its Experience page: replace
"Any" with explicit lists where you can, switch off "Members may add personal hints" where team hints must be
final, and check the users whose membership was dropped.

### 9.9 Team library items

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

### 9.8 Prompt guard (since 1.14.0)

The prompt guard stops forbidden or injected instructions from reaching the tools of a team. It is **off for every
team** until you turn it on, and existing teams are not changed by the upgrade. It inspects two things and nothing
else (it never inspects what a tool returns, for example a web page):

- **what a guarded user types** (`session/prompt`), before Goose sees it;
- **the arguments of a tool call** Goose asks permission for (`session/request_permission`), before the tool runs.

Two checks run, in this order:

1. **Rule sets** - deterministic rules, edited in **Admin > Prompt guard** (stored in the database). A rule names the
   tools it applies to (`<extension>__<tool>` glob, case-insensitive, for example `*splunk*` or `*shell*`), the
   arguments it reads (`*` = every text value, nested ones too), how it matches (**pipeline** = SPL command at the
   start of a pipeline segment, outside quotes and inside subsearches; **regex**; **words** = whole words or phrases),
   whether it applies to tool arguments, to what the user types, or both, and the message shown on a block. Every
   rule blocks. Two sets are shipped as editable defaults: **Splunk read-only** (outputlookup, outputcsv, outputtext,
   collect, tscollect, mcollect, meventcollect, sendemail, sendalert, delete, script, run, map, savedsearch,
   dbxoutput, outputtelemetry, and backtick macros) and **Destructive shell** (recursive deletes, format and disk
   tools, shutdown/restart, registry, boot and shadow-copy deletion, force-push / git clean / hard reset). *Reset to
   default* restores one; *Restore defaults* re-creates a deleted one. The **Test** box shows what a rule set would
   do with a tool call or a message (dry run, nothing is audited).
   The rule sets are **best-effort deny lists**: they stop the common forms and the evasions found in the 2026-11-11
   review (flag order, quoting, PowerShell parameter prefixes, `rd /s`, .NET deletes, `+branch` / `:branch` pushes,
   encoded PowerShell, `summaryindex`, `dump`, `dbxquery` writes, `fit ... into`, the Splunk REST API from a shell), not
   every way a shell can express the same action; for a hard guarantee give the account (for example the Splunk
   role) only the rights it needs. A rule's tool may list several globs separated by `|`. Since 1.15.1 rules run in
   two small child processes with a deadline (`guard.rules_timeout_ms`, 1500): a check that takes longer is
   **blocked** (`guard-timeout`), never allowed, and the gateway stays responsive. A regular expression with nested
   unbounded repeats such as `(\w+\s?)*` is refused when you save it; use bounded repeats (`{0,300}`). Argument text
   longer than 200,000 characters for a tool a rule applies to is blocked (`guard-too-long`). Unedited shipped sets
   are upgraded automatically (audited `guard.ruleset.upgrade`); edited ones are left alone (*Reset to default*).
2. **The classifier** - Meta's **Llama Prompt Guard 2 22M**, run locally on the gateway's CPU with ONNX Runtime (no
   GPU, no remote service, no network call at run time). It scores the user's text and the free-text arguments of
   guarded tool calls; at or above `guard.threshold` (0.5) the message or call is blocked. It is loaded on first use
   (or at start-up when a guard is on), text under `guard.min_chars` is not scored, scores are cached, and long text
   is read in windows of `guard.window_tokens` (128) tokens, **every** window (since 1.15.1; before, only the first
   ones and the last one, so the middle of a long text was not inspected). Text longer than `guard.max_input_chars`
   (16,000 characters) or needing more than `guard.max_windows` (48) windows is **not inspected**: a guarded message
   is refused ("too long for the prompt guard to check", before any work is done), and a tool call is never approved
   by Guarded auto - the user decides on the card (audited `guard.not_inspected`). `guard.timeout_ms` is 10,000 since
   1.15.1. The 22M model is mainly accurate for English; the 86M model is never used.

**Per team** (Admin > Teams & policy > *team* > Experience > **Prompt guard**): on/off; *Check what members type*;
*Guarded auto*; the rule sets; *Trusted extensions* (one name per line: their calls skip the rules and the classifier;
every other extension is guarded); and what happens on a block: *drop it and tell the user* (the user sees an error
for a message, or a notice for a tool call) or *drop it silently* (a message ends with no answer). A blocked tool call
is answered "deny once" by the gateway: Goose tells the model the user declined it.

**Approval modes.** The guard sees a tool call only when Goose asks first. Goose does not ask in Auto, and Smart
approve skips tools annotated (or judged) read-only, and a tool set to *Always allow* is never asked about again. So
for a guarded team: Auto and Smart approve are removed from the allowed modes (Any becomes Approve + Chat), members'
profiles are switched to Approve and their stored *always allow* tool permissions are removed (`permission.yaml`,
the worker restarts), the permission card has no *Always allow* button, an *always allow* answer is turned into
*allow once*, and *Set tool permissions* cannot set *always allow*. **Guarded auto** keeps the flow smooth: Goose stays
in Approve and the gateway itself answers *allow once* for every call that passes the guard, so members see no card.
Checked on Goose 1.50.0 and 1.57.0 (same permission logic in both).
Since 1.15.1 (security review 2026-11-11, SA-1) the agent cannot keep a tool out of the guard's sight: every worker
start provisions the member's profile again (the `always allow` entries, extensions, provider, model and mode of the
team policy are restored, whatever the agent wrote into its config files), tool arguments that name the profile's
own config files (`permission.yaml`, `config.yaml`, `secrets.yaml`, the hints file, `custom_providers`) are refused by
the built-in rule `guard-self-protect`, and a tool call that runs without a permission request (an *always allow*
entry, a provider that runs tools itself) cancels the run: audited `guard.bypass`, a notice in the chat and to
administrators, and an isolated member's worker restarts with clean settings. Members see a block's message but not
the rule id; administrators see both. After 10 blocks within 10 minutes a user's guarded requests are refused for the
rest of the window (`guard.burst`, administrators are told). A member cannot add an extension named like one of the
team's *trusted extensions*, and a trusted extension is trusted only while the profile's entry is the one the team
provides. A guarded user's system prompt, saved prompts, recipes, imported chats and MCP Apps tool calls are checked
too.

**Administrators** are not in a team: **Admin > Prompt guard > Administrators** turns a guard on for all of them (rule
sets, message check, on block). An administrator chat in **Auto bypasses** the guard; in **Approve** it gets the same
controls as a guarded team; a **Smart approve** chat is refused while the administrators' guard is on ("use Approve or
Auto"). Tools an administrator set to *always allow* earlier (the native profile's `permission.yaml`, shared with Goose
Desktop) are not changed by Goose Web; since 1.15.1 such a call in an Approve chat cancels the run (`guard.bypass`) -
remove the *always allow* entry, or use Auto for that chat (unguarded).

**Limits.** Scheduled runs have nobody to ask, so their tool calls are not guarded; sub-agents and recipe checks
started through the shell extensions are not seen either (the team page warns about both). Tool results and internet
content are not inspected (they are already in the model's context). Classifiers can be bypassed by adaptive attacks;
the rules are the enforcement for what must never happen.

**Fail open.** If the model is missing, damaged or slower than `guard.timeout_ms`, the message or call is allowed, the
rules still apply, `guard.unavailable` is audited (on each change, then at most every 10 minutes) and administrators
see a banner on every page until it is healthy again (*Check now* on Admin > Prompt guard re-tests it).

**Audit.** `guard.blocked` (user, team, profile, chat, point `prompt`/`tool`, extension and tool, rule set and rule or
classifier score, mode; `guardedUser` when an administrator typed into a member's chat), `guard.bypass`,
`guard.not_inspected`, `guard.burst` and `guard.unavailable` (with the user and chat since 1.15.1) go to the audit log and `activity.jsonl` (section 18.1). The text of
the message or the arguments is never recorded.

**The model.** `goose-web guard status` shows the runtime, the model, the package source and a self-test;
`goose-web guard install-model` installs it into `<system_dir>\models\prompt-guard-2-22m\`; `goose-web check`
reports it. `install.ps1` and `upgrade.ps1` run `guard install-model --if-missing`: it downloads and installs the model
when it is missing and leaves a valid installed model alone. A failed download is a warning, not a failure: the guard
then runs with rules only and fails open for the classifier until the model is installed. Nothing is installed unless
its SHA-256 matches (the pinned package, `guard.model_url` + `guard.model_sha256` in config.yaml, or `--file X.zip
--sha256 HEX` for a package of your own), and every file is checked once more against `export.json` in the package.

**Where the model comes from (since 1.14.2).** Meta publishes the weights on Hugging Face behind a licence
click-through, so Goose Web does not download from there. This project publishes the converted model as the asset of
a dedicated GitHub release, separate from the app versions so that its address never changes:

| | |
|---|---|
| Release | [`prompt-guard-2-22m-onnx-1`](https://github.com/GhostNet117/Goose_Web_UI/releases/tag/prompt-guard-2-22m-onnx-1) |
| File | `https://github.com/GhostNet117/Goose_Web_UI/releases/download/prompt-guard-2-22m-onnx-1/Llama-Prompt-Guard-2-22M-onnx-int8emb-11614a15.zip` |
| SHA-256 | `76d04f9014c82fbf28e51645272c974ca9273ad93512a36b9ef858e4e851eab3` |
| Size | 116,747,849 bytes (about 146 MB unpacked) |
| Contents | Meta's Llama Prompt Guard 2 22M at revision `11614a155199674a0a95e6602d6ab0417b790ed0` as ONNX (word embeddings int8, encoder fp32), Meta's `tokenizer.json` unchanged, `config.json`, `LICENSE`, `USE_POLICY.md`, `NOTICE`, `README.md` ("Built with Llama"), `export.json` (provenance and the SHA-256 of every file) |

Every source file was checked against the SHA-256 of Meta's release before the conversion
(`scripts/export-prompt-guard.py`, `OFFICIAL_FILES`). The pin (URL, SHA-256, size, revision) is `MODEL_PIN` in
`goose_web/guardmodel.py`. The download uses HTTPS only, on every redirect (at most 5; for the pinned package only
`github.com`, `objects.githubusercontent.com` and `release-assets.githubusercontent.com`), honours the standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`), gives up on a
connection that sends no data for 60 seconds, tries three times (waiting 5 and 15 seconds) on network errors and
server errors, prints its progress, and stops if the file is larger than the pinned size.

**Offline install, or a proxy/firewall that blocks the download.** Behind a proxy, set it for the command
(`set HTTPS_PROXY=http://proxy.example:8080` in the same `cmd` window, then run the command again). Without internet
access: download the file above on another computer, check it (`Get-FileHash <zip> -Algorithm SHA256` must show the
SHA-256 above), copy it to the server and run `goose-web guard install-model --file <zip>` (the pinned SHA-256
applies; `--sha256` is only needed for a package of your own), then `goose-web guard status`. An internal mirror of
the zip works too: `guard.model_url` (https) and `guard.model_sha256` in config.yaml (set both).

**Licence.** Built with Llama. Llama Prompt Guard 2 is licensed under the **Llama 4 Community License**, Copyright (c)
Meta Platforms, Inc. All Rights Reserved; its use is subject to that licence and the **Llama 4 Acceptable Use Policy**.
Both are in the package and are installed with the model (`LICENSE`, `USE_POLICY.md`, `NOTICE`); Goose Web's own
Apache-2.0 licence does not cover the model. If you redistribute the package (for example an internal mirror), keep
those files in it and display "Built with Llama" (THIRD-PARTY-NOTICES.md).

**Building a package yourself** (maintainers of a new model revision, or forks that prefer their own build):

1. Get Meta's files, one of three ways (`--source`); whichever you use, the script checks the size and SHA-256 of
   every file against the values of Meta's release pinned in the script (`OFFICIAL_FILES`) and refuses anything else:
   - `meta` (default): on huggingface.co sign in, open `meta-llama/Llama-Prompt-Guard-2-22M`, accept the licence,
     wait for access, create a *read* token and set `HF_TOKEN` to it;
   - `mirror`: the ungated copy `hipocap/Llama-Prompt-Guard-2-22M` at a pinned revision, byte-identical to Meta's
     release (the hashes prove it; no account needed). The Llama 4 Community License applies the same way;
   - `dir --from-dir <folder>`: a folder with the files (for example a copy verified earlier).
2. In a throwaway virtual environment (not the gateway's), install torch (CPU), transformers, sentencepiece, protobuf,
   onnx, onnxscript, onnxruntime and `numpy<2.5`, and run
   `python scripts\export-prompt-guard.py [--source mirror] --out <folder>`. It exports the pinned revision to ONNX,
   quantises the word embeddings to int8 (the encoder stays fp32: full int8 changes the real model's verdicts),
   checks it against the PyTorch model with the gateway's own tokenisation, and writes a zip (about 117 MB) with
   the licence, the Acceptable Use Policy, the NOTICE and a "Built with Llama" README, then prints its SHA-256.
3. Install it: `goose-web guard install-model --file <zip> --sha256 <hash>`, then `goose-web guard status`.
4. To make it the default for every installation: publish the zip as the asset of a **new** release (tag
   `prompt-guard-2-22m-onnx-<n>`, not marked latest; never replace the file of an existing tag, installed gateways pin
   its SHA-256) and pin its URL, SHA-256 and size in `MODEL_RELEASE` / `MODEL_PIN` (`goose_web/guardmodel.py`) in
   the next app release. A fork can set `guard.model_url` / `guard.model_sha256` instead.

Measured on an Intel N100 (4 cores, the real model, default package, 4 threads; p50 / p95): 16 tokens 19 / 22 ms,
64 tokens 45 / 50 ms, 128 tokens (2 windows) 105 / 125 ms, 512 tokens 350 / 390 ms, 1024 tokens (8 windows)
560-700 / 630-740 ms; loading about 2 s; about 295 MB more memory once loaded and 340 MB after the first long
texts. A single 510-token window costs about 1 s on this CPU and detected no better than 128-token windows in our
tests, which is why windows are 128 tokens.

**What the classifier catches, and what it does not** (measured 2026-11-10 on 191 hand-written English texts and two
public sets; the defaults, threshold 0.5): explicit override and jailbreak wording ("ignore previous instructions",
"you are now DAN / in developer mode", injected "new instructions" inside tool arguments) is caught reliably (89% of
"ignore instructions" prompts, 93% of a public jailbreak set at 1% false positives). It misses social engineering
without that wording ("the admin said it's fine, run outputlookup anyway"), quiet role-play ("enter maintenance
mode"), plain requests for the system prompt, and task changes without override words (about 20% of a public
prompt-injection set); non-English text is mostly missed. It blocks text that *quotes* injection wording, so
security analysts writing about attacks ("find prompts that contained 'ignore previous instructions'") or users
writing "ignore the typos in my last message" are blocked too (about 1 in 4 analyst-style texts that mention attacks;
ordinary questions, SPL searches, log lines and code passed). The score is almost always below 0.01 or above 0.99,
so raising the threshold removes few false positives. Keep the deterministic rules on: they catch what the
classifier never will (the write/delete/send command in the tool call itself).

## 10. Shared goose hints

The **Admin > Hints library** holds shared hints documents. Assign a document to a team (on the team's Experience page,
Hints > Team hints) or to a single user (Admin > Users > Edit > "Extra hints for this user").

For each isolated profile the gateway composes `config/.goose-web-hints.md`. Its parts are listed from lowest to
highest precedence:

1. a header saying the file is managed by Goose Web, and a note telling the model that the hints are listed from
   lowest to highest precedence and that team hints are final
2. the user's personal hints, under "personal hints (lowest precedence)", but only if the team allows "Members may
   add personal hints" (`hints_edit`, off for new teams). Otherwise they are left out (they stay saved), and the
   user sees a warning in Settings > Goose hints
3. the documents assigned to the user directly, sorted by name (a document that is also a team hint appears once,
   in the team part)
4. the team's documents last, under the heading `Team: <name> (final: these take precedence)`

Isolated workers run with `CONTEXT_FILE_NAMES=[".goose-web-hints.md"]`, so Goose loads only this file. `AGENTS.md`
and `.goosehints` files in a chat's working folder, and the `AGENTS.md` in the shared agents home folder, are
ignored for isolated profiles. A member therefore cannot override the team hints by placing a hints file in a
folder. In addition:

- non-admins cannot upload, or create with "New folder", anything named `AGENTS.md`, `.goosehints` or
  `.goose-web-hints.md`, in any folder (`403 hint_file_refused`);
- non-admins cannot change or remove `CONTEXT_FILE_NAMES` through the Goose configuration, even with `config_edit`.
  The worker's environment value is set after `goose.extra_env`, so it also wins over the configuration file;
- the `config/.goosehints` file that Goose Web 1.4 composed is removed at the next provisioning if it still starts
  with the Goose Web header. A `.goosehints` that the user wrote is left in place (Goose no longer loads it).

**Admin > Users > actions > View effective hints** shows what the user's Goose loads: the composed text, the file
path, the team, and a warning when the user's personal hints are dropped.

Saving, renaming or deleting a document rewrites the hints of every user it is assigned to immediately; this is
safe while Goose runs. Edits made directly in an isolated profile's `.goose-web-hints.md` file are overwritten.

The native profile is different. By default its `.goosehints` belongs to the admin and is never composed, and
Goose still loads `AGENTS.md` and `.goosehints` from the working folder as usual. The admin edits the file in their
own settings, and the previous file is copied to `<system_dir>/backups/native-hints/` before each save. Shared
documents assigned to a native-profile admin are listed but not written into that file - unless **managed native
hints** are on (section 10.1).

### 10.1 Managed native hints (the admin's hints from the library)

With managed native hints, Goose Web composes the native admin's hints exactly like an isolated user's (personal
hints, then documents assigned to the admin, then the admin's team documents last) and writes them into the native
profile's own `config/.goosehints`. Because that is Goose's normal global hints file, **Goose Desktop, the goose CLI
and scheduled runs on that Windows account load the same text as the web chats**: you manage your hints in one place,
in the browser. Typical setup: an "Admins" team that holds your hints document.

```powershell
cd C:\GooseWeb
.venv\Scripts\python.exe -m goose_web --config <config> native-hints status
# turn it on for the native admin, put them in the team Admins (created if missing) and keep the current
# .goosehints as a document of that team:
.venv\Scripts\python.exe -m goose_web --config <config> native-hints enable <admin> --team Admins --adopt
.venv\Scripts\python.exe -m goose_web --config <config> native-hints disable
```

- `enable` writes the composed text at once; the previous file goes to `<system_dir>/backups/native-hints/`. From
  then on, saving a hints document, a team change, or the admin's personal hints (Settings > Goose hints) rewrites
  the file; it is only written when the text changes. The file starts with a header that says it is managed and that
  direct edits are overwritten.
- `--adopt` turns the current `.goosehints` into a library document named "<admin> goose hints" (`--doc-name` to
  choose), assigned to `--team` or, without it, to the admin directly. Without `--adopt`, the old text is only in the
  backup.
- Administrators are not restricted by team policies, so the Admins team needs no providers or modes for them; a
  non-admin you later put in that team gets nothing until you allow it on the team's Experience page.
- `disable` stops the rewriting; the file keeps its last text and you edit it directly again.
- One native admin per native profile (it is one folder); the setting is `native_hints_owner`.
- Audit: `hints.native.managed`, `hints.native.unmanaged`, and `hints.update` / `hints.personal.save` for edits.
- What Goose still loads in addition (native profile only): `AGENTS.md` and `.goosehints` in the chat's working
  folder up to its git root. Admin > Users > View effective hints shows the managed text and this note.

## 11. Profiles

### 11.1 Isolated profiles (default)

Every non-native user gets `<profiles_root>/<username>/`, which is the `GOOSE_PATH_ROOT` of their worker:

```
<profiles_root>/<username>/
  config/        config.yaml, secrets.yaml, .goose-web-hints.md (composed), custom_providers/, recipes/, skills/
  data/          sessions/sessions.db, logs/        (written by Goose)
  state/                                            (written by Goose)
  workspace/     default folder for new chats
  .goose-web/managed.json                           what the gateway provisioned
```

- The profile is created when the user is created in the admin UI or at their first sign-in.
- The first provisioning copies the base platform extensions (`todo`, `skills`, `apps`, `chatrecall`, `summarize`,
  `extensionmanager`, `analyze`, `memory`, `summon`, `tom`) from the native admin's configuration when they exist
  there and sets `GOOSE_MODE: approve`.
- Members without `allow_shell` never get a command-running extension: `developer`, `computercontroller`,
  `code_execution`, `orchestrator`, `summon` (it runs sub-recipes) and `scheduler` (it runs recipes) are written
  **disabled** (removing them would let Goose turn them on by default), `extensionmanager` is disabled unless the
  team has both `extensions_edit` and `allow_shell` (it can switch a disabled extension back on), and command
  (stdio) extensions from team items are not written at all (their secrets are not copied). Other bundled
  extensions that are not in the base set are written disabled. Granting the permission later restores them.
  The provisioning record is kept in `<system_dir>/manifests/<user id>.json`, outside the user's reach (1.12).
  If the admin's provider is also provided to the user as a team item (and allowed), the admin's provider and model
  become the user's default.
- Isolated workers get `GOOSE_DISABLE_KEYRING=1` (secrets stay in the profile's `secrets.yaml`), a
  `GOOSE_RECIPE_PATH` with only their team recipe folders, and none of the gateway's `GOOSE_*` environment variables
  (except `GOOSE_DISABLE_KEYRING` and `GOOSE_TELEMETRY_ENABLED`). Values in `goose.extra_env` are passed to every
  worker, isolated ones included. Isolated workers also get `CONTEXT_FILE_NAMES=[".goose-web-hints.md"]`
  (section 10), which `extra_env` cannot override.

### 11.2 The native profile

Profile mode `native` binds an admin to an existing Goose profile folder (normally `%APPDATA%\Block\goose`;
on a fresh install `<profiles_root>/appdata`). It is stored as the `native_root` setting.

Implications:

- Goose Desktop, the goose CLI and the browser all work on the same chats, recipes, extensions, providers and
  settings. Changes made elsewhere show up in an open web chat within a few seconds.
- The gateway never provisions the native profile: no team items, no policy, no composed hints. It writes there
  only when the admin saves their own goose hints (after a backup).
- When the folder is Goose's default location, `GOOSE_PATH_ROOT` is not set for the native worker, and the worker
  inherits the gateway's full environment (including any `GOOSE_*` variables and the OS keyring).
- The native admin's default folder for new chats is `goose.default_workdir_native` (default: the home folder),
  and the file browser offers every drive.
- Only admins can have the native profile. Use it for one admin at most: every native user gets the same folder,
  and two workers on one profile would, for example, both run its scheduler. Additional admins should use isolated
  profiles.
- Scheduler ownership must be shared with Goose Desktop (section 13).
- Deleting the native admin never deletes the native profile folder.

### 11.3 Isolation limits

On Windows the limits below about the shared OS account are closed for non-admin users by the sandbox (11.6).

All workers run as the gateway's OS account. A tool that can read files or run commands can reach other profiles,
the database and the native profile. That is why the shell extensions and stdio MCP servers are off for non-admins
unless `allow_shell` is on; grant it only to people you would trust with that OS account. Home-folder skill and
recipe folders such as `~/.agents/skills` and `~/.agents/recipes` are not moved by `GOOSE_PATH_ROOT` and are visible to
all profiles. Admins always have the full power of the OS account.

**Known risk with teams.** Team policies, team folders and the hints rules are enforced by the gateway (over ACP
and in the file endpoints), not by Windows permissions: every isolated worker, of every team, runs under the same
Windows account as the gateway. If a team is given Shell (`allow_shell`), the `developer` extension or stdio
extensions, its members' agents can read other users' profiles and other teams' folders on disk. Keep Shell and
raw config editing (`config_edit`) off for non-admin teams; the Experience page warns when Shell is on. Separate
Windows accounts per team would close this gap; they are not built (possible future work). See
[SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md#7-addendum-goose-web-150-team-profiles-with-least-privilege).

### 11.4 Your own admin account: native or isolated, and moving from Desktop to the browser

| | Native profile (installer default for the first admin) | Isolated profile |
|---|---|---|
| Goose data | your existing Goose folder (`%APPDATA%\Block\goose`, or `GOOSE_PATH_ROOT`; section 3.2) | `<profiles_root>/<username>/` (new, empty) |
| Shared with Goose Desktop / CLI / schedules | yes: same chats, recipes, extensions, providers, settings, schedules | no |
| Hints | the native `.goosehints`; with managed native hints (10.1) composed from the Hints library and your team | composed `.goose-web-hints.md` from the library and your team |
| Policies | none (administrators are unrestricted) | none for administrators |
| Folders | every drive | every drive for administrators |

Recommended for a single person who used Goose Desktop and now wants to work mainly in the browser (no remote
desktop needed): **keep the native profile and turn on managed native hints**:

1. Admin > Teams: create a team for administrators (for example "Admins"), or let the command create it.
2. Run `native-hints enable <you> --team Admins --adopt` (10.1). Your current hints become the document
   "<you> goose hints" on that team, and the native `.goosehints` is now written by Goose Web.
3. Check Admin > Users > View effective hints (or Settings > Goose hints > Effective). Edit the document in
   Admin > Hints from now on; your personal hints (Settings > Goose hints) come first and the team document last.
4. Goose Desktop, if you still open it, uses the same chats and the same hints.

Moving the admin to an isolated profile instead (a clean start, nothing shared with Desktop): create a second admin
account with profile mode Isolated (Admin > Users > New), sign in with it, re-create the providers and extensions
you need in its Settings, and keep or disable the old native account. Chats, recipes and schedules of the native
profile are not copied. Changing an existing account's profile mode is not offered, because it would point the
account at a different set of chats.

Moving the native Goose folder itself (for example to `C:\AI\Goose_appdata`): section 3.2 (`goose-web native-root`).

### 11.5 Goose settings that matter for long chats and slow extensions (Goose 1.55 and later)

Administrators can change any Goose configuration key in **Settings > Advanced config** (written through Goose itself,
in the profile you are signed in to; for isolated profiles each user's own `config.yaml`).

- **Chats compact at about 225k tokens even on 1M-token models.** Goose 1.55 and later compact at
  `min(GOOSE_AUTO_COMPACT_THRESHOLD (0.8), GOOSE_AUTO_COMPACT_TOKEN_LIMIT / context_limit)` of the model's context
  window, and `GOOSE_AUTO_COMPACT_TOKEN_LIMIT` defaults to 225000. Set it to your largest model window (for example
  `1000000`) so every model compacts at 80% of its own window. The value is read at the start of each turn. Do not
  use `GOOSE_CONTEXT_LIMIT` for this: it overrides the window of every model.
- **Extensions missing from new chats ("process quit before initialization").** Goose (every version since 1.50) gives a command (stdio)
  extension 10 seconds to answer its first handshake; slow starters (Python/uv/node servers, several chats starting
  at once) are dropped silently. Make the server start faster, give it a launcher that answers the handshake at once,
  or use a remote (HTTP) extension. Each chat stores the extension commands it was created with, so a changed
  extension command reaches older chats only after removing and re-adding the extension in that chat.
- **"It compacts every few messages" in the browser:** check first whether Goose compacted at all (Goose's log line
  "Performing message compaction"). Before 1.10.0 the transcript showed only the last 80 items and hid older ones
  behind "Show earlier messages", which in tool-heavy chats looked like lost history. Since 1.10.0 it shows the
  last 300 by default (Settings > Preferences > Chat > Messages shown in a chat) and loads earlier ones when you
  scroll to the top.
- **Older chats keep their extension commands.** A chat started before you changed an extension's command keeps the
  old one. Goose Web marks such extensions **outdated** and offers **Refresh extensions** (chat menu or the Session
  extensions dialog): it removes them from the chat and adds the current definition, through Goose.
- **Goose 1.50 to 1.54** have no `GOOSE_AUTO_COMPACT_TOKEN_LIMIT` (11.7).

### 11.6 Sandboxing users' agents (Windows AppContainer)

All workers run as the one OS account the gateway runs as. Goose Web's own file browser keeps users inside their
folders, but an agent's shell, scripts and command (stdio) extensions run as that account and could otherwise read
anything it can: other users' profiles and chats, other teams' folders, the native Goose profile and its secrets, the
gateway's database. On Windows the sandbox (on by default since 1.9.0) makes the operating system enforce the folder
boundaries:

```yaml
sandbox:
  enabled: auto              # default: on; true | false
  network: internet          # none | internet | internet+lan
  read_dirs: []              # extra program folders agents may run, e.g. C:\Program Files\nodejs, a Python install
  relays: []                 # local services sandboxed agents may use, e.g. ["127.0.0.1:8317"] (a local model proxy)
```

What it does, for every **isolated, non-admin** user (administrators and the native profile are never sandboxed):

- The user's worker - `goose acp` and everything it starts: shells, scripts, MCP servers - runs inside the user's own
  Windows **AppContainer** (`GooseWeb.<id>.<username>`; created without administrator rights, same name = same
  security identifier after restarts and upgrades). It is also in the gateway's kill-on-close job object.
- The kernel allows file access only where an ACL grants that container: **Modify** on the user's profile folder
  (workspace included), the team folder and the team's **extra folders** (the team's Experience page > Folders: these
  are the team's *approved folders*), and **Read & execute** on the goose CLI's folder and `sandbox.read_dirs`.
  Everything else is denied - including the gateway's `_system` folder, other users' profiles, the native Goose
  profile (for example `C:\AI\Goose_appdata`) and every other folder on the disk that does not grant access to "ALL
  APPLICATION PACKAGES" (system folders such as `C:\Windows` stay readable, as for any Windows app).
- The gateway talks to the worker over the worker's own stdin/stdout pipes - no network port, no shared secret, no
  loopback exemption, no administrator rights. **Loopback (127.0.0.1) stays closed** for the container, so local
  services (a browser's remote-debugging port, a local model proxy, other workers) cannot be reached from it.
  `network: internet` allows outbound internet (needed for cloud model providers); `internet+lan` also the local
  network; `none` nothing.
- Grants follow changes: adding or removing an extra folder, moving a user to another team, or making a user an
  administrator updates the ACLs at the worker's next start (a running worker restarts when it is idle). Deleting a
  user revokes every grant and deletes the container. The applied grants are recorded in `<system_dir>/sandbox/`.

Requirements and limits:

- Windows 10/11 or Server 2019+ (Goose Web refuses to start on other systems; section 2).
- **Model providers must be reachable over the network** (cloud APIs, or a server elsewhere on the LAN with
  `internet+lan`), or be listed in `sandbox.relays` (below). A container cannot reach this machine's own LAN
  address either, so a service on this machine is reachable only through a relay.
- Programs the agents run must be readable by the container: tools under `C:\Program Files` usually are; per-user
  installs (Python, node, uv in the user profile) must be added to `sandbox.read_dirs`. The workers' temp, uv, pip and
  npm caches live in the user's profile (`tmp\`, `cache\`).
- The Windows Credential Manager is not reachable from a container; isolated profiles already keep their secrets in
  their own `secrets.yaml`.
- Windows file shares (SMB) cannot be limited per container: the file server sees only the shared account. Teams that
  need their own shares need their own account.
- Granting a folder rewrites its ACL (with inheritance to everything below it), once per change; the account the
  gateway runs as must be allowed to change permissions on the approved folders.

Check: `goose-web check` (`[OK] sandbox`), `goose-web sandbox status` (every container, its SID and grants),
Admin > System (the Sandbox column shows **AppContainer** for sandboxed workers). Remove one user's container by hand:
`goose-web sandbox remove <username>` (stop the worker first).

#### Local services for sandboxed users (relays)

A model proxy or another service that listens only on 127.0.0.1 of this machine is out of reach of sandboxed
agents. List the ones they may use:

```yaml
sandbox:
  relays: ["127.0.0.1:8317"]
```

For each sandboxed user and listed service, the gateway starts a small forwarder **inside the user's own
container**. It listens on a loopback address of that user's own (`127.64.x.y`, from the user id) and the same
port, and passes each connection over a named pipe to the gateway, which connects to the real service. The pipe's
ACL admits only that user's container, so another user's agent cannot use it. Only the listed services become
reachable; the rest of 127.0.0.1 stays closed (no loopback exemption).

The user's Goose configuration (`config/config.yaml` and `config/custom_providers/*.json` in their profile) is
rewritten so URLs to the service (`//127.0.0.1:8317`, `//localhost:8317`) point at the forwarder
(`//127.64.x.y:8317`). The rewrite is undone when the service is removed from `sandbox.relays`, when the user stops
being sandboxed (administrator, sandbox off) and by `goose-web sandbox remove`. The forwarder runs on the gateway's
own Python (its base installation is granted Read & execute). Relays take effect at the worker's next start.
`goose-web sandbox status` lists them.

### 11.7 Goose versions (1.50 and later)

Goose Web works with Goose **1.50 or later** and detects the version of each worker when it connects (the
`initialize` answer; `goose-web check` and `install.ps1` report it too). Every release from 1.50.0 to 1.57.0 was
tested end to end (an administrator on `goose serve` and a sandboxed member on `goose acp`: chatting, reopening a chat
after a worker restart, fork, edit and rerun, extensions, tool calls, delete). They behave the same except for the
features below, which arrived in these versions:

| Feature | First Goose version | On older Goose, Goose Web ... |
|---|---|---|
| Direct tool calls (`tools/call`) honour `extensionName` | 1.51 | checks the tool against the named extension (`tools/list`) and refuses a mismatch; it does this on every version |
| Custom provider "Tool shim" option | 1.51 | hides the checkbox |
| Live voice (`session/live-voice/*`) | 1.52 | refuses it with a clear message |
| Importing a chat (`session/import`) without `source` | 1.54 | sends `source: json` |
| Per-chat system prompt (chat menu > System prompt) kept when the worker restarts | 1.55 | re-applies it when the chat is opened again (kept by the gateway; lost when the gateway itself restarts - the dialog says so) |
| `GOOSE_AUTO_COMPACT_TOKEN_LIMIT` and its 225k default cap (11.5) | 1.55 | nothing to do: older Goose compacts at `GOOSE_AUTO_COMPACT_THRESHOLD` (0.8) x the model's window |

Extension start-up (the 10-second handshake limit in 11.5) behaves the same in all of them. Install and upgrade are
the same for every version: point `goose.binary` (or `install.ps1 -GooseBinary`) at the goose CLI you use.

After upgrading Goose, run `goose-web check`, open a chat and check that its extensions load. If an upgrade changes
Goose's compaction or extension start-up behaviour, revisit the settings in 11.5.

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
| Pending restart | after a profile change (section 9.6) or a scheduler hand-over (section 13), when no run is active |
| Stop by admin | Admin > System > Stop: in-flight calls fail with "stopped by an administrator"; the worker starts again when the user connects |
| Restart by admin | Admin > System > Restart: active runs are interrupted (the UI asks for confirmation) |
| Process tree | stopping a worker also stops its MCP server processes (`taskkill /T`) |
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

- In `auto` mode the gateway checks for Goose Desktop.
  When Desktop starts or stops, the native worker is restarted once no run is active, which hands the scheduler
  over. If detection fails, the gateway assumes Desktop is running, so jobs never fire twice.
- A worker whose profile has jobs in `data/schedule.json` and that owns its scheduler is started even when nobody is
  connected, is never stopped for idleness, and is restarted after a crash.
- When the gateway does not own the scheduler, the Schedules page shows "The scheduler is not active in this Goose
  Web instance" with the reason, and schedules are read-only there.
- The gateway must be running for schedules to fire. With the Windows logon task, that means the gateway user must
  be signed in.
- Disabled users' workers are not started at gateway start, so their schedules do not run.

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
| Sign-in | `auth.login` (success and failure), `auth.logout`, `auth.totp` (wrong code), `auth.ldap` (insecure LDAP refused), `auth.oidc` (OIDC failure), `user.oidc.bind`, `auth.password.weak` (existing password below the policy, change forced), `auth.ip.blocked`, `auth.ip.unblocked` (`"via": "cli"` from the console) |
| Own account | `user.password`, `user.totp.enable`, `user.totp.disable`, `user.token.create`, `user.token.delete`, `hints.personal.save`, `hints.native.save` |
| User admin | `user.create`, `user.update` (changed field names, never the password), `user.delete`, `user.reset_password`, `user.totp.reset` (two-factor reset, `"via": "cli"` from the console), `user.unlock`, `user.provision`, `user.team.directory` (directory sign-in matched several teams; the first was used) |
| Teams and hints | `team.create`, `team.update` (with `moved`: users moved here from another team), `team.delete`, `team.migrate.membership` (1.5.0 upgrade: a second team membership was dropped), `team.item.add`, `team.item.remove`, `hints.create`, `hints.update`, `hints.delete` |
| Settings | `settings.auth`, `settings.update` |
| Operations | `worker.restart`, `worker.stop`, `hosttask.<action>`, `fs.upload` |
| Agent calls | `acp.denied` (policy denials, with the reason), `acp.<method>` for sensitive methods (configuration, providers and secrets, recipes save/delete, schedules create/delete, apps import/delete, sources, tool permissions, direct tool calls, adding session extensions, defaults, session delete) and for every call on another user's profile, `acp.answer` (answers to permission prompts and forms, with the choice) |
| Admin access | `ws.impersonate` |
| Everyday use (1.11) | `chat.new` (with the folder), `chat.open`, `chat.prompt` (length and number of attachments - never the text), `chat.steer` (1.15, the same), `chat.cancel`, `chat.fork`, `chat.mode`; `settings.tls`, `tls.renewed` |

Retention: entries older than `logs.audit_days` (365) are deleted, and the table is kept to `logs.audit_max_rows`
(500,000) newest rows; both are applied at start and every `logs.check_minutes`. There is no export button; for
longer retention, copy entries out regularly through
`GET /api/admin/audit?limit=500&before=<id>` (admin token), from your database backups, or from the activity log
file (section 18), which a log shipper can collect.

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
| Gateway | `<system_dir>/logs/gateway.log`, and stderr when there is a console (not under the Windows logon task, which uses `pythonw.exe`) | `logs.gateway_file_mb` (10 MB) x `logs.gateway_files` (5) |
| User activity | `<system_dir>/logs/activity.jsonl`: one JSON line per event - `ts` (UTC), `user`, `uid`, `ip`, `action`, `target`, `ok`, `detail`. Every audit event (section 16) plus browser connections (`ws.connect`, `ws.disconnect` with the duration). Prompt text is never logged. `logs.activity: false` turns it off. | `logs.activity_file_mb` (20 MB) x `logs.activity_files` (10) |
| Worker (Goose stdout/stderr) | `<system_dir>/logs/worker-<username>.log`; each start writes a `==== <time> start serve ... root=<profile>` line | above 10 MB at a worker start it is rotated (3 old files); a running worker's log that passes a tenth of the budget is copied to `.1` and emptied in place |
| Goose's own logs | `<profile>/state/logs/` (or `data/logs/`) of every isolated profile, or the native profile's log folder | Goose; and the disk budget below |
| Audit | in the database (section 16) | `logs.audit_days`, `logs.audit_max_rows` |

**Disk budget.** All of these together stay under `logs.max_disk_percent` (0.5 %) of the disk volume that holds
`<system_dir>` - for example 2.4 GB on a 476 GB disk. At start and every `logs.check_minutes` (30) the gateway adds
up the gateway logs, the activity log, the worker logs and the Goose logs of the isolated profiles; above the budget
it deletes the oldest files that are not in use (never the current `gateway.log` / `activity.jsonl`, never a file
written in the last five minutes) until the total is under 90 % of the budget. The native profile's Goose logs are
shared with Goose Desktop and the CLI and are left alone unless `logs.include_native_goose_logs: true`. Files that do
not look like logs are never touched. **Admin > System > Logs & activity** shows the usage, the budget and the last
cleanup; `goose-web check` prints it too.

**Admin > Logs** shows the tail of the gateway log or any worker log (200 to 2000 lines, filter, auto-refresh,
copy). Set the log level with the environment variable `GOOSE_WEB_LOG_LEVEL` (for example `DEBUG`; default
`INFO`). Logs can contain user names, IP addresses, folder paths and error text; protect them like the database.

### 18.1 Forwarding logs to Splunk (Universal Forwarder) or another SIEM

**Where:** everything worth forwarding is in one folder, `<system_dir>\logs`. By default that is
`<profiles_root>\_system\logs`; with the installer's default profiles root that is
`C:\Goose_Web_Profiles\_system\logs`. `goose-web check` prints
`profiles root`. The path can be changed with `paths.system_dir`. Forward from the gateway machine itself: the
gateway writes plain files, with no syslog or HTTP output.

| File (in `<system_dir>\logs`) | Forward? | Suggested sourcetype | What it is for |
|---|---|---|---|
| `activity.jsonl` and `activity.jsonl.1` ... `.10` | **Yes - the security feed** | `goose_web:activity` | One JSON object per line: who did what, when, from where. Every audit event (sign-ins, failed sign-ins, IP blocks, admin and security changes, refused agent calls `acp.denied`) plus chat activity and browser connections. Prompt text is never in it. |
| `gateway.log` and `gateway.log.1` ... `.5` | Yes - operations | `goose_web:gateway` | Gateway start/stop (`Goose Web <version> ready`), warnings, errors with Python tracebacks (multi-line), log-budget runs. |
| `worker-<user>.log` | Optional | `goose_web:worker` | Each agent worker's start line (`==== <time> start ...`) and Goose's stdout/stderr - crashes and failed extension starts. |
| `worker-<user>.log.1`, `.2`, `.3` | No | - | Copies made when a worker log is rotated; their content was already read from the live file. |

**Do not forward** Goose's own logs inside the profiles (`<profiles_root>\<user>\state\logs`, `...\data\logs`) or
the native profile's Goose logs: they can contain conversation content, model replies and tool output, and they
live in the users' (sandboxed) folders. Do not read the database for the audit trail: `activity.jsonl` already
carries every audit event.

**Permissions.** The log folder inherits a narrow ACL: administrators, SYSTEM and the gateway's account. A Universal
Forwarder running as Local System can read it as is. Splunk UF 9.1 and later installs by default as the
least-privileged virtual account `NT SERVICE\SplunkForwarder`, which cannot. Grant it read on the **log folder
only** (run as the gateway's account or an administrator):

```powershell
icacls "C:\Goose_Web_Profiles\_system\logs" /grant "NT SERVICE\SplunkForwarder:(OI)(CI)RX"
```

Never grant the forwarder `<system_dir>` itself (it holds the database and keys) or `<profiles_root>`. Goose Web
does not rewrite the log folder's ACL, so the grant survives upgrades and restarts.

**inputs.conf** (on the Universal Forwarder; replace the folder and the index):

```ini
[monitor://C:\Goose_Web_Profiles\_system\logs\activity.jsonl*]
sourcetype = goose_web:activity
index = goose_web

[monitor://C:\Goose_Web_Profiles\_system\logs\gateway.log*]
sourcetype = goose_web:gateway
index = goose_web

[monitor://C:\Goose_Web_Profiles\_system\logs\worker-*.log]
sourcetype = goose_web:worker
index = goose_web
```

**props.conf.** `activity.jsonl` is structured, so its stanza must be on the **forwarder**. The line-breaking and
timestamp rules for the other two belong on the **indexers** (or a heavy forwarder). The search-time lines go on
the search heads.

```ini
# Universal Forwarder (and the search heads, for KV_MODE/AUTO_KV_JSON)
[goose_web:activity]
INDEXED_EXTRACTIONS = json
TIMESTAMP_FIELDS = ts
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%3N%:z
KV_MODE = none
AUTO_KV_JSON = false

# Indexers / heavy forwarder
[goose_web:gateway]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)(?=\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3} )
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%d %H:%M:%S,%3N
MAX_TIMESTAMP_LOOKAHEAD = 23
# gateway.log uses the gateway machine's LOCAL time without an offset: set its zone, for example
TZ = America/New_York

[goose_web:worker]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TRUNCATE = 20000
```

**Time zones.** `activity.jsonl` `ts` is UTC with an explicit offset. `gateway.log` is the gateway machine's
local time without an offset, hence the `TZ` line. Worker logs mix Goose's own timestamps with the start lines.

**Rotation and the disk budget.** `gateway.log` and `activity.jsonl` rotate by renaming (`.1` is the newest copy),
which the trailing `*` in the monitor stanzas covers. The forwarder recognises a renamed file by its content and
does not index it twice. Worker logs are copied to `.1` and emptied in place, so only the live `worker-*.log` is
monitored. The log budget (section 18) deletes the oldest rotated files when all logs together pass
`logs.max_disk_percent`. A forwarder that has been stopped longer than the logs take to fill the budget loses what
was deleted in the meantime. Keep it running, or raise `logs.activity_files` / `logs.max_disk_percent`.

**Fields and example searches** (`activity`): `ts`, `user`, `uid`, `ip` (the real client address behind a trusted
proxy), `action`, `target`, `ok`, `detail`.

```
index=goose_web sourcetype=goose_web:activity action=auth.login ok=false | stats count by ip, user
index=goose_web sourcetype=goose_web:activity action IN (auth.ip.blocked, auth.ip.unblocked, acp.denied)
index=goose_web sourcetype=goose_web:activity action=user.* OR action=team.* OR action=sandbox.*
index=goose_web sourcetype=goose_web:gateway (ERROR OR WARNING OR Traceback)
```

Other SIEMs: forward the same three file patterns with any file-tailing agent. `activity.jsonl` is newline-delimited
JSON, and the gateway log is one line per event plus traceback continuation lines.

## 19. Backups and restore

### 19.1 What to back up

| Item | Default location | Why |
|---|---|---|
| Database | `<system_dir>/goose-web.db` (plus `-wal` and `-shm` while running) | users, password hashes, TOTP secrets, teams, policies, shared hints, team items, API token hashes, settings including the LDAP bind password, OIDC client secrets and peer tokens, audit log |
| Configuration | `<system_dir>/config.yaml` (or the file you pass with `--config`) | server, paths, goose and auth settings |
| Team library | `<system_dir>/library/` | team recipe files |
| Native hints backups | `<system_dir>/backups/native-hints/` | earlier versions of the admin's hints |
| Isolated profiles | `<profiles_root>/<username>/` | each user's chats (`data/sessions/sessions.db`), recipes, skills, extensions, providers and `secrets.yaml` |
| Archived profiles | `<profiles_root>/_deleted/` | profiles of deleted users |
| Native profile | `%APPDATA%\Block\goose` when bound to the existing profile (outside the profiles root); `<profiles_root>/appdata` on fresh installs | the admin's Goose profile |

The database and the profiles contain credentials. Encrypt and restrict backups like the originals. Since 1.15 the
database also holds messages users queued for a running chat (`chat_state`, plaintext, deleted when sent, removed
or older than 7 days; `secure_delete` is on since 1.15.1), so a database backup can contain prompt text: keep the
same retention for it.

### 19.2 Online backup of the database

The database uses SQLite in WAL mode. Do not copy `goose-web.db` alone while the gateway runs; use SQLite's backup
API, which produces a consistent copy:

```powershell
C:\GooseWeb\.venv\Scripts\python.exe -c "import sqlite3,sys; s=sqlite3.connect(sys.argv[1]); d=sqlite3.connect(sys.argv[2]); s.backup(d); d.close(); s.close()" C:\Goose_Web_Profiles\_system\goose-web.db D:\Backups\goose-web.db
```

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

### 19.4 Restore

1. Stop the gateway.
2. Put back the profiles root, the native profile and the configuration.
3. When you restore `goose-web.db`, delete any `goose-web.db-wal` and `goose-web.db-shm` files next to it that do not
   belong to the restored copy.
4. Restore files as the gateway's OS account (or fix ownership afterwards), so the gateway and Goose can write them.
5. Start the gateway and run `goose-web check`.

## 20. Upgrades

### 20.1 Windows: `scripts\upgrade.ps1`

One command, run as the gateway's normal (non-elevated) Windows user in the install folder:

```powershell
cd C:\GooseWeb
powershell -ExecutionPolicy Bypass -File scripts\upgrade.ps1            # newest commit of the current branch
powershell -ExecutionPolicy Bypass -File scripts\upgrade.ps1 -Ref v1.6.0   # a specific tag or commit
```

It finds the gateway task and its `config.yaml`, refuses while an agent is running (`-Force` overrides), backs up the
database (online SQLite backup) and `config.yaml` to `<profiles_root>\backups\upgrade-<time>\` **before** anything
changes, updates the code (`git pull --ff-only`, or `git checkout <Ref>`), installs the locked dependencies (with
`uv` when available - Goose ships it in `%LOCALAPPDATA%\Goose\bin` - otherwise pip), runs `goose-web check`, and only
then restarts the task and waits for `/healthz`. It prints the version before and after. Settings are never
touched: the task, the firewall rule, `config.yaml`, the database content (schema migrations run when the new
version opens it, after the backup), user profiles and Goose's own folders stay as they are. If any step fails it
stops; up to the restart, the gateway keeps running the old version. The log is in `%TEMP%` (`-Log FILE` to
choose).

- ZIP install (no git): unpack the new release over the install folder, then `upgrade.ps1 -NoGit`.
- From 1.5.x or older (no `upgrade.ps1` yet): `git -C C:\GooseWeb pull --ff-only`, then
  `scripts\upgrade.ps1 -NoGit`.
- 1.6.0 no longer looks for goose in `C:\Goose\dist-windows\resources\bin`. If `check` reports
  `[!!] goose binary: goose (not runnable)`, run `scripts\install.ps1 -GooseBinary <path to goose.exe>` (keeps
  everything else, does not register a second task) and then `upgrade.ps1 -NoGit`.
- Upgrading from a chat that runs through this goose-web (an agent doing it for you): add `-Detached`. The script
  starts itself outside the chat's process tree after `-DelaySeconds` (60) and returns; otherwise the restart would
  end the chat's shell before the gateway is started again. Read the log afterwards.

After the upgrade, ask users to reload the page (a hard refresh if the old UI still shows, see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md)).

Database schema changes are applied automatically when the gateway (or a console command) opens the database; the
version is kept in the `meta` table (`schema_version`, currently 4). Column migrations only add nullable columns
and indexes. The upgrade to 1.5.0 also converts team policies and memberships once (section 9.8), so back up the
database first. Keep the pre-upgrade database backup as your rollback path.

### 20.2 Updating Goose

Update the goose CLI or Goose Desktop as usual. Workers use the new binary the next time they start: restart them in
Admin > System, or restart the gateway (the goose version shown in Admin > System is read at gateway start).
`goose.binary` pins a specific binary; when it is empty the gateway uses `goose` on `PATH`, then the usual install
locations.

## 21. Uninstalling

In an elevated PowerShell:

```powershell
powershell -ExecutionPolicy Bypass -File C:\GooseWeb\scripts\uninstall.ps1 -Port 8710
```

This stops and removes the logon task and the firewall rule. The profiles root, the database and the logs are kept,
and the Goose profile is never touched. Delete `C:\Goose_Web_Profiles` and the install folder by hand if you want
everything gone (back up first).

## 22. Checklist for a new deployment

1. Check the requirements (section 2) and install as the normal Goose user, never elevated.
2. Store the initial admin password from the installer output. Sign in and change it.
3. Run `goose-web check` and fix anything marked `!!`.
4. Set up the reverse proxy with TLS. Set `server.public_url`, add only the proxy to `server.trusted_proxies`, bind
   `server.host` to the interface the proxy uses, and limit the port in the firewall to the proxy. Restart the
   gateway.
5. Open the public URL and confirm sign-in, the WebSocket (the connection indicator shows connected) and a test chat.
6. Enrol two-factor for your admin account, then switch on "Require two-factor for administrators".
7. Configure sign-in methods: LDAP (`ldaps://` or StartTLS, CA file, least-privilege bind account) and/or OIDC
   (`public_url` set, exact redirect URI registered). Keep one local admin as break-glass.
8. Set up each team on its Experience page, starting with **Everyone** (which allows nothing on a new install):
   allowed providers, models and approval modes, a default model, team hints, folders and run limits. Clear every
   warning marked as an error.
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
| OS account | Run the gateway and every console command as the normal Goose user, not elevated. Keep `server.allow_elevated: false`. Use the logon task with RunLevel Limited. |
| Exposure | Bind `server.host` to one interface; avoid `0.0.0.0` unless the firewall covers every interface. Allow the port only from the reverse proxy. |
| TLS | Terminate TLS at the proxy and set an `https://` `server.public_url` (Secure `__Host-` cookie, HSTS, strict Origins). |
| Proxies | Put only the proxy's own address in `server.trusted_proxies`, and make the proxy overwrite `X-Forwarded-For`. |
| Host and Origin | Keep `server.allowed_hosts` and `server.allowed_origins` empty unless users really use another name or a direct address. |
| Admin accounts | Few admins. Two-factor for all of them, then "Require two-factor for administrators". One local break-glass admin with a strong password stored safely. |
| Sessions | Lower `auth.remember_days` and the sign-in lifetime if devices are shared. Users can revoke sessions in their settings. |
| Failed sign-ins | Keep the address block on (`auth.ip_block_threshold` 10). Check Admin > Blocked addresses now and then; exempt only networks you control. |
| Directory sign-in | LDAP over `ldaps://` or StartTLS with `caFile` for a private CA, least-privilege bind account, `allowInsecure` off. OIDC with an `https://` issuer, exact redirect URI, and `stripDomain: false` if the identity provider has more than one domain. |
| Policies | Leave `allow_shell`, `config_edit`, `extensions_edit`, `providers_edit` and `notify_webhook` off for ordinary teams. Set `allowed_modes`, `allowed_providers`, `allowed_models`, `allowed_roots` and `max_concurrent_runs`, with explicit values rather than Any where you can. Keep personal hints off where team hints must be final. Remember that all teams share one Windows account (section 11.3). |
| Shared items | Share extensions and providers only when every member may hold the copied credentials. Import MCP Apps and extensions only from trusted sources. |
| Webhooks | Keep `notify.allow_private_targets: false`. |
| Native profile | Bind at most one admin to it. Restrict its folder's permissions to the gateway user (plus SYSTEM and Administrators). |
| File permissions | Keep the profiles root private (the installer restricts its ACL). Run the ownership check after any elevated activity. |
| Host tasks | Set `host_tasks.enabled: false` if admins do not need the view. |
| Peers | Use peer tokens of accounts whose agents admins may see; prefer `https://` peer URLs with certificate checks on. |
| Tokens | Give API tokens an expiry. Disable accounts promptly when people leave (this revokes their sessions and tokens). |
| Supply chain | Install only with `--require-hashes` from `requirements.lock`. |
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
| `ip list` | addresses blocked after failed sign-ins, and addresses collecting failures |
| `ip unblock ADDRESS` / `ip unblock --all` | end a block and clear the count (an IPv6 address unblocks its /64) |
| `check` | diagnostics; exit code 1 if something is wrong |
| `version` | print the version |

Admin console tabs: Users, Teams & policy, Hints library, Auth providers, Settings, System, Ownership check, Host
tasks, Blocked addresses, Audit log, Logs.

Admin REST endpoints (all under `/api/admin/`, admin session or admin API token; details in [API.md](API.md)):
`users`, `users/{id}`, `users/{id}/reset-password`, `users/{id}/reset-totp`, `users/{id}/unlock`,
`users/{id}/provision`, `users/{id}/hints`, `ip-blocks`, `ip-blocks/unblock`, `teams`, `teams/{id}`, `teams/{id}/items`, `teams/{id}/items/{item}`, `library`, `hints`, `hints/{id}`, `auth`, `settings`,
`audit`, `system`, `system/workers/{key}/{restart|stop}`, `ownership`, `hosttasks`, `hosttasks/action`, `logs`.

Health check: `GET /healthz` returns `ok` (exempt from the Host allow-list). It shows that the gateway process
answers; it does not check workers or the database.
