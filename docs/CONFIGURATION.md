# Configuration reference

This page covers every setting goose-web reads, where it comes from, and the scripts that install it. The REST and
WebSocket contract is in [API.md](API.md). The security implications are in
[SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md).

## 1. Precedence

From lowest to highest (`goose_web/config.py: load_settings`):

1. **Built-in defaults**: `DEFAULTS` in `goose_web/config.py` (section 2).
2. **One `config.yaml` file**. The first of these that exists is used. They are not merged with each other:
   1. `--config <file>` on the command line
   2. the `GOOSE_WEB_CONFIG` environment variable
   3. `<default profiles root>/_system/config.yaml`, where the default profiles root is `C:\Goose_Web_Profiles` on
      Windows and `$GOOSE_WEB_PROFILES` or `/var/lib/goose-web/profiles` elsewhere. This lookup always uses the
      **built-in** default root, not a `paths.profiles_root` you configured. If your root is somewhere else, pass
      `--config` (the installers and the systemd unit do).

   The file is deep-merged over the defaults.
3. **Environment variables** `GOOSE_WEB__<SECTION>__<KEY>=<value>`, for example
   `GOOSE_WEB__SERVER__PUBLIC_URL=https://goose.example.org`. Names are case-insensitive and must have exactly two
   parts. Values are converted like this (`_coerce`):
   - `true`/`yes`/`on` become true, and `false`/`no`/`off` become false
   - whole numbers become integers
   - values that start with `[` or `{` are parsed as YAML (for example `'["127.0.0.1", "192.168.1.10"]'`)
   - anything else stays a string

`goose-web check` prints which config file was used (`config file: ... (defaults)` when none was found).

Other environment variables:

| Variable | Used by | Meaning |
|---|---|---|
| `GOOSE_WEB_CONFIG` | `config.py` | config file path (see above) |
| `GOOSE_WEB_PROFILES` | `config.py` | default profiles root on Linux/macOS |
| `GOOSE_WEB_LOG_LEVEL` | `__main__.py: _setup_logging` | log level, default `INFO` |
| `GOOSE_WEB_ADMIN` | `docker/entrypoint.sh` | admin username at first container start (default `admin`) |
| `GOOSE_WEB_NATIVE_ROOT` | `docker/entrypoint.sh` | admin profile folder at first start (default `fresh`) |
| `GOOSE_WEB_UNELEVATED` | `winsec.py` | internal guard set during the de-elevation relaunch; do not set it |

## 2. config.yaml keys and defaults

```yaml
server:
  host: 127.0.0.1
  port: 8710
  public_url: ""
  trusted_proxies: ["127.0.0.1", "::1"]
  allowed_origins: []
  max_upload_mb: 25
  allow_elevated: false
paths:
  profiles_root: C:\Goose_Web_Profiles      # Linux/macOS: $GOOSE_WEB_PROFILES or /var/lib/goose-web/profiles
  system_dir: ""                            # "" = <profiles_root>/_system
goose:
  binary: ""                                # "" = auto-detect
  idle_minutes: 30
  start_timeout_seconds: 45
  native_scheduler: auto                    # auto | on | off
  extra_env: {}
  default_workdir_native: ""                # "" = home folder
auth:
  session_hours: 12
  remember_days: 30
  lockout_threshold: 8
  lockout_minutes: 15
  min_password_length: 10
host_tasks:
  enabled: true
  path_filter: "\\*"
```

| Key | Default | Meaning |
|---|---|---|
| `server.host` | `127.0.0.1` | Listen address. Use the LAN IP when a reverse proxy on another host connects. |
| `server.port` | `8710` | Listen port. |
| `server.public_url` | `""` | External URL, for example `https://goose.example.org`. It is always an allowed Origin. When it starts with `https://` the session cookie becomes `__Host-gw` with Secure, and HSTS is sent. It is also the OIDC redirect base and the link in webhook messages. |
| `server.trusted_proxies` | `["127.0.0.1", "::1"]` | IPs or CIDRs whose `X-Forwarded-For` (rightmost entry), `X-Forwarded-Proto` and `X-Forwarded-Host` are trusted. |
| `server.allowed_origins` | `[]` | Extra Origins accepted for the WebSocket and for cookie-authenticated writes. `public_url` and the request's own `scheme://Host` are always accepted. |
| `server.max_upload_mb` | `25` | Size limit per uploaded file (`/api/fs/upload`, at most 20 files per request). |
| `server.allow_elevated` | `false` | If true, the gateway runs with an elevated token (Windows) or as root (POSIX) instead of refusing. Leave it false. |
| `paths.profiles_root` | `C:\Goose_Web_Profiles` (Windows), `$GOOSE_WEB_PROFILES` or `/var/lib/goose-web/profiles` | Parent of all isolated profiles and of `_system`. |
| `paths.system_dir` | `""` (= `<profiles_root>/_system`) | Database, logs, team library, backups. |
| `goose.binary` | `""` | Path to `goose`. When empty: `goose` on `PATH`, then `C:\Goose\dist-windows\resources\bin\goose.exe`, `%LOCALAPPDATA%\Programs\Goose\resources\bin\goose.exe`, `%USERPROFILE%\.local\bin\goose.exe` (Windows) or `/usr/local/bin/goose`, `~/.local/bin/goose`. |
| `goose.idle_minutes` | `30` | A worker is stopped after this long with no browser clients, no active runs and no scheduler duty. |
| `goose.start_timeout_seconds` | `45` | How long `goose serve` may take to answer `/status`. |
| `goose.native_scheduler` | `auto` | Who runs the scheduler for the admin's native profile (section 7). |
| `goose.extra_env` | `{}` | Extra environment variables for **every** worker, isolated ones included. |
| `goose.default_workdir_native` | `""` | Default folder for new chats of native-profile users (home folder when empty). |
| `auth.session_hours` | `12` | Session length without "remember me". Overridden by the DB setting `session_hours`. |
| `auth.remember_days` | `30` | Session length with "remember me". |
| `auth.lockout_threshold` | `8` | Failed passwords before a lockout. |
| `auth.lockout_minutes` | `15` | Lockout duration. |
| `auth.min_password_length` | `10` | Minimum length for new passwords. |
| `host_tasks.enabled` | `true` | Turns the admin host-task view on or off (Windows only). |
| `host_tasks.path_filter` | `\*` | Task Scheduler folder filter. `\Microsoft\*` is always excluded. |

Fixed limits (not configurable): 2 MiB JSON bodies, 64 MiB WebSocket frames, 12 MiB live buffer per session,
256 MiB total, login limits of 40 attempts per 5 minutes per IP and 10 per 5 minutes per IP+username.

## 3. Command line

`python -m goose_web [--config FILE] <command>` (or the `goose-web` script). With no command it runs `serve`.

| Command | Flags | What it does |
|---|---|---|
| `serve` | `--host`, `--port` | Runs the gateway. It first checks the token (`winsec.ensure_unelevated`): when elevated on Windows it relaunches itself with a normal-user, Medium-integrity token, and on POSIX it refuses to run as root (exit 3). Logs go to `<system_dir>/logs/gateway.log` (5 MB x 5) and to stderr. |
| `init` | `--admin NAME` (default: current OS user), `--password` (default `ChangeMe`), `--native-root auto\|fresh\|PATH` (default `auto`), `--force` | Creates the database and the first admin (local, `must_change_pw`, profile mode `native`), creates the team **Everyone** and makes it the default team. `auto` uses Goose's default profile folder if it has a `config` subfolder, otherwise `fresh` (`<profiles_root>/appdata` with `config/`, `data/`, `state/`). A path ending in `config` is accepted and its parent is used. Without `--force`, an existing database is left as it is. |
| `user list` | | Lists users. |
| `user add NAME` | `--password`, `--admin` | Creates a local user (temporary password printed if none is given, change forced). |
| `user reset NAME` | `--password` | Sets a temporary password, forces a change, unlocks the account, switches it to local auth and signs it out everywhere. |
| `check` | | Diagnostics: version, config file, goose binary and version, OS user and integrity (fails if elevated), profiles root, Goose Desktop running (Windows), whether the port is free. Exit code 1 if something is wrong. |
| `version` | | Prints the version. |

## 4. Settings stored in the database

Admins change these in the UI (Admin > Settings / Sign-in). They are stored in the `settings` table of
`<system_dir>/goose-web.db` (`api.py: admin_settings`, `admin_auth`, and `auth.py: AuthService`).

| Setting | Default | Meaning |
|---|---|---|
| `native_root` | set by `init` | The admin's native Goose profile folder. |
| `default_team_id` | the Everyone team | Team for users created in the admin UI without explicit teams. Users auto-created by LDAP/OIDC join only their mapped teams. |
| `brand` | `{name: "Goose Web", tagline: ...}` | `name`, `tagline`, `machine` (shown in Herd). |
| `session_hours` | config `auth.session_hours` | 1 to 720. |
| `allow_self_totp` | `true` | Stored and shown in the UI. Note: `/api/me/totp/setup` does not currently check it. |
| `require_totp_admins` | `false` | Admins cannot turn off their TOTP. It does not force enrolment. |
| `peers` | `[]` | Herd peers: `{name, url, token, verifyTls}` (max 50). The gateway calls `<url>/api/herd` with `Bearer <token>`. Tokens are masked in reads. |
| `auth` | see below | Sign-in methods. |

`auth` (`auth.py: DEFAULT_AUTH`). Secrets are write-only: reads return `********`, and saving `********` keeps the
stored value.

| Key | Default | Meaning |
|---|---|---|
| `localEnabled` | `true` | Local passwords for non-admins. Local admins can always sign in. |
| `ldap.enabled` | `false` | LDAP/AD sign-in for unknown usernames and for users with `auth_source = ldap`. |
| `ldap.label` | `Active Directory` | Button label. |
| `ldap.url` | `""` | `ldap://host` or `ldaps://host`. |
| `ldap.bindDn`, `ldap.bindPassword` | `""` | Service account used for the search. |
| `ldap.userBase` | `""` | Search base. |
| `ldap.userFilter` | `(&(objectClass=user)(sAMAccountName={username}))` | `{username}` is escaped with `escape_filter_chars`. |
| `ldap.adminGroupDn` | `""` | `memberOf` value that makes the user an admin (native admins are never demoted). |
| `ldap.groupTeamMap` | `{}` | `{groupDn: teamId}`. |
| `ldap.startTls` | `false` | StartTLS on `ldap://`. |
| `ldap.caFile` | `""` | CA bundle. TLS with certificate checking is used for `ldaps://`, `startTls` or `caFile`; otherwise the bind is in clear text. |
| `ldap.autoCreate` | `true` | Create users at their first sign-in. |
| `oidc[]` | `[]` | Providers: `id` (safe name), `label`, `issuer` (discovery at `<issuer>/.well-known/openid-configuration`), `clientId`, `clientSecret`, `scopes` (default `openid profile email`), `adminClaim`, `adminValue` (if empty, the claim must be `true`), `teamClaim` (matched against team names), `autoCreate` (default true), `stripDomain` (default true: `alice@x` becomes `alice`). Redirect URI: `<public_url>/api/auth/oidc/<id>/callback`. |

## 5. Policies and teams

Policies apply to non-admins only. Admins get every permission with no lists and no run limit (`ADMIN_POLICY`).
Keys (`goose_web/policy.py`):

| Key | Type | Default | Allows |
|---|---|---|---|
| `recipes_edit` | bool | true | save/delete recipes, recipe and subrecipe sources |
| `skills_edit` | bool | true | create/update/delete/import skill, agent and project sources |
| `extensions_edit` | bool | false | add/remove/enable extensions, pick extensions for a new session |
| `providers_edit` | bool | false | custom providers, provider config and secrets, defaults, model downloads, onboarding import |
| `schedules` | bool | true | create/update/delete/pause/run schedules |
| `apps` | bool | true | import/delete MCP Apps, direct `tools/call` |
| `prompts_edit` | bool | false | system prompts |
| `hints_edit` | bool | true | personal goose hints |
| `tools_permissions` | bool | true | per-tool permission settings |
| `config_edit` | bool | false | raw config read/write (treat it like `allow_shell`) |
| `allow_shell` | bool | false | shell/code extensions (`developer`, `computercontroller`, `code_execution`, `orchestrator`), stdio MCP extensions, per-session MCP servers |
| `notify_webhook` | bool | false | a personal notification webhook |
| `allowed_modes` | list | `[]` = any | Goose modes (`session/set_mode`, `mode` option) |
| `allowed_providers` | list | `[]` = any | providers |
| `allowed_models` | list | `[]` = any | models |
| `allowed_roots` | list | `[]` | folders besides the user's workspace |
| `max_concurrent_runs` | int | 3 | running agents per profile (0 = no limit) |

Teams can also set `default_provider` and `default_model`, which are written into members' profiles.

How the effective policy is built (`effective_policy`):

- **No teams**: `DEFAULT_POLICY`.
- **One or more teams**: each team's policy is laid over `DEFAULT_POLICY` first. Then:
  - booleans are OR-ed (any team that allows it grants it)
  - `allowed_modes`, `allowed_providers` and `allowed_models` are unioned, but if any team leaves a list empty the
    result is unrestricted
  - `allowed_roots` are unioned
  - `max_concurrent_runs` is the highest value across the teams
- **User overrides** (`policy_overrides`, Admin > Users) replace single keys last.

Every ACP method a non-admin sends goes through `policy.check`. Methods that are not on the list are denied.

## 6. Profile layout

`goose_web/profiles.py`:

```
<profiles_root>/
  _system/                      config.yaml, goose-web.db (+ -wal/-shm)
    logs/                       gateway.log, worker-<user>.log
    library/teams/<id>/recipes/ team recipes (on members' GOOSE_RECIPE_PATH)
    backups/native-hints/       copies of the admin's .goosehints before a save from the UI
  <user>/                       one isolated profile = GOOSE_PATH_ROOT of that user's worker
    config/                     config.yaml, secrets.yaml, .goosehints (composed), custom_providers/, recipes/, skills/
    data/                       sessions/sessions.db, logs/ (written by Goose)
    state/
    workspace/                  default folder for new chats
    .goose-web/managed.json     what the gateway provisioned
  _deleted/<user>-<timestamp>/  archived profiles of deleted users
  appdata/                      the admin's profile on a fresh install (init --native-root fresh)
```

- **Native profile** (`profile_mode = native`, admins only): the admin's existing Goose profile, used in place.
  The gateway never provisions it. It only writes there when the admin saves their own hints in the UI (after a
  backup). When the folder is Goose's default location, `GOOSE_PATH_ROOT` is not set for that worker.
- **Isolated profile**: created at the first sign-in. The first provisioning copies the base platform extensions
  (`todo`, `skills`, `apps`, `chatrecall`, `summarize`, `extensionmanager`, `analyze`, `memory`, `summon`, `tom`)
  from the admin's config, sets `GOOSE_MODE: approve`, and writes `developer` disabled unless `allow_shell`.
  After that, team items (recipes, skills, extensions, providers, with secrets copied from the source profile when
  the item came from a profile library), hints and default models are applied on every reprovision. Items the user
  created are never overwritten.
- Isolated workers get `GOOSE_DISABLE_KEYRING=1` (secrets in the profile's `secrets.yaml`), `GOOSE_RECIPE_PATH` =
  their team recipe folders, and no inherited `GOOSE_*` variables except `GOOSE_DISABLE_KEYRING` and
  `GOOSE_TELEMETRY_ENABLED`.
- Not relocatable by `GOOSE_PATH_ROOT`: home-folder skill and recipe folders such as `~/.agents/skills` and
  `~/.agents/recipes` are shared by every profile on the machine.
- Usernames: letters, digits, `.`, `_`, `-`, starting with a letter or digit, up to 64 characters, no Windows device
  names. Avoid `appdata` and `workspace` (see SECURITY-ASSESSMENT GW-04).

## 7. Scheduler ownership

`workers.py: WorkerManager.wants_scheduler`. A worker gets `--enable-scheduler` when:

| Profile | `native_scheduler` | Scheduler runs in the gateway worker |
|---|---|---|
| isolated | (ignored) | always |
| native | `on` | always |
| native | `off` | never (schedules run in Goose Desktop or not at all) |
| native | `auto` | only while Goose Desktop is **not** running |

In `auto` mode the monitor checks every 15 seconds (Desktop detection is cached for 20 s). When Desktop starts or
stops, it restarts the native worker once no run is active, which hands the scheduler over. Desktop counts as
running when a `goose.exe` process exists whose image path does not end in `\resources\bin\goose.exe` (Windows only;
on other systems `auto` behaves like `on`). If your goose CLI lives elsewhere, for example
`%USERPROFILE%\.local\bin\goose.exe`, the gateway's own workers match that rule, so set `on` or `off` explicitly.

Profiles that have jobs in `data/schedule.json` and own their scheduler are started even when nobody is connected,
are not stopped when idle, and are restarted with backoff (up to 5 minutes) after a crash.

## 8. Scripts

| Script | Run as | What it does |
|---|---|---|
| `scripts/install.ps1` | the normal Windows user, **not elevated** (it exits with code 3 when elevated unless `-AllowElevated`) | Creates `.venv` (uv, else `py -3`/`python -m venv`) and installs the package. Finds the Goose profile: `-GooseAppData`, else `%APPDATA%\Block\goose` if it has `config\`, else asks (Enter = fresh, `<ProfilesRoot>\appdata`). Writes `<ProfilesRoot>\_system\config.yaml` only if it is missing. Runs `init --admin <-Admin> --native-root <profile>` (password `ChangeMe`, forced change), then `check`, then `register-service.ps1` through one elevation prompt. Parameters: `-ProfilesRoot` (`C:\Goose_Web_Profiles`), `-GooseAppData`, `-BindHost` (`127.0.0.1`), `-Port` (8710), `-PublicUrl`, `-TrustedProxy` (added to loopback), `-FirewallRemoteAddress` (`LocalSubnet`), `-TaskPath` (`\GooseWeb\`), `-Admin` (`%USERNAME%`), `-NoService`, `-NonInteractive`, `-AllowElevated`. It never writes into the Goose profile folder. |
| `scripts/register-service.ps1` | elevated | Registers the logon task and the firewall rule (section 9). Parameters: `-User`, `-InstallDir`, `-ConfigPath` (required), `-Port`, `-TaskPath`, `-TaskName` (`GooseWeb_Gateway`), `-FirewallRemoteAddress` (comma separated, `LocalSubnet`), `-NoFirewall`, `-NoTask`. |
| `scripts/uninstall.ps1` | elevated | Stops and removes the task and the firewall rule (`-Port`, `-TaskPath`, `-TaskName`). Profiles, database and logs are kept. |
| `scripts/start-gateway.cmd` | the normal user | Runs `.venv\Scripts\python.exe -m goose_web <args> serve` in the foreground. Pass `--config FILE` or set `GOOSE_WEB_CONFIG`. |
| `scripts/install.sh` | the normal user, **not root** | Linux/macOS. Needs `goose` on `PATH`. Creates `.venv`, installs, writes `<profiles-root>/_system/config.yaml` if missing (with `goose.binary` set), runs `chmod 700` on the profiles root, then `init --admin $USER` and `check`. Options: `--profiles-root` (`~/.local/share/goose-web`), `--goose-appdata DIR\|fresh` (default `auto`; an existing `~/.config/goose` is not picked up because it has no `config/` subfolder, so the admin starts fresh in `<root>/appdata`), `--host`, `--port`, `--public-url`, `--trusted-proxy` (repeatable), `--systemd` (user unit `goose-web.service`, `Restart=on-failure`, `NoNewPrivileges=yes`; run `loginctl enable-linger $USER` to start it at boot). |

## 9. Windows service model

goose-web does not install a Windows service. `register-service.ps1` creates:

- **A scheduled task** `\GooseWeb\GooseWeb_Gateway` that runs
  `.venv\Scripts\pythonw.exe -m goose_web --config "<config>" serve` in the install folder.
  - Trigger: at logon of that user. The gateway runs while the user is signed in.
  - Principal: that user, `LogonType Interactive`, `RunLevel Limited`, so it gets a normal non-elevated token. The
    script reads the task back and fails if the run level is not Limited.
  - Settings: restart on failure (`RestartCount 999`, every minute), no execution time limit, start when available,
    runs on battery, `MultipleInstances IgnoreNew`.
- **An inbound firewall rule** `GooseWeb-Gateway-TCP-<port>` that allows TCP `<port>` only from
  `-FirewallRemoteAddress` (default `LocalSubnet`). When a reverse proxy fronts the gateway, use only the proxy's IP.

Running as the user with a Limited token keeps every file the gateway and Goose create owned by that user. Elevated
or batch-logon tasks get the full admin token, and files they create become owned by Administrators. If the
gateway is started elevated anyway, it relaunches itself with a normal-user token (`winsec.run_unelevated`) or
refuses to run. Admin > System shows an ownership check of each profile's `config/` folder. Admin > Host tasks
lists the host's scheduled tasks with an elevation warning (`hosttasks.elevation_risk`).

## 10. Docker

`docker/compose.yaml` builds `docker/Dockerfile` (Python 3.13 slim, goose CLI `GOOSE_VERSION` 1.57.0 from the
official release) and sets these through environment variables: `HOST=0.0.0.0`, `PORT=8710`, `PROFILES_ROOT=/data`,
`BINARY=/usr/local/bin/goose`, `NATIVE_SCHEDULER=on`, `DEFAULT_WORKDIR_NATIVE=/data/workspace`, and
`GOOSE_DISABLE_KEYRING=1`. On first start, `entrypoint.sh` runs `init --admin ${GOOSE_WEB_ADMIN:-admin}
--native-root ${GOOSE_WEB_NATIVE_ROOT:-fresh}`. The admin is `admin` / `ChangeMe` (forced change), with the profile
in `/data/appdata`. Add `GOOSE_WEB__SERVER__PUBLIC_URL` and `GOOSE_WEB__SERVER__TRUSTED_PROXIES` for a reverse
proxy. Hardening already in compose: non-root uid 1000, `read_only: true`, tmpfs `/tmp` and `/home/goose`,
`cap_drop: [ALL]`, `no-new-privileges:true`, `pids_limit: 1024`, `mem_limit: 4g`, and the port published on
`127.0.0.1` only.
