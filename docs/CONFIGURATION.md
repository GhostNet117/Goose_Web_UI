# Configuration reference

This page covers every setting goose-web reads, where it comes from, and the scripts that install it. The REST and
WebSocket contract is in [API.md](API.md). The security implications (threat model, findings GW-01 to GW-38 and
NEW-01 to NEW-10, hardening checklist) are in [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md).

## 1. Precedence

From lowest to highest (`goose_web/config.py: load_settings`):

1. **Built-in defaults**: `DEFAULTS` in `goose_web/config.py` (section 2).
2. **One `config.yaml` file**. The first of these that exists is used. They are not merged with each other:
   1. `--config <file>` on the command line
   2. the `GOOSE_WEB_CONFIG` environment variable
   3. `<default profiles root>/_system/config.yaml`, where the default profiles root is `C:\Goose_Web_Profiles`.
      This lookup always uses the **built-in** default root, not a `paths.profiles_root` you configured. If your
      root is somewhere else, pass `--config` (the installer and the logon task do).

   A `--config` or `GOOSE_WEB_CONFIG` that names a file that does not exist is a fatal error (1.12): the gateway
   and every command stop with `config file not found` instead of quietly using another file.

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
| `GOOSE_WEB_LOG_LEVEL` | `__main__.py: _setup_logging` | log level, default `INFO` |
| `GOOSE_WEB_UNELEVATED` | `winsec.py` | internal guard set during the de-elevation relaunch; do not set it |

## 2. config.yaml keys and defaults

```yaml
server:
  host: 127.0.0.1
  port: 8710
  public_url: ""
  trusted_proxies: ["127.0.0.1", "::1"]
  allowed_origins: []
  allowed_hosts: []
  max_upload_mb: 25
  allow_elevated: false
  tls: auto                                 # auto | self-signed | files | off (ADMINISTRATION 6.3)
  tls_cert_file: ""
  tls_key_file: ""
  tls_names: []
paths:
  profiles_root: C:\Goose_Web_Profiles
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
  min_password_length: 12                   # never below 12
  ip_block_threshold: 10                    # failed sign-ins in a row that block an address; 0 = off
  ip_block_window_days: 30
  ip_block_days: 30                         # 0 = until an admin unblocks it
  ip_block_exempt: []                       # addresses/CIDR networks never blocked
notify:
  allow_private_targets: false
host_tasks:
  enabled: true
  path_filter: "\\*"
```

| Key | Default | Meaning |
|---|---|---|
| `server.host` | `127.0.0.1` | Listen address. Use the LAN IP when a reverse proxy on another host connects. |
| `server.port` | `8710` | Listen port. |
| `server.public_url` | `""` | External URL, for example `https://goose.example.org`. When it is set, the allowed Origins are its origin plus `server.allowed_origins`, and the request's own Host is **not** used. Its host name is always on the Host allow-list. When it starts with `https://` the session cookie becomes `__Host-gw` with Secure, and HSTS is sent. It is the OIDC redirect base (**OIDC sign-in is refused without it**, `oidc_needs_public_url`) and the link in webhook messages. |
| `server.trusted_proxies` | `["127.0.0.1", "::1"]` | IPs or CIDRs whose `X-Forwarded-For` (rightmost entry), `X-Forwarded-Proto` and `X-Forwarded-Host` are trusted. A trusted `X-Forwarded-Host` must also be on the Host allow-list. |
| `server.allowed_origins` | `[]` | Extra Origins (`scheme://host[:port]`) accepted for the WebSocket and for cookie-authenticated writes. Without `public_url`, the request's own `scheme://Host` is accepted as well (its Host has passed the allow-list). With `public_url` set, direct access under another address, for example `http://192.168.1.10:8710` or `http://127.0.0.1:8710`, works only if that origin is listed here. |
| `server.allowed_hosts` | `[]` | Extra host names or IPs (no ports, no wildcards) accepted in the `Host` header. This guards against DNS rebinding (`app.py: HostGuard`). Always allowed: the `public_url` host, `localhost`, `127.0.0.1`, `::1`, and `server.host` unless it is `0.0.0.0` or `::`. Other Host values get `400 invalid host`, and `GET /healthz` is exempt. Environment: `GOOSE_WEB__SERVER__ALLOWED_HOSTS=goose,192.168.1.10` (comma separated) or a YAML list. |
| `server.max_upload_mb` | `25` | Size limit per uploaded file (`/api/fs/upload`, at most 20 files per request). |
| `server.allow_elevated` | `false` | If true, the gateway runs with an elevated token instead of refusing. Leave it false. |
| `paths.profiles_root` | `C:\Goose_Web_Profiles` | Parent of all isolated profiles and of `_system`. |
| `paths.system_dir` | `""` (= `<profiles_root>/_system`) | Database, logs, team library, backups, built-in TLS files (`tls/`). |
| `server.tls` | `auto` | HTTPS: `self-signed` (built-in local CA + server certificate, renewed automatically), `files` (your PEM certificate and key), `off` (plain HTTP behind a reverse proxy). `auto` = `self-signed` unless `public_url` is set. Admin > System > HTTPS overrides it (stored in the database). Applies at the next start (ADMINISTRATION 6.3). |
| `server.tls_cert_file`, `server.tls_key_file` | `""` | PEM certificate (chain) and private key for `tls: files`. |
| `server.tls_names` | `[]` | Extra DNS names or IP addresses for the built-in certificate (it already covers localhost, 127.0.0.1, ::1, the host name, FQDN, the machine's addresses, the bind address, the public_url host and `allowed_hosts`). |
| `logs.max_disk_percent` | `0.5` | All Goose Web logs (gateway, activity, workers, isolated profiles' Goose logs) stay under this share of the disk volume; the oldest unused files are deleted (ADMINISTRATION 18). |
| `logs.check_minutes` | `30` | How often the log budget, the audit retention and the built-in certificate are checked. |
| `logs.activity` | `true` | User activity log `<system_dir>/logs/activity.jsonl` (JSON lines). |
| `logs.activity_file_mb`, `logs.activity_files` | `20`, `10` | Rotation of the activity log. |
| `logs.gateway_file_mb`, `logs.gateway_files` | `10`, `5` | Rotation of `gateway.log`. |
| `logs.include_native_goose_logs` | `false` | Also trim the native profile's Goose logs (shared with Goose Desktop and the CLI). |
| `logs.audit_days`, `logs.audit_max_rows` | `365`, `500000` | Audit table retention in the database. |
| `sandbox.enabled` | `auto` | `auto` = on; `true` / `false`. Runs every isolated non-admin user's worker in its own AppContainer, connected over stdio; file access only to the user's profile, the team folder and the team's extra folders (ADMINISTRATION 11.6). |
| `sandbox.network` | `internet` | Network capabilities of sandboxed workers: `none`, `internet` (outbound internet) or `internet+lan` (also the local network). Loopback is never reachable. |
| `sandbox.relays` | `[]` | Local services (`host:port` on this machine, for example a model proxy on `127.0.0.1:8317`) that sandboxed workers may reach through a per-user forwarder and a named pipe; their provider URLs are rewritten to the forwarder (ADMINISTRATION 11.6). Everything else on loopback stays closed. |
| `sandbox.read_dirs` | `[]` | Extra folders sandboxed workers may read and run (Python, node, uv, git installs outside `C:\Program Files`). The goose CLI folder is always included. |
| `goose.binary` | `""` | Path to `goose`. When empty: `goose` on `PATH`, then `%LOCALAPPDATA%\Programs\Goose\resources\bin\goose.exe`, `%ProgramFiles%\Goose\resources\bin\goose.exe`, `%USERPROFILE%\.local\bin\goose.exe`. Set it for any other location (for example `C:\AI\Goose\resources\bin\goose.exe`); `install.ps1 -GooseBinary` writes it. |
| `goose.idle_minutes` | `30` | A worker is stopped after this long with no browser clients, no active runs and no scheduler duty. |
| `goose.start_timeout_seconds` | `45` | How long `goose serve` may take to answer `/status`. |
| `goose.native_scheduler` | `auto` | Who runs the scheduler for the admin's native profile (section 7). |
| `goose.extra_env` | `{}` | Extra environment variables for **every** worker, isolated ones included. |
| `goose.default_workdir_native` | `""` | Default folder for new chats of native-profile users (home folder when empty). |
| `auth.session_hours` | `12` | Session length without "remember me". Overridden by the DB setting `session_hours`. |
| `auth.remember_days` | `30` | Session length with "remember me". |
| `auth.lockout_threshold` | `8` | Failed passwords before a lockout. |
| `auth.lockout_minutes` | `15` | Lockout duration. |
| `auth.min_password_length` | `12` | Minimum length for new passwords. Values below 12 are raised to 12. New passwords also need a lower-case letter, an upper-case letter, a number and a symbol, must not contain the user name, must not be (or be built from) a common password and must not repeat a character 4 times in a row ([ADMINISTRATION.md](ADMINISTRATION.md#72-creating-accounts)). |
| `auth.ip_block_threshold` | `10` | Failed sign-ins in a row from one client address (IPv6: per /64) that block it. A successful sign-in from the address resets the count. `0` turns address blocking off. |
| `auth.ip_block_window_days` | `30` | Only failures from the last N days count toward `ip_block_threshold`. |
| `auth.ip_block_days` | `30` | How long a block lasts. `0` = until an administrator unblocks it (Admin > Blocked addresses or `ip unblock`). |
| `auth.ip_block_exempt` | `[]` | Addresses or CIDR networks that are never counted or blocked. `server.trusted_proxies` are always exempt. |
| `notify.allow_private_targets` | `false` | Personal notification webhooks may only reach public internet addresses. Every resolved address is checked. Loopback, private, link-local, CGNAT, reserved, multicast and unspecified targets (including IPv4 embedded in IPv6) are refused, both when the webhook is saved (`400 webhook_blocked`) and when it is sent. Requests go to the checked IP, never follow redirects and ignore proxy environment variables. Set `true` only if users really need internal targets, such as a self-hosted ntfy on the LAN. |
| `host_tasks.enabled` | `true` | Turns the admin host-task view on or off (Windows only). |
| `host_tasks.path_filter` | `\*` | Task Scheduler folder filter. `\Microsoft\*` is always excluded. |

Fixed limits (not configurable): 2 MiB JSON bodies, 64 MiB WebSocket frames, 12 MiB live buffer per session,
256 MiB total, login limits of 40 attempts per 5 minutes per IP and 10 per 5 minutes per IP+username (wrong TOTP
codes count toward the account lockout and the address block like wrong passwords), worker logs rotated at 10 MiB with 3 backups (checked
before each worker start), audit rows kept for 365 days (older rows are deleted at startup).

API tokens (Settings > Account > API tokens) are sent as `Authorization: Bearer gwt_...`, for REST calls and for
the `/ws` handshake of non-browser clients. They are never accepted in a URL. A user's tokens are revoked when the
password is changed, set or reset, and when the account is disabled. See [API.md](API.md).

## 3. Command line

`python -m goose_web [--config FILE] <command>` (or the `goose-web` script). With no command it runs `serve`.

| Command | Flags | What it does |
|---|---|---|
| `serve` | `--host`, `--port` (a `--host` value also joins the Host allow-list) | Runs the gateway. It first checks the token (`winsec.ensure_unelevated`): when elevated it relaunches itself with a normal-user, Medium-integrity token (exit 3 if it cannot). On any system other than Windows it refuses to start (Goose Web runs on Windows only since 1.13.0). Logs go to `<system_dir>/logs/gateway.log` (5 MB x 5) and to stderr. |
| `init` | `--admin NAME` (default: current OS user), `--password PW`, `--password-file FILE` (first line of FILE, `-` = stdin), `--native-root auto\|fresh\|PATH` (default `auto`), `--force` | Creates the database and the first admin (local, `must_change_pw`, profile mode `native`), creates the team **Everyone** (with nothing allowed, like every new team) and makes it the default team. Without `--password`/`--password-file` it generates a **random 20-character initial password and prints it once**. Only its hash is stored and it is not shown again. If you lose it, run `user reset`. A given password that does not meet the password rules only triggers a warning, because it must be changed at first sign-in anyway. `auto` uses Goose's default profile folder if it has a `config` subfolder, otherwise `fresh` (`<profiles_root>/appdata` with `config/`, `data/`, `state/`). A path ending in `config` is accepted and its parent is used. Without `--force`, an existing database is left as it is. |
| `user list` | | Lists users. |
| `user add NAME` | `--password`, `--admin` | Creates a local user (temporary password printed if none is given, change forced). |
| `user reset NAME` | `--password` | Sets a temporary password (printed), forces a change, unlocks the account, switches it to local auth, signs it out everywhere and revokes its API tokens. Use it if the initial admin password is lost. |
| `user reset-totp NAME` | | Removes the user's two-factor (lost authenticator), unlocks the account, signs it out everywhere and revokes its API tokens; audited as `user.totp.reset`. Same as Admin > Users > Reset two-factor, and the way back in when the only admin lost their authenticator. |
| `ip list` | | Lists client addresses blocked after failed sign-ins and addresses that are collecting failures (count, last user name tried, end of the block). |
| `ip unblock ADDRESS` | `--all` | Ends the block of ADDRESS (an IPv6 address unblocks its /64) and clears its count, or with `--all` every block and count; audited as `auth.ip.unblocked`. Works while the gateway runs (it re-reads the blocks within 15 seconds), so it is the way back in when the admin's own address is blocked. |
| `check` | | Diagnostics: version, config file, goose binary and version, OS user and integrity (fails if elevated), profiles root, Goose Desktop running (Windows), whether the port is free, and (Windows, information only) the logon task that autostarts this install. Exit code 1 if something is wrong. |
| `tls` | `status \| renew \| export-ca FILE \| trust` | Built-in HTTPS (ADMINISTRATION 6.3): show the mode, certificate, names and fingerprints (creates the certificate when the mode is self-signed); renew the server certificate now; copy the local CA certificate to FILE; trust the CA for the current Windows user. |
| `sandbox` | `status \| remove USER \| remove --all` | Sandbox (ADMINISTRATION 11.6): list every user's AppContainer, SID and folder grants; or revoke one user's grants and delete the container. |
| `native-hints` | `status \| enable USER [--team NAME] [--adopt] [--doc-name NAME] \| disable` | Managed native hints (ADMINISTRATION 10.1): Goose Web writes the native admin's composed hints (personal, assigned, team documents) into the native profile's `config/.goosehints`, which Goose Desktop, the CLI and schedules on that account load too. `--team` puts the user in that team (created if missing); `--adopt` keeps the current file as a library document. Audit `hints.native.managed` / `hints.native.unmanaged`. |
| `native-root` | `[PATH]` | Without PATH: show the native Goose profile (Goose appdata folder). With PATH: move the native profile to that folder (must contain `config\`), update every native user that used the old one, audit `system.native_root`. Files are not copied. Restart the gateway afterwards. |
| `version` | | Prints the version. |

## 4. Settings stored in the database

Admins change these in the UI (Admin > Settings / Sign-in). They are stored in the `settings` table of
`<system_dir>/goose-web.db` (`api.py: admin_settings`, `admin_auth`, and `auth.py: AuthService`).

| Setting | Default | Meaning |
|---|---|---|
| `native_root` | set by `init` | The admin's native Goose profile folder. |
| `default_team_id` | the Everyone team | The team a new user joins when none is given: users created in the admin UI or API without `team`, users created with `user add`, and users auto-created by LDAP/OIDC when no group or claim maps to a team. Empty = new users have no team (they can sign in but cannot chat). |
| `brand` | `{name: "Goose Web", tagline: ...}` | `name`, `tagline`, `machine` (shown in Herd). |
| `session_hours` | config `auth.session_hours` | 1 to 720. |
| `allow_self_totp` | `true` | When false, non-admins cannot set up or enable TOTP themselves (`403 totp_self_disabled`). Admins can always enrol. |
| `require_totp_admins` | `false` | Admins cannot turn off their TOTP. It can only be switched on by an admin who already uses TOTP (`409 totp_needed_first`). The login response and `/api/me` report `totpEnrolmentRequired` for an admin without TOTP. Enrolment is not yet forced at sign-in. |
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
| `ldap.groupTeamMap` | `{}` | `{groupDn: teamId}`. One team per user: the mapped team replaces the previous one, and when several groups match the first one wins (audit `user.team.directory`). |
| `ldap.startTls` | `false` | StartTLS on `ldap://`. |
| `ldap.caFile` | `""` | CA bundle for a private CA. TLS uses certificate checking (`CERT_REQUIRED`). |
| `ldap.allowInsecure` | `false` | A plain `ldap://` URL without `startTls` is refused when the settings are saved (`400 bad_config`) and at sign-in (`503 ldap_insecure`, no bind is attempted), because it would send passwords in clear text. Setting this to `true` (admin UI checkbox "Allow unencrypted LDAP (not recommended)") allows it anyway. |
| `ldap.autoCreate` | `true` | Create users at their first sign-in. |
| `oidc[]` | `[]` | Providers: `id` (safe name), `label`, `issuer` (discovery at `<issuer>/.well-known/openid-configuration`), `clientId`, `clientSecret`, `scopes` (default `openid profile email`), `adminClaim`, `adminValue` (if empty, the claim must be `true`), `teamClaim` (matched against team names; the first match becomes the user's one team), `autoCreate` (default true), `stripDomain` (default true: `alice@x` becomes `alice`). Redirect URI: `<public_url>/api/auth/oidc/<id>/callback`. **Needs `server.public_url`.** An OIDC account is bound to the issuer + subject (`sub`) of its first sign-in. Existing unbound OIDC users are bound at their next sign-in. Another identity for the same name gets `oidc_conflict`, and local and LDAP accounts with that name are never taken over. |

## 5. Policies and teams

Policies apply to non-admins only. Admins get every permission with no lists and no run limit (`ADMIN_POLICY`).
Since 1.5.0 policies follow least privilege: a missing or false switch is off, an empty `allowed_modes`,
`allowed_providers` or `allowed_models` list allows **nothing**, and the value `"*"` (shown as **Any** in the admin
UI) allows everything. Keys of a team's `policy` (`goose_web/policy.py`):

| Key | Type | New team | Allows |
|---|---|---|---|
| `recipes_edit` | bool | false | save/delete recipes, recipe and subrecipe sources |
| `skills_edit` | bool | false | create/update/delete/import skill, agent and project sources |
| `extensions_edit` | bool | false | add/remove/enable extensions, pick extensions for a new session |
| `providers_edit` | bool | false | custom providers, provider config and secrets, defaults, model downloads, onboarding import |
| `schedules` | bool | false | create/update/delete/pause/run schedules |
| `apps` | bool | false | import/delete MCP Apps, direct `tools/call` |
| `prompts_edit` | bool | false | system prompts |
| `hints_edit` | bool | false | personal goose hints ("Members may add personal hints"); when false, personal hints are left out of the composed hints |
| `tools_permissions` | bool | false | per-tool permission settings |
| `config_edit` | bool | false | raw config read/write (treat it like `allow_shell`); `CONTEXT_FILE_NAMES` stays locked |
| `allow_shell` | bool | false | shell/code extensions (`developer`, `computercontroller`, `code_execution`, `orchestrator`), stdio MCP extensions, per-session MCP servers |
| `notify_webhook` | bool | false | a personal notification webhook |
| `allowed_modes` | list | `[]` = none | Goose modes (`session/set_mode`, `mode` option, `GOOSE_MODE`); `["*"]` = any |
| `allowed_providers` | list | `[]` = none | providers (`provider` option, `GOOSE_PROVIDER`, `defaults/save`); `["*"]` = any |
| `allowed_models` | list | `[]` = none | models (`model` option, `GOOSE_MODEL`, `defaults/save`); `["*"]` = any |
| `allowed_roots` | list | `[]` | extra folders besides the user's workspace and the team folder; absolute paths only, no `"*"` (`400 bad_folder`) |
| `max_concurrent_runs` | int | 3 | running agents per profile (0 = no limit; not set = 3) |
| `default_provider`, `default_model` | string | not set | the team default model, written into members' profiles (new members, and members still on the previous default) |
| `share_folder` | string | not set = `<profiles_root>/_teams/<team id>` | the team's shared folder; must be an absolute path (`400 bad_folder`) |

How the effective policy is built (`effective_policy`):

- **Admins**: `ADMIN_POLICY`; teams and overrides are ignored.
- **No team**: `DEFAULT_POLICY` (everything off, nothing allowed) and `chat_blocked` is set: the user can sign in
  and read chats but `session/new`, `session/fork` and `session/prompt` are refused.
- **One team** (a user has at most one): the team's policy laid over `DEFAULT_POLICY`. If the team allows no
  providers, models or modes, `chat_blocked` is set as well.
- **User overrides** (`policy_overrides`, Admin > Users) replace single keys last.

Every ACP method a non-admin sends goes through `policy.check`. Methods that are not on the list are denied. A
prompt in an existing chat is also refused when the chat's current provider, model or mode is not allowed
(`check_session_choice`).

Upgrading from 1.4 converts the stored policies once (schema version 4, `meta` key `policy_model` = 2): each team is
completed with the 1.4 defaults, empty mode/provider/model lists in teams and user overrides become `["*"]`, and a
user in several teams keeps the team with the lowest id (audit `team.migrate.membership`). See
[ADMINISTRATION.md](ADMINISTRATION.md#98-upgrading-from-14-the-policy-migration).

## 6. Profile layout

`goose_web/profiles.py`:

```
<profiles_root>/
  _system/                      config.yaml, goose-web.db (+ -wal/-shm)
    logs/                       gateway.log, worker-<user>.log
    library/teams/<id>/recipes/ team recipes (on members' GOOSE_RECIPE_PATH)
    backups/native-hints/       copies of the admin's .goosehints before a save from the UI
  _teams/<team id>/             a team's shared folder (unless the team sets share_folder)
  <user>/                       one isolated profile = GOOSE_PATH_ROOT of that user's worker
    config/                     config.yaml, secrets.yaml, .goose-web-hints.md (composed), custom_providers/, recipes/, skills/
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
  from the admin's config and sets `GOOSE_MODE: approve`. Without `allow_shell`, `developer`, `computercontroller`,
  `code_execution`, `orchestrator`, `summon` and `scheduler` are written disabled and team command extensions are
  left out; `extensionmanager` needs `extensions_edit` and `allow_shell` (ADMINISTRATION 11.1).
  After that, team items (recipes, skills, extensions, providers, with secrets copied from the source profile when
  the item came from a profile library), hints and default models are applied on every reprovision. Items the user
  created are never overwritten.
- Isolated workers get `GOOSE_DISABLE_KEYRING=1` (secrets in the profile's `secrets.yaml`), `GOOSE_RECIPE_PATH` =
  their team recipe folders, and no inherited `GOOSE_*` variables except `GOOSE_DISABLE_KEYRING` and
  `GOOSE_TELEMETRY_ENABLED`. They also get `CONTEXT_FILE_NAMES=[".goose-web-hints.md"]` (set after
  `goose.extra_env`), so Goose loads only the composed hints file and ignores `AGENTS.md` and `.goosehints` in
  working folders. Composition order: personal hints (only with `hints_edit`), documents assigned to the user, then
  the team's documents last, as the final word. A `config/.goosehints` written by Goose Web 1.4 is removed.
- Not relocatable by `GOOSE_PATH_ROOT`: home-folder skill and recipe folders such as `~/.agents/skills` and
  `~/.agents/recipes` are shared by every profile on the machine.
- Usernames: letters, digits, `.`, `_`, `-`, starting with a letter or digit, up to 64 characters, no Windows device
  names. Reserved names are refused (case-insensitive): `appdata`, `workspace`, `_system`, `_deleted`, `_teams`,
  `library`, `backups`, `logs` (see [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md) GW-04).
- Uploaded file names are sanitised (last path component only, no Windows-invalid characters, no trailing dots or
  spaces, device names such as `CON` get a `_` prefix). An existing file is never overwritten: the upload is saved as
  `name (1).ext`, `name (2).ext` and so on.

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
running when a `goose.exe` process exists that is not a CLI binary. A process counts as a CLI binary if its image
path ends in `\resources\bin\goose.exe`, if it is the configured `goose.binary`, or if there is no
`resources\app.asar` next to it. If the detection itself fails, the
gateway logs the error and treats Desktop as running, so the scheduler never runs twice.

Profiles that have jobs in `data/schedule.json` and own their scheduler are started even when nobody is connected,
are not stopped when idle, and are restarted with backoff (up to 5 minutes) after a crash.

## 8. Scripts

| Script | Run as | What it does |
|---|---|---|
| `scripts/install.ps1` | the normal Windows user, **not elevated** (it exits with code 3 when elevated unless `-AllowElevated`) | Creates `.venv` (uv, else `py -3`/`python -m venv`), installs the dependencies from `requirements.lock` with `--require-hashes`, then the package with `--no-deps`. Finds the Goose profile: `-GooseAppData`, else `%APPDATA%\Block\goose` if it has `config\`, else asks (Enter = fresh, `<ProfilesRoot>\appdata`). Writes `<ProfilesRoot>\_system\config.yaml` only if it is missing, and restricts the profiles root ACL to the installing user, SYSTEM and Administrators. Runs `init --admin <-Admin> --native-root <profile>` (random initial password, **shown once at the end of the installer output**, forced change at first sign-in; an existing installation keeps its password), then `check`, then `register-service.ps1` through one elevation prompt. Parameters: `-ProfilesRoot` (`C:\Goose_Web_Profiles`), `-GooseAppData`, `-BindHost` (`127.0.0.1`), `-Port` (8710), `-PublicUrl`, `-TrustedProxy` (added to loopback), `-FirewallRemoteAddress` (`LocalSubnet`), `-TaskPath` (`\GooseWeb\`), `-Admin` (`%USERNAME%`), `-NoService`, `-NonInteractive`, `-AllowElevated`. It never writes into the Goose profile folder. |
| `scripts/register-service.ps1` | elevated | Registers the logon task and the firewall rule (section 9). Parameters: `-User`, `-InstallDir`, `-ConfigPath` (required), `-Port`, `-TaskPath`, `-TaskName` (`GooseWeb_Gateway`), `-FirewallRemoteAddress` (comma separated, `LocalSubnet`), `-NoFirewall`, `-NoTask`. |
| `scripts/uninstall.ps1` | elevated | Stops and removes the task and the firewall rule (`-Port`, `-TaskPath`, `-TaskName`). Profiles, database and logs are kept. |
| `scripts/start-gateway.cmd` | the normal user | Runs `.venv\Scripts\python.exe -m goose_web <args> serve` in the foreground. Pass `--config FILE` or set `GOOSE_WEB_CONFIG`. |

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
