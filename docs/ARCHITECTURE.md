# Goose Web architecture

This document explains how Goose Web (the "Goose AI Web Interface") works
internally. It is written for developers who want to change the code and for
operators who need to understand what runs where, which process owns which
files, and where the security boundaries are.

Everything here describes the code in this repository. Where a feature is still
being built, the section says so explicitly.

Related documents:

| Document | Contents |
|---|---|
| `README.md` | Feature list, quick start, deployment options |
| `docs/CONFIGURATION.md` | Every configuration key, precedence, profile layout, scheduler ownership, Docker |
| `docs/API.md` | REST endpoints and the `/ws` real-time channel |
| `docs/acp-reference.md` | Agent Client Protocol methods, agent requests and notifications used by Goose |
| `docs/SECURITY-ASSESSMENT.md` | Threat model, STRIDE analysis, findings, hardening checklist |
| `USER-GUIDE.md` | End-user guide (separate document) |
| `ADMINISTRATION.md` | Administration guide (separate document) |
| `TROUBLESHOOTING.md` | Troubleshooting guide (separate document) |

## Contents

1. [Overview](#1-overview)
2. [File-by-file map](#2-file-by-file-map)
3. [Process model and worker lifecycle](#3-process-model-and-worker-lifecycle)
4. [Startup and shutdown](#4-startup-and-shutdown)
5. [HTTP request flow](#5-http-request-flow)
6. [WebSocket flow and ACP relay](#6-websocket-flow-and-acp-relay)
7. [The hub](#7-the-hub)
8. [Front end](#8-front-end)
9. [Service worker](#9-service-worker)
10. [Data model](#10-data-model)
11. [Profiles on disk](#11-profiles-on-disk)
12. [Security layers](#12-security-layers)
13. [Configuration loading](#13-configuration-loading)
14. [Packaging, deployment and CI](#14-packaging-deployment-and-ci)
15. [Testing layout](#15-testing-layout)
16. [Extension points: adding a feature](#16-extension-points-adding-a-feature)

---

## 1. Overview

Goose Web is a multi-user gateway and browser interface for the Goose agent.
The browser loads a single-page application (vanilla ES modules, no build step)
from the gateway, a Python ASGI application built on Starlette and served by
uvicorn. The gateway authenticates the user, applies that user's policy, and
relays Agent Client Protocol (ACP) JSON-RPC messages between the browser and a
`goose serve` process. Each user profile gets its own `goose serve` worker,
bound to `127.0.0.1` on a random port and protected by a per-worker secret.
Workers start on demand, keep running while a chat is active or schedules
need them, and stop after a period of idleness. The gateway keeps one
persistent upstream WebSocket per profile and shares it between all of that
user's browser tabs. Closing a tab therefore never cancels a running agent,
and a tab that joins late gets the session's buffered updates replayed. The
Goose workers talk to the LLM providers and start the MCP extensions. Goose
Web never calls a model itself.

```
 +-------------------+        HTTPS / WSS         +----------------------+
 |  Browser (SPA/PWA)|  <---------------------->   |  Reverse proxy (TLS) |
 |  tabs of alice    |                             |  e.g. goose.example  |
 |  tabs of bob      |                             |  .org  (optional)    |
 +-------------------+                             +----------+-----------+
                                                              |
                                          HTTP + WebSocket /ws | (loopback or LAN)
                                                              v
 +--------------------------------------------------------------------------+
 |  goose-web gateway  (Starlette app under uvicorn, default port 8710)     |
 |                                                                          |
 |  SecurityHeaders > GZip > HostGuard > IPBlockGuard > routes               |
 |  REST API (api.py)        /ws endpoint (app.py)                          |
 |  auth.py  policy.py  profiles.py                                         |
 |  db.py (SQLite: <system_dir>/goose-web.db)                              |
 |  hub.py: one Upstream per profile, session buffers, asks, herd           |
 |  workers.py: spawns and monitors one `goose serve` per profile           |
 +---------------+-----------------------------------+----------------------+
                 | ws://127.0.0.1:<random>/acp       | ws://127.0.0.1:<random>/acp
                 | header X-Secret-Key: <secret>     | header X-Secret-Key: <secret>
                 v                                   v
 +-------------------------------+   +-------------------------------+
 | goose serve (profile "alice") |   | goose serve (profile "bob")   |
 | GOOSE_PATH_ROOT=              |   | GOOSE_PATH_ROOT=              |
 |   <profiles_root>/alice       |   |   <profiles_root>/bob         |
 +---------------+---------------+   +---------------+---------------+
                 |                                   |
        +--------+---------+                 +-------+----------+
        v                  v                 v                  v
 +-------------+   +----------------+  +-------------+  +----------------+
 | LLM provider|   | MCP extensions |  | LLM provider|  | MCP extensions |
 | (HTTPS API) |   | (stdio / HTTP) |  | (HTTPS API) |  | (stdio / HTTP) |
 +-------------+   +----------------+  +-------------+  +----------------+
```

The main ideas:

| Concept | Where | Summary |
|---|---|---|
| Profile | `profiles.py`, `workers.py` | A Goose configuration root. Every user has one. It is either *isolated* (`<profiles_root>/<username>`, provisioned by the gateway) or *native* (the operating-system user's normal Goose directory, used by the installing administrator). |
| Worker | `workers.py` | One `goose serve` process per profile, loopback only, random port, random secret. |
| Upstream | `hub.py` | One persistent ACP WebSocket from the gateway to a worker, shared by all tabs of that profile. |
| Client | `hub.py` | One browser tab connected to `/ws`. |
| Herd | `hub.py`, `static/js/herd.js` | The list of agents (sessions) that are working, need the user, finished, or failed. The gateway derives it from the ACP stream. |
| Ask | `hub.py`, `static/js/asks.js` | An agent-to-client request (permission, elicitation, recipe parameters). It is fanned out to every tab, and the first answer wins. |
| Policy | `policy.py` | Per-user effective permissions: the user's one team over a least-privilege base, then per-user overrides. Enforced by a default-deny ACP method firewall. |

## 2. File-by-file map

### Back end (`goose_web/`)

| File | Responsibility |
|---|---|
| `__init__.py` | Package version. |
| `__main__.py` | CLI: `python -m goose_web [--config FILE] serve|init|user|check|version`. Logging setup, first-run initialisation (database, native root, first admin, `Everyone` team), user management, environment checks, `uvicorn.run`. |
| `config.py` | `Settings`: built-in defaults, then `config.yaml`, then `GOOSE_WEB__SECTION__KEY` environment variables. Goose binary auto-detection, default native Goose root. |
| `app.py` | ASGI app factory `create_app`: middleware (`SecurityHeaders`, `GZipMiddleware`, `HostGuard`, `IPBlockGuard`), static and SPA routes, `/ws` endpoint, lifespan, webhook SSRF guard and sender, event/audit handlers wired into the hub. |
| `context.py` | `Ctx` (shared services), `HTTPError`, request helpers: identity resolution, `require()` (auth, CSRF, origin, role), allowed origins, client IP, policy and roots for a user, `upstream_for(user)`, `body_json`. |
| `api.py` | All REST handlers and the `routes` list: auth, current user, preferences, TOTP, API tokens, hints, notifications, file system, MCP App frames, herd, and every `/api/admin/*` endpoint. |
| `sandbox.py` | Spec 012: per-user AppContainer (create/derive, folder grants with icacls, `CreateProcess` with `SECURITY_CAPABILITIES` and an inherited-handle allow-list, suspended start + job object) and `StdioChannel`, the newline-delimited JSON-RPC transport the hub uses instead of a WebSocket for sandboxed (`goose acp`) workers. |
| `hub.py` | `Hub`, `Upstream`, `Client`, `SessionState`: relays ACP, rewrites ids, buffers and replays session updates, fans out asks, derives herd status, watches for external changes, audits calls. |
| `workers.py` | `WorkerManager` and `Worker`: spawns, health-checks, restarts and idles out `goose serve`; scheduler ownership; worker logs; Windows Job Object; Goose Desktop detection. |
| `policy.py` | Least-privilege default, legacy (1.4) and admin policies, `effective_policy` (one team + overrides), chat gating (`chat_block`, `check_session_choice`), team warnings (`team_warnings`), roots (`user_roots`), path containment (`path_allowed`), and the ACP method firewall (`check`). |
| `auth.py` | `AuthService`: local passwords, LDAP/Active Directory, OIDC (authorization code with PKCE), TOTP, lockout and rate limits, cookie sessions, API tokens. |
| `ipblock.py` | `IPBlocker`: counts failed sign-ins per client address (IPv4, or IPv6 /64) in the `ip_blocks` table, blocks after `auth.ip_block_threshold` in a row within the window, expiry, unblock, listing; in-memory cache of blocked keys refreshed every 15 s. |
| `security.py` | Stdlib-only primitives: scrypt password hashing, strong-password rules, `ip_in`, tokens, constant-time compare, TOTP, `RateLimiter`, `safe_name`. |
| `db.py` | SQLite storage (WAL), schema, additive migrations, JSON column decoding, audit log and retention purge. |
| `profiles.py` | Profile layout, provisioning of isolated profiles from team items, team folders, hints composition (`.goose-web-hints.md`), cross-profile library and item export, profile archiving. |
| `winsec.py` | Windows token helpers: elevation and integrity checks, un-elevated relaunch (SAFER), file ownership reports. Safe no-ops on other platforms. |
| `hosttasks.py` | Admin view of Windows scheduled tasks with an elevation-risk flag; run/end/enable/disable actions. Returns nothing on other platforms. |

### Front end (`goose_web/static/`)

| File | Responsibility |
|---|---|
| `index.html` | Shell page: theme stylesheets, `modulepreload` of `js/app.js`, boot spinner. |
| `manifest.webmanifest` | PWA manifest. |
| `sw.js` | Service worker (`gw-shell-v10`): offline shell, network-first for app code, cache-first for vendor files. |
| `css/app.css` | All styles and themes. |
| `icons/` | `goose.svg`, `goose-maskable.svg`. |
| `vendor/` | Vendored libraries (marked, DOMPurify, highlight.js, qrcode-generator) with `README.md` and `SHA256SUMS`. |
| `js/app.js` | Entry point: boot and login flow, shell layout, route table, RPC event wiring, command palette, keyboard shortcuts, service worker registration. |
| `js/store.js` | `Emitter`, `Store`, the global `store` and `bus`, policy helpers. |
| `js/router.js` | Hash router (`#/view/arg?query`). |
| `js/rpc.js` | Reconnecting JSON-RPC client over `/ws`. |
| `js/api.js` | `fetch` wrapper for the REST API (CSRF header, errors, uploads). |
| `js/prefs.js` | User preferences (server-stored, cached in `localStorage`), themes. |
| `js/chatoptions.js` | Per-chat options shared by the chat header and the New chat screen: `pillSelect`, Goose's approval `MODES`, the learned thinking-effort values (`localStorage` `gw-effort-options`), `loadNewChatOptions()` and `applyNewChatOptions()` (spec 008). |
| `js/chatsession.js` | `ChatSession`: per-session controller. Maps ACP updates to transcript calls. Handles send, queue, steer, cancel and modes. |
| `js/transcript.js` | `Transcript`: incremental, windowed rendering of messages, thoughts, tool cards, plans, asks and inline MCP Apps. |
| `js/composer.js` | Message input: slash commands, @mentions, attachments, send/stop/steer/queue. |
| `js/asks.js` | Permission, elicitation and recipe-parameter cards and their answers. |
| `js/herd.js` | Herd store, status transitions, browser notifications, title and favicon badges. |
| `js/sessions.js` | Session list loading, paging, refresh, grouping by folder. |
| `js/markdown.js` | Markdown rendering (marked, then DOMPurify), code highlighting and copy buttons. |
| `js/cron.js` | Cron presets, validation, description, editor widget. |
| `js/ui.js` | DOM helpers (`h()`), buttons, modals, toasts, menus, dialogs, tables, tabs, formatting. |
| `js/icons.js` | Inline SVG icon set. |
| `js/views/*.js` | One module per screen: `home`, `chat`, `herd`, `recipes`, `skills`, `schedules`, `apps`, `extensions`, `settings`, `admin`, `login`, `sidebar`, `folderpicker`. |

### Packaging, deployment and tests

| Path | Responsibility |
|---|---|
| `pyproject.toml` | Package metadata (`goose-web`, Python >= 3.11), dependencies, `goose-web` console script, hatchling build, pytest settings. |
| `requirements.lock` | Hash-locked dependency set generated by `pip-compile --generate-hashes`. |
| `docker/Dockerfile` | Image with the gateway and a checksum-verified `goose` CLI. |
| `docker/compose.yaml` | Hardened Compose service definition. |
| `docker/entrypoint.sh` | First-start initialisation and command dispatch inside the container. |
| `scripts/install.ps1`, `scripts/install.sh` | Installers for Windows (current non-elevated user) and Linux/macOS (non-root). |
| `scripts/register-service.ps1`, `scripts/uninstall.ps1`, `scripts/start-gateway.cmd` | Windows logon task and firewall rule, removal, foreground start. |
| `.github/workflows/ci.yml`, `.github/dependabot.yml` | CI test matrix, dependency audit, dependency update automation. |
| `tests/` | pytest suite (see [section 15](#15-testing-layout)). |

---

## 3. Process model and worker lifecycle

### 3.1 Processes

| Process | Count | Runs as | Listens on |
|---|---|---|---|
| Gateway (`python -m goose_web serve`) | 1 | The operating-system user that installed Goose Web, never elevated or root | `server.host:server.port` (default `127.0.0.1:8710`) |
| `goose serve` worker | 0..1 per profile | Same user as the gateway | `127.0.0.1:<random port>`, path `/acp` |
| MCP extensions | Started by each worker | Same user | Whatever the extension uses (stdio children, HTTP) |

All Goose processes run under the gateway's own operating-system account.
Users are separated by Goose configuration root (`GOOSE_PATH_ROOT`), by the
policy firewall, and by path checks. They are not separated by
operating-system accounts. `docs/SECURITY-ASSESSMENT.md` discusses what this
means.

### 3.2 Registering and starting a worker

`Ctx.upstream_for(user)` (`context.py`) is the single entry point:

1. The key is the lower-cased username.
2. For an isolated profile, if `<profiles_root>/<username>/.goose-web/managed.json`
   is missing, the profile is provisioned first (see [section 11](#11-profiles-on-disk)).
3. `WorkerManager.register(key, username, path_root_env, native, recipe_dirs)`
   records the worker definition. `path_root_env` is `None` when the native
   profile is the Goose default location. `recipe_dirs` lists the team recipe
   library folders (isolated profiles only). If the root or the recipe folders
   change while the worker is `ready`, `restart_pending` is set.
4. `Hub.upstream(key, username)` returns, or creates, the `Upstream` for that
   profile.

The process starts lazily. `Upstream.ensure()` calls `WorkerManager.ensure(key)`,
which runs `_start()` under the worker's lock:

```python
args = [binary, "serve", "--host", "127.0.0.1", "--port", str(port),
        "--platform", "desktop"]
if scheduler:
    args.append("--enable-scheduler")
```

- **Port.** The worker binds a socket to `127.0.0.1:0`, reads the assigned
  port and closes the socket.
- **Secret.** `secrets.token_urlsafe(32)`, passed to Goose as
  `GOOSE_SERVER__SECRET_KEY`. The hub sends it as `X-Secret-Key` when it
  connects.
- **Environment** (`_env`). A copy of the gateway environment, minus
  `GOOSE_WEB_UNELEVATED`. For isolated profiles, every `GOOSE_*` variable is
  removed except `GOOSE_DISABLE_KEYRING` and `GOOSE_TELEMETRY_ENABLED`. Then
  `GOOSE_DISABLE_KEYRING=1` is set, so secrets go to the profile's
  `secrets.yaml` and not to the shared OS keyring, and `GOOSE_RECIPE_PATH` is
  set to the team recipe folders. `GOOSE_PATH_ROOT` is set to the profile root,
  or removed for the default native root. `goose.extra_env` from the
  configuration is applied next. Finally, for isolated profiles,
  `CONTEXT_FILE_NAMES` is set to `[".goose-web-hints.md"]`, so Goose loads
  only the composed hints file and ignores `AGENTS.md` and `.goosehints` in
  working folders and the agents home folder (`extra_env` cannot override
  it).
- **Working directory.** The profile root, or the home directory.
- **Process group.** On Windows the worker gets
  `CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP` and is added to a kill-on-close
  Job Object. On POSIX it gets `start_new_session=True`, so it leads its own
  process group.
- **Readiness.** The gateway polls `GET http://127.0.0.1:<port>/status` every
  0.25 s until it returns 200, for up to `goose.start_timeout_seconds`
  (default 45 s). On timeout the process is killed and the state becomes
  `crashed`.

Worker states: `stopped`, `starting`, `ready`, `crashed`.

### 3.3 Logs

| Log | Location | Rotation |
|---|---|---|
| Gateway | `<system_dir>/logs/gateway.log`, plus stderr | `RotatingFileHandler`, 5 MB x 5 |
| Worker | `<system_dir>/logs/worker-<key>.log` (worker stdout and stderr) | Rotated before each start at about 10 MB, 3 backups. A header line is written on every start. |

The level comes from `GOOSE_WEB_LOG_LEVEL`. The `httpx`, `httpcore`, `websockets`
and `uvicorn.access` loggers are held at WARNING. Admins can read the tail of
either log through `GET /api/admin/logs?worker=<key>&lines=<n>` (10 to 5000
lines).

### 3.4 Stopping

`_kill()` stops the whole process tree, so MCP children go with the worker:

- Windows: `taskkill /PID <pid> /T /F`.
- POSIX: `os.killpg(pid, SIGTERM)`, then a 10 s wait, then kill.

On gateway shutdown `WorkerManager.shutdown()` stops every worker. On Windows
the Job Object (`JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`) also guarantees that
workers die if the gateway process dies unexpectedly.

### 3.5 The monitor loop

`WorkerManager.start_monitor()` runs `_monitor()` every 15 seconds. For each
worker it asks the hub for `activity(key)`, a pair of counts (connected
clients, running sessions), and then applies these rules in order:

| Condition | Action |
|---|---|
| Process exited while `ready` | State becomes `crashed`, last error recorded, hub upstream reset (pending calls fail, running sessions become `error`). |
| `crashed` and (clients connected, or the profile has schedules and owns the scheduler) | Restart with exponential backoff: `min(300, 2 ** min(restarts, 8))` seconds. |
| `stopped`, the profile has jobs in `<root>/data/schedule.json`, and it owns the scheduler | Start it so schedules fire with nobody connected, then notify the hub (`on_restart`). |
| `ready` and (scheduler ownership changed, or `restart_pending`) and no running sessions | Restart. |
| `ready`, no clients, no running sessions, not needed for schedules, and unused longer than `goose.idle_minutes` (default 30) | Stop (reason `(idle)`). |

Running sessions are never interrupted by an idle stop or a pending restart.

### 3.6 Scheduler ownership

Only one process should run a profile's Goose schedules.

- **Isolated profiles** always run their own scheduler (`--enable-scheduler`).
- **The native profile** follows `goose.native_scheduler`:
  - `on`: the worker always runs the scheduler.
  - `off`: it never does.
  - `auto` (the default): the worker runs the scheduler only while Goose
    Desktop is not running.

`desktop_running()` scans processes (Toolhelp32 on Windows) for a `goose.exe`
that is the Desktop application. That means its image has `resources/app.asar`
next to it, and it is not the CLI under `resources\bin` or the configured
binary. The result is cached for 20 s. If the check fails, it assumes Desktop
is running, so two schedulers are never started. When Desktop starts or stops,
the monitor sees a scheduler mismatch and restarts the worker once it has no
running sessions. `GET /api/me` reports the result as
`scheduler {enabled, owner: gateway|desktop, reason}`.

### 3.7 Windows specifics (`winsec.py`)

Goose must not run elevated. Files written under an elevated token become owned
by `BUILTIN\Administrators`, and the normal user then loses access to their own
sessions and configuration.

- `ensure_unelevated(allow_elevated)` runs first in `cmd_serve`. If the process
  is elevated and `server.allow_elevated` is false:
  - POSIX: exit 3 with "goose-web refuses to run as root".
  - Windows: set `GOOSE_WEB_UNELEVATED=1` and relaunch `python -m goose_web <args>`
    through `run_unelevated()`, then exit with the child's code. If the
    relaunched process is still elevated (the variable is already set), exit 3.
- `run_unelevated()` uses the same technique as `runas /trustlevel:0x20000`:
  `SaferCreateLevel(SAFER_LEVELID_NORMALUSER)`, then
  `SaferComputeTokenFromLevel`. It sets the token integrity to Medium
  (`S-1-16-8192`) and the token owner to the user SID, then calls
  `CreateProcessAsUserW`. On failure it raises `OSError` and never falls back
  to an elevated launch.
- `is_elevated()`, `integrity_level()`, `current_user()` and `file_owner()` feed
  `python -m goose_web check` and `GET /api/admin/system`.
  `ownership_report(root)` lists up to 200 files under a profile (scanning at
  most 20,000, skipping `node_modules`, `.git` and `__pycache__`) that are not
  owned by the current user (`GET /api/admin/ownership`).
- `hosttasks.py` lists Windows scheduled tasks with PowerShell `Get-ScheduledTask`
  (cached 15 s, `\Microsoft\*` always excluded, filter from
  `host_tasks.path_filter`). It flags elevation risk: SYSTEM, LOCAL SERVICE or
  NETWORK SERVICE accounts, `RunLevel Highest`, and Password, S4U or
  ServiceAccount logon types. Actions (`run`, `end`, `enable`, `disable`) pass
  the task path and action through environment variables, not by string
  interpolation. The path must start with `\`, must not be under
  `\Microsoft\`, and must not contain CR, LF or NUL. A task's principal is
  never changed.

---

## 4. Startup and shutdown

`create_app(settings)` builds the Starlette application. Its lifespan handler:

1. Creates `<system_dir>`.
2. Opens `Database(<system_dir>/goose-web.db)`. This runs migrations and the
   audit purge.
3. Creates `WorkerManager`, `Hub(workers)`, `Profiles` and the `Ctx`, and reads
   the Goose version (`goose --version`, 20 s timeout).
4. Wires hub callbacks: `on_audit` (writes audit rows), `on_event` (webhook
   notifications), and `profile_root_for` (used by the external-change watcher).
5. Starts the hub flush loop (`hub.start()`) and the worker monitor.
6. Calls `upstream_for(user)` for every user who is not disabled. This
   registers every profile, so profiles with schedules get their workers
   started by the monitor even when nobody is signed in.
7. Writes the audit record `system.start`.

On shutdown it stops all workers, writes `system.stop` and closes the
database.

`cmd_serve` then calls `uvicorn.run` with `proxy_headers=False` (forwarded
headers are handled by the gateway's own trusted-proxy logic),
`ws_max_size=64 MB`, `ws_ping_interval=25`, `ws_ping_timeout=60`,
`timeout_keep_alive=30`, `server_header=False` and
`timeout_graceful_shutdown=10`.

---

## 5. HTTP request flow

### 5.1 Middleware order

```
request -> SecurityHeaders -> GZipMiddleware(min 1024 B, level 5) -> HostGuard -> IPBlockGuard -> router
```

`HostGuard` and `IPBlockGuard` are the innermost middleware, so their `400 invalid host` and
`403 ip_blocked` responses still pass through `SecurityHeaders`.

**IPBlockGuard.** For HTTP and WebSocket scopes (except `GET`/`HEAD /healthz`) it takes the context from
`scope["app"].state.ctx`, computes `Ctx.client_ip` on an `HTTPConnection` and asks
`AuthService.ipblock.is_blocked`. A blocked address gets `403` (JSON `{"error":"ip_blocked"}` under `/api/`,
plain text otherwise) or a WebSocket denial response. Before the lifespan has created the context, it passes
everything through.

**HostGuard.** It normalises the `Host` header (`host_only()`: strips the port
and IPv6 brackets, lower-cases, removes a trailing dot) and refuses any host
that is not allowed. The allow-list is:

- `localhost`, `127.0.0.1`, `::1`;
- the host name of `server.public_url`;
- the bind address, unless it is a wildcard (`''`, `0.0.0.0`, `::`, `*`);
- every entry in `server.allowed_hosts`;
- a host passed with `serve --host`.

`X-Forwarded-Host` is checked only when the peer is a trusted proxy, and then
every value must be allowed. WebSocket requests are refused with a denial
response or close code 1008. `GET` and `HEAD` on `/healthz` are exempt, so
container health checks work.

**SecurityHeaders.** Every response gets:

- `X-Content-Type-Options: nosniff`
- `Referrer-Policy: same-origin`
- `Cross-Origin-Opener-Policy: same-origin`
- `Cross-Origin-Resource-Policy: same-origin`
- a `Permissions-Policy` that disables camera, geolocation, payment and USB,
  and allows the microphone for the page itself only.

It also adds the SPA Content Security Policy and `X-Frame-Options: DENY`, but
only when the handler has not set its own. The MCP App frame and file
download endpoints set their own. It adds `Cache-Control: no-store` on
`/api/*`, and HSTS (one year) when `public_url` is `https`.

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data: blob:; media-src 'self' data: blob:; connect-src 'self';
frame-src 'self'; font-src 'self' data:; worker-src 'self'; manifest-src 'self';
object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'
```

### 5.2 Routes

| Route | Handler |
|---|---|
| `/`, `/index.html` | SPA shell, `Cache-Control: no-cache` |
| `/sw.js` | Service worker, `no-cache`, `Service-Worker-Allowed: /` |
| `/manifest.webmanifest` | PWA manifest |
| `/static/*` | Static files, `no-cache` (revalidated, served from cache when unchanged) |
| `/healthz` | Liveness |
| `/api/*` | `api.routes` (see `docs/API.md`) |
| `/ws` | WebSocket, `app.ws_endpoint` |

### 5.3 Authentication and CSRF in a handler

Every protected handler starts with `c.require(request, admin=..., allow_pw_change=...)`
(`context.py`):

1. `identity()`: an `Authorization: Bearer gwt_...` header resolves an API
   token. Otherwise the session cookie (`__Host-gw` when `public_url` is
   `https`, otherwise `gw`) resolves a cookie session. If neither resolves,
   the result is `401 unauthorized`.
2. For cookie sessions on methods other than GET, HEAD and OPTIONS:
   - If an `Origin` header is present, it must be one of the allowed origins,
     otherwise `403 bad_origin`.
   - The `X-CSRF-Token` header must match the session's CSRF token in
     constant time, otherwise `403 csrf`.
3. A user with `must_change_pw` gets `403 password_change_required`, except on
   endpoints that pass `allow_pw_change=True` (`GET /api/me` and
   `POST /api/me/password`).
4. `admin=True` requires `role == 'admin'`, otherwise `403 forbidden`.

Allowed origins come from `server.allowed_origins`. When `public_url` is set,
they also include `public_url` and its origin, and the request `Host` is
ignored. When `public_url` is not set, they include
`<scheme>://<Host header>`, plus the `X-Forwarded-Proto`/`X-Forwarded-Host`
variant, but only when the request comes from a trusted proxy.

The client IP (used for rate limits and audit) is the peer address. When the
peer is in `server.trusted_proxies`, it is the right-most `X-Forwarded-For`
entry instead.

### 5.4 Bodies and errors

- `body_json(request, limit=2 MB)` returns `413 too_large` for oversized
  bodies and `400 bad_json` when the body is not a JSON object. Some endpoints
  use smaller or larger limits (login 16 KB, preferences 64 KB, team items 8 MB).
- Handlers raise `HTTPError(status, code, message, **extra)`. It is rendered as
  `{"error": code, "message": ..., ...}`.
- App-level exception handlers: unknown `/api/*` paths return JSON 404,
  `ValueError` returns `400 bad_request`, and anything else returns
  `500 server_error`.
- `ok(data)` returns JSON with `Cache-Control: no-store`.

### 5.5 REST endpoints that reach the agent

Most agent features go over the WebSocket. Two REST paths call ACP directly
through `_acp_request()`. That helper runs `policy.check()` exactly like the
hub and audits denials as `acp.denied`:

- `GET /api/apps/frame?uri=ui://...&sessionId=...&ext=...` reads an MCP App
  resource (`_goose/unstable/resources/read`).
- `GET /api/apps/frame?name=...` exports a stored app (`_goose/unstable/apps/export`).

Both return the HTML with the app frame CSP described in
[section 12.8](#128-mcp-apps).

---

## 6. WebSocket flow and ACP relay

### 6.1 Handshake (`app.ws_endpoint`)

The browser opens `wss://<host>/ws`. The handshake is authenticated before
`accept()`:

| Credential | Requirement |
|---|---|
| API token | `Authorization: Bearer gwt_...` header **and no `Origin` header** (non-browser clients only). Tokens in the query string are not accepted. |
| Cookie session | `Origin` must be one of the allowed origins (cross-site WebSocket hijacking protection). |

The gateway refuses the handshake (close code 4401 before accept, which the
browser sees as HTTP 403) if neither credential resolves or the user still has
to change their password. An admin may add `?profile=<name>` to attach to
another user's profile. Non-admins get 4403, and an unknown profile gets 4404.
Every such impersonation is audited as `ws.impersonate`, and every ACP call
made on another user's profile is audited.

After accept, the endpoint creates a `Client` (send function, user, effective
policy, allowed roots, IP), attaches it to the profile's `Upstream` with
`hub.attach`, and loops:

- It reads a text frame. Frames over 64 MB end the loop.
- It parses the JSON and requires an object.
- It calls `await upstream.from_client(client, msg)`.
- Exceptions become a JSON-RPC error `-32603` for that message id.
- On exit it calls `hub.detach(client)`.

Detaching never cancels anything upstream.

Each `Client` has an outbound `asyncio.Queue(maxsize=20000)` drained by a pump
task. If a tab stops reading and its queue fills, that client is closed. A
stuck tab therefore cannot block the profile.

### 6.2 The upstream connection

`Upstream.ensure()` starts the worker if needed, then connects:

```python
websockets.connect(worker.url,                     # ws://127.0.0.1:<port>/acp
                   additional_headers={"X-Secret-Key": worker.secret},
                   max_size=64 MB, ping_interval=20, ping_timeout=60,
                   open_timeout=20, compression=None)
```

It sends `initialize` once with the gateway's own capabilities and caches the
result:

```python
INIT_PARAMS = {
  "protocolVersion": 1,
  "clientCapabilities": {"elicitation": {"form": {}}, ...},
  "_meta": {"goose": {
      "mcpHostCapabilities": {"extensions": {"io.modelcontextprotocol/ui":
                              {"mimeTypes": ["text/html;profile=mcp-app"]}}},
      "customNotifications": True,
      "recipeParameterRequests": True}},
  "clientInfo": {"name": "goose-web", "version": ...},
}
```

State changes are broadcast to the profile's clients as
`_gw/upstream {state: starting|ready|down, error}`. When the connection drops
or the worker restarts, `_fail_all()` does the following:

- fails every pending request with `-32000`;
- resolves every open ask with `_gw/ask_resolved {by: "worker-restart"}`;
- marks running sessions `error`;
- clears the buffers.

### 6.3 Message routing from a tab (`Upstream.from_client`)

| Message from tab | Handling |
|---|---|
| Response (has `id`, no `method`) | An answer to an ask. Goes to `_answer_ask` (see [7.4](#74-asks-fan-out-first-answer-wins)). |
| `_gw/*` method | Handled by the gateway itself (`Hub.gw_method`). Never forwarded. |
| Any other method | `policy.check(method, params, is_admin, policy, roots)`. A denial is audited as `acp.denied` and answered with `{"code": -32003, "message": "forbidden: <reason>"}`. |
| `initialize` | Answered from the cached upstream `initialize` result. Tabs never re-initialise the shared agent. |
| `recipes/delete` (non-admin) | `_guard_recipe_delete`: team recipes that live outside the user's profile root are refused ("team recipes are managed by your administrator"). |
| `session/prompt` | `_check_concurrency`: refused when the user already has `max_concurrent_runs` sessions running (0 means unlimited). On success, `prompts` is incremented, the status becomes `working`, and each prompt block is echoed as a synthetic `user_message_chunk` (with `_meta.gw = {synthetic: true, by: <username>}`). The echo is buffered and sent to the other tabs watching the session, so they see the prompt immediately. |
| `session/load` | Replay logic (see [7.3](#73-buffering-and-replay)). |
| Other requests | Forwarded with a new upstream id. `pending[up_id] = (client, original_id, ...)` maps the response back. |
| Other notifications (for example `session/cancel`) | Forwarded as they are. |

Every forwarded call is passed to `audit_call`. Calls whose method starts with
one of the `AUDITED_PREFIXES` are written to the audit log, except quiet
read-only suffixes (`/list`, `/read`, `/get`, `/status`, `config/read-all`).
Audited prefixes include configuration writes, provider and secret changes,
recipe save/delete, schedule create/delete, app import/delete, source changes,
tool permission changes, `tools/call`, extension adds, defaults, and session
delete.

### 6.4 Gateway methods (`_gw/*`)

| Method | Direction | Purpose |
|---|---|---|
| `_gw/hello` | tab -> gateway | Returns `{user {username, role}, profile, agent (cached initialize result), asks (raw pending ask messages), herd, upstream {state, error}}`. The SPA calls it on every (re)connect. |
| `_gw/watch {sessionIds}` | tab -> gateway | Replaces the set of sessions this tab receives updates for (max 200). |
| `_gw/herd {all}` | tab -> gateway | Returns the herd. `all: true` (admin only) returns every profile's agents and subscribes the tab to all herd updates. |
| `_gw/seen {sessionId}` | tab -> gateway | Acknowledges a `done` or `error` session, which goes back to `idle`. |
| `_gw/upstream` | gateway -> tab | Worker connection state. |
| `_gw/herd_update {agent}` | gateway -> tab | One agent changed (status, text, usage, ask). |
| `_gw/ask_resolved {id, by}` | gateway -> tab | An ask was answered in another tab, or cancelled by a worker restart. |
| `_gw/sessions_changed` | gateway -> tab | The profile's session database changed on disk. Refresh the list. |
| `_gw/prompt_created {sessionId, created}` | gateway -> tab | Sent only to the tab that sent a `session/prompt`: the server time (unix seconds) the gateway stamped on that prompt. The same value is in the prompt's echo (`_meta.goose.created`) for other tabs and replays. Needed to edit the prompt later (1.6.0). |
| `_gw/session_changed {sessionId, messageCount, updatedAt, title}` | gateway -> tab | A buffered session was changed by another client (for example Goose Desktop). |

Unknown `_gw/*` methods return `-32601 unknown gateway method`. The SPA also
handles a `_gw/notice` toast message, but the server code does not currently
send it.

### 6.5 What the policy firewall checks

`policy.check()` is default-deny. Section [12.6](#126-policy-enforcement)
covers the full rules. In short:

- `session/new` always gets `_meta.client = "goose-web"`, and `_meta.hidden`
  is removed. Inline `mcpServers` require `allow_shell`, and
  `_meta.enabledExtensions` requires `extensions_edit`.
- `tools/call` must name a tool whose `<ext>__` prefix matches its
  `extensionName`. This applies to every user, including admins.
- Admins are allowed everything else.
- For other users:
  - `cwd`/`additionalDirectories` on session new, load, fork and resume, and
    `session/working-dir/update`, must be inside the user's roots.
  - Modes, providers and models must be on the allow-lists.
  - A fixed `ALWAYS` set of read and session methods is allowed.
  - Other methods need the matching permission (`BY_PERMISSION`).
  - Anything not listed is denied.

---

## 7. The hub

`hub.py` is the core of the gateway. A `Hub` holds one `Upstream` per profile.
Each `Upstream` has its clients, the pending request map, pending asks, and a
`SessionState` per known session.

### 7.1 Per-session state

```python
class SessionState:
    sid, title, cwd
    status        # idle | working | needs_you | done | error
    since         # time of last status change
    run_id        # Goose activeRunId while a run is active
    last_text     # short preview for the herd (last 300 characters)
    usage         # {used, contextLimit, cost}
    buffer        # deque of raw session notifications
    buffer_bytes, truncated
    loaded, load_result, loading_client
    prompts       # in-flight session/prompt calls
    fp, fp_pending  # fingerprint (messageCount, updatedAt, title)
    error, last_touch
```

`running()` is true while `prompts > 0`, a `run_id` is set, or the status is
`working` or `needs_you`.

### 7.2 Notification routing (`_dispatch`)

| From the worker | Handling |
|---|---|
| Response | `_post_response()` updates state, then the response goes to the originating tab (original id restored) or to an internal future. |
| Agent request (`session/request_permission`, `elicitation/create`, `_goose/unstable/session/recipe/request-params`) | Stored as an ask keyed by its JSON id. The session status becomes `needs_you`, with `last_text` set to "Needs approval: <tool title>" or the message. The raw request is broadcast to all tabs of the profile, and a `needs_you` event is raised (webhook). |
| `session/update`, `_goose/unstable/session/update` | Herd derivation (7.5). Buffered if the session is loaded or replaying. During a replay it goes only to the loading tab, otherwise to every tab whose watch set contains the session. |
| Other notifications | Broadcast to all tabs of the profile. |

`_post_response()` side effects by method:

| Method | Effect |
|---|---|
| `session/new` | State created and `loaded`, title "New chat", the creating tab watches it, fingerprint refreshed. |
| `session/load` | Marked `loaded`, load result cached for replays. |
| `session/prompt` | `prompts` decremented. `stopReason: cancelled` sets `idle`. Any other stop reason sets `done` and raises a `done` event. An error result sets `error` and raises an `error` event. |
| `session/set_mode`, `session/set_config_option` | Cached load result updated, so replays show the current mode and options. |
| `_goose/unstable/session/conversation/truncate` | Refused by the gateway while the chat runs (Goose does not check) and unless `truncateFrom` is a positive integer. On success the session's buffer and cached load result are dropped (the next load comes from Goose) and the other tabs get `_gw/session_changed {sessionId, reason: "truncated"}`. Used by **Edit > Rerun here** (1.6.0); **Branch** uses `session/fork` with `_meta.conversationBefore`. Both cut at `created >= T` in whole seconds. |
| `_goose/unstable/session/extensions/add`, `.../remove` | The start-up `_meta.extensionResults` in the cached load result follows the change (`apply_extension_change`): a successful add marks the extension loaded, a failed add records Goose's error, a remove drops the entry. Otherwise a reconnecting tab would be replayed the start-up status, and an extension started later with Retry would show as failed again (fixed in 1.5.1). |
| `session/delete`, `session/close` | State removed. The herd gets a `removed` update. |
| `_goose/unstable/session/rename` | Title updated. |
| `_goose/unstable/schedules/*` | `hub.schedules_changed()`, an optional hook for schedule changes. |

### 7.3 Buffering and replay

Every loaded session keeps the raw session notifications it has received in a
buffer. Limits:

- `SESSION_BUFFER_BYTES` = 12 MB per session. Older entries are dropped and the
  buffer is marked `truncated`.
- `TOTAL_BUFFER_BYTES` = 256 MB across all sessions. `evict_buffers()` drops
  the buffers of the oldest idle, unwatched sessions until usage is at 70%.

When a tab sends `session/load`:

1. **Session loaded and running.** The gateway does not call the worker. It
   replays the buffer to that tab and answers with the cached load result
   (plus `_meta.gw.running`). A tab opened mid-run sees the whole run so far
   and then continues live.
2. **Session loaded and idle, fingerprint unchanged.** Same replay, which is
   cheaper than asking Goose to replay from its database.
3. **Otherwise.** The buffer is cleared, the requesting tab becomes
   `loading_client`, and the load is forwarded. Goose replays the history as
   `session/update` notifications. They are buffered and sent only to the
   loading tab.

**External changes.** The same profile may also be used by Goose Desktop or
the CLI. Each `Upstream` runs a watcher that calls `stat()` on
`<root>/data/sessions/sessions.db` and its `-wal` file every 2 s (falling back
to 15 s). On a change it does the following:

1. It broadcasts `_gw/sessions_changed`.
2. It re-fingerprints up to 40 idle, buffered sessions with
   `_goose/unstable/session/info` (`_meta.messageCount`, `updatedAt`, `title`).
3. For a session whose content changed (message count, or `updatedAt` when no
   count is available), it invalidates the buffer and broadcasts
   `_gw/session_changed`. The open tab reloads, and other tabs mark the chat
   unloaded. A title-only change updates the herd.

### 7.4 Asks fan-out, first answer wins

Permission requests, elicitations and recipe-parameter requests go to every tab
of the profile, so the user can answer from any device. `_gw/hello` also
returns all pending asks, so a tab opened later shows them too. When an answer
arrives (`_answer_ask`):

- The first answer is forwarded to the worker with the original request id,
  audited as `acp.answer`, and announced with
  `_gw/ask_resolved {id, by: <username>}`. Other tabs replace the card with
  "Answered by <user>".
- Later answers to the same id get `_gw/ask_resolved {by: "already-answered"}`.
- The session status goes back to `working`, or to `idle` if no run is active.

### 7.5 Herd status derivation

The herd is the gateway's summary of "what are my agents doing". It is derived
from the ACP stream in `_herd_from_update()` and `_post_response()`:

| Signal | Effect |
|---|---|
| `session/prompt` sent | `working` |
| Agent request (ask) | `needs_you`, ask `{id, kind, title}` attached |
| Ask answered | `working` (or `idle`) |
| `session_info_update` with `_meta.goose.activeRunId` | `working` while set. Cleared with no prompt in flight, it becomes `done`. Also used for scheduled runs started by the worker. |
| `session_info_update` with title | Title updated |
| `agent_message_chunk` | Text appended to `last_text` (last 300 characters) |
| `tool_call` | `last_text` = a tool marker plus the tool title |
| `usage_update` | `usage = {used, contextLimit: size, cost: amount}` |
| `_goose/unstable/session/update` with `contextLimit` | `usage = {used, contextLimit, cost: accumulatedCost}` |
| Goose status message | `last_text` |
| Prompt response | `done`, or `idle` if cancelled, or `error` |
| `_gw/seen` | `done`/`error` becomes `idle` |
| Worker crash or disconnect | Running sessions become `error` |
| Session deleted | `removed` |

Status changes are broadcast immediately as `_gw/herd_update`. Text and usage
changes mark the session dirty, and `Hub._flush_loop` sends them once per
second. `herd()` returns sessions whose status is not `idle`, or that are
loaded and running. Admin tabs that asked for `_gw/herd {all: true}` receive
updates for every profile. `GET /api/herd?all=1` additionally aggregates peer
gateways listed in the `peers` setting. They are fetched with a bearer token,
cached 5 s, available to cookie-authenticated admins only, and never fetched
recursively.

### 7.6 Events and notifications

`make_event_handler` (`app.py`) receives `needs_you`, `done` and `error`
events. It skips the event when a tab is currently watching the session (the
user is looking at it). Otherwise, if the user has a webhook in
`prefs._notify` and the `notify_webhook` permission, it sends the webhook
(section [12.10](#1210-ssrf-guard-for-webhooks)):

- ntfy URLs get `Title`, `Tags`, `Click` and `Priority` headers and a plain
  body.
- Other targets get JSON `{event, title, message, url, agent}`, where `url` is
  `<public_url>/#/chat/<sessionId>`.

Browser notifications and sounds are handled entirely in the SPA (`herd.js`).

### 7.7 Schedules

Schedules are Goose's own feature, stored in the profile's
`data/schedule.json`. The gateway does three things:

1. It relays the schedule methods. The `schedules` permission is required for
   create, update, delete, pause, unpause, run-now and killing a running job.
   Listing schedules, listing their sessions and inspecting a running job are
   always allowed.
2. It decides which process runs the scheduler (section
   [3.6](#36-scheduler-ownership)).
3. It keeps workers with schedules running when nobody is connected (section
   [3.5](#35-the-monitor-loop)).

Scheduled runs show up in the herd through `session_info_update`/`activeRunId`.
The session list includes them when `sidebar.includeScheduled` is on.

---

## 8. Front end

### 8.1 Principles

- Plain ES modules served from `/static/js/`. There is no bundler, no
  transpiler and no build step. Vendored libraries are loaded from
  `/static/vendor/`, and nothing comes from a CDN.
- The CSP is `script-src 'self'`, so there are no inline scripts.
- DOM is built with the `h(tag, props, ...children)` helper in `ui.js`.
  Untrusted strings are never assigned to `innerHTML`. Markdown is the only
  HTML path, and it always passes through DOMPurify. `h()` checks URL
  attributes with `isSafeUrlAttr`.

### 8.2 Boot sequence (`app.js`)

1. `GET /api/auth/config` (brand, version, enabled sign-in methods).
2. `GET /api/me`. A 401 or 403 shows the login view. `mustChangePassword`
   shows the forced password change. A network failure shows "Gateway
   unreachable".
3. `startApp()`:
   - stores `me`, sets the CSRF token in `api.js`, and loads the preferences;
   - for admins, reads `?profile=` into `rpc.profileParam` (impersonation,
     shown with an "Admin view of <name>'s profile" bar);
   - builds the shell (sidebar, main area, upstream status bar) and starts
     `rpc`;
   - defaults the hash to `#/new`, starts the router, and registers the
     service worker (secure contexts only).

### 8.3 State, events and routing

| Module | Role |
|---|---|
| `store.js` | `Emitter` (`on`, `off`, `once`, `emit`, with listener errors caught) and `Store` (`get`, `set`, `update`, `watch`; `set` emits `change:<key>`). The global `store` holds `me`, `authConfig`, `prefs`, `conn` (`idle|connecting|open|reconnecting|down`), `upstream` (`starting|ready|down|unknown`), `route`, `herd` (Map), `asks` (Map) and `agentInfo`. `bus` is the app-wide event bus. `policy(key)`, `policyList()` and `allowedValue()` read the user's effective policy (admins always pass). |
| `router.js` | Parses `#/view/arg1/arg2?query` into `{view, args, query, path}`, `go(path, {replace})`, emits `route`. |
| `app.js` route table | `''`/`new` (home), `chat/<id>`, `herd`, `recipes[/edit/<id>]`, `skills`, `schedules`, `apps/<name>`, `extensions`, `settings/<tab>`, `admin/<tab>`. |

A view is a function that returns `{el, destroy?, canLeave?, focus?}`. On
navigation the router asks the current view's `canLeave()`, calls `destroy()`,
and mounts the new view. `beforeunload` warns when any chat still has queued
messages.

### 8.4 Transport

**`rpc.js`.** One WebSocket to `/ws`, with `?profile=` when an admin is
impersonating.

- **Requests.** `call()` has a 60 s timeout, except for long methods with no
  timeout: `session/prompt`, `session/new`, `session/load`,
  `schedules/run-now`, `providers/config/authenticate` and `session/steer`.
- **Notifications.** `notify()` sends them. `respond()` and `respondError()`
  answer agent requests.
- **Watch list.** `setWatched(ids)` sends `_gw/watch`.
- **Reconnect.** On open the client sends `_gw/hello`, updates the store and
  re-sends the watch list. On close all pending calls reject with
  `disconnected`. Reconnection uses backoff
  `min(30 s, 0.5 s * 1.8^(n-1))` with 25% jitter. The connection is shown as
  `down` after 6 failed attempts.
- **Incoming messages.** A method with an id emits `request`. A method without
  an id emits the method name and `*`.
- **Helper.** `G(m)` returns `'_goose/unstable/' + m`.

**`api.js`.** `fetch` with `credentials: 'same-origin'`.

- It sends `X-CSRF-Token` on every non-GET request and handles `FormData`.
- Errors throw `ApiError(status, code, message, data)`.
- A 401 outside `/api/auth/` emits `unauthorized` on the bus, and a 403
  `password_change_required` emits its own bus event.

**RPC wiring in `app.js`.**

| Event | Handling |
|---|---|
| `hello` | Resets asks from the hello payload, sets the herd, reloads the session list, and reloads the current chat. Other cached chats are marked unloaded. |
| `request` | Asks (`ASK_METHODS`) go to `addAsk`. Anything else gets `-32601`. |
| `session/update`, `_goose/unstable/session/update` | `routeNotification()` in `chatsession.js`. |
| `_gw/ask_resolved` | `resolvedElsewhere()`. |
| `_gw/session_changed` | `sessionChangedElsewhere()`. |
| `_gw/sessions_changed` | `refreshSessionsSoon()`. |
| `_gw/herd_update` | `upsertAgent()`. |
| `_gw/upstream` | Status bar ("Starting your Goose agent...", "not running", "Cannot reach the gateway") and toasts. |
| Provider device-code notification | Modal with the code and an `https`-only link. |

### 8.5 ChatSession (`chatsession.js`)

One `ChatSession` per open session, cached up to `MAX_CACHED = 10`. The cache
evicts chats that are not current, not running and have an empty queue. The
union of cached session ids is kept in sync with the gateway through
`rpc.setWatched`, so a tab receives live updates for every chat it has cached.
`setCurrentChat()` also sends `_gw/seen`.

Main fields: `id`, `title`, `cwd`, `modes`, `configOptions`,
`usage {used, size, cost, currency}`, `running`, `promptPending`,
`activeRunId`, `queue`, `commands`, `loaded`, `loading`, `progress`, `draft`,
and `transcript` (a `Transcript`).

**load().**

1. Calls `session/info` if the working directory is unknown.
2. Clears the transcript and starts bulk mode.
3. Sends `session/load {sessionId, cwd, mcpServers: []}` with `replaying = true`.
4. Ends bulk mode.
5. Applies the result: modes, config options, `_meta.workingDir`, recipe,
   extension results, and `_meta.gw.running`.
6. Re-inserts pending asks for this session and takes the running state from
   the herd.

**send(blocks).**

- If a run is active, the message is queued. Otherwise a pending user item is
  added locally and `session/prompt` is sent.
- The `stopReason` is shown as a system line ("Stopped", "Stopped: output
  token limit reached", "Stopped: maximum turns reached", "The model refused
  to continue").
- If the socket drops mid-prompt, the chat shows: "Connection lost. The agent
  keeps working on the server; the transcript will resync when reconnected."
- When the run ends, `setRunning(false)` finalises all transcript items,
  emits `run:end` and sends the next queued message.

**Other actions.**

| Action | ACP call |
|---|---|
| Cancel | `session/cancel` notification |
| Steer | `_goose/unstable/session/steer {expectedRunId}`. Falls back to the queue if the run already ended. |
| Set mode | `session/set_mode` |
| Set config option (provider, model, thought level) | `session/set_config_option` |
| Rename | `_goose/unstable/session/rename` |
| Change working folder | `session/working-dir/update` |

### 8.6 Mapping ACP updates to transcript items

`routeNotification(method, params)` first applies `session_info_update` to the
session list (title, `updatedAt`, `_meta.messageCount`). It then calls
`chat.onUpdate(update)` for `session/update` or `chat.onGooseUpdate(update)` for
`_goose/unstable/session/update`.

| `sessionUpdate` kind | ChatSession / Transcript | UI item |
|---|---|---|
| `user_message_chunk` | `transcript.addUser([content], {messageId, time})` | User bubble. The gateway's synthetic echo makes prompts from other tabs appear immediately. |
| `agent_message_chunk` | `transcript.agentChunk()`. When live (not replaying) it also sets `running`. | Agent message. Markdown is re-rendered once per animation frame while streaming and highlighted when final. |
| `agent_thought_chunk` | `transcript.thoughtChunk()` | **Thinking** block: a `<details class="thought">` with a "Thinking" summary and character count, Markdown body; open or folded per the `thinking` activity preference (8.7). |
| `tool_call` | `transcript.toolCall()` | **Tool card** (see below). A `tool_call` whose id belongs to a finished card starts a new card. |
| `tool_call_update` | `transcript.toolUpdate()` | Updates the card's status, output, live output, locations, or inline app. |
| `plan` | `transcript.plan(entries)` | One plan card per turn, updated in place: done/total count, per-entry status, high-priority badge. A new user message resets it. |
| `available_commands_update` | `chat.commands` | Slash command list in the composer. |
| `current_mode_update`, `config_option_update` | Header pills | Mode, provider, model and thought-level selectors. |
| `session_info_update` | Title. `_meta.goose.activeRunId` drives `running`. | Header and sidebar. |
| `usage_update` | `usage {used, size, cost}` | Context-usage ring in the header. |
| Goose `usage_update` | `contextLimit`, `accumulatedCost`, token totals | Header ring and cost. |
| Goose `message_usage` | `transcript.messageUsage()` | Footer under an agent message: input tokens, output tokens, cost, duration. |
| Goose `status_message` | `progress` (type `progress`) or a system line | Progress line under the transcript. |
| Agent requests | `asks.js` `askCard` | Ask card inserted directly after the matching tool card. |

**Tool cards.** A card has a header button and a body.

- **Header:** a status icon (spinner, check or cross), a kind icon (`read`,
  `edit`, `delete`, `move`, `search`, `execute`, `think`, `fetch`,
  `switch_mode`, `other`), the title (or `_meta.goose.toolCall.toolName`), an
  exit-code badge, the extension name, and, while collapsed, the last line of
  live output.
- **Body:**
  - the input, shown as `$ command` for shell tools, otherwise as JSON;
  - **live output**, streamed from `_meta.toolNotification` entries of type
    `live_output` (`params.chunks[].output`), capped at 200,000 characters
    with a truncation flag;
  - the final output: stdout/stderr with the exit code, or the content list
    (text, image, resource link, embedded resource, diff, terminal), or the
    raw result;
  - the locations.
- **Diffs** are rendered with three lines of context. Long text is clipped at
  20,000 characters behind "Show all".

When a card opens and folds by itself depends on the `tools` activity
preference; see 8.7.

**Inline MCP Apps.** When a tool result carries the trusted
`_meta.goose.mcpApp {resourceUri: "ui://...", extensionName, toolName, readError}`
and the call completes, the card mounts an iframe:

```html
<iframe sandbox="allow-scripts allow-forms allow-popups"
        src="/api/apps/frame?sessionId=...&ext=...&uri=ui://..."
        referrerpolicy="no-referrer" loading="lazy"></iframe>
```

`createAppBridge` (lazily imported from `views/apps.js`) then delivers the
tool input and the reconstructed `CallToolResult`. A `ui/message` from the app
becomes a chat prompt after the user confirms it. The bridge rules are listed
in [section 12.8](#128-mcp-apps).

**Windowing.** The transcript keeps about 80 items attached (`WINDOW`). When
more than twice that are attached, older items are detached behind a "Show
earlier messages" button, which restores them in pages of 60. During a replay
(`beginBulk`/`endBulk`) only the last window is built.

### 8.7 Live activity (per-turn tracking, activity preferences, activity bar)

This is display logic only. It does not change what the gateway buffers or replays, and it needs nothing new from Goose. All inputs are the updates listed in 8.6.

**Turns.** `ChatSession.setRunning(true)` calls `Transcript.startTurn()`. `setRunning(false)`, which runs on the prompt response, on cancel, on error, or when the herd reports the run finished, calls `Transcript.endTurn()`. A turn records:

```js
this.turn = { start, tools, phase, label, target, thoughts: Set }
```

`startTurn()` also starts a one-second timer that redraws the bar. Items created while a turn is live (outside a replay, `this.bulk === false`) are marked live: thoughts get `item.live`, tool cards get `item.liveTurn`. Only live items are opened automatically, so history never pops open.

**Phases.** `Transcript.setPhase(phase, label, target)` is called from the item builders:

| Phase | Set by | Bar text |
|---|---|---|
| `thinking` | `startTurn()`, `thoughtChunk()` | Thinking... |
| `tool` | `toolCall()` / `toolUpdate()` through `toolPhase()` while the call is pending or in progress | Running *tool title* |
| `waiting` | `addAsk()` (permission or elicitation) | Waiting for your approval: *title* |
| `working` | `toolPhase()` when the current tool completes or fails, or `askResolved()` | Working... |
| `writing` | `agentText()` when non-blank text arrives | Writing the reply... |
| `progress` | `ChatSession.onGooseUpdate()` for a `status_message` of type `progress` | Goose's text, e.g. compacting |

While the phase is `waiting`, tool updates do not change it. The `ask:resolved` bus event calls `Transcript.askResolved(id)`. That method moves to the next unanswered approval of the same turn if there is one. Otherwise it shows `tool` (the tool is still running) or `working` (it has already finished). `toolCall()` counts new live tool calls in `turn.tools`.

**Activity bar.** `Transcript` owns `activityEl`, a `.tr-activity-wrap` placed after the item list, so it always sits under the last message. `renderActivity()` draws a spinner (or an alert icon while waiting), the phase text, the tool-call count and the elapsed time (`fmtElapsed`). Clicking the bar scrolls `turn.target` into view. The bar is hidden when there is no turn or when `prefs.activity.statusBar` is false.

**Preferences.** `prefs.js` adds `DEFAULT_PREFS.activity` and `activityPrefs()`, which merges the stored values over the defaults and validates them. The preferences are stored server-side with the rest of `/api/me/prefs` and edited in Settings > Preferences > Chat. A change applies to items built after it, and to every item when a chat is reopened.

| Key | Values (default first) | Thinking blocks / tool cards |
|---|---|---|
| `thinking` | `auto`, `expanded`, `collapsed` | `auto`: `buildThought()` opens live thoughts, and `endTurn()` folds the thoughts of that turn (`turn.thoughts`). `expanded`: always open. `collapsed`: closed. |
| `tools` | `auto`, `detailed`, `concise` | `auto`: `buildTool()` opens a live card that is not yet complete, and `toolUpdate()` opens it on live output and folds an auto-opened card when it completes. `detailed`: always open. `concise`: never opened automatically. |
| `statusBar` | `true`, `false` | Show or hide the bar. |

A click on a Thinking summary or a tool header sets `item.userToggled`, and automatic opening and folding then leave that item alone. Thinking text is rendered with `setMarkdown()`, the same sanitised Markdown path as agent messages, inside `.thought-text.md`.

Goose sends each thinking block as one `agent_thought_chunk` once the model finishes it, so the block appears in one piece rather than word by word.

### 8.8 Other front-end modules

| Module | Notes |
|---|---|
| `composer.js` | Auto-sizing textarea (up to 360 px). Slash commands from `_goose/unstable/slash-commands/list` (cached 60 s) or the session's available commands. `@` mentions from `agent-mentions/list`. Attachments: images up to 8 MB are sent inline as base64 image blocks. Other files are uploaded to `<cwd>/.goose-web-uploads` through `/api/fs/upload` and sent as `resource_link` `file://` URIs. Enter to send (preference). Ctrl+Enter steers a running agent. Send, stop, steer and queue buttons. |
| `asks.js` | `ASK_METHODS` maps the three agent requests to `permission`, `elicitation` and `recipe_params`. Permission options are sorted (allow once, allow always, reject once, reject always). Elicitation renders a form from a restricted JSON schema. Recipe parameters open a modal. Answers use `rpc.respond`. |
| `herd.js` | Herd map keyed `profile:sessionId`. Status transitions raise browser notifications, toasts, or a WebAudio chime, depending on preferences. The page title gets an `(n)` prefix, and the favicon gets a dot (amber for needs-you, green for done). Sort order: needs_you, working, error, done, idle, offline. |
| `sessions.js` | `session/list` with `_meta {types, goose {includeLastMessageSnippet}, query}` and cursor paging. Debounced refresh merges. Sessions are grouped by working folder, using the same grouping rules as Goose Desktop. |
| `markdown.js` | marked (GFM), then DOMPurify. Forbidden tags: `style`, `form`, `input`, `button`, `textarea`, `select`, `iframe`, `object`, `embed`. The `style` attribute is forbidden. Links get `target=_blank` with `rel="noopener noreferrer nofollow"`. `javascript:` URLs are removed. Remote images are dropped (only `data:image/`, `blob:` and same-origin paths are kept). Final messages get highlight.js and copy buttons on code blocks. |
| `prefs.js` | `DEFAULT_PREFS`: `theme`, `accent`, `density`, `fontSize`, `codeTheme`, `enterToSend`, `showTimestamps`, `pinned`, `recentFolders`, `lastCwd`, `newChat {provider, model, effort, mode}`, `notifications {browser, sound, events}`, `sidebar {collapsed, showArchived, includeScheduled, width}`, `herd {all}`. Stored through `PUT /api/me/prefs` (debounced 600 ms) and cached in `localStorage` (`gw.prefs`). `patchPref` merges nested objects with the defaults. `applyTheme` sets `data-theme`, `data-scheme`, `data-density`, `--accent` and `--fs`, and switches the highlight.js stylesheet. Nine themes. |
| `views/chat.js` | Chat header (rename, folder chip, mode/provider/model/thought-level selectors filtered by policy, context ring, extension status, run pill), scroller with stick-to-bottom, composer, queue row, and menu (fork, session extensions, tool permissions, system prompt, diagnostics, export, archive, delete). |
| `views/apps.js` | Apps gallery and `createAppBridge` (the MCP App host bridge). |
| `views/home.js` | New chat: `session/new {cwd, mcpServers: [], _meta}`, from a recipe or a deeplink. A missing provider is mapped to a setup hint. Option pickers (provider, model, thinking effort, approval mode; data from `_goose/unstable/providers/list`, `defaults/read`, `preferences/read`, filtered by policy, remembered in the `newChat` preference). After `session/new` and before the first `session/prompt`, `applyNewChatOptions()` sends `session/set_config_option` for `provider`, `model` and the `thought_level` option (in that order, each checked against the refreshed option list), then `session/set_mode`. These change only that session; the gateway enforces the policy on them (`policy.py`). |
| `views/herd.js` | Herd board (`_gw/herd`, `GET /api/herd` for peers). |
| `views/admin.js` | Users, teams, policy, team items, hints library, sign-in providers, settings, system, ownership, host tasks, audit, logs. |
| `views/settings.js` | Providers, prompts, preferences, hints, tool permissions, advanced configuration, appearance, notifications, account (password, TOTP, API tokens, sign-ins). |
| Other views | `recipes`, `skills`, `schedules`, `extensions`, `folderpicker`, `login`, `sidebar` (navigation array `NAV`, session list grouped by folder, herd summary). |

---

## 9. Service worker

`static/sw.js` gives the app an offline-capable shell without ever caching user
data:

| Request | Strategy |
|---|---|
| Not same-origin, or not GET | Not handled |
| `/api/*`, `/ws` | Never handled (always network) |
| `/`, `/index.html`, `/manifest.webmanifest` | Network-first with `cache: 'no-cache'`. The cache is an offline fallback, and shell requests fall back to `/`. |
| `/static/js/*`, `/static/css/*` | Network-first, cache as fallback |
| Other `/static/*` (vendor, icons) | Cache-first |

- **Install** pre-caches the shell list on a best-effort basis and calls
  `skipWaiting()`.
- **Activate** deletes every cache whose name is not the current `VERSION`
  (`gw-shell-v10`) and claims open clients.
- **notificationclick** focuses an open window, or opens one, at
  `/#/chat/<sessionId>` or `/#/herd`.

Bump `VERSION` whenever the shell list or the vendored files change.

---

## 10. Data model

The gateway's own state lives in one SQLite database,
`<system_dir>/goose-web.db`. Goose's own state (sessions, configuration,
secrets, schedules) stays in each profile and is never copied into it.

### 10.1 Connection

- PRAGMAs: `journal_mode=WAL`, `foreign_keys=ON`, `synchronous=NORMAL`,
  `busy_timeout=5000`.
- Autocommit mode (`isolation_level=None`), with explicit `transaction()`
  blocks where several statements must be atomic.
- One `RLock` serialises access, and the connection is shared across threads
  (`check_same_thread=False`).
- Helpers: `query`, `one`, `execute`, `execute_count`, `transaction`.

### 10.2 Tables

| Table | Purpose and notable columns |
|---|---|
| `meta` | `key`, `value`. Holds `schema_version` and `policy_model` (2 = least-privilege policies, written by the 1.5.0 migration). |
| `users` | `username` (unique, case-insensitive), `display_name`, `email`, `role` (`user`/`admin`), `auth_source` (`local`, `ldap`, `oidc`), `password_hash`, `must_change_pw`, `totp_secret`, `totp_enabled`, `totp_last_counter`, `disabled`, `profile_mode` (`isolated`/`native`), `profile_path`, `personal_hints`, `prefs` (JSON), `policy_overrides` (JSON), `has_schedules`, `failed_logins`, `locked_until`, `created_at`, `last_login_at`, `oidc_issuer`, `oidc_subject` |
| `teams` | `name` (unique, case-insensitive), `description`, `policy` (JSON: the policy keys plus `default_provider`, `default_model`, `share_folder`) |
| `team_members` | `(team_id, user_id)`, cascades on delete. Unique index `ux_team_members_user` on `user_id`: one team per user (schema version 4). `Database.set_user_team` replaces a membership. |
| `hints_docs` | Shared hints documents: `name`, `description`, `content` |
| `user_hints`, `team_hints` | Hints documents assigned to users or teams |
| `team_items` | Items provisioned into members' profiles: `kind` (`recipe`, `skill`, `extension`, `provider`), `name`, `payload` (JSON), `source`. Unique per `(team_id, kind, name)`. |
| `auth_sessions` | `token_hash` (primary key, SHA-256 of the cookie value), `user_id`, `csrf`, `created_at`, `expires_at`, `last_seen`, `ip`, `user_agent`, `method` |
| `api_tokens` | `name`, `token_hash` (unique), `prefix` (first 10 characters, for display), `created_at`, `last_used`, `expires_at` |
| `audit` | `ts`, `user_id`, `username`, `ip`, `action`, `target`, `detail` (JSON), `ok`. Indexed on `ts`. |
| `settings` | `key`, `value` (JSON): `auth`, `brand`, `default_team_id`, `session_hours`, `allow_self_totp`, `require_totp_admins`, `peers`, `native_root` |
| `oidc_states` | `state`, `verifier`, `nonce`, `created_at` (10-minute login handshakes) |
| `ip_blocks` | `ip` (address key: IPv4 or IPv6 /64), `failures` (JSON list of timestamps of the current run), `last_username`, `blocked_at` (0 = not blocked), `blocked_until` (0 = until unblocked), `updated_at` (schema version 3) |

**JSON columns.** `prefs`, `policy_overrides`, `policy`, `payload`, `detail` and
`value` are decoded automatically in `_row()`, so callers always get Python
objects.

**Guards.**

- `create_user` rejects the reserved names `appdata`, `workspace`, `_system`,
  `_deleted`, `_teams`, `library`, `backups` and `logs`, because user names become
  folder names under `<profiles_root>`.
- Dynamic user updates check column names against `PRAGMA table_info`
  (`_check_user_columns`). Link-table updates use a fixed allow-list
  (`_LINK_TABLES`).

### 10.3 Schema version and migrations

`SCHEMA_VERSION = 4` (3: the `ip_blocks` table, 1.3.0; 4: one team per user and
least-privilege policies, 1.5.0). Column migrations are additive and
idempotent:

```python
MIGRATIONS = [
    ("users", "totp_last_counter INTEGER"),
    ("users", "oidc_issuer TEXT"),
    ("users", "oidc_subject TEXT"),
]
POST_MIGRATION_SQL = [
    "CREATE UNIQUE INDEX IF NOT EXISTS ux_users_oidc "
    "ON users(oidc_issuer, oidc_subject) WHERE oidc_subject IS NOT NULL",
]
```

On open:

1. `CREATE TABLE IF NOT EXISTS` runs for every table.
2. Each migration column is added if it is missing.
3. The post-migration SQL runs.
4. `_migrate_policy_model` runs (one-shot, see below).
5. `meta.schema_version` is raised if it is lower than `SCHEMA_VERSION`.

Columns are never dropped or renamed, so an older gateway can still open a
newer database. To change the schema, append to `MIGRATIONS` and bump
`SCHEMA_VERSION`.

**Policy model migration** (`_migrate_policy_model`, `POLICY_MODEL = 2`). It
runs in one transaction when `meta.policy_model` is missing or lower than 2,
so existing teams keep their 1.4 behaviour under the new least-privilege
rules:

- each team policy is laid over `LEGACY_DEFAULT_POLICY` (the 1.4 defaults),
  and its empty `allowed_modes`, `allowed_providers` and `allowed_models`
  (which meant unrestricted) become `["*"]`;
- the same three lists become `["*"]` where they are empty in a user's
  `policy_overrides`;
- a user in several teams keeps the lowest team id; every dropped membership
  is audited as `team.migrate.membership`;
- the unique index `ux_team_members_user` is created and `meta.policy_model`
  is set to 2.

New databases run it too (there is nothing to convert) and only get the
index.

### 10.4 Audit retention

`AUDIT_RETENTION_DAYS = 365`. `purge_audit()` deletes older rows each time the
database is opened. Admins read the log through
`GET /api/admin/audit?before=&user=&action=&limit=` (at most 500 rows per page).

---

## 11. Profiles on disk

### 11.1 Roots

| Path | Contents |
|---|---|
| `<profiles_root>` | `paths.profiles_root`. One folder per isolated user. |
| `<system_dir>` | `paths.system_dir`, default `<profiles_root>/_system`: the database, `logs/`, `library/`, `backups/`, and (by default) `config.yaml`. |
| `<profiles_root>/_deleted/<name>-<timestamp>` | Archived profiles of deleted users, unless the profile was purged. |
| `<profiles_root>/_teams/<team id>` | A team's shared folder (`Profiles.team_folder`), unless the team sets an absolute `share_folder`. Created by `ensure_team_folder`; kept when the team is deleted. |
| `<profiles_root>/appdata` | Fresh native Goose root created by `init --native-root fresh` (contains `config/`, `data/`, `state/`). |

### 11.2 Isolated profile layout

The worker runs with `GOOSE_PATH_ROOT=<profiles_root>/<username>`:

```
<profiles_root>/alice/
  config/
    config.yaml          provider, model, mode, extensions
    secrets.yaml         API keys (keyring disabled)
    .goose-web-hints.md  composed hints, the only context file Goose loads
    custom_providers/    provider definitions provisioned from teams
    recipes/             the user's own recipes
    skills/              user skills and team skills (marked .goose-web-managed)
  data/
    sessions/sessions.db Goose session database (watched by the hub)
    schedule.json        Goose schedules
    logs/
  state/
  workspace/             default chat folder
  .goose-web/managed.json  record of what the gateway provisioned
```

### 11.3 Provisioning (`Profiles.provision`)

Provisioning runs on first login, on admin request
(`POST /api/admin/users/{id}/provision`), and whenever teams, team items, hints
or memberships change (`_reprovision`).

1. It creates the layout.
2. **First time only:** it copies the base extensions (`todo`, `skills`,
   `apps`, `chatrecall`, `summarize`, `extensionmanager`, `analyze`, `memory`,
   `summon`, `tom`) from the native admin configuration, if they are
   platform or built-in extensions. It sets `GOOSE_MODE` to `approve`.
   Shell-capable extensions (`developer`, `computercontroller`,
   `code_execution`, `orchestrator`) stay disabled unless the policy has
   `allow_shell`.
3. **Team items:**
   - **Extensions.** Shell or stdio extensions are disabled without
     `allow_shell`. `secretsFrom` copies the named environment secrets from
     the source profile.
   - **Providers.** Written to `custom_providers/<id>.json`, plus their
     secrets.
   - **Skills.** Written as files under `skills/<name>/` with a
     `.goose-web-managed` marker. Skill folders the user owns are never
     overwritten. Entries with `..` or absolute paths are skipped.
   - **Recipes.** Not copied. They stay in
     `<system_dir>/library/teams/<team_id>/recipes/` and are exposed through
     `GOOSE_RECIPE_PATH`.
4. Managed items that are no longer assigned are removed. Only items the
   gateway created are touched.
5. It creates the team folder (`ensure_team_folder`).
6. **Team default model.** If the team's `default_provider` (and
   `default_model`) are allowed, they are written on first provisioning,
   when the profile has no provider, or when the team default changed and
   the profile still used the previous one (stored as `teamDefault` in the
   manifest). A provider that is not allowed is reset to the team default
   or the first explicitly allowed provider; a model that is not allowed is
   reset to the default model or removed; a mode that is not allowed becomes
   `approve` if allowed, otherwise the first allowed mode.
7. It writes `config.yaml`, `secrets.yaml`, `config/.goose-web-hints.md` and the manifest
   atomically: a temporary file followed by `os.replace`, with LF line endings.

If provisioning changes anything while the worker is running,
`restart_pending` is set and the worker restarts once it has no running
sessions.

It also removes the `config/.goosehints` that 1.4 composed, if the file
starts with the Goose Web header (`_drop_legacy_hints`).

**Hints composition** (`hint_sections`, `compose_hints`). The file lists its
parts from lowest to highest precedence: the header and a precedence note,
the personal hints (only for admins or when the policy has `hints_edit`;
otherwise `personalDropped` is reported), the documents assigned to the user
(minus any that are also team documents), and the team's documents last
under `Team: <name> (final: these take precedence)`. `write_hints` rewrites
only this file, which is safe while Goose runs. Non-admins cannot create a
file or folder named `AGENTS.md`, `.goosehints` or `.goose-web-hints.md`
through the file endpoints (`api._refuse_hint_name`, `HINT_FILE_NAMES`).

### 11.4 Native profile

The user with `profile_mode = native`, normally the first admin, uses the
operating-system user's own Goose root, so the web UI and Goose Desktop share
sessions and configuration. The gateway **never provisions** a native profile.
The one exception is that an admin saving their own hints through the web UI
writes `.goosehints`. The previous file is first backed up to
`<system_dir>/backups/native-hints/.goosehints.<timestamp>`. A native profile
must belong to an admin. Its worker gets no `CONTEXT_FILE_NAMES`, so Goose
loads `AGENTS.md` and `.goosehints` as usual.

### 11.5 Library and export

`Profiles.library(user, kind)` lists recipes, skills, extensions and providers
in a profile. Admins use it to promote an item into a team.
`export_item` copies the item:

- skills are limited to 2 MB;
- secrets are never copied, only referenced through `secretsFrom`, and are
  resolved at provisioning time.

---

## 12. Security layers

`docs/SECURITY-ASSESSMENT.md` contains the threat model and findings. Finding
ids (`GW-nn`, `NEW-nn`) appear in code comments and test names. This section
lists the mechanisms.

| Layer | Mechanism | Code |
|---|---|---|
| Network exposure | Binds `127.0.0.1` by default. The Compose file publishes on loopback only. Workers are always loopback with a secret. | `config.py`, `workers.py`, `docker/compose.yaml` |
| Host header | `HostGuard` allow-list | `app.py` |
| Response headers | CSP, frame denial, nosniff, COOP/CORP, HSTS, `no-store` on API | `app.py` |
| Authentication | Local, LDAP, OIDC, TOTP, lockout, rate limits | `auth.py`, `security.py` |
| Sessions | HttpOnly SameSite=Strict cookie, hashed at rest, fixed expiry | `auth.py`, `api.py` |
| CSRF and origin | `X-CSRF-Token` plus `Origin` check, WebSocket origin check | `context.py`, `app.py` |
| Authorisation | Roles, effective policy, default-deny ACP firewall | `policy.py`, `hub.py`, `api.py` |
| File system | Roots and containment checks, safe uploads, sandboxed downloads | `policy.py`, `api.py` |
| Untrusted content | DOMPurify, sandboxed MCP App frames with their own CSP, restricted app bridge | `markdown.js`, `api.py`, `views/apps.js` |
| Outbound requests | Webhook SSRF guard | `app.py` |
| Process privilege | Refuses elevated/root operation, Windows de-elevation | `winsec.py`, `docker/entrypoint.sh` |
| Supply chain | Hash-locked dependencies, pinned image digest, verified Goose download, vendored JS checksums, SHA-pinned actions | `requirements.lock`, `docker/Dockerfile`, `static/vendor/SHA256SUMS`, `.github/` |
| Accountability | Audit log of sign-ins, admin actions, denied and sensitive ACP calls | `db.py`, `hub.py`, `api.py` |

### 12.1 Passwords, lockout and rate limits

- **Hashing.** scrypt with `N=2^15, r=8, p=1`, a 32-byte key and a 16-byte
  salt, stored as `scrypt$N$r$p$salt$hash`. Hashes are upgraded on login when
  the parameters change (`needs_rehash`). Unknown users are verified against a
  dummy hash, so response timing does not reveal which accounts exist.
- **Password rules** (`password_problems`, version 1.3.0). Minimum length
  `max(auth.min_password_length, PASSWORD_MIN_LENGTH)` = 12 by default; a
  lower-case letter, an upper-case letter, a digit and a symbol; must not
  contain the username (3+ characters); not a common password and not a common
  word once leading/trailing digits and symbols are stripped and leet swaps
  undone (`_common_base`); no character 4 times in a row (case-insensitive).
  `temp_password()` and `generate_admin_password()` loop until they comply.
  At a successful local sign-in, a password that fails the rules sets
  `must_change_pw` (audit `auth.password.weak`). Passwords set by an admin
  (create, PATCH, reset) always set `must_change_pw`.
- **Rate limits.**
  - 40 attempts per 300 s per IP and 10 per 300 s per IP and user, returning
    `429`.
  - `auth.lockout_threshold` (8) failures lock the account for
    `auth.lockout_minutes` (15), returning `423`.
  - The sliding-window `RateLimiter` holds at most 50,000 keys.
  - **Address block** (`ipblock.py`). Failed sign-ins (wrong password,
    unknown user, disabled, local sign-in off, locked, wrong TOTP) append a
    timestamp to the address's row in `ip_blocks` (`AuthService._fail`);
    timestamps older than `auth.ip_block_window_days` (30) are dropped and
    at most `auth.ip_block_threshold` (10) kept. When that many remain, the
    row gets `blocked_at` and `blocked_until` (`ip_block_days`, 30; 0 = no
    expiry), the response becomes `403 ip_blocked` and `auth.ip.blocked` is
    audited. A successful sign-in deletes the row (failures must be
    consecutive). Trusted proxies and `auth.ip_block_exempt` are never
    counted. IPv6 is keyed by /64, IPv4-mapped IPv6 by the IPv4 address.
- **Initial admin password.** `init` generates a random 20-character password
  (or accepts one from `--password-file` or stdin) and prints it once.

### 12.2 Sessions and cookies

- **Login.** `POST /api/auth/login` checks `Origin` and creates a session.
- **Token storage.** The cookie value is a random token. Only its SHA-256 is
  stored (`auth_sessions.token_hash`). The session also has a random CSRF
  token, returned to the SPA in the login and `/api/me` responses.
- **Cookie.** `__Host-gw` when `public_url` is `https`, otherwise `gw`. It is
  `HttpOnly`, `SameSite=Strict`, `Secure` on https, and `Path=/`. It is
  persistent (`max_age`) only when "remember me" is chosen.
- **Lifetime.** `remember_days` (30) or `session_hours` (12). The
  `session_hours` database setting overrides the configuration. Expiry is
  fixed, not sliding. `last_seen` is updated at most once a minute.
- **Revocation.**
  - A password change revokes all other sessions and all API tokens.
  - An admin password reset, disabling the account, or `python -m goose_web
    user reset` revokes all sessions and API tokens.
  - Users can list and end their own sign-ins (`/api/me/logins`).

### 12.3 API tokens

- **Format.** `gwt_` followed by a random token. Only the SHA-256 is stored,
  and the first 10 characters are kept for display.
- **Usage.** Accepted only in an `Authorization: Bearer` header, on REST and
  on `/ws` (where no `Origin` may be present).
- **Expiry.** Optional. `last_used` is updated at most every 5 minutes.
- **Restrictions.** Tokens of users who are disabled or must change their
  password are rejected. A token cannot be used to create another token.

### 12.4 TOTP

- RFC 6238: SHA-1, 6 digits, 30 s steps, a window of plus or minus one step,
  and constant work per check.
- **Replay protection.** Each accepted step is claimed with a conditional
  `UPDATE ... SET totp_last_counter = ? WHERE totp_last_counter < ?`, so a
  code (including the enrolment code) can be used only once.
- **Lockout.** A wrong or replayed code counts toward the same lockout as a
  wrong password. A missing code (the `totp_required` response) does not.
- **Settings.**
  - `allow_self_totp` lets non-admins enrol.
  - `require_totp_admins` forces admins to enrol, and the SPA reports
    `totpEnrolmentRequired`. An admin can only turn it on after enrolling
    themselves (`409 totp_needed_first`).
- **Admin reset (lost authenticator).** `api.admin_user_reset_totp`
  (`POST /api/admin/users/{id}/reset-totp`) and the CLI `user reset-totp`
  clear `totp_enabled`, `totp_secret`, `totp_last_counter`, the failure
  counter and the lock, delete the user's sessions and API tokens, and audit
  `user.totp.reset`. It is refused for the caller's own account (`400 self`),
  so a stolen admin session cannot drop its owner's second factor without the
  password (self-disable checks it).

### 12.5 External identity

**LDAP / Active Directory** (`ldap3`):

- service bind, then search with escaped filters, then user bind;
- the admin role comes from `adminGroupDn` membership, and the team from
  `groupTeamMap`: the mapped team replaces the previous one, and when
  several groups match the first wins (audited as `user.team.directory`);
  OIDC team claims follow the same rule (`_upsert_external`);
- users are created automatically as isolated profiles;
- plain `ldap://` without StartTLS is refused at save time and at login
  (`503 ldap_insecure`) unless `allowInsecure` is set.

**OIDC:**

- authorization code flow with PKCE S256 and discovery cached for one hour;
- it requires `server.public_url`, because the redirect URI is
  `<public_url>/api/auth/oidc/<id>/callback`;
- the ID token's `iss`, `aud`, `exp` and `nonce` are validated (the token comes
  directly from the token endpoint over TLS);
- accounts are bound by `(issuer, subject)`. An existing local or LDAP user
  cannot be taken over by an OIDC login with the same name (`409
  oidc_conflict`).

**Admin protection.** A native admin is never demoted by an external
sign-in.

### 12.6 Policy enforcement

**Building the policy** (`effective_policy`, spec 009 "least privilege"):

- Admins get `ADMIN_POLICY` (everything, `"*"` lists, no limits).
- Everyone else starts from `DEFAULT_POLICY`: every switch off, every list
  empty, `max_concurrent_runs` 3. An empty `allowed_modes`,
  `allowed_providers` or `allowed_models` allows nothing; `"*"` (`ANY`)
  allows every value (`allows`).
- A user without a team gets `no_team` and stays at the base.
- A user's one team (`teams[0]`; the database allows only one) is laid over
  the base: switches, lists, `max_concurrent_runs`, `default_provider`,
  `default_model`, plus `team: {id, name}`. `Ctx.policy_for` adds
  `team_folder`.
- The user's `policy_overrides` are applied last.
- `chat_blocked` is the reason text from `chat_block` when the user has no
  team or the team allows no providers, models or modes, otherwise empty.

| Permission | New team | Allows |
|---|---|---|
| `recipes_edit` | off | Saving and deleting recipes, recipe sources |
| `skills_edit` | off | Skill, agent and project sources |
| `extensions_edit` | off | Adding, removing and configuring extensions |
| `providers_edit` | off | Provider configuration, custom providers, secrets |
| `schedules` | off | Creating and changing schedules |
| `apps` | off | Importing and deleting apps, `tools/call` from apps |
| `prompts_edit` | off | Editing system prompt templates |
| `hints_edit` | off | Personal hints (included in the composed hints only when on) |
| `tools_permissions` | off | Per-tool permission settings |
| `config_edit` | off | Writing Goose configuration keys (never `CONTEXT_FILE_NAMES`) |
| `allow_shell` | off | Shell-capable extensions (`developer`, `computercontroller`, `code_execution`, `orchestrator`), stdio extensions, inline `mcpServers` |
| `notify_webhook` | off | Personal webhook notifications |
| `allowed_modes`, `allowed_providers`, `allowed_models` | `[]` (none) | Allow-lists for session mode and model selection; `["*"]` = any |
| `allowed_roots` | `[]` | Extra absolute folders beyond the workspace and the team folder (no `"*"`) |
| `max_concurrent_runs` | 3 | Running sessions per user (0 = unlimited) |

`team_warnings(policy, hints, members)` returns the Experience page warnings
(`err`: a chat list is empty; `warn`: default not allowed, Shell on, raw
config on, members can add providers; `info`: no default model, no team
hints, personal hints allowed, no members).

**Firewall** (`check`). Any ACP method that is not in `ALWAYS`, in
`SOURCE_METHODS` (checked by source type), in the readable configuration keys
(`GOOSE_PROVIDER`, `GOOSE_MODEL`, `GOOSE_MODE`, `GOOSE_THINKING_EFFORT`,
`GOOSE_MAX_TURNS`), or in `BY_PERMISSION` for a permission the user holds is
denied with "method not available to your account". Extra argument checks:

- enabling, adding or calling a shell extension needs `allow_shell`;
- `session/new`, `session/fork` and `session/prompt` are refused while
  `chat_block` returns a reason (no team, or an empty chat list);
- `session/prompt` is refused when the chat's current provider, model or
  mode is no longer allowed (`check_session_choice`, called by the hub with
  the cached `session/load` / `session/new` result);
- `session/set_mode` and `session/set_config_option` (`provider`, `model`,
  `mode`) are checked against the lists;
- `config/upsert` of `GOOSE_PROVIDER`, `GOOSE_MODEL` and `GOOSE_MODE` is
  checked against the matching list, and `defaults/save` against
  `allowed_providers` and `allowed_models`;
- `config/upsert` and `config/remove` of `CONTEXT_FILE_NAMES`
  (`MANAGED_CONFIG_KEYS`) are refused for every non-admin;
- project directories for sources must be inside the roots.

**Path checks** (`path_allowed(path, roots)`):

- The path must be absolute, non-empty and contain no NUL.
- It must be inside a root both lexically (`normpath`/`abspath`) and after
  resolving symlinks and junctions (`realpath`).
- Comparison is case-insensitive on Windows.
- A user's roots are `[workspace, team folder, *allowed_roots]`
  (`user_roots`). Admins may use any absolute path.

The REST file endpoints (`/api/fs/*`) use the same check through
`Ctx.path_ok`.

### 12.7 Uploads and downloads

**Uploads** (`POST /api/fs/upload?dir=`):

- the directory must pass the path check;
- non-admins cannot upload a file named `AGENTS.md`, `.goosehints` or
  `.goose-web-hints.md` (`403 hint_file_refused`);
- size is limited to `server.max_upload_mb` (25), checked against
  `Content-Length` first and again while streaming in 1 MB chunks;
- at most 20 files and 20 fields per request.

`safe_upload_name` sanitises file names:

- removes any path part and characters that are unsafe on Windows;
- trims trailing dots and spaces;
- limits the name to 180 characters and 200 bytes;
- prefixes Windows device names with `_`;
- falls back to `upload.bin`.

Files are created exclusively (`open(..., 'xb')`). An existing file is never
overwritten. A collision becomes `name (2).ext`, up to 1000 attempts. Uploads
are audited.

**Downloads** (`/api/fs/download`):

- served as `application/octet-stream` with `Content-Disposition: attachment`;
- `Content-Security-Policy: sandbox; default-src 'none'` and `no-store`, so a
  downloaded HTML file can never run in the gateway's origin.

`/api/fs/read` returns at most 1 MB of text with a `truncated` flag.

### 12.8 MCP Apps

MCP Apps are untrusted HTML supplied by extensions. They are isolated in four
layers.

1. **Policy.** `/api/apps/frame` fetches the resource through the same ACP
   policy check as the WebSocket, and audits denials.
2. **Frame response headers:**

   ```
   Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups;
     default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'
   X-Frame-Options: SAMEORIGIN
   Referrer-Policy: no-referrer
   Cache-Control: no-store
   ```

   The CSP `sandbox` directive gives the document an opaque origin even if it
   is opened directly, so it cannot read the gateway's cookies or call its
   API. `allow-same-origin` and `allow-popups-to-escape-sandbox` are
   deliberately absent, and a test asserts this.
3. **iframe.** `sandbox="allow-scripts allow-forms allow-popups"` and
   `referrerpolicy="no-referrer"`.
4. **Bridge** (`createAppBridge` in `views/apps.js`, protocol `2025-06-18`):
   - Messages are accepted only when `event.source === iframe.contentWindow`.
     Origin cannot be used because the frame's origin is opaque.
   - `tools/call` may only call tools of the app's own extension. A
     `<ext>__` prefix is stripped. Any other prefix, or `__` in the bare name,
     is refused. The call goes out as `_goose/unstable/tools/call` with the
     name `<ext>__<tool>`. The server checks again that the prefix matches
     `extensionName` (`check_tool_call_target`, for every user including
     admins) and that `allow_shell` covers shell extensions.
   - Tools of the sensitive extensions (`developer`, `computercontroller`,
     `code_execution`, `orchestrator`) need per-call confirmation where the
     host enables it.
   - `ui/message` always asks the user to confirm. It is limited to 8 KB and
     one message per 5 s.
   - `ui/open-link` accepts only `http`, `https` and `mailto` and opens with
     `noopener`.
   - Display mode is always `inline`. Reported height is clamped to
     80-4000 px.

### 12.9 Untrusted Markdown

Agent output is rendered by marked and sanitised by DOMPurify (section
8.8). Remote images are removed, which prevents tracking-pixel exfiltration.
Links open in a new tab with `noopener noreferrer nofollow`.

### 12.10 SSRF guard for webhooks

User-configured webhooks are outbound requests from the gateway's network
position, so they are guarded:

- **Who can set one.** Users need `notify_webhook`. The URL must be `http(s)`
  and at most 500 characters. It is validated when saved and again when sent.
- **Address check.** `webhook_target()` resolves every address of the host
  (`getaddrinfo`), and **all** of them must pass `address_blocked()`. That
  function rejects:
  - loopback, private, link-local, reserved, multicast, unspecified and other
    non-global addresses;
  - addresses embedded in IPv4-mapped, 6to4, Teredo and NAT64 (`64:ff9b::/96`)
    forms;
  - unparseable addresses.

  `notify.allow_private_targets` turns this off for LAN-only setups.
- **DNS pinning.** The request is sent to the first resolved address, with the
  original `Host` header and TLS SNI, so a second DNS lookup cannot
  redirect it.
- **Client settings.** `httpx` uses `follow_redirects=False` and
  `trust_env=False` (no environment proxies), with an 8 s timeout.

---

## 13. Configuration loading

`docs/CONFIGURATION.md` lists every key. This section covers the mechanism
only.

1. **Defaults.** `DEFAULTS` in `config.py`. The sections are `server`, `paths`,
   `goose`, `auth`, `notify` and `host_tasks`.
2. **Configuration file.** The first file that exists among:
   - `--config FILE`;
   - `$GOOSE_WEB_CONFIG`;
   - `<default profiles root>/_system/config.yaml`.

   It is YAML and is merged over the defaults section by section.
3. **Environment.** `GOOSE_WEB__<SECTION>__<KEY>=value` overrides a single key.
   Only two levels are supported. Values are coerced: `true/yes/on` and
   `false/no/off` become booleans, digits become integers, and values starting
   with `[` or `{` are parsed as YAML. For example:

   ```
   GOOSE_WEB__SERVER__PUBLIC_URL=https://goose.example.org
   GOOSE_WEB__SERVER__TRUSTED_PROXIES=["127.0.0.1"]
   ```

4. **Command line.** `serve --host/--port` override the bind address. A
   `--host` value is also added to the Host allow-list.
5. **Database settings.** Settings changed at run time in the admin UI
   (brand, default team, session hours, TOTP rules, sign-in providers, peers)
   live in the `settings` table, not in `config.yaml`. `session_hours` in the
   database overrides `auth.session_hours`.

Derived values:

- `profiles_root` defaults to a fixed folder on the system drive on Windows,
  and to `$GOOSE_WEB_PROFILES` or `/var/lib/goose-web/profiles` elsewhere.
- `system_dir` defaults to `<profiles_root>/_system`.
- `goose_binary` is `goose.binary`, otherwise `goose` on `PATH`, otherwise
  known install locations.
- `public_url` has its trailing slash removed.

The default native Goose root is `%APPDATA%\Block\goose` on Windows and
`~/.config/goose` elsewhere.

---

## 14. Packaging, deployment and CI

### 14.1 Python package

**`pyproject.toml`:**

- name `goose-web`, version 1.0.0, Python >= 3.11, Apache-2.0;
- built with hatchling;
- console script `goose-web = goose_web.__main__:main`;
- runtime dependencies: `starlette`, `uvicorn`, `websockets`, `httpx`,
  `pyyaml`, `ldap3`, `python-multipart`;
- the `dev` extra adds `pytest` and `pytest-asyncio`.

**`requirements.lock`** is generated with:

```
pip-compile --generate-hashes --output-file=requirements.lock --strip-extras pyproject.toml
```

Every installer, the Dockerfile and CI install with `--require-hashes` from
this file, then install the package itself with `--no-deps`. A test checks
that the lock file is hashed and covers every dependency in `pyproject.toml`.

**Vendored front-end libraries.**

| File | Library | Version | License |
|---|---|---|---|
| `marked.esm.js` | marked | 15.0.12 | MIT |
| `purify.es.mjs` | DOMPurify | 3.4.17 | Apache-2.0 or MPL-2.0 |
| `highlight.min.js`, `hljs-dark.css`, `hljs-light.css` | highlight.js | 11.12.0 | BSD-3-Clause |
| `qrcode.esm.js` | qrcode-generator (with an `export default` appended) | 1.4.4 | MIT |

`static/vendor/SHA256SUMS` lists their hashes, and a test fails on any
mismatch. `.gitattributes` marks `goose_web/static/vendor/*` as `-text`, so
line endings are never converted.

### 14.2 Docker image

`docker/Dockerfile` builds one image that contains the gateway and the Goose
CLI (linux/amd64 and linux/arm64).

- **Base.** `python:3.13-slim-bookworm`, pinned by multi-arch digest
  (Dependabot updates it).
- **Goose CLI.**
  - `ARG GOOSE_VERSION=1.57.0` plus `GOOSE_SHA256_AMD64` and
    `GOOSE_SHA256_ARM64`.
  - The release tarball for the target architecture is downloaded over
    `https` (`--proto '=https' --tlsv1.2`) and checked with `sha256sum -c`.
  - It is installed to `/usr/local/bin/goose` and checked with
    `goose --version`.
  - Changing the version without supplying matching checksums fails the build
    on purpose.
- **Python dependencies.** `pip install --require-hashes --only-binary=:all:
  -r requirements.lock`, then `pip install --no-deps .`.
- **Runtime user.** Non-root `goose` (uid 1000), with `/data` as the volume.
- **Environment:**
  - `GOOSE_WEB__SERVER__HOST=0.0.0.0` and `GOOSE_WEB__SERVER__PORT=8710`;
  - `GOOSE_WEB__PATHS__PROFILES_ROOT=/data` and
    `GOOSE_WEB__GOOSE__BINARY=/usr/local/bin/goose`;
  - `GOOSE_WEB__GOOSE__NATIVE_SCHEDULER=on` and
    `GOOSE_WEB__GOOSE__DEFAULT_WORKDIR_NATIVE=/data/workspace`;
  - `GOOSE_DISABLE_KEYRING=1`.
- **Process.** `HEALTHCHECK` with `curl -fsS http://127.0.0.1:8710/healthz`
  every 30 s. The entry point is `tini -- goose-web-entrypoint serve`.

**`docker/entrypoint.sh`:**

- It refuses to run as root (exit 3), sets `umask 077`, and creates
  `/data/workspace`.
- On the first start (no `/data/_system/goose-web.db`) it runs
  `python -m goose_web init` with the admin name from `GOOSE_WEB_ADMIN`. The
  password comes from `GOOSE_WEB_ADMIN_PASSWORD_FILE`, from stdin, or is
  generated and printed once to the log.
- The password variables are unset before the gateway starts.
- `serve`, `init`, `user`, `check` and `version` are passed to
  `python -m goose_web`. Any other command is executed as given.

**`docker/compose.yaml`:**

- publishes `127.0.0.1:8710:8710` (loopback only, put a reverse proxy in
  front);
- sets an example `GOOSE_WEB__SERVER__PUBLIC_URL=https://goose.example.org`
  and `TRUSTED_PROXIES` (trust only the proxy's own address);
- uses the named volume `goose-web-data:/data`;
- hardening: `read_only: true`, tmpfs `/tmp` and `/home/goose`,
  `cap_drop: [ALL]`, `no-new-privileges`, `pids_limit: 1024`,
  `mem_limit: 4g`.

### 14.3 Installers

| Script | Behaviour |
|---|---|
| `scripts/install.ps1` | Installs for the current non-elevated Windows user (refuses elevation). Creates `.venv` (with uv, or venv and pip), installs from `requirements.lock` with `--require-hashes`, then the package with `--no-deps`. |
| `scripts/install.sh` | Linux/macOS, non-root. Options: `--profiles-root` (default `~/.local/share/goose-web`), `--goose-appdata DIR|fresh`, `--host`, `--port`, `--public-url`, `--trusted-proxy`, `--systemd`. The admin is the current account, and its random initial password is shown once. |
| `scripts/register-service.ps1` | Run elevated once. Registers a logon task that runs the gateway as the given user with `RunLevel Limited`, plus a firewall rule (default scope `LocalSubnet`). |
| `scripts/start-gateway.cmd` | Runs the gateway in the foreground from `.venv`. |
| `scripts/uninstall.ps1` | Removes the task and the firewall rule. Data is kept. |

### 14.4 CI

`.github/workflows/ci.yml` runs on push and pull request with
`permissions: contents: read`.

- **test job.**
  - Matrix: `ubuntu-latest` and `windows-latest`, each with Python 3.11 and
    3.13 (`fail-fast: false`).
  - Git is set to `core.autocrlf false` and `eol lf`, because vendored files
    are checked byte for byte.
  - Actions are pinned by commit SHA, and checkout uses
    `persist-credentials: false`.
  - Install: `pip install --require-hashes -r requirements.lock`, then
    `pip install --no-deps -e .`, then pytest and pytest-asyncio.
  - Run: `python -m pytest -q`.
- **audit job.** `pip-audit -r requirements.lock` on Python 3.13.

`.github/dependabot.yml` checks pip, the Docker base image and GitHub
Actions weekly. pip updates must regenerate `requirements.lock` in the same
pull request.

---

## 15. Testing layout

Tests use pytest with `asyncio_mode = auto`. No Goose binary is needed: the hub
tests start a fake ACP agent, and the API tests use Starlette's `TestClient`
with fake profile services. `pyproject.toml` sets `--basetemp=.pytest_tmp`
(a project-local temp folder, because some Windows hosts deny the default temp
location) and disables the cache plugin.

| File | Covers |
|---|---|
| `tests/test_security.py` | Password hashing round trip, password rules, tokens, TOTP (RFC 6238 test vector), rate limiter, `safe_name`, `winsec` reports. |
| `tests/test_policy.py` | Admin bypass, forced `session/new` client metadata, cwd outside roots, unknown method denied, extension permissions, mode/model allow-lists, sources by type, config read allow-list, one-team policy, shell tool calls by name prefix, reserved usernames. |
| `tests/test_profiles.py` | Isolated layout and base extensions, team items and secrets, library listing, native scheduler yielding to Goose Desktop. |
| `tests/test_team_profiles.py` | Spec 009: new teams allow nothing, no team cannot chat, Any and explicit lists, config writes and the locked `CONTEXT_FILE_NAMES`, prompts refused in chats with a disallowed model, team warnings, roots, the 1.4 migration, hints order and dropped personal hints, the hints file and worker environment, team folder and default model, one team per user (moves), effective hints view and upload refusal. |
| `tests/test_hub.py` | A `FakeAgent` WebSocket server (`initialize`, `session/new`, `session/load`, `session/prompt`). Tests: a run survives a tab disconnect and is replayed, policy denial, the second answer to an ask loses, idle replay only while unchanged elsewhere, the watcher announces external changes, Retry/add/remove of an extension updates the replayed start-up status. `tests/test_edit_and_paths.py`: prompt stamping (`_gw/prompt_created` + echo), truncate guard and buffer invalidation, `native-root`, `GOOSE_PATH_ROOT` auto-detection, no author-specific goose path. |
| `tests/test_auth_hardening.py` | TOTP replay and lockout, TOTP settings, OIDC subject binding and takeover protection, LDAP plaintext refusal, token revocation on reset, disable and password change, admin and CLI two-factor reset, column and link-table allow-lists, audit purge, additive migration of a legacy database. |
| `tests/test_platform_hardening.py` | Generated admin password and one-time printing, `init` password options, path containment including symlink escapes, `address_blocked`, webhook pinning and no redirects, log rotation, vendored file checksums, hashed lock file covering `pyproject.toml`, Dockerfile download verification, SHA-pinned actions. |
| `tests/test_release_fixes.py` | Regression tests for the `NEW-nn` findings: WebSocket token only in the header and never with `Origin`, Host allow-list and `HostGuard` (including WebSockets and forwarded hosts), allowed origins with and without `public_url`, OIDC requires `public_url`, `tools/call` prefix matching, upload name sanitising and exclusive create, download headers, app frame CSP and policy check, webhook validation at save time, `trust_env=False`, CLI reset revokes tokens, vendored files not EOL-converted. |
| `tests/test_signin_hardening.py` | Strong-password rules and generated passwords, address keys, the address block (threshold, reset on success, 30-day window, expiry, permanent block, threshold 0, trusted proxies and exempt networks, IPv6 /64, restart), `IPBlockGuard` for HTTP and WebSocket and forwarded addresses, admin list/unblock API, login `403 ip_blocked`, forced change of admin-set passwords, weak existing password forces a change, `ip` CLI. |
| `tests/test_api.py` | Helpers of the apps frame endpoint (HTML extraction from resource contents). |

Run the suite with:

```
python -m pytest -q
```

---

## 16. Extension points: adding a feature

### 16.1 A new REST endpoint

1. Write a handler in `api.py`:

   ```python
   async def my_thing(request):
       c = ctx(request)
       ident = c.require(request)              # admin=True for admin endpoints
       body = await body_json(request)         # for POST/PUT/PATCH
       if not body.get("name"):
           raise HTTPError(400, "bad_request", "name is required")
       c.audit(request, "my.thing", ident.user, target=body["name"])
       return ok({"done": True})
   ```

2. Add `Route("/api/my/thing", my_thing, methods=["POST"])` to `routes`.
3. Any file system path from the client must go through `c.path_ok(user, path)`.
   Never trust a path from the browser.
4. Call it from the SPA with `POST('/api/my/thing', {...})` from `api.js`. The
   CSRF header is added automatically.
5. Document it in `docs/API.md` and add a `TestClient` test. The
   `tests/test_auth_hardening.py` fixtures show how to sign in.

### 16.2 Using a new ACP method

The firewall denies unknown methods, so a new Goose method used by the UI
needs a policy decision:

1. Add it to `ALWAYS` (safe for every user), or to `BY_PERMISSION` under the
   right permission in `policy.py`. Add argument checks if it takes paths,
   extensions, providers or models.
2. If it changes state, add it to `AUDITED_PREFIXES` in `hub.py`.
3. If it affects herd or session state, extend `_post_response()` or
   `_herd_from_update()`.
4. Add cases to `tests/test_policy.py`.
5. Call it from the SPA with `rpc.call(G('my/method'), params)`.

### 16.3 A new gateway (`_gw/*`) method

Add a branch to `Hub.gw_method()` and handle any server-to-client notification
with `rpc.on('_gw/...', ...)` in `app.js`. Document it in the real-time channel
section of `docs/API.md`.

### 16.4 A new view

1. Create `static/js/views/myview.js`:

   ```js
   import { h } from '../ui.js';
   export function renderMyView(ctx, ...args) {
     const el = h('div', { class: 'view' }, h('h1', {}, 'My view'));
     return { el, destroy() {}, canLeave: () => true, focus() {} };
   }
   ```

2. Add it to `ROUTES` in `app.js`, next to entries such as
   `herd: () => renderHerd(ctx)`. The key is the first hash segment
   (`#/myview/...`).
3. Add a navigation entry to `NAV` in `views/sidebar.js`, gated by `policy()`
   if needed.
4. Build DOM with `h()`. Use `markdown.js` for any HTML from the agent.
5. If the shell file list changes, update `SHELL` in `sw.js` and bump
   `VERSION`. Normal JS files are network-first, so no bump is needed for code
   changes.

### 16.5 Other changes

| Change | Where |
|---|---|
| New user preference | `DEFAULT_PREFS` in `prefs.js`. Nested objects are merged with defaults by `patchPref`. |
| New team permission | `BOOL_KEYS`/`LIST_KEYS` and `DEFAULT_POLICY` in `policy.py`, `_clean_policy` in `api.py`, the team editor in `views/admin.js`. |
| New database column | Append to `MIGRATIONS` and bump `SCHEMA_VERSION` in `db.py`. Add it to JSON columns if needed. Add a migration test. |
| New configuration key | `DEFAULTS` in `config.py` (the environment override works automatically), plus `docs/CONFIGURATION.md`. |
| New provisioned item kind | `Profiles.provision` and `export_item` in `profiles.py`, team item validation in `api.py`. |
| New vendored library | Add it to `static/vendor/`, `SHA256SUMS` and `vendor/README.md`. Add it to `SHELL` in `sw.js` and bump `VERSION`. |
| New Goose version in Docker | `GOOSE_VERSION` and both `GOOSE_SHA256_*` build arguments. |

