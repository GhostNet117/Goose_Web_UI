# Goose Web gateway API

This is the contract between the browser SPA (or any API client) and the gateway. All bodies are JSON
(UTF-8). Timestamps are ISO-8601 strings, or Unix seconds where the field name ends in `At` and the value
is a number.

## Authentication

* **Browser:** `POST /api/auth/login` sets the cookie `__Host-gw`, which is HttpOnly, Secure and
  SameSite=Strict. When the gateway is served over plain HTTP on loopback during development, the cookie
  name is `gw` and it is not Secure. Every non-GET request must send the header `X-CSRF-Token: <csrf>`,
  using the `csrf` value from the login response or from `GET /api/me`.
* **Automation:** send the header `Authorization: Bearer gwt_<token>`. Users create tokens in Settings →
  Account → API tokens. Bearer requests need no CSRF header.
* **Error format:** `{ "error": "<code>", "message": "<human text>" }` with status 400/401/403/404/409/
  413/429/500. When `GET /api/me` returns 401, the SPA shows the login screen.
* **Forced password change:** when a login returns `mustChangePassword: true`, every API call except
  `/api/me`, `/api/me/password` and `/api/auth/logout` returns `403 {error:"password_change_required"}`.

## Public endpoints

| Method | Path | Body / result |
|---|---|---|
| GET | `/healthz` | `ok` (text) |
| GET | `/api/auth/config` | `{ brand:{name, tagline}, version, local:true, ldap:{enabled, label}, oidc:[{id,label}] }` |
| POST | `/api/auth/login` | `{username, password, totp?, remember?}` → `{user, csrf, mustChangePassword}`. Errors: `401 invalid_credentials`, `401 totp_required` (ask for the code and resend), `423 locked`, `429 rate_limited` |
| POST | `/api/auth/logout` | `{}` → `{ok:true}` |
| GET | `/api/auth/oidc/{id}/start` | 302 to the IdP |
| GET | `/api/auth/oidc/{id}/callback` | 302 to `/` (or to `/#/login?error=...`) |

## Current user

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/me` | `{user, csrf, policy, teams:[{id,name}], scheduler:{enabled, owner, reason}, version, gooseVersion, isAdmin}` |
| POST | `/api/me/password` | `{current, new}` → `{ok}`. Error: `400 weak_password {problems:[...]}` |
| PATCH | `/api/me` | `{displayName?, email?}` |
| GET/PUT | `/api/me/prefs` | free-form JSON for UI preferences: theme, accent, density, fontSize, notifications, sidebar, herd, enterToSend, showTimestamps, codeTheme, pinned. PUT replaces the whole object. Max 64 KB |
| POST | `/api/me/totp/setup` | → `{secret, uri}` |
| POST | `/api/me/totp/enable` | `{code}` → `{ok}` |
| POST | `/api/me/totp/disable` | `{password}` → `{ok}` |
| GET | `/api/me/tokens` | `[{id,name,prefix,createdAt,lastUsed,expiresAt}]` |
| POST | `/api/me/tokens` | `{name, days?}` → `{id, token}`. The token is shown once |
| DELETE | `/api/me/tokens/{id}` | |
| GET | `/api/me/logins` | active browser sessions `[{id, createdAt, lastSeen, ip, userAgent, current}]` |
| DELETE | `/api/me/logins/{id}` | revoke one browser session (`id` = first 12 hex chars of its hash) |
| GET | `/api/me/hints` | `{personal, assigned:[{id,name,description}], effective, editable}` |
| PUT | `/api/me/hints` | `{personal}`. Requires `policy.hints_edit`. For the admin's native profile this writes `<native>/config/.goosehints` and backs up the previous file first |
| GET | `/api/me/notify` / PUT | `{webhook?: url, events:["needs_you","done","error"]}`. A webhook requires `policy.notify_webhook` |

## Files (scoped to the user's allowed roots; admin: any path)

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/fs/roots` | `{roots:[{path,label}], home, defaultCwd}` |
| GET | `/api/fs/list?path=` | `{path, parent, entries:[{name, path, dir, size, mtime}]}` (max 2000 entries) |
| POST | `/api/fs/mkdir` | `{path}` |
| POST | `/api/fs/upload?dir=<abs dir>` | multipart `file` (one or more) → `{files:[{name,path,size,mime}]}`. Max size `server.max_upload_mb` |
| GET | `/api/fs/download?path=` | the file as an attachment |
| GET | `/api/fs/read?path=` | `{path, content, truncated}` (text, max 1 MB) |

## Apps

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/apps/frame?name=<app name>&sessionId=<optional>` | The app's HTML (from `_goose/unstable/apps/export`). It is served with `Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups; default-src * data: blob: 'unsafe-inline' 'unsafe-eval'`, which gives it an opaque origin with no cookie or DOM access to the gateway. Embed it as `<iframe sandbox="allow-scripts allow-forms allow-popups" src="/api/apps/frame?name=...">`. Never use `srcdoc`, because a srcdoc frame inherits the SPA's strict CSP. The SPA bridges `postMessage` calls from the app to ACP methods (for example `tools/call` → `_goose/unstable/tools/call`). Every bridged call is checked again by the gateway policy |

## Static / SPA

* `/` → `static/index.html` (sent with `Cache-Control: no-cache`)
* `/static/*` → `goose_web/static/*` (immutable assets, ETag)
* `/sw.js` → `static/sw.js` (service worker with root scope; it caches only the app shell and never `/api` or `/ws`)
* `/manifest.webmanifest` → `static/manifest.webmanifest`
* SPA CSP: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; connect-src 'self'; frame-src 'self'; font-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'`. This means **no inline scripts and no inline event handlers**. Inline `style` attributes are allowed.

## Herd (live agents)

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/herd` | `{machine:{name,url}, agents:[Agent], peers:[{name,url,ok,error?,agents:[Agent]}]}`. Admins can add `?all=1` to include every profile |

`Agent = {profile, username, sessionId, title, cwd, status, since, runId, lastText, usage:{used, contextLimit, cost}, ask?:{id, kind, title}}`.
`status` is one of `working`, `needs_you`, `idle`, `done` (finished since you last looked), `error`, `offline`.

## Admin (role = admin)

| Method | Path | Notes |
|---|---|---|
| GET/POST | `/api/admin/users` | POST `{username, displayName?, email?, role:"user"\|"admin", password?, mustChangePassword?:true, teams:[id], hints:[id], profileMode:"isolated"\|"native", authSource:"local"\|"ldap"\|"oidc"}` → `{user, tempPassword?}` |
| GET/PATCH/DELETE | `/api/admin/users/{id}` | PATCH accepts any of the POST fields plus `disabled`, `policyOverrides`. DELETE `?purgeProfile=1` deletes the profile folder; otherwise the folder is renamed to `_deleted/<name>-<ts>` |
| POST | `/api/admin/users/{id}/reset-password` | → `{tempPassword}` (the user must change it at next login) |
| POST | `/api/admin/users/{id}/unlock` | |
| POST | `/api/admin/users/{id}/provision` | re-applies teams, hints and policy to the profile → `{changes:[...], restartPending}` |
| GET/POST | `/api/admin/teams` | `{name, description, policy}` |
| GET/PATCH/DELETE | `/api/admin/teams/{id}` | PATCH `{name?, description?, policy?, members?:[userId], hints?:[hintsId]}` |
| GET/POST | `/api/admin/teams/{id}/items` | POST `{kind:"recipe"\|"skill"\|"extension"\|"provider", name, payload?}` or `{kind, fromProfile:<username>, ref:<id/path/key>}` copies the item from a profile library |
| DELETE | `/api/admin/teams/{id}/items/{itemId}` | |
| GET/POST | `/api/admin/hints` | `{name, description, content}` |
| GET/PUT/DELETE | `/api/admin/hints/{id}` | |
| GET | `/api/admin/library?profile=<username>&kind=recipe\|skill\|extension\|provider` | read-only listing of items in a profile that can be added to a team `[{kind, ref, name, description, source}]` |
| GET/PUT | `/api/admin/auth` | `{ldap:{enabled, url, bindDn, bindPassword?, userBase, userFilter, adminGroupDn?, groupTeamMap:{groupDn: teamId}, startTls, label}, oidc:[{id,label,issuer,clientId,clientSecret?,scopes,adminClaim?,adminValue?,teamClaim?,autoCreate}], localEnabled}`. Secrets are write-only: reads return `"********"` when they are set |
| GET/PUT | `/api/admin/settings` | `{brand:{name,tagline}, defaultTeamId, sessionHours, allowSelfTotp, requireTotpForAdmins, peers:[{name,url,token?}]}` |
| GET | `/api/admin/audit?limit=&before=&user=&action=` | `[{id, ts, username, ip, action, target, detail, ok}]` |
| GET | `/api/admin/system` | `{version, gooseVersion, gooseBinary, integrity, elevated, user, profilesRoot, nativeRoot, desktopRunning, scheduler:{owner}, workers:[{key, username, pid, port, state, startedAt, clients, activeRuns, scheduler, restarts, lastError}]}` |
| POST | `/api/admin/system/workers/{key}/{action}` | `action` = `restart` \| `stop` |
| GET | `/api/admin/ownership?profile=<username>` | `{root, scanned, foreign:[{path, owner}], truncated}`: files not owned by the gateway user |
| GET | `/api/admin/hosttasks` | `[{path, name, state, lastRun, lastResult, nextRun, runAs, runLevel, logonType, elevated, actions, author}]` |
| POST | `/api/admin/hosttasks/action` | `{path, action:"run"\|"end"\|"enable"\|"disable"}` |
| GET | `/api/admin/logs?worker=<key>&lines=500` | `{lines:[...]}` tail of the gateway or worker log |

## Real-time channel: `GET /ws` (WebSocket)

The socket is authenticated with the session cookie, and the `Origin` header must match the public
origin. API tokens can use `?token=gwt_...`, which is only accepted when no Origin header is present.
Each socket is bound to the user's own profile worker. Admins can add `?profile=<username>` to drive
another user's profile (audited).

Frames are JSON-RPC 2.0 text frames.

### Client → gateway

* **Any ACP method**, for example `session/new`, `session/prompt` or `_goose/unstable/recipes/list`
  (see `acp-reference.md`). The gateway checks each method against the user's policy, rewrites the id,
  forwards it to Goose, and returns the response with the original id. A denied call gets
  `{error:{code:-32003, message:"forbidden: <reason>"}}`.
  * `session/new`: the gateway forces `_meta.client = "goose-web"`, so the session is a normal user
    session that the Goose Desktop also lists. `cwd` must be inside the allowed roots.
  * `session/load`: if the session is already live in this worker, the gateway answers from its buffer.
    It replays the buffered `session/update` frames to this socket only, then sends the cached result
    with `_meta.gw = {replayed:true, running:bool}`.
* **`_gw/hello`** `{}` → `{user, profile, agent:<initialize result>, asks:[AgentRequest], herd:[Agent], upstream:{state}}`
* **`_gw/watch`** `{sessionIds:[...]}` → `{ok}`. The socket receives full `session/update` streams only for the
  watched sessions. Herd summaries always flow.
* **`_gw/herd`** `{all?:bool}` → `{agents:[Agent]}`
* **`_gw/seen`** `{sessionId}`: changes `done` to `idle` for that session.
* **Responses to agent requests:** `{jsonrpc:"2.0", id:<id of the forwarded request>, result:{...}}`. The
  first answer wins. Later answers get the notification `_gw/ask_resolved` instead.

### Gateway → client

* **Goose notifications**, unchanged: `session/update`, `_goose/unstable/session/update`, and
  `_goose/unstable/providers/authentication/device-code`.
* **Agent requests**, forwarded with the gateway's id: `session/request_permission`, `elicitation/create`,
  and `_goose/unstable/session/recipe/request-params`. They go to every socket of the profile and are
  replayed to sockets that connect later.
* **`_gw/ask_resolved`** `{id, sessionId, by}`
* **`_gw/herd_update`** `{agent:Agent}`
* **`_gw/upstream`** `{state:"starting"|"ready"|"down", error?}`
* **`_gw/notice`** `{level, message}`

### Herd state machine (per session)

```
idle --prompt sent / activeRunId set--> working --permission or elicitation--> needs_you
working --prompt response (stopReason)--> done --(_gw/seen or watched by a socket)--> idle
any --JSON-RPC error on prompt / worker crash--> error
```
