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
  Account → API tokens. Bearer requests need no CSRF header. The same header authenticates the `/ws`
  handshake for non-browser clients (see below). Tokens are never accepted in a URL (`?token=` is not
  supported). A user's tokens are revoked when their password is changed, set or reset, and when the
  account is disabled.
* **Error format:** `{ "error": "<code>", "message": "<human text>" }` with status 400/401/403/404/409/
  413/423/429/500/503. When `GET /api/me` returns 401, the SPA shows the login screen.
* **Host check:** every request (HTTP and WebSocket) must carry an allow-listed `Host` header: the
  `server.public_url` host, `localhost`, `127.0.0.1`, `::1`, the bind address, or a name in
  `server.allowed_hosts`. Other hosts get `400` with the plain-text body `invalid host`. A WebSocket is refused
  with an HTTP 400 denial response where the server supports it, otherwise it is closed with code 1008.
  `GET /healthz` is exempt.
* **Forced password change:** when a login returns `mustChangePassword: true`, every API call except
  `/api/me`, `/api/me/password` and `/api/auth/logout` returns `403 {error:"password_change_required"}`.

## Public endpoints

| Method | Path | Body / result |
|---|---|---|
| GET | `/healthz` | `ok` (text) |
| GET | `/api/auth/config` | `{ brand:{name, tagline}, version, local:true, ldap:{enabled, label}, oidc:[{id,label}] }` |
| POST | `/api/auth/login` | `{username, password, totp?, remember?}` → `{user, csrf, mustChangePassword, totpEnrolmentRequired}`. Errors: `401 invalid_credentials`, `401 totp_required` (ask for the code and resend), `401 totp_invalid` (wrong or already used code; counts toward the lockout), `423 locked`, `429 rate_limited`, `403 ip_blocked` (too many failed sign-ins from this address; while blocked, every request from it gets this 403), `503 ldap_insecure` (LDAP configured without TLS, see `ldap.allowInsecure`), `403 bad_origin` |
| POST | `/api/auth/logout` | `{}` → `{ok:true}` |
| GET | `/api/auth/oidc/{id}/start` | 302 to the IdP. On an error, 302 to `/#/login?error=<code>`, for example `oidc_needs_public_url` (OIDC needs `server.public_url`) |
| GET | `/api/auth/oidc/{id}/callback` | 302 to `/` (or to `/#/login?error=...`, for example `oidc_conflict` when the name belongs to a local/LDAP account or is bound to another issuer + subject) |

## Current user

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/me` | `{user, csrf, policy, team:{id,name}\|null, teams:[{id,name}], scheduler:{enabled, owner, reason}, workspace, version, gooseVersion, isAdmin, totpEnrolmentRequired}`. `team` is the user's one team (`null` = no team); `teams` is the same as a list of 0 or 1 entries, kept for older clients. `policy` is the effective policy: the switches, the lists (`["*"]` = any, `[]` = none), `max_concurrent_runs`, `default_provider`/`default_model`, `team`, `team_folder`, and `chat_blocked`: a reason text when the user cannot chat (no team, or the team allows no providers, models or modes), otherwise empty. Admins always get an empty `chat_blocked`. `totpEnrolmentRequired` is true for an admin without TOTP while "Require two-factor for administrators" is on |
| POST | `/api/me/password` | `{current, new}` → `{ok}`. Signs out your other sessions and revokes all your API tokens. Error: `400 weak_password {problems:[...]}` |
| PATCH | `/api/me` | `{displayName?, email?}` |
| GET/PUT | `/api/me/prefs` | free-form JSON for UI preferences: theme, accent, density, fontSize, notifications, sidebar, herd, enterToSend, showTimestamps, codeTheme, pinned. PUT replaces the whole object. Max 64 KB |
| POST | `/api/me/totp/setup` | → `{secret, uri}`. `403 totp_self_disabled` for non-admins when self-service two-factor is turned off, `409 already_enabled` |
| POST | `/api/me/totp/enable` | `{code}` → `{ok}`. `400 totp_invalid`. The code's time step is used up, so the same code cannot be used to sign in |
| POST | `/api/me/totp/disable` | `{password}` → `{ok}`. `403 required` for admins while two-factor is required for administrators |
| GET | `/api/me/tokens` | `[{id,name,prefix,createdAt,lastUsed,expiresAt}]` |
| POST | `/api/me/tokens` | `{name, days?}` → `{id, token}`. The token is shown once |
| DELETE | `/api/me/tokens/{id}` | |
| GET | `/api/me/logins` | active browser sessions `[{id, createdAt, lastSeen, ip, userAgent, current}]` |
| DELETE | `/api/me/logins/{id}` | revoke one browser session (`id` = first 12 hex chars of its hash) |
| GET | `/api/me/hints` | `{personal, assigned:[{id,name,description,content}], effective, editable, native, personalDropped, team:{id,name}\|null}`. `effective` is the composed `config/.goose-web-hints.md` (team hints last, as the final word). `personalDropped` is true when the user has personal hints but the team does not allow them (`hints_edit` off), so Goose does not get them. For the admin's native profile: `{personal, assigned, effective, editable:true, native:true, path}` |
| PUT | `/api/me/hints` | `{personal}`. Requires `policy.hints_edit` (`403 forbidden` otherwise). For an isolated profile it rewrites `config/.goose-web-hints.md`. For the admin's native profile this writes `<native>/config/.goosehints` and backs up the previous file first |
| GET | `/api/me/notify` / PUT | `{webhook?: url, events:["needs_you","done","error"]}`. A webhook requires `policy.notify_webhook` (`403 forbidden`) and must be an absolute http(s) URL of at most 500 characters (`400 bad_url`). Unless `notify.allow_private_targets` is true, every address the host resolves to must be a public internet address, otherwise `400 webhook_blocked`. Webhooks are sent to the checked address, without following redirects |

## Files (scoped to the user's allowed roots; admin: any path)

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/fs/roots` | `{roots:[{path,label}], home, defaultCwd}`. For non-admins: the workspace (`Workspace`), the team folder (label `Team: ` + the team name), then the team's extra folders (labelled with the folder name) |
| GET | `/api/fs/list?path=` | `{path, parent, entries:[{name, path, dir, size, mtime}]}` (max 2000 entries) |
| POST | `/api/fs/mkdir` | `{path}`. Non-admins get `403 hint_file_refused` when the new folder is named `AGENTS.md`, `.goosehints` or `.goose-web-hints.md` (any case) |
| POST | `/api/fs/upload?dir=<abs dir>` | multipart `file` (one or more, at most 20) → `{files:[{name,path,size,mime}]}`. Max size per file `server.max_upload_mb` (`413 too_large`). Names are sanitised: last path component only, Windows-invalid characters and trailing dots/spaces removed, device names such as `CON` prefixed with `_`, `upload.bin` if nothing is left. Non-admins get `403 hint_file_refused` for a file named `AGENTS.md`, `.goosehints` or `.goose-web-hints.md` (team hints are managed by the administrator). Existing files are never overwritten: the file is saved as `name (1).ext`, `name (2).ext` and so on. `name` and `path` in the result are the names actually used |
| GET | `/api/fs/download?path=` | the file as an attachment: always `Content-Type: application/octet-stream`, `Content-Disposition: attachment`, `Content-Security-Policy: sandbox; default-src 'none'`, `Cache-Control: no-store` |
| GET | `/api/fs/read?path=` | `{path, content, truncated}` (text, max 1 MB) |

## Apps

| Method | Path | Body / result |
|---|---|---|
| GET | `/api/apps/frame?name=<app name>` or `/api/apps/frame?sessionId=<id>&ext=<extension>&uri=ui://...` | The app's HTML: a saved app (from `_goose/unstable/apps/export`), or the `ui://` resource of a tool in one of your sessions for an inline app (from `_goose/unstable/resources/read`). These ACP reads pass the same policy check as `/ws` calls, and denials are audited (`403 forbidden`). Other errors: `400 bad_name` / `400 bad_app_ref`, `404 app_not_found`. It is served with `Content-Security-Policy: sandbox allow-scripts allow-forms allow-popups; default-src * data: blob: 'unsafe-inline' 'unsafe-eval'; frame-ancestors 'self'`, `X-Frame-Options: SAMEORIGIN`, `Cache-Control: no-store` and `Referrer-Policy: no-referrer`, which gives it an opaque origin with no cookie or DOM access to the gateway. Embed it as `<iframe sandbox="allow-scripts allow-forms allow-popups" src="/api/apps/frame?name=...">`. Never use `srcdoc`, because a srcdoc frame inherits the SPA's strict CSP. The SPA bridges `postMessage` calls from the app to ACP methods (for example `tools/call` → `_goose/unstable/tools/call`). Every bridged call is checked again by the gateway policy. An app may only call tools of its own extension: a `tools/call` whose `<extension>__` name prefix differs from `extensionName` is denied for every user, admins included. Calls into `developer`, `computercontroller`, `code_execution` or `orchestrator` from grid or imported apps need the user's confirmation each time. Chat messages sent by an app (`ui/message`) need confirmation, are capped at 8 KB and limited to one per 5 seconds |

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
| GET/POST | `/api/admin/users` | POST `{username, displayName?, email?, role:"user"\|"admin", password?, team?:id\|null, hints:[id], profileMode:"isolated"\|"native", authSource:"local"\|"ldap"\|"oidc"}` → `{user, tempPassword?}`. `team` is the user's one team; without it the user joins the default team, and `team:null` creates a user without a team (can sign in, cannot chat). The older `teams:[id]` is still accepted with at most one entry (`400 one_team` otherwise). An unknown team id, or a value that is not a number, gives `400 bad_team`. GET returns users with `team` (id or `null`), `teams` (0 or 1 ids), `hints`, `policyOverrides` and `profilePath` |
| GET/PATCH/DELETE | `/api/admin/users/{id}` | PATCH accepts any of the POST fields plus `disabled`, `policyOverrides` → `{user, changes}`. Setting `team` (or `teams`) replaces the user's membership (one team per user) and re-provisions the profile. A password set here (or in POST) must meet the password rules (`400 weak_password {problems}`) and must always be changed at the user's next sign-in (`mustChangePassword` is ignored since 1.3.0). Disabling a user or setting a password revokes the user's sessions and API tokens. DELETE `?purgeProfile=1` deletes the profile folder; otherwise the folder is renamed to `_deleted/<name>-<ts>` |
| POST | `/api/admin/users/{id}/reset-password` | → `{tempPassword}` (the user must change it at next login). Revokes the user's sessions and API tokens |
| GET | `/api/admin/ip-blocks` | → `{items:[{ip, blocked, failures, lastFailureAt, lastUsername, blockedAt, blockedUntil}], threshold, windowDays, blockDays, exempt}`. Blocked addresses and addresses collecting failed sign-ins (IPv6 as a /64), blocked first. `blockedUntil: null` while blocked = until unblocked |
| POST | `/api/admin/ip-blocks/unblock` | `{ip}` or `{all:true}` → `{removed:n}`. Ends the block and clears the count. `404 not_found` if the address is not listed. Audit `auth.ip.unblocked` |
| POST | `/api/admin/users/{id}/reset-totp` | removes the user's two-factor (lost authenticator): clears the secret, unlocks, ends the user's sessions and revokes their API tokens → `{user, sessionsEnded:true, tokensRevoked:n}`. `409 totp_not_enabled` if the user has no two-factor, `400 self` for your own account. Audit `user.totp.reset` |
| POST | `/api/admin/users/{id}/unlock` | |
| POST | `/api/admin/users/{id}/provision` | re-applies the team, hints and policy to the profile → `{changes:[...], restartPending}` |
| GET | `/api/admin/users/{id}/hints` | "View effective hints": `{username, native, effective, path, team, personalDropped, note}`. `effective` is the text the user's Goose loads and `path` the file; `team` is the team name or `null`; `personalDropped` is true when personal hints are left out because the team does not allow them; `note` explains the loading rule (isolated: only this file, hints files in working folders are ignored; native: Goose also loads `AGENTS.md` and `.goosehints` from the working folder). A native profile returns `{username, native:true, effective, path, note}` |
| GET/POST | `/api/admin/teams` | GET → `[Team]`. POST `{name, description?, policy?}` → `{id, team:Team}`. A new team starts with every switch off and nothing allowed. Errors: `400 bad_name`, `409 exists`, `400 bad_folder` |
| GET/PATCH/DELETE | `/api/admin/teams/{id}` | GET → `Team`. PATCH `{name?, description?, policy?, members?:[userId], hints?:[hintsId]}` → `{team:Team, changes:{<username>:[...]}, moved:["<username> (from <team>)"]}`. `members` is the complete member list; users who are in another team are moved here (one team per user) and listed in `moved`, which the `team.update` audit entry records too. `policy` replaces the stored policy (`400 bad_folder` for a relative `share_folder`, or an `allowed_roots` entry that is `*` or not absolute). DELETE removes the team: its members are left without a team and its folder stays on disk |
| GET/POST | `/api/admin/teams/{id}/items` | POST `{kind:"recipe"\|"skill"\|"extension"\|"provider", name, payload?}` or `{kind, fromProfile:<username>, ref:<id/path/key>}` copies the item from a profile library |
| DELETE | `/api/admin/teams/{id}/items/{itemId}` | |
| GET/POST | `/api/admin/hints` | `{name, description, content}` |
| GET/PUT/DELETE | `/api/admin/hints/{id}` | |
| GET | `/api/admin/library?profile=<username>&kind=recipe\|skill\|extension\|provider` | read-only listing of items in a profile that can be added to a team `[{kind, ref, name, description, source}]` |
| GET/PUT | `/api/admin/auth` | `{ldap:{enabled, url, bindDn, bindPassword?, userBase, userFilter, adminGroupDn?, groupTeamMap:{groupDn: teamId}, startTls, caFile?, allowInsecure, label}, oidc:[{id,label,issuer,clientId,clientSecret?,scopes,adminClaim?,adminValue?,teamClaim?,autoCreate,stripDomain}], localEnabled}`. Secrets are write-only: reads return `"********"` when they are set. `400 bad_config` for an invalid configuration, for example an enabled `ldap://` URL without `startTls` while `allowInsecure` is false |
| GET/PUT | `/api/admin/settings` | `{brand:{name,tagline}, defaultTeamId, sessionHours, allowSelfTotp, requireTotpForAdmins, peers:[{name,url,token?}]}`. Turning `requireTotpForAdmins` on returns `409 totp_needed_first` unless the calling admin already uses TOTP |
| GET | `/api/admin/audit?limit=&before=&user=&action=` | `[{id, ts, username, ip, action, target, detail, ok}]` |
| GET | `/api/admin/system` | `{version, gooseVersion, gooseBinary, integrity, elevated, user, profilesRoot, nativeRoot, desktopRunning, scheduler:{owner}, workers:[{key, username, pid, port, state, startedAt, clients, activeRuns, scheduler, restarts, lastError}]}` |
| POST | `/api/admin/system/workers/{key}/{action}` | `action` = `restart` \| `stop` |
| GET | `/api/admin/ownership?profile=<username>` | `{root, scanned, foreign:[{path, owner}], truncated}`: files not owned by the gateway user |
| GET | `/api/admin/hosttasks` | `[{path, name, state, lastRun, lastResult, nextRun, runAs, runLevel, logonType, elevated, actions, author}]` |
| POST | `/api/admin/hosttasks/action` | `{path, action:"run"\|"end"\|"enable"\|"disable"}` |
| GET | `/api/admin/logs?worker=<key>&lines=500` | `{lines:[...]}` tail of the gateway or worker log |

### Team object and policy

`Team = {id, name, description, policy, members:[userId], hints:[hintsId], itemCount, createdAt, teamFolder, warnings:[{level, text}]}`.

* `policy` is shown over the defaults: the switches (`recipes_edit`, `skills_edit`, `extensions_edit`,
  `providers_edit`, `schedules`, `apps`, `prompts_edit`, `hints_edit`, `tools_permissions`, `config_edit`,
  `allow_shell`, `notify_webhook`), the lists `allowed_modes`, `allowed_providers` and `allowed_models`
  (`["*"]` = any, `[]` = nothing; a list that contains `*` is stored as `["*"]`), `allowed_roots` (absolute
  paths), `max_concurrent_runs` (empty or missing = 3, `0` = unlimited), and optional `default_provider`,
  `default_model` and `share_folder`.
* `teamFolder` is the team's shared folder: `share_folder`, or `<profiles_root>/_teams/<id>`.
* `warnings[].level` is `err` (for example "No models allowed: members can't chat."), `warn` or `info`.

Team and policy errors:

| Error | When |
|---|---|
| `400 one_team` | a user body sends `teams` with more than one id (a user belongs to one team at most) |
| `400 bad_team` | the `team` value is not a team id, or the team does not exist |
| `400 bad_folder` | a team's `share_folder` or an `allowed_roots` entry is not an absolute path, or `allowed_roots` contains `*` |
| `403 hint_file_refused` | a non-admin uploads or creates something named `AGENTS.md`, `.goosehints` or `.goose-web-hints.md` |

## Real-time channel: `GET /ws` (WebSocket)

Browsers authenticate the socket with the session cookie, and the `Origin` header must be an allowed
origin (the `server.public_url` origin plus `server.allowed_origins`; without `public_url`, the request's
own `scheme://Host`). Non-browser clients send `Authorization: Bearer gwt_...` in the handshake request.
This is only accepted when the request has **no** `Origin` header. Tokens in the query string
(`?token=`) are not supported, because URLs end up in access and proxy logs. Unauthenticated sockets, and
sockets of users with a pending password change, are refused before the handshake completes (close code
4401, seen by browsers as HTTP 403). Each socket is bound to the user's own profile worker. Admins can add `?profile=<username>` to drive
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
  * Chat gating for non-admins: `session/new`, `session/fork` and `session/prompt` are refused while
    `policy.chat_blocked` is set, for example `forbidden: You are not in a team yet, so you cannot chat. Ask your
    administrator to add you to a team.` `session/prompt` is also refused when the chat's current provider,
    model or mode is not allowed (`forbidden: this chat uses the model '...', which your team does not allow.
    Pick an allowed model for this chat first.`). `config/upsert` and `config/remove` of `CONTEXT_FILE_NAMES`
    are refused for non-admins (`... is managed by Goose Web`).
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
