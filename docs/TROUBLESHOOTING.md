# Goose Web troubleshooting

This guide is for administrators and users of Goose Web (the Goose AI Web Interface) who hit a problem. Each
section starts with a symptom -> cause -> fix table, then gives short procedures where needed. The error texts
quoted here are the exact messages the gateway, the browser app or the installers produce, so you can search this
page for the text you see.

Related documents:

| Document | Use it for |
| --- | --- |
| [ADMINISTRATION.md](ADMINISTRATION.md) | Installing, running and operating the gateway |
| [CONFIGURATION.md](CONFIGURATION.md) | Every configuration key and environment variable |
| [USER-GUIDE.md](USER-GUIDE.md) | Using the browser app (chats, herd view, schedules, apps) |
| [ARCHITECTURE.md](ARCHITECTURE.md) | How the gateway, the hub and the `goose serve` workers fit together |
| [API.md](API.md) | REST and WebSocket API, error envelope |
| [SECURITY-ASSESSMENT.md](SECURITY-ASSESSMENT.md) | Threat model and hardening background |
| [../SECURITY.md](../SECURITY.md) | How to report a security vulnerability |

Examples in this guide use the address `https://goose.example.org`, the LAN address `192.168.1.10`, the users
`alice` and `bob`, the Windows install folder `C:\GooseWeb` and the Linux install folder `/opt/goose-web`.
Replace them with your own values.

## Contents

1. [Getting diagnostics](#1-getting-diagnostics)
2. [Log locations](#2-log-locations)
3. [Cannot sign in](#3-cannot-sign-in)
4. [Lost authenticator](#lost-authenticator)
5. ["invalid host" (HTTP 400)](#5-invalid-host-http-400)
6. [WebSocket disconnects and reconnects](#6-websocket-disconnects-and-reconnects)
7. [The gateway or a worker will not start](#7-the-gateway-or-a-worker-will-not-start)
8. [A chat will not open ("Could not open this session")](#8-a-chat-will-not-open-could-not-open-this-session)
9. [Tool calls waiting for approval](#9-tool-calls-waiting-for-approval)
10. [App tool calls require Auto mode](#10-app-tool-calls-require-auto-mode)
11. [Extensions failing or missing](#11-extensions-failing-or-missing)
12. [Schedules not running](#12-schedules-not-running)
13. [Webhooks refused or not delivered](#13-webhooks-refused-or-not-delivered)
14. [Old user interface after an upgrade](#14-old-user-interface-after-an-upgrade)
15. [Other common errors](#15-other-common-errors)
16. [Reporting security issues](#16-reporting-security-issues)

---

## 1. Getting diagnostics

Work through these steps in order. They are quick and usually point straight at the cause.

### 1.1 Is the gateway process up?

The gateway answers `GET /healthz` with the plain text `ok` (no sign-in needed, never cached). The Host check
described in section 5 does not apply to this path, so it works from anywhere that can reach the port.

```sh
curl -fsS http://127.0.0.1:8710/healthz
```

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:8710/healthz | Select-Object -ExpandProperty Content
```

| Result | Meaning |
| --- | --- |
| `ok` | The gateway process is running and serving HTTP. Continue with the logs. |
| Connection refused | The gateway is not running, or listens on another host/port (`server.host`, `server.port`, `serve --host/--port`). |
| `ok` locally but not through the proxy | The reverse proxy is the problem (section 5 and section 6). |

The Docker image runs the same check as its `HEALTHCHECK`; `docker compose -f docker/compose.yaml ps` shows the
container as `healthy` or `unhealthy`.

### 1.2 Run the built-in check

`check` verifies the configuration, the Goose binary, the account the gateway runs as, the profiles root and the
port. Always pass the same `--config` the service uses, otherwise the command reads the defaults (and possibly a
different database).

```bat
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml check
```

```sh
/opt/goose-web/.venv/bin/python -m goose_web --config ~/.local/share/goose-web/_system/config.yaml check
```

```sh
docker compose -f docker/compose.yaml exec goose-web python -m goose_web check
```

Each line has the form `[OK] label: value` or `[!!] label: value`. The command exits with code 1 if any check
failed.

| Line | Fails when | Fix |
| --- | --- | --- |
| `goose-web version` | never | informational |
| `config file` | never; shows `(defaults)` when no file was found | if you see `(defaults)` but expected a file, pass `--config` or set `GOOSE_WEB_CONFIG` |
| `goose binary: <path> (<version>)` | the binary cannot be run (`not runnable`) | see section 7.2 |
| `running as: <user> integrity=<level>` | the process is elevated (Windows Administrator token) or root | run as the normal user, see section 7.1 |
| `profiles root` | the folder does not exist | create it or correct `paths.profiles_root` |
| `goose desktop running` | never (Windows only, informational) | matters for the native scheduler, section 12 |
| `port N: free` / `in use (gateway already running?)` | never (informational) | `in use` is expected while the gateway runs; if it is not running, another program holds the port |

Other useful commands:

```sh
python -m goose_web --config <config> version      # gateway version
python -m goose_web --config <config> user list    # accounts in the database this config points to
goose --version                                    # Goose CLI version (use the same binary as goose.binary)
```

### 1.3 Look in the admin console

Signed in as an administrator, open the admin console:

- **System**: gateway and Goose versions, process integrity level (with a warning banner if elevated), every
  worker with its state, port, PID, scheduler flag, last error and restart count, and Start/Stop/Restart buttons.
  The Goose version shown is read when the gateway starts; restart the gateway after updating Goose.
- **Logs**: the tail of the gateway log or of any worker log (10 to 5000 lines).
- **Audit log**: sign-ins, failures, lockouts, admin changes, denied agent requests (`acp.denied`) and more.

The same data is available over the API with an administrator API token, for example from a machine where the
browser cannot reach the UI:

```sh
curl -fsS -H "Authorization: Bearer gwt_..." https://goose.example.org/api/admin/system
curl -fsS -H "Authorization: Bearer gwt_..." "https://goose.example.org/api/admin/logs?lines=500"
curl -fsS -H "Authorization: Bearer gwt_..." "https://goose.example.org/api/admin/logs?worker=alice&lines=500"
curl -fsS -H "Authorization: Bearer gwt_..." https://goose.example.org/api/admin/audit
```

### 1.4 Look in the browser

Open the browser developer tools (F12):

- **Console**: client errors and WebSocket close codes.
- **Network**: failing `/api/...` requests show the JSON error body `{"error": "<code>", "message": "..."}`;
  the `/ws` entry shows whether the WebSocket upgrade succeeded (101) or was refused (400/403).
- **Application > Service workers**: which version of the app shell is active (section 14).

### 1.5 Turn up logging

Set the environment variable `GOOSE_WEB_LOG_LEVEL=DEBUG` for the gateway process and restart it. The default is
`INFO`. HTTP client and WebSocket library loggers stay at `WARNING` regardless. Set it back afterwards; debug logs
are larger and rotate sooner.

---

## 2. Log locations

`<system_dir>` is `paths.system_dir`, by default the `_system` folder inside the profiles root.

| Install | Gateway and worker logs |
| --- | --- |
| Windows (installer or code default) | `C:\Goose_Web_Profiles\_system\logs\` |
| Linux / macOS installer | `~/.local/share/goose-web/_system/logs/` |
| Docker | `/data/_system/logs/` inside the container (the `goose-web-data` volume) |
| POSIX without the installer | `$GOOSE_WEB_PROFILES/_system/logs/`, else `/var/lib/goose-web/profiles/_system/logs/` |

| Log | File | Rotation | Notes |
| --- | --- | --- | --- |
| Gateway | `<system_dir>/logs/gateway.log` | 5 MB, 5 old files | Also written to stderr when there is a console. |
| Worker (one per user) | `<system_dir>/logs/worker-<username>.log` (lower-case user name) | checked before each worker start: above 10 MB it is rotated, 3 old files | Each start writes `==== <time> start serve ... root=<profile or (default)>`. Contains everything `goose serve` prints. |
| Goose's own logs | `<profile root>/data/logs/` for each profile | managed by Goose | Provider/LLM and extension errors often only appear here. |
| Service output | Windows logon task: none (runs `pythonw.exe` without a console). Linux: `journalctl --user -u goose-web -f`. Docker: `docker compose -f docker/compose.yaml logs -f goose-web`. | | |
| Audit log | `audit` table in `<system_dir>/goose-web.db`, viewed in Admin > Audit log | entries older than 365 days are purged when the database is opened | |

Useful gateway log lines:

| Line | Meaning |
| --- | --- |
| `starting on <host>:<port> as <user> (integrity <level>), profiles <root>` | Gateway start; check the account and integrity level. |
| `Goose Web <version> ready (goose <version>)` | Start-up complete. |
| `worker <user> ready on port <port> (pid <pid>, scheduler=<bool>)` | A worker started. |
| `worker <user> crashed: goose serve exited with code N` | A worker exited unexpectedly; read its worker log. |
| `worker <user> stopped <reason>` | Normal stop (idle, admin, shutdown). |
| `worker <user> restarting (scheduler <a> -> <b>, pending=<bool>)` | Scheduler ownership changed (section 12). |
| `provisioning <user> failed` | The isolated profile could not be created or updated; a traceback follows. |
| `could not rotate <file>: <error>` | The worker log is locked or not writable. |
| `LDAP service bind failed: ...`, `LDAP error: ...`, `LDAP sign-in refused: ...`, `ldap3 is not installed` | Directory sign-in problems (section 3.4). |
| `OIDC sign-in refused: ...` | Single sign-on problems (section 3.5). |
| `webhook refused for <user>: ...`, `webhook failed for <user>: ...` | Notification problems (section 13). |
| `Goose Desktop detection failed; assuming it is running` | Native scheduler fail-safe (section 12). |
| `unhandled error on <path>` | A server bug or environment problem; the traceback follows. The client saw `500 server_error`. |
| `worker monitor error`, `ws frame error` | Internal errors with tracebacks; include them in bug reports. |

---

## 3. Cannot sign in

### 3.1 Quick table

| Symptom (UI text or API error) | Cause | Fix |
| --- | --- | --- |
| `Cross-origin request refused` (403 `bad_origin`) | The page was opened at an address that is not an allowed origin. When `server.public_url` is set, only that origin (plus `server.allowed_origins`) is accepted, so opening `http://192.168.1.10:8710` while `public_url` is `https://goose.example.org` fails. | Open the `public_url` address. To also allow the direct address, add its origin to `server.allowed_origins`, for example `http://192.168.1.10:8710` (and to `server.allowed_hosts`, section 5). |
| `Missing or invalid CSRF token. Reload the page.` (403 `csrf`) | The page is older than the current session, or a cookie was cleared or blocked. | Reload the page. Make sure the browser accepts cookies for the site. |
| Sign-in seems to succeed but you are back at the login page | The session cookie was not stored. With an `https://` `public_url` the cookie is `__Host-gw` with the `Secure` flag, which browsers only keep over HTTPS. | Use the `https://` address. Do not set an `https://` `public_url` when users connect over plain HTTP. |
| `Invalid username or password` (401 `invalid_credentials`) | Wrong user name or password, **or** the account is disabled, **or** the user does not exist locally and LDAP is off. The message is the same on purpose. | Check the account in Admin > Users (disabled?). Reset the password (section 3.6). |
| `Local sign-in is disabled` | Local passwords are turned off in Admin > Auth providers, and the account is a local non-admin account. Administrators can still sign in locally. | Sign in with the directory or SSO, or turn local sign-in back on. |
| `Too many attempts. Please wait a minute.` (429 `rate_limited`, API text `Too many attempts. Wait a few minutes.`) | Rate limit: 40 attempts per 5 minutes per client IP, and 10 per 5 minutes per IP and user name. | Wait up to 5 minutes. Behind a proxy, see section 3.2. |
| `This account is temporarily locked. Try again later or ask an administrator.` (423 `locked`) | `auth.lockout_threshold` (default 8) failed attempts, counting wrong passwords **and** wrong two-factor codes. Locked for `auth.lockout_minutes` (default 15). | Wait, or an administrator clicks Unlock in Admin > Users, or run `user reset` (section 3.6). |
| `Enter the code from your authenticator app` (`totp_required`) | The account has two-factor on; the password was right. | Enter the 6-digit code. |
| `Invalid code, try again.` (`totp_invalid`, API text `That code is not valid`) | Wrong code, a code that was already used, or the device clock is off by more than about 30 seconds. Counts toward the lockout. | Wait for the next code; fix the time on the phone and the server. Lost device: section 4. |
| `Change your password first` (403 `password_change_required`) | The account has a temporary password (new account, `user reset`, admin reset). Everything except changing the password is refused, including the WebSocket. | Change the password on the screen shown after sign-in. |
| `Directory sign-in is not configured securely. Ask an administrator to check the LDAP settings.` (503 `ldap_insecure`) | LDAP uses plain `ldap://` without StartTLS. | Section 3.4. |
| `/#/login?error=oidc_...` after single sign-on | See section 3.5. | Section 3.5. |
| `Gateway unreachable` with a Retry button | The app could not load `/api/me` (network error, proxy error, gateway down). | Section 1.1. |
| `Sign-in from your network address is blocked after too many failed attempts. Ask an administrator to unblock it.` (403 `ip_blocked`; every other page shows the same text as plain text) | 10 failed sign-ins in a row from this client address within 30 days (`auth.ip_block_*`), from any user names. | Section 3.7. |
| After signing in: `Choose a new password` although the password is not temporary | The password does not meet the strong-password rules of version 1.3.0 and later, or an administrator set it. | Choose a password with at least 12 characters, upper- and lower-case letters, a number and a symbol, not containing the user name. |
| `Rejected: ...` when choosing a password (400 `weak_password`) | The server's password rules: 12+ characters, lower case, upper case, number, symbol, not containing the user name, not a common password or a common word with digits/symbols added, no character 4 times in a row. | Choose a longer, less predictable password. |
| The initial admin password was lost | It is printed only once. | `user reset admin` (section 3.6). |
| `no such user` from `user reset` although the user exists in the UI | The command used a different database because `--config` was missing or wrong. | Pass the service's `--config` (section 3.6). |

### 3.2 Rate limits and lockouts behind a reverse proxy

The gateway takes the client IP from the rightmost `X-Forwarded-For` value only when the TCP peer is listed in
`server.trusted_proxies` (default `127.0.0.1` and `::1`). If your proxy runs on another machine (for example
`192.168.1.2`) and is not listed, every user appears to come from the proxy's address, so one user's failed
attempts can rate-limit everyone. Add the proxy address to `server.trusted_proxies` and restart.

The account lockout is per account. An account locked by someone guessing passwords stays locked for
`auth.lockout_minutes` after the last failure; the Audit log shows the attempts (`auth.login` failures and the
lockout) with client IPs. The address block (section 3.7) is per client IP, so with an untrusted proxy one bad
actor would block the proxy's address for everyone - except that trusted proxies are never blocked, which is one more
reason to list the proxy in `server.trusted_proxies`.

### 3.3 Unlocking or resetting from the admin console

In Admin > Users, select the user:

- **Unlock** clears the failure counter and the lock.
- **Reset password** sets a temporary password (shown once) that must be changed at the next sign-in.
- **Reset two-factor** removes the user's two-factor enrolment after a lost authenticator (section 4).
- **Enable** re-enables a disabled account.

Directory (LDAP) and SSO (OIDC) accounts have their passwords managed elsewhere; changing them in Goose Web gives
`This account's password is managed by your directory`.

### 3.4 LDAP / Active Directory

| Symptom | Cause | Fix |
| --- | --- | --- |
| Saving the LDAP settings fails with `The LDAP URL uses plain ldap:// without StartTLS, which would send passwords in cleartext. Use an ldaps:// URL, turn on StartTLS, or (only on a trusted network) set allowInsecure to true in the LDAP settings.` (400 `bad_config`) | Plain `ldap://` URL, StartTLS off, `allowInsecure` off. | Use `ldaps://dc.example.org:636`, or turn on StartTLS, or (trusted network only) set `allowInsecure`. |
| Users see `Directory sign-in is not configured securely...` (503 `ldap_insecure`); log `LDAP sign-in refused: ...`; audit `auth.ldap` | Same as above, for settings saved before the check or edited directly. | As above. |
| All directory users get `Invalid username or password`; log `LDAP service bind failed: ...` | Wrong service (bind) DN or password, or the server rejected the bind. | Fix the bind DN and password in Admin > Auth providers. |
| Log `LDAP error: ...` with a TLS or certificate message | The server certificate is not trusted. Certificates are always verified. | Set the CA file (`caFile`) to the CA that issued the directory server certificate. |
| Log `LDAP error: ...` with a timeout | Server unreachable. Connect timeout is 8 s, receive timeout 10 s. | Check DNS, firewall and port (636 for LDAPS, 389 for StartTLS). |
| One user gets `Invalid username or password` while others work | The user search returned zero or more than one entry (it must match exactly one), the user's password is wrong, or the user has no Goose Web account yet and automatic creation (`autoCreate`) is off. | Check the search base and filter for that user name; create the account or turn on `autoCreate`. |
| A directory user signs in but has the wrong role or team | Role and team come from the user's `memberOf` groups: `adminGroupDn` gives the admin role, `groupTeamMap` maps groups to teams. A user has one team: the mapped team replaces the previous one, and when several groups match the first one wins (audit `user.team.directory`). | Check the group DNs (compared without regard to case) in the LDAP settings. |
| Log `ldap3 is not installed` | The optional dependency is missing from the virtual environment. | Install `ldap3` into the gateway's environment (it is in the locked requirements; re-run the installer or `pip install --require-hashes -r requirements.lock`). |

### 3.5 OIDC single sign-on

After a failed single sign-on the browser lands on `/#/login?error=<code>` and the login page shows the code.

| Code / message | Cause | Fix |
| --- | --- | --- |
| `oidc_needs_public_url`: `Single sign-on (OIDC) needs server.public_url (the https:// address users open) so the redirect URI never depends on the request's Host header` (log `OIDC sign-in refused: ...`) | `server.public_url` is not set. | Set `server.public_url` to `https://goose.example.org` and restart. |
| `oidc_unavailable` | Starting the sign-in failed, usually because `<issuer>/.well-known/openid-configuration` could not be fetched (DNS, TLS, firewall, wrong issuer URL). Discovery is cached for one hour once it succeeds. | Check the issuer URL from the gateway machine with `curl`. Check the gateway log for the exception. |
| `oidc_denied` | The identity provider returned an error (user cancelled, not assigned to the app), **or** the gateway refused the account: `This account is not allowed to sign in` (account disabled, or no account exists and automatic creation is off). | Assign the user in the IdP; enable the account; turn on auto-create for the provider or create the user first. |
| `oidc_state`: `Sign-in expired, try again` / `Sign-in mismatch` | The sign-in took longer than 10 minutes, the callback was replayed, or it came back in another browser. | Start again from the login page in the same browser. |
| `oidc_token`: `The identity provider rejected the sign-in` | The code exchange failed: wrong client secret, or the redirect URI registered at the IdP does not match. | Register exactly `https://goose.example.org/api/auth/oidc/<provider id>/callback` and check the client secret. |
| `oidc_claims`: `The identity token failed validation` | Issuer, audience, expiry (60 s clock skew allowed) or nonce did not match. | Check the issuer URL (exact string, including any trailing slash) and client ID; fix the server clock. |
| `oidc_conflict` (409): `A local account with this name already exists` | The derived user name already belongs to a local or LDAP account. SSO accounts are bound to the IdP issuer and subject, not to the name. | Rename or delete the other account, or use a different name claim. |
| `oidc_conflict` (409): `This account is linked to a different sign-in identity` | The Goose Web account was created by another IdP user (different issuer/subject). | Check that it is really the same person; delete and recreate the account if the IdP identity legitimately changed. |
| `unknown_provider` (404) | The provider ID in the URL does not exist or is disabled. | Use the button on the login page; check Admin > Auth providers. |
| `oidc_failed` | Any other error during the callback. | Read the gateway log. |

User names from SSO have the domain part removed by default (`stripDomain`), so `alice@example.org` becomes
`alice`. If two IdP users would map to the same name, the second one gets `oidc_conflict`.

### 3.6 Resetting a password from the command line

`user reset` sets a temporary password, clears the failure counter and lock, re-enables the account, converts it
to a local account, and deletes all of its sign-in sessions and API tokens. It does **not** turn off two-factor
(use `user reset-totp`, section 4). It prints `Temporary password for <user>: <password>`; the user must change
it at the next sign-in.

Always pass the service's configuration file:

```bat
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml user reset alice
```

```sh
/opt/goose-web/.venv/bin/python -m goose_web --config ~/.local/share/goose-web/_system/config.yaml user reset alice
```

```sh
docker compose -f docker/compose.yaml exec goose-web python -m goose_web user reset admin
```

To choose the password instead of generating one, add `--password <value>`. Run `user list` first if you are not
sure of the exact user name. `no such user` almost always means the wrong database (missing `--config`).

The command works while the gateway is running; the user's open browser sessions are signed out because their
sessions were deleted.

---

### 3.7 A blocked address (`ip_blocked`)

After `auth.ip_block_threshold` (10) failed sign-ins in a row from one client address within
`auth.ip_block_window_days` (30), the gateway refuses every request from that address for `auth.ip_block_days` (30)
with HTTP 403 and the text `Sign-in from your network address is blocked after too many failed attempts. Ask an
administrator to unblock it.` IPv6 addresses are blocked per /64.

1. See who and what: Admin > **Blocked addresses** (address, failures, last user name tried, blocked until), or the
   Audit log entry `auth.ip.blocked`, or on the gateway machine:

   ```powershell
   C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml ip list
   ```

2. If it was a legitimate user (for example someone with an old saved password), click **Unblock** in Admin >
   Blocked addresses, or run `... ip unblock <address>` on the gateway machine. The console command also works when
   your own address is blocked and the gateway is running; the gateway picks it up within 15 seconds.
3. If many people share one address (office NAT, VPN), consider putting that network in `auth.ip_block_exempt`.
4. If every user is blocked at once, the gateway probably sees the proxy's address instead of the client's: add the
   proxy to `server.trusted_proxies` (section 3.2), restart, and run `ip unblock --all`.

## Lost authenticator

A user who lost the phone or app that generates their two-factor codes cannot sign in. An administrator removes
their two-factor enrolment (version 1.2.0 and later); the user then signs in with the password alone and enrols a
new authenticator. No database editing is needed.

**From the admin console** (any administrator who can still sign in):

1. Open Admin > Users, open the user's **Actions** menu and choose **Reset two-factor**. The item is shown only for
   users with the "2FA" badge, and never for your own account.
2. Confirm. Two-factor is removed, the failure counter and lock are cleared, all of the user's sessions end and all
   of their API tokens are revoked (the lost device may still be signed in). The audit log records
   `user.totp.reset` with the administrator and the user.
3. Ask the user to sign in and enrol a new authenticator straight away. This is required for administrators when
   **Require two-factor for administrators** is on; until they enrol they are reported as `totpEnrolmentRequired`.

The same action is available to scripts as `POST /api/admin/users/{id}/reset-totp` ([API.md](API.md)).

**From the command line** (for example when the only administrator lost their authenticator). Run it on the
gateway machine with the service's configuration file; the gateway may keep running:

```bat
C:\GooseWeb\.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml user reset-totp alice
```

```sh
/opt/goose-web/.venv/bin/python -m goose_web --config ~/.local/share/goose-web/_system/config.yaml user reset-totp alice
```

```sh
docker compose -f docker/compose.yaml exec goose-web python -m goose_web user reset-totp alice
```

It prints `Two-factor removed for alice: signed out everywhere, N API token(s) revoked. ...` and has the same effect
as the button. The audit entry `user.totp.reset` carries `"via": "cli"`. A user without two-factor is left
unchanged (`alice does not use two-factor; nothing changed`). If the password is in doubt as well, also run
`user reset alice` (section 3.6), which on its own deliberately leaves two-factor in place.

| Situation | What to do |
| --- | --- |
| A user lost their authenticator | **Reset two-factor** in Admin > Users, or `user reset-totp NAME`. |
| You (an administrator) still can sign in and want to change phones | Turn two-factor off and on again in your own account settings (password required). Not possible while **Require two-factor for administrators** is on: ask another administrator to reset it. |
| You lost your own authenticator | Another administrator resets it, or run `user reset-totp NAME` on the gateway machine. The admin console never offers the reset for your own account, so a stolen session cannot remove its owner's second factor. |
| `This user does not use two-factor` (409 `totp_not_enabled`) | Nothing to reset; reload the user list. |
| `Turn off your own two-factor in your account settings` (400 `self`) | The API was called for your own account; see the rows above. |
| A version before 1.2.0 | Upgrade first; the database needs no change. |

---

## 5. "invalid host" (HTTP 400)

The gateway refuses any request whose `Host` header is not on its allow-list. This protects against DNS
rebinding. A browser shows a plain-text page `invalid host`; a WebSocket is refused or closed with code 1008 and
reason `invalid host`. `GET /healthz` is never blocked.

The allow-list is:

- `localhost`, `127.0.0.1` and `::1`;
- the host name of `server.public_url`;
- `server.host`, unless it is a wildcard (`0.0.0.0`, `::`, `*` or empty); `serve --host` counts as well;
- every entry of `server.allowed_hosts` (a list, or a comma-separated string in an environment variable).

| Symptom | Cause | Fix |
| --- | --- | --- |
| `invalid host` when opening `http://192.168.1.10:8710` | The gateway listens on `0.0.0.0` (wildcard, not added) and the IP is not in `allowed_hosts`. | Add `192.168.1.10` to `server.allowed_hosts` (and its origin to `server.allowed_origins` if `public_url` is set). |
| `invalid host` through the reverse proxy | The proxy forwards its own upstream name (for example `Host: 127.0.0.1:8710` is fine, but `Host: goose-backend` is not) or a host that differs from `public_url`. | Make the proxy pass the original host (nginx `proxy_set_header Host $host;`; Caddy does this by default) and set `public_url` to that host, or add the name to `allowed_hosts`. |
| `invalid host` only through the proxy, Host is correct | The proxy is in `trusted_proxies` and sends an `X-Forwarded-Host` that is not allow-listed. A trusted forwarded host must be allowed too. | Add that name to `allowed_hosts`, or stop sending `X-Forwarded-Host`. |
| `invalid host` in Docker | The image listens on `0.0.0.0`; only localhost names and `public_url` are allowed. | Set `GOOSE_WEB__SERVER__PUBLIC_URL` or `GOOSE_WEB__SERVER__ALLOWED_HOSTS` (for example `goose.example.org,192.168.1.10`) in the compose file. |
| `invalid host` after renaming the server | The new name is not on the list. | Update `public_url` or `allowed_hosts` and restart. |

Port numbers are ignored in the comparison; only the host part counts. Configuration changes take effect after a
gateway restart.

---

## 6. WebSocket disconnects and reconnects

The chat runs over a single WebSocket to `/ws`. When it drops, the sidebar shows `Reconnecting…`, the chat shows
`Connection lost. The agent keeps working on the server; the transcript will resync when reconnected.`, and the
app retries with a growing delay (from 0.5 s up to 30 s, with jitter). After more than six failed attempts the
state becomes "down" and a **Retry now** button appears. Running agents are not affected by a disconnect; the
transcript resynchronises after reconnecting.

### 6.1 Symptom table

| Symptom | Cause | Fix |
| --- | --- | --- |
| Never connects through the proxy; REST pages work | The proxy does not pass the WebSocket upgrade. | Forward `Upgrade` and `Connection` headers and use HTTP/1.1 to the backend (example below). |
| Disconnects after about 60 s (or another fixed interval) of quiet | A proxy or load balancer idle timeout shorter than the keep-alive. The gateway pings every 25 s and drops the connection if no pong arrives within 60 s. | Set the proxy read/send timeout well above 60 s (for example 1 hour). |
| Disconnects when a large message, image or file is sent | A frame larger than 64 MiB is refused by the gateway, or the proxy has a smaller limit. | Use smaller attachments; raise the proxy's body/frame limit. |
| Disconnects every time the server's network changes, or at regular intervals in a corporate network | A middlebox resets long-lived connections. | The app reconnects on its own; whitelist the site in the middlebox if possible. |
| WebSocket refused with HTTP 403 in the Network tab | Not signed in, the session expired, or a password change is required (close code 4401 before the upgrade). | Reload and sign in. |
| WebSocket refused with HTTP 403, user is signed in | The `Origin` of the page is not an allowed origin (same rules as section 3.1). | Open the `public_url` address, or add the origin to `server.allowed_origins`. |
| Closed with code 4403 | A non-administrator asked for another user's profile (`?profile=`). | Only administrators can open other profiles. |
| Closed with code 4404 | The requested profile does not exist. | Check the user name. |
| Closed with code 1008 `invalid host` | Host check (section 5). | Section 5. |
| Closed with code 4000 `hello failed` | The connection opened but the first handshake did not complete within 20 s, usually because the worker could not start. | Read the worker log (section 7). |
| A yellow bar says the Goose agent is starting or down; toast `Goose agent stopped: <error>` | The `goose serve` worker stopped or crashed. When it is back the toast `Goose agent is back` appears. | Section 7.3. |
| A token-based client cannot connect | API tokens (`Authorization: Bearer gwt_...`) are accepted on the WebSocket only when the request has **no** `Origin` header. Browsers always send one. | Use the cookie session in browsers; send no `Origin` from scripts. |

### 6.2 Reverse proxy settings for the WebSocket

nginx:

```nginx
location / {
    proxy_pass http://127.0.0.1:8710;
    proxy_http_version 1.1;
    proxy_set_header Host $host;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_read_timeout 3600s;
    proxy_send_timeout 3600s;
    proxy_buffering off;
    client_max_body_size 30m;
}
```

Caddy passes WebSocket upgrades and the `Host` header by default:

```text
goose.example.org {
    reverse_proxy 127.0.0.1:8710
}
```

If the proxy runs on another machine, list its address in `server.trusted_proxies`, otherwise forwarded headers
are ignored. See [ADMINISTRATION.md](ADMINISTRATION.md) section 6 for the full proxy setup.

---

## 7. The gateway or a worker will not start

### 7.1 The gateway exits at start

| Message | Cause | Fix |
| --- | --- | --- |
| `goose-web: elevated token detected - relaunching as a normal user (Medium integrity).` | Started from an elevated ("Run as administrator") prompt on Windows. The gateway restarts itself un-elevated. | Nothing, but start it from a normal prompt in future. |
| `goose-web: could not de-elevate (<error>); refusing to run elevated.` / `goose-web: still elevated after de-elevation; refusing to run.` (exit code 3) | Could not drop elevation (for example the built-in Administrator account or UAC off). | Run as a normal user without elevation. `server.allow_elevated` exists but is not recommended. |
| `goose-web refuses to run as root; run it as the Goose user (or set server.allow_elevated).` (exit code 3) | Started as root on Linux or macOS. | Run it as the normal user who owns the Goose profiles (the installer sets up a user service). |
| `goose-web: refusing to run as root; use the image's default user (uid 1000).` (exit code 3) | Docker container started with `--user root` or `user: root`. | Remove the user override. |
| `goose-web: GOOSE_WEB_ADMIN_PASSWORD_FILE=<path> is not readable` (exit code 2) | The Docker secret file is missing or not readable by uid 1000. | Fix the mount or the file permissions. |
| `This installer must run as the normal Windows user (not 'Run as administrator').` (exit code 3) | `install.ps1` was run elevated. | Run it from a normal PowerShell window. |
| `goose CLI not found on PATH. Install it first:` (install.sh, exit code 1) | The Goose CLI is not installed. | Install the Goose CLI with the command the installer prints, then re-run. |
| Address already in use; `check` shows `port 8710: in use (gateway already running?)` | A gateway is already running (the Windows logon task ignores a second instance), or another program uses the port. | Stop the other instance, or use `serve --port` / `server.port`. |
| Starts, but has no users and shows a different install | No `--config` (or `GOOSE_WEB_CONFIG`), so it uses the default profiles root, not the installer's. This matters especially on Linux, where the installer uses `~/.local/share/goose-web`. | Start it the same way the service does, with `--config`. |
| `Goose profile folder not found: <path>` from `init` | The `--native-root` path does not exist. | Use `--native-root auto`, `fresh`, or an existing Goose profile folder. |
| `empty password in <file>` / `empty password in stdin` from `init` | The password file or stdin was empty. | Provide a non-empty password, or omit `--password-file` to have one generated. |
| `Already initialised (N users). Native profile: <root>` | `init` was run on an existing database. | Nothing to do. `--force` exists for deliberate re-initialisation; take a backup first. |

On Windows the logon task starts the gateway with `pythonw.exe`, which has no console: start-up errors only appear
in `gateway.log`. To see them directly, run the same command with `python.exe` in a normal prompt:

```bat
cd /d C:\GooseWeb
.venv\Scripts\python.exe -m goose_web --config C:\Goose_Web_Profiles\_system\config.yaml serve
```

### 7.2 A worker will not start

Each user's chats run in a `goose serve` worker started on demand:
`goose serve --host 127.0.0.1 --port <free port> --platform desktop [--enable-scheduler]`. The gateway waits
until `http://127.0.0.1:<port>/status` answers, for up to `goose.start_timeout_seconds` (default 45). The error is
shown in Admin > System (last error), in the chat (`Goose is not available: <error>`) and in the gateway log.

| Error | Cause | Fix |
| --- | --- | --- |
| `cannot start goose: <error>` (for example "No such file or directory" / "The system cannot find the file specified") | The Goose binary was not found or cannot be executed. | Set `goose.binary` to the full path of the Goose CLI and restart the gateway. See the resolution order below. |
| `goose serve exited with code N (see worker-<user>.log)` | Goose started and exited. Typical causes: a Goose version without the `serve` command, a broken profile `config.yaml`, a corrupt sessions database, files owned by another account. | Read `worker-<user>.log` from the last `==== ... start serve` line. Run `goose --version` and `goose serve --help` with the same binary. |
| `goose serve did not become ready in time` | The worker did not answer `/status` within `start_timeout_seconds`, for example on a slow machine, during first-time setup, or with antivirus scanning. | Raise `goose.start_timeout_seconds`; read the worker log. |
| `Goose is not connected` | The chat sent a request while the worker connection was down. | Wait for the worker to restart; reload. |
| `check` shows `goose binary: ... (not runnable)` | `goose --version` failed or took more than 20 s. | Run the binary by hand to see the error. |
| Admin > System > Restart returns `start_failed` | One of the errors above. | As above. |

How the Goose binary is found, in this order:

1. `goose.binary` in the configuration (recommended for services).
2. `goose` on the `PATH` of the gateway process. Services often have a shorter `PATH` than your shell.
3. Known install locations: on Windows `%LOCALAPPDATA%\Programs\Goose\resources\bin\goose.exe` and
   `%USERPROFILE%\.local\bin\goose.exe` (plus a Goose Desktop build folder); on Linux and macOS
   `/usr/local/bin/goose` and `~/.local/bin/goose`.
4. Plain `goose`, which fails with `cannot start goose` if none of the above exists.

About versions: the gateway does not check for a minimum Goose version. It needs a Goose CLI that provides
`goose serve` (the ACP server). The Docker image pins Goose 1.57.0 and verifies its checksum. If a native install
fails after a Goose update or downgrade, compare with that version. The version shown in Admin > System is read
at gateway start, so restart the gateway after changing Goose.

### 7.3 A worker keeps crashing or restarting

| Symptom | Cause | Fix |
| --- | --- | --- |
| Toast `Goose agent stopped: goose serve exited with code N`, log `worker <user> crashed: ...` | The worker process died. | Read the worker log and Goose's own log in `<profile>/data/logs`. |
| Worker does not come back after a crash | Crashed workers are restarted only while a browser is connected for that user or the profile owns schedules. The delay grows with each crash: 2, 4, 8 ... seconds up to 256 s (the cap is 300 s). | Fix the cause, then Admin > System > Restart, or reload the chat. |
| Worker stops after a while | Idle shutdown: no browser connected and nothing running for `goose.idle_minutes` (default 30). This is normal; it starts again on the next visit. | Raise `idle_minutes` if needed. Schedule-owning workers stay up. |
| Chats show `the Goose worker restarted` or `the Goose worker connection closed` | The worker restarted under an open chat. Pending approvals are cancelled. | Reload the chat; the agent's history is kept by Goose. |
| `stopped by an administrator` | An administrator clicked Stop or Restart. | Reload. |
| A restart is shown as pending | Restarts for scheduler ownership changes wait until no agent is running. | Wait for running chats to finish, or restart from Admin > System. |

### 7.4 File ownership on Windows

If the gateway was ever run elevated, files in a user's Goose profile may be owned by the Administrators group,
and later the normal, un-elevated worker cannot write them (`goose serve exited with code N`, access-denied errors
in the worker log). Admin > System shows `The gateway runs at <level> integrity (elevated). Files it creates may
be owned by Administrators and lock out the normal user. Run it un-elevated at medium integrity.` when this is
happening now. Admin > Ownership check lists files under `<profile>\config` with the wrong owner. Fix them from an
elevated prompt:

```bat
icacls "C:\Goose_Web_Profiles\alice" /setowner "<windows user>" /T
```

### 7.5 What the isolated worker does not inherit

Workers for isolated profiles get a clean environment: every `GOOSE_*` variable of the gateway is removed (except
`GOOSE_DISABLE_KEYRING` and `GOOSE_TELEMETRY_ENABLED`), `GOOSE_DISABLE_KEYRING=1` is set (secrets are stored in the
profile, not the OS keyring), and `GOOSE_RECIPE_PATH` points at the team recipe folders. If a provider or
extension works in your own shell but not in Goose Web, the missing piece is usually an environment variable or a
keyring secret. Put shared variables in `goose.extra_env` (passed to all workers), or set the provider secret in
the user's Goose Web settings.

---

## 8. A chat will not open ("Could not open this session")

When opening a chat fails, the chat page shows `Could not open this session` with the error text, a **Retry**
button and **Back to herd**.

| Error text | Cause | Fix |
| --- | --- | --- |
| Goose's own "session not found" style error | The session was deleted (in Goose Web, Goose Desktop or the CLI), or the link points at a session in another profile. Sessions belong to one profile. | Go back to the herd and pick an existing chat. Administrators open other users' chats through the herd or with `?profile=<user>`. |
| `forbidden: folder not allowed: <folder>` | The session's working folder is outside the user's allowed folders (the policy changed after the chat was created). | An administrator adds the folder to the team's extra folders, or the user starts a new chat in an allowed folder. |
| `Goose is not available: <error>` | The worker cannot start (section 7.2). | Section 7.2. |
| `the Goose worker restarted` / `the Goose worker connection closed` | The worker restarted while the chat was loading. | Click Retry. |
| `Goose is not connected` | The worker connection is down. | Wait for the yellow bar to clear, then Retry. |
| Chat opens but is empty or stale | The transcript is reloaded from Goose after reconnecting; a change made outside Goose Web (Goose Desktop on a native profile) is picked up within a few seconds. | Reload the page. |

Goose Web keeps a replay buffer per chat in memory (12 MiB per session, 256 MiB in total; idle chats that nobody
watches are dropped first). A dropped buffer is rebuilt from Goose when the chat is opened again, so this does not
lose history.

---

## 9. Tool calls waiting for approval

| Symptom | Cause | Fix |
| --- | --- | --- |
| The agent stops, the herd card says `Waiting for your approval` or `Needs you: <title>` | Goose asks for permission before running a tool. New isolated profiles start in `approve` mode (`GOOSE_MODE=approve`). | Open the chat and choose **Allow once**, **Always allow**, **Deny** or **Always deny**. |
| Several tabs show the same question | Questions are sent to every open tab of that user. The first answer wins; the others close. | Answer in any one tab. |
| Toast `Not connected - answer not sent` | The answer was clicked while the WebSocket was down. | Wait for the reconnect; the question is shown again. Answer again. |
| The question disappeared without an answer | The worker restarted; open questions are cancelled. | Send the request again. |
| The user cannot pick Auto mode or change tool permissions | The policy limits the allowed modes (`allowed_modes`) or does not grant `tools_permissions`. The agent then reports `forbidden: mode not allowed: <mode>`. | An administrator changes the user's or team's policy (Admin > Teams & policy), and the user reloads. |
| No notification arrived for a waiting question | Notifications for "needs you" are sent only when no open tab is watching that chat. | Expected behaviour; see section 13 for webhooks. |

Administrators can see every user's waiting questions in the herd view and can answer them when viewing that
user's chat (the view is audited).

---

## 10. App tool calls require Auto mode

MCP Apps (interactive extension UIs inside the chat) can ask the agent to run tools.

| Symptom | Cause | Fix |
| --- | --- | --- |
| Toast `This app tried to run the tool "<tool>". Goose only allows app tool calls when the chat is in Auto mode.` | Goose itself refuses tool calls from apps unless the session is in Auto mode. | Switch the chat to Auto mode and repeat the action in the app. If Auto is not offered, the policy does not allow it (section 9). |
| `forbidden: needs the apps permission` | The user's policy does not grant `apps`. | Grant `apps` in the user's or team's policy. |
| `forbidden: tool '<name>' does not belong to extension '<ext>': a tool call may only use tools of the extension it names` | An app tried to call a tool of a different extension. This rule applies to administrators too. | Expected; the app is misbehaving. |
| `forbidden: direct shell tool calls need the allow_shell permission` | An app (or client) tried to call a shell-capable tool without the `allow_shell` permission. | Grant `allow_shell` only if the user should run commands. |
| The app frame shows an error: `bad_app_ref`, `bad_name` (400) or `app_not_found` (404, "resource has no HTML content") | The app resource could not be loaded from the extension. | Check that the extension is enabled and working (section 11). |

---

## 11. Extensions failing or missing

### 11.1 Refused by policy

For users who are not administrators, extension changes go through the policy. Refusals reach the client as
`forbidden: <reason>` (JSON-RPC error -32003) and are written to the audit log as `acp.denied`.

| Message | Fix |
| --- | --- |
| `forbidden: choosing session extensions needs the extensions_edit permission` | Grant `extensions_edit`. |
| `forbidden: command-running extensions need the allow_shell permission` | Grant `allow_shell`, or use a remote (HTTP) extension instead. |
| `forbidden: shell extensions need the allow_shell permission` | The extension is one of `developer`, `computercontroller`, `code_execution` or `orchestrator`. Grant `allow_shell`. |
| `forbidden: per-session MCP servers need the allow_shell permission` | Grant `allow_shell`. |
| `forbidden: needs the <permission> permission` | Grant the named permission. |
| `forbidden: method not available to your account: <method>` | The method is reserved for administrators. |

When `allow_shell` is off, provisioning switches the shell extensions off in the user's profile; the developer
extension shows the description `Shell and file editing (disabled by policy)`. Saving a user's team, hints or
policy overrides, or a team's policy, provisions the affected profiles again; Admin > Users also has a provision
action for one user. After granting `allow_shell`, turn the extension on in the user's settings.

Policy and allowed folders are read when the browser connects. **After any policy change, the user must reload
the page** (or reconnect) before it applies to chats.

### 11.2 The extension starts but fails

| Symptom | Cause | Fix |
| --- | --- | --- |
| A command-based (stdio) extension fails in Docker with "not found" for `npx`, `uvx` or `node` | The Docker image does not include Node.js or uv. | Use remote (HTTP) extensions, or build your own image that adds them. |
| An extension fails in Docker when writing files or caches | The container's root file system is read-only and the home folder is a temporary file system; only `/data` persists. | Point the extension's data and cache paths into `/data`, or adjust the compose file. |
| An extension cannot find its API key | Isolated workers do not use the OS keyring and do not inherit the gateway's `GOOSE_*` variables (section 7.5). | Enter the secret in the user's settings, or pass non-secret variables via `goose.extra_env`. |
| An extension works in Goose Desktop but not in Goose Web | Different profile (isolated vs native) or different environment/`PATH` of the service. | Compare the profile used, and the `PATH` of the service account. |
| An extension that failed at the chat's start still shows "failed" after a successful Retry, once the page reloads or reconnects, although its tools work (before 1.5.1) | The gateway replayed the chat's cached start-up status. Fixed in 1.5.1: Retry, add and remove now update it. | Upgrade. Retry on an extension that is already running is a harmless no-op: Goose keeps the running process and does not restart it. |
| Any other failure | | Read `worker-<user>.log` and `<profile>/data/logs`. Goose prints the extension's start-up error there. |

---

## 12. Schedules not running

Schedules are run by the Goose scheduler inside a worker. Exactly one program must own the scheduler of a profile.

| Profile | Who runs its schedules |
| --- | --- |
| Isolated (per-user) profile | Always the Goose Web worker for that user. |
| Native (shared) profile, `goose.native_scheduler: on` | Goose Web. The Docker image sets this. |
| Native profile, `off` | Goose Desktop, or nobody. |
| Native profile, `auto` (default) | Goose Web only while Goose Desktop is **not** running on that profile (Windows detection). On other systems `auto` behaves like `on`. |

When Goose Web does not own the scheduler, the Schedules page shows a banner:
`The scheduler is not active in this Goose Web instance: <reason> (owner: <owner>). Schedules are read-only here.`

| Reason in the banner | Meaning | Fix |
| --- | --- | --- |
| `native_scheduler=off (schedules run in Goose Desktop or not at all)` | Configured off. | Keep Goose Desktop running, or set `goose.native_scheduler` to `auto` or `on`. |
| `Goose Desktop is running on this profile and owns its scheduler` | `auto` and Goose Desktop is open. | Expected. Schedules run in Desktop. Close Desktop to hand them back (the worker restarts with the scheduler once nothing is running). |
| (log) `Goose Desktop detection failed; assuming it is running` | Detection failed; to avoid running schedules twice, Goose Web assumes Desktop is running. | Check the gateway log for the cause; set `on` or `off` explicitly to avoid detection. |

Other reasons schedules do not fire:

| Symptom | Cause | Fix |
| --- | --- | --- |
| Nothing runs while nobody is signed in to Windows | The Windows logon task runs the gateway only while that Windows user is logged on. | Keep the user logged on (locked screen is fine), or run the gateway differently (see [ADMINISTRATION.md](ADMINISTRATION.md) section 5). |
| Nothing runs after logout on Linux | A systemd user service stops at logout unless lingering is enabled. | `loginctl enable-linger <user>` |
| One user's schedules never run | The account is disabled (workers for disabled users are not started), or the worker keeps crashing (section 7.3). | Enable the account; fix the worker. |
| User cannot create a schedule | The policy does not grant `schedules`. | Grant `schedules`. |
| Schedules run at the wrong time in Docker | The compose file sets `TZ: UTC`. | Set `TZ` to your time zone, or write cron expressions in UTC. |
| Schedule ran but failed | The scheduled run uses the profile's provider, extensions and recipe. | Read Goose's log in `<profile>/data/logs` and the worker log. |
| Schedule count shown as zero | The count comes from `<profile>/data/schedule.json`; the file is missing or unreadable. | Check the file and its owner. |

The gateway's worker for a profile that owns schedules is kept running (no idle shutdown) and is restarted after a
crash even with no browser connected.

---

## 13. Webhooks refused or not delivered

Users can set a webhook (for example an ntfy topic) to be notified when a chat needs them, finishes or fails.
The gateway resolves the host name and refuses addresses that are not public, to prevent the gateway being used to
reach internal services (SSRF).

| Message | Cause | Fix |
| --- | --- | --- |
| `Webhooks are not enabled for your account` (403 `forbidden`) | The policy does not grant `notify_webhook`. | Grant `notify_webhook`. |
| `Webhook must be an http(s) URL` (400 `bad_url`) | Not `http://` or `https://`, or longer than 500 characters. | Use a full URL, for example `https://ntfy.example.org/goose-alice`. |
| `This webhook address is not allowed: <host> resolves to a non-public address (<addresses>); set notify.allow_private_targets to allow internal targets` (400 `webhook_blocked`) | The host resolves to a private, loopback, link-local or otherwise non-public address, such as `192.168.1.10`. | Use a public service, or (administrator, trusted network only) set `notify.allow_private_targets: true` and restart the gateway. |
| `This webhook address is not allowed: cannot resolve <host>` | DNS lookup failed on the gateway machine. | Fix the name or DNS. |
| `This webhook address is not allowed: invalid URL: ...` / `webhook must be an absolute http(s) URL` | Malformed URL. | Correct the URL. |
| Saved, but nothing arrives; log `webhook refused for <user>: ...` | The check is repeated at send time; the address now resolves to a non-public IP. | As above. |
| Nothing arrives; log `webhook failed for <user>: ...` | The request failed (timeout after 8 s, TLS error, HTTP error). | Test the URL with `curl` from the gateway machine. |
| Works with `curl` but not from the gateway | The gateway ignores `HTTP_PROXY`/`HTTPS_PROXY` environment variables and does not follow redirects. | Use the final URL (no redirect). The gateway must reach the target directly. |
| No notification for "needs you" while the chat is open | Not sent while a tab is watching that chat. | Expected. |
| The notification has no link to the chat | The link is only included when `server.public_url` is set. | Set `public_url`. |

URLs that contain `ntfy` receive the message as plain text with the headers `Title`, `Tags: goose`, `Click` (the
chat link) and `Priority` (`high` for "needs you", otherwise `default`). Other URLs receive a JSON body with
`event`, `title`, `message`, `url` and `agent`.

---

## 14. Old user interface after an upgrade

The browser app is installed as a Progressive Web App with a service worker (`sw.js`, cache `gw-shell-v10`). The
page, scripts and styles are fetched from the network first, and the cache is used only when the gateway cannot
be reached; `/api/` and `/ws` are never cached. Third-party libraries and icons are served from the cache first.
The gateway sends these files with `Cache-Control: no-cache`.

| Symptom | Cause | Fix |
| --- | --- | --- |
| After an upgrade the UI looks old, buttons are missing, or new features fail | An old tab, the installed app window or the service worker still holds the previous version. | Hard refresh: Ctrl+Shift+R (Windows/Linux) or Cmd+Shift+R (macOS). |
| Still old after a hard refresh | The old service worker is still in control, for example because other tabs or the installed app are open. | Close every Goose Web tab and the installed app window, then open it again. |
| Still old | Stale cache. | Developer tools > Application > Service workers > **Unregister**, then Application > Storage > **Clear site data**, then reload. Clearing site data signs you out. |
| Old for everyone | The reverse proxy or a CDN caches responses. | Do not cache the Goose Web site at the proxy; pass `Cache-Control` through unchanged. |
| The app opens offline with an old page | The gateway was not reachable and the cached shell was shown. | Check section 1.1. |

---

## 15. Other common errors

| Message | Cause | Fix |
| --- | --- | --- |
| `Uploads are limited to N MB` (413 `too_large`) | File larger than `server.max_upload_mb` (default 25), or more than 20 files at once. | Raise `server.max_upload_mb` (and the proxy body limit), or upload fewer/smaller files. |
| `That folder is outside your allowed folders` (403 `path_forbidden`) | Non-admins can use only their workspace, the team folder and the team's extra folders. | Add the folder to the team's extra folders (Experience > Folders), or use the team folder. |
| `Access denied by the file system` (403 `denied`) | The operating system refused access to the account the gateway runs as. | Fix file permissions/ownership (section 7.4). |
| `Folder not found` / `File not found` (404) | The path does not exist. | Check the path. |
| `name_taken` (409) | A file or folder with that name already exists. | Choose another name. |
| `forbidden: you already have N agents running (limit M)` | `max_concurrent_runs` in the policy (default 3). | Wait for a run to finish, or raise the limit. |
| `forbidden: folder not allowed: <folder>` / `forbidden: project folder not allowed` | Working folder outside the workspace, the team folder and the team's extra folders. | Add the folder to the team's extra folders, then the user reloads. |
| `forbidden: provider not allowed: <provider>` / `model not allowed: <model>` | Not in `allowed_providers` / `allowed_models`. | Adjust the policy. |
| `forbidden: mode not allowed: <mode>` | Not in `allowed_modes`. | Adjust the policy. |
| `forbidden: You are not in a team yet, so you cannot chat. ...` (also a banner on the home page) | The user has no team: created without one, removed from a team, or the team was deleted. They can still sign in and read old chats. | Add the user to a team (Admin > Users > Edit > Team, or the team's Members list). |
| `forbidden: Your team allows no models, so you cannot chat. ...` (or providers, or approval modes) | Since 1.5.0 an empty allowed list allows nothing. The team shows an error warning in Admin > Teams & policy. | Allow values on the team's Experience page, or switch on Any. |
| `forbidden: this chat uses the model '<model>', which your team does not allow. ...` | The chat's provider, model or mode was allowed when the chat started, but not any more. | The user picks an allowed value in the chat header, or an administrator allows it. |
| `forbidden: GOOSE_MODEL value not allowed by your team` / `provider not allowed` / `model not allowed` | A change of the profile default (`defaults/save`) or of the raw config outside the team's lists. | Pick an allowed value. |
| `forbidden: CONTEXT_FILE_NAMES is managed by Goose Web` | Non-admins cannot change which hints files Goose loads. | Nothing to fix: team hints are set by an administrator. |
| `'AGENTS.md' is a Goose hints file name. ...` (403 `hint_file_refused`) | Non-admins cannot upload or create anything named `AGENTS.md`, `.goosehints` or `.goose-web-hints.md`. | Rename the file (for example `AGENTS.txt`), or ask an administrator to put the content in the Hints library. |
| Goose ignores an `AGENTS.md` or `.goosehints` in the project folder (isolated profiles) | Since 1.5.0 isolated workers load only the composed `config/.goose-web-hints.md` (`CONTEXT_FILE_NAMES`). | Put shared instructions in the Hints library and assign them to the team. Check the result with Admin > Users > View effective hints. |
| Personal hints are not used (warning in Settings > Goose hints) | The team does not allow personal hints (`hints_edit` off, the default for new teams). | An administrator switches on "Members may add personal hints", or moves the content into team hints. |
| A user is in a different team, or in none, after the upgrade to 1.5.0 | Users who were in several teams keep only the team with the lowest id (audit `team.migrate.membership`). | Move the user to the right team. |
| `team recipes are managed by your administrator` | A user tried to delete a recipe that comes from the team library. | An administrator removes it from the team library. |
| `Administrators only` (403 `forbidden`) | Admin endpoint used by a normal user. | Use an administrator account. |
| `Your administrator has turned off self-service two-factor enrolment` | `allowSelfTotp` is off. | An administrator turns it on. |
| `Turn on two-factor for your own account before requiring it for administrators` (409) | Prevents an administrator from locking themselves out. | Enrol two-factor first. |
| `Two-factor is required for administrators` (403) | An administrator tried to turn off their own two-factor while it is required. | Turn the requirement off first, or keep two-factor. |
| `names may contain letters, digits, '.', '_' and '-' and must start with a letter or digit` / `reserved name` | Invalid user, team or item name. Reserved: `appdata`, `workspace`, `_system`, `_deleted`, `_teams`, `library`, `backups`, `logs`. | Choose another name. |
| `Internal error (see the gateway log)` (500 `server_error`) | Unexpected error. | Read `gateway.log` for `unhandled error on <path>` and the traceback. |
| A policy change has no effect | Policies are captured when the WebSocket connects. | The user reloads the page. |
| An API token stopped working | Tokens are refused once expired, for disabled accounts, and while a password change is required; `user reset`, a two-factor reset and account deletion remove them. | Create a new token. |

---

## 16. Reporting security issues

Do not report security vulnerabilities in public issues, pull requests or discussions. Follow
[SECURITY.md](../SECURITY.md): use GitHub Security Advisories (the **Report a vulnerability** button on the
repository's **Security** tab).

Include:

- the Goose Web version (`goose-web version`, or `python -m goose_web version`);
- the Goose version (`goose --version`);
- the operating system, or the Docker setup;
- steps to reproduce and the impact;
- your configuration with all secrets removed (passwords, client secrets, tokens, webhook URLs).

Supported versions and what is in and out of scope are listed in [SECURITY.md](../SECURITY.md). For ordinary bugs,
open a normal issue with the relevant lines from `gateway.log` and `worker-<user>.log`, again with secrets,
user names and host names removed.
