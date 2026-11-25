# Security assessment: Goose AI Web Interface (goose-web v1.0.0)

> Since 1.13.0 Goose Web supports Windows only; statements about Linux, macOS and Docker below describe earlier
> versions.

- **Version:** goose-web 1.0.0
- **Date:** 2026-11-06
- **Scope:** the goose-web gateway as a LAN-exposed service: `goose_web/*.py`, the SPA in `goose_web/static/`,
  `scripts/`, `docker/` and the build/CI files (`requirements.lock`, `.github/`). Goose itself (`goose serve`, its
  extensions and its MCP servers) is out of scope, except where the gateway depends on how Goose behaves.
- **Method:** a code review that checks every claim below against the source (file and function are cited), plus
  automated scanning: **bandit** (Python static analysis), **pip-audit** (known vulnerabilities in the locked Python
  dependencies), **detect-secrets** (secrets committed to the repository) and a check of the vendored JavaScript
  libraries against the GitHub security advisory database. The tool output was triaged during the review. The
  relevant results are covered by the findings below. A second, independent code review produced the NEW-01 to
  NEW-10 findings. **No external penetration test was done.** Nothing was attacked at runtime beyond the
  project's own unit tests. Statements about Goose internals that were not verified are marked as such.
- **Reporting:** see [SECURITY.md](../SECURITY.md).
- **Addendum:** [section 7](#7-addendum-goose-web-150-team-profiles-with-least-privilege) records the
  security-relevant changes of goose-web 1.5.0 (team profiles with least privilege) and the known risk that
  remains. Sections 1 to 6 describe v1.0.0. [Section 13](#13-addendum-mxc-sandbox-backend-2026-11-12-1190) covers
  the MXC sandbox backend of 1.19.0 (threat model, change from the AppContainer backend, accepted trade-offs).
  [Section 16](#16-addendum-the-appcontainer-backend-measured-again-2026-11-13-1211) measures the AppContainer
  backend again and records a limit of both backends: the registry of the gateway's account is readable.

## 1. Summary

goose-web lets many people use one Goose installation through the browser. It signs them in, routes each person to
their own `goose serve` worker (one Goose profile each, `GOOSE_PATH_ROOT=<profiles_root>/<user>`) and puts a
default-deny ACP method firewall in front of every non-admin call.

The web-facing controls are solid:

- Passwords use scrypt. Session and API tokens are random and stored as hashes.
- Cookies are HttpOnly and SameSite=Strict, and also `__Host-`/Secure behind HTTPS.
- Every write that uses a cookie needs a CSRF header and passes an Origin check. The WebSocket checks the Origin.
- The Host header is allow-listed, which guards against DNS rebinding.
- The CSP is strict and untrusted Markdown goes through DOMPurify.
- MCP Apps run at an opaque origin, and their bridge can only reach the app's own extension.
- Workers listen on loopback with a secret that changes on every start.
- Dependencies are installed from a hash-locked file.

The main residual risk is structural. **Every worker runs as the same OS account**, so profile isolation is a
privacy boundary, not a hard security boundary. The gateway controls what a user asks Goose for over ACP. It does
not control what a tool does once it runs. That is why shell-capable extensions are off for non-admins unless the
`allow_shell` policy is set. Admins hold the full power of that OS account.

Findings: 0 Critical, 3 High, 14 Medium, 14 Low, 17 Info (48 in total: GW-01 to GW-38 from the main review and
NEW-01 to NEW-10 from the independent review). In v1.0.0 every finding is **Mitigated**, an **Accepted risk**
(explained in its row), or, for GW-08, an open **Recommendation**. GW-14 and GW-24 are mitigated with a remaining
part noted in their rows. Severities show the risk before the fix, so the totals in 4.1 still count mitigated rows.

## 2. System model

```
Browser (SPA/PWA) --HTTPS--> reverse proxy (TLS) --HTTP--> gateway :8710 --ws 127.0.0.1:<random>/acp--> goose serve (one per profile)
                                                            |  SQLite (_system/goose-web.db), logs, team library
                                                            +--> LDAP/AD, OIDC IdP, webhooks, herd peers
```

| Component | Code | Role |
|---|---|---|
| HTTP/WS front | `app.py` (`create_app`, `SecurityHeaders`, `HostGuard`, `ws_endpoint`), `api.py` | REST API, static SPA, `/ws` JSON-RPC channel |
| Request context | `context.py` (`Ctx.require`, `client_ip`, `allowed_origins`) | identity, CSRF/Origin, trusted proxies |
| Auth | `auth.py` (`AuthService`), `security.py` | local, LDAP/AD, OIDC, TOTP, sessions, API tokens, rate limits |
| Policy firewall | `policy.py` (`check`, `check_tool_call_target`, `effective_policy`, `path_allowed`) | per-method allow/deny for non-admins, tool-target check for everyone |
| Hub | `hub.py` (`Hub`, `Upstream`, `Client`) | one persistent upstream ACP socket per profile, id rewriting, asks, herd |
| Workers | `workers.py` (`WorkerManager`) | start, supervise and stop `goose serve`, rotate worker logs |
| Profiles | `profiles.py` (`Profiles.provision`) | profile layout, team items, hints |
| Windows token | `winsec.py` | refuses to run elevated, ownership report |
| Host tasks | `hosttasks.py` | admin view of Windows scheduled tasks |
| Storage | `db.py` | SQLite (WAL): users, teams, sessions, tokens, audit, settings |

### 2.1 Assets

| ID | Asset | Where |
|---|---|---|
| AS1 | Account credentials: password hashes, TOTP secrets, session tokens, API tokens | `users`, `auth_sessions`, `api_tokens` in `goose-web.db` |
| AS2 | Directory/IdP secrets: LDAP bind password, OIDC client secrets, herd peer tokens | `settings` table (`auth`, `peers`) |
| AS3 | Provider API keys and extension secrets | each profile's `config/secrets.yaml` (written by Goose) |
| AS4 | Conversations, recipes, skills, schedules, hints | each profile's `data/`, `config/` |
| AS5 | The admin's native Goose profile (on Windows it can be shared with Goose Desktop) | `%APPDATA%\Block\goose` or the configured profile folder |
| AS6 | Every file the gateway OS account can read or write, and its ability to run commands | host |
| AS7 | Worker secrets (one per worker start) | worker environment, gateway memory |
| AS8 | Audit trail and logs | `audit` table, `_system/logs/` |
| AS9 | Availability of the gateway and of the host | host |

### 2.2 Trust boundaries

| ID | Boundary | Control |
|---|---|---|
| TB1 | Browser to reverse proxy | TLS at the proxy (the gateway has no TLS of its own) |
| TB2 | Reverse proxy to gateway | host firewall, Host allow-list, `trusted_proxies` for `X-Forwarded-*` |
| TB3 | Gateway to `goose serve` workers | loopback only, random port, `X-Secret-Key` per start |
| TB4 | Workers to LLM providers, MCP servers, the internet | Goose and extension config (outside the gateway) |
| TB5 | SPA to MCP App frame | sandboxed opaque-origin frame, `postMessage` bridge limited to the app's own extension |
| TB6 | Gateway to LDAP/AD, OIDC IdP, webhooks, peers | TLS (LDAP: required unless `allowInsecure`), state/nonce/PKCE, webhook SSRF guard |
| TB7 | Gateway/workers to the OS (file system, processes) | one non-elevated OS account for everything |
| TB8 | Profile to profile | logical only (separate folders and processes, same OS account) |

### 2.3 Attackers

| ID | Attacker | Capabilities assumed |
|---|---|---|
| A1 | Unauthenticated LAN host | can reach the proxy (and the gateway port if the firewall allows it), can run a malicious web page in a user's browser (including DNS rebinding) |
| A2 | Authenticated low-privilege user | valid non-admin account, any HTTP/WS request, controls their prompts and files in their workspace |
| A3 | Malicious MCP App or extension content | HTML/JS in an MCP App, tool output, web pages or files the model reads (prompt injection) |
| A4 | Compromised reverse proxy | sees decrypted traffic, can forge headers including `X-Forwarded-For` |
| A5 | Local OS user | another account on the gateway host, or code running as the gateway account |

## 3. STRIDE threat model

| STRIDE | Threat | Attacker | Controls in the code | Residual / findings |
|---|---|---|---|---|
| **S**poofing | Password guessing, credential stuffing | A1 | scrypt (`security.hash_password`), 40 attempts/5 min per IP and 10/5 min per IP+user (`AuthService.__init__`, `login`), lockout after 8 failures (password or TOTP) for 15 min, generic errors, dummy hash for unknown users (`verify_password`) | GW-26 (lockout abuse) |
| S | Default or guessable first admin password | A1 | random 20-character initial password from `goose-web init` (`__main__.generate_admin_password`), shown once; `must_change_pw` gate (`Ctx.require`, `ws_endpoint`) | GW-09 |
| S | Session theft or fixation | A1, A4 | 256-bit random token per login, stored as SHA-256 (`create_session`, `resolve_cookie`), HttpOnly, SameSite=Strict, `__Host-` + Secure when `public_url` is https (`Ctx.cookie_name`, `api._set_cookie`) | GW-10 (no TLS without a proxy), GW-28 |
| S | Forged identity from the IdP or directory | A1 | OIDC state (single use, 10 min), PKCE S256, nonce, iss/aud/exp, accounts bound by issuer + subject (`oidc_start`, `oidc_callback`); OIDC refused without `public_url`; LDAP filter escaping, exactly one matching entry, TLS required (`_ldap_login`, `ldap_transport_insecure`) | GW-11, GW-12, GW-13 |
| S | Forged client IP | A1, A4 | `X-Forwarded-For` honoured only from `trusted_proxies`, rightmost entry (`Ctx.client_ip`) | GW-25 |
| S | Second factor bypass | A1 | TOTP RFC 6238, constant-time compare, each time step accepted once per user (`AuthService.accept_totp`, `security.totp_match`) | GW-14 |
| S | DNS rebinding against a loopback or LAN bind | A1 | Host allow-list (`app.HostGuard`, `allowed_hosts`); origins come from `public_url` when it is set (`Ctx.allowed_origins`) | NEW-04, GW-30 |
| **T**ampering | Cross-site request forgery | A1 | per-session CSRF header (`Ctx.require`), Origin allow-list, SameSite=Strict, Origin check on login (`api.login`) | GW-29 |
| T | Cross-site WebSocket hijacking | A1 | Origin must be allowed before the socket is accepted; token sockets must have no Origin (`ws_endpoint`) | GW-30 |
| T | Non-admin changing config, extensions, providers, other folders | A2 | default-deny ACP firewall (`policy.check`), cwd/root confinement with symlink resolution (`path_allowed`), shell extension gating, config key allow-list | GW-06, GW-08, GW-19 |
| T | MCP App reaching tools of another extension, or acting as the user | A3 | `policy.check_tool_call_target` (all users), client-side prefix check, per-call confirmation for sensitive extensions, confirmation and rate limit for app chat messages (`static/js/views/apps.js: createAppBridge`) | GW-07, NEW-01, NEW-02 |
| T | Writing into another profile through the hub | A2 | one upstream per profile, keyed by the caller's username (`Ctx.upstream_for`); `?profile=` is admin-only and audited (`ws_endpoint`) | GW-37 |
| T | Injected answers to agent requests | A2 | answers are only accepted for pending asks and the first answer wins (`Upstream._answer_ask`) | GW-37 |
| T | Tampering with worker traffic | A5 | loopback, per-start secret (`WorkerManager._start`, `Upstream.ensure`) | GW-18 |
| T | Prompt injection steering tools | A3 | approve mode for new isolated profiles (`Profiles.provision`), permission cards, shell off for non-admins | GW-03 |
| T | Tampered dependencies or build inputs | supply chain | `requirements.lock` with hashes, base image by digest, goose tarball SHA-256, `static/vendor/SHA256SUMS` | GW-24 |
| **R**epudiation | Denying admin actions or impersonation | A2 | audit rows for sign-ins, user/team/settings changes, `ws.impersonate`, audited ACP writes, answers and denials (`Hub.audit_call`, `audit_ask`, `audit_denied`, `api._acp_request`) | GW-23 (365-day retention); A4/A5 can rewrite the DB |
| **I**nformation disclosure | Reading another profile's chats/secrets | A2, A3 | separate `GOOSE_PATH_ROOT`, `GOOSE_*` env scrub, shell gated, fs endpoints confined (`api._check_path`) | GW-01, GW-04, GW-05, GW-08 |
| I | XSS stealing data | A3 | strict CSP (`app.SPA_CSP`), DOMPurify (`static/js/markdown.js`), unsafe URL schemes dropped by `h()` (`static/js/ui.js`), MCP Apps at an opaque origin (`api.apps_frame`) | GW-07, GW-31, NEW-06 |
| I | Credentials in URLs and logs | A4, A5 | API tokens only in the `Authorization` header, also for the WebSocket (`ws_endpoint`) | GW-21, NEW-03 |
| I | Server-side request forgery through webhooks | A2 | address checks on every resolved IP, pinned connection, no redirects, no environment proxy (`app.webhook_target`, `send_webhook`) | GW-20 |
| I | Secrets at rest | A5 | hashes for passwords/tokens; everything else is plaintext on disk | GW-15, GW-16, GW-17 |
| I | Logs | A5, admins | rotated gateway and worker logs; audit stores keys and ids, not values | GW-23 |
| **D**enial of service | Large requests, slow consumers, many runs | A1, A2 | 2 MiB JSON bodies (`body_json`), upload limit, 64 MiB WS frames, 12 MiB per-session / 256 MiB total buffers, 20000-message client queue, `max_concurrent_runs` | GW-22 |
| **E**levation of privilege | Non-admin to shell or admin | A2, A3 | `allow_shell` gate (`policy.check`, `Profiles.provision`), admin endpoints need `role == admin` (`Ctx.require(admin=True)`) | GW-04, GW-06, GW-08, NEW-01 |
| E | Gateway running with an admin token | A5 | `winsec.ensure_unelevated` (SAFER normal-user token, Medium integrity), logon task RunLevel Limited, installer refuses to run elevated, POSIX refuses root | GW-34 |
| E | Compromised reverse proxy | A4 | nothing the gateway can do: the proxy sees cookies and passwords | accepted, see the checklist |

## 4. Findings

Severity assumes a LAN deployment behind a TLS reverse proxy and describes the risk **before** the fix. Status:

- **Mitigated (v1.0.0)** = fixed in this release. The row describes the fix and notes any residual risk.
- **Mitigated** = a control that was already in place and was verified.
- **Accepted risk** = known, and either by design or out of scope for the gateway.
- **Recommendation** = a change is advised and not yet made.

| ID | Title | Severity | Status | Evidence (file: function) | Mitigation / recommendation |
|---|---|---|---|---|---|
| GW-01 | Profile isolation is a privacy boundary, not a security boundary (one OS account for all workers) | High | Accepted risk | `workers.py: WorkerManager._start, _env`; `profiles.py: Profiles.root_for` | Separate profile folders and processes, `GOOSE_*` env scrubbed for isolated workers, shell/stdio extensions off unless `allow_shell`, cwd confined. Any tool that can read files (or a granted shell) runs with the shared account's rights and can reach other profiles and the admin's files. Grant `allow_shell` only to people you would give that OS account. For a hard boundary, run one gateway per OS user or per container. |
| GW-02 | Admin role = full Goose power on the host | Info | Accepted risk | `policy.py: check` (returns early for admins, after the tool-target check), `ADMIN_POLICY`; `context.py: Ctx.path_ok`; `api.py: fs_roots` (all drives), `admin_hosttask_action`; `app.py: ws_endpoint` (`?profile=`) | Admins can browse any absolute path, use every extension, run host tasks and open any profile (audited as `ws.impersonate`). Keep admins few, turn on TOTP and `requireTotpForAdmins`. |
| GW-03 | LLM prompt injection can steer tools | High | Accepted risk | `profiles.py: Profiles.provision` (`GOOSE_MODE: approve` on first provisioning); `hub.py: Upstream._dispatch` (permission asks); `policy.py: DEFAULT_POLICY` (`allowed_modes: []`) | This risk comes with any agent that uses tools. New isolated profiles start in approve mode, and permission requests reach every tab of the profile. The default policy does not restrict modes, so a user can switch to auto. Set `allowed_modes` for teams (for example `approve`, `smart_approve`, `chat`) and review which extensions read the web or files. |
| GW-04 | A user named `appdata` (or `workspace`) maps onto the fresh-install admin profile (or the Docker admin workdir) | High | Mitigated (v1.0.0) | `db.py: Database.create_user` rejects `RESERVED_USERNAMES` (`appdata`, `workspace`, `_system`, `_deleted`, `library`, `backups`, `logs`, case-insensitive). The CLI, the admin UI and LDAP/OIDC auto-create all go through `create_user`. Test: `tests/test_policy.py::test_reserved_usernames` | Before the fix, an isolated user with one of these names (created by an admin or auto-created from LDAP/OIDC) would have received the admin's chats and secrets on installs where the admin profile is `<profiles_root>/appdata` (Linux/macOS by default, Docker, and Windows without an existing Goose profile). |
| GW-05 | Herd peer results (fetched with the admin-configured peer token) were returned to every signed-in user | Medium | Mitigated (v1.0.0) | `api.py: herd` fetches peers only when `ident.via == "cookie" and role == "admin"` | Non-admins see only their own herd. Use a peer token for an account whose agents admins may see. |
| GW-06 | `tools/call` shell gating checked `extensionName`, not the prefix of the tool `name` | Medium | Mitigated (v1.0.0) | `policy.py: check` also denies when the prefix of `name`/`toolName` (the part before `__`) is a shell extension, unless `allow_shell` is set; `check_tool_call_target` refuses any prefix that differs from `extensionName` (NEW-01). Test: `tests/test_policy.py::test_tools_call_shell_by_name_prefix` | Whether Goose dispatches on the prefixed name was not verified; both readings are now covered. |
| GW-07 | MCP App frames: opaque origin, but unrestricted network access and tool calls | Medium | Mitigated (v1.0.0) | `api.py: apps_frame`, `APP_FRAME_CSP` (`sandbox allow-scripts allow-forms allow-popups; default-src * ...; frame-ancestors 'self'`), `_acp_request`; `static/js/views/apps.js: createAppBridge` (iframe `sandbox="allow-scripts allow-forms allow-popups"`, `event.source` check, http(s)/mailto-only `ui/open-link`) | No `allow-same-origin`, so the frame has no cookies, no SPA DOM and no API access (the CSP `sandbox` also applies when someone opens the URL directly). v1.0.0 removed `allow-popups-to-escape-sandbox` from the frame CSP. `apps_frame` now runs `policy.check` and audits denials (`acp.denied`). Tool calls are limited to the app's own extension (NEW-01), and chat messages need confirmation (NEW-02). Residual: an app can still send data it receives to any host (`default-src *`). Import apps only from trusted sources. |
| GW-08 | Tool behaviour is outside the ACP firewall (file reads, agent-side extension management) | Medium | Recommendation | `profiles.py: BASE_EXTENSIONS` (includes `extensionmanager`, `analyze`, `summon`), `Profiles.provision` (writes a disabled `developer` entry); `policy.py: check` | The firewall sees ACP requests, not what a running tool does. Built-in tools that read paths are not confined to `allowed_roots`. It was not verified whether Goose's `extensionmanager` lets the model turn on a configured-but-disabled `developer` entry during a session. Test this on your Goose version. If it can, remove `extensionmanager` from `BASE_EXTENSIONS` and drop the `developer` entry for profiles without `allow_shell`. Treat `config_edit` (raw `config/upsert`) as equivalent to `allow_shell`. |
| GW-09 | Default-password window during first install | Medium | Mitigated (v1.0.0) | `__main__.py: cmd_init`, `generate_admin_password`, `_print_initial_password`, `_read_password_file`; `scripts/install.ps1`, `install.sh`; `docker/entrypoint.sh`; `context.py: Ctx.require` (`password_change_required`) | There is no fixed default password any more. `goose-web init` generates a random 20-character password that meets the password policy and prints it once. `--password` and `--password-file FILE` (`-` = stdin) set one explicitly. The installers show the generated password at the end of their output. The container prints it to its log on the first start only. It also accepts `GOOSE_WEB_ADMIN_PASSWORD_FILE` (preferred, for example a compose secret) or `GOOSE_WEB_ADMIN_PASSWORD`, passed to `init` through a file or stdin and unset before the gateway is exec'd. The forced change at first sign-in is kept. A lost initial password is reset with `goose-web user reset NAME`. |
| GW-10 | No built-in TLS | Medium | Accepted risk | `__main__.py: cmd_serve` (uvicorn without TLS); `context.py: Ctx.secure` | Terminate TLS at a reverse proxy and set `public_url` to `https://...`. This turns on Secure + `__Host-` cookies and HSTS. Without a proxy, passwords and cookies cross the LAN in clear text. Restrict the gateway port to the proxy in the firewall. |
| GW-11 | OIDC ID token signature is not verified | Low | Accepted risk | `auth.py: oidc_callback`, `_jwt_claims` | OIDC Core 3.1.3.7 allows this: the token comes straight from the token endpoint over TLS (httpx verifies certificates by default), and iss, aud, exp, nonce, state and PKCE are checked. This depends on an `https://` issuer. Checking the signature against the JWKS would add defence in depth. |
| GW-12 | OIDC accounts were linked by `preferred_username`/email local part, not by issuer + `sub` | Medium | Mitigated (v1.0.0) | `db.py: MIGRATIONS` (`users.oidc_issuer`, `users.oidc_subject`, unique index `ux_users_oidc`); `auth.py: oidc_callback` / `_upsert_external`; `api.py: _redirect_uri` | An OIDC account is now bound to the issuer + subject of its first sign-in. Existing OIDC users that are not yet bound are bound at their next sign-in. A different issuer/subject for a bound name returns `409 oidc_conflict`, and local and LDAP accounts with that name stay protected. OIDC now needs `server.public_url`, so the redirect URI never depends on the Host header (`400 oidc_needs_public_url`). Residual: on the very first sign-in, the name still comes from the IdP's username claim, so `stripDomain: false` remains advisable for multi-domain IdPs. |
| GW-13 | LDAP sent passwords in clear if the configuration did not use TLS | Medium | Mitigated (v1.0.0) | `auth.py: ldap_transport_insecure`, `save_auth_config`, `login`, `_ldap_login` | A plain `ldap://` URL without StartTLS is refused when the settings are saved (`400 bad_config`) and at sign-in (`503 ldap_insecure`, no bind is attempted), unless `ldap.allowInsecure` is `true` (admin UI checkbox "Allow unencrypted LDAP (not recommended)"). TLS uses `CERT_REQUIRED`, with `caFile` for a private CA. Already in place: `escape_filter_chars` on the username, exactly one matching entry, empty passwords refused before bind, timeouts. |
| GW-14 | TOTP gaps: codes replayable inside the window, failed codes not counted toward lockout, `requireTotpForAdmins` does not force enrolment, `allowSelfTotp` not enforced | Low | Mitigated (v1.0.0), one part remains a Recommendation | `auth.py: accept_totp`, `login`, `_record_failure`, `totp_enrolment_required`; `security.py: totp_match`; `db.py` (`users.totp_last_counter`); `api.py: _check_self_totp_allowed`, `totp_setup`, `totp_enable`, `admin_settings` | Fixed: the last accepted time step is stored per user and claimed atomically, so a code cannot be used twice (the enrolment code included). Wrong or replayed codes count toward the account lockout. `allowSelfTotp` is enforced for non-admins (`403 totp_self_disabled`). `requireTotpForAdmins` can only be turned on by an admin who already uses TOTP (`409 totp_needed_first`). The login response and `/api/me` report `totpEnrolmentRequired`. **Remaining (Recommendation):** an admin without TOTP is not yet forced to enrol at sign-in while the requirement is on. |
| GW-15 | Gateway secrets stored in plaintext in SQLite | Medium | Accepted risk | `db.py: SCHEMA` (`totp_secret`); `auth.py: save_auth_config` (LDAP `bindPassword`, OIDC `clientSecret`); `api.py: admin_settings` (peer `token`) | They are masked in API reads (`masked_auth_config`, `********`). Password hashes, session tokens and API tokens are hashed. Protect `_system/` with file permissions (GW-17) and protect your backups. |
| GW-16 | Goose stores provider and extension secrets in plaintext `secrets.yaml`; team items copy secrets between profiles | Medium | Accepted risk | `workers.py: _env` (`GOOSE_DISABLE_KEYRING=1` for isolated workers); `profiles.py: Profiles.provision` (`secrets_from`) | This is Goose's own file-based secret store. Team members receive the shared keys in their own `secrets.yaml`, and the shared account can read every profile's secrets (GW-01). Share only keys you would give each member, and use per-team keys with spending limits. |
| GW-17 | Windows installer did not tighten ACLs on the profiles root | Medium | Mitigated (v1.0.0) | `scripts/install.ps1` (`icacls <ProfilesRoot> /inheritance:r /grant:r <installing user>:(OI)(CI)F SYSTEM:(OI)(CI)F Administrators:(OI)(CI)F`); compare `scripts/install.sh` (`chmod 700`), `docker/entrypoint.sh` (`umask 077`) | A folder created under `C:\` usually inherits Authenticated Users Modify. The installer now removes inheritance and grants only the installing user, SYSTEM and Administrators. Check the native Goose profile folder the same way on hosts with other accounts. |
| GW-18 | Same-machine attacker: loopback worker ports, port-selection race | Low | Accepted risk | `workers.py: _free_port`, `_start` (port chosen, released, then bound by goose; readiness through the unauthenticated `/status`); `hub.py: Upstream.ensure` (sends `X-Secret-Key`) | Any local process can connect to a worker port but needs the 32-byte secret. A local process that wins the bind race could pose as a worker and receive the secret and prompts. Code running as the gateway account can read worker environments anyway. Keep untrusted users and code off the host. |
| GW-19 | Path confinement was lexical; some source scopes are not checked | Low | Mitigated (v1.0.0) | `policy.py: path_allowed`, `_real`, `_within`; `check` (`sources/*`) | A path is allowed only when **both** checks pass: the lexical one (normpath/abspath, so `..` cannot climb out) and the resolved one (`os.path.realpath` on the path and on every root, so a symlink or junction inside an allowed root cannot point outside it). Residual: `sources/*` still checks only `scope: projectDir`. It was not verified whether Goose writes `global` skills under `GOOSE_PATH_ROOT` or the shared home folder. |
| GW-20 | Webhooks allowed server-side requests to any http(s) URL | Low | Mitigated (v1.0.0) | `app.py: address_blocked`, `webhook_target`, `send_webhook`, `make_event_handler`; `api.py: me_notify`; config `notify.allow_private_targets` | Every address the host name resolves to is checked. Non-global targets are refused: loopback, private, link-local, CGNAT, reserved, multicast, unspecified, and IPv4 embedded in IPv6 (IPv4-mapped, 6to4, Teredo, NAT64). The request then goes to the checked IP with the original Host header and TLS SNI, so DNS rebinding between check and connect cannot redirect it. Redirects are not followed, and environment proxies are ignored (`trust_env=False`). The URL is also validated when it is saved (`400 webhook_blocked`). Opt-out for internal targets: `notify.allow_private_targets: true` (default `false`). Webhooks still need the `notify_webhook` permission (default off). |
| GW-21 | API tokens are unscoped, could travel in the WebSocket query string, and survived a password change | Low | Mitigated (v1.0.0) | `auth.py: create_api_token`, `resolve_token`, `revoke_user_tokens`; `app.py: ws_endpoint`; `api.py: me_password`, admin password set/reset and disable; `__main__.py` (`user reset`) | A user's API tokens are now revoked on a self-service password change, an admin password set or reset, account disable, and CLI `user reset`. Tokens are no longer accepted in the WebSocket query string. They are accepted only in the `Authorization: Bearer` handshake header, and only when there is no Origin (NEW-03). Already in place: `gwt_` + 256 bits, stored as SHA-256, optional expiry, refused while a password change is pending, a token cannot create more tokens. Residual: tokens carry the user's full rights (no scopes). Set expiries. |
| GW-22 | Denial of service limits are partial | Low | Accepted risk | `context.py: body_json` (2 MiB); `__main__.py: cmd_serve` (`ws_max_size` 64 MiB); `hub.py: SESSION_BUFFER_BYTES`, `TOTAL_BUFFER_BYTES`, `Client.queue` (20000); `policy.py: DEFAULT_POLICY` (`max_concurrent_runs: 3`); `docker/compose.yaml` (`pids_limit`, `mem_limit`) | There is no global cap on workers or users and no request rate limit outside sign-in. An authenticated user can use CPU, memory and LLM budget within their policy. Keep the user population trusted, set `max_concurrent_runs`, and use the container limits or OS quotas. |
| GW-23 | Log content and retention | Low | Mitigated (v1.0.0) | `workers.py: rotate_log` (`WORKER_LOG_MAX_BYTES` 10 MiB, `WORKER_LOG_BACKUPS` 3, before each worker start); `__main__.py: _setup_logging` (gateway.log 5 x 5 MB); `db.py: purge_audit` (`AUDIT_RETENTION_DAYS` 365, at startup) | Worker logs rotate at 10 MiB with 3 backups. Audit rows older than 365 days are deleted when the gateway starts. Residual: worker logs contain whatever `goose serve` prints and admins can read them in the UI (`api.admin_logs`). If a worker log is still held open on Windows, the rotation is skipped and logged. The audit log records keys, ids and IPs, not config values. |
| GW-24 | Dependency supply chain | Medium | Mitigated (v1.0.0), residual noted | `requirements.lock`; `docker/Dockerfile`; `scripts/install.ps1`, `install.sh`; `goose_web/static/vendor/SHA256SUMS` and `tests/test_platform_hardening.py`; `.github/dependabot.yml`; `.github/workflows/ci.yml` | Python dependencies come from `requirements.lock` with hashes (`pip install --require-hashes`), then the app itself with `--no-deps`, in Docker, the installers and CI. The Docker base image is pinned by digest. The goose release tarball is checked against a SHA-256 per architecture (`GOOSE_SHA256_AMD64`/`ARM64` build args). The build fails on a mismatch. Vendored JS is listed in `static/vendor/SHA256SUMS`, and a test fails on any change. Dependabot covers pip, docker and GitHub Actions. CI pins actions by commit SHA and runs a `pip-audit` job. **Remaining:** the build backend (hatchling) is fetched without hash pinning when the app is installed. Dependabot may not regenerate `requirements.lock`, so re-run `pip-compile --generate-hashes` in those PRs. Watch DOMPurify and marked advisories. |
| GW-25 | Trusted proxy configuration | Low | Mitigated | `context.py: Ctx.client_ip`, `from_trusted_proxy`, `allowed_origins`; `app.py: HostGuard` | `X-Forwarded-For` (rightmost entry) and `X-Forwarded-Proto/Host` are used only when the TCP peer is in `trusted_proxies` (default: loopback only). A trusted `X-Forwarded-Host` must also be on the Host allow-list. Trusting a broad range, such as the commented `172.16.0.0/12` in `docker/compose.yaml`, lets any host in it fake client IPs for the rate limiter and the audit log. |
| GW-26 | Account lockout can be triggered by others | Low | Accepted risk | `auth.py: login`, `_record_failure` | 8 wrong passwords or TOTP codes lock an account for 15 minutes. The per-IP limiter slows a single source. Admins can unlock (`api.admin_user_unlock`, `goose-web user reset`). Lockout does not apply to names that have no database row yet (first LDAP sign-in). |
| GW-27 | Password storage and policy | Info | Mitigated | `security.py: hash_password` (scrypt N=2^15, r=8, p=1, 16-byte salt, 32-byte key), `verify_password` (constant time, dummy hash for unknown users), `needs_rehash`, `password_problems` (min length 10, not the username, common-password list, 3 character classes below 16 characters) | Hashes are upgraded at sign-in when the parameters change. |
| GW-28 | Session cookies and lifetime | Info | Mitigated | `auth.py: create_session`, `session_alive`, `resolve_cookie`, `session_hours`, `clamp_sessions`; `api.py: _set_cookie`; `context.py: Ctx.cookie_name` | HttpOnly, SameSite=Strict, Secure and `__Host-gw` with an https `public_url`; a session cookie (no Max-Age). Since 1.25.0: 8 h at most (DB `session_hours` / `auth.session_hours`, 1-8), no "remember me", stored sign-ins cut to the lifetime at start-up, optional idle limit (section 21.3). Sessions are revoked on password change (other sessions), reset and disable. Lifetimes are fixed: `last_seen` is updated, `expires_at` is never extended. |
| GW-29 | CSRF protection | Info | Mitigated | `context.py: Ctx.require` (non-GET with cookie auth: Origin in the allow-list if present, `X-CSRF-Token` equal to the session's token, constant time); `api.py: login` (Origin check) | Bearer-token requests do not need CSRF (no ambient credential). |
| GW-30 | WebSocket origin and gating | Info | Mitigated | `app.py: ws_endpoint`, `HostGuard` | Cookie sockets need an allowed Origin. Token sockets need the `Authorization` header and no Origin. Sockets are closed before accept for unauthenticated users or a pending password change. `?profile=` is admin-only and audited. Since v1.0.0 the Host header is allow-listed as well (NEW-04), so a DNS-rebinding page can no longer reach the gateway under its own host name. |
| GW-31 | Security headers and XSS | Info | Mitigated | `app.py: SecurityHeaders`, `SPA_CSP`; `static/js/markdown.js` (DOMPurify, forbidden tags and `style`, `javascript:` links removed, remote images dropped); `static/js/ui.js: h()` (NEW-06); `api.py: fs_download` (NEW-08) | CSP `script-src 'self'`, `object-src 'none'`, `base-uri 'none'`, `frame-ancestors 'none'`; X-Frame-Options DENY, nosniff, Referrer-Policy same-origin, COOP/CORP same-origin, Permissions-Policy, `no-store` on `/api/`, HSTS (1 year) with an https `public_url`, no Server header. `style-src` allows `'unsafe-inline'`. |
| GW-32 | Non-admin ACP firewall | Info | Mitigated | `policy.py: check`, `ALWAYS`, `BY_PERMISSION`, `READABLE_CONFIG_KEYS`; `hub.py: Upstream.from_client`; `api.py: _acp_request` | Unknown methods are denied (code -32003, audited `acp.denied`). cwd and `additionalDirectories` must be inside the user's roots. Per-session MCP servers (`mcpServers` on `session/new`, `session/load`, `session/fork` and `session/resume` - before 1.7.0 only `session/new` was checked, see 8.1 NEW-30) and command-running extensions need `allow_shell`. Without `config_edit`, only five config keys are readable, and never secrets. Members cannot delete team recipes (`_guard_recipe_delete`). Concurrency limit (`_check_concurrency`). ACP calls the gateway makes for REST routes (`apps_frame`) go through the same check. |
| GW-33 | Worker process isolation | Info | Mitigated | `workers.py: _start` (`--host 127.0.0.1`, random port, `secrets.token_urlsafe(32)` per start via `GOOSE_SERVER__SECRET_KEY`), `_env` (drops `GOOSE_*` except two for isolated workers, sets `GOOSE_PATH_ROOT`, `GOOSE_RECIPE_PATH`), `_Job` (kill-on-close Job Object), `_kill` (process tree / process group); `WorkerManager.desktop_running` | `goose.extra_env` is applied to every worker, isolated ones included. The native worker inherits the full environment. On POSIX, workers are not killed automatically if the gateway dies abruptly. Goose Desktop detection (for `native_scheduler: auto`) fails safe: an error counts as "Desktop is running", so the native profile's scheduler is never started twice. |
| GW-34 | Elevation guard and file ownership | Info | Mitigated | `winsec.py: ensure_unelevated`, `run_unelevated` (SAFER normal-user level, Medium integrity, owner = user SID, no fallback to elevated), `ownership_report`; `scripts/register-service.ps1` (Interactive, RunLevel Limited, verified after registration); `scripts/install.ps1` (refuses elevated) | POSIX: refuses root (exit 3). `server.allow_elevated` turns the guard off; leave it false. |
| GW-35 | Host tasks feature | Info | Mitigated | `hosttasks.py: task_action` (action allow-list, path must start with `\`, not `\Microsoft\`, no CR/LF/NUL, values passed in environment variables, not interpolated), `elevation_risk`; `api.py: admin_hosttasks` (admin only, `host_tasks.enabled`) | The gateway never changes a task's principal. Admins can run, end, enable or disable any task the gateway account can manage. Set `host_tasks.enabled: false` if you do not need this. |
| GW-36 | File endpoints | Info | Mitigated | `api.py: _check_path`, `fs_list`, `fs_mkdir`, `fs_upload` (`max_upload_mb`, 20 files, streamed size check, `safe_upload_name`, `_create_exclusive`), `fs_read` (1 MiB), `fs_download` | Non-admins are confined to their workspace plus `allowed_roots` (lexical and resolved, GW-19). Admins can use any absolute path (GW-02). Uploads never overwrite (NEW-05). Downloads are always attachments (NEW-08). |
| GW-37 | Hub multiplexing | Info | Mitigated | `hub.py: Upstream.from_client` (gateway-assigned upstream ids), `_dispatch`, `_answer_ask` (only pending asks, first answer wins, `_gw/ask_resolved` broadcast), `Hub.gw_method` (`_gw/herd all` admin only, `_gw/watch` capped at 200), `Client.send` (drops stuck tabs) | Clients share one upstream only within the same profile. |
| GW-38 | Container hardening | Info | Mitigated | `docker/Dockerfile` (uid 1000 `goose`, `USER goose`, tini); `docker/entrypoint.sh` (refuses root, `umask 077`, initial-password variables unset before exec); `docker/compose.yaml` (`read_only: true`, tmpfs `/tmp` and `/home/goose`, `cap_drop: [ALL]`, `no-new-privileges:true`, `pids_limit: 1024`, `mem_limit: 4g`, port published on `127.0.0.1`) | Inside the container all profiles still share uid 1000 (GW-01). |
| NEW-01 | MCP App bridge let an app call tools of other extensions (tool name prefix) | Medium | Mitigated (v1.0.0) | `policy.py: check_tool_call_target` (called from `check` for every user, admins included); `static/js/views/apps.js: createAppBridge` (`SENSITIVE_EXTENSIONS`, `confirmSensitiveTools`) | The client refuses a tool name whose `<extension>__` prefix differs from the app's extension. The server policy denies any `tools/call` whose name prefix differs from `extensionName`, independently of the client. Grid or imported apps that declare `developer`, `computercontroller`, `code_execution` or `orchestrator` need the user's confirmation for each call (default: deny). |
| NEW-02 | MCP Apps could send chat messages as the user | Low | Mitigated (v1.0.0) | `static/js/views/apps.js: createAppBridge` (`ui/message`, `appConsent`, `MAX_APP_MESSAGE_BYTES`, `APP_MESSAGE_INTERVAL_MS`) | Each app message needs confirmation in a dialog (Cancel has the focus, closing means cancel). Messages are capped at 8 KB, limited to one per 5 s per app, and only one can be pending at a time. |
| NEW-03 | WebSocket API token in the query string leaked into access and proxy logs | Medium | Mitigated (v1.0.0) | `app.py: ws_endpoint` | `?token=` is no longer accepted. Non-browser clients send `Authorization: Bearer gwt_...` in the handshake, without an Origin header. |
| NEW-04 | Host header trusted (DNS rebinding against a `127.0.0.1` bind) | Low | Mitigated (v1.0.0) | `app.py: HostGuard`, `allowed_hosts`; `context.py: Ctx.allowed_origins`; `api.py: _redirect_uri` | `HostGuard` refuses HTTP and WebSocket requests whose Host is not allow-listed (`400 invalid host`). The allow-list holds the `public_url` host, `localhost`, `127.0.0.1`, `::1`, `server.host` (unless it is a wildcard address) and `server.allowed_hosts`. `GET /healthz` is exempt. `X-Forwarded-Host` is used only from trusted proxies and must be allow-listed too. When `public_url` is set, allowed origins come from it (plus `server.allowed_origins`), not from the request's Host. OIDC refuses to run without `public_url`. |
| NEW-05 | Upload names: Windows device names, trailing dots/spaces; overwrite race | Low | Mitigated (v1.0.0) | `api.py: safe_upload_name`, `_create_exclusive`, `fs_upload` | Names keep only the last path component. Windows-invalid characters and trailing dots/spaces are removed, and device names (`CON`, `COM1`, `con.txt`, ...) get a `_` prefix. Files are created with exclusive create. On a clash the gateway tries `name (1).ext`, `name (2).ext` and so on, so an existing file is never overwritten. |
| NEW-06 | Device-code sign-in link scheme was not checked | Info | Mitigated (v1.0.0) | `static/js/ui.js: h()` (`URL_ATTRS`, `SAFE_URL_SCHEMES`, `isSafeUrlAttr`) | The DOM helper drops unsafe URL schemes (anything except http, https, mailto and blob) on `href`, `src`, `action`, `formaction` and `xlink:href`. This covers the provider device-code link and every other link the SPA builds. |
| NEW-07 | `apps_frame` bypassed the policy check and audit; frame CSP allowed popups to escape the sandbox | Info | Mitigated (v1.0.0) | `api.py: apps_frame`, `_acp_request`, `APP_FRAME_CSP` | See GW-07: the frame's ACP reads now go through `policy.check` with `acp.denied` auditing, and `allow-popups-to-escape-sandbox` was removed. |
| NEW-08 | Downloads were served with guessed content types | Info | Mitigated (v1.0.0) | `api.py: fs_download` | Always `application/octet-stream`, `Content-Disposition: attachment`, `Content-Security-Policy: sandbox; default-src 'none'`, `Cache-Control: no-store`. |
| NEW-09 | Documentation linked to documents that were not published | Low | Mitigated (v1.0.0) | `README.md`, `SECURITY.md`, `docs/CONFIGURATION.md` | This public assessment now exists, and the links point to it. Links to internal design notes were removed. |
| NEW-10 | Code comments described a private deployment; a stray empty file was in the tree | Info | Mitigated (v1.0.0) | source comments, `goose_web/static/js/views/` | The comments were made generic and the stray file was deleted. |

### 4.1 Totals

| Severity | Count | IDs |
|---|---|---|
| Critical | 0 | - |
| High | 3 | GW-01, GW-03, GW-04 |
| Medium | 14 | GW-05, GW-06, GW-07, GW-08, GW-09, GW-10, GW-12, GW-13, GW-15, GW-16, GW-17, GW-24, NEW-01, NEW-03 |
| Low | 14 | GW-11, GW-14, GW-18, GW-19, GW-20, GW-21, GW-22, GW-23, GW-25, GW-26, NEW-02, NEW-04, NEW-05, NEW-09 |
| Info | 17 | GW-02, GW-27 to GW-38, NEW-06, NEW-07, NEW-08, NEW-10 |
| **Total** | **48** | |

By status in v1.0.0:

| Status | IDs |
|---|---|
| Accepted risk | GW-01, GW-02, GW-03, GW-10, GW-11, GW-15, GW-16, GW-18, GW-22, GW-26 |
| Recommendation (open) | GW-08; the remaining part of GW-14 (forced TOTP enrolment for admins) |
| Mitigated (v1.0.0) | GW-04, GW-05, GW-06, GW-07, GW-09, GW-12, GW-13, GW-14 (partly), GW-17, GW-19, GW-20, GW-21, GW-23, GW-24 (residual noted), NEW-01 to NEW-10 |
| Mitigated (control in place and verified) | GW-25, GW-27 to GW-38 (GW-28 and GW-30 were also updated in v1.0.0) |

### 4.2 Feature notes

- **Inline MCP Apps** (`GET /api/apps/frame?sessionId=&ext=&uri=`): the gateway reads a `ui://` resource through
  the signed-in user's own Goose worker, for their own session, with the same controls as the standalone app frame
  (`APP_FRAME_CSP`, `X-Frame-Options: SAMEORIGIN`, `no-store`, `no-referrer`, iframe
  `sandbox="allow-scripts allow-forms allow-popups"`). The SPA uses only the `_meta.goose.mcpApp` data that Goose
  itself provides. Requests with a non-`ui://` URI or no session get 400. Other sessions or extensions get 404,
  and requests without sign-in get 401.
- **App tool calls** use Goose's `_goose/unstable/tools/call`. As far as we know, Goose itself allows this only in
  Auto mode (not verified for every Goose version). The gateway adds the NEW-01 target check and, for non-admins,
  the per-extension policy.
- **Desktop sync watcher**: it only calls `stat()` on the profile's `sessions.db` / `-wal`. It never opens or
  writes Goose files.
- **Device-code provider sign-in (Goose behaviour):** besides notifying the client, Goose opens the verification URL
  in a browser and copies the code to the clipboard **on the gateway host's interactive desktop session** (when
  there is one). This briefly exposes a short-lived device code on the host's console. The risk is low.

## 5. Residual risks and limitations

Risks that remain in v1.0.0:

- **Shared OS account (GW-01).** All workers run as one OS user. A tool that can read files, or a granted shell,
  reaches every profile and the admin's files. Much of the design follows from this.
- **Admins (GW-02).** An admin account is equivalent to the OS account. Protect it like one, with TOTP. The gateway
  does not yet force admins to enrol in TOTP at sign-in (GW-14).
- **Same-machine attacker (GW-15, GW-16, GW-17, GW-18).** Code running as the gateway account, or anyone who can
  read the profiles root, gets the database, the `secrets.yaml` files and worker secrets. The gateway cannot defend
  against the host itself.
- **Prompt injection (GW-03, GW-07, GW-08).** Untrusted content can steer the model. Approve mode, permission
  cards, the shell gate and the MCP App limits reduce the impact. They do not remove it. Tool behaviour itself
  (file reads by built-in tools) is outside the ACP firewall.
- **MCP Apps can reach the network.** The frame CSP allows `default-src *`, so an app can send data it receives to
  any host (GW-07).
- **Secrets at rest (GW-15, GW-16).** Goose writes `secrets.yaml` in plaintext. The gateway stores TOTP secrets,
  the LDAP bind password, OIDC client secrets and peer tokens in plaintext in SQLite.
- **Transport (GW-10, GW-11).** There is no TLS in the gateway. OIDC relies on TLS to the token endpoint (no JWKS
  signature check). LDAP can still be run in clear text if an admin explicitly sets `allowInsecure`.
- **API tokens have no scopes (GW-21).** A token can do everything its user can.
- **Supply chain (GW-24).** The build backend is not hash-pinned, and `requirements.lock` has to be regenerated by
  hand when dependencies change.
- **DoS (GW-22, GW-26).** The limits are per request and per session. Nothing caps the total number of workers or
  runs on a host, and others can trigger an account lockout.
- **Configuration mistakes.** A non-https OIDC issuer, multi-domain username collapsing on first sign-in (GW-12), a
  broad `trusted_proxies` (GW-25), `notify.allow_private_targets: true` (GW-20), broad `server.allowed_hosts`
  (NEW-04), or a firewall rule that lets clients bypass the reverse proxy.

Limits of this assessment:

- It is a source code review with automated scanning. It is not a penetration test, and there was no external
  audit.
- Goose itself, its extensions and MCP servers, LLM providers and the reverse proxy were not reviewed. Where a
  finding depends on Goose behaviour that was not verified, the row says so (GW-06, GW-08, GW-19, 4.2).
- The results apply to the v1.0.0 source. Later changes, or patched dependencies and vendored libraries, need a new
  review.

## 6. Deployment hardening checklist

1. Run the gateway as the normal Goose user, never elevated (installers, logon task RunLevel Limited, built-in
   guard). Keep `server.allow_elevated: false`.
2. Store the initial admin password that `goose-web init` printed (installer output, or
   `docker compose logs goose-web` on the first container start). Sign in and replace it before you widen
   `server.host`, the firewall or the published port. Alternatively, preset it with `--password-file` or `GOOSE_WEB_ADMIN_PASSWORD_FILE` (GW-09).
3. Put a TLS reverse proxy in front. Set `server.public_url: https://...` (Secure `__Host-` cookie, HSTS, origins,
   OIDC) and add only the proxy's address to `server.trusted_proxies` (GW-10, GW-25). Make the proxy **overwrite**
   `X-Forwarded-For` with the real client address instead of appending to a client-supplied chain.
4. Limit the gateway port in the host firewall to the proxy's IP (`register-service.ps1 -FirewallRemoteAddress`).
   Bind `server.host` to the interface the proxy uses. Do not use `0.0.0.0` unless the firewall covers every
   interface. VPN or overlay-network interfaces often have their own permissive firewall rules, and a wildcard bind
   would expose the gateway there without TLS. Do not add whole client ranges (for example VPN or CGNAT ranges) to
   the gateway's firewall rule either: those clients would bypass the proxy and its TLS. Send them through the proxy.
5. Keep the Host allow-list narrow. Add a name to `server.allowed_hosts` only if users really type it in the address
   bar. With `public_url` set, add any direct-access origin to `server.allowed_origins` only if you need it
   (NEW-04).
6. Turn on TOTP for every admin, then set "Require two-factor for administrators". Keep the admin count low (GW-02,
   GW-14).
7. Leave `allow_shell`, `config_edit`, `extensions_edit`, `providers_edit` and `notify_webhook` off for ordinary
   teams. Set `allowed_modes`, `allowed_providers`, `allowed_models` and `max_concurrent_runs` (GW-03, GW-08,
   GW-20). Keep `notify.allow_private_targets: false`. Since 1.5.0 a new team allows nothing until you allow it;
   keep Shell and raw config editing off for non-admin teams (section 7).
8. Reserved usernames (`appdata`, `workspace`, ...) are refused by the gateway (GW-04). Older builds did not refuse
   them.
9. Restrict the ACLs of the profiles root and the native profile folder to the gateway user, SYSTEM and
   Administrators (the Windows installer does this for the profiles root, GW-17).
10. LDAP: use `ldaps://` or `startTls`, set `caFile` for a private CA, use a least-privilege bind account, and leave
    `allowInsecure` off (GW-13).
11. OIDC: set `public_url`, use an `https://` issuer, register the exact redirect URI
    `<public_url>/api/auth/oidc/<id>/callback`, and set `stripDomain: false` unless the IdP has a single domain
    (GW-11, GW-12).
12. Herd peers are shown only to admins (GW-05). Use a peer token for an account whose agents admins may see.
13. Import MCP Apps and extensions only from trusted sources (GW-07, GW-08, NEW-01).
14. Logs rotate and the audit log keeps 365 days (GW-23). Back up `_system/` and the profiles, and protect the
    backups as well as the originals (GW-15).
15. Install from `requirements.lock` with `--require-hashes` (the installers and the Dockerfile do this). To update
    the goose CLI in the image, change `GOOSE_VERSION` together with `GOOSE_SHA256_AMD64`/`GOOSE_SHA256_ARM64` and
    rebuild (GW-24).
16. Set `host_tasks.enabled: false` if admins do not need the host task view (GW-35).
17. Docker: keep the compose hardening, publish only on `127.0.0.1` or behind the proxy, and set
    `GOOSE_WEB__SERVER__PUBLIC_URL` and a narrow `GOOSE_WEB__SERVER__TRUSTED_PROXIES` (GW-38, GW-25).
18. Run `goose-web check` after every change. It reports elevation, the config file, the goose binary and the port.

## 7. Example: LAN deployment behind a reverse proxy

A generic layout that follows the checklist. The gateway host is `192.168.1.10`, the reverse proxy is
`192.168.1.2`, and users open `https://goose.example.org`.

| Item | Setting |
|---|---|
| Gateway listener | `server.host: 192.168.1.10`, `server.port: 8710` (one interface, not `0.0.0.0`) |
| Who can connect | host firewall: inbound TCP 8710 from `192.168.1.2` only |
| TLS | terminated by the reverse proxy for `goose.example.org` |
| Gateway config | `server.public_url: https://goose.example.org`, `server.trusted_proxies: ["127.0.0.1", "::1", "192.168.1.2"]` |
| Service (Windows) | logon scheduled task as the Goose user, Interactive, RunLevel Limited, restart on failure (`scripts/register-service.ps1`) |
| Admin profile (Windows) | the existing Goose profile in `%APPDATA%\Block\goose`; `native_scheduler: auto`, so Goose Desktop and the gateway never both run its scheduler |

Windows installer command for this layout:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\install.ps1 -BindHost 192.168.1.10 `
  -PublicUrl https://goose.example.org -TrustedProxy 192.168.1.2 -FirewallRemoteAddress 192.168.1.2
```

Caddy example. Caddy proxies WebSockets. The timeouts are switched off so long agent runs are not cut, and
`X-Forwarded-For` is overwritten with the real client address:

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

Why this works: browsers reach the gateway only through the proxy, over HTTPS. The gateway accepts TCP only from the
proxy. Because only the proxy is trusted, the client IP used for rate limiting and audit is the one the proxy
reports, and no other host can forge it. `public_url` makes the cookies, the Origin checks, the Host allow-list and
the OIDC redirect URI all match `https://goose.example.org`.

Commands to check a Windows host:

```powershell
Get-NetFirewallRule -Name GooseWeb-Gateway-TCP-8710 | Get-NetFirewallAddressFilter   # RemoteAddress = the proxy
Get-ScheduledTask -TaskName GooseWeb_Gateway | Select-Object -ExpandProperty Principal  # Interactive / Limited
.\.venv\Scripts\python.exe -m goose_web check                                         # running as ... not elevated
```

## 7. Addendum: goose-web 1.5.0, team profiles with least privilege

This addendum lists the security-relevant changes of goose-web 1.5.0 and the known risk that remains. It is not a
new full review: the findings above keep their v1.0.0 status unless this section says otherwise.

### 7.1 Changes

| Change | Effect | Evidence (file: function) |
|---|---|---|
| Deny by default | An empty `allowed_modes`, `allowed_providers` or `allowed_models` now allows nothing; `"*"` (Any) allows everything. New teams start with every switch off and every list empty. A user without a team can sign in and read chats but cannot chat. Admins are not restricted. | `policy.py: DEFAULT_POLICY, allows, chat_block, effective_policy, check` |
| One team per user | The 1.4 rule merged several teams (switches OR-ed, lists unioned, an empty list made the result unrestricted), so a user got the most permissive combination. Now a user has one team (unique index), adding a user to a team moves them, and a directory sign-in sets the mapped team (the first match wins). | `db.py: set_user_team, _migrate_policy_model`; `api.py: admin_team, _team_from_body`; `auth.py: _upsert_external` |
| Chats checked against the current policy | A prompt in an older chat is refused when the chat's provider, model or mode is no longer allowed. `config/upsert` of `GOOSE_PROVIDER`, `GOOSE_MODEL`, `GOOSE_MODE` and `defaults/save` are checked against the lists. | `policy.py: check_session_choice, check, CONFIG_LIST_KEYS`; `hub.py` |
| Working-folder hints loophole closed | In 1.4 a member could place an `AGENTS.md` or `.goosehints` in a working folder, and Goose loaded it next to the team hints, which could override them. Isolated workers now run with `CONTEXT_FILE_NAMES=[".goose-web-hints.md"]` and load only the composed file, in which team hints come last and are marked final. Personal hints are included only when the team allows them. Non-admins cannot upload or create files with these names (`403 hint_file_refused`) or change `CONTEXT_FILE_NAMES`. The native (admin) profile is unchanged. | `workers.py: WorkerManager._env`; `profiles.py: hint_sections, compose_hints`; `api.py: _refuse_hint_name`; `policy.py: MANAGED_CONFIG_KEYS` |
| Folder roots | Non-admin roots are the workspace, the team folder and the team's extra folders. Extra folders and `share_folder` must be absolute paths; `*` is never a folder (`400 bad_folder`). | `policy.py: user_roots`; `api.py: _clean_policy`; `profiles.py: team_folder` |
| Upgrade migration | So that existing deployments behave as before, 1.4 teams are converted with their empty chat lists set to Any, and users in several teams keep the lowest team id (audited). Migrated teams are therefore as open as before until an admin narrows them. | `db.py: _migrate_policy_model` |

GW-03 (prompt injection): the row above says the default policy does not restrict modes. In 1.5.0 a new team allows no
modes until an admin chooses them; teams migrated from 1.4 keep Any until narrowed.

### 7.2 Known risk: one Windows account for all team profiles

Severity High, status Accepted risk (this extends GW-01).

- All isolated workers, of every team, run under the same Windows (OS) account as the gateway. Team policies, team
  folders and the hints rules are enforced by the gateway, over ACP and in the file endpoints. They are not Windows
  file permissions.
- If a team is given Shell (`allow_shell`), the `developer` extension or other command-running or stdio
  extensions, or raw config editing (`config_edit`), its members' agents can read and change other users' profiles
  (including chats and `secrets.yaml`), other teams' folders and the gateway's database on disk.
- Built-in tools that read files are not confined to the roots either (GW-08).

Mitigation: keep Shell and config editing off for non-admin teams (the team's Experience page warns when Shell is
on), share only credentials that every member may hold, and give teams that need a shell their own gateway under a
separate OS account or container. Separate Windows worker accounts per team were assessed separately and are not
built; they are possible future work.

### 7.3 Checklist additions

1. Back up the database before upgrading to 1.5.0. After the upgrade, open each team's Experience page and replace
   "Any" with explicit providers, models and approval modes where you can.
2. Switch off "Members may add personal hints" for teams whose hints must be authoritative, and check the result
   with Admin > Users > View effective hints.
3. Review the audit log for `team.migrate.membership` (memberships dropped by the upgrade) and
   `user.team.directory` (a directory user matched several teams).
4. Keep `allow_shell` and `config_edit` off for every non-admin team (7.2). On Windows, turn on `sandbox.enabled` as well (8.2).

## 8. Addendum: goose-web 1.5.1 - 1.7.0 (2026-11-08)

Scope: an independent review of the whole public repository before the 1.7.0 release - every commit reachable from
any ref and the working tree scanned for secrets and private data, `pip-audit`, the vendored front-end libraries,
bandit and semgrep, a manual review of everything changed since 1.5.0, and a regression pass over the surfaces of
sections 4 and 7 (282 tests passed).

### 8.1 Findings

| ID | Title | Severity | Status | Where | Notes |
|---|---|---|---|---|---|
| NEW-30 | Per-session MCP servers on `session/load`, `session/fork`, `session/resume` bypassed `allow_shell` | High | **Fixed in 1.7.0** | `policy.py: check` | Goose persists the `mcpServers` given on any of these four calls (it activates them for the session), and a stdio server is an arbitrary command run as the gateway's OS account. Up to 1.6.0 only `session/new` refused them for members without `allow_shell`. 1.7.0 applies the same rule to all four; members' `session/fork` `_meta` is reduced to `conversationBefore`. Tests: `test_per_session_mcp_servers_need_allow_shell_on_every_entry_point`, `test_fork_meta_reduced_to_cut_point_for_members`. **Upgrade if you have non-admin users.** |
| NEW-31 | `conversation/truncate` accepted `true` as `truncateFrom` | Low | Fixed in 1.7.0 | `hub.py: Upstream.from_client` | `true` is an integer in Python, so it meant "delete from time 1", i.e. the whole conversation of the caller's own chat. Now only a positive integer is accepted. Only the caller's own chats were reachable (each user has their own worker). The running-chat guard only knows runs started through this gateway; a run started by Goose Desktop or a schedule on the native profile is not seen. Truncates are now audited. |
| NEW-32 | `upgrade.ps1 -Ref` not validated | Low | Fixed in 1.7.0 | `scripts/upgrade.ps1` | An option-like value reached `git checkout`. Now: a plain name pattern, resolved with `git rev-parse --verify <ref>^{commit}` and checked out by commit id; quoted in `-Detached` mode. Operator input only. |
| NEW-33 | Upgrade backups contain full database copies | Info | Mitigated in 1.7.0 | `scripts/upgrade.ps1` | They hold password hashes, two-factor and directory secrets. They inherit the profiles root ACL (installing user, SYSTEM, Administrators); only the newest 10 are kept. |
| NEW-34 | Managed native hints | Info | Reviewed, no finding | `profiles.py`, `api.py: me_hints`, `__main__.py: cmd_native_hints` | Only admins can have the native profile (API and directory sign-in cannot create or demote one). Managed mode is switched on locally (`goose-web native-hints`), not over the network; the composed text goes only into that admin's native `.goosehints`. |
| NEW-35 | Edit / Branch (1.6.0) | Info | Reviewed, no finding | `transcript.js`, `chatsession.js`, `hub.py`, `policy.py` | The editor uses text nodes and `textarea.value` only (no HTML). Truncate/fork act on the caller's own worker; cross-profile calls (admin `?profile=`) are admin-only and audited. |

Supply chain: `pip-audit -r requirements.lock --require-hashes`: no known vulnerabilities. Vendored files (all covered
by `SHA256SUMS` and a test): DOMPurify 3.4.17, marked 15.0.12 (no known CVE; an older major line, a move to the
current major is planned), highlight.js 11.12.0, qrcode-generator 1.4.4. Secrets scan: no keys, tokens, private keys,
private addresses or internal names in any commit or file; detect-secrets hits are test fixtures and the
common-password list. `.gitignore` also excludes `config.yaml`, `DEPLOYED.json`, `*.log`, `.env`, `*.sqlite`.

### 8.2 One OS account for all profiles (7.2): sandbox in 1.8.0

1.8.0 adds an optional, OS-enforced boundary for 7.2 on Windows (`sandbox.enabled`, ADMINISTRATION 11.6): each
isolated non-admin user's worker and everything it starts run in the user's own AppContainer, with file access only to
that user's profile, the team folder and the team's extra folders. The gateway talks to the worker over inherited
stdin/stdout pipes, so the container needs no network listener and no loopback exemption, and loopback stays closed
(local services such as a browser's debugging port or a local model proxy are unreachable from it). Design choices:

- Per **user**, not per team: members of one team cannot read each other's profiles (chats, `secrets.yaml`), while
  the team folder and extra folders are granted to every member.
- A loopback exemption per container (`CheckNetIsolation LoopbackExempt`) was rejected: it is a developer setting,
  opens all of 127.0.0.1 to the container, is commonly reset by policy, and persistent exemptions cover outbound
  loopback only.
- The grant records live in `<system_dir>/sandbox/`, outside every container.

Verified: a sandboxed user's agent read and wrote its approved folders; got "Access is denied" for another team's
folder, the gateway's configuration and database folder, the administrator's native profile and other files of the
account; could not connect to 127.0.0.1; could reach the internet (`network: internet`); after the user was removed no
container ACE was left. `tests/test_sandbox.py` runs the kernel check on every Windows CI run.

Still accepted: administrators and the native profile run unsandboxed (they are trusted); without `sandbox.enabled`,
or on Linux/macOS, 7.2 applies unchanged; SMB shares cannot be restricted per container; system folders readable by
all Windows apps stay readable.

### 8.3 1.10.0: relays and Goose 1.50

- **Relays** (`sandbox.relays`): a sandboxed agent reaches an allow-listed local service only through a forwarder in
  its own container and a named pipe whose DACL admits that container's SID (plus SYSTEM and the gateway's account)
  with a low mandatory label. Verified: the user's agent reached the listed service through its forwarder; direct
  127.0.0.1 to the same service, the gateway's port and another user's forwarder address were refused; another
  container could not open the pipe. Anything the relayed service accepts is reachable by every sandboxed user, so
  list only services meant for them (for example a model proxy) and keep their own authentication.
- **Goose 1.50.x `tools/call`** ignores `extensionName` (fixed in Goose 1.51) and resolves a tool by name across the chat, so a policy that
  allows direct calls for one extension could reach another extension's tool. The gateway now checks every direct
  tool call against `tools/list` of the named extension and refuses a mismatch (on all Goose versions).

### 8.4 1.11.0: built-in HTTPS, activity log, log budget

- **Built-in HTTPS** (`server.tls`, default `auto` = on unless a public URL / proxy is configured): a local CA
  (EC P-256, 10 years, `pathlen 0`) signs a 90-day server certificate for the machine's own names and addresses; it is
  renewed automatically and hot-loaded. The CA key stays in `<system_dir>/tls/` (same protection as the database);
  whoever can read it can mint certificates trusted by clients that imported the CA - accepted, the same people can
  already read every session. Clients must verify the CA fingerprint when importing it. HSTS is not sent for the
  built-in certificate. Verified by `tests/test_tls_logs.py` (a real gateway over HTTPS: localhost and 127.0.0.1 verify
  against the CA, `__Host-gw` cookie `Secure`, plain HTTP refused, renewal hot reload).
- **User activity** is attributable: every audit event and everyday chat action (open, new, prompt length, cancel,
  fork, mode) and every browser connection carries the user and the real client address (trusted proxies only), in
  the database and in `activity.jsonl`. Prompt text is never logged.
- **Log budget**: logs cannot fill the disk (`logs.max_disk_percent`, 0.5 %); the audit table is capped by age and
  rows.

## 9. Addendum: independent assessment of 1.11.0 (2026-11-09), fixed in 1.12.0

Four parallel adversarial reviews of 1.11.0 (web and sign-in; agent firewall, hub and profiles; Windows sandbox,
relays, TLS, log janitor and install scripts; browser front end), each proving findings with working attacks against
throwaway gateways. Everything below is fixed in 1.12.0 with regression tests (`tests/test_sec_web.py`,
`test_sec_agent.py`, `test_sec_os.py`, `test_frontend_modules.py`), and every attack was re-run against the fixed code.

| ID | Severity | Finding | Fix |
|---|---|---|---|
| B-1 | **Critical** | A member with every permission off ran any command at chat creation: `session/new` with `_meta.recipeDeeplink` started the recipe's extensions (stdio commands, `developer`). Also via `session/import` (crafted extension state), `schedules/create` with an inline recipe, and summon sub-recipes. | Member `_meta` is allow-listed; the gateway resolves every recipe (deeplink, id, schedule, import) and refuses extensions, sub-recipes and checks the member may not use; imports keep only harmless bundled extensions. |
| B-2/B-3 | High | The model (or a direct tool call with `apps`) re-enabled the disabled `developer` through `extensionmanager`. | Command-capable extensions (incl. `summon`, `scheduler`) are pinned off without `allow_shell`; `extensionmanager` needs `extensions_edit` + `allow_shell`; tool calls to guarded extensions are refused. |
| C-1 | High | Any local process could create a relay's named pipe first and read prompts / forge model answers. | Random pipe name per start, first-instance flag, forwarder verifies the server process. |
| C-2 | High | Sandboxed workers inherited the gateway account's environment (API keys). | The environment is built from an allow-list. |
| C-3 | High | The provisioning record sat in the user's writable profile; its ids drove deletes outside the profile. | Record moved to `<system_dir>/manifests/`; every delete is id-checked and confined, never through links. |
| C-4 | High | `install.ps1` left the install folder writable by every local user (code that runs as the gateway account). | install/upgrade lock the folder down; `goose-web check` flags it. |
| A-1/A-2 | High/Medium | Request bodies were read fully before the size check (memory exhaustion without signing in; chunked uploads past `max_upload_mb`). | A streaming body-limit middleware (413). |
| A-6 / C-9 | High | The local CA could sign certificates for any domain, and an admin could download `ca.key` through the file browser. | The CA carries name constraints (this machine's names, loopback and private ranges; 1.11 CAs are replaced: clients must import the new CA once); key files are owner-only; the file API refuses `system_dir` for everyone. |
| A-3 | Medium | Anyone could lock any account; the lock answer revealed user names and blocked the owner's address. | Locked accounts answer like a wrong password; only the correct password learns about the lock and does not count against the address. |
| A-4/A-5 | Medium | OIDC sign-in was not tied to the browser (login CSRF), and unbound accounts could be claimed by user name. | Browser-bound state cookie; binding only by verified e-mail; `stripDomain` default off. |
| C-5 | Medium | `jo.ann` and `joann` shared one AppContainer. | Container names include a hash of the exact user name; old containers are migrated. |
| C-6 | Medium | A sparse "500 GB" log made the log janitor delete other logs. | Allocated size, per-owner budget. |
| C-7 | Medium | Detached agent processes survived a worker stop. | One kill-on-close job per worker. |
| D-1/D-2 | Medium | Model output could draw full-screen fake dialogs with the app's CSS classes; "Copy code" copied hidden text. | Sanitizer drops classes/ids/styles; markdown is contained; code blocks are reset to their plain text. |
| A-7..A-14, B-4, C-8, C-10..C-12, D-3..D-10 | Low/Info | Forwarded-address parsing, admin two-factor not enforced, user-name timing, silent config fallback, secrets kept across endpoint changes, TLS file checks, error text, logout CSRF, janitor and junctions, audit of runtime extension starts, login error text, app-bridge confirmations, protocol-relative images, storage after sign-out, unattributed permission cards, dangerous team folders. | See CHANGELOG 1.12.0. |

Still accepted: administrators and the native profile are trusted and unsandboxed; without the sandbox (Linux, or
`sandbox.enabled: false`) every member's agent runs as the gateway's account, so `allow_shell: false` is only backed
by an OS boundary when the sandbox is on; a member with `allow_shell` can run anything inside their sandbox;
read-only extensions (`analyze`, `summarize`, `chatrecall`) can read what the worker can read (the sandbox limits it).

## 10. Addendum: Goose plugins in a chat folder (2026-11-10), fixed in 1.13.1

| ID | Finding | Severity | Status | Where | Notes |
|---|---|---|---|---|---|
| NEW-36 | Goose auto-loads plugins from `<cwd>/.agents/plugins`: a member without `allow_shell` ran commands | High | **Fixed in 1.13.1** | `policy.py: check`, `project_plugins`, `has_agents_component`; `api.py: _refuse_agents_dir` (`fs_mkdir`, `fs_upload`) | Goose 1.50-1.57 treats every folder under `<cwd>/.agents/plugins` of a new chat as an enabled plugin (`plugins/discovery.rs`; unknown plugins are added to config as enabled) and starts its MCP servers (`.mcp.json` or the plugin manifest: any command line) during `session/new` (`acp/server.rs: initial_session_extensions`). No Goose setting or environment variable turns discovery off. A member with every permission off created `.agents/plugins/x/.mcp.json` with the file browser in their workspace or the team folder, started a chat there, and the command ran in their sandbox (measured on Goose 1.50.0 and 1.57.0, sandbox on). In the team folder it would run in every member's worker that opens a chat there, and unsandboxed in an administrator's native worker. Now: non-admins cannot create or upload into any `.agents` folder through the file browser (any case, trailing dots/spaces, NTFS stream names, 8.3 short names via the resolved path; `403 agents_folder_refused`), and a member without `allow_shell` cannot start a chat in a folder whose `.agents/plugins` has a plugin folder (an unreadable one counts). Correction (security review 2026-11-11, section 12): until 1.15.1 Goose's own `sources/create` (skills_edit) could still write `.agents/skills` and `.agents/agents` into the team folder (SD-3), and a plugin in a team folder ran in the chats of members WITH `allow_shell` and of administrators (SD-2); both are closed in 1.15.1. Goose rediscovers plugins only on `session/new`; `session/load`, `fork`, `resume` and working-folder changes do not, and recipe chats skip plugins. Plugin hooks and scheduled jobs use the worker's own folder (the profile root), which members cannot reach through the file API. Correction (1.27.1, 23.13): the sandboxed backends already started a member's worker in the member's workspace, and since 1.27.1 every member worker does; the same rule as for `session/new` now applies to that folder (`workers.start_dir`: a workspace with plugins is the start folder only with `allow_shell`, otherwise the worker starts in the profile root). Tests: `tests/test_agents_plugins.py`, `tests/test_scheduled_runs.py`. **Upgrade if you have non-admin users.** |

Still accepted: members with `allow_shell` can create `.agents` folders with their shell (they can run commands
anyway). Plugin `skills` folders are still read as instructions where the folder already exists. Since 1.15.1 (SD-2)
a member cannot start a chat in a shared folder (team folder, team extra folders) that holds plugins, whatever
their permissions - plugins run only in the member's own workspace and only with `allow_shell` - and an
administrator starting a chat in a member-writable folder with plugins must confirm the exact plugin list first
(audited `chat.plugins_allowed`); a confirmed admin chat runs them unsandboxed, as Goose Desktop would.

## 11. Addendum: prompt guard (2026-11-10), 1.14.0

Spec 018 adds an optional, per-team **prompt guard** (ADMINISTRATION 9.10, ARCHITECTURE 12.11) that narrows GW-08
("untrusted content can steer the model"):

- **Deterministic rules on tool-call arguments** (for example *Splunk read-only*, *Destructive shell*) enforced by the
  gateway at `session/request_permission`: a matching call is answered `reject_once` by the gateway, whatever the
  user, the model or injected content asked for. **Classifier** (Llama Prompt Guard 2 22M, local CPU) on what guarded
  users type and on free-text tool arguments.
- **Closing the gaps the guard depends on:** for guarded teams Auto and Smart approve are not allowed, stored *always
  allow* tool permissions are removed and cannot be set again through Goose Web, and *always allow* answers are
  downgraded - so Goose asks before every tool call. Correction (section 12, SA-1): before 1.15.1 the removal ran only
  at re-provisioning and the agent could write the entry into its own `permission.yaml`; since 1.15.1 every worker
  start re-provisions the profile, tool arguments naming the profile's config files are refused, and a tool call
  that runs without a permission request cancels the run (`guard.bypass`) (Goose 1.50 and 1.57: `permission_inspector.rs`, Approve asks unless the tool has a user
  `always_allow`). Guarded auto approves passing calls in the gateway instead.
- **Fail open by design** for the classifier (rules still apply); `guard.unavailable` is audited and admins see a
  banner. `guard.blocked` never records content.
- **Residual risk:** tool results (web pages, search results) are not inspected - an injection can still steer the
  model, but a guarded tool call must still pass the rules; classifiers can be evaded; scheduled runs, sub-agents and
  recipe checks started through shell extensions are not guarded; administrators' existing *always allow* tools are
  not guarded; the 22M model is weak on non-English text. New dependencies (onnxruntime, tokenizers and their
  dependencies, numpy < 2.5) are hash-locked; the model package is installed only with a verified SHA-256 and its
  zip is extracted with a fixed file list (no paths). Since 1.14.2 the package is downloaded from this project's
  GitHub release `prompt-guard-2-22m-onnx-1` (https only, size-capped, SHA-256 pinned in the code): a changed or
  replaced asset is refused, so trust rests on the pinned hash, not on the release page. Correction (section 12,
  SB-3): before 1.15.1 only the final address had to be https; since 1.15.1 every redirect is checked (https, at
  most 5, GitHub download hosts only for the pinned source).
- **Not covered in 1.14.0 (section 12):** rule matching ran on the gateway's event loop without a time limit, and the
  shipped patterns backtracked quadratically, so one long tool argument or prompt (from a member or from injected
  content) could stall every user (SA-2); admin regexes were only compiled. The shipped rule sets are best-effort
  deny lists: they stop common forms, not every way a shell can say the same thing (SA-5).

## 12. Addendum: security review of 1.12.0 - 1.15.0 (2026-11-11), fixed in 1.15.1

Four adversarial reviews (prompt guard; supply chain and model install; live state and queue; files, plugins and
admin) of every change since section 9, each finding proven with a PoC on a throwaway gateway. 33 findings after
de-duplication. Every fix was re-attacked on a throwaway gateway with Goose 1.57.0 and the real Prompt Guard 2 22M.

| ID | Finding | Severity | Status |
|---|---|---|---|
| SA-1 | The agent writes `always_allow` into its own `permission.yaml` (or rewrites `config.yaml`); after the next worker start Goose stops asking, so the guard never sees the tool | High | **Fixed**: every worker start re-provisions an isolated profile (policy, extensions, mode, `always_allow`); built-in rule `guard-self-protect` refuses tool arguments naming the profile's config files; a guarded tool call that runs without a permission request cancels the run, is audited `guard.bypass`, and restarts an isolated worker. Re-test: write refused; tampered file reset at restart; live bypass on Goose 1.57 cancelled. |
| SA-2, SD-1, SA-11 | Rule-engine ReDoS on the event loop (one 60 KB argument froze the gateway 6.3 s; 200 KB: 43-307 s per shipped regex); admin regexes unchecked; Test box on the loop | High | **Fixed**: rules run in child processes (`rulematch.py`) with a deadline (`guard.rules_timeout_ms`, 1500); timeout = blocked; shipped gaps bounded (whole default set < 1.1 s on 200 KB adversarial text); nested quantifiers refused at save; Test box uses the same path, 503 without a guard. Re-test: /healthz max 0.06 s (was 6.3 s). |
| SA-3 | A guarded 16 MB prompt was tokenised whole (gateway frozen 18 s) and never classified | Medium | **Fixed**: refused before any tokenising above `guard.max_input_chars` (16,000); `guard.unavailable` names user and chat. Re-test: refused in 0.4 s, /healthz 0.008 s. |
| SA-4 | The classifier skipped the middle of long texts | Medium | **Fixed**: every window scored (`max_windows` 48); longer = not inspected: prompts refused, tool calls never auto-allowed (`guard.not_inspected`). Re-test: mid-text injection blocked (was 0.0014). |
| SA-5 | 17 evasions of the shipped rules | Medium | **Fixed for the listed evasions** (flag order, quoting, PowerShell prefixes, `rd/del /s`, .NET deletes, `+ref`/`:ref` pushes, `-enc`, `summaryindex`, `dump`, `dbxquery` writes, `fit into`, Splunk REST from a shell, more tool-name globs); unmodified built-ins upgrade automatically. Rules remain best-effort deny lists. |
| SA-6 | System prompt, saved prompts, recipes, imported chats not checked | Low | **Fixed** for guarded users (checked like a prompt); attachments other than text are not classified. |
| SA-7 | MCP Apps `tools/call` not guarded by the gateway | Low | **Fixed** (tool check of caller and owner). |
| SA-8 | Trusted extension by name only; guard context failed open on errors | Low | **Fixed** (config-entry fingerprint, colliding names refused, last good context or fail closed). |
| SA-9, SA-10 | Rule ids shown to members; audit gaps | Info | **Fixed** (members see the rule's message only; 10 blocks in 10 min = refused for the window, `guard.burst`; `chat.prompt` after the guard). |
| SB-1 | Model folder installed with an owner-only DACL (Python >= 3.12.4): a `-RunAs` service account cannot read it | Medium | **Fixed** (permissions reset to inherit; `--if-missing` repairs; `check`/`guard status` report it). |
| SB-2, SB-3, SB-4, SB-5, SB-9 | `model_dir` unchecked; redirect hops; size-only integrity; ONNX telemetry; no rollback | Low/Info | **Fixed**. |
| SB-6, SB-7 | Export toolchain unpinned; very fresh / unused transitive dependencies | Info | **Accepted / documented**: the published package is SHA-pinned; next lock refresh with a 7-day `--exclude-newer` cool-down. |
| SB-8 (C-4) | Install and repo folders Modify for Authenticated Users on the maintainer's host | High | **Accepted by the operator** (operational, not code); `goose-web check` reports it. |
| SC-1, SC-6, SC-8 | An administrator viewing a member's chat auto-sent the member's queued text as the administrator (member's guard bypassed) | Medium | **Fixed**: only the owner's tab sends its own items automatically (server-enforced); text into a profile always passes the owner's guard; non-owner take/remove audited; rows show who queued them. Re-test: automatic take refused; manual send blocked by the member's guard. |
| SC-2, SC-4, SC-9 | Queue DoS (whole queue re-serialised and written on the loop per change, 36 GB per profile, full queues in every hello) | Medium | **Fixed**: 32 MB per profile, 20 chats, 10 pending steers; writes in a background thread; tabs get rows, not content. Re-test: other member's round trip 0.35 s (was 8.85 s), hello 4 KB. |
| SC-3 | An open socket survived user deletion and re-created the user's state for a new same-name account | Medium | **Fixed**: delete/disable/reset/token revoke close the user's sockets at once, others re-validate every 30 s; a deleted user's state never writes again; a new account starts clean. |
| SC-5, SC-7 | Drafts keyed by chat id only; queued text kept in plaintext and forever | Low | **Fixed** (drafts per user and profile, 7 days, cleared on expiry; `secure_delete`, 7-day queue expiry, rows of chats deleted elsewhere pruned). DB backups made by deploy scripts contain queued messages: keep them as private as the database. |
| SD-2 | A plugin in a team folder ran in another member's chat (allow_shell) and unsandboxed for admins | Medium | **Fixed** (see section 10). Re-test: member refused (also with trailing spaces / `\.`); admin needs the confirmed list. |
| SD-3, SD-5, SD-6 | `sources/create` into the team folder; raw cwd; hint name with `:stream` | Low/Info | **Fixed**. |
| SD-4 | Inaccurate statements in sections 10 and 11 | Info | **Fixed** (corrections above). |

Residual risks: rules and classifier remain best effort (a shell can express a command in ways no deny list
covers); the bypass detector notices a tool that ran without asking after it started; the native administrator
profile is never rewritten (its chats are cancelled instead while the admin guard is on); a guarded member who
keeps both rule matchers busy can make other guarded users' checks time out (blocked, never allowed) until the
burst limit stops them; queued messages are still plaintext in the database.

## 13. Addendum: MXC sandbox backend (2026-11-12), 1.19.0

Since 1.19.0 isolated non-admin members' agents run in **Microsoft Execution Containers** (MXC) by default;
the AppContainer backend of section 8.2 stays selectable (`sandbox.backend: appcontainer`). Administrators and the
native profile stay unsandboxed (GW-01 unchanged: one OS account).

### 13.1 What changed compared with the AppContainer backend

| Aspect | AppContainer (1.8.0 - 1.18) | MXC (1.19.0) |
|---|---|---|
| Containment | Goose Web's own code: `CreateAppContainerProfile`, capabilities, ACL grants with icacls, grant/revoke state in `<system_dir>/sandbox` | OS policy (process containers, PSEC) driven by Microsoft's `wxc-exec.exe`; no ACL is changed, nothing to revoke; a new container (and SID) per start |
| Files | Modify/Read&execute ACEs on granted folders | read/write and read-only paths in the policy; Goose Web refuses grants of its own system folder, the profiles root, other profiles, the native profile, its code (write) and drive roots, also through junctions and 8.3 names |
| File and folder names | not listable outside grants | listable (names only, no contents) on the drives of granted folders (`enumeratePaths`; node and cmd need it) - **accepted (Q2)**. Until 1.21.0 this row said "folder names"; file names are listed too |
| Network | capabilities: `internetClient` (+ `privateNetworkClientServer`), any protocol; loopback closed; relays through an in-container forwarder and a named pipe; provider URLs rewritten | no own network; one loopback endpoint, the member's **egress proxy** in the gateway, which decides every destination and audits it; **HTTP/HTTPS only** - **accepted (Q1)**; provider URLs unchanged |
| UI | AppContainer defaults | clipboard, input injection, desktop/system-settings control and IME blocked (Win32k on) |
| Process | suspended start in the gateway's kill-on-close job | `wxc-exec` suspended, joined to the gateway's and the worker's kill-on-close jobs, then resumed |
| Supply chain | none (Windows API) | pinned `wxc-exec.exe` 1.0.1 (npm sha512 integrity, file SHA-256, Microsoft Authenticode), re-hashed before every launch through a write-denied handle |
| Telemetry | none | request contract 1.0.0, telemetry opt-in, never opted in - **accepted (Q3)**; a later contract with required telemetry may be adopted later |
| Requirements | Windows 10/11, Server 2019+ | Windows build 26100.9278+; otherwise fail closed or the AppContainer fallback |

### 13.2 Threat model (MXC specific)

| Threat | Mitigation |
|---|---|
| A member's agent reads or writes another member's profile, the database, keys, logs or the native profile | Not in the policy; such grants are refused even when configured (junction-aware); kernel-enforced by MXC. E2E test: outside file `PermissionError`, also from a child process. |
| The agent changes the code the gateway runs or the executor | Never granted for writing (Goose Web's code, its venv and base Python, the goose CLI folder, the MXC folder - in any path spelling, 1.19.1); every pinned file's SHA-256 is checked before every launch and write-locked until it runs. The install folder's ACL is not changed by Goose Web (SB-8: on the reference box Authenticated Users may modify it - accepted by the owner). |
| A tampered or substituted `wxc-exec.exe`, or a DLL planted next to it | Never executed: pin (integrity, SHA-256, size, signer) at install; at every launch and probe (1.19.1) every pinned file hashed through a write-denied handle held until the process runs, the version folder must hold nothing but the pinned files and `install.json` (checked before the start and again while the executor is suspended), and the executor is created with PreferSystem32Images + MicrosoftSignedOnly + NoRemoteImages, so a planted `userenv.dll` and the like is not loaded; signature at start; mismatch = fail closed. Unit and e2e tests. |
| A member's agent reaches local services (browser debugging port, other workers, the gateway, a database on loopback or on this machine's LAN address) | The container reaches only its proxy; the proxy refuses loopback except `sandbox.relays`, every address of this machine, link-local/metadata, and names resolving to them; the resolved address is the one connected to. Relays on the gateway's or a proxy's own port are ignored. E2E: direct loopback blocked, another loopback port through the proxy 403. |
| Another local process or member uses a member's proxy | 127.0.0.1 only, random port, per-member credential (HTTP Basic, constant-time compare, new per worker start); other containers can only reach their own proxy. A local process of the gateway's account could read the policy file (as it could read the database): GW-01. |
| Request smuggling / host switching through a kept-alive connection | Plain HTTP is forwarded as one request with `Connection: close`; `Proxy-*` and hop-by-hop headers removed; CONNECT tunnels go to the vetted address only. |
| Proxy exhaustion | Per-member connection limit (503), header size (16 KB) and time (30 s) limits, idle timeout, connect timeout; the proxy runs on the gateway's event loop without blocking calls. Since 1.19.1 name lookups run in the proxies' own 4-thread pool (never the gateway's default executor, which sign-in, MFA and provisioning use), at most 2 per member in flight (503), 5 s each, 30 s negative cache, single-label and `.local` names refused unlooked-up (MX-2); the activity log gets at most 30 egress lines per member and minute plus one summary (MX-4). |
| Data exfiltration over the allowed internet | Same as before (a member allowed `internet` can send data out); now every destination is in the activity log (`sandbox.egress`, host:port and decision, never content). |
| A member's agent starts unsandboxed because MXC is unavailable | Never: fail closed with an admin-visible reason; the only alternative is the explicit, audited AppContainer fallback. |
| Secrets in logs | The policy (with the proxy credential) stays in the gateway's system folder and is deleted at stop; logs and audit show the proxy as `127.0.0.1:<port>` only; egress audit has no paths or headers; the worker environment is the allow-list of section 8.2 (no gateway secrets). |

### 13.3 Residual risks

- GW-01 (one OS account) is unchanged; MXC is an AppContainer-class boundary inside that account.
- MXC is young (GA 2026-10-07); the executor is documented by Microsoft for testing or when the SDK cannot be
  embedded. Pinned and re-verified; a new version is a new pin after review.
- The names of files and folders on the drives of granted folders are visible to members' agents (Q2). Measured in
  an MXC container on 2026-11-13: the names in the gateway account's home folder (for example in Documents, and of
  its Goose skills) can be listed; reading any of those files is refused.
- Programs inside the container that send requests without the proxy credential are refused (407); Windows'
  certificate-revocation lookups are among them (HTTPS still works).
- Learning mode / denial capture is not used (it fails on the tested build).
- **A relay forwards everything** the relayed service exposes on its `host:port` (MX-13): every path and, behind a
  local reverse proxy, every virtual host (the agent chooses the `Host` header and the TLS name). The proxy filters
  by destination, not by URL. Relay only services every sandboxed member may use in full.
- **MXC grants are path policy** (MX-3): a hard link that already exists in a member's read/write folders reaches a
  file outside them. Contained processes cannot create hard links or junctions, so such links come from outside MXC
  (an agent on the AppContainer backend/fallback, or the host). Since 1.19.1 a bounded scan (5 s / 200,000 entries,
  per set of folders, again after any AppContainer run) refuses the MXC start when a file has a name outside the
  read/write folders; a scan that hits its bound lets the start go ahead (logged) and runs again at the next start -
  accepted, as is a link planted by the host between the scan and the start.
- **DLL planting next to the executor** (MX-8): the folder content check runs before the start and while the
  executor is suspended; a file planted in the moment between that check and the loader's search is not loaded for
  System32 DLLs (PreferSystem32Images, MicrosoftSignedOnly). Whoever can write the install folder can also edit
  `goose_web\*.py` (SB-8, accepted).

### 13.4 Security review 2026-11-12 (MXC, 1.19.0) - fixed in 1.19.1

Independent adversarial review of the 1.19.0 MXC code with a real executor (0 Critical, 0 High, 2 Medium, 6 Low,
6 Info); the review record and its PoCs are kept with the project's records. Regression tests:
`tests/test_mxc_review_fixes.py` (one or more per finding) and `tests/test_mxc_e2e.py`.

| ID | Sev | Finding | Fix in 1.19.1 |
|---|---|---|---|
| MX-1 | Medium | Own-address check compared strings: an upper-case or uncompressed IPv6 literal of this machine passed (`internet+lan` members reached SSH/SMB/RDP) | Every candidate parsed with `ipaddress` (scope dropped, IPv4-mapped unwrapped; IPv4-compatible, NAT64, 6to4 and Teredo embeddings checked too) and compared with the parsed own addresses; the checked, normalised address is connected |
| MX-2 | Medium | Lookups in the gateway's default executor: one member's slow names stalled sign-in, MFA, provisioning (~9 s) | Own 4-thread resolver pool, 2 lookups per member in flight (503), 5 s per lookup, 30 s negative cache, shared in-flight lookups, single-label and `.local` names refused (unless a relay target) |
| MX-3 | Low | Pre-existing hard links reach files outside the grants (path policy) | Bounded scan before an MXC start; a link to a name outside the read/write folders refuses the start (fail closed, admin-visible, audited); see 13.3 |
| MX-4 | Low | ~780 `sandbox.egress` lines/s from one member could rotate the activity log in minutes | Per member: 30 decisions a minute verbatim, the rest as one summary line (counts per destination); same for `gateway.log` |
| MX-5 | Low | A CONNECT target with LF forged a `gateway.log` line | Method, version and target validated (400); host names must be valid; every member- or container-controlled string passes `activity.clean_text` (control characters escaped, length capped) before gateway.log, the activity log, the audit and an admin's last-error text |
| MX-6 | Low | `\\?\` and UNC forms of the system folder / another profile passed the grant filter; base Python and goose folder writable | Canonical paths (`\\?\`, `/`, case, trailing dots/spaces, 8.3, junctions), UNC and device paths refused; base Python, venv and goose CLI folder never writable; `sandbox.read_dirs` checked the same way for both backends and listed by `sandbox status` / `check` |
| MX-7 | Low | A `sandbox.enabled` typo turned the sandbox off (fail open) | Only `auto`, `true/false`, `yes/no`, `on/off`, `1/0` (not set = `auto`); anything else counts as on and is a configuration problem: members' agents do not start |
| MX-8 | Low | Pin did not cover DLLs loaded from the executor's folder; `--probe` ran unpinned | All pinned files hashed through held write-denied handles, exact folder content checked twice, image-load mitigations, probe through the same path; install-folder ACLs left as they are (SB-8) |
| MX-9 | Info | Failing to join a kill-on-close job was only a warning | The executor is ended and the start fails |
| MX-10 | Info | The proxy credential lived on after the worker | Revoked when the worker stops or crashes, new at every start; the proxy is closed when the user is deleted or no longer sandboxed |
| MX-11 | Info | `fec0::/10`, Azure WireServer, 6to4 classified as public/LAN | Refused: site-local, 6to4, Teredo, local-use NAT64, IPv4-compatible, `0.0.0.0/8`; metadata adds `168.63.129.16`, `169.254.170.2`, `192.0.0.192` (`100.100.100.200`, `fd00:ec2::254` already) |
| MX-12 | Info | A > 63-character label dropped the connection without an answer | 400 with a reason, no lookup |
| MX-13 | Info | A relay is a whole host:port (virtual hosts) | Documented (13.3, ADMINISTRATION 11.6) |
| MX-14 | Info | Docstring/comment drift, dead `redacted()`, container text as admin last error | Wording fixed, `redacted()` removed, `explain_exit` output cleaned (MX-5) |

## 14. Addendum: Goose-native security (2026-11-12), 1.20.0

Scope: `goosesec.py`, `classifyapi.py` and their hooks in `profiles.py`, `workers.py`, `context.py`, `app.py`,
`policy.py`, `api.py`, `__main__.py` (spec 026). Goose's own detection and reviewer are Goose's code and out of scope,
except for how they behave: that was read in the source of Goose 1.57.0 and 1.59.0 (the security modules are identical
in both) and measured with the real 1.57.0 binary (`tests/test_goosesec_e2e.py`). This section is the design's threat
model. It is not an independent review.

### 14.1 What it adds, and what it does not

It adds a control that follows the agent instead of the gateway: Goose's pattern check of shell commands, with an
approval request also in Auto mode, in every profile and every front end; optionally Goose's reviewer (adversary
mode). It does not make Goose's detection stronger than it is:

- only the tool named `shell` is inspected;
- the classifier sees user messages, not commands or tool results, and can only raise a pattern finding. Text an
  agent reads from a web page or a file, the usual carrier of an injection, is not scored by this layer;
- an unattended run in Auto mode allows a flagged command and logs it;
- every failure of the classifier or the reviewer allows the call (Goose's design).

It is a safeguard against known dangerous commands, not a guarantee. The sandbox (section 13), the policy firewall
and the prompt guard of section 11 remain the controls that do not depend on the model's cooperation.

### 14.2 Threat model

| Threat | Control |
|---|---|
| The endpoint is reached from the network | Bound to `127.0.0.1` only, on its own port; not a route of the web application |
| Another program on the computer uses the classifier (CPU) or probes it | Bearer token per profile (HMAC-SHA256 of the user id, key only in the database, constant-time check, disabled users refused within 15 s); rate limit per profile; body cap; uniform `401`. The work is bounded, not only the requests: the endpoint has its own classifier thread, at most 8 pieces queued or running in total and 3 per profile, more is refused before it is queued, and a piece that has not started at the deadline is dropped (14.4, E-1) |
| A token is stolen | It authorises classification only: no chat, file, setting or account is reachable with it. *Replace all tokens* invalidates every token at once |
| A member, or an agent that was talked into it, switches the detection off | Written before every start of the agent; also in the worker's environment, which Goose ranks above its files (measured), for the MXC and the AppContainer backend; `config/upsert` and `config/remove` of `SECURITY_*` refused by the firewall; other `SECURITY_*` keys removed from the member's `config.yaml` at every start; `adversary.md` is a refused file name and is rewritten at every start; a link or a folder in its place fails the start (fail closed) and is audited (`goosesec.profile`). Limit: see 14.3, "adversary.md between starts" |
| A sandboxed agent uses the endpoint to reach the gateway | The relay target is the classifier port only; the web application's port is not reachable from the sandbox, as before |
| Chat text leaks through the endpoint | Nothing is logged or audited; the cache holds a SHA-256 of the text and a score; requests stay on the loopback interface |
| The gateway points Goose at a port someone else holds | A profile gets the endpoint only while the gateway itself holds the socket (exclusive bind on Windows); otherwise the classifier is switched off in the plan |
| The feature breaks or overrides the administrator's Goose | The native profile is changed through Goose's own configuration API, key by key, each write read back; a request Goose could not be asked is a failure, never "not there"; a failure is recorded and nothing else is changed (`adversary.md` is touched only after the settings went in). Goose Web remembers what it wrote and replaces or removes only that: a value the administrator set (a stricter threshold, an own classifier with its token) is kept and reported, and "off" removes only Goose Web's own values. What is kept is what was there before Goose Web first wrote the key. A key Goose Web wrote stays its own: if it is later changed or removed in the file, it is put back at the next start whatever the new value is, with the changed value saved, an audit entry and a notice (14.5, R-3 and T-1). Limit: this is detection after the fact, between two gateway starts, against something that already runs under the administrator's Windows account; such a program has other ways to weaken Goose that Goose Web does not see (the environment, the secret store, the Goose binary itself). Neither those nor an `adversary.md` Goose Web did not write is taken over without an explicit choice and a backup; a file it cannot read is left alone |
| A long text ties up the classifier | Body cap; at most `classifier_max_pieces` pieces, and a text that cannot be scored completely is answered `413`, never "safe"; a deadline below Goose's timeout; the bounded backlog above. Limit: the bound is on pieces, not on time; see 14.3, "One profile can make the endpoint unavailable to the others" |
| The rules text or a token ends up in a log | The audit holds switches and sizes only (`goosesec.summary`); the state holds a 16-hex-digit fingerprint of the token, not the token |

### 14.3 Residual risks

- **The port while the gateway is down.** The native profile's `config.yaml` keeps the endpoint address between
  gateway runs. While the gateway is stopped, another Windows account on the same computer could listen on that port
  and would be sent the recent user messages of the administrator's Goose Desktop, CLI and scheduled chats, with
  the token. Goose's client cannot verify who answers (plain HTTP to a fixed address). A sandboxed member's agent
  cannot do this (no loopback, section 13). Mitigations: run the gateway at boot (service account); do not give other
  people interactive or remote-desktop access to the gateway's computer; or set `guard.classifier_port: 0`.
- **One profile can make the endpoint unavailable to the others (open, Medium; 14.5 R-1).** The endpoint and the
  prompt guard of section 11 have a thread each, so the endpoint cannot make the guard wait in a queue; both use the
  same processor cores, so heavy endpoint use slows the guard down. The endpoint's bound counts pieces, not time,
  and its one thread serves requests in the order they arrive. Measured on a 4-core computer: one token-dense text of
  `guard.max_input_chars` (16,000) characters keeps that thread busy for 9 to 11 seconds (ordinary English of the
  same length: 2 seconds), longer than the 4 seconds a request may take, and a profile may have 3 requests waiting.
  A member's agent that keeps sending such texts with its own token therefore makes other profiles' requests end in
  `503`, and Goose uses its patterns only for those tool calls, for as long as it continues. Nothing is disclosed and
  nothing is blocked wrongly; pattern detection, the sandbox, the policy firewall and the prompt guard of section 11
  are not affected. The listener counts these answers (`listener.stats.busy` in `GET /api/admin/goose-security`); the
  admin page does not show the counter yet. Not fixed in 1.20.0: it needs fair scheduling per profile and scoring
  that stops at the deadline.
- **Connections.** uvicorn has no timeout for a connection that never sends a request. A program on the computer
  that opens 1,024 connections to the endpoint and sends nothing makes every classification request `503` until it
  stops. A sandboxed member cannot (64 connections through its proxy). Goose then uses its patterns only.
- **adversary.md between starts.** The file is in the member's profile, which the member's agent can write. Goose
  1.59 reads it once per process, and the gateway rewrites it before every start, so an edit has no effect there.
  Goose 1.57 reads it per chat: an agent that edits the file changes the rules for that member's NEXT chat until the
  agent's next start. Use Goose 1.59 or later with adversary mode for members. (The detection settings are not
  affected: they are in the environment.)
- **The token in the MXC policy file.** A sandboxed worker's environment is written into its policy file under
  `<system_dir>\sandbox\mxc`, readable by the gateway's account and administrators. Since 1.20.0 that includes the
  classifier token (classification only).
- **Command-line token rotation on a running gateway.** `goose-web security rotate-tokens` takes effect for the
  listener within 15 s; running agents keep the old token (Goose falls back to its patterns) until the gateway
  restarts or an administrator clicks Apply now. Rotating in Admin > Prompt guard has no such gap.
- **AppContainer backend.** With detection and the classifier on, every AppContainer member gets a relay forwarder
  for the endpoint (and the read grant on the gateway's base Python that relays need), also where no relay was
  configured before.
- **The token in a member's profile.** It is in the profile's `secrets.yaml` and in the agent's environment, readable
  by that member's agent, like every other secret of that profile. It gives the agent nothing it does not have.
- **An unstable Goose method.** The native apply uses `_goose/unstable/config/*`. If Goose renames it, the apply
  fails visibly and the native profile keeps its last settings. `tests/test_goosesec_e2e.py` detects it.
- **Adversary mode** adds a model call that sees the user's first message, recent messages and the tool call. It
  goes to the chat's own provider, which already has that content.
- **Not covered:** a native profile on another computer, and Goose instances started with another
  `GOOSE_PATH_ROOT` that Goose Web does not know.

### 14.4 Independent review 2026-11-12 (before release)

A second reviewer attacked the first version of this feature (read-only, code only). All findings were fixed or are
listed as residual risks above before 1.20.0 was released; each fix has a test in `tests/test_goosesec.py` or
`tests/test_classifyapi.py`.

| ID | Severity | Finding in the first version | Now |
|---|---|---|---|
| E-1 | High | Work that missed the deadline carried on in the classifier thread shared with the prompt guard, with no bound: one profile's token could queue unique long texts until the guard of guarded teams timed out and failed open | Own thread for the endpoint, bounded backlog (8 pieces, 3 per profile), refused before queueing, not-started work dropped at the deadline; flood test |
| E-2 | Medium | 64 idle connections made every request `503` | Limit 1,024, out of a sandboxed member's reach; residual for a local program (14.3) |
| E-3 | Medium | In the native profile "off" removed, and "on" overwrote, values the administrator had set themselves | Ownership: only Goose Web's own values are replaced or removed; others kept and reported; take-over only on request, with a backup |
| E-4 | Medium | Text beyond the piece limit, and pieces that did not fit, were answered `SAFE` | `413`; the test that asserted `SAFE` now asserts the refusal |
| E-5 | Medium | A link or folder in place of a member's `adversary.md` was skipped in silence; an exception in this step was logged and ignored | Fails the start (fail closed), audited; other `SECURITY_*` keys scrubbed; residual for Goose 1.57 (14.3) |
| E-6 | Medium | With the AppContainer fallback the environment pinned an address the container cannot reach | The environment is built from the backend chosen at that start, with the relay forwarder's address |
| E-7 | Low | A removal that failed because Goose could not be asked was recorded as applied | Only Goose's answer counts as "not there"; anything else is a failure and is retried at the next start |
| E-8 | Low | An `adversary.md` that could not be read was treated as absent | Reported as an error and left alone |
| E-9 | Low | A disabled user keeps access for up to 15 s; command-line rotation on a running gateway | Documented (14.3) |
| E-10 | Low | The token is in the MXC policy file | Documented (14.3) |
| E-11 | Info | Relay forwarder for every AppContainer member | Documented (14.3) |
| - | - | A non-numeric `guard.classifier_*` value stopped the gateway at start; a lone surrogate in the text or a failing scorer could flip the guard's state | The default is used and logged; the text is sanitised; a scoring error for one text no longer changes the guard's state |

The same day's review of the rest of the product (authentication and the API, the hub and workers, the sandbox, and
upgrade, installers and logs) led to these fixes in 1.20.0: open WebSockets are closed when the caller's role, policy
or folders change (A-1); the change-password check runs off the event loop and is rate limited (A-3); session buffer
accounting after a worker stop (B-1); a start that times out no longer blocks the event loop while the worker is
killed (B-4); a member's unreadable `config.yaml` / `secrets.yaml` is set aside and rebuilt instead of blocking every
start (B-9); `icacls` and `powershell.exe` are started by full path (C-5); `goose-web check` no longer migrates the
database (D-1); the audit log is no longer purged with a fixed 365 days at every database open (D-4); the installer
shows the initial password before any later step can fail (D-7). No path was found that starts a member's agent
without its sandbox, and no upgrade path that loses chats, users, teams, settings or preferences. The findings that
are not fixed yet are tracked outside this document.

### 14.5 Second independent review 2026-11-12 (the changes made after 14.4)

The fixes of 14.4 and the changes that followed (`guard.native_profile`, the process priority) had been reviewed by
nobody but their author. Before release a reviewer read exactly that difference (read-only, code only). It found no
way for a member to read or change another member's data or to leave the sandbox, no private information in the
published lines, and nothing that fails on Python 3.11. It found two regressions and one overstated claim:

| ID | Severity | Finding | Now |
|---|---|---|---|
| R-1 | Medium | The endpoint's bound counts pieces, not thread time: one profile can keep the endpoint's thread busy (14.3 had said three colluding profiles are needed) | **Open.** 14.3 corrected, with measurements |
| R-2 | Medium | Regression of the E-6 fix: an MXC start after an AppContainer fallback built its environment from the previous start's backend, so the worker was given the relay forwarder's address, which no MXC worker can reach; the classifier was unreachable for that worker's whole life | The start passes its own backend; test for fallback, then MXC |
| R-3 | Medium | Regression of the E-3 fix: in the native profile a value Goose Web wrote and something later weakened was treated as the administrator's own: no drift, no audit, no notice | A key Goose Web wrote stays its own: changed or removed outside, it is put back, audited and administrators are told (see T-1 below for why not only "weaker" values) |
| R-4 | Low | A value the administrator had set that happened to equal Goose Web's was recorded as Goose Web's, so a later "off" removed it | Only what Goose Web wrote (or took over on request) is its own |
| R-5 | Low | On take-over the backup of the replaced values was written last, so a failure in between lost them | Written before the first value is replaced |
| R-6 | Low | The new re-validation of a WebSocket's rights kept the socket when the check itself failed | The socket is closed; the browser reconnects |
| R-7 | Low | That re-validation creates the team folder if it is missing (a file-system call on the event loop, every 30 s per socket) | **Open.** Negligible on a local disk |
| R-8 | Low | Every refused change-password request wrote an audit row at no cost: a member could fill the audit table until its oldest rows were pruned | One row per window |
| R-9 | Low | Set-aside profile files: never pruned; two in the same second overwrote each other | Unique names; the newest 5 per member and file name are kept |
| R-10 | Low | Only two kinds of parser error led to the set-aside; others still blocked every start | Every parser error; something that is not a file still fails the start |
| R-11 | Info | Three places still said the rest of an over-long text "is not scored" | Corrected (`413`) |
| R-12 | Info | `taskkill` was still started by bare name | Full path |
| R-13 | Info | A `guard.native_profile` value that is neither true nor false means "not managed", silently | Said in the log at every start |

**Third review, of those fixes.** The first fix for R-3 judged whether the outside change protected less, put
only such a value back, and let go of the key otherwise. A third reviewer read that commit and showed two ways
round it, and several lesser defects in the same logic and in the set-aside:

| ID | Severity | Finding in the first fix of R-3 to R-10 | Now |
|---|---|---|---|
| T-1 | Medium | Two steps (a harmless-looking change first, so that Goose Web let go of the key, then the real one), or another endpoint together with the classifier switch, ended with the protection down and nothing said | No judgement any more: a key Goose Web wrote is put back whatever it was changed to |
| T-2 | Low | What was written was recorded before the read-back; after a mismatch the next apply blamed a change "outside" | What Goose really holds is remembered; a mismatch stays a failure of its own |
| T-3 | Low | A write that landed while the apply was interrupted (gateway stopping, a lost answer) belonged to nobody afterwards | What is about to be written is recorded first; an interrupted apply is recorded too |
| T-4 | Low | The notice was lost when a later step of the same apply failed, and reached only administrators connected at that moment | Sent whenever something was put back; also in the audit and, until the next time, on the page |
| T-5 | Low | A false "changed outside" notice for the classifier switch | That category no longer exists |
| T-6 | Low | A removed key was restored without saying so | Reported like a changed one |
| T-7, T-8 | Low | Set-aside pruning went by the file's own date, which the member's agent controls, and stopped at the first file it could not delete | The file is dated when it is set aside and never pruned in the same step; attributes are cleared; one failure does not stop the rest |
| T-9 | Low | The other half of R-6: the hub kept a socket when the check itself raised | Closed |

**Fourth review, of the simplified rule.** One High finding, introduced by the commit under review, and two
Medium ones:

| ID | Severity | Finding | Now |
|---|---|---|---|
| F-1 | High | Numbers were compared through `float()`. A huge integer written into the threshold made the comparison raise; the check that decides whether anything must be applied failed, the failure was only logged, and from then on nothing was put back, recorded, audited or said at any start | Numbers are compared exactly, without conversion; a comparison that fails counts as "something to apply"; a failure of the check itself is recorded, audited and shown like a failed apply |
| F-2 | Medium | An apply that failed before it had decided anything (Goose still not answering) forgot the write that was in flight from the apply before | The record of a write in flight is kept until an apply has seen what Goose holds |
| F-3 | Medium | The classifier group still let go of a switch Goose Web had written when an endpoint appeared that Goose Web never wrote, now without any trace | The group rule never covers a key Goose Web wrote |
| F-4 | Low | The record made before the first write kept the previous apply's "ok" and date | It says "not finished", with what was written so far |
| F-5 | Low | On "off", a key Goose Web wrote that had been changed outside was let go; after "off" and "on" it counted as the administrator's own | Removed like the rest, the changed value saved |
| F-7 | Low | A write in flight that had landed was not taken over before the next write | Taken over as soon as Goose is seen to hold it |
| F-8 | Low | The read-back stopped at the first key that came back differently | Every key is read back, then the apply fails once |
| F-12 | Info | Listing the set-aside folder could fail after the file was moved, skipping the log line and the audit row | Caught |
| F-6, F-9, F-10 | Low | **Open.** After a failed write, a value the administrator sets for that very key before the next apply is overwritten (saved first); a put-back that landed in an apply that was cancelled or whose answer was lost gets no audit row of its own (the page still shows it when the apply was cancelled); a removal whose answer was lost can later be reported as "removed outside" | Rare sequences of two failures; documented |

After four reviews of this one function the lesson is recorded here on purpose: every version that tried to
tell a harmless outside change from a harmful one had a way round it, and every repair of a repair added a state.
The rule that survived is the one with the fewest states. These last fixes were not reviewed again. They are
covered by tests in `tests/test_goosesec.py`, checked by running them against the code as it was before each round
of fixes: the tests of every R and T finding and of F-1 to F-5 and F-8 fail there (F-7 and F-12 have no test of
their own). Also: the whole suite on Python 3.11 and 3.13, and a throwaway gateway run with the real Goose binary.
Not tested against a real Goose: how Goose returns value types other than the ones Goose Web writes.

## 15. Addendum: library items from Goose's home folders (2026-11-13), 1.21.0

Scope: `profiles.py` (`library`, `export_item`, `_skill_dirs`, `_recipe_dirs`, `_read_skill_files`), the
`goose-web check` line, and what the documents say about Goose's home-folder skills, recipes and agents.

### 15.1 What is true about those folders

Goose looks for global skills, recipes and agents under the operating system's home folder
(`~/.agents/skills`, `~/.claude/skills`, `~/.config/agents/skills`; `~/.agents/recipes`, `~/.goose/recipes`;
`~/.agents/agents`, `~/.goose/agents`, `~/.claude/agents`): read in the source of Goose 1.57.0 and 1.59.0, and
measured with the 1.57.0 binary, which lists the account's home-folder skills for a profile with its own
`GOOSE_PATH_ROOT` whatever `USERPROFILE`, `HOME`, `HOMEDRIVE` and `HOMEPATH` say. The home is the gateway account's.

| A member's agent | Sandbox on (default) | Sandbox off |
|---|---|---|
| reads the contents of those folders | refused (measured in an MXC container) | yes |
| so its Goose loads those skills, recipes and agents | no | yes, all of them |
| can list the names in them | yes (Q2, 13.1) | yes |

Earlier versions of this document and the README said these folders "are visible to all profiles". That is the
right-hand column only.

### 15.2 What 1.21.0 adds

An administrator can offer skills from those folders to a team (the library picker of the native profile now lists
them, in Goose's order of precedence) and recipes from `~/.goose/recipes` as well. Nothing changes in how items are
delivered, and nothing is shared without an item. Home-folder agents are not offered.

| Threat | Control |
|---|---|
| A member lists or adds library items | `GET /api/admin/library` and `POST /api/admin/teams/{id}/items` require an administrator (unchanged) |
| A member's profile is used to read a file the member cannot read (below, 15.3) | Nothing is read through a link in a member's profile: junctions, symbolic links and hard-linked files are skipped in skills and recipes; a `skills`, `recipes` or `custom_providers` folder that is a link, or has a link between it and the profile root, is not read; `config.yaml`, `secrets.yaml` and provider files must be regular files (15.5, L-1). In the administrator's home folders skills and recipes are likewise not read through a link; folders named in `GOOSE_RECIPE_PATH` are checked only for being links themselves |
| A huge, deep or endless folder, or a huge file, in a member's profile | Every limit applies before the work it limits (15.5 L-4, 15.6 M-10): the picker lists at most 2,000 entries of a folder, reads 16 KB of a `SKILL.md`, skips recipe and provider files over 1 MB and parses at most 16 MB of them per listing, and does not read a member's `config.yaml` over 1 MB; a skill has at most 500 files, 2 MB (binary files count, though they are not shared), 5,000 entries walked (no folder is listed beyond the entries still allowed), 12 levels, 180 characters per path; a linked folder is never entered |
| A value in a member's file makes the picker's answer, or the stored item, huge or unserialisable | Names and descriptions are text of bounded length or empty, with anything that cannot be encoded replaced; an extension entry or provider file is shared only when it is plain data within a budget of values and levels, so nested YAML aliases cannot be written out as gigabytes of JSON (15.5 L-2, 15.6 M-1, M-8, M-9) |
| One odd skill stops members' agents from starting | A file that cannot be written into a member's profile is skipped and logged; provisioning goes on, and a skill delivered before is not taken for withdrawn (15.5 L-3, 15.6 M-2) |
| The home-folder items reach members who were not given them | They are copied only as team items. The gateway cannot stop Goose from reading the home folder when the sandbox is off; `goose-web check` says so |
| The tests read, or depend on, the developer's own home folder | The test session replaces the home folder and removes `GOOSE_RECIPE_PATH` for every test |

### 15.3 A defect in earlier versions, fixed here

Before 1.21.0 `export_item` read every file under a skill folder, also through links. A skill folder in a member's
profile is the member's to fill: with a junction or a hard link in it to a file outside the profile (another
profile's `secrets.yaml`, the gateway's database), an administrator who later offered that skill to a team made the
gateway read the target with its own rights and copy it into the profiles of the team's members. Reproduced
against 1.20.0 with a junction and with a hard link placed in the folder; neither is read now.

How such a link could get there decides how serious this was. It needed an administrator to choose that skill from
that member's profile, and it needed the link:

- **A member confined by the MXC sandbox could not create one.** Measured in a container: a hard link, a junction
  and a symbolic link to a file or folder outside the member's own folder are all refused.
- **Without the sandbox** a member's agent that can run commands can create them, but it can also read the target
  directly; the defect then only added that the content was copied to other members.
- **Not measured:** the AppContainer backend, and links that reach a profile some other way (a restored backup, an
  administrator's own tool).

Severity: Low for an installation that uses the MXC sandbox. The same held for the other two kinds of item
(15.5, L-1): a provider file, a `config.yaml` or a `secrets.yaml` in a member's profile that was a link was read,
and the secret it named was copied to the team. All of it is closed for members' profiles, because the gateway has
no reason to read a member's file through a link at all.

### 15.4 Residual risks

- **What the administrator shares is text.** A skill that mentions paths, host names or a pasted key carries them
  into every member's profile. Goose Web does not inspect skills.
- **Between the check and the read.** The export checks a file and then reads it. A member's agent running at the
  very moment an administrator exports from that member's profile could swap a file for a link in between. Exports
  from the administrator's own profile are not affected.
- **Without the sandbox** the home-folder skills, recipes and agents are loaded by every profile's Goose (15.1).
- **Names** of files and folders are listable inside the sandbox (Q2).
- **Same-named skills** in two folders: the first in Goose's order is offered. Goose itself goes by the name
  inside `SKILL.md`, Goose Web by the folder name; when those differ the picker and Goose can disagree about which
  one "wins".
- **The AppContainer backend** was not measured for any of this (15.1 and 15.3 are MXC measurements). It has been
  since: section 16 (contents and names refused, no link to the outside can be made).
- **A source profile whose `secrets.yaml` becomes a link** after an item was offered from it: the secret is no
  longer copied, and a copy made earlier is withdrawn from the team's members at their next start (their provider
  then has no key). A source that merely cannot be read at that moment changes nothing.
- **The administrator's own profile** (`config.yaml`, `secrets.yaml`, provider files) is read through whatever
  links it has, as Goose reads it.

### 15.5 Independent review of this change (2026-11-13, before release)

A reviewer read the first version of this change (read-only, code only). No High finding; for members' skills and
recipes no way through a link beyond the check-then-read race of 15.4. It found three Medium problems in the lines
around the change, which the change's own documents claimed to cover, one regression and several smaller ones:

| ID | Severity | Finding | Now |
|---|---|---|---|
| L-1 | Medium | Extension and provider listing and export, and the secrets copied with them, still read through links (`config.yaml`, `custom_providers` and its files, the source profile's `secrets.yaml`), while the documents said the export follows no link | Regular files only in a member's profile; nothing is copied from a linked `secrets.yaml` |
| L-2 | Medium | A recipe's description went untyped into the picker's answer: a YAML date failed the picker for that profile, nested aliases expand to gigabytes as JSON on the event loop | Text of at most 500 characters, or empty; the same for extension and provider names and descriptions |
| L-3 | Medium | Any error writing one file of a team skill failed provisioning, and with it every start of that member's agent, until the item was removed | The file is skipped and reported; provisioning goes on; over-long paths are refused at export |
| L-4 | Low | Limits applied after the work: whole files read for a description, folders listed and sorted before the cap, the walk unbounded | See 15.2 |
| L-5 | Low | Regression: a skill whose file is `skill.md` in another case was listed but could not be exported | Shared as `SKILL.md` |
| L-6, L-7 | Low | In the administrator's home only the last folder was checked for being a link, and `check` said "none" for linked folders although Goose follows them | Every folder between the home folder and the skills folder is checked; `check` counts behind links and says which folders are not offered |
| L-8 | Low | A linked skill in the first folder did not take its name, so a later folder's skill was offered in its place; `Review` and `review` were both offered and land in one folder | The first folder takes the name, in any case, also when it is a link |
| L-9 | Low | The "managed" mark of a team skill was written in place, through a link if the member had put one there | A linked mark is not Goose Web's mark: the skill is left alone; the mark is written atomically |
| L-10 | Low | Sentences the code or the measurements did not support ("in any profile", "the sandbox" where only MXC was measured, "nothing else" for a new profile) | Corrected |
| L-11 | Low | Tests that did less than their names said, and missing ones | Each finding above has a test that fails on the reviewed commit (checked by running them against it) |
| L-12 | Info | The home folder was taken from `USERPROFILE`, which Goose does not use | Asked from Windows, as Goose does |
| L-13 | Info | Small items: the mark compared in exact case, deep trees | Fixed with L-4 |

Not followed up: the reviewer's list of things that reading could not settle (among them `st_nlink` on a volume
that is not NTFS, a home folder redirected to a cloud drive, the check-then-read race). The fixes of this table
were not reviewed again by the same depth of reading: a second, narrower review looked only at them (15.6).

### 15.6 Second review, of the fixes of 15.5 (2026-11-13, before release)

A second reviewer read only the commit with those fixes. No High finding. One of the fixes had introduced a
regression (M-2) and several smaller new defects; and four things were as before although 15.5 presented them as
closed:

| ID | Severity | Finding | Now |
|---|---|---|---|
| M-1 | Medium, as before | Exporting an extension still wrote nested YAML aliases out as JSON on the event loop: L-2 had fixed the listing only | Shared only as plain data within a budget of values and levels; a member's `config.yaml` over 1 MB is not read |
| M-2 | Low, regression | When the mark of a team skill could not be written, the skill left the record and the cleanup deleted its folder although the skill was still assigned; a new folder whose mark failed stayed behind, never updated and never withdrawn | A skill delivered before stays on record; the mark is written first; a new folder that could not be marked is removed again |
| M-3 | Low, new | A file that could not be written was reported as a change, which marks the member's agent for a restart at every administrator action | Logged once per provisioning; not a change |
| M-4 | Low, new | A source `secrets.yaml` that could not be read at that moment made the cleanup remove the key from every recipient, without a word | Keys copied earlier are kept; logged |
| M-5 | Low, new | A skills folder behind a link took no names, so a later folder's skill of the same name was offered in its place | Names are taken from every folder Goose loads from |
| M-6 | Low, new | A native profile reached through a link lost its own skills and recipes in the picker, silently | The native profile's config folders are checked only for being links themselves, like `GOOSE_RECIPE_PATH` |
| M-7 | Low, new | In a case-sensitive folder the last case variant of `SKILL.md` won | The exact `SKILL.md`; otherwise exactly one variant |
| M-8, M-9 | Low, as before | Text that cannot be encoded (a lone surrogate) in a name or description, or a deeply nested provider file, failed the picker for that profile | Replaced; skipped |
| M-10 | Low, as before | Some limits still applied after the work, or were missing | See 15.2 |
| M-11 | Low, new | The `check` line named the configured backend also when members ran in the fallback | One sentence that holds for both backends |
| M-12 | Low | Three tests did less than they said; two findings had none | Rewritten and added; each finding has a test that fails on the commit it was found in (checked by running the tests against both reviewed commits) |
| M-13 | Info | The profile folder was asked again after a failure; its buffer was freed only on success | Asked once; freed regardless |

Not followed up from this reviewer's list of things reading could not settle: whether Goose's own saving ever
leaves a second hard link on `config.yaml` (a member's extension could then not be offered until the file is
rewritten), files on a volume with deduplication or cloud placeholders counting as links, and whether a sandboxed
agent can make a folder case-sensitive. The fixes of this table were read once more, narrowly (15.7).

### 15.7 Third review, of the delivery and export functions only (2026-11-13, before release)

The second round of fixes had rewritten the branch that delivers a team skill, the place of the regression M-2, so
a third reviewer read only those functions in the commit with the fixes of 15.6. No High finding; no path on which
a skill that is still assigned is deleted, or a member's own skill is overwritten or deleted. It found:

| ID | Severity | Finding | Now |
|---|---|---|---|
| N-1 | Medium, residual of M-1 | The budget counted values and each text, not the text as a whole: one long text used thousands of times still passed, about a gigabyte as JSON | A budget of 1 MB for all text and keys of an item |
| N-2 | Medium, as before | An extension's `env_keys` or a provider's `api_key_env` that is not a list of names (a number, a nested list) made provisioning raise for every member of the team | Refused at export; provisioning takes only names from a stored item, whoever built it |
| N-3 | Low | The temporary file of a failed write stayed; in a new skill folder it kept the folder from being removed again, and a folder without the mark is the member's own for good | A failed write leaves nothing behind |
| N-4 | Low, new | "The exact `SKILL.md` wins" did not hold for `SKILL.MD`, which sorts before it (refused instead; nothing wrong was shared) | The exact name wins wherever it sorts |
| N-5, N-6 | Low / Info, as before | A withdrawn skill with a file in use left a folder that was reported as removed and never removed; a withdrawn provider file in use made provisioning raise | What is left stays on record and is removed at a later start; never a failed start |
| N-7 | Info | Sizes are checked with `stat` and the file is then read whole; the mark and the delivered files in a member's profile are read without a limit | **Open** |

These last changes are small and local, and each has a test; they were not reviewed by anyone else. Not followed
up from this reviewer's list: two team items whose names differ only in case share one folder in a member's
profile; a number that is not finite (`NaN`) in a provider file passes; a source `secrets.yaml` that is empty for a
moment reads as "no keys" and withdraws them until the next start.

## 16. Addendum: the AppContainer backend, measured again (2026-11-13), 1.21.1

The AppContainer backend of 1.8.0 is what a member's agent runs in where Windows cannot run MXC process containers
(`sandbox.backend: appcontainer`, or `sandbox.fallback: appcontainer`). Since MXC became the default (1.19.0) it was
covered by unit tests and one container test, and sections 14 and 15 say that their claims were measured with MXC
only. For 1.21.1 it was run again with real containers on Windows build 26100: a Python, and the real goose 1.57.0
binary, both started by the product's own code (`sandbox.prepare`, `sandbox.spawn`, `relay.PipeRelayServer`,
`WorkerManager`). One finding of this work is not about the AppContainer backend alone (16.3).

### 16.1 Still supported

Started by `WorkerManager` on `sandbox.backend: appcontainer`, goose 1.57.0 was ready in 2 s, answered `initialize`
and `session/new`, and finished a prompt whose model was a service on this machine's loopback, reached through
forwarder -> named pipe -> gateway. Its shell call ran inside the container. Goose's prompt injection detection
(section 14) asked the classification endpoint through a relay of its own, with the profile's token. Stopping the
worker ended goose and both forwarders; removing the container removed its grants.

### 16.2 What a member's container reaches (measured)

| Subject | Result |
|---|---|
| Files outside the grants | Refused for reading and for listing: another member's profile, the system folder, the profiles root, the gateway account's home folder and Goose's home-folder skills and agents in it (section 15), the native Goose profile and its `secrets.yaml`, the install folder, the drive root. Unlike MXC (Q2), names are not listable either. A child process is refused the same way. |
| Network | Loopback, and this machine's own LAN address, are closed with every capability. Without a capability there is no network at all; with `internetClient` name lookup, TCP and TLS with certificate check work. |
| Relay | Works. Another member's container is refused by the pipe (access denied). |
| Links | A hard link to a file outside, a hard link to a file in a read-only grant, and a junction to a folder outside or to another member's folder are refused: the container cannot link to what it may not write. Symbolic links were refused for lack of the privilege (a machine without Developer Mode). Links inside and between the container's own folders are allowed, the team folder included - so a link can outlive a grant that is withdrawn later. Earlier text (13.3, the administration guide) assumed an AppContainer agent could create hard links to any outside file; it cannot. The scan of MX-3 stays for the links that remain possible and for those the host makes. |
| Processes | The gateway process cannot be opened (query, read memory, terminate). |
| Temporary files | Windows replaces `TEMP`, `TMP` and `LOCALAPPDATA` of an AppContainer process with a folder of that container under the gateway account's `%LOCALAPPDATA%\Packages`; the values Goose Web sets for them are not what the agent sees. Only that container can use the folder. Without `LOCALAPPDATA` in the environment the process cannot be created at all (error 203), which is why it is on the allow-list. |
| Registry | **Readable**, see 16.3. |

### 16.3 The registry is readable from the sandbox - both backends (AC-1, open)

**Severity: High where secrets are kept in environment variables stored in the registry (the user variables of the
gateway's account, the machine's variables) or elsewhere in the account's registry hive; otherwise information.** A
sandboxed agent runs as the gateway's Windows account inside an application container. The access rights of
`HKEY_CURRENT_USER` let "ALL APPLICATION PACKAGES" read it, and so do those of `HKEY_CURRENT_USER\Environment`,
where the account's user environment variables are stored (by an entry of its own or by inheritance, depending on
the installation), and of the key that holds the machine's environment variables.

- Measured from an AppContainer and from an **MXC** container (whose token is an application-container token too):
  both keys were opened and their value names listed, and a value of the user key was read. On the test machine the
  user key held 15 values, 9 of them named like API keys. The real agent's shell ran `reg query HKCU\Environment`
  with the same result.
- This goes round a control this assessment relied on: C-2 of section 9 ("Sandboxed workers inherited the gateway
  account's environment (API keys)" - fixed by an allow-listed environment) and the statement of 13.2 that the worker
  environment holds no gateway secrets. Both remain true of the *environment*; the same values can be read from the
  registry.
- **Not closed by Goose Web.** A "less privileged" AppContainer (which ignores the ALL APPLICATION PACKAGES
  entries) was tried: without the `registryRead` capability Python does not start in it, and with that capability
  the key is readable again. A deny entry on the key would close this one key; changing the access rights of an
  account's registry is the administrator's decision, not something this web application does on its own.
- **What an administrator does** (ADMINISTRATION 11.3): keep secrets out of environment variables on the gateway's
  machine; for the user variables, running the gateway under an account that is used for nothing else has the same
  effect. `goose-web check` prints a "registry" line that names the user and machine variables whose names look
  like secrets. It judges names only: a secret under a plain name is not found.
- Not examined: which other keys of other programs under `HKEY_CURRENT_USER` hold secrets on a given machine, and
  the other machine-wide keys an application container may read (`HKEY_LOCAL_MACHINE\SOFTWARE` was readable).

Files are not affected: 16.2 holds for the account's files, the native Goose profile and its secret store.

### 16.4 Fixed in 1.21.1

| Id | Severity | Finding | Change |
|---|---|---|---|
| AC-2 | Medium | The AppContainer backend and fallback granted every folder of a member's settings with icacls. MXC filters them at each start; here a team folder set to the code or to a folder above the system folder was granted as written. | `workers._start_appcontainer` applies `mxc.filter_grants`: the same rules, in canonical form and through links; a refused folder is logged, and a grant an earlier version made is taken back |
| AC-11 | Medium (function) | A granted folder that is reached through a directory link (junction) was granted on the link; the folder behind it stayed closed, and a program started through the link could not load its DLLs (exit 0xC0000135). uv keeps its Pythons behind such a link, so on a gateway running on one the relay forwarders did not start. Found by the test run on Python 3.11, not by review. | The grant filter of AC-2 resolves links, so the grant lands on the real folder (measured: the program then runs through the link) |
| AC-3 | Medium | A relay accepted any number of connections; each costs the gateway two threads and a socket, and the gateway serves everyone. | At most `sandbox.proxy_max_connections` at once per member and service; more are closed at once and counted |
| AC-4 | Low | `sandbox.spawn` resumed a process that could not be put in its kill-on-close job (a warning only). | The process is ended while still suspended and the start fails, as MX-9 for MXC; a job that does not exist counts as a failure |
| AC-5 | Low | The relay URL rewrite matched a port as a prefix (`:80` in `:8080`); wrote the record that undoes it after the rewrite; wrote files in place, converting line endings, and through links in folders the member can write. | The port must end; record first; whole-file replacement with bytes kept; regular files of the profile only, a bounded number and size, never read beyond the bound; the forwarder file is compared by size first and replaced, never written through a link; a restore that cannot finish is kept as owed and tried again |
| AC-6 | Low | An entry of `sandbox.relays` that is not `host:port` raised where the member's connection is set up. | Left out and named by `check`, `sandbox status` and the log; nothing else is affected; IPv6 is left out; a value of any type is handled |
| AC-7 | Low | Container state files were written in place. A folder permission that could not be taken back was dropped from the record. | Replaced as a whole; a failed revoke stays on record and is tried again |
| AC-8 | Info | The forwarder logged the normal end of every answer as an error; a forwarder that printed nothing held the worker's start for ever. | Not logged; the start waits 30 s |
| V-9 | Low | The container held the right to create further instances of its own relay pipe (GENERIC_WRITE includes it). Its forwarder refuses a pipe not served by the gateway, but with an instance of its own in front of the gateway's the agent could keep the serving thread alive after the worker stopped. | The pipe grants the container read and write-data only; the forwarder opens it that way (measured: creating an instance is refused, the relay works) |
| V-12 | Low | Two relayed services on one port shared one forward address: the second forwarder could not bind, and that stopped all relays of every member. | Each gets an address of its own (`127.64.x.y`, `127.65.x.y`, ...) |
| V-8 | Low | A relay target whose name cannot be encoded raised something other than `OSError` in the gateway; the pipe instance stayed open. | Such names are refused as targets, and any failure to connect closes the instance |

### 16.5 Residual risks

- The registry (16.3).
- The relay's limit is per member and service; a member with several relayed services can hold that many
  connections on each. A connection that sends nothing holds its place until the service or the agent closes it.
- Between the gateway's check of a profile file and its replacement a member's agent could swap the file; it could
  only make the gateway replace a name inside the member's own folders (the replacement never follows a link).
- A member whose `config.yaml` has a second name (a hard link the agent made inside its own folders) is not
  rewritten: with the AppContainer backend that member's relayed provider does not work until the second name is
  gone, and after a move to MXC the restore stays owed. Logged at every start.
- Granting a folder still rewrites its access rights for the container, with inheritance; a folder that passes the
  rules but holds hard links to files elsewhere carries those files' rights with it.
- Not closed, Low (16.6): handles that leak when the creation of a sandboxed process fails before the process
  exists; the forwarder's own log line for a connection over the limit.
- Measured on one Windows build (26100). Older builds that cannot run MXC are the ones this backend is for. The
  container tests of `tests/test_appcontainer.py` run on the Windows image of the project's CI.

### 16.6 Independent review of this change (2026-11-13, before release)

A reviewer who had not written the change read the diff and the code around it and ran the container tests. No High
finding. What was found, and what became of it:

| Id | Severity | Finding | Status |
|---|---|---|---|
| V-1 | Medium | The new connection-limit test raced the relay's threads and failed at random | Fixed (the test waits for the free place) |
| V-2 | Medium | The check and the documents covered the user variables only; the machine's variables are readable the same way and another account does not help there | Fixed: both are listed and described |
| V-3 | Medium | The forwarder file in the member's profile was read whole whatever its size, at every start with a relay | Fixed: size first, never more than the expected size is read; the configuration files likewise |
| V-4 | Low, regression | A restore that could not finish (file in use, link) was logged and forgotten | Fixed: kept as owed, tried again at every start |
| V-5 | Low, regression | Replacing a file fails while another reader has it open; the in-place write did not | Fixed: tried again for half a second; random temporary name |
| V-6 | Low, regression | A relay entry that used to be tolerated stopped every member's agent | Fixed: left out and reported, nothing else affected |
| V-7 | Low | `sandbox.relays` that is not a list ended `check` in a traceback | Fixed |
| V-8, V-9, V-12 | Low | see 16.4 | Fixed |
| V-10 | Low | A revoke that failed was dropped from the record | Fixed |
| V-11 | Low | Process and pipe handles not closed on some paths | Fixed in part: the process handle is closed with its object, the caller's pipe ends when process creation fails. **Open:** failures before the process is created |
| V-13 | Low | Names such as `OPENAI_API_KEY2`, `GITHUB_PAT`, `apiToken` were not recognised; the [OK] line reassured | Fixed: plurals, digits, camel case, more words; the line says it judges names |
| V-14 | Low | Sentences that overstated: "no link to anything outside", "cannot prevent", "none of the gateway's variables", the CI claim | Corrected |
| V-15 | Info | Test hygiene (clean-up when the fixture fails half-way, a process that never ends) | Fixed |

Not verified by the reviewer: anything from inside a container (the review was of code), GitHub's Windows image,
older Windows builds, and a possible reuse of a handle value between the two relay threads of one connection.

**A second, narrow review** read only the fixes above. Nothing blocking (no High, nothing that breaks an ordinary
installation). It found one Medium regression of the fix of V-4 and some smaller points:

| Id | Severity | Finding | Status |
|---|---|---|---|
| W-1 | Medium, regression | An owed restore whose forward address had since been given to another relay target (targets on one port reordered or replaced) was replayed at every start: two URLs in a member's `config.yaml` swapped, or one was pointed at a closed address | Fixed: such an entry is applied once at the changeover and never kept or replayed |
| W-2 | Low, regression | A restore owed for a relay that runs again was dropped before the relay had started | Fixed: kept until the relay's record is written |
| W-3 | Low, regression | `sandbox remove --all` did not visit a container of which only an unfinished restore was left | Fixed |
| W-4 | Low, regression | Retrying a file that can never be replaced, for many files, on the event loop | Fixed: 150 ms, at most three failing files per start, off the event loop |
| W-5 | Low | `icacls /grant` adds to an entry whose revoke failed: a folder taken down from modify to read kept modify | Fixed: the entry is replaced (measured in a container) |
| W-7 | Info | The pipe's security descriptor was not freed when the first instance could not be created | Fixed |
| W-6, W-8, W-10 | Info | A failed revoke is listed as "folder missing"; the limit of 32 services per port is not in the configuration reference; a temporary file left by a crash is not collected | **Open** |

The fixes of this second review each have a test and were not reviewed by anyone else.

## 17. Addendum: folder permissions of the AppContainer backend (2026-11-13), 1.22.0

Found in use by the owner of the project, not by the reviews or the tests of section 16: on a folder whose
permissions the gateway's account may not change, the AppContainer backend recorded a grant it had not made.

**Cause.** `sandbox.grant` and `sandbox.revoke` ran `icacls ... /C` and trusted its exit code. `/C` ("continue on
errors") is there so that one locked file below a folder does not fail the folder; with it `icacls` exits 0 even
when it could not open the folder's access list at all. Every test of section 16 used folders made by the account
that ran the test, where changing permissions always works.

**Effect.** In the direction of less access for grants: the member's container did not get the folder (the agent
could not use a team folder, or could not start when the goose folder was concerned), the record and `sandbox
status` said it had, and the start never tried again. For revokes the direction is the other one: an entry that
could not be removed was recorded as removed. That needs a folder whose permissions the account could change when
the entry was made and not when it was to be taken off; then a member kept a folder that had been taken away, and
nothing showed it.

**Change (1.22.0).** The access list of the folder is read after every grant and revoke (`sandbox._aces`,
`allowed`, `exceeds`): a grant is recorded only when the container's entry is there and no wider than wanted, a
revoke only when the entry is gone; what could not be taken off stays on record (`pending`) and is shown as still
on the folder. A grant that an earlier version recorded without making is made at the next start. A folder that "ALL
APPLICATION PACKAGES" may read gets no entry. A folder that cannot be given is either left out with the agent
starting (logged, audited as `sandbox.grant.failed`, listed with its reason under the member's container by
`sandbox status`) or - the member's profile, the goose folder - fails the start, in both cases naming the folder,
the account and the command; the record is saved before the start fails. When an administrator takes a folder away
(team, folder or membership change) the entries no longer permitted are taken off at once in the background
(`api._sync_grants`, `sandbox.shrink`; audited as `sandbox.revoke`), not at the member's next start. One container's
folders and record are changed by one caller at a time.

**Independent review of this change (before release).** One High finding, in the first version of the fix itself:
an entry of the member's container that was on a folder but not on record was taken for an administrator's and
left alone for good. A record can be missing for ordinary reasons - a start that gave two folders and failed on a
third before saving - so a member would have kept a folder that was taken away (X-1). Now such an entry goes on
record as Goose Web's and is taken off when the folder is no longer wanted; the record is saved before a failure
is raised; `icacls` timing out is a failed change, not a crash. Also from that review: a change from modify to
read on a folder that could no longer be changed was recorded as read while modify stayed (X-2, fixed: "wider
than wanted" is a failure, the old entry stays on record); `check` failed, and with it an upgrade, over a Python
folder no agent needed or over the fallback backend (X-3, fixed: only the profiles root and the goose folder count,
for the configured backend); `install.ps1` stopped for a local account written as `.\name` (X-4, fixed; that form
had left the profiles root unrestricted before); `sandbox status` did not show what could not be given (X-5,
fixed); an administrator's change could create a container and give folders (X-6, fixed: it only takes entries
off). The fixes of that review each have a test; they were not reviewed again.

**Residual.**
- The fix for a program folder is an entry for "ALL APPLICATION PACKAGES": every application container of an
  account that can itself read the folder may then read it, as with `C:\Program Files`. The alternative - letting
  the gateway's account change the permissions of the programs it runs - is worse and is not recommended.
- `check` and `sandbox status` judge the folders for the account that runs them. Run by an administrator they say
  nothing about a service account; the gateway's own log does.
- The check reads the entry on the folder, not on every file below it; a file with protected permissions inside a
  granted folder stays closed to the container, as before.
- A member who is disabled keeps the entries until deleted or enabled and started; a container that is not running
  cannot use them.
- A member's agent that is starting at the very moment an administrator takes a folder away can be given the folder
  by that start, with the folder set of before the change; it then keeps it until it restarts (it is marked for a
  restart when idle). Taking away at once holds for agents that are running or stopped.
- An entry that 1.21.1 or earlier reported as removed without removing it is on no record. It is found only if the
  folder is given to that member again.
- Taken off at once: changes made through the administration pages. A team set at sign-in from a directory, changes
  made with the command line and changes to `sandbox.read_dirs` take effect at the member's next start.
- `check` cannot judge a team's extra folders or a service account it is not run as.
- Taking an entry off looks below the folder too (a subfolder whose inheritance was switched off kept a copy of the
  entry; found by the last review, true of every earlier version): up to 200,000 files and folders or 20 seconds.
  Beyond that it is logged that the folder was not looked through completely.
- The record is written when a start has finished with the folders. A gateway that is stopped in the middle leaves
  entries that are found again only when the folder is still wanted at the next start.
- A damaged record stops the member's start with the file named, instead of being replaced by an empty one.
- Seen while testing this, and true of section 16.2 as well: a container cannot list a folder it has no access to,
  but it can tell whether a path it guesses exists there - a missing file answers "not found", an existing one
  "access denied". Windows answers every process without access that way.

## 18. Addendum: a gateway nobody is signed in to (2026-11-14), 1.22.2

**What changed.** The AppContainer backend gives a member's container an entry on the window station and the
desktop the gateway runs on, where those do not let application packages in (`sandbox.admit`, called by
`sandbox.spawn`); takes it off when the container is deleted (`sandbox.dismiss`); starts the member's processes on
that window station and desktop by name when the gateway is not on the interactive window station; and tests the
whole at its start (`sandbox.selftest`). The team page of the admin SPA saves by itself and has switches that give
and take a provider (browser code only: it calls the same admin endpoints as before, with the same checks).

**Why.** Section 16 measured the backend from a signed-in session only. A gateway started at boot under a service
account sits on the window station of its own logon; a desktop there gives application packages read, list and
switch, and `user32` needs read and write objects to initialise. Every process of a member's container that loads
`user32` ended with `0xC0000142`. Measured on build 26100 with real containers on a desktop made for the purpose.

**What a container gets, and what it does not.**

| Object | Given to the member's container | Compared with a signed-in session |
|---|---|---|
| Window station of the gateway | `0x00020327`, only when neither the container nor an application-packages group is named there | Windows gives ALL APPLICATION PACKAGES the same on the interactive window station and on the non-interactive one of the same logon (build 26100) |
| Desktop of the gateway | `0x000200C7`: read objects, write objects, list, create window, create menu, read the access list - only when the desktop does not give the container read and write objects already | Windows gives ALL APPLICATION PACKAGES `0x000F00FF` on the desktop of a signed-in user: also hook control, journal record and playback, and the rights to change the access list, take ownership and delete. None of those are given here |

**Judged.**

- *Does a member reach more than before?* Where somebody is signed in: nothing changes. Under a gateway nobody is
  signed in to, the member's processes could not run at all before. They now share one desktop with the other
  members' containers and with the gateway's own processes, as they always have in a signed-in session. What one
  process may do to a window of another on a shared desktop is decided by Windows (integrity levels; a container
  runs at low integrity, the gateway and the administrator's own agent at medium), not by Goose Web. **Not
  measured:** whether a process in one member's container can reach a window that a process in another member's
  container created on that desktop. Goose shows no windows; a tool an agent starts might. The residual is the
  same in a signed-in session and is recorded here for the first time.
- *Can the entry be turned against the gateway?* The container cannot change or delete the desktop, switch it, or
  install hooks. It is given nothing on any other desktop or window station.
- *Can `dismiss` be made to remove something else?* It handles only a SID of the form of one container's own, and
  only an entry that `admit` added in the same process. This was a real defect of the first version (see below).
- *An object without an access list* is left without one: adding one entry would have shut everybody else out.
- *Two members starting at once*: read-add-write of an access list is under one lock.
- *Failure*: when the gateway account may not change an access list the start goes on, the log says so once per
  container, and the worker's error names `0xC0000142` and the self-test. Nothing fails open: a process that
  cannot use its desktop does not run.

**An incident while this was written (2026-11-14, about nine minutes).** `sandbox.remove` called the first
version of `dismiss` with the SID from the container's record. An existing test writes a record with the stand-in
SID `S-1-15-2-1`; running the tests therefore took the entries of ALL APPLICATION PACKAGES off the window station
and the Default desktop of the signed-in session of the development machine. The entries of ALL RESTRICTED
APPLICATION PACKAGES stayed, and a container process still started in that state (measured). Both access lists were
put back exactly as recorded before the change. Fixes: `dismiss` as described; `admit` refuses any SID that is not
one container's own; the test run fails when the window station or desktop it runs on is not left as it was.
Nothing of the first version was ever committed or deployed.

**Not verified.** A real boot task under a service account on an installation: the CI job "AppContainer as a boot
task" (Windows Server 2022 and 2025, a scheduled task of a local account that never signs in) is the first
measurement and reports without failing the run. The MXC backend under such a gateway. Windows versions other than
build 26100 for the access a desktop must give.

**Review.** One independent, read-only review of the sandbox part and the CI job of the first commit (findings
S-1 to S-16; it read the code and ran nothing, and ran out of turns before the tests and the worker's call). No
blocking finding; no path was found that removes or narrows anybody's access but one container's own, and the
Windows calls and structures were checked for 64-bit. Fixed before publication:

- S-1 (Medium): the self-test said "ok" when only the console program had run - `cmd.exe` starts exactly where a
  member's agent ends with `0xC0000142`. Without the program that uses its desktop there is no "ok" now.
- S-2: an access list that was not built is never written (it would have meant "everybody").
- S-4, in part: the window stations of Windows' own service accounts (SYSTEM, NETWORK SERVICE, LOCAL SERVICE) are
  never changed; a gateway there is told to run under an account of its own.
- S-6, S-7, S-9: each clean-up step of the self-test and of `dismiss` stands on its own and says when it fails; a
  folder grant that failed half-way is taken off.
- S-10: the test guard says when it could not read the access lists, and on a runner that is itself a service it
  does not count the entries the product makes by design.
- S-11, S-12: the CI script masks the account's password in the log, refuses to run outside GitHub Actions,
  checks `icacls`, and stops the task before it deletes the account.
- S-13, S-14, S-15: the SID test matches the whole string; nothing `admit` does can be the reason a start fails.

Open, recorded as residuals:

- **S-3 (Medium, design).** The entry on the window station (`0x00020327`) is what Windows gives application
  packages, not a measured minimum: it includes the clipboard, the global atom table and reading the screen, which
  everything on one window station shares. It is only added where the window station names no application packages
  at all; where Windows names them (build 26100, both kinds of window station) every container has the same from
  Windows, also in a signed-in session. The minimum could not be measured: an account that is not an
  administrator cannot make a window station that names no application packages.
- **S-4 (Medium, design).** All members' containers are let in on the gateway's own desktop. Besides the shared
  windows noted above, one member could use up that desktop's memory and make other agents fail to start. A
  desktop of its own per member, made by the gateway with only that member's container on it, would end both and
  leave the gateway's desktop untouched. Not done in this release.
- Low: S-5 (the lock is per process: two gateways in one logon could lose each other's entry, which the next
  start of that member puts back), S-8 (a gateway killed in the middle of the self-test leaves the throwaway
  container), S-16 (pytest is not pinned in CI, as in the existing job).

## 19. Addendum: the screen of a signed-in gateway account; Medium findings of the 2026-11-12 review (2026-11-14), 1.23.0

### 19.1 WS-1: a member's agent could read the screen, and with one backend the clipboard

**Found** while measuring section 18: on the window station of a signed-in user Windows names ALL APPLICATION
PACKAGES with `0x00020327`, which includes "read screen" and the clipboard. **Measured** (build 26100, real
containers, the product's own start for both backends; the container reports a hash of what it read, nothing of
the screen or clipboard is stored):

| Started as before 1.23.0 (`sandbox.desktop: shared`) | Screen | Clipboard text |
|---|---|---|
| AppContainer backend | read: the same pixels as the signed-in account | read: the same text |
| MXC backend | read: the same pixels | not read (MXC's own clipboard rule) |

So a member's agent - or whatever steers it - could copy what the administrator has on screen, on every
installation whose gateway account is signed in. It has been so since the sandbox exists.

**Changed.** Where the gateway is on the interactive window station, members' processes are started on a desktop
the gateway makes on the window station of its logon that nobody sits at (`sandbox.members_desktop`): the
AppContainer backend through `STARTUPINFO.lpDesktop` of the process, the MXC backend through that of the executor,
which the container inherits. The desktop names the gateway's account, SYSTEM and the application-packages groups
with what a program needs (`0x000200C7`, section 18) - MXC containers get a new SID at every start and cannot be
named one by one. If the desktop cannot be made, sandboxed workers do not start (fail closed); `sandbox.desktop:
shared` is the opt-out.

| Started as since 1.23.0 (`private`) | Screen | Clipboard text | Opening `WinSta0` from there |
|---|---|---|---|
| AppContainer backend | not read (no copy, a uniform area) | not read (another, empty clipboard) | access denied |
| MXC backend | not read | not read | access denied |

**Residual (High for an installation with members who are not trusted with the administrator's screen).** A
process in the container can start a process of its own with `lpDesktop = "WinSta0\Default"`; that one lands on
the interactive desktop and reads the screen (both backends) and the clipboard (AppContainer backend). Measured.
Looked at and not done: user-interface restrictions on the worker's job (they close the clipboard, not the screen,
and the MXC executor does not start under them); deny entries for the container on the interactive window station
(possible for the AppContainer backend, whose container keeps its SID; an MXC container has a new SID at every
start; and it means editing the access list of a person's live session for every start). **What closes it is the
deployment:** a gateway under an account nobody is signed in to has no screen and no clipboard of a person
(section 18; verified by CI for the AppContainer backend). ADMINISTRATION 11.3 says so.

**Judged.** The private desktop changes no access list that existed before; it creates one object the gateway
owns. Making it puts the gateway process on the other window station for one call and back, under the lock that
also guards `admit`; nothing else in the gateway uses windows. All members' containers share that desktop, as
they shared the interactive one (section 18, S-4).

### 19.2 Medium findings of the whole-product review of 2026-11-12

| Finding | Was | Now |
|---|---|---|
| B-8 | The sub-recipe check read any path a member with `allow_shell` named, with the gateway's rights, no size limit; the refusal quoted title and extensions of the file | Only a regular file of at most 1 MB inside the member's own folders (profile and allowed folders, links resolved); never a network or device path |
| A-2 | OIDC: no signature check of the identity token and no https requirement: an http issuer let somebody on the path sign in as anyone | Issuer and the authorization, token and user-info addresses must be https (or this machine itself); refused when saved and at sign-in; `allowInsecure` per provider opts in. The token is still not signature-checked: the TLS server check stands in (OIDC Core 3.1.3.7) |
| D-6 | A mistyped setting, or one set in the environment, was silent | Named in the gateway log at start and marked by `check` (the exit code of `check` is unchanged) |
| D-5 | A start-up failure under the task left no trace | `<system_dir>/logs/startup-error.log`, shown by `check`, removed by the next start that works |
| B-7 | One session record per client-named id, never dropped | Capped at 2000 per worker; idle ones that no tab shows and no request waits on go first, and what they had buffered leaves the gateway-wide count |
| D-3 | `upgrade.ps1` could skip the database backup and report it done | Paths come from the package; no database = the upgrade stops |

**Still open** from that review (Medium): B-2, B-3, B-5, B-6, D-2, D-8. From section 18: S-3, S-5, S-8, S-16; S-4
is not planned (a desktop per member was judged not worth its cost by the owner).

### 19.3 Review

One independent, read-only review of the first commit of 1.23.0 (findings T-1 to T-14; it ran nothing that
touches windows, and verified T-1 by running the line through Windows PowerShell). Blocking: two regressions and
one new Medium, all fixed before publication:

- **T-1 (regression).** `upgrade.ps1` asked the package with a line that held double quotes; Windows PowerShell
  5.1 drops them on the way to a program, so every upgrade would have stopped at its first step. No quotes now; a
  test runs the line through `powershell.exe`.
- **T-2 (regression).** The B-8 rule refused the sub-recipes of a recipe a team gave the member: those live in the
  team's folder, outside the profile. The member's team recipe folders count as hers.
- **T-3.** Dropping a session record (B-7) left its buffered bytes in the gateway-wide count, which a member could
  have used to make the gateway clear every user's buffers again and again.

Also fixed: T-5 (a handle given back on every failure path of the members' desktop), T-6 (two paths that could
have ended on the interactive desktop after an unlikely failure now refuse; a gateway that could not be put back
on its window station starts nothing more), T-7 (the window stations of Windows' own service accounts are never
used for members either), T-8 (`dismiss` looks at both places), T-9 (`spawn` refuses a desktop that is not the
gateway's), T-10 (`sandbox selftest` follows `sandbox.desktop`), T-11 in part (one open, the size judged on what
is read), T-12 (`check` names a refused provider; the opt-in can be ticked), T-13 (unknown names are shown, the
exit code of `check` is unchanged), T-14 (a gateway stopped with Ctrl+C is not a failed start; a start that works
removes the file), T-4 in part (a record a request still waits on is kept).

Open: T-4 (a tab that watches without limit keeps records without limit), T-11 (between the check of the folder
and the open, a path component could be swapped for a link - by somebody who can write there). The fixes were not
reviewed again.

### 19.4 1.23.1: the members' window station on Windows Server (2026-11-14)

1.23.0's CI failed: on the runners (Windows Server 2022 and 2025, a signed-in logon) the window station of the
logon that nobody sits at does not name the application-packages groups - on Windows 11 it does (`0x00020327`
each). `members_desktop(True)`, the MXC path, refused there, so no MXC member could start under a signed-in
gateway on Windows Server. Section 18's table said "the same on the interactive window station and on the
non-interactive one of the same logon (build 26100)": true for Windows 11, not for Windows Server 2025 of the
same build.

**Changed.** When an MXC container is to be started and the members' window station does not let application
packages in, ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION PACKAGES are given `0x00020327` there - what
Windows 11 gives them on that object. Judged: additive only (nothing is ever taken off); one object, the
non-interactive window station of the gateway's own logon, which has no screen; it ends with the logon. It gives
every application container of that account - not only Goose Web's - what Windows 11 gives it there. The
AppContainer backend keeps naming its container alone. A window station of SYSTEM, NETWORK SERVICE or LOCAL
SERVICE is refused before this point (19.3, T-7).

**Not verified.** A real MXC container on a window station where the entry was added by Goose Web. No independent
review of this change (about 20 lines).

## 20. Addendum: Windows Server devices; a team's guarded extension items (2026-11-16), 1.24.0

### 20.1 The NUL device and the mount manager

**Reported** from Windows Server 2022 (AppContainer backend, gateway at boot, Goose 1.59): a member's agent starts
but cannot start a program (`NUL` denied to the container, measured there), and Goose skips the member's hints
(a path it cannot make canonical; whether the mount manager is the cause is what the self-test asks).
**Measured on Windows 11 (build 26100):** `\\.\NUL` gives ALL APPLICATION PACKAGES and ALL RESTRICTED APPLICATION
PACKAGES `0x1201bf`, `\\.\MountPointManager` gives them `0x1200a0`, and a container does everything asked.
The access lists on Windows Server were not read before this release.

**Changed.** (1) The self-test asks and reports (no change of anything). (2) `goose-web sandbox devices grant`:
adds, for the two groups on the two devices, the entry Windows 11 has, where it is missing.

**Judged.** The grant needs an administrator - the gateway cannot do it and never tries. It is additive only and
uses the routine that never writes a list it did not build. It is machine-wide: every application container on
that server - not only Goose Web's - may then open NUL and ask the mount manager, as on every Windows 11. Neither
gives access to data: NUL holds nothing; the mount manager answers which drive letter a volume has. It lasts
until Windows restarts; a start-up task as SYSTEM that runs the product's own Python repeats it - the install
folder must then be writable by administrators only, which the installer sees to. An administrator who does not
want a machine-wide change leaves it, and members work without a shell tool and without hints.

**Not verified.** The grant itself, anywhere (it needs an administrator on a Windows Server); that it cures both
failures; the start-up task line. The CI job reports the first two for Windows Server 2022 and 2025.

### 20.2 A team's item for a guarded extension

Before, a team item for a shell-capable or extension-starting extension was never delivered. Now it is, when the
team's policy gives what `policy.extension_needs` asks for that extension (Shell; the extension manager also
"edit extensions"). Judged: a member with Shell can already run any program, so the extension gives nothing the
permission did not; without the permission nothing changes (the key stays pinned off). The item going, or the
permission going, switches the extension off in the member's profile - it is not taken out, because Goose turns
a bundled extension on when its key is missing. The team page and `check` say when an item is not delivered.

No independent review of this release.

### 20.3 1.24.1: the grant at every start of Windows

**Measured for 20.1** by the CI run of 1.24.0 (an administrator on Windows Server 2022 and 2025): both devices
keep application containers out; the grant works on a device object and a program in a container can then open
NUL and get a real path.

**Changed.** `scripts/register-devices-task.ps1` registers a start-up task, as SYSTEM, that runs
`scripts/grant-devices.ps1`.

**Judged - the question is what SYSTEM runs.** Goose Web's own folder and its Python are, in the ordinary
installation, writable by the account that installed it, which is not an administrator: a SYSTEM task that ran
`python -m goose_web ...` from there would be a way from that account to SYSTEM. So the task runs Windows
PowerShell from System32 with one script file that uses nothing but Windows (four Windows calls and .NET), and
that file is a copy in `<ProgramData>\GooseWeb`: the folder must be a plain folder (a link is refused), is given
to the Administrators, and its access list is replaced by SYSTEM and Administrators only, nothing inherited; the
copy is made new (never written through what was there), compared with the original by hash, and its own access
list is checked before the task is registered. The script only ever adds the two entries Windows 11 has; it has
no way to take anything off. The administration guide warns against a task that runs Goose Web's Python as SYSTEM.

**Not verified.** The task on a Windows Server and after a real restart; a machine that allows only signed
scripts (the task then fails and the script says what to do instead). No independent review.

**Corrected 2026-11-19 (section 21.8, S-1 and S-2).** Two things in this judgement were wrong. The folder: a
folder in `<ProgramData>` can be created beforehand by any account of the machine, which then owns it, and the
script used a folder that was already there - "is given to the Administrators" does not help against a handle
that was opened before. And "nothing of Goose Web's own folder runs as SYSTEM": the copy is made from the install
folder by a script that is itself run elevated from the install folder, so whoever can change that folder
decides what SYSTEM runs - once, at registration, but that is enough. 1.25.0 changes the first and says the
second.

### 20.4 1.24.2: what CI measured for the start-up task

By the CI run of 1.24.1, as an administrator on Windows Server 2022 and 2025: the script is copied to a folder
only SYSTEM and Administrators can write, the task is registered, runs as SYSTEM and ends with 0; the grant
script, run by an administrator, opens both devices to application containers. Not measured by that run: the task
opening devices that are still closed (they had been opened before it ran). 1.24.2 changes the CI job so that
this is what its last step sees on Windows Server 2022. No change of the product; nothing new to judge. Still
not verified: a real restart; a machine that allows only signed scripts.

## 21. Addendum: 1.25.0 (2026-11-19) - read-only folders, uploads, the sign-in lifetime, team provider aliases

Requested by the owner; built as specs 031-033 and one fix record. Assessed with the working tree that became
the release: the test suites on Python 3.13 (real Goose, real MXC) and 3.11, a headless browser against a gateway
running the tree (an administrator and a member, desktop and phone), and one independent read-only review (21.6).

### 21.1 Folders a team may only read (`read_roots`)

**What is promised.** A member - in the file browser, by an upload, and through the member's agent - can read a
read-only folder and cannot create, change, rename or delete anything in it.

| Path | Control | Verified by |
|---|---|---|
| File API writes (`fs/mkdir`, `fs/upload`) | `context.path_ok(write=True)`: inside the writable roots, as written AND with links resolved | `test_file_api_reads_but_does_not_write_...`: 403 `read_only_folder`, nothing created; a `Web_Uploads` junction into the read-only folder and one to outside are refused |
| File API reads | allowed in both kinds of root | same test |
| The agent, MXC backend | the folder is in the container's `readonlyPaths` | `test_mxc_reads_a_read_only_folder_and_cannot_write_it`: a Python in a real container reads and lists; create, append, delete, rename, mkdir, a write below, and a child process writing all fail; the folder is unchanged |
| The agent, AppContainer backend | a Read & execute entry for the container | `test_appcontainer_reads_a_read_only_folder_and_cannot_write_it` (real container, `cmd.exe`) |
| A folder switched from writable to read-only | AppContainer: `sandbox.shrink` replaces the Modify entry by a read entry at once; the next start does the same | `test_appcontainer_a_folder_switched_...`: after the switch a program in the container cannot write, also not a file it made while the folder was writable |
| Two lists that meet | read-only wins (`policy._split_roots`): a folder in both lists, or a writable folder containing a read-only one, is only read; refused at saving for a team and for one person's overrides | `test_read_only_wins_where_the_lists_meet`, `test_admin_api_refuses_a_nested_read_only_folder_and_checks_overrides` |
| Folders that must not be shared at all (C-11) | `read_roots` goes through `folder_grant_problem` like `allowed_roots` | `test_a_read_only_folder_cannot_lie_inside_a_writable_one` |

**Residual, stated.**
- *MXC, a running agent.* A container's folders are fixed when it starts. After a switch to read-only (or after
  a folder is taken away) an agent that is in a run keeps what it started with until the run has finished; the
  gateway restarts it then. The file API refuses at once. The team page names the members concerned; an
  administrator can restart the agent at once. Not closable from outside the container.
- *Sandbox off.* The agent then runs as the gateway's Windows account; only the gateway's own file API is held to
  read-only. The team page warns. (Unchanged: without the sandbox a member's agent is not confined at all.)
- *Reading is not confidentiality between members:* every member of the team reads the folder; that is its purpose.
- *Administrators* are not restricted by folders (unchanged).

### 21.2 Uploads: `<chat folder>\Web_Uploads`

The server appends the folder name; the page cannot choose where a file lands inside the chat folder. The write
check runs on the resolved `<dir>\Web_Uploads` (the gateway is not sandboxed, so this check is the guard against
a link of that name), before the body is read and again right before each file is created (21.6, R-5). Files are
created exclusively (never overwritten); names are sanitised as before; hint-file names and `.agents` folders are
refused as before. A refusal writes nothing. Images, which were sent inline only, are now written too: an image
attached to a chat exists as a file in the chat folder.

### 21.3 Sign-ins: eight hours, no persistent sign-in

> Superseded in 1.27.0 by 23.3: "Keep me signed in" is back, capped at 24 hours.

**Threat.** A copied sign-in cookie is a working sign-in for as long as it lives, and this product starts
programs for whoever is signed in. Before: 30 days when "Keep me signed in" was ticked (it was, by default), kept
on disk by the browser; 12 hours otherwise, up to 720 by an administrator's setting. An installation in use
therefore collects sign-ins that are good for weeks on devices nobody uses any more.

**Now.** One lifetime, 1 to 8 hours, fixed at sign-in and never extended (`auth.SESSION_HOURS_MAX`); no
persistent sign-in; a session cookie; sign-ins stored by an earlier version are cut at start-up
(`clamp_sessions`) - the upgrade signs everybody out; an open socket is closed within 30 seconds of its sign-in
ending (measured in the browser: the tab is at the sign-in page). Optional idle limit, off by default.

**Checked against** the OWASP Session Management Cheat Sheet, ASVS V3 and NIST SP 800-63B (AAL2: re-authentication
every 12 hours at most, 30 minutes of inactivity): absolute lifetime - yes, stricter; inactivity - available, off
by default (below); no persistent sign-in - yes; cookie attributes - HttpOnly, SameSite=Strict, Secure and the
`__Host-` prefix over https; token stored as a hash; a new token at every sign-in, the others ended on password
change, reset and disable; sign-out ends the token on the server; a CSRF token per sign-in on every write.

**Decisions left to the owner, stated.**
- *The idle limit is off by default.* An open tab counts as use (the tab's connection is re-checked every 30
  seconds and that marks the sign-in as used; chatting goes over that connection). So the limit ends forgotten
  sign-ins, not an unattended open browser - measuring a person's own activity would need the browser to report
  it, and whoever holds the cookie could report it too. With a limit set, a phone that has been in a pocket for
  longer signs in again. Recommended where devices are shared: 30 to 60 minutes.
- *API tokens* (Settings > Account) can still be created without an expiry. Not changed in this release.
- *Not done:* tying a sign-in to an address or a browser name (phones change address; whoever copies a cookie
  copies the browser name).

### 21.4 Provider aliases for a team (`provider_groups`)

A display rule. The value is cleaned by the function that cleans a person's own groups (size limits, ids, one
group per provider) and travels in the member's policy. Names, prefixes and model names reach the page only as
text nodes and option labels (`ui.h`), never as HTML. Choosing an alias entry sets the real provider, then the
real model, through the calls that existed; the allowed lists are checked on the real ids by the gateway
(`policy.check`), so an alias cannot make a chat use what the policy does not allow. A member cannot change the
team's aliases: they are not in the member's preferences, and the member's own groups cannot take a provider out
of a team alias.

The team page's provider switch: for a provider of the administrator's own profile it creates the team's copy
(definition and key, as the library item always did) and allows it; for other providers it only allows - no key
of the administrator's own account is handed out by a switch that says "allow".

### 21.5 Fixes

- Home page on a phone: the menu button was covered by the page content (CSS). No security bearing.
- A steer shown twice: one message was sent; the tab made a second bubble when Goose's echo came before the
  answer to the call. Two paths that could really have sent a message twice are closed with it: a steer Goose had
  already echoed was queued again when its call failed, and a steer whose connection dropped in flight was queued
  and sent again by itself (it now waits for the person).
- Team items: an extension that starts a program is not delivered without the Shell permission (unchanged, by
  design); the page now says so, and marks an item whose source is gone.
- One person's policy overrides: the folder lists were stored unchecked (an administrator's own typing only);
  they now pass the rules of a team's lists.

### 21.6 Independent review of the working tree (2026-11-19, read-only, by reading)

| # | Severity | Finding | Outcome |
|---|---|---|---|
| R-1 | Medium | The idle limit would have ended the sign-in of somebody chatting: `last_seen` was written by requests only, and chatting goes over the socket | Fixed: the socket's 30-second re-check goes through `auth.session_alive`, which marks the sign-in as used. Test `test_an_open_tab_counts_as_use` |
| R-2 | Medium | A folder switched to read-only was not narrowed for a running agent (AppContainer: "a changed right is the next start's business") | Fixed for AppContainer: `sandbox.shrink` narrows at once (tested in a real container). MXC cannot be narrowed from outside: stated in 21.1; the page names the members |
| R-3 | Low/Medium | The nesting rule was checked only on the side being saved; overrides and a team's lists could meet so that a "read-only" folder was writable | Fixed at use: read-only wins (`policy._split_roots`); also checked when overrides are saved |
| R-4 | Low | A new team's own folder was not in the nesting check | Fixed: checked once the team has its id |
| R-5 | Low | The upload folder was checked before the body was read, not when the file was made | Fixed: checked again right before each file. A race inside that instant remains in theory; it needs somebody who can create a link in a folder they may write to a place they may not, which an application container is not expected to be able to do - not measured |
| R-6 | Low | Two tabs steering the same words into one chat at the same moment: one bubble can stand for both | Open, cosmetic: nothing is lost, a reload shows both |
| R-7 | Low | Documents and version still described 1.24.2 | Done with this release |
| R-8 | Note | Images are now written to disk | Intended (21.2); in the changelog and the guides |
| R-9 | Note | A real service's name as an example in the page and a test | Replaced by a neutral one before the commit |
| R-10 | Note | The team page: a pane drawn again could save over what a switch had just stored; folder rows were saved while being typed | Fixed: an old pane never saves, a path is taken when its field is left |

The reviewer read; it ran nothing. What it marked as not checked: API tokens, LDAP/OIDC internals, three
front-end files line by line, and the cost of looking up an item's source.

### 21.7 Audit of the whole product, 2026-11-19 (summary)

Mechanical: all 64 routes ask for an identity except the seven that must be open (health, sign-in, sign-in
configuration, sign-out, the two OIDC steps, the second-factor step); all 37 `/api/admin` routes ask for an
administrator. `pip-audit`: no known vulnerabilities. Functional: 116 page loads (every page and every Settings
and Admin section, as an administrator and as a member, desktop and phone) without a script error, a failed
request or a dead menu button after the fixes of this release; chat, stop, queue, steer, an ended sign-in and
sign-out in the browser.

Still open from earlier reviews, unchanged by this release: B-2, B-3, B-5, B-6 (a worker's life cycle), D-2 (no
rollback in `upgrade.ps1`), D-8 (the build backend is not hash-locked); Low: S-3, S-5, S-8, S-16, T-4, T-11, R-6.
Not verified by anybody: OIDC against a real provider; a Windows Server restart with the devices task; MXC under
a gateway nobody is signed in to; Goose 1.59 with this release.

### 21.8 Second independent review: what nobody but the author had read (2026-11-19, read-only, by reading)

Scope: the changes from the last reviewed commit to 1.24.2 (the self-test's limits, the device grant, the start-up
task and its two scripts, the upgrade script's search for uv, the sub-recipe check, session pruning, guarded
extension items), and the browser code as a whole by sink.

| # | Severity | Finding | Outcome |
|---|---|---|---|
| S-1 | High | **Published in 1.24.1 and 1.24.2.** `register-devices-task.ps1` put the script that SYSTEM runs at every start into `<ProgramData>\GooseWeb` and used a folder of that name that was already there. Any account of the machine can create that folder first and owns it then; a handle it keeps open with the right to change the access list outlasts the script's new access list, and a folder swapped for a link between two steps sends the access list and the copy elsewhere. Either way that account decides what SYSTEM runs. Measured here: `<ProgramData>` lets ordinary accounts create folders (`BUILTIN\Users:(CI)(WD,AD,WEA,WA)`), `<Program Files>` does not. Not measured: the attack itself | Fixed: the copy lives in `<Program Files>\GooseWeb.Startup`; a new folder is made WITH its access list (no moment with another one); a folder that is already there is used only when nobody but SYSTEM, the Administrators and Windows' installer owns it or can change it; the old copy is removed. Who can pull it: an account of the machine that is not an administrator - the gateway's own account included; not a member's sandboxed agent, which cannot write to ProgramData. **An installation that registered the task with 1.24.1 or 1.24.2 should run the new script and restart Windows** (ADMINISTRATION 11.6) |
| S-2 | High (where the install folder is writable by an account that is no administrator) | The copy is made from the install folder, and the script is run elevated from the install folder. The hash check compared the copy with that same file. So an account that can change the install folder decides what runs elevated at once and as SYSTEM afterwards - against what 20.3 said | The script now looks at the two files, their folder and the folder above and stops when anybody but SYSTEM, the Administrators, Windows' installer and the caller can change them (`-TrustSource` to go on); it prints the SHA-256 of what it installed. This helps against an honest mistake, not against somebody who has already changed the script - which is why the guide now says where the two files must come from. The same holds for everything an administrator runs elevated out of the install folder; `install.ps1` leaves that folder writable by administrators and the installing account only, and `check` says when it is not so |
| S-3 | Low | `upgrade.ps1` also took `uv.exe` from the folder of the goose binary, which can be writable by accounts with fewer rights than whoever runs the upgrade | That place is not searched any more |
| S-4 | Low | The build backend is fetched unpinned at every upgrade | Open (it is D-8 of the 2026-11-12 review) |
| S-5 | Low | A sub-recipe's path was judged and then opened by name; a link put in between made the gateway read up to 1 MB of YAML outside the member's folders (what leaks: a title and an extension name in the refusal) | Fixed: where the open really ended is asked of the open file (`security.final_path`); elsewhere = not read |
| S-6 | Low | A team item stored under another key whose entry is a bundled shell-capable extension (`{type: builtin, name: developer}`) was delivered, switched on, to a team without the Shell permission. Only an administrator can make such an item | Fixed: delivery, switching off and the team page's warning go by the name in the entry as well |
| S-7 | Low | With the Shell permission still given, taking a guarded item away from a team switches the extension off for good | Intended: taking the item away takes the extension away; giving it again brings it back |
| S-8 | Low | A prompt for a made-up session id made a state that counted as watched for as long as the socket lived, past the cap | Fixed: a prompt Goose refuses for a session it never loaded here is not watched |
| S-9 | Note | The members' window station gives all members' agents one clipboard (it is S-3 of the 2026-11-14 review, open); `sandbox.grant_devices` merges the entry where the script adds one - "only ever adds" is exact for the script; the grant script compiles four Windows declarations as SYSTEM in the system's temporary folder at each start; under PowerShell 7 the registration stopped at the first access-list call | The script now says at once that it needs Windows PowerShell; the rest stands as described |
| F-1 | Low | A sign-in that ended by itself left folders, pinned chats and provider lists in the browser's storage for the next person (signing out cleared them) | Fixed: both ways clear the same |
| F-2 | Low | Markdown: only an image's address was held to this site; `video`, `audio`, `source`, `track`, `poster` and `background` passed the sanitiser, so only the Content-Security-Policy stood between a model's text and a request to an address of its choosing | Fixed: those elements and attributes are removed |
| F-3 | Note | A link `#/new?cwd=..&recipe=..` in a message prefills the New chat page; an image address on this site makes a signed-in request | Stands: nothing is started without the person |
| F-4 | Note | A link with `?profile=` puts an administrator's tab on another profile without asking (audited) | Stands |
| F-5 | Note | A grid app can open an http(s) or mailto link without asking, and its frame may send what it is given anywhere (its origin is opaque) | By design of the apps bridge; stated |

Found sound by that review (by reading): the Content-Security-Policy has no inline script and no eval; `innerHTML`
is used for constants, sanitised markdown and highlighted flat text only; `ui.h` drops `javascript:` and `data:`
addresses; app frames are sandboxed without same-origin and the bridge checks the sender; downloads are served as
attachments; the CSRF token is in memory only and no secret is in the browser's storage; there is no "next"
parameter at sign-in; the service worker caches the shell only; a socket needs an allowed origin; both device
names are fixed and the rights given carry no delete, no change of access list and no write to the mount manager
(the last assumed from the Windows header, not measured); the task runs Windows PowerShell by its full path with
`-NoProfile`; a failure to make the members' desktop stops the start instead of using the interactive desktop.

Not verified by anybody: the new registration on a Windows Server (the CI job of this release registers it, runs
it as SYSTEM and reports the owners and access lists Windows gives the task folder, the task and the copy's
folder); what Task Scheduler lets an account do with a task folder it created itself; a real restart; a machine
that allows only signed scripts.

## 22. Addendum: 1.26.0 (2026-11-20) - host tools, runtimes for sandboxed members, the Schedules switch

Requested by the owner: members whose agents run in the sandbox should use house extensions that need something
outside it - a credential from the owner's password store, a service on the LAN, a program on the host - with the
same credential the owner uses, nothing per member to maintain, and the sandbox as strict as before. Assessed before
building (options, threat model, decision), built as specs 035 and 036 and one fix record, measured with the real
Goose 1.57 and real MXC containers, and reviewed independently before release (22.4).

### 22.1 Host tools (spec 035)

**What is new.** A host tool is a stdio MCP server that the gateway runs outside every sandbox, as its own account,
and lends to the members of teams that have it - only the tools the administrator lists. Defined in `config.yaml`
only; a team gets it with a switch. A member's Goose reaches it as an HTTP extension at
`http://<name>.goose-web.invalid/mcp` through the member's egress proxy.

**Why not the alternatives.** Putting the credential into the member's environment or profile at each start was
rejected: with Shell, the member's agent reads its own environment and profile. Copying a per-member key (what a
library item does with `env_keys`) adds keys to maintain and puts them where the agent reads them. Opening the LAN
(`internet+lan`) or relaying a whole service is broader than one extension needs.

| Threat | Control | Verified by |
|---|---|---|
| A credential readable by the member's agent | None enters the sandbox: the server uses the owner's own credential store on the host; the member's profile gets an HTTP entry without command, key or folder | `test_provisioning_delivers_an_http_extension_only_on_mxc` |
| Spoofed member, another member's session | Identity only from the per-start proxy credential (407 otherwise, also after revocation); sessions bound to member and host tool; one process per member and host tool | `test_through_the_members_egress_proxy`, `test_who_may_use_it_is_checked_at_every_request` |
| Revoked access still working | Every request re-checks the team's items, the account and the definition; the sweep stops withdrawn servers | same |
| The protocol beyond tools (resources, prompts, sampling, roots) | Deny by default; `initialize` from the gateway's own handshake (tools capability only); server requests answered with an error; `_meta` and progress tokens not forwarded | `test_member_gets_only_the_lent_tools` |
| A lent tool steered to the host (confused deputy) | Only listed tools are listed or callable; the team page flags lent tools whose parameters name a path, file, URL or command; ADMINISTRATION 11.9 says never to lend those | `test_member_gets_only_the_lent_tools` (a `read_file` tool offered by the server is refused) |
| Code of other accounts run as the gateway | A server whose program, scripts, interpreter or path variables lie in a folder broad groups can change, or below one they can rename or re-permission, does not start; checked at load, every minute and before each start | `test_program_folder_checks_reach_ancestors_arguments_and_path_variables`, `test_the_folder_check_is_repeated_at_every_start` |
| A new listening port | None: the name exists only inside the members' proxies | by construction (egress.py) |
| The gateway frozen or starved by a server | Own reader and writer threads per server, bounded queue, write deadline, kill-first stop; JSON parsed and encoded off the event loop; limits per member and host tool | `test_a_server_that_stops_reading_never_blocks_the_gateway` |
| Floods of requests or log lines | Requests per minute per member and host tool; per-member audit limiter (summaries) | `test_requests_are_limited_and_refusals_summarised` |
| Goose's own behaviour with such a server | Real goose 1.57 through a real egress proxy: `server/discover` -> "method not found" -> `initialize` -> `tools/list` | `test_real_goose_through_the_egress_proxy` |

### 22.2 Runtimes for sandboxed members (spec 036)

The goose CLI folder and `sandbox.read_dirs` come first on a sandboxed member's `PATH`; uv there never downloads a
Python and copies instead of linking. No new rights: those folders were already granted read and execute. Measured
in an MXC container: with a Python granted read-only, `uvx duckduckgo-mcp-server` installs and runs and `uvx ddgs`
searches through the proxy; Goose's Node 22.14 `fetch` ignores the proxy (Node 22.21+ and 24+ honour
`NODE_USE_ENV_PROXY`, which Goose Web sets). `goose-web check` reports the runtimes and does not run one that broad
groups can change.

### 22.3 The Schedules switch (FIX `scheduler-needs-schedules`, Medium)

A team with Shell on and Schedules off still gave its members' agents Goose's `scheduler` tool (seen live), and every
isolated worker ran Goose's scheduler, which also runs a job an agent with Shell writes into `data/schedule.json` of
its own profile. Now `scheduler` needs Shell and Schedules (pinned off, direct calls refused, recipes and session
extensions checked), and a member's worker starts Goose's scheduler only with Schedules. Tests:
`tests/test_scheduler_permission.py`.

### 22.4 Independent review of the working tree (2026-11-20, read-only, before release)

| ID | Severity | Finding | Status |
|---|---|---|---|
| HT-1 | High | Writes to a server's stdin ran in the gateway's default thread pool and `stop()` closed stdin on the event loop: a server that stops reading could freeze the gateway and exhaust the pool | Fixed: one writer thread per server with a bounded queue, a write deadline (the sweep stops the server), a stop that kills first and never waits on a pipe |
| HT-2 | Medium | Large server messages parsed and answers encoded on the event loop; process start on the loop | Fixed: parsed and encoded in the reader thread; messages above 8 MB dropped; start in a thread |
| HT-3 | Medium | Refusals audited without a limit; no request limit beyond tool calls | Fixed: per-member audit limiter with summaries; requests per minute per member and host tool |
| HT-4 | Low | Limits reset when a server restarted; crashes did not count toward the start back-off | Fixed: counters kept per member and host tool; a crash counts as a failure |
| HT-5 | Low | The member's `_meta` was passed to the server | Fixed: name and arguments only |
| HT-6 | Low | The folder check missed ancestors, `--x=<path>` arguments, path variables, `node_modules`; ran only at load | Fixed, except: a `node_modules` folder another account creates later above the program, what a `.cmd` wrapper calls, and modules a server imports from its working folder (gateway-owned) |
| HT-7 | Low | A lent tool that writes files could plant programs in the server's working folder | Mitigated: `NoDefaultCurrentDirectoryInExePath=1`, own `TEMP`; a tool that writes files is not to be lent (11.9) |
| HT-8 | Low | A cancellation skipped the authorisation and the host tool of the session | Fixed |
| HT-9 | Low | No overall deadline for a request body; no lingering close for early answers | Fixed |
| HT-10 | Low | A server could start just after the member's agent stopped and live until the idle sweep | Fixed: a per-member generation checked after the start |
| HT-11 | Note | Servers share the gateway account's user profile between members | `TEMP` per member; the profile is kept (servers find their credential stores there); stated in 11.9 |
| HT-12 | Note | One error log per host tool for all members; notification parameters logged at debug level | Fixed: a log per member; nothing of a notification logged |
| HT-13 | Note | 403 for a host-tool name the gateway cannot serve would start Goose's OAuth attempt | Fixed: 400 (invalid name) and 502 (no host tools) |
| RT-1 | Low | Refused `read_dirs` put first on PATH | Not the case: `path_dirs` is built from the accepted folders only (tested) |
| RT-2 | Low | `check` ran `python --version` / `node --version` from `read_dirs` | Fixed: not run when broad groups can change the folder or file |
| RT-3 | Note | A tool folder first on PATH replaces Windows tools of the same name for members | Stated in 11.6 |
| SC-1 | Medium (if confirmed) | A `register` call without the permission would switch the scheduler back on | Not the case today (all callers pass it); hardened: no value keeps the current one |
| SC-2 | Note | A running worker keeps its scheduler until it restarts, which happens when no run is active | Accepted |

### 22.4b Second independent review: the fixes of 22.4 (2026-11-20, read-only, before release)

| ID | Severity | Finding | Status |
|---|---|---|---|
| R2-1 | Medium | Node looks for a module it does not find in every `node_modules` up to the root of the drive, and every account may create `C:\node_modules`; a Python reads `pyvenv.cfg` next to it and one folder up | Fixed: the check goes up to the root; for a Node program every folder above it where broad groups may create a sub-folder must already hold a `node_modules` only administrators can change (the gateway refuses to start the server and says so); for a Python the folder above its folder is checked as well |
| R2-2 | Medium | The server inherited the gateway's `PATH` and interpreter variables (`NODE_OPTIONS`, `PYTHONPATH`, ...) unchecked | Fixed: those variables are not passed on (a definition that sets one has it checked); `PATH` keeps only existing folders no broad group can change, own or replace |
| R2-3 | Low-Medium | Owners, links, conditional entries and unreadable permissions were not considered | Fixed: a folder owned by an account other than SYSTEM, Administrators, TrustedInstaller or the gateway's own refuses; paths are checked as written and resolved; conditional allow entries count; permissions that cannot be read refuse (fail closed); `{service_dir}` no longer hides the rest of a value |
| R2-4 | Low | A stop could run in two threads at once | Fixed: once, behind a lock; the reader thread asks the event loop to stop |
| R2-5 | Low | A writer thread that died left calls waiting until their time-out | Fixed: the server counts as ended |
| R2-6 | Low | A server could start a process before it was put into its jobs | Fixed: created suspended, put into both kill-on-close jobs (or not started at all), then resumed |
| R2-7 | Low | A start cancelled while running left the server behind | Fixed |
| R2-8 | Low | The generation of HT-10 was read late | Fixed: read when the request arrives |
| R2-9 | Low | Names nobody defined created counters | Fixed: refused before any counter, session or database lookup |
| R2-10 | Low | Very large or deeply nested messages | Messages above 4 MB dropped; an unreadable message no longer ends the reader |
| R2-11 | Low | A start could hold its lock for a long time | Fixed: 120 s for a whole start, 150 s for waiting on another one |
| R2-12 | Low | The error log grows while the server runs | Covered by the log budget of 15 (`logs\**`) |
| R2-13 | Note | Two members on one service folder if their names mapped to one | Not the case: user names are already valid folder names (`safe_name` validates, it does not change) |
| R2-14 | Note | Server-side ids restarted with every process | Fixed: unique in the gateway |
| R2-15 | Low | A new member worker registered without the permission got the scheduler | Fixed: it gets none unless told (all callers tell) |
| R2-16 | Note | Tool names from the server shown on the admin page | Names that are not plain tool names are not shown; the page puts all text in as text (`ui.h`) |

Measured on the owner's machine before release, with the code of this release outside the live gateway: the owner's
own index-search server and budget server, lent as host tools (2 and 39 tools), answered their read tools through
the real broker - the budget server with the owner's own credential from his password store, nothing copied - while
the write tools that were not lent and the attachment tool (a file path) were refused.

### 22.5 Residual risks

- A lent tool acts outside the sandbox with the gateway account's rights. The control is the administrator's choice
  of tools; the page flags suspicious parameters, the guide says what never to lend.
- Host tools reach members on the MXC backend only.
- A server's own audit records the gateway's account; who asked is in the activity log (`sandbox.hosttool`).
- The registry exposure of 16.3 is unchanged.

### 22.6 The stdio start-up guard (1.26.1, FIX `member-stdio-start-hang`)

What it is: `goose_web/stdio_guard.py`, written into each isolated member's profile (`.goose-web/stdio_guard.py`) and
run on the members' Python (`sandbox.read_dirs`) in front of every stdio extension a team gives its members. It
answers Goose's `server/discover` with "method not found" and passes every other message on unchanged; a server that
does not answer `initialize` within `sandbox.extension_start_seconds` is ended (job object) and Goose gets an error.

- **No new reach.** It runs inside the member's sandbox, as part of the member's own agent, with the member's rights;
  no grant, relay, port or network path is added. Stdio extensions already need `allow_shell`, which is unchanged.
- **In the member's writable profile.** A member (or the member's agent) can change the file; that only changes what
  runs in that member's own sandbox, which Shell allows anyway. Provisioning rewrites it whenever it differs. A link
  (junction, symbolic link) at `.goose-web` or at the file makes provisioning skip the guard rather than write
  through it.
- **Nothing leaves the profile.** `export_item` removes the guard from an entry before it becomes a team item, so a
  member's path never reaches a team library or another member.
- **Falls back to the old behaviour, never closed:** without a members' Python, with the setting 0, or when the file
  cannot be written, entries start directly as before 1.26.1 (`check` says so).
- **Residual:** a member's own stdio extensions and per-session MCP servers are not guarded; a server that accepts
  only the 2026-07-28 handshake fails at once instead of hanging.
- **1.26.2 (FIX `stdio-guard-orphans`):** the live check of 1.26.1 found a server started through `uvx` surviving the
  guard's time-out (its child had started before the guard put it into the job) and keeping the member's chat
  waiting through the stderr it had inherited. The server now starts suspended and joins the kill-on-close job before
  it runs (the job allows no breakaway, so ending it ends the whole tree), and has its own stderr pipe (forwarded by
  the guard, at most 64 KiB per line). Only when the job cannot be used does the guard look for the server's
  descendants by process snapshot: by parent link, each created after its parent, a process id that is now alive as
  another process (or cannot be examined) not followed, each one checked again through the handle that ends it.
  Residual of that fallback: a parent that has ended and whose id was reused by a process that has also ended could
  have that process's children taken for its own - possible only without the job, and only within the guard's
  member's sandbox. The guard still runs with the member's rights inside the member's sandbox; nothing else changes.

### 22.7 Socket pairs through the egress proxy (1.26.2, FIX `mxc-asyncio-socketpair`)

Why: on Windows `socket.socketpair()` is a TCP connection to a listener on 127.0.0.1 - the wake-up channel of every
asyncio, anyio and trio event loop. An MXC member's container may connect to no loopback address but its egress proxy
(the policy is "egress deny" with `runtimeConfig.networkProxy`; MXC refuses allow rules next to a runtime proxy, and
AF_UNIX sockets are denied in the container - measured), so every asyncio program, every Python MCP server, hung.

What it is: the member's egress proxy answers `CONNECT <32 hex digits>.pair.goose-web.invalid:<port>`: two requests
with the same token are both answered `200` and joined to each other. Goose Web writes `sitecustomize.py`
(`goose_web/sandbox_sitecustomize.py`) into the member's profile (`.goose-web/python`), puts that folder first on the
member's `PYTHONPATH` and sets `GOOSE_WEB_SOCKETPAIR=proxy`; `socket.socketpair()` for stream sockets then asks the
proxy, with the proxy credential MXC already gives the container (`HTTP_PROXY`).

- **No new reach.** A pair joins two connections that both carry this member's proxy credential; each member has
  its own proxy, so no other member's connection can be joined; tokens are 128-bit random and live at most 10 s
  unmatched. Nothing is looked up, connected or forwarded - the host's loopback services (other ports on 127.0.0.1,
  the native worker, a browser's DevTools port) stay unreachable, and the MXC policy is unchanged. Bytes between the
  two halves never leave the gateway process.
- **Not egress, so not audited** as `sandbox.egress` (nothing leaves the machine); the proxy counts pairs
  (Admin > System, proxy `pairs` / `pairConnections`).
- **Resources:** pair connections are exempt from `proxy_max_connections` (also accepted when it is reached) and from
  the idle time-out (an event loop's channel lives as long as its process), and limited on their own: at most 64
  unmatched requests (`504` after 10 s) and 256 open pair connections per member (`503` beyond, answered without
  lingering), and each direction of a pair carries at most 64 KiB/s (burst 256 KiB) - a wake-up channel needs a few
  bytes, so pairs cannot be used to load the gateway's event loop, which serves every member. Pairs end with their
  proxy (closed connections are aborted); refusals are counted (`pairRefused`) and logged at most once a minute per
  member, not audited.
- **The sitecustomize** is in the member's writable profile, like the start-up guard (22.6): changing it only changes
  the member's own processes. It is rewritten when it differs, and anything else placed in its folder - which is first
  on the member's `PYTHONPATH`, ahead of the standard library - is removed (a link itself, never what it points to).
  A link at the folder or the file makes Goose Web skip it; that the gateway never writes through a link also rests on
  members being unable to create links there (MXC and AppContainer processes cannot create junctions to places they
  may not write - measured, 11.6). The proxy credential is only sent to a proxy on loopback. A `sitecustomize` further
  along the path still runs, once. Without the switch, or with `sandbox.python_socketpair: false`, Python keeps its
  own `socketpair()`; without a proxy it fails at once instead of hanging.
- **Residual:** programs started with `python -I`, `-E` or `-S` (and embedded Pythons with a `._pth` file) do not load
  it; members with network `none` and no relays have no proxy, so asyncio still cannot start there; an `AF_INET6`
  request gets IPv4 sockets (asyncio does not care).
- **Independent review (2026-11-22, read-only, before release):** no Critical or High finding. Medium M1 (pair
  traffic unlimited, could load the gateway's loop) - fixed: per-direction rate cap and byte count. Low L1 (pair
  refusals lingered uncounted; pairs refused at the egress limit) - fixed; L2 (no half-close, cancelled tasks not
  awaited) - fixed; L3 (pairs outlived the proxy) - fixed: aborted at close; L4 (folder ahead of the standard
  library) - fixed: nothing else stays in it; L5 (process-id reuse in the tree walk) - the job ends the tree, the walk
  only without a job, unexaminable ids not followed (residual above); L6 (unbounded stderr lines) - fixed; L7 (crash
  exit codes made `os._exit` fail) - fixed; L8 (one pair budget per member) - limits raised and named in the refusal.
  Also fixed: every spelling of `PYTHONPATH` merged, the credential only to loopback, the next `sitecustomize` found
  like Python finds it (package or compiled file too) and run as `sitecustomize`, the job handle closed when it cannot
  be set up, a failed job assignment logged, the resume guarded. Tests: fixed sleeps replaced by conditions, timing
  bounds widened, vacuous assertions replaced, a unit test that the server starts suspended and joins the job before
  it runs, link refusal and folder clean-up, exact tokens only, rate cap, half-close, end with the proxy.

## 23. Release 1.27.0 (2026-11-24)

Four features - "Keep me signed in" again, capped at 24 hours (spec 037); a provider for one person (spec 038);
uploads up to 5 GB with images the model can take (spec 039); a retention period for chats (spec 040) - plus personal
hints on for new teams, and three fixes of faults found in use (`chat-open-replay-overflow`,
`idle-sessions-keep-mcp-servers`, `chat-open-readonly-fallback`). Built on separate branches, merged into one release
candidate, assessed independently before release (23.1, 23.2) and corrected after that assessment (commit
`1499ab7`). Sections 23.3 to 23.11 describe the changes as released, including what the assessment changed.

### 23.1 Independent assessment: scope and method (2026-11-24, before release)

- **Who.** An independent AI reviewer (a separate frontier-model agent, not the one that wrote the changes); read-only on all code; production not
  touched; no secrets recorded.
- **What.** The release candidate, commit `8f87cc8`, against 1.26.2 (`e9c41c4`): 55 files, +8,884 / -318 lines.
- **How.** (A) A code review of the diff and of what it touches. (B) The full test suite: 1,202 passed, 14 skipped,
  0 failed. (C) Live checks on a throwaway gateway on loopback with its own system folder and profiles root (plain
  HTTP, sandbox off; one administrator, two members): cookie attributes and lifetimes; CSRF, Origin and role checks
  on every new route; the WebSocket handshake and the gateway methods; upload isolation between members, offsets,
  limits, never-overwrite, read-only folders and junctions (also one swapped in mid-upload); the transcript's access
  rules and rate limit; a per-user grant reaching only the grantee and leaving on withdrawal; retention failing safe
  when Goose cannot confirm a deletion. (D) A short spot check of the rest: the firewall's always-allowed set, the
  CSRF model, the gateway-method dispatcher, an identity check on every new route; no new outbound HTTP call,
  subprocess call or deserialisation in the diff.
- **Not exercised.** Anything that needs a running Goose: no Goose binary was installed where it ran, so real
  retention deletion (`session/delete`), idle unloading (`session/close`), the orphan reaper on real process trees
  and WebSocket chat traffic (replay, resync, waiters, watchdog) were judged from the code, the project's tests
  against stand-ins and one in-process reproduction (M-1); the opt-in real-Goose tests were skipped. No browser: the
  front end was reviewed by reading (no XSS sink found). `hub.py`'s diff was read in part - the prompt path, the
  unloader hooks, the gateway-method dispatcher, the response hooks and the open-chat, waiter and watchdog code; the
  coalescing buffer and the byte-bounded tab queue were checked against the fix record and the tests, not line by
  line. `Secure` and the `__Host-` prefix (plain HTTP) and the disk-margin refusal (`disk_full`) were not checked
  live. The sandbox, the egress proxy, OIDC / LDAP and the prompt guard, unchanged since 1.26.2, were not audited
  again.
- **Verdict.** Ship after fixes: no Critical or High finding; fix M-1 and close M-2 and M-3 before the release.

### 23.2 Findings

| ID | Severity | Finding | Status |
|---|---|---|---|
| M-1 | Medium | The prompt-time check of a chat's provider, model and approval mode was skipped once for every chat the idle unloader had closed (`hub.py` `_from_client`, `unload.py`, `policy.check_session_choice`) | Fixed in `1499ab7` |
| M-2 | Low | The candidate still identified as 1.26.2, had no CHANGELOG entry, and this document contradicted the shipped behaviour (21.3) | Fixed by the release documents: version, CHANGELOG, this section |
| M-3 | Low | An upgrade switched on irreversible chat deletion (180 days, Goose Desktop and CLI history included) with a log line and one settings line as the only notice | Fixed in `1499ab7` |
| M-4 | Info | A `rememberHours` that is not a number was stored as the maximum (24 hours) instead of being refused | Fixed in `1499ab7` |
| M-5 | Info | `POST /api/fs/uploads/link` recorded a "last use" row for any well-formed chat id | Fixed in `1499ab7` |

**M-1 (Medium).** For a member, `session/prompt` is refused when the chat's current provider, model or approval mode
is not allowed (`policy.check_session_choice`); since spec 038 it is also the only place where a model given to one
person is held to the provider it was given with (`session/set_config_option` checks the model without its
provider). The check reads the chat's last `session/new` / `session/load` result. The idle unloader clears that
result when it closes a chat, the check returned at once when there was none, and the silent re-load came only after
it - so one prompt per unload ran unchecked (reproduced against the real hub with a fake Goose: a model given with
one provider was used with another), and a member could repeat that at will: a chat is unloaded after 30 idle
minutes, or after 2 once more than 12 are held. The same "no load result, no check" shape existed in 1.26.2 after a
worker restart or a buffer eviction, but nothing reloaded the chat on the prompt's behalf there. Fix: a member's
prompt to a chat with no load result - unloaded, or never loaded on this connection - first loads the chat
(`Unloader.ensure_loaded`, the same silent load) and is then checked on the fresh load result; when the chat cannot
be loaded, or is running without a load result, the prompt is refused ("this chat could not be loaded to check its
settings: open it again"). Three tests with a member client in `tests/test_unload.py` (unloaded and not allowed:
refused before Goose sees a prompt; unloaded and allowed: load, then prompt; never loaded here: loaded and checked
first) fail on the candidate and pass with the fix.

**M-2 (Low).** Operators could not tell the candidate from 1.26.2 (start-up log, `/api/auth/config`, package
metadata), and 21.3 still said there is no persistent sign-in. Fixed by the release documents: version 1.27.0, the
CHANGELOG entry with the retention notice first, this section, and 21.3 marked as superseded by 23.3. A sentence of a
draft for this section that M-1 disproved - that the silent re-load runs after the triggering method passed every
policy and guard check - is corrected in 23.10. The database schema number stays 6: the new tables and the column
are created at every start whatever the number.

**M-3 (Low).** Spec 040's default applied to an existing installation by itself: the first maintenance pass armed
retention, and seven days later the hourly sweep began deleting every chat unused for 180 days - for chats older
than the upgrade, counted from when Goose last wrote them - including a native profile's Goose Desktop and CLI
history. The only notice was a log line and one line on the settings page. Fix: retention never arms itself.
Automatic deletion is in force only once an administrator confirms the period - by saving it in Admin > Settings, or
with **Start automatic deletion**, which shows the Preview numbers and asks once (`retention.confirm`:
`retention_armed_at`, `retention_confirmed_by`). The first sweep runs a day later; a changed period starts that day
again; saving another setting confirms nothing (the page sends the period only when it was stored before or
changed). Until then the page says "Not in force yet", the gateway log warns once, and `goose-web check` prints a
`!!` line. Test: `tests/test_retention.py::test_automatic_deletion_waits_for_an_administrator_to_confirm`.

**M-4 (Info).** `PUT /api/admin/settings` stored a `rememberHours` that is not a number (`"abc"`, `null`) as 24, so a
script that meant "off" switched kept sign-ins on at their maximum for everybody. Now 400, and nothing of that
request is written; numbers keep the clamp (above 24 is stored as 24).

**M-5 (Info).** The link call recorded a use for any well-formed chat id, also when it linked nothing; such rows were
removed only by a real sweep of that profile, never while retention is off. Always under the caller's own profile -
no other person's chat or file was affected; slow growth of the gateway database only. Now a use is recorded only
when files were really linked to the chat.

### 23.3 "Keep me signed in", 24 hours at most (spec 037)

This reverses part of 21.3: a persistent sign-in exists again, chosen per sign-in and capped.

- **What changes for an attacker.** A kept sign-in's cookie is stored by the browser on disk. Someone who takes an
  unlocked device, or copies the cookie (malware on the client, a backup of the browser profile), holds a working
  sign-in for up to 24 hours instead of until the browser closes (a session cookie, 8 hours at most) - with
  everything the person can do, including starting agents.
- **Mitigations.** A hard cap of 24 hours in code (`auth.REMEMBER_HOURS_MAX`; the configuration, the database and
  the admin page clamp; `check` names a higher value; the settings API refuses a value that is not a number, M-4);
  a fixed lifetime counted from signing in, never extended; unchecked by default, a deliberate choice per sign-in
  (only JSON `true` counts); the cookie is HttpOnly, SameSite=Strict, path /, and Secure with the `__Host-` prefix
  over HTTPS; only the SHA-256 of the token is stored; two-factor at sign-in and the idle limit (`auth.idle_minutes`)
  apply; the person sees kept sign-ins (Settings > Account > Active sign-ins) and can end them; a password change or
  reset and disabling the account end them; an administrator can lower the lifetime or set 0, which shortens or ends
  the kept sign-ins that exist, at once and at start-up (each stored sign-in knows its kind,
  `auth_sessions.remember`). Single sign-on sign-ins are never kept.
- **Checked live (23.1).** Without `remember`: a session cookie, 8 hours. `remember: true`: `Max-Age=86400`,
  24 hours. `"true"` or `1`: not kept. Lowering the setting to 1 cut an existing kept sign-in to an hour at once; 0
  ended it while a normal sign-in of the same person went on.
- **Mistakes.** Ticking the box on a shared or public computer leaves a 24-hour sign-in there (the box's tooltip and
  the user guide warn; end it from another device). A lifetime below the normal one makes kept sign-ins shorter than
  normal ones (harmless).
- **Residual.** Up to 24 hours of exposure for a kept sign-in on a stolen or infected device. Recommended: 0 where
  devices are shared, and an idle limit. Not done, as in 21.3: tying a sign-in to an address or a browser name.

### 23.4 A provider for one person (spec 038)

- **Who can do it.** Administrators only (403 otherwise), with CSRF and Origin checks; audited (`user.item.add`,
  `user.item.remove`, `user.item.refresh`, with the source and the models). The source must be an enabled
  administrator's own profile (`400 bad_source`): a member's provider - its address and key - can never be copied
  into another person's profile this way. A grant to the account on the native profile is refused.
- **The key goes to the grantee only.** As with a team's provider item, the grantee gets the provider definition and
  its key value in their own `secrets.yaml`, readable by their own agent (with Shell or a file tool) - give only
  providers whose key you would hand to that person. Nobody else gets the file or the key: teammates' profiles are
  provisioned from their own rows, and the key value is never stored in the database. Tested, and checked live: the
  grantee's profile got the provider file and exactly the one key the provider names (a second key of the
  administrator's was not copied), a teammate got neither, and no API answer contains the value.
- **Provider and model as a pair.** The grant only adds, after the team's lists and the person's overrides (a team's
  Any stays Any); the team stays the base (no team, no chat). A given model counts only with the provider it was
  given with, at every check that knows the provider (prompt, defaults and save, recipes, provisioning).
  `session/set_config_option` and `config/upsert` accept a given model for its providers, so the pair is held at the
  prompt - since M-1 also for a chat the gateway unloaded or never loaded on this connection, which is loaded and
  checked first (refused if that fails); on the release candidate the first prompt after an unload was not checked
  (23.2). Ids that are not text are refused, not crashed on.
- **Withdrawal.** The file and the key leave the profile at once; a chat running at that moment keeps what its agent
  loaded until the agent restarts (it is marked and restarts when idle), as for team items; open sockets reconnect
  with the new rights. A grant is a copy of the key: withdrawing it does not make a key that was used or read
  elsewhere safe again - rotate it after taking it from someone who should no longer have it.
- **Following the source.** Only administrators' profiles are followed (a demoted or disabled source stops
  counting); a source that is gone keeps the copy without delivering the key.
- **Residual.** A team's `allowed_models` stays provider-agnostic (unchanged). The grantee holds the key value while
  the grant lasts.

### 23.5 Personal hints on for new teams

Members of teams created from now on may write personal hints, which their own agent loads before assigned and team
hints. They could already instruct their own agent in every prompt; hints make that persistent. Team hints stay
last, with the "final: these take precedence" note - an instruction to the model, not an enforcement (unchanged).
Hint file names stay refused in uploads. Existing teams are not changed. An administrator who expects a new team to
start fully locked down finds the switch on the team's Experience page (Hints; the team page shows it as an info
line), or sends `policy.hints_edit: false` when creating a team by API. Residual: a personal hint that contradicts a
team hint relies on the model following the stated precedence, as before for teams that had personal hints on.

### 23.6 Uploads up to 5 GB in pieces (spec 039)

New surface: a person can write up to the administrator's limit (25 MB by default, at most 5 GB) per file through
four routes (`/api/fs/uploads`), over several requests.

- **Who and where.** Sign-in, CSRF token and Origin on every write. The folder is checked as written and as resolved
  at the start, before every piece and before the final name (a read-only folder, or a `Web_Uploads` that links
  elsewhere: refused, nothing written); names are cleaned; hint file names and `.agents` are refused for members. An
  upload id is 32 random bytes, stored as its SHA-256 and usable only by the account that started it (anyone else,
  an administrator included, gets the 404 of an unknown id). An administrator's `profile` argument only labels whose
  chat a file belongs to; a member cannot use it.
- **Partial files and junctions.** The gateway is not sandboxed and writes into folders a member's agent can change.
  The partial file has a random name (not the id), is created exclusively, and its volume:file index is stored. A
  piece opens it only when `lstat` shows a plain file (no link) and the opened handle has the stored identity, so a
  partial file replaced by a link or another file, or a `Web_Uploads` swapped for a junction, is never written
  through (tested; live, a junction swapped in between two pieces made the next piece 403 and nothing was written
  outside). After creating the file and after the final rename the gateway checks it is still the same file in the
  folder resolved at the start, else removes it (`409 upload_moved`, audited). The rename never replaces a file.
  Residual: a junction swapped in inside the rename call itself could move the finished file - with the person's own
  content - to where it points; Windows does not let a sandboxed process create a junction to a folder it cannot
  write, and without a sandbox the agent has the gateway account's rights anyway.
- **Limits and the disk.** The declared size is the most the server accepts (a piece beyond it, or above 32 MiB, is
  refused); pieces are written as they arrive with at most 1 MiB held (measured: 600 MB through a live gateway,
  working set about 50 MB); a piece that brings no byte for 120 s ends (408) and frees its slot; 4 pieces at once
  and 20 unfinished uploads per person; at the start the disk must have the size, plus what other open uploads still
  need, plus 1 GB free (507 otherwise); partial files idle for 24 hours are deleted. Residual: no per-person quota -
  with a raised limit a member can fill the drive of a writable folder with finished files down to the 1 GB margin
  (as with the old endpoint, faster); retention (23.8) removes unused files eventually.
- **The old endpoint** (`POST /api/fs/upload`) keeps its ceiling, never above `server.max_upload_mb`: its multipart
  body is spooled to the system's temporary folder, outside the disk check.

### 23.7 Images sent to the model (spec 039)

The browser makes the copy shown to the model (decoding happens in the browser, not on the gateway); the gateway
stores the original unchanged. Nothing new reaches the model: images were sent inline before (up to 8 MB an image;
now at most 10 MB of images per message, and the gateway's limit for one queued or steered message rose from 9 to
15 MiB with it). As before, the prompt guard reads text only - text written inside an image reaches a vision model
unchecked. A model sees images only when Goose treats it as vision-capable (`supports_vision`); turning that on for
a model is the administrator's decision.

### 23.8 Chat retention (spec 040)

New: the gateway deletes chats and files on its own, and what it deletes comes back only from a backup - so the
safeguards are about data loss.

- **Only after an administrator confirms it (M-3).** Retention never arms itself: nothing is deleted automatically
  until an administrator confirms the period in Admin > Settings > Files and chats (saving it, or **Start automatic
  deletion** after the Preview numbers). The first automatic sweep runs a day later and a changed period starts that
  day again; until then the page says so, the log warns once and `goose-web check` prints `!!`. 0 = never.
- **What can be deleted.** Only top-level chats of the types Goose lists (`user`, `scheduled`, `acp`), through Goose
  (`session/delete`), with their sub-agent sessions; never a file by a path the profile chose - file paths come from
  the gateway's own upload records. A chat's files go only after Goose confirmed the chat's deletion, and a file only
  when it is still in a folder named `Web_Uploads` (as written and resolved), in a folder the profile may write
  (`path_ok(write=True)`), a regular file and no link, with the volume:file index recorded at upload (a file put in
  its place is kept), and not linked to a chat that is kept. Upload rows older than the account are ignored (a
  deleted account of the same name).
- **What is never deleted.** A chat that is running, being opened (or whose load Goose never answered), open in a
  tab, with queued messages, steers, questions or open requests, or running in Goose Desktop or a scheduled job; any
  chat of a profile whose `sessions.db` cannot be read; a chat when the hub's state cannot be read (kept, logged);
  anything when retention is 0 or not confirmed; chats of disabled accounts. At most 200 chats per sweep, oldest
  first; a profile stops at the first chat Goose does not delete.
- **Mistakes.** The default is 180 days and the native profile (Goose Desktop and CLI history) is included. The page
  shows the Preview per user (also for a number typed but not saved), Run now asks for a confirmation, and every
  deletion is audited with the chat id, file count and bytes (`retention.chat_deleted`, `retention.files_deleted`,
  `retention.run`).
- **Checked.** Live, without Goose (23.1): the Preview lists only chats past the cut-off and keeps a file shared with
  a kept chat; Run now deleted nothing (one error per profile, every file still on disk). Tests: files outside
  `Web_Uploads`, outside writable folders, replaced since the upload or behind a junction are kept. A harness of the
  assessment that swapped `Web_Uploads` for a junction 2,963 times during 58,802 deletions deleted no outside file.
- **Last-use records** (`chat_access`) come from the hub's audit hook and the upload link call (ids of at most 128
  safe characters). Rows for ids Goose does not have are removed at the end of a real sweep of that profile; since
  M-5 the link call records a use only when it linked something.
- **Admin API.** Administrators only (403 otherwise; CSRF on Run now).
- **Residual.** Backups keep what retention deleted (ADMINISTRATION 19.1). A fork made in Goose Desktop does not
  share the files of its chat; when the original expires, its files go. Files attached before 1.27.0 have no record
  and are never deleted by retention. A file is checked and then deleted by its path: the window between needs
  someone who can already write the member's folder (deleting through the opened handle would close it). Last use is
  under the member's control (opening a chat counts), so a member can keep their own chats.

### 23.9 Opening chats: tab queues, replays, the load watchdog (FIX `chat-open-replay-overflow`)

**Change.** The per-tab send queue was bounded by count (20,000 frames of any size); it is now bounded by bytes:
64 MiB (`CLIENT_QUEUE_BYTES`) of queued and held frames, of which session notifications may be dropped - the tab then
gets `_gw/resync` and loads the chat again - and 128 MiB (`CLIENT_QUEUE_HARD_BYTES`) of frames that are never
dropped (responses, agent requests, gateway notices), past which the socket is closed (`queue-full`). A chat's
buffer merges the text chunks of one message and keeps at most 5,000 frames. Replays run as tasks, one per tab and
chat (a newer load of the same chat by the same tab ends the older one), sending JSON arrays of at most 256 KB while
the tab has at most 4 MiB queued. One upstream `session/load` per chat; tabs of the same profile wait for it. A
watchdog (`goose.session_load_timeout_seconds`, 180 s) ends a load Goose does not answer.

- **Memory per tab** is bounded in bytes (before: 20,000 entries of up to 64 MiB each). A replay holds references to
  the chat's buffered strings (at most 12 MB and 5,000 frames per chat) plus the rendered last chunk; frames held
  back for a tab during its replay count toward its 64 MiB.
- **No cross-tab exposure.** A waiting tab passed the same `pol.check` (folder roots, policy) for its own
  `session/load` before it waits, and gets the frames of the chat it asked for from its profile's own upstream, as it
  would from its own load. `_gw/resync` carries only a session id, to the tab whose frames were dropped; a tab that
  sends `_gw/resync` or `_gw/unload` itself gets "unknown gateway method" (checked live).
- **Denial of service.** A tab cannot make the gateway hold unbounded data (byte caps), cannot pin a Goose load
  forever (watchdog), and cannot force repeated loads of a chat Goose is stuck on (refused at once until Goose's late
  answer or a worker restart). The browser's retries are bounded (4) and paced (0.5 to 4 s), and its reconnect
  backoff no longer resets after a socket that dies at once.
- **Logging.** The overflow warning names profile, user, session id, frame and byte counts - no content.
  `ws.disconnect` records a reason.
- **Compatibility.** Scripts on `/ws` get replayed frames as JSON arrays of notifications (CHANGELOG 1.27.0).
- **Residual.** A chat whose upstream load Goose never answers stays refused until the worker restarts (by design: a
  second load would hang the same way). A tab that drops frames reloads the chat, which costs a replay; a tab that
  keeps falling behind repeats that, bounded by the browser's retries.

### 23.10 Idle-chat unloading and the orphan reaper (FIX `idle-sessions-keep-mcp-servers`)

Why: Goose 1.57 keeps a chat's agent and all its stdio MCP servers until the chat is closed; Goose Web never closed
one, so long-lived workers accumulated processes and memory without bound - a resource-exhaustion path any member
could drive by opening chats. On Windows Goose also ends only a released server's direct child.

- **Unloading never ends work.** `session/close` cancels a running turn in Goose, so the gateway closes only a chat
  with no turn, prompt, question, request, queued message or steer, not being loaded, not shown in a connected tab,
  and idle for the configured time. The decision is checked again under a per-chat lock right before the close, and
  a prompt or load arriving meanwhile waits for the close and then loads the chat. The close is an internal request
  (pseudo-method `_gw/unload` in the pending table), never a client action; the client-facing close and delete paths
  are unchanged.
- **The silent re-load (corrected after M-1).** A method that needs the agent of a chat the gateway unloaded first
  loads the chat again, through the chat's one upstream load (23.9) with no tab waiting; the replay goes into the
  gateway's buffer, to no tab. It runs after the method passed the firewall and the checks that do not depend on the
  chat's settings. For a member's prompt it runs before the check of the chat's provider, model and approval mode,
  which is then made on the fresh load result; a member's prompt to a chat never loaded on this connection is loaded
  the same way first, and a prompt without a load result is refused (M-1). The draft of this section said the
  re-load ran after every policy and guard check; on the release candidate that order was the gap - the check ran
  first, on nothing (23.2). The re-load uses the folder recorded at the chat's earlier load or, for a chat not loaded
  on this connection, the folder Goose stored for it; before a member's prompt makes Goose load a chat, that folder
  is checked against the member's current folder rules exactly as opening the chat in a tab is (`policy.check` of
  `session/load`; an unknown folder is refused), so a chat in a folder the member may no longer use is never loaded
  for them (found by the release documentation review, fixed before release; test
  `test_a_members_prompt_never_loads_a_chat_in_a_folder_they_may_not_use`). With the sandbox the agent is held to the
  member's folders in any case (21.1). Members reach only their own profile's worker, so it opens no other profile's
  chats.
- **`current` in `_gw/watch` / `_gw/seen`** lets a socket keep one chat of its own profile loaded (at most 200
  characters, per socket). A member could pin as many chats as sockets they open - the same as keeping tabs open; no
  effect on other profiles. Accepted.
- **What the reaper can end.** Only members of the worker's own job object (a member's processes cannot leave it);
  only processes it classified while they were part of a configured stdio extension's tree - a direct child of the
  worker's goose.exe whose command line matches an entry of the profile's `config.yaml`, plus descendants by parent
  link and creation time; only once the tree's root has ended and the process's ancestor chain no longer reaches
  goose.exe, after a grace (`goose.orphan_grace_seconds`, 120 s); every end through a handle whose creation time is
  checked (`stdio_guard._terminate`), so a reused process id is never hit.
- **What it cannot end.** The worker, the gateway, anything outside the worker's job (another profile's worker and
  its servers included) and anything it did not classify. A member who can edit their own extensions can at most get
  processes in their own worker's job ended - for example a developer-shell command whose command line is exactly a
  configured extension's.
- **Audit content.** Each end is audited (`worker.orphan_ended`, administrators only) with the command line; values
  of key, token, secret, password and auth options, URL credentials and long opaque strings are masked. A secret
  passed as a short positional argument could remain visible to administrators (residual).
- **Windows calls.** `QueryInformationJobObject` (JobObjectBasicProcessIdList) on the gateway's own job handles,
  `CreateToolhelp32Snapshot`, `OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION)` and `NtQueryInformationProcess`
  (ProcessCommandLineInformation, at most 1 MiB), `TerminateProcess` - all within the gateway account's own
  processes.
- **Tested** against the real Goose 1.57.0 with the opt-in tests (`GOOSE_WEB_TEST_GOOSE=1`): unloading leaves no
  server process, a re-loaded chat starts its servers again, and the reaper ends a launcher's orphaned child after
  the grace. The independent assessment could not run them (23.1).

### 23.11 Read-only copy of a chat (FIX `chat-open-readonly-fallback`)

Why: a chat Goose cannot load was unreadable, although its messages are in the profile's Goose session database all
the time. `GET /api/sessions/{id}/transcript` (`transcript.py`) reads that database and returns the chat's
user-visible messages in pages; `readonly.js` shows them behind a button on the chat's error card.

- **The access rules of `session/load`, no wider.** The caller's own profile; `?profile=` with another name only for
  administrators (403 otherwise, with one message for existing and unknown names) - the `/ws` rule - audited as
  `transcript.view`, the counterpart of `ws.impersonate`. For a member the firewall's `session/load` check runs with
  the chat's folder from the database and the member's policy and folders: a chat in a folder the member may no
  longer use is refused with the same `403 forbidden: <reason>` and audited as `acp.denied` (via the transcript).
  Another member's chat is not in the caller's database (404). Sign-in as for every route (a pending password change
  or two-factor enrolment first); GET only.
- **Never writes Goose's data.** Opened with `mode=ro` and `PRAGMA query_only=1`; a missing database is not created;
  2 s busy timeout, closed at once. Tested: INSERT, UPDATE, DELETE and CREATE are refused and the file's hash is
  unchanged. A WAL database nobody has open may get SQLite's `-wal` / `-shm` companions when it is opened (as with
  `elsewhere.py`); the database file itself is not written.
- **Input.** The session id must match `^[A-Za-z0-9_.:-]{1,128}$` (400) and is only a bound SQL parameter; `after`
  and `limit` are whole numbers (400 for text, inf, nan); the SQL text is built from constants only.
- **Bounded.** 200 messages per page by default, 1,000 at most; per message 200 KB of text and 500 blocks; tool
  arguments and results 2,000 characters; a page at most 4 MB of JSON and 64 MB of stored content read (rows one at
  a time); a stored message over 16 MB is not read (a notice instead); 60 requests per person and minute (429).
  Image data is never returned (its type only).
- **Rendering.** Goose's text and thinking go through the Markdown sanitiser (marked, then DOMPurify with the
  existing options); user text, tool text, names and notices are text nodes; `readonly.js` uses no `innerHTML`
  (tested). The server re-checks an administrator's `?profile=`.
- **Disclosure.** The copy shows what opening the chat would show, minus live-only parts; messages Goose marks
  `userVisible: false` (agent-only context) are filtered in SQL and never leave the server.
- **Checked live (23.1).** Own chat 200; another member's chat 404; `?profile=` as a member 403; a chat in the
  member's own database whose folder is another member's workspace or a system folder 403; malformed ids 400; 64
  quick requests gave 60 answers and four 429s, another user unaffected. No browser test of the copy was made.

### 23.12 Residual risks

- A kept sign-in on a stolen or infected device works for up to 24 hours (23.3).
- A grant copies a provider's key into the grantee's profile; withdrawing it does not make a key already read
  elsewhere safe again - rotate it (23.4).
- No per-person upload quota: with a raised limit one member can fill a disk down to the 1 GB margin (23.6; the same
  class as GW-22).
- Retention deletes for good; backups keep what it deleted (23.8).
- A chat whose load Goose never answers stays refused until its worker restarts (23.9).
- Not run against a real Goose by the independent assessment: retention deletion, unloading, the reaper and chat
  traffic (23.1). Not tested in a browser by anybody independent: the new front end (uploads, images, the read-only
  copy).

### 23.13 1.27.1 (2026-11-25): a member's scheduled runs in the member's own folder; one writer per chat

**Finding (fixed, Low).** Goose 1.57 creates a scheduled run's chat with the worker process's current folder as its
working folder (`scheduler/full.rs`: `create_session(std::env::current_dir()?, ..., SessionType::Scheduled)`). The
sandboxed backends start a member's worker in `<profile>\workspace`; the start without them used the profile root.
A member's scheduled run (when the team allows Schedules) therefore ran with the profile root - `config.yaml`,
`secrets.yaml`, `data\` - as its working folder, and the member could not open their own run: the folder rule refused
`session/load` ("folder not allowed"). Reproduced end to end on 1.27.0 (sandbox off, real Goose 1.57): the run's
folder was `<profiles_root>\<user>`; `session/load` and `session/prompt` answered `-32003`.

**Fix.** `workers.start_dir`, used by all three start paths: an isolated profile's worker starts in the member's
workspace (the profile root when there is none; the native profile unchanged). No folder was added to anybody's
roots. End to end on 1.27.1: the run was in the member's chat list with the workspace as folder, opened, and
continued.

**What else follows the worker's folder (independent review S-1, S-7).** Goose also loads plugins from it
(`.agents/plugins`: hooks for every agent of the worker, MCP servers for scheduled runs), resolves relative paths
(recipe search, a relatively configured extension command) against it, and Windows searches it for DLLs after the
system folders. For sandboxed members this was already the workspace. The `session/new` plugin rule (NEW-36, SD-2)
now also applies to the start folder: a workspace with plugins is used only when the member has `allow_shell`;
otherwise the worker starts in the profile root, where the member cannot write, and logs why. A member without
`allow_shell` cannot create `.agents` through the file API, and uploads land in `<folder>\Web_Uploads`, never in the
workspace itself; with `allow_shell` a member can run programs anyway. Changing `allow_shell` restarts the worker
when it is quiet.

**Second writer.** Goose's scheduler writes a running job's chat outside the gateway's sight.
`Upstream._written_by_scheduler` asks the worker's scheduler which chats its running jobs write (`schedules/list`:
`currentlyRunning`, `currentSessionId`) and `session/prompt` and `conversation/truncate` on such a chat are refused
with `-32011`, after the policy firewall and the spec 020 check, before anything is loaded (also before the M-1 load
of 23.2) and before the prompt guard. Only a worker that runs a scheduler and is running is asked (the check never
starts a worker, S-3); one question at a time, its answer stamped when it arrives and shared by every prompt meanwhile
(S-2), reused 2 s; the question waits at most 3 s, and a scheduler that does not answer refuses nothing (fail open:
a refusal would block every prompt of the profile) and is not asked again for 30 s, with one warning in the log
(S-5). A member can query and affect only their own worker. **Residual (S-4):** Goose names a run's chat only after
the run's extensions have started; until then, and for up to 2 s after a check, a message to that new chat is not
refused.

**Using a run.** Goose creates runs in the Auto approval mode; in a team that does not allow Auto, the member picks
an allowed mode in the chat header before continuing the run (the prompt check of 23.2 refuses it until then, S-8).

**Independent review (2026-11-25, before release, read-only, by a separate AI agent, not the one that wrote the changes).**
Verdict "ship after fixes"; findings S-1 (Medium: the plugin rule did not cover the new start folder; no exploit
found) and S-2 to S-8 (Low/Info: the cache race of two tabs, a check that could start a stopped worker, the
residual, a slow scheduler, test strength, what else follows the worker's folder, the approval mode). All fixed or
documented in this release as described above.

**Tests.** `tests/test_scheduled_runs.py` (17): the start folder per profile kind and with plugins (with and without
`allow_shell`), `WorkerManager._start` with a fake `Popen`, both sandboxed starts, the permission's restart, refusal
while a job writes the chat (prompt, edit, member before any load), two tabs at once at the real cache (one
question), no question to a stopped worker, a scheduler that does not answer (one question in 30 s, one warning),
other chats unaffected, continuing after the run. The refusal tests fail on 1.27.0.

## 24. Addendum: 1.28.0 (2026-11-25) - Files

The **Files** page (spec 041): people browse the folders they are already granted, upload large files into them,
download them, see their SHA-256, preview text and common images, hand a file to Goose, rename, move and delete them
(with a recycle bin) and see a folder's activity. It was built for a team that works on shared material - an
incident's captures, logs and exports - in its team folder, where the audit of who uploaded, downloaded or changed
what serves as a chain of custody. Built in two packages (server, browser), merged into a release candidate
(`a4f31a0`), assessed independently before release (24.3), corrected after that assessment (commits `cb0957e` to
`3cf2842`), and the fixes reviewed three more times, with a browser test between, and corrected each time (`e249652` to
`f7b1ed0`, 24.4). Sections 24.1 and 24.2 describe the feature as released, including what the reviews changed.

### 24.1 What the feature exposes, and to whom

- **New surface.** Fourteen routes under `/api/files/*` (locations, list, info, hash, download, preview, mkdir,
  rename, move, delete, recycle, recycle/empty, restore, activity; API.md), `POST /api/fs/uploads` with
  `target: "folder"` (a chunked upload into the folder itself instead of `<chat folder>\Web_Uploads`), the page
  `#/files`, and `?attach=` on New chat and in a chat. Before, a member could put a file into a folder only as a
  chat attachment, and no page offered a file download; `/api/fs/download` and `/api/fs/read` existed for API
  clients, without an audit row.
- **Folder rights unchanged.** Everything works only in the folders the administrator already grants - a member's
  workspace, the team folder, the team's extra and read-only folders (spec 031, 21.1) - checked by the same
  `api._check_path` / `Ctx.path_ok` as every file route; read-only folders stay read-only; there is no new kind of
  folder right. The members' agents already reach these folders; the page gives the people the same view. New is
  that the gateway - not sandboxed, with its account's rights - renames, moves, copies and deletes in folders that
  the members' agents can change at the same time; most of 24.2 is about that.
- **Two switches.** `files` (the page and its API: browse, download, preview, SHA-256; upload and new folder where
  the person may write) and `files_manage` (rename, move, delete, restore; counts only with `files`). Both are in
  `BOOL_KEYS`, so per-person overrides apply; an override must be JSON `true` or `false` (400 otherwise) and a
  stored one that is not `true` counts as off (F-6); a team switch - and a team's `require_totp` - is `true` or
  `false`, `1` or `0`, `null` (off) or one of the words `true`, `on`, `yes`, `1`, `false`, `off`, `no`, `0`, `""`;
  anything else is refused (`400 bad_value`, G-3, H-3). Both are on for new teams (`NEW_TEAM_POLICY`) and were switched
  on once for every existing team at the first start (`policy.apply_files_switches`, settings key
  `files_switches_applied`, each change audited `team.update` by the system); only keys a team does not have are
  added, so an explicit off stays off, even when the settings key is lost, and a team saved without the keys keeps
  the stored values (F-8). Without `files` the page is hidden and every `/api/files/*` route answers
  `403 files_off`, and so do `/api/fs/download`, `/api/fs/read` and each piece and the finish of a folder upload
  (F-9); the folder picker (`/api/fs/roots|list|mkdir`) keeps working.
- **On by default** is a decision of 2026-11-25: on upgrade every member gains download, upload, rename, move and
  delete in the folders they already have - also in a team without Shell, where the gateway now does what the
  member's agent may not. Administrators who do not want that switch it off per team.
- **Administrators** always have both switches. Their locations are those of the folder picker - their workspace
  and the drives - where they act with the gateway's rights (never in the system folder, on UNC or device paths).
  Every team's folders, every workspace, the system folder and the profiles root are protected tops for them as for
  everyone (24.2), so their deletes in a team folder or a workspace land in the recycle bin that team or person
  sees, and no folder holding a workspace or Goose Web's data can be moved or deleted from the page. Only
  administrators can empty a recycle bin early (`POST /api/files/recycle/empty`).
- **Who sees what.** Listings, details, previews and a folder's activity need read access to the folder; the
  recycle listing shows the items whose original folder the caller may write; restore needs `files_manage` and
  write access there. Whoever may read a folder sees who uploaded a file and when, and the folder's activity: the
  successful `files.*` rows of that folder and everything below it - teammates' and administrators' actions
  included, with the other end of a move in or out.

### 24.2 Threat model and mitigations

Assumptions: a member can write in their writable folders through the page and, with Shell, through their agent;
the gateway is not sandboxed and acts in those folders while the members' agents can change them; a link inside them
can come from outside the sandbox (an administrator, a native profile's agent, a host tool, an unpacked archive, a
folder tree that already carries junctions) - a sandboxed agent cannot create a link to a place it may not write
(13.3, 16.2).

- **Authorization on every route.** Sign-in; `files.gate` (`files`; `files_manage` too for rename, move, delete and
  restore; `403 files_off`); then each path through `api._check_path`: absolute only (`400 bad_request`), inside
  the person's folders as written and as resolved (`403 denied`), in a writable folder for anything that creates or
  changes something (`403 read_only_folder`), never the system folder, a UNC or a device path. Every POST needs the
  CSRF header and passes the Origin check (tested per route). Upload ids stay their owner's (`404` for anyone else,
  administrators included); restoring an item of a folder the caller cannot reach is `404`. The assessment's
  isolation probes - other workspaces, other teams' folders, the profiles root, a profile folder, the system
  folder, recycle items and ids, upload ids, read-only folders, traversal, UNC and device paths, NTFS stream names,
  trailing dots and spaces, case - all held on the candidate (24.3).
- **Links, junctions and races between the check and the change (TOCTOU).**
  - *Rename, move, delete, restore* (F-2). Right after the checks `_pin` records the item's identity (volume:file
    index) and both folders as resolved, each checked again against the person's resolved writable folders (a team
    folder that itself sits behind a junction keeps working). On Windows the move then opens the item (the link
    itself, delete access, no `FILE_SHARE_DELETE`) and the target folder and holds both while it runs: nobody can
    rename or delete them, and NTFS refuses to rename any folder above an open item, so no path the move uses can
    be swapped meanwhile. The item must be the one checked, in the folder checked, and the target must resolve to
    the folder checked; otherwise `403 denied` and nothing moves. The rename goes through the item's handle and
    never replaces anything. A delete makes its recycle slot first and measures the item and looks up its SHA-256
    after the move, so the candidate's window (a walk of up to 20,000 entries between check and move) is gone.
    Elsewhere than on Windows identity and folders are compared before and after, with a put-back on a mismatch.
  - *Across volumes* (F-1, F-10). A folder that holds a link (symbolic link, junction, mount point) is refused
    whole before anything is copied (`409 has_link`); every entry is opened, must be exactly where it should be
    (its final path is the expected one, so a link on the way is found) and is held while it is copied under a
    hidden `.goose-web-move-<hex>` name next to the target; a link item itself is never copied to another volume.
    The rename of the finished copy is the commit; the original is then deleted entry by entry through handles (a
    link as a link), and what cannot be deleted is answered as a warning and audited (`sourceLeft`) -
    by a move, a delete and a restore (F-10, completed in `e249652`); a restore that leaves something keeps the
    item in the bin, so the rest is purged with it.
  - *Uploads* keep the defences of spec 039 (23.6): the folder as written and as resolved at the start and before
    every piece, the partial file's identity, a final rename that never replaces, checked afterwards. A folder
    upload goes into the folder itself, which must exist (nothing is created on the way). *New folders* are checked
    again once made and removed when they no longer lie in a folder the person may write.
  - *Restore and purge* never follow links: the recycle folder, the id folder and the item must not be links and
    must resolve where Goose Web put them, otherwise restore answers `409 denied` and purge drops the record
    without touching anything; purge removes a link as a link, never what it points to, and does not follow links
    inside a folder it removes (probe: a recycle slot and a recycle folder swapped for junctions - purge removed
    only the links' own records).
  - *Reads* (download, preview, info, hash) open the file by its path after the check, as `/api/fs/download` always
    did (24.5).
- **Protected tops** (F-3). No location's top folder, nor a folder holding one, is renamed, moved or deleted from
  the page, and the tops are everybody's, for members too: every person's workspace and extra folders, every team's
  folder and extra folders (read and write), the system folder and the profiles root, compared as written and as
  resolved (a member's list is only compared, never shown). What is deleted inside nested locations goes to the
  recycle folder of the deepest one - the bin its team or person sees.
- **Goose's hint and agent folders** (F-4, F-7). Goose takes instructions and code from the folder a chat starts
  in: the hints files (`AGENTS.md`, `.goosehints`, `.goose-web-hints.md`), `.gooseignore` (which files its tools
  may touch), plugins in `.agents\plugins` (NEW-36), and project skills, recipes and agents in `.agents`, `.goose`
  and `.claude` (Goose's `skills/mod.rs`; summon runs a recipe it finds there). "Ask Goose about this" starts chats
  in exactly such shared folders, for teammates and for administrators, whose agents are not sandboxed. For members
  every route that creates or changes something - the folder picker, chat attachments, folder uploads and the Files
  page - refuses a path with an `.agents`, `.goose` or `.claude` component (any case, trailing dots and spaces,
  stream names, 8.3 short names through the resolved path; `403 agents_folder_refused`) and the names of the hints
  files and `.gooseignore` (`403 hint_file_refused`). On the Files page members also cannot rename, move or delete
  such a file (also by its 8.3 short name) or anything in those folders, nor a folder that holds a hints file, a
  `.gooseignore` or an `.agents`, `.goose` or `.claude` folder (G-2; a walk of at most 100,000 entries that enters
  no link; a larger folder, or one with a part the walk cannot read, is refused: H-5). A member's agent that may write a folder (with Shell) can still write such files there, as before
  (spec 009, NEW-36).
- **Content of downloads and previews.** Downloads (`/api/files/download`, `/api/fs/download`) are always
  `application/octet-stream` with `Content-Disposition: attachment` (RFC 5987 for odd names), the CSP
  `sandbox; default-src 'none'`, `nosniff` and `Cache-Control: no-store`; the page starts them as a plain
  navigation, so a file is never loaded into the page (any size, resumable with `Range`). It goes out as it is: the two download
  routes bypass the gateway's GZip middleware, so `Content-Length` is the file's size and the audit counts the
  file's bytes (found in the browser test, 24.4). Text previews are JSON -
  the first 256 KB as UTF-8, or UTF-16 with a byte order mark, with replacement characters - which the page puts
  into a `<pre>` with `textContent`, never with `innerHTML` (a test checks `views/files.js` has none) or Markdown.
  An image is previewed only when its first bytes are PNG, JPEG, GIF or WebP, and sent with that type whatever its
  name, with `nosniff`, `inline` and the sandbox CSP, at most 20 MB, shown from a blob URL that is revoked when the
  preview closes; SVG is text, never an image; anything else is `415`. Probes: HTML, SVG and UTF-16 markup came
  back as JSON text; a GIF/JS polyglot and a PNG header with HTML behind it went out as images with `nosniff` and
  the sandbox CSP. Names, paths, user names and activity details are text nodes, links are built with `qs()` and
  `encodeURIComponent`, and the page's CSP allows images only from `'self'`, `data:` and `blob:`. An `?attach=`
  link places a visible chip only after `GET /api/files/info` confirmed the person may read the file; nothing is
  sent before the person presses Send.
- **Resource limits** (F-12, F-13). A listing looks at 20,000 entries of a folder at most (`truncated`; a probe
  listed 21,000 files in 0.11 s) and pages of at most 500; a move or delete takes 200 paths at most; the recycle
  listing 1,000 items, the activity 200 rows. SHA-256 computations, moves and the final read of an upload run in
  eight threads of their own (H-4), not in the shared pool that sign-in, listings and upload writes use, and one person
  holds at most two of them at a time, given back when the work has finished (G-1); per person at most two SHA-256
  computations, two move or delete requests and two previews at a time (`429 busy`), and one
  forced SHA-256 of a file every 10 s. Previews read at most 256 KB of text or 20 MB of an image. Uploads keep the
  limits of spec 039 (23.6). Purge removes at most 500 items a run; an item it cannot remove waits an hour and then
  goes behind the others. Request paths longer than 4,096 characters or with more than 128 levels are refused before
  anything resolves them (`400 bad_path`; a chat's folders: denied), a chat takes at most 32 `additionalDirectories`,
  and **New folder** makes at most 32 folders at once, off the event loop (H-1, I-1, I-2, J-1).
- **Recycle bin and purge.** A delete moves the item into `<location top>\.goose-web-recycle\<id>\<name>` (same
  volume, hidden, made when needed; refused when it is a link or does not resolve right inside the location).
  Anything else under that name - a file or a link a teammate's agent made - is moved aside to
  `.goose-web-recycle.conflict-<hex>` and audited `files.recycle_conflict` (F-11). No route but restore reaches the
  recycle folder: `api._check_path` answers `404` for any path with that component, as written or resolved, and no
  listing shows it. Restore puts the item back into its folder (made again when it is gone; `name (restored).ext`
  when the name is taken). Purge (maintenance loop) removes items older than `files.recycle_days` (default 30, 1 to
  365) with the checks above and ends their records (folder upload rows marked deleted, cached hashes dropped); an
  administrator can empty one location's bin at once (`files.purge` with `early`).
- **Retention (spec 040).** A folder upload is recorded with `uploads.target = 'folder'`: it belongs to no chat,
  the link call never takes it, and retention's sweep takes only `target = 'chat'` - chat retention never deletes a
  file uploaded on the Files page. A chat attachment moved out of `Web_Uploads` on the page keeps its row's old
  path, and retention deletes only a file still in a `Web_Uploads` folder with the recorded file index, so it does
  not follow the attachment to its new place. A folder upload's row follows its file through renames, moves, the
  recycle bin and restore, so "uploaded by" stays right.
- **Audit and chain of custody** (F-5, F-16). Every upload, download (also through `/api/fs/download`), read
  (`/api/fs/read`), preview, new folder, rename, move, delete, restore, purge and recycle conflict is audited
  (`files.*`; the path as target; size, SHA-256 when known, from and to for moves) and reaches `activity.jsonl` and
  so the SIEM (spec 017). For evidence, a recorded SHA-256 must be the file's:
  - An upload's SHA-256 is computed from the pieces as they arrive and compared with the finished file, read once
    through a handle nobody may write meanwhile. A file changed on the server during its upload - the hidden
    partial file can be written by the teammates' agents - is not kept (`409 upload_changed`; `files.upload` with
    `ok=false`, `sha256Received` and `sha256OnDisk`).
  - A stored SHA-256 (of an upload, or computed on request) is given only while the file's size and modification
    time are exactly - to the nanosecond - what they were, and always with its source (`upload` or `computed`) and
    time; **Compute again** (`force`) reads the file anew.
  - A download is audited when its answer has ended, with the SHA-256 of exactly the bytes sent when they were the
    whole file; a part (`Range`), a download that did not finish or another status records `sha256Omitted` with the
    reason, `status`, `complete: false` and the bytes sent. No stored hash is ever written into these rows, and a
    `HEAD` request writes none. Previews and `/api/fs/read` record the SHA-256 of what they read when it was the
    whole file.
  - A request refused with 403 is recorded as `files.refused` (`ok=false`; route, refusal and the path asked for),
    at most once a minute per person, route, refusal and path, so probing for other people's paths shows in the
    SIEM.
  - The one-time switch-on and every later change of a team's switches are `team.update` rows with the values that
    changed (F-8).

### 24.3 The independent assessment (2026-11-25, before release)

- **Who.** An independent review: a separate AI agent, not the one that wrote the changes; read-only on all code,
  nothing in the repository was changed; its probes ran in-process against the test suite's fixtures.
- **What.** The release candidate `a4f31a0` against 1.27.1 (`7be00d2`): 33 files, +4,055 / -219 lines - the new
  `files.py`, `views/files.js`, `uploader.js` and their tests, and changes to `api.py`, `uploads.py`, `policy.py`,
  `retention.py`, `db.py`, `app.py`, `config.py`, `composer.js`, `home.js`, `chat.js` and `admin.js`. Focus, in
  this order: authorization and isolation; path and file-system attacks on Windows; content safety in the browser;
  resource exhaustion; data loss and audit completeness; test quality and the uploader extraction.
- **How.** (A) A review of the whole server diff - `files.py` line by line - and of what it calls, and of the
  browser's sinks (`views/files.js`, the composer's attach functions, `?attach=`, `uploader.js` against the code it
  replaced). (B) The test suites of the feature: 147 passed, 1 failed (F-14), 1 skipped. (C) 21 probes that drive
  the real routes in-process with the suite's own fixtures, with real NTFS junctions and 8.3 names enabled on the
  volume; races were simulated with a hook at the exact point of the window, another volume by a rename that fails
  as across volumes, as the suite does. (D) One fact checked in Goose's source: its project skill folders.
- **Not exercised.** No browser session, no real second volume and no real race; Goose was not started (F-4 was
  not tried against a running Goose); whether a sandboxed agent can create links was not measured again - the
  assessment relies on 13.3, 16.2 and 22.7 (it cannot link to a place it may not write).
- **Verdict.** Ship after fixes. The core held: every route goes through the switch and `_check_path`, and none of
  the direct attempts got out of a person's folders; previews and downloads are served safely; retention leaves
  Files uploads alone; purge removes only what it recorded; the uploader extraction did not change the chat path.
  To be fixed before release: F-1 to F-6 and F-14; the rest could follow in a point release.
- **Fixes.** All seventeen are fixed in this release: F-17 by these release documents, the others each with a
  regression test that failed on the candidate's code or with its fix taken out (F-10: by construction) -
  `tests/test_files.py::test_f<N>_*` and `tests/test_frontend_files.py`. After the fixes the same suites: 189
  passed, 1 skipped; the rest of the suite without the long-running files: 1,149 passed, 4 skipped, 0 failed.

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-1 | Medium (High where a writable folder holds a link made outside the sandbox) | A move across volumes copied what a junction inside the moved folder points to, with the gateway's rights, into a folder the person reads | Fixed in `cb0957e`: a folder holding a link is not copied (`409 has_link`); every entry held and checked while copied |
| F-2 | Medium | Rename, move and delete re-checked only the destination: a source folder swapped for a link moved someone else's files | Fixed in `cb0957e`, `3cf2842`: the item and both folders pinned and held open while it moves |
| F-3 | Medium | A member could rename, move or delete another team's location top lying inside a folder they may write | Fixed in `ad6824e`: everybody's locations are protected tops for members too |
| F-4 | Medium | A member with every Goose permission off could plant skills, recipes and agents in `.goose` / `.claude` folders, and a `.gooseignore` | Fixed in `b93e7f9`: refused for members on every route that creates or changes something |
| F-5 | Medium | The SHA-256 recorded for an upload was of the bytes received, not of the file, and was shown and written into download audit rows after the file changed | Fixed in `cb68222`: the finished file is read and must match; stored values only for the unchanged file, labelled; downloads audited with the SHA-256 of the bytes sent |
| F-6 | Low | A per-person override that is not a boolean (`"false"`, `"off"`, `"0"`) switched Files and manage on | Fixed in `2f4126a`: 400 when saved; anything but `true` is off |
| F-7 | Low | Hints files could be renamed, moved or deleted through their 8.3 short name, or with the folder holding them (also an `.agents` folder) | Fixed in `3cede7f`: the long name is checked too; members do not change a folder holding them (also `.goose` / `.claude` folders since `e249652`, G-2) |
| F-8 | Low | A team saved without the two keys lost both switches silently; a lost settings key would switch them on again | Fixed in `2524f87`: stored values kept on such a save; the policy change audited |
| F-9 | Low | The Files switch was checked only when an upload started; its pieces and the finish went on after it was switched off | Fixed in `643cd17`: checked for every piece and at the finish |
| F-10 | Low | A move across volumes that could not delete the whole source answered "denied", yet left a full copy, a half-deleted source and no audit row | Fixed in `cb0957e`, `643cd17`; for delete and restore in `e249652` (24.4): answered with a warning, audited `sourceLeft` |
| F-11 | Low | Anything named `.goose-web-recycle` that is not a folder blocked every delete in that location | Fixed in `643cd17`: moved aside, audited `files.recycle_conflict`; one its maker keeps open still blocks (24.5) |
| F-12 | Low | Heavy work shared asyncio's default thread pool with sign-in and uploads; no global cap on hashing, none on copies and previews | Fixed in `8d231c6`, `e249652` (G-1), `c3a5013` (H-4): eight threads of its own, at most two per person; per-person limits; a pause between forced hashes |
| F-13 | Low | Purge retried the items it could not remove first, for ever, so enough of them starved the rest; no way to empty a bin early | Fixed in `0cdd009`: such items wait an hour, behind the others; administrators can empty a bin; its size is shown |
| F-14 | Low (release gate) | The candidate's own front-end test failed | Fixed in `cb68222`: expectation corrected; a test for Compute again added |
| F-15 | Info | Bidirectional and zero-width control characters were kept in names (`invoice<U+202E>fdp.exe` showed as `invoiceexe.pdf`) | Fixed in `643cd17`: Unicode format characters dropped; refused by the folder picker's New folder since `e249652`; the zero-width joiners kept where words and emoji need them since `c3a5013` (24.4) |
| F-16 | Info | Refused attempts were not audited; a `HEAD` request wrote a `files.download` row | Fixed in `cb68222`, `643cd17`: `files.refused`; `HEAD` not audited; downloads recorded when sent; not for the older `/api/fs/*` routes (24.5) |
| F-17 | Info | Version, CHANGELOG and this section were missing; two rows of the builders' threat table overstated what was refused | Fixed by the release documents: version 1.28.0, CHANGELOG, this section (written from the code as released) |

### 24.4 Further reviews of the fixes, and a browser test (2026-11-25)

Three rounds: a second review of the fixes of 24.3, a third review of what that and a browser test changed, and two
verifications of the last fixes. Each round's findings were fixed - or are residual risks (24.5) - before the next.

**Second review (of `cb0957e` to `3cf2842`).**

- **Who and what.** The same kind of independent review as 24.3 (a separate AI agent, not the one that wrote the
  changes; read-only), of the fixes `cb0957e` to `3cf2842` against the candidate `a4f31a0`: each finding tried
  again, and the new code read for what it might have broken.
- **How.** The feature's suites (189 passed, 1 skipped: the MXC end-to-end test, MXC not installed there) and 17
  probes in 5 files against the real routes in-process, with real NTFS junctions and 8.3 names; another volume and
  the races simulated as the suite does. Symbolic links could not be created there (no privilege), so only junctions
  were tried; no real second volume, network drive or browser.
- **Verdict.** Ship. None of the new findings lets a person out of their folders.
- **The seventeen findings.** Fixed as described (24.3): F-1 (a junction as the item, four levels down, leading into
  the person's own folders, put in during the copy or during the delete of the original: `409 has_link` or only the
  link removed; nothing outside touched, no temporary copies left), F-2 (every swap tried from inside a move - the
  item's folder, the item, the target folder, the folder above it - refused by NTFS while the handles are held; no
  handle left afterwards), F-3 (other teams' and persons' tops denied in every spelling tried: 8.3 name, both
  `$INDEX_ALLOCATION` forms, trailing dot or space, through a junction, a team folder behind a junction), F-4 (15
  names by 5 routes and 6 spellings of an existing `.goose` / `.claude` by 10 routes changed nothing), F-5
  (`409 upload_changed`; the SHA-256 of what was sent; `sha256Omitted` for every `Range` form; no row for `HEAD`;
  `complete: false` for a download broken off on a real uvicorn), F-6 to F-9, F-13 and F-14 (F-9 by the suite and
  the code). F-12 holds for sign-in and listings (but see G-1). Two were incomplete and are completed in `e249652`:
  F-10 (a delete or a restore across volumes dropped the list of what could not be deleted; now a warning and
  `sourceLeft`, as for a move) and F-15 (`/api/fs/mkdir` kept U+202E and U+200B; now `400 bad_name`). Two keep a
  residual (24.5): F-11 (something squatting the recycle folder's name that its maker keeps open still blocks
  deletes there) and F-16 (refusals of the older `/api/fs/*` routes are not recorded). F-17 was the release
  documents, these.
- **Also found sound.** No deadlock; no leaked handle (none over 200 failing copies and 80 renames); no limit slot
  left taken; chat uploads unchanged; **Empty now** needs the CSRF header and is refused to members (`403`); the
  recycle bin's size; deep paths (232 and 430 characters); files open elsewhere.

| ID | Severity | Finding | Status |
|---|---|---|---|
| G-1 | Low | One person could fill all four Files threads (two SHA-256 computations and two moves, or four upload finishes); everybody else's rename, delete, hash and upload finish waited for them (4.1 s in the probe; minutes with files of several GB) | Fixed in `e249652`: one person holds at most two of the threads, given back when the work has finished, not when the request went away |
| G-2 | Low | A member could rename, move or delete a folder that holds an administrator's `.goose` or `.claude` folder; the walk of F-7 looked for hints files, `.gooseignore` and `.agents` only | Fixed in `e249652`: the walk looks for all three folders (`403 agents_folder_refused`) |
| G-3 | Low | A team saved with `"false"`, `"off"` or `"0"` for a switch stored it as on (`bool("false")` is true); the Admin page sends booleans, so only a script could | Fixed in `e249652`: the words are read as words, other text is `400 bad_value` |
| G-4 | Info | `files.refused` has no limit per person: 300 different paths gave 300 rows | Residual (24.5) |
| G-5 | Info | A folder tree 1,100 levels deep moved across volumes raised an unhandled `RecursionError` (`500`); nothing was lost | Residual (24.5) |
| G-6 | Info | From the code: folders that resolve to a network path would refuse rename, move and delete with a misleading message | Residual (24.5) |
| G-7 | Info | A finished upload that something else holds open for writing is discarded as changed (`409 upload_changed`) | Residual (24.5); fails safe |

- **After the review.** `e249652` fixes G-1, G-2 and G-3 and completes F-10 and F-15, each with a test in
  `tests/test_files.py` (`test_g1_*`, `test_g2_*`, `test_g3_*`, `test_f10_delete_and_restore_*`, and
  `test_f15_*` extended) that fails on `3cf2842` and passes on `e249652`. The full suite at `e249652`: 1,289 passed, 14 skipped, 1 failed - a test that measures wall-clock
  time and fails when the machine is busy (the browser test was running); it passed alone.

**Browser test (T11, by the builders).** The release on a throwaway gateway with two members of one team (no Shell;
the team's Files switches on by default) and a team folder: one member uploaded a 20 MB pcap, a text file and a PNG
through the file chooser and by drag-and-drop and made a folder; the other saw them with "uploaded by", the type
recognised from the bytes and the SHA-256 recorded at upload - equal to the SHA-256 taken before the upload -,
computed it again, downloaded, previewed the text and the image, used **Ask Goose about this** (the agent, with the
base extensions only, read the teammate's file and answered correctly), renamed, moved, deleted with **Undo**,
restored from the recycle bin and read the folder's activity; all 13 audit rows had the right SHA-256. A 1 GiB file went
through the same chunked upload (12 s) and download (9 s, `Content-Length` the file's size, not compressed) with
the same SHA-256 at every step, and the page was used at a phone's width (390 pixels). Found and
fixed in `8c25d92`: downloads went through the gateway's GZip middleware - compressed on the fly, without
`Content-Length` (no size or progress in the browser), and the audit row's `sent` counted compressed bytes (its
SHA-256 was right); and with the details pane open at 1,264 pixels the list was 346 pixels wide and names broke
after four letters.

**Third review (2026-11-25, of `e249652` and `8c25d92`).** The same kind of independent review, of the delta
`3cf2842..8c25d92`: the feature's suites (83 passed) and probes. Verdict: ship after fixes (H-1).

| ID | Severity | Finding | Status |
|---|---|---|---|
| H-1 | Medium | Made by the F-15 completion: **New folder** (`/api/fs/mkdir`) walked up the missing folders on the event loop without a limit, in a time growing with their square - a 60 KB request held the gateway for 20 s, and the 2 MB body limit allows hours | Fixed in `c3a5013`: at most 32 new folders, the walk and the folder made in a thread, request paths over 4,096 characters refused before they are resolved (`400 bad_path`) |
| H-2 | Low | A restore that left something in the bin kept the item's full size there; a second restore brings what was left back as `name (restored)`, and its purge is audited like an item | Partly, in `c3a5013`: the size of what is left; the rest is a residual risk (24.5) |
| H-3 | Low | Team switches given as `["false"]`, `{"a": 1}` or `2` were stored as on; a team's `require_totp` given as `"true"` was dropped silently (two-factor not required) | Fixed in `c3a5013`: only true/false, 0/1, null and the words; `require_totp` read the same way |
| H-4 | Low | Two people at their share still filled the four threads | Fixed in `c3a5013`: eight threads |
| H-5 | Low | The walk of F-7 / G-2 skipped a sub-folder it could not list - the check failed open there | Fixed in `c3a5013`: a member does not change such a folder (`403 denied`) |
| H-6 | Info | `_GATES` keeps a closed event loop alive after contention; only tests have more than one loop | Residual |
| H-7 | Info | Dropping every format character also dropped the zero-width non-joiner and joiner that Persian and Indic words and emoji sequences need | Fixed in `c3a5013`: kept right after a non-ASCII character that is not one of them |
| H-8 | Info | A member cannot rename, move or delete their own folder where a tool made `.goose` or `.claude` | Residual (24.5) |
| H-9 | Info | By reading: what is left of an original after a delete across drives loses its "uploaded by" and SHA-256 records to the copy in the bin | Residual (24.5) |

**Verifications (2026-11-25).** The reviewer checked `c3a5013` (132 passed; the H-1 request now answers in
0.006 s, a 10 KB path in 0.003 s) and then `56821ca` (198 passed, 1 skipped; a 32 KB `cwd` denied in under
0.1 ms), and found the same kind of freeze through two older doors, and lower issues:

| ID | Severity | Finding | Status |
|---|---|---|---|
| I-1 | Medium (older than 1.28.0) | The chat socket resolved a member's `cwd` of `session/new` - and `additionalDirectories`, `workingDir`, `projectDir`, sub-recipe paths - with `realpath` and no length limit, on the event loop: 24 s for 32 KB | Fixed in `56821ca`: `policy.path_too_long` (over 4,096 characters or 128 levels) is checked before anything resolves a path |
| I-2 | Low | Within 4,096 characters, 2,000 path levels still took 1.9 s per folder request | Fixed in `56821ca`: at most 128 levels (`400 bad_path` in 5 ms) |
| I-3 | Info | Unassigned code points (U+E0000, U+E0002-E001F, U+2065) and a few invisible characters outside category Cf stay in names; none reorders text | Residual: dropping unassigned characters would also drop emoji newer than the server's Unicode tables |
| J-1 | Medium (older than 1.28.0) | `additionalDirectories` had no limit on its entries, each resolved on the event loop: 1,000 deep entries 8.5 s, a 64 MB message minutes | Fixed in `f7b1ed0`: a list of at most 32, for administrators too |
| J-2 | Low | A delete or move of 200 paths, each 128 levels deep, takes 10 to 14 s; the gateway is not frozen (others waited 0.2 to 0.4 s) | Residual (24.5) |
| J-3 | Low | Made by I-1's fix, administrators only: a member-writable folder written with more than 128 separators was no longer recognised, so its plugins were not confirmed | Fixed in `f7b1ed0`: such a path counts as member-writable |
| J-4 | Info | The Files routes answered `bad_request` for a long path, the folder routes `bad_path` | Fixed in `f7b1ed0`: `bad_path` for both |

- **Tests after all fixes.** Each fix has a test in `tests/test_files.py` that fails on the code before it
  (`test_downloads_go_out_as_they_are_never_compressed_on_the_fly`, `test_h1_*`, `test_h3_*`, `test_h5_*`,
  `test_i1_*`, and `test_f10_delete_and_restore_*`, `test_f15_*`, `test_g1_*` extended). The full suite at
  `56821ca`: 1,295 passed, 14 skipped, 0 failed; at `f7b1ed0`: 1,295 passed, 14 skipped, 0 failed.

### 24.5 Residual risks

- **On by default.** On upgrade every member of every team gains download, upload, rename, move and delete in the
  folders they already have, through the gateway - also in teams without Shell (24.1). Switch it off per team
  where that is not wanted.
- **The recycle folder is an ordinary folder.** The members' agents that may write in the location, and anyone
  with access to the server's disk, can read, change or remove recycled items; it is not a backup. A member cannot
  remove a file uploaded by mistake for good before `files.recycle_days` (an administrator can empty the bin).
  Recycled items use disk space until purged, and there is no quota per location or person (as 23.6).
- **Reads by path.** Download, preview, info and hash open the file by its path after the check, so a link swapped
  in between would be followed - for a read only, and only with a link made outside the sandbox and a won race (the
  precondition of F-1 and F-2).
- **SHA-256.** Someone who may write a file can change it in place and restore its size and modification time to
  the nanosecond; the stored SHA-256 is then still shown - labelled with its source and time - while downloads and
  previews record the SHA-256 of what they actually sent. For evidence use **Compute again**. An upload whose
  SHA-256 state is rebuilt after a gateway restart reads the partial file from disk, so a change made before the
  restart is not caught by the final check. A gateway that stops in the middle of a download leaves no
  `files.download` row (rows are written when the answer has ended).
- **What people see.** A folder's activity shows teammates' and administrators' actions in it, and paths in other
  locations (where an item came from or went to); "uploaded by" shows user names. **Copy link** puts server paths
  into URLs, browser history and chat messages. A link `#/chat/<id>?attach=<path>` from someone else places a
  visible chip for a file the reader may read; nothing is sent without Send.
- **Administrators** act with the gateway's rights on whole drives on their Files page; their deletes there land in
  `<drive>\.goose-web-recycle` or in the recycle folder of the deepest protected folder (the profiles root's for a
  profile's own files).
- **Nested locations** (F-3). What a member deletes inside another team's location that lies within their own
  folder lands in that team's recycle bin: its owners see it, the member does not.
- **Goose's folders.** Members' agents with Shell can still write hints files and `.agents`, `.goose` and `.claude`
  folders where they may write, as before. Goose's memory extension may keep `.goose\memory` in a chat folder;
  members cannot change it through the file browser any more (their agent can), nor rename, move or delete a folder
  that holds it (G-2): such a folder - also one where only Goose's memory extension made `.goose\memory` - is
  renamed, moved or deleted by an administrator (H-8); so is a folder with a part the gateway cannot read (H-5).
  Not done: a warning at `session/new` for a folder with project skills when the member has no `skills_edit` (an
  option the assessment named for F-4), and a `goose-web check` line for something squatting the recycle folder's
  name (handled at delete time instead, F-11).
- **Limits.** Members cannot rename, move or delete a folder with more than 100,000 entries (the walk of F-7 fails
  closed). A file that is itself a reparse point (a deduplicated file, a cloud placeholder) is not moved to another
  drive (`409 has_link`); inside folders such files are copied as data. A copy to another drive takes the
  destination's permissions; its times and read-only flag are set by path after it is closed, inside the held
  temporary folder. The per-person limits and the once-a-minute limit of `files.refused` are kept in memory and
  start again after a restart. Each preview may hold up to 20 MB in memory (two per person). A Files upload that
  failed on the network keeps its partial file for **Retry** until its row is removed, or for 24 hours. Listings
  match upload rows without an index and the activity view scans the audit table; both grow with use.
- **Left from the reviews (24.4).** Each of one person's refused attempts at a different path makes a
  `files.refused` row (G-4; the once-a-minute limit is per path). A folder tree more than about 1,000 levels deep
  cannot be moved to another drive (an unhandled error, `500`; nothing is lost; G-5). Folders that resolve to a
  network path (`\\server\share`) would refuse rename, move and delete with a misleading message (G-6, from the
  code). A finished upload that something else holds open for writing is discarded as changed (`409
  upload_changed`: upload it again; G-7). Something squatting the recycle folder's name that its maker keeps open
  still blocks deletes in that location until it is closed (F-11). Refusals of the older `/api/fs/*` routes (the
  folder picker, chat attachments) are not recorded as `files.refused` (F-16). After a restore across drives that
  left something in the bin, a second **Restore** brings what was left back as `name (restored)`, and its purge is
  audited like an item (H-2); what is left of an original after a delete across drives loses its "uploaded by" and
  SHA-256 records to the copy in the bin (H-9). A delete or move of 200 very deep paths takes 10 to 14 seconds
  while the gateway goes on serving others (J-2). A few invisible characters outside Unicode's format category stay
  in names (I-3).
- **Platform.** Elsewhere than on Windows the held moves fall back to comparing before and after, with a put-back
  on a mismatch; the product and its CI are Windows-only.
- **Not exercised:** by the reviews, a browser session (the builders' browser test of 24.4 covered the page, with
  one browser, the two members one after the other); by anyone, a real second volume, a network drive, a real race,
  symbolic links (junctions only), and F-4 against a running Goose (24.3).
