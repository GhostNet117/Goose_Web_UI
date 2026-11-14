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
| GW-28 | Session cookies and lifetime | Info | Mitigated | `auth.py: create_session`, `resolve_cookie`, `session_seconds`; `api.py: _set_cookie`; `context.py: Ctx.cookie_name` | HttpOnly, SameSite=Strict, Secure and `__Host-gw` with an https `public_url`; 12 h default (DB `session_hours`, 1-720) or `remember_days` (30). Sessions are revoked on password change (other sessions), reset and disable. Lifetimes are fixed: `last_seen` is updated, `expires_at` is never extended. v1.0.0 corrected the code comment that called it a sliding expiry. |
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
| NEW-36 | Goose auto-loads plugins from `<cwd>/.agents/plugins`: a member without `allow_shell` ran commands | High | **Fixed in 1.13.1** | `policy.py: check`, `project_plugins`, `has_agents_component`; `api.py: _refuse_agents_dir` (`fs_mkdir`, `fs_upload`) | Goose 1.50-1.57 treats every folder under `<cwd>/.agents/plugins` of a new chat as an enabled plugin (`plugins/discovery.rs`; unknown plugins are added to config as enabled) and starts its MCP servers (`.mcp.json` or the plugin manifest: any command line) during `session/new` (`acp/server.rs: initial_session_extensions`). No Goose setting or environment variable turns discovery off. A member with every permission off created `.agents/plugins/x/.mcp.json` with the file browser in their workspace or the team folder, started a chat there, and the command ran in their sandbox (measured on Goose 1.50.0 and 1.57.0, sandbox on). In the team folder it would run in every member's worker that opens a chat there, and unsandboxed in an administrator's native worker. Now: non-admins cannot create or upload into any `.agents` folder through the file browser (any case, trailing dots/spaces, NTFS stream names, 8.3 short names via the resolved path; `403 agents_folder_refused`), and a member without `allow_shell` cannot start a chat in a folder whose `.agents/plugins` has a plugin folder (an unreadable one counts). Correction (security review 2026-11-11, section 12): until 1.15.1 Goose's own `sources/create` (skills_edit) could still write `.agents/skills` and `.agents/agents` into the team folder (SD-3), and a plugin in a team folder ran in the chats of members WITH `allow_shell` and of administrators (SD-2); both are closed in 1.15.1. Goose rediscovers plugins only on `session/new`; `session/load`, `fork`, `resume` and working-folder changes do not, and recipe chats skip plugins. Plugin hooks and scheduled jobs use the worker's own folder (the profile root), which members cannot reach through the file API. Tests: `tests/test_agents_plugins.py`. **Upgrade if you have non-admin users.** |

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
