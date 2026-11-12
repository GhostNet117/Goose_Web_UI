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
| Folder names | not listable outside grants | listable (names only, no contents) on the drives of granted folders (`enumeratePaths`; node and cmd need it) - **accepted (Q2)** |
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
- Folder names on the drives of granted folders are visible to members' agents (Q2).
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
| Another program on the computer uses the classifier (CPU) or probes it | Bearer token per profile (HMAC-SHA256 of the user id, key only in the database, constant-time check, disabled users refused); rate limit per profile; body cap; 64 connections; uniform `401` |
| A token is stolen | It authorises classification only: no chat, file, setting or account is reachable with it. *Replace all tokens* invalidates every token at once |
| A member, or an agent that was talked into it, switches the detection off | Written before every start of the agent; also in the worker's environment, which Goose ranks above its files (measured); `config/upsert` and `config/remove` of `SECURITY_*` refused by the firewall; `adversary.md` is a refused file name and is rewritten at every start |
| A sandboxed agent uses the endpoint to reach the gateway | The relay target is the classifier port only; the web application's port is not reachable from the sandbox, as before |
| Chat text leaks through the endpoint | Nothing is logged or audited; the cache holds a SHA-256 of the text and a score; requests stay on the loopback interface |
| The gateway points Goose at a port someone else holds | A profile gets the endpoint only while the gateway itself holds the socket (exclusive bind on Windows); otherwise the classifier is switched off in the plan |
| The feature breaks the administrator's Goose | The native profile is changed through Goose's own configuration API, key by key, read back; a failure is recorded and changes nothing else; an `adversary.md` Goose Web did not write is never replaced without an explicit choice and a backup |
| A long text ties up the classifier | Body cap, at most `classifier_max_pieces` pieces, a deadline below Goose's timeout, one request at a time in the classifier thread |
| The rules text or a token ends up in a log | The audit holds switches and sizes only (`goosesec.summary`); the state holds a 16-hex-digit fingerprint of the token, not the token |

### 14.3 Residual risks

- **The port while the gateway is down.** The native profile's `config.yaml` keeps the endpoint address between
  gateway runs. While the gateway is stopped, another Windows account on the same computer could listen on that port
  and would be sent the recent user messages of the administrator's Goose Desktop, CLI and scheduled chats, with
  the token. Goose's client cannot verify who answers (plain HTTP to a fixed address). A sandboxed member's agent
  cannot do this (no loopback, section 13). Mitigations: run the gateway at boot (service account); do not give other
  people interactive or remote-desktop access to the gateway's computer; or set `guard.classifier_port: 0`.
- **One classifier thread.** The endpoint and the prompt guard of section 11 share it. A member's long message can
  delay the administrator's request up to the deadline (the answer is then `503` and Goose uses its patterns).
- **The token in a member's profile.** It is in the profile's `secrets.yaml` and in the agent's environment, readable
  by that member's agent, like every other secret of that profile. It gives the agent nothing it does not have.
- **An unstable Goose method.** The native apply uses `_goose/unstable/config/*`. If Goose renames it, the apply
  fails visibly and the native profile keeps its last settings. `tests/test_goosesec_e2e.py` detects it.
- **Adversary mode** adds a model call that sees the user's first message, recent messages and the tool call. It
  goes to the chat's own provider, which already has that content.
- **Not covered:** a native profile on another computer, and Goose instances started with another
  `GOOSE_PATH_ROOT` that Goose Web does not know.
