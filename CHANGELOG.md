# Changelog

## 1.12.0 - 2026-11-09

**Security release - upgrade if you have non-admin users.** An independent adversarial assessment of 1.11.0 found one
Critical and eight High issues; all are fixed (SECURITY-ASSESSMENT 9). Most important: a member with every permission
off could run commands through a recipe deeplink at chat creation (B-1), and the model could switch the disabled
shell extension back on through `extensionmanager` (B-2).

- **Agent firewall:** recipes (deeplink, id, schedules, imports, sub-recipes) are resolved and checked by the gateway;
  members' `_meta` is allow-listed; `developer`, `computercontroller`, `code_execution`, `orchestrator`, `summon` and
  `scheduler` are pinned off without `allow_shell` (members without it lose sub-agents and schedules) and
  `extensionmanager` needs `extensions_edit` + `allow_shell`; runtime extension starts and delegations are audited.
- **Sandbox and relays:** allow-listed worker environment (no more inherited API keys), unguessable relay pipes that
  cannot be squatted, per-user container names that cannot collide, one kill-on-close job per worker, provisioning
  records moved out of the user's profile, dangerous team folders refused.
- **Sign-in:** request bodies capped while streaming; lockouts no longer a denial-of-service or user-name oracle;
  OIDC tied to the browser, no account binding by user name, `stripDomain` default off, two-factor asked after
  OIDC; "Require two-factor for administrators" is enforced (enrolment screen); logout needs the CSRF token.
- **TLS:** the local CA is name-constrained to this machine (**clients must import the new CA once**: a 1.11 CA is
  replaced at the first start), keys are owner-only, and the file browser can no longer open `<system_dir>`.
- **Install:** `install.ps1` / `upgrade.ps1` lock the install folder down (it was writable by every local user);
  `goose-web check` reports it; `goose-web sandbox remove --all`; uninstall removes the containers. A missing
  `--config` / `GOOSE_WEB_CONFIG` file is now an error.
- **Front end:** model output can no longer style itself as app dialogs; "Copy code" copies what you see; app tool
  calls and resource reads always ask first; the login page shows only known error texts; sign-out clears local data.
- **Admin > Teams:** allowed providers and models are picked from lists of what your Goose knows (with model context
  sizes, All/None per provider), and the default provider and model are drop-downs.

## 1.11.0 - 2026-11-09

- **Built-in HTTPS:** Goose Web creates its own local certificate authority and a server certificate for every name
  and address of the machine (localhost, 127.0.0.1, ::1, host name, FQDN, IP addresses, bind address, public URL,
  allowed hosts, `server.tls_names`), renews it automatically (30 days before expiry, or when a new name/address
  appears) and loads it without a restart. **Admin > System > HTTPS** switches between the built-in certificate, your
  own certificate files, and off (TLS at a reverse proxy); `goose-web tls status|renew|export-ca|trust`;
  `install.ps1 -Tls`, `-TrustCert`. **Upgrade note:** the default `server.tls: auto` turns HTTPS on for installs
  without `server.public_url`: `http://` URLs, bookmarks and proxies pointing at `http://` must change, or set
  `server.tls: off` before upgrading (ADMINISTRATION 6.3).
- **User activity log:** who did what, when and from where - every audit event plus opening, starting, prompting
  (length only, never the text), stopping and forking chats, mode changes and browser connections - in the audit
  log and in `<system_dir>/logs/activity.jsonl` (JSON lines for log shippers).
- **Log budget:** all logs (gateway, activity, workers, the isolated profiles' Goose logs) stay under 0.5 % of the
  disk volume (`logs.max_disk_percent`); the oldest unused files are deleted, a long-running worker's log is rotated
  in place, and the audit table is capped (`logs.audit_days`, `logs.audit_max_rows`). Admin > System shows usage.
- New dependency: `cryptography` (hash-locked).

## 1.10.1 - 2026-11-08

- **Every Goose release from 1.50.0 to 1.57.0 tested end to end** (administrator on `goose serve`, sandboxed member on
  `goose acp` with a relay). Goose Web now adapts per feature at the version that introduced it instead of treating
  everything before 1.57 like 1.50: scoped tool calls and the tool-shim option 1.51, live voice 1.52, import without
  `source` 1.54, saved per-chat system prompt and `GOOSE_AUTO_COMPACT_TOKEN_LIMIT` 1.55 (ADMINISTRATION 11.7).
  `goose-web check` lists what a version lacks.
- **Fix:** the chat's System prompt dialog failed with "Invalid params" in *Append* mode on every Goose version (Goose
  needs a key for appended prompts). Appended prompts now use the key `goose-web`; the gateway re-applies both the
  appended and the replaced prompt after a worker restart on Goose before 1.55.

## 1.10.0 - 2026-11-08

- **Goose 1.50 support:** Goose Web now works with Goose 1.50 and later (tested with 1.50.1 and 1.57.0). It reads the
  worker's Goose version and adapts: direct tool calls are checked against the named extension (Goose 1.50 ignores
  it - checked on every version now), live voice and the tool-shim option are hidden or refused, chat import sends
  the `source` 1.50 needs, and a per-chat system prompt is re-applied when the chat is reopened (1.50 does not save
  it). `goose-web check` and `install.ps1` report the Goose version (ADMINISTRATION 11.7).
- **Refresh extensions:** chats keep the extension definitions they were created with. Goose Web marks extensions
  whose definition changed since as **outdated** and offers **Refresh extensions** (chat menu, Session extensions,
  and a notice when such a chat opens): it removes and re-adds them through Goose with the current definition.
- **Longer visible history:** a chat now shows the last 300 messages and tool steps (was 80; Settings > Preferences >
  Chat > Messages shown in a chat: 100, 300, 1000 or All) and loads earlier ones automatically when you scroll to the
  top. The old limit looked like early compaction in tool-heavy chats.
- **Relays for sandboxed users:** `sandbox.relays: ["127.0.0.1:8317"]` lets sandboxed agents use a local service such
  as a model proxy, through a forwarder in the user's own container and a named pipe only that container can open;
  the user's provider URLs are pointed at the forwarder and restored when no longer needed. The rest of loopback stays
  closed (ADMINISTRATION 11.6, SECURITY-ASSESSMENT 8.3).

## 1.9.0 - 2026-11-08

- **Guided setup** (`scripts\install.ps1`): asks for the Goose program folder, the first administrator's Goose
  appdata (existing - with a chat count - or fresh), a separate chat-sessions folder (linked in), the administrator's
  user name, Goose Web's data folder, the Windows account that runs the gateway, and the sandbox; summary before any
  change; every answer also a parameter for `-NonInteractive`. The Desktop app's `Goose.exe` is never mistaken for
  the CLI.
- **Service account:** `-RunAs DOMAIN\svc` or a gMSA (`DOMAIN\name$`) registers a start-at-boot task (password in a
  secure prompt, none for a gMSA) and grants the account the folders it needs. `register-service.ps1 -Mode Service`,
  `-DryRun`. `upgrade.ps1` asks for elevation once if restarting such a task needs it.
- **Sandbox on by default on Windows:** `sandbox.enabled` defaults to `auto` (on for Windows, off elsewhere). Upgrading
  turns it on for existing Windows installs: non-admin users' agents are then confined to their profile, team folder
  and the team's extra folders, and cannot reach services on 127.0.0.1 (for example a local model proxy). Set
  `sandbox.enabled: false` to keep the old behaviour.

## 1.8.0 - 2026-11-08

- **Sandbox (Windows):** `sandbox.enabled` runs every isolated non-admin user's agent in its own Windows AppContainer.
  The operating system then limits it to the user's profile, the team folder and the team's extra (approved) folders;
  loopback stays closed. The worker is `goose acp`, connected over its stdin/stdout - no port, no loopback exemption,
  no administrator rights. Grants follow team and folder changes and are revoked when the user is removed.
  `goose-web sandbox status|remove`, Admin > System shows sandboxed workers (ADMINISTRATION 11.6,
  SECURITY-ASSESSMENT 8.2).

## 1.7.0 - 2026-11-08

**Security fix - upgrade if you have non-admin users.** Per-session MCP servers (`mcpServers`) on `session/load`,
`session/fork` and `session/resume` were not checked against the `allow_shell` permission (only `session/new` was).
Goose activates them for the session, and a command (stdio) server runs as the gateway's OS account
(SECURITY-ASSESSMENT 8.1, NEW-30, High). Also: `conversation/truncate` refuses non-integer times (NEW-31) and is
audited; `upgrade.ps1 -Ref` is validated (NEW-32) and only the newest 10 upgrade backups are kept.

- **Managed native hints:** `goose-web native-hints enable <admin> --team Admins --adopt` lets Goose Web write the
  native admin's composed hints (personal + assigned + team documents) into the native `.goosehints`, which Goose
  Desktop, the CLI and schedules load too (ADMINISTRATION 10.1, 11.4).
- Docs: your own admin account (native vs isolated, moving from Desktop to the browser), Goose 1.57 settings for long
  chats and slow extensions (ADMINISTRATION 11.5), CLI reference.

## 1.6.0 - 2026-11-08

- **Edit a sent message** (pencil on your message): Rerun here (removes it and everything after it, then sends the
  edited text in the same chat) or Branch (a new chat from that point); like Goose Desktop.
- **`scripts\upgrade.ps1`**: one-command upgrade that keeps every setting (backup first, refuses while an agent runs,
  `goose-web check` before the restart, healthz after; `-Ref`, `-NoGit`, `-Detached`).
- **Custom Goose folders:** `install.ps1 -GooseBinary`, `-GooseAppData`/`GOOSE_PATH_ROOT`; `goose-web native-root`
  moves the native profile later; `check` shows the autostart task. Auto-detection no longer includes a
  developer-specific path: set `goose.binary` if goose is not in a standard location.

## 1.5.1 - 2026-11-08

- Retry/add/remove of an extension in a chat now updates the start-up status that reconnecting tabs are shown
  (before, an extension started later still showed "failed" after a reload).

Older versions: see the commit history.
