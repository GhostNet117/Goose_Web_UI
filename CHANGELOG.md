# Changelog

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
