# Changelog

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
