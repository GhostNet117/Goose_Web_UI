# Changelog

## 1.15.0 - 2026-11-10

A steer is never lost silently (bug steer-lost-on-slow-turn), and your live state survives a refresh, another
device and a restart (spec 019).

- **Why steers were lost.** Goose accepts a steer at once but the agent reads it only at its next step (after the
  model's current reply or tool call). In a long chat the first reply can take minutes; pressing Stop before then made
  Goose drop the steer without a word, while the page showed it as sent. Reproduced with a provider whose first reply
  takes 75 s (Goose 1.57.0; the same code in 1.50.0).
- **Steer tracking in the gateway.** The hub follows each steer until its user message appears in the run
  (*delivered*); if the run ends first (Stop, error, end, worker restart) the steer goes back to the top of the chat's
  queue, **held**, with a notice in the transcript and a toast. The steer bubble shows *waiting for the agent's next
  step*, *delivered* or *not delivered - back in your queue*. Fixed: a delivered steer showed its text twice; a
  steer's chunk could take over the bubble of the prompt before it.
- **Steers are audited** as `chat.steer` (length and attachments, never the text) and go through the **prompt guard**
  like prompts (they were not checked before).
- **Stop while disconnected** now says it was not sent (it used to do nothing).
- **The queue lives in the gateway** (`_gw/queue`, `_gw/queue_update`): it survives a refresh, shows on all your
  devices, is sent once even with several tabs open (a tab claims an item before sending), and is kept across a
  restart (`chat_state` table, schema version 6). Queued items gain **Edit** (back into the message box). Held items
  (returned steers, items kept across a restart) are only sent by your click.
- **Per-user snapshot on connect.** `_gw/hello` also returns the queues and pending steers. The *done* / *error*
  markers ("done" counter, green dots) are kept in the database until you open the chat, so a Goose Web restart no
  longer resets them; a chat that was running when Goose Web restarted shows *Error: Interrupted*.
- **Drafts** (unsent text in a chat's message box) are kept in the browser per chat and cleared at sign-out.
- Docs: USER-GUIDE (While Goose is running, Herd statuses, FAQ), TROUBLESHOOTING 19, ARCHITECTURE (hub steers and
  queue, `_gw` methods, `chat_state`), ADMINISTRATION (audit list). Service worker cache `gw-shell-v21`.

## 1.14.2 - 2026-11-10

The Prompt Guard model is installed automatically (spec 018).

- **Model package published and pinned.** The Llama Prompt Guard 2 22M package (ONNX, int8 word embeddings, Meta's
  revision `11614a15`, every source file checked against Meta's release) is the asset of the dedicated GitHub release
  `prompt-guard-2-22m-onnx-1` (independent of app versions, so the address stays the same). `MODEL_PIN` in
  `goose_web/guardmodel.py` pins its URL, SHA-256 (`76d04f90...eab3`) and size (116,747,849 bytes). Fresh installs
  (`install.ps1`), upgrades (`upgrade.ps1`) and `goose-web guard install-model [--if-missing]` now download and verify
  it with no manual step; a valid installed model is left alone; a failure stays a warning (the guard fails open).
- **Download:** HTTPS only (a redirect to http is refused), the standard proxy variables (`HTTPS_PROXY`, `NO_PROXY`),
  60 s read timeout, three attempts on network/server errors, progress messages, stopped at the pinned size, then the
  SHA-256 and every file in `export.json` are checked. Offline: `goose-web guard install-model --file <zip>` (the
  pinned SHA-256 applies; `--sha256` only for a package of your own).
- `goose-web guard status` and `goose-web check` show the package source; Admin > Prompt guard shows it and the
  offline command. Removed the "official weights are gated, nothing pinned" messages.
- Tests: the pinned download path with mocked HTTP (redirect, progress, no second download, tampered or oversized
  download refused, retries, proxy environment, offline file); no test reaches the network (`tests/conftest.py`).
- Docs: ADMINISTRATION 9.8 (where the model comes from, offline install, licence), README, CONFIGURATION,
  TROUBLESHOOTING 18, THIRD-PARTY-NOTICES.md. Service worker cache `gw-shell-v20`.

## 1.14.1 - 2026-11-10

Prompt guard, verified with the real Llama Prompt Guard 2 22M model (spec 018).

- **`scripts/export-prompt-guard.py`:** `--source meta | mirror | dir` - besides Meta's gated repository (HF_TOKEN),
  the ungated byte-identical copy at a pinned revision or a local folder. Every file's size and SHA-256 is checked
  against Meta's release (pinned in the script, with their provenance) before it is used.
- **Export fix - tokenisation in the validation.** Prompt Guard 2's tokenizer removes whitespace on purpose (resistance
  to "i g n o r e" style attacks); transformers 5 rebuilds a standard DeBERTa tokenizer without that step, so the
  script's PyTorch reference saw other tokens than the gateway. The validation now feeds both models exactly what
  the gateway feeds (the package's tokenizer.json). The gateway itself was always right.
- **Export default `--quantize embeddings`:** only the word embeddings are int8, the encoder stays fp32 (package
  about 117 MB). Full int8 changed the real model's verdicts (score differences up to 0.55-0.96 on 191 test texts);
  this keeps them (max 0.09, mean 0.004).
- **Classifier:** windows of different lengths are scored without padding (the full ones together, the shorter last
  one alone): a text just over one window is about 1.5x faster.
- Docs: ADMINISTRATION 9.8 - building the package from the mirror, real N100 timings and what the classifier
  catches and misses. No package is pinned yet (distribution is being decided).

## 1.14.0 - 2026-11-10

- **Prompt guard (spec 018), off for every team until an administrator turns it on.** Admin > Teams & policy >
  Experience > *Prompt guard* and the new **Admin > Prompt guard** page:
  - **Rule sets** stored in the database and edited in the UI (tool glob, arguments, pipeline / regex / words match,
    applies to tool arguments and/or prompts, message); shipped defaults *Splunk read-only* and *Destructive shell*,
    resettable; a Test box (dry run).
  - **Classifier:** Meta's Llama Prompt Guard 2 22M on ONNX Runtime, CPU only, loaded on first use, windows of 128
    tokens, cached, nothing at run time over the network. Built with Llama.
  - **Enforcement:** what guarded users type (block, as an error or silently) and the arguments of tool calls Goose
    asks permission for (the gateway answers *deny once*; tool results are never inspected). Guarded teams use
    Approve (no Auto / Smart approve, no *always allow*); **guarded auto** lets the gateway approve calls that pass.
    Administrators: their own guard; Auto bypasses, Approve is guarded, Smart approve is refused while it is on.
  - **Fail open** with `guard.unavailable` audit and an admin banner; `guard.blocked` audit (and activity.jsonl)
    without content.
  - `goose-web guard status | install-model | remove-model`, a `check` line, `install.ps1` / `upgrade.ps1` install the
    model when a package is pinned (SHA-256 verified). The official weights are gated on Hugging Face, so 1.14.0 pins
    no package yet: `scripts/export-prompt-guard.py` builds it once from an account that accepted the Llama 4
    Community License (ADMINISTRATION 9.8).
- New dependencies (hash-locked): onnxruntime, tokenizers, numpy (< 2.5, for Python 3.11). Database schema 5
  (`guard_rulesets`). Service worker cache `gw-shell-v19`. THIRD-PARTY-NOTICES.md.
- Tests: a TestClient test now uses the httpx flavour Starlette picks (httpx2 when installed).

## 1.13.1 - 2026-11-10

**Security fix - upgrade if you have non-admin users.**

- **Goose plugins in a chat folder (NEW-36, High).** Goose 1.50-1.57 loads every folder under
  `<chat folder>\.agents\plugins` as an enabled plugin when a chat starts and runs its MCP servers (commands), with
  no setting to turn that off. A member with `allow_shell` off could upload such a folder with the file browser
  (workspace or team folder) and run commands in their sandbox, or in the worker of anyone who opened a chat there.
  Now non-admins cannot create or upload into a `.agents` folder (`403 agents_folder_refused`; case, trailing
  dots, NTFS stream and 8.3 short names included), and a member without `allow_shell` cannot start a chat in a
  folder whose `.agents\plugins` holds a plugin. Admins and the native profile are unchanged (SECURITY-ASSESSMENT
  10, ADMINISTRATION 9.7, TROUBLESHOOTING).

- **Docs: forwarding logs to Splunk or another SIEM** (ADMINISTRATION 18.1): which files in
  `<system_dir>\logs` to monitor (`activity.jsonl*` = security feed with every audit event, `gateway.log*`,
  `worker-*.log`), which not to (Goose's own per-profile logs hold conversation content), inputs.conf and
  props.conf examples, time zones, rotation and the disk budget, and the read grant a Splunk UF 9.1+ running as
  `NT SERVICE\SplunkForwarder` needs. TROUBLESHOOTING has a row for a forwarder that reads nothing.

## 1.13.0 - 2026-11-09

- **Windows only for now.** Linux, macOS and Docker are no longer shipped or supported: Goose Web has no per-user
  sandbox there yet, so team members' agents would share the gateway's OS account with access to every profile.
  `scripts/install.sh` and `docker/` are removed, CI runs on Windows only, and `goose-web serve` refuses to start on
  other systems (`goose-web check` reports it). Support may return once Linux and macOS have a sandbox like the
  Windows AppContainer one (ADMINISTRATION 2). Releases up to 1.12.0 in the git history still contain those files
  but are unsupported.

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
