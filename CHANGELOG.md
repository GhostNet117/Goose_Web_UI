# Changelog

## 1.21.0 - 2026-11-13

**Offer your own Goose skills and recipes to a team; nothing is shared by default.** Spec 028. No database schema
change.

- **The picker sees where Goose keeps skills.** "Add from library" for your own (native) profile now lists the
  skills in Goose's home-folder locations as well: `~/.agents/skills`, then `config/skills`, `~/.claude/skills` and
  `~/.config/agents/skills`, in Goose's order (the first folder that has a name wins; the Source column shows the
  folder). Until now it read only `config/skills`, so skills kept where Goose recommends could not be offered.
  Recipes: `~/.goose/recipes` is read too. Home-folder agents are not offered.
- **What the documents said about those folders was too broad.** The README and guides said Goose's home-folder
  skill and recipe folders "are visible to all profiles". Checked in Goose's source (1.57.0, 1.59.0), with the
  Goose binary and in a real container: Goose does find them through the operating system's home folder, which
  `GOOSE_PATH_ROOT` does not move, and that home is the gateway account's. With the sandbox (the default) a member's
  agent cannot read them, so its Goose loads none; without it every profile's Goose loads them all. Members get
  what you offer their team and nothing else. `goose-web check` has a new line that says how many such skills,
  recipes and agents there are and warns when members are not sandboxed.
- **Hardening: the library export no longer reads through links.** Offering a skill from a profile read every
  file in the skill's folder with the gateway's rights, also through a junction, a symbolic link or a hard link; if
  a skill folder in a member's profile held such a link to a file outside it, an administrator who offered that
  skill to a team copied the file's content to the team's members. A member confined by the sandbox cannot create
  such a link (measured: refused), so this mattered where members are not sandboxed or a link got there another
  way. Links are now never followed, for skills and recipes, in any profile; a skill needs a regular `SKILL.md` and
  has at most 500 files (SECURITY-ASSESSMENT 15.3).
- **Correction:** inside the sandbox the names of files and folders on the drive can be listed, not only folder
  names as the documents said (contents cannot be read; accepted since 1.19.0).
- **Tests** never read the developer's own home folder or `GOOSE_RECIPE_PATH`. New: `tests/test_library.py`.

## 1.20.0 - 2026-11-12

**Goose-native security: Goose's own prompt injection detection and adversary mode, for every profile.** Spec 026.
The prompt guard of 1.14.0 runs in the gateway and sees only chats that pass through it. Goose has two security
features of its own that run inside the agent in every front end (Goose Web, Goose Desktop, the goose CLI, scheduled
recipes); Goose Web now configures them where Goose reads them. No database schema change.

- **Prompt injection detection, on by default.** Every member's profile and the administrator's Goose profile get
  `SECURITY_PROMPT_ENABLED`, `SECURITY_PROMPT_THRESHOLD` (0.8) and the classifier settings. Goose then checks every
  `shell` command against its threat patterns and asks before running a match, also in Auto mode. An installation
  that never chose gets this at the first start after the upgrade; `goose-web security off`, Admin > Prompt guard or
  `install.ps1 -GooseSecurity off` turn it off, and the choice survives upgrades.
- **Prompt Guard 2 as Goose's classifier.** New classification endpoint (`classifyapi.py`) that follows Goose's
  Classification API specification, served by the classifier the gateway already runs. Loopback only
  (`127.0.0.1:8711`, `guard.classifier_port`, `0` = off), its own listener, one single-purpose token per profile,
  no request text logged. A port that cannot be bound is reported and Goose then uses its patterns only: profiles are
  never pointed at a port the gateway does not hold. A sandboxed member's agent reaches this port and nothing else of
  the gateway.
- **Members cannot weaken it.** The settings are written before every start of a member's agent and are also in the
  worker's environment, which Goose ranks above its files; a member's `config/upsert` or `config/remove` of a
  `SECURITY_*` key is refused; `adversary.md` joins the file names members cannot create.
- **The native profile through Goose itself.** The administrator's Goose profile (shared with Goose Desktop, the CLI
  and scheduled recipes) is changed through Goose's own configuration API, so Goose decides the file format and where
  the secret is stored; only when something differs, at gateway start and at every change. A failure is recorded,
  audited (`goosesec.native`) and shown, and never stops the gateway or a chat.
- **Adversary mode, off until an administrator turns it on.** Admin > Prompt guard: rules in plain language, reviewed
  tools, separately for members and for the native profile. Goose Web writes `adversary.md`; an `adversary.md` it did
  not write in the native profile is kept (and can be taken over, with a backup). It is off by default because a
  BLOCK cannot be overridden, also stops unattended runs, and every reviewed call costs one more model call.
- **What Goose really does** (read in the source of Goose 1.57.0 and 1.59.0, measured with 1.57.0), where it differs
  from Goose's guides - documented in ADMINISTRATION 9.11: the classifier token is read from the secret store, not
  from `config.yaml`; the classifier is sent the chat's recent user messages, never the command, and can only raise a
  pattern finding; only the tool named `shell` is inspected; a headless run in Auto mode allows a flagged command and
  only logs it.
- **Reviewed before release.** An independent review of this feature found one High and several Medium problems in
  its first version; all are fixed or documented as residual risks (SECURITY-ASSESSMENT 14.3, 14.4). In short: the
  endpoint's work is bounded and has its own thread, so it cannot make the prompt guard fail open; in the native
  profile only Goose Web's own values are ever replaced or removed (yours are kept, "off" leaves them alone); text
  that cannot be scored completely is refused, never reported safe; a tampered `adversary.md` path fails the
  member's start and is audited.
- **`guard.native_profile` (default `true`).** `false` = Goose Web never changes the administrator's own Goose
  profile. Found while verifying the release: a real gateway applies the settings to its administrator's Goose
  profile when it starts, and the test suite starts a real gateway whose administrator is the developer's real Goose
  folder, so running the tests wrote the settings into that profile. The test session now sets
  `GOOSE_WEB__GUARD__NATIVE_PROFILE=false` (`tests/conftest.py`), with a test that proves nothing is asked or changed.
- **Other fixes from the same day's review of the whole product:**
  - Open WebSockets are closed when the caller's role, policy or folders change (a demoted administrator, or a
    member whose team lost a permission, kept the old rights until the tab was closed). The browser reconnects.
  - The change-password check runs off the event loop and is limited to 8 attempts per user in 5 minutes.
  - The audit log is no longer purged with a fixed 365 days at every database open (every start and CLI command):
    a longer `logs.audit_days` now really keeps its rows. The maintenance loop applies the configured retention.
  - `goose-web check` no longer migrates the database (it runs with the new code next to the old gateway during an
    upgrade); it reads the HTTPS setting through a read-only connection.
  - A member's `config.yaml` or `secrets.yaml` that is not readable YAML is moved to
    `<system_dir>\backups\profiles\<user>\` and rebuilt, audited as `profile.file.set_aside`, instead of blocking
    every start of that member's agent until someone repaired it by hand.
  - Session buffer accounting after a worker stop; a tie in the eviction order no longer raises.
  - A worker start that times out no longer freezes every chat while the process is killed.
  - `icacls` and `powershell.exe` are started by their full System32 path.
  - `install.ps1` shows the generated initial password before any later step can fail.
  - `.gitignore`: models, archives, key stores, environment files, journals and backups.
  - Tests and one comment use a neutral example relay port.
- **The gateway runs at normal priority.** Task Scheduler starts a task below normal (CPU, I/O and memory priority)
  unless the task has a priority, and the gateway's task had none. Whenever the computer was busy the whole gateway
  was starved: on 4 busy cores `/healthz` took 3.5 to 4.9 s instead of 2 ms, and the new classification endpoint did
  not answer within Goose's 5 s, so Goose fell back to its patterns. The gateway now raises what is below normal to
  normal at every start (`server.priority`, default `normal`; `inherit` leaves it) and logs it, which also covers
  tasks registered by earlier versions; `register-service.ps1` registers new tasks with priority 4. Measured after
  the fix, same load: `/healthz` in 2 to 33 ms, a classification in 0.4 to 0.7 s.
- **A second independent review, of the fixes themselves** (SECURITY-ASSESSMENT 14.5). The changes made after the
  first review had been read by nobody but their author, so they were reviewed again before release. Two of the
  fixes had introduced regressions, both corrected: an agent started in an MXC container after an AppContainer
  fallback was pointed at a classifier address it could not reach; and in the administrator's Goose profile a
  setting Goose Web had written and something later weakened was silently accepted as the administrator's own. A
  third review of that fix showed ways round a rule that only put "weaker" values back, so the rule is now simple:
  **a setting Goose Web wrote in the administrator's Goose profile stays Goose Web's.** Changed or removed in the
  file, it is put back at the next start, with the changed value saved, an audit entry, a notice and a line on the
  page. What was there before Goose Web first wrote a setting is still kept. A fourth review of that rule found
  that a value which could not be compared (a huge number) stopped the check for good, in silence; comparisons no
  longer convert, and a check that fails is recorded and shown. Also: a setting that merely equals
  Goose Web's is no longer treated as Goose Web's; the backup on take-over is written first; an interrupted apply
  no longer leaves values that belong to nobody; a WebSocket whose sign-in or rights cannot be re-checked is closed;
  refused change-password requests write one audit row per window; set-aside profile files get unique names, the
  newest five are kept and the pruning cannot be steered by the file's date or attributes; every YAML parser error
  leads to the set-aside; `taskkill` by full path. **Known and open:** one profile can keep the classification endpoint busy so that other
  profiles' requests end in `503` and Goose uses its patterns only for those calls (14.3, with measurements).
- **Command line:** `goose-web security status | on | off | rotate-tokens`; `goose-web check` shows the state.
  **API:** `GET/PUT /api/admin/goose-security`, `POST .../check`, `POST .../rotate`.
- **Fix:** `goose-web check` reported the gateway's port as free when `server.host` is a LAN address (it probed
  `127.0.0.1` only).
- **Tests:** `tests/test_goosesec.py`, `tests/test_classifyapi.py`, and `tests/test_goosesec_e2e.py`, which drives the
  real goose binary (set `GOOSE_WEB_TEST_GOOSE`; run it after every Goose upgrade).

## 1.19.2 - 2026-11-12

- **Fix: Python 3.11 support for the MXC backend.** The hard-link check before an MXC start (MX-3) used `DirEntry.is_junction()`, which exists only from Python 3.12, so on 3.11 every sandboxed member's start failed (CI, Python 3.11). It now skips junctions, symlinks and mount points by their reparse-point attribute on every Python version.

## 1.19.1 - 2026-11-12

**Security review of the MXC backend: a sturdier egress proxy, grant filter and executor launch.** FIX of the security
review 2026-11-12 (MX-1 to MX-14, SECURITY-ASSESSMENT 13.4). No database schema change, no new setting.

- **Egress proxy.** Own addresses, loopback, link-local and metadata are compared as parsed, normalised addresses
  (upper-case, uncompressed, scope-id, IPv4-mapped/compatible, NAT64, 6to4 and Teredo forms no longer slip past the
  "this machine" check) and the checked address is the one connected (MX-1). Name lookups run in the proxies' own
  4-thread pool, at most 2 per member at once (503), 5 s each, with a 30 s negative cache; names without a dot and
  `.local` names are not looked up unless they are a relay target, so a member can no longer stall sign-in, MFA and
  provisioning with slow lookups (MX-2). Site-local `fec0::/10`, 6to4, Teredo, local-use NAT64, IPv4-compatible and
  `0.0.0.0/8` addresses are refused; Azure WireServer `168.63.129.16`, `169.254.170.2` and `192.0.0.192` join the
  metadata addresses (MX-11). Malformed or over-long host names, methods and versions get 400 (MX-5, MX-12).
- **Logs.** Per member, the first 30 `sandbox.egress` decisions of a minute are logged one by one, the rest as one
  summary line with counts per destination (MX-4). Everything a member or a container controls is cleaned
  (control characters escaped, length capped) before it reaches `gateway.log`, the activity log, the audit or an
  admin's last-error text (MX-5).
- **Grants.** Paths are compared in canonical form (`\\?\`, `/`, case, trailing dots/spaces, 8.3, junctions); UNC and
  device paths are never granted; the base Python, the venv and the goose CLI folder are never writable;
  `sandbox.read_dirs` entries naming a refused folder are left out for both backends and listed by `sandbox status`
  and `check` (MX-6). Before an MXC start a bounded scan refuses to start a worker whose read/write folders hold a
  hard link to a file outside them (MX-3).
- **`sandbox.enabled`.** Only `auto` (also when not set), `true/false`, `yes/no`, `on/off`, `1/0`; any other value
  counts as on and is a configuration error, so members' agents do not start instead of running unsandboxed (MX-7).
- **Executor launch.** Every pinned file (`MXC_PIN`, today `wxc-exec.exe`) is hashed through a write-denied handle held
  until the executor runs, the version folder must hold nothing else (checked before the start and while suspended),
  and `wxc-exec` is created with the PreferSystem32Images, MicrosoftSignedOnly and NoRemoteImages mitigations;
  `--probe` goes through the same path (MX-8). A kill-on-close job that cannot be joined ends the executor and fails
  the start (MX-9). The member's proxy credential is revoked when the worker stops or crashes and the proxy closed when
  the user is deleted or no longer sandboxed (MX-10).
- **Docs.** A relay forwards everything on its port (every path, every virtual host) (MX-13); docstring/comment drift
  fixed and the unused `mxc.redacted()` removed (MX-14).

## 1.19.0 - 2026-11-12

**Members' agents run in Microsoft Execution Containers (MXC) by default.** Spec 025. No database schema change.
Needs Windows build 26100.9278 or later and the pinned executor: `upgrade.ps1` / `install.ps1` install it
(`goose-web sandbox install-mxc --if-missing`); on older Windows set `sandbox.backend: appcontainer` or
`sandbox.fallback: appcontainer` before upgrading, or members' agents will not start (fail closed).

- **MXC sandbox backend (`sandbox.backend: mxc`, the default).** Every isolated non-admin member's worker runs in an
  MXC process container built from their sandbox settings: read/write on their profile, team folder and team extra
  folders, read and run on the Goose folder and `sandbox.read_dirs`; the system folder, profiles root, other profiles,
  the native profile, Goose Web's code and drive roots are refused even when configured (junction- and 8.3-aware);
  clipboard, input injection, desktop/system-settings control and IME locked. The AppContainer backend stays
  available (`sandbox.backend: appcontainer`) and tested; its containers and grants are kept while MXC is used.
- **Per-member egress proxy.** MXC members reach the network only through their own loopback proxy in the gateway
  (per-member credential, constant-time check): public internet and, with `internet+lan`, the LAN; `sandbox.relays`
  services such as a local model proxy at their real address (provider URLs are no longer rewritten for MXC members);
  everything else on this machine refused. HTTP/HTTPS only. Every destination is audited in the activity log
  (`sandbox.egress`, host:port and decision). Limits: `sandbox.proxy_max_connections`, `sandbox.proxy_idle_seconds`.
- **Pinned, verified executor.** `goose-web sandbox install-mxc [--if-missing] [--file TGZ] [--force]` installs
  `wxc-exec.exe` 1.0.1 from `@microsoft/mxc-sdk` 1.0.1 (npm sha512 integrity, SHA-256, Microsoft Authenticode
  signature) into `<install>\vendor\mxc\` (not in git). Its SHA-256 is checked again before every launch, with the
  file locked against writes until it runs.
- **Fail closed, with diagnostics.** `wxc-exec --probe` and the Windows build are checked at gateway start, by
  `goose-web sandbox status` and `goose-web check`. When MXC cannot run, members' agents do not start ("The sandbox is
  unavailable ... Contact your administrator."); the reason is in Admin > System (new Sandbox card), gateway.log and
  the audit (`sandbox.unavailable`). Opt-in `sandbox.fallback: appcontainer` starts them in the AppContainer backend
  instead (audited `sandbox.fallback`) and moves them back to MXC when it is available again, never during a run.
  Invalid `sandbox.*` values also fail closed.
- Admin > System: Sandbox card (backend, MXC state, probe, signature, egress proxies); the Workers table shows MXC or
  AppContainer. `goose-web sandbox remove --all` also removes MXC policy files.
- Docs: ADMINISTRATION 11.6, CONFIGURATION, ARCHITECTURE, SECURITY-ASSESSMENT 13 (MXC threat model; accepted:
  HTTP/HTTPS-only egress, folder-name listing, opt-in telemetry contract), TROUBLESHOOTING 20, USER-GUIDE, README.

## 1.18.3 - 2026-11-12

**Skills load with `load` as well as `load_skill` in members' chats.** No database schema change.

- **Fix: a chat's first attempt to load a skill failed.** Agents usually call the Summon tool `load(source="<skill>")`, but Goose 1.57's Summon only knows recipes and agents, and in Code Mode `load_skill` is reachable only inside `execute_javascript`. So the first `load("<skill name>")` failed and the chat seemed to start without its skills. Goose Web now writes a bridge `config/agents/<name>.md` (same text as the skill, marked as managed) for every skill in an isolated profile, both team-provisioned skills and the member's own. Bridges are refreshed whenever the profile is provisioned, which happens before every worker start, and removed when their skill goes. Agent files the member made are never touched. Nothing is read or written through junctions or links, and hard-linked or oversized SKILL.md files are skipped. A bridge error never stops a chat from starting, and a new bridge needs no restart. Native profiles are untouched; on a native box, bridge `~/.agents/skills` yourself, for example with a nightly script.

## 1.18.2 - 2026-11-12

**Preferences are merged, never overwritten by an old tab.** No database schema change (the revision lives in the prefs JSON).

- **Fix: a browser tab opened before a preference changed elsewhere could delete or revert it.** Every preference change (theme, sidebar, a new chat's folder, a New chat pick, Settings pages) sent the tab's WHOLE copy and the server replaced the stored prefs with it, so keys added later (for example provider groups) disappeared and newer values went back. Now a tab sends only the keys it changed with the revision its copy is based on (`PATCH /api/me/prefs`); a key that changed on the server since is refused (409) instead of overwritten; only an explicit removal deletes a key. A front end before 1.18.2 that is still open (`PUT`, whole object) is merged: nothing is deleted and values the server has since replaced are ignored.
- **Live between tabs:** every save is pushed to the user's other tabs and browsers, and a reconnect re-reads the prefs, so no tab keeps an old copy.
- **Audit:** `prefs.update` records the changed preference names (never values), the tab and the revision.
- Notification settings and preferences saved at the same moment no longer lose each other.
- Docs: the prompt guard section of ADMINISTRATION is 9.10 (it was a second 9.8; references updated); the platform message and docs say "Goose Web runs on Windows only" without a version.

## 1.18.1 - 2026-11-11

**Close-out fixes.** No database schema change.

- **Fix: a team or user save no longer cuts a sandboxed member off their provider.** With `sandbox.relays`, the
  worker points the member's provider URL at its relay forwarder. Re-provisioning (any team or user save) wrote the
  real loopback URL back, so the member's next chats timed out until the worker restarted, and every save reported
  the provider as changed. Provider and extension URLs are now written with the worker's relay mapping applied: a
  save that changes nothing changes nothing.
- **Prompt guard: per-team classifier threshold.** Admin > Teams > Prompt guard > **Classifier threshold** (0.5 to
  0.99; empty = the global `guard.threshold`). Admin > Prompt guard > Test shows what a score means for each team
  with its own threshold. ADMINISTRATION 9.8 explains that ordinary security-operations wording can score high and
  how to test real prompts before switching on the input check.
- **Prompt guard: `guard remove-model` on a running gateway** takes effect at the next check (the model is unloaded
  and the guard fails open with the admin banner) instead of after a restart.
- **`goose-web gateway drain|undrain` exit codes:** 0 = done (also while a turn runs), 5 = not done. Only `status`
  exits 3 for busy. `upgrade.ps1` drains, then asks `status`.
- **Sidebar:** the sessions of one job that runs elsewhere (Goose Desktop, the goose CLI, a scheduled task) are one row
  per folder, like the Herd; its count lists the sessions.
- **Chat header:** the effort picker of a model that gets no effort from Goose is one greyed-out "Set by provider"
  entry for every such model; the provider list has New chat's order and leaves out Goose's own "Goose (Default)"
  entry unless the chat uses it.
- Neutral example names and ports in the docs and tests.

## 1.18.0 - 2026-11-11

**Provider groups and model labels.** No database schema change.

- **Settings > Models & Providers > Provider groups.** Create, rename and delete groups; tick the providers that
  belong to a group (a provider is in one group only) and give each an optional prefix. **Model display names**
  give model ids friendly names. Saved per user on the server (new `providerGroups` preference, cleaned by the
  server); members get it for their own profile without `providers_edit`.
- **Pickers.** On the New chat screen and in the chat header a group is ONE provider entry; its model list is the
  union of its providers' models labelled `<prefix>-<model name>`, sorted by prefix then model. Picking a label
  sets the real provider and model (in a chat: provider switch, then model; the history is kept). A chat on a
  member shows the group name and the label. Display names apply to ungrouped providers too.
- **Rules.** Team policy applies to the real ids first; spec 023's Chat pickers hiding works per member (a group row
  there hides all its providers; a hidden member leaves the group's list; the default provider and the chat's own
  provider are always kept, and a group holding the default provider shows it as the default). The thinking-effort
  picker is unchanged (providers whose effort is fixed by their configuration keep the note).
- Display only: Goose's configuration, recipes, schedules and Goose Desktop are not affected. The members' model
  lists come from the provider list New chat and Settings already load (remembered per user), so opening a picker
  sends no request.
- Docs: USER-GUIDE (Settings > Models & Providers, New chat, chat header), ARCHITECTURE, API.

## 1.17.0 - 2026-11-11

**Choose which providers the chat pickers offer.** No database schema change.

- **Settings > Models & Providers > Chat pickers.** One **Show in chat pickers** checkbox per configured provider
  (name and id), plus **Show all** and **Hide all except default**. Unticked providers, and their models, are left
  out of the provider picker on the New chat screen and in the chat header. Saved per user on the server (a new
  `providerVisibility` preference: the hidden ids only, so a provider set up later is shown); it follows the user
  to every browser. Members get it for their own profile; it needs no `providers_edit` permission.
- **Never hidden:** the default provider (unticking it is refused with an explanation), and the provider a chat
  already uses (its header shows it marked "(hidden in settings)").
- **Policy first:** the team's allowed providers still decide what can be listed at all; hiding is a display
  preference and blocks nothing. Admin pages (team provider pickers), the default-model picker and the Settings
  provider list are not filtered.
- **Chat header:** its provider picker now offers the same providers as New chat. Goose lists every provider it
  knows there (about 95), including ones that are not set up; those are left out (the chat's own provider always
  stays). The list is remembered from the last New chat or Settings visit, so opening a picker sends no request.
- Built so that effort-variant providers (spec 022, not part of this release) can be left out of the pickers while
  staying valid targets (`variantOf` role, `allProviders` list).
- Docs: USER-GUIDE (Settings > Models & Providers, New chat, chat header), ARCHITECTURE.

## 1.16.1 - 2026-11-11

**New chats use the highest thinking effort by default.** No database schema change.

- **Max effort by default.** Without a pick on the New chat screen, a new chat gets the highest effort the chosen
  provider and model offer: `max`, else the top of Goose's list (for example `high`). The picker says
  **Default effort (max)** (or the real top level; "highest offered" until the model has been used once). A level the
  user picks - remembered on the New chat screen, or set in the chat header - still wins.
- **Isolated profiles** are provisioned with `GOOSE_THINKING_EFFORT: max` when they have no value; a member's saved
  preference is kept.
- **Honest picker for models Goose sends no effort to.** On the OpenAI engine Goose sends `reasoning_effort` only for
  OpenAI reasoning models and xAI Grok, so GLM, DeepSeek and similar models behind an OpenAI-compatible gateway never
  received the picker's value. The New chat picker now shows "Effort set by the provider configuration, not per chat"
  for them (the chat header's effort picker says it in its tooltip). The gateway adds each custom provider's engine
  (`gwEngine`) to `providers/list` replies for this. CONFIGURATION ("Thinking effort") shows how to give such a model
  a fixed effort with per-model `request_params` in the custom provider file.
- Docs: USER-GUIDE (New chat options), CONFIGURATION (Thinking effort), ADMINISTRATION 11.8.

## 1.16.0 - 2026-11-11

**An upgrade no longer interrupts running chats, and administrators see what Goose Desktop, the CLI and scheduled
jobs are running.** No database schema change.

- **Upgrades and deploys wait until nothing runs (fix).** The busy check of `scripts\upgrade.ps1` sampled the workers'
  CPU for 5 s; a turn waiting for a long tool call or a sub-agent uses no CPU, so it counted as idle and the restart
  ended it (seen on 2026-11-11: two chats killed, one inside a 30-minute tool call). The gateway now answers the
  question itself: `goose-web gateway status` lists every running turn in every worker (prompts in flight, long tool
  calls and sub-agents included, pending permission requests and questions, direct tool calls, prompts being checked,
  jobs of Goose's scheduler running inside a gateway worker); exit 3 = busy. `goose-web gateway drain` makes the
  gateway refuse new prompts for a moment (`-32010`; the text goes back into the message box) and tells every tab
  *Goose Web restarts for an update in a moment*, so no turn starts between the last check and the restart.
  `upgrade.ps1` checks before it changes anything, drains and checks again right before the restart, and waits instead
  of refusing with `-WaitHours`. Local control channel in `<system_dir>\run\`, no port, no credential; a gateway older
  than 1.16 is judged by its herd marks.
- **"Interrupted" is visible.** A chat a restart ended was marked *error* since 1.15, but the reason was not shown;
  the Herd card, the sidebar tooltip and the transcript now say *Interrupted: Goose Web restarted while this chat was
  running*.
- **Working elsewhere (spec 020, administrators).** Sessions of the native profile that Goose Desktop, the goose CLI or
  a scheduled job (Goose's scheduler, or a Windows task running `goose run`) is running appear in a *Working
  elsewhere* group in the sidebar and the Herd, with a counter. Many short sessions of one job are one entry (count +
  newest). Opening one is read-only: no message box, no Stop or steering; prompts and edits into it are refused
  (`-32011`) until it has finished. The native `sessions.db` is read with a read-only connection, only when it
  changed, only while an administrator has Goose Web open; tabs get names, ids and times only. Members never see it.
  New `elsewhere.*` settings (CONFIGURATION).
- **Done includes chats that finished elsewhere.** A session that finished in Goose Desktop, the goose CLI or a
  scheduled job joins the Herd's Done column and the done counter (one entry per job, with a count) and stays there
  until it is opened in Goose Web, cleared, or *Mark all read* is used; kept in the database across refreshes,
  devices and restarts; runs that finished while Goose Web was closed are caught up at the next visit.

## 1.15.1 - 2026-11-11

**Security release.** A review of everything changed since the 2026-11-09 assessment (1.12.0 - 1.15.0) found 33
issues; all code findings are fixed (SECURITY-ASSESSMENT 12). Upgrade if you use the prompt guard, have members, or
let administrators view members' chats. No database schema change.

- **Prompt guard could be switched off by the agent (SA-1, High).** The agent runs as its profile and could write an
  *always allow* entry into its own `permission.yaml`; after the next worker start Goose stopped asking and the guard
  never saw that tool. Now every worker start provisions an isolated profile again (team policy, extensions, mode,
  provider, *always allow*), a built-in rule refuses tool arguments that name the profile's config files, and a tool
  call that runs without a permission request in a guarded profile cancels the run (`guard.bypass`; the member's
  worker restarts with clean settings).
- **One tool call or prompt could freeze the whole gateway (SA-2, High).** Rule matching ran on the event loop and the
  shipped *Destructive shell* patterns backtracked quadratically (60 KB froze every user for 6 s; 200 KB for minutes).
  Rules now run in two child processes with a deadline (`guard.rules_timeout_ms`, slower = blocked), the shipped
  patterns are bounded, admin regexes with nested repeats are refused, and the Test box uses the same path.
- **Classifier gaps (SA-3, SA-4).** A guarded prompt longer than `guard.max_input_chars` (16,000) is refused before any
  work (a 16 MB prompt used to stall the gateway 18 s and was never classified); every window of a text is scored
  (the middle used to be skipped); text too long to score is never auto-approved.
- **Rule sets hardened (SA-5)** against 17 evasions (flag order, quotes, PowerShell prefixes, `rd /s`, .NET deletes,
  `+branch`/`:branch` pushes, encoded PowerShell, `summaryindex`, `dump`, `dbxquery` writes, `fit into`, Splunk REST from
  a shell, more tool names); unedited shipped sets are upgraded automatically. They remain best-effort deny lists.
- **Guard odds and ends (SA-6..SA-10):** system prompts, saved prompts, recipes, imported chats and MCP Apps tool calls
  of guarded users are checked; trusted extensions are trusted by their configuration, not their name; the guard fails
  closed when its settings cannot be read; members no longer see rule ids; 10 blocks in 10 minutes pause a user's
  guarded requests (`guard.burst`); `guard.unavailable` names the user and chat.
- **An administrator viewing a member's chat sent the member's queued messages as the administrator (SC-1, SC-6).**
  Only the owner's tab sends its own queued messages automatically (enforced by the gateway); any text typed into a
  member's chat also passes the member's prompt guard; takes and removals by others are audited; queue rows show who
  queued them.
- **Queue limits (SC-2, SC-4, SC-9).** One member could stall every user for ~9 s per queue change and store 36 GB.
  Now 32 MB of queued messages per profile, 20 chats with a queue, 10 pending steers; queue state is written in the
  background; tabs and reconnects get queue rows, not message content.
- **Deleted, disabled or signed-out users (SC-3).** Their open sockets are closed at once (others re-checked every 30 s),
  a deleted user's state never writes again, and a new account with the same name starts clean.
- **Plugins in shared folders (SD-2, SD-3, SD-5, SD-6).** No member can start a chat in the team folder (or the team's
  extra folders) while it holds Goose plugins, with or without `allow_shell`; administrators must confirm the plugin
  list; project skills/agents only in the member's own workspace; chat folders are canonicalised; `AGENTS.md::$...`
  names are refused.
- **Model install (SB-1..SB-5, SB-9).** The model folder inherits its parent's permissions again (a `-RunAs` service
  account could not read it on Python 3.12.4+; `--if-missing` repairs it, `check` reports it); a wrong `guard.model_dir`
  can no longer replace or delete other folders; every redirect must be https on GitHub's download hosts; files are
  hashed at load and by `--if-missing`; ONNX Runtime telemetry is off; a failed swap restores the old model.
- **Drafts and residue (SC-5, SC-7).** Drafts are kept per user and profile, for 7 days, and cleared when the sign-in
  expires; SQLite `secure_delete` is on; queued messages expire after 7 days; state of chats deleted elsewhere is
  pruned.
- Config: `guard.max_windows` 8 -> 48, `guard.timeout_ms` 3000 -> 10000, new `guard.max_input_chars` (16000) and
  `guard.rules_timeout_ms` (1500). Service worker cache `gw-shell-v22`. Tests: `tests/test_security_review.py`.

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
- **Relays for sandboxed users:** `sandbox.relays: ["127.0.0.1:4000"]` lets sandboxed agents use a local service such
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
