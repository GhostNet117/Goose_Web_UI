# Goose Web user guide

This guide is for people who sign in to Goose AI Web Interface ("Goose Web") and use it to work with the Goose
agent from a browser. It explains every screen and gives step-by-step instructions.

Related documents:

- [ADMINISTRATION.md](ADMINISTRATION.md): users, teams, policies, sign-in methods (for administrators).
- [ARCHITECTURE.md](ARCHITECTURE.md): how the gateway, the workers and Goose fit together.
- [CONFIGURATION.md](CONFIGURATION.md): configuration keys and policy keys.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): what to do when something does not work.
- [API.md](API.md): the HTTP and WebSocket API, for scripts that use an API token.

Contents:

1. [What Goose Web is](#1-what-goose-web-is)
2. [Signing in and out](#2-signing-in-and-out)
3. [The screen layout](#3-the-screen-layout)
4. [Starting a chat](#4-starting-a-chat)
5. [The chat screen](#5-the-chat-screen)
6. [Watching Goose work (live activity)](#6-watching-goose-work-live-activity)
7. [Keyboard shortcuts](#7-keyboard-shortcuts)
8. [Herd](#8-herd)
9. [Recipes](#9-recipes)
10. [Skills](#10-skills)
11. [Schedules](#11-schedules)
12. [Apps](#12-apps)
13. [Extensions](#13-extensions)
14. [Settings](#14-settings)
15. [What your policy can restrict](#15-what-your-policy-can-restrict)
16. [FAQ](#16-faq)

## 1. What Goose Web is

Goose Web is a browser front end for the [Goose](https://github.com/block/goose) AI agent. Goose runs on a server.
You talk to it from any browser, on a desktop or a phone.

Things to know before you start:

- **You have your own Goose profile.** Your chats, recipes, skills, extensions, providers and secrets are kept
  in your own profile. Other users do not see them in the UI.
- **Goose keeps working when you close the tab.** The server owns the connection to Goose. When you come back,
  the chat replays and shows what happened.
- **Several tabs and devices stay in sync.** If Goose asks for permission, every open tab shows the question.
  The first answer wins.
- **Your team decides what you may do.** You belong to one team. Its policy, set by your administrator, decides
  which providers, models and approval modes you can use, which folders you can reach, which hints Goose gets and
  whether you can add extensions. Pages show a "Read-only" note when your policy does not allow a change. See
  [section 15](#15-what-your-policy-can-restrict).
- **No team, no chat.** If you are not in a team yet, you can sign in, look around and read your old chats, but
  you cannot start or continue a chat until your administrator adds you to a team.

## 2. Signing in and out

### Open the site

Open the address your administrator gave you, for example `https://goose.example.org`. You see the sign-in
screen with the site name, the version number and the sign-in options that are turned on.

### Sign in with a username and password

Use this for local accounts and for directory (LDAP or Active Directory) accounts. When a directory is
configured, the username field is labelled with its name, for example "Directory username".

1. Enter your username and password.
2. Leave **Keep me signed in** ticked on your own device. Untick it on a shared computer.
3. Click **Sign in**.

### Sign in with single sign-on

If your organisation uses OpenID Connect, the sign-in screen shows one button per provider, for example
**Continue with Company SSO**. Click it, sign in at your identity provider, and you return to Goose Web
signed in. If something goes wrong, you come back to the sign-in screen with an error code in red.

### Two-factor code (TOTP)

If you turned on two-factor authentication (see [Account](#account)), the screen asks for an
**Authentication code** after your password.

1. Open your authenticator app.
2. Type the 6-digit code. Spaces are ignored.
3. Click **Verify**.

A code can be used only once. If it is rejected, wait for the next code.

### Sign-in messages

| Message | What it means |
|---|---|
| Invalid username or password. | The username or password is wrong. |
| Invalid code, try again. | The two-factor code is wrong or was already used. |
| This account is temporarily locked. | Too many failed attempts. Wait, or ask an administrator to unlock you. |
| Too many attempts. Please wait a minute. | Sign-in is rate limited. Wait a minute and retry. |
| Sign-in from your network address is blocked after too many failed attempts. | 10 failed sign-ins in a row came from your network address. Ask an administrator to unblock it. |
| Gateway unreachable | The browser cannot reach the server. Click **Retry**, or see [TROUBLESHOOTING.md](TROUBLESHOOTING.md). |

### First-time setup

When an administrator creates your account or sets your password, you get a temporary password. You always have to
change it at your first sign-in. The same screen appears if your current password does not meet the rules below
(for example a password chosen before the rules were tightened).

1. Sign in with the temporary password.
2. The **Choose a new password** screen opens. You cannot use the app until you change it.
3. Enter the temporary password, then your new password twice. The checklist under the field turns green as
   you meet each rule.
4. Click **Change password**.

Password rules (local accounts):

- at least 12 characters
- a lowercase letter, an uppercase letter, a number and a symbol (a space counts as a symbol)
- it must not contain your username
- it must not be a common password, or a common word with numbers or symbols added (`Summer2026!` is refused)
- no character four or more times in a row

Directory and single sign-on accounts do not have a password in Goose Web. Your organisation manages it.

On your first chat, Goose may say that no model provider is set up. Open **Settings > Models & Providers** and
configure one, or ask your administrator to assign one to your team. Many administrators provision providers,
recipes, skills and extensions for teams, so they may already be there. Your team may also set a default model,
which new chats start with.

If the home page shows a yellow banner instead, you cannot chat yet:

| Banner | Meaning |
|---|---|
| You are not in a team yet, so you cannot chat. Ask your administrator to add you to a team. | Your account has no team. You can still browse and read your old chats. |
| Your team allows no providers (or models, or approval modes), so you cannot chat. Ask your administrator. | Your team is not set up yet. |

### Signing out

Click your name at the bottom of the sidebar and choose **Sign out**. You can also press `Ctrl+K` and run
**Sign out**.

To sign out other devices, use **Settings > Account > Active sign-ins** and click **Revoke**.

If your sign-in expires, Goose Web shows "Your sign-in expired. Please sign in again." and returns to the
sign-in screen. Running agents are not affected.

### Install as an app

Goose Web is a Progressive Web App. It can be installed when you open it over HTTPS (or on `localhost`).

- **Desktop Chrome or Edge:** click the install icon in the address bar, or use the browser menu and choose
  **Install Goose Web** (the wording depends on the browser).
- **Android:** browser menu > **Add to Home screen** or **Install app**.
- **iPhone and iPad (Safari):** Share > **Add to Home Screen**.

The installed app opens in its own window. Its shortcut menu has **New chat** and **Herd**. The app caches only
its own files, so it still needs a connection to the server to do anything.

## 3. The screen layout

The screen has a sidebar on the left and the main area on the right. On narrow screens (phones) the sidebar is
a drawer: open it with the menu button at the top left, close it with the X or by tapping outside.

### Sidebar, from top to bottom

| Part | What it does |
|---|---|
| Logo and site name | Click to start a new chat. |
| **New chat** | Opens the new-chat screen (`Alt+N`). |
| Command button | Opens the command palette (`Ctrl+K`). |
| Status counters | "N need you", "N working" and, when there are any, "N done". Click to open the Herd. |
| Navigation | Herd, Recipes, Skills, Schedules, Apps, Extensions, Settings, and Admin for administrators. |
| **Search chats** | Searches your chats (`/` focuses it, `Esc` clears it). |
| List options button | Filters and folder controls (see below). |
| Chat list | Your chats, grouped by working folder. |
| Your name | Opens the user menu. |
| Connection indicator | Shows the connection state. Click it to reconnect now. |

The status counters show the same live status as the Herd. "Need you" means an agent waits for an approval or
an answer. "Done" means an agent finished since you last looked at that chat.

### The chat list

Chats are grouped by their working folder, like in Goose Desktop. The most recently active folder is at the
top. Each row shows a status dot, the title, a pin icon if pinned, and the time of the last message.

Status dots:

| Dot | Meaning |
|---|---|
| Pulsing, "needs you" colour | Waiting for your approval or answer. |
| Pulsing, "working" colour | Goose is working on it now. |
| "done" colour | Finished since you last opened it. |
| "error" colour | The last run failed. |
| No dot | Idle. |

Folder headings:

- Click a folder heading to collapse or expand it.
- Click the **+** on a folder heading to start a new chat in that folder.

Chat actions: hover a row and click the **...** button.

| Action | Result |
|---|---|
| Pin to top / Unpin | Pinned chats appear in a **Pinned** group at the top. |
| Rename | Gives the chat a new title. |
| Archive / Unarchive | Archived chats are hidden from the list unless you show them. |
| Open in new tab | Opens the chat in another browser tab. |
| Delete... | Deletes the chat and its history permanently, after a confirmation. |

List options (the sliders button next to the search box):

| Option | Result |
|---|---|
| Archived chats | Shows or hides archived chats. |
| Scheduled runs | Shows or hides chats created by schedules (shown by default). |
| Collapse all folders / Expand all folders | Folds or unfolds every folder group. |
| Refresh | Reloads the list from the server. |

The list loads more chats as you scroll. If there are more, a **Load more** link appears at the end.

Search looks at your chats on the server. While a search is active, collapsed folders open so you can see the
matches.

### Connection indicator

| Label | Meaning |
|---|---|
| Connected | The browser is connected and your Goose agent is ready. |
| Connecting... / Reconnecting... | The browser is (re)connecting to the server. |
| Offline - retrying | The server cannot be reached. Goose Web retries on its own. |
| Goose starting... | Your personal Goose agent is starting. This takes a few seconds after a period of inactivity. |
| Goose down | Your Goose agent stopped. The server restarts it automatically. |

A banner above the main area repeats important states, for example "Starting your Goose agent..." or "Cannot
reach the gateway. Retrying..." with a **Retry now** link.

### User menu

Click your name at the bottom of the sidebar:

- **Account**: opens Settings > Account.
- **Settings**: opens Settings.
- **Keyboard shortcuts**: shows the shortcut list.
- **Theme**: System, Dark or Light. **More themes...** opens Settings > Appearance.
- **Sign out**.

### Command palette

Press `Ctrl+K` (or `Cmd+K` on a Mac), or click the command button. Type to filter, use the arrow keys, and press
`Enter`. The palette lists:

- **Needs you**: pending approvals and questions.
- **Chats**: your recent chats (all chats when you type).
- **Go to**: every page, the main Settings tabs and, for administrators, the Admin pages.
- **Actions**: New chat, New chat in folder..., Toggle sidebar, switch between light and dark, Reload chat list,
  Keyboard shortcuts, Sign out.
- **Recipes**: "Run recipe: ..." for each of your recipes.

### Attention signals

- The browser tab title starts with a number, for example "(2) Goose", when chats need you, are done or failed.
- The tab icon gets a coloured dot: amber when something needs you, green otherwise.
- When the tab is visible, a pop-up message (toast) appears at the corner with **Review** or **Open**.
- When the tab is in the background, you get a desktop notification and an optional sound, if you turned them
  on in [Notifications](#notifications).

## 4. Starting a chat

Click **New chat** (or press `Alt+N`). The new-chat screen shows a greeting, a message box, two chips above it
and a row of option pickers for the new chat.

### Step by step

1. Check the **folder chip**. It shows the working folder Goose will use. It starts with the last folder you
   used, or your default workspace. Click it to choose another folder.
2. Optional: click the **Recipe** chip and pick a recipe to start from. Its prompt is put into the message box.
   Click the small X on the chip to clear it.
3. Optional: choose the **options for this chat** in the picker row (version 1.4.0 and later):

   | Picker | What it sets |
   |---|---|
   | Provider | The model provider. Only providers set up in your profile (and allowed by your policy) are listed. |
   | Model | The model of that provider. Changing the provider resets the model to its default. |
   | Thinking effort | How much the model reasons before answering (Off, Low, Medium, High, Max, or the values the provider offers). The list shows the values Goose offered last time for that model. |
   | Approval mode | When Goose asks before it runs a tool: Auto, Approve, Smart approve or Chat only (see [Mode](#mode)). |

   Each picker starts at **Default (...)**, which keeps the default from **Settings > Models & Providers** and
   **Settings > Preferences**. Your choices are remembered for the next new chat. They are applied to the chat
   before your first message is sent. If the new chat does not offer a choice (for example a thinking effort the
   model does not support), Goose Web shows a warning and the chat starts with Goose's value instead. The pickers
   in the chat header can still change everything later.
4. Type what Goose should work on.
5. Press `Enter` (or click the send button).

Goose Web creates the chat, opens it and sends your message. The chat keeps running even if you close the tab.

**Start without a message** creates the chat and opens it without sending anything. With a recipe, the recipe
prompt is waiting in the message box.

Below the message box you may see:

- **Needs you**: up to three chats waiting for you.
- **Recent folders**: click one to use it as the working folder.
- **Recent chats**: your five most recent chats.

### Choosing a working folder

The folder picker opens when you click a folder chip.

- **Locations** on the left lists the folders you may use: your **Workspace**, your team's shared folder (shown
  as **Team:** and the team name), and any extra folders your team allows. Administrators also see **Home** and
  the drives or `/`.
- **Recent** lists folders you used recently.
- Type or paste a path in the box at the top and press `Enter`, for example `C:\work\project` or `~/project`.
- Click a folder to open it. Use the breadcrumbs or `..` to go up.
- **Filter...** narrows the list.
- The new-folder button creates a subfolder.
- Click **Use this folder** to confirm.

You can only pick folders inside your allowed folders. Goose cannot be started in other folders.

**The team folder** is shared by everyone in your team: what you put there, your teammates can see and change.
Keep private work in your Workspace.

## 5. The chat screen

### The header

| Element | What it does |
|---|---|
| Title | Click it (or press `F2`) to rename the chat. A "Working" badge appears while Goose runs. |
| Folder chip | Shows the working folder. Click it to change the folder. |
| Mode picker | Chooses how Goose asks for permission. |
| Provider, model and thinking pickers | Choose the model for this chat. |
| Extensions chip | Shows how many extensions loaded, for example "16/17 extensions". |
| Context meter | Shows how full the model's context window is, and the cost. |
| **...** menu | The session menu. |

### Change the working folder

1. Click the folder chip in the header.
2. Pick a folder and click **Switch folder**.

Goose uses the new folder from the next message on.

### Mode

The mode decides when Goose asks before it runs a tool. The modes and their names come from Goose. They
usually are:

| Mode | Behaviour |
|---|---|
| `auto` (autonomous) | Goose runs tools without asking. |
| `approve` (manual approval) | Goose asks before each tool call. |
| `smart_approve` (smart approval) | Goose asks only for tools it considers risky. |
| `chat` (chat only) | Goose does not use tools. |

Your team decides which modes you may choose. Only allowed modes appear in the list. Accounts created by
the gateway normally start in `approve` mode. Apps that call tools need `auto` mode (see [Apps](#12-apps)).

### Provider, model and thinking level

The pickers next to the mode list come from Goose. Typically there is a provider picker, a model picker and,
for models that support it, a thinking level picker.

- Changes apply to this chat only. The default for new chats is set in **Settings > Models & Providers**.
- Your team decides which providers and models you can use. Only allowed values appear.
- If your team stops allowing the provider, model or mode that an older chat uses, Goose Web refuses new messages
  in that chat ("this chat uses the model ..., which your team does not allow"). Pick an allowed one in the chat
  header first, then send again.
- The thinking level controls how much the model reasons before answering. A higher level can be slower and
  cost more.

### Extensions chip

The chip shows how many extensions are loaded in this chat. If one fails to start, the chip shows a warning
icon and a message appears with **Details**.

Click the chip (or **Session extensions...** in the session menu) to open the **Session extensions** dialog:

- **Failed to start**: each failed extension with its error. **Retry** starts it again.
- **Active in this session**: loaded extensions. **Remove** takes one out of this chat.
- **Add from your configured extensions**: extensions you have configured but that are not in this chat.
  **Add** loads one into this chat.

Retry, Remove and Add need the `extensions_edit` permission. Without it the dialog is read-only.

### Context and cost meter

The ring fills up as the conversation uses the model's context window. It turns warmer above 60% and hot above
85%. Next to it you see "used / limit" tokens and, if known, the cost so far. Hover it for the exact numbers,
total input and output tokens and the cost.

When the context gets full, Goose summarises (compacts) the conversation. You can change when this happens with
**Auto-compact threshold** in [Goose preferences](#goose-preferences).

### Session menu

Click **...** at the top right of the chat.

| Item | What it does |
|---|---|
| Rename | Renames the chat (`F2`). |
| Pin to top / Unpin | Pins the chat in the sidebar. |
| Fork conversation | Copies the chat into a new chat named "... (fork)" and opens it. |
| Session extensions... | Opens the extensions dialog (see above). |
| Tools... | Lists every tool in this chat with its description and input schema. With the `tools_permissions` permission you can set each tool to Always allow, Ask before or Never allow. |
| System prompt... | Adds extra instructions to this chat only, or replaces the session prompt. Needs the `prompts_edit` permission. |
| Diagnostics | Shows a Summary or Full diagnostics report from Goose, with **Download**. Useful for bug reports. |
| Export as Markdown / Export as JSON | Downloads the conversation. |
| Reload transcript | Reloads the conversation from the server. |
| Archive / Unarchive | Hides the chat from the default list. |
| Delete... | Deletes the chat permanently. |

### The message box (composer)

Type your message and send it.

| Key | Default behaviour |
|---|---|
| `Enter` | Send. |
| `Shift+Enter` | New line. |
| `Ctrl+Enter` | Send. While Goose runs: steer (see below). |

If you prefer `Enter` for new lines, turn off **Enter sends the message** in **Settings > Preferences > Chat**.
Then `Ctrl+Enter` sends. The hint next to the send button shows the current key.

#### Attach files and images

You can attach in three ways: click the paper-clip button, paste from the clipboard, or drag files onto the
message box.

- **Images up to 8 MB** are sent to the model as images. A thumbnail appears in the message box.
- **Other files, and larger images,** are uploaded into a `.goose-web-uploads` folder inside the chat's working
  folder. Goose gets a link to the uploaded file. Existing files are never overwritten: a second `report.pdf`
  becomes `report (1).pdf`.
- You need a working folder before you can upload a file.
- The administrator sets the maximum file size. Up to 20 files can be uploaded at once.
- Files named `AGENTS.md`, `.goosehints` or `.goose-web-hints.md` cannot be uploaded, and you cannot create a
  folder with those names ("... is a Goose hints file name"). Your team's hints are managed by your
  administrator, and Goose ignores such files in your folders anyway. Rename the file (for example
  `AGENTS.txt`) if you only want to share its text.
- Click the X on an attachment to remove it before sending. Goose Web waits for uploads to finish before it
  sends.

#### Slash commands

Type `/` at the start of the message. A menu lists the commands Goose offers in this chat, including recipes
that have a slash command. Use the arrow keys and `Enter` or `Tab` to insert one. `Esc` closes the menu.

#### Mentions

Type `@` to mention an agent. The menu lists what Goose offers, with a tag that shows the source. Pick one with
the arrow keys and `Enter` or `Tab`.

### While Goose is running

While a turn runs, the header shows "Working", and the composer changes:

- **Send queues the message.** The send button changes to a queue icon. Your message appears in a queue above
  the message box and is sent automatically when the current run finishes. Each queued message has **Send now**
  and an X to remove it.
- **Steer** sends your message to the running agent right away, so Goose can take it into account without
  stopping. Click **Steer** or press `Ctrl+Enter`. A steered message is marked "steer" in the transcript. If
  steering fails, the message is queued instead.
- **Stop** ends the run. Click the stop button or press `Ctrl+.`. The transcript shows "Stopped".

If you try to leave the page while messages are still queued, the browser asks you to confirm, because queued
messages are kept in the page.

### Your goose hints as an administrator with the native profile

If your account uses the native profile (the Goose folder Goose Desktop uses), Settings > Goose hints says which
of two modes is on:

- **Managed native hints:** Goose Web writes your effective hints (your personal hints, documents assigned to you,
  your team's documents last) into the native `.goosehints`, so Goose Desktop and your scheduled runs use the same
  text. Edit your personal part here and the documents in Admin > Hints.
- Otherwise you edit the native `.goosehints` file directly here, and library documents are not applied to it.

### What your agent can reach

If your administrator turned on the sandbox, your agent - its shell, scripts and tools - can only use your workspace,
your team's folder and the folders your team was given; everything else on the server answers "Access is denied", and
it cannot connect to services on the server itself. Ask your administrator to add a folder to your team if you need it.

### Editing a message you sent

Hover over one of your messages and click the pencil (**Edit and rerun from here**). The text opens in place; change
it and choose:

- **Rerun here** replaces the rest of this chat: your message and everything after it are removed, and the edited
  message is sent in the same chat. You are asked to confirm, because this cannot be undone. Shortcut: `Ctrl+Enter`.
- **Branch** starts a new chat that contains the conversation up to (not including) this message and sends the
  edited message there. The original chat stays as it was. The new chat is named "<title> (edited)".
  Shortcut: `Ctrl+Shift+Enter`.
- **Cancel** (or `Esc`) closes the editor.

Pictures and other attachments of the original message are sent again with the edited text. Editing is not possible
while the chat is running (stop it first) or for steered messages. Goose cuts the conversation by the time a message
was saved, in whole seconds; in the rare case that the reply before your message was saved in the same second
(typically a queued message that was sent the moment the previous run ended), the edit is refused: edit the message
before it instead, or use **Fork conversation** in the chat menu. Other open tabs of the same chat reload
automatically after **Rerun here**.

Your policy can limit how many agents you run at the same time (the default for non-administrators is 3). When
you reach the limit, sending fails with a message such as "you already have 3 agents running (limit 3)". Wait
for one to finish or stop one in the Herd.

### Permission prompts

In `approve` and `smart_approve` modes Goose asks before it runs a tool. A **Permission needed** card appears
under the tool call. It shows the tool title, the command or the arguments, and buttons:

| Button | Effect |
|---|---|
| Allow once | Run this call. |
| Always allow | Run it and do not ask again for this tool. |
| Deny | Do not run this call. |
| Always deny | Do not run it and refuse this tool from now on. |

Goose offers only the options that apply, so you may not see all four. You can also answer from the Herd or
from the "needs you" pop-up. The first answer wins across all your tabs and devices. Other tabs then show
"Answered by ...".

### Questions and forms

Sometimes Goose or an extension needs information. An **Input needed** card shows a small form. Fill it in and
click **Submit**, or click **Decline** or **Cancel**. Required fields are marked with `*`.

If a recipe needs parameters, a **Recipe parameters** dialog opens. Fill in the values and click **Start**, or
click **Cancel run**. If you close the dialog without answering, a message reminds you that the parameters are
still pending, with **Open**.

### Plans

When Goose makes a plan, a **Plan** box shows the steps with a counter such as "2/5". Finished steps get a check,
the current step a spinner, and high-priority steps a "high" badge. The box updates as Goose works.

### MCP Apps in tool results

Some tools come with an interactive app. When such a tool finishes, the app appears inside the tool card. It
runs in a sandbox and has no access to Goose Web or your sign-in. If the app wants to send a chat message for
you, or run a tool from a powerful extension, you are asked to confirm first. See [Apps](#12-apps) for the
rules.

### Reading the transcript

- **Your messages** appear on the right. Turn on **Show message timestamps** in Settings > Preferences to see
  the time on them.
- **Goose's replies** are formatted Markdown. The first reply of a turn shows the Goose name and the time.
- **Copy** buttons appear when you hover a message. Code blocks have their own copy button and a language label.
  Tool input and output sections have copy buttons too.
- **File edits** are shown as a diff with removed lines (-) and added lines (+). A new file gets a "new" badge.
- **Long output** is cut at 20,000 characters. Click **Show all** to see the rest.
- **Usage footer**: under a reply you may see input and output tokens, the cost and the time it took.
- **Images from the internet** in replies are not loaded, for security. Their address is shown instead. Links
  open in a new tab.
- **Show earlier messages** at the top loads older parts of a long chat.
- **Jump to latest** (the down-arrow button) appears when you scroll up. Click it to return to the end.
- **System lines** explain why a run ended, for example "Stopped: output token limit reached", "Stopped:
  maximum turns reached" or "The model refused to continue".
- **"Connection lost"**: the agent keeps working on the server. The transcript resyncs when you reconnect.
- **Updated elsewhere**: if the same chat is continued in Goose Desktop, the CLI or a schedule, the open chat
  reloads within a few seconds and shows "This chat was updated in another Goose app".

## 6. Watching Goose work (live activity)

New in this release. While Goose works on a turn, Goose Web shows what it is thinking and doing, step by step.
Three preferences in **Settings > Preferences > Chat** control how much detail you see.

### Thinking

When the model reasons before it acts, that reasoning appears as a **Thinking** block. The block sits above
the step it led to, and it is formatted as Markdown.

Preference **Thinking**:

| Value | Behaviour |
|---|---|
| Auto (default) | Blocks are open while Goose is working and fold when the turn ends. |
| Always expanded | Blocks are always open, also in older turns and in history. |
| Collapsed | Blocks are always folded. Click one to read it. |

Opening or closing a block by hand always wins over the preference.

Good to know:

- Goose delivers each thinking block in one piece once the model has finished it. The block therefore appears
  all at once, not word by word.
- Not every model or provider produces thinking. If you never see a Thinking block, your model may not support it.
- The chat's thinking level picker in the header affects how much the model thinks.

### Tool calls

Each step Goose takes is a card. The card title says what the step does, for example `shell · npm test` or
`analyze · src/`. The header also shows:

- the extension the tool belongs to
- a status icon: a spinner while it runs, a check when it succeeded, a cross when it failed
- for shell commands, an exit-code badge such as "exit 1" when the command failed

Click a card header to open or close it. An open card shows the **Input**, the **Live output** while the tool
runs, and the **Output** or **Result** when it is done. Any approval prompt for the tool appears directly under
its card.

Preference **Tool details**:

| Value | Behaviour |
|---|---|
| Auto (default) | A card opens when the tool starts, so you see its input, live output and any approval prompt. It folds when the tool completes. |
| Detailed | Cards are always open, including results and older turns in history. |
| Concise | Only the headers are shown. Click a header to see the details. |

### Live activity bar

While a turn runs, a bar appears under the last message. It shows:

- a spinner
- the current phase:
  - **Thinking...**
  - **Running** followed by the tool title
  - **Waiting for your approval:** followed by the tool title
  - **Working...** (between steps, for example after a tool finished or an approval was given)
  - **Writing the reply...**
  - Goose's own progress text, for example while it compacts the conversation
- the number of tool calls in this turn
- the elapsed time

Click the bar to jump to the current step. The bar disappears when the turn ends.

Preference **Live activity bar**: on (default) or off.

### Change these preferences

1. Open **Settings > Preferences**.
2. In the **Chat** section, choose a value for **Thinking**, **Tool details** and **Live activity bar**.
3. The change is saved automatically and follows you to every device. It applies to new steps straight away, and to older steps when you reopen a chat.

Tip: the Herd and the sidebar counters show the same status (working, needs you, done) across all your chats.
Use them to see which chat needs you without opening each one.

## 7. Keyboard shortcuts

Press `?` (outside a text field) to see this list in the app. On a Mac, use `Cmd` where this table says `Ctrl`.

### General

| Keys | Action |
|---|---|
| `Ctrl+K` | Command palette |
| `?` | Keyboard shortcuts |
| `Alt+N` | New chat |
| `/` | Search chats (outside a text field) |
| `Alt+Up` / `Alt+Down` | Previous / next chat in the sidebar |
| `Esc` | Close a dialog, menu or the mobile sidebar |
| `Ctrl+B` | Show or hide the sidebar |

### Go to (press `g`, then the key)

| Keys | Page |
|---|---|
| `g` `c` | New chat |
| `g` `h` | Herd |
| `g` `r` | Recipes |
| `g` `k` | Skills |
| `g` `s` | Schedules |
| `g` `a` | Apps |
| `g` `e` | Extensions |
| `g` `,` | Settings |
| `g` `d` | Admin (administrators only) |

### Chat

| Keys | Action |
|---|---|
| `Enter` | Send (configurable) |
| `Shift+Enter` | New line |
| `Ctrl+Enter` | Send, or steer while Goose runs |
| `Ctrl+.` | Stop the agent |
| `F2` | Rename the chat |
| `/` | Slash commands (at the start of the message) |
| `@` | Mention an agent |
| `Up` / `Down`, `Enter` or `Tab`, `Esc` | Move in, pick from, or close the command or mention menu |

### Editors

| Keys | Action |
|---|---|
| `Ctrl+S` | Save the recipe in the recipe editor |

## 8. Herd

The Herd page shows every live agent with its status, so you see at a glance which one needs you. Agents keep
working when you close the tab.

### Statuses

| Status | Meaning |
|---|---|
| Needs you | Waiting for a permission answer or for input. |
| Working | Running a turn now. |
| Error | The last run failed, or the agent stopped unexpectedly. |
| Done | Finished since you last looked. It becomes Idle when you open the chat. |
| Idle | Nothing running. |
| Offline | Not reachable at the moment. |

Cards are grouped by status, with "Needs you" first.

### A card shows

- the status dot, the chat title and how long it has been in that state
- the working folder
- the cost so far and how full the context window is, when known
- the last text Goose wrote
- pending approvals and questions, with the same buttons as in the chat (**Answer...** opens a form)
- **Open** to go to the chat, and **Stop** while the agent is working or needs you

### Other machines

If your administrator connected other Goose Web servers ("peers"), an **Other machines** section lists their
agents, with an online or unreachable badge. **Open on ...** opens the chat on that server in a new tab.

### For administrators

Administrators see an **All users** switch that shows every user's agents. Opening another user's chat opens a
new tab in an admin view of that profile, with a banner that says actions are audited. See
[ADMINISTRATION.md](ADMINISTRATION.md).

## 9. Recipes

A recipe is a reusable setup: instructions, a first prompt, parameters, model settings and extensions. You can
run, share and schedule recipes.

### Run a recipe

1. Open **Recipes**.
2. Click **Run** on a card (or **...** > **Run in new chat**).
3. The new-chat screen opens with the recipe chosen and its prompt in the message box. Choose a folder, change
   the prompt if you like, and send.
4. If the recipe has parameters, the **Recipe parameters** dialog opens. Fill in the values and click **Start**.

You can also run recipes from the command palette ("Run recipe: ..."), from the Recipe chip on the new-chat
screen, or with their slash command in the message box.

### Recipe cards

Each card shows the title, description, slash command, schedule, number of parameters, file name and last
change. The **...** menu has: Run in new chat, Edit, Copy share link, Download YAML, Schedule..., Slash
command..., and Delete....

### Create a recipe

1. Click **New recipe**.
2. Fill in the **Form** tab:
   - **Basics**: Title and Description are required. Version and Author contact are optional.
   - **Agent**: Instructions (added to the system prompt) and/or Prompt (the first message). You need at least
     one of the two. Use `{{ key }}` in the prompt to insert a parameter.
   - **Parameters**: click **Add parameter**. Set the key, type (string, number, boolean, date, file, select),
     requirement (required, optional, user_prompt), description, default and, for select, the options.
   - **Settings**: provider, model, temperature and maximum turns. Leave empty for the defaults.
   - **Extensions**: a JSON list. **Add from my extensions** adds one of your configured extensions.
   - **Activities**: suggested starter activities, one per line.
   - **Structured response**: an optional JSON schema for the final answer.
   - **Sub-recipes** and **Retry** for advanced use.
3. Click **Save** (or press `Ctrl+S`).

The **YAML** tab shows the same recipe as YAML, which you can edit directly. **Preview** shows a summary.
If you leave with unsaved changes, Goose Web asks you to confirm.

### Other editor buttons

- **Scan** runs a security scan. It warns about content such as hidden Unicode characters.
- **Share** creates a link that anyone with Goose can import.
- **Run** starts the recipe in a new chat.
- **...** > Schedule..., Slash command..., Download YAML, Delete....

### Import a recipe

1. Click **Import**.
2. Choose **Paste YAML**, **From file** (a `.yaml`, `.yml` or `.json` file) or **Deeplink** (a `goose://recipe`
   link).
3. Click **Open in editor**, check the recipe and click **Save**.

### Slash commands and schedules for a recipe

- **Slash command...**: enter a name with letters, numbers, `-` and `_`. Then type `/name` in any chat to run the
  recipe. Leave it empty to remove it.
- **Schedule...**: opens the cron helper (see [Schedules](#11-schedules)). **Remove schedule** stops it.

Recipes provided by your team cannot be deleted by you. Without the `recipes_edit` permission you can still run
recipes, but not change them.

## 10. Skills

Skills are Markdown instructions that Goose loads when they are relevant.

The list on the left has three groups:

- **Global**: skills in your profile.
- **Project**: skills that belong to a project folder.
- **Built-in**: skills that come with Goose. They are read-only.

Click a skill to read it. The detail view shows the name, description, file location, supporting files and the
content.

### Create or edit a skill

1. Click **New skill** (or **Edit** on a skill).
2. Enter a **Name** (lowercase, dashes allowed) and a **Description** that says when Goose should use it.
3. Write the content in Markdown. Use the **Preview** tab to check it.
4. Click **Create** or **Save**.

New skills are saved in your global skills.

### Other actions

- **Export** downloads a skill as a JSON file.
- **Import** loads skills from such a JSON file.
- The bin icon deletes a skill after a confirmation.

Skills marked "read-only" cannot be changed. Without the `skills_edit` permission the page is read-only.

## 11. Schedules

A schedule runs a recipe automatically at set times. Each run creates a chat, which appears in the sidebar
when **Scheduled runs** is turned on in the list options.

### Create a schedule

1. Open **Schedules** and click **New schedule**. (You need at least one recipe.)
2. Choose the **Recipe**.
3. Check the **Schedule ID**. It is filled in from the recipe title and must be unique.
4. Set the time with the cron helper (see below).
5. Click **Create**.

### The cron helper

Goose uses cron expressions with six fields: second, minute, hour, day of month, month, day of week. Times are
in the server's local time. Below the field, a plain-English description confirms what you typed, or shows an
error.

The **Presets** list fills in common schedules:

| Preset | Cron |
|---|---|
| Every 15 minutes | `0 */15 * * * *` |
| Every hour | `0 0 * * * *` |
| Every day at 09:00 | `0 0 9 * * *` |
| Every day at 14:00 | `0 0 14 * * *` |
| Weekdays at 08:30 | `0 30 8 * * 1-5` |
| Every Monday at 09:00 | `0 0 9 * * 1` |
| First of the month at 06:00 | `0 0 6 1 * *` |

### Manage schedules

Each schedule shows its ID, the description and cron expression, the recipe file, and when it last ran.

| Action | What it does |
|---|---|
| Run now | Runs the recipe immediately. A message offers **Open** for the new chat. |
| Open run | Opens the chat of a run that is in progress. |
| Edit schedule... | Changes the cron expression. |
| Pause / Resume | Stops or restarts future runs. |
| Past runs... | Lists the chats from earlier runs. |
| Inspect running job | Shows when the current run started and its chat. |
| Kill running job | Ends the current run. |
| Delete... | Removes the schedule. Chats of past runs are kept. |

If the page says the scheduler is not active on this server, schedules are read-only here. This can happen when
the same profile is used by Goose Desktop, which then runs the schedules. Without the `schedules` permission you
can view schedules but not change them.

## 12. Apps

Apps (MCP Apps) are small interactive HTML tools that run in a sandbox and can call Goose tools.

### Open an app

1. Open **Apps**.
2. Click **Open** on a card. The app runs in the page. The header shows "Running · sandboxed" when it is ready.
3. Use the reload button to restart the app, or the external-link button to open it in a new tab.

The card's **...** menu also has **Open in new tab**, **Export HTML**, **View description** (if the app has one)
and **Delete**.

### Import an app

1. Click **Import**.
2. Upload an `.html` file or paste the HTML.
3. Click **Import**.

You can also ask Goose to build an app for you in a chat.

### Safety rules for apps

- An app runs at an isolated origin. It cannot read your Goose Web session or cookies.
- An app may only call tools of its own extension.
- If an app wants to run a tool from a powerful extension (`developer`, `computercontroller`, `code_execution`,
  `orchestrator`), you must confirm each call. **Cancel** is the default.
- If an app wants to send a chat message for you, you must confirm it. Messages are limited to 8 KB and one every
  5 seconds.
- Apps can open only `http`, `https` and `mailto` links.

### Auto mode is required for app tool calls

Goose only lets apps run tools when the chat is in `auto` mode. If an app tries to run a tool in another mode,
Goose Web shows a warning that says so. Switch the chat's mode to `auto` if you trust the app.

Importing, deleting and app tool calls need the `apps` permission.

## 13. Extensions

Extensions give Goose its tools. They are MCP servers or Goose built-ins.

### The Extensions page

- Tabs **All**, **Enabled** and **Disabled** with counts, and a search box.
- Each row shows the name, type (`stdio`, `http`, `sse` or `builtin`), a "bundled" badge for extensions that come
  with Goose, the description and the command or URL.
- The switch on each row enables or disables the extension for new chats.
- **...** > **View configuration** shows the stored settings. **Edit...** (MCP extensions only) and **Remove**
  change them.

Changes apply to new chats. Running chats keep their extensions until they reload. To change the extensions of
one chat, use the [extensions chip](#extensions-chip) in that chat.

### Add an extension

1. Click **Add extension**.
2. Choose the type:
   - **Command (stdio)**: the full command line, for example `npx -y @modelcontextprotocol/server-everything`,
     plus environment variables. Needs the `allow_shell` permission.
   - **Streamable HTTP**: the URL, for example `https://example.com/mcp`, plus headers such as
     `Authorization: Bearer ...`.
   - **Built-in**: the name of a Goose built-in, for example `memory` or `todo`.
3. Enter a **Name** (letters, numbers, `-`, `_`, `.`), an optional description and a timeout in seconds.
4. Click **Add**.

Adding, removing and enabling extensions needs the `extensions_edit` permission, which is off by default for
non-administrators. Extensions that can run commands (`developer`, `computercontroller`, `code_execution`,
`orchestrator` and any command extension) also need `allow_shell`.

## 14. Settings

Open **Settings** from the sidebar. The tabs are on the left (a drop-down list on phones). A tab that your
policy does not allow shows a "Read-only" note or is hidden.

### Models & Providers

**Default model**: choose the **Provider** and **Model** used for new chats and click **Save default**.
**Clear** removes the default. **Check readiness** tests the provider.

**Providers**: a list of providers. Configured ones come first. Turn on **Show unconfigured** to see all.

To set up a provider:

1. Turn on **Show unconfigured** and click the provider.
2. Follow the setup steps shown, if any.
3. Fill in the fields. Secret fields (marked "secret") are never shown again. Leave a secret empty to keep the
   stored value.
4. Click **Save**, then **Check**.

Other buttons in a provider:

- **Sign in**: for providers that use a browser sign-in. If the provider uses a device code, a dialog shows the
  code, a copy button and a link to open. Enter the code on that page before the timer runs out.
- **Refresh models** updates the model list. **Supported models** lists what the provider reports.
- **Remove configuration** deletes the stored keys for that provider.
- **Custom provider** (at the top) adds an OpenAI-compatible, Anthropic-compatible or Ollama endpoint with its
  URL, API key, models and extra headers. Custom providers can be edited or deleted.

**Stored secrets**: lists stored provider secrets with their status and expiry. Use the bin icon to delete one.

Changing providers, defaults and secrets needs the `providers_edit` permission. Your policy may also hide
providers that are not allowed.

### System prompts

The templates Goose uses to build its system prompt. Pick one on the left. The **Edit** tab changes it, **Diff
vs default** shows your changes, and **Default** shows the original. **Save** stores your version in your profile.
**Reset to default** removes it. Needs the `prompts_edit` permission. For changes to one chat only, use
**System prompt...** in the chat's session menu.

### Preferences

#### Chat

These settings belong to Goose Web and follow you to every device.

| Setting | Values | Default |
|---|---|---|
| Enter sends the message | On: `Enter` sends. Off: `Ctrl+Enter` sends and `Enter` adds a line. | On |
| Show message timestamps | Shows the time on your messages. | Off |
| Thinking | Auto, Always expanded, Collapsed | Auto |
| Tool details | Auto, Detailed, Concise | Auto |
| Live activity bar | On, Off | On |

See [section 6](#6-watching-goose-work-live-activity) for what Thinking, Tool details and the Live activity bar do.

#### Goose preferences

These settings are stored in your Goose profile. Click **Save preferences** after a change.

| Setting | What it does |
|---|---|
| Auto-compact threshold | The fraction of the context window (0 to 1) at which Goose summarises the conversation. Empty means the Goose default (0.8). 0 turns it off. |
| Default thinking effort | For models with extended thinking: off, low, medium, high or max. Empty means the Goose default. |
| Voice auto-submit phrases | Comma-separated phrases that send a dictated message. |
| Dictation provider | The speech-to-text provider. |
| Preferred microphone | Device name or ID. |

The list comes from Goose, so your version may show other settings.

### Goose hints

Goose hints are extra instructions added to every chat.

- **Assigned by your administrator**: hints documents assigned to you or to your team. They are read-only.
- **Personal hints**: your own hints. Write them in the **Personal** tab, check them in **Preview**, and click
  **Save**.
- **Effective (what Goose sees)**: the combined text Goose receives.

The parts are combined from lowest to highest precedence: your personal hints first, then documents assigned to
you, then your team's hints last. **Team hints win**: if one of your hints conflicts with a team hint, Goose follows
the team hint.

Your team decides whether you may have personal hints ("Members may add personal hints", off unless your
administrator turns it on). If it is off, the editor is read-only, and any personal hints you saved earlier are kept
but not used: a warning says "Your personal hints are not used: your team does not allow personal hints."

Goose loads only these combined hints. `AGENTS.md` or `.goosehints` files in your working folders are ignored, and
you cannot upload or create files with those names.

Example personal hints:

```markdown
# My hints
- Prefer PowerShell 7 on Windows.
- Our repositories are in C:\work.
- Answer in short paragraphs.
```

### Tool permissions

Sets, per tool, what happens in `approve` and `smart_approve` modes.

1. Under **Load tools from chat**, pick a chat. Tools are listed from a chat so that its extensions are loaded.
   If loading fails, open that chat once and try again.
2. Filter the list if needed.
3. For each tool choose **Mode default**, **Always allow**, **Ask before** or **Never allow**.
4. Click **Save N change(s)**.

Needs the `tools_permissions` permission.

### Advanced config

Shown only with the `config_edit` permission. It lists the raw values of your Goose `config.yaml`. You can add,
edit and remove keys, and store a value as a secret. Wrong values can break Goose, so prefer the other pages.

### Appearance

- **Theme**: System, Dark, Light, Midnight, Nord, Solarized Dark, Solarized Light, Dracula or High contrast.
  "System" follows your operating system.
- **Accent color**: the theme default, one of eight colours, or a custom colour.
- **Layout**: **Density** (Comfortable or Compact), **Font size** (12 to 18 px) and **Code theme** (Match theme,
  GitHub Dark or GitHub Light).
- **Preview** shows sample text and code with your choices.

Changes apply immediately and are saved to your account.

### Notifications

**Browser notifications**

1. Click **Allow notifications** and accept the browser prompt.
2. Turn on **Show desktop notifications**. They appear when the Goose Web tab is in the background.
3. Optional: turn on **Play a sound**. Click **Test** to hear it.
4. Under **Notify me when**, choose the events: an agent needs you, an agent finished, an agent failed.
5. Click **Send a test notification** to check.

If the browser blocked notifications, allow them for this site in the browser settings.

**Webhook**

The server can send a JSON event to a web address, even when no browser is open. This works with Slack, Teams
or ntfy style webhooks.

1. Enter the **Webhook URL**, for example `https://hooks.example.org/goose`.
2. Choose the events.
3. Click **Save webhook**.

A webhook needs the `notify_webhook` permission (off by default). The address must be a public internet address
unless your administrator allows internal ones. Clear the field and save to remove the webhook.

### Account

**Profile**: shows your username, role, sign-in source and team. Change your **Display name** and **Email**
and click **Save profile**.

**Password** (local accounts only): enter your current password and the new one twice, then click **Change
password**. Changing your password signs out your other sessions and revokes all your API tokens. Directory and
single sign-on accounts show who manages the password instead.

**Two-factor authentication**

To turn it on:

1. Click **Set up**.
2. Scan the QR code with an authenticator app, or copy the secret into it.
3. Enter the 6-digit code and click **Verify & enable**.

From then on, sign-in asks for a code. To turn it off, click **Disable** and confirm with your password.
Your administrator can turn off self-service two-factor for non-administrators, and can require it for
administrator accounts. See [ADMINISTRATION.md](ADMINISTRATION.md). If you lose your phone, an administrator can
reset your two-factor so you can sign in with your password and set it up again (see the FAQ).

**Active sign-ins**: every browser where you are signed in, with device, address, sign-in time and last activity.
The current browser is marked "this browser". Click **Revoke** to sign out another one.

**API tokens**: tokens let scripts use the Goose Web API as you (see [API.md](API.md)).

1. Click **New token**.
2. Enter a name and choose when it expires: 30 days, 90 days, 1 year or never.
3. Click **Create**.
4. Copy the token now. It is shown only once.

Scripts send it in the header `Authorization: Bearer gwt_...`. Click **Revoke** to delete a token. All tokens
are revoked when your password changes or is reset.

## 15. What your policy can restrict

You belong to one team, and your administrator sets that team's policy (and sometimes a few settings for you
alone). Administrators themselves have no restrictions. Since version 1.5.0 policies follow least privilege: a
new team allows nothing until the administrator turns things on. If a button is missing or a page says
"Read-only", your policy is the likely reason. Ask your administrator, and see
[ADMINISTRATION.md](ADMINISTRATION.md) and [CONFIGURATION.md](CONFIGURATION.md).

| Permission | What it allows | On a new team |
|---|---|---|
| `recipes_edit` | Create, change and delete recipes | Not allowed |
| `skills_edit` | Create, change, import and delete skills | Not allowed |
| `extensions_edit` | Add, remove, enable and disable extensions | Not allowed |
| `providers_edit` | Set up providers, defaults, custom providers and secrets | Not allowed |
| `schedules` | Create, change, pause, run and delete schedules | Not allowed |
| `apps` | Import and delete apps, app tool calls | Not allowed |
| `prompts_edit` | Change system prompts, including per-chat prompts | Not allowed |
| `hints_edit` | Personal Goose hints ("Members may add personal hints"); without it your personal hints are not used | Not allowed |
| `tools_permissions` | Set per-tool permissions | Not allowed |
| `config_edit` | Raw Goose configuration (Advanced config tab) | Not allowed |
| `allow_shell` | Shell and command extensions, command (stdio) MCP extensions | Not allowed |
| `notify_webhook` | A personal notification webhook | Not allowed |

Lists and limits:

| Setting | Effect |
|---|---|
| Allowed approval modes | Only these modes appear in the mode picker. None allowed = you cannot chat. |
| Allowed providers / models | Only these appear in the pickers and in Models & Providers. None allowed = you cannot chat. |
| Default provider / model | What new chats start with. |
| Team folder | A folder shared by your team, shown as **Team:** and the team name. |
| Extra folders | Folders you can use besides your workspace and the team folder. |
| Concurrent runs | How many agents can run at the same time (default 3). |

Teams that existed before version 1.5.0 kept their earlier settings, so your team may allow more than a new team.

## 16. FAQ

**Does Goose stop when I close the browser?**
No. The server keeps the agent running. Open the chat again later to see the result. Turn on notifications or a
webhook to be told when it finishes or needs you.

**Why does Goose ask me before every command?**
The chat is in `approve` mode. Choose **Always allow** for tools you trust, set tool permissions in
**Settings > Tool permissions**, or switch to another mode if your policy allows it.

**Why can't I pick a folder?**
You can only use your workspace, your team folder and the extra folders your team allows. Ask for access to
other folders.

**Why can't I chat?**
The home page says why. Either you are not in a team yet, or your team allows no providers, models or approval
modes. Ask your administrator. In an older chat, the reason can also be that the chat uses a model, provider or
mode your team no longer allows: pick an allowed one in the chat header.

**Why does Goose ignore the AGENTS.md in my project?**
Goose Web gives Goose only the hints your team and you set (Settings > Goose hints). Hints files in working
folders are ignored, and you cannot upload files with those names. Ask your administrator to add shared
instructions to your team's hints.

**Why don't I see the Thinking block?**
Not every model produces thinking. Check the thinking level picker in the chat header and the **Default
thinking effort** in Goose preferences. Also check that **Thinking** is not set to **Collapsed** in
Settings > Preferences.

**Why does thinking appear all at once instead of word by word?**
Goose sends each thinking block in one piece once the model has finished it.

**I sent a message while Goose was running. Where did it go?**
It is in the queue above the message box and will be sent when the run ends. Click **Send now** to steer
instead.

**Where do my uploaded files go?**
Into `.goose-web-uploads` inside the chat's working folder, for example
`C:\work\project\.goose-web-uploads\report.pdf`. Images up to 8 MB are sent directly to the model instead.

**I use Goose Desktop too. Do I see the same chats?**
If your account uses the same Goose profile as Goose Desktop, yes. Chats continued in Desktop, the CLI or a
schedule refresh in the open web chat within a few seconds.

**Why is a page read-only?**
Your policy does not allow changes there. See [section 15](#15-what-your-policy-can-restrict).

**Why does an app say it needs Auto mode?**
Goose only allows app tool calls in `auto` mode. Switch the chat to `auto` if you trust the app.

**I lost my two-factor device. What now?**
Ask an administrator to reset your two-factor (Admin > Users > Reset two-factor). You are signed out
everywhere and your API tokens are revoked; then you sign in with your password alone. Set up two-factor again
with your new phone straight away (Settings > Account > Two-factor authentication). Administrators: see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md#lost-authenticator).

**The connection indicator says "Goose down". What do I do?**
Wait a moment: the server restarts your agent automatically. If it stays down, see
[TROUBLESHOOTING.md](TROUBLESHOOTING.md) or contact your administrator.

**My scripts stopped working after I changed my password.**
Changing your password revokes all your API tokens. Create a new token in Settings > Account.
