# Operating codemode-mcp

Commands below assume the binary is on `PATH` (`~/.local/bin/codemode-mcp` after install). `cmcp` is the same
binary under a shorter name. Times in logs are UTC.

## Install

1. Build and fetch the worker in the repository: `cargo build --release`, with the Monty worker at
   `.tools/bin/monty`.
2. Write the starter config, then edit it:

   ```sh
   codemode-mcp config init            # ~/.config/codemode-mcp/config.toml; refuses to overwrite
   codemode-mcp config init --print    # or look first
   ```

   It configures 1Password, the OpenAI docs, Calendar, Reminders and Xcode. Approval notifications use the
   `[notify.ntfy]` section of `~/.config/homebased/config.toml` unless you add one here.
3. Preview, then install the LaunchAgent from the repository root:

   ```sh
   ./target/release/codemode-mcp service install --dry-run
   ./target/release/codemode-mcp service install
   ```

   This copies the binary to `~/.local/bin/codemode-mcp`, links `~/.local/bin/cmcp` to it, copies the worker to
   `~/.local/share/codemode-mcp/monty`, writes `~/Library/LaunchAgents/dev.praveen.codemode-mcp.plist` and loads
   it. Run it again after every rebuild; it replaces both files and reloads the service. If something else is
   already at `~/.local/bin/cmcp`, the install leaves it alone and logs a warning.

   Both binaries are signed with the InfraOps LLC Developer ID, the one homebased releases use, as
   `com.avencera.codemode-mcp` and `com.avencera.monty`. macOS and the 1Password app tie their approvals to an
   ad-hoc binary's hash, so without the certificate every rebuild would prompt again. The install refuses to
   run when the identity is not in the keychain. To set it up once, import the .p12:

   ```sh
   security import InfraOps.p12 -k ~/Library/Keychains/login.keychain-db -T /usr/bin/codesign
   ```

   The first signing may ask whether codesign can use the key; choose Always Allow. Check an installed binary
   with `codesign -dv ~/.local/bin/codemode-mcp`, which should show `TeamIdentifier=Q8UP8C53Y8` and `flags=0x10000(runtime)`.

4. Check it: `codemode-mcp service status` (plist, launchd state, `/healthz`).
5. Expose the approval pages to the phone: `tailscale serve --bg --https=8443 http://127.0.0.1:7681`.
   Set `public_origin` in the config to that address, such as `https://mac.tailnet-name.ts.net:8443`
   (`tailscale status --json | jq -r .Self.DNSName` prints the name). Unset, links point at
   `http://localhost:7681` and open only on the Mac. Its host is the passkeys' relying party id, so changing it
   later means enrolling them again.

## Releases

Bump `version` in `Cargo.toml`, then push a matching `v*` tag. `.github/workflows/release.yml` builds
`aarch64-apple-darwin` and installs the `monty-runtime` worker matching the `monty-pool` version in `Cargo.lock`.
It signs both with the same identity and identifiers as a local install and attaches
`codemode-mcp-<tag>-aarch64-apple-darwin.tar.gz` (holding `codemode-mcp` and `monty`), its `.sha256` and
`install.sh`. It
reads the `MACOS_SIGNING_P12_BASE64` and `MACOS_SIGNING_P12_PASSWORD` secrets and the `MACOS_SIGNING_IDENTITY`
variable, the same names homebased uses, and fails rather than ship unsigned.

## Update

```sh
codemode-mcp update --dry-run   # which release would replace what
codemode-mcp update             # latest release; --tag v0.2.0 for another
```

This downloads the release archive and checks it against the published checksum. It also requires both
executables to be signed by team `Q8UP8C53Y8` as `com.avencera.codemode-mcp` and `com.avencera.monty`. Only then
does it replace `~/.local/bin/codemode-mcp` and `~/.local/share/codemode-mcp/monty`, worker first, and restart the
service if its LaunchAgent is installed. The release signatures are kept as they are, so updating needs no
certificate in the keychain and the 1Password and EventKit grants carry over. Nothing happens when the
installed binary already reports the tag, or reports a newer version than the latest release, as a local build
can; `--force` reinstalls anyway. To roll back, pass the previous release with `--tag`. `cmd fleet update` runs
it on the Mac.

The LaunchAgent plist is not rewritten. When a release changes it, run `codemode-mcp service install` once.

## Enroll a passkey

```sh
codemode-mcp passkey enroll --label iPhone
```

- First passkey: open the printed link on the phone (10 minutes, one use) and create the passkey. The phone
  gets a notification that a first passkey is being enrolled.
- Later passkeys: the command prints a confirmation code and two links. Approve the first one with an
  existing passkey after checking that the page shows the same code, then open the second one on the new
  device. A denied or expired approval kills the enrollment link.
- `codemode-mcp passkey list` shows passkeys. `codemode-mcp passkey remove <id>` prints an approval link; the
  passkey is removed only after an existing passkey approves it. The last passkey can't be removed: enroll a
  replacement first, then remove the old one. If you lose your only device, stop the service and delete the
  row from the `passkeys` table in `~/.local/state/codemode-mcp/codemode.sqlite`.
- Every enrollment or removal request notifies the phone. One you did not start means something on the Mac
  is running the CLI: deny it and look.

## Approve at the Mac

While you are at the Mac (screen unlocked, input in the last 5 minutes), a tool call waiting for approval shows
a Touch ID prompt there instead of buzzing the phone. It names the tool, what a touch grants, the client, and
the thread title and reason the agent passed to `execute`; those two are the agent's own words, shown in quotes.

- Touch the sensor to approve the call and every tool of that server not marked `grant = "per_call"` for 60
  minutes in the agent's session. Mark writes you want asked every time, such as calendar deletes,
  `per_call`. A tool with `grant = "per_call"`, such as a
  1Password write, is approved for that one call only, and the prompt says `once`. When a script starts
  several such calls together, such as a set of deletes under `asyncio.gather`, one prompt names them all
  (`calendar.delete_event ×5 once`) and one touch approves the set. The phone push and the page cover the
  same set, and the page lists every call's arguments.
- Press **Open Page** to open the approval page in the browser, for a single call, 15 minutes, or to deny. The
  page takes your passkey.
- Leave it, and after 60 seconds the phone is told too (60 seconds after **Open Page** if you opened the page).
  Locking the screen or walking away (no input for 5 minutes) sends it to the phone within a couple of seconds.

Passkey enrollment and removal requests never offer Touch ID: they show a Mac notification and notify the
phone at once. On a Mac without Touch ID the prompt is replaced by a notification that opens the page, which
needs `terminal-notifier` (`brew install terminal-notifier`); allow its notifications the first time macOS asks.
On the phone nothing changes: the page shows everything, and you choose and confirm with the passkey.

```toml
[notify.mac]
enabled = true              # false: phone only
idle_secs = 300             # no input for this long counts as away
escalate_after_secs = 60    # then the phone is told as well
touch_id = true             # false: a notification instead of the prompt
```

## Warm up 1Password

```sh
codemode-mcp op warm
```

Runs the configured warm calls on the daemon so the 1Password app's prompts appear on the Mac now. Accept them
there; agent calls then only need the phone approval. Results are never printed.

## Read 1Password references from another Mac

When you work from another Mac, such as a MacBook Air, the gateway Mac's 1Password prompt for `{{ op://… }}`
references cannot be answered, even over remote desktop, because Touch ID is on the gateway Mac. A companion
fixes that: the same `codemode-mcp` binary on the other Mac reads the reference through that Mac's own
1Password and `op`, after a Touch ID prompt there that names the reference, and sends the value back over iroh.
The 1Password Environments server is not covered; it only signs in through the gateway Mac's app.

1. On the gateway Mac, with the daemon running:

   ```sh
   codemode-mcp companion invite
   ```

   It prints a command for the other Mac, also as a QR code, and waits until that Mac is done. The command holds
   a single-use invite that expires after ten minutes (`--valid-for <seconds>` shortens it). Until it is used,
   treat it like a password: whoever runs it first is registered, so check that the name and id `invite` prints
   are the other Mac's. Stopping `invite` with Ctrl-C does not cancel the invite; it stays valid until it is
   used or expires. Only the user that runs the daemon can open an invite: it takes the token in `admin.token`
   in the daemon's state directory (mode 0600), which other accounts on the Mac cannot read. The token is
   never sent; the CLI and the daemon each prove they hold it, so a program that took the admin port while the
   daemon was down can neither learn it nor hand out its own ticket. Once a Mac has used it, it is spent even if that Mac's setup then fails; run `invite` again,
   and the Mac keeps its existing entry.
2. Paste the command into a terminal on the other Mac. To get it there, scan the QR code with a phone's camera,
   copy the text it shows, and paste it on the Mac through Universal Clipboard. The command installs the signed
   release through `install.sh`. A release install needs no InfraOps .p12: since 0.2.1 the install keeps the
   release's own signatures. Then it runs `codemode-mcp companion pair`, which:
   - registers the Mac with the gateway over iroh. The gateway appends a `[[secrets.companions]]` entry to the
     end of its config. The running daemon starts reading through it once the check below reaches it, with
     no restart, so a Mac whose setup fails is never asked in place of the gateway's own `op`; `invite` then
     says so and exits with an error.
   - writes a `[companion]` section to this Mac's config, with the references the gateway's servers use as the
     allow list.
   - installs and starts the companion's LaunchAgent, as `codemode-mcp companion install` does.
   - asks the gateway to read one of those references through this Mac. Approve the one Touch ID prompt. While
     1Password has authorized `op` on that Mac, the prompt is the companion's and names the reference;
     otherwise it is 1Password's, and a notification names the reference. Both Macs print the value's
     length, never the value.

   On a Mac that already has codemode-mcp, the second command `invite` prints, `codemode-mcp companion pair
   <ticket>`, does the same without reinstalling. Run it with the installed binary
   (`~/.local/bin/codemode-mcp`), so the key it creates belongs to the signed copy.
3. Check it again later from the gateway Mac; approve the Touch ID prompt on the other Mac:

   ```sh
   codemode-mcp companion check op://Dev/Context7/credential
   ```

   It prints each companion's answer and the value's length, never the value.

If the other Mac cannot reach the gateway, pair by hand. `codemode-mcp companion invite --manual` prints a ticket
holding the gateway's id and references. `codemode-mcp companion pair <ticket>` on the other Mac writes its
`[companion]` section, starts the agent and prints a `[[secrets.companions]]` block. Append that block to the end
of the gateway Mac's config, then run `codemode-mcp service restart` there. The block is printed before the
agent is installed; if the install fails, fix the cause and run the same `pair` command again, which installs
again and prints the block again.

A companion built from a checkout instead of a release is signed by `companion install`, which needs the InfraOps
signing identity as in [Install](#install).

How reads work with a companion configured:

- The gateway runs its own `op read` only while you are at the gateway Mac (input within `notify.mac.idle_secs`),
  and asks every companion at the same time. The first value wins and the other reads are cancelled, so working
  over remote desktop, which makes the gateway Mac look in use, still reaches the companion.
- A companion answers only the gateway it was paired with, and only references on its `allow` list. 1Password's
  own prompt does not name the item, and one approval lets `op` read anything for about ten minutes, so the
  companion asks Touch ID itself, naming the reference, on every request. Edit `allow` in its `[companion]`
  section to change what the gateway may read, then `codemode-mcp companion install` again to restart it.
- The gateway accepts nothing over iroh unless a peer is listed or an invite is open. While an invite is open it
  accepts pairing; while a phone is listed under `[[secrets.phones]]` it accepts that phone's id, and refuses
  every other id. The rest of the time it only dials its companions. An invite lets one Mac register, once. Pairing the same Mac again
  keeps its existing entry, and a different Mac with a name that is already taken is listed as `name-2`.
- Each Mac's iroh key is created on first use and kept in its login keychain. The binary that creates it reads it
  without a prompt, and so does any build signed with the same identity; any other program gets a keychain
  prompt. That is why pairing and the gateway's first `invite` should run from the installed, signed binary. A
  keychain prompt asking for `dev.praveen.codemode-mcp.iroh` from any other program is worth denying.
- By default both sides use n0's relays and DNS discovery to find each other, which publishes each Mac's
  endpoint id and current addresses to n0's DNS. Traffic stays end-to-end encrypted. To keep it and the
  addresses on your network, set `discovery = false` under `[secrets]` on the gateway before inviting. The
  invite then carries the gateway's current addresses. Pairing gives the companion `discovery = false` and
  `listen = "0.0.0.0:7678"`, and lists that Mac's IPv4 addresses in its `[[secrets.companions]]` entry, so
  the two Macs must reach each other directly over IPv4, for example over the tailnet.

## Approve from an iPhone

The Companion app answers `{{ op://… }}` reads from an iPhone. The phone does not read 1Password itself: each
time a reference is read, the gateway seals the value to a key in the phone's Secure Enclave and keeps only that
sealed copy. The phone answers by opening the copy, which takes Face ID. So:

- The first time a reference is asked for, the phone has no copy. Paste the value into the read, or fill it in
  with AutoFill from 1Password or Passwords, and send it. The gateway seals whatever value wins, so the next
  read opens with Face ID. Pairing seals what the daemon has already read since its last start.
- The copy holds the value from the last time the reference was read. After rotating a secret, tap Enter a
  different value on the phone's next read, or read it once at the gateway Mac or a companion Mac.
- Changing Face ID's enrolled faces voids the phone's key, and opening a copy then fails; pair again.

Install the app from TestFlight, or build it onto a connected iPhone with `just ios-run` (needs Xcode, xcodegen,
and the phone's UDID in `IOS_DEVICE_UDID`).

1. To wake the phone when a read comes in, give the gateway an APNs key (Certificates, IDs & Profiles, Keys,
   with Apple Push Notifications service enabled) under `[secrets]`:

   ```toml
   [secrets.apns]
   key_file = "/Users/you/.config/codemode-mcp/apns/AuthKey_ABC123DEFG.p8"
   key_id = "ABC123DEFG"
   team_id = "Q8UP8C53Y8"
   ```

   Without it, the phone answers only while Companion is open on screen. The push goes through Apple and
   names the reference and the gateway Mac, never the value. It is marked time-sensitive, so it can break
   through a Focus that allows time-sensitive notifications.
2. With the daemon running, run `codemode-mcp companion invite` on the gateway Mac. Open Companion and point it at
   the QR code, or copy the command and tap Paste invite. The phone registers, the gateway
   appends a `[[secrets.phones]]` entry to the end of its config, and the gateway reads one reference through
   the phone: approve it with Face ID. If nothing has been read since the daemon started, there is nothing
   sealed to check yet, and pairing says so. A phone must register the iroh id it connects with, so a leaked invite
   cannot list a phone for another device's id.
3. Check it later from the gateway Mac with `codemode-mcp companion check <reference>`; the phone shows the read.

How reads work with a phone paired:

- Every listed phone is asked alongside the gateway's own `op` and the companion Macs, and the first value
  wins. While you are at the gateway Mac, the phones are asked 5 seconds later, so a read you answer there
  never pushes to the phone. When another source answers first, the phone's prompt is taken
  down; when the phone answers first, the other prompts are.
- The phone dials the gateway, since iOS does not let a suspended app accept connections. The gateway sends
  each read over that connection and waits up to 120 seconds; the phone shows a countdown and marks the read
  expired when the gateway stops waiting.
- The phone shows one read at a time, naming the reference. It answers the references the gateway used when
  it paired, matched exactly; any other reference waits for you to tap Allow this reference, after which the
  phone answers it like the rest. The gateway screen lists the allowed references; swipe one to remove it. The values it opens or is given never leave its memory except in the answer, which is at most 64 KiB.
- The phone keeps its iroh key, the gateway's address and its allow list in its Keychain, readable only while
  it is unlocked. Deleting the app forgets the pairing.
- With `discovery = false`, set `listen` under `[secrets]` to a fixed address such as `"0.0.0.0:7679"`, so the
  address the invite gives the phone stays valid across restarts. The phone must then reach that address
  directly, for example over the tailnet.

To unpair, tap Unpair in Companion. The gateway forgets the phone's sealed copies and push token and stops
accepting it, and the phone forgets its keys. Remove its `[[secrets.phones]]` entry from the gateway's config by
hand; until then a restarted daemon accepts the old id again, though no device holds its key any more.

## Calendar and Reminders access

The `calendar` and `reminders` servers read the Mac's Calendar and Reminders apps through EventKit, across every
account those apps show. The first time the daemon starts each adapter, macOS asks on the Mac whether
"codemode-mcp" may use your calendars, then your reminders; click Allow on both. Until then their tools answer
with what to do instead of data.

- The grant belongs to the signed binary (`com.avencera.codemode-mcp`), so reinstalling a rebuild keeps it. A
  binary signed with another identity, or not signed, is asked again or refused.
- Denied by mistake: turn codemode-mcp on in System Settings > Privacy & Security > Calendars (or Reminders);
  no restart is needed.
- No prompt appeared: the adapter asks again 30 seconds after an unanswered request, on the next tool call.
  `codemode-mcp service restart` asks at once.

Run by hand from a terminal (`codemode-mcp adapter calendar`), the request is attributed to the terminal app
instead, so test through the daemon.

## Xcode access

The `xcode` server runs Xcode's own bridge, `xcrun mcpbridge` (Xcode 26.3 or later), against the Xcode that
`xcode-select` picks. Xcode approves agents itself, and through the gateway the daemon is that agent for every
client. Until it is approved every tool fails with "This agent isn't approved to use Xcode's tools yet".

- Approve: have an agent call `XcodeOpenWorkspace` with a project path (or `XcodeNewProject`). Xcode asks on the
  Mac to approve the agent and that project's folder; accept both. Each new folder asks again.
- Check: `xcrun mcp-server status` shows whether Xcode's tool service is running and which workspaces are open.
  In headless mode, `sudo xcrun mcp-server approve <id>` approves a pending request by the id `status` shows.
- Revoke: `sudo xcrun mcp-server clear-permissions` removes every agent and folder grant.

## OAuth sign-in

```sh
codemode-mcp oauth login <server>    # prints the link and opens the browser
codemode-mcp oauth status            # logged in, expiry, refresh token, scopes, connection state
codemode-mcp oauth logout <server>   # forget the tokens; the server reconnects anonymously
```

For a `url` server with `oauth = true`. The browser returns to `http://127.0.0.1:7682/oauth/callback/<server>` on the admin listener, so sign in from a
browser on this Mac. Tokens refresh automatically. A server that refuses anonymous clients shows
`needs_login` in `/healthz` and `codemode-mcp tools` until you sign in.

An authorization server without dynamic client registration needs a client you create there yourself: set
`client_id`, and `client_secret` for a confidential client. The secret can be an `op://` reference; it is read
at login and stored with the tokens. `authorization_params` adds query parameters to the sign-in URL.

### Gmail and Google Calendar

Google's Workspace MCP servers (developer preview) take a client from your own Google Cloud project:

1. In a Google Cloud project, enable the Gmail API, Google Calendar API, `gmailmcp.googleapis.com` and
   `calendarmcp.googleapis.com`.
2. Under Google Auth Platform, set up the consent screen (audience Internal for a Workspace account; External
   needs you added as a test user).
3. Create an OAuth client of type Web application, tick "Use this client for an AI-powered agent", and add the
   redirect URIs `http://127.0.0.1:7682/oauth/callback/gmail` and
   `http://127.0.0.1:7682/oauth/callback/google_calendar`.
4. Save the client secret in 1Password, add the tables below, restart, and run `codemode-mcp oauth login gmail`
   and `codemode-mcp oauth login google_calendar`.

```toml
# every Gmail call asks on the phone; reads accept a 15 or 60 minute session
# grant, and every change asks each time. There is no send tool: drafts are
# as far as it goes
[servers.gmail]
url = "https://gmailmcp.googleapis.com/mcp/v1"
oauth = true
client_id = "<id>.apps.googleusercontent.com"
client_secret = "{{ op://Private/Google Workspace MCP/credential }}"
# without these Google issues no refresh token and the login lasts an hour
authorization_params = { access_type = "offline", prompt = "consent" }
scopes = [
  "https://www.googleapis.com/auth/gmail.readonly",
  "https://www.googleapis.com/auth/gmail.compose",
  "https://www.googleapis.com/auth/gmail.modify",
  "https://www.googleapis.com/auth/gmail.labels",
]
policy = "ask"
aliases = ["email", "mail"]

[servers.gmail.tools.create_draft]
grant = "per_call"
# ...and the same for every other tool that is not a read

[servers.google_calendar]
url = "https://calendarmcp.googleapis.com/mcp/v1"
oauth = true
client_id = "<id>.apps.googleusercontent.com"
client_secret = "{{ op://Private/Google Workspace MCP/credential }}"
authorization_params = { access_type = "offline", prompt = "consent" }
scopes = [
  "https://www.googleapis.com/auth/calendar.calendarlist.readonly",
  "https://www.googleapis.com/auth/calendar.events",
  "https://www.googleapis.com/auth/calendar.events.freebusy",
]
aliases = ["gcal"]

[servers.google_calendar.tools.create_event]
policy = "ask"
[servers.google_calendar.tools.update_event]
policy = "ask"
[servers.google_calendar.tools.respond_to_event]
policy = "ask"
[servers.google_calendar.tools.delete_event]
policy = "ask"
grant = "per_call"
```

Both servers list their tools without a login, so they appear in the catalog at once; calls fail until you
sign in.

## Add a server

Add a table under `servers` and restart (`codemode-mcp service restart`):

```toml
[servers.docs]                 # remote, Streamable HTTP
url = "https://example.com/mcp"

[servers.mytool]               # local, stdio
command = "/opt/homebrew/bin/mytool-mcp"
args = ["--stdio"]
policy = "ask"                 # every call needs a phone approval; logs keep tool names only

[servers.mytool.tools.delete_everything]
policy = "deny"
```

- `oauth = true` on a `url` server enables `oauth login` (optional `scopes`, `client_name`, or `client_id` and `client_secret` for a client registered ahead of time, and `authorization_params`).
- Rarely used stdio servers: `lazy = true` starts the process on the first call and stops it after `idle_secs` (default 600) without calls; `/healthz` shows it as `idle` meanwhile and its tools stay searchable. A failed start fails that call only, and the next call tries again.
- Keys stay in 1Password: a `headers` or `env` value can hold `{{ op://vault/item/field }}` references, as in `op inject`, e.g. `headers = { authorization = "Bearer {{ op://Dev/Context7/credential }}" }`. The daemon runs `op read` the first time the server connects and keeps the value in memory until it exits; to pick up a rotated key, run `codemode-mcp service restart`. With the 1Password app integration the Mac asks once when the daemon starts (a locked or unanswered prompt shows `secret_unavailable` in `/healthz` and retries every 10 minutes). `[secrets] op` names the `op` binary (default `op` on `PATH`).
- Per tool: `policy` (`allow`, `ask`, `deny`) and, for `ask`, `grant` (`session` or `per_call`). A `session` grant is given to the calling client, not to one MCP session: it covers every running session of that client name for 15 or 60 minutes.
- The server is session-less: it issues no `mcp-session-id`, for any protocol version. Clients are told apart by the client name in the request `_meta`, the `initialize` handshake or the `user-agent` header. While `execute` or `wait` is waiting, it sends progress notifications every `limits.progress_interval_ms` (15000) to clients that sent a `progressToken`.
- Result types. A tool that declares no output schema returns a `JsonValue` that scripts read with the `json_*` accessors. Give it a type in the tool's table: `output = "text"` for prose or markdown (the script gets a `str`, never parsed), or `output_schema` with an inline JSON Schema table for JSON, e.g. `output_schema = { type = "object", required = ["id"], properties = { id = { type = "string" } } }`. An upstream-declared schema wins over `output_schema` unless the table also sets `force_output_schema = true`. Every result is checked against the schema, so write only fields the tool really returns and mark optional ones with a `required` list or a `["string", "null"]` type. Probe it first: `codemode-mcp exec` a script that prints `json.dumps(await server_tool(...))`.
- Check the result with `codemode-mcp tools` (connects, lists every tool with its status).

## Restarts and in-flight work

`service install`, `service restart`, a crash and a reboot all restart the daemon. State is in
`<state_dir>/codemode.sqlite` (default `~/.local/state/codemode-mcp/`) and needs no import: the daemon opens the
file the previous build wrote, in place, and adds its new tables on first start. There is no
`codemode.sqlite.imported-*` file and the old file is not moved or copied, so back it up before installing if you
want a way back (a build older than the schema refuses to open it).

What a restart does:

- Finished results stay available to `wait` for 30 minutes (`limits.result_ttl_secs`).
- Pending approvals stay pending; the phone link keeps working and the timer continues from the original
  deadline. An ntfy that had failed is sent again at boot.
- Executions waiting only on an approval resume once it is approved, denied or expired. Calls they make after
  that use the tools the restarted daemon has.
- On a normal stop (SIGTERM, which `service restart` sends) the daemon stops taking new executions, waits up to
  `limits.drain_secs` (default 20) for running scripts, parks the ones waiting on approval, and flushes the usage
  log. The plist `ExitTimeOut` is set to the drain plus 30 seconds when you run `service install`, so rerun it
  after changing `drain_secs`; `serve` logs a warning at start when the installed plist allows less than the
  drain plus 10 seconds.
- A script still running after the drain, or running when the daemon died, ends as `interrupted`. `wait` says so
  and lists the upstream calls that finished. Writes may have happened: check before running it again.
- Anything that touched a sensitive server (1Password) is not written to disk. After a restart `wait` reports it
  as `interrupted`, its approval page shows the request as withdrawn, and the script has to be run again. Grants
  survive.
- Enrollment links and passkey removals waiting on approval survive too.
- Only one daemon can run on a state directory: a second `codemode-mcp serve` exits at once with "another
  daemon owns <dir>" and changes nothing. A CLI command (`exec`, `stats`, `review`, `passkey list`) works beside
  the running daemon.
- A kill with SIGKILL, or a power loss, also drops the last usage-log lines that were not yet flushed.

## Read the usage review

```sh
codemode-mcp stats --since 7d
codemode-mcp review --since 7d --out review.md
```

The review lists the most common error fingerprints with an example, the runs that struggled most (a run is an MCP session, or for session-less clients one client's calls with gaps under 10 minutes, so approximate),
hallucinated tool names, scripts that called tools they never described, type strictness, and approval timings.
Use it to fix the agent directions or the stubs. `/stats` on the main listener shows the same numbers as `stats`.

The "Type strictness" section ends with a verdict line:

- `Looks too loose` names the signal: probe executes, runtime errors typing should have caught, or scripts
  parsing JSON text. Look at the untyped-tool ranking in the section and add `output` / `output_schema` overrides for the
  top tools.
- `Looks too strict` names a rule whose errors the next execute did not fix, runs abandoned after a type error, or
  a tool whose results keep failing their schema (`output_mismatch`: loosen or fix that `output_schema`, or use
  `output = "text"`).
- `Mixed` means both; fix the schema mismatches first, since they hide the rest.
- Act on a signal that holds across two reviews; the thresholds are in `docs/design.md`.

## Troubleshoot

- Logs: `~/.local/state/codemode-mcp/logs/codemode-mcp.err.log` (set `RUST_LOG=debug` in the plist's
  environment for more).
- `service status` says not loaded: `service install` again; `launchctl print gui/$(id -u)/dev.praveen.codemode-mcp`
  shows launchd's view.
- An upstream is `unavailable`: `codemode-mcp tools` prints the local error. For stdio servers check the command
  path; launchd's PATH is `~/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`.
- `ask` calls are refused at once: no notifier (add `[notify.ntfy]`) or no passkey (enroll one).
- An approval link does not open on the phone: check `tailscale serve status` and `public_origin`.
- Requests go to the phone while you are at the Mac: the log says why (`Touch ID is not available`,
  `Mac notification failed`). The daemon must run as a LaunchAgent in your login session to see the screen.
- Monty worker not found: `service install` again, or set `worker_path`.
- A calendar or reminders tool says macOS denied access, or is asking: see Calendar and Reminders access.
- An Xcode tool says the agent isn't approved: see Xcode access.

## Uninstall

```sh
codemode-mcp service uninstall --dry-run
codemode-mcp service uninstall
```

This unloads the service and removes the plist. State (`~/.local/state/codemode-mcp`), the config and the
installed binary, the `cmcp` link and the worker stay; delete them by hand if wanted. Remove the agents' `codemode` MCP entries and
`tailscale serve --https=8443 off` as well.
