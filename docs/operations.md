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

   It configures 1Password, the OpenAI docs, Exa (OAuth), homebased, Calendar, Reminders and Xcode. Approval notifications use the
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
   with `codesign -dv ~/.local/bin/codemode-mcp`, which should show `TeamIdentifier=Q8UP8C53Y8`.

4. Check it: `codemode-mcp service status` (plist, launchd state, `/healthz`).
5. Expose the approval pages to the phone: `tailscale serve --bg --https=8443 http://127.0.0.1:7681`.
   `public_origin` (default `https://mac.tailnet-name.ts.net:8443`) must match.

## Releases

Pushing a `v*` tag runs `.github/workflows/release.yml`, which builds `aarch64-apple-darwin`, signs it with the
same identity and identifier, and attaches `codemode-mcp-<tag>-aarch64-apple-darwin.tar.gz` and its checksum.
It reads the `MACOS_SIGNING_P12_BASE64` and `MACOS_SIGNING_P12_PASSWORD` secrets and the
`MACOS_SIGNING_IDENTITY` variable, the same names homebased uses, and fails rather than ship unsigned. The
Monty worker is not part of the release.

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
  1Password write, is approved for that one call only, and the prompt says `once`.
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
codemode-mcp oauth login exa       # prints the link and opens the browser
codemode-mcp oauth status          # logged in, expiry, refresh token, scopes, connection state
codemode-mcp oauth logout exa      # forget the tokens; the server reconnects anonymously
```

The browser returns to `http://127.0.0.1:7682/oauth/callback/exa` on the admin listener, so sign in from a
browser on this Mac. Tokens refresh automatically. A server that refuses anonymous clients shows
`needs_login` in `/healthz` and `codemode-mcp tools` until you sign in.

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

- `oauth = true` on a `url` server enables `oauth login` (optional `scopes`, `client_name`).
- Per tool: `policy` (`allow`, `ask`, `deny`) and, for `ask`, `grant` (`session` or `per_call`). A `session` grant is given to the calling client, not to one MCP session: it covers every running session of that client name for 15 or 60 minutes.
- The server is session-less: it issues no `mcp-session-id`, for any protocol version. Clients are told apart by the client name in the request `_meta`, the `initialize` handshake or the `user-agent` header. While `execute` or `wait` is waiting, it sends progress notifications every `limits.progress_interval_ms` (15000) to clients that sent a `progressToken`.
- Result types. A tool that declares no output schema returns a `JsonValue` that scripts narrow with `isinstance`. Give it a type in the tool's table: `output = "text"` for prose or markdown (the script gets a `str`, never parsed), or `output_schema` with an inline JSON Schema table for JSON, e.g. `output_schema = { type = "object", required = ["id"], properties = { id = { type = "string" } } }`. An upstream-declared schema wins over `output_schema` unless the table also sets `force_output_schema = true`. Every result is checked against the schema, so write only fields the tool really returns and mark optional ones with a `required` list or a `["string", "null"]` type. Probe it first: `codemode-mcp exec` a script that prints `json.dumps(await server_tool(...))`.
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
- On start the daemon removes `codemode-homebased-*` temp dirs older than 10 minutes left by a crash.
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

- `Looks too loose` names the signal: probe executes, runtime errors typing should have caught, or `json.loads`
  scripts. Look at the untyped-tool ranking in the section and add `output` / `output_schema` overrides for the
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
- The homebased adapter answers `homebased error <code>`: the code is homebased's own (see its skill's
  `errors.md`). `unknown_thread` means the `thread` argument is not a live session on this Mac.
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
