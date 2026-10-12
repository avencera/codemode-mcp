# Operating codemode-mcp

Commands below assume the binary is on `PATH` (`~/.local/bin/codemode-mcp` after install). Times in logs are UTC.

## Install

1. Build and fetch the worker in the repository: `cargo build --release`, with the Monty worker at
   `.tools/bin/monty`.
2. Write the starter config, then edit it:

   ```sh
   codemode-mcp config init            # ~/.config/codemode-mcp/config.toml; refuses to overwrite
   codemode-mcp config init --print    # or look first
   ```

   It configures 1Password, the OpenAI docs, Exa (OAuth) and homebased. Approval notifications use the
   `[notify.ntfy]` section of `~/.config/homebased/config.toml` unless you add one here.
3. Preview, then install the LaunchAgent from the repository root:

   ```sh
   ./target/release/codemode-mcp service install --dry-run
   ./target/release/codemode-mcp service install
   ```

   This copies the binary to `~/.local/bin/codemode-mcp` and the worker to
   `~/.local/share/codemode-mcp/monty`, writes `~/Library/LaunchAgents/dev.praveen.codemode-mcp.plist` and loads
   it. Run it again after every rebuild; it replaces both files and reloads the service.
4. Check it: `codemode-mcp service status` (plist, launchd state, `/healthz`).
5. Expose the approval pages to the phone: `tailscale serve --bg --https=8443 http://127.0.0.1:7681`.
   `public_origin` (default `https://mac.tailnet-name.ts.net:8443`) must match.

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

## Warm up 1Password

```sh
codemode-mcp op warm
```

Runs the configured warm calls on the daemon so the 1Password app's prompts appear on the Mac now. Accept them
there; agent calls then only need the phone approval. Results are never printed.

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
- Check the result with `codemode-mcp tools` (connects, lists every tool with its status).

## Read the usage review

```sh
codemode-mcp stats --since 7d
codemode-mcp review --since 7d --out review.md
```

The review lists the most common error fingerprints with an example, the runs that struggled most (a run is an MCP session, or for session-less clients one client's calls with gaps under 10 minutes, so approximate),
hallucinated tool names, scripts that called tools they never described, and approval timings. Use it to fix
the agent directions or the stubs. `/stats` on the main listener shows the same numbers as `stats`.

## Troubleshoot

- Logs: `~/.local/state/codemode-mcp/logs/codemode-mcp.err.log` (set `RUST_LOG=debug` in the plist's
  environment for more).
- `service status` says not loaded: `service install` again; `launchctl print gui/$(id -u)/dev.praveen.codemode-mcp`
  shows launchd's view.
- An upstream is `unavailable`: `codemode-mcp tools` prints the local error. For stdio servers check the command
  path; launchd's PATH is `~/.local/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin`.
- `ask` calls are refused at once: no notifier (add `[notify.ntfy]`) or no passkey (enroll one).
- An approval link does not open on the phone: check `tailscale serve status` and `public_origin`.
- Monty worker not found: `service install` again, or set `worker_path`.
- The homebased adapter answers `homebased error <code>`: the code is homebased's own (see its skill's
  `errors.md`). `unknown_thread` means the `thread` argument is not a live session on this Mac.

## Uninstall

```sh
codemode-mcp service uninstall --dry-run
codemode-mcp service uninstall
```

This unloads the service and removes the plist. State (`~/.local/state/codemode-mcp`), the config and the
installed binary and worker stay; delete them by hand if wanted. Remove the agents' `codemode` MCP entries and
`tailscale serve --https=8443 off` as well.
