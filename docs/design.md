# codemode-mcp design

An always-on local daemon that aggregates upstream MCP servers behind a Code
Mode surface. Agents (Claude Code, Codex, OpenCode) connect to one MCP
endpoint, discover tools by search, and run short Python scripts that call
many tools in one round trip. Tool definitions never enter the agent's
context unless it asks for them

## Goals

- One MCP endpoint for every agent on this Mac, reachable over LAN and Tailscale
- Add upstream MCPs (including our own) without growing agent context
- Scripts are type-checked against tool signatures before they run
- Sensitive tool calls (1Password) pause for approval from a phone, protected by a passkey
- Survive agent-side MCP tool-call timeouts and daemon restarts during approvals

## Non-goals (v1)

- Authenticating agents to the endpoint: LAN and tailnet are the trust boundary
- Remote/multi-machine execution; homebased Fleet already covers that
- Waking agent sessions when an execution finishes (`homebased message send` is a later option)

## Components

```text
agents ──Streamable HTTP /mcp──▶ server (axum + rmcp)
                                   │
              ┌────────────────────┼─────────────────────┐
              ▼                    ▼                     ▼
          catalog             executor               approvals
   (index, search,      (monty-pool workers,    (policy, ntfy push,
    Python stubs)        type check, limits,      passkey web page,
              │           snapshots)              grants)
              ▼                    │
          upstreams ◀──────────────┘
   (rmcp clients: stdio, HTTP, HTTP+OAuth, HTTP with caller-token passthrough)
```

### Upstreams

rmcp 3.x clients, one long-lived connection per configured server

| Kind | Example | Notes |
|---|---|---|
| stdio | `1password-mcp`, our own MCPs (homebased adapter) | child process supervised by the daemon; restart with backoff |
| HTTP | `openaiDeveloperDocs` | plain Streamable HTTP |
| HTTP + OAuth | Exa | rmcp `AuthorizationManager` with a file-backed `CredentialStore`; the browser redirect lands on our `/oauth/callback` |
| HTTP, caller auth | T3 Code (`127.0.0.1:3773/mcp`) | T3 mints a bearer token per thread, so the caller's own token is forwarded instead of one shared token |

Upstream calls use `PeerRequestOptions::with_timeout` so a timeout sends
`notifications/cancelled`; an outer `tokio::time::timeout` would not.
Calls are never retried automatically, since upstream tools may not be
idempotent. `tools/list_changed` refreshes the catalog

### Catalog

- Tools are namespaced by server: `exa.web_search`, `onepassword.list_environments`
- Each server becomes a Python host module with a generated `.pyi` stub:
  JSON Schema → `TypedDict` inputs, `async def` functions, docstrings from tool descriptions
- Search ranks over name, description and parameter names (BM25 is enough at this scale)

### Executor

- Language: typed Python restricted to simple constructs Monty supports, run by pydantic/monty (`monty-pool` worker subprocesses)
- Agent directions (server instructions, `execute` description, `describe_tools` header) share one text: annotate types, await tools with keyword arguments, use `asyncio.gather` for concurrency, stdlib subset only, no inheritance/generators/`match`/custom exceptions, last expression is the JSON result
- Type checking with the bundled `ty` against the generated stubs; type errors are returned to the agent as-is
- Limits per execution: memory, wall-clock budget excluding time spent waiting for approval, max suspensions
- Tool calls inside a script run concurrently through `asyncio.gather`
- Upstream results are measured (depth, element count, bytes; `limits.max_tool_result_bytes`, default 4 MiB) before they are converted into Python values; an oversized result raises `ValueError` at the call site
- While an execution waits only on approvals, its session is dumped (`Checkout::dump`), sealed with HMAC-SHA256 under a per-install key (`<state_dir>/snapshot.key`, mode 0600), the worker and its slot are released, and on the decision the dump is verified and restored on a fresh worker (see Approvals)

### Approvals

- Policy per tool: `allow`, `ask`, or `deny`, with server-level defaults (1Password: `ask`)
- Grant mode per `ask` tool: `session` (default) or `per_call`. A session grant (15 or 60 min) covers every
  `session`-grant tool of that server for the same MCP session (`Mcp-Session-Id`), and also answers that
  session's other pending requests for such tools. `per_call` tools ask on every call and refuse session grants
- An `ask` call needs a notifier and at least one enrolled passkey; otherwise it is refused at once
  (`no passkey enrolled; run \`codemode-mcp passkey enroll\``)
- On an `ask` call the gateway creates a pending request (random 128-bit id) and sends an ntfy notification:
  title `codemode: <client> wants <server>.<tool>`, high priority, click URL `<public_origin>/approve/<id>`.
  Arguments never go into the notification
- `GET /approve/{id}` (server-rendered, mobile layout, all agent-supplied text escaped, strict CSP) shows the
  client, session, `server.tool`, pretty-printed arguments, the script and the time left. Buttons: Approve once;
  Approve for this session 15 / 60 min (only for `session` tools in a session); Deny
- Approving takes a passkey assertion (webauthn-rs 0.5): `POST /approve/{id}/options` binds the choice to a
  server-side ceremony (random id, 5 min TTL, in memory, never serialized), then `POST /approve/{id}/confirm`
  verifies the assertion and applies that choice. Deny (`POST /approve/{id}/deny`) needs no passkey. All POSTs
  take JSON bodies, which keeps cross-site form posts out. `assets/webauthn.js` is the only script (no build step)
- The relying party id is the host of `public_origin` (default `https://mac.tailnet-name.ts.net:8443`); `Passkey`
  JSON is stored in SQLite and its counter updated after each assertion
- Pending requests are denied automatically after `approvals.timeout_secs` (600). Deny and expiry raise
  `PermissionError` at the call site; the agent directions tell scripts to catch it as `except OSError`, because
  Monty's type stubs do not define `PermissionError`
- While a call waits, the execution's wall-clock budget is paused, and `execute`/`wait` answer
  `{status: "pending", execution_id, approval_url, waiting_for: "<server>.<tool>", message}`
- Approval-gated calls are always answered with `ResumeValue::Future`, even when awaited directly, so the session
  reaches `ResolveFutures` with the gated call ids pending. When nothing but approvals is outstanding the session is
  dumped, sealed, and the worker returned; on the decision the dump is verified, restored on a fresh checkout,
  and the restored `ResolveFutures` pending ids must equal the ids recorded at the dump. If the dump fails the worker
  is held for the wait instead (Monty's own duration limits count execution time only, so holding costs no budget).
  Evidence: monty `ReplResolveFutures` serializes `pending_call_ids` (monty-1.1.0 `src/repl.rs:978-992`),
  `Checkout::dump` works at any suspension (monty-pool-1.1.0 `src/checkout.rs:1162-1176`), `restore` re-announces
  the suspension (`src/checkout.rs:779-812`), and the integration test
  `approval_waits_release_the_worker_and_pause_the_budget` runs a second script on the only worker while the first waits
- Dumps live in memory only, so a daemon restart mid-approval loses the execution (the request is withdrawn)
- `codemode-mcp passkey enroll` asks the daemon's admin listener for a one-time enrollment link
  (`<public_origin>/enroll/<token>`, 10 min); the page registers a passkey with a label.
  `passkey list` and `passkey remove <id>` work on the database directly

### 1Password warm-up

The daemon keeps one `1password-mcp` connection open. `codemode-mcp op warm [--server NAME]` asks the
daemon's admin listener to run the server's configured warm calls directly on the upstream, bypassing
approvals because the admin listener only answers loopback peers on the Mac:

```toml
[servers.onepassword.warm]
calls = [{ tool = "authenticate" }, { tool = "list_environments" }]
```

Each call prints `ok (<n> bytes of output, not shown)` or a failure category; results are never printed.
The CLI warns that the 1Password app on the Mac may show prompts to accept. Agent calls then only need the
phone passkey approval. Unconfirmed: whether a 1Password lock ends the MCP session

### Agent-facing tools

| Tool | Purpose |
|---|---|
| `search_tools(query, limit?)` | ranked tool paths with one-line descriptions |
| `describe_tools(paths)` | Python stubs for the chosen tools |
| `execute(code)` | type-check and run; waits up to a short budget, then returns `{status: "pending", execution_id, approval_url?, waiting_for?}` |
| `wait(execution_id)` | waits again for a pending execution and returns its result or the same pending shape |

The short `execute` wait keeps calls under agent MCP timeouts. Codex
defaults `tool_timeout_sec` to 60 s per call. Claude Code's wall-clock
`MCP_TOOL_TIMEOUT` defaults to about 28 hours, but an HTTP call with no
response or progress notification aborts after 5 minutes of idle time
(`CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT`). A 25 s wait budget fits both

### Usage tracking

Goal: see whether agents use Code Mode well or get confused, and feed that back into the directions and stubs

- SQLite at `<state_dir>/codemode.sqlite` (WAL, numbered migrations in `PRAGMA user_version`, mode 0600).
  Tables: `calls` (every agent-facing call: time, MCP session, client name/version from `initialize`, tool,
  input — query, described names or script —, outcome, detail, fingerprint, duration, result bytes, execution id),
  `executions` (one row per finished execution with its script and final outcome), `upstream_calls` (server,
  tool, Python name, arguments, outcome, duration, approval id), `approvals`, `passkeys`
- Records go through a bounded channel (4096) to a writer thread; when it is full the record is dropped and
  counted, so logging never blocks or fails an agent call
- Outcome taxonomy, classified from structured executor results: `ok`, `type_error` (ty rule codes kept),
  `unsupported_syntax` (Monty `NotImplementedError`), `name_error` (only `unresolved-reference` diagnostics, unknown
  tools, unknown described names), `import_error` (only `unresolved-import`), `runtime_error` (exception type kept),
  `tool_error`, `timeout`, `denied`, `pending`, `busy`. An exception is traced back to the tool failure the host
  injected when its type and message match, so an unhandled tool error is `tool_error`/`denied`/`timeout`, not
  `runtime_error`
- Error fingerprint: outcome plus the detail with quoted literals, numbers, hex ids and whitespace normalized
- Sensitive servers (`sensitive = true`, default when the server policy is `ask`): upstream rows keep tool name and
  outcome only; a failure from such a tool is logged as the tool name; once an execution has read a sensitive
  tool's result, its exception detail keeps only the exception type
- `codemode-mcp stats [--since 7d]`: per client calls, sessions, execute success rate, mean attempts until success
  per session; top 10 fingerprints; slowest upstream tools; approval counts. `GET /stats` shows the same
- `codemode-mcp review [--since 7d] [--out FILE]`: Markdown with a per-client summary, top fingerprints with one
  example script and error each, the 5 sessions with the most failed executes before success or abandonment as their
  ordered attempt sequence, hallucinated tool names (`name_error` names that start with a configured `<server>_`),
  executes that called tools never described in the session, empty and repeated searches, and approval stats
  (count, median wait, denied, expired)
- Retention `log_retention_days` (90); purged on startup and daily. Passkeys are kept

### Service

- Rust 2024, tokio, axum 0.8, rmcp, monty-pool, webauthn-rs, rusqlite; conventions match homebased (color-eyre, thiserror, no unwrap/expect)
- launchd agent `dev.praveen.codemode-mcp`, listening on `0.0.0.0`, Host header rules accept localhost, private, Tailscale and `*.ts.net` names (plus `extra_allowed_hosts`)
- HTTPS for the passkey page through `tailscale serve` on a dedicated port (`/` on 443 is already taken)
- Admin API (`/admin/enroll`, `/admin/warm`) on a separate listener, `admin_listen` (default `127.0.0.1:7682`, must be
  loopback). `tailscale serve` proxies phone traffic from 127.0.0.1 to the main listener, so a peer check there would
  admit the tailnet; the admin listener is never proxied, checks the socket peer (not the Host header) and refuses
  requests carrying proxy headers
- `/healthz` reports each upstream's name, state, tool count and a coarse error category only; raw connection
  errors (URLs, commands, paths) stay in local logs. Errors handed to scripts keep the server name and category;
  MCP error and tool error text is passed through after configured header values, env values and URL query
  strings are redacted
- Config: `~/.config/codemode-mcp/config.toml`; state: `state_dir` (default `$XDG_STATE_HOME/codemode-mcp` or
  `~/.local/state/codemode-mcp`): `codemode.sqlite`, `snapshot.key`
- Notifications: `[notify.ntfy]` (`server`, default `https://ntfy.sh`; `topic`; optional `token_file`), the same shape
  as homebased. Without it the `[notify.ntfy]` section of `~/.config/homebased/config.toml` is used
  (`notify.homebased_config` overrides the path). The topic and token are never logged

Example 1Password server block:

```toml
[servers.onepassword]
command = "1password-mcp"
policy = "ask"            # sensitive defaults to true for ask servers

[servers.onepassword.tools.create_environment]
grant = "per_call"
[servers.onepassword.tools.rename_environment]
grant = "per_call"
[servers.onepassword.tools.append_variables]
grant = "per_call"
[servers.onepassword.tools.create_local_env_file]
grant = "per_call"

[servers.onepassword.warm]
calls = [{ tool = "authenticate" }, { tool = "list_environments" }]
```

## Decisions

- Existing upstreams move behind codemode-mcp; their direct agent entries are removed once it works (a direct 1Password entry would bypass phone approval)
- 1Password policy: read tools `ask` with session grants (15 or 60 min); write tools (`create_environment`, `rename_environment`, `append_variables`, `create_local_env_file`) `ask` on every call
- Approval notifications reuse homebased's ntfy topic; the notification names the client and tool only, arguments stay on the passkey page
- Approvals served over `tailscale serve` on HTTPS port 8443; pending approvals auto-deny after 10 minutes
- Admin endpoints get their own loopback listener rather than a peer check on the proxied main listener
- Denied and expired approvals raise `PermissionError`, caught in scripts as `OSError`
- Approval waits release the worker through sealed in-memory dumps; surviving a daemon restart mid-approval is not implemented

## Open questions

- Persisting sealed dumps so approvals survive a daemon restart (needs re-attaching pending upstream calls)
- 1Password session lifetime across app lock
