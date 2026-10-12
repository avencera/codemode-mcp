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
- A paused execution can be dumped (`Checkout::dump`), HMAC-signed and stored, then restored after a daemon restart

### Approvals

- Policy per tool: `allow`, `ask`, or `deny`, with server-level defaults (1Password: `ask`)
- On an `ask` call the execution suspends, an approval record is created and an
  ntfy notification links to `https://mac.tailnet-name.ts.net:<port>/approve/<id>`
- The approval page shows the tool, arguments and the script, and requires a passkey (webauthn-rs) to approve
- An approval can grant the same agent session the same tool (or server) for a chosen period, so repeated calls don't each need a tap
- Deny or expiry raises a normal Python exception in the script

### 1Password warm-up

The daemon keeps one `1password-mcp` connection open. `codemode-mcp op warm`
(and a button on the approval page) calls `authenticate` and touches each
configured environment so the 1Password app's own prompts happen on the Mac
up front. Agent calls then only need the phone passkey approval.
Unconfirmed: whether a 1Password lock ends the MCP session

### Agent-facing tools

| Tool | Purpose |
|---|---|
| `search_tools(query, limit?)` | ranked tool paths with one-line descriptions |
| `describe_tools(paths)` | Python stubs for the chosen tools |
| `execute(code)` | type-check and run; waits up to a short budget, then returns `{status: "pending", execution_id, approval_url?}` |
| `wait(execution_id)` | waits again for a pending execution and returns its result or the same pending shape |

The short `execute` wait keeps calls under agent MCP timeouts. Codex
defaults `tool_timeout_sec` to 60 s per call. Claude Code's wall-clock
`MCP_TOOL_TIMEOUT` defaults to about 28 hours, but an HTTP call with no
response or progress notification aborts after 5 minutes of idle time
(`CLAUDE_CODE_MCP_TOOL_IDLE_TIMEOUT`). A 25 s wait budget fits both

### Usage tracking

Goal: see whether agents use Code Mode well or get confused, and feed that back into the directions and stubs

- Every agent-facing call is a row in SQLite: client name (from MCP `initialize`), session, tool (`search_tools`/`describe_tools`/`execute`/`wait`), query or described names, script, upstream calls made, duration, result size, outcome
- Outcome taxonomy: `ok`, `type_error` (with ty rule code), `unsupported_syntax`, `name_error` (unknown tool), `import_error`, `runtime_error` (exception type), `tool_error`, `timeout`, `denied`, `pending`
- Sensitive servers (1Password) log tool names and outcomes only, never arguments or results
- Derived signals: attempts-to-success per session, top error fingerprints, hallucinated tool names, execute without a prior describe, empty or repeated searches, sessions whose last execute failed
- Built for manual review (weekly or more often): `codemode-mcp review --since 7d` writes a Markdown report with per-client summary, top error fingerprints with an example script each, the sessions with the most retries shown as their full attempt sequence, hallucinated tool names, and empty searches
- `codemode-mcp stats` for quick numbers; the same views on the web server
- Retention 90 days by default (configurable)

### Service

- Rust 2024, tokio, axum 0.8, rmcp, monty-pool, webauthn-rs, rusqlite; conventions match homebased (color-eyre, thiserror, no unwrap/expect)
- launchd agent `dev.praveen.codemode-mcp`, listening on `0.0.0.0`, Host header rules accept localhost, private, Tailscale and `*.ts.net` names (plus `extra_allowed_hosts`)
- HTTPS for the passkey page through `tailscale serve` on a dedicated port (`/` on 443 is already taken)
- Config: `~/.config/codemode-mcp/config.toml`; state: `~/.local/state/codemode-mcp/` (SQLite for approvals, passkeys, grants, OAuth credentials, snapshots)
- Notifications: ntfy, the same topic homebased uses unless configured otherwise

## Decisions

- Existing upstreams move behind codemode-mcp; their direct agent entries are removed once it works (a direct 1Password entry would bypass phone approval)
- 1Password policy: read tools `ask` with session grants (15 or 60 min); write tools (`create_environment`, `rename_environment`, `append_variables`, `create_local_env_file`) `ask` on every call
- Approval notifications reuse homebased's ntfy topic; the notification names the client and tool only, arguments stay on the passkey page
- Approvals served over `tailscale serve` on HTTPS port 8443; pending approvals auto-deny after 10 minutes

## Open questions

- Monty spike results: pool latency, stub generation from real schemas, dump/restore of a suspended call
- 1Password session lifetime across app lock
