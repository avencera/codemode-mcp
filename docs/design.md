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
| stdio | `1password-mcp`, our own MCPs (`codemode-mcp adapter homebased`) | child process supervised by the daemon; restart with backoff |
| HTTP | `openaiDeveloperDocs` | plain Streamable HTTP |
| HTTP + OAuth | Exa | rmcp `AuthorizationManager` with SQLite-backed credential and state stores; the browser redirect lands on the admin listener's `/oauth/callback/<server>` (see OAuth) |
| HTTP, caller auth | T3 Code (`127.0.0.1:3773/mcp`) | deferred; see T3 Code |

Upstream calls use `PeerRequestOptions::with_timeout` so a timeout sends
`notifications/cancelled`; an outer `tokio::time::timeout` would not.
Calls are never retried automatically, since upstream tools may not be
idempotent. `tools/list_changed` refreshes the catalog

### Catalog

- Tools are namespaced by server: `exa.web_search`, `onepassword.list_environments`
- Each server becomes a Python host module with a generated `.pyi` stub:
  JSON Schema → `TypedDict` inputs and results, `async def` functions, docstrings from tool descriptions. No
  function returns `Any`: a tool with an output schema returns the generated type, any other returns `JsonValue`
  (see Type strictness). `describe_tools` declares each shared `TypedDict` once
- Search ranks over name, description and parameter names (BM25 is enough at this scale)

### Executor

- Language: typed Python restricted to simple constructs Monty supports, run by pydantic/monty (`monty-pool` worker subprocesses)
- Agent directions (server instructions, `execute` description, `describe_tools` header) share one text: annotate types, await tools with keyword arguments, use `asyncio.gather` for concurrency, stdlib subset only, no inheritance/generators/`match`/custom exceptions, last expression is the JSON result
- Type checking with the bundled `ty` against the generated stubs; type errors are returned to the agent as-is
- Limits per execution: memory, wall-clock budget excluding time spent waiting for approval, max suspensions
- Tool calls inside a script run concurrently through `asyncio.gather`
- Scripts that use `Any`, `cast` or a `# type: ignore` / `# ty: ignore` comment are refused before `ty` runs (see Type strictness)
- A tool result is validated against the tool's effective output schema before the script sees it; a mismatch
  raises `RuntimeError` naming the tool, the JSON path and the expected and actual type, and the upstream call is
  logged as `output_mismatch`
- Upstream results are measured (depth, element count, bytes; `limits.max_tool_result_bytes`, default 4 MiB) before they are converted into Python values; an oversized result raises `ValueError` at the call site
- The host parses scripts itself (bans, review heuristics), so a script is capped at `limits.max_script_bytes` (default 64 KiB) and parsed on a thread with a 256 MiB virtual stack: deep nesting such as `1+1+…` otherwise overflows a tokio worker stack and aborts the daemon. The output schema check visits at most 100,000 schema nodes per result, because self-referring `anyOf` branches multiply
- While an execution waits only on approvals, its session is dumped (`Checkout::dump`), sealed with HMAC-SHA256 under a per-install key (`<state_dir>/snapshot.key`, mode 0600), the worker and its slot are released, and on the decision the dump is verified and restored on a fresh worker (see Approvals)

### Approvals

- Policy per tool: `allow`, `ask`, or `deny`, with server-level defaults (1Password: `ask`)
- Grant mode per `ask` tool: `session` (default, name kept for existing configs) or `per_call`. A session grant
  (15 or 60 min) is keyed by (app session hash, server), see App sessions. It covers every `session`-grant tool
  of that server for later calls that carry the same session, and also answers that session's other pending
  requests for such tools. It is allowed for any caller, local or proxied, because the unguessable token is the
  credential. A client grant (15 or 60 min, keyed by client name and server) is the fallback for calls that did
  not pass a valid session: it covers every connection of the same client name (see Protocol versions) and needs
  a direct local caller: a request from a non-loopback peer, or carrying any proxy header, never matches a client
  grant and cannot create one. A caller that sent no client name cannot get a client grant. `per_call` tools ask
  on every call and refuse both kinds of grant
- An `ask` call needs a notifier and at least one enrolled passkey; otherwise it is refused at once
  (`no passkey enrolled; run \`codemode-mcp passkey enroll\``)
- On an `ask` call the gateway creates a pending request (random 128-bit id) and sends an ntfy notification:
  title `codemode: <client> wants <server>.<tool>`, high priority, click URL `<public_origin>/approve/<id>`.
  Arguments never go into the notification
- `GET /approve/{id}` (server-rendered, mobile layout, all agent-supplied text escaped, strict CSP) shows the
  client, `server.tool`, pretty-printed arguments, the script and the time left. Buttons: Approve once;
  "Approve this session for 15 / 60 min" (only for `session` tools; every MCP call has a session) and, for a
  call that did not pass a valid session from a named, direct local client, also "Approve <client title or name>
  for 15 / 60 min" with a line saying the grant covers every running session of that client; a proxied or remote
  request is never offered the client grant, and the page says why. The server refuses a choice the page did not
  offer (`session15`, `session60`, `client15`, `client60`); Deny
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
- `codemode-mcp passkey enroll --label NAME` asks the daemon's admin listener for a one-time enrollment link
  (`<public_origin>/enroll/<token>`, 10 min); the page registers a passkey under that label.
  With no passkey enrolled the link works at once (and stops working as soon as any passkey exists, so a
  link minted before the owner enrolled cannot add a second one). With one or more passkeys, the link only
  becomes usable after an `admin` approval, "Enroll a new passkey named …", is approved with an existing
  passkey on the same approval page; denial or expiry kills the link, and approval restarts its 10 minutes
- `passkey remove <id>` creates an `admin` approval, "Remove the passkey named …", and the daemon removes the
  passkey only once an existing passkey approves it. The last passkey cannot be removed (409), because zero
  passkeys would reopen first enrollment to any local caller; enroll a replacement first. `passkey list` reads the
  database directly
- Every enrollment request and every removal request sends an ntfy notification (urgent priority), so an
  unexpected one shows up on the phone. Admin requests carry a six-character confirmation code that the CLI
  prints and the page and notification repeat, labels may not contain quotes, and a removal is pinned to the
  passkey's enrollment time so a reused row id cannot be hit. The CLI warns when no notifier is configured.
  Agent `notify` titles are prefixed `agent:` so they cannot pass for these The first-passkey notification carries no link, because the
  enrollment link is a capability. Admin approvals offer only Approve and Deny, never client grants
- An ntfy token configured for a plain `http://` server logs a warning at startup

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

### App sessions

The protocol has no session id, so the server issues its own: an app session, passed by the agent as the optional
`session` parameter of `search_tools`, `describe_tools`, `execute` and `wait`

- Token: 128 random bits as `cs_` plus 26 base32 characters. Only its SHA-256 is stored (in memory, SQLite, logs,
  `/stats`, reports), because the token is a bearer secret for grants. People see the first 8 hex characters
- A call with no `session`, or one that is unknown, idle past `session_idle_hours` (default 24), or minted for a
  different client name, gets a new session. Every response carries the session to use next: a `session` field in
  the JSON body of `execute` and `wait` (including the pending answer), and a first line `session: cs_…` in
  `search_tools`, `describe_tools` and the plain-text failures of `execute` and `wait`. A rejected value is
  replaced with a one-line note (`session_note` field or a `note:` line). `wait` works with or without the session
  as long as the execution id is valid; an execution stays bound to the session that started it
- Sessions live in the `sessions` table (hash, client, created, last seen), so they survive daemon restarts, and
  are purged daily with the log retention purge
- `calls.session` holds the 8-character hash prefix, and `calls.session_state` records `reused`, `minted` or
  `reminted` (a new session although the same client had an active one within the last hour: an agent that
  forgot to pass it back, a parallel first-turn call, or a second agent of that client starting). `stats` and
  `review` show per client the sessions minted, calls with a passed session and sessions used once. A
  "reminted" count is not shown: live trials on 2026-10-12 had Haiku and Sonnet mint extra sessions from
  parallel first-turn calls while passing every later session back correctly
- The guidance (server instructions, `execute` description, `describe_tools` header) tells agents to pass the
  `session` value from their previous codemode result on every call

### Protocol versions

The server is session-less for every client. It offers every protocol version rmcp knows (2024-11-05 through
2026-07-28) and serves them with `StreamableHttpServerConfig::with_legacy_session_mode(false)` (rmcp
`transport/streamable_http_server/tower.rs`, `legacy_session_mode`) over a `NeverSessionManager`. The 2026-07-28
protocol is stateless by design and is where clients are heading. Older clients still send `initialize` and get
a normal answer, but the server never issues an `mcp-session-id`, keeps no per-connection state, and has no
server-to-client stream (`GET /mcp` answers 405). Nothing is lost on restart or expiry: a client cannot hit a
dead session

Callers are identified per request, in this order:

1. `_meta["io.modelcontextprotocol/clientInfo"]` of the request (2026-07-28 clients send it on every call)
2. the `initialize` handshake's client info, only when rmcp has one that is not its own default identity (a
   session-less server rarely does, because later requests do not carry the handshake)
3. the `user-agent` header, parsed as `name/version` from its first product (`claude-code/2.1.296 (...)`)

`Mcp-Session-Id` is no longer read; `calls.session` holds the app session instead (see App sessions) and is null
only for calls outside the MCP tools. Claude Code 2.1.296 sends `_meta` with clientInfo, the protocol version, a different
`claudecode/toolUseId` on every call and a `progressToken`, and no session or conversation id anywhere
(verified 2026-10-12 against a stateless build)

Tradeoff: calls that do not pass an app session fall back to approval grants keyed by (client name, server). One
such approval covers every running session of that client for 15 or 60 minutes, so two Claude Code windows share
it. The client name is also self-asserted (`_meta` or `user-agent`), so grants apply only to direct local callers: the
TCP peer is loopback (`ConnectInfo<SocketAddr>`, enabled with `into_make_service_with_connect_info` on the main
listener and read from rmcp's injected request parts) and the request has none of `forwarded`, `x-forwarded-for`,
`x-forwarded-host`, `x-forwarded-proto`, `x-real-ip` or any `tailscale-*` header (`tailscale serve` connects from
127.0.0.1 and adds `X-Forwarded-For` and `Tailscale-User-*`). LAN and tailnet callers therefore need their own
approval for every call, and a grant can only be created from a local request; both rules are enforced on the
server, not only on the page. Per-call tools and admin actions never accept a grant

Waiting `execute` and `wait` calls send MCP progress notifications about every 15 s (`limits.progress_interval_ms`)
when the request carries a `progressToken`. Claude Code aborts an HTTP call that is idle for 5 minutes, and a
notification counts as activity

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

### Type strictness

**Goal.** A fast agent experience with few mistakes and few wasted tokens, not maximum strictness. Agents lose
turns two ways: they do not know a tool's result shape, so they spend an `execute` printing it or guess a key and
hit a runtime error; and they silence a type error that then fails at runtime. Hard rule: no tool function's
return type is `Any`.

**Enforced.**

- Result types. A tool with an `outputSchema` returns the `TypedDict` (or type) generated from it. A tool without
  one returns `JsonValue`, declared once in the stub header as
  `type JsonValue = str | int | float | bool | None | list[JsonValue] | dict[str, JsonValue]` (PEP 695; ty 0.0.14
  narrows it with `isinstance`, the stubs are never executed, so Monty never sees the statement). Parameters of
  unknown type accept `object`, results of unknown type are `JsonValue`; the header has no `Any`. The
  `**kwargs` fallback for parameter names that are not identifiers is `**kwargs: Unpack[<TypedDict>]` using the
  functional `TypedDict` syntax, which ty accepts
- Per-tool overrides (`[servers.<s>.tools.<t>]`): `output_schema` is an inline TOML table holding a JSON Schema;
  `output = "text"` returns the joined text as `str`, never parsed. Precedence: `output = "text"` wins over any
  upstream schema; an upstream-declared schema wins over `output_schema`, so a schema written for a server that
  later documents its own stops applying without an edit; `force_output_schema = true` makes the configured schema
  win. `output` and `output_schema` cannot be combined. The starter config types the OpenAI docs search, list and
  endpoint tools and marks Exa and `fetch_openai_doc` as text
- Runtime check. Every result is validated against its effective schema (upstream, config or adapter) before the
  script sees it, by a validator for the subset `stubs` turns into types (`type`, `nullable`, `enum`, `const`,
  `required`, `properties`, `additionalProperties`, `items`/`prefixItems`, `allOf`/`anyOf`/`oneOf`, `$ref`); other
  keywords such as `pattern`, `minimum` and `format` pass. A text result for a `str` tool always passes. Sensitive
  servers log only the expected type of a mismatch: the path can hold keys from the data
- Bans before `ty` runs (`src/bans.rs`, `ruff_python_parser` pinned to the version Monty uses): a use of `Any` or
  `cast` imported under any alias, `<typing alias>.Any` and `<typing alias>.cast`, and `# type: ignore` /
  `# ty: ignore` comment tokens (text inside a string is not a comment). An unused import is allowed: it switches
  nothing off, and the first smoke run showed agents add one out of habit, which cost a retry for no gain. They come back as a `type_error` with rule ids
  `ban:any`, `ban:cast`, `ban:type-ignore` and a one-line hint

**Deliberately skipped.** A second checker (mypy, basedpyright), required annotations on `def`s, and bans on bare
`list` or `dict`. They cost agents turns, and the review below says whether they would pay off.

**How the weekly review judges it.** `review` and `/stats` carry a "Type strictness" section per client:

- Too strict: `type_error` counts per rule (ty rule names and `ban:*`); for each rule the share resolved by the
  next execute of the run (the next execute no longer reports the rule); the share of runs with a type error that
  never had a successful execute afterwards; `output_mismatch` counts per tool
- Not strict enough: runtime errors that typing should have caught (`KeyError`, `TypeError`, `AttributeError`, or
  a message naming a tool result); probe executes (a script that is, ignoring imports, one awaited tool call or a
  gather of bare tool calls returned as is, optionally through a variable); calls to tools still returning
  `JsonValue`, ranked, which are the next schemas to write (`upstream_calls.output` records `schema`, `text` or
  `untyped` per call); scripts using `json.loads`
- One verdict line from named constants in `src/usage/report/strictness.rs`:

| Constant | Value | Meaning |
|---|---|---|
| `MIN_RULE_ERRORS` | 5 | errors of a rule before its unresolved share counts |
| `UNRESOLVED_SHARE_LIMIT` | 40% | unresolved share from which a rule looks too strict |
| `MIN_ERROR_RUNS` | 5 | runs with a type error before the abandoned share counts |
| `ABANDONED_SHARE_LIMIT` | 30% | abandoned share from which the rules look too strict |
| `MISMATCH_LIMIT` | 3 | `output_mismatch` calls of one tool that mark its schema wrong |
| `PROBE_LIMIT` | 5 | probe executes from which typing looks too loose |
| `RUNTIME_ERROR_LIMIT` | 5 | typed-catchable runtime errors from which typing looks too loose |
| `JSON_LOADS_LIMIT` | 5 | `json.loads` scripts from which typing looks too loose |

The verdict is `Looks too strict`, `Looks too loose`, `Mixed` or `Looks balanced`, summed over clients.

**Escalation.** If the not-strict-enough signals stay over their thresholds across two consecutive reviews after
the untyped tools they name got schemas, add a strict checker for scripts. If a rule's unresolved share stays high,
relax that rule (or drop its ban) instead of adding hints.

### Usage tracking

Goal: see whether agents use Code Mode well or get confused, and feed that back into the directions and stubs

- SQLite-format database at `<state_dir>/codemode.sqlite`, kept with turso (WAL, numbered migrations in
  `PRAGMA user_version`, mode 0600). Every open uses turso's multiprocess WAL so the CLI can read and write while
  the daemon runs; a SQLite build must not open the file at the same time, since the two coordinate WAL access
  differently.
  Tables: `sessions`, `calls` (every agent-facing call: time, app session label, session state, client name/version, tool,
  input — query, described names or script —, outcome, detail, fingerprint, duration, result bytes, execution id),
  `executions` (one row per finished execution with its script and final outcome), `upstream_calls` (server,
  tool, Python name, arguments, outcome, duration, approval id, how the result was typed), `approvals`, `passkeys`
- Records go through a bounded channel (4096) to a writer thread; when it is full the record is dropped and
  counted, so logging never blocks or fails an agent call
- Outcome taxonomy, classified from structured executor results: `ok`, `type_error` (ty rule codes kept),
  `unsupported_syntax` (Monty `NotImplementedError`), `name_error` (only `unresolved-reference` diagnostics, unknown
  tools, unknown described names), `import_error` (only `unresolved-import`), `runtime_error` (exception type kept),
  `tool_error`, `output_mismatch` (a result broke its output schema), `timeout`, `denied`, `pending`, `busy`. An exception is traced back to the tool failure the host
  injected when its type and message match, so an unhandled tool error is `tool_error`/`denied`/`timeout`, not
  `runtime_error`
- Error fingerprint: outcome plus the detail with quoted literals, numbers, hex ids and whitespace normalized
- Sensitive servers (`sensitive = true`, default when the server policy is `ask`): upstream rows keep tool name and
  outcome only; a failure from such a tool is logged as the tool name; once an execution has read a sensitive
  tool's result, its exception detail keeps only the exception type
- A "run" is the unit behind every per-session number: the app session when the call carried one, otherwise one
  client name's calls and executions with gaps under 10 minutes, computed in Rust from rows ordered by time. Runs
  without a session are approximate: two sessions of one client that overlap or follow within 10 minutes merge.
  An agent that forgets to pass its session splits into several runs, which the session-reuse numbers expose
- `codemode-mcp stats [--since 7d]`: per client calls, runs (approximate when session-less), execute success rate,
  mean attempts until success per run, session reuse (minted, calls with a passed session, used once); top 10 fingerprints; slowest upstream tools; approval counts. `GET /stats` shows the same
- `codemode-mcp review [--since 7d] [--out FILE]`: Markdown with a per-client summary, top fingerprints with one
  example script and error each, the 5 runs with the most failed executes before success or abandonment as their
  ordered attempt sequence, hallucinated tool names (`name_error` names that start with a configured `<server>_`),
  executes that called tools never described in that run, empty and repeated searches, type strictness (see
  Type strictness), and approval stats (count, median wait, denied, expired)
- Retention `log_retention_days` (90); purged on startup and daily. Passkeys are kept

### Threat model

- Trusted: the owner, the phone holding the passkey, the Mac's user account
- Defended against:
  - agents limited to MCP tools: they reach tools only through `execute`, and `ask` tools wait for a passkey
    assertion on the phone
  - confused agents with a shell: the CLI cannot approve anything. Enrolling a second passkey or removing one
    needs an existing passkey's approval, and every such request is announced on the phone. A first passkey
    can still be enrolled from the CLI while none exists
- Not defended against: hostile code running as the same macOS user. Such code can edit the SQLite file
  (insert a passkey, read OAuth tokens), edit the config (set a tool to `allow`), replace the binary, or talk to
  upstreams directly. Defending against it needs OS-user separation (daemon and state under another account)
- The admin listener is loopback-only and refuses proxied requests and non-loopback `Host` headers; its JSON
  bodies keep cross-site form posts out. `op warm` bypasses approvals by design, and only from the Mac
- LAN and tailnet peers can reach `/mcp` without authentication (non-goal above); they get the same rights as a
  local MCP-only agent, except that they can never use or create a client grant, so every `ask` call they make
  needs its own approval
- Local same-user processes can still impersonate a client name and ride a live client grant (the fallback for
  calls without a valid session), because the name is self-asserted and loopback gives no identity. Session
  grants close this for agents that pass their session: the token is unguessable, and a caller that presents a
  valid session never matches a client grant. Whoever holds a token (it appears in the agent's own context and
  transcript) can use its grants for as long as the session lives

### OAuth

- A `url` server with `oauth = true` (optional `scopes`, `client_name`) is tried anonymously until someone signs
  in. A server that answers anonymous `initialize` (Exa does) keeps working; one that answers 401 is reported as
  `needs_login` in `/healthz` and `codemode-mcp tools`, its tools leave the catalog, and it is retried every
  30 minutes or at once after a login
- `codemode-mcp oauth login <server>` calls `POST /admin/oauth/login` on the admin listener, which runs rmcp's
  discovery (RFC 9728 protected-resource metadata, then authorization-server metadata; servers without
  published metadata are refused), dynamic client registration (public client), and builds a PKCE (S256)
  authorization URL with redirect URI `http://127.0.0.1:<admin port>/oauth/callback/<server>`. The CLI prints it
  and runs `open` on macOS (`--no-open` skips that)
- `GET /oauth/callback/<server>` on the admin listener exchanges the code (the CSRF state must match a stored
  flow) and shows a plain "you can close this tab" page; the upstream then reconnects with
  `AuthClient` + `StreamableHttpClientTransport::with_client`
- Storage in `codemode.sqlite` (mode 0600, as are its WAL files):
  - `oauth_pending`: PKCE verifier, CSRF state and the fresh registration of each flow in progress, 10 minute
    lifetime, so a daemon restart mid-login does not strand the browser
  - `oauth_logins`: the client registration (id, secret if any, redirect URI, scopes) and rmcp's
    `StoredCredentials`, written together in one transaction when the callback succeeds. rmcp keeps only the
    client id with the tokens, and registers before the user signs in, so committing both at the end means an
    abandoned or failed flow never replaces a working login
- Refresh is rmcp's: `get_access_token` refreshes 30 s before expiry (or after a 401) and the credential store
  saves the rotated tokens in place; a rejected refresh token ends in `needs_login`
- `oauth status` shows login state, scopes, expiry and whether a refresh token exists, never token values;
  `oauth logout <server>` deletes the login and reconnects anonymously

### T3 Code (deferred)

T3 Code mints a bearer token per thread and passes it inline in its own MCP entry, and its tools (preview,
device, PR linking) are scoped to that thread and already present in every T3 session. Putting T3 behind the
gateway would mean forwarding each caller's own token, which needs one upstream connection per caller session
instead of the one long-lived connection per server everything else uses. The gain is small because T3
sessions already have the tools. Seam for later: an upstream kind `caller_auth` whose `Upstream` is created
lazily per caller (the server is session-less, so keyed by token header rather than a session id; the token comes
from a header the agent's entry sets), dropped when idle, and excluded from the shared catalog build

### Our own MCPs: homebased adapter

- `codemode-mcp adapter homebased` is a stdio MCP server in the same binary (`src/adapters/homebased.rs`;
  more adapters go next to it). Each tool runs `homebased --json ...` with an argv array, never a shell, under a
  timeout (30 s reads, 60 s cancel and message, 150 s submits, since a local submit retries a busy daemon for
  about 90 s)
- Tools: `daemon_status`, `task_list`, `task_show`, `task_log` (tail 200), `task_usage`, `fleet_machines`,
  `task_submit_agent`, `task_submit_command`, `task_followup`, `task_cancel`, `message_send`, `notify`. Left out:
  daemon stop, restart and update, config, fleet mutations, the resource and GPU queue, `t3`, `task report` and
  container submits
- Submits build the spec (`homebased task schema`) and pass it on stdin; `thread` is required and the docstring
  tells the agent to pass its own session id and not to poll, since results arrive as `HOMEBASED_EVENT`
  messages. The prompt (and the follow-up message) is written to a 0600 file in a private 0700 temp dir that is
  removed after the command; homebased inlines prompt files at submit. A `request_id` (and `message_id` for
  messages) is generated when none is given and returned, so a retry is safe
- Option values are passed as `--flag=value` and ids must be UUIDs, so agent text cannot become another option.
  The adapter strips `HOMEBASED_TASK_ID`, `CODEX_THREAD_ID`, `CODEX_SESSION_ID` and `CLAUDE_CODE_SESSION_ID`
  from homebased's environment: it acts for many sessions and must not pass its own caller identity on
- `notify` posts through the shared ntfy module (blocked = urgent, important = high, done = default), because
  `homebased notify` only sends a test message
- Every tool declares an `outputSchema` and returns `structured_content` (serde structs with schemars in
  `src/adapters/homebased/outputs.rs`), read from real `homebased --json` output and cut to the fields an agent
  acts on: statuses are enums (stubs: `Literal`), fields homebased leaves out are `NotRequired`, and mutating tools
  return small acks (`request_id`/`id`/`status`, `message_id`, `{ok}`). A dry run submit returns
  `{request_id, dry_run: true, argv}`. `task_list` drops the CLI's extra fields, which shrinks a long history
- homebased errors (`{"error": {code, message, retryable}}` on stderr) become tool errors:
  `homebased error <code> (exit <n>, retryable: <bool>): <message>`
- Starter policies: `task_submit_command`, `task_cancel` and `message_send` are `ask` with session grants, the
  rest `allow`, and the server is not `sensitive`. Caveat: homebased starts agent workers with their sandbox and
  approvals bypassed (`--dangerously-bypass-approvals-and-sandbox`, `--permission-mode`), so an allowed
  `task_submit_agent` is as powerful as `task_submit_command`: the prompt alone can run anything. Filtering
  `extra_args` alone does not change that. Decision: `task_submit_agent` stays `allow`, because delegation is
  routine and every current agent has a shell that can run `homebased` directly, so `ask` would add taps
  without adding protection. `extra_args` is still limited to reasoning-effort flags (`--effort LEVEL`,
  `-c model_reasoning_effort=LEVEL`) as a cheap extra layer, and the prompt is logged, so misuse shows up in
  `review`. Revisit if MCP-only agents (no shell) start using the adapter

### Service

- Rust 2024, tokio, axum 0.8, rmcp, monty-pool, webauthn-rs, turso; conventions match homebased (color-eyre, thiserror, no unwrap/expect)
- launchd agent `dev.praveen.codemode-mcp`, listening on `0.0.0.0`, Host header rules accept localhost, private, Tailscale and `*.ts.net` names (plus `extra_allowed_hosts`)
- `codemode-mcp service install` copies the running binary to `~/.local/bin/codemode-mcp` and the Monty worker
  (`worker_path`, else `.tools/bin/monty` in the current directory) to `~/.local/share/codemode-mcp/monty`, both
  through a temp file and rename, writes `~/Library/LaunchAgents/dev.praveen.codemode-mcp.plist` (RunAtLoad,
  KeepAlive, ThrottleInterval 10, PATH with `~/.local/bin` and `/opt/homebrew/bin`, stdout and stderr under
  `<state_dir>/logs/`), lints it with `plutil`, then `launchctl bootout` (failure ignored) and `bootstrap
  gui/<uid>` (retried for 10 s), as homebased does. An explicit `--config` is pinned in the plist.
  `service uninstall` boots out and removes the plist, keeping state and installed files; `service status` and
  `service restart` (`kickstart -k`). Every one takes `--dry-run`
- With `worker_path` unset the daemon uses `~/.local/share/codemode-mcp/monty`, then `monty` on `PATH`
- `codemode-mcp config init` writes a starter config (1Password, OpenAI docs, Exa with OAuth, homebased) to the
  config path and refuses to overwrite; `--print` writes it to stdout
- HTTPS for the passkey page through `tailscale serve` on a dedicated port (`/` on 443 is already taken)
- Admin API (`/admin/enroll`, `/admin/passkey/remove`, `/admin/warm`, `/admin/oauth/{login,status,logout}`, and
  the browser's `GET /oauth/callback/<server>`) on a separate listener, `admin_listen` (default `127.0.0.1:7682`, must be
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
- With a passkey enrolled, adding or removing passkeys needs an existing passkey's approval and every request is
  announced; hostile same-user code is out of scope (see Threat model)
- OAuth registrations and tokens are committed together at the end of a login, in SQLite
- T3 Code stays outside the gateway for now
- The homebased adapter ships in the main binary; submit is split by workload (`agent` allowed, `task` asks)
- No tool returns `Any`; `Any`, `cast` and `type: ignore` in scripts are refused; the review decides whether to tighten or relax (see Type strictness)

## Open questions

- Persisting sealed dumps so approvals survive a daemon restart (needs re-attaching pending upstream calls)
- 1Password session lifetime across app lock
- OS-user separation for the daemon and its state, which would extend the threat model to same-user code
- Whether Exa's authorization server accepts the loopback redirect at sign-in (discovery, registration and the
  authorization URL work; the browser step has not been run)
