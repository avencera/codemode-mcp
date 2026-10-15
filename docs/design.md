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
| stdio | `1password-mcp`, `xcrun mcpbridge`, our own MCPs (`codemode-mcp adapter calendar`, `reminders`) | child process supervised by the daemon; restart with backoff |
| HTTP | `openaiDeveloperDocs` | plain Streamable HTTP |
| HTTP + OAuth | any `url` server with `oauth = true` | rmcp `AuthorizationManager` with SQLite-backed credential and state stores; the browser redirect lands on the admin listener's `/oauth/callback/<server>` (see OAuth) |
| HTTP, caller auth | T3 Code (`127.0.0.1:3773/mcp`) | deferred; see T3 Code |

A stdio server with `lazy = true` is for tools used now and then (Blender, video, diagrams): no process runs
until a script calls one of its tools, and after `idle_secs` (default 600) with no call in flight the daemon
closes the connection, which kills the process, and shows it as `idle`. Its tools stay in the catalog from the
cached tool list, so search and describe work while it sleeps, and the approval check lets calls through. The
first call wakes it and waits up to 3 minutes for the connect (including any 1Password prompt); a failed start
fails that call, and the next call tries again, with no background retries. Without a cached tool list (the very
first boot) it connects at once to learn its tools, then idles like any other quiet spell. Instructions the
server sends are learned on its first connect of each daemon run. A lazy server runs in its own process group,
and when its connection ends the daemon kills the group, so children a launcher such as `uvx` or `npx` left
behind go too; other servers stay in the daemon's group, which launchd ends with it. The idle stop takes the
connection under the same lock calls use to register, so a call either keeps the server up or waits for a fresh
start, never a connection that is shutting down. If the daemon itself is killed, a lazy server's group is not
in launchd's reach and relies on stdin closing to exit

Upstream calls use `PeerRequestOptions::with_timeout` so a timeout sends
`notifications/cancelled`; an outer `tokio::time::timeout` would not.
Calls are never retried automatically, since upstream tools may not be
idempotent. `tools/list_changed` refreshes the catalog

### Catalog

- Tools are namespaced by server: `openai_docs.search_openai_docs`, `onepassword.list_environments`
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
- Scripts that use `Any`, `cast`, `json.loads` or a `# type: ignore` / `# ty: ignore` comment are refused before `ty` runs (see Type strictness)
- Every session is fed the JSON accessors (`src/json_access.rs`) as its own snippet, type check skipped, before the
  script, so the script's line numbers stay its own. They are Python rather than host functions: a host call is a
  suspension and a worker round trip, and a loop over a few hundred rows would spend `max_suspensions` (1000). No
  tool may take an accessor's name; one that would is renamed like any other collision
- `from typing import JsonValue` is blanked before the check (`src/script_fixes.rs`): the name is predefined, and the
  import otherwise failed both the checker and the sandbox. Blanking keeps lines, columns and continuation
  backslashes, a statement left empty becomes `pass`, and approval pages and the log keep the agent's own text
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
- Batches: a `per_call` request waits 250 ms before it is announced, and the `per_call` requests of the same
  execution made meanwhile (the calls of one `asyncio.gather`) join it. The batch is announced once: one push
  titled with every tool and its count (`fixture.add ×2, fixture.json_text`), one Touch ID prompt, one page.
  Approving once or denying answers every request in it; each keeps its own row, with the first request as
  `approved_by`. A batch closes when it is announced, its page renders or it is decided, so a decision never
  covers a call the owner was not shown; a later call starts a new batch. Calls awaited one after another ask
  one by one. Membership is stored in each request's payload, so restored requests still share one page, but
  batches are not reopened after a restart. Agents learn this from the docstring `describe_tools` shows for
  each `ask` tool: it says the tool needs approval, and for `per_call` tools, to start several calls together
  with `asyncio.gather`. The note stays out of search text. The server instructions say the same in general
- An `ask` call needs a notifier and at least one enrolled passkey; otherwise it is refused at once
  (`no passkey enrolled; run \`codemode-mcp passkey enroll --label NAME\``)
- On an `ask` call the gateway creates a pending request (random 128-bit id) and sends an ntfy notification:
  title `codemode: <client> wants <server>.<tool>`, high priority, click URL `<public_origin>/approve/<id>`.
  Arguments never go into the notification
- While the owner is at the Mac (screen unlocked, keyboard or mouse input within `notify.mac.idle_secs`, 300;
  read through CoreGraphics), a tool call is asked there first and the ntfy push waits
  `notify.mac.escalate_after_secs` (60), going out only if the request is still pending. Presence is checked
  again every 2 seconds while it waits, so a locked screen or an idle owner sends the push at once. The Mac
  shows a Touch ID prompt (LocalAuthentication, biometrics only, no password fallback) naming the call, what a
  fingerprint grants, the client, and the `thread` and `reason` the agent passed to `execute` (optional, cut at
  60 and 160 characters, persisted with the request but never logged). The fingerprint approves with the
  longest grant of the narrowest kind allowed: a 60 minute session grant, else a 60 minute client grant, else
  once, so `per_call` tools are approved once. Agent-chosen text (client name, thread, reason) is quoted with
  quotes escaped, and line breaks, Unicode line separators, invisible and direction-changing characters are
  replaced, so none of it can pass for the daemon's own wording; the tool and grant come from the daemon. The
  prompt's other button, "Open Page", opens the approval page in the default browser for other choices and
  starts the push delay over. A prompt the system takes down (the screen locked) sends the push at once, and
  one still up when the request is decided elsewhere is taken down. Prompts show one at a time, a second apart
  however the previous one ended, so a touch meant for one cannot land on the next. Without Touch ID (no
  sensor, none enrolled, `notify.mac.touch_id = false`) the Mac shows a notification through
  `terminal-notifier` whose click opens the page. Presence only picks where the request appears first:
  approval still takes a fingerprint or a passkey assertion. Admin requests never offer Touch ID; on the Mac
  they show the notification and the push goes out at once. `notify.mac.enabled = false` asks on the phone only
- `GET /approve/{id}` (server-rendered, mobile layout, all agent-supplied text escaped, strict CSP) shows the
  client, `server.tool`, pretty-printed arguments, the script and the time left; for a batch, each call's
  arguments under `<n> of <total>: server.tool`, with "Approve all <total>" and "Deny all <total>". Buttons: Approve once;
  "Approve this session for 15 / 60 min" (only for `session` tools; every MCP call has a session) and, for a
  call that did not pass a valid session from a named, direct local client, also "Approve <client title or name>
  for 15 / 60 min" with a line saying the grant covers every running session of that client; a proxied or remote
  request is never offered the client grant, and the page says why. The server refuses a choice the page did not
  offer (`session15`, `session60`, `client15`, `client60`); Deny
- Approving takes a passkey assertion (webauthn-rs 0.6.1-dev, which uses RustCrypto, not
  OpenSSL): `POST /approve/{id}/options` binds the choice to a server-side ceremony (random id, 5 min TTL, stored in the database and bound to the approval id and the choice, never sent to the browser), then `POST /approve/{id}/confirm`
  verifies the assertion and applies that choice. Deny (`POST /approve/{id}/deny`) needs no passkey. All POSTs
  take JSON bodies, which keeps cross-site form posts out. `assets/webauthn.js` is the only script (no build step)
- The relying party id is the host of `public_origin` (when unset, `http://localhost:<listen port>`); `Passkey`
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
- Dumps are written to the database when a session parks, so a daemon restart mid-approval does not lose the execution (see Durability); only sensitive executions are withdrawn
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
| `execute(code, session?, thread?, reason?)` | type-check and run; `thread` and `reason` are shown when a tool needs approval; waits up to a short budget, then returns `{status: "pending", execution_id, approval_url?, waiting_for?}` |
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
  `type JsonValue = str | int | float | bool | None | Sequence[JsonValue] | Mapping[str, JsonValue]` (PEP 695; ty
  0.0.14 narrows it with `isinstance`, the stubs are never executed, so Monty never sees the statement). The
  covariant `Sequence` and `Mapping` let a helper declared `-> JsonValue` return a `dict[str, str]` or a
  `list[dict[str, str]]`; with invariant `list` and `dict` that was the most common type error agents hit. Parameters of
  unknown type accept `object`, results of unknown type are `JsonValue`; the header has no `Any`. The
  `**kwargs` fallback for parameter names that are not identifiers is `**kwargs: Unpack[<TypedDict>]` using the
  functional `TypedDict` syntax, which ty accepts
- JSON accessors. `isinstance(r, dict)` on the covariant alias narrows to an intersection with `Unknown` in it
  (`(Sequence[JsonValue] & dict[Unknown, Unknown]) | dict[str, …]`), which reads badly in a diagnostic and stops
  checking what it touches; the invariant `list`/`dict` alias narrows cleanly but brings back the helper return
  error above. So scripts read a `JsonValue` through predefined accessors instead: `json_str`, `json_int`,
  `json_float` (an int is converted), `json_bool`, `json_list` (`list[JsonValue]`), `json_dict`
  (`dict[str, JsonValue]`), each `(value: object, path: str = "$")`, raising `TypeError`, `KeyError` or `IndexError`
  as `at $.hits[0]: expected str, got int`; `json_get` returns `None` for a missing step; `json_parse(text)` is the
  typed `json.loads`. A path is `$` and `.key`, `[index]` or `["odd key"]` steps; the leading `$` is optional.
  `describe_tools` documents them whenever a described tool uses `JsonValue`. They are for third-party data only:
  a tool we write, and every other interface we control, declares its full shape instead
- Per-tool overrides (`[servers.<s>.tools.<t>]`): `output_schema` is an inline TOML table holding a JSON Schema;
  `output = "text"` returns the joined text as `str`, never parsed. Precedence: `output = "text"` wins over any
  upstream schema; an upstream-declared schema wins over `output_schema`, so a schema written for a server that
  later documents its own stops applying without an edit; `force_output_schema = true` makes the configured schema
  win. `output` and `output_schema` cannot be combined. The starter config types the OpenAI docs search, list and
  endpoint tools and marks `fetch_openai_doc` as text
- Server-level helpers (`[servers.<s>]`): `arguments` is a table the gateway passes to every tool that declares
  one of its keys, and those parameters are dropped from the stubs, so a script cannot guess them (1Password's
  `accountId`). `setup` lists calls made once per connection, lazily, before the first other call on it, inside
  that call's approval; a server that grants scopes per connection, such as 1Password's `authenticate`, needs
  this, and running it lazily keeps the 1Password app from prompting at boot. A failed setup call fails the call
  that needed it with a message naming only the setup tool. `aliases` are extra search terms for the server's
  tools (`1password` for `onepassword`)
- Branded strings. The schema keyword `"x-codemode-type" = "Name"` on a string schema renders the type as
  `Name = NewType("Name", str)` (declared once, ahead of the TypedDicts, and never renamed or reused for a
  generated type; a name that is not a capitalized Python identifier, or that a generated type already holds, is
  ignored with a warning). A `str` literal or plain `str` is not assignable to it, so a parameter typed this way
  accepts only a value some tool returned typed the same way. The output side is the keyword inside an
  `output_schema`; the input side is `param_types = { <param> = "Name" }` in the same per-tool table, which
  writes the keyword into that property of the tool's input schema before the stub is generated (only
  top-level string parameters; a missing or non-string one is skipped with a warning, an invalid name is a config
  error). The parameter's doc line names a tool result that yields the brand. `ty` reports a bad call as
  ``Expected `Name`, found `Literal["..."]` ``. Nothing is wrapped at runtime, values stay plain `str`, and a
  local annotation `x: Name = ...` runs because Monty does not evaluate it. The name itself does not exist in the
  sandbox, so `Name("x")` passes the checker and then raises `TypeError` before any tool is called
- Runtime check. Every result is validated against its effective schema (upstream, config or adapter) before the
  script sees it, by a validator for the subset `stubs` turns into types (`type`, `nullable`, `enum`, `const`,
  `required`, `properties`, `additionalProperties`, `items`/`prefixItems`, `allOf`/`anyOf`/`oneOf`, `$ref`); other
  keywords such as `pattern`, `minimum` and `format` pass. A text result for a `str` tool always passes. Sensitive
  servers log only the expected type of a mismatch: the path can hold keys from the data
- Bans before `ty` runs (`src/bans.rs`, `ruff_python_parser` pinned to the version Monty uses): a use of `Any` or
  `cast` imported under any alias, `<typing alias>.Any` and `<typing alias>.cast`, `json.loads` reached the same
  ways (it returns `Any`; `json_parse` is the typed replacement), and `# type: ignore` / `# ty: ignore` comment
  tokens (text inside a string is not a comment). An unused import is allowed: it switches nothing off, and the
  first smoke run showed agents add one out of habit, which cost a retry for no gain. They come back as a
  `type_error` with rule ids `ban:any`, `ban:cast`, `ban:json-loads`, `ban:type-ignore` and a one-line hint

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
  `untyped` per call); scripts parsing JSON text (`json_parse`, or `json.loads` before it was refused). An accessor's
  `TypeError` or `KeyError` counts as a runtime error typing should have caught: a schema for the tool would have caught it at the call
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
| `JSON_TEXT_LIMIT` | 5 | scripts parsing JSON text from which typing looks too loose |

The verdict is `Looks too strict`, `Looks too loose`, `Mixed` or `Looks balanced`, summed over clients.

**Escalation.** If the not-strict-enough signals stay over their thresholds across two consecutive reviews after
the untyped tools they name got schemas, add a strict checker for scripts. If a rule's unresolved share stays high,
relax that rule (or drop its ban) instead of adding hints.

### Usage tracking

Goal: see whether agents use Code Mode well or get confused, and feed that back into the directions and stubs

- SQLite-format database at `<state_dir>/codemode.sqlite`, kept with turso (WAL, numbered migrations in
  `PRAGMA user_version`, mode 0600, created that way before turso opens them, so no process-wide umask is needed). Every open uses turso's multiprocess WAL so the CLI can read and write while
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

- Trusted: the owner, the devices holding the passkey, the Mac's Touch ID sensor, the Mac's user account
- Defended against:
  - agents limited to MCP tools: they reach tools only through `execute`, and `ask` tools wait for a passkey
    assertion or a fingerprint on the Mac's Touch ID sensor. The thread and reason in the prompt are the
    agent's words; a misleading one cannot change the tool or grant it names
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

- A `url` server with `oauth = true` (optional `scopes`, `client_name`, `client_id`, `client_secret`,
  `authorization_params`) is tried anonymously until someone signs
  in. A server that answers anonymous `initialize` keeps working; one that answers 401 is reported as
  `needs_login` in `/healthz` and `codemode-mcp tools`, its tools leave the catalog, and it is retried every
  30 minutes or at once after a login
- `codemode-mcp oauth login <server>` calls `POST /admin/oauth/login` on the admin listener, which runs rmcp's
  discovery (RFC 9728 protected-resource metadata, then authorization-server metadata; servers without
  published metadata are refused), dynamic client registration (public client), and builds a PKCE (S256)
  authorization URL with redirect URI `http://127.0.0.1:<admin port>/oauth/callback/<server>`. The CLI prints it
  and runs `open` on macOS (`--no-open` skips that)
- A configured `client_id` skips registration, for authorization servers that offer none, such as Google's.
  Its `client_secret` may hold `op://` references, read through `op` at login only; the resolved secret is
  stored with the registration, as a registered client's is, so refreshes need no 1Password prompt.
  `authorization_params` are added to the authorization URL, replacing any rmcp set; the parameters PKCE, the
  CSRF check and the token exchange rely on are refused at config load
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

### Secrets in headers and env

- A `headers` or `env` value can hold `{{ op://vault/item/field }}` references (`op inject`'s template syntax),
  alone or inside text, e.g. `Bearer {{ op://Dev/Context7/credential }}`. Malformed references fail at config load,
  and the error never quotes the text between the braces in case it is a pasted secret
- The first connect runs `op read --no-newline <reference>` for each one (`[secrets] op`, default `op` on `PATH`),
  outside the 30 s connect timeout with its own 120 s limit so a Touch ID prompt can be answered. Each reference
  is read once per process and kept in memory, shared by every server that names it, and reads run one at a
  time, so servers starting together share one prompt and reconnects never prompt again; a rotated key needs a
  restart. A literal `{{` cannot be escaped, so a value that needs one cannot go in `headers` or `env`
- Reads go through the 1Password app integration, so the Mac prompts. A service account token
  (`OP_SERVICE_ACCOUNT_TOKEN`) would read without prompting, but it is a reusable credential on the Mac that
  supply-chain malware could copy, so the daemon is not set up with one
- A failed read leaves the server `unavailable` with category `secret_unavailable` and retries every 10 minutes
  rather than on the usual backoff, since each try can put a prompt on the Mac. The local error names the
  reference and `op`'s first error line, never a value
- Values read are added to the redactor that already scrubs configured header and env values, URL query strings
  and userinfo from upstream error text before a script sees it, and from stdio servers' stderr before it is
  logged

### T3 Code (deferred)

T3 Code mints a bearer token per thread and passes it inline in its own MCP entry, and its tools (preview,
device, PR linking) are scoped to that thread and already present in every T3 session. Putting T3 behind the
gateway would mean forwarding each caller's own token, which needs one upstream connection per caller session
instead of the one long-lived connection per server everything else uses. The gain is small because T3
sessions already have the tools. Seam for later: an upstream kind `caller_auth` whose `Upstream` is created
lazily per caller (the server is session-less, so keyed by token header rather than a session id; the token comes
from a header the agent's entry sets), dropped when idle, and excluded from the shared catalog build

### Our own MCPs: Calendar and Reminders adapters

- `codemode-mcp adapter calendar` and `codemode-mcp adapter reminders` are stdio servers over EventKit
  (`src/adapters/apple/`), so they cover every account the Mac's Calendar and Reminders apps show (iCloud, Google,
  Exchange, subscribed). They are two processes because macOS grants calendars and reminders separately
- Calendar tools: `list_calendars`, `list_events`, `get_event`, `create_event`, `update_event`, `delete_event`.
  Reminders tools: `list_reminder_lists`, `list_reminders`, `get_reminder`, `create_reminder`, `update_reminder`,
  `complete_reminder`, `delete_reminder`. There is no free-time tool: a script computes it from `list_events`
- Starter policies: reads `allow`, every write `ask` with session grants, and both servers are not `sensitive`, so
  titles and times reach the usage log
- Times: agents pass ISO 8601. A date (`2026-10-14`) is a whole day; a time without an offset is the Mac's local
  time; times come back in the Mac's zone with its offset and each list result names the zone. Window and filter
  ends given as dates include that whole day. An all-day event takes dates (its `end` is the last day, inclusive)
  and a timed one takes times; mixing them is refused. jiff parses `2026-10-14T09:30` as a date too, so only text
  with no time part is read as a date
- Lost updates: every item carries `last_modified` (UTC, milliseconds). `update_*` and `delete_*` must send it
  back unchanged and are refused when the item changed since, with the current value in the error.
  `complete_reminder` does not need it, since marking a reminder done twice is harmless. The check and the save
  are two store calls, so a change landing between them is not caught
- Repeating events: `list_events` expands occurrences, and each carries an `occurrence`, the start the series gave
  it before any change. `update_event` and `delete_event` refuse a repeating event without one, so a whole series
  is never changed by accident; with it they change that occurrence (`EKSpanThisEvent`), and with
  `and_future=true` it and every later one (`EKSpanFutureEvents`), which EventKit does by ending the series and
  starting a new one with a new id. Passing the first occurrence with `and_future` changes or deletes the whole
  series; deleting an original series that way also removed a continuation split off from it (checked live).
  EventKit finds events by id only, so an occurrence is looked up among the series' events within 31 days of its
  place; one moved further on its own is not found. Timed occurrences match to the second; all-day ones match by
  day in the Mac's zone, since an event kept in another zone places them at another midnight. Changing or deleting
  one occurrence changes the series, so every other occurrence's `last_modified` moves on and tokens read before
  it are stale (checked live). An occurrence changed on its own gets the id
  `<series id>/RID=<seconds>`, matched to its series by the part before `/RID=`. Moving a single occurrence to
  another calendar is refused, and `create_event` makes one-off events only. Saving an all-day event always
  clears its zone so its dates stay the Mac's dates; a timed event keeps its own zone unless it was all-day. Repeating reminders can be edited. Completing one (checked live with a weekly reminder) leaves it open with its next due date and
  adds a separate completed reminder, with a new id, for the finished occurrence; `complete_reminder` returns the
  open one, and its description says so
- New timed events are pinned to the Mac's zone (`timeZone`) and all-day ones float. Due date components are
  written and read as Gregorian whatever calendar the Mac displays. An empty string in an update clears that text
  field, as does naming it in `clear`
- Reminders: a due time also gets an alert at that time, as the Reminders app adds one; fixed-time alerts are
  replaced only when the due date changes, so a hand-set alert survives other edits. Priority maps EventKit's
  0-9 to `none`/`high` (1-4)/`medium` (5)/`low` (6-9) and writes 1, 5 or 9. `list_reminders` sorts not-done items
  by due date (undated last), cuts notes to 200 characters and returns at most `limit` (default 200, cap 1000)
  with `truncated`. EventKit does not expose sections, tags, subtasks, flags or smart lists, so neither do the
  tools. Reading the Reminders database directly would add them but needs Full Disk Access for the daemon, and
  its schema is private; not done
- Structure: the adapters check arguments and the rules above, then call a `CalendarBackend` or
  `RemindersBackend` that only reads and writes. The shipped backend is `EventKit`: one thread owns the
  `EKEventStore` (it and its objects are not thread-safe) and callers block on its answer, off the async
  workers. A panic in a call (the bindings panic when EventKit returns nil where it promised an object) is caught
  and returned as an error, so the thread keeps serving. The tests run the same adapters over an in-memory backend
  (`tests/fixtures/fake_eventkit.rs`, `tests/gateway/apple.rs`). A long-lived store sees changes made elsewhere
  (checked with a reminder added by another process)
- Permission: macOS shows its prompt once per entity type and binary identity. It reads the prompt text and
  identifier from an Info.plist that `build.rs` embeds (`assets/Info.plist`, `-sectcreate __TEXT
  __info_plist`); without one the request is refused silently. The grant goes to the responsible process, which
  for an adapter is the launchd-started daemon, and is keyed to the signing identity and identifier, so it
  survives rebuilds signed by `service install` (checked across a rebuild). The adapter asks at startup, so the
  prompt appears when the daemon starts it. In testing, a request sent straight after the store was created never
  reached the privacy service; the adapter queries the store first and asks again when a request is still
  unanswered after 30 s. Until access is granted every tool fails with what to do: click Allow, or turn the
  binary on in System Settings > Privacy & Security
- Not on Linux: the EventKit code and its dependencies are macOS-only; elsewhere the subcommands exit with an
  error

### Xcode

- The `xcode` server is Xcode's own stdio bridge, `/usr/bin/xcrun mcpbridge`, with no adapter of ours. It talks
  to Xcode's background tool service (XcodeService), which runs with or without the Xcode window. Every tool
  declares an output schema, and the bridge sends `tools/list_changed`, so the catalog follows Xcode's tool set
- Approval is Xcode's: an agent must be approved, along with each project folder, and the request is raised by
  `XcodeOpenWorkspace` or `XcodeNewProject`. Through the gateway the daemon is one agent, so one approval covers
  every client; the phone policies below are the per-call layer on top. Xcode records the agent by its signature
  (`signed Q8UP8C53Y8 com.avencera.codemode-mcp` in `xcrun mcp-server status`), so the grant survives rebuilds
  signed by `service install`. A folder grant covers that folder and its subfolders, so each worktree asks again
- Starter policies: building, testing, running the scheme, reading and editing project files, build settings and
  string catalogs are `allow`, as a local agent could do the same from its shell. `RunCodeSnippet` and
  `InvokeDebuggerCommand` run arbitrary code and `XcodeRM` can delete files from disk, so those three `ask`. The
  server is not `sensitive`, so file contents reach the usage log
- `MCP_XCODE_PID` is left unset: pointed at a process that is not Xcode, the bridge never answers `initialize`

### Durability

A daemon restart, whether a deploy, a crash or a reboot, must not lose what an agent or the owner is waiting on.
State is written through to `codemode.sqlite` when it changes, never only at shutdown; every deadline is a
wall-clock epoch in milliseconds, not an `Instant`. The file is the one the rusqlite build used: turso opens it in
place, new tables arrive through the migration list (schema version 5), and a file written by a newer binary is
refused (`SchemaTooNew`).

**What persists**

- Executions: a `running` row is inserted when a script starts. The finished outcome (result JSON, printed
  output, outcome) is stored on the same row, and `wait` reads through to it when the id is not in memory, for
  `result_ttl_secs` (30 min). The payload is purged after the TTL, and oldest first once the stored results pass
  `max_retained_result_bytes`; the audit row stays. The row is written before waiters wake, so a result a client
  was told about is never missing after a crash
- Pending approvals: everything the page and the decision need (`ApprovalInfo`, deadline, grant choices, ntfy
  state). The expiry timer is re-armed from the stored deadline, and a request whose ntfy send failed
  (`unnotified`) is sent again at boot
- Client and session grants, with a wall-clock expiry. A grant is only (key, server, approval id, expiry), so
  1Password grants persist too
- Parked executions: the sealed dump and its tag, the stubs, the caller and script, the budget spent and slept,
  the output so far, the failures, the call ids and each gated call (`PreparedCall` and approval id). At boot each
  parked row is registered as running again (so `wait` works), its approvals are re-attached, and when a verdict
  or the expiry arrives the dump is verified and restored on a fresh worker exactly as in a live unpark
  (ids compared with the recorded ones). The parked row is deleted right after a successful restore, before the
  verdict is acted on: a crash from then on yields `interrupted` and never a call made twice. The delete is the
  claim: a resumed execution that finds the row already gone (another process took it) stops without acting on
  the verdict, and a process that has stopped writing never starts a call
- Enrollment links, as the SHA-256 of the token only, with label, gate and expiry; a link stays valid across a
  restart and a pending "approve the new passkey" step resumes
- Admin actions waiting on approval (enroll approval, passkey removal): the kind and target (passkey id or
  enrollment hash) are stored with the approval and re-attached at boot, so an approval decided after a restart
  still performs it
- WebAuthn ceremonies, 5 min TTL, serialized with webauthn-rs `danger-allow-state-serialisation` (the feature
  exists for server-side storage); the state never reaches the browser and stays bound to its approval id and
  choice
- Each upstream's last tool list (`tool_cache`). A server that is down at boot shows as `unavailable` with its
  cached tools, as when it drops mid-run; a `lazy` one shows as `idle` with them and does not start

**Derived and rebuilt**: the catalog and stubs (from live upstreams, with the cache standing in for a missing
one), the worker pool, the in-flight upstream connections, OAuth access in memory, and the usage log buffer.

**The sensitive exception.** Data from a `sensitive` server (1Password) stays off disk. Every durable write of a
payload goes through `Durable<T>` (`src/durable.rs`): `Durable::gate` does not even run the closure that builds the
payload when the data is sensitive, so a later caller cannot write one by accident. This covers the dump, result,
arguments and approval details of an execution that has used sensitive data (`sensitive_used`) and of any gated
call with `PreparedCall.sensitive`. What is kept is the row with a `sensitive` flag and no payload. After a
restart `wait` answers `interrupted`, saying sensitive state is not kept and the script must be run again, and
the approval page shows the request as withdrawn. Grants still persist. An integration test greps the database
file bytes for the arguments and results of a sensitive execution. Sensitivity is known only once the script has
touched a sensitive server or reached a sensitive gated call: an execution is flagged from then on, and an
approval is withheld when it is created for a sensitive call. Because `ask` servers are sensitive by default,
only an `ask` server with `sensitive = false` yields execution that can resume

**One owner per state directory.** `serve` takes an exclusive `flock` on `<state_dir>/daemon.lock` before it
touches any state and exits at once with "another daemon owns <dir>" when another process holds it; the kernel
releases the lock however the process ends. The listeners are bound next, then the previous process's leftovers
are settled, and only then do they answer. Without this a second daemon would resume the first one's parked
executions, interrupt its running ones and call an upstream twice. A finish never replaces a row that already
ended (the first terminal outcome wins). A one-off `exec` run of another process is recorded with its pid
(`executions.owner_pid`) and is left alone at boot while that process is alive and within the execution time
limit.

**Teardown freezes.** An `App` freezes its durable state (approvals stop settling, execution tasks stop writing
and are aborted) when its last handle goes away, and `serve` also holds a guard that freezes on any exit. A task
dropped during teardown therefore never marks an approval abandoned or deletes a parked row; only an explicit
outcome (a decision, an expiry, a finish, an interruption) does.

**Drain and `interrupted`.** On SIGTERM the daemon stops admitting executions (`execute` answers that the daemon is restarting), gives the
running ones `limits.drain_secs` (default 20) to finish, and parks those that wait only on approvals, which then
resume at the next boot. It then freezes durable state (so tearing tasks down cannot withdraw the approvals that
parked executions wait on) and flushes the usage log, which `serve` never did before. A script still running
after the drain, and any row still `running` and not parked at boot (a crash), becomes `interrupted`, a terminal
outcome counted in the review and in `/stats`. `wait` on it returns a restart message, the upstream calls that
recorded as completed (server, tool, status) and a warning that writes may have happened, so check before
re-running. The list comes from the usage log, so it may be incomplete: a SIGKILL loses the records still queued
for the writer thread, and an empty list never means that nothing happened. A sensitive execution that had
already finished is not called interrupted: `wait` says it finished (with its outcome), that its result is not
kept across restarts because it used a sensitive server, and not to re-run it. `serve` also warns at start when
the installed plist's `ExitTimeOut` is below the drain plus 10 s (run `service install` again).

**After a resume, tool calls resolve against the live catalog.** The catalog snapshot the script started with is
gone with the process, so a call made after the resume uses the tools and policies of the running daemon. The
script was type-checked against the old stubs, and a tool that changed shape in between fails at the call. The
stubs are stored only to restore the session. A restored dump is also run by whatever Monty worker is installed
then, which may be a newer version than the one that wrote it.

**Housekeeping.** Stored results past `result_ttl_secs`, and the oldest ones beyond the byte cap, lose their
payload at boot and then every minute, whether or not anyone calls; the audit row stays.

**The CLI** (`stats`, `review`, `exec`, `passkey list`) opens the same file beside the running daemon through
turso's `experimental_multiprocess_wal`, which every open uses (turso refuses a mix of modes). Recovery of
in-flight work runs only in the daemon, never in a CLI run, so `exec` does not touch another process's rows.

### Service

- Rust 2024, tokio, axum 0.8, rmcp, monty-pool, webauthn-rs, turso; conventions match homebased (color-eyre, thiserror, no unwrap/expect)
- launchd agent `dev.praveen.codemode-mcp`, listening on `0.0.0.0`, Host header rules accept localhost, private, Tailscale and `*.ts.net` names (plus `extra_allowed_hosts`)
- `codemode-mcp service install` copies the running binary to `~/.local/bin/codemode-mcp` and the Monty worker
  (`worker_path`, else `.tools/bin/monty` in the current directory) to `~/.local/share/codemode-mcp/monty`, both
  through a temp file and rename, writes `~/Library/LaunchAgents/dev.praveen.codemode-mcp.plist` (RunAtLoad,
  KeepAlive, ThrottleInterval 10, PATH with `~/.local/bin` and `/opt/homebrew/bin`, stdout and stderr under
  `<state_dir>/logs/`, `ExitTimeOut` = `limits.drain_secs` + 30 s so launchd waits out the drain), lints it with `plutil`, then `launchctl bootout` (failure ignored) and `bootstrap
  gui/<uid>` (retried for 10 s), as homebased does. An explicit `--config` is pinned in the plist.
  `service uninstall` boots out and removes the plist, keeping state and installed files; `service status` and
  `service restart` (`kickstart -k`). Every one takes `--dry-run`
- With `worker_path` unset the daemon uses `~/.local/share/codemode-mcp/monty`, then `monty` on `PATH`
- `codemode-mcp config init` writes a starter config (1Password, OpenAI docs, Calendar, Reminders, Xcode) to the
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
- Approval waits release the worker through sealed dumps, which are also written to the database so a parked execution survives a daemon restart (sensitive ones excepted, see Durability)
- With a passkey enrolled, adding or removing passkeys needs an existing passkey's approval and every request is
  announced; hostile same-user code is out of scope (see Threat model)
- OAuth registrations and tokens are committed together at the end of a login, in SQLite
- T3 Code stays outside the gateway for now
- No homebased adapter: agents drove homebased through its CLI about 3,800 times against 8 through the gateway.
  It holds no secret the agent shouldn't see, its flow is submit then wait for the callback with little to chain,
  and `ask` on submits held nothing back while the CLI sits in the same shell. Revisit for agents without a shell
- Xcode goes through Apple's `mcpbridge` unchanged rather than an adapter: its tools already declare output
  schemas, and Xcode owns the agent and folder approvals
- Calendar and Reminders go through EventKit rather than CalDAV: no password to store, every account the Mac
  shows, and a one-time macOS grant kept across rebuilds by the stable signature. They stay local; exposing them
  to ChatGPT would need endpoint authentication first (see Non-goals)
- No tool returns `Any`; `Any`, `cast` and `type: ignore` in scripts are refused; the review decides whether to tighten or relax (see Type strictness)

## Known gaps

- A sensitive execution cannot survive a restart (by design); the script has to be run again
- The usage log is written by a background thread, so a SIGKILL or power loss drops the records not yet written
- A parked dump restored after a Monty worker upgrade may be refused or behave differently; such an execution
  ends as an error, not a silent wrong answer
- Calls after a resume use the live catalog, not the one the script was checked against
- `flock` is advisory and local: a state directory on a network file system is not protected from two daemons
- Calendar and Reminders: an edit that lands between the `last_modified` check and the save is overwritten;
  an occurrence moved more than 31 days from its place in the series cannot be found; Reminders' tags, sections, subtasks and flags are not
  reachable through EventKit. A reminders fetch that times out (30 s) is cancelled, and a completion already
  running is waited for (20 s more) so it does not overlap the next call; one still running after that can

## Open questions

- Whether a sensitive execution could be resumed after a restart without writing its dump to disk (it would need a key held outside the daemon)
- 1Password session lifetime across app lock
- OS-user separation for the daemon and its state, which would extend the threat model to same-user code
