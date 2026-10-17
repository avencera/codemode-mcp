# codemode-mcp

A local MCP gateway that puts many MCP servers behind one endpoint and lets agents call them by writing short,
type-checked Python scripts.

Agents such as Claude Code and Codex connect once and see four tools instead of every upstream tool definition.
They search for the tools they need, read typed Python stubs for those, and run a script that calls several tools
in one round trip. Tool definitions stay out of the agent's context until it asks for them.

## How it works

| Tool | Purpose |
|---|---|
| `search_tools(query, limit?)` | Ranked tool paths with one-line descriptions |
| `describe_tools(paths)` | Typed Python stubs for the chosen tools |
| `execute(code, ...)` | Type-check a script against the stubs and run it in a sandbox |
| `wait(execution_id)` | Keep waiting on an execution that outlived the first response |

A script awaits tools as async functions with keyword arguments, and its last expression is the result:

```python
import asyncio

this_week, next_week = await asyncio.gather(
    calendar_list_events(start="2026-10-19", end="2026-10-23"),
    calendar_list_events(start="2026-10-26", end="2026-10-30"),
)
[event["title"] for event in this_week["events"] + next_week["events"]]
```

Scripts run in [Monty](https://github.com/pydantic/monty), a sandboxed Python subset, after a `ty` type check
against stubs generated from each tool's JSON Schema. Results are validated against the tool's output schema
before the script sees them.

## Features

- **Upstreams.** stdio servers, Streamable HTTP servers, and HTTP servers that sign in with OAuth
- **Lazy servers.** Rarely used stdio servers start on their first call and stop when idle
- **Keys from 1Password.** Header, environment and HTTP `url` values can hold `{{ op://vault/item/field }}`
  references, read once by the daemon and redacted from anything a script sees and from the daemon's logs. Embed
  the reference where a URL's key sits: `url = "https://host/mcp/{{ op://Personal/Zoho MCP - InfraOps/key }}/message"`
  (the `url` must start with a literal `http://` or `https://` and host; references may sit only in path segments and
  query names or values, so a `url` that is one whole reference is refused)
- **1Password values for programs.** `codemode-mcp op inject`, `op run` and `op read` work like 1Password's
  CLI, but the values are approved at the Mac, on the phone, or on another Mac, wherever you are. Agents use
  the `secrets` server's `write_env` to put values into an env file they name, without ever seeing them
- **Approvals.** Each tool is `allow`, `ask` or `deny`. An `ask` call waits for approval with Touch ID at the Mac,
  or with a passkey on your phone after an [ntfy](https://ntfy.sh) push. Approvals can cover one call or a 15 or
  60 minute session
- **Durable executions.** A script waiting on an approval is snapshotted and survives agent timeouts and daemon
  restarts
- **Built-in adapters.** Calendar and Reminders through EventKit, served as MCP tools
- **Website sign-in.** An agent driving the Mac's screen can have a 1Password username, password or
  one-time code typed into a login page on that login's sites, in a code-signed browser, without the value
  reaching the agent
- **Usage review.** Per-client stats and a Markdown review of how agents use the gateway
- **launchd service** with signed binaries, so macOS and 1Password permission grants survive updates

## Requirements

- macOS on Apple silicon
- A Developer ID certificate in your keychain. Binaries are signed so that macOS and 1Password keep their grants
  across updates, and `service install` refuses to run without the identity. As published, that is the author's
  identity; to run your own copy, set `SIGNING_IDENTITY` and `TEAM_ID` in `src/service.rs` and the signing
  variables in `.github/workflows/release.yml`

## Install

```sh
curl -LSfs https://github.com/avencera/codemode-mcp/releases/latest/download/install.sh | sh
codemode-mcp config init        # writes ~/.config/codemode-mcp/config.toml
codemode-mcp service install    # loads the launchd agent
codemode-mcp service status
```

The script checks the release against its checksum and Developer ID signature, then installs
`~/.local/bin/codemode-mcp` and the Monty worker. Add `~/.local/bin` to your `PATH` if it is not there. Pass
`--tag v0.1.0` after `sh -s --` for a specific release.

`codemode-mcp update` installs later releases. To build from source instead, see
[Operations](docs/operations.md#install).

## Connect an agent

The gateway listens on port 7681:

```sh
claude mcp add --transport http codemode http://localhost:7681/mcp
```

For Codex, add to `~/.codex/config.toml`:

```toml
[mcp_servers.codemode]
url = "http://localhost:7681/mcp"
```

## Add a server

```toml
[servers.docs]                 # remote, Streamable HTTP
url = "https://example.com/mcp"

[servers.mytool]               # local, stdio
command = "/opt/homebrew/bin/mytool-mcp"
args = ["--stdio"]
policy = "ask"

[servers.mytool.tools.delete_everything]
policy = "deny"
```

Then run `codemode-mcp service restart` and check the catalog with `codemode-mcp tools`.

## Documentation

- [Operations](docs/operations.md): install, passkeys, approvals, OAuth, updates and troubleshooting
- [Design](docs/design.md): architecture, approval model, type strictness, durability and threat model

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your
option.
