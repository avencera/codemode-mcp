//! Instructions shown to agents
//!
//! The script rules are macros so the same text can be spliced into the
//! `execute` tool description (which needs a literal) and into runtime strings

macro_rules! tool_call_rule {
    () => {
        "Tools are async functions taking keyword arguments only: `r = await server_tool(arg=...)`. \
         Use the types from the describe_tools stubs (TypedDict/Literal) as given."
    };
}

macro_rules! script_rules {
    () => {
        concat!(
            "Scripts are typed Python in a sandboxed Monty subset. They are type-checked before running; \
             fix reported errors and retry.\n\
             - Annotate function params/returns and non-obvious variables.\n\
             - ",
            $crate::guidance::tool_call_rule!(),
            "\n\
             - Results are typed. A tool with no declared result type returns `JsonValue` (predefined, never \
             imported). Read it with the predefined accessors, which take a path and raise naming it when a \
             step is missing or has another type:\n  \
             `url = json_str(r, \"$.hits[0].url\")`; also json_int, json_float, json_bool, json_list, json_dict\n  \
             `cursor = json_get(r, \"$.next\")` is None when missing; `data = json_parse(text)` parses JSON text\n  \
             `Any`, `cast`, `# type: ignore` and `json.loads` are rejected.\n\
             - A helper may return any JSON-like value as `JsonValue`, `dict[str, str]` and `list[dict[str, int]]` \
             included. A variable annotated `dict[str, JsonValue]` or `list[JsonValue]` is stricter: build it \
             with that annotation from the start.\n\
             - Allowed: top-level `await`; `async def` helpers; `await asyncio.gather(a(), b())` for concurrency \
             (no keyword args such as return_exceptions); if/for/while; list/dict/set comprehensions; f-strings; \
             try/except/finally with built-in exceptions (a refused or unapproved tool call raises \
             PermissionError, caught as `except OSError`; an error from the tool itself raises RuntimeError); dict, list, set, tuple, str, int, float, bool, None; \
             `@dataclass` only if really needed (eq=/frozen= options only).\n\
             - Stdlib only: asyncio, json, re, datetime, math, itertools, functools, collections, base64, \
             hashlib, random, time, typing. No third-party packages; no file or network access except through tools.\n\
             - Avoid: classes with inheritance, @property/@classmethod/@staticmethod, generators/yield, match, del, \
             async with/async for, user-defined exception classes, eval/exec.\n\
             - Import what you use (`import asyncio`, `import json`); nothing is pre-imported.\n\
             - The script runs at the top level, not inside a function: never `return`; the last expression is \
             the result. Make it JSON-serializable (dict/list/str/int/float/bool/None). \
             Return only the fields asked for (titles, URLs, short excerpts), never whole pages or documents. \
             Use print() for intermediate notes. Keep scripts short and focused."
        )
    };
}

macro_rules! session_rule {
    () => {
        "Pass the `session` value from your previous codemode result on every call; \
         the first call gets one automatically."
    };
}

macro_rules! onepassword_rule {
    () => {
        "When a program needs a 1Password value, never fetch the value into your context: decide \
         which env file the program reads, such as a stack's `*.secrets.env`, asking the user when it \
         is not clear, and have the values written there. From a script, call the `write_env` tool of \
         the `secrets` server (search_tools \"env file\") with the file's absolute path and each \
         variable's op:// reference; it answers with the variable names only. In a shell on this Mac, \
         `codemode-mcp op inject -i TEMPLATE -o FILE --reason WHY` fills each `{{ op://vault/item/field \
         }}` of a template the same way. For a high-severity secret that should never be in a file, \
         write only its op:// reference into the env file and start the program with `codemode-mcp op \
         run --env-file FILE --reason WHY -- COMMAND`, which puts the value in that command's \
         environment only and masks it in its output. `codemode-mcp op read` prints values, so use it \
         only when nothing else will do. When you do not know the exact reference, find it first: \
         `codemode-mcp op find WORDS --reason WHY` (or the `secrets` server's `find_references` \
         tool) lists matching items' op:// references and types, never values, after the user \
         approves on a Mac; then use the reference you picked. Or pass a description in one step: \
         `codemode-mcp op read --describe \"Apple signing cert\" --out-file PATH` or `write_env`'s \
         `describe`. If the user approves on a Mac it searches instead, writes nothing and answers the \
         matches (`op read` exits 3), so run again with the exact reference; if they approve on their \
         phone they pick the item, file attachments included, and it is written. A file attached to an item, such as a `.p12`, is \
         not text: write it with `codemode-mcp op read REFERENCE --out-file PATH`, which keeps its \
         exact bytes, since env files, templates and `op run` take text only. The user approves each batch once, with Touch ID on \
         this Mac or on their phone or other Mac, and sees the file it goes to; add `--keep 15m` (or \
         `keep_minutes`) only when the next few commands send the same values to the same file or \
         command. Prefer all of these to \
         `op`, which only works while the user is at this Mac. The `onepassword` tools here cover \
         1Password Environments only, not vault items."
    };
}

pub(crate) use {script_rules, session_rule, tool_call_rule};

/// Shown with `search_tools` results for a query about 1Password or secrets
pub const ONEPASSWORD_RULE: &str = onepassword_rule!();

/// Rule about calling tools, repeated at the top of `describe_tools` output
pub const TOOL_CALL_RULE: &str = tool_call_rule!();

/// Rule about passing the app session back, repeated at the top of
/// `describe_tools` output
pub const SESSION_RULE: &str = session_rule!();

/// Server-level instructions sent when an agent connects
pub const INSTRUCTIONS: &str = concat!(
    "Many upstream tools are reachable through scripts. Workflow: search_tools to find tools by keyword, \
     describe_tools to get their typed Python signatures, then execute a script that calls them. \
     execute returns status \"pending\" with an execution_id if the script is slow; call wait(execution_id). \
     Some tools need the user's approval: pass execute a short `thread` title for your task and a one-line \
     `reason` for the script, which the user sees when approving. A pending answer with approval_url and \
     waiting_for means pass its message and the approval_url on to the user, then call wait. When a script \
     makes several such calls, such as a set of deletes, start them together with `asyncio.gather` instead \
     of awaiting each in a loop, so the user approves the whole set at once. ",
    session_rule!(),
    "\n\n",
    onepassword_rule!(),
    "\n\n",
    script_rules!()
);

/// Whether a `search_tools` query is about reading a secret, so the results
/// carry [`ONEPASSWORD_RULE`]
pub fn asks_for_secrets(query: &str) -> bool {
    let query = query.to_ascii_lowercase();

    [
        "1password",
        "onepassword",
        "op://",
        "secret",
        "password",
        "api key",
        "credential",
        "token",
    ]
    .iter()
    .any(|word| query.contains(word))
}
